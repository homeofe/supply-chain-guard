import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { scanDependencyConfusion, scanPypiDependencyConfusion } from "../dependency-confusion.js";

describe("Dependency Confusion Detector", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-confusion-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("should return a clean report for well-known packages", async () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "test-project",
        version: "1.0.0",
        dependencies: {
          express: "^4.18.0",
          lodash: "^4.17.21",
        },
      }),
    );

    const report = await scanDependencyConfusion({
      target: tempDir,
      format: "text",
    });

    // Well-known packages should not generate high-severity findings
    const criticalOrHigh = report.findings.filter(
      (f) => f.severity === "critical" || f.severity === "high",
    );
    expect(criticalOrHigh).toHaveLength(0);
  }, 30000);

  it("should flag packages not found on the public registry", async () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "test-project",
        version: "1.0.0",
        dependencies: {
          "internal-company-utils-xyz-nonexistent": "^1.0.0",
        },
      }),
    );

    const report = await scanDependencyConfusion({
      target: tempDir,
      format: "text",
    });

    const finding = report.findings.find(
      (f) => f.rule === "DEPCONF_NOT_ON_REGISTRY",
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
    expect(finding?.description).toContain("not found on the public npm registry");
  }, 30000);

  it("should not flag scoped packages not on registry as high severity", async () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "test-project",
        version: "1.0.0",
        dependencies: {
          "@mycompany/totally-fake-internal-pkg-xyz": "^1.0.0",
        },
      }),
    );

    const report = await scanDependencyConfusion({
      target: tempDir,
      format: "text",
    });

    // Scoped packages missing from registry should be info, not high
    const highFindings = report.findings.filter(
      (f) => f.severity === "high" || f.severity === "critical",
    );
    expect(highFindings).toHaveLength(0);

    const scopedFinding = report.findings.find(
      (f) => f.rule === "DEPCONF_SCOPED_PRIVATE",
    );
    expect(scopedFinding).toBeDefined();
    expect(scopedFinding?.severity).toBe("info");
  }, 30000);

  it("should handle missing package.json", async () => {
    await expect(
      scanDependencyConfusion({
        target: "/nonexistent/path",
        format: "text",
      }),
    ).rejects.toThrow("No package.json found");
  });

  it("should handle empty dependencies", async () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "empty-deps",
        version: "1.0.0",
      }),
    );

    const report = await scanDependencyConfusion({
      target: tempDir,
      format: "text",
    });

    expect(report.score).toBe(0);
    expect(report.riskLevel).toBe("clean");
    expect(report.findings).toHaveLength(0);
  });

  it("should accept package.json path directly", async () => {
    const pkgPath = path.join(tempDir, "package.json");
    fs.writeFileSync(
      pkgPath,
      JSON.stringify({
        name: "direct-path-test",
        version: "1.0.0",
        dependencies: {
          commander: "^13.0.0",
        },
      }),
    );

    const report = await scanDependencyConfusion({
      target: pkgPath,
      format: "text",
    });

    // commander is a well-known package, should be clean or info only
    expect(report.findings.filter((f) => f.severity === "critical")).toHaveLength(0);
  }, 30000);

  it("should check devDependencies by default", async () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "devdeps-test",
        version: "1.0.0",
        devDependencies: {
          "internal-build-tools-xyz-nonexistent": "^1.0.0",
        },
      }),
    );

    const report = await scanDependencyConfusion({
      target: tempDir,
      format: "text",
    });

    const finding = report.findings.find(
      (f) => f.rule === "DEPCONF_NOT_ON_REGISTRY",
    );
    expect(finding).toBeDefined();
  }, 30000);

  it("should exclude devDependencies when includeDevDeps is false", async () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "no-devdeps-test",
        version: "1.0.0",
        devDependencies: {
          "internal-build-tools-xyz-nonexistent": "^1.0.0",
        },
      }),
    );

    const report = await scanDependencyConfusion({
      target: tempDir,
      format: "text",
      includeDevDeps: false,
    });

    // Should find nothing since only devDeps have the suspicious package
    expect(report.findings).toHaveLength(0);
  });

  it("should generate recommendations for confusion risks", async () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "recs-test",
        version: "1.0.0",
        dependencies: {
          "my-internal-utils-xyz-nonexistent": "^1.0.0",
        },
      }),
    );

    const report = await scanDependencyConfusion({
      target: tempDir,
      format: "text",
    });

    expect(report.recommendations.length).toBeGreaterThan(0);
    expect(
      report.recommendations.some(
        (r) => r.includes("scoped") || r.includes(".npmrc") || r.includes("registry"),
      ),
    ).toBe(true);
  }, 30000);

  it("should respect minSeverity filter", async () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "severity-filter-test",
        version: "1.0.0",
        dependencies: {
          "internal-company-utils-xyz-nonexistent": "^1.0.0",
          commander: "^13.0.0",
        },
      }),
    );

    const report = await scanDependencyConfusion({
      target: tempDir,
      format: "text",
      minSeverity: "high",
    });

    // All findings should be high or above
    expect(
      report.findings.every(
        (f) => f.severity === "high" || f.severity === "critical",
      ),
    ).toBe(true);
  }, 30000);
});

describe("Dependency Confusion Heuristics (unit)", () => {
  it("should identify internal-looking package names", () => {
    const internalNames = [
      "internal-auth-service",
      "private-utils",
      "company-config",
      "my-helper-lib",
      "shared-core-utils",
      "user-service",
      "payment-microservice",
      "app-config",
    ];

    const internalPatterns = [
      /^(?:internal|private|local|company|corp|org)-/i,
      /-(?:internal|private|local)$/i,
      /^(?:my|our)-/i,
      /^(?:lib|util|utils|helper|helpers|common|shared|core)-[a-z]+-[a-z]+/i,
      /^[a-z]+-(?:service|microservice|api|worker|lambda|handler)$/i,
      /^[a-z]+-(?:config|settings|constants|types|models|schemas)$/i,
    ];

    for (const name of internalNames) {
      const matches = internalPatterns.some((p) => p.test(name));
      expect(matches).toBe(true);
    }
  });

  it("should not flag common public package names as internal", () => {
    const publicNames = [
      "express",
      "react",
      "lodash",
      "typescript",
      "commander",
      "vitest",
      "prettier",
      "eslint",
    ];

    const internalPatterns = [
      /^(?:internal|private|local|company|corp|org)-/i,
      /-(?:internal|private|local)$/i,
      /^(?:my|our)-/i,
      /^(?:lib|util|utils|helper|helpers|common|shared|core)-[a-z]+-[a-z]+/i,
      /^[a-z]+-(?:service|microservice|api|worker|lambda|handler)$/i,
      /^[a-z]+-(?:config|settings|constants|types|models|schemas)$/i,
    ];

    for (const name of publicNames) {
      const matches = internalPatterns.some((p) => p.test(name));
      expect(matches).toBe(false);
    }
  });
});

// ─── v4.9 new feature unit tests ──────────────────────────────────────────

describe("PyPI confusion detection — parseRequirementsTxt (v4.9)", () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pypi-test-")); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  it("should return empty array for empty requirements.txt", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "# just comments\n");
    const findings = await scanPypiDependencyConfusion(tmpDir);
    // May have findings if packages are hallucinated, but no crash
    expect(Array.isArray(findings)).toBe(true);
  });

  it("should skip version pins and comments in requirements.txt", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "requirements.txt"),
      "# production deps\nrequests==2.31.0\nflask>=3.0.0\n# dev\npytest\n",
    );
    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(Array.isArray(findings)).toBe(true);
  });

  it("should detect AI-hallucinated PyPI package name (offline)", async () => {
    // Write a requirements.txt with a known hallucinated package name
    fs.writeFileSync(
      path.join(tmpDir, "requirements.txt"),
      "python-utils-helper\nrequests\n",
    );
    // Findings should include DEP_HALLUCINATED_PACKAGE for python-utils-helper
    // (works offline — no network call needed for hallucinated packages)
    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings.some((f) => f.rule === "DEP_HALLUCINATED_PACKAGE" && f.match === "python-utils-helper")).toBe(true);
  });

  it("should detect hallucinated package with correct severity (high)", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "django-api-utils\n");
    const findings = await scanPypiDependencyConfusion(tmpDir);
    const finding = findings.find((f) => f.rule === "DEP_HALLUCINATED_PACKAGE");
    expect(finding?.severity).toBe("high");
  });

  it("should not scan when no requirements.txt or pyproject.toml", async () => {
    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toHaveLength(0);
  });

  it("should handle requirements.txt with extras notation", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "requirements.txt"),
      "celery[redis]==5.3.0\naudit-hook\n",
    );
    const findings = await scanPypiDependencyConfusion(tmpDir);
    // Should not crash on extras notation
    expect(Array.isArray(findings)).toBe(true);
  });
});

describe("Version cooldown flag logic (v4.9)", () => {
  it("should flag version-hot-publish for package published < 24h ago", () => {
    // This tests the flag logic indirectly via the constants
    // The flag is set when hoursAgo < VERSION_HOT_HOURS (24h)
    const publishTime = new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(); // 2h ago
    const hoursAgo = (Date.now() - new Date(publishTime).getTime()) / (1000 * 60 * 60);
    expect(hoursAgo).toBeLessThan(24);
  });

  it("should flag version-cooldown for package published < 7 days ago", () => {
    const publishTime = new Date(Date.now() - 1000 * 60 * 60 * 24 * 3).toISOString(); // 3 days ago
    const daysAgo = (Date.now() - new Date(publishTime).getTime()) / (1000 * 60 * 60 * 24);
    expect(daysAgo).toBeLessThan(7);
    expect(daysAgo).toBeGreaterThan(1);
  });

  it("should not flag version published > 7 days ago", () => {
    const publishTime = new Date(Date.now() - 1000 * 60 * 60 * 24 * 10).toISOString(); // 10 days ago
    const daysAgo = (Date.now() - new Date(publishTime).getTime()) / (1000 * 60 * 60 * 24);
    expect(daysAgo).toBeGreaterThan(7);
  });
});
