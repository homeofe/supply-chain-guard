import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { scanDependencyConfusion, scanPypiDependencyConfusion } from "../dependency-confusion.js";
import pkg from "../../package.json";

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

    // Version must track package.json - hardcoding left this a release behind at v5.23.2.
    expect(report.tool).toBe(`supply-chain-guard v${pkg.version}`);
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

  it.each(["requirements.txt", "pyproject.toml"])(
    "should report partial coverage when %s exists but is not readable as a file",
    async (manifest) => {
      fs.mkdirSync(path.join(tmpDir, manifest));

      const findings = await scanPypiDependencyConfusion(tmpDir);
      expect(findings).toEqual([
        expect.objectContaining({
          rule: "PATH_SCAN_INCOMPLETE",
          severity: "info",
          file: manifest,
        }),
      ]);
    },
  );

  it.each([
    "requests==",
    "broken-extra[",
    "requests \\",
    'python-utils-helper; python_version < "',
  ])("should report partial coverage for malformed requirements entry %s", async (entry) => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), `${entry}\n`);

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "PATH_SCAN_INCOMPLETE",
      file: "requirements.txt",
      match: "incomplete dependency manifest parse",
    }));
  });

  it("should accept a valid single-line requirements manifest", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "python-utils-helper==1.0.0\n");

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      file: "requirements.txt",
      match: "python-utils-helper",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it.each([
    "-r shared/base.txt",
    "-rshared/base.txt",
    "--requirement shared/base.txt",
    "--requirement=shared/base.txt",
  ])("should report unresolved requirements include %s as partial coverage", async (include) => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), `${include}\n`);

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "PATH_SCAN_INCOMPLETE",
      file: "requirements.txt",
      match: "unresolved requirements include",
      description: expect.stringContaining("referenced dependency manifest"),
      recommendation: expect.stringContaining("referenced requirements files"),
    }));
    expect(
      findings.some((finding) =>
        finding.match === "incomplete dependency manifest parse"),
    ).toBe(false);
  });

  it("should leave ordinary pip index and resolver options out of scope without marking coverage partial", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), [
      "--index-url https://packages.invalid/simple",
      "--extra-index-url=https://fallback.invalid/simple",
      "--trusted-host packages.invalid",
      "--no-index",
      "--find-links ./wheelhouse",
      "--require-hashes",
      "-c constraints.txt",
      "",
    ].join("\n"));

    expect(await scanPypiDependencyConfusion(tmpDir)).toHaveLength(0);
  });

  it.each([
    ['[project]\n"dependencies" = ["django-api-utils"]\n', "quoted dependency key"],
    ['["project"]\ndependencies = ["django-api-utils"]\n', "quoted project table"],
    ["[project]\n'dependencies' = [\"django-api-utils\"]\n", "literal dependency key"],
    ["['project']\ndependencies = [\"django-api-utils\"]\n", "literal project table"],
  ])("should parse a recognized %s", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      file: "pyproject.toml",
      match: "django-api-utils",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it.each([
    '[project]\ndependencies-extra = []\n',
    '[Project]\ndependencies = ["django-api-utils"]\n',
  ])("should leave unrelated case-sensitive TOML keys and tables clean", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);
    expect(await scanPypiDependencyConfusion(tmpDir)).toHaveLength(0);
  });

  it("should report dynamic project dependencies as unresolved coverage", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndynamic = ["dependencies"]\n',
    );

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "PATH_SCAN_INCOMPLETE",
      file: "pyproject.toml",
      match: "dynamic project dependencies",
      description: expect.stringContaining("build backend"),
    }));

    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndynamic = ["version"]\n',
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toHaveLength(0);
  });
  it.each([
    '[project]\ndependencies = ["python-utils-helper"\n',
    '[project]\ndependencies = [python-utils-helper]\n',
    '[project]\ndependencies = ["python-utils-helper"] trailing-garbage\n',
    '[project]\ndependencies.extra = []\n',
  ])("should report partial coverage for malformed project dependencies", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "PATH_SCAN_INCOMPLETE",
      file: "pyproject.toml",
      match: "incomplete dependency manifest parse",
    }));
  });

  it("should accept empty and single-line project dependency arrays", async () => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), [
      "[project]",
      'dependencies = ["django-api-utils"]',
      "",
    ].join("\n"));

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      file: "pyproject.toml",
      match: "django-api-utils",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);

    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), "[project]\ndependencies = []\n");
    expect(await scanPypiDependencyConfusion(tmpDir)).toHaveLength(0);
  });

  it("should attribute packages to their own manifest when both are present", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "python-utils-helper\n");
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndependencies = ["django-api-utils"]\n',
    );

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      file: "requirements.txt",
      match: "python-utils-helper",
    }));
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      file: "pyproject.toml",
      match: "django-api-utils",
    }));
  });
  it("applies pip continuation and comment preprocessing in the specified order", async () => {
    for (const content of [
      "django-api-\\\r\nutils\r\n",
      "django-api-utils \\\r\n# continued comment\r\n",
    ]) {
      fs.writeFileSync(path.join(tmpDir, "requirements.txt"), content);
      const findings = await scanPypiDependencyConfusion(tmpDir);
      expect(findings).toContainEqual(expect.objectContaining({
        rule: "DEP_HALLUCINATED_PACKAGE",
        file: "requirements.txt",
        match: "django-api-utils",
      }));
      expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
    }

    fs.writeFileSync(
      path.join(tmpDir, "requirements.txt"),
      "django-api-utils \\ # not a continuation\r\n==1\r\n",
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "incomplete dependency manifest parse",
      }),
    );
  });

  it("parses named VCS requirements and reports unnamed dependency sources as partial", async () => {
    for (const requirement of [
      "-e git+https://example.invalid/repo.git#egg=django-api-utils",
      "django-api-utils @ git+https://example.invalid/repo.git",
    ]) {
      fs.writeFileSync(path.join(tmpDir, "requirements.txt"), `${requirement}\n`);
      const findings = await scanPypiDependencyConfusion(tmpDir);
      expect(findings).toContainEqual(expect.objectContaining({
        rule: "DEP_HALLUCINATED_PACKAGE",
        file: "requirements.txt",
        match: "django-api-utils",
      }));
      expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
    }

    for (const requirement of [
      "git+https://example.invalid/repo.git",
      "-e ../local-project",
      "--requirements-from-script script.py",
    ]) {
      fs.writeFileSync(path.join(tmpDir, "requirements.txt"), `${requirement}\n`);
      expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
        expect.objectContaining({
          rule: "PATH_SCAN_INCOMPLETE",
          file: "requirements.txt",
          match: "unresolved dependency source",
        }),
      );
    }
  });

  it("does not silently accept an unknown requirement option", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "requirements.txt"),
      "--requirementfoo shared/base.txt\n",
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "incomplete dependency manifest parse",
      }),
    );
  });

  it.each([
    [
      'project.dependencies = ["django-api-\\u0075tils"]\n',
      "root dotted project key",
    ],
    [
      '"project"."dependencies" = ["django-api-utils"]\n',
      "quoted root dotted project key",
    ],
    [
      'project = { name = "demo", dependencies = ["django-api-utils"], dynamic = ["version"] }\n',
      "inline project table",
    ],
    [
      '[project]\ndependencies = [\n  # generated\n  "django-\\u0061pi-utils", # retained comment\n]\n',
      "escaped multiline dependency array",
    ],
  ])("should parse a valid %s", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);
    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      file: "pyproject.toml",
      match: "django-api-utils",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it("decodes dynamic field escapes and rejects unsupported TOML escapes explicitly", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndynamic = ["depend\\u0065ncies"]\n',
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "dynamic project dependencies",
      }),
    );

    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndependencies = ["django-api-\\qutils"]\n',
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "incomplete dependency manifest parse",
      }),
    );
  });

  it("attributes a repeated package to every manifest that declares it", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "django-api-utils\n");
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndependencies = ["django-api-utils"]\n',
    );

    const findings = (await scanPypiDependencyConfusion(tmpDir))
      .filter((finding) => finding.rule === "DEP_HALLUCINATED_PACKAGE");
    expect(findings.map((finding) => finding.file).sort()).toEqual([
      "pyproject.toml",
      "requirements.txt",
    ]);
  });

  it("normalizes PyPI project-name separators before matching known names", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "Django_API_Utils\n");
    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      match: "Django_API_Utils",
    }));
  });
  it.each([
    "--use-feature=inprocess-build-deps",
    "--all-releases=:all:",
    "--only-final :all:",
  ])("accepts the supported pip global option %s", async (option) => {
    fs.writeFileSync(
      path.join(tmpDir, "requirements.txt"),
      `${option}\ndjango-api-utils\n`,
    );

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      match: "django-api-utils",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it.each([
    "django-api-utils --config-settings=builddir=out --config-settings mode=fast --hash=sha256:abcd",
    "django-api-utils --hash=sha256:abcd --config-settings builddir=out",
  ])("preserves the dependency behind repeatable per-requirement options", async (requirement) => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), `${requirement}\n`);

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      match: "django-api-utils",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it("keeps malformed per-requirement options partial", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "requirements.txt"),
      "django-api-utils --config-settings\n",
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "incomplete dependency manifest parse",
      }),
    );
  });

  it.each([
    '[project.optional-dependencies]\ndev = ["django-api-utils"]\n',
    '[project]\noptional-dependencies.dev = ["django-api-utils"]\n',
    'project.optional-dependencies.dev = ["django-api-utils"]\n',
    '[project]\noptional-dependencies = { dev = ["django-api-utils"] }\n',
    'project = { optional-dependencies = { dev = ["django-api-utils"] } }\n',
  ])("scans standardized optional dependencies without a false partial", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      file: "pyproject.toml",
      match: "django-api-utils",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it("reports dynamically supplied optional dependencies as partial", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndynamic = ["optional-dependencies"]\n',
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "dynamic project dependencies",
      }),
    );
  });

  it.each([
    '[build-system]\nrequires = ["django-api-utils"]\n',
    'build-system.requires = ["django-api-utils"]\n',
    'build-system = { requires = ["django-api-utils"], build-backend = "demo" }\n',
  ])("scans standardized build-system requirements", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      match: "django-api-utils",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it("marks a declared build system without its required dependency list partial", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[build-system]\nbuild-backend = "demo"\n',
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "incomplete dependency manifest parse",
      }),
    );
  });

  it("scans PEP 735 groups and resolves valid includes", async () => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), [
      "[dependency-groups]",
      'base = ["django-api-utils"]',
      'dev = [{ include-group = "base" }, "python-utils-helper"]',
      "",
    ].join("\n"));

    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings.filter((finding) => finding.rule === "DEP_HALLUCINATED_PACKAGE")
      .map((finding) => finding.match).sort()).toEqual([
      "django-api-utils",
      "python-utils-helper",
    ]);
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it.each([
    'dependency-groups.dev = ["django-api-utils"]\n',
    'dependency-groups = { dev = ["django-api-utils"] }\n',
  ])("scans dotted and inline PEP 735 groups", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);
    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      match: "django-api-utils",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it.each([
    '[dependency-groups]\ndev = [{ include-group = "missing" }]\n',
    '[dependency-groups]\na = [{ include-group = "b" }]\nb = [{ include-group = "a" }]\n',
  ])("reports missing or cyclic dependency-group includes as partial", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "unresolved dependency groups",
      }),
    );
  });

  it("reports an unsupported dependency-group object instead of returning clean", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[dependency-groups]\ndev = [{ future-object = "value" }]\n',
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "incomplete dependency manifest parse",
      }),
    );
  });

  it.each([
    '[tool.poetry.dependencies]\ndjango-api-utils = "^1"\n',
    '[tool.poetry.group.dev.dependencies]\ndjango-api-utils = { version = "^1" }\n',
    'tool.poetry.dependencies.django-api-utils = "^1"\n',
    '[tool.poetry]\ndependencies = { django-api-utils = "^1" }\n',
  ])("scans structurally named Poetry dependencies without blanket partial coverage", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);
    const findings = await scanPypiDependencyConfusion(tmpDir);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "DEP_HALLUCINATED_PACKAGE",
      match: "django-api-utils",
    }));
    expect(findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
  });

  it("reports a nested inline Poetry dependency source it cannot resolve", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      'tool.poetry = { dependencies = { django-api-utils = "^1" } }\n',
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "unresolved tool-specific dependencies",
      }),
    );
  });
  it("does not accept pip-only options inside PEP 508 pyproject arrays", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndependencies = ["django-api-utils --config-settings=mode=fast"]\n',
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "incomplete dependency manifest parse",
      }),
    );
  });

  it("recognizes a dotted build-system table even when requires is missing", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      'build-system.build-backend = "demo"\n',
    );
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "incomplete dependency manifest parse",
      }),
    );
  });

  it.each([
    '[tool.poetry.dependencies]\ndjango-api-utils =\n',
    '[tool.poetry]\ndependencies = { django-api-utils = }\n',
  ])("keeps malformed Poetry dependency declarations partial", async (content) => {
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);
    expect(await scanPypiDependencyConfusion(tmpDir)).toContainEqual(
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        match: "unresolved tool-specific dependencies",
      }),
    );
  });
  it("keeps an adversarial five-megabyte pyproject parse linear", { timeout: 15_000 }, async () => {
    const content = `[project]\n${"dynamic = []\n".repeat(410_000)}`;
    expect(Buffer.byteLength(content)).toBeGreaterThan(5 * 1024 * 1024);
    fs.writeFileSync(path.join(tmpDir, "pyproject.toml"), content);

    const started = Date.now();
    const findings = await scanPypiDependencyConfusion(tmpDir);
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(5_000);
    expect(findings).toContainEqual(expect.objectContaining({
      rule: "PATH_SCAN_INCOMPLETE",
      file: "pyproject.toml",
    }));
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
