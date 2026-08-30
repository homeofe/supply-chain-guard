/**
 * CLI integration tests.
 * Runs the compiled dist/cli.js via child_process.spawnSync.
 * Requires `npm run build` to have been run first.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../..");
const CLI = path.join(ROOT, "dist", "cli.js");
const FIXTURES_SRC = path.join(__dirname, "fixtures");

// Scan temp COPIES of the fixtures, never the source dirs. The scanner writes a
// .scg-history/ folder into whatever directory it scans, which otherwise dirtied
// the version-controlled fixtures on every `npm test` run.
let workdir: string;
let CLEAN_FIXTURE: string;
let MALICIOUS_FIXTURE: string;
let HIGH_FIXTURE: string;
let PARTIAL_FIXTURE: string;
let PARTIAL_CRITICAL_FIXTURE: string;
let INTERNAL_PARTIAL_FIXTURE: string;

beforeAll(() => {
  workdir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cli-test-"));
  CLEAN_FIXTURE = path.join(workdir, "clean-npm-pkg");
  MALICIOUS_FIXTURE = path.join(workdir, "malicious-npm-pkg");
  HIGH_FIXTURE = path.join(workdir, "high-only-npm-pkg");
  PARTIAL_FIXTURE = path.join(workdir, "partial-npm-pkg");
  PARTIAL_CRITICAL_FIXTURE = path.join(workdir, "partial-critical-npm-pkg");
  INTERNAL_PARTIAL_FIXTURE = path.join(workdir, "internal-partial-npm-pkg");
  fs.cpSync(path.join(FIXTURES_SRC, "clean-npm-pkg"), CLEAN_FIXTURE, { recursive: true });
  fs.cpSync(path.join(FIXTURES_SRC, "malicious-npm-pkg"), MALICIOUS_FIXTURE, { recursive: true });
  fs.cpSync(CLEAN_FIXTURE, HIGH_FIXTURE, { recursive: true });
  fs.writeFileSync(
    path.join(HIGH_FIXTURE, "unicode.js"),
    `const marker = "normal\u200B\u200B\u200B\u200Btext";`,
    "utf-8",
  );
  fs.cpSync(CLEAN_FIXTURE, PARTIAL_FIXTURE, { recursive: true });
  fs.cpSync(CLEAN_FIXTURE, INTERNAL_PARTIAL_FIXTURE, { recursive: true });
  fs.cpSync(MALICIOUS_FIXTURE, PARTIAL_CRITICAL_FIXTURE, { recursive: true });
  for (const fixture of [PARTIAL_FIXTURE, PARTIAL_CRITICAL_FIXTURE]) {
    fs.writeFileSync(path.join(fixture, "oversized.js"), Buffer.alloc(5 * 1024 * 1024 + 1));
  }
  fs.writeFileSync(
    path.join(INTERNAL_PARTIAL_FIXTURE, ".supply-chain-guard.yml"),
    "internalDisclosure:\n  hashedTerms:\n    - " + "0".repeat(64) + "\n",
    "utf-8",
  );
  const denylistFiller = Array.from(
    { length: 410 },
    (_, index) => "token" + index,
  ).join(" ");
  fs.writeFileSync(
    path.join(INTERNAL_PARTIAL_FIXTURE, "internal.ts"),
    denylistFiller + " unseen.internal.example",
    "utf-8",
  );
});

afterAll(() => {
  fs.rmSync(workdir, { recursive: true, force: true });
});

/** Run the CLI with the given args. Returns stdout, stderr, and exit status. */
function cli(args: string[]): { stdout: string; stderr: string; status: number } {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf-8",
    timeout: 30000,
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status ?? 1,
  };
}

// ─── --version ────────────────────────────────────────────────────────────────

describe("CLI --version", () => {
  it("should exit 0", () => {
    const { status } = cli(["--version"]);
    expect(status).toBe(0);
  });

  it("should output a semver string", () => {
    const { stdout } = cli(["--version"]);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

// ─── --help ───────────────────────────────────────────────────────────────────

describe("CLI --help", () => {
  it("should exit 0", () => {
    const { status } = cli(["--help"]);
    expect(status).toBe(0);
  });

  it("should mention supply-chain-guard in usage", () => {
    const { stdout } = cli(["--help"]);
    expect(stdout).toContain("supply-chain-guard");
  });

  it("should list the scan command", () => {
    const { stdout } = cli(["--help"]);
    expect(stdout).toContain("scan");
  });

  it("should list the watchlist command", () => {
    const { stdout } = cli(["--help"]);
    expect(stdout).toContain("watchlist");
  });

  it("documents the opt-in complete text finding list", () => {
    const { stdout, status } = cli(["scan", "--help"]);
    expect(status).toBe(0);
    expect(stdout).toContain("--all-findings");
  });
});

// ─── scan – clean fixture ─────────────────────────────────────────────────────

describe("CLI scan – clean fixture", () => {
  it("should exit 0 for a clean package", () => {
    const { status } = cli(["scan", CLEAN_FIXTURE]);
    expect(status).toBe(0);
  });

  it("should produce JSON output with no security findings", () => {
    const { stdout, status } = cli(["scan", CLEAN_FIXTURE, "--format", "json"]);
    expect(status).toBe(0);
    const parsed = JSON.parse(stdout) as { findings: Array<{ rule: string; severity: string }>; score: number };
    // v4.9: SLSA posture findings (info) may appear for directories without build provenance
    const securityFindings = parsed.findings.filter((f) => !f.rule.startsWith("SLSA_"));
    expect(securityFindings).toHaveLength(0);
    expect(parsed.summary?.critical ?? 0).toBe(0);
    expect(parsed.summary?.high ?? 0).toBe(0);
  });

  it("should produce valid SARIF output with no security results", () => {
    const { stdout, status } = cli(["scan", CLEAN_FIXTURE, "--format", "sarif"]);
    expect(status).toBe(0);
    const parsed = JSON.parse(stdout) as { version: string; runs: Array<{ results: Array<{ ruleId: string }> }> };
    expect(parsed.version).toBe("2.1.0");
    // v4.9: SLSA posture findings may appear; filter them out
    const securityResults = (parsed.runs[0].results ?? []).filter(
      (r) => !r.ruleId.startsWith("SLSA_"),
    );
    expect(securityResults).toHaveLength(0);
  });

  it("should produce SBOM output with CycloneDX format", () => {
    const { stdout, status } = cli(["scan", CLEAN_FIXTURE, "--format", "sbom"]);
    expect(status).toBe(0);
    const parsed = JSON.parse(stdout) as { bomFormat: string; specVersion: string };
    expect(parsed.bomFormat).toBe("CycloneDX");
    expect(parsed.specVersion).toBe("1.6");
  });
});

// ─── scan – malicious fixture ─────────────────────────────────────────────────

describe("CLI scan – malicious fixture", () => {
  it("should exit non-zero for a malicious package", () => {
    const { status } = cli(["scan", MALICIOUS_FIXTURE]);
    expect(status).toBeGreaterThan(0);
  });

  it("should exit 2 when critical findings are found", () => {
    const { status } = cli(["scan", MALICIOUS_FIXTURE]);
    expect(status).toBe(2);
  });

  it("should include findings in JSON output", () => {
    const { stdout } = cli(["scan", MALICIOUS_FIXTURE, "--format", "json"]);
    const parsed = JSON.parse(stdout) as { findings: Array<{ severity: string }> };
    expect(parsed.findings.length).toBeGreaterThan(0);
    expect(parsed.findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("should detect GlassWorm marker in JSON output", () => {
    const { stdout } = cli(["scan", MALICIOUS_FIXTURE, "--format", "json"]);
    const parsed = JSON.parse(stdout) as { findings: Array<{ rule: string }> };
    expect(parsed.findings.some((f) => f.rule === "GLASSWORM_MARKER")).toBe(true);
  });

  it("should produce valid SARIF with results for malicious package", () => {
    const { stdout } = cli(["scan", MALICIOUS_FIXTURE, "--format", "sarif"]);
    const parsed = JSON.parse(stdout) as { runs: Array<{ results: unknown[] }> };
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
  });
});

// ─── --output flag ──────────────────────────────────────────────────────────

describe("CLI scan --output", () => {
  it("writes the formatted report to a file instead of stdout", () => {
    const outFile = path.join(workdir, "clean-report.json");
    const { stdout, stderr, status } = cli([
      "scan", CLEAN_FIXTURE, "--format", "json", "--output", outFile,
    ]);
    expect(status).toBe(0);
    // The report went to the file, so stdout stays empty...
    expect(stdout.trim()).toBe("");
    // ...and the status line goes to stderr.
    expect(stderr).toContain(outFile);
    expect(fs.existsSync(outFile)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(outFile, "utf-8")) as { findings: unknown[] };
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  it("writes canonical JSON from the same scan while stdout uses another format", () => {
    const jsonFile = path.join(workdir, "canonical-report.json");
    const { stdout, status } = cli([
      "scan",
      CLEAN_FIXTURE,
      "--format",
      "markdown",
      "--json-output",
      jsonFile,
      "--no-history",
    ]);

    expect(status).toBe(0);
    expect(stdout).toContain("supply-chain-guard Scan Report");
    const canonical = JSON.parse(fs.readFileSync(jsonFile, "utf-8")) as {
      findings: unknown[];
      summary: { totalFiles: number; filesScanned: number };
    };
    expect(Array.isArray(canonical.findings)).toBe(true);
    expect(canonical.summary.filesScanned).toBeLessThanOrEqual(
      canonical.summary.totalFiles,
    );
  });

  it("drains a large failing JSON report before applying the exit status", () => {
    const fixture = path.join(workdir, "large-failing-output");
    fs.mkdirSync(fixture);
    fs.writeFileSync(
      path.join(fixture, "package.json"),
      JSON.stringify({ name: "large-failing-output", version: "1.0.0" }),
      "utf-8",
    );
    fs.writeFileSync(
      path.join(fixture, "payload.js"),
      Array.from(
        { length: 4_000 },
        (_, index) => `const payload${index} = eval(atob("YWxlcnQoMSk="));`,
      ).join("\n"),
      "utf-8",
    );
    const sidecar = path.join(workdir, "large-failing-sidecar.json");

    const result = spawnSync(process.execPath, [
      CLI,
      "scan",
      fixture,
      "--format",
      "json",
      "--json-output",
      sidecar,
      "--min-severity",
      "high",
      "--fail-on",
      "high",
      "--no-history",
    ], {
      encoding: "utf-8",
      timeout: 30_000,
      maxBuffer: 64 * 1024 * 1024,
    });

    expect(result.status).toBe(1);
    expect(Buffer.byteLength(result.stdout ?? "", "utf-8")).toBeGreaterThan(64 * 1024);
    expect(JSON.parse(result.stdout ?? "")).toEqual(
      JSON.parse(fs.readFileSync(sidecar, "utf-8")),
    );
  });
  it("rejects output-file aliases before any writer can overwrite another", () => {
    for (const flag of ["--output", "--sbom-output", "--save-baseline"]) {
      const name = `collision-${flag.slice(2)}.json`;
      const canonical = path.join(workdir, name);
      const alias = path.join(workdir, "unused", "..", name);
      const { stderr, status } = cli([
        "scan",
        CLEAN_FIXTURE,
        "--json-output",
        canonical,
        flag,
        alias,
        "--no-history",
      ]);

      expect(status, flag).toBe(1);
      const collisionMessage = flag === "--output"
        ? "--json-output must not target the same file as --output"
        : `${flag} must not target the same file as --json-output`;
      expect(stderr, flag).toContain(collisionMessage);
      expect(fs.existsSync(canonical), flag).toBe(false);
    }

    const report = path.join(workdir, "report-and-sbom.json");
    const collision = cli([
      "scan",
      CLEAN_FIXTURE,
      "--output",
      report,
      "--sbom-output",
      path.join(workdir, ".", "report-and-sbom.json"),
      "--no-history",
    ]);
    expect(collision.status).toBe(1);
    expect(collision.stderr).toContain(
      "--sbom-output must not target the same file as --output",
    );
  });

  it("rejects a dangling final-symlink alias before either writer runs", (context) => {
    const target = path.join(workdir, "dangling-target.json");
    const alias = path.join(workdir, "dangling-alias.json");
    try {
      fs.symlinkSync(target, alias, "file");
    } catch {
      context.skip();
      return;
    }

    const { stderr, status } = cli([
      "scan",
      CLEAN_FIXTURE,
      "--format",
      "text",
      "--output",
      target,
      "--json-output",
      alias,
      "--no-history",
    ]);

    expect(status).toBe(1);
    expect(stderr).toContain(
      "--json-output must not target the same file as --output",
    );
    expect(fs.existsSync(target)).toBe(false);
  });
  it("writes a JUnit XML report to a file", () => {
    const outFile = path.join(workdir, "report.xml");
    cli(["scan", MALICIOUS_FIXTURE, "--format", "junit", "--output", outFile]);
    expect(fs.existsSync(outFile)).toBe(true);
    const xml = fs.readFileSync(outFile, "utf-8");
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    expect(xml).toContain("<testsuite");
    expect(xml).toContain("</testsuite>");
  });
});

// ─── --fail-on flag ───────────────────────────────────────────────────────────

describe("CLI --fail-on flag", () => {
  it("should exit 1 with --fail-on critical when critical findings exist", () => {
    const { status } = cli(["scan", MALICIOUS_FIXTURE, "--fail-on", "critical"]);
    expect(status).toBe(1);
  });

  it("should exit 1 with --fail-on high when critical findings exist (>= threshold)", () => {
    const { status } = cli(["scan", MALICIOUS_FIXTURE, "--fail-on", "high"]);
    expect(status).toBe(1);
  });

  it("should exit 0 with --fail-on critical when no critical findings in clean package", () => {
    const { status } = cli(["scan", CLEAN_FIXTURE, "--fail-on", "critical"]);
    expect(status).toBe(0);
  });

  it("should exit 0 with --fail-on high when no high+ findings in clean package", () => {
    const { status } = cli(["scan", CLEAN_FIXTURE, "--fail-on", "high"]);
    expect(status).toBe(0);
  });

  it("rejects a minimum severity that would hide the explicit fail threshold", () => {
    const { stdout, stderr, status } = cli([
      "scan",
      CLEAN_FIXTURE,
      "--min-severity",
      "critical",
      "--fail-on",
      "high",
    ]);
    expect(status).toBe(1);
    expect(stdout.trim()).toBe("");
    expect(stderr).toContain(
      "--min-severity critical would hide findings required by --fail-on high",
    );
  });

  it("rejects a minimum severity that would hide the implicit high gate", () => {
    const { stdout, stderr, status } = cli([
      "scan",
      HIGH_FIXTURE,
      "--min-severity",
      "critical",
    ]);
    expect(status).toBe(1);
    expect(stdout.trim()).toBe("");
    expect(stderr).toContain(
      "--min-severity critical would hide findings required by the default high gate",
    );
  });

  it("accepts compatible report and fail thresholds", () => {
    const { status } = cli([
      "scan",
      CLEAN_FIXTURE,
      "--min-severity",
      "low",
      "--fail-on",
      "critical",
    ]);
    expect(status).toBe(0);
  });

  it("rejects unknown severity option values", () => {
    const { stderr, status } = cli([
      "scan",
      CLEAN_FIXTURE,
      "--min-severity",
      "urgent",
    ]);
    expect(status).toBe(1);
    expect(stderr).toContain("--min-severity must be one of");
  });

describe("CLI partial-scan verdict", () => {
  it("exits 1 and preserves partialScan when severity filtering hides the coverage finding", () => {
    const { stdout, status } = cli([
      "scan",
      PARTIAL_FIXTURE,
      "--format",
      "json",
      "--min-severity",
      "critical",
      "--fail-on",
      "critical",
    ]);
    expect(status).toBe(1);
    const parsed = JSON.parse(stdout) as {
      partialScan?: boolean;
      findings: unknown[];
      recommendations: string[];
    };
    expect(parsed.partialScan).toBe(true);
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.recommendations.join(" ")).toMatch(/scan incomplete/i);
    expect(parsed.recommendations.join(" ")).not.toMatch(/appears clean/i);
  });

  it("treats internal-disclosure truncation as partial after filtering", () => {
    const { stdout, status } = cli([
      "scan",
      INTERNAL_PARTIAL_FIXTURE,
      "--format",
      "json",
      "--min-severity",
      "critical",
      "--fail-on",
      "critical",
    ]);

    expect(status).toBe(1);
    const parsed = JSON.parse(stdout) as {
      partialScan?: boolean;
      findings: unknown[];
      recommendations: string[];
    };
    expect(parsed.partialScan).toBe(true);
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.recommendations.join(" ")).toMatch(/scan incomplete/i);
  });

  it("exits 1 for partial coverage even when --fail-on would otherwise pass", () => {
    const { status } = cli([
      "scan",
      PARTIAL_FIXTURE,
      "--min-severity",
      "critical",
      "--fail-on",
      "critical",
    ]);
    expect(status).toBe(1);
  });

  it("does not let partial coverage weaken the default critical exit code", () => {
    const { status } = cli(["scan", PARTIAL_CRITICAL_FIXTURE]);
    expect(status).toBe(2);
  });

  it("writes the partial marker through --sbom-output", () => {
    const outFile = path.join(workdir, "partial.cdx.json");
    const { status } = cli([
      "scan",
      PARTIAL_FIXTURE,
      "--format",
      "json",
      "--min-severity",
      "critical",
      "--fail-on",
      "critical",
      "--sbom-output",
      outFile,
    ]);
    expect(status).toBe(1);
    const parsed = JSON.parse(fs.readFileSync(outFile, "utf-8")) as {
      metadata: { properties?: Array<{ name: string; value: string }> };
    };
    expect(parsed.metadata.properties).toContainEqual({
      name: "supply-chain-guard:scan-status",
      value: "partial",
    });
  });
});
});

// ─── watchlist ────────────────────────────────────────────────────────────────

describe("CLI watchlist list", () => {
  it("should exit 0", () => {
    const { status } = cli(["watchlist", "list"]);
    expect(status).toBe(0);
  });

  it("should produce output without error", () => {
    const { stderr } = cli(["watchlist", "list"]);
    expect(stderr).toBe("");
  });
});

// ─── unknown command ──────────────────────────────────────────────────────────

describe("CLI unknown command", () => {
  it("should exit non-zero for an unknown command", () => {
    const { status } = cli(["nonexistent-command-xyz"]);
    expect(status).not.toBe(0);
  });
});

describe("CLI org partial-scan wiring", () => {
  it("tracks incomplete and failed repository scans without weakening critical exits", () => {
    const source = fs.readFileSync(path.join(ROOT, "src", "cli.ts"), "utf-8");
    const orgStart = source.indexOf('.command("org")');
    const monitorStart = source.indexOf('.command("monitor")', orgStart);
    const orgCommand = source.slice(orgStart, monitorStart);

    expect(orgStart).toBeGreaterThanOrEqual(0);
    expect(monitorStart).toBeGreaterThan(orgStart);
    expect(orgCommand).toContain("partialRepos");
    expect(orgCommand).toContain("failedRepos");
    expect(orgCommand).toContain("partialScan: true");
    expect(orgCommand).toContain("getReportExitCode(report)");
    expect(orgCommand).toContain("getFindingsExitCode(orgFindings)");
    expect(orgCommand).toContain(
      "finishCliCommand(orgExitCode !== 0 ? orgExitCode : partialScan ? 1 : 0)",
    );
    expect(orgCommand).not.toContain("process.exit(");
  });

  it("lets blocked install-guard output drain before applying its exit code", () => {
    const source = fs.readFileSync(path.join(ROOT, "src", "cli.ts"), "utf-8");
    const guardStart = source.indexOf('.command("guard")');
    const hashStart = source.indexOf('.command("internal-hash")', guardStart);
    const guardCommand = source.slice(guardStart, hashStart);

    expect(guardStart).toBeGreaterThanOrEqual(0);
    expect(hashStart).toBeGreaterThan(guardStart);
    expect(guardCommand).toContain("finishCliCommand(code)");
    expect(guardCommand).not.toContain("process.exit(");
  });
});
