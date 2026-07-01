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

beforeAll(() => {
  workdir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cli-test-"));
  CLEAN_FIXTURE = path.join(workdir, "clean-npm-pkg");
  MALICIOUS_FIXTURE = path.join(workdir, "malicious-npm-pkg");
  fs.cpSync(path.join(FIXTURES_SRC, "clean-npm-pkg"), CLEAN_FIXTURE, { recursive: true });
  fs.cpSync(path.join(FIXTURES_SRC, "malicious-npm-pkg"), MALICIOUS_FIXTURE, { recursive: true });
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
