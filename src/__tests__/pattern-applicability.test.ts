import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Finding, PatternEntry } from "../types.js";
import {
  isPatternApplicableToFile,
  TEST_FILE_PATTERN,
} from "../pattern-applicability.js";
import { scanExtractedNpmFiles } from "../npm-scanner.js";
import { scanExtractedFiles as scanExtractedPypiFiles } from "../pypi-scanner.js";
import { scanReadmeLures } from "../github-trust-scanner.js";
import { MAX_FILE_SIZE } from "../patterns.js";
import { scan } from "../scanner.js";
import { getReportExitCode } from "../reporter.js";
import {
  isPartialScanFinding,
  matchPatternInFile,
  recordUnreadablePath,
} from "../pattern-scanner.js";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("central pattern applicability", () => {
  it("enforces every PatternEntry file-level guard together", () => {
    const pattern: PatternEntry = {
      name: "guarded",
      pattern: "payload",
      description: "test",
      severity: "high",
      rule: "TEST_GUARDED",
      onlyExtensions: [".js"],
      onlyFilePattern: /(?:^|\/)src\//,
      notFilePattern: /vendor/,
      notTestFile: true,
      requiresInFile: /fetch\s*\(/,
    };

    expect(
      isPatternApplicableToFile(pattern, "payload\nfetch(url);", "src/main.JS"),
    ).toBe(true);
    expect(isPatternApplicableToFile(pattern, "payload\nfetch(url);", "src/main.py")).toBe(false);
    expect(isPatternApplicableToFile(pattern, "payload\nfetch(url);", "lib/main.js")).toBe(false);
    expect(isPatternApplicableToFile(pattern, "payload\nfetch(url);", "src/vendor/main.js")).toBe(false);
    expect(isPatternApplicableToFile(pattern, "payload\nfetch(url);", "src/main.test.js")).toBe(false);
    expect(isPatternApplicableToFile(pattern, "payload", "src/main.js")).toBe(false);
  });

  it("normalizes Windows paths and recognizes test/fixture locations", () => {
    expect(TEST_FILE_PATTERN.test("test/fixtures/sample.js")).toBe(true);
    expect(TEST_FILE_PATTERN.test("spec/helpers/sample.rb")).toBe(true);
    expect(TEST_FILE_PATTERN.test("test-fixtures/sample.js")).toBe(true);
    expect(
      isPatternApplicableToFile(
        { notTestFile: true },
        "payload",
        "test\\fixtures\\sample.js",
      ),
    ).toBe(false);
  });

  it("resets global guard regexes so repeated files get stable verdicts", () => {
    const pattern = { requiresInFile: /fetch\s*\(/g };
    expect(isPatternApplicableToFile(pattern, "fetch(url);", "src/a.js")).toBe(true);
    expect(isPatternApplicableToFile(pattern, "fetch(url);", "src/b.js")).toBe(true);
  });
});

describe("coverage transparency", () => {
  const partialRules = [
    "FILE_TOO_LARGE_SKIPPED",
    "PATTERN_SCAN_INCOMPLETE",
    "PATH_SCAN_INCOMPLETE",
    "INTERNAL_DISCLOSURE_TRUNCATED",
    "PYPI_NO_SOURCE",
    "NPM_NO_ARTIFACT",
    "INTERNAL_DENYLIST_UNAVAILABLE",
    "INTERNAL_DENYLIST_INVALID_ENTRY",
    "INTERNAL_DENYLIST_REFUSED",
    "POLICY_INVALID_INTERNAL_TERM",
  ];

  it.each(partialRules)("%s marks coverage as partial", (rule) => {
    expect(isPartialScanFinding({ rule })).toBe(true);
  });

  it("deduplicates path coverage and never publishes an absolute path", () => {
    const findings: Finding[] = [];
    recordUnreadablePath(findings, "src/private.js");
    recordUnreadablePath(findings, "src\\private.js");
    recordUnreadablePath(findings, process.platform === "win32" ? "C:/Users/me/secret.js" : "/home/me/secret.js");

    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({
      rule: "PATH_SCAN_INCOMPLETE",
      severity: "info",
      file: "src/private.js",
    });
    expect(findings[1]!.file).toBe(".");
    expect(JSON.stringify(findings)).not.toContain("Users/me");
    expect(JSON.stringify(findings)).not.toContain("home/me");
  });

  it.each([
    "PYPI_NO_REPO",
    "SLSA_NO_PROVENANCE",
    "POLICY_UNKNOWN_KEY",
  ])("%s remains a posture finding, not a coverage failure", (rule) => {
    expect(isPartialScanFinding({ rule })).toBe(false);
  });

  it("keeps a policy validation coverage failure partial after filtering", async () => {
    const dir = makeTempDir("scg-policy-coverage-");
    fs.writeFileSync(
      path.join(dir, ".supply-chain-guard.yml"),
      "internalDisclosure:\n  hashedTerms:\n    - not-a-digest\n",
      "utf-8",
    );

    const report = await scan({
      target: dir,
      format: "json",
      minSeverity: "critical",
      noHistory: true,
    });

    expect(report.findings).toHaveLength(0);
    expect(report.partialScan).toBe(true);
    expect(report.recommendations.join(" ")).toMatch(/scan incomplete/i);
    expect(getReportExitCode(report)).toBe(1);
  });

  it("marks a configured depth-limit truncation partial", async () => {
    const dir = makeTempDir("scg-depth-coverage-");
    const nested = path.join(dir, "nested", "deeper");
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(nested, "payload.js"), "const safe = true;");

    const report = await scan({
      target: dir,
      format: "json",
      maxDepth: 0,
      noHistory: true,
    });

    expect(report.partialScan).toBe(true);
    expect(report.findings).toContainEqual(
      expect.objectContaining({ rule: "PATH_SCAN_INCOMPLETE", file: "nested" }),
    );
  });

  it("does not mark a depth-limited directory partial when policy.ignore removes it from scope", async () => {
    const dir = makeTempDir("scg-ignored-depth-");
    fs.writeFileSync(
      path.join(dir, ".supply-chain-guard.yml"),
      "ignore:\n  - nested/**\n",
    );
    fs.mkdirSync(path.join(dir, "nested", "deeper"), { recursive: true });
    fs.writeFileSync(path.join(dir, "nested", "deeper", "payload.js"), "safe");

    const report = await scan({
      target: dir,
      format: "json",
      maxDepth: 0,
      noHistory: true,
    });

    expect(report.findings.some((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")).toBe(false);
    expect(report.partialScan).not.toBe(true);
  });

  it("scans published dist, build, and .next artifacts by default", async () => {
    const dir = makeTempDir("scg-published-artifacts-");
    for (const outputDir of ["dist", "build", ".next"]) {
      fs.mkdirSync(path.join(dir, outputDir), { recursive: true });
      fs.writeFileSync(
        path.join(dir, outputDir, "payload.js"),
        'eval(atob("YWxlcnQoMSk="));',
      );
    }

    const report = await scan({ target: dir, format: "json", noHistory: true });
    const artifactHits = report.findings.filter(
      (finding) => finding.rule === "EVAL_ATOB",
    );

    expect(artifactHits.map((finding) => finding.file).sort()).toEqual([
      ".next/payload.js",
      "build/payload.js",
      "dist/payload.js",
    ]);
    expect(report.summary.totalFiles).toBe(3);
    expect(report.summary.filesScanned).toBe(3);
  });

  it("counts extensionless Docker/config targets once without duplicate findings", async () => {
    const dir = makeTempDir("scg-inline-target-count-");
    fs.writeFileSync(
      path.join(dir, "Dockerfile"),
      "RUN curl https://example.invalid/install.sh | bash\n",
    );
    fs.writeFileSync(
      path.join(dir, ".npmrc"),
      "registry=http://packages.example.invalid\n",
    );

    const report = await scan({ target: dir, format: "json", noHistory: true });

    expect(report.summary.totalFiles).toBe(2);
    expect(report.summary.filesScanned).toBe(2);
    expect(
      report.findings.filter((finding) => finding.rule === "DOCKER_CURL_PIPE"),
    ).toHaveLength(1);
    expect(
      report.findings.filter((finding) => finding.rule === "CONFIG_HTTP_REGISTRY"),
    ).toHaveLength(1);
  });
  it.skipIf(process.platform === "win32")(
    "surfaces denied reads in main, npm, and PyPI walkers",
    async (context) => {
      const dir = makeTempDir("scg-denied-read-");
      const file = path.join(dir, "denied.js");
      fs.writeFileSync(file, "const safe = true;");
      fs.chmodSync(file, 0o000);

      let denied = false;
      try { fs.readFileSync(file); } catch { denied = true; }
      if (!denied) {
        fs.chmodSync(file, 0o600);
        context.skip();
        return;
      }

      try {
        const main = await scan({ target: dir, format: "json", noHistory: true });
        expect(main.partialScan).toBe(true);
        expect(main.summary.filesScanned).toBe(0);

        for (const walk of [scanExtractedNpmFiles, scanExtractedPypiFiles]) {
          const findings: Finding[] = [];
          const counts = walk(dir, findings);
          expect(counts.filesScanned).toBe(0);
          expect(findings.filter((f) => f.rule === "PATH_SCAN_INCOMPLETE")).toHaveLength(1);
        }
      } finally {
        fs.chmodSync(file, 0o600);
      }
    },
  );

  it.skipIf(process.platform === "win32")(
    "surfaces denied directory enumeration",
    async (context) => {
      const dir = makeTempDir("scg-denied-dir-");
      const locked = path.join(dir, "locked");
      fs.mkdirSync(locked);
      fs.writeFileSync(path.join(locked, "payload.js"), "safe");
      fs.chmodSync(locked, 0o000);

      let denied = false;
      try { fs.readdirSync(locked); } catch { denied = true; }
      if (!denied) {
        fs.chmodSync(locked, 0o700);
        context.skip();
        return;
      }

      try {
        const report = await scan({ target: dir, format: "json", noHistory: true });
        expect(report.partialScan).toBe(true);
        expect(report.findings).toContainEqual(
          expect.objectContaining({ rule: "PATH_SCAN_INCOMPLETE", file: "locked" }),
        );
      } finally {
        fs.chmodSync(locked, 0o700);
      }
    },
  );

  it("surfaces a structural matcher failure instead of returning a clean result", () => {
    const findings: Finding[] = [];
    const result = matchPatternInFile(
      {
        pattern: "payload",
        rule: "TEST_MATCHER_FAILURE",
        spansLines: 2,
        correlatedMatcher: () => {
          throw new Error("boom");
        },
      },
      "payload",
      "src/payload.js",
      findings,
    );

    expect(result?.coverage.complete).toBe(false);
    expect(result?.coverage.limitations).toEqual(["matcher-error"]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.rule).toBe("PATTERN_SCAN_INCOMPLETE");
    expect(findings[0]!.file).toBe("src/payload.js");
  });
  it("marks a real directory report partial when an oversized file is skipped", async () => {
    const dir = makeTempDir("scg-pattern-coverage-");
    const srcDir = path.join(dir, "src");
    fs.mkdirSync(srcDir, { recursive: true });
    fs.writeFileSync(
      path.join(srcDir, "long.js"),
      "x".repeat(MAX_FILE_SIZE + 1),
    );

    const report = await scan({
      target: dir,
      format: "json",
      noHistory: true,
    });

    expect(report.partialScan).toBe(true);
    const coverage = report.findings.filter(
      (finding) => finding.rule === "FILE_TOO_LARGE_SKIPPED",
    );
    expect(coverage).toHaveLength(1);
    expect(coverage[0]!.file?.replace(/\\/g, "/")).toBe("src/long.js");
    expect(coverage[0]!.severity).toBe("info");
    expect(report.recommendations.join(" ")).toMatch(/scan incomplete/i);
    expect(report.recommendations.join(" ")).not.toMatch(/appears clean/i);
  });
});
describe("entry-point guard parity", () => {
  it("npm tarball scanning skips test fixtures but still scans production files", () => {
    const dir = makeTempDir("scg-applicability-npm-");
    const fixtureDir = path.join(dir, "test", "fixtures");
    fs.mkdirSync(fixtureDir, { recursive: true });
    fs.writeFileSync(path.join(fixtureDir, "payload.js"), 'eval(atob("fixture"));');
    fs.writeFileSync(path.join(dir, "payload.js"), 'eval(atob("production"));');

    const findings: Finding[] = [];
    scanExtractedNpmFiles(dir, findings);

    const evalHits = findings.filter((finding) => finding.rule === "EVAL_ATOB");
    expect(evalHits.map((finding) => finding.file?.replace(/\\/g, "/"))).toEqual([
      "payload.js",
    ]);
  });

  it("PyPI package scanning skips test fixtures but scans production modules", () => {
    const dir = makeTempDir("scg-applicability-pypi-");
    const fixtureDir = path.join(dir, "tests");
    fs.mkdirSync(fixtureDir, { recursive: true });
    fs.writeFileSync(path.join(fixtureDir, "payload.py"), 'eval(atob("fixture"))');
    fs.writeFileSync(path.join(dir, "payload.py"), 'eval(atob("production"))');

    const findings: Finding[] = [];
    scanExtractedPypiFiles(dir, findings);

    const evalHits = findings.filter((finding) => finding.rule === "EVAL_ATOB");
    expect(evalHits.map((finding) => finding.file?.replace(/\\/g, "/"))).toEqual([
      "payload.py",
    ]);
  });

  it("README lure scanning honours notTestFile", () => {
    expect(scanReadmeLures("Unlimited cracked premium build", "test/fixtures/README.md")).toEqual([]);
    expect(
      scanReadmeLures("Unlimited cracked premium build", "README.md").some(
        (finding) => finding.rule === "README_LURE_CRACK",
      ),
    ).toBe(true);
  });
});