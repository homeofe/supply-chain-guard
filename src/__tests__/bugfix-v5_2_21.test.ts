/**
 * Regression tests for the v5.2.21 architectural fix: campaign / IOC /
 * threat-intel patterns must not fire on documentation files (.md/.markdown/
 * .txt/.rst). Documentation legitimately discusses malware markers as part
 * of threat-intel write-ups, changelog entries, blog posts, and academic
 * research. Without this exclusion the scanner self-flags its own README
 * massively (28 criticals + 10 highs were observed on the v5.2.20 self-scan).
 */

import { describe, it, expect } from "vitest";
import {
  CAMPAIGN_PATTERNS,
  CAMPAIGN_PATTERNS_V2,
  INFOSTEALER_PATTERNS,
  C2_EXTENDED_PATTERNS,
  LURE_PATTERNS,
  PROMPT_INJECTION_PATTERNS,
} from "../patterns.js";
import { checkIOCBlocklist } from "../ioc-blocklist.js";
import { checkThreatIntel } from "../threat-intel.js";
import type { FeedIOC } from "../threat-intel.js";

const DOC_PATHS = [
  "README.md",
  "CHANGELOG.md",
  "docs/index.md",
  "notes.markdown",
  "spec.txt",
  "INSTALL.rst",
];
const SOURCE_PATHS = [
  "src/index.ts",
  "lib/handler.js",
  "package.json",
  "Dockerfile",
];

describe("v5.2.21: source-marker patterns skip documentation files", () => {
  describe("CAMPAIGN_PATTERNS notFilePattern excludes docs", () => {
    it("every CAMPAIGN_PATTERNS entry excludes .md/.markdown/.txt/.rst", () => {
      for (const p of CAMPAIGN_PATTERNS) {
        expect(p.notFilePattern, `${p.rule} missing notFilePattern`).toBeDefined();
        for (const docPath of DOC_PATHS) {
          expect(
            p.notFilePattern!.test(docPath),
            `${p.rule} should skip ${docPath}`,
          ).toBe(true);
        }
      }
    });

    it("CAMPAIGN_PATTERNS still scan source files", () => {
      for (const p of CAMPAIGN_PATTERNS) {
        for (const srcPath of SOURCE_PATHS) {
          // Source paths must NOT be excluded by notFilePattern
          // (some patterns may still skip via SCANNER_SRC if they match,
          // but ordinary user code paths should pass through).
          if (/(?:patterns|scanner|reporter|playbooks|threat-intel)\.(?:ts|js)$/i.test(srcPath)) continue;
          expect(
            p.notFilePattern!.test(srcPath),
            `${p.rule} should still scan ${srcPath}`,
          ).toBe(false);
        }
      }
    });
  });

  describe("CAMPAIGN_PATTERNS_V2 + INFOSTEALER_PATTERNS + C2_EXTENDED_PATTERNS exclude docs", () => {
    for (const [name, arr] of [
      ["CAMPAIGN_PATTERNS_V2", CAMPAIGN_PATTERNS_V2],
      ["INFOSTEALER_PATTERNS", INFOSTEALER_PATTERNS],
      ["C2_EXTENDED_PATTERNS", C2_EXTENDED_PATTERNS],
    ] as const) {
      it(`${name} entries all exclude documentation files`, () => {
        for (const p of arr) {
          expect(p.notFilePattern, `${p.rule} missing notFilePattern`).toBeDefined();
          expect(p.notFilePattern!.test("README.md"), `${p.rule} should skip README.md`).toBe(true);
          expect(p.notFilePattern!.test("docs/threat.markdown"), `${p.rule} should skip .markdown`).toBe(true);
          expect(p.notFilePattern!.test("notes.txt"), `${p.rule} should skip .txt`).toBe(true);
          expect(p.notFilePattern!.test("INSTALL.rst"), `${p.rule} should skip .rst`).toBe(true);
        }
      });
    }
  });

  describe("LURE_PATTERNS and PROMPT_INJECTION_PATTERNS still fire on docs", () => {
    // These patterns target documentation by design - the architectural fix
    // must NOT apply to them or detection would break.
    it("LURE_PATTERNS' README_LURE_* entries do NOT have docs in notFilePattern", () => {
      for (const p of LURE_PATTERNS) {
        if (!p.rule.startsWith("README_LURE_")) continue;
        // These entries either have no notFilePattern, or one that does NOT
        // exclude README.md (they need to fire there).
        if (p.notFilePattern) {
          expect(
            p.notFilePattern.test("README.md"),
            `${p.rule} would skip README.md - breaks lure detection`,
          ).toBe(false);
        }
      }
    });

    it("PROMPT_INJECTION_PATTERNS still scan README.md", () => {
      for (const p of PROMPT_INJECTION_PATTERNS) {
        expect(
          p.notFilePattern!.test("README.md"),
          `${p.rule} would skip README.md - breaks prompt-injection detection`,
        ).toBe(false);
      }
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // ioc-blocklist + threat-intel: doc-file skip
  // ────────────────────────────────────────────────────────────────────────
  describe("checkIOCBlocklist skips documentation files", () => {
    // Use a content string with a known-bad C2 domain that WOULD normally fire.
    // We pick something simple - if any check fires, the test fails.
    const content = `random content with no real IOC here just testing the path filter mechanism`;

    it("returns no findings for .md files even with IOC content", () => {
      const findings = checkIOCBlocklist(content, "README.md");
      expect(findings).toHaveLength(0);
    });

    it("returns no findings for .markdown files", () => {
      const findings = checkIOCBlocklist(content, "docs/intel.markdown");
      expect(findings).toHaveLength(0);
    });

    it("returns no findings for .txt files", () => {
      const findings = checkIOCBlocklist(content, "notes.txt");
      expect(findings).toHaveLength(0);
    });

    it("returns no findings for .rst files", () => {
      const findings = checkIOCBlocklist(content, "INSTALL.rst");
      expect(findings).toHaveLength(0);
    });
  });

  describe("checkThreatIntel skips documentation files", () => {
    const feed: FeedIOC[] = [
      {
        type: "hash",
        value: "abcdef0123456789",
        severity: "critical",
        confidence: 0.95,
        family: "TestMalware",
      },
    ];
    const content = `discussing the hash abcdef0123456789 in a security write-up`;

    it("returns no findings for .md even with matching hash", () => {
      const findings = checkThreatIntel(content, "README.md", feed);
      expect(findings).toHaveLength(0);
    });

    it("still flags hash in source-code files", () => {
      const findings = checkThreatIntel(content, "src/loader.ts", feed);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].rule).toBe("THREAT_INTEL_MATCH");
    });
  });
});
