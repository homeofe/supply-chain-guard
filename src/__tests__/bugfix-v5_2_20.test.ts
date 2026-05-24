/**
 * Regression tests for the pattern bugs uncovered by the v5.2.19 self-scan.
 * Each block corresponds to one fix documented in the v5.2.20 changelog.
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { FILE_PATTERNS } from "../patterns.js";
import { verifySLSA } from "../slsa-verifier.js";
import { checkLockfile } from "../lockfile-checker.js";

function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-v5220-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("v5.2.20 bug fixes", () => {
  // ────────────────────────────────────────────────────────────────────────
  // Fix 1: SOLANA_MAINNET pattern now excludes scanner-internal source files
  // ────────────────────────────────────────────────────────────────────────
  describe("SOLANA_MAINNET no longer self-flags solana-monitor.ts", () => {
    const solanaPattern = FILE_PATTERNS.find((p) => p.rule === "SOLANA_MAINNET");

    it("rule is registered", () => {
      expect(solanaPattern).toBeDefined();
    });

    it("has notFilePattern excluding scanner source", () => {
      expect(solanaPattern!.notFilePattern).toBeDefined();
    });

    it("excludes src/solana-monitor.ts (the actual Solana monitor)", () => {
      expect(solanaPattern!.notFilePattern!.test("src/solana-monitor.ts")).toBe(true);
      expect(solanaPattern!.notFilePattern!.test("src/solana-monitor.js")).toBe(true);
      expect(solanaPattern!.notFilePattern!.test("dist/solana-monitor.js")).toBe(true);
    });

    it("excludes src/solana-watchlist.ts and slsa-verifier.ts", () => {
      expect(solanaPattern!.notFilePattern!.test("src/solana-watchlist.ts")).toBe(true);
      expect(solanaPattern!.notFilePattern!.test("src/slsa-verifier.ts")).toBe(true);
    });

    it("still flags Solana mainnet in unrelated user code", () => {
      expect(solanaPattern!.notFilePattern!.test("src/my-trojan.ts")).toBe(false);
      expect(solanaPattern!.notFilePattern!.test("lib/c2-channel.ts")).toBe(false);
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // Fix 4: SLSA verifier recognises `npm publish --provenance`
  // ────────────────────────────────────────────────────────────────────────
  describe("SLSA verifier recognises npm publish --provenance", () => {
    it("classifies npm publish --provenance workflow as SLSA Level 2", () => {
      withTempDir((dir) => {
        const wfDir = path.join(dir, ".github", "workflows");
        fs.mkdirSync(wfDir, { recursive: true });
        fs.writeFileSync(
          path.join(wfDir, "ci.yml"),
          [
            "name: CI",
            "jobs:",
            "  publish:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      id-token: write",
            "    steps:",
            "      - run: npm publish --access public --provenance",
          ].join("\n"),
        );

        const findings = verifySLSA(dir);
        // No SLSA_NO_PROVENANCE finding should be emitted
        expect(findings.some((f) => f.rule === "SLSA_NO_PROVENANCE")).toBe(false);
      });
    });

    it("still flags workflows that build but do not sign provenance", () => {
      withTempDir((dir) => {
        const wfDir = path.join(dir, ".github", "workflows");
        fs.mkdirSync(wfDir, { recursive: true });
        fs.writeFileSync(
          path.join(wfDir, "ci.yml"),
          [
            "name: CI",
            "jobs:",
            "  publish:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - run: npm publish",
          ].join("\n"),
        );

        const findings = verifySLSA(dir);
        expect(findings.some((f) => f.rule === "SLSA_NO_PROVENANCE")).toBe(true);
      });
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // Fix 5: LOCKFILE_ORPHANED_DEPENDENCY recommendation reflects npm v7+ reality
  // ────────────────────────────────────────────────────────────────────────
  describe("LOCKFILE_ORPHANED_DEPENDENCY recommendation is npm-v7-correct", () => {
    it("recommendation no longer suggests the wrong `npm prune` action", () => {
      withTempDir((dir) => {
        const lockfile = {
          name: "fixture",
          version: "1.0.0",
          lockfileVersion: 3,
          requires: true,
          packages: {
            "": { name: "fixture", version: "1.0.0", dependencies: { commander: "^13.0.0" } },
            "node_modules/commander": { version: "13.1.0" },
            "node_modules/some-transitive": { version: "1.0.0" },
            "node_modules/another-transitive": { version: "2.0.0" },
          },
        };
        const pkg = {
          name: "fixture",
          version: "1.0.0",
          dependencies: { commander: "^13.0.0" },
        };
        fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify(lockfile));
        fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(pkg));

        const findings = checkLockfile(dir);
        const orphan = findings.find((f) => f.rule === "LOCKFILE_ORPHANED_DEPENDENCY");
        expect(orphan).toBeDefined();
        // The recommendation must NOT tell the user to run `npm prune` (does
        // not work for transitives in npm v7+).
        expect(orphan!.recommendation).not.toMatch(/npm\s+prune/i);
        // Should mention npm v7+ semantics.
        expect(orphan!.recommendation).toMatch(/npm\s+v7\+/i);
      });
    });
  });
});
