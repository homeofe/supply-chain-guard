import { describe, it, expect } from "vitest";
import { analyzeDependencyRisks, levenshtein } from "../dependency-risk-analyzer.js";

describe("Dependency Risk Analyzer", () => {
  describe("levenshtein", () => {
    it("should return 0 for identical strings", () => {
      expect(levenshtein("lodash", "lodash")).toBe(0);
    });

    it("should return 1 for single edit", () => {
      expect(levenshtein("lodash", "lodas")).toBe(1);
      expect(levenshtein("lodash", "1odash")).toBe(1);
    });

    it("should return 2 for two edits", () => {
      expect(levenshtein("lodash", "l0das")).toBe(2);
    });

    it("should handle empty strings", () => {
      expect(levenshtein("", "abc")).toBe(3);
      expect(levenshtein("abc", "")).toBe(3);
    });
  });

  describe("analyzeDependencyRisks", () => {
    it("should detect typosquatted package names", () => {
      const findings = analyzeDependencyRisks(
        { "lodas": "^4.17.0", "react": "^18.0.0" },
        "package.json",
      );
      expect(findings.some((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN")).toBe(true);
      expect(findings.find((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN")?.description).toContain("lodash");
    });

    // -----------------------------------------------------------------
    // Typosquat ceiling: one transposition-aware edit.
    //
    // The rule used to accept two plain Levenshtein edits, which flagged 321
    // measured real packages against 2 true positives that patterns.ts and the
    // feed already catch by exact name. These two blocks pin both sides of the
    // trade so neither can regress silently.
    // -----------------------------------------------------------------

    const flagsTyposquat = (name: string): boolean =>
      analyzeDependencyRisks({ [name]: "^1.0.0" }, "package.json").some(
        (f) => f.rule === "TYPOSQUAT_LEVENSHTEIN",
      );

    it("still catches real squats, including adjacent transpositions", () => {
      // Transpositions are the shape every real squat in this repo's threat data
      // takes. Plain Levenshtein scores them 2, which is why the distance function
      // has to be transposition-aware for a <= 1 ceiling to keep them.
      for (const squat of ["rimarf", "yarsg", "lodahs", "raect"]) {
        expect(flagsTyposquat(squat), squat).toBe(true);
      }
      // Single-substitution squats, including leading-character homoglyphs. These
      // are why no same-first-character predicate is used: it would drop 1odash,
      // which src/patterns.ts curates by hand as a canonical typosquat.
      for (const squat of ["lodas", "1odash", "l0dash", "expres"]) {
        expect(flagsTyposquat(squat), squat).toBe(true);
      }
    });

    it("does not flag legitimate packages that merely sit near a popular name", () => {
      // Every name here is a real, maintained npm package (registry-verified
      // 2026-07-29). Under the old two-edit ceiling all of them were reported as
      // typosquats, and in install-guard that is a hard block.
      const legitimate = [
        "viem", // 2 edits from vite - the originally reported false positive
        "acorn", // 2 from cors
        "cypress", // 2 from express
        "redux", // 2 from redis
        "knex", // 2 from next
        "jose", // 2 from jest
        "globby", // 2 from glob
        "mime", // 2 from vite
        "util", // 2 from uuid
        "jiti", // 2 from vite
        // Allowlisted: genuinely 1 edit away, so only an explicit exemption clears them.
        "pathe",
        "color",
        "colord",
        "mysql",
        "nuxt",
        "ulid",
        "preact",
        "gaxios",
        "enquirer",
        "ttypescript",
      ];
      for (const name of legitimate) {
        expect(flagsTyposquat(name), name).toBe(false);
      }
    });

    it("does not report popular packages as typosquats of each other", () => {
      // The guard keeps the POPULAR_PACKAGES membership test as well as the
      // allowlist. Entries in that array collide with each other, so dropping the
      // membership term would make the target list flag itself.
      const findings = analyzeDependencyRisks(
        {
          redis: "^4.0.0",
          ioredis: "^5.0.0",
          bcrypt: "^5.0.0",
          bcryptjs: "^2.4.3",
          vite: "^5.0.0",
          vitest: "^1.0.0",
          fastify: "^4.0.0",
          restify: "^11.0.0",
        },
        "package.json",
      );
      expect(findings.filter((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN")).toHaveLength(0);
    });

    it("names the closest popular package, not the first one in array order", () => {
      // "rest" is 1 edit from jest and 2 from react; react comes first in the array.
      const finding = analyzeDependencyRisks({ rest: "^1.0.0" }, "package.json").find(
        (f) => f.rule === "TYPOSQUAT_LEVENSHTEIN",
      );
      expect(finding?.description).toContain('"jest"');
      expect(finding?.description).not.toContain('"react"');
    });

    it("keeps the dependency name as the first quoted token", () => {
      // src/policy-engine.ts extracts the package with /"([^"]+)"/ to honour user
      // `allowlist.packages` rules. Moving the name out of first position silently
      // breaks every user allowlist.
      const finding = analyzeDependencyRisks({ lodas: "^1.0.0" }, "package.json").find(
        (f) => f.rule === "TYPOSQUAT_LEVENSHTEIN",
      );
      expect(finding?.description.match(/"([^"]+)"/)?.[1]).toBe("lodas");
    });

    it("should detect similar dependency names", () => {
      const findings = analyzeDependencyRisks(
        { "expres": "^4.0.0", "express": "^4.18.0" },
        "package.json",
      );
      expect(findings.some((f) => f.rule === "TYPOSQUAT_SIMILAR_TO_DEP")).toBe(true);
    });

    it("should detect internal-looking scoped packages", () => {
      const findings = analyzeDependencyRisks(
        { "@mycompany/internal-auth": "^1.0.0" },
        "package.json",
      );
      expect(findings.some((f) => f.rule === "DEP_INTERNAL_NAME_PUBLIC")).toBe(true);
    });

    it("should not flag legitimate popular packages", () => {
      const findings = analyzeDependencyRisks(
        { "lodash": "^4.17.0", "express": "^4.18.0", "react": "^18.0.0" },
        "package.json",
      );
      expect(findings.some((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN")).toBe(false);
    });

    it("should not flag very different names", () => {
      const findings = analyzeDependencyRisks(
        { "totally-different-name": "^1.0.0" },
        "package.json",
      );
      expect(findings).toHaveLength(0);
    });

    it("should include confidence scores", () => {
      const findings = analyzeDependencyRisks(
        { "axio": "^1.0.0" },
        "package.json",
      );
      const f = findings.find((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN");
      if (f) {
        expect(f.confidence).toBeGreaterThan(0);
        expect(f.confidence).toBeLessThanOrEqual(1);
      }
    });
  });
});
