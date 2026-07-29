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

    it("ignores short popular targets, where almost any name is one edit away", () => {
      // The target floor is 5. Four-letter targets (path, jest, cors, sass, vite,
      // uuid, glob, less, next) were responsible for roughly half the measured
      // false positives: "rest"/"test"/"nest" against jest, "upath"/"xpath"/"mpath"
      // against path. Curated squats all target names of 5 characters or more.
      for (const name of ["rest", "nest", "upath", "xpath", "corn", "scss"]) {
        expect(flagsTyposquat(name), name).toBe(false);
      }
      // A 5+ character target still reports, and names that target.
      const finding = analyzeDependencyRisks({ mocha1: "^1.0.0" }, "package.json").find(
        (f) => f.rule === "TYPOSQUAT_LEVENSHTEIN",
      );
      expect(finding?.description).toContain('"mocha"');
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

    // -----------------------------------------------------------------
    // TYPOSQUAT_SIMILAR_TO_DEP: two direct dependencies one edit apart.
    // -----------------------------------------------------------------

    const pairFindings = (deps: Record<string, string>) =>
      analyzeDependencyRisks(deps, "package.json").filter(
        (f) => f.rule === "TYPOSQUAT_SIMILAR_TO_DEP",
      );

    it("does not flag legitimate co-installed sibling packages", () => {
      // Measured over 939 real manifests, these pairs accounted for the bulk of
      // the rule's false positives. Every one is two real packages that projects
      // legitimately install together.
      const pairs: Record<string, string>[] = [
        { vue: "^3", vuex: "^4" },
        { react: "^18", preact: "^10" },
        { path: "^0.12", pathe: "^2" },
        { color: "^5", colors: "^1" },
        { mysql: "^2", mysql2: "^3" },
        { uuid: "^9", ulid: "^3" },
        { ws: "^8", wss: "^1" },
        { np: "^10", nx: "^19" },
      ];
      for (const deps of pairs) {
        expect(pairFindings(deps), Object.keys(deps).join("+")).toHaveLength(0);
      }
    });

    it("still flags a squat sitting next to the package it imitates", () => {
      // The known-good check is one-sided, so the popular side is skipped while
      // the suspicious side still reports. Making it two-sided would silence
      // exactly this shape, which is the rule's whole purpose.
      for (const deps of [
        { expres: "^4", express: "^4.18" },
        { "1odash": "^4", lodash: "^4.17" },
        { lodahs: "^4", lodash: "^4.17" },
        { axois: "^1", axios: "^1.7" },
        { yarsg: "^17", yargs: "^17" },
      ]) {
        expect(pairFindings(deps), Object.keys(deps).join("+")).toHaveLength(1);
      }
    });

    it("reports a colliding pair once, not once per side", () => {
      const findings = pairFindings({ expres: "^4.0.0", express: "^4.18.0" });
      expect(findings).toHaveLength(1);
      // The suspicious side is named first so it is the token users allowlist.
      expect(findings[0].description.match(/"([^"]+)"/)?.[1]).toBe("expres");
    });

    it("catches transposition squats the plain-Levenshtein version missed", () => {
      // lodahs/lodash scores 2 under plain Levenshtein and 1 under OSA, so these
      // were silently quiet before. Reverting to levenshtein turns this red.
      for (const deps of [
        { lodahs: "^4", lodash: "^4.17" },
        { raect: "^18", react: "^18" },
        { rimarf: "^5", rimraf: "^5" },
      ]) {
        expect(pairFindings(deps), Object.keys(deps).join("+")).toHaveLength(1);
      }
    });

    // -----------------------------------------------------------------
    // npm alias resolution. An alias installs the TARGET while the manifest
    // key is arbitrary text, so every rule must judge the target.
    // -----------------------------------------------------------------

    it("resolves npm aliases so the installed package is what gets judged", () => {
      // Squat hidden behind an innocuous key.
      const hidden = analyzeDependencyRisks(
        { helpers: "npm:lodahs@1.0.0" },
        "package.json",
      );
      expect(hidden.some((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN")).toBe(true);
      expect(hidden[0].description).toContain("lodahs");
      expect(hidden[0].description).toContain('npm alias "helpers"');

      // An alias to a legitimate package stays clean.
      expect(
        analyzeDependencyRisks({ fine: "npm:lodash@4.17.21" }, "package.json"),
      ).toHaveLength(0);

      // The KEY is never judged: "lodahs" as a label pointing at real lodash is
      // not a squat, because lodash is what actually gets installed.
      expect(
        analyzeDependencyRisks({ lodahs: "npm:lodash@4.17.21" }, "package.json"),
      ).toHaveLength(0);
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
