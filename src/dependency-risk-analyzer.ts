/**
 * Dependency risk analyzer (v4.2).
 *
 * Levenshtein-based typosquat detection and namespace squatting.
 * Checks package names against popular packages to detect mimicry.
 */

import type { Finding } from "./types.js";

/** Top popular npm packages (targets for typosquatting) */
const POPULAR_PACKAGES: string[] = [
  "lodash", "chalk", "express", "react", "axios", "commander", "debug",
  "glob", "minimist", "semver", "uuid", "mkdirp", "rimraf", "yargs",
  "moment", "bluebird", "underscore", "async", "request", "inquirer",
  "colors", "path", "dotenv", "body-parser", "webpack", "typescript",
  "eslint", "prettier", "jest", "mocha", "chai", "sinon", "supertest",
  "mongoose", "sequelize", "pg", "mysql2", "redis", "ioredis",
  "socket.io", "cors", "helmet", "morgan", "cookie-parser", "jsonwebtoken",
  "bcrypt", "bcryptjs", "passport", "nodemailer", "multer", "sharp", "puppeteer",
  "cheerio", "node-fetch", "got", "superagent", "http-proxy-middleware",
  "ws", "next", "gatsby", "vue", "angular", "svelte", "tailwindcss",
  "postcss", "autoprefixer", "sass", "less", "babel", "esbuild",
  "rollup", "vite", "turbo", "nx", "lerna", "husky", "lint-staged",
  "cross-env", "concurrently", "nodemon", "pm2", "fastify", "koa",
  "hapi", "restify",
  // Very common packages that are legitimately close in name to other popular ones
  "swr", "tsx", "zod", "trpc", "drizzle", "prisma", "vitest",
];

/** Packages that are known-safe even when close in name to popular packages */
const POPULAR_PACKAGES_SET = new Set(POPULAR_PACKAGES);

/**
 * Legitimate, widely-used packages that sit one edit from an entry in
 * POPULAR_PACKAGES and must never be reported as typosquats.
 *
 * This is an ADDITIONAL exemption, not a replacement for POPULAR_PACKAGES_SET:
 * entries here are NOT typosquat targets. Adding a name to POPULAR_PACKAGES to
 * exempt it would also make every name near it a candidate squat, which is how
 * this defect would otherwise spread (appending "viem" there, for instance,
 * newly flags the legitimate vuex and timm at distance 2).
 *
 * Scope note: this set gates exactly one rule (TYPOSQUAT_LEVENSHTEIN, at the
 * single call site below). It is NOT a malware bypass - feed IOC matches, the
 * known-bad-version blocklist and every scanner pattern run on separate paths
 * that never consult it. Do not move this check earlier in install-guard's
 * checkSpec, where it would start gating real malware verdicts.
 *
 * Every entry was verified against the npm registry on 2026-07-29 as a real,
 * maintained package with an identifiable owner - the same evidentiary bar
 * src/patterns.ts applies before blocking any bare name.
 */
const TYPOSQUAT_ALLOWLIST = new Set([
  "pathe", // unjs, universal path utils (also a transitive dep of this repo)
  "color", // Qix-/color; NOT a squat of the sabotaged "colors"
  "colord", // omgovich, color manipulation
  "mysql", // the original mysqljs driver; "mysql2" is the successor, both real
  "nuxt", // the Nuxt framework
  "ulid", // ULID id generator; near "uuid" by coincidence
  "preact", // 3kb React-compatible virtual DOM
  "gaxios", // googleapis HTTP client
  "enquirer", // interactive CLI prompts
  "ttypescript", // TypeScript wrapper supporting custom transformers
]);

/** Patterns that suggest internal/private package names */
const INTERNAL_PATTERNS = [
  /^@[^/]+\/internal-/,
  /^@[^/]+\/private-/,
  /^@[^/]+\/.+-service$/,
  /^@[^/]+\/.+-api$/,
  /^@[^/]+\/.+-lib$/,
  /^@[^/]+\/.+-utils$/,
  /^@[^/]+\/.+-common$/,
  /^@[^/]+\/.+-core$/,
  /^@[^/]+\/.+-shared$/,
];

/**
 * Calculate Levenshtein distance between two strings.
 */
export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    Array.from({ length: n + 1 }, () => 0),
  );

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
    }
  }

  return dp[m][n];
}

/**
 * Optimal String Alignment distance (Damerau-Levenshtein restricted to adjacent
 * transpositions), used ONLY by the typosquat heuristic below.
 *
 * Deliberately separate from the exported `levenshtein`, which is public API
 * (re-exported from src/index.ts) and pinned to exact values by its own tests.
 *
 * Why the typosquat rule needs transposition awareness: the realistic squat is a
 * swapped pair of adjacent characters, which plain Levenshtein scores as 2 edits
 * (two substitutions) rather than 1. Measured against this repo's own curated
 * malicious names, every true positive the rule catches is a transposition:
 * "rimarf" -> rimraf, "yarsg" -> yargs, "lodahs" -> lodash, "veim" -> viem.
 * Scoring those as 1 is what allows the distance ceiling to drop from 2 to 1
 * without losing a single one of them.
 */
function osaDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    Array.from({ length: n + 1 }, () => 0),
  );

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
      // Adjacent transposition counts as a single edit.
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + cost);
      }
    }
  }

  return dp[m][n];
}

/**
 * Analyze dependencies for typosquatting and confusion risks.
 */
export function analyzeDependencyRisks(
  dependencies: Record<string, string>,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const depNames = Object.keys(dependencies);

  for (const name of depNames) {
    // Skip scoped packages for Levenshtein (handled separately)
    if (name.startsWith("@")) {
      // Check internal name patterns on public registry
      for (const pattern of INTERNAL_PATTERNS) {
        if (pattern.test(name)) {
          findings.push({
            rule: "DEP_INTERNAL_NAME_PUBLIC",
            description: `Dependency "${name}" looks like an internal package name. If this is on a public registry, it may be a dependency confusion attack.`,
            severity: "critical",
            file: relativePath,
            confidence: 0.7,
            category: "supply-chain",
            recommendation: `Verify "${name}" is your organization's real package. If not, this is dependency confusion.`,
          });
          break;
        }
      }
      continue;
    }

    // Typosquat check against popular packages.
    //
    // The ceiling is ONE transposition-aware edit. It used to be two plain
    // Levenshtein edits, which flagged 321 measured real packages (acorn, preact,
    // cypress, redux, viem, knex, globby, jose...) against 2 true positives that
    // patterns.ts and the feed already catch by exact name - a ~1:160 signal ratio,
    // and it got WORSE the more popular the package was (2.37% of packages above
    // 10M weekly downloads). Two edits against a 4-character name is simply not
    // evidence of anything. Transposition awareness (see osaDistance) is what makes
    // the tightening free: every real squat in this repo's threat data is an
    // adjacent swap, so all of them still score 1 and are still caught.
    //
    // No first-character predicate is used. It would cut a further ~24 false
    // positives, but this repo curates "1odash" and "l0dash" in patterns.ts as
    // canonical squats, and both change character zero - a leading-homoglyph rule
    // would make this heuristic structurally unable to generalize them. It is also
    // published source, so it would be a one-character documented bypass.
    //
    // Skip if the name is itself a known popular/safe package - prevents false
    // positives where two legitimate popular packages are close in name (next/jest).
    if (
      !POPULAR_PACKAGES_SET.has(name) &&
      !TYPOSQUAT_ALLOWLIST.has(name) &&
      name.length >= 4
    ) {
      // Report the CLOSEST target, not the first one in array order. Array order
      // previously decided which package the "Did you mean" text named.
      let best: { popular: string; dist: number } | undefined;
      for (const popular of POPULAR_PACKAGES) {
        if (name === popular) continue; // Exact match = legitimate
        // Skip very short popular packages (ws, pg, nx…) - too many false positives
        if (popular.length < 4) continue;
        if (Math.abs(name.length - popular.length) > 1) continue; // Quick skip

        const dist = osaDistance(name, popular);
        if (dist > 0 && dist <= 1 && (!best || dist < best.dist)) {
          best = { popular, dist };
          break; // Distance 1 is the tightest possible hit; nothing can beat it.
        }
      }

      if (best) {
        findings.push({
          rule: "TYPOSQUAT_LEVENSHTEIN",
          // The dependency name MUST stay the first quoted token: policy-engine.ts
          // extracts it with /"([^"]+)"/ to honour user `allowlist.packages` rules.
          description: `Dependency "${name}" is ${best.dist} edit(s) away from popular package "${best.popular}". Likely a typosquat.`,
          severity: "high",
          file: relativePath,
          confidence: 0.85,
          category: "supply-chain",
          recommendation: `Did you mean "${best.popular}"? Typosquatting replaces popular packages with malicious copies.`,
        });
      }
    }

    // Check if name is similar to another direct dependency
    for (const otherName of depNames) {
      if (name === otherName) continue;
      if (name.startsWith("@") || otherName.startsWith("@")) continue;
      if (Math.abs(name.length - otherName.length) > 2) continue;

      const dist = levenshtein(name, otherName);
      if (dist > 0 && dist <= 1) {
        findings.push({
          rule: "TYPOSQUAT_SIMILAR_TO_DEP",
          description: `Dependencies "${name}" and "${otherName}" differ by only ${dist} character(s). One may be a typosquat of the other.`,
          severity: "high",
          file: relativePath,
          confidence: 0.7,
          category: "supply-chain",
          recommendation: `Review both "${name}" and "${otherName}". Only one should be in your dependencies.`,
        });
        break;
      }
    }
  }

  return findings;
}
