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
 * entries here are NOT typosquat targets. The two lists are separate because a
 * name can need exempting without being worth defending: putting a name in
 * POPULAR_PACKAGES also makes every name one edit from it a candidate squat, so
 * the target list has to stay a deliberate choice rather than a dumping ground
 * for whatever tripped the rule this week.
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

/** Registry name shape, used to validate an alias target. */
const ALIAS_NAME_RE = /^(@[a-z0-9][a-z0-9-._~]*\/)?[a-z0-9-._~][a-z0-9-._~]*$/i;

/**
 * Resolve an npm alias spec to the package that actually gets installed.
 *
 * `"utils": "npm:chalk-tempalte@1.0.0"` installs chalk-tempalte and calls it
 * `utils` in the tree. The KEY is a local label chosen by whoever wrote the
 * manifest; the TARGET is the real registry package. Checking the key is
 * therefore checking attacker-controlled text, which is how a known-malicious
 * package used to scan completely clean: every consumer here read the key.
 *
 * Returns null for anything that is not an `npm:` alias, so callers can fall
 * back to the literal name.
 */
export function resolveNpmAlias(
  spec: string | undefined,
): { name: string; version?: string } | null {
  if (typeof spec !== "string") return null;
  const trimmed = spec.trim();
  if (!trimmed.startsWith("npm:")) return null;

  const target = trimmed.slice(4);
  if (target.length === 0) return null;

  // Same split rule as a plain spec: the LAST "@" separates the version, and
  // index 0 is a scope marker rather than a separator.
  const at = target.lastIndexOf("@");
  const name = at > 0 ? target.substring(0, at) : target;
  const version = at > 0 ? target.substring(at + 1) : undefined;

  if (!ALIAS_NAME_RE.test(name)) return null;
  // A nested protocol ("npm:foo@git:...") is not a plain registry pin. Keep the
  // resolved NAME, which is still checkable, and drop only the version.
  if (version !== undefined && (version.length === 0 || version.includes(":"))) {
    return { name };
  }

  return version === undefined ? { name } : { name, version };
}

/**
 * Patterns that suggest an internal/private package name published publicly.
 *
 * Only the two EXPLICIT prefixes are kept. The six suffix patterns that used to
 * live here (-service, -api, -lib, -utils, -common, -core, -shared) matched
 * around 1.7% of every real scoped package on npm and reported them at CRITICAL:
 * @babel/helper-plugin-utils, @vue/compiler-core, @tanstack/query-core,
 * @jest/expect-utils, @azure/msal-common and @prisma/driver-adapter-utils were
 * all dependency-confusion verdicts. "-core" is how the JavaScript ecosystem
 * names its core packages; it is not evidence of anything.
 *
 * They did overlap two curated malicious packages, but by coincidence of name
 * shape rather than knowledge. That knowledge now lives where it belongs: the
 * malicious VERSIONS are pinned in the bundled feed, and @tc-core/campus-service
 * carries a bare-name feed entry (registry-verified: absent from npm, every
 * published version malicious).
 *
 * "internal-" and "private-" are deliberate, self-declared markers and had zero
 * measured false positives.
 */
const INTERNAL_PATTERNS = [
  /^@[^/]+\/internal-/,
  /^@[^/]+\/private-/,
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
 * (two substitutions) rather than 1. The curated squats this rule catches that
 * are transpositions - "rimarf" -> rimraf, "yarsg" -> yargs, "lodahs" -> lodash,
 * "axois" -> axios, "raect" -> react - would all be lost at a plain 1-edit
 * ceiling. Scoring them as 1 is what allows the ceiling to drop from 2 to 1
 * without losing them.
 *
 * Note this rule only ever sees squats of names in POPULAR_PACKAGES. Curated
 * malicious names whose target is NOT in that list (cyrpto, hardhta, naniod,
 * suport-color) are matched by exact name in patterns.ts and the feed, never
 * here - so this heuristic's job is unpublished future squats, not the corpus
 * already curated.
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

  // Every rule below judges the package that is actually INSTALLED. For an npm
  // alias ("utils": "npm:lodahs@1.0.0") that is the target, not the manifest
  // key, which is arbitrary text chosen by whoever wrote the file.
  const entries = Object.keys(dependencies).map((key) => {
    const alias = resolveNpmAlias(dependencies[key]);
    return { key, name: alias ? alias.name : key, aliased: alias !== null };
  });
  /** Sorted "a b" keys, so one pair yields one finding rather than one per side. */
  const reportedPairs = new Set<string>();

  for (const { key, name, aliased } of entries) {
    const via = aliased ? ` (installed via the npm alias "${key}")` : "";

    // Skip scoped packages for Levenshtein (handled separately)
    if (name.startsWith("@")) {
      // Check internal name patterns on public registry
      for (const pattern of INTERNAL_PATTERNS) {
        if (pattern.test(name)) {
          findings.push({
            rule: "DEP_INTERNAL_NAME_PUBLIC",
            description: `Dependency "${name}" looks like an internal package name${via}. If this is on a public registry, it may be a dependency confusion attack.`,
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
      // At a ceiling of 1 every hit is the same distance, so there is no closer
      // match to search for and the first hit is reported. (Under the old 2-edit
      // ceiling this loop could report a distance-2 target while a distance-1 one
      // sat later in the array.) If the ceiling is ever raised, this must go back
      // to tracking the minimum before reporting.
      let best: { popular: string; dist: number } | undefined;
      for (const popular of POPULAR_PACKAGES) {
        if (name === popular) continue; // Exact match = legitimate
        // Skip short popular targets. The floor is 5, not 4: measured over 29,687
        // real published npm names, a floor of 4 produced 57 false positives and a
        // floor of 5 produces 29, with the curated true-positive set unchanged. The
        // four-letter targets are the damaging ones because almost any short name is
        // one edit from them - "path" alone accounted for 11 (upath, mpath, xpath,
        // paths, ...) and "jest" for 5 (test, nest, rest, ...). Floor 6 is too far:
        // it loses yarsg, axois, raect and chlak.
        if (popular.length < 5) continue;
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
          description: `Dependency "${name}"${via} is ${best.dist} edit(s) away from popular package "${best.popular}". Likely a typosquat.`,
          severity: "high",
          file: relativePath,
          confidence: 0.85,
          category: "supply-chain",
          recommendation: `Did you mean "${best.popular}"? Typosquatting replaces popular packages with malicious copies.`,
        });
      }
    }

    // Check if name is similar to another direct dependency.
    //
    // Measured over 939 real manifests, this rule fired on 5.0% of them (8.1% of
    // real repository roots) and every colliding pair was a legitimate co-install:
    // preact+react, vue+vuex, path+pathe, color+colors, mysql+mysql2, uuid+ulid,
    // eslint+tslint. Four guards below cut that to under 1% while INCREASING
    // recall, because switching to osaDistance starts catching the transposition
    // squats (lodahs+lodash, axois+axios, raect+react, yarsg+yargs) that the rule
    // was silently missing next to their own target.
    //
    // The known-good test is ONE-SIDED on purpose. The outer loop visits both
    // members of a pair, so testing only the reported side keeps the case this
    // rule exists for: {expres, express} still reports, because the express-side
    // pass is dropped while the expres-side pass survives. Testing otherName too
    // would suppress exactly the squat-next-to-its-target shape (measured: it
    // drops 11 of 14 true positives).
    //
    // Guards are scoped to this block rather than the outer loop so the two
    // typosquat rules stay independently editable.
    const skipPairRule =
      name.length < 4 || POPULAR_PACKAGES_SET.has(name) || TYPOSQUAT_ALLOWLIST.has(name);

    if (!skipPairRule) {
      for (const other of entries) {
        const otherName = other.name;
        if (name === otherName) continue;
        if (name.startsWith("@") || otherName.startsWith("@")) continue;
        // Same length floor as the sibling rule: below 4 characters almost any
        // name is one edit from another (ws/wss, np/nx, fs/fse, qs/q).
        if (otherName.length < 4) continue;
        if (Math.abs(name.length - otherName.length) > 1) continue;

        const dist = osaDistance(name, otherName);
        if (dist > 0 && dist <= 1) {
          const pairKey = [name, otherName].sort().join(" ");
          if (reportedPairs.has(pairKey)) break;
          reportedPairs.add(pairKey);

          const otherVia = other.aliased ? ` (installed via the npm alias "${other.key}")` : "";
          findings.push({
            rule: "TYPOSQUAT_SIMILAR_TO_DEP",
            // "name" leads and is guaranteed to be the non-allowlisted side, so
            // the suspicious package is named first.
            description: `Dependencies "${name}"${via} and "${otherName}"${otherVia} differ by only ${dist} character(s). One may be a typosquat of the other.`,
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
  }

  return findings;
}
