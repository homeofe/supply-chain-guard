#!/usr/bin/env node
/**
 * Measure the false-positive rate of TYPOSQUAT_LEVENSHTEIN against real npm names.
 *
 * Why this exists: every threshold in src/dependency-risk-analyzer.ts is justified in a
 * comment by a false-positive count over real package names ("a floor of 4 produced 57
 * false positives and a floor of 5 produces 29"), but the corpus and the counting were
 * never committed. The numbers could not be reproduced, re-checked, or recomputed after
 * a change - which is the same failure mode as an unverified claim anywhere else in this
 * repo. This script makes the calibration reproducible.
 *
 * It calls the SHIPPED classifier (classifyTyposquat) rather than a copy, so the
 * measurement cannot drift away from the behaviour it claims to measure.
 *
 * Corpus: names are drawn from the public npm replication endpoint, spread across the
 * alphabet rather than taken from the head of the index, because the head is dominated
 * by punctuation-prefixed junk that is not representative of what people depend on.
 * The corpus is cached on disk so a re-run is deterministic and offline.
 *
 * Usage:
 *   node scripts/measure-typosquat-fp.mjs                 # measure, using cache
 *   node scripts/measure-typosquat-fp.mjs --refresh       # re-fetch the corpus
 *   node scripts/measure-typosquat-fp.mjs --cache <path>  # alternative cache location
 */

import fs from "node:fs";
import path from "node:path";
import { classifyTyposquat } from "../dist/dependency-risk-analyzer.js";

const args = process.argv.slice(2);
const REFRESH = args.includes("--refresh");
const cacheIdx = args.indexOf("--cache");
if (cacheIdx !== -1 && (!args[cacheIdx + 1] || args[cacheIdx + 1].startsWith("--"))) {
  throw new Error("--cache requires a file path");
}
// Default under node_modules/.cache, NOT inside the tracked tree. A 31,000-name
// corpus is a file full of arbitrary package names, and some of them inevitably
// match a content heuristic: parked in scripts/ it made this repository's own
// self-scan report VIDAR_WALLET_THEFT against the measurement's cache. Scanners
// skip node_modules, so the cache cannot pollute a scan of a checkout that ran it.
const CACHE =
  cacheIdx !== -1
    ? args[cacheIdx + 1]
    : path.join("node_modules", ".cache", "typosquat-corpus.json");

/**
 * TWO-letter prefixes, not one.
 *
 * The replication index is alphabetical, so a one-letter startkey returns the
 * alphabetically FIRST names under that letter - which is dominated by "a0", "a1",
 * "a-b-c" style junk rather than by anything a manifest depends on. Sampling on two
 * letters spreads the draw over 156 points in the index instead of 26 and pulls in
 * ordinary package names. The absolute false-positive count still depends on the
 * sample; what the comparison below relies on is that both variants are measured
 * over the SAME corpus.
 */
const LETTERS = "abcdefghijklmnopqrstuvwxyz".split("");
const SECONDS = ["a", "e", "i", "o", "r", "u"];
const PER_PREFIX = 200;

async function fetchCorpus() {
  const names = [];
  for (const a of LETTERS) {
    for (const b of SECONDS) {
      const prefix = a + b;
      const url =
        `https://replicate.npmjs.com/_all_docs?limit=${PER_PREFIX}` +
        `&startkey=${encodeURIComponent(JSON.stringify(prefix))}`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`corpus fetch failed for "${prefix}": HTTP ${res.status}`);
      const body = await res.json();
      for (const row of body.rows || []) {
        const id = row.id;
        // Scoped names never reach the Levenshtein path (the caller returns early), and
        // ids starting with punctuation are not real dependencies.
        if (!id || id.startsWith("@") || id.startsWith("_") || !/^[a-z0-9]/.test(id)) continue;
        names.push(id);
      }
    }
    process.stderr.write(`  ${a}*: ${names.length} cumulative\n`);
  }
  return [...new Set(names)].sort();
}

let corpus;
if (!REFRESH && fs.existsSync(CACHE)) {
  corpus = JSON.parse(fs.readFileSync(CACHE, "utf8"));
  console.log(`Corpus: ${corpus.length} names (cached at ${CACHE})`);
} else {
  console.log("Fetching corpus from the npm replication endpoint...");
  corpus = await fetchCorpus();
  fs.mkdirSync(path.dirname(CACHE), { recursive: true });
  fs.writeFileSync(CACHE, JSON.stringify(corpus));
  console.log(`Corpus: ${corpus.length} names (written to ${CACHE})`);
}

/**
 * Curated squats this repo relies on the heuristic to catch. A predicate that improves
 * the false-positive count while dropping any of these is not an improvement - recall
 * has to be reported next to precision or the number is meaningless.
 */
const CURATED_SQUATS = [
  "lodas", "lodahs", "1odash", "l0dash", "axois", "raect", "yarsg", "chlak", "expres",
];

const VARIANTS = [
  ["no guard (previous behavior)", "none"],
  ["blanket first-char predicate", "same-leading"],
  ["homoglyph-aware (shipped)", "homoglyph-aware"],
];

// Every variant starts from the same corpus and calls the production classifier with
// one explicit policy. The classifier owns the popular-name, allowlist, minimum-length,
// distance, and leading-character guards, so this cannot pre-filter away the 27 -> 8
// comparison or accidentally count names that the shipped analyzer exempts.
const rowsByPolicy = new Map(VARIANTS.map(([, policy]) => [policy, []]));
for (const name of corpus) {
  for (const [, policy] of VARIANTS) {
    const hit = classifyTyposquat(name, policy);
    if (hit) rowsByPolicy.get(policy).push({ name, ...hit });
  }
}

console.log("\n=== Flagged by TYPOSQUAT_LEVENSHTEIN over the corpus ===");
const rawRows = rowsByPolicy.get("none");
for (const [label, policy] of VARIANTS) {
  const rows = rowsByPolicy.get(policy);
  console.log(`  ${label.padEnd(30)} ${String(rows.length).padStart(4)} flagged` +
    `   (${rawRows.length - rows.length} suppressed)`);
}

console.log("\n=== Recall on the curated squats ===");
console.log(`  ${"name".padEnd(10)} ${"no guard".padEnd(18)} ${"blanket".padEnd(10)} shipped`);
const lost = { blanket: 0, homoglyph: 0 };
for (const squat of CURATED_SQUATS) {
  const raw = classifyTyposquat(squat, "none");
  const blanket = classifyTyposquat(squat, "same-leading");
  const shipped = classifyTyposquat(squat, "homoglyph-aware");
  if (!raw) {
    console.log(`  ${squat.padEnd(10)} ${"miss".padEnd(18)} ${"-".padEnd(10)} -`);
    continue;
  }
  if (!blanket) lost.blanket++;
  if (!shipped) lost.homoglyph++;
  console.log(
    `  ${squat.padEnd(10)} ${`HIT (${raw.popular})`.padEnd(18)} ` +
      `${(blanket ? "HIT" : "LOST").padEnd(10)} ${shipped ? "HIT" : "LOST"}`,
  );
}
console.log(`\n  curated squats lost - blanket: ${lost.blanket}, homoglyph-aware: ${lost.homoglyph}`);

const shippedRows = rowsByPolicy.get("homoglyph-aware");
const shippedNames = new Set(shippedRows.map((row) => row.name));
const droppedByHomoglyph = rawRows.filter((row) => !shippedNames.has(row.name));

console.log("\n=== Suppressed by the homoglyph-aware predicate ===");
for (const r of droppedByHomoglyph) console.log(`  ${r.name.padEnd(24)} <- "${r.popular}"`);

console.log("\n=== Still flagged by the homoglyph-aware predicate ===");
for (const r of shippedRows) console.log(`  ${r.name.padEnd(24)} <- "${r.popular}"`);
