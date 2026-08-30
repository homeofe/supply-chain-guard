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
const CACHE = cacheIdx !== -1 ? args[cacheIdx + 1] : path.join("scripts", ".typosquat-corpus.json");

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

function firstCharDiffers(name, target) {
  return name[0] !== target[0];
}

/**
 * Character pairs that are deliberate visual substitutions rather than a different
 * word. A leading "1" for "l" is the whole point of "1odash"; a leading "z" for "r"
 * is not a disguise, it is a different name.
 */
const HOMOGLYPHS = new Map([
  ["1", "l"], ["l", "1"],
  ["0", "o"], ["o", "0"],
  ["5", "s"], ["s", "5"],
  ["3", "e"], ["e", "3"],
  ["4", "a"], ["a", "4"],
  ["i", "l"], ["l", "i"],
]);

/**
 * Homoglyph-aware variant: the first character may differ ONLY when the difference is
 * a known visual substitution. Keeps leading-homoglyph squats while dropping the
 * "different first letter entirely" collisions that dominate the false positives.
 */
function firstCharDiffersNonHomoglyph(name, target) {
  const a = name[0];
  const b = target[0];
  if (a === b) return false;
  return HOMOGLYPHS.get(a) !== b;
}

const rows = [];
for (const name of corpus) {
  const hit = classifyTyposquat(name);
  if (hit) rows.push({ name, ...hit });
}

const VARIANTS = [
  ["as shipped today", () => false],
  ["blanket first-char predicate", firstCharDiffers],
  ["homoglyph-aware first-char", firstCharDiffersNonHomoglyph],
];

console.log("\n=== Flagged by TYPOSQUAT_LEVENSHTEIN over the corpus ===");
for (const [label, drop] of VARIANTS) {
  const kept = rows.filter((r) => !drop(r.name, r.popular));
  console.log(`  ${label.padEnd(30)} ${String(kept.length).padStart(4)} flagged` +
    `   (${rows.length - kept.length} suppressed)`);
}

console.log("\n=== Recall on the curated squats ===");
console.log(`  ${"name".padEnd(10)} ${"today".padEnd(18)} ${"blanket".padEnd(10)} homoglyph-aware`);
const lost = { blanket: 0, homoglyph: 0 };
for (const squat of CURATED_SQUATS) {
  const hit = classifyTyposquat(squat);
  if (!hit) {
    console.log(`  ${squat.padEnd(10)} ${"miss".padEnd(18)} ${"-".padEnd(10)} -`);
    continue;
  }
  const b = !firstCharDiffers(squat, hit.popular);
  const h = !firstCharDiffersNonHomoglyph(squat, hit.popular);
  if (!b) lost.blanket++;
  if (!h) lost.homoglyph++;
  console.log(
    `  ${squat.padEnd(10)} ${`HIT (${hit.popular})`.padEnd(18)} ` +
      `${(b ? "HIT" : "LOST").padEnd(10)} ${h ? "HIT" : "LOST"}`,
  );
}
console.log(`\n  curated squats lost - blanket: ${lost.blanket}, homoglyph-aware: ${lost.homoglyph}`);

const droppedByHomoglyph = rows.filter((r) => firstCharDiffersNonHomoglyph(r.name, r.popular));
const keptByHomoglyph = rows.filter((r) => !firstCharDiffersNonHomoglyph(r.name, r.popular));

console.log("\n=== Suppressed by the homoglyph-aware predicate ===");
for (const r of droppedByHomoglyph) console.log(`  ${r.name.padEnd(24)} <- "${r.popular}"`);

console.log("\n=== Still flagged by the homoglyph-aware predicate ===");
for (const r of keptByHomoglyph) console.log(`  ${r.name.padEnd(24)} <- "${r.popular}"`);
