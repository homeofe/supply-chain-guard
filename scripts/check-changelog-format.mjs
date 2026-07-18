#!/usr/bin/env node
// check-changelog-format.mjs - Enforce ONE machine-checkable CHANGELOG grammar so
// the release/LOG/OSV parsers can never break on a hand-formatted entry again.
//
// Standard: Keep a Changelog 1.1.0 + SemVer. The heading grammar here is the SAME
// one the LOG generator (scripts/aahp-dashboard.mjs) parses, so generator output and
// this validator cannot diverge. Wired into `prebuild` alongside the other check:*
// gates. See the fleet CHANGELOG spec.
//
// It enforces the STRUCTURE strictly (headings, dates, ordering, links, no BOM,
// top==version) and the section vocabulary WHERE sections are used. It does NOT
// force historical prose entries into ### sections - migrating years of shipped
// notes into a taxonomy would rewrite history and invent categorization. New
// entries accumulate under ## [Unreleased] in full Keep a Changelog form.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const raw = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8");

const fail = [];
const SECTIONS = new Set(["Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"]);
// R1 heading grammar - shared with the LOG generator. No 'v' inside the brackets.
const RELEASE_RE = /^## \[(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\] - (\d{4}-\d{2}-\d{2})\s*$/;

// R9: UTF-8 without BOM.
if (raw.charCodeAt(0) === 0xfeff) fail.push("R9: file starts with a UTF-8 BOM - save as UTF-8 without BOM.");
const lines = raw.replace(/^﻿/, "").split(/\r?\n/);

const today = new Date().toISOString().slice(0, 10);
const cmp = (a, b) => {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
};

const releases = []; // {version, date, line}
const bracketLabels = []; // every ## [label] for R8
let unreleasedCount = 0;
let firstH2Index = -1;
let currentSection = null;

lines.forEach((line, i) => {
  if (/^## /.test(line)) {
    if (firstH2Index === -1) firstH2Index = i;
    currentSection = null;
    if (/^## \[Unreleased\]\s*$/.test(line)) {
      unreleasedCount++;
      bracketLabels.push("Unreleased");
      // R2: Unreleased must be the first H2.
      if (i !== firstH2Index) fail.push(`R2: "## [Unreleased]" (line ${i + 1}) must be the first H2 heading.`);
      return;
    }
    const m = line.match(RELEASE_RE);
    if (!m) {
      fail.push(`R1: H2 heading (line ${i + 1}) is not a valid release heading "## [X.Y.Z] - YYYY-MM-DD": ${JSON.stringify(line)}`);
      return;
    }
    const [, version, date] = m;
    // R3: real ISO date, not in the future.
    const d = new Date(date + "T00:00:00Z");
    if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== date) fail.push(`R3: ${version} has an invalid calendar date "${date}".`);
    else if (date > today) fail.push(`R3: ${version} is dated "${date}", in the future (today is ${today}).`);
    releases.push({ version, date, line: i + 1 });
    bracketLabels.push(version);
  } else if (/^### /.test(line)) {
    // R4: section vocab where sections are used.
    const s = line.slice(4).trim();
    currentSection = s;
    if (!SECTIONS.has(s)) fail.push(`R4: invalid section heading "### ${s}" (line ${i + 1}). Allowed: ${[...SECTIONS].join(", ")}.`);
  }
});

// R2 count
if (unreleasedCount > 1) fail.push(`R2: "## [Unreleased]" appears ${unreleasedCount} times; it must appear exactly once.`);

if (releases.length === 0) fail.push("R1: no valid release headings found.");
else {
  // R7: topmost release equals package.json version.
  if (releases[0].version !== pkg.version)
    fail.push(`R7: topmost release is [${releases[0].version}] but package.json is ${pkg.version} - the newest entry must match the release.`);
  // R6: strictly descending, no duplicates.
  for (let i = 1; i < releases.length; i++) {
    const c = cmp(releases[i - 1].version, releases[i].version);
    if (c === 0) fail.push(`R6: duplicate version [${releases[i].version}] (line ${releases[i].line}).`);
    else if (c < 0) fail.push(`R6: [${releases[i - 1].version}] then [${releases[i].version}] is out of order - releases must strictly descend by SemVer.`);
  }
}

// R8: every bracket label has a reference-link definition at the foot.
const defined = new Set([...raw.matchAll(/^\[([^\]]+)\]:\s*https?:\/\/\S+$/gm)].map((m) => m[1]));
for (const label of bracketLabels)
  if (!defined.has(label)) fail.push(`R8: "[${label}]" has no reference-link definition (add "[${label}]: https://..." at the file foot).`);

if (fail.length > 0) {
  console.error(
    `\n  CHANGELOG.md does not match the Keep a Changelog format standard.\n` +
      `  One grammar fleet-wide is what keeps the release / LOG / OSV parsers from\n` +
      `  breaking. Canonical shape: "## [X.Y.Z] - YYYY-MM-DD" (no 'v' in brackets),\n` +
      `  sections from {${[...SECTIONS].join(", ")}}, a reference-link footer, no BOM.\n`,
  );
  for (const f of fail) console.error(`  - ${f}`);
  console.error("");
  process.exit(1);
}

console.log(`CHANGELOG.md format OK: ${releases.length} releases, Keep a Changelog + SemVer, top=[${releases[0].version}] matches package.json.`);
