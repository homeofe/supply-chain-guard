#!/usr/bin/env node
// Verify that CHANGELOG.md contains a changelog heading for the current package.json version.
// Exits 1 if missing. Wired into `npm run build` so a release cannot ship without docs.
//
// Background: the changelog has drifted behind tags twice (v5.2.5-v5.2.7 backfilled
// in commit 6d0e887, v5.2.9-v5.2.13 backfilled later). Memory + checklist were not enough.
// Since v5.2.45 the changelog lives in CHANGELOG.md (moved out of README.md to keep the
// npm/GitHub landing page readable); this gate moved with it.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const changelog = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8");

const version = pkg.version;
// Keep a Changelog heading (no 'v' inside the brackets). Full grammar is enforced
// by check:changelog-format; this gate just guarantees the current release exists.
const heading = new RegExp(`^## \\[${version.replace(/\./g, "\\.")}\\] - `, "m");

if (!heading.test(changelog)) {
  console.error(
    `\n  CHANGELOG.md is missing an entry for ${version}.\n` +
      `  Add a section below "## [Unreleased]" in Keep a Changelog form:\n\n` +
      `    ## [${version}] - YYYY-MM-DD\n` +
      `    ### Added\n` +
      `    - what changed\n\n` +
      `  and a reference-link line at the file foot. Release cannot ship without this.\n`,
  );
  process.exit(1);
}

console.log(`CHANGELOG.md contains entry for ${version}.`);
