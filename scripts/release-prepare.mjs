// release-prepare.mjs - move the bundle cutoff, as part of a release.
//
// The cutoff is NOT derived from the clock at build time: that would make the
// generated files a function of the day they were generated, so the same commit
// would produce different output tomorrow and check:feed would fail on an
// untouched tree. It is NOT derived from the newest feed entry either: that
// would slide the window on every daily import, putting a migration inside
// every threat-intel pull request and burying the day's additions in hundreds
// of unrelated removals. Reviewing those diffs is a security control here.
//
// Binding it to the release gets the automation without either cost: a release
// is already a deliberate, reviewed, gated event that regenerates many files.
//
// Design: docs/threat-feed-catalog-decoupling-design.md section 5.1.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const WINDOW_DAYS = 30;

/**
 * The cutoff date for a release cut at `now`.
 *
 * `now` is a parameter, never `new Date()` read inside: a function that reads
 * the clock cannot be tested against a fixed expectation, and this repository
 * has already lost a day to clock-dependent tests that passed until the date
 * rolled over.
 */
export function cutoffFor(now, windowDays = WINDOW_DAYS) {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new TypeError("cutoffFor requires a valid Date");
  }
  if (!Number.isInteger(windowDays) || windowDays < 0) {
    throw new TypeError(`windowDays must be a non-negative integer, got ${windowDays}`);
  }
  return new Date(now.getTime() - windowDays * 86_400_000).toISOString().slice(0, 10);
}

/**
 * Move the cutoff forward, refusing to move it backwards.
 *
 * Moving it backwards would not un-migrate anything: the entries are already in
 * the catalog and gone from the bundle. It would instead make check:feed-partition
 * red on entries that are correctly placed, with a message about a policy
 * violation that nobody introduced.
 */
export function advanceCutoff(config, next) {
  if (next < config.bundleCutoffDate) {
    throw new Error(
      `refusing to move bundleCutoffDate backwards, ${config.bundleCutoffDate} -> ${next}. ` +
        `Entries already migrated are not returned to the bundle by moving the date back, ` +
        `so this only makes the placement gate red on correctly placed entries.`,
    );
  }
  return { ...config, bundleCutoffDate: next };
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  const path = join(repoRoot, "feed-partition.config.json");
  const config = JSON.parse(readFileSync(path, "utf8"));
  const previous = config.bundleCutoffDate;
  const next = cutoffFor(new Date());

  if (next === previous) {
    console.log(`bundleCutoffDate already ${previous}; nothing to do.`);
  } else {
    writeFileSync(path, `${JSON.stringify(advanceCutoff(config, next), null, 2)}\n`);
    console.log(`bundleCutoffDate ${previous} -> ${next}`);
    console.log("Next: node scripts/feed-migrate.mjs --write");
  }
}
