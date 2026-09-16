// check-feed-budget.mjs - gate: the compiled bundle must stay inside its budget.
//
// The root cause of the deferral backlog was that no step in any workflow owned
// the feed's size, so it grew until one upstream event made it a crisis. This
// gate is the durable half of the fix: a release that would breach the budget
// cannot be built, and the remedy is to move bundleCutoffDate forward and
// migrate, not to raise the limit reflexively.
//
// Design: docs/threat-feed-catalog-decoupling-design.md section 6.

import { statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { extractBundledEntries } from "./generate-feed.mjs";
import { loadPartitionConfig, isoToEpoch } from "./feed-partition.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * A cutoff date that brings the bundle back inside maxBundledEntries.
 *
 * Curated and undatable entries are immovable by the policy, so they are
 * excluded from the ranking and counted against the budget up front.
 *
 * Dates are day-granular and partitionTarget keeps every entry whose firstSeen
 * is >= the cutoff, so the answer has to be a DATE BOUNDARY, not the Nth entry.
 * Picking the Nth entry's date is wrong whenever entries share a date: with a
 * limit of 1 and two entries dated 2026-09-05 it would suggest 2026-09-05 and
 * keep both, leaving the gate red after applying its own advertised remedy.
 *
 * So walk the distinct dates newest first and take the largest boundary whose
 * cumulative count still fits. Returns null when even the newest date group
 * does not fit, or when the immovable entries alone already exceed the limit;
 * both are different problems from a stale cutoff and deserve a different
 * message rather than a date that cannot work.
 */
export function suggestCutoff(entries, maxBundledEntries) {
  const counts = new Map();
  let immovable = 0;
  for (const e of entries) {
    if (e.campaign !== undefined || e.family !== undefined) { immovable++; continue; }
    // The policy's own parser, not a second looser one. A shape-only test
    // accepts 2026-02-31, which partitionTarget rejects and therefore keeps in
    // the bundle, so counting it as movable produced a date that cannot work.
    const d = String(e.firstSeen ?? "");
    if (isoToEpoch(d) === null) { immovable++; continue; }
    counts.set(d, (counts.get(d) ?? 0) + 1);
  }

  const room = maxBundledEntries - immovable;
  if (room <= 0) return null;

  let cumulative = 0;
  let best = null;
  for (const date of [...counts.keys()].sort().reverse()) {
    const next = cumulative + counts.get(date);
    if (next > room) break;
    cumulative = next;
    best = date;
  }
  // The caller reports the count this boundary actually produces, so return it
  // rather than letting the message assume the limit was reached exactly.
  return best === null ? null : { date: best, bundledEntries: immovable + cumulative };
}

export function checkBudget(root = repoRoot) {
  const config = loadPartitionConfig(root);
  const violations = [];

  const entries = extractBundledEntries(root);
  const overEntryLimit = entries.length > config.maxBundledEntries;
  if (overEntryLimit) {
    violations.push(
      `${entries.length} bundled entries exceeds ${config.maxBundledEntries}. ` +
      `Move bundleCutoffDate forward in feed-partition.config.json and migrate.`,
    );
  }

  const bytes = statSync(join(root, "src", "threat-intel.ts")).size;
  if (bytes > config.maxBundleBytes) {
    violations.push(
      `src/threat-intel.ts is ${bytes} bytes, which exceeds the ${config.maxBundleBytes} byte ` +
      `budget. Move bundleCutoffDate forward in feed-partition.config.json and migrate.`,
    );
  }

  // Name the value, not just the action. The cutoff is the one recurring manual
  // input in this design, and a gate that says "move it forward" without saying
  // where is a gate that gets guessed at.
  //
  // Only when the ENTRY limit is what broke, because that is the constraint
  // suggestCutoff solves. On a byte-only breach it would return a boundary that
  // moves nothing, and the operator would apply the advertised remedy and stay
  // red with no indication why.
  if (overEntryLimit) {
    const suggestion = suggestCutoff(entries, config.maxBundledEntries);
    if (suggestion) {
      violations.push(
        `Suggested bundleCutoffDate: ${suggestion.date} ` +
        `(brings the bundle to ${suggestion.bundledEntries} entries).`,
      );
    }
  }

  return violations;
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const violations = checkBudget();
  if (violations.length > 0) {
    console.error("");
    for (const v of violations) console.error(`  ${v}`);
    console.error("");
    process.exit(1);
  }
  console.log("feed budget OK.");
}
