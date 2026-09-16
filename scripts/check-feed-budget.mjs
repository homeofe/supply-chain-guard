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
import { loadPartitionConfig } from "./feed-partition.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * The date that would bring the bundle back to maxBundledEntries: the firstSeen
 * of the Nth newest entry that the cutoff can actually move.
 *
 * Curated entries and undatable ones are immovable by the policy, so they are
 * excluded from the ranking. Returns null when no date can achieve the limit,
 * which happens when the immovable entries alone already exceed it, and that is
 * a different problem than a stale cutoff.
 */
export function suggestCutoff(entries, maxBundledEntries) {
  const movable = [];
  let immovable = 0;
  for (const e of entries) {
    if (e.campaign !== undefined || e.family !== undefined) { immovable++; continue; }
    const d = String(e.firstSeen ?? "");
    if (!ISO_DATE.test(d)) { immovable++; continue; }
    movable.push(d);
  }
  const room = maxBundledEntries - immovable;
  if (room <= 0 || room > movable.length) return null;
  movable.sort().reverse();
  return movable[room - 1];
}

export function checkBudget(root = repoRoot) {
  const config = loadPartitionConfig(root);
  const violations = [];

  const entries = extractBundledEntries(root);
  if (entries.length > config.maxBundledEntries) {
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
  if (violations.length > 0) {
    const suggestion = suggestCutoff(entries, config.maxBundledEntries);
    if (suggestion) {
      violations.push(
        `Suggested bundleCutoffDate: ${suggestion} ` +
        `(brings the bundle to ${config.maxBundledEntries} entries).`,
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
