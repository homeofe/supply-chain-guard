// check-feed-partition.mjs - gate: is every IOC in the right store?
//
// With two authored stores instead of one generated store, nothing structurally
// prevents an entry from landing in both or in the wrong one. This gate is what
// replaces that structural guarantee, so it fails the build rather than warning.
//
// Design: docs/threat-feed-catalog-decoupling-design.md sections 4.1 and 4.2.

import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { extractBundledEntries } from "./generate-feed.mjs";
import { partitionTarget, loadPartitionConfig } from "./feed-partition.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Relative path of the catalog store, for DISPLAY: a forward-slash literal, so
 * a violation reads identically on every platform and can be grepped for in CI
 * logs or asserted by a test. path.join is used only to touch the filesystem.
 */
export const CATALOG_PATH = "data/threat-catalog.jsonl";

export function checkPartition(root = repoRoot) {
  const config = loadPartitionConfig(root);
  const violations = [];

  const bundleValues = new Set(extractBundledEntries(root).map((e) => e.value));

  const catalogFile = join(root, "data", "threat-catalog.jsonl");
  if (!existsSync(catalogFile)) {
    return [`${CATALOG_PATH} is missing; it must exist, even empty.`];
  }

  const catalogValues = new Set();
  readFileSync(catalogFile, "utf8").split("\n").forEach((line, i) => {
    if (line.trim() === "") return;
    const at = `${CATALOG_PATH} line ${i + 1}`;

    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      violations.push(`${at}: not valid JSON`);
      return;
    }
    // SCOPE: this gate checks PLACEMENT, not validity. It needs only enough
    // shape to answer "which store does this belong in".
    //
    // The full FeedIOC contract is enforced by "the committed catalog is a
    // valid feed document" in src/__tests__/feed-partition.test.ts, which
    // imports the real isValidFeedIOC. It is not duplicated here on purpose: a
    // .mjs copy of a validator with per-type value shapes, timestamp offsets
    // and a lastSeen ordering rule would drift from the original, and a gate
    // that disagrees with the loader is worse than one that defers to it.
    //
    // Consequence to know: `npm run build` alone does not catch an entry the
    // loader would quarantine. `npm test` does, and CI runs both.
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)
        || typeof entry.value !== "string") {
      violations.push(`${at}: not a FeedIOC object`);
      return;
    }

    if (catalogValues.has(entry.value)) violations.push(`${at}: duplicate value ${entry.value}`);
    catalogValues.add(entry.value);

    if (bundleValues.has(entry.value)) {
      violations.push(`${entry.value} is in both stores; it must be in exactly one`);
    }

    // Atomic indicators are the highest-value detections in the feed and none
    // of them may leave the bundle silently. If one is about to, the entry is
    // under-documented: the fix is the campaign or family it should have had,
    // which 401 of 404 non-package entries already carry.
    if (entry.type !== undefined && entry.type !== "package") {
      violations.push(
        `${at}: ${entry.type} indicator in the catalog. Atomic indicators must stay in the ` +
        `bundle: give it a campaign or family field rather than moving it.`,
      );
      return;
    }

    if (partitionTarget(entry, config) === "bundle") {
      violations.push(
        `${at}: ${entry.value} is in the catalog but belongs in the bundle by the partition policy`,
      );
    }
  });

  return violations;
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const violations = checkPartition();
  if (violations.length > 0) {
    console.error(`\n  feed partition: ${violations.length} violation(s)\n`);
    for (const v of violations.slice(0, 25)) console.error(`    ${v}`);
    if (violations.length > 25) console.error(`    ... and ${violations.length - 25} more`);
    console.error("");
    process.exit(1);
  }
  console.log("feed partition OK: every IOC is in exactly one store, correctly placed.");
}
