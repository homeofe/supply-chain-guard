// feed-partition.mjs - the single routing rule deciding whether an IOC belongs
// in the compiled bundle (src/threat-intel.ts) or the downloadable catalog
// (data/threat-catalog.jsonl).
//
// Three callers: the importer when an entry is first written, the Phase 2
// migration when an existing bundled entry is moved, and
// check-feed-partition.mjs when validating placement. One rule, so placement
// cannot mean different things in different places.
//
// Design: docs/threat-feed-catalog-decoupling-design.md section 4.2.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * Parse an ISO date into a UTC epoch, or null when it is not a real calendar
 * date. Rejects values that parse but do not round-trip ("2026-02-31"), because
 * Date.UTC silently rolls those over into a later, wrong day.
 */
function isoToEpoch(value) {
  if (typeof value !== "string") return null;
  // Match the WHOLE value, never a slice of it. Slicing first accepts trailing
  // junk: "2020-01-01oops" would parse as a valid old date and route a
  // detection out of the bundle, which is the opposite of the documented
  // fail-open behaviour for unparsable dates. Measured on the v6.1.3 feed, all
  // 20,958 dated entries are exactly YYYY-MM-DD, so the slice bought nothing.
  const m = ISO_DATE.exec(value);
  if (!m) return null;
  const [, y, mo, d] = m;
  const epoch = Date.UTC(Number(y), Number(mo) - 1, Number(d));
  const back = new Date(epoch);
  // Year and month are sufficient. A day overflow always moves the month or
  // the year, so a third check on getUTCDate() can never be the one that
  // fires: measured across 14,784 candidate date strings, zero cases. It was
  // in an earlier draft and survived every mutation cut, which is what
  // identified it as unreachable rather than untested. Do not add it back.
  if (back.getUTCFullYear() !== Number(y)) return null;
  if (back.getUTCMonth() !== Number(mo) - 1) return null;
  return epoch;
}

/**
 * Read the committed partition policy, refusing a malformed one.
 *
 * The validation is not decoration. A missing or misspelled limit would return
 * undefined, and `entries.length > undefined` is false, so check:feed-budget
 * would report success for any bundle size: one typo in a committed config
 * silently disables the gate. A gate that fails open is worse than no gate,
 * because the build stays green while nobody is watching the thing it guards.
 */
export function loadPartitionConfig(root = repoRoot) {
  const raw = JSON.parse(readFileSync(join(root, "feed-partition.config.json"), "utf8"));

  const limit = (name) => {
    const v = raw[name];
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0) {
      throw new Error(
        `feed-partition.config.json: ${name} must be a finite non-negative number, got ${JSON.stringify(v)}`,
      );
    }
    return v;
  };

  if (typeof raw.bundleCutoffDate !== "string") {
    throw new Error(
      `feed-partition.config.json: bundleCutoffDate must be a string, got ${JSON.stringify(raw.bundleCutoffDate)}`,
    );
  }

  return {
    bundleCutoffDate: raw.bundleCutoffDate,
    maxBundledEntries: limit("maxBundledEntries"),
    maxBundleBytes: limit("maxBundleBytes"),
  };
}

/**
 * Where does this entry belong? Pure: depends only on the entry and the
 * committed config, never on the current date.
 *
 * Rule 2 (curation) is evaluated before rule 4 (the cutoff), so a hand-reviewed
 * campaign entry stays bundled at any age. Rule 1 is bounded by curation rather
 * than by type: an unbounded "all non-package entries stay" rule would let a
 * source that begins publishing atomic indicators in bulk grow the bundle
 * forever. check-feed-partition.mjs fails the build if an atomic indicator
 * would actually leave, so the bound cannot lose one silently.
 *
 * An entry with a missing or unparsable firstSeen stays in the bundle. Failing
 * closed toward MORE detection is the safe direction: the cost is a few bytes,
 * where guessing it out of the bundle would silently drop coverage.
 *
 * Rule 3, the curated-comment anchor, is NOT here. It needs a parse of
 * src/threat-intel.ts and applies only to the Phase 2 migration, which is the
 * only caller that moves entries a human already authored. Keeping it out of
 * this function is what lets the importer share the rule.
 */
export function partitionTarget(entry, config) {
  // Rule 2: curated entries stay, whatever their type or age.
  if (entry.campaign !== undefined || entry.family !== undefined) return "bundle";

  const cutoff = isoToEpoch(config.bundleCutoffDate);
  if (cutoff === null) {
    throw new Error(
      `feed-partition.config.json: bundleCutoffDate "${config.bundleCutoffDate}" is not a valid ISO date`,
    );
  }

  const seen = isoToEpoch(entry.firstSeen);
  if (seen === null) return "bundle";

  return seen >= cutoff ? "bundle" : "catalog";
}
