// feed-migrate.mjs - move entries out of the compiled bundle into the catalog.
//
// This parses src/threat-intel.ts at the LINE level rather than through
// extractBundledEntries(), which evaluates the array in a node:vm sandbox and
// therefore discards every comment. The comments are the point: the chunk
// literals carry hundreds of lines of curated rationale (why an apex is
// deliberately not listed, why a maintainer is a victim rather than an
// indicator, why an entry is version-pinned instead of name-blocked), and
// FeedIOC has no field for any of it. A migration that cannot see those
// comments cannot avoid orphaning them.
//
// Design: docs/threat-feed-catalog-decoupling-design.md sections 4.1 and 4.2.

import { readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

import { partitionTarget, loadPartitionConfig } from "./feed-partition.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const CATALOG_RELATIVE_PATH = "data/threat-catalog.jsonl";

const CHUNK_START = /^const FEED_CHUNK_\d+: FeedIOC\[\] = \[/;
const CHUNK_END = /^\];/;
const COMMENT = /^\s*\/\//;
const ENTRY = /^\s*\{ type:/;
const IMPORTER_HEADER = /Imported from/i;

/**
 * Group the chunk literals into {header comments, entries beneath them}.
 *
 * A group starts at a run of comment lines and runs until the next such run, so
 * every entry knows which comment block it sits under.
 *
 * Every line carries its zero-based `index`, and the migration deletes by that
 * index rather than by string identity. Entry lines happen to be unique in the
 * file today (20,969 distinct of 20,969), but header lines are NOT: the importer
 * writes the same batch header into every chunk it touches on a given day, so
 * 745 distinct header texts cover 792 header lines. Two of those texts head a
 * fully-moved group AND a group that keeps entries, and deleting by text would
 * strip the header from the second one, silently orphaning 251 entries from
 * their provenance. Indices are correct whether or not two lines read alike.
 *
 * `line` is still the exact source line, unmodified, so the diff can be checked
 * against what was planned.
 *
 * `isCurated` distinguishes a human-authored block from an importer batch
 * header. That distinction is the whole basis of the comment anchor: the
 * importer writes its own one-line header before each batch, so its output is
 * never mistaken for curated rationale.
 */
export function parseChunks(source) {
  const groups = [];
  // Split on either ending and store each line WITHOUT its terminator, which
  // is exactly what applyMigration compares against when it walks the source
  // the same way. Storing a trailing \r here would match nothing on a CRLF
  // checkout, and the migration would silently delete no entries at all.
  const lines = source.split(/\r?\n/);

  let inChunk = false;
  let pending = [];
  let current = null;

  const flush = () => {
    if (current) {
      groups.push(current);
      current = null;
    }
  };

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (CHUNK_START.test(line)) { inChunk = true; flush(); pending = []; continue; }
    if (inChunk && CHUNK_END.test(line)) { inChunk = false; flush(); pending = []; continue; }
    if (!inChunk) continue;

    if (COMMENT.test(line)) {
      if (current) flush();
      pending.push({ line, index });
      continue;
    }

    if (ENTRY.test(line)) {
      if (!current) {
        current = {
          header: pending.map((p) => p.line),
          headerIndices: pending.map((p) => p.index),
          isCurated: pending.length > 0 && !IMPORTER_HEADER.test(pending[0].line),
          entries: [],
        };
        pending = [];
      }
      const value = /value: "([^"]+)"/.exec(line);
      const firstSeen = /firstSeen: "([^"]+)"/.exec(line);
      current.entries.push({
        line,
        index,
        value: value ? value[1] : "",
        firstSeen: firstSeen ? firstSeen[1] : null,
        hasCampaignField: /campaign:|family:/.test(line),
        isPackage: /type: "package"/.test(line),
      });
      continue;
    }
    // A blank line keeps the current group open: the importer separates batches
    // with one, and closing the group there would orphan the header.
  }
  flush();
  return groups;
}

/**
 * Decide what moves.
 *
 * Rules 1, 2 and 4 come from partitionTarget(), which the importer and the
 * placement gate also use, so an entry cannot mean different things in
 * different places.
 *
 * Rule 3, the comment anchor, is applied HERE and only here: an entry sitting
 * beneath a curated comment block never moves. Curation in this repository is
 * expressed in COMMENTS, not in fields, and 60 of the 1,094 comment-anchored
 * entries carry no campaign or family at all. Without this rule their
 * rationale is orphaned as they age past the cutoff, left describing a file
 * that no longer contains what it describes.
 *
 * The importer never needs rule 3, because its own output is written beneath
 * an importer batch header, which isCurated explicitly does not match. That is
 * what lets partitionTarget stay a pure function of the entry.
 */
export function planMigration(source, config) {
  const groups = parseChunks(source);
  const move = [];
  let keep = 0;
  const report = [];

  for (const group of groups) {
    let moved = 0;
    for (const entry of group.entries) {
      // Reconstruct only what the rule reads. partitionTarget looks at
      // campaign/family presence and firstSeen; the parser cannot know which
      // of the two curation fields was present, and the rule does not care.
      const immovable =
        group.isCurated ||
        partitionTarget(
          {
            type: entry.isPackage ? "package" : "other",
            value: entry.value,
            firstSeen: entry.firstSeen ?? undefined,
            ...(entry.hasCampaignField ? { campaign: "present" } : {}),
          },
          config,
        ) === "bundle";

      if (immovable) { keep++; continue; }
      move.push({ value: entry.value, line: entry.line, index: entry.index });
      moved++;
    }

    // Rule 3 makes every entry under a curated block immovable, so a curated
    // group can never report a moved entry. This is an ASSERTION, not a guard:
    // it is unreachable today and is meant to stay that way. Written as a
    // conjunct in removeHeader it was indistinguishable from dead code - cutting
    // it left every test green, so it read as protection while protecting
    // nothing. As an assertion it is both honest and stronger: if rule 3 is ever
    // narrowed, the damage is not a removed header but removed curated ENTRIES,
    // and the migration stops outright instead of quietly orphaning rationale.
    if (group.isCurated && moved > 0) {
      throw new Error(
        `curated block reported ${moved} moved entries, which rule 3 forbids: ` +
          (group.header[0] ?? "(no header)"),
      );
    }

    report.push({
      header: group.header,
      headerIndices: group.headerIndices,
      // parseChunks opens a group only on an entry line, so entries.length is
      // never 0 here and "every entry moved" cannot be vacuously true.
      removeHeader: moved === group.entries.length,
      movedCount: moved,
      keptCount: group.entries.length - moved,
    });
  }

  return { move, keep, groups: report };
}

// The catalog is a published artifact whose digest is checked by consumers, so
// its bytes must be reproducible: same entries in, same file out, on any
// platform. That means a fixed key order rather than whatever order the source
// literal happened to use, and LF endings (see .gitattributes).
//
// The order mirrors FEED_ENTRY_KEYS in src/threat-intel.ts. It is deliberately
// a closed list: an entry carrying a field not on it aborts the migration
// rather than silently publishing a field the loader will not read back. The
// legacy `note` and `ecosystem` fields were dropped from FEED_ENTRY_KEYS in
// Phase 1, and this is what stops them reappearing through the catalog.
const CATALOG_KEY_ORDER = [
  "type",
  "value",
  "severity",
  "confidence",
  "family",
  "campaign",
  "source",
  "firstSeen",
  "lastSeen",
];

export function renderCatalogLine(entry) {
  const unknown = Object.keys(entry).filter((k) => !CATALOG_KEY_ORDER.includes(k));
  if (unknown.length > 0) {
    throw new Error(
      `entry ${entry.value} carries field(s) the catalog has no place for: ` +
        `${unknown.join(", ")}. Add them to FEED_ENTRY_KEYS and CATALOG_KEY_ORDER ` +
        `together, or drop them before migrating.`,
    );
  }
  const out = {};
  for (const key of CATALOG_KEY_ORDER) {
    if (entry[key] !== undefined) out[key] = entry[key];
  }
  return JSON.stringify(out);
}

/**
 * Produce the rewritten source and the catalog lines, without writing anything.
 *
 * `entries` is the EVALUATED bundle from extractBundledEntries(): the parser
 * sees text and cannot produce a FeedIOC, the evaluator produces FeedIOCs and
 * cannot see line numbers, so the two are zipped by position. That
 * correspondence is checked rather than assumed, entry by entry, because if it
 * ever slipped the migration would write one indicator's line into the catalog
 * while deleting a different one from the bundle, and both files would still
 * look entirely plausible.
 *
 * Deletion is line-exact and by index: a kept line is never reformatted, so the
 * resulting diff is removals and nothing else.
 */
export function applyMigration(source, entries, config) {
  const plan = planMigration(source, config);
  const parsed = parseChunks(source).flatMap((g) => g.entries);

  if (parsed.length !== entries.length) {
    throw new Error(
      `the parser found ${parsed.length} entries but the evaluated bundle holds ` +
        `${entries.length}. One of them is reading src/threat-intel.ts wrongly, and ` +
        `migrating on a short read would strand the entries it could not see.`,
    );
  }
  for (let i = 0; i < parsed.length; i++) {
    if (parsed[i].value !== entries[i].value) {
      throw new Error(
        `entry ${i} is "${parsed[i].value}" to the parser and "${entries[i].value}" ` +
          `to the evaluator. The two walks of the file have diverged, so no line can ` +
          `be trusted to belong to the indicator beside it.`,
      );
    }
  }

  // extractBundledEntries refuses an empty BUNDLED_FEED, and rightly: an empty
  // bundle means the package ships no offline detection at all. Refuse here,
  // where the operator can still change the cutoff, rather than at the gate.
  if (plan.move.length >= entries.length) {
    throw new Error(
      `this cutoff moves all ${entries.length} entries and would leave BUNDLED_FEED ` +
        `empty. The bundle is the offline floor: it must keep something.`,
    );
  }

  const drop = new Set(plan.move.map((m) => m.index));
  for (const group of plan.groups) {
    if (group.removeHeader) {
      for (const index of group.headerIndices) drop.add(index);
    }
  }

  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  const lines = source.split(/\r?\n/);
  const nextSource = lines.filter((_, i) => !drop.has(i)).join(eol);

  const byIndex = new Map(parsed.map((p, i) => [p.index, entries[i]]));
  const moved = plan.move.map((m) => byIndex.get(m.index));
  const jsonl = moved.length > 0 ? moved.map(renderCatalogLine).join("\n") + "\n" : "";

  return { source: nextSource, jsonl, moved, plan, droppedLines: drop.size };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/**
 * Applying is OPT-IN, via --write.
 *
 * This rewrites a 3.7 MB source file and appends to a published artifact, and
 * the plan's sketch had it writing by default with --dry-run to opt out. That
 * is the wrong way round for a destructive operation whose blast radius is the
 * detection corpus of a security scanner: the safe outcome should be what
 * happens when the flag is forgotten or misspelled. --dry-run is still accepted
 * so the documented sequence keeps working, it is simply the default.
 */
function parseArgs(argv) {
  const write = argv.includes("--write");
  const unknown = argv.filter((a) => a.startsWith("--") && a !== "--write" && a !== "--dry-run");
  return { write, unknown };
}

async function main(argv) {
  const { write, unknown } = parseArgs(argv);
  if (unknown.length > 0) {
    console.error(`Unknown option(s): ${unknown.join(", ")}`);
    console.error("Usage: node scripts/feed-migrate.mjs [--write]");
    process.exitCode = 2;
    return;
  }

  const { extractBundledEntries } = await import("./generate-feed.mjs");
  const config = loadPartitionConfig(repoRoot);
  const target = join(repoRoot, "src", "threat-intel.ts");
  const source = readFileSync(target, "utf8");
  const entries = extractBundledEntries(repoRoot);
  const result = applyMigration(source, entries, config);

  const headerLines = result.droppedLines - result.plan.move.length;
  console.log(`migration plan (cutoff ${config.bundleCutoffDate}):`);
  console.log(`  move  : ${result.plan.move.length}`);
  console.log(`  keep  : ${result.plan.keep}`);
  console.log(`  total : ${result.plan.move.length + result.plan.keep}`);
  // Header LINES, not groups: one fully-moved group has no header at all, so
  // the group count says 44 where 43 lines are actually removed.
  console.log(`  header lines removed: ${headerLines}`);
  console.log(`  groups split        : ${
    result.plan.groups.filter((g) => g.movedCount > 0 && g.keptCount > 0).length
  }`);

  if (!write) {
    console.log("Nothing written. Re-run with --write to apply.");
    return;
  }

  // The catalog ACCUMULATES. Each release moves the cutoff forward and migrates
  // again, so overwriting would silently drop everything a previous release
  // moved. Appending is only safe while the two sets are disjoint, and they are
  // disjoint by construction because a migrated entry is no longer in the
  // bundle to be moved twice. "By construction" is exactly the kind of claim
  // that stops being true without anyone noticing, so it is checked.
  const catalogPath = join(repoRoot, "data", "threat-catalog.jsonl");
  const existing = readFileSync(catalogPath, "utf8");
  const existingValues = new Set(
    existing
      .split("\n")
      .filter((l) => l.trim() !== "")
      .map((l) => JSON.parse(l).value),
  );
  const collisions = result.moved.filter((e) => existingValues.has(e.value));
  if (collisions.length > 0) {
    console.error(
      `${collisions.length} entr${collisions.length === 1 ? "y is" : "ies are"} already in ` +
        `${CATALOG_RELATIVE_PATH} and would be appended a second time, starting with ` +
        `"${collisions[0].value}". The bundle and the catalog have drifted out of sync; ` +
        `resolve that before migrating.`,
    );
    process.exitCode = 1;
    return;
  }

  writeFileSync(target, result.source);
  appendFileSync(catalogPath, result.jsonl);
  console.log(
    `migrated ${result.moved.length} entries into ${CATALOG_RELATIVE_PATH} ` +
      `(now ${existingValues.size + result.moved.length} total).`,
  );
  console.log("Next: npm run feed:generate && npm run self-scan:generate && npm run handoff:refresh");
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  await main(process.argv.slice(2));
}
