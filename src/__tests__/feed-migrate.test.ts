import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  parseChunks,
  planMigration,
  applyMigration,
  parseArgs,
  renderCatalogLine,
} from "../../scripts/feed-migrate.mjs";

const SRC = [
  "const FEED_CHUNK_0: FeedIOC[] = [",
  "  // Imported from GitHub Advisory Database (2026-01-01) - see docs/threat-feed-sources.md",
  '  { type: "package", value: "a@1.0.0", severity: "critical", firstSeen: "2026-01-01" },',
  '  { type: "package", value: "b@1.0.0", severity: "critical", firstSeen: "2026-01-02" },',
  "",
  "  // Some campaign (January 2026). Two lines of rationale that must survive",
  "  // whatever the migration does to the entries underneath it.",
  '  { type: "package", value: "c@1.0.0", severity: "critical", campaign: "x", firstSeen: "2026-01-03" },',
  '  { type: "ip", value: "203.0.113.9", severity: "critical", firstSeen: "2026-01-03" },',
  "];",
].join("\n");

describe("parseChunks", () => {
  it("separates importer headers from curated blocks", () => {
    const groups = parseChunks(SRC);
    expect(groups).toHaveLength(2);

    expect(groups[0].isCurated).toBe(false);
    expect(groups[0].header).toHaveLength(1);
    expect(groups[0].entries.map((e) => e.value)).toEqual(["a@1.0.0", "b@1.0.0"]);

    expect(groups[1].isCurated).toBe(true);
    expect(groups[1].header).toHaveLength(2);
    expect(groups[1].entries.map((e) => e.value)).toEqual(["c@1.0.0", "203.0.113.9"]);
  });

  it("extracts the fields the partition rules need", () => {
    const [imported, curated] = parseChunks(SRC);
    expect(imported.entries[0]).toMatchObject({
      value: "a@1.0.0",
      firstSeen: "2026-01-01",
      hasCampaignField: false,
      isPackage: true,
    });
    expect(curated.entries[0].hasCampaignField).toBe(true);
    expect(curated.entries[1].isPackage).toBe(false);
  });

  // The migration deletes entry lines by exact identity, so a parser that
  // reformats or trims them would delete the wrong thing, or nothing.
  it("preserves each entry's exact source line", () => {
    const groups = parseChunks(SRC);
    expect(groups[0].entries[0].line).toBe(
      '  { type: "package", value: "a@1.0.0", severity: "critical", firstSeen: "2026-01-01" },',
    );
  });

  it("ignores anything outside a FEED_CHUNK literal", () => {
    const noise =
      'const OTHER = [\n  { type: "package", value: "z@1", severity: "critical" },\n];\n' + SRC;
    const groups = parseChunks(noise);
    expect(groups.flatMap((g) => g.entries).some((e) => e.value === "z@1")).toBe(false);
  });

  it("handles CRLF sources, which is what a Windows checkout has", () => {
    const groups = parseChunks(SRC.replace(/\n/g, "\r\n"));
    expect(groups).toHaveLength(2);
    expect(groups[0].entries).toHaveLength(2);
    // The stored line must round-trip against the CRLF source, or an exact
    // match on it will never find anything to delete.
    expect(SRC.replace(/\n/g, "\r\n").split("\r\n")).toContain(groups[0].entries[0].line);
  });

  it("treats an entry with no comment above it as uncurated", () => {
    const bare = [
      "const FEED_CHUNK_0: FeedIOC[] = [",
      '  { type: "package", value: "n@1", severity: "critical", firstSeen: "2026-01-01" },',
      "];",
    ].join("\n");
    const groups = parseChunks(bare);
    expect(groups).toHaveLength(1);
    expect(groups[0].isCurated).toBe(false);
    expect(groups[0].header).toEqual([]);
  });
});

describe("parseChunks against the real file", () => {
  // The control that matters: the entry count must equal feed.json's, or the
  // parser is dropping lines and every later migration step is built on a short
  // read. A migration that silently sees fewer entries than exist would leave
  // the missed ones in the bundle with no error.
  it("finds every entry the generated feed contains", () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    const source = fs.readFileSync(path.join(repoRoot, "src", "threat-intel.ts"), "utf8");
    const feed = JSON.parse(fs.readFileSync(path.join(repoRoot, "feed.json"), "utf8"));

    const groups = parseChunks(source);
    const entries = groups.reduce((n, g) => n + g.entries.length, 0);
    expect(entries).toBe(feed.entryCount);
  });

  it("separates the real file into importer and curated groups", () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    const source = fs.readFileSync(path.join(repoRoot, "src", "threat-intel.ts"), "utf8");
    const groups = parseChunks(source);

    const curated = groups.filter((g) => g.isCurated);
    const imported = groups.filter((g) => !g.isCurated);

    // Both kinds must be present. If curated ever reads zero the anchor rule
    // protects nothing, and the 706 comment lines it exists for are at risk.
    expect(curated.length).toBeGreaterThan(0);
    expect(imported.length).toBeGreaterThan(0);
    expect(curated.reduce((n, g) => n + g.header.length, 0)).toBeGreaterThan(100);
  });
});

// ---------------------------------------------------------------------------
// planMigration: which entries move, and which headers may be removed.
// ---------------------------------------------------------------------------

const CONFIG = {
  bundleCutoffDate: "2026-06-01",
  maxBundledEntries: 15000,
  maxBundleBytes: 2097152,
};

const chunk = (...lines: string[]) =>
  ["const FEED_CHUNK_0: FeedIOC[] = [", ...lines, "];"].join("\n");
const old = (v: string, extra = "") =>
  `  { type: "package", value: "${v}", severity: "critical"${extra}, firstSeen: "2026-01-01" },`;
const recent = (v: string) =>
  `  { type: "package", value: "${v}", severity: "critical", firstSeen: "2026-09-01" },`;
const IMPORTED = "  // Imported from GitHub Advisory Database (2026-01-01)";
const OTHER_IMPORT = "  // Imported from OSV (2026-09-01)";

describe("planMigration", () => {
  it("moves an old plain package under an importer header", () => {
    const plan = planMigration(chunk(IMPORTED, old("a@1")), CONFIG);
    expect(plan.move.map((m) => m.value)).toEqual(["a@1"]);
  });

  it("keeps a recent package", () => {
    const plan = planMigration(chunk(IMPORTED, recent("b@1")), CONFIG);
    expect(plan.move).toEqual([]);
  });

  it("keeps an old entry that carries a campaign field", () => {
    const plan = planMigration(chunk(IMPORTED, old("c@1", ', campaign: "x"')), CONFIG);
    expect(plan.move).toEqual([]);
  });

  // Rule 3, the comment anchor. Curation in this repository lives in COMMENTS,
  // not in fields: 60 of 1,094 comment-anchored entries carry no campaign or
  // family. Without this rule their rationale is orphaned as they age past the
  // cutoff, describing a file that no longer contains them.
  it("keeps an old plain package beneath a CURATED comment block", () => {
    const plan = planMigration(
      chunk("  // Hand-added because the importer could not reach it.", old("d@1")),
      CONFIG,
    );
    expect(plan.move).toEqual([]);
  });

  it("removes an importer header only when every entry beneath it moved", () => {
    const all = planMigration(chunk(IMPORTED, old("e@1"), old("f@1")), CONFIG);
    expect(all.groups[0].removeHeader).toBe(true);

    const split = planMigration(chunk(IMPORTED, old("g@1"), recent("h@1")), CONFIG);
    expect(split.groups[0].removeHeader).toBe(false);
    expect(split.move.map((m) => m.value)).toEqual(["g@1"]);
  });

  // The fixture must be an entry that WOULD move but for rule 3. An earlier
  // version used one carrying a campaign field, so rule 2 kept it and the
  // curated path was never exercised: the test passed without the anchor doing
  // anything, which is the failure mode this whole file exists to catch.
  it("keeps a curated block whole: no entry moves, so its header stays", () => {
    const plan = planMigration(chunk("  // Curated rationale.", old("i@1")), CONFIG);
    expect(plan.move).toEqual([]);
    expect(plan.groups[0].movedCount).toBe(0);
    expect(plan.groups[0].removeHeader).toBe(false);
  });

  // Why removeHeader needs no empty-group guard: parseChunks opens a group only
  // on an entry line, so a comment with nothing beneath it yields NO group and
  // there is nothing to remove. Asserting that structural fact is the control;
  // asserting it through planMigration was vacuous, because `.every()` over an
  // empty array is true no matter what removeHeader computes.
  it("produces no group at all for a header with no entries beneath it", () => {
    expect(parseChunks(chunk(IMPORTED))).toEqual([]);
    expect(planMigration(chunk(IMPORTED), CONFIG).groups).toEqual([]);
  });

  it("accounts for every entry: move plus keep equals the total", () => {
    const plan = planMigration(
      chunk(IMPORTED, old("j@1"), recent("k@1"), old("l@1", ', family: "f"')),
      CONFIG,
    );
    expect(plan.move.length + plan.keep).toBe(3);
  });

  // Header TEXT is not unique. The importer writes the same batch header into
  // every chunk it touches on a given day, so in the real file 745 distinct
  // texts cover 792 header lines, and two of those texts head a fully-moved
  // group AND a group that keeps entries. Removing headers by text would strip
  // the header from the second one, orphaning 251 entries from their
  // provenance. These two groups are identical in every field except their
  // indices, so the index is the only thing that can tell them apart.
  it("separates two groups that share the exact same header text", () => {
    const src = [
      "const FEED_CHUNK_0: FeedIOC[] = [",
      IMPORTED,
      old("m@1"),
      "];",
      "const FEED_CHUNK_1: FeedIOC[] = [",
      IMPORTED,
      old("n@1"),
      recent("o@1"),
      "];",
    ].join("\n");
    const plan = planMigration(src, CONFIG);

    expect(plan.groups).toHaveLength(2);
    expect(plan.groups[0].header).toEqual(plan.groups[1].header);
    expect(plan.groups[0].removeHeader).toBe(true);
    expect(plan.groups[1].removeHeader).toBe(false);

    const removable = new Set(
      plan.groups.filter((g) => g.removeHeader).flatMap((g) => g.headerIndices),
    );
    const kept = plan.groups.filter((g) => !g.removeHeader).flatMap((g) => g.headerIndices);
    expect(kept.filter((i) => removable.has(i))).toEqual([]);
  });

  it("gives every moved entry a distinct integer line index", () => {
    const plan = planMigration(chunk(IMPORTED, old("p@1"), old("q@1")), CONFIG);
    expect(plan.move.every((m) => Number.isInteger(m.index))).toBe(true);
    expect(new Set(plan.move.map((m) => m.index)).size).toBe(plan.move.length);
  });
});

describe("planMigration against the real file", () => {
  const realSource = () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    return fs.readFileSync(path.join(repoRoot, "src", "threat-intel.ts"), "utf8");
  };

  it("accounts for every entry and never moves a comment-anchored one", () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    const source = realSource();
    const feed = JSON.parse(fs.readFileSync(path.join(repoRoot, "feed.json"), "utf8"));

    const plan = planMigration(source, { ...CONFIG, bundleCutoffDate: "2026-08-17" });
    expect(plan.move.length + plan.keep).toBe(feed.entryCount);

    // No entry under a curated block may appear in the move set.
    const curatedLines = new Set(
      parseChunks(source).filter((g) => g.isCurated).flatMap((g) => g.entries.map((e) => e.line)),
    );
    expect(plan.move.filter((m) => curatedLines.has(m.line))).toEqual([]);
  });

  // The migration has run. Re-running it at the SAME cutoff must move nothing:
  // everything that qualified is already in the catalog, and a second pass that
  // found work to do would mean the two stores disagree about where an entry
  // belongs. This is the property that makes the recurring release step safe to
  // run unconditionally.
  it("is idempotent at the committed cutoff", () => {
    const plan = planMigration(realSource(), {
      ...CONFIG,
      bundleCutoffDate: "2026-08-17",
    });
    expect(plan.move).toEqual([]);
    expect(plan.groups.filter((g) => g.removeHeader)).toEqual([]);
  });

  // Moving the cutoff forward must still find work, or the plan is inert for a
  // reason other than "already migrated" and the idempotence above proves
  // nothing. This is the control for that test.
  it("still finds work when the cutoff moves forward", () => {
    const plan = planMigration(realSource(), {
      ...CONFIG,
      bundleCutoffDate: "2026-09-16",
    });
    expect(plan.move.length).toBeGreaterThan(0);
  });

  // The header-collision hazard is covered by the synthetic case above. It is
  // no longer observable in the real file: the migration removed the duplicated
  // importer headers whose groups were fully moved, which is exactly what it was
  // supposed to do. Asserting the hazard still exists here would fail for the
  // right reason and read like a regression.
  it("never marks a header line for removal that another group still needs", () => {
    const plan = planMigration(realSource(), {
      ...CONFIG,
      bundleCutoffDate: "2026-09-16",
    });
    const removableIdx = new Set(
      plan.groups.filter((g) => g.removeHeader).flatMap((g) => g.headerIndices),
    );
    const keptIdx = plan.groups.filter((g) => !g.removeHeader).flatMap((g) => g.headerIndices);
    expect(keptIdx.filter((i) => removableIdx.has(i))).toEqual([]);
  });
});

describe("parseArgs", () => {
  it("writes only with --write", () => {
    expect(parseArgs(["--write"]).write).toBe(true);
    expect(parseArgs([]).write).toBe(false);
    expect(parseArgs(["--dry-run"]).write).toBe(false);
  });

  // A wrapper or an operator appending --dry-run to an existing write command
  // is asking for nothing to happen. The cautious reading of a contradictory
  // pair is the only safe one when the operation deletes entries.
  it("refuses to write when --write and --dry-run are both given", () => {
    const parsed = parseArgs(["--write", "--dry-run"]);
    expect(parsed.write).toBe(false);
    expect(parsed.conflict).toBe(true);
  });

  it("reports an unrecognised option instead of ignoring it", () => {
    expect(parseArgs(["--wrtie"]).unknown).toEqual(["--wrtie"]);
  });
});
