import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  parseChunks,
  planMigration,
  applyMigration,
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
  it("accounts for every entry and never moves a comment-anchored one", () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    const source = fs.readFileSync(path.join(repoRoot, "src", "threat-intel.ts"), "utf8");
    const feed = JSON.parse(fs.readFileSync(path.join(repoRoot, "feed.json"), "utf8"));

    // A finite cutoff, so the plan is non-trivial even though the committed
    // config is still the Phase 1 placeholder.
    const plan = planMigration(source, { ...CONFIG, bundleCutoffDate: "2026-08-17" });

    expect(plan.move.length + plan.keep).toBe(feed.entryCount);
    expect(plan.move.length).toBeGreaterThan(0);

    // No entry under a curated block may appear in the move set.
    const curatedLines = new Set(
      parseChunks(source).filter((g) => g.isCurated).flatMap((g) => g.entries.map((e) => e.line)),
    );
    expect(plan.move.filter((m) => curatedLines.has(m.line))).toEqual([]);
  });

  it("never marks a header line for removal that another group still needs", () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    const source = fs.readFileSync(path.join(repoRoot, "src", "threat-intel.ts"), "utf8");
    const plan = planMigration(source, { ...CONFIG, bundleCutoffDate: "2026-08-17" });

    const removableText = new Set(
      plan.groups.filter((g) => g.removeHeader).flatMap((g) => g.header),
    );
    const keptText = plan.groups.filter((g) => !g.removeHeader).flatMap((g) => g.header);

    // The control. The disjointness assertion below is only meaningful while
    // colliding header texts actually exist in this file. If THIS line ever
    // goes red the collision has gone away, which makes the assertion below
    // vacuously true - re-derive both rather than deleting either.
    expect(keptText.some((l) => removableText.has(l))).toBe(true);

    // Indices are not fooled by the shared text.
    const removableIdx = new Set(
      plan.groups.filter((g) => g.removeHeader).flatMap((g) => g.headerIndices),
    );
    const keptIdx = plan.groups.filter((g) => !g.removeHeader).flatMap((g) => g.headerIndices);
    expect(keptIdx.filter((i) => removableIdx.has(i))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// applyMigration: the rewritten source and the catalog lines.
// ---------------------------------------------------------------------------

// The parser sees text and cannot build a FeedIOC; the evaluator builds FeedIOCs
// and cannot see line numbers. These fixtures pair the two the way the real run
// does, in the same order.
const obj = (value: string, firstSeen = "2026-01-01", extra: Record<string, unknown> = {}) => ({
  type: "package",
  value,
  severity: "critical",
  confidence: 1,
  ...extra,
  firstSeen,
});

describe("renderCatalogLine", () => {
  it("emits a fixed key order regardless of the source object's order", () => {
    const line = renderCatalogLine({
      firstSeen: "2026-01-01",
      value: "a@1",
      severity: "critical",
      type: "package",
      confidence: 1,
    });
    expect(line).toBe(
      '{"type":"package","value":"a@1","severity":"critical","confidence":1,"firstSeen":"2026-01-01"}',
    );
  });

  it("omits absent fields rather than emitting nulls", () => {
    const parsed = JSON.parse(renderCatalogLine(obj("b@1")));
    expect(Object.keys(parsed)).not.toContain("campaign");
    expect(Object.keys(parsed)).not.toContain("lastSeen");
  });

  // The legacy note/ecosystem fields were dropped from FEED_ENTRY_KEYS in
  // Phase 1. Publishing one through the catalog would put a field into a
  // downloaded artifact that the loader then refuses to read back.
  it("refuses an entry carrying a field the catalog has no place for", () => {
    expect(() => renderCatalogLine(obj("c@1", "2026-01-01", { note: "legacy" }))).toThrow(
      /no place for: note/,
    );
  });
});

describe("applyMigration", () => {
  it("removes exactly the planned lines and reformats nothing", () => {
    const src = chunk(IMPORTED, old("a@1"), recent("b@1"));
    const result = applyMigration(src, [obj("a@1"), obj("b@1", "2026-09-01")], CONFIG);

    const before = src.split("\n");
    const after = result.source.split("\n");
    expect(after).toEqual(before.filter((l) => l !== old("a@1")));
    // The header stays: one entry beneath it was kept.
    expect(result.source).toContain(IMPORTED);
  });

  it("removes a fully-moved importer header along with its entries", () => {
    // A second chunk keeps an entry, because emptying the bundle entirely is
    // refused outright and would mask what this test is checking.
    const src = [
      "const FEED_CHUNK_0: FeedIOC[] = [",
      IMPORTED,
      old("a@1"),
      old("b@1"),
      "];",
      "const FEED_CHUNK_1: FeedIOC[] = [",
      OTHER_IMPORT,
      recent("c@1"),
      "];",
    ].join("\n");
    const result = applyMigration(
      src,
      [obj("a@1"), obj("b@1"), obj("c@1", "2026-09-01")],
      CONFIG,
    );
    expect(result.source.split("\n")).toEqual([
      "const FEED_CHUNK_0: FeedIOC[] = [",
      "];",
      "const FEED_CHUNK_1: FeedIOC[] = [",
      OTHER_IMPORT,
      recent("c@1"),
      "];",
    ]);
  });

  // The defect this file exists to prevent. Both groups carry byte-identical
  // header text; only the first is fully moved. A text-based removal strips
  // both, detaching the surviving entry from its provenance.
  it("removes the shared header text only where the group is fully moved", () => {
    const src = [
      "const FEED_CHUNK_0: FeedIOC[] = [",
      IMPORTED,
      old("a@1"),
      "];",
      "const FEED_CHUNK_1: FeedIOC[] = [",
      IMPORTED,
      old("b@1"),
      recent("c@1"),
      "];",
    ].join("\n");
    const result = applyMigration(
      src,
      [obj("a@1"), obj("b@1"), obj("c@1", "2026-09-01")],
      CONFIG,
    );

    // One copy of the header survives, above the group that kept an entry.
    const remaining = result.source.split("\n").filter((l) => l === IMPORTED);
    expect(remaining).toHaveLength(1);
    const after = result.source.split("\n");
    expect(after[after.indexOf(IMPORTED) + 1]).toBe(recent("c@1"));
  });

  it("keeps CRLF endings on a CRLF source", () => {
    const src = chunk(IMPORTED, old("a@1"), recent("b@1")).replace(/\n/g, "\r\n");
    const result = applyMigration(src, [obj("a@1"), obj("b@1", "2026-09-01")], CONFIG);
    expect(result.source).toContain("\r\n");
    expect(result.source).not.toMatch(/[^\r]\n/);
  });

  it("writes the catalog with LF endings and one entry per line", () => {
    const src = chunk(IMPORTED, old("a@1"), old("b@1"), recent("c@1"));
    const result = applyMigration(
      src,
      [obj("a@1"), obj("b@1"), obj("c@1", "2026-09-01")],
      CONFIG,
    );
    expect(result.jsonl.includes("\r")).toBe(false);
    expect(result.jsonl.endsWith("\n")).toBe(true);
    const lines = result.jsonl.trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    expect(lines.map((l) => JSON.parse(l).value)).toEqual(["a@1", "b@1"]);
  });

  it("is reproducible: the same input yields byte-identical output", () => {
    const src = chunk(IMPORTED, old("a@1"), recent("b@1"));
    const args = [src, [obj("a@1"), obj("b@1", "2026-09-01")], CONFIG] as const;
    const first = applyMigration(...args);
    const second = applyMigration(...args);
    expect(second.jsonl).toBe(first.jsonl);
    expect(second.source).toBe(first.source);
  });

  // The bundle is the offline floor. extractBundledEntries refuses an empty
  // BUNDLED_FEED, so emptying it would break every gate at once; refuse here,
  // where the operator can still choose a different cutoff.
  it("refuses a cutoff that would move every entry", () => {
    // The control: one kept entry is enough, and the same call succeeds.
    const ok = chunk(IMPORTED, old("a@1"), recent("b@1"));
    expect(() =>
      applyMigration(ok, [obj("a@1"), obj("b@1", "2026-09-01")], CONFIG),
    ).not.toThrow();

    const allMoved = chunk(IMPORTED, old("a@1"), old("b@1"));
    expect(() => applyMigration(allMoved, [obj("a@1"), obj("b@1")], CONFIG)).toThrow(
      /moves all 2 entries and would leave BUNDLED_FEED empty/,
    );
  });

  // If the two walks ever diverge the migration would write one indicator to
  // the catalog while deleting a different one from the bundle, and both files
  // would still look entirely plausible.
  it("refuses when the parser and the evaluator disagree on the count", () => {
    const src = chunk(IMPORTED, old("a@1"), recent("b@1"));
    expect(() => applyMigration(src, [obj("a@1")], CONFIG)).toThrow(
      /parser found 2 entries but the evaluated bundle holds 1/,
    );
  });

  it("refuses when the parser and the evaluator disagree on an entry", () => {
    const src = chunk(IMPORTED, old("a@1"), recent("b@1"));
    expect(() =>
      applyMigration(src, [obj("WRONG@1"), obj("b@1", "2026-09-01")], CONFIG),
    ).toThrow(/is "a@1" to the parser and "WRONG@1" to the evaluator/);
  });
});

describe("applyMigration against the real file", () => {
  const tmpDirs: string[] = [];
  afterEach(() => {
    for (const dir of tmpDirs.splice(0)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  const realRun = async () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    const gen = await import("../../scripts/generate-feed.mjs");
    const source = fs.readFileSync(path.join(repoRoot, "src", "threat-intel.ts"), "utf8");
    const entries = gen.extractBundledEntries(repoRoot);
    const config = { ...CONFIG, bundleCutoffDate: "2026-08-17" };
    return { repoRoot, gen, source, entries, result: applyMigration(source, entries, config) };
  };

  // The catalog is downloaded and parsed back by the loader. A line the loader
  // rejects is an indicator that silently stops being enforced, so the emitted
  // bytes are checked against the REAL validator rather than a mirror of it.
  it("emits catalog lines that the real isValidFeedIOC accepts", async () => {
    const { result } = await realRun();
    const { isValidFeedIOC } = await import("../threat-intel.js");

    const lines = result.jsonl.trimEnd().split("\n");
    expect(lines.length).toBe(result.moved.length);

    const rejected: string[] = [];
    for (const line of lines) {
      if (!isValidFeedIOC(JSON.parse(line))) rejected.push(line);
    }
    expect(rejected.slice(0, 3)).toEqual([]);
    expect(rejected).toHaveLength(0);
  }, 60_000);

  // Zero loss is a claim, so it is measured against the real evaluator rather
  // than against the parser that produced the plan. The rewritten source is
  // evaluated exactly the way the build gates evaluate it.
  it("partitions every indicator into exactly one of bundle or catalog", async () => {
    const { gen, entries, result } = await realRun();

    const mirror = fs.mkdtempSync(path.join(os.tmpdir(), "scg-migrate-"));
    tmpDirs.push(mirror);
    fs.mkdirSync(path.join(mirror, "src"), { recursive: true });
    fs.writeFileSync(path.join(mirror, "src", "threat-intel.ts"), result.source);

    const kept = gen.extractBundledEntries(mirror);
    expect(kept.length).toBe(result.plan.keep);

    const before = new Set(entries.map((e: { value: string }) => e.value));
    const keptValues = new Set(kept.map((e: { value: string }) => e.value));
    const movedValues = new Set(result.moved.map((e: { value: string }) => e.value));

    const lost = [...before].filter((v) => !keptValues.has(v) && !movedValues.has(v));
    const duplicated = [...keptValues].filter((v) => movedValues.has(v));
    expect(lost.slice(0, 3)).toEqual([]);
    expect(duplicated.slice(0, 3)).toEqual([]);
    expect(keptValues.size + movedValues.size).toBe(before.size);
  }, 60_000);

  // Line-exact: the rewritten file must be the original minus whole lines. If a
  // kept line were reformatted the diff would carry changes nobody planned, and
  // a reviewer could no longer read the migration as pure removal.
  it("produces a removals-only diff", async () => {
    const { source, result } = await realRun();
    const original = source.split(/\r?\n/);
    const rewritten = result.source.split(/\r?\n/);

    let cursor = 0;
    let unmatched = 0;
    for (const line of rewritten) {
      const at = original.indexOf(line, cursor);
      if (at === -1) unmatched++;
      else cursor = at + 1;
    }
    expect(unmatched).toBe(0);
    expect(rewritten.length).toBe(original.length - result.droppedLines);
  }, 60_000);
});
