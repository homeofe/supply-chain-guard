/**
 * The daily feed channel's builder (scripts/build-daily-feed.mjs).
 *
 * The daily feed reaches users WITHOUT review (docs/daily-feed-channel-design.md),
 * so the invariant here is the control that keeps it to what the owner approved:
 * main's reviewed feed unchanged, plus only listed exact pins, hashes and the
 * catalog entries main already carries. Package names are synthetic.
 */
import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const SCRIPT_URL = new URL("../../scripts/build-daily-feed.mjs", import.meta.url).href;
const load = () => import(/* @vite-ignore */ SCRIPT_URL);

type Entry = Record<string, unknown> & { type: string; value: string };

const pkg = (value: string, extra: Record<string, unknown> = {}): Entry => ({
  type: "package",
  value,
  severity: "critical",
  confidence: 0.9,
  source: "MAL-2026-0001",
  ...extra,
});

const mainFeed = () => ({
  schema: 1,
  package: "supply-chain-guard",
  version: "6.5.10",
  entryCount: 2,
  generatedAt: "2026-10-21T00:00:00.000Z",
  entries: [pkg("scg-old@1.0.0"), { type: "domain", value: "scg-old.example", severity: "critical", confidence: 1 }],
});

const report = (rows: Array<[string, string | null]>, extra: Record<string, unknown> = {}) => ({
  dryRun: true,
  truncated: false,
  unmapped: 0,
  entries: rows.map(([value]) => pkg(value)),
  derivations: rows.map(([, d]) => d),
  ...extra,
});

const NOW = new Date("2026-10-22T06:15:00Z");

describe("selectDailyPins", () => {
  it("keeps only listed exact pins", async () => {
    const { selectDailyPins } = await load();
    const r = report([
      ["scg-a@1.0.0", "listed"],
      ["scg-b@2.0.0", "range-resolved"],
      ["scg-c", null],
      ["scg-d@1.0.0", "whole-claim-sample"],
      ["scg-e@1.0.0", "pin-only"],
      ["pypi:scg-f@0.1.0", "listed"],
    ]);
    const { pins, dropped } = selectDailyPins(r);
    expect(pins.map((p: Entry) => p.value)).toEqual(["scg-a@1.0.0", "pypi:scg-f@0.1.0"]);
    expect(dropped).toEqual({ "range-resolved": 1, "no-version": 1, "whole-claim-sample": 1, "pin-only": 1 });
  });

  // A listed label on an entry without a version cannot happen today; if it
  // ever does, the entry is still a bare name and must not pass.
  it("drops a bare name even when it is labelled listed", async () => {
    const { selectDailyPins } = await load();
    const { pins, dropped } = selectDailyPins(report([["scg-bare", "listed"]]));
    expect(pins).toEqual([]);
    expect(dropped).toEqual({ "no-version": 1 });
  });

  it("refuses a report whose derivations do not line up with its entries", async () => {
    const { selectDailyPins } = await load();
    expect(() => selectDailyPins({ ...report([["scg-a@1.0.0", "listed"]]), derivations: [] })).toThrow(/derivations/);
  });
});

describe("catalogAdditionsSinceRelease", () => {
  it("returns the catalog entries main has and the release does not", async () => {
    const { catalogAdditionsSinceRelease } = await load();
    const shared = JSON.stringify(pkg("scg-shared@1.0.0"));
    const added = JSON.stringify(pkg("scg-new@1.0.0"));
    expect(catalogAdditionsSinceRelease([shared, added], [shared]).map((e: Entry) => e.value)).toEqual(["scg-new@1.0.0"]);
  });
});

describe("buildDailyFeed", () => {
  it("does not duplicate a pin main already has", async () => {
    const { buildDailyFeed } = await load();
    const daily = buildDailyFeed(mainFeed(), [pkg("scg-old@1.0.0"), pkg("scg-a@1.0.0")], NOW);
    expect(daily.entryCount).toBe(3);
    expect(daily.entries.map((e: Entry) => e.value)).toEqual(["scg-old@1.0.0", "scg-old.example", "scg-a@1.0.0"]);
  });

  it("sets a full timestamp, not midnight", async () => {
    const { buildDailyFeed } = await load();
    expect(buildDailyFeed(mainFeed(), [], NOW).generatedAt).toBe("2026-10-22T06:15:00.000Z");
  });
});

describe("assertDailyInvariant", () => {
  const good = async () => {
    const { buildDailyFeed } = await load();
    return buildDailyFeed(mainFeed(), [pkg("scg-a@1.0.0"), { type: "hash", value: "a".repeat(64), severity: "critical", confidence: 0.85 }], NOW);
  };

  it("accepts listed pins, hashes and catalog additions", async () => {
    const { assertDailyInvariant, buildDailyFeed } = await load();
    const catalogAdd = pkg("scg-cat@1.0.0", { firstSeen: "2026-09-01" });
    const daily = buildDailyFeed(mainFeed(), [pkg("scg-a@1.0.0"), catalogAdd], NOW);
    expect(() => assertDailyInvariant(mainFeed(), daily, [catalogAdd])).not.toThrow();
    const withHash = await good();
    expect(() => assertDailyInvariant(mainFeed(), withHash, [])).not.toThrow();
  });

  // Each breach keeps entryCount consistent and names the reason it must fail
  // for: a mutation that only broke the count would pass for the wrong reason
  // (it did, until a mutation cut of the type check stayed green).
  const breaches: Array<[string, (d: { entries: Entry[]; generatedAt: string }) => void, RegExp]> = [
    ["a removed main entry", (d) => void d.entries.shift(), /main entry removed/],
    ["a changed main entry", (d) => void (d.entries[0].severity = "low"), /main entry changed/],
    ["an added bare name", (d) => void d.entries.push(pkg("scg-evil")), /not allowed without review: package scg-evil/],
    ["an added domain", (d) => void d.entries.push({ type: "domain", value: "scg-evil.example", severity: "high" }), /not allowed without review: domain/],
    ["an added ip", (d) => void d.entries.push({ type: "ip", value: "192.0.2.1", severity: "high" }), /not allowed without review: ip/],
    ["an added url", (d) => void d.entries.push({ type: "url", value: "https://scg-evil.example/x", severity: "high" }), /not allowed without review: url/],
    ["a midnight generatedAt", (d) => void (d.generatedAt = "2026-10-22T00:00:00.000Z"), /not a full build timestamp/],
    ["a generatedAt not later than main", (d) => void (d.generatedAt = "2026-10-20T06:00:00.000Z"), /not later than main/],
  ];
  for (const [name, mutate, reason] of breaches) {
    it(`rejects ${name}`, async () => {
      const { assertDailyInvariant } = await load();
      const daily = await good();
      mutate(daily);
      daily.entryCount = daily.entries.length;
      expect(() => assertDailyInvariant(mainFeed(), daily, [])).toThrow(reason);
    });
  }

  it("rejects an entryCount that does not match the entries", async () => {
    const { assertDailyInvariant } = await load();
    const daily = await good();
    daily.entryCount += 1;
    expect(() => assertDailyInvariant(mainFeed(), daily, [])).toThrow(/entryCount/);
  });

  it("rejects a catalog addition that main does not carry", async () => {
    const { assertDailyInvariant, buildDailyFeed } = await load();
    const forged = pkg("scg-forged", { firstSeen: "2026-09-01" });
    const daily = buildDailyFeed(mainFeed(), [forged], NOW);
    expect(() => assertDailyInvariant(mainFeed(), daily, [])).toThrow(/not allowed without review: package scg-forged/);
    // A catalog entry that main carries, but changed on the way, is not main's.
    const carried = pkg("scg-carried", { firstSeen: "2026-09-01" });
    const altered = buildDailyFeed(mainFeed(), [{ ...carried, severity: "low" }], NOW);
    expect(() => assertDailyInvariant(mainFeed(), altered, [carried])).toThrow(/not allowed without review: package scg-carried/);
  });

  it("rejects 2,001 added pins under the default cap and accepts 2,000", async () => {
    const { assertDailyInvariant, buildDailyFeed } = await load();
    const pins = (n: number) => Array.from({ length: n }, (_, i) => pkg(`scg-bulk-${i}@1.0.0`));
    expect(() => assertDailyInvariant(mainFeed(), buildDailyFeed(mainFeed(), pins(2000), NOW), [])).not.toThrow();
    expect(() => assertDailyInvariant(mainFeed(), buildDailyFeed(mainFeed(), pins(2001), NOW), [])).toThrow(/cap/);
  });
});

describe("the CLI", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });
  const tree = (catalogLines: string[], feed?: object) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-daily-"));
    dirs.push(root);
    fs.mkdirSync(path.join(root, "data", "threat-catalog"), { recursive: true });
    fs.writeFileSync(path.join(root, "data", "threat-catalog", "part-000.jsonl"), catalogLines.map((l) => `${l}\n`).join(""));
    if (feed) fs.writeFileSync(path.join(root, "feed.json"), JSON.stringify(feed, null, 2));
    return root;
  };
  const run = async (reportBody: object) => {
    const { main } = await load();
    const shared = JSON.stringify(pkg("scg-shared@1.0.0"));
    const mainRoot = tree([shared, JSON.stringify(pkg("scg-cat@1.0.0"))], mainFeed());
    const releaseRoot = tree([shared]);
    const out = fs.mkdtempSync(path.join(os.tmpdir(), "scg-daily-out-"));
    dirs.push(out);
    const reportFile = path.join(out, "report.json");
    fs.writeFileSync(reportFile, JSON.stringify(reportBody));
    const code = await main(
      ["--report", reportFile, "--main-root", mainRoot, "--release-root", releaseRoot, "--out", out],
      { now: NOW },
    );
    return { code, out, feedPath: path.join(out, "feed.json") };
  };

  it("writes the daily feed with listed pins and main's catalog additions", async () => {
    const { code, feedPath } = await run(report([["scg-a@1.0.0", "listed"], ["scg-b@1.0.0", "range-resolved"]]));
    expect(code).toBe(0);
    const daily = JSON.parse(fs.readFileSync(feedPath, "utf8"));
    expect(daily.entries.map((e: Entry) => e.value)).toEqual(["scg-old@1.0.0", "scg-old.example", "scg-a@1.0.0", "scg-cat@1.0.0"]);
    expect(daily.generatedAt).toBe("2026-10-22T06:15:00.000Z");
  });

  it("refuses a report that is truncated or has gaps", async () => {
    for (const extra of [{ truncated: true }, { unmapped: 1 }, { dryRun: false }]) {
      const { code, feedPath } = await run(report([["scg-a@1.0.0", "listed"]], extra));
      expect(code).toBe(1);
      expect(fs.existsSync(feedPath)).toBe(false);
    }
  });

  it("refuses a report without derivations (an importer older than the labels)", async () => {
    const r: Record<string, unknown> = report([["scg-a@1.0.0", "listed"]]);
    delete r.derivations;
    const { code, feedPath } = await run(r);
    expect(code).toBe(1);
    expect(fs.existsSync(feedPath)).toBe(false);
  });
});
