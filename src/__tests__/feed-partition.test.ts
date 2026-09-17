import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { partitionTarget, loadPartitionConfig } from "../../scripts/feed-partition.mjs";
import { checkPartition } from "../../scripts/check-feed-partition.mjs";
import { checkBudget, suggestCutoff } from "../../scripts/check-feed-budget.mjs";

const CONFIG = {
  bundleCutoffDate: "2026-06-01",
  maxBundledEntries: 25000,
  maxBundleBytes: 4194304,
};

// Every fixture root is registered here and removed after each test. Without
// this the suite leaves roughly thirty directories behind per run, each holding
// a synthetic src/threat-intel.ts. That is not hypothetical in this repository:
// the Linux runner already carries leftover scg-issue54-empty-* and
// scg-two-tier-* directories from earlier suites.
const tempRoots: string[] = [];

function makeTempRoot(prefix: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    const root = tempRoots.pop();
    if (root !== undefined) fs.rmSync(root, { recursive: true, force: true });
  }
});

describe("partitionTarget", () => {
  it("keeps a CURATED non-package type in the bundle regardless of age", () => {
    for (const type of ["ip", "domain", "url", "hash"]) {
      expect(
        partitionTarget({ type, value: "x", campaign: "c", firstSeen: "2020-01-01" }, CONFIG),
      ).toBe("bundle");
      expect(
        partitionTarget({ type, value: "x", family: "f", firstSeen: "2020-01-01" }, CONFIG),
      ).toBe("bundle");
    }
  });

  // Rule 1 is bounded by curation, not by type. An unbounded rule would let a
  // source that begins publishing atomic indicators in bulk grow the bundle
  // forever with no mechanism to stop it. Measured on the v6.1.3 feed: 404
  // non-package entries, 401 already carry campaign or family, only 3 rely on
  // the type alone and none of those is older than a 30-day cutoff. So this
  // moves zero entries today. The loss risk is closed by check:feed-partition,
  // which fails the build rather than letting an atomic indicator leave.
  it("routes an UNCURATED old non-package type to the catalog", () => {
    expect(
      partitionTarget({ type: "ip", value: "203.0.113.9", firstSeen: "2020-01-01" }, CONFIG),
    ).toBe("catalog");
  });

  it("keeps an uncurated non-package type that is recent", () => {
    expect(
      partitionTarget({ type: "ip", value: "203.0.113.9", firstSeen: "2026-09-01" }, CONFIG),
    ).toBe("bundle");
  });

  it("keeps curated package entries in the bundle regardless of age", () => {
    expect(
      partitionTarget({ type: "package", value: "a@1", campaign: "c", firstSeen: "2020-01-01" }, CONFIG),
    ).toBe("bundle");
    expect(
      partitionTarget({ type: "package", value: "b@1", family: "f", firstSeen: "2020-01-01" }, CONFIG),
    ).toBe("bundle");
  });

  it("keeps packages on or after the cutoff, routes those before it", () => {
    expect(
      partitionTarget({ type: "package", value: "c@1", firstSeen: "2026-06-01" }, CONFIG),
    ).toBe("bundle");
    expect(
      partitionTarget({ type: "package", value: "d@1", firstSeen: "2026-05-31" }, CONFIG),
    ).toBe("catalog");
  });

  // Failing closed toward MORE detection is the safe direction here: the cost
  // is a few bytes in the bundle, where guessing an undatable entry out of it
  // would silently drop coverage.
  it("keeps an undatable entry in the bundle rather than guessing", () => {
    expect(partitionTarget({ type: "package", value: "e@1" }, CONFIG)).toBe("bundle");
    expect(
      partitionTarget({ type: "package", value: "f@1", firstSeen: "not-a-date" }, CONFIG),
    ).toBe("bundle");
    // Parses but does not round-trip: Date.UTC rolls this into 2026-03-03.
    expect(
      partitionTarget({ type: "package", value: "g@1", firstSeen: "2026-02-31" }, CONFIG),
    ).toBe("bundle");
  });

  it("is independent of the current clock", () => {
    const entry = { type: "package", value: "h@1", firstSeen: "2026-05-31" };
    const first = partitionTarget(entry, CONFIG);
    const realNow = Date.now;
    Date.now = () => realNow() + 365 * 86_400_000;
    try {
      expect(partitionTarget(entry, CONFIG)).toBe(first);
    } finally {
      Date.now = realNow;
    }
  });

  it("refuses a config whose cutoff is not a real calendar date", () => {
    const bad = { ...CONFIG, bundleCutoffDate: "2026-13-01" };
    expect(() =>
      partitionTarget({ type: "package", value: "i@1", firstSeen: "2026-01-01" }, bad),
    ).toThrow(/bundleCutoffDate/);
  });
});

describe("loadPartitionConfig", () => {
  it("reads the committed config", () => {
    const config = loadPartitionConfig();
    expect(typeof config.bundleCutoffDate).toBe("string");
    expect(config.bundleCutoffDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(typeof config.maxBundledEntries).toBe("number");
    expect(typeof config.maxBundleBytes).toBe("number");
  });

  it("reads from an explicit root", () => {
    const root = makeTempRoot("scg-cfg-");
    fs.writeFileSync(
      path.join(root, "feed-partition.config.json"),
      JSON.stringify({ bundleCutoffDate: "2001-02-03", maxBundledEntries: 7, maxBundleBytes: 9 }),
    );
    expect(loadPartitionConfig(root)).toEqual({
      bundleCutoffDate: "2001-02-03",
      maxBundledEntries: 7,
      maxBundleBytes: 9,
      // Absent in the file means no declared bulk-backfill windows, which the
      // loader normalizes to an empty list so every consumer can read it.
      catalogWindows: [],
    });
  });
});

// ---------------------------------------------------------------------------
// The two build gates. Both read the real generate-feed.mjs extractor, so the
// fixtures below have to look like real FEED_CHUNK literals.
// ---------------------------------------------------------------------------

/** Build a throwaway repo root that both gates can be pointed at. */
function fixture(
  bundleEntries: Record<string, unknown>[],
  catalogLines: string[],
  config: Record<string, unknown> = {
    bundleCutoffDate: "2026-06-01",
    maxBundledEntries: 25000,
    maxBundleBytes: 4194304,
  },
): string {
  const root = makeTempRoot("scg-part-");
  fs.mkdirSync(path.join(root, "src"));
  fs.mkdirSync(path.join(root, "data"));
  const body = bundleEntries.map((e) => `  ${JSON.stringify(e)},`).join("\n");
  fs.writeFileSync(
    path.join(root, "src", "threat-intel.ts"),
    // extractBundledEntries requires the BUNDLED_FEED marker, so the fixture
    // has to match the real file shape: chunk literals spread into it.
    `const FEED_CHUNK_0: FeedIOC[] = [\n${body}\n];\n\n` +
      `const BUNDLED_FEED: FeedIOC[] = [\n  ...FEED_CHUNK_0,\n];\n`,
  );
  fs.writeFileSync(path.join(root, "data", "threat-catalog.jsonl"), catalogLines.join("\n"));
  fs.writeFileSync(path.join(root, "feed-partition.config.json"), JSON.stringify(config));
  return root;
}

const pkg = (value: string, firstSeen: string, over: Record<string, unknown> = {}) => ({
  type: "package", value, severity: "critical", firstSeen, ...over,
});

// extractBundledEntries refuses an empty BUNDLED_FEED, which is correct: in the
// real file an empty bundle means something broke. Every fixture therefore
// carries one filler entry that no assertion looks at.
const FILLER = pkg("filler@1.0.0", "2026-07-01");

describe("checkPartition", () => {
  it("passes a clean split", () => {
    const root = fixture(
      [pkg("new@1", "2026-07-01")],
      [JSON.stringify(pkg("old@1", "2026-01-01"))],
    );
    expect(checkPartition(root)).toEqual([]);
  });

  it("passes an empty catalog", () => {
    expect(checkPartition(fixture([pkg("new@1", "2026-07-01")], []))).toEqual([]);
  });

  it("rejects a value present in both stores", () => {
    const dup = pkg("dup@1", "2026-07-01");
    const root = fixture([dup], [JSON.stringify(pkg("dup@1", "2026-01-01"))]);
    expect(checkPartition(root).join(" ")).toMatch(/dup@1 is in both stores/);
  });

  it("rejects a duplicate value inside the catalog", () => {
    const line = JSON.stringify(pkg("twice@1", "2026-01-01"));
    expect(checkPartition(fixture([FILLER], [line, line])).join(" "))
      .toMatch(/duplicate value twice@1/);
  });

  // The atomic-indicator rule: these must never leave the bundle silently, and
  // the message has to name the real fix rather than the symptom.
  it("rejects a non-package entry in the catalog, naming the real fix", () => {
    const root = fixture([FILLER], [JSON.stringify({
      type: "ip", value: "203.0.113.9", severity: "critical", firstSeen: "2026-01-01",
    })]);
    const out = checkPartition(root).join(" ");
    expect(out).toMatch(/Atomic indicators must stay in the bundle/);
    expect(out).toMatch(/campaign or family/);
  });

  it("rejects a curated entry in the catalog", () => {
    const root = fixture([FILLER], [JSON.stringify(pkg("c@1", "2026-01-01", { campaign: "x" }))]);
    expect(checkPartition(root).join(" ")).toMatch(/belongs in the bundle/);
  });

  it("rejects a recent entry in the catalog", () => {
    const root = fixture([FILLER], [JSON.stringify(pkg("r@1", "2026-09-01"))]);
    expect(checkPartition(root).join(" ")).toMatch(/belongs in the bundle/);
  });

  it("reports a malformed line by number, not by value", () => {
    const root = fixture([FILLER], ["{ not json"]);
    const out = checkPartition(root).join(" ");
    expect(out).toMatch(/line 1/);
    expect(out).toMatch(/not valid JSON/);
  });

  it("fails when the catalog file is missing entirely", () => {
    const root = fixture([FILLER], []);
    fs.rmSync(path.join(root, "data", "threat-catalog.jsonl"));
    expect(checkPartition(root).join(" ")).toMatch(/is missing; it must exist, even empty/);
  });
});

describe("checkBudget", () => {
  const many = (n: number) =>
    Array.from({ length: n }, (_, i) => pkg(`p${i}@1.0.0`, "2026-07-01"));

  it("passes one entry under the entry limit", () => {
    const root = fixture(many(9), [], {
      bundleCutoffDate: "2026-06-01", maxBundledEntries: 10, maxBundleBytes: 4194304,
    });
    expect(checkBudget(root)).toEqual([]);
  });

  it("fails one entry over the entry limit", () => {
    const root = fixture(many(11), [], {
      bundleCutoffDate: "2026-06-01", maxBundledEntries: 10, maxBundleBytes: 4194304,
    });
    expect(checkBudget(root).join(" ")).toMatch(/11 bundled entries exceeds 10/);
  });

  it("fails when the generated source exceeds the byte budget", () => {
    const root = fixture(many(3), [], {
      bundleCutoffDate: "2026-06-01", maxBundledEntries: 25000, maxBundleBytes: 50,
    });
    expect(checkBudget(root).join(" ")).toMatch(/exceeds the 50 byte budget/);
  });

  // The cutoff is the one recurring manual input in this design. A gate that
  // says "move it forward" without saying where is a gate that gets guessed at.
  it("names a usable date, and that date achieves the limit", () => {
    const entries = [
      pkg("a@1", "2026-09-05"), pkg("b@1", "2026-09-04"),
      pkg("c@1", "2026-09-03"), pkg("d@1", "2026-09-02"),
    ];
    const root = fixture(entries, [], {
      bundleCutoffDate: "2020-01-01", maxBundledEntries: 2, maxBundleBytes: 4194304,
    });
    const out = checkBudget(root).join(" ");
    const m = /Suggested bundleCutoffDate: (\d{4}-\d{2}-\d{2})/.exec(out);
    expect(m).not.toBeNull();

    const suggested = m![1];
    const kept = entries.filter(
      (e) => partitionTarget(e, {
        bundleCutoffDate: suggested, maxBundledEntries: 2, maxBundleBytes: 4194304,
      }) === "bundle",
    );
    expect(kept).toHaveLength(2);
  });

  it("suggests nothing when immovable entries alone exceed the limit", () => {
    const root = fixture(
      [pkg("x@1", "2026-09-01", { campaign: "c" }), pkg("y@1", "2026-09-01", { campaign: "c" })],
      [],
      { bundleCutoffDate: "2026-06-01", maxBundledEntries: 1, maxBundleBytes: 4194304 },
    );
    const out = checkBudget(root).join(" ");
    expect(out).toMatch(/exceeds 1/);
    expect(out).not.toMatch(/Suggested bundleCutoffDate/);
  });
});

// ---------------------------------------------------------------------------
// Review findings, each with a test that fails without the fix.
// ---------------------------------------------------------------------------

describe("partitionTarget, trailing junk in firstSeen", () => {
  // Slicing the value before applying the anchored regex accepted trailing
  // junk: "2020-01-01oops" parsed as a valid old date and routed a detection
  // OUT of the bundle, the opposite of the documented fail-open behaviour.
  // Measured on the v6.1.3 feed, all 20,958 dated entries are exactly
  // YYYY-MM-DD, so the slice bought nothing and cost this.
  it("fails open for a date-prefixed invalid string", () => {
    for (const bad of ["2020-01-01oops", "2020-01-01T00:00:00Z", "2020-01-01 ", "2020-01-012"]) {
      expect(partitionTarget({ type: "package", value: "x@1", firstSeen: bad }, CONFIG))
        .toBe("bundle");
    }
  });

  it("still routes a clean old date to the catalog", () => {
    expect(partitionTarget({ type: "package", value: "x@1", firstSeen: "2020-01-01" }, CONFIG))
      .toBe("catalog");
  });
});

describe("loadPartitionConfig, malformed limits", () => {
  // A missing or misspelled limit returned undefined, and `n > undefined` is
  // false, so check:feed-budget reported success for ANY bundle size. One typo
  // in a committed config silently disabled the gate.
  const write = (cfg: Record<string, unknown>) => {
    const root = makeTempRoot("scg-badcfg-");
    fs.writeFileSync(path.join(root, "feed-partition.config.json"), JSON.stringify(cfg));
    return root;
  };

  it("refuses a missing limit rather than failing open", () => {
    const root = write({ bundleCutoffDate: "2026-06-01", maxBundleBytes: 10 });
    expect(() => loadPartitionConfig(root)).toThrow(/maxBundledEntries/);
  });

  it("refuses a misspelled limit", () => {
    const root = write({ bundleCutoffDate: "2026-06-01", maxBundledEntires: 10, maxBundleBytes: 10 });
    expect(() => loadPartitionConfig(root)).toThrow(/maxBundledEntries/);
  });

  it("refuses non-numeric, non-finite and negative limits", () => {
    for (const v of ["10", null, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      const root = write({ bundleCutoffDate: "2026-06-01", maxBundledEntries: v, maxBundleBytes: 10 });
      expect(() => loadPartitionConfig(root)).toThrow(/maxBundledEntries/);
    }
  });

  it("refuses a non-string cutoff", () => {
    const root = write({ bundleCutoffDate: 20260601, maxBundledEntries: 10, maxBundleBytes: 10 });
    expect(() => loadPartitionConfig(root)).toThrow(/bundleCutoffDate/);
  });

  // The control: a well-formed config still loads.
  it("accepts a well-formed config", () => {
    const root = write({ bundleCutoffDate: "2026-06-01", maxBundledEntries: 10, maxBundleBytes: 20 });
    expect(loadPartitionConfig(root)).toEqual({
      bundleCutoffDate: "2026-06-01", maxBundledEntries: 10, maxBundleBytes: 20,
      catalogWindows: [],
    });
  });

  it("accepts a well-formed catalog window", () => {
    const root = write({
      bundleCutoffDate: "2026-06-01", maxBundledEntries: 10, maxBundleBytes: 20,
      catalogWindows: [{ since: "2026-09-02", until: "2026-09-13", reason: "bulk" }],
    });
    expect(loadPartitionConfig(root).catalogWindows).toHaveLength(1);
  });

  // A malformed window must not be silently ignored. Ignoring one would send an
  // entire declared backfill to the bundle, which is the failure the window
  // exists to prevent, and the budget gate would then fail for a reason that
  // looks nothing like the cause.
  it.each([
    ["not an array", { catalogWindows: {} }],
    ["a missing until", { catalogWindows: [{ since: "2026-09-02" }] }],
    ["a missing since", { catalogWindows: [{ until: "2026-09-13" }] }],
    ["a reversed range", { catalogWindows: [{ since: "2026-09-13", until: "2026-09-02" }] }],
    ["a non-string bound", { catalogWindows: [{ since: 20260902, until: "2026-09-13" }] }],
    ["a missing zero-pad", { catalogWindows: [{ since: "2026-09-13", until: "2026-9-13" }] }],
    ["a non-ISO spelling", { catalogWindows: [{ since: "09/02/2026", until: "09/13/2026" }] }],
  ])("refuses %s", (_label, extra) => {
    const root = write({
      bundleCutoffDate: "2026-06-01", maxBundledEntries: 10, maxBundleBytes: 20, ...extra,
    });
    expect(() => loadPartitionConfig(root)).toThrow(/catalogWindows/);
  });
});

describe("suggestCutoff, tied dates", () => {
  const apply = (entries: Record<string, unknown>[], cutoff: string) =>
    entries.filter((e) => partitionTarget(e, {
      bundleCutoffDate: cutoff, maxBundledEntries: 0, maxBundleBytes: 0,
    }) === "bundle").length;

  // Picking the Nth entry's date is wrong whenever entries share a date:
  // partitionTarget keeps everything >= the cutoff, so with a limit of 1 and
  // two entries on 2026-09-05 the old code suggested 2026-09-05 and kept both,
  // leaving the gate red after applying its own advertised remedy.
  it("never suggests a date that leaves the bundle over the limit", () => {
    const tied = [
      pkg("a@1", "2026-09-05"), pkg("b@1", "2026-09-05"),
      pkg("c@1", "2026-09-04"), pkg("d@1", "2026-09-03"),
    ];
    for (const limit of [1, 2, 3, 4]) {
      const s = suggestCutoff(tied, limit);
      if (s === null) continue;
      expect(apply(tied, s.date)).toBeLessThanOrEqual(limit);
      // The reported count must be the count actually achieved.
      expect(s.bundledEntries).toBe(apply(tied, s.date));
    }
  });

  it("returns null when even the newest date group does not fit", () => {
    const tied = [pkg("a@1", "2026-09-05"), pkg("b@1", "2026-09-05")];
    expect(suggestCutoff(tied, 1)).toBeNull();
  });

  it("picks the largest boundary that fits, not the smallest", () => {
    const entries = [pkg("a@1", "2026-09-05"), pkg("b@1", "2026-09-04"), pkg("c@1", "2026-09-03")];
    expect(suggestCutoff(entries, 2)?.date).toBe("2026-09-04");
    expect(apply(entries, "2026-09-04")).toBe(2);
  });

  it("returns null when immovable entries alone exceed the limit", () => {
    const curated = [
      pkg("x@1", "2026-09-01", { campaign: "c" }),
      pkg("y@1", "2026-09-01", { campaign: "c" }),
    ];
    expect(suggestCutoff(curated, 1)).toBeNull();
  });
});

describe("the committed catalog is a valid feed document", () => {
  // The gate cannot enforce the full FeedIOC contract: it is a .mjs script, it
  // runs before tsc, and isValidFeedIOC lives in TypeScript with per-type value
  // shapes, timestamp parsing and a lastSeen ordering rule. Mirroring all of
  // that in the gate would be a drift liability, so the contract is enforced
  // HERE, against the real function, where no copy is needed.
  //
  // It matters because loadThreatIntel() filters the cached catalog through
  // isValidFeedIOC: an entry that is well-shaped but invalid is silently
  // quarantined at scan time, so a gate that only checked for a string `value`
  // would pass while the detection disappeared.
  it("every committed catalog line passes the loader's own validator", async () => {
    const { isValidFeedIOC } = await import("../threat-intel.js");
    const repoRoot = path.resolve(__dirname, "..", "..");
    const file = path.join(repoRoot, "data", "threat-catalog.jsonl");
    const raw = fs.readFileSync(file, "utf8");

    const bad: string[] = [];
    raw.split("\n").forEach((line, i) => {
      if (line.trim() === "") return;
      let entry: unknown;
      try {
        entry = JSON.parse(line);
      } catch {
        bad.push(`line ${i + 1}: not valid JSON`);
        return;
      }
      if (!isValidFeedIOC(entry)) bad.push(`line ${i + 1}: isValidFeedIOC rejected it`);
    });

    expect(bad).toEqual([]);
  });

  // The control: the assertion above passes trivially on an empty catalog, so
  // prove it would actually catch a bad entry.
  it("would reject an entry the loader quarantines", async () => {
    const { isValidFeedIOC } = await import("../threat-intel.js");
    expect(isValidFeedIOC({ type: "package", value: "bad@1", firstSeen: "2020-01-01" })).toBe(false);
    expect(isValidFeedIOC({ type: "package", value: "ok@1", severity: "catastrophic" })).toBe(false);
    expect(isValidFeedIOC({ type: "package", value: "ok@1", severity: "critical" })).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Review findings: each of these fails without its fix.
// ---------------------------------------------------------------------------

describe("loadPartitionConfig, invalid cutoff date", () => {
  // The throw inside partitionTarget is unreachable for both gates on a repo
  // with an empty catalog, so an invalid date used to pass every gate silently.
  it("refuses a cutoff that is a string but not a date", () => {
    for (const bad of ["not-a-date", "2026-13-01", "2026-02-31", "2026-6-1", ""]) {
      const root = makeTempRoot("scg-date-");
      fs.writeFileSync(
        path.join(root, "feed-partition.config.json"),
        JSON.stringify({ bundleCutoffDate: bad, maxBundledEntries: 10, maxBundleBytes: 10 }),
      );
      expect(() => loadPartitionConfig(root)).toThrow(/bundleCutoffDate/);
    }
  });

  it("reaches both gates, not just the per-entry path", () => {
    const root = fixture([pkg("a@1", "2026-07-01")], [], {
      bundleCutoffDate: "not-a-date", maxBundledEntries: 25000, maxBundleBytes: 4194304,
    });
    expect(() => checkPartition(root)).toThrow(/bundleCutoffDate/);
    expect(() => checkBudget(root)).toThrow(/bundleCutoffDate/);
  });
});

describe("checkBudget, suggestion is scoped to the binding constraint", () => {
  it("suggests nothing when only the byte limit is breached", () => {
    const root = fixture(
      [pkg("a@1", "2026-09-05"), pkg("b@1", "2026-09-04"), pkg("c@1", "2026-09-03")], [],
      { bundleCutoffDate: "2020-01-01", maxBundledEntries: 25000, maxBundleBytes: 50 },
    );
    const out = checkBudget(root).join(" ");
    expect(out).toMatch(/exceeds the 50 byte budget/);
    expect(out).not.toMatch(/Suggested bundleCutoffDate/);
  });

  it("reports the count the boundary actually produces", () => {
    const entries = [pkg("a@1", "2026-09-05"), pkg("b@1", "2026-09-04"), pkg("c@1", "2026-09-03")];
    const root = fixture(entries, [], {
      bundleCutoffDate: "2020-01-01", maxBundledEntries: 2, maxBundleBytes: 4194304,
    });
    const line = checkBudget(root).find((v) => v.includes("Suggested"))!;
    const m = /Suggested bundleCutoffDate: (\S+) \(brings the bundle to (\d+) entries\)/.exec(line)!;
    expect(m).not.toBeNull();

    const kept = entries.filter((e) => partitionTarget(e, {
      bundleCutoffDate: m[1], maxBundledEntries: 2, maxBundleBytes: 0,
    }) === "bundle").length;
    expect(Number(m[2])).toBe(kept);
  });
});

describe("suggestCutoff uses the policy's own date parser", () => {
  // A shape-only test accepts 2026-02-31, which partitionTarget rejects and
  // therefore keeps in the bundle. Counting it as movable produced a boundary
  // that cannot work.
  it("treats a non-round-trip date as immovable, like partitionTarget does", () => {
    const entries = [pkg("bad@1", "2026-02-31"), pkg("good@1", "2026-09-05")];
    expect(partitionTarget(entries[0], CONFIG)).toBe("bundle");
    expect(suggestCutoff(entries, 1)).toBeNull();
  });
});

describe("violation paths are platform-independent", () => {
  it("names the catalog with forward slashes", () => {
    const root = fixture([FILLER], ["{ not json"]);
    expect(checkPartition(root).join(" ")).toContain("data/threat-catalog.jsonl line 1");
  });
});
