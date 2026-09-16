import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { partitionTarget, loadPartitionConfig } from "../../scripts/feed-partition.mjs";
import { checkPartition } from "../../scripts/check-feed-partition.mjs";
import { checkBudget } from "../../scripts/check-feed-budget.mjs";

const CONFIG = {
  bundleCutoffDate: "2026-06-01",
  maxBundledEntries: 25000,
  maxBundleBytes: 4194304,
};

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
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cfg-"));
    fs.writeFileSync(
      path.join(root, "feed-partition.config.json"),
      JSON.stringify({ bundleCutoffDate: "2001-02-03", maxBundledEntries: 7, maxBundleBytes: 9 }),
    );
    expect(loadPartitionConfig(root)).toEqual({
      bundleCutoffDate: "2001-02-03",
      maxBundledEntries: 7,
      maxBundleBytes: 9,
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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-part-"));
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
