import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  renderCatalogEntry,
  routeEntries,
  assertNoAtomicInCatalog,
} from "../../scripts/import-threat-feed.mjs";
import { partitionTarget } from "../../scripts/feed-partition.mjs";
import { CATALOG_KEY_ORDER } from "../../scripts/feed-migrate.mjs";

// The cutoff these tests reason against. Pinned, never derived from the clock:
// this file has already been broken once by tests that read the real date.
const CUTOFF = "2026-08-17";
const CONFIG = {
  bundleCutoffDate: CUTOFF,
  maxBundledEntries: 15000,
  maxBundleBytes: 2097152,
};

const entry = (over: Record<string, unknown> = {}) => ({
  type: "package",
  value: "routed-fixture-pkg@1.0.0",
  severity: "critical",
  confidence: 1,
  firstSeen: "2026-01-01",
  ...over,
});

describe("importer routing follows the same policy as the migration", () => {
  // The importer must not have its own opinion about where an entry belongs.
  // If it did, an entry could be in the bundle to the importer and in the
  // catalog to the gate, and the placement check would go red on a file nobody
  // edited by hand.
  it("sends an old plain package to the catalog", () => {
    expect(partitionTarget(entry(), CONFIG)).toBe("catalog");
  });

  it("keeps a recent package in the bundle", () => {
    expect(partitionTarget(entry({ firstSeen: "2026-09-01" }), CONFIG)).toBe("bundle");
  });

  it("keeps an old entry that carries curation in the bundle", () => {
    expect(partitionTarget(entry({ campaign: "some-campaign" }), CONFIG)).toBe("bundle");
    expect(partitionTarget(entry({ family: "some-family" }), CONFIG)).toBe("bundle");
  });

  // Rule 1 is bounded by CURATION, not by type, and that is deliberate: design
  // section 4.2 records that an unconditional "every non-package entry stays"
  // is an unbounded rule, because a source publishing atomic indicators in bulk
  // would grow the bundle forever with no mechanism to stop it. Measured on the
  // v6.1.3 feed, 401 of 404 non-package entries already carry curation and none
  // of the other 3 is old enough to move, so the bound costs nothing today.
  //
  // So the POLICY does route an old, uncurated atomic indicator to the catalog.
  // The loss risk is closed by a gate instead, and by the importer refusing to
  // write one. The plan's own snippet for this task asserted the opposite and
  // contradicted the design.
  it.each([["ip", "203.0.113.9"], ["domain", "old.example"], ["hash", "a".repeat(64)]])(
    "routes an old uncurated %s indicator by date, like any other entry",
    (type, value) => {
      expect(partitionTarget(entry({ type, value, firstSeen: "2020-01-01" }), CONFIG)).toBe(
        "catalog",
      );
      // ...and curation is what keeps it, which is how the other 401 stay.
      expect(
        partitionTarget(entry({ type, value, firstSeen: "2020-01-01", campaign: "x" }), CONFIG),
      ).toBe("bundle");
    },
  );

  // An entry with no usable date cannot be shown to be old, and the fail-safe
  // direction is to keep it where it is always available.
  it("keeps an undatable entry in the bundle", () => {
    expect(partitionTarget(entry({ firstSeen: undefined }), CONFIG)).toBe("bundle");
    expect(partitionTarget(entry({ firstSeen: "not-a-date" }), CONFIG)).toBe("bundle");
  });
});

describe("renderCatalogEntry", () => {
  it("emits the canonical field order the migration uses", () => {
    const line = renderCatalogEntry(entry({ source: "GHSA-xxxx" }));
    const keys = Object.keys(JSON.parse(line));
    const expected = CATALOG_KEY_ORDER.filter((k: string) => keys.includes(k));
    expect(keys).toEqual(expected);
  });

  it("omits fields the entry does not carry", () => {
    const parsed = JSON.parse(renderCatalogEntry(entry()));
    expect(Object.keys(parsed)).not.toContain("campaign");
    expect(Object.keys(parsed)).not.toContain("lastSeen");
  });

  // The importer and the migration write into the SAME file, read back by the
  // same generator. A line written by one that the other would not have written
  // makes the catalog's field order depend on which code path added the entry.
  it("emits only fields the catalog allows", () => {
    const parsed = JSON.parse(renderCatalogEntry(entry({ source: "GHSA-xxxx" })));
    for (const key of Object.keys(parsed)) {
      expect(CATALOG_KEY_ORDER).toContain(key);
    }
  });

  it("is valid JSON on one line", () => {
    const line = renderCatalogEntry(entry());
    expect(line).not.toContain("\n");
    expect(() => JSON.parse(line)).not.toThrow();
  });
});

describe("the importer leaves a repository without a partition policy alone", () => {
  let root: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-route-"));
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  // Failing loud is the point. A fallback to some default would send every
  // imported entry to the bundle, which is precisely the regression the routing
  // exists to prevent, and it would do it without saying anything.
  it("refuses rather than defaulting when the config is missing", async () => {
    const { loadPartitionConfig } = await import("../../scripts/feed-partition.mjs");
    expect(() => loadPartitionConfig(root)).toThrow();
  });
});


describe("the gate and the importer both refuse an atomic indicator in the catalog", () => {
  // The design closes rule 1's loss risk with a gate rather than a rule. That
  // claim is only worth anything if the gate exists, so this asserts the gate's
  // own source contains the check, and the importer test below asserts the
  // earlier refusal.
  it("check:feed-partition rejects a non-package catalog entry", async () => {
    const fsMod = await import("node:fs");
    const pathMod = await import("node:path");
    const gate = fsMod.readFileSync(
      pathMod.resolve(__dirname, "..", "..", "scripts", "check-feed-partition.mjs"),
      "utf8",
    );
    expect(gate).toContain('entry.type !== "package"');
    expect(gate).toContain("Atomic indicators must stay in the");
  });

  it.each([["ip", "203.0.113.9"], ["domain", "old.example"], ["hash", "b".repeat(64)]])(
    "refuses an old uncurated %s indicator before writing",
    (type, value) => {
      expect(() => assertNoAtomicInCatalog([entry({ type, value })])).toThrow(
        /import refused: 1 atomic indicator/,
      );
    },
  );

  it("names the offending indicator so the fix is obvious", () => {
    expect(() =>
      assertNoAtomicInCatalog([entry({ type: "domain", value: "old.example" })]),
    ).toThrow(/domain "old\.example"/);
  });

  // The control in the other direction: a catalog of packages is fine, and an
  // empty one is fine, so the check is not simply refusing everything.
  it("allows a catalog of packages, and an empty one", () => {
    expect(() => assertNoAtomicInCatalog([entry(), entry({ value: "b@1" })])).not.toThrow();
    expect(() => assertNoAtomicInCatalog([])).not.toThrow();
  });

  // Failing at the next build is too late for an automated daily import: the
  // tree has already been rewritten. The importer refuses before writing.
  it("the importer refuses before writing anything", async () => {
    const fsMod = await import("node:fs");
    const pathMod = await import("node:path");
    const importer = fsMod.readFileSync(
      pathMod.resolve(__dirname, "..", "..", "scripts", "import-threat-feed.mjs"),
      "utf8",
    );
    const refusal = importer.indexOf("assertNoAtomicInCatalog(toCatalog)");
    const firstWrite = importer.indexOf("writeFileSync(threatIntelPath, updated)");
    expect(refusal).toBeGreaterThan(-1);
    expect(firstWrite).toBeGreaterThan(-1);
    expect(refusal).toBeLessThan(firstWrite);
  });
});


describe("routeEntries", () => {
  it("sends each entry to the destination the policy names", () => {
    const { toBundle, toCatalog } = routeEntries(
      [
        entry({ value: "old@1.0.0" }),
        entry({ value: "fresh@1.0.0", firstSeen: "2026-09-01" }),
        entry({ value: "curated@1.0.0", campaign: "x" }),
      ],
      CONFIG,
    );
    expect(toCatalog.map((e: { value: string }) => e.value)).toEqual(["old@1.0.0"]);
    expect(toBundle.map((e: { value: string }) => e.value)).toEqual([
      "fresh@1.0.0",
      "curated@1.0.0",
    ]);
  });

  // Accounting: an entry that reached neither list would be dropped from the
  // import entirely, and the summary would still report it as added.
  it("loses nothing and duplicates nothing", () => {
    const entries = [
      entry({ value: "a@1" }),
      entry({ value: "b@1", firstSeen: "2026-09-01" }),
      entry({ value: "c@1" }),
      entry({ value: "d@1", family: "f" }),
    ];
    const { toBundle, toCatalog } = routeEntries(entries, CONFIG);
    expect(toBundle.length + toCatalog.length).toBe(entries.length);
    const seen = new Set([...toBundle, ...toCatalog].map((e: { value: string }) => e.value));
    expect(seen.size).toBe(entries.length);
  });

  it("returns two empty lists for no entries", () => {
    expect(routeEntries([], CONFIG)).toEqual({ toBundle: [], toCatalog: [] });
  });

  // The control that the split is doing something. If everything landed in one
  // list the tests above could still pass on a degenerate input set.
  it("actually splits a mixed set", () => {
    const { toBundle, toCatalog } = routeEntries(
      [entry({ value: "old@1" }), entry({ value: "new@1", firstSeen: "2026-09-01" })],
      CONFIG,
    );
    expect(toBundle).toHaveLength(1);
    expect(toCatalog).toHaveLength(1);
  });
});

describe("rule 5: declared bulk-backfill windows", () => {
  // Rule 4 reads age from firstSeen, which is the advisory's PUBLICATION date.
  // The September 2026 waves are historical by content but were published on
  // five days, so every entry carries a firstSeen inside the window and the
  // date rule reads the whole corpus as fresh. Measured: 8,548 entries in one
  // range, all bundle-bound, against a budget of 15,000.
  const WINDOWED = {
    ...CONFIG,
    catalogWindows: [{ since: "2026-09-02", until: "2026-09-13", reason: "bulk backfill" }],
  };

  it("routes an entry published inside a declared window to the catalog", () => {
    expect(partitionTarget(entry({ firstSeen: "2026-09-06" }), WINDOWED)).toBe("catalog");
  });

  // The control: the SAME entry without the window goes to the bundle, so the
  // window is doing the work rather than the date.
  it("would otherwise be bundled by date", () => {
    expect(partitionTarget(entry({ firstSeen: "2026-09-06" }), CONFIG)).toBe("bundle");
  });

  it("is inclusive on both ends, and excludes the days either side", () => {
    expect(partitionTarget(entry({ firstSeen: "2026-09-02" }), WINDOWED)).toBe("catalog");
    expect(partitionTarget(entry({ firstSeen: "2026-09-13" }), WINDOWED)).toBe("catalog");
    expect(partitionTarget(entry({ firstSeen: "2026-09-01" }), WINDOWED)).toBe("bundle");
    expect(partitionTarget(entry({ firstSeen: "2026-09-14" }), WINDOWED)).toBe("bundle");
  });

  // Curation still wins. A window is a statement about a bulk corpus, not a
  // licence to move something a human deliberately kept.
  it("never moves a curated entry", () => {
    expect(
      partitionTarget(entry({ firstSeen: "2026-09-06", campaign: "x" }), WINDOWED),
    ).toBe("bundle");
  });

  // Package-only, so a declared window cannot quietly strip the offline scan of
  // a domain or a hash.
  it.each([["ip", "203.0.113.9"], ["domain", "burst.example"], ["hash", "c".repeat(64)]])(
    "never moves a %s indicator by window",
    (type, value) => {
      expect(partitionTarget(entry({ type, value, firstSeen: "2026-09-06" }), WINDOWED)).toBe(
        "bundle",
      );
    },
  );

  it("ignores an entry with no usable date", () => {
    expect(partitionTarget(entry({ firstSeen: undefined }), WINDOWED)).toBe("bundle");
  });

  it("treats a config with no windows exactly as before", () => {
    expect(partitionTarget(entry({ firstSeen: "2026-09-06" }), { ...CONFIG })).toBe("bundle");
    expect(
      partitionTarget(entry({ firstSeen: "2026-09-06" }), { ...CONFIG, catalogWindows: [] }),
    ).toBe("bundle");
  });
});
