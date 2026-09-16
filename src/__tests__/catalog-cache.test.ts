import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";

import {
  loadThreatIntel,
  lastCatalogState,
  getFeedCacheState,
  getBundledFeed,
  resetThreatIntelCache,
  CATALOG_CACHE_FILE,
  FEED_CACHE_FILE,
  getDetectionSetProvenance,
} from "../threat-intel.js";
import { CATALOG_DIGEST } from "../catalog-digest.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  resetThreatIntelCache();
});

const tmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "scg-catalog-"));
  dirs.push(d);
  return d;
};

// A value that cannot already be in the bundle, so a successful merge is
// visible as a length change rather than being swallowed by mergeFeeds.
const NOVEL = "catalog-only-fixture-pkg@9.9.9";
const entryFor = (value: string) => ({
  type: "package" as const,
  value,
  severity: "critical" as const,
  confidence: 1,
});

const checksumOf = (entries: unknown) =>
  createHash("sha256").update(JSON.stringify(entries), "utf8").digest("hex");

const writeCatalog = (
  dir: string,
  over: Record<string, unknown> = {},
  entries = [entryFor(NOVEL)],
) => {
  const doc = {
    version: CATALOG_DIGEST.version,
    sha256: CATALOG_DIGEST.sha256,
    checksum: checksumOf(entries),
    entries,
    ...over,
  };
  fs.writeFileSync(path.join(dir, CATALOG_CACHE_FILE), JSON.stringify(doc));
  return doc;
};

describe("catalog cache availability", () => {
  it("reports absent when no catalog has been downloaded", () => {
    const dir = tmp();
    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "absent" });
    expect(feed).toHaveLength(getBundledFeed().length);
  });

  it("merges a matching catalog and reports it available", () => {
    const dir = tmp();
    writeCatalog(dir);
    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({
      available: true,
      entryCount: 1,
      cachedVersion: CATALOG_DIGEST.version,
    });
    expect(feed).toHaveLength(getBundledFeed().length + 1);
    expect(feed.some((e) => e.value === NOVEL)).toBe(true);
  });

  it("refuses a catalog built for a different release", () => {
    const dir = tmp();
    writeCatalog(dir, { version: "0.0.1-other" });
    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({
      available: false,
      reason: "version-mismatch",
      cachedVersion: "0.0.1-other",
    });
    expect(feed.some((e) => e.value === NOVEL)).toBe(false);
  });

  it("refuses a catalog built from a different index digest", () => {
    const dir = tmp();
    writeCatalog(dir, { sha256: "0".repeat(64) });
    loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "digest-mismatch" });
  });

  it("refuses an unreadable catalog without throwing", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, CATALOG_CACHE_FILE), "{not json");
    expect(() => loadThreatIntel(dir)).not.toThrow();
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "unreadable" });
  });

  it("refuses a catalog whose entries are not an array", () => {
    const dir = tmp();
    fs.writeFileSync(
      path.join(dir, CATALOG_CACHE_FILE),
      JSON.stringify({ version: CATALOG_DIGEST.version, sha256: CATALOG_DIGEST.sha256, entries: 7 }),
    );
    loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "unreadable" });
  });

  // Shape is checked BEFORE provenance. Without the structural guard this
  // reports "version-mismatch", because the version comparison runs first and a
  // malformed document still has a version field; the caller is then sent
  // looking for a stale download instead of a corrupt file. The earlier
  // non-array test does not catch that on its own: with the guard removed it
  // still lands on "unreadable", but by way of the exception handler rather
  // than the guard, so it passes either way.
  it("reports a malformed catalog as unreadable even when the version is wrong too", () => {
    const dir = tmp();
    fs.writeFileSync(
      path.join(dir, CATALOG_CACHE_FILE),
      JSON.stringify({ version: "0.0.1-other", sha256: CATALOG_DIGEST.sha256, entries: 7 }),
    );
    loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "unreadable" });
  });

  // The version and digest fields compare the cache against constants compiled
  // into this package, so they cannot see an edit to the entries sitting beside
  // them. The checksum is what makes an edited or truncated cache detectable.
  // Removing entries is the dangerous direction: it silently disables
  // detection, and nothing else in this function would notice.
  it("refuses a catalog whose entries were edited under a valid header", () => {
    const dir = tmp();
    const good = [entryFor(NOVEL), entryFor("second-fixture-pkg@9.9.9")];
    writeCatalog(dir, {}, good);
    const file = path.join(dir, CATALOG_CACHE_FILE);
    const doc = JSON.parse(fs.readFileSync(file, "utf-8"));

    // Truncate the entries, leave version, sha256 and checksum untouched.
    doc.entries = [doc.entries[0]];
    fs.writeFileSync(file, JSON.stringify(doc));

    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "corrupt" });
    expect(feed.some((e) => e.value === NOVEL)).toBe(false);
  });

  // Deleting one line must not skip verification. While the comparison was
  // guarded on the field being present, removing it was enough to have the
  // entries merged unread, which defeats the check entirely.
  it("refuses a catalog with no checksum at all", () => {
    const dir = tmp();
    fs.writeFileSync(
      path.join(dir, CATALOG_CACHE_FILE),
      JSON.stringify({
        version: CATALOG_DIGEST.version,
        sha256: CATALOG_DIGEST.sha256,
        entries: [entryFor(NOVEL)],
      }),
    );
    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "corrupt" });
    expect(feed.some((e) => e.value === NOVEL)).toBe(false);
  });

  // The control in the other direction: a cache whose checksum was recomputed
  // after a legitimate rewrite is accepted, so the check is not simply refusing
  // everything.
  it("accepts a catalog whose checksum matches its entries", () => {
    const dir = tmp();
    const two = [entryFor(NOVEL), entryFor("second-fixture-pkg@9.9.9")];
    writeCatalog(dir, {}, two);
    loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: true, entryCount: 2 });
  });

  it("quarantines malformed catalog entries instead of trusting them", () => {
    const dir = tmp();
    const mixed = [entryFor(NOVEL), { type: "package", value: "", severity: "critical" }];
    writeCatalog(dir, {}, mixed as never);
    loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: true, entryCount: 1 });
  });
});

describe("the catalog participates in the memo identity", () => {
  // Without the catalog stamp in the memo key, a catalog that arrives after the
  // first load stays invisible until the FEED cache happens to change, and the
  // process keeps matching against a set built before the catalog existed.
  it("sees a catalog that arrives after the first load", () => {
    const dir = tmp();
    const before = loadThreatIntel(dir);
    expect(lastCatalogState().available).toBe(false);

    writeCatalog(dir);
    const after = loadThreatIntel(dir);

    expect(lastCatalogState().available).toBe(true);
    expect(after.length).toBe(before.length + 1);
  });

  it("sees a catalog that is removed after being merged", () => {
    const dir = tmp();
    writeCatalog(dir);
    const withCatalog = loadThreatIntel(dir);
    expect(lastCatalogState().available).toBe(true);

    fs.rmSync(path.join(dir, CATALOG_CACHE_FILE));
    const without = loadThreatIntel(dir);

    expect(lastCatalogState()).toMatchObject({ available: false, reason: "absent" });
    expect(without.length).toBe(withCatalog.length - 1);
  });
});

describe("the catalog does not override the bundle", () => {
  // mergeFeeds is first-wins on type:value and the catalog is merged last, so
  // the compiled bundle and the fresher feed stay authoritative for anything
  // all of them carry. A downloaded document must not be able to downgrade a
  // severity that ships in the package.
  it("keeps the bundled entry when both carry the same indicator", () => {
    const dir = tmp();
    const bundled = getBundledFeed()[0];
    writeCatalog(dir, {}, [{ ...bundled, severity: "info", confidence: 0.01 }]);

    const feed = loadThreatIntel(dir);
    const match = feed.filter((e) => e.type === bundled.type && e.value === bundled.value);
    expect(match).toHaveLength(1);
    expect(match[0].severity).toBe(bundled.severity);
  });
});

describe("detection-set provenance counts the catalog", () => {
  // This reader used to count the bundle alone unless a FRESH feed cache
  // existed, so a merged catalog was reported as no coverage at all.
  it("reports the effective count with a catalog but no feed cache", () => {
    const dir = tmp();
    writeCatalog(dir);
    const provenance = getDetectionSetProvenance(dir);

    expect(provenance.cacheMerged).toBe(false);
    expect(provenance.bundledEntryCount).toBe(getBundledFeed().length);
    expect(provenance.effectiveEntryCount).toBe(getBundledFeed().length + 1);
  });

  it("still reports the bundle alone when nothing is cached", () => {
    const dir = tmp();
    const provenance = getDetectionSetProvenance(dir);
    expect(provenance.effectiveEntryCount).toBe(getBundledFeed().length);
  });

  it("leaves the feed cache state untouched by the catalog", () => {
    const dir = tmp();
    writeCatalog(dir);
    loadThreatIntel(dir);
    expect(getFeedCacheState()).toMatchObject({ present: false });
    expect(lastCatalogState().available).toBe(true);
  });
});

describe("feed and catalog caches are independent", () => {
  it("merges both when both are present", () => {
    const dir = tmp();
    const feedOnly = entryFor("feed-only-fixture-pkg@9.9.9");
    fs.writeFileSync(
      path.join(dir, FEED_CACHE_FILE),
      JSON.stringify({ timestamp: new Date().toISOString(), entries: [feedOnly] }),
    );
    writeCatalog(dir);

    const feed = loadThreatIntel(dir);
    expect(feed.some((e) => e.value === feedOnly.value)).toBe(true);
    expect(feed.some((e) => e.value === NOVEL)).toBe(true);
    expect(feed).toHaveLength(getBundledFeed().length + 2);
  });
});
