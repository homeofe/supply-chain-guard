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
import { catalogFindings } from "../feed.js";
import { CATALOG_DIGEST } from "../catalog-digest.js";
import { readCatalogEntries } from "../../scripts/generate-catalog.mjs";

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

// Positive cache tests use the real committed catalog because exact content,
// not merely a synthetic replacement of the same size, is authenticated.
const REAL_CATALOG = readCatalogEntries();
const NOVEL = REAL_CATALOG[0].value as string;
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
    writeCatalog(dir, {}, REAL_CATALOG);
    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({
      available: true,
      entryCount: CATALOG_DIGEST.entryCount,
      cachedVersion: CATALOG_DIGEST.version,
    });
    expect(feed.some((e) => e.value === NOVEL)).toBe(true);
  });

  // A short cache with a matching header is the same shape as the empty
  // forgery below. It is not this release's catalog, even when the checksum
  // over its own entries is consistent.
  it("refuses a short cache whose checksum matches its own entries", () => {
    const dir = tmp();
    writeCatalog(dir);
    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({
      available: false,
      reason: "digest-mismatch",
    });
    expect(feed.some((e) => e.value === NOVEL)).toBe(false);
  });

  // version, sha256 and the self-checksum are all public or self-computed, so a
  // scanned repository can commit an empty cache that looks well-formed. The
  // package-anchored entries digest must still refuse it.
  it("refuses an empty cache whose checksum was recomputed over the empty list", () => {
    const dir = tmp();
    writeCatalog(dir, {}, []);
    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({
      available: false,
      reason: "digest-mismatch",
    });
    expect(feed).toHaveLength(getBundledFeed().length);
    expect(catalogFindings(lastCatalogState(), "required")).toHaveLength(1);
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

  // The checksum beside the entries makes an edited or truncated cache
  // distinguishable from a self-consistent replacement, so the finding can
  // report corruption rather than a package digest mismatch.
  // Removing entries is the dangerous direction: it silently disables
  // detection, and nothing else in this function would notice.
  it("refuses a catalog whose entries were edited under a valid header", () => {
    const dir = tmp();
    writeCatalog(dir, {}, REAL_CATALOG);
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

  // The control in the other direction: the exact catalog produced by the
  // release is accepted, so the check is not simply refusing everything.
  it("accepts the exact catalog this release pins", () => {
    const dir = tmp();
    writeCatalog(dir, {}, REAL_CATALOG);
    loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({
      available: true,
      entryCount: CATALOG_DIGEST.entryCount,
    });
  });

  it("quarantines malformed catalog entries instead of trusting them", () => {
    const dir = tmp();
    const mixed = [entryFor(NOVEL), { type: "package", value: "", severity: "critical" }];
    writeCatalog(dir, {}, mixed as never);
    loadThreatIntel(dir);
    // One surviving entry against a non-zero pin is not this release's catalog,
    // so the malformed entry is not merged either.
    expect(lastCatalogState()).toMatchObject({
      available: false,
      reason: "digest-mismatch",
    });
    expect(loadThreatIntel(dir).some((e) => e.value === NOVEL)).toBe(false);
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

    writeCatalog(dir, {}, REAL_CATALOG);
    const after = loadThreatIntel(dir);

    expect(lastCatalogState().available).toBe(true);
    expect(after.length).toBe(before.length + CATALOG_DIGEST.entryCount);
  });

  it("sees a catalog that is removed after being merged", () => {
    const dir = tmp();
    writeCatalog(dir, {}, REAL_CATALOG);
    const withCatalog = loadThreatIntel(dir);
    expect(lastCatalogState().available).toBe(true);

    fs.rmSync(path.join(dir, CATALOG_CACHE_FILE));
    const without = loadThreatIntel(dir);

    expect(lastCatalogState()).toMatchObject({ available: false, reason: "absent" });
    expect(without.length).toBe(withCatalog.length - CATALOG_DIGEST.entryCount);
  });
});

describe("catalog content authentication", () => {
  // Matching the public header, self-checksum and exact entry count used to be
  // enough. Repeating one valid IOC to the pinned length proves that content,
  // not just shape and size, is now anchored in the package.
  it("refuses a self-consistent full-size replacement", () => {
    const dir = tmp();
    const forged = Array.from({ length: CATALOG_DIGEST.entryCount }, () => entryFor(NOVEL));
    writeCatalog(dir, {}, forged);

    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({
      available: false,
      reason: "digest-mismatch",
    });
    expect(feed).toHaveLength(getBundledFeed().length);
  });
});

describe("detection-set provenance counts the catalog", () => {
  // This reader used to count the bundle alone unless a FRESH feed cache
  // existed, so a merged catalog was reported as no coverage at all.
  it("reports the effective count with a catalog but no feed cache", () => {
    const dir = tmp();
    writeCatalog(dir, {}, REAL_CATALOG);
    const provenance = getDetectionSetProvenance(dir);

    expect(provenance.cacheMerged).toBe(false);
    expect(provenance.bundledEntryCount).toBe(getBundledFeed().length);
    expect(provenance.effectiveEntryCount).toBe(
      getBundledFeed().length + CATALOG_DIGEST.entryCount,
    );
  });

  it("still reports the bundle alone when nothing is cached", () => {
    const dir = tmp();
    const provenance = getDetectionSetProvenance(dir);
    expect(provenance.effectiveEntryCount).toBe(getBundledFeed().length);
  });

  it("leaves the feed cache state untouched by the catalog", () => {
    const dir = tmp();
    writeCatalog(dir, {}, REAL_CATALOG);
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
    writeCatalog(dir, {}, REAL_CATALOG);

    const feed = loadThreatIntel(dir);
    expect(feed.some((e) => e.value === feedOnly.value)).toBe(true);
    expect(feed.some((e) => e.value === NOVEL)).toBe(true);
    expect(feed).toHaveLength(getBundledFeed().length + 1 + CATALOG_DIGEST.entryCount);
  });
});
