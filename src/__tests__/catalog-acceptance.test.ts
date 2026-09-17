import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";

import {
  loadThreatIntel,
  lastCatalogState,
  checkThreatIntel,
  matchPackageIOC,
  getBundledFeed,
  resetThreatIntelCache,
  getDetectionSetProvenance,
  CATALOG_CACHE_FILE,
} from "../threat-intel.js";
import { catalogFindings, CATALOG_MISSING_RULE } from "../feed.js";
import { matchBareNpmIOC } from "../install-guard.js";
import { CATALOG_DIGEST } from "../catalog-digest.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  resetThreatIntelCache();
});

const tmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "scg-accept-"));
  dirs.push(d);
  return d;
};

// Indicators that exist ONLY in the catalog. If any of these were also in the
// bundle the test would pass without the catalog doing anything, which is the
// failure mode this whole file exists to rule out.
const CATALOG_ONLY_PACKAGE = "catalog-only-acceptance-pkg";
const CATALOG_ONLY_PYPI = "catalog-only-acceptance-dist";
const CATALOG_ONLY_DOMAIN = "catalog-only-acceptance.example";

const CATALOG_ENTRIES = [
  {
    type: "package",
    value: `${CATALOG_ONLY_PACKAGE}@1.0.0`,
    severity: "critical",
    confidence: 1,
    source: "acceptance-fixture",
  },
  {
    type: "package",
    value: `pypi:${CATALOG_ONLY_PYPI}@2.0.0`,
    severity: "critical",
    confidence: 1,
    source: "acceptance-fixture",
  },
  {
    type: "domain",
    value: CATALOG_ONLY_DOMAIN,
    severity: "critical",
    confidence: 1,
    source: "acceptance-fixture",
  },
];

/** Write a catalog cache the loader accepts, exactly as refreshFeed writes it. */
const installCatalog = (dir: string, entries: unknown[] = CATALOG_ENTRIES) => {
  const pinned: number = CATALOG_DIGEST.entryCount;
  const complete = entries.slice();
  for (let i = complete.length; i < pinned; i++) {
    complete.push({
      type: "package",
      value: `catalog-accept-pad-${i}@0.0.0`,
      severity: "low",
      confidence: 1,
    });
  }
  fs.writeFileSync(
    path.join(dir, CATALOG_CACHE_FILE),
    JSON.stringify({
      version: CATALOG_DIGEST.version,
      sha256: CATALOG_DIGEST.sha256,
      checksum: createHash("sha256").update(JSON.stringify(complete), "utf8").digest("hex"),
      timestamp: new Date().toISOString(),
      entries: complete,
    }),
  );
};

describe("Phase 1 acceptance: an indicator that exists only in the catalog is detected", () => {
  // The control, first and in both directions. These indicators must NOT be in
  // the bundle, or every assertion below is satisfied without the catalog.
  it("the fixture indicators are absent from the bundled feed", () => {
    const bundled = getBundledFeed();
    expect(bundled.some((e) => e.value.startsWith(CATALOG_ONLY_PACKAGE))).toBe(false);
    expect(bundled.some((e) => e.value === CATALOG_ONLY_DOMAIN)).toBe(false);
    expect(bundled.some((e) => e.value.includes(CATALOG_ONLY_PYPI))).toBe(false);
  });

  it("without the catalog, the package is not matched", () => {
    const feed = loadThreatIntel(tmp());
    // A BARE value means the npm namespace, and bare npm entries resolve
    // through matchBareNpmIOC. matchPackageIOC("npm", ...) requires an explicit
    // "npm:" prefix and returns null for a bare entry, which reads exactly like
    // a missing indicator; asking the wrong resolver here would make the
    // positive case below fail for a reason that has nothing to do with the
    // catalog.
    expect(matchBareNpmIOC(CATALOG_ONLY_PACKAGE, "1.0.0", feed)).toBeNull();
    expect(matchPackageIOC("pypi", CATALOG_ONLY_PYPI, "2.0.0", feed)).toBeNull();
  });

  // The claim the whole design rests on: moving an indicator out of the
  // compiled bundle and into the downloadable catalog does not stop it being
  // enforced. This is what makes the Phase 2 migration safe.
  it("with the catalog, the package IS matched by the same matcher the scanner uses", () => {
    const dir = tmp();
    installCatalog(dir);
    const feed = loadThreatIntel(dir);

    expect(lastCatalogState().available).toBe(true);

    const bare = matchBareNpmIOC(CATALOG_ONLY_PACKAGE, "1.0.0", feed);
    expect(bare).not.toBeNull();
    expect(bare?.severity).toBe("critical");

    // And the prefixed path, through the matcher the scanner uses for every
    // non-npm ecosystem.
    const prefixed = matchPackageIOC("pypi", CATALOG_ONLY_PYPI, "2.0.0", feed);
    expect(prefixed).not.toBeNull();
    expect(prefixed?.severity).toBe("critical");
  });

  it("with the catalog, a file referencing the domain produces a finding", () => {
    const withoutCatalog = loadThreatIntel(tmp());
    expect(
      checkThreatIntel(`const c = "${CATALOG_ONLY_DOMAIN}";`, "src/app.js", withoutCatalog),
    ).toHaveLength(0);

    const dir = tmp();
    installCatalog(dir);
    const withCatalog = loadThreatIntel(dir);
    const findings = checkThreatIntel(
      `const c = "${CATALOG_ONLY_DOMAIN}";`,
      "src/app.js",
      withCatalog,
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("reports the catalog entries in the effective detection-set count", () => {
    const dir = tmp();
    installCatalog(dir);
    expect(getDetectionSetProvenance(dir).effectiveEntryCount).toBe(
      getBundledFeed().length + CATALOG_DIGEST.entryCount,
    );
  });
});

describe("Phase 1 acceptance: the absence of the catalog is reported, never silent", () => {
  // The other half. If the catalog cannot be consulted the scan must say so,
  // otherwise a narrower scan reports the same success as a complete one, which
  // is the silent false negative this repository exists to prevent.
  it("names the rule when a non-empty catalog is missing", () => {
    // Forced to required, because while the release pins an EMPTY catalog the
    // optional path is deliberately silent: there is no coverage to miss yet.
    const findings = catalogFindings(
      { available: false, reason: "absent", entryCount: 0 },
      "required",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe(CATALOG_MISSING_RULE);
    expect(findings[0].severity).toBe("critical");
  });

  it("says nothing once the catalog is available", () => {
    const dir = tmp();
    installCatalog(dir);
    loadThreatIntel(dir);
    expect(catalogFindings(lastCatalogState(), "required")).toEqual([]);
  });
});

describe("Phase 2 acceptance: the corpus is partitioned, not reduced", () => {
  // The migration moved 11,998 indicators out of the compiled bundle. The claim
  // that matters is that none of them was LOST: every indicator is now in
  // exactly one of the two stores, and the two together are what the bundle
  // alone used to be.
  it("bundle plus catalog accounts for every indicator, with no overlap", () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    const catalogLines = fs
      .readFileSync(path.join(repoRoot, "data", "threat-catalog.jsonl"), "utf8")
      .split(/\r?\n/)
      .filter((l) => l.trim() !== "");

    const bundled = getBundledFeed();
    const catalogValues = new Set(catalogLines.map((l) => JSON.parse(l).value));
    const bundledValues = new Set(bundled.map((e) => e.value));

    // Derived, not hardcoded. An earlier version pinned 8,971 and 11,998 and
    // went red the moment a deferred range was drained, which says nothing
    // about whether an indicator was lost. The invariant that matters is that
    // the two stores account for everything and overlap nowhere.
    expect(bundled.length).toBeGreaterThan(0);
    expect(catalogLines.length).toBeGreaterThan(0);
    expect(bundledValues.size).toBe(bundled.length);
    expect(catalogValues.size).toBe(catalogLines.length);

    // Disjoint: an indicator in both would be carried twice and counted twice.
    const both = [...bundledValues].filter((v) => catalogValues.has(v));
    expect(both.slice(0, 3)).toEqual([]);

    // Floor, not a pinned total. Deleting entries from either store used to
    // leave this test green because every assertion is monotone under
    // deletion. Bump the floor when the corpus grows; never lower it without
    // a recorded reason. 9,015 bundled + 68,234 catalog as of the Phase 3
    // drain that shipped on this branch.
    expect(bundled.length + catalogLines.length).toBeGreaterThanOrEqual(77249);
  });

  it("the shipped digest describes the shipped catalog", () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    const lines = fs
      .readFileSync(path.join(repoRoot, "data", "threat-catalog.jsonl"), "utf8")
      .split(/\r?\n/)
      .filter((l) => l.trim() !== "");
    expect(CATALOG_DIGEST.entryCount).toBe(lines.length);
  });

  it("feed.json matches the bundle that remains", () => {
    const repoRoot = path.resolve(__dirname, "..", "..");
    const feed = JSON.parse(fs.readFileSync(path.join(repoRoot, "feed.json"), "utf8"));
    expect(getBundledFeed().length).toBe(feed.entryCount);
  });

  // Every catalog line has to survive the loader, or the indicator is silently
  // quarantined and the migration has removed it from detection after all.
  it("every committed catalog line passes the real isValidFeedIOC", async () => {
    const { isValidFeedIOC } = await import("../threat-intel.js");
    const repoRoot = path.resolve(__dirname, "..", "..");
    const lines = fs
      .readFileSync(path.join(repoRoot, "data", "threat-catalog.jsonl"), "utf8")
      .split(/\r?\n/)
      .filter((l) => l.trim() !== "");

    const rejected = lines.filter((l) => !isValidFeedIOC(JSON.parse(l)));
    expect(rejected.slice(0, 3)).toEqual([]);
    expect(rejected).toHaveLength(0);
  }, 60_000);

  // The curated rationale is the thing the comment anchor exists to protect.
  it("keeps every curated comment line in the bundle", async () => {
    const { parseChunks } = await import("../../scripts/feed-migrate.mjs");
    const repoRoot = path.resolve(__dirname, "..", "..");
    const source = fs.readFileSync(path.join(repoRoot, "src", "threat-intel.ts"), "utf8");
    const groups = parseChunks(source);

    const curatedLines = groups
      .filter((g: { isCurated: boolean }) => g.isCurated)
      .reduce((sum: number, g: { header: string[] }) => sum + g.header.length, 0);
    // At least the 706 that existed before the migration. Curated prose may
    // GROW, and did: restoring the campaign indicators added a header. What
    // must never happen is losing one, which is what the comment anchor exists
    // to prevent.
    expect(curatedLines).toBeGreaterThanOrEqual(706);

    // No comment block left describing entries that are no longer beneath it.
    expect(groups.filter((g: { entries: unknown[] }) => g.entries.length === 0)).toHaveLength(0);
  }, 60_000);
});
