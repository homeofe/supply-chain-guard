import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";

import { scan } from "../scanner.js";
import { formatReport } from "../reporter.js";
import {
  CATALOG_CACHE_FILE,
  getDetectionSetProvenance,
  lastCatalogState,
  loadThreatIntel,
  resetThreatIntelCache,
} from "../threat-intel.js";
import { CATALOG_DIGEST } from "../catalog-digest.js";
import { catalogCoverageNote, catalogCoverageOf } from "../mcp-server.js";
import { readCatalogEntries } from "../../scripts/generate-catalog.mjs";
import type { ScanReport } from "../types.js";

// Why this file exists. THREAT_FEED_CATALOG_MISSING is `info` on purpose: it
// fires on every fresh install, and a finding that turns every first run yellow
// gets the tool switched off (PR 309). But `info` is exactly what the default
// `--min-severity low` removes, and that is the GitHub Action's default. So a
// default Action run matched against the bundled set alone and nothing in the
// report said so. The detection-set provenance now carries the catalog state,
// and every format renders it whatever the severity filter.

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  resetThreatIntelCache();
});

const tmp = (prefix: string) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  dirs.push(d);
  return d;
};

/** Write a catalog cache the loader accepts, exactly as refreshFeed writes it. */
const installCatalog = (dir: string) => {
  const entries = readCatalogEntries();
  fs.writeFileSync(
    path.join(dir, CATALOG_CACHE_FILE),
    JSON.stringify({
      version: CATALOG_DIGEST.version,
      sha256: CATALOG_DIGEST.sha256,
      checksum: createHash("sha256").update(JSON.stringify(entries), "utf8").digest("hex"),
      timestamp: new Date().toISOString(),
      entries,
    }),
  );
};

/** A small tree with one real file, so the scan has a denominator. */
const cleanTarget = () => {
  const dir = tmp("scg-coverage-target-");
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "coverage-fixture", version: "1.0.0" }),
  );
  return dir;
};

const NOT_CONSULTED = "historical catalog indicators were not consulted";

describe("the release pins a non-empty catalog", () => {
  // Every assertion below about "not consulted" is vacuous if the release pins
  // an empty catalog, because the line is deliberately omitted then.
  it("has catalog entries to miss", () => {
    expect(CATALOG_DIGEST.entryCount).toBeGreaterThan(0);
  });
});

describe("detection-set provenance records the catalog", () => {
  it("without a cache, the catalog is recorded as not consulted, with the reason", () => {
    const provenance = getDetectionSetProvenance(tmp("scg-coverage-cache-"));
    expect(provenance.catalog).toEqual({
      consulted: false,
      entryCount: CATALOG_DIGEST.entryCount,
      reason: "absent",
    });
  });

  it("with an accepted cache, the catalog is recorded as consulted", () => {
    const dir = tmp("scg-coverage-cache-");
    installCatalog(dir);
    const provenance = getDetectionSetProvenance(dir);
    expect(provenance.catalog).toEqual({
      consulted: true,
      entryCount: CATALOG_DIGEST.entryCount,
    });
  });

  it("prefers the state snapshot the scanner passes over a later load", () => {
    const withCatalog = tmp("scg-coverage-cache-");
    installCatalog(withCatalog);
    // The snapshot says absent; the directory would say available. The
    // snapshot must win, or a nested load could rewrite what this scan reports.
    const provenance = getDetectionSetProvenance(withCatalog, {
      available: false,
      reason: "absent",
      entryCount: 0,
    });
    expect(provenance.catalog?.consulted).toBe(false);
  });
});

describe("a scan at the Action's default severity threshold still states it", () => {
  it("records the catalog as not consulted even though the info finding is filtered", async () => {
    const report = await scan({
      target: cleanTarget(),
      format: "markdown",
      minSeverity: "low",
      noHistory: true,
      cacheDir: tmp("scg-coverage-cache-"),
    });

    // The control: at this threshold the finding itself is gone. This is the
    // exact state that used to be silent.
    expect(report.findings.map((f) => f.rule)).not.toContain("THREAT_FEED_CATALOG_MISSING");

    expect(report.detectionSet?.catalog?.consulted).toBe(false);
    expect(formatReport(report, "markdown")).toContain(NOT_CONSULTED);
    expect(formatReport(report, "text")).toContain(NOT_CONSULTED);
  });

  it("does not turn a clean scan into a finding: score, level and count are unchanged", async () => {
    const report = await scan({
      target: cleanTarget(),
      format: "json",
      minSeverity: "low",
      noHistory: true,
      cacheDir: tmp("scg-coverage-cache-"),
    });
    expect(report.findings).toEqual([]);
    expect(report.riskLevel).toBe("clean");
    expect(report.score).toBe(0);
  });

  it("says the catalog was consulted when the cache was accepted", async () => {
    const cacheDir = tmp("scg-coverage-cache-");
    installCatalog(cacheDir);
    const report = await scan({
      target: cleanTarget(),
      format: "markdown",
      minSeverity: "low",
      noHistory: true,
      cacheDir,
    });
    expect(report.detectionSet?.catalog?.consulted).toBe(true);
    const md = formatReport(report, "markdown");
    expect(md).not.toContain(NOT_CONSULTED);
    expect(md).toContain("Historical catalog consulted");
  });
});

describe("every report format renders the catalog state", () => {
  const baseReport = (consulted: boolean): ScanReport => ({
    tool: "supply-chain-guard",
    timestamp: "2026-09-25T00:00:00.000Z",
    target: "/fixture",
    scanType: "directory",
    durationMs: 1,
    findings: [],
    summary: { totalFiles: 1, filesScanned: 1, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    score: 0,
    riskLevel: "clean",
    recommendations: [],
    detectionSet: {
      bundledVersion: "0.0.0",
      bundledEntryCount: 10,
      cacheMerged: false,
      effectiveEntryCount: consulted ? 40 : 10,
      catalog: consulted
        ? { consulted: true, entryCount: 30 }
        : { consulted: false, entryCount: 30, reason: "absent" },
    },
  });

  for (const format of ["text", "markdown", "html", "gitlab", "junit"] as const) {
    it(`${format}: says the catalog was not consulted, and says consulted when it was`, () => {
      const skipped = formatReport(baseReport(false), format);
      expect(skipped).toContain(NOT_CONSULTED);
      expect(skipped).toContain("feed refresh");
      const included = formatReport(baseReport(true), format);
      expect(included).not.toContain(NOT_CONSULTED);
      expect(included).toContain("Historical catalog consulted");
    });
  }

  it("json and sarif carry the structured record", () => {
    const json = JSON.parse(formatReport(baseReport(false), "json"));
    expect(json.detectionSet.catalog).toEqual({ consulted: false, entryCount: 30, reason: "absent" });
    const sarif = JSON.parse(formatReport(baseReport(false), "sarif"));
    expect(sarif.runs[0].properties.detectionSet.catalog.consulted).toBe(false);
  });

  it("sbom carries the catalog as properties", () => {
    const sbom = JSON.parse(formatReport(baseReport(false), "sbom"));
    const props = new Map(
      (sbom.metadata.properties as Array<{ name: string; value: string }>).map((p) => [p.name, p.value]),
    );
    expect(props.get("supply-chain-guard:detection-set:catalog-consulted")).toBe("false");
    expect(props.get("supply-chain-guard:detection-set:catalog-entry-count")).toBe("30");
  });

  it("stays silent about the catalog when the release pins an empty one", () => {
    const report = baseReport(false);
    report.detectionSet!.catalog = { consulted: false, entryCount: 0, reason: "absent" };
    const md = formatReport(report, "markdown");
    expect(md).not.toContain(NOT_CONSULTED);
    expect(md).not.toContain("Historical catalog consulted");
  });
});

describe("MCP ioc_lookup states which indicator set it answered from", () => {
  it("records the catalog state beside the verdict", () => {
    const record = catalogCoverageOf({ available: false, reason: "absent", entryCount: 0 });
    expect(record).toEqual({ consulted: false, entryCount: CATALOG_DIGEST.entryCount, reason: "absent" });
    expect(catalogCoverageOf({ available: true, entryCount: 5 })).toEqual({
      consulted: true,
      entryCount: CATALOG_DIGEST.entryCount,
    });
  });

  it("qualifies a clean package verdict when the catalog was not consulted", () => {
    const skipped = catalogCoverageOf({ available: false, reason: "absent", entryCount: 0 });
    const note = catalogCoverageNote("clean", skipped);
    expect(note).toContain(NOT_CONSULTED);
    expect(note).toContain("feed refresh");
  });

  it("adds no note to a malicious verdict or when the catalog was consulted", () => {
    const skipped = catalogCoverageOf({ available: false, reason: "absent", entryCount: 0 });
    const consulted = catalogCoverageOf({ available: true, entryCount: 5 });
    expect(catalogCoverageNote("malicious", skipped)).toBeUndefined();
    expect(catalogCoverageNote("clean", consulted)).toBeUndefined();
  });

  it("the live lookup result agrees with the loader's catalog state", async () => {
    const { handleMcpMessage } = await import("../mcp-server.js");
    const response = (await handleMcpMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "ioc_lookup", arguments: { ecosystem: "npm", name: "left-pad", version: "1.3.0" } },
    })) as { result: { content: Array<{ text: string }> } };
    const result = JSON.parse(response.result.content[0].text);
    const state = lastCatalogState();
    expect(result.checkedAgainst.catalog.consulted).toBe(state.available);
    expect(result.checkedAgainst.offline).toBe(true);
    if (result.verdict === "clean" && !state.available) {
      expect(result.coverageNote).toContain(NOT_CONSULTED);
    }
  });

  it("indicator lookups need no caveat: the catalog carries packages only", () => {
    const lines = fs
      .readFileSync(path.join(__dirname, "..", "..", "data", "threat-catalog.jsonl"), "utf8")
      .split(/\r?\n/)
      .filter((l) => l.trim() !== "");
    // Control in both directions: the catalog is not empty, and none of it is
    // a domain, IP, URL or hash, so the offline indicator lookup is complete.
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.filter((l) => JSON.parse(l).type !== "package")).toEqual([]);
    // loadThreatIntel is exercised so the assertion above is about the store
    // the lookup actually reads from.
    expect(loadThreatIntel(tmp("scg-coverage-cache-")).length).toBeGreaterThan(0);
  });
});
