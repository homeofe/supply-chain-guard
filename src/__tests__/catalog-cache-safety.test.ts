import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { EventEmitter } from "node:events";

vi.mock("node:https", () => {
  const get = vi.fn();
  return { default: { get }, get };
});

import * as https from "node:https";
import { refreshFeed, DEFAULT_FEED_URL, feedFreshness } from "../feed.js";
import { scan } from "../scanner.js";
import {
  CATALOG_CACHE_FILE,
  CATALOG_MARKER_FILE,
  FEED_CACHE_FILE,
  FEED_GENERATED_AT,
  getFeedCacheState,
  loadThreatIntel,
  resetThreatIntelCache,
} from "../threat-intel.js";
import { CATALOG_DIGEST } from "../catalog-digest.js";
import { readCatalogEntries, buildCatalog } from "../../scripts/generate-catalog.mjs";

// Security fixes F16 (catalog write), F17 (unusable catalog is partial) and F36
// (feed rollback / shrink / client-clock staleness). Everything goes through
// refreshFeed(), loadThreatIntel() or scan(), not through the helpers alone.

const NO_FLOOR = { minEntries: 0 };
// These suites exercise transport, cache safety and catalog behaviour with unsigned local
// routes; feed-signature.test.ts covers the signature check itself.
const ALLOW_UNSIGNED = { allowUnsigned: true };
const FEED_PATH = new URL(DEFAULT_FEED_URL).pathname;
const RELEASE_BASE = `/homeofe/supply-chain-guard/releases/download/v${CATALOG_DIGEST.version}`;

const REAL = (() => {
  const { indexJson, shards } = buildCatalog(readCatalogEntries(), CATALOG_DIGEST.version);
  return { indexJson, shards };
})();

const feedDoc = (generatedAt?: string, count = 1) =>
  JSON.stringify({
    schema: 1,
    ...(generatedAt === undefined ? {} : { generatedAt }),
    entries: Array.from({ length: count }, (_, i) => ({
      type: "domain",
      value: `feed-fixture-${i}.example`,
      severity: "critical",
      confidence: 1,
    })),
  });

const serve = (routes: Record<string, Buffer | string>) => {
  (https.get as unknown as ReturnType<typeof vi.fn>).mockImplementation(
    (options: { path?: string }, callback: (res: unknown) => void) => {
      const body = routes[options.path ?? ""];
      const res = new EventEmitter() as EventEmitter & {
        statusCode: number;
        headers: Record<string, string>;
      };
      res.statusCode = body === undefined ? 404 : 200;
      res.headers = {};
      const req = new EventEmitter();
      process.nextTick(() => {
        callback(res);
        setImmediate(() => {
          if (body !== undefined) {
            res.emit("data", typeof body === "string" ? Buffer.from(body, "utf8") : body);
          }
          res.emit("end");
        });
      });
      return req;
    },
  );
};

const realRoutes = (feed: string): Record<string, Buffer | string> => {
  const routes: Record<string, Buffer | string> = {
    [FEED_PATH]: feed,
    [`${RELEASE_BASE}/catalog-index.json`]: REAL.indexJson,
  };
  for (const shard of REAL.shards) routes[`${RELEASE_BASE}/${shard.path}`] = shard.gz;
  return routes;
};

let tmpDir: string;
beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cache-safety-"));
  vi.clearAllMocks();
  resetThreatIntelCache();
});
afterEach(() => {
  vi.useRealTimers();
  resetThreatIntelCache();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("F16: the catalog is written like the feed cache", () => {
  it("refuses a hard-linked catalog target, leaves the other file alone and fails the refresh", async () => {
    const victim = path.join(tmpDir, "victim.txt");
    fs.writeFileSync(victim, "precious");
    const cacheDir = path.join(tmpDir, "cache");
    fs.mkdirSync(cacheDir);
    fs.linkSync(victim, path.join(cacheDir, CATALOG_CACHE_FILE));
    serve(realRoutes(feedDoc(FEED_GENERATED_AT)));

    await expect(refreshFeed(DEFAULT_FEED_URL, cacheDir, NO_FLOOR, ALLOW_UNSIGNED)).rejects.toThrow(/hard link/);
    expect(fs.readFileSync(victim, "utf-8")).toBe("precious");
  });

  it("refuses a hard-linked feed target the same way", async () => {
    const victim = path.join(tmpDir, "victim.txt");
    fs.writeFileSync(victim, "precious");
    const cacheDir = path.join(tmpDir, "cache");
    fs.mkdirSync(cacheDir);
    fs.linkSync(victim, path.join(cacheDir, FEED_CACHE_FILE));
    serve(realRoutes(feedDoc(FEED_GENERATED_AT)));

    await expect(refreshFeed(DEFAULT_FEED_URL, cacheDir, NO_FLOOR, ALLOW_UNSIGNED)).rejects.toThrow(/hard link/);
    expect(fs.readFileSync(victim, "utf-8")).toBe("precious");
  });

  it("refuses a symbolic-link catalog target", async () => {
    const victim = path.join(tmpDir, "victim.txt");
    fs.writeFileSync(victim, "precious");
    const cacheDir = path.join(tmpDir, "cache");
    fs.mkdirSync(cacheDir);
    try {
      fs.symlinkSync(victim, path.join(cacheDir, CATALOG_CACHE_FILE));
    } catch (error) {
      // Creating a symlink needs a privilege on Windows. The hard-link tests
      // above cover the same refusal path there.
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    serve(realRoutes(feedDoc(FEED_GENERATED_AT)));

    await expect(refreshFeed(DEFAULT_FEED_URL, cacheDir, NO_FLOOR, ALLOW_UNSIGNED)).rejects.toThrow(/symbolic link/);
    expect(fs.readFileSync(victim, "utf-8")).toBe("precious");
  });

  it("installs the catalog through a temporary file and leaves none behind", async () => {
    const cacheDir = path.join(tmpDir, "cache");
    serve(realRoutes(feedDoc(FEED_GENERATED_AT)));

    const result = await refreshFeed(DEFAULT_FEED_URL, cacheDir, NO_FLOOR, ALLOW_UNSIGNED);

    expect(result.catalog?.entryCount).toBe(CATALOG_DIGEST.entryCount);
    expect(fs.readdirSync(cacheDir).sort()).toEqual(
      [CATALOG_CACHE_FILE, CATALOG_MARKER_FILE, FEED_CACHE_FILE].sort(),
    );
    expect(fs.lstatSync(path.join(cacheDir, CATALOG_CACHE_FILE)).nlink).toBe(1);
    // The installed catalog loads and is accepted.
    resetThreatIntelCache();
    loadThreatIntel(cacheDir);
    const { lastCatalogState } = await import("../threat-intel.js");
    expect(lastCatalogState().available).toBe(true);
  });
});

describe("F17: an installed catalog that cannot be used makes the scan partial", () => {
  let project: string;
  beforeEach(() => {
    project = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cache-safety-project-"));
    fs.writeFileSync(path.join(project, "index.js"), "console.log('ordinary code');\n");
  });
  afterEach(() => {
    fs.rmSync(project, { recursive: true, force: true });
  });

  const scanWith = async (cacheDir: string) => {
    resetThreatIntelCache();
    return scan({ target: project, format: "json", noHistory: true, cacheDir });
  };

  it("control: an absent catalog stays the informational note and is not partial", async () => {
    const cacheDir = path.join(tmpDir, "empty-cache");
    fs.mkdirSync(cacheDir);
    const report = await scanWith(cacheDir);
    const finding = report.findings.find((f) => f.rule === "THREAT_FEED_CATALOG_MISSING");
    expect(finding?.severity).toBe("info");
    expect(report.findings.map((f) => f.rule)).not.toContain("THREAT_FEED_CATALOG_UNAVAILABLE");
    expect(report.partialScan).toBeUndefined();
  });

  it.each([
    ["garbage", "{not json"],
    ["truncated", `{"version":"${CATALOG_DIGEST.version}","sha256":"${CATALOG_DIGEST.sha256}","entries":[{"type":"pack`],
    ["entries not an array", JSON.stringify({ version: CATALOG_DIGEST.version, entries: {} })],
    [
      "wrong digest",
      JSON.stringify({ version: CATALOG_DIGEST.version, sha256: "0".repeat(64), checksum: "x", entries: [] }),
    ],
  ])("%s catalog: high finding, partialScan true", async (_name, content) => {
    const cacheDir = path.join(tmpDir, "cache");
    fs.mkdirSync(cacheDir);
    fs.writeFileSync(path.join(cacheDir, CATALOG_CACHE_FILE), content);

    const report = await scanWith(cacheDir);

    const finding = report.findings.find((f) => f.rule === "THREAT_FEED_CATALOG_UNAVAILABLE");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
    expect(report.partialScan).toBe(true);
  });

  // The ordinary state right after an upgrade, until the next refresh: low and
  // NOT partial, or every upgraded user would get exit 1 until they refreshed.
  it("a catalog built for another release is low and not partial", async () => {
    const cacheDir = path.join(tmpDir, "cache");
    fs.mkdirSync(cacheDir);
    fs.writeFileSync(
      path.join(cacheDir, CATALOG_CACHE_FILE),
      JSON.stringify({ version: "6.0.0", sha256: CATALOG_DIGEST.sha256, checksum: "x", entries: [] }),
    );
    const report = await scanWith(cacheDir);
    const finding = report.findings.find((f) => f.rule === "THREAT_FEED_CATALOG_MISSING");
    expect(finding?.severity).toBe("low");
    expect(report.findings.map((f) => f.rule)).not.toContain("THREAT_FEED_CATALOG_UNAVAILABLE");
    expect(report.partialScan).toBeUndefined();
  });

  it("an unreadable (garbage) catalog is high, not medium", async () => {
    const cacheDir = path.join(tmpDir, "cache");
    fs.mkdirSync(cacheDir);
    fs.writeFileSync(path.join(cacheDir, CATALOG_CACHE_FILE), "{not json");
    const report = await scanWith(cacheDir);
    expect(
      report.findings.find((f) => f.rule === "THREAT_FEED_CATALOG_UNAVAILABLE")?.severity,
    ).toBe("high");
  });

  describe("an installed catalog that is deleted afterwards", () => {
    const marker = (over: Record<string, unknown> = {}) =>
      JSON.stringify({
        version: CATALOG_DIGEST.version,
        sha256: CATALOG_DIGEST.sha256,
        installedAt: new Date().toISOString(),
        ...over,
      });
    const withMarker = (content: string) => {
      const cacheDir = path.join(tmpDir, "cache");
      fs.mkdirSync(cacheDir);
      fs.writeFileSync(path.join(cacheDir, CATALOG_MARKER_FILE), content);
      return cacheDir;
    };
    const expectOrdinaryAbsent = (report: Awaited<ReturnType<typeof scanWith>>, severity: string) => {
      expect(report.findings.find((f) => f.rule === "THREAT_FEED_CATALOG_MISSING")?.severity).toBe(severity);
      expect(report.findings.map((f) => f.rule)).not.toContain("THREAT_FEED_CATALOG_UNAVAILABLE");
      expect(report.partialScan).toBeUndefined();
    };

    it("refresh, then delete the catalog: high finding and partialScan true", async () => {
      const cacheDir = path.join(tmpDir, "cache");
      serve(realRoutes(feedDoc(FEED_GENERATED_AT)));
      await refreshFeed(DEFAULT_FEED_URL, cacheDir, NO_FLOOR, ALLOW_UNSIGNED);
      fs.rmSync(path.join(cacheDir, CATALOG_CACHE_FILE));

      const report = await scanWith(cacheDir);

      const finding = report.findings.find((f) => f.rule === "THREAT_FEED_CATALOG_UNAVAILABLE");
      expect(finding?.severity).toBe("high");
      expect(report.findings.map((f) => f.rule)).not.toContain("THREAT_FEED_CATALOG_MISSING");
      expect(report.partialScan).toBe(true);
    });

    it("a marker for an older release and no catalog is the post-upgrade state: not partial", async () => {
      const report = await scanWith(withMarker(marker({ version: "6.0.0" })));
      expectOrdinaryAbsent(report, "info");
    });

    it("a marker naming another digest is not trusted", async () => {
      const report = await scanWith(withMarker(marker({ sha256: "0".repeat(64) })));
      expectOrdinaryAbsent(report, "info");
    });

    it.each([
      ["garbage", () => "{not json"],
      ["not an object", () => "42"],
      ["no installedAt", () => marker({ installedAt: undefined })],
      ["future-dated", () => marker({ installedAt: "2999-01-01T00:00:00.000Z" })],
      ["oversized", () => marker({ padding: "x".repeat(8192) })],
    ])("a %s marker is treated as no marker", async (_name, content) => {
      const report = await scanWith(withMarker(content()));
      expectOrdinaryAbsent(report, "info");
    });

    it("a symlinked marker is treated as no marker", async () => {
      const cacheDir = path.join(tmpDir, "cache");
      fs.mkdirSync(cacheDir);
      const real = path.join(tmpDir, "real-marker.json");
      fs.writeFileSync(real, marker());
      try {
        fs.symlinkSync(real, path.join(cacheDir, CATALOG_MARKER_FILE));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EPERM") return;
        throw error;
      }
      expectOrdinaryAbsent(await scanWith(cacheDir), "info");
    });

    it("a hard-linked marker is treated as no marker", async () => {
      const cacheDir = path.join(tmpDir, "cache");
      fs.mkdirSync(cacheDir);
      const real = path.join(tmpDir, "real-marker.json");
      fs.writeFileSync(real, marker());
      fs.linkSync(real, path.join(cacheDir, CATALOG_MARKER_FILE));
      expectOrdinaryAbsent(await scanWith(cacheDir), "info");
    });

    it("control: a valid marker beside a present, valid catalog changes nothing", async () => {
      const cacheDir = path.join(tmpDir, "cache");
      serve(realRoutes(feedDoc(FEED_GENERATED_AT)));
      await refreshFeed(DEFAULT_FEED_URL, cacheDir, NO_FLOOR, ALLOW_UNSIGNED);
      fs.rmSync(path.join(cacheDir, FEED_CACHE_FILE));
      const report = await scanWith(cacheDir);
      expect(report.findings.map((f) => f.rule)).not.toContain("THREAT_FEED_CATALOG_UNAVAILABLE");
      expect(report.partialScan).toBeUndefined();
    });
  });

  it("a catalog installed by refresh scans clean and complete", async () => {
    const cacheDir = path.join(tmpDir, "cache");
    serve(realRoutes(feedDoc(FEED_GENERATED_AT)));
    await refreshFeed(DEFAULT_FEED_URL, cacheDir, NO_FLOOR, ALLOW_UNSIGNED);
    // Use only the catalog for this control: the feed fixture is not under test.
    fs.rmSync(path.join(cacheDir, FEED_CACHE_FILE));

    const report = await scanWith(cacheDir);

    expect(report.findings.map((f) => f.rule)).not.toContain("THREAT_FEED_CATALOG_UNAVAILABLE");
    expect(report.findings.map((f) => f.rule)).not.toContain("THREAT_FEED_CATALOG_MISSING");
    expect(report.partialScan).toBeUndefined();
  });
});

describe("F36: a refresh cannot roll the feed back, shrink it or fake its age", () => {
  const cachedDoc = () => JSON.parse(fs.readFileSync(path.join(tmpDir, FEED_CACHE_FILE), "utf-8"));

  it("refuses a feed whose generatedAt is older than the cached copy", async () => {
    serve({ [FEED_PATH]: feedDoc("2999-01-01T00:00:00.000Z") });
    // Install a newer-than-bundled feed first (a date inside the skew window).
    const newer = new Date(Date.now() + 3_600_000).toISOString();
    serve({ [FEED_PATH]: feedDoc(newer) });
    await refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, ALLOW_UNSIGNED);
    expect(cachedDoc().generatedAt).toBe(newer);

    const older = new Date(Date.parse(newer) - 3_600_000).toISOString();
    serve({ [FEED_PATH]: feedDoc(older) });
    await expect(refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, ALLOW_UNSIGNED)).rejects.toThrow(
      /older than the cached feed/,
    );
    expect(cachedDoc().generatedAt).toBe(newer);
  });

  it("refuses a feed older than the one bundled with this release", async () => {
    serve({ [FEED_PATH]: feedDoc("2020-01-01T00:00:00.000Z") });
    await expect(refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, ALLOW_UNSIGNED)).rejects.toThrow(
      /older than the feed bundled/,
    );
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  });

  it("refuses a feed generated in the future, which would block every later refresh", async () => {
    serve({ [FEED_PATH]: feedDoc("2999-01-01T00:00:00.000Z") });
    await expect(refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, ALLOW_UNSIGNED)).rejects.toThrow(/in the future/);
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  });

  it("refuses a feed that drops generatedAt when the cached one has it", async () => {
    serve({ [FEED_PATH]: feedDoc(FEED_GENERATED_AT) });
    await refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, ALLOW_UNSIGNED);

    serve({ [FEED_PATH]: feedDoc(undefined) });
    await expect(refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, ALLOW_UNSIGNED)).rejects.toThrow(
      /declares no generatedAt/,
    );
    expect(cachedDoc().generatedAt).toBe(FEED_GENERATED_AT);
  });

  it("refuses, by default, a feed with fewer than half the bundled entries", async () => {
    serve({ [FEED_PATH]: feedDoc(FEED_GENERATED_AT, 1) });
    await expect(refreshFeed(DEFAULT_FEED_URL, tmpDir, {}, ALLOW_UNSIGNED)).rejects.toThrow(/half of the bundled feed/);
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  });

  it("accepts a feed of the same generation time and records generatedAt in the cache", async () => {
    serve({ [FEED_PATH]: feedDoc(FEED_GENERATED_AT) });
    await refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, ALLOW_UNSIGNED);
    serve({ [FEED_PATH]: feedDoc(FEED_GENERATED_AT) });
    await refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, ALLOW_UNSIGNED);

    resetThreatIntelCache();
    loadThreatIntel(tmpDir);
    expect(getFeedCacheState().generatedAt).toBe(FEED_GENERATED_AT);
  });

  it("does not let a cache timestamped far in the future look permanently fresh", () => {
    fs.writeFileSync(
      path.join(tmpDir, FEED_CACHE_FILE),
      JSON.stringify({
        timestamp: "2999-01-01T00:00:00.000Z",
        unsigned: true,
        entries: [{ type: "domain", value: "future-stamp.example", severity: "critical", confidence: 1 }],
      }),
    );
    loadThreatIntel(tmpDir);
    const state = getFeedCacheState();
    expect(state.stale).toBe(true);
    expect(state.unreadable).toBe(true);
  });

  it("does not let an injected firstSeen of today reset the staleness check", async () => {
    const project = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cache-safety-stale-"));
    fs.writeFileSync(path.join(project, "index.js"), "console.log('ordinary code');\n");
    // Ninety days after the bundled feed was generated, a cache that says it was
    // generated with the bundle but carries an indicator first seen "yesterday".
    const now = Date.parse(FEED_GENERATED_AT) + 90 * 86_400_000;
    const yesterday = new Date(now - 86_400_000).toISOString().slice(0, 10);
    fs.writeFileSync(
      path.join(tmpDir, FEED_CACHE_FILE),
      JSON.stringify({
        timestamp: new Date(now).toISOString(),
        unsigned: true,
        generatedAt: FEED_GENERATED_AT,
        entries: [
          { type: "domain", value: "reset-stale.example", severity: "low", confidence: 1, firstSeen: yesterday },
        ],
      }),
    );
    vi.useFakeTimers({ toFake: ["Date"], now });
    try {
      resetThreatIntelCache();
      const report = await scan({ target: project, format: "json", noHistory: true, cacheDir: tmpDir });
      expect(report.findings.map((f) => f.rule)).toContain("THREAT_FEED_STALE");
    } finally {
      vi.useRealTimers();
      fs.rmSync(project, { recursive: true, force: true });
    }
  });

  it("feedFreshness takes no ceiling when the cache recorded no generation time", () => {
    const now = Date.parse("2027-01-01T00:00:00.000Z");
    const feed = [
      { type: "domain", value: "a.example", severity: "low", confidence: 1, firstSeen: "2026-12-31" },
    ] as never;
    expect(feedFreshness(feed, now).stale).toBe(false);
    expect(feedFreshness(feed, now, FEED_GENERATED_AT).stale).toBe(true);
  });
});
