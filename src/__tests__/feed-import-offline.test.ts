/**
 * `feed import <dir>`: the signed feed (and optionally the release's catalog)
 * installed from local files, for networks without internet access
 * (docs/daily-feed-channel-design.md, "Offline import"). Same checks as
 * `feed refresh`, and no network request at all.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { generateKeyPairSync, sign } from "node:crypto";

// Any network call is a failure of this feature, so every request throws.
vi.mock("node:https", () => {
  const get = vi.fn(() => {
    throw new Error("network access in an offline import");
  });
  return { default: { get }, get };
});

import * as https from "node:https";
import { importFeedFromDirectory, FeedNotNewerError } from "../feed.js";
import { setFeedPublicKeyForTests, FEED_SIGNED_COPY_FILE } from "../feed-signing-key.js";
import { CATALOG_CACHE_FILE, FEED_CACHE_FILE, resetThreatIntelCache } from "../threat-intel.js";
import { CATALOG_DIGEST } from "../catalog-digest.js";
import { readCatalogEntries, buildCatalog } from "../../scripts/generate-catalog.mjs";

const pair = generateKeyPairSync("ed25519");
const otherPair = generateKeyPairSync("ed25519");
const sigOf = (data: string, key = pair.privateKey) => sign(null, Buffer.from(data), key).toString("base64") + "\n";
const doc = (generatedAt: string, value = "offline-fixture.example") =>
  JSON.stringify({ schema: 1, generatedAt, entries: [{ type: "domain", value, severity: "critical", confidence: 1 }] });
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

let dirs: string[] = [];
let cache: string;
const mkdir = (prefix: string) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  dirs.push(d);
  return d;
};
/** A transfer directory with the given files. */
const transfer = (files: Record<string, string | Buffer>) => {
  const d = mkdir("scg-offline-in-");
  for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(d, name), body);
  return d;
};

beforeEach(() => {
  vi.clearAllMocks();
  resetThreatIntelCache();
  setFeedPublicKeyForTests(pair.publicKey.export({ type: "spki", format: "pem" }) as string);
  cache = mkdir("scg-offline-cache-");
});
afterEach(() => {
  setFeedPublicKeyForTests(undefined);
  resetThreatIntelCache();
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

const NO_FLOOR = { minEntries: 0 };

describe("importFeedFromDirectory", () => {
  it("installs a signed feed from a directory", async () => {
    const d = doc(ago(60_000));
    const result = await importFeedFromDirectory(transfer({ "feed.json": d, "feed.json.sig": sigOf(d) }), cache, NO_FLOOR);
    expect(result.source).toBe("file");
    expect(result.entryCount).toBe(1);
    expect(fs.readFileSync(path.join(cache, FEED_SIGNED_COPY_FILE), "utf8")).toBe(d);
    expect(result.catalogError).toMatch(/no catalog files/);
  });

  it("refuses a missing signature offline", async () => {
    const d = doc(ago(60_000));
    await expect(importFeedFromDirectory(transfer({ "feed.json": d }), cache, NO_FLOOR)).rejects.toThrow(/signature/);
    expect(fs.existsSync(path.join(cache, FEED_CACHE_FILE))).toBe(false);
  });

  it("refuses a feed signed by another key", async () => {
    const d = doc(ago(60_000));
    await expect(
      importFeedFromDirectory(transfer({ "feed.json": d, "feed.json.sig": sigOf(d, otherPair.privateKey) }), cache, NO_FLOOR),
    ).rejects.toThrow(/does not verify/);
    expect(fs.existsSync(path.join(cache, FEED_CACHE_FILE))).toBe(false);
  });

  it("refuses an older feed than the cache", async () => {
    const newer = doc(ago(60_000));
    await importFeedFromDirectory(transfer({ "feed.json": newer, "feed.json.sig": sigOf(newer) }), cache, NO_FLOOR);
    const older = doc(ago(3_600_000), "older-offline.example");
    const err = await importFeedFromDirectory(transfer({ "feed.json": older, "feed.json.sig": sigOf(older) }), cache, NO_FLOOR).catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(String(err.message)).toMatch(/older than the cached feed/);
    expect(JSON.parse(fs.readFileSync(path.join(cache, FEED_CACHE_FILE), "utf8")).generatedAt).toBe(JSON.parse(newer).generatedAt);
    expect(FeedNotNewerError).toBeDefined();
  });

  it("refuses a short feed against the bundle floor", async () => {
    const d = doc(ago(60_000));
    await expect(importFeedFromDirectory(transfer({ "feed.json": d, "feed.json.sig": sigOf(d) }), cache)).rejects.toThrow(
      /fewer than/,
    );
  });

  it("installs the catalog when its files are present and verify", async () => {
    const { indexJson, shards } = buildCatalog(readCatalogEntries(), CATALOG_DIGEST.version);
    const d = doc(ago(60_000));
    const files: Record<string, string | Buffer> = { "feed.json": d, "feed.json.sig": sigOf(d), "catalog-index.json": indexJson };
    for (const shard of shards) files[shard.path] = shard.gz;
    const result = await importFeedFromDirectory(transfer(files), cache, NO_FLOOR);
    expect(result.catalogError).toBeUndefined();
    expect(result.catalog?.entryCount).toBeGreaterThan(1000);
    expect(fs.existsSync(path.join(cache, CATALOG_CACHE_FILE))).toBe(true);
  }, 60_000);

  it("refuses a catalog shard that was altered", async () => {
    const { indexJson, shards } = buildCatalog(readCatalogEntries(), CATALOG_DIGEST.version);
    const d = doc(ago(60_000));
    const files: Record<string, string | Buffer> = { "feed.json": d, "feed.json.sig": sigOf(d), "catalog-index.json": indexJson };
    for (const shard of shards) files[shard.path] = shard.gz;
    files[shards[0].path] = Buffer.from("[]");
    const result = await importFeedFromDirectory(transfer(files), cache, NO_FLOOR);
    expect(result.catalog).toBeUndefined();
    expect(result.catalogError).toMatch(/digest|catalog/);
    expect(fs.existsSync(path.join(cache, CATALOG_CACHE_FILE))).toBe(false);
  }, 60_000);

  it("never touches the network", async () => {
    const d = doc(ago(60_000));
    await importFeedFromDirectory(transfer({ "feed.json": d, "feed.json.sig": sigOf(d) }), cache, NO_FLOOR);
    await importFeedFromDirectory(transfer({ "feed.json": d }), cache, NO_FLOOR).catch(() => undefined);
    expect(https.get).not.toHaveBeenCalled();
  });
});
