import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { EventEmitter } from "node:events";

vi.mock("node:https", () => {
  const get = vi.fn();
  return { default: { get }, get };
});

import * as https from "node:https";
import {
  refreshFeed,
  catalogUrlFor,
  catalogTemplateForFeedUrl,
  DEFAULT_CATALOG_URL_TEMPLATE,
  DEFAULT_FEED_URL,
} from "../feed.js";
import { CATALOG_CACHE_FILE, FEED_CACHE_FILE } from "../threat-intel.js";
import { CATALOG_DIGEST } from "../catalog-digest.js";
import { readCatalogEntries, buildCatalog } from "../../scripts/generate-catalog.mjs";

const sha = (s: string | Buffer) =>
  createHash("sha256").update(typeof s === "string" ? Buffer.from(s, "utf8") : s).digest("hex");

const FEED_DOC = JSON.stringify({
  schema: 1,
  entries: [
    { type: "domain", value: "feed-fixture.example", severity: "critical", confidence: 1 },
  ],
});

const CATALOG_ENTRY = {
  type: "package",
  value: "catalog-fixture-pkg@1.0.0",
  severity: "critical",
  confidence: 1,
};

/**
 * The REAL published assets for this release.
 *
 * Built with the generator the release runs, over the committed catalog, at the
 * committed version, so the index digest is CATALOG_DIGEST.sha256 by
 * construction rather than by a fixture agreeing with itself. That is what lets
 * the happy path below prove the whole chain: package anchor -> index -> shard.
 */
const REAL = (() => {
  const { indexJson, shards } = buildCatalog(readCatalogEntries(), CATALOG_DIGEST.version);
  return { indexJson, shards };
})();

const RELEASE_BASE = `/homeofe/supply-chain-guard/releases/download/v${CATALOG_DIGEST.version}`;

const realRoutes = (): Record<string, Buffer | string> => {
  const routes: Record<string, Buffer | string> = {
    [FEED_PATH]: FEED_DOC,
    [`${RELEASE_BASE}/catalog-index.json`]: REAL.indexJson,
  };
  for (const shard of REAL.shards) routes[`${RELEASE_BASE}/${shard.path}`] = shard.gz;
  return routes;
};

/** The request path the bounded downloader will use for a URL. */
const pathOf = (url: string) => new URL(url).pathname;

const FEED_PATH = pathOf(DEFAULT_FEED_URL);

/**
 * Answer each request from a path -> body map; anything else is a 404.
 *
 * The body is emitted on a LATER tick than the response callback, the way a
 * socket delivers it and the way the existing feed mock does. Emitting it in
 * the same tick leaves any reader that awaits first hanging until the test
 * times out.
 */
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

let tmpDir: string;
beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-refresh-"));
  vi.clearAllMocks();
});
afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("catalogUrlFor", () => {
  it("substitutes the version and the file name", () => {
    expect(catalogUrlFor("1.2.3", "catalog-index.json")).toBe(
      "https://github.com/homeofe/supply-chain-guard/releases/download/v1.2.3/catalog-index.json",
    );
  });

  it("accepts an explicit template", () => {
    expect(catalogUrlFor("1.2.3", "catalog-000.json.gz", "https://mirror.invalid/{version}/{file}")).toBe(
      "https://mirror.invalid/1.2.3/catalog-000.json.gz",
    );
  });

  it("leaves a template without placeholders alone", () => {
    expect(catalogUrlFor("1.2.3", "x", "https://mirror.invalid/fixed")).toBe(
      "https://mirror.invalid/fixed",
    );
  });
});

describe("catalogTemplateForFeedUrl", () => {
  // The catalog follows the feed. Pointing the tool at a mirror and having it
  // reach past that mirror to a hardcoded public host would mix two origins in
  // one scan without saying so.
  it("uses the release template for the default feed", () => {
    expect(catalogTemplateForFeedUrl(DEFAULT_FEED_URL)).toBe(DEFAULT_CATALOG_URL_TEMPLATE);
  });

  it("resolves beside a custom feed URL", () => {
    expect(catalogTemplateForFeedUrl("https://mirror.invalid/scg/feed.json")).toBe(
      "https://mirror.invalid/scg/{file}",
    );
  });

  it("ignores a query string and a fragment", () => {
    expect(catalogTemplateForFeedUrl("https://mirror.invalid/scg/feed.json?v=2#x")).toBe(
      "https://mirror.invalid/scg/{file}",
    );
  });
});

describe("refreshFeed installs the catalog", () => {
  // The happy path, against the real generated assets. Every link is checked
  // against an anchor the serving side does not control: the index must hash to
  // the constant compiled into this package, and each shard to the digest the
  // index recorded.
  it("verifies the chain and writes the catalog cache", async () => {
    serve(realRoutes());

    const result = await refreshFeed(DEFAULT_FEED_URL, tmpDir);
    expect(result.entryCount).toBe(1);
    expect(result.catalogError).toBeUndefined();
    expect(result.catalog).toBeDefined();
    expect(result.catalog?.entryCount).toBe(CATALOG_DIGEST.entryCount);

    const cachePath = path.join(tmpDir, CATALOG_CACHE_FILE);
    expect(fs.existsSync(cachePath)).toBe(true);
    const cached = JSON.parse(fs.readFileSync(cachePath, "utf-8"));
    expect(cached.version).toBe(CATALOG_DIGEST.version);
    expect(cached.sha256).toBe(CATALOG_DIGEST.sha256);
    // Written so the reader can notice the file changing afterwards. Without
    // it the reader's corrupt check is skipped entirely.
    expect(cached.checksum).toBe(sha(JSON.stringify(cached.entries)));
    expect(cached.checksum).toBe(CATALOG_DIGEST.entriesSha256);
  });

  // The anchor is the package constant, not anything the server said. A server
  // that serves a self-consistent index it built itself must still be refused.
  it("refuses an index that does not match the pinned digest", async () => {
    const tampered = JSON.stringify({
      schema: 1,
      kind: "catalog-index",
      package: "supply-chain-guard",
      version: CATALOG_DIGEST.version,
      entryCount: 1,
      shards: [{ path: "catalog-000.json.gz", sha256: sha("anything"), entryCount: 1 }],
    });
    serve({ [FEED_PATH]: FEED_DOC, [`${RELEASE_BASE}/catalog-index.json`]: tampered });

    const result = await refreshFeed(DEFAULT_FEED_URL, tmpDir);
    expect(result.catalog).toBeUndefined();
    expect(result.catalogError).toMatch(/index digest .* does not match/);
    expect(fs.existsSync(path.join(tmpDir, CATALOG_CACHE_FILE))).toBe(false);
  });

  // A correct index with a swapped shard. The index digest verifies, so this is
  // caught only by the second link in the chain.
  it("refuses a shard that does not match the digest the index records", async () => {
    const routes = realRoutes();
    routes[`${RELEASE_BASE}/${REAL.shards[0].path}`] = gzipSync(
      Buffer.from(
        JSON.stringify({ schema: 1, kind: "catalog", entries: [CATALOG_ENTRY] }),
        "utf8",
      ),
    );
    serve(routes);

    const result = await refreshFeed(DEFAULT_FEED_URL, tmpDir);
    expect(result.catalog).toBeUndefined();
    expect(result.catalogError).toMatch(/shard .* digest .* does not match/);
    expect(fs.existsSync(path.join(tmpDir, CATALOG_CACHE_FILE))).toBe(false);
  });

  it("still writes the feed cache when the catalog is unavailable", async () => {
    serve({ [FEED_PATH]: FEED_DOC });
    const result = await refreshFeed(DEFAULT_FEED_URL, tmpDir);

    expect(result.entryCount).toBe(1);
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(true);
    expect(result.catalog).toBeUndefined();
    expect(result.catalogError).toBeTruthy();
  });

  // The reason must survive. A missing asset and a digest mismatch are
  // different events, and collapsing them into one silent line would hide the
  // one worth acting on.
  it("reports a digest mismatch differently from a missing asset", async () => {
    serve({ [FEED_PATH]: FEED_DOC });
    const missing = await refreshFeed(DEFAULT_FEED_URL, tmpDir);

    serve({
      [FEED_PATH]: FEED_DOC,
      [`${RELEASE_BASE}/catalog-index.json`]: JSON.stringify({
        kind: "catalog-index",
        shards: [],
      }),
    });
    const mismatched = await refreshFeed(DEFAULT_FEED_URL, tmpDir);

    expect(missing.catalogError).toBeTruthy();
    expect(mismatched.catalogError).toMatch(/digest/);
    expect(missing.catalogError).not.toBe(mismatched.catalogError);
  });

  it("fetches the catalog from the same origin as a custom feed URL", async () => {
    serve({ "/scg/feed.json": FEED_DOC });
    await refreshFeed("https://mirror.invalid/scg/feed.json", tmpDir);

    const calls = (https.get as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    const hosts = calls.map((c) => (c[0] as { hostname?: string }).hostname);
    expect(hosts).toContain("mirror.invalid");
    // Never reaches past the mirror to the public release host.
    expect(hosts).not.toContain("github.com");
  });
});
