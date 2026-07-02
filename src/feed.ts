/**
 * Live threat-intel feed channel (v5.3).
 *
 * Companion to threat-intel.ts. The curated IOC feed ships bundled with every
 * npm release; this module adds the "same-day protection" path on top:
 *
 *   1. `scripts/generate-feed.mjs` publishes the bundled feed as feed.json at
 *      the repo root (committed, served via raw.githubusercontent.com).
 *   2. `supply-chain-guard feed refresh` (refreshFeed below) downloads that
 *      published feed.json and writes it to the local cache file
 *      `<cacheDir>/threat-feed.json` in the exact `{ timestamp, entries }`
 *      shape that loadThreatIntel() already consumes.
 *   3. Every scan entry point calls loadThreatIntel(), which merges cache
 *      entries younger than 24h over the bundled feed: scanner.ts scan()
 *      feeds the merged list into checkThreatIntel() per file, and the
 *      composer/nuget/rubygems scanners resolve package IOCs against it via
 *      matchPackageIOC(). A refreshed cache therefore extends detection at
 *      scan time without a new npm release.
 *
 * Zero-dependency: uses node:https directly (mockable in tests).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as https from "node:https";
import { CACHE_DIR, FEED_CACHE_FILE, type FeedIOC } from "./threat-intel.js";

/** Published feed location: the committed feed.json on the main branch. */
export const DEFAULT_FEED_URL =
  "https://raw.githubusercontent.com/homeofe/supply-chain-guard/main/feed.json";

// ---------------------------------------------------------------------------
// Feed statistics (offline)
// ---------------------------------------------------------------------------

export interface FeedStats {
  total: number;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
}

/**
 * Count feed entries by IOC type and severity. Pure and offline - the CLI
 * passes getBundledFeed() / loadThreatIntel() output in.
 */
export function feedStats(feed: FeedIOC[]): FeedStats {
  const byType: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const ioc of feed) {
    byType[ioc.type] = (byType[ioc.type] ?? 0) + 1;
    bySeverity[ioc.severity] = (bySeverity[ioc.severity] ?? 0) + 1;
  }
  return { total: feed.length, byType, bySeverity };
}

// ---------------------------------------------------------------------------
// Feed refresh (download published feed.json into the local cache)
// ---------------------------------------------------------------------------

export interface RefreshResult {
  /** Number of IOC entries written to the cache. */
  entryCount: number;
  /** Absolute or relative path of the cache file that was written. */
  cachePath: string;
}

/**
 * Validate a downloaded feed payload. Accepts both the published shape
 * `{ schema: 1, entries: [...] }` (feed.json) and a raw FeedIOC[] array
 * (the format the legacy updateThreatFeed() consumed).
 */
export function parseFeedPayload(raw: string): FeedIOC[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("feed is not valid JSON");
  }

  const entries: unknown = Array.isArray(parsed)
    ? parsed
    : (parsed as { entries?: unknown } | null)?.entries;

  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("invalid feed format: missing non-empty entries array");
  }

  for (const entry of entries) {
    const e = entry as Partial<FeedIOC> | null;
    if (
      e === null ||
      typeof e !== "object" ||
      typeof e.type !== "string" ||
      typeof e.value !== "string" ||
      typeof e.severity !== "string"
    ) {
      throw new Error("invalid feed format: entry missing type/value/severity");
    }
  }

  return entries as FeedIOC[];
}

/** Download a URL over HTTPS and resolve with the response body. */
function httpsGetBody(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res: {
      statusCode?: number;
      on: (event: string, handler: (chunk?: Buffer) => void) => void;
    }) => {
      const status = res.statusCode ?? 0;
      let data = "";
      res.on("data", (chunk?: Buffer) => {
        if (chunk) data += chunk.toString();
      });
      res.on("end", () => {
        if (status !== 200) {
          reject(new Error(`HTTP ${status}`));
          return;
        }
        resolve(data);
      });
    });
    req.on("error", (err: Error) => {
      reject(new Error(`network error: ${err.message}`));
    });
  });
}

/**
 * Download the published threat-intel feed and cache it locally in the
 * `{ timestamp, entries }` shape loadThreatIntel() reads. Entries stay live
 * for 24h (CACHE_TTL_MS in threat-intel.ts); re-run daily for same-day
 * protection between npm releases. Never crashes the process on network
 * failure - callers get a rejected promise with a clear message.
 */
export async function refreshFeed(
  feedUrl: string = DEFAULT_FEED_URL,
  cacheDir: string = CACHE_DIR,
): Promise<RefreshResult> {
  try {
    const body = await httpsGetBody(feedUrl);
    const entries = parseFeedPayload(body);

    fs.mkdirSync(cacheDir, { recursive: true });
    const cachePath = path.join(cacheDir, FEED_CACHE_FILE);
    fs.writeFileSync(
      cachePath,
      JSON.stringify({ timestamp: new Date().toISOString(), entries }, null, 2),
    );

    return { entryCount: entries.length, cachePath };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to refresh threat feed from ${feedUrl}: ${message}`);
  }
}
