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
 * Zero-dependency: the download goes through remote-download.ts, the package's
 * bounded HTTPS retrieval module, which is the same code path the npm, PyPI and
 * VS Code scanners use. It is node:https underneath (mockable in tests) with an
 * absolute deadline, a byte cap and per-hop redirect revalidation added.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fetchHttpsBuffer, type RemoteRequestLimits } from "./remote-download.js";
import {
  CACHE_DIR,
  FEED_CACHE_FILE,
  FEED_REMOTE_LIMITS,
  isValidFeedIOC,
  normalizeFeedIOC,
  type FeedIOC,
  type FeedLimitOverrides,
} from "./threat-intel.js";

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

  const normalizedEntries: FeedIOC[] = [];
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
    // Indicator contract (issue #54): values are LITERAL indicators, never
    // regexes. Refresh is an explicit user action, so violations are a
    // deterministic hard reject with a precise reason - a rejected feed is
    // never written to the cache, and the previous cache stays in effect.
    if (!isValidFeedIOC(e)) {
      // Both fields are attacker-controlled remote data: bound them before
      // interpolating into the error string.
      throw new Error(
        `invalid feed entry (type ${JSON.stringify(e.type).slice(0, 32)}, value ${JSON.stringify(e.value).slice(0, 80)}): type must be one of domain/ip/url/hash/package and the value must be a literal indicator matching that type's shape (max 2048 chars)`,
      );
    }
    normalizedEntries.push(normalizeFeedIOC(e));
  }

  return normalizedEntries;
}

/**
 * Download a URL over HTTPS and resolve with the response body.
 *
 * This used to be a hand-rolled https.get with no deadline and no cap, so a peer
 * that sent headers and then stalled held `feed refresh` open with no output and
 * no exit, and a peer that sent an oversized document was buffered in full. The
 * request now goes through the package's bounded downloader, which carries an
 * absolute deadline across every redirect hop, refuses a declared Content-Length
 * over the cap before reading a byte, and counts bytes while streaming when no
 * length is declared.
 */
async function httpsGetBody(url: string, limits: RemoteRequestLimits): Promise<string> {
  const { body } = await fetchHttpsBuffer(url, limits);
  // Decode ONCE over the whole buffer. The previous reader did `data +=
  // chunk.toString()` per chunk, which turns a multi-byte UTF-8 sequence split
  // across a chunk boundary into replacement characters.
  return body.toString("utf-8");
}

/**
 * Download the published threat-intel feed and cache it locally in the
 * `{ timestamp, entries }` shape loadThreatIntel() reads. Entries stay live
 * for 24h (CACHE_TTL_MS in threat-intel.ts); re-run daily for same-day
 * protection between npm releases. Never crashes the process on network
 * failure - callers get a rejected promise with a clear message.
 *
 * The download is bounded by FEED_REMOTE_LIMITS. `limitOverrides` relaxes or
 * tightens a single dimension per call (a slow link may want a longer deadline)
 * and leaves the rest at the package defaults. Every bound fails closed: the
 * download is abandoned, nothing is written, and the previous cache stays in
 * effect.
 */
export async function refreshFeed(
  feedUrl: string = DEFAULT_FEED_URL,
  cacheDir: string = CACHE_DIR,
  limitOverrides: FeedLimitOverrides = {},
): Promise<RefreshResult> {
  const limits: RemoteRequestLimits = { ...FEED_REMOTE_LIMITS, ...limitOverrides };
  try {
    const body = await httpsGetBody(feedUrl, limits);
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
