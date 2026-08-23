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
import type { Finding } from "./types.js";
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
// Feed freshness (offline)
// ---------------------------------------------------------------------------

/**
 * Age, in days, past which the rule set in use can no longer claim currency.
 *
 * Why this exists at all: `scan` runs OFFLINE against the feed bundled with the
 * installed version. A consumer that pins an exact version and never moves the
 * pin therefore freezes its detection rules at that release's date, and until
 * now nothing reported it - not the exit code, not the risk score, not the
 * check name. The pin kept producing a green check while the rules aged, which
 * is the one failure mode a scanner cannot afford, because the green check is
 * the whole reason anybody trusts it.
 *
 * The number is chosen against this project's own measured release rate: 134
 * releases in the 155 days to 2026-08-21, a median of about 20 hours between
 * releases. A rule set whose newest indicator is over a month old is therefore
 * around a hundred releases behind, not one or two.
 */
export const FEED_STALE_AFTER_DAYS = 30;

/** Rule id of the staleness finding. Stable: consumers exclude it by name. */
export const FEED_STALE_RULE = "THREAT_FEED_STALE";

export interface FeedFreshness {
  /** `YYYY-MM-DD` of the newest usable indicator, or null if none was usable. */
  newestIndicator: string | null;
  /** Whole days between the newest usable indicator and `now`, or null. */
  ageDays: number | null;
  /** How many entries carried a usable, non-future `firstSeen`. */
  datedEntries: number;
  /** True when the rule set is older than FEED_STALE_AFTER_DAYS, or undatable. */
  stale: boolean;
}

const MS_PER_DAY = 86_400_000;
const ISO_DATE_PREFIX = /^(\d{4})-(\d{2})-(\d{2})/;

/**
 * Parse a `firstSeen` value into a UTC epoch, or null if it is not a real
 * calendar date. Rejects values that parse but do not round-trip (`2026-02-31`),
 * because Date.UTC silently rolls those over into a later, wrong day.
 */
function indicatorDateMs(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const match = ISO_DATE_PREFIX.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const ms = Date.UTC(year, month - 1, day);
  if (!Number.isFinite(ms)) return null;
  const parsed = new Date(ms);
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() + 1 !== month ||
    parsed.getUTCDate() !== day
  ) {
    return null;
  }
  return ms;
}

/**
 * How old the rule set actually in use is, derived from the newest `firstSeen`
 * across the entries the scan will match against. Pure, offline and
 * deterministic: it reads only the feed that was passed in.
 *
 * Deliberately computed over the EFFECTIVE feed (loadThreatIntel(): bundled
 * plus a cache entry younger than 24h), not over the bundled feed alone. That
 * makes the answer a statement about the consequence - how recent are the rules
 * this scan can match - rather than about the configuration. A consumer running
 * `feed refresh` before each scan is genuinely current even on an old pin, and
 * is correctly reported as such.
 *
 * A `firstSeen` in the FUTURE relative to `now` is ignored rather than trusted.
 * Trusting it would let one mistyped year in one entry make every feed look
 * permanently current, which is precisely the false negative this function is
 * here to prevent.
 */
export function feedFreshness(
  feed: readonly FeedIOC[],
  now: number | Date = Date.now(),
): FeedFreshness {
  const nowMs = now instanceof Date ? now.getTime() : now;
  let newestMs: number | null = null;
  let datedEntries = 0;

  for (const ioc of feed) {
    const ms = indicatorDateMs((ioc as { firstSeen?: unknown }).firstSeen);
    if (ms === null || ms > nowMs) continue;
    datedEntries += 1;
    if (newestMs === null || ms > newestMs) newestMs = ms;
  }

  // No entry carried a usable date. That is not evidence of freshness, so it
  // reports as stale: an undatable rule set is unclassifiable, and a staleness
  // check that stays silent on the one input it cannot classify is the check
  // that never fires.
  if (newestMs === null) {
    return { newestIndicator: null, ageDays: null, datedEntries: 0, stale: true };
  }

  const ageDays = Math.floor((nowMs - newestMs) / MS_PER_DAY);
  return {
    newestIndicator: new Date(newestMs).toISOString().slice(0, 10),
    ageDays,
    datedEntries,
    stale: ageDays > FEED_STALE_AFTER_DAYS,
  };
}

/**
 * The staleness finding, or an empty array when the rule set is current.
 *
 * Severity is `medium` on purpose. It moves the score off zero and the risk
 * level off `clean`, so the rule is named in EIGHT of the nine report formats
 * and in the Action's pull request comment, without silently turning the
 * default `fail-on: critical` gate red for every consumer on the day this
 * ships. Raising it is a policy decision for the maintainer, not a side effect.
 *
 * The ninth is `badge`: `formatBadge` in `src/reporter.ts` builds a Shields.io
 * endpoint payload out of `report.summary` counts alone, so no rule id or
 * description can reach it by construction. There the condition shows as an
 * otherwise clean repository's badge going from `clean`/`brightgreen` to
 * `1 medium`/`yellow`. In `junit` the rule id IS present, but as a passing
 * `<testcase>`, because only `critical`/`high` become `<failure>` there. This
 * comment said "every report format" until it was measured; do not restore that
 * wording without re-rendering all nine.
 */
export function feedStalenessFindings(freshness: FeedFreshness): Finding[] {
  if (!freshness.stale) return [];

  const age =
    freshness.ageDays === null || freshness.newestIndicator === null
      ? "of unknown age (no indicator in it carries a usable date)"
      : `${freshness.ageDays} days old (newest indicator ${freshness.newestIndicator}, ` +
        `across ${freshness.datedEntries} dated indicators)`;

  return [
    {
      rule: FEED_STALE_RULE,
      description:
        `The threat-intel rule set this scan matched against is ${age}. ` +
        `Scanning is offline, so indicators published after that date could not ` +
        `be detected by this run, and no other part of the result says so.`,
      severity: "medium",
      confidence: 1.0,
      category: "trust",
      rationale:
        "The bundled rule set travels with the installed version, so a version " +
        "pin that stops moving freezes detection at that release's date while " +
        "every scan keeps reporting success.",
      recommendation:
        "Update supply-chain-guard to a current release, or run " +
        "`supply-chain-guard feed refresh` before the scan to merge the " +
        `published feed for 24h. Exclude the ${FEED_STALE_RULE} rule only if a ` +
        "deliberately frozen rule set is the intent.",
    },
  ];
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
