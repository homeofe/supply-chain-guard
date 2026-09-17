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
import { gunzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { fetchHttpsBuffer, type RemoteRequestLimits } from "./remote-download.js";
import type { Finding } from "./types.js";
import { CATALOG_DIGEST } from "./catalog-digest.js";
import {
  CACHE_DIR,
  FEED_CACHE_FILE,
  CATALOG_CACHE_FILE,
  FEED_REMOTE_LIMITS,
  isValidFeedIOC,
  type CatalogState,
  normalizeFeedIOC,
  type FeedIOC,
  type FeedLimitOverrides,
} from "./threat-intel.js";

/** Published feed location: the committed feed.json on the main branch. */
export const DEFAULT_FEED_URL =
  "https://raw.githubusercontent.com/homeofe/supply-chain-guard/main/feed.json";

/** Where the catalog assets are published for a tagged release. */
export const DEFAULT_CATALOG_URL_TEMPLATE =
  "https://github.com/homeofe/supply-chain-guard/releases/download/v{version}/{file}";

/** Substitute a release version and an asset name into a catalog URL template. */
export function catalogUrlFor(
  version: string,
  file: string,
  template: string = DEFAULT_CATALOG_URL_TEMPLATE,
): string {
  return template.replace("{version}", version).replace("{file}", file);
}

/**
 * Where to look for the catalog, given where the feed was fetched from.
 *
 * The catalog follows the feed. Someone who points this at a mirror, an
 * air-gapped copy or a test server is asking for THAT source's view of the
 * corpus, and reaching past it to a hardcoded github.com URL would mix two
 * origins in one scan without saying so.
 *
 * It also keeps the unit tests honest: the bounds suite mocks node:https by
 * forwarding to node:http against a loopback server, so a hardcoded public host
 * here would have every one of those tests make a real outbound request.
 */
export function catalogTemplateForFeedUrl(feedUrl: string): string {
  if (feedUrl === DEFAULT_FEED_URL) return DEFAULT_CATALOG_URL_TEMPLATE;
  // Built by string surgery rather than through URL, whose serializer
  // percent-encodes the braces the template is made of.
  const withoutQuery = feedUrl.split(/[?#]/)[0];
  const lastSlash = withoutQuery.lastIndexOf("/");
  if (lastSlash === -1) return DEFAULT_CATALOG_URL_TEMPLATE;
  return `${withoutQuery.slice(0, lastSlash + 1)}{file}`;
}

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

/** The rule id for a catalog that could not be consulted. */
export const CATALOG_MISSING_RULE = "THREAT_FEED_CATALOG_MISSING";

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


/**
 * Human wording for each reason the catalog was not consulted.
 *
 * Kept as a total map rather than a default string so that adding a reason to
 * CatalogUnavailableReason without adding wording here is a TYPE error instead
 * of a finding that says "undefined".
 */
const CATALOG_REASON_TEXT: Record<NonNullable<CatalogState["reason"]>, string> = {
  absent: "no catalog has been downloaded on this machine",
  unreadable: "the cached catalog could not be read",
  "version-mismatch": "the cached catalog was built for a different release",
  "digest-mismatch": "the cached catalog does not match the digest this release pins",
  corrupt: "the cached catalog's entries do not match the checksum recorded beside them",
};

/**
 * Severity by reason: how much is actually wrong.
 *
 * `absent` is `info`, and that is a correction made after the catalog stopped
 * being empty. At `medium` this fired on EVERY scan of every fresh install,
 * because a fresh install has never had the chance to download anything, and
 * `medium` turns the badge from `clean`/`brightgreen` to yellow. A finding that
 * fires for every user on every run until they take an action is not a finding,
 * it is a nag, and the thing this repository says about nags is that they get
 * the tool switched off, which is worse than the finding being quieter.
 *
 * `info` still names the rule, still counts it, and still puts the number of
 * unconsulted indicators in every report that lists findings. What it does not
 * do is claim the scanned repository is less clean than it is, which is true:
 * this describes the SCANNER's optional data, not the repository. The same
 * reasoning is already applied to the `SLSA_` posture findings.
 *
 * The ladder above `absent` is about how much is actually wrong:
 *
 * - `version-mismatch` is `low`: a catalog is present, it is simply the wrong
 *   release's. One refresh fixes it.
 * - `unreadable` is `medium`: the file is there and broken.
 * - `digest-mismatch` and `corrupt` are `high`: neither is a normal state. One
 *   means the cached catalog was built from a different catalog than this
 *   release pins, the other that its entries no longer match their own
 *   checksum. Both say the scanner's own detection data was replaced or
 *   corrupted underneath it, which is a different claim from "not downloaded".
 *
 * `catalog: required` raises all of them to `critical`, which is how an
 * operator who needs the full corpus says so.
 */
const CATALOG_REASON_SEVERITY: Record<
  NonNullable<CatalogState["reason"]>,
  "info" | "low" | "medium" | "high"
> = {
  absent: "info",
  "version-mismatch": "low",
  unreadable: "medium",
  "digest-mismatch": "high",
  corrupt: "high",
};

/**
 * The severity this reason earns under this mode.
 *
 * Exported so the mapping can be proved directly. Through `catalogFindings` it
 * currently cannot be: while the release pins an EMPTY catalog the optional
 * path returns nothing at all, so every assertion about medium versus high
 * would sit behind a condition that is never true, and the distinction between
 * "not downloaded" and "modified underneath us" would ship untested until the
 * catalog first became non-empty.
 */
export function catalogSeverityFor(
  reason: NonNullable<CatalogState["reason"]>,
  mode: "optional" | "required",
): "info" | "low" | "medium" | "high" | "critical" {
  return mode === "required" ? "critical" : CATALOG_REASON_SEVERITY[reason];
}

/**
 * The catalog-missing finding, or an empty array when there is nothing to say.
 *
 * This is the safety net that makes moving indicators out of the compiled
 * bundle safe to ship: without it, a scan that consulted a fraction of the
 * corpus reports exactly the same clean result as one that consulted all of it.
 *
 * Two cases deliberately return nothing, because a false positive here gets the
 * whole tool switched off, which is worse than the finding being absent:
 *
 * - The catalog IS available. That means loadThreatIntel accepted a cache
 *   whose canonical entries match the content digest this release pins (or
 *   the release pins an empty catalog). The cache's public version/index
 *   digest and self-computed checksum are not sufficient on their own.
 * - The release pins an EMPTY catalog and the mode is `optional`. There is then
 *   no coverage to miss, so a finding would name zero indicators and appear on
 *   every scan for no reason. Under `required` it still fires, because that
 *   setting is a statement about the mechanism being in place, not about how
 *   many indicators happen to be in it.
 */
export function catalogFindings(
  state: CatalogState,
  mode: "optional" | "required" = "optional",
): Finding[] {
  if (state.available) return [];

  // Widened deliberately. CATALOG_DIGEST is generated with `as const`, so
  // `entryCount` carries the literal type of whatever this release happens to
  // pin, and comparing that literal to 0 is a type error the moment the catalog
  // stops being empty. The comparison is a real runtime condition over a
  // generated value, not a dead branch, so the type is widened rather than the
  // check removed.
  const missing: number = CATALOG_DIGEST.entryCount;
  if (missing === 0 && mode !== "required") return [];

  const reason = state.reason ?? "absent";
  const built = state.cachedVersion ? ` (it was built for ${state.cachedVersion})` : "";

  return [
    {
      rule: CATALOG_MISSING_RULE,
      description:
        `${missing} historical indicators were not consulted by this scan, because ` +
        `${CATALOG_REASON_TEXT[reason]}${built}. Those indicators are published ` +
        `separately from the package and are downloaded on demand, so this scan ` +
        `matched against the bundled set alone and no other part of the result says so.`,
      severity: catalogSeverityFor(reason, mode),
      confidence: 1.0,
      category: "trust",
      rationale:
        "The offline bundle carries recent and curated indicators; the catalog " +
        "carries the historical corpus that no longer fits in the package. A scan " +
        "without it is narrower than a scan with it, and reports the same success.",
      recommendation:
        "Run `supply-chain-guard feed refresh` to download the catalog, which is " +
        `cached for later scans. Exclude the ${CATALOG_MISSING_RULE} rule only if ` +
        "scanning against the bundled set alone is the intent.",
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
  /**
   * The catalog, when it was fetched, verified and installed this run.
   *
   * Absent means it was not installed. The feed refresh still succeeded: the
   * catalog is a second document with its own failure modes, and losing it must
   * not cost the caller the feed it asked for.
   */
  catalog?: { entryCount: number; cachePath: string };
  /**
   * Why the catalog was not installed, when it was not.
   *
   * Recorded rather than swallowed. A 404, a truncated shard and a digest
   * mismatch are three very different events: the last one says the published
   * asset does not match what this release pins, which is either a broken
   * publish or someone replacing the scanner's detection data. Reporting all
   * three as one silent "no catalog" line would hide exactly the case worth
   * seeing.
   */
  catalogError?: string;
}

/**
 * Validate a downloaded feed payload. Accepts both the published shape
 * `{ schema: 1, entries: [...] }` (feed.json) and a raw FeedIOC[] array
 * (the format the legacy updateThreatFeed() consumed).
 *
 * `expectedKind` says which of the two documents the caller asked for. A
 * document that does not declare a `kind` is a feed, which is what every
 * published feed.json is today, so the default keeps existing callers exact.
 *
 * The discriminator exists so a catalog cannot be served where a feed was
 * requested, or the reverse. Both are fetched over the same transport from the
 * same origin, and the two carry different trust: the feed is the current
 * published corpus, the catalog is historical bulk. Silently accepting either
 * in place of the other would let a stale or swapped asset masquerade as the
 * one that was asked for.
 */
export function parseFeedPayload(
  raw: string,
  expectedKind: "feed" | "catalog" = "feed",
): FeedIOC[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("feed is not valid JSON");
  }

  // Null-safe on purpose: `JSON.parse("null")` yields null, and the entries
  // extraction below has always tolerated it via optional chaining. Reading
  // `.kind` off it without the same care would turn a clean format error into
  // a TypeError.
  const declared = (parsed as { kind?: unknown } | null)?.kind;
  const kind = typeof declared === "string" ? declared : "feed";
  if (kind !== expectedKind) {
    throw new Error(
      `invalid feed format: expected kind ${JSON.stringify(expectedKind)}, got ${JSON.stringify(kind).slice(0, 64)}`,
    );
  }

  const entries: unknown = Array.isArray(parsed)
    ? parsed
    : (parsed as { entries?: unknown } | null)?.entries;

  // An empty catalog is legitimate and is the state Phase 1 ships: the catalog
  // exists, is signed and is reachable, and simply holds nothing yet. An empty
  // FEED is not, because it would silently replace the corpus with nothing.
  // Note the check is only relaxed for length: a missing or non-array `entries`
  // is still a hard reject for both kinds.
  if (!Array.isArray(entries) || (entries.length === 0 && expectedKind === "feed")) {
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
 * Cap on what a catalog document may expand to once decompressed.
 *
 * The transport caps the bytes on the WIRE (FEED_REMOTE_LIMITS.maxBytes, 32
 * MiB). That says nothing about what those bytes become: gzip compresses long
 * runs of one byte by roughly a thousand to one, so a 32 MiB body inside the
 * wire cap can still expand to gigabytes. This is the cap on the other side.
 */
export const CATALOG_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;

/** gzip magic: 0x1f 0x8b. Mirrors the sniff in src/archive-extractor.ts. */
function isGzip(body: Buffer): boolean {
  return body.length >= 2 && body[0] === 0x1f && body[1] === 0x8b;
}

/**
 * Decode a catalog body, decompressing it if it is gzipped, with the expansion
 * bounded so a decompression bomb cannot exhaust memory.
 *
 * `maxOutputLength: N` accepts exactly N bytes and throws at N + 1, so the cap
 * is passed as-is. The design's `+ 1` form belongs with archive-extractor,
 * which compares the length itself afterwards; without that comparison the
 * `+ 1` would let exactly one byte over the cap through.
 *
 * The uncompressed branch applies no size check of its own. That is safe only
 * because every caller arrives through `fetchHttpsBuffer` under
 * FEED_REMOTE_LIMITS, whose 32 MiB wire cap is below this 64 MiB expansion cap.
 * If this is ever called on a locally read file that premise is gone, and the
 * caller must bound the input itself.
 */
export function decodeCatalogBody(body: Buffer): string {
  if (!isGzip(body)) return body.toString("utf-8");
  try {
    return gunzipSync(body, {
      maxOutputLength: CATALOG_MAX_DECOMPRESSED_BYTES,
    }).toString("utf-8");
  } catch (err) {
    // Discriminate on the error CODE. The over-cap message is "Cannot create a
    // Buffer larger than 67108864 bytes" and contains neither "maxOutputLength"
    // nor "size", so a message regex matches it only through the word "buffer"
    // and would stop matching if Node ever reworded it. The regex is kept as a
    // fallback, not as the test.
    const code = (err as NodeJS.ErrnoException | null)?.code;
    const message = err instanceof Error ? err.message : String(err);
    if (code === "ERR_BUFFER_TOO_LARGE" || /maxOutputLength|buffer|size/i.test(message)) {
      throw new Error(
        `decompressed catalog exceeds ${CATALOG_MAX_DECOMPRESSED_BYTES} bytes`,
      );
    }
    throw new Error(`catalog is not valid gzip: ${message}`);
  }
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
/** sha256 of a string, as lowercase hex. */
function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * Fetch, verify and install the catalog. Throws with a specific reason.
 *
 * The download chain of trust runs package -> index -> shard, and every link
 * is checked before anything is written:
 *
 *  - the index must hash to CATALOG_DIGEST.sha256, which ships compiled into
 *    this package, so a replaced release asset is caught against an anchor the
 *    publisher of that asset does not control;
 *  - each shard must hash to the digest the index recorded for it;
 *  - each shard must parse as a catalog document;
 *  - the combined canonical entries must match CATALOG_DIGEST.entriesSha256,
 *    which keeps the installed cache bound to the same package anchor.
 *
 * Nothing is written until every shard has verified, so a run that fails
 * halfway leaves the previous catalog in place rather than a partial one.
 */
async function installCatalog(
  feedUrl: string,
  cacheDir: string,
  limits: RemoteRequestLimits,
): Promise<{ entryCount: number; cachePath: string }> {
  const version = CATALOG_DIGEST.version;
  const template = catalogTemplateForFeedUrl(feedUrl);

  const indexBody = (
    await fetchHttpsBuffer(catalogUrlFor(version, "catalog-index.json", template), limits)
  ).body.toString("utf-8");

  const indexDigest = sha256Hex(indexBody);
  if (indexDigest !== CATALOG_DIGEST.sha256) {
    throw new Error(
      `catalog index digest ${indexDigest.slice(0, 12)} does not match the ` +
        `${CATALOG_DIGEST.sha256.slice(0, 12)} this release pins`,
    );
  }

  const index = JSON.parse(indexBody) as {
    kind?: string;
    shards?: Array<{ path: string; sha256: string }>;
  };
  // The `shards` half is load-bearing: the loop below indexes it. The `kind`
  // half cannot fire while the digest check above precedes it, because any
  // document whose kind differs from the generated one hashes differently and
  // is rejected there first. It is kept as a shape assertion, not as a guard,
  // and a mutation that removes it leaves every test green: that is expected
  // here rather than a gap in the tests.
  if (index.kind !== "catalog-index" || !Array.isArray(index.shards)) {
    throw new Error("catalog index is not a catalog-index document");
  }

  const entries: FeedIOC[] = [];
  for (const shard of index.shards) {
    const raw = (await fetchHttpsBuffer(catalogUrlFor(version, shard.path, template), limits)).body;
    // Digest the DECODED document, matching how the generator computes it: a
    // mirror may serve the asset uncompressed, and gzip output is not
    // byte-stable across zlib versions.
    const body = decodeCatalogBody(raw);
    const digest = sha256Hex(body);
    if (digest !== shard.sha256) {
      throw new Error(
        `catalog shard ${shard.path} digest ${digest.slice(0, 12)} does not match the ` +
          `${String(shard.sha256).slice(0, 12)} the index records`,
      );
    }
    entries.push(...parseFeedPayload(body, "catalog"));
  }

  const entriesChecksum = sha256Hex(JSON.stringify(entries));
  if (entriesChecksum !== CATALOG_DIGEST.entriesSha256) {
    throw new Error(
      `catalog entries digest ${entriesChecksum.slice(0, 12)} does not match the ` +
        `${CATALOG_DIGEST.entriesSha256.slice(0, 12)} this release pins`,
    );
  }

  fs.mkdirSync(cacheDir, { recursive: true });
  const cachePath = path.join(cacheDir, CATALOG_CACHE_FILE);
  fs.writeFileSync(
    cachePath,
    JSON.stringify({
      version,
      sha256: CATALOG_DIGEST.sha256,
      // Over the entries as written. The reader checks it both against the
      // file and against the package-anchored entries digest above.
      checksum: entriesChecksum,
      timestamp: new Date().toISOString(),
      entries,
    }),
  );

  return { entryCount: entries.length, cachePath };
}

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

    // The catalog is a second, independent document. Its failures are recorded
    // and returned, never thrown: a caller who asked to refresh the feed got
    // the feed, and a missing catalog is reported by the scan itself through
    // THREAT_FEED_CATALOG_MISSING rather than by failing the refresh.
    let catalog: RefreshResult["catalog"];
    let catalogError: string | undefined;
    try {
      catalog = await installCatalog(feedUrl, cacheDir, limits);
    } catch (err) {
      catalogError = err instanceof Error ? err.message : String(err);
    }

    return { entryCount: entries.length, cachePath, catalog, catalogError };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to refresh threat feed from ${feedUrl}: ${message}`);
  }
}
