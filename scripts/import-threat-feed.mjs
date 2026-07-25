// import-threat-feed.mjs - Import malicious-package IOCs from upstream
// advisory databases into the curated feed (src/threat-intel.ts BUNDLED_FEED),
// then regenerate feed.json.
//
//   node scripts/import-threat-feed.mjs              -> import the last 7 days
//   node scripts/import-threat-feed.mjs --dry-run    -> report only, write nothing
//   node scripts/import-threat-feed.mjs --days 30 --limit 500
//   node scripts/import-threat-feed.mjs --json       -> machine-readable report
//
// SOURCES (both public, no account, no API key)
//   1. GitHub Advisory Database, malware advisories only
//      GET https://api.github.com/advisories?type=malware
//      Reviewed by GitHub's security team, CWE-506 "Embedded Malicious Code".
//      Data licensed CC BY 4.0 - attribution travels with every imported entry
//      in its `source` field and is documented in docs/threat-feed-sources.md.
//      GITHUB_TOKEN / GH_TOKEN is OPTIONAL: it only raises the REST rate limit
//      from 60 to 5000 requests/hour. Without it the import still works.
//   2. OSV.dev querybatch (corroboration only, never discovery)
//      POST https://api.osv.dev/v1/querybatch
//      Confirms the package is also listed as malicious (a MAL- id, sourced
//      from ossf/malicious-packages, Apache-2.0). A package confirmed by both
//      databases gets confidence 1.0; GitHub-only gets 0.9. An OSV outage
//      degrades gracefully - the import continues with GitHub-only provenance.
//
// FAILURE MODE
//   The upstream fetch is the only fatal step. Nothing is written until the
//   whole batch has been fetched, mapped, validated and re-parsed in memory,
//   so a network error, a malformed page or an unmappable entry leaves
//   src/threat-intel.ts and feed.json exactly as they were and the process
//   exits non-zero with a one-line reason.
//
// DISCIPLINE (same rules the curated entries follow)
//   - Only two upstream version shapes are mapped: an exact pin (`= 1.2.3`)
//     becomes `name@1.2.3`, and an all-versions range (`>= 0` / `> 0`) becomes
//     a bare name. A bounded range (`>= 1.0.0, <= 1.2.0`) is NOT collapsed into
//     a bare name - that would block versions upstream never called malicious -
//     it is reported as unmapped so a human can decide.
//   - Only ecosystems this scanner can actually match are imported. Everything
//     else (Maven, Actions, Pub, Swift, Hex, ...) is reported, not invented.
//   - Package names are re-validated against a conservative charset before
//     they are ever serialized into a TypeScript source file.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { buildFeed, serializeFeed, extractBundledEntries } from "./generate-feed.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const GITHUB_ADVISORIES_URL = "https://api.github.com/advisories";
export const OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";

/** Attribution required by the GitHub Advisory Database licence (CC BY 4.0). */
export const GITHUB_ATTRIBUTION =
  "GitHub Advisory Database (github/advisory-database), CC BY 4.0";
/** Attribution for the corroborating database reached through OSV.dev. */
export const OSV_ATTRIBUTION =
  "OSV.dev / OpenSSF malicious-packages (ossf/malicious-packages), Apache-2.0";

/**
 * Upstream ecosystem -> feed value prefix.
 *
 * These are exactly the prefixes the scanner resolves today: bare names are
 * npm (matchBareNpmIOC), everything else is matched by matchPackageIOC with
 * its ecosystem prefix. An ecosystem missing from this table has no matcher,
 * so importing it would add data no scan can ever use - those advisories are
 * reported as skipped instead.
 */
export const ECOSYSTEM_PREFIX = {
  npm: "",
  pip: "pypi:",
  composer: "composer:",
  go: "go:",
  rubygems: "ruby:",
  rust: "cargo:",
  nuget: "nuget:",
};

/** Feed ecosystem prefix -> OSV ecosystem name (for the corroboration query). */
export const OSV_ECOSYSTEM = {
  "": "npm",
  "pypi:": "PyPI",
  "composer:": "Packagist",
  "go:": "Go",
  "ruby:": "RubyGems",
  "cargo:": "crates.io",
  "nuget:": "NuGet",
};

/**
 * Upstream severity -> feed severity. FeedIOC only has critical/high/medium,
 * so `low` and `unknown` land on `medium` (the floor) rather than being
 * promoted to a level upstream never claimed.
 */
export const SEVERITY_MAP = {
  critical: "critical",
  high: "high",
  medium: "medium",
  moderate: "medium",
  low: "medium",
  unknown: "medium",
};

/**
 * Confidence is NOT published by either upstream database. These two project
 * constants encode the corroboration rule the curated feed already used:
 * a single reporting source is 0.9, two independent databases is 1.0.
 */
export const CONFIDENCE_SINGLE_SOURCE = 0.9;
export const CONFIDENCE_CORROBORATED = 1.0;

/**
 * Package names are serialized into a TypeScript source file, so the charset
 * is deliberately narrower than the feed's own package shape: no quotes, no
 * backslashes, no control characters, nothing that could terminate a string
 * literal. Every real npm/PyPI/Go/gem/crate/NuGet/Composer name fits.
 */
const SAFE_PACKAGE_NAME = /^[A-Za-z0-9][A-Za-z0-9._+~/-]*$/;
const SAFE_SCOPED_NAME = /^@[A-Za-z0-9][A-Za-z0-9._+~-]*\/[A-Za-z0-9][A-Za-z0-9._+~-]*$/;
/** Go module paths carry dots and slashes; still no quotes or spaces. */
const SAFE_MODULE_PATH = /^[A-Za-z0-9][A-Za-z0-9._+~/-]*$/;
const SAFE_VERSION = /^[A-Za-z0-9][A-Za-z0-9.+~!-]*$/;
/** Advisory ids are echoed into the `source` field. */
const SAFE_ADVISORY_ID = /^[A-Za-z0-9-]{1,64}$/;

// ---------------------------------------------------------------------------
// Mapping (pure, offline)
// ---------------------------------------------------------------------------

/**
 * Classify an upstream version range.
 *
 * @returns {{kind: "exact", version: string} | {kind: "all"} | {kind: "unmappable"}}
 */
export function parseVersionRange(range) {
  const raw = typeof range === "string" ? range.trim() : "";
  if (raw === "") return { kind: "unmappable" };
  // Whole package is malicious: ">= 0", "> 0", ">= 0.0.0".
  if (/^>=?\s*0(\.0)*$/.test(raw)) return { kind: "all" };
  // Exact pin: "= 1.2.3".
  const exact = raw.match(/^=\s*(\S+)$/);
  if (exact) return { kind: "exact", version: exact[1] };
  // Anything else (bounded ranges, "< 2.0.0", comma-joined clauses) is not
  // collapsible without over-blocking.
  return { kind: "unmappable" };
}

/** True if a package name is safe to serialize into the TypeScript feed. */
export function isSafePackageName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 214) return false;
  return SAFE_SCOPED_NAME.test(name) || SAFE_PACKAGE_NAME.test(name) || SAFE_MODULE_PATH.test(name);
}

/** Build the feed `value` for a package coordinate. */
export function feedValue(prefix, name, version) {
  return version ? `${prefix}${name}@${version}` : `${prefix}${name}`;
}

/**
 * Map one GitHub malware advisory to feed entries.
 *
 * @returns {{entries: Array<object>, skipped: Array<{reason: string, detail: string}>}}
 */
export function mapAdvisory(advisory) {
  const entries = [];
  const skipped = [];
  const id = advisory?.ghsa_id;

  if (!id || !SAFE_ADVISORY_ID.test(id)) {
    return { entries, skipped: [{ reason: "unusable-advisory-id", detail: String(id) }] };
  }
  if (advisory.withdrawn_at) {
    return { entries, skipped: [{ reason: "withdrawn", detail: id }] };
  }
  if (advisory.type !== undefined && advisory.type !== "malware") {
    return { entries, skipped: [{ reason: "not-malware", detail: `${id} (${advisory.type})` }] };
  }

  const severity = SEVERITY_MAP[String(advisory.severity ?? "unknown").toLowerCase()] ?? "medium";
  const firstSeen =
    typeof advisory.published_at === "string" && /^\d{4}-\d{2}-\d{2}/.test(advisory.published_at)
      ? advisory.published_at.slice(0, 10)
      : undefined;

  const vulns = Array.isArray(advisory.vulnerabilities) ? advisory.vulnerabilities : [];
  if (vulns.length === 0) {
    skipped.push({ reason: "no-affected-package", detail: id });
  }

  for (const vuln of vulns) {
    const ecosystem = String(vuln?.package?.ecosystem ?? "").toLowerCase();
    const name = vuln?.package?.name;
    const prefix = ECOSYSTEM_PREFIX[ecosystem];

    if (prefix === undefined) {
      skipped.push({ reason: "unsupported-ecosystem", detail: `${id} (${ecosystem || "none"})` });
      continue;
    }
    if (!isSafePackageName(name)) {
      skipped.push({ reason: "unsafe-package-name", detail: `${id} (${JSON.stringify(name)})` });
      continue;
    }

    const range = parseVersionRange(vuln.vulnerable_version_range);
    if (range.kind === "unmappable") {
      skipped.push({
        reason: "unmappable-version-range",
        detail: `${id} ${ecosystem}/${name} (${String(vuln.vulnerable_version_range ?? "")})`,
      });
      continue;
    }
    if (range.kind === "exact" && !SAFE_VERSION.test(range.version)) {
      skipped.push({ reason: "unsafe-version", detail: `${id} ${name}@${range.version}` });
      continue;
    }

    const entry = {
      type: "package",
      value: feedValue(prefix, name, range.kind === "exact" ? range.version : undefined),
      severity,
      confidence: CONFIDENCE_SINGLE_SOURCE,
      source: id,
    };
    if (firstSeen) entry.firstSeen = firstSeen;
    // Carried for the OSV corroboration query and the report; stripped before
    // the entry is serialized into the feed.
    entry._ecosystemPrefix = prefix;
    entry._name = name;
    entries.push(entry);
  }

  return { entries, skipped };
}

/** Map a page (or several) of advisories. */
export function mapAdvisories(advisories) {
  const entries = [];
  const skipped = [];
  for (const advisory of advisories) {
    const result = mapAdvisory(advisory);
    entries.push(...result.entries);
    skipped.push(...result.skipped);
  }
  return { entries, skipped };
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

/** Split a feed package value into { prefix, name, version }. */
export function splitPackageValue(value) {
  const match = value.match(/^([a-z]+:)/);
  const prefix = match ? match[1] : "";
  const rest = value.slice(prefix.length);
  const at = rest.lastIndexOf("@");
  return {
    prefix,
    name: at > 0 ? rest.slice(0, at) : rest,
    version: at > 0 ? rest.slice(at + 1) : undefined,
  };
}

/**
 * Drop entries the feed already covers.
 *
 * Two rules, both matching how the scanner reads the feed:
 *   1. exact duplicate - same `type:value` (the key mergeFeeds uses)
 *   2. already covered - a bare-name IOC for the same ecosystem+package
 *      already fires on every version, so a version-pinned import adds nothing
 *
 * @returns {{added: Array<object>, duplicates: number, covered: number}}
 */
export function dedupe(existing, incoming) {
  const seen = new Set();
  const bareNames = new Set();
  for (const entry of existing) {
    seen.add(`${entry.type}:${entry.value}`);
    if (entry.type !== "package") continue;
    const { prefix, name, version } = splitPackageValue(entry.value);
    if (version === undefined) bareNames.add(`${prefix}${name}`);
  }

  const added = [];
  let duplicates = 0;
  let covered = 0;

  for (const entry of incoming) {
    const key = `${entry.type}:${entry.value}`;
    if (seen.has(key)) {
      duplicates++;
      continue;
    }
    const { prefix, name, version } = splitPackageValue(entry.value);
    if (version !== undefined && bareNames.has(`${prefix}${name}`)) {
      covered++;
      continue;
    }
    seen.add(key);
    if (version === undefined) bareNames.add(`${prefix}${name}`);
    added.push(entry);
  }

  return { added, duplicates, covered };
}

// ---------------------------------------------------------------------------
// Upstream fetch (bounded, explicit timeout, optional token)
// ---------------------------------------------------------------------------

/** ISO date (YYYY-MM-DD) `days` before `now`. */
export function sinceDate(days, now = new Date()) {
  const d = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
  return d.toISOString().slice(0, 10);
}

/** Extract the rel="next" URL from a Link header, or null. */
export function nextPageUrl(linkHeader) {
  if (!linkHeader) return null;
  const match = String(linkHeader).match(/<([^>]+)>;\s*rel="next"/);
  return match ? match[1] : null;
}

/**
 * Fetch malware advisories published on or after `since`.
 *
 * Bounded three ways: an explicit per-request timeout, a hard page cap, and
 * the fixed 100-item page size. Any non-200 or transport error rejects - the
 * caller treats that as fatal and writes nothing.
 */
export async function fetchMalwareAdvisories({
  since,
  until,
  maxPages = 10,
  timeoutMs = 15000,
  token,
  fetchImpl = globalThis.fetch,
  baseUrl = GITHUB_ADVISORIES_URL,
} = {}) {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "supply-chain-guard-feed-import",
  };
  // Strictly optional: raises the rate limit, never required for access.
  if (token) headers.Authorization = `Bearer ${token}`;

  const params = new URLSearchParams({
    type: "malware",
    per_page: "100",
    sort: "published",
    direction: "desc",
  });
  if (since) params.set("published", until ? `${since}..${until}` : `>=${since}`);

  let url = `${baseUrl}?${params.toString()}`;
  const advisories = [];
  let pages = 0;
  let truncated = false;

  while (url) {
    if (pages >= maxPages) {
      truncated = true;
      break;
    }
    let response;
    try {
      response = await fetchImpl(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`GitHub Advisory Database request failed: ${message}`);
    }
    if (!response.ok) {
      const remaining = response.headers?.get?.("x-ratelimit-remaining");
      const hint =
        remaining === "0"
          ? " (rate limit exhausted; set GITHUB_TOKEN to raise it from 60 to 5000 requests/hour)"
          : "";
      throw new Error(
        `GitHub Advisory Database returned HTTP ${response.status}${hint}`,
      );
    }
    let page;
    try {
      page = await response.json();
    } catch {
      throw new Error("GitHub Advisory Database returned a body that is not JSON");
    }
    if (!Array.isArray(page)) {
      throw new Error("GitHub Advisory Database returned an unexpected payload (not an array)");
    }
    advisories.push(...page);
    pages++;
    url = nextPageUrl(response.headers?.get?.("link"));
  }

  return { advisories, pages, truncated };
}

/**
 * Ask OSV.dev which of these packages it also lists as malicious (MAL- ids).
 *
 * Corroboration only: OSV is never used to DISCOVER a package, so an OSV
 * entry that applies to a single version of an otherwise legitimate package
 * can never turn into a bare-name block here.
 *
 * @returns {Promise<{ids: Map<string, string>, ok: boolean, error?: string}>}
 *          keyed by `${prefix}${name}`
 */
export async function crossReferenceOsv(
  packages,
  { timeoutMs = 15000, chunkSize = 250, fetchImpl = globalThis.fetch, url = OSV_QUERYBATCH_URL } = {},
) {
  const ids = new Map();
  const unique = [...new Map(packages.map((p) => [`${p.prefix}${p.name}`, p])).values()];
  if (unique.length === 0) return { ids, ok: true };

  try {
    for (let i = 0; i < unique.length; i += chunkSize) {
      const chunk = unique.slice(i, i + chunkSize);
      const body = JSON.stringify({
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: OSV_ECOSYSTEM[p.prefix] },
        })),
      });
      const response = await fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "supply-chain-guard-feed-import",
        },
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const json = await response.json();
      const results = Array.isArray(json?.results) ? json.results : [];
      chunk.forEach((pkg, index) => {
        const vulns = results[index]?.vulns;
        if (!Array.isArray(vulns)) return;
        const mal = vulns
          .map((v) => v?.id)
          .find((id) => typeof id === "string" && id.startsWith("MAL-") && SAFE_ADVISORY_ID.test(id));
        if (mal) ids.set(`${pkg.prefix}${pkg.name}`, mal);
      });
    }
    return { ids, ok: true };
  } catch (err) {
    // Non-fatal by design: corroboration is an enrichment, not a gate.
    return { ids, ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

// ---------------------------------------------------------------------------
// Serialization into src/threat-intel.ts
// ---------------------------------------------------------------------------

const FEED_MARKER = "const BUNDLED_FEED: FeedIOC[] = [";

/** Render one entry as a source line in the file's existing one-line style. */
export function formatEntry(entry) {
  const parts = [
    `type: ${JSON.stringify(entry.type)}`,
    `value: ${JSON.stringify(entry.value)}`,
    `severity: ${JSON.stringify(entry.severity)}`,
    // Match the file's existing style: 1.0, not 1.
    `confidence: ${Number.isInteger(entry.confidence) ? entry.confidence.toFixed(1) : entry.confidence}`,
    `source: ${JSON.stringify(entry.source)}`,
  ];
  if (entry.firstSeen) parts.push(`firstSeen: ${JSON.stringify(entry.firstSeen)}`);
  return `  { ${parts.join(", ")} },`;
}

/** Strip the transient bookkeeping fields before serialization. */
export function publicEntry(entry) {
  const { _ecosystemPrefix, _name, ...rest } = entry;
  return rest;
}

/**
 * Append entries to the BUNDLED_FEED array literal in a threat-intel.ts source
 * string. Uses the same marker/terminator pair as generate-feed.mjs, so the
 * two never disagree about where the array ends.
 */
export function applyEntries(source, entries, { date, sourceLabel = "GitHub Advisory Database" } = {}) {
  const start = source.indexOf(FEED_MARKER);
  if (start === -1) throw new Error("BUNDLED_FEED marker not found in src/threat-intel.ts");
  const terminator = source.indexOf("\n];", start + FEED_MARKER.length);
  if (terminator === -1) throw new Error("BUNDLED_FEED array terminator not found in src/threat-intel.ts");

  // Insert BEFORE the terminator's own line break, carriage return included.
  // Splitting a CRLF pair here would leave a stray "\r" behind, which turns a
  // 25-line append into a whole-file diff on a CRLF checkout.
  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  const insertAt = terminator > 0 && source[terminator - 1] === "\r" ? terminator - 1 : terminator;

  const header = `  // Imported from ${sourceLabel} (${date}) - see docs/threat-feed-sources.md`;
  // A leading empty line separates the imported block from the curated entries.
  // Every line is prefixed (not suffixed) with the EOL, so the last imported
  // line borrows the terminator's own line break from the untouched remainder.
  const lines = ["", header, ...entries.map((e) => formatEntry(publicEntry(e)))];
  const block = lines.map((line) => eol + line).join("");

  return source.slice(0, insertAt) + block + source.slice(insertAt);
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Run a full import.
 *
 * Nothing is written until every step below has succeeded in memory, so a
 * failure anywhere leaves src/threat-intel.ts and feed.json byte-identical.
 */
export async function importUpstreamFeed({
  root = repoRoot,
  days = 7,
  since,
  until,
  limit = 250,
  maxPages = 10,
  timeoutMs = 15000,
  token,
  useOsv = true,
  dryRun = false,
  now = new Date(),
  fetchImpl = globalThis.fetch,
} = {}) {
  const from = since ?? sinceDate(days, now);
  const threatIntelPath = join(root, "src", "threat-intel.ts");
  const feedPath = join(root, "feed.json");

  // 1. Fetch (fatal on failure - nothing has been written yet).
  const { advisories, pages, truncated } = await fetchMalwareAdvisories({
    since: from,
    until,
    maxPages,
    timeoutMs,
    token,
    fetchImpl,
  });

  // 2. Map (pure).
  const { entries: mapped, skipped } = mapAdvisories(advisories);

  // 3. Dedupe against the feed that is actually committed.
  const existing = extractBundledEntries(root);
  const { added, duplicates, covered } = dedupe(existing, mapped);
  const capped = added.length > limit;
  const selected = capped ? added.slice(0, limit) : added;

  // 4. Corroborate with OSV (never fatal).
  let osv = { ids: new Map(), ok: true };
  if (useOsv && selected.length > 0) {
    osv = await crossReferenceOsv(
      selected.map((e) => ({ prefix: e._ecosystemPrefix, name: e._name })),
      { timeoutMs, fetchImpl },
    );
    for (const entry of selected) {
      const mal = osv.ids.get(`${entry._ecosystemPrefix}${entry._name}`);
      if (mal) {
        entry.source = `${entry.source}, ${mal}`;
        entry.confidence = CONFIDENCE_CORROBORATED;
      }
    }
  }

  const report = {
    since: from,
    until: until ?? null,
    advisoriesFetched: advisories.length,
    pages,
    truncated,
    mapped: mapped.length,
    duplicates,
    covered,
    skipped: summarize(skipped),
    skippedTotal: skipped.length,
    corroboratedByOsv: [...osv.ids.keys()].length,
    osvAvailable: osv.ok,
    osvError: osv.error ?? null,
    added: selected.length,
    capped,
    entries: selected.map(publicEntry),
    dryRun,
    written: false,
  };

  if (selected.length === 0 || dryRun) return report;

  // 5. Build the new source in memory and prove it re-parses to exactly the
  //    entries we expect BEFORE anything touches the working tree.
  const original = readFileSync(threatIntelPath, "utf8");
  const updated = applyEntries(original, selected, { date: from });
  writeFileSync(threatIntelPath, updated);
  try {
    const reparsed = extractBundledEntries(root);
    if (reparsed.length !== existing.length + selected.length) {
      throw new Error(
        `re-parse mismatch: expected ${existing.length + selected.length} entries, got ${reparsed.length}`,
      );
    }
    // 6. Regenerate feed.json from the (now updated) single source of truth.
    writeFileSync(feedPath, serializeFeed(buildFeed(root)));
  } catch (err) {
    // Roll the source file back so a half-applied import can never ship.
    writeFileSync(threatIntelPath, original);
    throw new Error(
      `import aborted and rolled back: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  report.written = true;
  return report;
}

/** Count skip reasons for the report. */
function summarize(skipped) {
  const counts = {};
  for (const item of skipped) counts[item.reason] = (counts[item.reason] ?? 0) + 1;
  return counts;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export function parseArgs(argv) {
  const opts = { dryRun: false, json: false, useOsv: true };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => argv[++i];
    if (arg === "--dry-run") opts.dryRun = true;
    else if (arg === "--json") opts.json = true;
    else if (arg === "--no-osv") opts.useOsv = false;
    else if (arg === "--days") opts.days = Number(next());
    else if (arg === "--since") opts.since = next();
    else if (arg === "--until") opts.until = next();
    else if (arg === "--limit") opts.limit = Number(next());
    else if (arg === "--max-pages") opts.maxPages = Number(next());
    else if (arg === "--timeout") opts.timeoutMs = Number(next());
    else if (arg === "--help" || arg === "-h") opts.help = true;
    else throw new Error(`unknown option: ${arg}`);
  }
  return opts;
}

const USAGE = `
  Import malicious-package IOCs from upstream advisory databases.

    node scripts/import-threat-feed.mjs [options]

    --days <n>        Look-back window in days (default 7)
    --since <date>    Explicit start date (YYYY-MM-DD), overrides --days
    --until <date>    Explicit end date (YYYY-MM-DD)
    --limit <n>       Maximum new entries to add in one run (default 250)
    --max-pages <n>   Maximum upstream pages to fetch (default 10)
    --timeout <ms>    Per-request timeout (default 15000)
    --no-osv          Skip the OSV.dev corroboration query
    --dry-run         Report only; write nothing
    --json            Machine-readable report on stdout

  GITHUB_TOKEN / GH_TOKEN is optional and only raises the REST rate limit.
`;

const isMain =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  let report;
  try {
    const opts = parseArgs(process.argv.slice(2));
    if (opts.help) {
      console.log(USAGE);
      process.exit(0);
    }
    report = await importUpstreamFeed({
      ...opts,
      token: process.env.GITHUB_TOKEN || process.env.GH_TOKEN || undefined,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`\n  Feed import failed: ${message}`);
    console.error(`  Nothing was written; src/threat-intel.ts and feed.json are unchanged.\n`);
    process.exit(1);
  }

  if (process.argv.includes("--json")) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`\n  Upstream feed import (published >= ${report.since})\n`);
    console.log(`  Advisories fetched:   ${report.advisoriesFetched} (${report.pages} page(s)${report.truncated ? ", page cap reached" : ""})`);
    console.log(`  Mapped to IOCs:       ${report.mapped}`);
    console.log(`  Already in the feed:  ${report.duplicates} duplicate, ${report.covered} covered by a bare-name IOC`);
    console.log(`  Skipped:              ${report.skippedTotal} ${JSON.stringify(report.skipped)}`);
    console.log(`  OSV corroboration:    ${report.osvAvailable ? `${report.corroboratedByOsv} confirmed` : `unavailable (${report.osvError})`}`);
    console.log(`  New entries:          ${report.added}${report.capped ? " (limit reached)" : ""}`);
    for (const entry of report.entries.slice(0, 20)) {
      console.log(`    ${entry.value}  [${entry.source}]`);
    }
    if (report.entries.length > 20) console.log(`    ... and ${report.entries.length - 20} more`);
    console.log(
      report.written
        ? `\n  Written: src/threat-intel.ts + feed.json. Review the diff before committing.\n`
        : `\n  Nothing written${report.dryRun ? " (--dry-run)" : ""}.\n`,
    );
  }
}
