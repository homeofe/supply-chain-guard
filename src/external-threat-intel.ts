/**
 * Native External Threat Intelligence Feed Clients & Cache (Node.js 22+)
 *
 * Integrates:
 * - OSV (Open Source Vulnerabilities API & Malicious Package Database)
 * - EPSS (Exploit Prediction Scoring System via FIRST.org API)
 * - CISA KEV (Known Exploited Vulnerabilities Catalog)
 * - OpenSSF Scorecards (Security Scorecards API)
 *
 * Requirements:
 * - Strict ecosystem prefixing (npm:, pypi:, cargo:, golang:, etc.)
 * - Native Node 22 APIs (fetch, crypto, node:zlib, node:stream)
 * - Zero native C-bindings or external SQLite dependencies
 * - In-memory and file cache with 2500ms timeout per lookup
 * - Fail-open resilience: timeouts/offline fall back to safe defaults
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { lockfileEntryName } from "./sbom-generator.js";
import type {
  ConfirmedMalwareInput,
  ExternalIntelReport,
  ExternalLookupStatus,
  SbomRating,
  Severity,
  VulnerabilityScoreInput,
} from "./types.js";

/**
 * Version reported to the upstream feeds. Read from package.json rather than
 * hardcoded: this file is not one of the aahp.config.json versionSites, so a literal
 * here would be invisible to the version-sync gate and would keep identifying the
 * tool by a released-and-gone version with every check green.
 */
const TOOL_VERSION: string = (() => {
  for (const candidate of [
    path.join(__dirname, "..", "package.json"),
    path.join(__dirname, "..", "..", "package.json"),
  ]) {
    try {
      const pkg = JSON.parse(fs.readFileSync(candidate, "utf-8")) as {
        name?: string;
        version?: string;
      };
      if (pkg.name === "supply-chain-guard" && typeof pkg.version === "string") {
        return pkg.version;
      }
    } catch {
      // Try the next candidate
    }
  }
  return "0.0.0";
})();

const USER_AGENT = `supply-chain-guard/${TOOL_VERSION}`;

/** Default timeout per lookup: 2500ms */
export const LOOKUP_TIMEOUT_MS = 2500;

/** Default fallback OpenSSF Scorecard score on timeout or missing data */
export const SCORECARD_FALLBACK_SCORE = 3.0;

/** Default fallback EPSS probability */
export const EPSS_FALLBACK_SCORE = 0.0;

/**
 * Standard ecosystem prefixes.
 * All feed lookups and cache keys MUST use one of these standard prefixes
 * to prevent cross-ecosystem cache poisoning or collisions.
 */
export const STANDARD_ECOSYSTEM_PREFIXES = [
  "npm:",
  "pypi:",
  "cargo:",
  "golang:",
  "go:",
  "rubygems:",
  "ruby:",
  "composer:",
  "nuget:",
  // OSV serves these too. They were missing, so a Maven or Swift coordinate threw
  // out of a lookup path whose whole contract is to fail open.
  "maven:",
  "swift:",
  "hex:",
  "cran:",
  "pub:",
  "conan:",
] as const;

export type StandardEcosystemPrefix = (typeof STANDARD_ECOSYSTEM_PREFIXES)[number];

/** OSV ecosystem name mapping */
const OSV_ECOSYSTEM_MAP: Record<string, string> = {
  "npm:": "npm",
  "pypi:": "PyPI",
  "cargo:": "crates.io",
  "golang:": "Go",
  "go:": "Go",
  "rubygems:": "RubyGems",
  "ruby:": "RubyGems",
  "composer:": "Packagist",
  "nuget:": "NuGet",
  "maven:": "Maven",
  "swift:": "SwiftURL",
  "hex:": "Hex",
  "cran:": "CRAN",
  "pub:": "Pub",
  "conan:": "ConanCenter",
};

/**
 * Validate that an input ecosystem string is a recognized standard prefix.
 */
export function isValidEcosystemPrefix(prefix: string): boolean {
  const normalized = prefix.endsWith(":") ? prefix.toLowerCase() : `${prefix.toLowerCase()}:`;
  return STANDARD_ECOSYSTEM_PREFIXES.includes(normalized as StandardEcosystemPrefix);
}

/**
 * Normalize and validate ecosystem prefix.
 * Throws if the ecosystem is not recognized.
 */
export function normalizeEcosystemPrefix(ecosystem: string): string {
  const normalized = ecosystem.endsWith(":") ? ecosystem.toLowerCase() : `${ecosystem.toLowerCase()}:`;
  if (!STANDARD_ECOSYSTEM_PREFIXES.includes(normalized as StandardEcosystemPrefix)) {
    throw new Error(
      `Invalid ecosystem prefix: "${ecosystem}". Must be one of: ${STANDARD_ECOSYSTEM_PREFIXES.join(", ")}`,
    );
  }
  // Canonicalize aliases. The canonical spellings are the ones this repo's feed
  // already uses (src/threat-intel.ts, scripts/osv-export.ts): `go:` and `ruby:`,
  // not `golang:` / `rubygems:`. Canonicalising the other way meant a cache key
  // could never line up with a feed key for the same package.
  if (normalized === "golang:") return "go:";
  if (normalized === "rubygems:") return "ruby:";
  return normalized;
}

/**
 * Format a standard cache key for package lookups with mandatory ecosystem prefix.
 */
export function formatPackageCacheKey(
  ecosystemPrefix: string,
  packageName: string,
  version?: string,
): string {
  const normalizedPrefix = normalizeEcosystemPrefix(ecosystemPrefix);
  const trimmedName = packageName.trim();
  // Package identity is ecosystem-specific. Lowercasing every coordinate made
  // distinct Go, Maven, Swift and Conan packages share an authoritative cache
  // entry. Only normalize registries whose identity rules are case-insensitive.
  const cleanName =
    normalizedPrefix === "pypi:"
      ? trimmedName.toLowerCase().replace(/[-_.]+/g, "-")
      : ["npm:", "ruby:", "composer:", "nuget:", "cargo:", "hex:", "cran:", "pub:"].includes(
            normalizedPrefix,
          )
        ? trimmedName.toLowerCase()
        : trimmedName;
  const cleanVersion = version ? version.trim() : "*";
  return `${normalizedPrefix}${cleanName}@${cleanVersion}`;
}

/**
 * Split a prefixed package string into ecosystem prefix and package name.
 * Throws if prefix is missing or invalid.
 */
export function parsePrefixedPackage(packageIdentifier: string): {
  ecosystemPrefix: string;
  packageName: string;
  version?: string;
} {
  const colonIndex = packageIdentifier.indexOf(":");
  if (colonIndex <= 0) {
    throw new Error(
      `Missing standard ecosystem prefix in "${packageIdentifier}". All feed lookups must use standard ecosystem prefixes (e.g. "npm:package-name", "pypi:requests").`,
    );
  }

  const prefix = packageIdentifier.slice(0, colonIndex + 1);
  const normalizedPrefix = normalizeEcosystemPrefix(prefix);
  const rest = packageIdentifier.slice(colonIndex + 1);

  // Version separator is the last @ if after index 0 (handling npm scopes like @scope/pkg@1.0.0)
  const lastAt = rest.lastIndexOf("@");
  if (lastAt > 0) {
    const packageName = rest.slice(0, lastAt);
    const version = rest.slice(lastAt + 1);
    return { ecosystemPrefix: normalizedPrefix, packageName, version };
  }

  return { ecosystemPrefix: normalizedPrefix, packageName: rest };
}

// ---------------------------------------------------------------------------
// Cache Structure
// ---------------------------------------------------------------------------

interface CacheEntry<T> {
  data: T;
  cachedAt: number;
  ttlMs: number;
}

interface CacheFile {
  version: 1;
  entries: Record<string, CacheEntry<unknown>>;
}

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * TTL for a result that is a FALLBACK rather than an answer: the lookup timed out,
 * the host was unreachable, or the API returned a non-ok status.
 *
 * Failing open for the current scan is correct. Storing that fallback for a day is
 * not: it turns one 2500ms blip into 24 hours during which a real MAL- record or a
 * KEV entry is never seen again, because the empty result is served from cache and
 * no request is made. Keep it short enough that the next scan retries.
 */
export const LOOKUP_FAILURE_TTL_MS = 60 * 1000; // 1 minute

const MAX_CACHE_FILE_BYTES = 5 * 1024 * 1024;
const MAX_CACHE_ENTRIES = 20_000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const MAX_INVENTORY_FILE_BYTES = 10 * 1024 * 1024;
const MAX_INVENTORY_COORDINATES = 1_000;
const MAX_VULNERABILITY_INPUTS = 1_000;
const DEFAULT_OVERALL_TIMEOUT_MS = 30_000;

function responseExceedsLimit(response: Response): boolean {
  const value = response.headers?.get?.("content-length");
  if (!value || !/^\d+$/.test(value)) return false;
  return Number(value) > MAX_RESPONSE_BYTES;
}

class InvalidExternalResponse extends Error {}

/** Read and parse a JSON response without trusting Content-Length to be present. */
async function readJsonResponseBounded(response: Response): Promise<unknown> {
  if (responseExceedsLimit(response)) {
    throw new InvalidExternalResponse("external response exceeds the byte limit");
  }

  const body = response.body;
  if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let total = 0;
    let raw = "";
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          throw new InvalidExternalResponse("external response exceeds the byte limit");
        }
        raw += decoder.decode(value, { stream: true });
      }
      raw += decoder.decode();
    } finally {
      reader.releaseLock();
    }
    try {
      return JSON.parse(raw) as unknown;
    } catch {
      throw new InvalidExternalResponse("external response is not valid JSON");
    }
  }

  // Test doubles often expose json() without a web ReadableStream. Production
  // fetch responses take the bounded stream path above.
  if (typeof response.json === "function") {
    try {
      return await response.json() as unknown;
    } catch {
      throw new InvalidExternalResponse("external response is not valid JSON");
    }
  }
  throw new InvalidExternalResponse("external response has no readable body");
}

function readJsonFileBounded(filePath: string, rootDir: string): unknown {
  const sourceStat = fs.lstatSync(filePath);
  if (sourceStat.isSymbolicLink()) {
    throw new Error("external-intelligence inventory files must not be symbolic links");
  }
  const canonicalRoot = fs.realpathSync(rootDir);
  const canonicalFile = fs.realpathSync(filePath);
  const relative = path.relative(canonicalRoot, canonicalFile);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) {
    throw new Error("external-intelligence inventory file escapes the scan root");
  }
  if (sourceStat.size > MAX_INVENTORY_FILE_BYTES) {
    throw new Error("JSON input exceeds the external-intelligence inventory limit");
  }
  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as unknown;
}

/** User-owned cache directory, deliberately outside the repository being scanned. */
export function defaultThreatIntelCacheDir(): string {
  const base =
    process.platform === "win32" && process.env.LOCALAPPDATA
      ? process.env.LOCALAPPDATA
      : process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache");
  return path.join(base, "supply-chain-guard", "external-intel");
}

export class ThreatIntelCache {
  private memory = new Map<string, CacheEntry<unknown>>();
  private cacheFilePath?: string;
  private dirty = false;

  constructor(cacheDir?: string) {
    if (cacheDir) {
      try {
        fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
        if (fs.lstatSync(cacheDir).isSymbolicLink()) return;
        this.cacheFilePath = path.join(cacheDir, "external-threat-cache.json");
        this.loadFromFile();
      } catch {
        // In-memory only on restricted filesystem
      }
    }
  }

  get<T>(key: string): T | undefined {
    const entry = this.memory.get(key) as CacheEntry<T> | undefined;
    if (!entry) return undefined;
    if (Date.now() - entry.cachedAt > entry.ttlMs) {
      this.memory.delete(key);
      this.dirty = true;
      return undefined;
    }
    return entry.data;
  }

  set<T>(key: string, data: T, ttlMs = DEFAULT_TTL_MS): void {
    if (Number.isFinite(ttlMs) && ttlMs <= 0) {
      this.delete(key);
      return;
    }
    const boundedTtl = Number.isFinite(ttlMs)
      ? Math.max(1, Math.min(DEFAULT_TTL_MS, ttlMs))
      : DEFAULT_TTL_MS;
    if (!this.memory.has(key) && this.memory.size >= MAX_CACHE_ENTRIES) {
      const oldest = this.memory.keys().next().value as string | undefined;
      if (oldest) this.memory.delete(oldest);
    }
    this.memory.set(key, {
      data,
      cachedAt: Date.now(),
      ttlMs: boundedTtl,
    });
    this.dirty = true;
  }

  delete(key: string): void {
    if (this.memory.delete(key)) this.dirty = true;
  }

  flush(): void {
    if (!this.dirty || !this.cacheFilePath) return;
    try {
      if (fs.existsSync(this.cacheFilePath) && fs.lstatSync(this.cacheFilePath).isSymbolicLink()) {
        return;
      }
      const entries: Record<string, CacheEntry<unknown>> = Object.create(null) as Record<
        string,
        CacheEntry<unknown>
      >;
      const now = Date.now();
      let serializedBytes = 32;
      for (const [key, entry] of [...this.memory.entries()].reverse()) {
        if (now - entry.cachedAt > entry.ttlMs) continue;
        const fragment = JSON.stringify({ [key]: entry });
        const fragmentBytes = Buffer.byteLength(fragment, "utf-8") + 1;
        if (serializedBytes + fragmentBytes > MAX_CACHE_FILE_BYTES) continue;
        entries[key] = entry;
        serializedBytes += fragmentBytes;
      }
      const tempPath = `${this.cacheFilePath}.${process.pid}.${randomUUID()}.tmp`;
      const cacheFile: CacheFile = { version: 1, entries };
      const serialized = JSON.stringify(cacheFile);
      if (Buffer.byteLength(serialized, "utf-8") > MAX_CACHE_FILE_BYTES) return;
      fs.writeFileSync(tempPath, serialized, {
        encoding: "utf-8",
        mode: 0o600,
        flag: "wx",
      });
      fs.renameSync(tempPath, this.cacheFilePath);
      this.dirty = false;
    } catch {
      // Non-fatal cache flush failure
    }
  }

  clear(): void {
    this.memory.clear();
    this.dirty = true;
    if (this.cacheFilePath && fs.existsSync(this.cacheFilePath)) {
      try {
        fs.unlinkSync(this.cacheFilePath);
      } catch {
        // ignore
      }
    }
  }

  private loadFromFile(): void {
    if (!this.cacheFilePath || !fs.existsSync(this.cacheFilePath)) return;
    try {
      const stat = fs.lstatSync(this.cacheFilePath);
      if (stat.isSymbolicLink() || stat.size > MAX_CACHE_FILE_BYTES) return;
      const raw = fs.readFileSync(this.cacheFilePath, "utf-8");
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
      const cacheFile = parsed as Partial<CacheFile>;
      if (cacheFile.version !== 1 || !cacheFile.entries || typeof cacheFile.entries !== "object") return;
      const now = Date.now();
      for (const [key, candidate] of Object.entries(cacheFile.entries).slice(0, MAX_CACHE_ENTRIES)) {
        if (!candidate || typeof candidate !== "object") continue;
        const entry = candidate as Partial<CacheEntry<unknown>>;
        if (
          typeof entry.cachedAt === "number" &&
          Number.isFinite(entry.cachedAt) &&
          entry.cachedAt >= 0 &&
          entry.cachedAt <= now &&
          typeof entry.ttlMs === "number" &&
          Number.isFinite(entry.ttlMs) &&
          entry.ttlMs > 0 &&
          entry.ttlMs <= DEFAULT_TTL_MS &&
          now - entry.cachedAt <= entry.ttlMs &&
          "data" in entry
        ) {
          this.memory.set(key, entry as CacheEntry<unknown>);
        }
      }
    } catch {
      // Corrupt cache falls back to clean memory cache
    }
  }
}

// Global in-process cache singleton
const globalMemoryCache = new ThreatIntelCache();

// ---------------------------------------------------------------------------
// Native Feed Query Types & Results
// ---------------------------------------------------------------------------

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  isMalicious?: boolean;
  databaseSpecific?: Record<string, unknown>;
  severity?: Array<{ type: string; score: string }>;
}

export interface OsvQueryResult {
  vulns: OsvVulnerability[];
  hasMalwareSignature: boolean;
  malwareReasons?: string[];
  status: ExternalLookupStatus;
}

export interface EpssResult {
  cve: string;
  epss: number;
  percentile: number;
  status: ExternalLookupStatus;
}

export interface CisaKevResult {
  cve: string;
  inKev: boolean;
  dateAdded?: string;
  dueDate?: string;
  notes?: string;
  status: ExternalLookupStatus;
}

export interface ScorecardResult {
  repo: string;
  score: number;
  date?: string;
  checks?: Record<string, number>;
  status: ExternalLookupStatus;
}

export interface ExternalIntelOptions {
  timeoutMs?: number;
  cache?: ThreatIntelCache;
  fetchFn?: typeof fetch;
  maxPackages?: number;
  /** Aggregate deadline for one gather operation. Individual query clients ignore it unless supplied internally. */
  overallTimeoutMs?: number;
  deadlineAt?: number;
}

export interface GatherExternalIntelOptions extends ExternalIntelOptions {
  /** Caller-supplied Scorecard value; when present no Scorecard network lookup is required. */
  scorecardOverride?: number;
}

function effectiveLookupTimeout(options: ExternalIntelOptions): number {
  const perLookup = Math.max(1, Math.min(30_000, options.timeoutMs ?? LOOKUP_TIMEOUT_MS));
  if (options.deadlineAt === undefined) return perLookup;
  return Math.max(0, Math.min(perLookup, Math.floor(options.deadlineAt - Date.now())));
}

function isLookupStatus(value: unknown): value is ExternalLookupStatus {
  return value === "ok" || value === "not-found" || value === "unavailable" || value === "invalid";
}

function isOsvVulnerability(value: unknown): value is OsvVulnerability {
  if (!value || typeof value !== "object") return false;
  const v = value as OsvVulnerability;
  return (
    typeof v.id === "string" && v.id.length > 0 && v.id.length <= 200 &&
    (v.summary === undefined || (typeof v.summary === "string" && v.summary.length <= 100_000)) &&
    (v.details === undefined || (typeof v.details === "string" && v.details.length <= 1_000_000)) &&
    (v.aliases === undefined || (Array.isArray(v.aliases) && v.aliases.length <= 100 && v.aliases.every((a) => typeof a === "string" && a.length <= 200))) &&
    (v.severity === undefined ||
      (Array.isArray(v.severity) &&
        v.severity.length <= 10 &&
        v.severity.every((s) => s && typeof s.type === "string" && s.type.length <= 50 && typeof s.score === "string" && s.score.length <= 500)))
  );
}

function isOsvQueryResult(value: unknown): value is OsvQueryResult {
  if (!value || typeof value !== "object") return false;
  const result = value as OsvQueryResult;
  return (
    isLookupStatus(result.status) &&
    typeof result.hasMalwareSignature === "boolean" &&
    Array.isArray(result.vulns) &&
    result.vulns.every(isOsvVulnerability)
  );
}

function isEpssResult(value: unknown): value is EpssResult {
  if (!value || typeof value !== "object") return false;
  const result = value as EpssResult;
  return (
    isLookupStatus(result.status) &&
    typeof result.cve === "string" &&
    Number.isFinite(result.epss) &&
    result.epss >= 0 &&
    result.epss <= 1 &&
    Number.isFinite(result.percentile) &&
    result.percentile >= 0 &&
    result.percentile <= 1
  );
}

function isCisaKevResult(value: unknown): value is CisaKevResult {
  if (!value || typeof value !== "object") return false;
  const result = value as CisaKevResult;
  return isLookupStatus(result.status) && typeof result.cve === "string" && typeof result.inKev === "boolean";
}

function isScorecardResult(value: unknown): value is ScorecardResult {
  if (!value || typeof value !== "object") return false;
  const result = value as ScorecardResult;
  return (
    isLookupStatus(result.status) &&
    typeof result.repo === "string" &&
    Number.isFinite(result.score) &&
    result.score >= 0 &&
    result.score <= 10
  );
}

// ---------------------------------------------------------------------------
// Client Implementations (Node.js 22+ Native Fetch)
// ---------------------------------------------------------------------------

/**
 * Query OSV API for a package with mandatory ecosystem prefix.
 * Fail-open resilience: returns empty result on timeout or network error.
 */
export async function queryOsv(
  prefixedPackage: string,
  version?: string,
  options: ExternalIntelOptions = {},
): Promise<OsvQueryResult> {
  // parsePrefixedPackage throws on a missing or unknown prefix. Throwing out of a
  // fail-open lookup is the opposite of failing open, so degrade to an empty result
  // here and leave the throw for callers that use the parser directly.
  let parsed: ReturnType<typeof parsePrefixedPackage>;
  try {
    parsed = parsePrefixedPackage(prefixedPackage);
  } catch {
    return { vulns: [], hasMalwareSignature: false, status: "invalid" };
  }
  const { ecosystemPrefix, packageName, version: parsedVersion } = parsed;
  const effVersion = version ?? parsedVersion;
  const cacheKey = `osv:${formatPackageCacheKey(ecosystemPrefix, packageName, effVersion)}`;
  const cache = options.cache ?? globalMemoryCache;

  const cached = cache.get<unknown>(cacheKey);
  if (isOsvQueryResult(cached)) return cached;
  if (cached !== undefined) cache.delete(cacheKey);

  const timeoutMs = effectiveLookupTimeout(options);
  if (timeoutMs === 0) return { vulns: [], hasMalwareSignature: false, status: "unavailable" };
  const fetchImpl = options.fetchFn ?? fetch;
  const osvEcosystem = OSV_ECOSYSTEM_MAP[ecosystemPrefix] ?? "npm";

  try {
    const payload: Record<string, unknown> = {
      package: {
        name: packageName,
        ecosystem: osvEcosystem,
      },
    };
    if (effVersion && effVersion !== "*") {
      payload.version = effVersion;
    }

    const res = await fetchImpl("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!res.ok) {
      const fallback: OsvQueryResult = { vulns: [], hasMalwareSignature: false, status: "unavailable" };
      cache.set(cacheKey, fallback, LOOKUP_FAILURE_TTL_MS);
      return fallback;
    }
    const data = await readJsonResponseBounded(res);
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return { vulns: [], hasMalwareSignature: false, status: "invalid" };
    }
    const candidateVulns = (data as { vulns?: unknown }).vulns;
    if (candidateVulns !== undefined && !Array.isArray(candidateVulns)) {
      return { vulns: [], hasMalwareSignature: false, status: "invalid" };
    }
    const rawVulns = (candidateVulns ?? []) as unknown[];
    if (rawVulns.length > 1_000 || !rawVulns.every(isOsvVulnerability)) {
      return { vulns: [], hasMalwareSignature: false, status: "invalid" };
    }

    const vulns: OsvVulnerability[] = [];
    let hasMalwareSignature = false;
    const malwareReasons: string[] = [];

    for (const rawVuln of rawVulns) {
      const v = rawVuln as OsvVulnerability & { database_specific?: unknown };
      const id = v.id;
      const summary = typeof v.summary === "string" ? v.summary : "";
      const details = typeof v.details === "string" ? v.details : "";
      const aliases = v.aliases ?? [];

      // Detect OSV Malicious Database (MAL- ids or explicit malicious flag)
      const isMalId = id.startsWith("MAL-") || aliases.some((a) => typeof a === "string" && a.startsWith("MAL-"));
      const isDbMalicious =
        v.database_specific &&
        typeof v.database_specific === "object" &&
        ((v.database_specific as Record<string, unknown>).malicious === true ||
          (v.database_specific as Record<string, unknown>).malware === true);
      // Only a MAL- id or an explicit database_specific flag is an OSV Malicious
      // Database hit. A keyword scan of summary/details matched ordinary CVE
      // write-ups instead: an advisory describing how an attacker installs a
      // backdoor through a bug is a vulnerability report about the package, not a
      // declaration that the package IS malware.
      const isMalicious = isMalId || Boolean(isDbMalicious);
      if (isMalicious) {
        hasMalwareSignature = true;
        malwareReasons.push(`OSV Malicious Database match: ${id} (${summary || "Confirmed malicious package"})`);
      }

      vulns.push({
        id,
        summary,
        details,
        aliases,
        modified: typeof v.modified === "string" ? v.modified : undefined,
        published: typeof v.published === "string" ? v.published : undefined,
        isMalicious,
        databaseSpecific:
          v.database_specific && typeof v.database_specific === "object"
            ? (v.database_specific as Record<string, unknown>)
            : undefined,
        severity: Array.isArray(v.severity)
          ? (v.severity as Array<{ type: string; score: string }>)
          : undefined,
      });
    }

    const result: OsvQueryResult = {
      vulns,
      hasMalwareSignature,
      malwareReasons: malwareReasons.length > 0 ? malwareReasons : undefined,
      status: vulns.length > 0 ? "ok" : "not-found",
    };

    cache.set(cacheKey, result);
    return result;
  } catch (error) {
    if (error instanceof InvalidExternalResponse) {
      return { vulns: [], hasMalwareSignature: false, status: "invalid" };
    }
    // Fail-open resilience: timeouts/offline fall back to a clean verdict for THIS
    // scan, cached only briefly so the next one retries instead of serving the blip.
    const fallback: OsvQueryResult = { vulns: [], hasMalwareSignature: false, status: "unavailable" };
    cache.set(cacheKey, fallback, LOOKUP_FAILURE_TTL_MS);
    return fallback;
  }
}

/**
 * Query FIRST EPSS API for a CVE identifier.
 * Fail-open resilience: returns 0.0 probability on timeout or network error.
 */
export async function queryEpss(
  cve: string,
  options: ExternalIntelOptions = {},
): Promise<EpssResult> {
  const cleanCve = cve.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cleanCve)) {
    return { cve: cleanCve, epss: EPSS_FALLBACK_SCORE, percentile: 0, status: "invalid" };
  }
  const cacheKey = `epss:${cleanCve}`;
  const cache = options.cache ?? globalMemoryCache;

  const cached = cache.get<unknown>(cacheKey);
  if (isEpssResult(cached) && cached.cve === cleanCve) return cached;
  if (cached !== undefined) cache.delete(cacheKey);

  const timeoutMs = effectiveLookupTimeout(options);
  if (timeoutMs === 0) {
    return { cve: cleanCve, epss: EPSS_FALLBACK_SCORE, percentile: 0, status: "unavailable" };
  }
  const fetchImpl = options.fetchFn ?? fetch;

  try {
    const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cleanCve)}`;
    const res = await fetchImpl(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!res.ok) {
      const fallback: EpssResult = { cve: cleanCve, epss: EPSS_FALLBACK_SCORE, percentile: 0.0, status: "unavailable" };
      cache.set(cacheKey, fallback, LOOKUP_FAILURE_TTL_MS);
      return fallback;
    }
    const json = await readJsonResponseBounded(res) as { data?: unknown };

    if (json.data !== undefined && !Array.isArray(json.data)) {
      return { cve: cleanCve, epss: 0, percentile: 0, status: "invalid" };
    }
    if (Array.isArray(json.data) && json.data.length > 10) {
      return { cve: cleanCve, epss: 0, percentile: 0, status: "invalid" };
    }
    const entry = Array.isArray(json.data) && json.data.length > 0
      ? json.data[0] as { cve?: unknown; epss?: unknown; percentile?: unknown }
      : undefined;
    if (!entry) {
      const result: EpssResult = { cve: cleanCve, epss: 0, percentile: 0, status: "not-found" };
      cache.set(cacheKey, result);
      return result;
    }
    if (
      typeof entry.cve !== "string" || entry.cve.trim().toUpperCase() !== cleanCve ||
      typeof entry.epss !== "string" ||
      (entry.percentile !== undefined && typeof entry.percentile !== "string")
    ) {
      return { cve: cleanCve, epss: 0, percentile: 0, status: "invalid" };
    }
    const epssVal = Number(entry.epss);
    const percentileVal = entry.percentile === undefined ? 0 : Number(entry.percentile);

    if (!Number.isFinite(epssVal) || epssVal < 0 || epssVal > 1 || !Number.isFinite(percentileVal) || percentileVal < 0 || percentileVal > 1) {
      return { cve: cleanCve, epss: 0, percentile: 0, status: "invalid" };
    }
    const result: EpssResult = {
      cve: cleanCve,
      epss: Math.max(0.0, Math.min(1.0, epssVal)),
      percentile: Math.max(0.0, Math.min(1.0, percentileVal)),
      status: "ok",
    };

    cache.set(cacheKey, result);
    return result;
  } catch (error) {
    if (error instanceof InvalidExternalResponse) {
      return { cve: cleanCve, epss: 0, percentile: 0, status: "invalid" };
    }
    const fallback: EpssResult = { cve: cleanCve, epss: EPSS_FALLBACK_SCORE, percentile: 0.0, status: "unavailable" };
    cache.set(cacheKey, fallback, LOOKUP_FAILURE_TTL_MS);
    return fallback;
  }
}

/**
 * Query CISA Known Exploited Vulnerabilities catalog.
 * Fail-open resilience: returns false on timeout or network error.
 */
export async function queryCisaKev(
  cve: string,
  options: ExternalIntelOptions = {},
): Promise<CisaKevResult> {
  const cleanCve = cve.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cleanCve)) {
    return { cve: cleanCve, inKev: false, status: "invalid" };
  }
  const cacheKey = `cisa-kev:${cleanCve}`;
  const cache = options.cache ?? globalMemoryCache;

  const cached = cache.get<unknown>(cacheKey);
  if (isCisaKevResult(cached) && cached.cve === cleanCve) return cached;
  if (cached !== undefined) cache.delete(cacheKey);

  const catalogKey = "cisa-kev-catalog:set";
  type CatalogEntry = { dateAdded?: string; dueDate?: string; notes?: string };
  type CatalogCache = {
    status: "ok" | "unavailable" | "invalid";
    entries: Record<string, CatalogEntry>;
  };
  const isCatalogCache = (value: unknown): value is CatalogCache =>
    Boolean(
      value &&
        typeof value === "object" &&
        ["ok", "unavailable", "invalid"].includes(String((value as CatalogCache).status)) &&
        (value as CatalogCache).entries &&
        typeof (value as CatalogCache).entries === "object",
    );

  let catalog = cache.get<unknown>(catalogKey);
  if (!isCatalogCache(catalog)) {
    if (catalog !== undefined) cache.delete(catalogKey);
    const timeoutMs = effectiveLookupTimeout(options);
    const fetchImpl = options.fetchFn ?? fetch;

    if (timeoutMs === 0) {
      return { cve: cleanCve, inKev: false, status: "unavailable" };
    }

    try {
      const res = await fetchImpl(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        {
          headers: {
            Accept: "application/json",
            "User-Agent": USER_AGENT,
          },
          signal: AbortSignal.timeout(timeoutMs),
        },
      );

      if (!res.ok) {
        catalog = { status: "unavailable", entries: {} } satisfies CatalogCache;
        cache.set(catalogKey, catalog, LOOKUP_FAILURE_TTL_MS);
      } else {
        const json = await readJsonResponseBounded(res);
        const catalogDocument =
          json && typeof json === "object" && !Array.isArray(json)
            ? json as {
                title?: unknown;
                catalogVersion?: unknown;
                dateReleased?: unknown;
                count?: unknown;
                vulnerabilities?: unknown;
              }
            : undefined;
        const items = catalogDocument?.vulnerabilities;
        if (
          typeof catalogDocument?.title !== "string" ||
          !catalogDocument.title.toLowerCase().includes("known exploited vulnerabilities") ||
          typeof catalogDocument.catalogVersion !== "string" ||
          typeof catalogDocument.dateReleased !== "string" ||
          !Number.isInteger(catalogDocument.count) ||
          (catalogDocument.count as number) <= 0 ||
          !Array.isArray(items) ||
          items.length !== catalogDocument.count ||
          items.length > 10_000
        ) {
          catalog = { status: "invalid", entries: {} } satisfies CatalogCache;
        } else {
          const map: Record<string, CatalogEntry> = Object.create(null) as Record<string, CatalogEntry>;
          let invalid = false;
          for (const raw of items) {
            if (!raw || typeof raw !== "object") {
              invalid = true;
              break;
            }
            const item = raw as { cveID?: unknown; dateAdded?: unknown; dueDate?: unknown; notes?: unknown };
            if (typeof item.cveID !== "string" || !/^CVE-\d{4}-\d{4,}$/i.test(item.cveID)) {
              invalid = true;
              break;
            }
            map[item.cveID.toUpperCase()] = {
              dateAdded: typeof item.dateAdded === "string" ? item.dateAdded : undefined,
              dueDate: typeof item.dueDate === "string" ? item.dueDate : undefined,
              notes: typeof item.notes === "string" ? item.notes : undefined,
            };
          }
          catalog = {
            status: invalid ? "invalid" : "ok",
            entries: invalid ? {} : map,
          } satisfies CatalogCache;
          if (!invalid) cache.set(catalogKey, catalog, DEFAULT_TTL_MS);
        }
      }
    } catch (error) {
      if (error instanceof InvalidExternalResponse) {
        catalog = { status: "invalid", entries: {} } satisfies CatalogCache;
        return { cve: cleanCve, inKev: false, status: "invalid" };
      }
      catalog = { status: "unavailable", entries: {} } satisfies CatalogCache;
      cache.set(catalogKey, catalog, LOOKUP_FAILURE_TTL_MS);
    }
  }

  if (!isCatalogCache(catalog) || catalog.status !== "ok") {
    const status = isCatalogCache(catalog) ? catalog.status : "unavailable";
    const result: CisaKevResult = { cve: cleanCve, inKev: false, status };
    if (status === "unavailable") cache.set(cacheKey, result, LOOKUP_FAILURE_TTL_MS);
    return result;
  }

  const match = catalog.entries[cleanCve];
  const result: CisaKevResult = {
    cve: cleanCve,
    inKev: Boolean(match),
    dateAdded: match?.dateAdded,
    dueDate: match?.dueDate,
    notes: match?.notes,
    status: match ? "ok" : "not-found",
  };
  cache.set(cacheKey, result, DEFAULT_TTL_MS);
  return result;
}

/**
 * Query OpenSSF Scorecards API for repository hygiene metrics.
 * Range 0.0 to 10.0; falls back to 3.0 on timeout or missing data.
 */
function parseGithubSlug(repoPathOrUrl: string): string | undefined {
  const trimmed = repoPathOrUrl.trim();
  let candidate = trimmed;
  if (trimmed.includes("://")) {
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      return undefined;
    }
    if (
      url.protocol !== "https:" ||
      url.hostname.toLowerCase() !== "github.com" ||
      url.port ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    ) {
      return undefined;
    }
    candidate = url.pathname.replace(/^\/+|\/+$/g, "");
  }
  candidate = candidate.replace(/\.git$/i, "");
  const parts = candidate.split("/");
  if (
    parts.length !== 2 ||
    parts.some(
      (part) =>
        part === "." ||
        part === ".." ||
        part.length === 0 ||
        part.length > 100 ||
        !/^[A-Za-z0-9_.-]+$/.test(part),
    )
  ) {
    return undefined;
  }
  return `${parts[0]}/${parts[1]}`;
}

export async function queryScorecard(
  repoPathOrUrl: string,
  options: ExternalIntelOptions = {},
): Promise<ScorecardResult> {
  const slug = parseGithubSlug(repoPathOrUrl);
  if (!slug) {
    // Never echo invalid input: it may contain embedded credentials.
    return { repo: "invalid", score: SCORECARD_FALLBACK_SCORE, status: "invalid" };
  }

  const cacheKey = `scorecard:github.com/${slug.toLowerCase()}`;
  const cache = options.cache ?? globalMemoryCache;

  const cached = cache.get<unknown>(cacheKey);
  if (isScorecardResult(cached) && cached.repo.toLowerCase() === slug.toLowerCase()) return cached;
  if (cached !== undefined) cache.delete(cacheKey);

  const timeoutMs = effectiveLookupTimeout(options);
  if (timeoutMs === 0) {
    return { repo: slug, score: SCORECARD_FALLBACK_SCORE, status: "unavailable" };
  }
  const fetchImpl = options.fetchFn ?? fetch;

  try {
    // Encode each path segment on its own. encodeURIComponent(slug) percent-encoded
    // the "/" between owner and repo, so every lookup 404'd into the 3.0 fallback.
    const encodedSlug = slug.split("/").map(encodeURIComponent).join("/");
    const url = `https://api.securityscorecards.dev/projects/github.com/${encodedSlug}`;
    const res = await fetchImpl(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (res.status === 404) {
      const notFound: ScorecardResult = {
        repo: slug,
        score: SCORECARD_FALLBACK_SCORE,
        status: "not-found",
      };
      cache.set(cacheKey, notFound, DEFAULT_TTL_MS);
      return notFound;
    }
    if (!res.ok) {
      const fallback: ScorecardResult = { repo: slug, score: SCORECARD_FALLBACK_SCORE, status: "unavailable" };
      cache.set(cacheKey, fallback, LOOKUP_FAILURE_TTL_MS);
      return fallback;
    }
    const json = await readJsonResponseBounded(res) as {
      score?: number;
      date?: string;
      checks?: Array<{ name?: string; score?: number }>;
    };

    if (typeof json.score !== "number" || !Number.isFinite(json.score) || json.score < 0 || json.score > 10) {
      const invalid: ScorecardResult = { repo: slug, score: SCORECARD_FALLBACK_SCORE, status: "invalid" };
      return invalid;
    }
    const scoreNum = json.score;
    const checks: Record<string, number> = {};
    if (Array.isArray(json.checks)) {
      for (const check of json.checks) {
        if (typeof check.name === "string" && typeof check.score === "number") {
          checks[check.name] = check.score;
        }
      }
    }

    const result: ScorecardResult = {
      repo: slug,
      score: Math.max(0.0, Math.min(10.0, Math.round(scoreNum * 10) / 10)),
      date: json.date,
      checks: Object.keys(checks).length > 0 ? checks : undefined,
      status: "ok",
    };

    cache.set(cacheKey, result);
    return result;
  } catch (error) {
    if (error instanceof InvalidExternalResponse) {
      return { repo: slug, score: SCORECARD_FALLBACK_SCORE, status: "invalid" };
    }
    const fallback: ScorecardResult = { repo: slug, score: SCORECARD_FALLBACK_SCORE, status: "unavailable" };
    cache.set(cacheKey, fallback, LOOKUP_FAILURE_TTL_MS);
    return fallback;
  }
}

/**
 * Extract CVSS score from an OSV vulnerability record.
 *
 * Returns undefined when the record states no severity. A missing score must stay
 * missing: this value feeds S_vuln = CVSS * 10 * sqrt(EPSS), so substituting a
 * "moderate" 5.0 manufactured up to 50 points of exploitability for a CVE that has
 * no published vector at all, and 50 outright for one in KEV (where EPSS is 1.0).
 */
interface ExtractedCvssRating {
  score?: number;
  vector?: string;
  method?: SbomRating["method"];
}

function roundUpCvss(value: number): number {
  return Math.ceil((value - Number.EPSILON) * 10) / 10;
}

/** Calculate a CVSS 3.0/3.1 base score from a complete base vector. */
function scoreCvssV3(vector: string): number | undefined {
  const prefix = /^CVSS:3\.[01]\//.exec(vector);
  if (!prefix) return undefined;
  const isV31 = vector.startsWith("CVSS:3.1/");
  const metrics = new Map<string, string>();
  for (const part of vector.slice(prefix[0].length).split("/")) {
    const [key, value, extra] = part.split(":");
    if (!key || !value || extra !== undefined || metrics.has(key)) return undefined;
    metrics.set(key, value);
  }
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.get("AV") ?? ""];
  const ac = { L: 0.77, H: 0.44 }[metrics.get("AC") ?? ""];
  const scope = metrics.get("S");
  const prTable =
    scope === "C" ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };
  const pr = prTable[metrics.get("PR") as keyof typeof prTable];
  const ui = { N: 0.85, R: 0.62 }[metrics.get("UI") ?? ""];
  const impactWeight = { H: 0.56, L: 0.22, N: 0 };
  const c = impactWeight[metrics.get("C") as keyof typeof impactWeight];
  const i = impactWeight[metrics.get("I") as keyof typeof impactWeight];
  const a = impactWeight[metrics.get("A") as keyof typeof impactWeight];
  if (
    av === undefined ||
    ac === undefined ||
    pr === undefined ||
    ui === undefined ||
    c === undefined ||
    i === undefined ||
    a === undefined ||
    (scope !== "U" && scope !== "C")
  ) {
    return undefined;
  }
  const impactSubScore = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact =
    scope === "U"
      ? 6.42 * impactSubScore
      : isV31
        ? 7.52 * (impactSubScore - 0.029) -
          3.25 * (impactSubScore * 0.9731 - 0.02) ** 13
        : 7.52 * (impactSubScore - 0.029) -
          3.25 * (impactSubScore - 0.02) ** 15;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const base =
    scope === "U"
      ? Math.min(impact + exploitability, 10)
      : Math.min(1.08 * (impact + exploitability), 10);
  return roundUpCvss(base);
}

function methodForOsvSeverity(type: string, vector?: string): SbomRating["method"] | undefined {
  const normalized = type.toUpperCase();
  if (normalized === "CVSS_V2") return "CVSSv2";
  if (normalized === "CVSS_V4") return "CVSSv4";
  if (normalized === "CVSS_V3") return vector?.startsWith("CVSS:3.1/") ? "CVSSv31" : "CVSSv3";
  return undefined;
}

export function extractCvssRatingFromOsv(vuln: OsvVulnerability): ExtractedCvssRating {
  let best: ExtractedCvssRating | undefined;
  let unsupportedVector: ExtractedCvssRating | undefined;
  const consider = (rating: ExtractedCvssRating): void => {
    if (rating.score === undefined) return;
    if (best?.score === undefined || rating.score > best.score) best = rating;
  };
  for (const severity of vuln.severity ?? []) {
    const raw = severity.score.trim();
    const method = methodForOsvSeverity(severity.type, raw);
    if (!method) continue;
    if (/^(?:10(?:\.0+)?|[0-9](?:\.\d+)?)$/.test(raw)) {
      const numeric = Number(raw);
      if (numeric >= 0 && numeric <= 10) consider({ score: numeric, method });
    }
    if (raw.startsWith("CVSS:")) {
      const rating = {
        score: method === "CVSSv3" || method === "CVSSv31" ? scoreCvssV3(raw) : undefined,
        vector: raw,
        method,
      };
      if (rating.score !== undefined) consider(rating);
      else unsupportedVector ??= rating;
    }
  }
  const dbCvss = vuln.databaseSpecific?.cvss;
  if (typeof dbCvss === "number" && Number.isFinite(dbCvss) && dbCvss >= 0 && dbCvss <= 10) {
    consider({ score: dbCvss });
  }
  // Qualitative labels are not CVSS scores. Inventing 9.5 for "critical" makes
  // an unscored advisory look more precise and more exploitable than its source.
  return best ?? unsupportedVector ?? {};
}

export function extractCvssFromOsv(vuln: OsvVulnerability): number | undefined {
  return extractCvssRatingFromOsv(vuln).score;
}

/**
 * Resolve the GitHub `owner/repo` slug a project declares, for a Scorecard lookup.
 * Returns undefined when nothing in package.json names a GitHub repository.
 */
function resolveGithubSlug(pkg: Record<string, unknown>): string | undefined {
  const repo = pkg.repository;
  const raw =
    typeof repo === "string"
      ? repo
      : repo && typeof repo === "object" && typeof (repo as { url?: unknown }).url === "string"
        ? ((repo as { url: string }).url)
        : undefined;
  if (!raw) return undefined;
  const normalized = raw.replace(/^git\+/i, "");
  if (/^github:/i.test(normalized)) {
    return parseGithubSlug(normalized.replace(/^github:/i, ""));
  }
  if (/^git@github\.com:/i.test(normalized)) {
    return parseGithubSlug(normalized.replace(/^git@github\.com:/i, ""));
  }
  if (/^ssh:\/\/git@github\.com\//i.test(normalized)) {
    return parseGithubSlug(normalized.replace(/^ssh:\/\/git@github\.com\//i, ""));
  }
  if (/^git:\/\/github\.com\//i.test(normalized)) {
    return parseGithubSlug(normalized.replace(/^git:/i, "https:"));
  }
  return parseGithubSlug(normalized);
}

export interface ExternalIntelResult extends ExternalIntelReport {
  scorecard?: number;
  vulnerabilities: VulnerabilityScoreInput[];
  confirmedMalware: ConfirmedMalwareInput[];
}

interface PackageCoordinate {
  ecosystemPrefix: string;
  packageName: string;
  packageVersion: string;
  affectsRefs: string[];
}

function isConcreteVersion(value: string): boolean {
  return /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value.trim());
}

function collectNpmCoordinates(projectDir: string, pkg: Record<string, unknown>): {
  coordinates: PackageCoordinate[];
  skipped: number;
  partial: boolean;
  note?: string;
} {
  const coordinates: PackageCoordinate[] = [];
  const byPackage = new Map<string, PackageCoordinate>();
  let inventoriedRefs = 0;
  let skipped = 0;
  const add = (packageName: unknown, packageVersion: unknown, affectsRef: string): boolean => {
    if (typeof packageName !== "string" || packageName.trim() === "") return false;
    if (typeof packageVersion !== "string" || !isConcreteVersion(packageVersion)) {
      skipped++;
      return false;
    }
    const coordinate: PackageCoordinate = {
      ecosystemPrefix: "npm:",
      packageName: packageName.trim(),
      packageVersion: packageVersion.trim().replace(/^v/, ""),
      affectsRefs: [affectsRef],
    };
    const key = formatPackageCacheKey("npm:", coordinate.packageName, coordinate.packageVersion);
    const existing = byPackage.get(key);
    if (existing) {
      if (existing.affectsRefs.includes(affectsRef)) return true;
      if (inventoriedRefs >= MAX_INVENTORY_COORDINATES) {
        skipped++;
        return false;
      }
      existing.affectsRefs.push(affectsRef);
      inventoriedRefs++;
      return true;
    }
    if (inventoriedRefs >= MAX_INVENTORY_COORDINATES) {
      skipped++;
      return false;
    }
    byPackage.set(key, coordinate);
    coordinates.push(coordinate);
    inventoriedRefs++;
    return true;
  };

  add(pkg.name, pkg.version, "target");

  const lockfilePath = path.join(projectDir, "package-lock.json");
  let partial = false;
  let note: string | undefined;
  try {
    const lock = readJsonFileBounded(lockfilePath, projectDir) as {
      packages?: Record<string, { name?: unknown; version?: unknown; link?: unknown; resolved?: unknown }>;
      dependencies?: Record<string, unknown>;
    };
    if (lock.packages && typeof lock.packages === "object") {
      for (const [pkgPath, entry] of Object.entries(lock.packages)) {
        if (inventoriedRefs >= MAX_INVENTORY_COORDINATES) {
          skipped += Math.max(0, Object.keys(lock.packages).length - inventoriedRefs);
          break;
        }
        if (pkgPath === "" || !entry || typeof entry !== "object") continue;
        if (entry.link === true) {
          if (typeof entry.resolved === "string" && Object.hasOwn(lock.packages, entry.resolved)) {
            continue;
          }
          skipped++;
          continue;
        }
        const { name } = lockfileEntryName(pkgPath.replace(/\\/g, "/"), entry.name);
        add(name, entry.version, pkgPath.replace(/\\/g, "/"));
      }
      return { coordinates, skipped, partial: false };
    }

    // The SBOM generator deliberately treats package-lock v1 as direct-only and
    // emits package.json dependency keys as bom-refs. Querying the legacy nested
    // tree here would create VEX affects references that do not exist in that
    // document, so use the same exact package.json fallback below. This is only
    // direct coverage, and must remain visibly partial.
    partial = true;
    note = "package-lock.json has no supported v2+ package inventory; using direct dependencies only";
  } catch {
    // A missing lockfile is an ordinary direct-only project. An existing lockfile
    // that cannot be read is a coverage failure, not evidence that no transitives
    // exist.
    if (fs.existsSync(lockfilePath)) {
      partial = true;
      note = "package-lock.json could not be safely read; using direct dependencies only";
    }
  }

  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const) {
    const deps = pkg[field];
    if (!deps || typeof deps !== "object" || Array.isArray(deps)) continue;
    for (const [declaredName, rawVersion] of Object.entries(deps)) {
      if (typeof rawVersion === "string" && rawVersion.startsWith("npm:")) {
        const alias = rawVersion.slice(4);
        const separator = alias.lastIndexOf("@");
        if (separator > 0) {
          add(alias.slice(0, separator), alias.slice(separator + 1), declaredName);
          continue;
        }
      }
      add(declaredName, rawVersion, declaredName);
    }
  }
  return { coordinates, skipped, partial, note };
}

async function mapWithConcurrency<T, R>(
  values: T[],
  concurrency: number,
  fn: (value: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (next < values.length) {
      const index = next++;
      results[index] = await fn(values[index]!);
    }
  });
  await Promise.all(workers);
  return results;
}

function mergeLookupStatus(current: ExternalLookupStatus, incoming: ExternalLookupStatus): ExternalLookupStatus {
  const rank: Record<ExternalLookupStatus, number> = {
    "not-found": 0,
    ok: 1,
    unavailable: 2,
    invalid: 3,
  };
  return rank[incoming] > rank[current] ? incoming : current;
}

/**
 * Opt-in external intelligence gathering for a scanned project directory.
 *
 * The scanner calls this only when ScanOptions.externalIntel is explicitly true.
 * The default scan path remains offline; keeping collection inside the scanner
 * ensures local and cloned targets use the same resolved directory and report.
 *
 * Every lookup fails open: an unreachable feed leaves its field unset rather than
 * contributing a fabricated value.
 */
export async function gatherExternalIntel(
  projectDir: string,
  options: GatherExternalIntelOptions = {},
): Promise<ExternalIntelResult> {
  const result: ExternalIntelResult = {
    vulnerabilities: [],
    confirmedMalware: [],
    notes: [],
    statuses: {
      osv: "not-found",
      scorecard: "not-found",
      epss: "not-found",
      cisaKev: "not-found",
    },
    packagesQueried: 0,
    packagesSkipped: 0,
    partial: false,
  };

  const ownsCache = options.cache === undefined;
  const cache = options.cache ?? new ThreatIntelCache(defaultThreatIntelCacheDir());
  const overallTimeoutMs = Math.max(
    1_000,
    Math.min(120_000, options.overallTimeoutMs ?? DEFAULT_OVERALL_TIMEOUT_MS),
  );
  const effectiveOptions: ExternalIntelOptions = {
    ...options,
    cache,
    deadlineAt: options.deadlineAt ?? Date.now() + overallTimeoutMs,
  };

  let pkg: Record<string, unknown>;
  try {
    const parsed = readJsonFileBounded(path.join(projectDir, "package.json"), projectDir);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new TypeError("package.json is not an object");
    }
    pkg = parsed as Record<string, unknown>;
  } catch {
    result.notes.push("no readable package.json: external intel skipped");
    result.partial = true;
    return result;
  }

  const slug = resolveGithubSlug(pkg);
  if (options.scorecardOverride !== undefined) {
    result.scorecard = options.scorecardOverride;
    result.statuses.scorecard = "ok";
    result.notes.push(`OpenSSF Scorecard ${options.scorecardOverride} supplied by caller; lookup skipped`);
  } else if (slug) {
    const scorecard = await queryScorecard(slug, effectiveOptions);
    result.statuses.scorecard = scorecard.status;
    if (scorecard.status === "ok") {
      result.scorecard = scorecard.score;
      result.notes.push(`OpenSSF Scorecard ${scorecard.score} for ${slug}`);
    } else {
      result.notes.push(`OpenSSF Scorecard ${scorecard.status} for ${slug}`);
    }
  } else {
    result.notes.push("no GitHub repository declared: Scorecard skipped");
  }

  const inventory = collectNpmCoordinates(projectDir, pkg);
  if (inventory.partial) {
    result.partial = true;
    if (inventory.note) result.notes.push(inventory.note);
  }
  const maxPackages = Math.max(1, Math.min(1_000, options.maxPackages ?? 250));
  const coordinates = inventory.coordinates.slice(0, maxPackages);
  result.packagesQueried = coordinates.length;
  result.packagesSkipped = inventory.skipped + Math.max(0, inventory.coordinates.length - coordinates.length);
  if (coordinates.length === 0) {
    result.notes.push("no resolved npm package coordinates: OSV skipped");
  } else {
    const inputs: VulnerabilityScoreInput[] = [];
    let advisoryCount = 0;
    let truncatedAdvisories = false;
    let advisoryLimitReached = false;
    let packagesStarted = 0;
    let packagesSkippedAtLimit = 0;
    await mapWithConcurrency(coordinates, 8, async (coordinate) => {
      // Once the global result budget is exhausted, stop scheduling more remote
      // bodies. At most the eight already in-flight lookups remain resident.
      if (advisoryLimitReached) {
        packagesSkippedAtLimit++;
        return;
      }
      packagesStarted++;
      const osv = await queryOsv(
        `${coordinate.ecosystemPrefix}${coordinate.packageName}`,
        coordinate.packageVersion,
        effectiveOptions,
      );
      result.statuses.osv = mergeLookupStatus(result.statuses.osv, osv.status);
      advisoryCount += osv.vulns.length;

      // Another in-flight lookup may have filled the shared budget while this
      // request was pending. Do not retain its full parsed result in an aggregate.
      if (advisoryLimitReached) {
        truncatedAdvisories ||= osv.vulns.length > 0;
        return;
      }
      for (const vulnerability of osv.vulns) {
        const cve =
          vulnerability.aliases?.find((alias) => /^CVE-\d{4}-\d{4,}$/i.test(alias)) ??
          (/^CVE-\d{4}-\d{4,}$/i.test(vulnerability.id) ? vulnerability.id : undefined);
        const rating = extractCvssRatingFromOsv(vulnerability);
        const source = {
          name: "OSV",
          url: `https://osv.dev/vulnerability/${encodeURIComponent(vulnerability.id)}`,
        };
        const baseInput: VulnerabilityScoreInput = {
          id: vulnerability.id,
          cve,
          cvss: rating.score,
          cvssVector: rating.vector,
          cvssMethod: rating.method,
          source,
          affectsRef: coordinate.affectsRefs[0],
          packageName: coordinate.packageName,
          packageVersion: coordinate.packageVersion,
          ecosystem: coordinate.ecosystemPrefix,
        };
        for (const affectsRef of coordinate.affectsRefs) {
          if (inputs.length >= MAX_VULNERABILITY_INPUTS) {
            truncatedAdvisories = true;
            advisoryLimitReached = true;
            break;
          }
          inputs.push({ ...baseInput, affectsRef });
        }
        if (inputs.length >= MAX_VULNERABILITY_INPUTS) {
          truncatedAdvisories = true;
          advisoryLimitReached = true;
        }
        if (vulnerability.isMalicious) {
          for (const affectsRef of coordinate.affectsRefs) {
            if (result.confirmedMalware.length >= MAX_VULNERABILITY_INPUTS) {
              truncatedAdvisories = true;
              advisoryLimitReached = true;
              break;
            }
            result.confirmedMalware.push({
              id: vulnerability.id,
              packageName: coordinate.packageName,
              packageVersion: coordinate.packageVersion,
              ecosystem: coordinate.ecosystemPrefix,
              source,
              description: vulnerability.summary || "OSV Malicious Database match",
              affectsRef,
            });
          }
        }
        if (advisoryLimitReached) break;
      }
    });
    result.packagesQueried = packagesStarted;
    result.packagesSkipped += packagesSkippedAtLimit;
    const enriched = await enrichVulnerabilityInputsWithStatus(inputs, effectiveOptions);
    result.vulnerabilities = enriched.inputs;
    result.statuses.epss = enriched.epss;
    result.statuses.cisaKev = enriched.cisaKev;
    if (truncatedAdvisories) {
      result.partial = true;
      result.notes.push(`external advisory matches truncated at ${MAX_VULNERABILITY_INPUTS}`);
    }
    if (result.statuses.osv === "unavailable" || result.statuses.osv === "invalid") {
      result.notes.push(`OSV ${result.statuses.osv}: coverage incomplete`);
    } else {
      result.notes.push(
        `OSV: ${advisoryCount} advisor${advisoryCount === 1 ? "y" : "ies"} across ${coordinates.length} resolved npm package${coordinates.length === 1 ? "" : "s"}`,
      );
    }
    if (result.confirmedMalware.length > 0) {
      result.notes.push(`OSV Malicious Database: ${result.confirmedMalware.length} confirmed match${result.confirmedMalware.length === 1 ? "" : "es"}`);
    }
  }

  result.partial =
    result.partial ||
    result.packagesSkipped > 0 ||
    Object.values(result.statuses).some((status) => status === "unavailable" || status === "invalid");
  if (ownsCache) cache.flush();
  return result;
}

/**
 * High-level orchestration: enrich vulnerability records with EPSS, CISA KEV, and CVSS.
 */
export async function enrichVulnerabilityInputs(
  vulnerabilities: Array<VulnerabilityScoreInput & { severity?: Severity }>,
  options: ExternalIntelOptions = {},
): Promise<VulnerabilityScoreInput[]> {
  return (await enrichVulnerabilityInputsWithStatus(vulnerabilities, options)).inputs;
}

async function enrichVulnerabilityInputsWithStatus(
  vulnerabilities: VulnerabilityScoreInput[],
  options: ExternalIntelOptions,
): Promise<{ inputs: VulnerabilityScoreInput[]; epss: ExternalLookupStatus; cisaKev: ExternalLookupStatus }> {
  let epssStatus: ExternalLookupStatus = "not-found";
  let kevStatus: ExternalLookupStatus = "not-found";
  const cves = [...new Set(vulnerabilities.flatMap((item) => {
    const cve = item.cve ?? (item.id?.startsWith("CVE-") ? item.id : undefined);
    return cve ? [cve.toUpperCase()] : [];
  }))];

  const epssPairs = await mapWithConcurrency(cves, 8, async (cve) =>
    [cve, await queryEpss(cve, options)] as const,
  );
  // Prime the shared KEV catalog once before concurrent per-CVE reads. Without
  // this seed, a cold cache launched eight identical full-catalog downloads.
  const kevPairs: Array<readonly [string, CisaKevResult]> = [];
  if (cves[0]) {
    kevPairs.push([cves[0], await queryCisaKev(cves[0], options)] as const);
    kevPairs.push(...await mapWithConcurrency(cves.slice(1), 8, async (cve) =>
      [cve, await queryCisaKev(cve, options)] as const,
    ));
  }

  const epssByCve = new Map(epssPairs);
  const kevByCve = new Map(kevPairs);
  for (const result of epssByCve.values()) epssStatus = mergeLookupStatus(epssStatus, result.status);
  for (const result of kevByCve.values()) kevStatus = mergeLookupStatus(kevStatus, result.status);

  const results = vulnerabilities.map((item) => {
    const cve = (item.cve ?? (item.id?.startsWith("CVE-") ? item.id : undefined))?.toUpperCase();
    const epssRes = cve ? epssByCve.get(cve) : undefined;
    const kevRes = cve ? kevByCve.get(cve) : undefined;
    return {
      ...item,
      cve,
      epss: epssRes?.status === "ok" ? epssRes.epss : undefined,
      inCisaKev:
        kevRes?.status === "ok" || kevRes?.status === "not-found"
          ? kevRes.inKev
          : undefined,
    } satisfies VulnerabilityScoreInput;
  });
  return { inputs: results, epss: epssStatus, cisaKev: kevStatus };
}
