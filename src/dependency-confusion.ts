/**
 * Dependency Confusion Detector
 *
 * Analyzes a project's package.json to detect potential dependency confusion attacks.
 * Checks if dependencies exist on the public npm registry and flags suspicious ones:
 * - Unscoped packages that look like internal names
 * - Packages with no README, very recent publish, or low download counts
 * - Packages where the public version was published AFTER the project started using it
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as https from "node:https";
import type { Finding, ScanReport, ScanSummary, Severity } from "./types.js";
import { SEVERITY_SCORES } from "./types.js";
import { readOptionalUtf8File } from "./pattern-scanner.js";

const TOOL_VERSION = "5.28.1";
const NPM_REGISTRY = "https://registry.npmjs.org";
const NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week";
const PYPI_REGISTRY = "https://pypi.org/pypi";

// Heuristic thresholds
const LOW_DOWNLOAD_THRESHOLD = 100;        // weekly downloads
const RECENT_PUBLISH_DAYS = 90;            // published within last N days
const VERY_RECENT_PUBLISH_DAYS = 30;       // very recently published
/** Version published within this many days is flagged as suspiciously fresh */
const VERSION_COOLDOWN_DAYS = 7;
/** Version published within 24h is flagged as critically fresh */
const VERSION_HOT_HOURS = 24;

/**
 * Known AI-hallucinated npm package names (LLMs frequently suggest these non-existent packages).
 * If any of these appear on the public registry, it may indicate a squatting/confusion attack
 * exploiting AI-generated dependency recommendations.
 */
const AI_HALLUCINATED_NPM_PACKAGES = new Set([
  "express-validator-middleware",
  "react-use-fetch",
  "node-auth-helper",
  "jest-mock-utils",
  "typescript-utils",
  "react-form-validator",
  "node-logger-pro",
  "express-jwt-helper",
  "mongoose-utils",
  "webpack-config-helper",
  "babel-preset-node",
  "eslint-config-node",
  "react-hooks-helper",
  "node-crypto-utils",
  "express-error-handler",
  "jwt-node",
  "node-mailer-helper",
  "sequelize-helper",
  "redis-node-client",
  "socket-io-helper",
]);

/**
 * Known AI-hallucinated PyPI package names.
 */
const AI_HALLUCINATED_PYPI_PACKAGES = new Set([
  "python-utils-helper",
  "django-api-utils",
  "flask-auth-helper",
  "fastapi-utils",
  "sqlalchemy-helper",
  "pytest-mock-utils",
  "pydantic-utils",
  "python-jwt-helper",
  "celery-utils",
  "redis-python-client",
]);

// Patterns that suggest internal/private package names
const INTERNAL_NAME_PATTERNS: RegExp[] = [
  /^(?:internal|private|local|company|corp|org)-/i,
  /-(?:internal|private|local)$/i,
  /^(?:my|our)-/i,
  /^(?:lib|util|utils|helper|helpers|common|shared|core)-[a-z]+-[a-z]+/i,
  /^[a-z]+-(?:service|microservice|api|worker|lambda|handler)$/i,
  /^[a-z]+-(?:config|settings|constants|types|models|schemas)$/i,
];

interface NpmRegistryInfo {
  name: string;
  description?: string;
  readme?: string;
  time?: Record<string, string>;
  "dist-tags"?: Record<string, string>;
  versions?: Record<string, unknown>;
  maintainers?: Array<{ name: string; email?: string }>;
  repository?: { url?: string } | string;
}

interface DownloadInfo {
  downloads: number;
  package: string;
}

interface DependencyResult {
  name: string;
  version: string;
  existsOnPublicRegistry: boolean;
  registryInfo?: {
    description?: string;
    hasReadme: boolean;
    firstPublished?: string;
    latestPublished?: string;
    weeklyDownloads?: number;
    maintainerCount?: number;
    versionCount?: number;
    hasRepository: boolean;
  };
  flags: string[];
  severity: Severity;
}

export interface ConfusionScanOptions {
  /** Path to the project directory (containing package.json) */
  target: string;
  /** Output format */
  format: "text" | "json" | "markdown" | "sarif" | "sbom";
  /** Minimum severity to report */
  minSeverity?: Severity;
  /** Include devDependencies in the check */
  includeDevDeps?: boolean;
}

/**
 * Scan a project for dependency confusion risks.
 */
export async function scanDependencyConfusion(
  options: ConfusionScanOptions,
): Promise<ScanReport> {
  const startTime = Date.now();
  const findings: Finding[] = [];

  // Find and read package.json
  const pkgJsonPath = resolvePackageJson(options.target);
  const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8")) as {
    name?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  // Collect dependencies to check
  const depsToCheck: Record<string, string> = {};

  if (pkgJson.dependencies) {
    Object.assign(depsToCheck, pkgJson.dependencies);
  }
  if (options.includeDevDeps !== false && pkgJson.devDependencies) {
    Object.assign(depsToCheck, pkgJson.devDependencies);
  }

  const depNames = Object.keys(depsToCheck);
  if (depNames.length === 0) {
    return buildReport(options.target, startTime, findings);
  }

  // Check each dependency
  const results: DependencyResult[] = [];

  // Process in batches of 5 to avoid overwhelming the registry
  const batchSize = 5;
  for (let i = 0; i < depNames.length; i += batchSize) {
    const batch = depNames.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map((name) =>
        checkDependency(name, depsToCheck[name] ?? "*"),
      ),
    );
    results.push(...batchResults);
  }

  // Generate findings from results
  for (const result of results) {
    if (result.flags.length > 0) {
      const description = buildDescription(result);
      findings.push({
        rule: determineRule(result),
        description,
        severity: result.severity,
        file: "package.json",
        match: `${result.name}@${result.version}`,
        recommendation: buildRecommendation(result),
      });
    }
  }

  // Filter by severity
  const filteredFindings = filterFindings(findings, options.minSeverity);

  return buildReport(options.target, startTime, filteredFindings);
}

/**
 * Resolve the path to package.json from a target path.
 */
function resolvePackageJson(target: string): string {
  // If target is a file, use it directly
  if (target.endsWith("package.json") && fs.existsSync(target)) {
    return target;
  }

  // If target is a directory, look for package.json inside
  const dirPath = path.resolve(target);
  const pkgPath = path.join(dirPath, "package.json");

  if (!fs.existsSync(pkgPath)) {
    throw new Error(`No package.json found at ${pkgPath}`);
  }

  return pkgPath;
}

/**
 * Check a single dependency against the public npm registry.
 */
async function checkDependency(
  name: string,
  version: string,
): Promise<DependencyResult> {
  const result: DependencyResult = {
    name,
    version,
    existsOnPublicRegistry: false,
    flags: [],
    severity: "info",
  };

  // Skip scoped packages (less likely to be confusion targets, though not impossible)
  const isScoped = name.startsWith("@");

  try {
    // Fetch registry info
    const registryInfo = await fetchRegistryInfo(name);
    result.existsOnPublicRegistry = true;

    // Parse metadata
    const hasReadme =
      !!registryInfo.readme &&
      registryInfo.readme.length > 50 &&
      registryInfo.readme !== "ERROR: No README data found!";
    const versions = registryInfo.versions
      ? Object.keys(registryInfo.versions)
      : [];
    const firstPublished = registryInfo.time?.created;
    const latestVersion = registryInfo["dist-tags"]?.latest;
    const latestPublished = latestVersion
      ? registryInfo.time?.[latestVersion]
      : undefined;
    const maintainerCount = registryInfo.maintainers?.length ?? 0;
    const hasRepository = !!registryInfo.repository;

    result.registryInfo = {
      description: registryInfo.description,
      hasReadme,
      firstPublished,
      latestPublished,
      maintainerCount,
      versionCount: versions.length,
      hasRepository,
    };

    // Fetch download counts
    try {
      const downloads = await fetchDownloads(name);
      result.registryInfo.weeklyDownloads = downloads.downloads;
    } catch {
      // Downloads API can fail, continue without it
    }

    // Apply heuristics

    // 0. AI-hallucinated package name
    if (AI_HALLUCINATED_NPM_PACKAGES.has(name)) {
      result.flags.push("ai-hallucinated-name");
    }

    // 0b. Scope-confusion: scoped package that exists on public npm (potential @org squatting)
    if (isScoped) {
      result.flags.push("scoped-public-npm");
    }

    // 0c. Version-specific cooldown: the version used was published < 7 days ago
    const usedVersion = version.replace(/^[^0-9]*/, "");
    const versionPublished = usedVersion && registryInfo.time
      ? registryInfo.time[usedVersion]
      : undefined;
    if (versionPublished) {
      const hoursAgo = (Date.now() - new Date(versionPublished).getTime()) / (1000 * 60 * 60);
      const daysAgo = hoursAgo / 24;
      if (hoursAgo < VERSION_HOT_HOURS) {
        result.flags.push("version-hot-publish");
      } else if (daysAgo < VERSION_COOLDOWN_DAYS) {
        result.flags.push("version-cooldown");
      }
    }

    // 1. Check for internal-looking name pattern (unscoped only)
    if (!isScoped) {
      const looksInternal = INTERNAL_NAME_PATTERNS.some((p) => p.test(name));
      if (looksInternal) {
        result.flags.push("internal-name-pattern");
      }
    }

    // 2. No README
    if (!hasReadme) {
      result.flags.push("no-readme");
    }

    // 3. No repository link
    if (!hasRepository) {
      result.flags.push("no-repository");
    }

    // 4. Very few downloads
    if (
      result.registryInfo.weeklyDownloads !== undefined &&
      result.registryInfo.weeklyDownloads < LOW_DOWNLOAD_THRESHOLD
    ) {
      result.flags.push("low-downloads");
    }

    // 5. Recently published
    if (firstPublished) {
      const publishedDate = new Date(firstPublished);
      const daysSincePublish = (Date.now() - publishedDate.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSincePublish < VERY_RECENT_PUBLISH_DAYS) {
        result.flags.push("very-recently-published");
      } else if (daysSincePublish < RECENT_PUBLISH_DAYS) {
        result.flags.push("recently-published");
      }
    }

    // 6. Very few versions
    if (versions.length <= 2) {
      result.flags.push("few-versions");
    }

    // 7. Single maintainer with no other packages (hard to check without extra API calls)
    if (maintainerCount === 1 && !hasRepository && !hasReadme) {
      result.flags.push("single-maintainer-no-info");
    }

    // Determine severity based on flag combination
    result.severity = calculateSeverity(result.flags, isScoped);
  } catch (err) {
    // Package doesn't exist on public registry
    const errMsg = err instanceof Error ? err.message : String(err);
    if (errMsg.includes("not found") || errMsg.includes("404")) {
      result.existsOnPublicRegistry = false;
      // An unscoped package that doesn't exist on npm but is in dependencies is suspicious
      if (!isScoped) {
        result.flags.push("not-on-public-registry");
        result.severity = "high";
      } else {
        result.flags.push("scoped-not-on-registry");
        result.severity = "info";
      }
    }
    // Other errors (network, rate limit) are silently skipped
  }

  return result;
}

/**
 * Calculate severity based on the combination of flags.
 */
function calculateSeverity(flags: string[], isScoped: boolean): Severity {
  // If no suspicious flags, it's clean
  if (flags.length === 0) return "info";

  // High severity: name looks internal + suspicious registry signals
  const hasInternalName = flags.includes("internal-name-pattern");
  const hasLowDownloads = flags.includes("low-downloads");
  const hasNoReadme = flags.includes("no-readme");
  const hasNoRepo = flags.includes("no-repository");
  const isVeryRecent = flags.includes("very-recently-published");
  const hasFewVersions = flags.includes("few-versions");
  const isHallucinated = flags.includes("ai-hallucinated-name");
  const isVersionHot = flags.includes("version-hot-publish");
  const isVersionCooldown = flags.includes("version-cooldown");

  // Critical: AI-hallucinated package name that exists on registry
  if (isHallucinated) return "high";

  // High: version published within last hour
  if (isVersionHot) return "high";

  // Medium: version in cooldown window
  if (isVersionCooldown) return "medium";

  // Critical: internal name + recent publish + low downloads (classic confusion attack)
  if (hasInternalName && isVeryRecent && hasLowDownloads) {
    return "critical";
  }

  // High: multiple strong signals
  const strongSignals = [
    hasInternalName,
    hasLowDownloads && hasNoReadme,
    isVeryRecent && hasNoRepo,
    hasFewVersions && hasLowDownloads && hasNoReadme,
  ].filter(Boolean).length;

  if (strongSignals >= 2) return "high";

  // Medium: internal name with some signals, or multiple weak signals
  if (hasInternalName && flags.length >= 2) return "medium";
  if (!isScoped && flags.length >= 3) return "medium";

  // Low: some flags but not enough to be confident
  if (flags.length >= 2) return "low";

  // Single flag: info
  return "info";
}

/**
 * Determine the rule ID based on flags.
 */
function determineRule(result: DependencyResult): string {
  if (result.flags.includes("not-on-public-registry")) {
    return "DEPCONF_NOT_ON_REGISTRY";
  }
  if (result.flags.includes("ai-hallucinated-name")) {
    return "DEP_HALLUCINATED_PACKAGE";
  }
  if (result.flags.includes("version-hot-publish") || result.flags.includes("version-cooldown")) {
    return "DEP_FRESH_PUBLISH";
  }
  if (result.flags.includes("scoped-public-npm") && result.flags.includes("no-readme")) {
    return "DEP_SCOPED_PUBLIC";
  }
  if (result.flags.includes("internal-name-pattern")) {
    if (result.flags.includes("very-recently-published") || result.flags.includes("low-downloads")) {
      return "DEPCONF_LIKELY_CONFUSION";
    }
    return "DEPCONF_INTERNAL_NAME";
  }
  if (result.flags.includes("very-recently-published") && result.flags.includes("low-downloads")) {
    return "DEPCONF_SUSPICIOUS_PACKAGE";
  }
  if (result.flags.includes("scoped-not-on-registry")) {
    return "DEPCONF_SCOPED_PRIVATE";
  }
  return "DEPCONF_WEAK_SIGNAL";
}

/**
 * Build a human-readable description for a dependency result.
 */
function buildDescription(result: DependencyResult): string {
  const parts: string[] = [];

  if (result.flags.includes("not-on-public-registry")) {
    return `Unscoped package "${result.name}" is not found on the public npm registry. This may be an internal package vulnerable to dependency confusion if not using a scoped name or registry configuration.`;
  }

  if (result.flags.includes("scoped-not-on-registry")) {
    return `Scoped package "${result.name}" is not found on the public npm registry. Likely a private/internal package.`;
  }

  if (result.flags.includes("ai-hallucinated-name")) {
    return `Package "${result.name}" matches a known AI-hallucinated package name. LLMs frequently suggest this non-existent package, making it a prime target for squatting attacks.`;
  }

  if (result.flags.includes("version-hot-publish")) {
    return `Version of "${result.name}" used in this project was published to npm less than ${VERSION_HOT_HOURS} hours ago. This is within the critical window where supply chain attacks are most likely to succeed before detection.`;
  }

  if (result.flags.includes("version-cooldown")) {
    return `Version of "${result.name}" used in this project was published to npm less than ${VERSION_COOLDOWN_DAYS} days ago. Security vendors typically need 7 days to detect malicious packages - using brand-new versions carries elevated risk.`;
  }

  if (result.flags.includes("scoped-public-npm") && result.flags.includes("no-readme")) {
    return `Scoped package "${result.name}" exists on the public npm registry with no README. If this is your organization's private package, it has been squatted on the public registry.`;
  }

  parts.push(`Package "${result.name}" has suspicious characteristics:`);

  if (result.flags.includes("internal-name-pattern")) {
    parts.push("name matches internal/private naming patterns");
  }
  if (result.flags.includes("no-readme")) {
    parts.push("no README on npm");
  }
  if (result.flags.includes("no-repository")) {
    parts.push("no repository link");
  }
  if (result.flags.includes("low-downloads")) {
    parts.push(
      `only ${result.registryInfo?.weeklyDownloads ?? "?"} weekly downloads`,
    );
  }
  if (result.flags.includes("very-recently-published")) {
    parts.push(`first published ${result.registryInfo?.firstPublished ?? "recently"}`);
  } else if (result.flags.includes("recently-published")) {
    parts.push(`published within last ${RECENT_PUBLISH_DAYS} days`);
  }
  if (result.flags.includes("few-versions")) {
    parts.push(`only ${result.registryInfo?.versionCount ?? "?"} version(s) published`);
  }
  if (result.flags.includes("single-maintainer-no-info")) {
    parts.push("single maintainer with no repository or README");
  }

  return parts.join("; ");
}

/**
 * Build a recommendation for a dependency result.
 */
function buildRecommendation(result: DependencyResult): string {
  if (result.flags.includes("not-on-public-registry")) {
    return `Ensure "${result.name}" is scoped to your organization (e.g., @yourorg/${result.name}) or configure .npmrc to point to your private registry for this package. Unscoped internal names can be hijacked via dependency confusion.`;
  }

  if (result.flags.includes("internal-name-pattern") && result.severity === "critical") {
    return `HIGH RISK: "${result.name}" looks like an internal package name but exists on the public npm registry with suspicious characteristics. Verify this is the correct package and not a confusion attack. Check the maintainer and compare with your expected private package.`;
  }

  if (result.severity === "high" || result.severity === "critical") {
    return `Verify "${result.name}" is the legitimate package you intend to use. Check the npm page, maintainer identity, and compare with your expected dependency. Consider using package-lock.json integrity hashes.`;
  }

  return `Review "${result.name}" on npmjs.com. While not necessarily malicious, it has some characteristics common in dependency confusion attacks.`;
}

/**
 * Fetch package metadata from the npm registry.
 */
async function fetchRegistryInfo(packageName: string): Promise<NpmRegistryInfo> {
  // npm registry expects scoped packages as @scope%2Fname
  const encodedName = packageName.startsWith("@")
    ? `@${packageName.slice(1).replace("/", "%2F")}`
    : encodeURIComponent(packageName);

  const url = `${NPM_REGISTRY}/${encodedName}`;

  return new Promise((resolve, reject) => {
    https
      .get(
        url,
        {
          headers: {
            Accept: "application/json",
            "User-Agent": `supply-chain-guard/${TOOL_VERSION}`,
          },
        },
        (res) => {
          if (res.statusCode === 404) {
            reject(new Error(`Package not found: ${packageName}`));
            return;
          }
          if (res.statusCode !== 200) {
            reject(new Error(`Registry returned status ${res.statusCode}`));
            return;
          }

          let data = "";
          res.on("data", (chunk: Buffer) => {
            data += chunk.toString();
          });
          res.on("end", () => {
            try {
              resolve(JSON.parse(data) as NpmRegistryInfo);
            } catch {
              reject(new Error("Failed to parse registry response"));
            }
          });
        },
      )
      .on("error", reject);
  });
}

/**
 * Fetch weekly download count from npm.
 */
async function fetchDownloads(packageName: string): Promise<DownloadInfo> {
  const encodedName = encodeURIComponent(packageName);
  const url = `${NPM_DOWNLOADS_API}/${encodedName}`;

  return new Promise((resolve, reject) => {
    https
      .get(
        url,
        {
          headers: {
            Accept: "application/json",
            "User-Agent": `supply-chain-guard/${TOOL_VERSION}`,
          },
        },
        (res) => {
          if (res.statusCode !== 200) {
            reject(new Error(`Downloads API returned status ${res.statusCode}`));
            return;
          }

          let data = "";
          res.on("data", (chunk: Buffer) => {
            data += chunk.toString();
          });
          res.on("end", () => {
            try {
              resolve(JSON.parse(data) as DownloadInfo);
            } catch {
              reject(new Error("Failed to parse downloads response"));
            }
          });
        },
      )
      .on("error", reject);
  });
}

/**
 * Filter findings by minimum severity.
 */
function filterFindings(findings: Finding[], minSeverity?: Severity): Finding[] {
  if (!minSeverity) return findings;

  const severityOrder: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };

  const minLevel = severityOrder[minSeverity] ?? 0;
  return findings.filter((f) => (severityOrder[f.severity] ?? 0) >= minLevel);
}

/**
 * Build the final scan report.
 */
function buildReport(
  target: string,
  startTime: number,
  findings: Finding[],
): ScanReport {
  const summary: ScanSummary = {
    totalFiles: 1,
    filesScanned: 1,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  let score = 0;
  for (const finding of findings) {
    score += SEVERITY_SCORES[finding.severity];
  }
  score = Math.min(100, score);

  const riskLevel =
    score === 0
      ? ("clean" as const)
      : score <= 10
        ? ("low" as const)
        : score <= 30
          ? ("medium" as const)
          : score <= 60
            ? ("high" as const)
            : ("critical" as const);

  const recommendations: string[] = [];
  if (findings.some((f) => f.rule === "DEPCONF_NOT_ON_REGISTRY")) {
    recommendations.push(
      "Some dependencies are not on the public npm registry. Use scoped package names (@org/name) and configure .npmrc to prevent dependency confusion attacks.",
    );
  }
  if (findings.some((f) => f.rule === "DEPCONF_LIKELY_CONFUSION")) {
    recommendations.push(
      "CAUTION: Potential dependency confusion detected. Internal-looking package names exist on the public registry with suspicious characteristics. Verify these are your intended packages.",
    );
  }
  if (findings.some((f) => f.rule === "DEPCONF_SUSPICIOUS_PACKAGE")) {
    recommendations.push(
      "Some dependencies have suspicious registry characteristics (recent publish, low downloads). Pin exact versions and verify package integrity.",
    );
  }
  if (findings.length === 0) {
    recommendations.push(
      "No dependency confusion risks detected. All dependencies appear to be legitimate public packages.",
    );
  }

  return {
    tool: `supply-chain-guard v${TOOL_VERSION}`,
    timestamp: new Date().toISOString(),
    target,
    scanType: "directory",
    durationMs: Date.now() - startTime,
    findings,
    summary,
    score,
    riskLevel,
    recommendations,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PyPI Confusion Detection (v4.9)
// ─────────────────────────────────────────────────────────────────────────────

interface PypiInfo {
  info?: {
    name?: string;
    summary?: string;
    home_page?: string;
    project_url?: string;
    version?: string;
    author?: string;
  };
  releases?: Record<string, unknown[]>;
  urls?: Array<{ upload_time?: string }>;
}

/**
 * Fetch package metadata from PyPI.
 */
async function fetchPypiInfo(packageName: string): Promise<PypiInfo> {
  const url = `${PYPI_REGISTRY}/${encodeURIComponent(packageName)}/json`;

  return new Promise((resolve, reject) => {
    https
      .get(
        url,
        { headers: { Accept: "application/json", "User-Agent": `supply-chain-guard/${TOOL_VERSION}` } },
        (res) => {
          if (res.statusCode === 404) {
            reject(new Error(`PyPI package not found: ${packageName}`));
            return;
          }
          if (res.statusCode !== 200) {
            reject(new Error(`PyPI returned status ${res.statusCode}`));
            return;
          }
          let data = "";
          res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
          res.on("end", () => {
            try { resolve(JSON.parse(data) as PypiInfo); }
            catch { reject(new Error("Failed to parse PyPI response")); }
          });
        },
      )
      .on("error", reject);
  });
}

interface ParsedDependencyNames {
  names: string[];
  complete: boolean;
  unresolvedIncludes?: boolean;
  unresolvedDependencySources?: boolean;
  unresolvedDynamicDependencies?: boolean;
  unresolvedDependencyGroups?: boolean;
  unresolvedToolDependencies?: boolean;
}

type PypiManifestName = "requirements.txt" | "pyproject.toml";

function normalizePypiProjectName(value: string): string {
  return value.toLowerCase().replace(/[-_.]+/g, "-");
}

interface PypiPackageReference {
  name: string;
  manifest: PypiManifestName;
}

/**
 * Parse one PEP 508-shaped requirement conservatively. Returning null means
 * the line carries dependency intent that this scanner cannot evaluate safely.
 */
function stripPerRequirementOptions(value: string): string {
  let requirement = value.trim();
  while (requirement !== "") {
    const hash = /\s+--hash=\S+\s*$/.exec(requirement);
    if (hash !== null) {
      requirement = requirement.slice(0, hash.index).trimEnd();
      continue;
    }

    const configSetting =
      /\s+--config-settings(?:=|\s+)([^\s=]+=[^\s]*)\s*$/.exec(requirement);
    if (configSetting !== null) {
      requirement = requirement.slice(0, configSetting.index).trimEnd();
      continue;
    }
    break;
  }
  return requirement;
}

function parseRequirementName(
  value: string,
  allowPipOptions = false,
): string | null {
  const requirement = allowPipOptions ? stripPerRequirementOptions(value) : value.trim();
  if (requirement === "") return null;

  const markerIndex = requirement.indexOf(";");
  if (markerIndex >= 0) {
    const marker = requirement.slice(markerIndex + 1);
    let quote: "\"" | "'" | undefined;
    let escaped = false;
    for (const char of marker) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === "\\" && quote === '"') {
        escaped = true;
        continue;
      }
      if (char === '"' || char === "'") {
        quote = quote === char ? undefined : quote ?? char;
      }
    }
    if (quote !== undefined || /(?:===|==|!=|<=|>=|<|>)\s*$/.test(marker)) {
      return null;
    }
  }

  const nameShape = "[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?";
  const extrasShape = "(?:\\[\\s*[A-Za-z0-9._-]+(?:\\s*,\\s*[A-Za-z0-9._-]+)*\\s*\\])?";
  const operatorShape = "(?:===|==|~=|!=|<=|>=|<|>)";
  const versionShape = `${operatorShape}\\s*[^,;\\s)]+`;
  const constraintsShape = `(?:\\s*\\(\\s*${versionShape}(?:\\s*,\\s*${versionShape})*\\s*\\)|\\s*${versionShape}(?:\\s*,\\s*${versionShape})*)?`;
  const directReferenceShape = "(?:\\s*@\\s*\\S+)?";
  const markerShape = "(?:\\s*;\\s*\\S[\\s\\S]*)?";
  const match = new RegExp(
    `^(${nameShape})${extrasShape}${constraintsShape}${directReferenceShape}${markerShape}$`,
  ).exec(requirement);
  return match?.[1] ?? null;
}

function stripRequirementComment(line: string): string {
  for (let index = 0; index < line.length; index++) {
    if (line[index] === "#" && (index === 0 || /\s/.test(line[index - 1]!))) {
      return line.slice(0, index);
    }
  }
  return line;
}

function hasUnescapedTrailingBackslash(line: string): boolean {
  let count = 0;
  for (let index = line.length - 1; index >= 0 && line[index] === "\\"; index--) {
    count++;
  }
  return count % 2 === 1;
}

interface LogicalRequirementLines {
  lines: string[];
  complete: boolean;
}

/** pip joins continuations before it removes comments. */
function buildLogicalRequirementLines(content: string): LogicalRequirementLines {
  const lines: string[] = [];
  const physicalLines = content.split(/\r\n|\n|\r/);
  if (/(?:\r\n|\n|\r)$/.test(content)) physicalLines.pop();
  let logicalLine = "";
  let continued = false;

  for (const physicalLine of physicalLines) {
    const continues = hasUnescapedTrailingBackslash(physicalLine);
    logicalLine += continues ? physicalLine.slice(0, -1) : physicalLine;
    if (continues) {
      continued = true;
      continue;
    }
    lines.push(logicalLine);
    logicalLine = "";
    continued = false;
  }

  if (continued || logicalLine !== "") lines.push(logicalLine);
  return { lines, complete: !continued };
}

function optionArgument(
  line: string,
  shortOption: string,
  longOption: string,
): string | null {
  if (line === shortOption || line === longOption) return "";
  if (line.startsWith(`${shortOption} `)) return line.slice(shortOption.length).trimStart();
  if (line.startsWith(shortOption) && !line.startsWith("--")) {
    return line.slice(shortOption.length).trimStart();
  }
  if (line.startsWith(`${longOption} `)) return line.slice(longOption.length).trimStart();
  if (line.startsWith(`${longOption}=`)) return line.slice(longOption.length + 1).trimStart();
  return null;
}

function parseLegacyEggName(value: string): string | null {
  const match = /(?:[#&])egg=([^&#]+)/i.exec(stripPerRequirementOptions(value));
  if (!match?.[1]) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(match[1]);
  } catch {
    return null;
  }
  return parseRequirementName(decoded);
}

const PIP_OPTIONS_WITH_ARGUMENT = [
  ["-i", "--index-url"],
  ["-f", "--find-links"],
  ["-c", "--constraint"],
] as const;
const PIP_LONG_OPTIONS_WITH_ARGUMENT = [
  "--extra-index-url",
  "--trusted-host",
  "--no-binary",
  "--only-binary",
  "--build-constraint",
  "--all-releases",
  "--only-final",
  "--use-feature",
] as const;
const PIP_FLAG_OPTIONS = new Set([
  "--no-index",
  "--prefer-binary",
  "--require-hashes",
  "--pre",
]);

function isRecognizedNonDependencyOption(line: string): boolean {
  if (PIP_FLAG_OPTIONS.has(line)) return true;
  for (const [shortOption, longOption] of PIP_OPTIONS_WITH_ARGUMENT) {
    const argument = optionArgument(line, shortOption, longOption);
    if (argument !== null) return argument !== "";
  }
  for (const option of PIP_LONG_OPTIONS_WITH_ARGUMENT) {
    if (line.startsWith(`${option} `)) return line.slice(option.length).trim() !== "";
    if (line.startsWith(`${option}=`)) return line.slice(option.length + 1).trim() !== "";
  }
  return false;
}

function looksLikeDependencySource(line: string): boolean {
  return /^(?:https?|git\+|hg\+|svn\+|bzr\+|file:)/i.test(line) ||
    /^(?:\.{1,2}[\\/]|[\\/]|[A-Za-z]:[\\/])/.test(line) ||
    /\.(?:whl|zip|tgz|tar\.gz|tar\.bz2)(?:$|[?#])/i.test(line);
}

/**
 * Parse requirements.txt lines into package names while preserving a coverage
 * signal for malformed, delegated, or unsupported dependency entries.
 */
function parseRequirementsTxt(content: string): ParsedDependencyNames {
  const names: string[] = [];
  const logical = buildLogicalRequirementLines(content);
  let complete = logical.complete;
  let unresolvedIncludes = false;
  let unresolvedDependencySources = false;

  for (const rawLine of logical.lines) {
    const line = stripRequirementComment(rawLine).trim();
    if (line === "") continue;

    const includeArgument = optionArgument(line, "-r", "--requirement");
    if (includeArgument !== null) {
      unresolvedIncludes = true;
      continue;
    }

    const scriptArgument = line.startsWith("--requirements-from-script ")
      ? line.slice("--requirements-from-script".length).trim()
      : line.startsWith("--requirements-from-script=")
        ? line.slice("--requirements-from-script=".length).trim()
        : null;
    if (scriptArgument !== null) {
      unresolvedDependencySources = true;
      continue;
    }

    const editableArgument = optionArgument(line, "-e", "--editable");
    if (editableArgument !== null) {
      const editableName = parseRequirementName(editableArgument, true) ??
        parseLegacyEggName(editableArgument);
      if (editableName === null) unresolvedDependencySources = true;
      else names.push(editableName);
      continue;
    }

    if (isRecognizedNonDependencyOption(line)) continue;

    const name = parseRequirementName(line, true);
    if (name !== null && line.includes("@")) {
      names.push(name);
      continue;
    }

    if (looksLikeDependencySource(line)) {
      const eggName = parseLegacyEggName(line);
      if (eggName === null) unresolvedDependencySources = true;
      else names.push(eggName);
      continue;
    }

    if (name !== null) names.push(name);
    else complete = false;
  }

  return {
    names,
    complete,
    unresolvedIncludes,
    unresolvedDependencySources,
  };
}

interface TomlStringArrayResult {
  values: string[];
  complete: boolean;
  endIndex: number;
}

interface TomlEscapeResult {
  value: string;
  nextIndex: number;
}

function decodeTomlBasicEscape(value: string, slashIndex: number): TomlEscapeResult | null {
  const escape = value[slashIndex + 1];
  const simple: Record<string, string> = {
    b: "\b",
    t: "\t",
    n: "\n",
    f: "\f",
    r: "\r",
    '"': '"',
    "\\": "\\",
  };
  if (escape !== undefined && Object.hasOwn(simple, escape)) {
    return { value: simple[escape]!, nextIndex: slashIndex + 2 };
  }
  if (escape !== "u" && escape !== "U") return null;

  const digits = escape === "u" ? 4 : 8;
  const encoded = value.slice(slashIndex + 2, slashIndex + 2 + digits);
  if (!new RegExp(`^[0-9A-Fa-f]{${digits}}$`).test(encoded)) return null;
  const codePoint = Number.parseInt(encoded, 16);
  if (codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) return null;
  return {
    value: String.fromCodePoint(codePoint),
    nextIndex: slashIndex + 2 + digits,
  };
}

/** Parse a TOML array of quoted dependency strings from the opening bracket. */
function parseTomlStringArray(
  value: string,
  allowInlineTail = false,
): TomlStringArrayResult {
  const values: string[] = [];
  let index = 0;

  const closeArray = (): TomlStringArrayResult => {
    index++;
    if (allowInlineTail) return { values, complete: true, endIndex: index };
    const newline = value.indexOf("\n", index);
    const sameLineTail = value.slice(index, newline < 0 ? value.length : newline);
    return {
      values,
      complete: /^\s*(?:#.*)?$/.test(sameLineTail),
      endIndex: index,
    };
  };

  const fail = (): TomlStringArrayResult => ({ values, complete: false, endIndex: index });

  const skipTrivia = (): void => {
    while (index < value.length) {
      if (/\s/.test(value[index]!)) {
        index++;
        continue;
      }
      if (value[index] === "#") {
        const newline = value.indexOf("\n", index + 1);
        index = newline < 0 ? value.length : newline + 1;
        continue;
      }
      break;
    }
  };

  skipTrivia();
  if (value[index] !== "[") return fail();
  index++;

  while (index < value.length) {
    skipTrivia();
    if (value[index] === "]") return closeArray();

    const quote = value[index];
    if (quote !== '"' && quote !== "'") return fail();
    index++;

    let dependency = "";
    let closed = false;
    while (index < value.length) {
      const char = value[index]!;
      if (char === quote) {
        index++;
        closed = true;
        break;
      }
      if (quote === '"' && char === "\\") {
        const decoded = decodeTomlBasicEscape(value, index);
        if (decoded === null) return fail();
        dependency += decoded.value;
        index = decoded.nextIndex;
        continue;
      }
      if (char === "\n" || char === "\r") return fail();
      if (char.charCodeAt(0) < 0x20 && char !== "\t") return fail();
      dependency += char;
      index++;
    }
    if (!closed) return fail();
    values.push(dependency);

    skipTrivia();
    if (value[index] === ",") {
      index++;
      continue;
    }
    if (value[index] === "]") return closeArray();
    return fail();
  }

  return fail();
}

interface CollectedTomlArray {
  source: string;
  endLine: number;
}

/** Collect one array once and let the caller advance beyond its closing line. */
function collectTomlArray(
  lines: string[],
  startLine: number,
  initialValue: string,
): CollectedTomlArray {
  if (!initialValue.trimStart().startsWith("[")) {
    return { source: initialValue, endLine: startLine };
  }

  const chunks: string[] = [];
  let quote: '"' | "'" | undefined;
  let escaped = false;
  let started = false;

  for (let lineIndex = startLine; lineIndex < lines.length; lineIndex++) {
    const chunk = lineIndex === startLine ? initialValue : lines[lineIndex]!;
    chunks.push(chunk);
    let comment = false;

    for (let index = 0; index < chunk.length; index++) {
      const char = chunk[index]!;
      if (comment) break;
      if (quote !== undefined) {
        if (escaped) {
          escaped = false;
        } else if (quote === '"' && char === "\\") {
          escaped = true;
        } else if (char === quote) {
          quote = undefined;
        }
        continue;
      }
      if (char === "#") {
        comment = true;
      } else if (char === '"' || char === "'") {
        quote = char;
      } else if (char === "[") {
        started = true;
      } else if (char === "]" && started) {
        return { source: chunks.join("\n"), endLine: lineIndex };
      }
    }
  }

  return { source: chunks.join("\n"), endLine: lines.length - 1 };
}

function decodeTomlBasicQuotedToken(token: string): string | null {
  if (!token.startsWith('"') || !token.endsWith('"')) return null;
  let decoded = "";
  for (let index = 1; index < token.length - 1;) {
    const char = token[index]!;
    if (char === "\\") {
      const escape = decodeTomlBasicEscape(token, index);
      if (escape === null || escape.nextIndex > token.length - 1) return null;
      decoded += escape.value;
      index = escape.nextIndex;
      continue;
    }
    if (char === "\n" || char === "\r" || (char.charCodeAt(0) < 0x20 && char !== "\t")) {
      return null;
    }
    decoded += char;
    index++;
  }
  return decoded;
}

/** Parse a single TOML key or dotted-key path without changing case. */
function parseTomlDottedKey(value: string): string[] | null {
  const segments: string[] = [];
  let index = 0;

  const skipWhitespace = (): void => {
    while (index < value.length && /\s/.test(value[index]!)) index++;
  };

  while (index < value.length) {
    skipWhitespace();
    if (index >= value.length) return null;

    let segment: string;
    const quote = value[index];
    if (quote === '"' || quote === "'") {
      const start = index;
      index++;
      let closed = false;
      while (index < value.length) {
        const char = value[index]!;
        if (quote === '"' && char === "\\") {
          index += 2;
          continue;
        }
        if (char === quote) {
          index++;
          closed = true;
          break;
        }
        index++;
      }
      if (!closed) return null;

      const token = value.slice(start, index);
      if (quote === '"') {
        const decoded = decodeTomlBasicQuotedToken(token);
        if (decoded === null) return null;
        segment = decoded;
      } else {
        segment = token.slice(1, -1);
      }
    } else {
      const match = /^[A-Za-z0-9_-]+/.exec(value.slice(index));
      if (!match) return null;
      segment = match[0];
      index += match[0].length;
    }

    segments.push(segment);
    skipWhitespace();
    if (index === value.length) return segments;
    if (value[index] !== ".") return null;
    index++;
  }

  return segments.length > 0 ? segments : null;
}

interface TomlAssignment {
  key: string[];
  value: string;
}

/** Split a TOML assignment at the first equals sign outside a quoted key. */
function parseTomlAssignment(line: string): TomlAssignment | null {
  let quote: '"' | "'" | undefined;
  let escaped = false;

  for (let index = 0; index < line.length; index++) {
    const char = line[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === '"' && char === "\\") {
      escaped = true;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = quote === char ? undefined : quote ?? char;
      continue;
    }
    if (char !== "=" || quote !== undefined) continue;

    const key = parseTomlDottedKey(line.slice(0, index));
    return key === null ? null : { key, value: line.slice(index + 1) };
  }

  return null;
}

function startsWithTomlField(line: string, field: string): boolean {
  return new RegExp(
    `^(?:${field}|["']${field}["'])(?=\\s|=|\\.|$)`,
  ).test(line);
}

function sameTomlPath(left: string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

interface ParsedInlineDependencyGroup {
  name: string;
  values: string[];
  includes: string[];
}

interface InlineDependencyTableResult {
  groups: ParsedInlineDependencyGroup[];
  complete: boolean;
  endIndex: number;
}

interface InlineProjectResult extends ParsedDependencyNames {
  seenFields: Array<"dependencies" | "dynamic">;
  optionalGroups: ParsedInlineDependencyGroup[];
  dynamicRequiredDependencies: boolean;
  dynamicOptionalDependencies: boolean;
}

function skipInlineTomlValue(value: string, start: number): number {
  let quote: '"' | "'" | undefined;
  let escaped = false;
  let squareDepth = 0;
  let curlyDepth = 0;

  for (let index = start; index < value.length; index++) {
    const char = value[index]!;
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (quote === '"' && char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === "[") squareDepth++;
    else if (char === "]") squareDepth = Math.max(0, squareDepth - 1);
    else if (char === "{") curlyDepth++;
    else if (char === "}" && squareDepth === 0 && curlyDepth === 0) return index;
    else if (char === "}") curlyDepth--;
    else if (char === "," && squareDepth === 0 && curlyDepth === 0) return index;
  }
  return value.length;
}

interface InlineTomlKey {
  key: string[];
  nextIndex: number;
}

function parseInlineTomlKey(value: string, start: number): InlineTomlKey | null {
  let index = start;
  let quote: '"' | "'" | undefined;
  let escaped = false;

  while (index < value.length) {
    const char = value[index]!;
    if (char === "\n" || char === "\r") return null;
    if (escaped) {
      escaped = false;
    } else if (quote === '"' && char === "\\") {
      escaped = true;
    } else if (char === '"' || char === "'") {
      quote = quote === char ? undefined : quote ?? char;
    } else if (char === "=" && quote === undefined) {
      const key = parseTomlDottedKey(value.slice(start, index));
      return key === null ? null : { key, nextIndex: index + 1 };
    } else if ((char === "," || char === "}") && quote === undefined) {
      return null;
    }
    index++;
  }
  return null;
}

interface ParsedTomlString {
  value: string;
  nextIndex: number;
}

function parseTomlQuotedString(value: string, start: number): ParsedTomlString | null {
  const quote = value[start];
  if (quote !== '"' && quote !== "'") return null;
  let decoded = "";

  for (let index = start + 1; index < value.length;) {
    const char = value[index]!;
    if (char === quote) return { value: decoded, nextIndex: index + 1 };
    if (quote === '"' && char === "\\") {
      const escape = decodeTomlBasicEscape(value, index);
      if (escape === null) return null;
      decoded += escape.value;
      index = escape.nextIndex;
      continue;
    }
    if (char === "\n" || char === "\r" || (char.charCodeAt(0) < 0x20 && char !== "\t")) {
      return null;
    }
    decoded += char;
    index++;
  }
  return null;
}

interface TomlDependencyGroupArrayResult extends TomlStringArrayResult {
  includes: string[];
}

function parseTomlDependencyGroupArray(
  value: string,
  allowInlineTail = false,
): TomlDependencyGroupArrayResult {
  const values: string[] = [];
  const includes: string[] = [];
  let index = 0;

  const finish = (complete: boolean): TomlDependencyGroupArrayResult => ({
    values,
    includes,
    complete,
    endIndex: index,
  });
  const skipTrivia = (): void => {
    while (index < value.length) {
      if (/\s/.test(value[index]!)) {
        index++;
        continue;
      }
      if (value[index] === "#") {
        const newline = value.indexOf("\n", index + 1);
        index = newline < 0 ? value.length : newline + 1;
        continue;
      }
      break;
    }
  };
  const parseInclude = (): string | null => {
    index++;
    while (index < value.length && /[ \t]/.test(value[index]!)) index++;
    const parsedKey = parseInlineTomlKey(value, index);
    if (parsedKey === null || parsedKey.key.length !== 1 || parsedKey.key[0] !== "include-group") {
      return null;
    }
    index = parsedKey.nextIndex;
    while (index < value.length && /[ \t]/.test(value[index]!)) index++;
    const parsedValue = parseTomlQuotedString(value, index);
    if (parsedValue === null) return null;
    index = parsedValue.nextIndex;
    while (index < value.length && /[ \t]/.test(value[index]!)) index++;
    if (value[index] !== "}") return null;
    index++;
    return parsedValue.value;
  };

  skipTrivia();
  if (value[index] !== "[") return finish(false);
  index++;

  while (index < value.length) {
    skipTrivia();
    if (value[index] === "]") {
      index++;
      if (allowInlineTail) return finish(true);
      const newline = value.indexOf("\n", index);
      const tail = value.slice(index, newline < 0 ? value.length : newline);
      return finish(/^\s*(?:#.*)?$/.test(tail));
    }

    if (value[index] === "{") {
      const include = parseInclude();
      if (include === null) return finish(false);
      includes.push(include);
    } else {
      const parsed = parseTomlQuotedString(value, index);
      if (parsed === null) return finish(false);
      values.push(parsed.value);
      index = parsed.nextIndex;
    }

    skipTrivia();
    if (value[index] === ",") {
      index++;
      continue;
    }
    if (value[index] === "]") continue;
    return finish(false);
  }

  return finish(false);
}

function parseInlineDependencyTable(
  value: string,
  kind: "optional" | "groups" | "build",
  allowInlineTail = false,
): InlineDependencyTableResult {
  const groups: ParsedInlineDependencyGroup[] = [];
  let complete = true;
  let index = 0;
  const skipWhitespace = (): void => {
    while (index < value.length && /[ \t]/.test(value[index]!)) index++;
  };
  const finish = (isComplete: boolean): InlineDependencyTableResult => ({
    groups,
    complete: complete && isComplete,
    endIndex: index,
  });

  skipWhitespace();
  if (value[index] !== "{") return finish(false);
  index++;

  while (index < value.length) {
    skipWhitespace();
    if (value[index] === "}") {
      index++;
      if (allowInlineTail) return finish(true);
      return finish(/^\s*(?:#.*)?$/.test(value.slice(index)));
    }

    const parsedKey = parseInlineTomlKey(value, index);
    if (parsedKey === null || parsedKey.key.length !== 1) return finish(false);
    const name = parsedKey.key[0]!;
    index = parsedKey.nextIndex;
    skipWhitespace();

    if (kind === "build" && name !== "requires") {
      index = skipInlineTomlValue(value, index);
    } else if (kind === "groups") {
      const parsed = parseTomlDependencyGroupArray(value.slice(index), true);
      groups.push({ name, values: parsed.values, includes: parsed.includes });
      complete = complete && parsed.complete;
      if (!parsed.complete) return finish(false);
      index += parsed.endIndex;
    } else {
      const parsed = parseTomlStringArray(value.slice(index), true);
      groups.push({ name, values: parsed.values, includes: [] });
      complete = complete && parsed.complete;
      if (!parsed.complete) return finish(false);
      index += parsed.endIndex;
    }

    skipWhitespace();
    if (value[index] === ",") {
      index++;
      continue;
    }
    if (value[index] !== "}") return finish(false);
  }

  return finish(false);
}

function parseInlineProjectTable(value: string): InlineProjectResult {
  const names: string[] = [];
  const seenFields: Array<"dependencies" | "dynamic"> = [];
  const optionalGroups: ParsedInlineDependencyGroup[] = [];
  let complete = true;
  let dynamicRequiredDependencies = false;
  let dynamicOptionalDependencies = false;
  let sawOptionalDependencies = false;
  let index = 0;
  const skipWhitespace = (): void => {
    while (index < value.length && /[ \t]/.test(value[index]!)) index++;
  };
  const result = (isComplete: boolean): InlineProjectResult => ({
    names,
    complete: complete && isComplete,
    seenFields,
    optionalGroups,
    dynamicRequiredDependencies,
    dynamicOptionalDependencies,
  });

  skipWhitespace();
  if (value[index] !== "{") return result(false);
  index++;

  while (index < value.length) {
    skipWhitespace();
    if (value[index] === "}") {
      index++;
      return result(/^\s*(?:#.*)?$/.test(value.slice(index)));
    }

    const parsedKey = parseInlineTomlKey(value, index);
    if (parsedKey === null || parsedKey.key.length !== 1) return result(false);
    const field = parsedKey.key[0]!;
    index = parsedKey.nextIndex;
    skipWhitespace();

    if (field === "dependencies" || field === "dynamic") {
      const parsedArray = parseTomlStringArray(value.slice(index), true);
      seenFields.push(field);
      complete = complete && parsedArray.complete;
      if (field === "dynamic") {
        dynamicRequiredDependencies = dynamicRequiredDependencies ||
          parsedArray.values.includes("dependencies");
        dynamicOptionalDependencies = dynamicOptionalDependencies ||
          parsedArray.values.includes("optional-dependencies");
      } else {
        for (const dependency of parsedArray.values) {
          const name = parseRequirementName(dependency);
          if (name === null) complete = false;
          else names.push(name);
        }
      }
      if (!parsedArray.complete) return result(false);
      index += parsedArray.endIndex;
    } else if (field === "optional-dependencies") {
      if (sawOptionalDependencies) complete = false;
      sawOptionalDependencies = true;
      const parsedTable = parseInlineDependencyTable(value.slice(index), "optional", true);
      optionalGroups.push(...parsedTable.groups);
      complete = complete && parsedTable.complete;
      if (!parsedTable.complete) return result(false);
      index += parsedTable.endIndex;
    } else {
      index = skipInlineTomlValue(value, index);
    }

    skipWhitespace();
    if (value[index] === ",") {
      index++;
      continue;
    }
    if (value[index] !== "}") return result(false);
  }

  return result(false);
}

function looksLikeRelevantTomlField(line: string, tablePath: string[] | null): boolean {
  if (tablePath === null) return false;
  if (sameTomlPath(tablePath, ["project"])) {
    return startsWithTomlField(line, "dependencies") ||
      startsWithTomlField(line, "optional-dependencies") ||
      startsWithTomlField(line, "dynamic");
  }
  if (
    sameTomlPath(tablePath, ["project", "optional-dependencies"]) ||
    sameTomlPath(tablePath, ["dependency-groups"])
  ) {
    return true;
  }
  if (sameTomlPath(tablePath, ["build-system"])) {
    return startsWithTomlField(line, "requires");
  }
  if (tablePath.length === 0) {
    return /^(?:(?:project|build-system|dependency-groups|tool)(?:\s*\.|\s*=)|["'](?:project|build-system|dependency-groups|tool)["'](?:\s*\.|\s*=))/.test(line);
  }
  return isPoetryDependencyPath(tablePath);
}

interface TomlTableHeader {
  path: string[];
  array: boolean;
}

function parseTomlTableHeader(line: string): TomlTableHeader | null {
  const array = line.startsWith("[[");
  if (!line.startsWith("[")) return null;
  const openerLength = array ? 2 : 1;
  let quote: string | undefined;
  let escaped = false;

  for (let index = openerLength; index < line.length; index++) {
    const char = line[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === '"' && char === "\\") {
      escaped = true;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = quote === char ? undefined : quote ?? char;
      continue;
    }
    if (char !== "]" || quote !== undefined) continue;
    const closeLength = array ? 2 : 1;
    if (array && line[index + 1] !== "]") return null;
    const tail = line.slice(index + closeLength);
    if (!/^\s*(?:#.*)?$/.test(tail)) return null;
    const path = parseTomlDottedKey(line.slice(openerLength, index));
    return path === null ? null : { path, array };
  }

  return null;
}

function isValidDependencyGroupName(value: string): boolean {
  return /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(value);
}

function normalizeDependencyGroupName(value: string): string {
  return value.toLowerCase().replace(/[-_.]+/g, "-");
}

function isPoetryDependencyPath(path: readonly string[]): boolean {
  if (path[0] !== "tool" || path[1] !== "poetry") return false;
  if (
    path.length === 3 &&
    (path[2] === "dependencies" || path[2] === "dev-dependencies")
  ) {
    return true;
  }
  return path.length === 5 &&
    path[2] === "group" &&
    path[4] === "dependencies";
}

function poetryDependencyNameFromPath(path: readonly string[]): string | undefined {
  if (
    path.length === 4 &&
    path[0] === "tool" &&
    path[1] === "poetry" &&
    (path[2] === "dependencies" || path[2] === "dev-dependencies")
  ) {
    return path[3];
  }
  if (
    path.length === 6 &&
    path[0] === "tool" &&
    path[1] === "poetry" &&
    path[2] === "group" &&
    path[4] === "dependencies"
  ) {
    return path[5];
  }
  return undefined;
}

interface InlinePoetryDependencies {
  names: string[];
  complete: boolean;
}

function parseInlinePoetryDependencies(value: string): InlinePoetryDependencies {
  const names: string[] = [];
  let index = 0;
  const skipWhitespace = (): void => {
    while (index < value.length && /[ \t]/.test(value[index]!)) index++;
  };
  const result = (complete: boolean): InlinePoetryDependencies => ({ names, complete });

  skipWhitespace();
  if (value[index] !== "{") return result(false);
  index++;
  while (index < value.length) {
    skipWhitespace();
    if (value[index] === "}") {
      index++;
      return result(/^\s*(?:#.*)?$/.test(value.slice(index)));
    }
    const parsedKey = parseInlineTomlKey(value, index);
    if (parsedKey === null || parsedKey.key.length !== 1) return result(false);
    const poetryName = parseRequirementName(parsedKey.key[0]!);
    if (poetryName === null) return result(false);
    let valueStart = parsedKey.nextIndex;
    while (valueStart < value.length && /[ \t]/.test(value[valueStart]!)) valueStart++;
    if (
      valueStart >= value.length ||
      value[valueStart] === "," ||
      value[valueStart] === "}" ||
      value[valueStart] === "#"
    ) {
      return result(false);
    }
    if (poetryName !== "python") names.push(poetryName);
    index = skipInlineTomlValue(value, valueStart);
    skipWhitespace();
    if (value[index] === ",") {
      index++;
      continue;
    }
    if (value[index] !== "}") return result(false);
  }
  return result(false);
}

/**
 * Parse standardized dependency-bearing pyproject.toml metadata without a
 * general TOML dependency. Relevant arrays are collected once and the line
 * cursor advances past them, keeping malformed multi-megabyte manifests linear.
 */
function parsePyprojectToml(content: string): ParsedDependencyNames {
  const names: string[] = [];
  const lines = content.split(/\r\n|\n|\r/);
  let tablePath: string[] | null = [];
  let complete = true;
  let dynamicRequiredDependencies = false;
  let dynamicOptionalDependencies = false;
  let unresolvedDependencyGroups = false;
  let unresolvedToolDependencies = false;
  let hasStaticOptionalDependencies = false;
  let hasBuildSystem = false;
  let sawBuildRequires = false;
  const seenProjectFields = new Set<"dependencies" | "dynamic">();
  const seenOptionalGroups = new Set<string>();
  const dependencyGroups = new Map<string, { includes: string[] }>();

  const addRequirementValues = (values: readonly string[]): void => {
    for (const dependency of values) {
      const name = parseRequirementName(dependency);
      if (name === null) complete = false;
      else names.push(name);
    }
  };
  const noteProjectField = (field: "dependencies" | "dynamic"): void => {
    if (seenProjectFields.has(field)) complete = false;
    seenProjectFields.add(field);
  };
  const consumeProjectArray = (
    field: "dependencies" | "dynamic",
    parsedArray: TomlStringArrayResult,
  ): void => {
    noteProjectField(field);
    complete = complete && parsedArray.complete;
    if (field === "dynamic") {
      dynamicRequiredDependencies = dynamicRequiredDependencies ||
        parsedArray.values.includes("dependencies");
      dynamicOptionalDependencies = dynamicOptionalDependencies ||
        parsedArray.values.includes("optional-dependencies");
    } else {
      addRequirementValues(parsedArray.values);
    }
  };
  const noteOptionalGroup = (group: ParsedInlineDependencyGroup): void => {
    hasStaticOptionalDependencies = true;
    if (!isValidDependencyGroupName(group.name)) complete = false;
    const normalized = normalizeDependencyGroupName(group.name);
    if (seenOptionalGroups.has(normalized)) complete = false;
    seenOptionalGroups.add(normalized);
    addRequirementValues(group.values);
  };
  const noteBuildRequires = (values: readonly string[]): void => {
    hasBuildSystem = true;
    if (sawBuildRequires) complete = false;
    sawBuildRequires = true;
    addRequirementValues(values);
  };
  const noteDependencyGroup = (group: ParsedInlineDependencyGroup): void => {
    if (!isValidDependencyGroupName(group.name)) complete = false;
    const normalized = normalizeDependencyGroupName(group.name);
    if (dependencyGroups.has(normalized)) complete = false;
    dependencyGroups.set(normalized, { includes: group.includes });
    addRequirementValues(group.values);
  };

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex]!.trim();
    if (line === "" || line.startsWith("#")) continue;

    if (line.startsWith("[")) {
      const header = parseTomlTableHeader(line);
      if (header === null) {
        complete = false;
        tablePath = null;
      } else if (header.array) {
        if (
          header.path[0] === "project" ||
          header.path[0] === "build-system" ||
          header.path[0] === "dependency-groups"
        ) {
          complete = false;
        }
        if (isPoetryDependencyPath(header.path)) unresolvedToolDependencies = true;
        tablePath = null;
      } else {
        tablePath = header.path;
        if (sameTomlPath(header.path, ["project", "dependencies"])) {
          noteProjectField("dependencies");
        } else if (sameTomlPath(header.path, ["project", "optional-dependencies"])) {
          hasStaticOptionalDependencies = true;
        } else if (sameTomlPath(header.path, ["project", "dynamic"])) {
          complete = false;
        } else if (sameTomlPath(header.path, ["build-system"])) {
          hasBuildSystem = true;
        } else if (
          header.path[0] === "build-system" && header.path.length > 1 ||
          header.path[0] === "dependency-groups" && header.path.length > 1 ||
          header.path[0] === "project" &&
            header.path[1] === "optional-dependencies" &&
            header.path.length > 2
        ) {
          complete = false;
        }
        if (poetryDependencyNameFromPath(header.path) !== undefined) {
          unresolvedToolDependencies = true;
        }
      }
      continue;
    }

    const assignment = parseTomlAssignment(line);
    if (assignment === null) {
      if (looksLikeRelevantTomlField(line, tablePath)) complete = false;
      continue;
    }

    if (tablePath !== null && isPoetryDependencyPath(tablePath)) {
      const poetryName = assignment.key.length === 1
        ? parseRequirementName(assignment.key[0]!)
        : null;
      if (poetryName === null || assignment.value.trim() === "") {
        unresolvedToolDependencies = true;
      } else if (poetryName !== "python") {
        names.push(poetryName);
      }
      continue;
    }
    if (tablePath !== null && sameTomlPath(tablePath, ["project", "dependencies"])) {
      if (assignment.key.length === 1) names.push(assignment.key[0]!);
      else complete = false;
      continue;
    }

    if (tablePath !== null && sameTomlPath(tablePath, ["project", "optional-dependencies"])) {
      if (assignment.key.length !== 1) {
        complete = false;
        continue;
      }
      const collected = collectTomlArray(lines, lineIndex, assignment.value);
      const parsedArray = parseTomlStringArray(collected.source);
      noteOptionalGroup({ name: assignment.key[0]!, values: parsedArray.values, includes: [] });
      complete = complete && parsedArray.complete;
      lineIndex = collected.endLine;
      continue;
    }

    if (tablePath !== null && sameTomlPath(tablePath, ["dependency-groups"])) {
      if (assignment.key.length !== 1) {
        complete = false;
        continue;
      }
      const collected = collectTomlArray(lines, lineIndex, assignment.value);
      const parsedArray = parseTomlDependencyGroupArray(collected.source);
      noteDependencyGroup({
        name: assignment.key[0]!,
        values: parsedArray.values,
        includes: parsedArray.includes,
      });
      complete = complete && parsedArray.complete;
      lineIndex = collected.endLine;
      continue;
    }

    if (tablePath !== null && sameTomlPath(tablePath, ["build-system"])) {
      if (sameTomlPath(assignment.key, ["requires"])) {
        const collected = collectTomlArray(lines, lineIndex, assignment.value);
        const parsedArray = parseTomlStringArray(collected.source);
        noteBuildRequires(parsedArray.values);
        complete = complete && parsedArray.complete;
        lineIndex = collected.endLine;
      }
      continue;
    }

    if (tablePath === null) continue;
    const fullKey = [...tablePath, ...assignment.key];
    if (fullKey[0] === "build-system") hasBuildSystem = true;

    const poetryDependencyKey = poetryDependencyNameFromPath(fullKey);
    if (poetryDependencyKey !== undefined) {
      const poetryName = parseRequirementName(poetryDependencyKey);
      if (poetryName === null || assignment.value.trim() === "") {
        unresolvedToolDependencies = true;
      } else if (poetryName !== "python") {
        names.push(poetryName);
      }
      continue;
    }
    if (isPoetryDependencyPath(fullKey)) {
      const parsedPoetry = parseInlinePoetryDependencies(assignment.value);
      names.push(...parsedPoetry.names);
      unresolvedToolDependencies = unresolvedToolDependencies || !parsedPoetry.complete;
      continue;
    }
    if (
      sameTomlPath(fullKey, ["tool", "poetry"]) &&
      /(?:^|[{,])\s*(?:dependencies|dev-dependencies)\s*=/.test(assignment.value)
    ) {
      unresolvedToolDependencies = true;
      continue;
    }
    if (
      fullKey[0] === "tool" &&
      fullKey[1] === "poetry" &&
      (fullKey[2] === "dependencies" ||
        fullKey[2] === "dev-dependencies" ||
        fullKey[2] === "group" && fullKey[4] === "dependencies")
    ) {
      unresolvedToolDependencies = true;
      continue;
    }

    if (sameTomlPath(fullKey, ["project"])) {
      const parsedInline = parseInlineProjectTable(assignment.value);
      complete = complete && parsedInline.complete;
      names.push(...parsedInline.names);
      dynamicRequiredDependencies = dynamicRequiredDependencies ||
        parsedInline.dynamicRequiredDependencies;
      dynamicOptionalDependencies = dynamicOptionalDependencies ||
        parsedInline.dynamicOptionalDependencies;
      for (const field of parsedInline.seenFields) noteProjectField(field);
      for (const group of parsedInline.optionalGroups) noteOptionalGroup(group);
      continue;
    }

    if (sameTomlPath(fullKey, ["build-system"])) {
      hasBuildSystem = true;
      const parsedInline = parseInlineDependencyTable(assignment.value, "build");
      complete = complete && parsedInline.complete;
      const requires = parsedInline.groups.filter((group) => group.name === "requires");
      for (const group of requires) noteBuildRequires(group.values);
      continue;
    }

    if (sameTomlPath(fullKey, ["dependency-groups"])) {
      const parsedInline = parseInlineDependencyTable(assignment.value, "groups");
      complete = complete && parsedInline.complete;
      for (const group of parsedInline.groups) noteDependencyGroup(group);
      continue;
    }

    const projectField = sameTomlPath(fullKey, ["project", "dependencies"])
      ? "dependencies"
      : sameTomlPath(fullKey, ["project", "dynamic"])
        ? "dynamic"
        : undefined;
    if (projectField !== undefined) {
      const collected = collectTomlArray(lines, lineIndex, assignment.value);
      const parsedArray = parseTomlStringArray(collected.source);
      consumeProjectArray(projectField, parsedArray);
      lineIndex = collected.endLine;
      continue;
    }

    if (sameTomlPath(fullKey, ["project", "optional-dependencies"])) {
      hasStaticOptionalDependencies = true;
      const parsedInline = parseInlineDependencyTable(assignment.value, "optional");
      complete = complete && parsedInline.complete;
      for (const group of parsedInline.groups) noteOptionalGroup(group);
      continue;
    }

    if (
      fullKey.length === 3 &&
      fullKey[0] === "project" &&
      fullKey[1] === "optional-dependencies"
    ) {
      const collected = collectTomlArray(lines, lineIndex, assignment.value);
      const parsedArray = parseTomlStringArray(collected.source);
      noteOptionalGroup({ name: fullKey[2]!, values: parsedArray.values, includes: [] });
      complete = complete && parsedArray.complete;
      lineIndex = collected.endLine;
      continue;
    }

    if (sameTomlPath(fullKey, ["build-system", "requires"])) {
      const collected = collectTomlArray(lines, lineIndex, assignment.value);
      const parsedArray = parseTomlStringArray(collected.source);
      noteBuildRequires(parsedArray.values);
      complete = complete && parsedArray.complete;
      lineIndex = collected.endLine;
      continue;
    }

    if (
      fullKey.length === 2 &&
      fullKey[0] === "dependency-groups"
    ) {
      const collected = collectTomlArray(lines, lineIndex, assignment.value);
      const parsedArray = parseTomlDependencyGroupArray(collected.source);
      noteDependencyGroup({
        name: fullKey[1]!,
        values: parsedArray.values,
        includes: parsedArray.includes,
      });
      complete = complete && parsedArray.complete;
      lineIndex = collected.endLine;
      continue;
    }

    if (
      fullKey.length > 2 &&
      fullKey[0] === "project" &&
      (fullKey[1] === "dependencies" || fullKey[1] === "dynamic") ||
      fullKey.length > 3 &&
      fullKey[0] === "project" &&
      fullKey[1] === "optional-dependencies" ||
      fullKey.length > 2 &&
      fullKey[0] === "build-system" &&
      fullKey[1] === "requires" ||
      fullKey.length > 2 &&
      fullKey[0] === "dependency-groups"
    ) {
      complete = false;
    }
  }

  if (
    dynamicRequiredDependencies && seenProjectFields.has("dependencies") ||
    dynamicOptionalDependencies && hasStaticOptionalDependencies
  ) {
    complete = false;
  }
  if (hasBuildSystem && !sawBuildRequires) complete = false;

  const indegree = new Map<string, number>();
  for (const group of dependencyGroups.keys()) indegree.set(group, 0);
  for (const definition of dependencyGroups.values()) {
    for (const include of definition.includes) {
      if (!isValidDependencyGroupName(include)) {
        unresolvedDependencyGroups = true;
        continue;
      }
      const target = normalizeDependencyGroupName(include);
      if (!dependencyGroups.has(target)) {
        unresolvedDependencyGroups = true;
        continue;
      }
      indegree.set(target, (indegree.get(target) ?? 0) + 1);
    }
  }
  const queue = [...indegree.entries()]
    .filter(([, degree]) => degree === 0)
    .map(([group]) => group);
  let visited = 0;
  for (let cursor = 0; cursor < queue.length; cursor++) {
    const group = queue[cursor]!;
    visited++;
    for (const include of dependencyGroups.get(group)?.includes ?? []) {
      const target = normalizeDependencyGroupName(include);
      const degree = indegree.get(target);
      if (degree === undefined) continue;
      const nextDegree = degree - 1;
      indegree.set(target, nextDegree);
      if (nextDegree === 0) queue.push(target);
    }
  }
  if (visited !== dependencyGroups.size) unresolvedDependencyGroups = true;

  return {
    names,
    complete,
    unresolvedDynamicDependencies:
      dynamicRequiredDependencies || dynamicOptionalDependencies,
    unresolvedDependencyGroups,
    unresolvedToolDependencies,
  };
}
function recordUnresolvedDynamicDependencies(findings: Finding[]): void {
  findings.push({
    rule: "PATH_SCAN_INCOMPLETE",
    description:
      "pyproject.toml declares required or optional project dependency metadata as dynamic, so a build backend supplies it from a source this scan did not resolve and dependency-confusion coverage is incomplete.",
    severity: "info",
    confidence: 1,
    category: "info",
    file: "pyproject.toml",
    match: "dynamic project dependencies",
    recommendation:
      "Treat this result as partial, not clean. Resolve the build backend's dependency source into static [project] dependency metadata or scan that source directly, then run the scan again.",
  });
}
function recordUnresolvedDependencyGroups(findings: Finding[]): void {
  findings.push({
    rule: "PATH_SCAN_INCOMPLETE",
    description:
      "pyproject.toml contains a dependency-group include that is missing, invalid or cyclic, so dependency-confusion coverage is incomplete.",
    severity: "info",
    confidence: 1,
    category: "info",
    file: "pyproject.toml",
    match: "unresolved dependency groups",
    recommendation:
      "Treat this result as partial, not clean. Repair dependency-group includes and cycles, then run the scan again.",
  });
}

function recordUnresolvedToolDependencies(findings: Finding[]): void {
  findings.push({
    rule: "PATH_SCAN_INCOMPLETE",
    description:
      "pyproject.toml declares dependencies in tool-specific Poetry metadata that this scanner did not resolve safely, so dependency-confusion coverage is incomplete.",
    severity: "info",
    confidence: 1,
    category: "info",
    file: "pyproject.toml",
    match: "unresolved tool-specific dependencies",
    recommendation:
      "Treat this result as partial, not clean. Export the Poetry dependency set to standardized project metadata or requirements.txt and scan it directly.",
  });
}
function recordUnresolvedRequirementsInclude(findings: Finding[]): void {
  findings.push({
    rule: "PATH_SCAN_INCOMPLETE",
    description:
      "requirements.txt delegates dependency declarations to a referenced dependency manifest that was not resolved, so dependency-confusion coverage is incomplete.",
    severity: "info",
    confidence: 1,
    category: "info",
    file: "requirements.txt",
    match: "unresolved requirements include",
    recommendation:
      "Treat this result as partial, not clean. Scan the referenced requirements files directly or consolidate them, then run the scan again.",
  });
}

function recordUnresolvedDependencySources(findings: Finding[]): void {
  findings.push({
    rule: "PATH_SCAN_INCOMPLETE",
    description:
      "requirements.txt contains a dependency-bearing source whose project name could not be resolved safely, so dependency-confusion coverage is incomplete.",
    severity: "info",
    confidence: 1,
    category: "info",
    file: "requirements.txt",
    match: "unresolved dependency source",
    recommendation:
      "Treat this result as partial, not clean. Use an explicit PEP 508 name-at-URL requirement or scan the referenced project metadata directly, then run the scan again.",
  });
}

function recordMalformedManifest(
  findings: Finding[],
  manifest: PypiManifestName,
): void {
  findings.push({
    rule: "PATH_SCAN_INCOMPLETE",
    description:
      "An in-scope dependency manifest was malformed or truncated, so its dependencies could not be fully scanned.",
    severity: "info",
    confidence: 1,
    category: "info",
    file: manifest,
    match: "incomplete dependency manifest parse",
    recommendation:
      "Treat this result as partial, not clean. Repair the dependency manifest, then run the scan again.",
  });
}

/**
 * Scan a project directory for PyPI dependency confusion risks.
 * Reads requirements.txt and pyproject.toml.
 */
export async function scanPypiDependencyConfusion(projectDir: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const packageReferences: PypiPackageReference[] = [];

  // Collect from requirements.txt. Optional absence is normal; an in-scope
  // manifest that exists but cannot be read or parsed makes coverage partial.
  const reqTxt = path.join(projectDir, "requirements.txt");
  const reqContent = readOptionalUtf8File(
    projectDir,
    reqTxt,
    "requirements.txt",
    findings,
  );
  if (reqContent !== null) {
    const parsed = parseRequirementsTxt(reqContent);
    parsed.names.forEach((name) => {
      packageReferences.push({ name, manifest: "requirements.txt" });
    });
    if (!parsed.complete) recordMalformedManifest(findings, "requirements.txt");
    if (parsed.unresolvedIncludes) recordUnresolvedRequirementsInclude(findings);
    if (parsed.unresolvedDependencySources) recordUnresolvedDependencySources(findings);
  }

  // Collect from pyproject.toml under the same coverage contract.
  const pyproject = path.join(projectDir, "pyproject.toml");
  const pyprojectContent = readOptionalUtf8File(
    projectDir,
    pyproject,
    "pyproject.toml",
    findings,
  );
  if (pyprojectContent !== null) {
    const parsed = parsePyprojectToml(pyprojectContent);
    parsed.names.forEach((name) => {
      packageReferences.push({ name, manifest: "pyproject.toml" });
    });
    if (!parsed.complete) recordMalformedManifest(findings, "pyproject.toml");
    if (parsed.unresolvedDynamicDependencies) {
      recordUnresolvedDynamicDependencies(findings);
    }
    if (parsed.unresolvedDependencyGroups) {
      recordUnresolvedDependencyGroups(findings);
    }
    if (parsed.unresolvedToolDependencies) {
      recordUnresolvedToolDependencies(findings);
    }
  }
  const seen = new Set<string>();
  const pypiInfoRequests = new Map<string, Promise<PypiInfo>>();
  for (const { name, manifest } of packageReferences) {
    const normalizedName = normalizePypiProjectName(name);
    const referenceKey = `${manifest}\0${normalizedName}`;
    if (seen.has(referenceKey)) continue;
    seen.add(referenceKey);

    // AI-hallucinated PyPI package
    if (AI_HALLUCINATED_PYPI_PACKAGES.has(normalizedName)) {
      findings.push({
        rule: "DEP_HALLUCINATED_PACKAGE",
        description: `PyPI package "${name}" matches a known AI-hallucinated package name. LLMs frequently suggest this non-existent package - it may be squatted on PyPI.`,
        severity: "high",
        file: manifest,
        match: name,
        recommendation:
          "Verify this is the correct package. AI-suggested package names that don't exist are frequently registered by attackers.",
      });
      continue;
    }

    // Internal name pattern
    const looksInternal = INTERNAL_NAME_PATTERNS.some((p) => p.test(normalizedName));

    try {
      let infoRequest = pypiInfoRequests.get(normalizedName);
      if (infoRequest === undefined) {
        infoRequest = fetchPypiInfo(name);
        pypiInfoRequests.set(normalizedName, infoRequest);
      }
      const info = await infoRequest;
      const hasDescription = !!info.info?.summary && info.info.summary.length > 10;
      const hasHomePage = !!(info.info?.home_page || info.info?.project_url);
      const releaseCount = info.releases ? Object.keys(info.releases).length : 0;
      const latestUpload = info.urls?.[0]?.upload_time;

      const flags: string[] = [];
      if (!hasDescription) flags.push("no-description");
      if (!hasHomePage) flags.push("no-homepage");
      if (releaseCount <= 2) flags.push("few-releases");
      if (looksInternal) flags.push("internal-name-pattern");

      if (latestUpload) {
        const hoursAgo = (Date.now() - new Date(latestUpload).getTime()) / (1000 * 60 * 60);
        if (hoursAgo < VERSION_HOT_HOURS) flags.push("version-hot-publish");
        else if (hoursAgo / 24 < VERSION_COOLDOWN_DAYS) flags.push("version-cooldown");
      }

      if (flags.length >= 2 || (looksInternal && flags.length >= 1)) {
        const severity: Severity =
          looksInternal && flags.includes("version-hot-publish")
            ? "critical"
            : looksInternal && flags.length >= 2
              ? "high"
              : flags.includes("version-hot-publish")
                ? "high"
                : "medium";

        findings.push({
          rule: "DEP_PYPI_CONFUSION",
          description: `PyPI package "${name}" has suspicious characteristics: ${flags.join(", ")}`,
          severity,
          file: manifest,
          match: name,
          recommendation: `Verify "${name}" is the legitimate package. Check https://pypi.org/project/${name}/ and compare with your expected dependency.`,
        });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("not found") && looksInternal) {
        findings.push({
          rule: "DEPCONF_NOT_ON_REGISTRY",
          description: `PyPI package "${name}" with internal-looking name is not found on PyPI. Private package vulnerable to dependency confusion.`,
          severity: "high",
          file: manifest,
          match: name,
          recommendation: `Ensure "${name}" is always resolved from your private registry. Configure pip with --index-url pointing to your private registry.`,
        });
      }
    }
  }

  return findings;
}
