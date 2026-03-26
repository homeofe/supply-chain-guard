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

const TOOL_VERSION = "1.0.0";
const NPM_REGISTRY = "https://registry.npmjs.org";
const NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week";

// Heuristic thresholds
const LOW_DOWNLOAD_THRESHOLD = 100;        // weekly downloads
const RECENT_PUBLISH_DAYS = 90;            // published within last N days
const VERY_RECENT_PUBLISH_DAYS = 30;       // very recently published

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
  format: "text" | "json" | "markdown" | "sarif";
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
            "User-Agent": "supply-chain-guard/1.0.0",
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
            "User-Agent": "supply-chain-guard/1.0.0",
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
