/**
 * Composer/PHP supply-chain scanner.
 *
 * Detects supply-chain risks in composer.json and composer.lock: packages
 * matching curated threat-intel IOCs (composer: prefixed package entries),
 * non-https dist/source URLs, and repositories entries served over plain
 * http.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";

/** Composer-related file names */
const COMPOSER_JSON = "composer.json";
const COMPOSER_LOCK = "composer.lock";

interface ComposerLockPackage {
  name?: unknown;
  version?: unknown;
  dist?: { url?: unknown };
  source?: { url?: unknown };
}

/**
 * Check if a file is a Composer-related file.
 */
export function isComposerFile(filename: string): boolean {
  return filename === COMPOSER_JSON || filename === COMPOSER_LOCK;
}

/**
 * Scan Composer files in a directory.
 */
export function scanComposerFiles(dir: string): Finding[] {
  const findings: Finding[] = [];
  const feed = loadThreatIntel();

  const composerJson = path.join(dir, COMPOSER_JSON);
  if (fs.existsSync(composerJson)) {
    try {
      const content = fs.readFileSync(composerJson, "utf-8");
      findings.push(...scanComposerJsonContent(content, COMPOSER_JSON, feed));
    } catch { /* skip */ }
  }

  const composerLock = path.join(dir, COMPOSER_LOCK);
  if (fs.existsSync(composerLock)) {
    try {
      const content = fs.readFileSync(composerLock, "utf-8");
      findings.push(...scanComposerLockContent(content, COMPOSER_LOCK, feed));
    } catch { /* skip */ }
  }

  return findings;
}

/**
 * Scan composer.json content.
 */
export function scanComposerJsonContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return findings; // malformed manifest: nothing to parse
  }
  if (!parsed || typeof parsed !== "object") return findings;

  // require / require-dev: names only (constraints like "^1.0" are ranges,
  // not resolved versions - versioned IOCs are matched via composer.lock)
  for (const section of ["require", "require-dev"]) {
    const deps = parsed[section];
    if (!deps || typeof deps !== "object") continue;
    for (const name of Object.keys(deps)) {
      const ioc = matchPackageIOC("composer", name, undefined, iocFeed);
      if (ioc) {
        findings.push(maliciousPackageFinding(name, undefined, ioc, relativePath));
      }
    }
  }

  // repositories: plain-http entries allow package tampering in transit
  const repos = parsed["repositories"];
  const repoList = Array.isArray(repos)
    ? repos
    : repos && typeof repos === "object"
      ? Object.values(repos)
      : [];
  for (const repo of repoList) {
    if (!repo || typeof repo !== "object") continue;
    const url = (repo as { url?: unknown }).url;
    if (typeof url === "string" && /^http:\/\//i.test(url)) {
      findings.push({
        rule: "COMPOSER_HTTP_REPOSITORY",
        description: `Composer repository uses plain http (${url}). Unencrypted repositories allow package tampering in transit.`,
        severity: "medium",
        file: relativePath,
        match: truncate(url),
        confidence: 0.8,
        category: "supply-chain",
        recommendation:
          "Switch the repository URL to https. Composer refuses http by default (secure-http); do not disable that setting.",
      });
    }
  }

  return findings;
}

/**
 * Scan composer.lock content.
 */
export function scanComposerLockContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return findings; // malformed lockfile: nothing to parse
  }
  if (!parsed || typeof parsed !== "object") return findings;

  for (const section of ["packages", "packages-dev"]) {
    const packages = parsed[section];
    if (!Array.isArray(packages)) continue;

    for (const entry of packages) {
      if (!entry || typeof entry !== "object") continue;
      const pkg = entry as ComposerLockPackage;
      if (typeof pkg.name !== "string") continue;

      // Composer versions often carry a "v" prefix ("v2.0.1"); IOC values do not.
      const version =
        typeof pkg.version === "string" ? pkg.version.replace(/^v(?=\d)/, "") : undefined;

      const ioc = matchPackageIOC("composer", pkg.name, version, iocFeed);
      if (ioc) {
        findings.push(maliciousPackageFinding(pkg.name, version, ioc, relativePath));
      }

      const distUrl = pkg.dist?.url;
      if (typeof distUrl === "string" && /^http:\/\//i.test(distUrl)) {
        findings.push(httpUrlFinding("COMPOSER_HTTP_DIST_URL", "dist", pkg.name, distUrl, relativePath));
      }

      const sourceUrl = pkg.source?.url;
      if (typeof sourceUrl === "string" && /^http:\/\//i.test(sourceUrl)) {
        findings.push(httpUrlFinding("COMPOSER_HTTP_SOURCE_URL", "source", pkg.name, sourceUrl, relativePath));
      }
    }
  }

  return findings;
}

function maliciousPackageFinding(
  name: string,
  version: string | undefined,
  ioc: FeedIOC,
  relativePath: string,
): Finding {
  return {
    rule: "COMPOSER_MALICIOUS_PACKAGE",
    description: `Known malicious Composer package: ${name}${version ? `@${version}` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
    severity: ioc.severity,
    file: relativePath,
    match: truncate(version ? `${name}@${version}` : name),
    confidence: ioc.confidence,
    category: "malware",
    recommendation: `Remove ${name} immediately, rotate any credentials available to `
      + "`composer install`, and audit systems that installed it. This package is listed in threat intelligence feeds.",
  };
}

function httpUrlFinding(
  rule: "COMPOSER_HTTP_DIST_URL" | "COMPOSER_HTTP_SOURCE_URL",
  kind: "dist" | "source",
  name: string,
  url: string,
  relativePath: string,
): Finding {
  return {
    rule,
    description: `Package "${name}" has a plain-http ${kind} URL (${url}). Unencrypted downloads allow package tampering in transit.`,
    severity: "medium",
    file: relativePath,
    match: truncate(url),
    confidence: 0.8,
    category: "supply-chain",
    recommendation: `Regenerate composer.lock against an https ${kind} URL and verify the package contents against the upstream release.`,
  };
}

function truncate(value: string): string {
  return value.length > 120 ? value.substring(0, 120) + "..." : value;
}
