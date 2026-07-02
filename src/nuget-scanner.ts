/**
 * NuGet/.NET supply-chain scanner.
 *
 * Detects supply-chain risks in packages.lock.json, *.csproj, and
 * nuget.config: packages matching curated threat-intel IOCs (nuget:
 * prefixed package entries, ids compared case-insensitively) and plain
 * http package feeds. XML is scanned with hand-rolled regexes - no XML
 * library is used.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";

/** NuGet-related file names (compared case-insensitively, .NET style) */
const PACKAGES_LOCK = "packages.lock.json";
const NUGET_CONFIG = "nuget.config";
const CSPROJ_EXT = ".csproj";

/** <PackageReference Include="Name" Version="1.2.3" /> (attribute order free) */
const PACKAGE_REFERENCE = /<PackageReference\b[^>]*/i;
const INCLUDE_ATTR = /\bInclude\s*=\s*["']([^"']+)["']/i;
const VERSION_ATTR = /\bVersion\s*=\s*["']([^"']+)["']/i;
const RESTORE_SOURCES = /<RestoreSources>([^<]*)<\/RestoreSources>/i;

/**
 * Check if a file is a NuGet-related file.
 */
export function isNuGetFile(filename: string): boolean {
  const lower = filename.toLowerCase();
  return lower === PACKAGES_LOCK || lower === NUGET_CONFIG || lower.endsWith(CSPROJ_EXT);
}

/**
 * Check if a directory contains NuGet-related files (scanner entry gate).
 */
export function hasNuGetFiles(dir: string): boolean {
  try {
    return fs.readdirSync(dir).some((name) => isNuGetFile(name));
  } catch {
    return false;
  }
}

/**
 * Scan NuGet files in a directory.
 */
export function scanNuGetFiles(dir: string): Finding[] {
  const findings: Finding[] = [];
  const feed = loadThreatIntel();

  let entries: string[];
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return findings;
  }

  for (const name of entries) {
    const lower = name.toLowerCase();
    const fullPath = path.join(dir, name);
    if (!isNuGetFile(name)) continue;

    let content: string;
    try {
      content = fs.readFileSync(fullPath, "utf-8");
    } catch {
      continue;
    }

    if (lower === PACKAGES_LOCK) {
      findings.push(...scanPackagesLockContent(content, name, feed));
    } else if (lower === NUGET_CONFIG) {
      findings.push(...scanNuGetConfigContent(content, name));
    } else {
      findings.push(...scanCsprojContent(content, name, feed));
    }
  }

  return findings;
}

/**
 * Scan packages.lock.json content (dependencies tree with resolved versions).
 */
export function scanPackagesLockContent(
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

  const dependencies = parsed["dependencies"];
  if (!dependencies || typeof dependencies !== "object") return findings;

  // dependencies: { "<framework>": { "<PackageId>": { resolved: "1.2.3", ... } } }
  for (const framework of Object.values(dependencies as Record<string, unknown>)) {
    if (!framework || typeof framework !== "object") continue;
    for (const [name, info] of Object.entries(framework as Record<string, unknown>)) {
      const resolved =
        info && typeof info === "object" && typeof (info as { resolved?: unknown }).resolved === "string"
          ? ((info as { resolved: string }).resolved)
          : undefined;
      const ioc = matchPackageIOC("nuget", name, resolved, iocFeed);
      if (ioc) {
        findings.push(maliciousPackageFinding(name, resolved, ioc, relativePath));
      }
    }
  }

  return findings;
}

/**
 * Scan *.csproj content (PackageReference / RestoreSources).
 */
export function scanCsprojContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";

    const refMatch = PACKAGE_REFERENCE.exec(line);
    if (refMatch) {
      const tag = refMatch[0];
      const name = INCLUDE_ATTR.exec(tag)?.[1];
      const version = VERSION_ATTR.exec(tag)?.[1];
      if (name) {
        const ioc = matchPackageIOC("nuget", name, version, iocFeed);
        if (ioc) {
          findings.push(maliciousPackageFinding(name, version, ioc, relativePath, i + 1));
        }
      }
    }

    const restoreMatch = RESTORE_SOURCES.exec(line);
    if (restoreMatch) {
      for (const source of (restoreMatch[1] ?? "").split(";")) {
        const trimmed = source.trim();
        if (/^http:\/\//i.test(trimmed)) {
          findings.push(httpFeedFinding(trimmed, relativePath, i + 1));
        }
      }
    }
  }

  return findings;
}

/**
 * Scan nuget.config content for plain-http package feeds.
 */
export function scanNuGetConfigContent(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];

  // Scope to <packageSources> when present, otherwise scan the whole file
  // (credential/mapping sections do not carry feed URLs in value attributes).
  const sourcesMatch = /<packageSources>([\s\S]*?)<\/packageSources>/i.exec(content);
  const scope = sourcesMatch?.[1] ?? content;
  const baseOffset = sourcesMatch ? (sourcesMatch.index + (/<packageSources>/i.exec(content)?.[0]?.length ?? 0)) : 0;

  const addTag = /<add\b[^>]*\bvalue\s*=\s*["'](http:\/\/[^"']+)["'][^>]*>/gi;
  let match: RegExpExecArray | null;
  while ((match = addTag.exec(scope)) !== null) {
    const line = content.substring(0, baseOffset + match.index).split("\n").length;
    findings.push(httpFeedFinding(match[1] ?? "", relativePath, line));
  }

  return findings;
}

function maliciousPackageFinding(
  name: string,
  version: string | undefined,
  ioc: FeedIOC,
  relativePath: string,
  line?: number,
): Finding {
  return {
    rule: "NUGET_MALICIOUS_PACKAGE",
    description: `Known malicious NuGet package: ${name}${version ? `@${version}` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
    severity: ioc.severity,
    file: relativePath,
    line,
    match: truncate(version ? `${name}@${version}` : name),
    confidence: ioc.confidence,
    category: "malware",
    recommendation: `Remove ${name} immediately, rotate any credentials available to `
      + "`dotnet restore`, and audit systems that restored it. This package is listed in threat intelligence feeds.",
  };
}

function httpFeedFinding(url: string, relativePath: string, line: number): Finding {
  return {
    rule: "NUGET_HTTP_FEED",
    description: `NuGet package feed uses plain http (${url}). Unencrypted feeds allow package tampering in transit.`,
    severity: "medium",
    file: relativePath,
    line,
    match: truncate(url),
    confidence: 0.8,
    category: "supply-chain",
    recommendation:
      "Switch the feed to https. NuGet warns on http sources since 6.3 and blocks them by default in newer SDKs (allowInsecureConnections should stay off).",
  };
}

function truncate(value: string): string {
  return value.length > 120 ? value.substring(0, 120) + "..." : value;
}
