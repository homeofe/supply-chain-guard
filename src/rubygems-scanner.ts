/**
 * RubyGems supply-chain scanner.
 *
 * Detects supply-chain risks in Gemfile and Gemfile.lock: gems matching
 * curated threat-intel IOCs (ruby: prefixed package entries), non-https
 * gem sources, and git/path gem sources that bypass rubygems.org
 * integrity checks.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";

/** RubyGems-related file names */
const GEMFILE = "Gemfile";
const GEMFILE_LOCK = "Gemfile.lock";

/** gem "name" [, "1.2.3"] [, git:/path:/github: ...] */
const GEM_LINE = /^\s*gem\s+["']([A-Za-z0-9._-]+)["'](.*)$/;
/** Exact pinned version requirement, e.g. ", '1.2.3'" (no ~>, >=, ... operators) */
const GEM_EXACT_VERSION = /^\s*,\s*["']([0-9][A-Za-z0-9.]*)["']/;
/** Gemfile.lock spec line: exactly 4-space indent "name (version)" */
const LOCK_SPEC_LINE = /^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)\s*$/;

/**
 * Check if a file is a RubyGems-related file.
 */
export function isRubyGemsFile(filename: string): boolean {
  return filename === GEMFILE || filename === GEMFILE_LOCK;
}

/**
 * Scan RubyGems files in a directory.
 */
export function scanRubyGemsFiles(dir: string): Finding[] {
  const findings: Finding[] = [];
  const feed = loadThreatIntel();

  const gemfile = path.join(dir, GEMFILE);
  if (fs.existsSync(gemfile)) {
    try {
      const content = fs.readFileSync(gemfile, "utf-8");
      findings.push(...scanGemfileContent(content, GEMFILE, feed));
    } catch { /* skip */ }
  }

  const lockfile = path.join(dir, GEMFILE_LOCK);
  if (fs.existsSync(lockfile)) {
    try {
      const content = fs.readFileSync(lockfile, "utf-8");
      findings.push(...scanGemfileLockContent(content, GEMFILE_LOCK, feed));
    } catch { /* skip */ }
  }

  return findings;
}

/**
 * Scan Gemfile content.
 */
export function scanGemfileContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    // Strip trailing Ruby comments before source inspection
    const code = line.split("#")[0] ?? "";

    // Non-https source: gems fetched over plain http can be MITMed
    const sourceMatch = /^\s*source\s+["'](http:\/\/[^"']+)["']/.exec(code);
    if (sourceMatch) {
      findings.push(httpSourceFinding(relativePath, i + 1, sourceMatch[1] ?? ""));
    }

    const gemMatch = GEM_LINE.exec(code);
    if (!gemMatch) continue;
    const name = gemMatch[1] ?? "";
    const rest = gemMatch[2] ?? "";

    // Threat-intel IOC match (bundled ruby: package entries)
    const versionMatch = GEM_EXACT_VERSION.exec(rest);
    const ioc = matchPackageIOC("ruby", name, versionMatch?.[1], iocFeed);
    if (ioc) {
      findings.push(maliciousGemFinding(name, versionMatch?.[1], ioc, relativePath, i + 1, code));
    }

    // git:/github: sources bypass rubygems.org integrity checks
    if (/(?::git\b|\bgit\s*:|:github\b|\bgithub\s*:|\bgit_source\b)/.test(rest)) {
      findings.push({
        rule: "RUBY_GEM_GIT_SOURCE",
        description: `Gem "${name}" is sourced from git instead of rubygems.org. Git sources bypass registry integrity checks.`,
        severity: "medium",
        file: relativePath,
        line: i + 1,
        match: truncate(code.trim()),
        confidence: 0.6,
        category: "supply-chain",
        recommendation:
          "Prefer rubygems.org releases. If a git source is required, pin it to a full commit SHA (ref:) instead of a branch.",
      });
    }

    // path: sources point outside the dependency tree
    if (/(?::path\b|\bpath\s*:)/.test(rest)) {
      findings.push({
        rule: "RUBY_GEM_PATH_SOURCE",
        description: `Gem "${name}" is sourced from a local path. Path sources are not versioned or integrity-checked.`,
        severity: "low",
        file: relativePath,
        line: i + 1,
        match: truncate(code.trim()),
        confidence: 0.5,
        category: "supply-chain",
        recommendation:
          "Verify the local path gem is intentional (common in monorepos) and not a dependency-confusion staging artifact.",
      });
    }
  }

  return findings;
}

/**
 * Scan Gemfile.lock content.
 */
export function scanGemfileLockContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();
  const lines = content.split("\n");

  let section = "";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (line.length > 0 && !/^\s/.test(line)) {
      section = line.trim(); // GEM / GIT / PATH / PLATFORMS / DEPENDENCIES / ...
      continue;
    }
    if (section !== "GEM") continue;

    // "  remote: http://..." - non-https gem source
    const remoteMatch = /^ {2}remote:\s*(\S+)/.exec(line);
    if (remoteMatch && /^http:\/\//i.test(remoteMatch[1] ?? "")) {
      findings.push(httpSourceFinding(relativePath, i + 1, remoteMatch[1] ?? ""));
      continue;
    }

    // "    name (1.2.3)" spec lines (6-space indented lines are transitive
    // dependency constraints, not resolved specs - skip those)
    const specMatch = LOCK_SPEC_LINE.exec(line);
    if (specMatch) {
      const name = specMatch[1] ?? "";
      // Strip platform suffix, e.g. "1.2.3-x86_64-linux"
      const version = (specMatch[2] ?? "").split("-")[0];
      const ioc = matchPackageIOC("ruby", name, version, iocFeed);
      if (ioc) {
        findings.push(maliciousGemFinding(name, version, ioc, relativePath, i + 1, line));
      }
    }
  }

  return findings;
}

function maliciousGemFinding(
  name: string,
  version: string | undefined,
  ioc: FeedIOC,
  relativePath: string,
  line: number,
  matchLine: string,
): Finding {
  return {
    rule: "RUBY_MALICIOUS_GEM",
    description: `Known malicious gem: ${name}${version ? `@${version}` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
    severity: ioc.severity,
    file: relativePath,
    line,
    match: truncate(matchLine.trim()),
    confidence: ioc.confidence,
    category: "malware",
    recommendation: `Remove ${name} immediately, rotate any credentials available to `
      + "`bundle install`, and audit systems that installed it. This gem is listed in threat intelligence feeds.",
  };
}

function httpSourceFinding(relativePath: string, line: number, url: string): Finding {
  return {
    rule: "RUBY_GEM_HTTP_SOURCE",
    description: `Gem source uses plain http (${url}). Unencrypted sources allow package tampering in transit.`,
    severity: "medium",
    file: relativePath,
    line,
    match: truncate(url),
    confidence: 0.8,
    category: "supply-chain",
    recommendation: "Switch the gem source to https. Bundler supports https for all major gem servers.",
  };
}

function truncate(value: string): string {
  return value.length > 120 ? value.substring(0, 120) + "..." : value;
}
