/**
 * Python lockfile supply-chain scanner.
 *
 * Detects supply-chain risks in Python resolved-dependency lockfiles:
 * - poetry.lock and uv.lock (TOML with flat [[package]] blocks: name = "x",
 *   version = "y")
 * - Pipfile.lock (JSON: { "default": {...}, "develop": {...} } with per-package
 *   { "version": "==x.y" } specifiers)
 *
 * Resolved name+version pairs are checked against known-compromised PyPI
 * versions (ioc-blocklist) and curated threat-intel IOCs (pypi: prefixed feed
 * entries). TOML is parsed with a hand-rolled line-state parser and Pipfile.lock
 * with JSON.parse - no TOML library is added (same approach as the JS lockfile
 * parsers and how requirements.txt / pyproject.toml are read elsewhere).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { checkBadVersion } from "./ioc-blocklist.js";

/** Python lockfile names */
const POETRY_LOCK = "poetry.lock";
const UV_LOCK = "uv.lock";
const PIPFILE_LOCK = "Pipfile.lock";

/**
 * Check if a file is a Python lockfile.
 */
export function isPythonLockfile(filename: string): boolean {
  return filename === POETRY_LOCK || filename === UV_LOCK || filename === PIPFILE_LOCK;
}

/**
 * Scan Python lockfiles in a directory.
 */
export function scanPythonLockfiles(dir: string): Finding[] {
  const findings: Finding[] = [];
  const feed = loadThreatIntel();

  const poetry = path.join(dir, POETRY_LOCK);
  if (fs.existsSync(poetry)) {
    try {
      findings.push(...scanPoetryLockContent(fs.readFileSync(poetry, "utf-8"), POETRY_LOCK, feed));
    } catch { /* skip */ }
  }

  const uv = path.join(dir, UV_LOCK);
  if (fs.existsSync(uv)) {
    try {
      findings.push(...scanUvLockContent(fs.readFileSync(uv, "utf-8"), UV_LOCK, feed));
    } catch { /* skip */ }
  }

  const pipfile = path.join(dir, PIPFILE_LOCK);
  if (fs.existsSync(pipfile)) {
    try {
      findings.push(...scanPipfileLockContent(fs.readFileSync(pipfile, "utf-8"), PIPFILE_LOCK, feed));
    } catch { /* skip */ }
  }

  return findings;
}

/**
 * Scan poetry.lock content (TOML [[package]] blocks).
 */
export function scanPoetryLockContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  return checkTomlPackages(content, relativePath, feed ?? loadThreatIntel());
}

/**
 * Scan uv.lock content (TOML [[package]] blocks; same shape as poetry.lock).
 */
export function scanUvLockContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  return checkTomlPackages(content, relativePath, feed ?? loadThreatIntel());
}

/**
 * Scan Pipfile.lock content (JSON default/develop package maps).
 */
export function scanPipfileLockContent(
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

  // Scan EVERY top-level package-map section, not just default/develop: pipenv
  // supports custom package categories (since ~2022.10.4), each serialized as
  // its own top-level key (e.g. "docs", "tests", "ci") with the same
  // {name: {version: "==x.y"}} shape. "_meta" is lockfile metadata, not packages.
  for (const [section, deps] of Object.entries(parsed)) {
    if (section === "_meta") continue;
    if (!deps || typeof deps !== "object" || Array.isArray(deps)) continue;
    for (const [name, info] of Object.entries(deps as Record<string, unknown>)) {
      const version =
        info && typeof info === "object" && typeof (info as { version?: unknown }).version === "string"
          ? (info as { version: string }).version
          : undefined;
      checkPythonPackage(name, version, relativePath, iocFeed, findings);
    }
  }

  return findings;
}

/**
 * Run the TOML lockfile packages through the shared PyPI IOC checks.
 */
function checkTomlPackages(content: string, relativePath: string, feed: FeedIOC[]): Finding[] {
  const findings: Finding[] = [];
  for (const { name, version } of parseTomlPackages(content)) {
    checkPythonPackage(name, version, relativePath, feed, findings);
  }
  return findings;
}

interface TomlPackage {
  name: string;
  version?: string;
}

/**
 * Line-state parser for poetry.lock / uv.lock [[package]] blocks. A new
 * [[package]] header (or any other table header) flushes the current block.
 */
function parseTomlPackages(content: string): TomlPackage[] {
  const packages: TomlPackage[] = [];
  let current: TomlPackage | null = null;

  const flush = (): void => {
    if (current && current.name) packages.push(current);
    current = null;
  };

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (line === "[[package]]") {
      flush();
      current = { name: "" };
      continue;
    }
    // Any other table header ends the current package block (e.g. [metadata]).
    if (line.startsWith("[")) {
      flush();
      continue;
    }
    if (current === null) continue;

    const nameMatch = /^name\s*=\s*"([^"]+)"/.exec(line);
    if (nameMatch) {
      current.name = nameMatch[1]!;
      continue;
    }
    const versionMatch = /^version\s*=\s*"([^"]+)"/.exec(line);
    if (versionMatch) {
      current.version = versionMatch[1]!;
      continue;
    }
  }
  flush();
  return packages;
}

/**
 * Check one resolved Python package against the known-bad version blocklist
 * and the threat-intel feed.
 */
function checkPythonPackage(
  name: string,
  rawVersion: string | undefined,
  relativePath: string,
  feed: FeedIOC[],
  findings: Finding[],
): void {
  const version = rawVersion ? cleanVersion(rawVersion) : undefined;

  // Known-compromised version (ioc-blocklist; KNOWN_BAD_PYPI_VERSIONS)
  if (version) {
    const bad = checkBadVersion(name, version, "pypi");
    if (bad) findings.push({ ...bad, file: relativePath });
  }

  // Threat-intel IOC match (bundled pypi: package entries)
  const ioc = matchPackageIOC("pypi", name, version, feed);
  if (ioc) findings.push(maliciousPackageFinding(name, version, ioc, relativePath));
}

/** Strip Poetry / PEP440 version operators: "==1.2.3" -> "1.2.3". */
function cleanVersion(v: string): string {
  return v.replace(/^[=~!<>^ ]+/, "").trim();
}

function maliciousPackageFinding(
  name: string,
  version: string | undefined,
  ioc: FeedIOC,
  relativePath: string,
): Finding {
  return {
    rule: "PYTHON_MALICIOUS_PACKAGE",
    description: `Known malicious PyPI package: ${name}${version ? `@${version}` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
    severity: ioc.severity,
    file: relativePath,
    match: truncate(version ? `${name}@${version}` : name),
    confidence: ioc.confidence,
    category: "malware",
    recommendation: `Remove ${name} immediately, rotate any credentials available to `
      + "`pip install`, and audit systems that installed it. This package is listed in threat intelligence feeds.",
  };
}

function truncate(value: string): string {
  return value.length > 120 ? value.substring(0, 120) + "..." : value;
}
