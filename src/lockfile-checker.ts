/**
 * Lockfile integrity verification (T-006)
 *
 * Covers all four major JavaScript package-manager lockfile formats:
 * - package-lock.json (npm, lockfile v1/v2/v3)
 * - pnpm-lock.yaml (pnpm v6 "/name@1.2.3" and v9 "name@1.2.3" package keys)
 * - yarn.lock (classic v1 and Berry v2+ with __metadata)
 * - bun.lock (JSONC text lockfile, bun >= 1.2); binary bun.lockb is flagged
 *   as unauditable instead of parsed
 *
 * Shared checks across all formats:
 * - Integrity hashes matching expected format (sha512/sha256/sha1)
 * - Packages resolved from non-registry / plain-HTTP / git URLs
 * - Missing integrity data on resolvable packages
 * - Known-compromised package versions (ioc-blocklist)
 *
 * npm-only checks (package-lock.json):
 * - Dependencies in lockfile but not in package.json
 * - Lockfile version downgrades
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { checkBadVersion } from "./ioc-blocklist.js";

/** Valid integrity hash prefixes */
const VALID_INTEGRITY_PREFIXES = ["sha512-", "sha256-", "sha1-"];

/** Known alternative registries that are generally trusted */
const TRUSTED_REGISTRIES = [
  "https://registry.npmjs.org/",
  "https://registry.yarnpkg.com/",
];

/** Minimum expected lockfile version for modern projects */
const MIN_LOCKFILE_VERSION = 2;

interface LockfilePackageEntry {
  version?: string;
  resolved?: string;
  integrity?: string;
  dependencies?: LockfileDependencies;
  dev?: boolean;
  optional?: boolean;
}

interface LockfileDependencies {
  [name: string]: LockfilePackageEntry;
}

interface LockfileV2Packages {
  [path: string]: LockfilePackageEntry & {
    link?: boolean;
  };
}

interface Lockfile {
  name?: string;
  version?: string;
  lockfileVersion?: number;
  dependencies?: LockfileDependencies;
  packages?: LockfileV2Packages;
}

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

/**
 * A dependency extracted from any lockfile format, normalized so the same
 * threat checks can run regardless of which package manager wrote the file.
 */
interface ParsedLockDependency {
  name: string;
  /** Exact resolved version (only set when the specifier is a plain version) */
  version?: string;
  /** Tarball / registry / git URL the package resolves from */
  resolved?: string;
  /** Integrity hash or checksum, if present */
  integrity?: string;
  /** Whether this entry type is expected to carry integrity data */
  expectsIntegrity: boolean;
  /** Whether the integrity value uses SRI format (sha512-base64). yarn Berry
   *  checksums use their own cacheKey-prefixed format and are not validated. */
  sriIntegrity: boolean;
}

/**
 * Check a directory for lockfile issues across all supported formats.
 * A repo can contain several lockfiles (e.g. after a package-manager
 * migration); all present ones are checked.
 */
export function checkLockfile(dir: string): Finding[] {
  return [
    ...checkNpmLockfile(dir),
    ...checkPnpmLockfile(dir),
    ...checkYarnLockfile(dir),
    ...checkBunLockfile(dir),
  ];
}

// ---------------------------------------------------------------------------
// npm: package-lock.json
// ---------------------------------------------------------------------------

/**
 * Check package-lock.json (npm) for lockfile issues.
 * Returns findings if the lockfile is present.
 */
export function checkNpmLockfile(dir: string): Finding[] {
  const lockfilePath = path.join(dir, "package-lock.json");
  const packageJsonPath = path.join(dir, "package.json");

  if (!fs.existsSync(lockfilePath)) {
    return [];
  }

  let lockfile: Lockfile;
  try {
    lockfile = JSON.parse(fs.readFileSync(lockfilePath, "utf-8")) as Lockfile;
  } catch {
    return [parseErrorFinding("package-lock.json", "npm install")];
  }

  const findings: Finding[] = [];

  // Check lockfile version
  checkLockfileVersion(lockfile, findings);

  // Parse package.json for cross-reference
  let packageJson: PackageJson | null = null;
  if (fs.existsSync(packageJsonPath)) {
    try {
      packageJson = JSON.parse(
        fs.readFileSync(packageJsonPath, "utf-8"),
      ) as PackageJson;
    } catch {
      // If package.json is unparseable, skip cross-reference checks
    }
  }

  // Check packages (lockfile v2/v3 format)
  if (lockfile.packages) {
    checkPackages(lockfile.packages, findings);
  }

  // Check dependencies (lockfile v1 format, also present in v2)
  if (lockfile.dependencies) {
    checkDependencies(lockfile.dependencies, findings);
  }

  // Cross-reference lockfile with package.json
  if (packageJson) {
    checkOrphanedDependencies(lockfile, packageJson, findings);
  }

  return findings;
}

/**
 * Check lockfile version for downgrades.
 */
function checkLockfileVersion(lockfile: Lockfile, findings: Finding[]): void {
  const version = lockfile.lockfileVersion;

  if (version === undefined) {
    findings.push({
      rule: "LOCKFILE_NO_VERSION",
      description:
        "package-lock.json has no lockfileVersion field. This indicates a very old or tampered lockfile.",
      severity: "medium",
      file: "package-lock.json",
      recommendation:
        "Regenerate the lockfile with a modern npm version (npm 7+).",
    });
    return;
  }

  if (version < MIN_LOCKFILE_VERSION) {
    findings.push({
      rule: "LOCKFILE_VERSION_DOWNGRADE",
      description: `package-lock.json uses lockfileVersion ${version}. Modern npm uses version ${MIN_LOCKFILE_VERSION}+. A downgraded lockfile may lack integrity checks.`,
      severity: "medium",
      file: "package-lock.json",
      recommendation:
        "Upgrade lockfile by running `npm install` with npm 7 or newer. Lockfile v1 lacks the `packages` field used for stricter validation.",
    });
  }
}

/**
 * Check v2/v3 packages entries for integrity and URL issues.
 */
function checkPackages(
  packages: LockfileV2Packages,
  findings: Finding[],
): void {
  for (const [pkgPath, entry] of Object.entries(packages)) {
    // Skip the root package entry (empty string key)
    if (pkgPath === "") continue;

    // Extract package name from path (e.g. "node_modules/lodash" -> "lodash")
    const pkgName = pkgPath.replace(/^node_modules\//, "");

    // Check integrity hash format
    if (entry.integrity) {
      checkIntegrityHash(entry.integrity, pkgName, "package-lock.json", findings);
    } else if (entry.resolved && !entry.link) {
      // Packages with a resolved URL should have integrity
      findings.push({
        rule: "LOCKFILE_MISSING_INTEGRITY",
        description: `Package "${pkgName}" has a resolved URL but no integrity hash. This bypasses tamper detection.`,
        severity: "high",
        file: "package-lock.json",
        recommendation: `Run \`npm install\` to regenerate integrity hashes. If this persists, the package source may not provide integrity data.`,
      });
    }

    // Check resolved URL
    if (entry.resolved) {
      checkResolvedUrl(entry.resolved, pkgName, "package-lock.json", findings);
    }
  }
}

/**
 * Check v1 dependencies entries.
 */
function checkDependencies(
  dependencies: LockfileDependencies,
  findings: Finding[],
): void {
  for (const [name, entry] of Object.entries(dependencies)) {
    // Check integrity
    if (entry.integrity) {
      checkIntegrityHash(entry.integrity, name, "package-lock.json", findings);
    }

    // Check resolved URL
    if (entry.resolved) {
      checkResolvedUrl(entry.resolved, name, "package-lock.json", findings);
    }

    // Recurse into nested dependencies
    if (entry.dependencies) {
      checkDependencies(entry.dependencies, findings);
    }
  }
}

// ---------------------------------------------------------------------------
// Shared checks (all formats)
// ---------------------------------------------------------------------------

/**
 * Standard parse-error finding for a corrupt or empty lockfile.
 */
function parseErrorFinding(lockfileName: string, installCmd: string): Finding {
  return {
    rule: "LOCKFILE_PARSE_ERROR",
    description: `Failed to parse ${lockfileName}. The file may be corrupted or empty.`,
    severity: "medium",
    file: lockfileName,
    recommendation: `Regenerate the lockfile with \`${installCmd}\`.`,
  };
}

/**
 * Run the format-agnostic threat checks on a normalized dependency:
 * integrity format, missing integrity, suspicious resolved URLs, and
 * known-compromised versions (ioc-blocklist).
 */
function checkParsedDependency(
  dep: ParsedLockDependency,
  lockfileName: string,
  findings: Finding[],
): void {
  if (dep.integrity) {
    if (dep.sriIntegrity) {
      checkIntegrityHash(dep.integrity, dep.name, lockfileName, findings);
    }
  } else if (dep.expectsIntegrity) {
    findings.push({
      rule: "LOCKFILE_MISSING_INTEGRITY",
      description: `Package "${dep.name}" has no integrity hash in ${lockfileName}. This bypasses tamper detection.`,
      severity: "high",
      file: lockfileName,
      recommendation:
        "Regenerate the lockfile with your package manager to restore integrity hashes. If this persists, the package source may not provide integrity data.",
    });
  }

  if (dep.resolved) {
    checkResolvedUrl(dep.resolved, dep.name, lockfileName, findings);
  }

  // Known-compromised versions (only meaningful for exact registry versions)
  if (dep.version && /^\d/.test(dep.version)) {
    const bad = checkBadVersion(dep.name, dep.version, "npm");
    if (bad) {
      findings.push({ ...bad, file: lockfileName });
    }
  }
}

/**
 * Verify integrity hash matches expected format.
 */
function checkIntegrityHash(
  integrity: string,
  pkgName: string,
  lockfileName: string,
  findings: Finding[],
): void {
  const hasValidPrefix = VALID_INTEGRITY_PREFIXES.some((prefix) =>
    integrity.startsWith(prefix),
  );

  if (!hasValidPrefix) {
    findings.push({
      rule: "LOCKFILE_INVALID_INTEGRITY",
      description: `Package "${pkgName}" has an integrity hash with unexpected format: "${integrity.substring(0, 30)}..."`,
      severity: "high",
      file: lockfileName,
      match: `${pkgName}: ${integrity.substring(0, 50)}`,
      recommendation:
        "Valid integrity hashes start with sha512-, sha256-, or sha1-. An invalid hash may indicate tampering.",
    });
  }

  // Check for suspiciously short hashes (potential truncation/tampering)
  const hashPart = integrity.split("-")[1] ?? "";
  if (hashPart.length < 20) {
    findings.push({
      rule: "LOCKFILE_SHORT_INTEGRITY",
      description: `Package "${pkgName}" has a suspiciously short integrity hash. This may indicate tampering.`,
      severity: "high",
      file: lockfileName,
      match: `${pkgName}: ${integrity}`,
      recommendation:
        "Regenerate the lockfile and compare integrity values.",
    });
  }
}

/**
 * Check if a resolved URL points to a non-registry source.
 */
function checkResolvedUrl(
  resolved: string,
  pkgName: string,
  lockfileName: string,
  findings: Finding[],
): void {
  // Skip if it's a known trusted registry
  const isTrusted = TRUSTED_REGISTRIES.some((registry) =>
    resolved.startsWith(registry),
  );

  if (!isTrusted) {
    // GitHub tarball URLs are somewhat common but still worth flagging
    if (
      resolved.startsWith("https://github.com/") ||
      resolved.startsWith("https://codeload.github.com/")
    ) {
      findings.push({
        rule: "LOCKFILE_GITHUB_RESOLVED",
        description: `Package "${pkgName}" resolves to a GitHub URL instead of the npm registry. This bypasses npm's integrity verification.`,
        severity: "medium",
        file: lockfileName,
        match: `${pkgName}: ${resolved}`,
        recommendation:
          "Prefer registry-published packages. GitHub-resolved packages can change without version bumps.",
      });
    } else if (resolved.startsWith("http://")) {
      // Plain HTTP is always suspicious
      findings.push({
        rule: "LOCKFILE_HTTP_RESOLVED",
        description: `Package "${pkgName}" resolves over plain HTTP (not HTTPS). This is vulnerable to MITM attacks.`,
        severity: "high",
        file: lockfileName,
        match: `${pkgName}: ${resolved}`,
        recommendation:
          "All package URLs should use HTTPS. Plain HTTP allows man-in-the-middle package replacement.",
      });
    } else if (!resolved.startsWith("https://")) {
      // Non-HTTPS, non-HTTP (could be file:, git:, etc.)
      findings.push({
        rule: "LOCKFILE_UNUSUAL_RESOLVED",
        description: `Package "${pkgName}" resolves from an unusual source: ${resolved.substring(0, 80)}`,
        severity: "medium",
        file: lockfileName,
        match: `${pkgName}: ${resolved.substring(0, 100)}`,
        recommendation:
          "Verify this package source is intentional and trusted.",
      });
    } else {
      // HTTPS but not a known registry
      findings.push({
        rule: "LOCKFILE_NONREGISTRY_RESOLVED",
        description: `Package "${pkgName}" resolves from a non-standard registry: ${resolved.substring(0, 80)}`,
        severity: "low",
        file: lockfileName,
        match: `${pkgName}: ${resolved.substring(0, 100)}`,
        recommendation:
          "Verify this custom registry is intentional. Packages from unknown registries may not be audited.",
      });
    }
  }
}

/**
 * Find dependencies in the lockfile that aren't declared in package.json.
 * Only checks top-level dependencies, not transitive ones.
 */
function checkOrphanedDependencies(
  lockfile: Lockfile,
  packageJson: PackageJson,
  findings: Finding[],
): void {
  // Collect all declared dependencies from package.json
  const declared = new Set<string>();
  for (const deps of [
    packageJson.dependencies,
    packageJson.devDependencies,
    packageJson.peerDependencies,
    packageJson.optionalDependencies,
  ]) {
    if (deps) {
      for (const name of Object.keys(deps)) {
        declared.add(name);
      }
    }
  }

  // Check v2 packages format
  if (lockfile.packages) {
    const orphaned: string[] = [];
    for (const pkgPath of Object.keys(lockfile.packages)) {
      // Only check direct dependencies (one level under node_modules)
      const match = pkgPath.match(/^node_modules\/(@[^/]+\/[^/]+|[^@/][^/]*)$/);
      if (!match) continue;

      const pkgName = match[1]!;
      if (!declared.has(pkgName)) {
        orphaned.push(pkgName);
      }
    }
    // Emit a single aggregated finding instead of one per package.
    // Modern npm v7+ lockfiles contain ALL transitive deps at the root level,
    // so individual findings would flood results for any non-trivial project.
    if (orphaned.length > 0) {
      const examples = orphaned.slice(0, 5).join(", ");
      const suffix = orphaned.length > 5 ? ` and ${orphaned.length - 5} more` : "";
      findings.push({
        rule: "LOCKFILE_ORPHANED_DEPENDENCY",
        description: `${orphaned.length} package(s) in lockfile are not declared in package.json (likely transitive deps): ${examples}${suffix}.`,
        severity: "info",
        file: "package-lock.json",
        // v5.2.20: corrected recommendation. npm v7+ lockfile format
        // intentionally includes ALL transitive dependencies at the root
        // node_modules/ level (flat install). These are NOT orphans in the
        // pre-npm-v7 sense and `npm prune` will not remove them. Only act if
        // the listed names look unexpected from a supply-chain perspective.
        recommendation:
          "npm v7+ lockfiles include transitive dependencies at the root node_modules/ level by design - these are not orphans. Verify the listed packages come from trusted publishers; if any are unexpected, investigate the dependency tree with `npm ls <name>`.",
      });
    }
  }
}

// ---------------------------------------------------------------------------
// pnpm: pnpm-lock.yaml
// ---------------------------------------------------------------------------

/**
 * Check pnpm-lock.yaml for lockfile issues.
 * Supports v6 ("/name@1.2.3") and v9 ("name@1.2.3") package-key styles.
 */
export function checkPnpmLockfile(dir: string): Finding[] {
  const lockfileName = "pnpm-lock.yaml";
  const lockfilePath = path.join(dir, lockfileName);
  if (!fs.existsSync(lockfilePath)) return [];

  let content: string;
  try {
    content = fs.readFileSync(lockfilePath, "utf-8");
  } catch {
    return [];
  }

  const deps = parsePnpmLock(content);
  if (deps === null) {
    return [parseErrorFinding(lockfileName, "pnpm install")];
  }

  const findings: Finding[] = [];
  for (const dep of deps) {
    checkParsedDependency(dep, lockfileName, findings);
  }
  return findings;
}

/**
 * Hand-rolled indentation-based extraction of the `packages:` section of a
 * pnpm-lock.yaml. Returns null when the file does not look like a pnpm
 * lockfile at all (corrupt or empty).
 */
function parsePnpmLock(content: string): ParsedLockDependency[] | null {
  if (content.trim().length === 0) return null;
  const lines = content.split(/\r?\n/);

  // Every pnpm lockfile starts with a lockfileVersion key
  if (!lines.some((l) => l.startsWith("lockfileVersion"))) return null;

  const deps: ParsedLockDependency[] = [];
  let inPackages = false;
  let current: ParsedLockDependency | null = null;

  const flush = (): void => {
    if (current) deps.push(current);
    current = null;
  };

  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+$/, "");
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;

    const indent = line.length - line.trimStart().length;

    // Top-level section headers (packages:, snapshots:, importers:, ...)
    if (indent === 0) {
      flush();
      inPackages = line === "packages:";
      continue;
    }
    if (!inPackages) continue;

    // Package keys sit at 2-space indentation, e.g.
    //   /lodash@4.17.21:            (v6)
    //   lodash@4.17.21:             (v9)
    //   '@scope/pkg@1.0.0':         (quoted)
    if (indent === 2 && line.endsWith(":")) {
      flush();
      current = parsePnpmPackageKey(trimmed.slice(0, -1));
      continue;
    }

    // Package properties (resolution, engines, ...) at deeper indentation
    if (current === null || indent < 4) continue;
    const cur: ParsedLockDependency = current;

    const integrity = /integrity: ['"]?(sha[^,'"}\s]+)/.exec(trimmed);
    if (integrity) cur.integrity = integrity[1]!;

    const tarball = /tarball: ['"]?([^,'"}\s]+)/.exec(trimmed);
    if (tarball) cur.resolved = tarball[1]!;

    const repo = /\brepo: ['"]?([^,'"}\s]+)/.exec(trimmed);
    if (repo) {
      cur.resolved = repo[1]!;
      cur.expectsIntegrity = false;
    }

    // Git resolutions carry a commit hash instead of an integrity hash
    if (/\btype: git\b/.test(trimmed)) cur.expectsIntegrity = false;
  }
  flush();
  return deps;
}

/**
 * Parse a pnpm packages-section key into name + version/URL.
 * Handles v6 leading slashes, quoting, scoped packages, and
 * peer-dependency suffixes like "foo@1.0.0(react@18.2.0)".
 */
function parsePnpmPackageKey(rawKey: string): ParsedLockDependency | null {
  let key = rawKey.replace(/^['"]/, "").replace(/['"]$/, "");

  // Strip peer-dependency suffix
  const paren = key.indexOf("(");
  if (paren > 0) key = key.slice(0, paren);

  // v6 keys are prefixed with "/"
  if (key.startsWith("/")) key = key.slice(1);

  const at = key.lastIndexOf("@");
  if (at <= 0) return null;
  const name = key.slice(0, at);
  const spec = key.slice(at + 1);
  if (name === "" || spec === "") return null;

  // Local links/workspaces carry no auditable source
  if (spec.startsWith("link:") || spec.startsWith("workspace:")) return null;

  // Non-registry specifier (git/tarball/local file)
  if (/^(git\+|https?:\/\/|file:)/.test(spec)) {
    return { name, resolved: spec, expectsIntegrity: false, sriIntegrity: true };
  }

  return { name, version: spec, expectsIntegrity: true, sriIntegrity: true };
}

// ---------------------------------------------------------------------------
// yarn: yarn.lock (classic v1 and Berry v2+)
// ---------------------------------------------------------------------------

/**
 * Check yarn.lock for lockfile issues. Detects classic v1 (entry headers
 * like 'name@^1.0.0:') and Berry v2+ (YAML with __metadata, keys like
 * "name@npm:^1.0.0") automatically.
 */
export function checkYarnLockfile(dir: string): Finding[] {
  const lockfileName = "yarn.lock";
  const lockfilePath = path.join(dir, lockfileName);
  if (!fs.existsSync(lockfilePath)) return [];

  let content: string;
  try {
    content = fs.readFileSync(lockfilePath, "utf-8");
  } catch {
    return [];
  }

  const deps = parseYarnLock(content);
  if (deps === null) {
    return [parseErrorFinding(lockfileName, "yarn install")];
  }

  const findings: Finding[] = [];
  for (const dep of deps) {
    checkParsedDependency(dep, lockfileName, findings);
  }
  return findings;
}

/**
 * Parse a yarn.lock of either generation. Returns null when the file does
 * not look like a yarn lockfile at all (corrupt or empty).
 */
function parseYarnLock(content: string): ParsedLockDependency[] | null {
  if (content.trim().length === 0) return null;
  if (/^__metadata:/m.test(content)) {
    return parseYarnBerry(content);
  }
  return parseYarnClassic(content);
}

/**
 * Parse classic yarn.lock v1 entries:
 *   lodash@^4.17.20, lodash@^4.17.21:
 *     version "4.17.21"
 *     resolved "https://registry.yarnpkg.com/..."
 *     integrity sha512-...
 */
function parseYarnClassic(content: string): ParsedLockDependency[] | null {
  const lines = content.split(/\r?\n/);
  const hasMarker = lines.some((l) => l.includes("yarn lockfile v1"));

  const deps: ParsedLockDependency[] = [];
  let current: ParsedLockDependency | null = null;

  const flush = (): void => {
    if (current) deps.push(current);
    current = null;
  };

  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+$/, "");
    if (line === "" || line.startsWith("#")) continue;

    // Entry headers sit at zero indentation and end with ":"
    if (!line.startsWith(" ") && line.endsWith(":")) {
      flush();
      current = parseYarnHeaderSpec(line.slice(0, -1));
      continue;
    }
    if (current === null) continue;
    const cur: ParsedLockDependency = current;

    let m = /^ {2}version "([^"]+)"/.exec(line);
    if (m) {
      cur.version = m[1]!;
      continue;
    }
    m = /^ {2}resolved "([^"]+)"/.exec(line);
    if (m) {
      cur.resolved = m[1]!;
      // A registry tarball without an integrity line lacks tamper detection
      cur.expectsIntegrity = true;
      continue;
    }
    m = /^ {2}integrity (\S+)/.exec(line);
    if (m) {
      cur.integrity = m[1]!;
      continue;
    }
  }
  flush();

  // Neither the v1 marker comment nor a single parseable entry: corrupt
  if (deps.length === 0 && !hasMarker) return null;
  return deps;
}

/**
 * Parse yarn Berry (v2+) entries:
 *   "lodash@npm:^4.17.21":
 *     version: 4.17.21
 *     resolution: "lodash@npm:4.17.21"
 *     checksum: 10c0/...
 *     linkType: hard
 */
function parseYarnBerry(content: string): ParsedLockDependency[] {
  const lines = content.split(/\r?\n/);
  const deps: ParsedLockDependency[] = [];
  let current: ParsedLockDependency | null = null;

  const flush = (): void => {
    if (current) deps.push(current);
    current = null;
  };

  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+$/, "");
    if (line === "" || line.startsWith("#")) continue;

    if (!line.startsWith(" ") && line.endsWith(":")) {
      flush();
      const header = line.slice(0, -1);
      current = header === "__metadata" ? null : parseYarnBerryHeader(header);
      continue;
    }
    if (current === null) continue;
    const cur: ParsedLockDependency = current;

    let m = /^ {2}version: "?([^"\s]+)"?/.exec(line);
    if (m) {
      cur.version = m[1]!;
      continue;
    }
    m = /^ {2}checksum: (\S+)/.exec(line);
    if (m) {
      cur.integrity = m[1]!;
      continue;
    }
    // Soft links (workspaces resolved on disk) carry no checksum
    if (/^ {2}linkType: soft\b/.test(line)) {
      cur.expectsIntegrity = false;
    }
  }
  flush();
  return deps;
}

/**
 * Parse a Berry entry header like "name@npm:^1.0.0" (possibly a
 * comma-separated alias list). Local protocols (workspace/link/portal/
 * patch) are skipped; they have no auditable remote source.
 */
function parseYarnBerryHeader(header: string): ParsedLockDependency | null {
  const firstSpec = (header.split(",")[0] ?? "").trim().replace(/^"/, "").replace(/"$/, "");
  const at = firstSpec.lastIndexOf("@");
  if (at <= 0) return null;
  const name = firstSpec.slice(0, at);
  const descriptor = firstSpec.slice(at + 1);

  if (/^(workspace:|link:|portal:|patch:|virtual:)/.test(descriptor)) {
    return null;
  }
  // Remote tarball: Berry still records a checksum for these
  if (/^https?:\/\//.test(descriptor)) {
    return { name, resolved: descriptor, expectsIntegrity: true, sriIntegrity: false };
  }
  // Git sources: pinned by commit instead of checksum
  if (/^(git|github:|ssh:)/.test(descriptor)) {
    return { name, resolved: descriptor, expectsIntegrity: false, sriIntegrity: false };
  }
  // npm: protocol (registry package)
  return { name, expectsIntegrity: true, sriIntegrity: false };
}

/**
 * Parse a classic v1 header spec like 'lodash@^4.17.21' (possibly a
 * comma-separated alias list, possibly quoted).
 */
function parseYarnHeaderSpec(header: string): ParsedLockDependency | null {
  const firstSpec = (header.split(",")[0] ?? "").trim().replace(/^"/, "").replace(/"$/, "");
  const at = firstSpec.lastIndexOf("@");
  if (at <= 0) return null;
  const name = firstSpec.slice(0, at);
  if (name === "") return null;
  return { name, expectsIntegrity: false, sriIntegrity: true };
}

// ---------------------------------------------------------------------------
// bun: bun.lock (JSONC) and bun.lockb (binary)
// ---------------------------------------------------------------------------

/**
 * Check bun lockfiles. The text lockfile (bun.lock, JSONC) is parsed and
 * audited; the binary lockfile (bun.lockb) cannot be audited and is flagged
 * with a low-severity finding instead. When both exist, bun uses the text
 * lockfile, so the binary one is not flagged.
 */
export function checkBunLockfile(dir: string): Finding[] {
  const findings: Finding[] = [];
  const textPath = path.join(dir, "bun.lock");
  const binaryPath = path.join(dir, "bun.lockb");

  if (!fs.existsSync(textPath)) {
    if (fs.existsSync(binaryPath)) {
      findings.push({
        rule: "LOCKFILE_BUN_BINARY_UNAUDITABLE",
        description:
          "bun.lockb is a binary lockfile and cannot be audited for tampered integrity hashes, suspicious registry URLs, or known-compromised versions.",
        severity: "low",
        confidence: 1.0,
        category: "supply-chain",
        file: "bun.lockb",
        recommendation:
          "Migrate to the text lockfile with `bun install --save-text-lockfile` (bun >= 1.2) so supply-chain scanners and code review can audit dependency sources.",
      });
    }
    return findings;
  }

  let raw: string;
  try {
    raw = fs.readFileSync(textPath, "utf-8");
  } catch {
    return findings;
  }

  let lock: unknown;
  try {
    lock = JSON.parse(stripJsonc(raw)) as unknown;
  } catch {
    findings.push(parseErrorFinding("bun.lock", "bun install"));
    return findings;
  }

  const packages = (lock as { packages?: unknown }).packages;
  if (packages && typeof packages === "object") {
    for (const entry of Object.values(packages as Record<string, unknown>)) {
      const dep = parseBunPackageEntry(entry);
      if (dep) checkParsedDependency(dep, "bun.lock", findings);
    }
  }
  return findings;
}

/**
 * Parse a bun.lock packages entry. Entries are arrays like
 *   ["lodash@4.17.21", "", { ...meta }, "sha512-..."]
 * where the second element is a registry/tarball URL for non-default
 * registries and the trailing string is the SRI integrity hash.
 */
function parseBunPackageEntry(entry: unknown): ParsedLockDependency | null {
  if (!Array.isArray(entry) || entry.length === 0) return null;
  const spec: unknown = entry[0];
  if (typeof spec !== "string") return null;

  const at = spec.lastIndexOf("@");
  if (at <= 0) return null;
  const name = spec.slice(0, at);
  const specifier = spec.slice(at + 1);
  if (specifier.startsWith("workspace:")) return null;

  let integrity: string | undefined;
  let resolved: string | undefined;
  for (let i = 1; i < entry.length; i++) {
    const el: unknown = entry[i];
    if (typeof el !== "string" || el === "") continue;
    if (/^sha(512|256|1)-/.test(el)) {
      integrity = el;
    } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(el)) {
      resolved = el;
    }
  }

  // Plain version: registry package, integrity expected
  if (/^\d/.test(specifier)) {
    return {
      name,
      version: specifier,
      resolved,
      integrity,
      expectsIntegrity: true,
      sriIntegrity: true,
    };
  }

  // Git/tarball/other specifier: audit the source URL instead
  return {
    name,
    resolved: resolved ?? specifier,
    integrity,
    expectsIntegrity: false,
    sriIntegrity: true,
  };
}

/**
 * Strip JSONC comments and trailing commas so the result parses as strict
 * JSON. String-aware: comment markers and commas inside string literals are
 * preserved.
 */
function stripJsonc(text: string): string {
  // Pass 1: remove // line comments and /* */ block comments
  let noComments = "";
  let inString = false;
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (inString) {
      noComments += ch;
      if (ch === "\\" && i + 1 < text.length) {
        noComments += text[i + 1]!;
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i++;
      continue;
    }
    if (ch === '"') {
      inString = true;
      noComments += ch;
      i++;
      continue;
    }
    if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    noComments += ch;
    i++;
  }

  // Pass 2: remove trailing commas before } or ]
  let result = "";
  inString = false;
  for (let j = 0; j < noComments.length; j++) {
    const ch = noComments[j]!;
    if (inString) {
      result += ch;
      if (ch === "\\" && j + 1 < noComments.length) {
        result += noComments[j + 1]!;
        j++;
        continue;
      }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      result += ch;
      continue;
    }
    if (ch === ",") {
      let k = j + 1;
      while (k < noComments.length && /\s/.test(noComments[k]!)) k++;
      if (k < noComments.length && (noComments[k] === "}" || noComments[k] === "]")) {
        continue;
      }
    }
    result += ch;
  }
  return result;
}
