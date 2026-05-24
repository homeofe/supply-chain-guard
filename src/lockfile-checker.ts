/**
 * Lockfile integrity verification (T-006)
 *
 * Parses package-lock.json and checks for:
 * - Integrity hashes matching expected format (sha512/sha256/sha1)
 * - Packages resolved from non-registry URLs
 * - Dependencies in lockfile but not in package.json
 * - Lockfile version downgrades
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";

/** Expected npm registry URL prefix */
const NPM_REGISTRY_PREFIX = "https://registry.npmjs.org/";

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
 * Check a directory for lockfile issues.
 * Returns findings if a lockfile is present.
 */
export function checkLockfile(dir: string): Finding[] {
  const lockfilePath = path.join(dir, "package-lock.json");
  const packageJsonPath = path.join(dir, "package.json");

  if (!fs.existsSync(lockfilePath)) {
    return [];
  }

  let lockfile: Lockfile;
  try {
    lockfile = JSON.parse(fs.readFileSync(lockfilePath, "utf-8")) as Lockfile;
  } catch {
    return [
      {
        rule: "LOCKFILE_PARSE_ERROR",
        description: "Failed to parse package-lock.json. The file may be corrupted.",
        severity: "medium",
        file: "package-lock.json",
        recommendation: "Regenerate the lockfile with `npm install`.",
      },
    ];
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
      checkIntegrityHash(entry.integrity, pkgName, findings);
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
      checkResolvedUrl(entry.resolved, pkgName, findings);
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
      checkIntegrityHash(entry.integrity, name, findings);
    }

    // Check resolved URL
    if (entry.resolved) {
      checkResolvedUrl(entry.resolved, name, findings);
    }

    // Recurse into nested dependencies
    if (entry.dependencies) {
      checkDependencies(entry.dependencies, findings);
    }
  }
}

/**
 * Verify integrity hash matches expected format.
 */
function checkIntegrityHash(
  integrity: string,
  pkgName: string,
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
      file: "package-lock.json",
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
      file: "package-lock.json",
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
        file: "package-lock.json",
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
        file: "package-lock.json",
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
        file: "package-lock.json",
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
        file: "package-lock.json",
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
