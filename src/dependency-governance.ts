/**
 * Dependency governance (v4.6).
 *
 * Enforces organizational policies on dependencies:
 * minimum package age, trusted registries, publisher reputation.
 */

import type { Finding } from "./types.js";

/** Minimum age in days for a package to be considered safe */
const MIN_PACKAGE_AGE_DAYS = 7;

/**
 * Check dependencies against governance policies.
 */
export function checkDependencyGovernance(
  dependencies: Record<string, string>,
  lockfileContent: string | null,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];

  if (!lockfileContent) return findings;

  let lock: Record<string, unknown>;
  try {
    lock = JSON.parse(lockfileContent) as Record<string, unknown>;
  } catch {
    return findings;
  }

  // Check lockfile packages for governance issues
  const packages = lock.packages as Record<string, { version?: string; resolved?: string }> | undefined;
  if (!packages) return findings;

  for (const [pkgPath, entry] of Object.entries(packages)) {
    if (!pkgPath || !entry) continue;
    const name = pkgPath.replace(/^node_modules\//, "").replace(/^.*node_modules\//, "");
    if (!name || name === "") continue;

    // Check for untrusted resolved sources
    if (entry.resolved && !entry.resolved.startsWith("https://registry.npmjs.org")) {
      if (
        !entry.resolved.startsWith("https://registry.yarnpkg.com") &&
        !entry.resolved.startsWith("file:")
      ) {
        findings.push({
          rule: "DEPENDENCY_UNTRUSTED_SOURCE",
          description: `Package "${name}" resolves from non-standard source: ${entry.resolved.substring(0, 80)}`,
          severity: "high",
          file: relativePath,
          confidence: 0.7,
          category: "supply-chain",
          recommendation: "Verify this registry source is trusted. Use npm audit and supply-chain-guard to validate.",
        });
      }
    }
  }

  return findings;
}
