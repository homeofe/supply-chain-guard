/**
 * Dependency governance (v4.6).
 *
 * Enforces organizational policies on dependencies:
 * minimum package age, trusted registries, publisher reputation.
 */

import type { Finding } from "./types.js";

/** Minimum age in days for a package to be considered safe */
const MIN_PACKAGE_AGE_DAYS = 7;

/** Registries whose tarballs a lockfile may resolve to without a finding. */
const TRUSTED_REGISTRY_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);

/**
 * Whether a lockfile `resolved` value points at a trusted registry.
 *
 * Decided on the parsed host, not on a string prefix: `startsWith(
 * "https://registry.npmjs.org")` also accepted
 * "https://registry.npmjs.org.attacker.example/pkg.tgz", so a lockfile could
 * point a package at any host that begins with the registry's name and raise
 * no finding (CodeQL js/incomplete-url-substring-sanitization). Credentials or
 * a port in the URL make it untrusted too. `file:` stays trusted, as before.
 */
export function isTrustedResolved(resolved: string): boolean {
  if (resolved.startsWith("file:")) return true;
  let url: URL;
  try {
    url = new URL(resolved);
  } catch {
    return false;
  }
  return (
    url.protocol === "https:" &&
    TRUSTED_REGISTRY_HOSTS.has(url.hostname) &&
    url.port === "" &&
    url.username === "" &&
    url.password === ""
  );
}

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
    if (entry.resolved && !isTrustedResolved(entry.resolved)) {
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

  return findings;
}
