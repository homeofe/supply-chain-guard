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
export function isTrustedResolved(resolved: unknown): boolean {
  // A non-string `resolved` is malformed lockfile data, never trusted.
  if (typeof resolved !== "string") return false;
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
  if (!lock || typeof lock !== "object") return findings;

  // A v2 lockfile lists each package under both `packages` and `dependencies`.
  const seen = new Set<string>();
  const report = (name: string, resolved: unknown): void => {
    if (resolved === undefined || resolved === null || resolved === "") return;
    if (isTrustedResolved(resolved)) return;
    const key = `${name}\0${typeof resolved === "string" ? resolved : typeof resolved}`;
    if (seen.has(key)) return;
    seen.add(key);
    const shown = typeof resolved === "string" ? resolved.substring(0, 80) : `<${typeof resolved} value>`;
    findings.push({
      rule: "DEPENDENCY_UNTRUSTED_SOURCE",
      description: `Package "${name}" resolves from non-standard source: ${shown}`,
      severity: "high",
      file: relativePath,
      confidence: 0.7,
      category: "supply-chain",
      recommendation: "Verify this registry source is trusted. Use npm audit and supply-chain-guard to validate.",
    });
  };

  // Lockfile v2/v3 `packages`
  const packages = lock.packages;
  if (packages && typeof packages === "object") {
    for (const [pkgPath, entry] of Object.entries(packages as Record<string, unknown>)) {
      if (!pkgPath || !entry || typeof entry !== "object") continue;
      const name = pkgPath.replace(/^node_modules\//, "").replace(/^.*node_modules\//, "");
      if (!name) continue;
      report(name, (entry as { resolved?: unknown }).resolved);
    }
  }

  // Lockfile v1 (and the v2 compatibility copy) `dependencies`, nested
  const walk = (deps: unknown, depth: number): void => {
    if (!deps || typeof deps !== "object" || depth > 64) return;
    for (const [name, entry] of Object.entries(deps as Record<string, unknown>)) {
      if (!entry || typeof entry !== "object") continue;
      report(name, (entry as { resolved?: unknown }).resolved);
      walk((entry as { dependencies?: unknown }).dependencies, depth + 1);
    }
  };
  walk(lock.dependencies, 0);

  return findings;
}
