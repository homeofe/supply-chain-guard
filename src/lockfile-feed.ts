/**
 * Threat-feed matching for npm lockfiles (package-lock.json, yarn.lock,
 * pnpm-lock.yaml, bun.lock).
 *
 * A lockfile is the only place a TRANSITIVE dependency appears, so it is the
 * only place a malicious package pulled in by another package can be seen.
 * Two findings:
 *   - LOCKFILE_MALICIOUS_VERSION: the resolved version is pinned in the feed.
 *   - LOCKFILE_MALICIOUS_PACKAGE: the package is listed as malicious in every
 *     version (a whole-name entry).
 *
 * No package is reported twice:
 *   - once per name (and version) per lockfile, however deeply it is nested;
 *   - a whole-name hit is skipped when the sibling package.json already reports
 *     it (MALICIOUS_DEPENDENCY), using the SAME candidate logic as that check,
 *     including npm aliases;
 *   - anything the hand-kept KNOWN_BAD_NPM_VERSIONS list covers is left to the
 *     IOC_KNOWN_BAD_VERSION finding the lockfile checkers already emit.
 *
 * Before 2026-09-23 whole-name entries were deliberately not reported here, on
 * the premise that "they already fire on the package.json path". That premise
 * holds only for DIRECT dependencies, so a transitive malicious package was
 * reported by nothing; and yarn/pnpm/bun lockfiles were never matched against
 * the feed at all.
 */

import type { Finding } from "./types.js";
import type { FeedIOC } from "./threat-intel.js";
import { matchBareNpmIOC } from "./install-guard.js";
import { checkBadVersion } from "./ioc-blocklist.js";
import { resolveNpmAlias } from "./dependency-risk-analyzer.js";
import { parseJsonObject } from "./json-utils.js";

export interface LockfileDependency {
  name: string;
  version?: string;
}

type DependencyGroup = Record<string, string> | undefined;

/**
 * The installed package for every manifest dependency entry: the alias target
 * for `npm:` aliases, otherwise the key. Shared with the package.json check so
 * the two cannot disagree about what the manifest already reports.
 */
export function manifestDependencyCandidates(
  pkg: Record<string, unknown>,
): Map<string, { name: string; version?: string; alias?: string }> {
  const candidates = new Map<string, { name: string; version?: string; alias?: string }>();
  for (const group of [
    pkg.dependencies as DependencyGroup,
    pkg.devDependencies as DependencyGroup,
    pkg.optionalDependencies as DependencyGroup,
    pkg.peerDependencies as DependencyGroup,
  ]) {
    for (const [key, spec] of Object.entries(group ?? {})) {
      const alias = resolveNpmAlias(spec);
      const candidate = alias
        ? { name: alias.name, version: alias.version, alias: key }
        : { name: key, version: undefined as string | undefined };
      candidates.set(`${candidate.name}@${candidate.version ?? ""}`, candidate);
    }
  }
  return candidates;
}

/**
 * Package names the package.json check reports on its own. Parsed the same
 * way that check parses, so an unparseable manifest reports nothing and
 * therefore excuses nothing here.
 */
export function manifestReportedNames(manifestContent: string | null): Set<string> {
  if (manifestContent === null) return new Set();
  const pkg = parseJsonObject(manifestContent);
  if (!pkg) return new Set();
  return new Set([...manifestDependencyCandidates(pkg).values()].map((c) => c.name));
}

/**
 * Feed findings for the dependencies a lockfile resolves.
 */
export function lockfileFeedFindings(
  deps: readonly LockfileDependency[],
  file: string,
  reportedByManifest: ReadonlySet<string>,
  feed: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const { name, version } of deps) {
    if (!name) continue;
    if (version && checkBadVersion(name, version, "npm")) continue;
    const ioc = matchBareNpmIOC(name, version, feed);
    if (!ioc) continue;
    const attrib = ioc.campaign ? ` (campaign: ${ioc.campaign})` : "";
    const pinned = ioc.value.lastIndexOf("@") > 0;

    if (pinned) {
      const key = `v:${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        rule: "LOCKFILE_MALICIOUS_VERSION",
        description: `Lockfile resolves "${name}" to ${version}, a version listed in the threat feed as malicious${attrib}.`,
        severity: "critical",
        confidence: ioc.confidence ?? 0.95,
        category: "supply-chain",
        file,
        match: `${name}@${version}`,
        recommendation: `Remove ${name}@${version}. Update the lockfile to a clean version and rotate any credentials the install may have had access to.`,
      });
      continue;
    }

    if (reportedByManifest.has(name)) continue;
    const key = `p:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      rule: "LOCKFILE_MALICIOUS_PACKAGE",
      description: `Lockfile resolves "${name}", a package the threat feed lists as malicious in every version${attrib}. It is not a direct dependency, so another package pulls it in.`,
      severity: "critical",
      confidence: ioc.confidence ?? 0.95,
      category: "supply-chain",
      file,
      match: version ? `${name}@${version}` : name,
      recommendation: `Find which dependency pulls in ${name} (npm ls ${name}), remove or replace it, regenerate the lockfile, and rotate any credentials the install may have had access to.`,
    });
  }
  return findings;
}
