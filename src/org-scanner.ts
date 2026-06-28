/**
 * Organization-level scanner (v4.5).
 *
 * Scans all repositories in a GitHub organization for shared
 * malicious patterns, compromised maintainers, and suspicious clusters.
 */

import { execFileSync } from "node:child_process";
import type { Finding } from "./types.js";

// GitHub org / user names: alphanumeric with hyphens, up to 39 chars, and may
// not begin with a hyphen. Forbidding a leading hyphen stops the value from being
// read as a gh flag; the allowlist also keeps shell metacharacters out even
// though execFileSync already runs gh without a shell (defense in depth).
const ORG_NAME = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/;

/**
 * List repositories in a GitHub organization via `gh` CLI.
 */
export function listOrgRepos(org: string, limit = 50): string[] {
  if (!ORG_NAME.test(org) || !Number.isInteger(limit) || limit < 1 || limit > 1000) {
    return [];
  }
  try {
    const output = execFileSync(
      "gh",
      ["repo", "list", org, "--limit", String(limit), "--json", "url", "--jq", ".[].url"],
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    return output.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Analyze findings across multiple repos for shared patterns.
 */
export function analyzeOrgFindings(
  repoFindings: Map<string, Finding[]>,
): Finding[] {
  const findings: Finding[] = [];
  const ruleFrequency = new Map<string, string[]>();

  // Count how many repos share each rule
  for (const [repo, repoResults] of repoFindings) {
    const rules = new Set(repoResults.map((f) => f.rule));
    for (const rule of rules) {
      if (!ruleFrequency.has(rule)) ruleFrequency.set(rule, []);
      ruleFrequency.get(rule)!.push(repo);
    }
  }

  // Flag patterns appearing in multiple repos
  for (const [rule, repos] of ruleFrequency) {
    if (repos.length >= 3) {
      findings.push({
        rule: "ORG_SHARED_MALICIOUS_PATTERN",
        description: `Rule "${rule}" triggered in ${repos.length} repos across the organization. This may indicate a coordinated compromise or shared vulnerable dependency.`,
        severity: "critical",
        confidence: Math.min(1.0, 0.5 + repos.length * 0.1),
        category: "supply-chain",
        recommendation: `Investigate why ${rule} appears in multiple repos: ${repos.slice(0, 5).join(", ")}`,
      });
    }
  }

  // Check for unusual repo clusters (many repos created recently with similar names)
  const repoNames = [...repoFindings.keys()];
  if (repoNames.length > 10) {
    const reposWithFindings = [...repoFindings.entries()].filter(
      ([, f]) => f.some((finding) => finding.severity === "critical"),
    );
    if (reposWithFindings.length > repoNames.length * 0.5) {
      findings.push({
        rule: "ORG_REPO_CLUSTER_ANOMALY",
        description: `${reposWithFindings.length} of ${repoNames.length} repos have critical findings. This organization may be compromised.`,
        severity: "high",
        confidence: 0.7,
        category: "trust",
        recommendation: "Review the organization's maintainer accounts and access controls.",
      });
    }
  }

  return findings;
}
