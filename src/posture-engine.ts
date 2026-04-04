/**
 * Organization risk posture engine (v4.7).
 *
 * Aggregates scan results across multiple repos into a portfolio view
 * with posture scores, recurring patterns, and systemic risks.
 */

import type { Finding, ScanReport, Severity } from "./types.js";

export interface OrgPosture {
  organization: string;
  reposScanned: number;
  overallPostureScore: number;
  topRiskyRepos: Array<{ repo: string; score: number; criticalCount: number }>;
  recurringPackages: Array<{ name: string; repos: string[]; severity: Severity }>;
  recurringActions: Array<{ action: string; repos: string[]; pinned: boolean }>;
  systemicFindings: Finding[];
}

/**
 * Calculate organization-wide risk posture from multiple scan reports.
 */
export function calculateOrgPosture(
  org: string,
  reports: Map<string, ScanReport>,
): OrgPosture {
  const repoScores: Array<{ repo: string; score: number; criticalCount: number }> = [];
  const packageUsage = new Map<string, { repos: Set<string>; severity: Severity }>();
  const actionUsage = new Map<string, { repos: Set<string>; pinned: boolean }>();
  const systemicFindings: Finding[] = [];

  for (const [repo, report] of reports) {
    repoScores.push({
      repo,
      score: report.score,
      criticalCount: report.summary.critical,
    });

    // Track recurring risky packages
    for (const f of report.findings) {
      if (f.rule === "IOC_KNOWN_BAD_VERSION" || f.rule.startsWith("TYPOSQUAT_")) {
        const pkg = f.description.match(/"([^"]+)"/)?.[1] ?? f.rule;
        if (!packageUsage.has(pkg)) {
          packageUsage.set(pkg, { repos: new Set(), severity: f.severity });
        }
        packageUsage.get(pkg)!.repos.add(repo);
      }

      // Track recurring risky actions
      if (f.rule === "GHA_UNPINNED_ACTION") {
        const action = f.match?.match(/uses:\s*(\S+)/)?.[1] ?? "unknown";
        if (!actionUsage.has(action)) {
          actionUsage.set(action, { repos: new Set(), pinned: false });
        }
        actionUsage.get(action)!.repos.add(repo);
      }
    }
  }

  // Systemic policy drift: >50% repos have same policy violation
  const ruleFreq = new Map<string, number>();
  for (const [, report] of reports) {
    const rules = new Set(report.findings.map((f) => f.rule));
    for (const r of rules) ruleFreq.set(r, (ruleFreq.get(r) ?? 0) + 1);
  }

  for (const [rule, count] of ruleFreq) {
    if (count >= reports.size * 0.5 && count >= 3) {
      systemicFindings.push({
        rule: "ORG_SYSTEMIC_POLICY_DRIFT",
        description: `Rule "${rule}" triggers in ${count}/${reports.size} repos. Systemic issue requiring org-wide remediation.`,
        severity: "high",
        confidence: Math.min(1.0, 0.5 + count * 0.05),
        category: "supply-chain",
        recommendation: `Address "${rule}" across the organization with a shared policy or dependency update.`,
      });
    }
  }

  // Overall posture score (average of repo scores, capped)
  const avgScore = repoScores.length > 0
    ? repoScores.reduce((s, r) => s + r.score, 0) / repoScores.length
    : 0;

  return {
    organization: org,
    reposScanned: reports.size,
    overallPostureScore: Math.round(avgScore),
    topRiskyRepos: repoScores
      .sort((a, b) => b.score - a.score)
      .slice(0, 10),
    recurringPackages: [...packageUsage.entries()]
      .filter(([, v]) => v.repos.size >= 2)
      .map(([name, v]) => ({ name, repos: [...v.repos], severity: v.severity })),
    recurringActions: [...actionUsage.entries()]
      .filter(([, v]) => v.repos.size >= 2)
      .map(([action, v]) => ({ action, repos: [...v.repos], pinned: v.pinned })),
    systemicFindings,
  };
}
