/**
 * Security metrics & KPI engine (v4.8).
 *
 * Calculates key security metrics from scan history,
 * triage decisions, and current findings.
 */

import type { Finding, RiskHistoryEntry, TriageDecision, SecurityMetrics } from "./types.js";

/**
 * Calculate security metrics from findings, history, and triage data.
 */
export function calculateMetrics(
  findings: Finding[],
  history: RiskHistoryEntry[],
  decisions: TriageDecision[],
): SecurityMetrics {
  // Open findings by severity
  const resolvedRules = new Set(
    decisions.filter((d) => d.status === "resolved").map((d) => d.findingRule),
  );
  const openFindings = findings.filter((f) => !resolvedRules.has(f.rule) && f.severity !== "info");
  const openCritical = openFindings.filter((f) => f.severity === "critical").length;
  const openHigh = openFindings.filter((f) => f.severity === "high").length;

  // MTTR for critical findings (days)
  const resolvedCritical = decisions.filter(
    (d) => d.status === "resolved" && d.findingRule.includes("CRITICAL"),
  );
  let mttrCritical: number | undefined;
  if (resolvedCritical.length > 0) {
    // This would need creation timestamps in a real implementation
    // For now, estimate from triage-to-resolution time
    mttrCritical = undefined; // Placeholder
  }

  // SLA compliance rate
  const totalTriaged = decisions.filter(
    (d) => d.status !== "new",
  ).length;
  const resolved = decisions.filter(
    (d) => d.status === "resolved" || d.status === "false-positive",
  ).length;
  const slaComplianceRate = totalTriaged > 0 ? Math.round((resolved / totalTriaged) * 100) : 100;

  // Risk trend
  let riskTrend: "increasing" | "stable" | "decreasing" = "stable";
  if (history.length >= 3) {
    const recent = history.slice(-3).map((h) => h.score);
    if (recent[2] > recent[0] + 5) riskTrend = "increasing";
    else if (recent[2] < recent[0] - 5) riskTrend = "decreasing";
  }

  // Top risk contributors (most frequent critical/high rules)
  const ruleCounts = new Map<string, number>();
  for (const f of openFindings) {
    if (f.severity === "critical" || f.severity === "high") {
      ruleCounts.set(f.rule, (ruleCounts.get(f.rule) ?? 0) + 1);
    }
  }
  const topRiskContributors = [...ruleCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([rule]) => rule);

  return {
    mttrCritical,
    openCritical,
    openHigh,
    slaComplianceRate,
    riskTrend,
    topRiskContributors,
  };
}
