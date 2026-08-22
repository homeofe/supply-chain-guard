/**
 * Security metrics & KPI engine (v4.8).
 *
 * Calculates key security metrics from scan history,
 * triage decisions, and current findings.
 */

import type { Finding, RiskHistoryEntry, TriageDecision, SecurityMetrics } from "./types.js";
import { buildTriageScope } from "./triage-scope.js";

/**
 * Calculate security metrics from findings, history, and triage data.
 *
 * KNOWN LIMIT, stated so the next reader does not rediscover it as a defect.
 * Every field here is a number or a closed string union with no member meaning
 * "unknown", so an empty `history` and an empty `decisions` produce the same
 * metrics whether the store was absent or unreadable: `riskTrend` reads
 * `stable` and `slaComplianceRate` reads 100. When the store could not be read,
 * both are answers about an empty set rather than about the project.
 *
 * What keeps that from being a silent wrong answer is the layer above, not this
 * one. `src/scanner.ts` raises `RISK_HISTORY_UNREADABLE` or
 * `TRIAGE_STORE_UNREADABLE` and sets `partialScan`, `src/reporter.ts` then
 * exits nonzero independently of `--fail-on` and strips clean-verdict
 * recommendations, and the finding text says in words that these metrics were
 * computed from an empty store. A consumer reading `metrics` in isolation must
 * check `partialScan` first; a report with `partialScan: true` is an
 * indeterminate result and its metrics are not a measurement of the project.
 *
 * Widening the types to carry "unknown" was considered and not done here: both
 * fields are published in `SecurityMetrics`, so it is a breaking change for
 * library and JSON consumers and belongs in a major, not in a defect fix.
 */
export function calculateMetrics(
  findings: Finding[],
  history: RiskHistoryEntry[],
  decisions: TriageDecision[],
): SecurityMetrics {
  // Open findings by severity.
  //
  // A decision resolves the finding it names, not every finding that shares its
  // rule. Scope is defined once in ./triage-scope.ts and shared with the
  // governance check in ./triage-engine.ts, so the two consumers of this same
  // decisions array cannot key on different widths again. Building the set from
  // d.findingRule alone is what produced
  // https://github.com/homeofe/supply-chain-guard/issues/171 : one resolved
  // instance zeroed the KPI while every other instance was still live in
  // report.findings in the same document.
  const resolvedScope = buildTriageScope(decisions.filter((d) => d.status === "resolved"));
  const openFindings = findings.filter((f) => !resolvedScope.covers(f) && f.severity !== "info");
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
