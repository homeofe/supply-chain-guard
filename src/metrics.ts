/**
 * Security metrics & KPI engine (v4.8).
 *
 * Calculates key security metrics from scan history,
 * triage decisions, and current findings.
 *
 * This module deliberately owns NO definition of SLA compliance. It asks
 * `src/sla-engine.ts` for a verdict per decision and counts the answers. The
 * previous version computed `slaComplianceRate` from its own formula
 * (resolved divided by not-new, a resolution rate) and therefore contradicted
 * the SLA engine on the same input in both directions.
 */

import type {
  Finding,
  RiskHistoryEntry,
  TriageDecision,
  SecurityMetrics,
  SlaConfig,
} from "./types.js";
import { slaVerdict } from "./sla-engine.js";

/**
 * SLA compliance over a set of triage decisions.
 *
 * Returns a whole percentage, or `null` when nothing measurable exists.
 *
 * Contract, in full:
 *
 * - The denominator is every decision whose verdict is measurable. A decision
 *   with an unparseable `decidedAt` is excluded from BOTH sides rather than
 *   counted as compliant, so a corrupt triage store reports "not measured"
 *   instead of "perfect".
 * - `at-risk` counts as within SLA. Its deadline has not passed.
 * - `null` means no measurement, not zero and not full compliance. It is
 *   returned for an empty decision set and for a set in which every decision
 *   is unmeasurable. `null` rather than `undefined` on purpose:
 *   `JSON.stringify` drops an `undefined` value, and a consumer cannot tell a
 *   dropped key from an older tool version that never had the field.
 * - `Math.floor`, not `Math.round`. Rounding would let one breach in 200
 *   decisions report as 100 percent. Flooring makes the published invariant
 *   exact: WHEN THE VALUE IS NON-NULL it is 100 if and only if
 *   `checkSlaCompliance` finds zero breaches in the same decisions. An earlier
 *   draft of this comment dropped that qualifier and stated the biconditional
 *   unrestricted, which is false in one direction: the two `return null` paths
 *   above are reached with zero breaches, so zero breaches does not imply 100.
 *   The `if (breaches === 0) expect(rate === null || rate === 100)` assertion
 *   in `src/__tests__/sla-engine.test.ts` is the form the tests always used.
 *   The cost of flooring is that the number is never rounded up, which is the
 *   correct direction of error for a compliance figure.
 */
function slaComplianceRateOf(
  decisions: TriageDecision[],
  slaConfig?: SlaConfig,
): number | null {
  const verdicts = decisions.map((d) => slaVerdict(d, slaConfig));
  const measurable = verdicts.filter((v) => v !== "unmeasurable");
  if (measurable.length === 0) return null;
  const withinSla = measurable.filter((v) => v !== "breached").length;
  return Math.floor((withinSla / measurable.length) * 100);
}

/**
 * Calculate security metrics from findings, history, and triage data.
 *
 * `slaConfig` is optional and no caller passes it today: the scanner has no
 * SLA configuration surface, so both this function and `checkSlaCompliance`
 * fall back to the engine's built-in default. The parameter exists so that a
 * future configuration surface cannot be wired into one of the two and not
 * the other, which is the shape of the defect this module just lost.
 *
 * KNOWN LIMIT, stated so the next reader does not rediscover it as a defect.
 * `riskTrend` is a closed string union with no member meaning "unknown", so an
 * empty `history` yields `stable` whether the store was absent, unreadable, or
 * genuinely empty: that is an answer about an empty set, not about the project.
 * `slaComplianceRate` no longer shares that limit - it reads `null` when there
 * is nothing measurable - but `null` still does not separate "no decisions were
 * made" from "the decision store could not be read".
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
 * `slaComplianceRate` was widened from `number` to `number | null` as part of
 * giving SLA compliance a single definition. That IS a breaking change for
 * library and JSON consumers and is carried as one. `riskTrend` was NOT widened
 * with it: it is published in `SecurityMetrics` on the same terms, so widening
 * it is a separate decision rather than a consequence of this one.
 */
export function calculateMetrics(
  findings: Finding[],
  history: RiskHistoryEntry[],
  decisions: TriageDecision[],
  slaConfig?: SlaConfig,
): SecurityMetrics {
  // Open findings by severity
  const resolvedRules = new Set(
    decisions.filter((d) => d.status === "resolved").map((d) => d.findingRule),
  );
  const openFindings = findings.filter((f) => !resolvedRules.has(f.rule) && f.severity !== "info");
  const openCritical = openFindings.filter((f) => f.severity === "critical").length;
  const openHigh = openFindings.filter((f) => f.severity === "high").length;

  // SLA compliance rate, from the one definition in src/sla-engine.ts
  const slaComplianceRate = slaComplianceRateOf(decisions, slaConfig);

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
    openCritical,
    openHigh,
    slaComplianceRate,
    riskTrend,
    topRiskContributors,
  };
}
