/**
 * SLA engine (v4.8).
 *
 * Tracks remediation SLAs based on finding severity
 * and flags breaches and at-risk items.
 *
 * This module owns the single definition of "is this triage decision
 * inside its SLA". `slaVerdict` below is that definition. Everything that needs
 * an SLA answer calls it, including the `slaComplianceRate` metric in
 * `src/metrics.ts`, which previously carried a second, contradicting definition
 * of its own (a resolution rate). Two definitions of one concept disagreed on
 * the same input for every release from v4.8.0 to v5.28.1. Do not add a third:
 * if a caller needs a different classification, extend `SlaVerdict` here so both
 * callers move together.
 */

import type { Finding, SlaConfig, TriageDecision } from "./types.js";

const DEFAULT_SLA: SlaConfig = {
  critical: "24h",
  high: "3d",
  medium: "7d",
};

/**
 * Fraction of the SLA window after which a still-open decision is reported as
 * at risk rather than merely open.
 *
 * 0.8 is not a new choice: it is the value this engine has emitted
 * `SLA_AT_RISK` on since v4.8.0, named here rather than left as a literal
 * because it is now part of a definition two modules share. It is a WARNING
 * threshold only. The deadline has not passed at 0.8, so an at-risk decision
 * is still inside its SLA and still counts as compliant in
 * `slaComplianceRate`. Moving this number changes which decisions are warned
 * about; it does not change what counts as a breach.
 */
const AT_RISK_FRACTION = 0.8;

/**
 * The verdict for a single triage decision against its SLA.
 *
 * - `compliant`   the deadline has not passed, or the decision has no
 *                 remaining deadline to miss (see `slaVerdict`).
 * - `at-risk`     the deadline has not passed but the decision is past
 *                 `AT_RISK_FRACTION` of its window. Still inside the SLA.
 * - `breached`    the deadline has passed.
 * - `unmeasurable` `decidedAt` is not a usable timestamp, so no age and
 *                 therefore no deadline comparison exists for this decision.
 *                 It is neither compliant nor breached; it is unknown, and
 *                 callers must not silently promote it to either.
 */
export type SlaVerdict = "compliant" | "at-risk" | "breached" | "unmeasurable";

/**
 * Parse SLA duration string to milliseconds.
 */
function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)(h|d|w)$/);
  if (!match) return 7 * 24 * 60 * 60 * 1000; // default 7 days
  const value = parseInt(match[1], 10);
  switch (match[2]) {
    case "h": return value * 60 * 60 * 1000;
    case "d": return value * 24 * 60 * 60 * 1000;
    case "w": return value * 7 * 24 * 60 * 60 * 1000;
    default: return 7 * 24 * 60 * 60 * 1000;
  }
}

/**
 * SLA window for one decision, derived from the rule name.
 *
 * The severity is approximated from the rule id because `TriageDecision` does
 * not carry the original finding's severity. This approximation predates the
 * single-definition refactor and is unchanged by it.
 *
 * `TriageDecision.dueDate` is deliberately NOT consulted here, and never has
 * been by either the engine or the metric. The field is declared and accepted
 * from the triage store, so a reader may reasonably assume setting it moves the
 * deadline. It does not. Honouring it would change what counts as a breach for
 * every project that already sets it, which is an owner decision rather than
 * part of unifying two existing definitions. Stated here so the gap is visible
 * at the line that would have to change.
 */
function slaWindowMs(decision: TriageDecision, sla: SlaConfig): number {
  if (decision.findingRule.includes("CRITICAL") || decision.findingRule.startsWith("IOC_")) {
    return parseDuration(sla.critical);
  }
  if (decision.findingRule.includes("HIGH") || decision.findingRule.startsWith("INSTALL_HOOK")) {
    return parseDuration(sla.high);
  }
  return parseDuration(sla.medium);
}

/**
 * The single definition of SLA compliance for one triage decision.
 *
 * Assumptions, written here because both callers depend on them:
 *
 * 1. `resolved`, `false-positive` and `accepted-risk` are compliant by status,
 *    without consulting a date. A resolved or dismissed finding has nothing
 *    left to remediate, and an accepted risk is a recorded decision not to
 *    remediate, so neither has a remediation deadline it can miss. This
 *    matches how the engine has always behaved and is why an all-accepted-risk
 *    decision set is 100 percent compliant rather than 0 percent.
 *    The alternative reading, that an accepted risk should expire and be
 *    re-approved, would need an expiry field on `TriageDecision`, which does
 *    not exist. Adding one is an owner decision, not an implementation detail,
 *    and it would change this function and both callers at once.
 * 2. `new` IS evaluated. A decision recorded but never picked up still has a
 *    clock running against it. The old metric excluded `new` from its
 *    denominator while this engine evaluated it, which is how a report could
 *    show 100 percent compliance next to real breaches.
 * 3. An unparseable `decidedAt` yields `unmeasurable`, never `compliant`.
 *    A record whose age cannot be computed has not been shown to meet its
 *    SLA; reporting it as compliant is the flattering answer that this whole
 *    change exists to remove.
 * 4. A `decidedAt` in the future yields a non-positive age and is therefore
 *    compliant. This is deliberate rather than an oversight: the triage store
 *    is a committed file that different machines write, so small clock skew is
 *    ordinary, and a decision recorded seconds ago is genuinely inside its
 *    deadline. No future-dating bound is imposed, because any cut-off would be
 *    an invented number.
 */
export function slaVerdict(
  decision: TriageDecision,
  slaConfig?: SlaConfig,
): SlaVerdict {
  if (
    decision.status === "resolved" ||
    decision.status === "false-positive" ||
    decision.status === "accepted-risk"
  ) {
    return "compliant";
  }

  const decidedAtMs = new Date(decision.decidedAt).getTime();
  if (!Number.isFinite(decidedAtMs)) return "unmeasurable";

  const age = Date.now() - decidedAtMs;
  const slaMs = slaWindowMs(decision, slaConfig ?? DEFAULT_SLA);

  if (age > slaMs) return "breached";
  if (age > slaMs * AT_RISK_FRACTION) return "at-risk";
  return "compliant";
}

/**
 * Check SLA compliance for triaged findings.
 *
 * Emits one finding per breached or at-risk decision. Decisions that are
 * compliant or `unmeasurable` produce nothing, which for `unmeasurable` is the
 * behaviour this engine has always had: a decision with an unusable
 * `decidedAt` produced no finding before this refactor and produces none now.
 * Inventing a finding rule for it would be a new detection, not a bug fix.
 */
export function checkSlaCompliance(
  decisions: TriageDecision[],
  slaConfig?: SlaConfig,
): Finding[] {
  const findings: Finding[] = [];
  const sla = slaConfig ?? DEFAULT_SLA;
  const now = Date.now();

  for (const d of decisions) {
    const verdict = slaVerdict(d, sla);
    if (verdict !== "breached" && verdict !== "at-risk") continue;

    // Safe: a breached or at-risk verdict implies `decidedAt` parsed to a
    // finite time. `now` is re-read from the loop preamble rather than from
    // slaVerdict, so the printed age can differ from the verdict's by the
    // microseconds between the two Date.now() calls. That cannot move a day
    // count or an hour count, and keeping one clock read per call would mean
    // threading a timestamp through the shared definition for no gain.
    const age = now - new Date(d.decidedAt).getTime();
    const slaMs = slaWindowMs(d, sla);

    if (verdict === "breached") {
      findings.push({
        rule: "SLA_BREACH_CRITICAL",
        description: `SLA breached for "${d.findingRule}" — open for ${Math.round(age / (24 * 60 * 60 * 1000))} days (SLA: ${slaMs / (24 * 60 * 60 * 1000)}d). Owner: ${d.owner ?? "unassigned"}.`,
        severity: "critical",
        confidence: 1.0,
        category: "trust",
        recommendation: "Escalate immediately. SLA breach indicates remediation is stalled.",
      });
    } else {
      findings.push({
        rule: "SLA_AT_RISK",
        description: `SLA at risk for "${d.findingRule}" — ${Math.round((slaMs - age) / (60 * 60 * 1000))} hours remaining. Owner: ${d.owner ?? "unassigned"}.`,
        severity: "high",
        confidence: 1.0,
        category: "trust",
        recommendation: "Prioritize remediation. SLA deadline approaching.",
      });
    }
  }

  return findings;
}
