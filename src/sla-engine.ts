/**
 * SLA engine (v4.8).
 *
 * Tracks remediation SLAs based on finding severity
 * and flags breaches and at-risk items.
 */

import type { Finding, SlaConfig, TriageDecision } from "./types.js";

const DEFAULT_SLA: SlaConfig = {
  critical: "24h",
  high: "3d",
  medium: "7d",
};

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
 * Check SLA compliance for triaged findings.
 */
export function checkSlaCompliance(
  decisions: TriageDecision[],
  slaConfig?: SlaConfig,
): Finding[] {
  const findings: Finding[] = [];
  const sla = slaConfig ?? DEFAULT_SLA;
  const now = Date.now();

  for (const d of decisions) {
    if (d.status === "resolved" || d.status === "false-positive" || d.status === "accepted-risk") continue;

    const age = now - new Date(d.decidedAt).getTime();
    let slaMs: number;

    // Determine SLA based on original finding severity (approximated from rule)
    // In production, this would reference the actual finding severity
    if (d.findingRule.includes("CRITICAL") || d.findingRule.startsWith("IOC_")) {
      slaMs = parseDuration(sla.critical);
    } else if (d.findingRule.includes("HIGH") || d.findingRule.startsWith("INSTALL_HOOK")) {
      slaMs = parseDuration(sla.high);
    } else {
      slaMs = parseDuration(sla.medium);
    }

    if (age > slaMs) {
      findings.push({
        rule: "SLA_BREACH_CRITICAL",
        description: `SLA breached for "${d.findingRule}" — open for ${Math.round(age / (24 * 60 * 60 * 1000))} days (SLA: ${slaMs / (24 * 60 * 60 * 1000)}d). Owner: ${d.owner ?? "unassigned"}.`,
        severity: "critical",
        confidence: 1.0,
        category: "trust",
        recommendation: "Escalate immediately. SLA breach indicates remediation is stalled.",
      });
    } else if (age > slaMs * 0.8) {
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
