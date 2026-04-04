/**
 * Triage engine (v4.8).
 *
 * Manages finding status, ownership, and decision tracking.
 * Persists triage decisions for team collaboration.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, TriageDecision, FindingStatus } from "./types.js";

const TRIAGE_DIR = ".scg-history";
const TRIAGE_FILE = "triage-decisions.json";

/**
 * Load triage decisions from persistent storage.
 */
export function loadTriageDecisions(dir: string): TriageDecision[] {
  const triagePath = path.join(dir, TRIAGE_DIR, TRIAGE_FILE);
  if (!fs.existsSync(triagePath)) return [];

  try {
    return JSON.parse(fs.readFileSync(triagePath, "utf-8")) as TriageDecision[];
  } catch {
    return [];
  }
}

/**
 * Save triage decisions.
 */
export function saveTriageDecisions(
  dir: string,
  decisions: TriageDecision[],
): void {
  const triageDir = path.join(dir, TRIAGE_DIR);
  fs.mkdirSync(triageDir, { recursive: true });
  fs.writeFileSync(
    path.join(triageDir, TRIAGE_FILE),
    JSON.stringify(decisions, null, 2),
  );
}

/**
 * Check findings against triage decisions and flag governance issues.
 */
export function checkTriageGovernance(
  findings: Finding[],
  decisions: TriageDecision[],
): Finding[] {
  const govFindings: Finding[] = [];
  const decisionMap = new Map<string, TriageDecision>();

  for (const d of decisions) {
    decisionMap.set(`${d.findingRule}|${d.findingFile ?? ""}`, d);
  }

  // Check for critical findings without owner
  const criticalWithoutOwner = findings.filter(
    (f) => f.severity === "critical" && !decisionMap.has(`${f.rule}|${f.file ?? ""}`),
  );
  if (criticalWithoutOwner.length > 0) {
    govFindings.push({
      rule: "CRITICAL_FINDING_NO_OWNER",
      description: `${criticalWithoutOwner.length} critical finding(s) have no assigned owner or triage decision.`,
      severity: "high",
      confidence: 1.0,
      category: "trust",
      recommendation: "Assign owners to all critical findings. Unowned critical risks are unmanaged risks.",
    });
  }

  // Check for accepted risks without expiry
  const acceptedNoExpiry = decisions.filter(
    (d) => d.status === "accepted-risk" && !d.dueDate,
  );
  if (acceptedNoExpiry.length > 0) {
    govFindings.push({
      rule: "RISK_ACCEPTED_WITHOUT_EXPIRY",
      description: `${acceptedNoExpiry.length} risk acceptance(s) have no expiry date. Risks should be periodically re-evaluated.`,
      severity: "medium",
      confidence: 1.0,
      category: "trust",
      recommendation: "Add expiry dates to all risk acceptances. Review accepted risks quarterly.",
    });
  }

  // Check for expired risk acceptances
  const now = Date.now();
  const expired = decisions.filter(
    (d) => d.status === "accepted-risk" && d.dueDate && new Date(d.dueDate).getTime() < now,
  );
  if (expired.length > 0) {
    govFindings.push({
      rule: "RISK_ACCEPTANCE_EXPIRED",
      description: `${expired.length} risk acceptance(s) have expired and need re-evaluation.`,
      severity: "high",
      confidence: 1.0,
      category: "trust",
      recommendation: "Re-evaluate expired risk acceptances. Either remediate or renew with justification.",
    });
  }

  // Check for stale critical findings (>30 days old in triage without resolution)
  const stale = decisions.filter((d) => {
    if (d.status !== "triaged" && d.status !== "in-remediation") return false;
    const age = now - new Date(d.decidedAt).getTime();
    return age > 30 * 24 * 60 * 60 * 1000; // 30 days
  });
  if (stale.length > 0) {
    govFindings.push({
      rule: "STALE_CRITICAL_FINDING",
      description: `${stale.length} finding(s) have been in triage/remediation for over 30 days without resolution.`,
      severity: "high",
      confidence: 1.0,
      category: "trust",
      recommendation: "Escalate stale findings. Long-unresolved findings increase organizational risk.",
    });
  }

  return govFindings;
}
