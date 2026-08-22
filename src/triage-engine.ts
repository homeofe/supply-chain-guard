/**
 * Triage engine (v4.8).
 *
 * Manages finding status, ownership, and decision tracking.
 * Persists triage decisions for team collaboration.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, TriageDecision, FindingStatus } from "./types.js";
import { STATE_DIR, ensureStateDir } from "./state-dir.js";
import { buildTriageScope } from "./triage-scope.js";

const TRIAGE_DIR = STATE_DIR;
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
  const triageDir = ensureStateDir(dir);
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

  // A finding has an owner when ANY decision covers it, whatever its status:
  // being triaged, accepted or in remediation all mean somebody has looked at
  // it. Which findings a decision covers is decided in ./triage-scope.ts, the
  // one place that rule lives, and the metrics engine in ./metrics.ts asks the
  // same module. Before that module existed these two consumers of the same
  // decisions array keyed on different widths and could contradict each other
  // inside a single scan report:
  // https://github.com/homeofe/supply-chain-guard/issues/171
  //
  // Behaviour change that came with the shared rule: this check used to join
  // `rule` and `file ?? ""` into one string key, which made a decision carrying
  // no findingFile match only findings that carry no file. A rule-wide decision
  // therefore left every instance in a real file counted as unowned. It now
  // covers them, which is what "no findingFile" has always meant on the metrics
  // side and what the field's optionality says. Both halves have a test in
  // src/__tests__/triage-engine.test.ts.
  const triaged = buildTriageScope(decisions);

  // Check for critical findings without owner.
  // v5.2.20: only fire this meta-governance check when the project is actually
  // using the triage system (i.e. has at least one decision recorded). Firing
  // it by default on every scan produced a cascade of HIGH findings every time
  // another pattern triggered a critical FP, on projects that never opted into
  // triage in the first place.
  if (decisions.length > 0) {
    const criticalWithoutOwner = findings.filter(
      (f) => f.severity === "critical" && !triaged.covers(f),
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
