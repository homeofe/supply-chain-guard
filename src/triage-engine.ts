/**
 * Triage engine (v4.8).
 *
 * Manages finding status, ownership, and decision tracking.
 * Persists triage decisions for team collaboration.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, TriageDecision, FindingStatus } from "./types.js";
import {
  STATE_DIR,
  ensureStateDir,
  readJsonArrayStore,
  type StateStoreRead,
  type StateStoreUnreadableReason,
} from "./state-dir.js";
import { buildTriageScope } from "./triage-scope.js";

const TRIAGE_FILE = "triage-decisions.json";

/** The valid values of `TriageDecision.status`. */
const FINDING_STATUSES: ReadonlySet<string> = new Set<FindingStatus>([
  "new",
  "triaged",
  "accepted-risk",
  "in-remediation",
  "resolved",
  "false-positive",
]);

/** The result of reading the persisted triage decisions. */
export type TriageDecisionsRead = StateStoreRead<TriageDecision>;

/**
 * Why a triage store that exists could not be used.
 *
 * See {@link StateStoreUnreadableReason} in `src/state-dir.ts`.
 */
export type TriageDecisionsUnreadableReason = StateStoreUnreadableReason;

/**
 * Structural check for one persisted triage decision.
 *
 * `status` is checked against the closed `FindingStatus` set rather than merely
 * being required to be a string, because every governance rule in
 * `checkTriageGovernance` below selects on it. An unrecognised status silently
 * matches no rule, so an entry carrying one would be counted in
 * `decisions.length` and in the SLA denominator while contributing to no check,
 * which is a wrong answer rather than an absent one.
 *
 * `decidedAt` is required to be a string but is not required to be a parseable
 * date. The staleness rule below computes `now - new Date(d.decidedAt)`, which
 * yields `NaN` for an unparseable value, and `NaN > threshold` is `false`, so
 * an unparseable date fails toward reporting less. That is a real weakness, but
 * it is a pre-existing one about date handling, it is not the read-path
 * conflation this store is being corrected for, and tightening it here would
 * reject stores written by earlier versions that never validated the field.
 * Stated rather than left for the next reader to rediscover.
 */
function isTriageDecision(value: unknown): value is TriageDecision {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const decision = value as Record<string, unknown>;
  return (
    typeof decision.findingRule === "string" &&
    typeof decision.status === "string" &&
    FINDING_STATUSES.has(decision.status) &&
    typeof decision.decidedAt === "string"
  );
}

/**
 * Read the persisted triage decisions and say which of the three things happened.
 *
 * This store carries the same defect class as the risk history and was measured
 * to have the same consequence, which is why both are fixed together rather
 * than one being left as an unremarked twin for the pattern to be copied from.
 * On a fixture holding one expired risk acceptance and one stale in-remediation
 * decision, truncating this file took the scan from exit 1 with two `high`
 * findings to exit 0 with none, and took `metrics.slaComplianceRate` from 0 to
 * 100. The second number is the sharper harm: a corrupt file did not merely
 * hide a verdict, it manufactured a perfect compliance score.
 *
 * `null` and `{}` additionally crashed the scan outright with
 * `decisions is not iterable` and no report at all, because the previous reader
 * ended in `as TriageDecision[]`, which is an assertion and not a check.
 *
 * The three-way contract is documented on `readJsonArrayStore` in
 * `src/state-dir.ts`. The caller that acts on `unreadable` is `src/scanner.ts`,
 * which raises `TRIAGE_STORE_UNREADABLE` and marks the report `partialScan`.
 */
export function readTriageDecisions(dir: string): TriageDecisionsRead {
  return readJsonArrayStore(dir, TRIAGE_FILE, isTriageDecision);
}

/**
 * Load triage decisions from persistent storage.
 *
 * @deprecated Use {@link readTriageDecisions}, which distinguishes an absent
 * store from an unreadable one. This wrapper collapses both to `[]` and
 * therefore cannot tell a caller that governance evidence was lost. It is kept
 * because it is published API (`src/index.ts`), so removing or re-typing it
 * would break library consumers; it is not kept because the behaviour is
 * correct.
 */
export function loadTriageDecisions(dir: string): TriageDecision[] {
  return readTriageDecisions(dir).entries;
}

/**
 * Build the finding that reports an unusable triage store.
 *
 * Severity `high` on the same derivation as `RISK_HISTORY_UNREADABLE`: the
 * governance findings this loses (`RISK_ACCEPTANCE_EXPIRED`,
 * `STALE_CRITICAL_FINDING`, `CRITICAL_FINDING_NO_OWNER`) are `high`, and the
 * default gate in `src/reporter.ts` with no `--fail-on` is `summary.high > 0`,
 * so anything lower would leave that gate green and reproduce the defect one
 * layer down.
 */
export function triageStoreUnreadableFinding(
  reason: TriageDecisionsUnreadableReason,
): Finding {
  return {
    rule: "TRIAGE_STORE_UNREADABLE",
    description:
      `The triage decision store at ${STATE_DIR}/${TRIAGE_FILE} exists but could not be used (${reason}). ` +
      `Governance checks therefore ran against no decisions, so expired risk acceptances, stale remediations and unowned ` +
      `critical findings cannot be reported, and the SLA compliance rate in this report is computed from an empty store ` +
      `rather than from the recorded decisions.`,
    severity: "high",
    confidence: 1,
    category: "trust",
    recommendation:
      `Treat this run as unverified rather than compliant. Inspect ${STATE_DIR}/${TRIAGE_FILE}: complete entries can often be ` +
      `recovered by closing the truncated JSON array by hand. Delete the file only if the recorded triage decisions are ` +
      `genuinely expendable, since they are the record of who accepted which risk and when.`,
  };
}

/**
 * Save triage decisions.
 *
 * Unlike `saveRiskHistory`, this function does NOT refuse to run when the store
 * on disk is unreadable, and the asymmetry is deliberate. `saveRiskHistory`
 * performs a read, append and write, so it would overwrite a corrupt file with
 * a single fresh entry and destroy the complete entries still recoverable from
 * it; refusing is what preserves them. This function takes the full decision
 * list from its caller and replaces the file wholesale, so refusing here would
 * remove the only supported way to repair a corrupt store through the API,
 * while preventing no measured loss: no caller in this repository performs a
 * read-modify-write of this store, and a library consumer that does can use
 * {@link readTriageDecisions} to see the `unreadable` status before deciding.
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
