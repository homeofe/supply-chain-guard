/**
 * Continuous risk monitoring engine (v4.8).
 *
 * Persists scan history, tracks risk trends over time,
 * and detects risk regressions and spikes.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, RiskHistoryEntry, ScanReport } from "./types.js";
import {
  STATE_DIR,
  ensureStateDir,
  readJsonArrayStore,
  type StateStoreRead,
  type StateStoreUnreadableReason,
} from "./state-dir.js";

const HISTORY_FILE = "risk-history.json";
const MAX_HISTORY_ENTRIES = 100;

/** The result of reading the persisted risk history. */
export type RiskHistoryRead = StateStoreRead<RiskHistoryEntry>;

/**
 * Why a risk history that exists could not be used.
 *
 * Enumerated identifiers, never an exception message, because the value is
 * published inside a scan report. See {@link StateStoreUnreadableReason} in
 * `src/state-dir.ts` for the reasoning and the members.
 */
export type RiskHistoryUnreadableReason = StateStoreUnreadableReason;

/**
 * Structural check for one persisted history entry.
 *
 * The previous reader ended in `as RiskHistoryEntry[]`, which is a cast and not
 * a check, so two shapes that are valid JSON never reached its `catch` at all
 * and instead crashed the scan downstream with an unhandled `TypeError`: `null`
 * at `analyzeRiskTrend`'s `history.length`, and `{}` at its `history.slice(-5)`.
 * This function checks the shape the cast merely asserted.
 *
 * Every field the `RiskHistoryEntry` contract declares is required, with no
 * partial-credit tier, and that is a deliberate bound rather than arbitrary
 * strictness. `saveRiskHistory` below is the only writer and it always writes
 * all four fields together; the interface has never had another shape, having
 * exactly one touching commit, the v4.8.0 feature commit. So a file missing a
 * field was not written by this tool, and a store that is not the store this
 * tool wrote is not evidence of what this tool measured. Accepting it partially
 * would also publish a `riskHistory` block in the report whose entries do not
 * satisfy the type the report declares for them.
 *
 * `Number.isFinite` rather than `typeof value === "number"`: `NaN` is a number
 * and would propagate through every average, slope and comparison in this file,
 * producing a trend verdict that is wrong rather than absent, which is the same
 * failure class this module is being corrected for.
 */
function isRiskHistoryEntry(value: unknown): value is RiskHistoryEntry {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const entry = value as Record<string, unknown>;
  return (
    typeof entry.timestamp === "string" &&
    Number.isFinite(entry.score) &&
    Number.isFinite(entry.findingsCount) &&
    Number.isFinite(entry.criticalCount)
  );
}

/**
 * Read the persisted risk history and say which of the three things happened.
 *
 * Prefer this over {@link loadRiskHistory} in any caller that can act on the
 * difference. `loadRiskHistory` cannot report a failure because its return type
 * has no room for one, which is the root cause this function exists to remove:
 * the old `catch` did not decide to hide the corruption, it had no vocabulary
 * in which to report it.
 *
 * The three-way contract, and why the failure branch must not be "simplified"
 * back into an empty array, is documented on `readJsonArrayStore` in
 * `src/state-dir.ts`. In this project the caller that acts on `unreadable` is
 * `src/scanner.ts`, which raises `RISK_HISTORY_UNREADABLE` and marks the report
 * `partialScan`.
 */
export function readRiskHistory(dir: string): RiskHistoryRead {
  return readJsonArrayStore(dir, HISTORY_FILE, isRiskHistoryEntry);
}

/**
 * Load risk history from persistent storage.
 *
 * @deprecated Use {@link readRiskHistory}, which distinguishes an absent
 * history from an unreadable one. This wrapper collapses both to `[]` and
 * therefore cannot tell a caller that evidence was lost. It is kept because it
 * is published API (`src/index.ts`), so removing or re-typing it would break
 * library consumers; it is not kept because the behaviour is correct.
 */
export function loadRiskHistory(dir: string): RiskHistoryEntry[] {
  return readRiskHistory(dir).entries;
}

/**
 * Raised instead of overwriting a risk history that could not be read.
 *
 * Carries the enumerated reason only. No path, no exception text: see
 * {@link RiskHistoryUnreadableReason}.
 */
export class RiskHistoryUnreadableError extends Error {
  readonly reason: RiskHistoryUnreadableReason;

  constructor(reason: RiskHistoryUnreadableReason) {
    super(
      `Refusing to overwrite an unreadable risk history (${reason}). ` +
        `Inspect ${STATE_DIR}/${HISTORY_FILE} in the scanned directory and ` +
        `remove or repair it before recording new measurements.`,
    );
    this.name = "RiskHistoryUnreadableError";
    this.reason = reason;
  }
}

/**
 * Build the finding that reports an unusable risk history.
 *
 * Severity is `high`, and the number is derived rather than chosen. Every
 * finding this defect suppresses is `high`: `RISK_TREND_INCREASING` and
 * `RISK_STAGNATION_HIGH` below, `RISK_FORECAST_CRITICAL` and
 * `RISK_TRAJECTORY_DEGRADING` in `src/risk-forecast.ts`. The default gate in
 * `src/reporter.ts` with no `--fail-on` is `summary.high > 0`, so anything
 * lower would leave that gate green and reproduce this very defect one layer
 * further down: a corrupt history would still exit 0.
 *
 * It is not `critical`, even though `RISK_TREND_SPIKE` is, because `critical`
 * means CLI exit code 2 and this finding is not a claim that a spike occurred.
 * It is a claim that the baseline is unavailable, which is exit code 1
 * territory. The `partialScan` flag the caller sets alongside it already forces
 * exit 1 independently of `--fail-on`, so the severity is the backstop for a
 * consumer reading `summary`, not the only thing holding the gate.
 *
 * `confidence: 1` because this is not an inference. The file was opened and it
 * did not parse or did not match the declared shape.
 */
export function riskHistoryUnreadableFinding(
  reason: RiskHistoryUnreadableReason,
): Finding {
  return {
    rule: "RISK_HISTORY_UNREADABLE",
    description:
      `The persisted risk history at ${STATE_DIR}/${HISTORY_FILE} exists but could not be used (${reason}). ` +
      `Trend and forecast analysis therefore ran with no baseline, so this scan cannot report a risk regression ` +
      `and is not comparable with earlier scans. A previous scan of this directory recorded measurements that are now unreadable.`,
    severity: "high",
    confidence: 1,
    category: "trust",
    recommendation:
      `Treat this run as unverified rather than clean. Inspect ${STATE_DIR}/${HISTORY_FILE}: complete entries can often be recovered by ` +
      `closing the truncated JSON array by hand. Delete the file to start a new baseline, accepting that the old trend is gone. ` +
      `History is not written while this finding is present, so the file is preserved until it is dealt with.`,
  };
}

/**
 * Save current scan result to risk history.
 *
 * @throws {RiskHistoryUnreadableError} when a history file exists that could
 * not be read. Overwriting it would destroy recoverable evidence: a history
 * truncated mid-write still holds every complete entry before the cut, and this
 * function would otherwise replace the whole file with a single fresh entry, so
 * one more scan turns "corrupt" into "gone" and the feature restarts from a
 * baseline indistinguishable from a genuine first run. Throwing rather than
 * returning quietly is the point: a silent no-op here would be the same
 * conflation of "cannot answer" with "answered nothing" that the reader above
 * was corrected for. `src/scanner.ts` never reaches this throw, because it sets
 * `partialScan` on an unreadable history and its own save is already gated on
 * that; the throw is what protects a library consumer calling this directly.
 */
export function saveRiskHistory(
  dir: string,
  report: ScanReport,
): void {
  // An incomplete scan is not a comparable measurement and must never become
  // a deceptively low baseline, even when this public helper is called directly.
  if (report.partialScan) return;

  // Read before ensureStateDir so a refusal does not leave a state directory
  // behind in a scanned repository that did not have one.
  const existing = readRiskHistory(dir);
  if (existing.status === "unreadable") {
    throw new RiskHistoryUnreadableError(
      existing.reason ?? "read-failed",
    );
  }

  const historyDir = ensureStateDir(dir);

  const history = existing.entries;
  history.push({
    timestamp: report.timestamp,
    score: report.score,
    findingsCount: report.findings.length,
    criticalCount: report.summary.critical,
  });

  // Keep only last N entries
  const trimmed = history.slice(-MAX_HISTORY_ENTRIES);
  fs.writeFileSync(
    path.join(historyDir, HISTORY_FILE),
    JSON.stringify(trimmed, null, 2),
  );
}

/**
 * Analyze risk trend from history.
 */
export function analyzeRiskTrend(
  history: RiskHistoryEntry[],
  currentScore: number,
): Finding[] {
  const findings: Finding[] = [];
  if (history.length < 2) return findings;

  const recent = history.slice(-5);
  const avgRecent = recent.reduce((s, h) => s + h.score, 0) / recent.length;
  const prevScore = history[history.length - 1].score;

  // Spike detection: current score > 2x previous
  if (currentScore > prevScore * 2 && currentScore > 30) {
    findings.push({
      rule: "RISK_TREND_SPIKE",
      description: `Risk score spiked from ${prevScore} to ${currentScore} (${Math.round((currentScore / prevScore - 1) * 100)}% increase). Investigate recent changes.`,
      severity: "critical",
      confidence: 0.85,
      category: "trust",
      recommendation: "A sudden risk spike indicates new threats or regressions. Review recent dependency changes and commits.",
    });
  }

  // Increasing trend: average of last 5 scans > average of 5 before that
  if (history.length >= 10) {
    const older = history.slice(-10, -5);
    const avgOlder = older.reduce((s, h) => s + h.score, 0) / older.length;
    if (avgRecent > avgOlder * 1.3 && avgRecent > 20) {
      findings.push({
        rule: "RISK_TREND_INCREASING",
        description: `Risk score trending upward: recent average ${Math.round(avgRecent)} vs previous ${Math.round(avgOlder)}. Supply-chain risk is growing.`,
        severity: "high",
        confidence: 0.7,
        category: "trust",
        recommendation: "Increasing risk trend suggests accumulating supply-chain debt. Prioritize remediation.",
      });
    }
  }

  // Stagnation at high risk - require at least 5 history entries to avoid
  // false alarms from new projects that haven't been remediated yet
  if (history.length >= 5 && recent.every((h) => h.score > 50) && recent.length >= 3) {
    findings.push({
      rule: "RISK_STAGNATION_HIGH",
      description: `Risk score has remained above 50 for the last ${recent.length} scans. High risk is not being remediated.`,
      severity: "high",
      confidence: 0.6,
      category: "trust",
      recommendation: "Persistent high risk scores indicate remediation is stalled. Escalate to management.",
    });
  }

  return findings;
}

/**
 * Determine overall risk trend direction.
 */
export function getRiskTrend(
  history: RiskHistoryEntry[],
): "increasing" | "stable" | "decreasing" {
  if (history.length < 3) return "stable";

  const recent3 = history.slice(-3).map((h) => h.score);
  const isIncreasing = recent3[2] > recent3[0] && recent3[2] - recent3[0] > 5;
  const isDecreasing = recent3[2] < recent3[0] && recent3[0] - recent3[2] > 5;

  if (isIncreasing) return "increasing";
  if (isDecreasing) return "decreasing";
  return "stable";
}
