/**
 * Continuous risk monitoring engine (v4.8).
 *
 * Persists scan history, tracks risk trends over time,
 * and detects risk regressions and spikes.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, RiskHistoryEntry, ScanReport } from "./types.js";

const HISTORY_DIR = ".scg-history";
const HISTORY_FILE = "risk-history.json";
const MAX_HISTORY_ENTRIES = 100;

/**
 * Load risk history from persistent storage.
 */
export function loadRiskHistory(dir: string): RiskHistoryEntry[] {
  const historyPath = path.join(dir, HISTORY_DIR, HISTORY_FILE);
  if (!fs.existsSync(historyPath)) return [];

  try {
    return JSON.parse(fs.readFileSync(historyPath, "utf-8")) as RiskHistoryEntry[];
  } catch {
    return [];
  }
}

/**
 * Save current scan result to risk history.
 */
export function saveRiskHistory(
  dir: string,
  report: ScanReport,
): void {
  const historyDir = path.join(dir, HISTORY_DIR);
  fs.mkdirSync(historyDir, { recursive: true });

  const history = loadRiskHistory(dir);
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

  // Stagnation at high risk
  if (recent.every((h) => h.score > 50) && recent.length >= 3) {
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
