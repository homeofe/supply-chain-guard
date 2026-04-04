/**
 * Risk forecasting engine (v4.8).
 *
 * Predicts future risk trajectory based on historical trends
 * and recurring patterns.
 */

import type { Finding, RiskHistoryEntry } from "./types.js";

/**
 * Forecast risk trajectory based on history.
 */
export function forecastRisk(
  history: RiskHistoryEntry[],
  currentScore: number,
): Finding[] {
  const findings: Finding[] = [];
  if (history.length < 5) return findings;

  // Simple linear regression on last 10 data points
  const recent = history.slice(-10);
  const n = recent.length;
  const xMean = (n - 1) / 2;
  const yMean = recent.reduce((s, h) => s + h.score, 0) / n;

  let numerator = 0;
  let denominator = 0;
  for (let i = 0; i < n; i++) {
    numerator += (i - xMean) * (recent[i].score - yMean);
    denominator += (i - xMean) ** 2;
  }

  const slope = denominator !== 0 ? numerator / denominator : 0;

  // Forecast 5 scans ahead
  const forecastScore = Math.round(currentScore + slope * 5);

  if (forecastScore > 60 && currentScore <= 60) {
    findings.push({
      rule: "RISK_FORECAST_CRITICAL",
      description: `Risk is projected to reach critical level (${forecastScore}/100) within 5 scans if current trend continues (slope: +${slope.toFixed(1)}/scan).`,
      severity: "high",
      confidence: 0.6,
      category: "trust",
      recommendation: "Risk trajectory is heading toward critical. Proactive remediation recommended now.",
    });
  }

  if (Math.abs(slope) > 5) {
    findings.push({
      rule: "RISK_TRAJECTORY_UNSTABLE",
      description: `Risk score is highly volatile (slope: ${slope > 0 ? "+" : ""}${slope.toFixed(1)}/scan). Unstable risk indicates inconsistent security practices.`,
      severity: "medium",
      confidence: 0.5,
      category: "trust",
      recommendation: "Stabilize risk by implementing consistent policies and baseline enforcement.",
    });
  }

  return findings;
}
