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

  // v5.2.24: split trajectory analysis into direction (slope sign) and
  // volatility (residuals from the linear fit). Previously a single
  // |slope| > 5 check flagged "unstable" both for runaway-bad trends and
  // for fast-improving trends - the latter is the opposite of unstable.
  // The self-scan on v5.2.23 reported -13.9/scan as "highly volatile"
  // even though every release that day strictly improved the score.

  // Compute stdev of residuals from the linear regression line.
  // High stdev means the score bounces unpredictably around the trend.
  let sumSq = 0;
  for (let i = 0; i < n; i++) {
    const predicted = yMean + slope * (i - xMean);
    const residual = recent[i].score - predicted;
    sumSq += residual * residual;
  }
  const stdev = Math.sqrt(sumSq / n);

  if (slope > 5) {
    // Getting worse fast - real degradation worth flagging.
    findings.push({
      rule: "RISK_TRAJECTORY_DEGRADING",
      description: `Risk score is rising fast (slope: +${slope.toFixed(1)}/scan). Security posture is worsening over the last ${n} scans.`,
      severity: "high",
      confidence: 0.6,
      category: "trust",
      recommendation: "Investigate the cause of the upward trend. Recent commits, dependency updates, or new findings should be triaged immediately.",
    });
  }
  // Fast-improving trend (slope < -5) emits no finding - it is the
  // outcome we want, surfaced silently in the score itself.

  // Count direction changes in the sequence. A monotonic sequence (always
  // dropping or always rising) has 0 direction changes even if the rate is
  // non-linear (e.g. flat then a knee). True volatility requires the score
  // to actually reverse direction, not just decelerate or accelerate.
  let directionChanges = 0;
  let lastDelta = 0;
  for (let i = 1; i < n; i++) {
    const delta = recent[i].score - recent[i - 1].score;
    if (lastDelta !== 0 && delta !== 0 && Math.sign(delta) !== Math.sign(lastDelta)) {
      directionChanges++;
    }
    if (delta !== 0) lastDelta = delta;
  }

  if (stdev > 10 && directionChanges >= 2) {
    // True volatility: high residuals AND multiple direction reversals.
    // The score bounces back and forth instead of moving consistently
    // in one direction. This is what "unstable" was meant to detect.
    findings.push({
      rule: "RISK_TRAJECTORY_UNSTABLE",
      description: `Risk score is volatile (stdev ${stdev.toFixed(1)} around trend, ${directionChanges} direction reversals). Score bounces unpredictably across scans.`,
      severity: "medium",
      confidence: 0.5,
      category: "trust",
      recommendation: "Stabilize risk by implementing consistent policies and baseline enforcement. Investigate why scores fluctuate.",
    });
  }

  return findings;
}
