/**
 * Regression test for v5.2.24: the risk trajectory analysis was firing
 * RISK_TRAJECTORY_UNSTABLE on consistently-improving scores because the
 * check used Math.abs(slope) > 5 - it could not tell oscillation from
 * a steady downward (improving) trend.
 *
 * The v5.2.23 self-scan produced slope -13.9/scan (six straight releases
 * each fixing real bugs) and was flagged as "highly volatile". The fix
 * separates direction (sign of slope) from volatility (stdev of
 * residuals from the linear fit).
 */

import { describe, it, expect } from "vitest";
import { forecastRisk } from "../risk-forecast.js";
import type { RiskHistoryEntry } from "../types.js";

function history(scores: number[]): RiskHistoryEntry[] {
  const base = Date.now();
  return scores.map((score, i) => ({
    timestamp: new Date(base - (scores.length - i) * 86400000).toISOString(),
    score,
    findingsCount: 1,
    criticalCount: 0,
  }));
}

describe("v5.2.24: trajectory direction split from volatility", () => {
  it("does NOT fire RISK_TRAJECTORY_UNSTABLE on a strict monotone decrease", () => {
    // Six straight releases each dropping the score by ~15
    const hist = history([100, 100, 100, 87, 37, 17]);
    const findings = forecastRisk(hist, 17);
    expect(findings.some((f) => f.rule === "RISK_TRAJECTORY_UNSTABLE")).toBe(false);
  });

  it("does NOT fire any trajectory finding on consistent improvement", () => {
    // Fast improvement (matches what supply-chain-guard's own scan looked
    // like over the v5.2.18 - v5.2.23 release stretch).
    const hist = history([100, 100, 100, 87, 37, 17]);
    const findings = forecastRisk(hist, 17);
    expect(findings.some((f) => f.rule === "RISK_TRAJECTORY_DEGRADING")).toBe(false);
    // RISK_FORECAST_CRITICAL only fires when forecast > 60 AND current <= 60,
    // which is not the case for an improving trend.
    expect(findings.some((f) => f.rule === "RISK_FORECAST_CRITICAL")).toBe(false);
  });

  it("DOES fire RISK_TRAJECTORY_DEGRADING when the score is rising fast", () => {
    // Score climbing steadily - the kind of trend that means something is
    // genuinely getting worse.
    const hist = history([10, 15, 25, 40, 60, 80]);
    const findings = forecastRisk(hist, 80);
    expect(findings.some((f) => f.rule === "RISK_TRAJECTORY_DEGRADING")).toBe(true);
  });

  it("DOES fire RISK_TRAJECTORY_UNSTABLE on real oscillation (high residuals, small slope)", () => {
    // Score bouncing around the same level - the actual definition of
    // "volatile". Slope is near zero but stdev around the trend line is high.
    const hist = history([20, 80, 25, 75, 30, 70]);
    const findings = forecastRisk(hist, 50);
    expect(findings.some((f) => f.rule === "RISK_TRAJECTORY_UNSTABLE")).toBe(true);
    expect(findings.some((f) => f.rule === "RISK_TRAJECTORY_DEGRADING")).toBe(false);
  });

  it("does NOT fire on a stable flat trajectory", () => {
    const hist = history([25, 26, 24, 25, 26, 25]);
    const findings = forecastRisk(hist, 25);
    expect(findings.some((f) => f.rule === "RISK_TRAJECTORY_UNSTABLE")).toBe(false);
    expect(findings.some((f) => f.rule === "RISK_TRAJECTORY_DEGRADING")).toBe(false);
  });
});
