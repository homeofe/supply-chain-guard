import { describe, it, expect } from "vitest";
import { analyzeRiskTrend, getRiskTrend } from "../continuous-monitor.js";
import { forecastRisk } from "../risk-forecast.js";
import type { RiskHistoryEntry } from "../types.js";

function makeHistory(scores: number[]): RiskHistoryEntry[] {
  return scores.map((score, i) => ({
    timestamp: new Date(Date.now() - (scores.length - i) * 86400000).toISOString(),
    score, findingsCount: score, criticalCount: Math.floor(score / 25),
  }));
}

describe("Continuous Monitor", () => {
  it("should detect risk spike", () => {
    const history = makeHistory([20, 22, 18, 20]);
    const findings = analyzeRiskTrend(history, 65);
    expect(findings.some((f) => f.rule === "RISK_TREND_SPIKE")).toBe(true);
  });

  it("should detect increasing trend", () => {
    const history = makeHistory([10, 12, 15, 18, 22, 28, 35, 40, 45, 50]);
    const findings = analyzeRiskTrend(history, 55);
    expect(findings.some((f) => f.rule === "RISK_TREND_INCREASING")).toBe(true);
  });

  it("should detect stagnation at high risk", () => {
    const history = makeHistory([55, 60, 58, 62, 59]);
    const findings = analyzeRiskTrend(history, 61);
    expect(findings.some((f) => f.rule === "RISK_STAGNATION_HIGH")).toBe(true);
  });

  it("does not report stagnation or an upward trend for a scan that is clean now", () => {
    // Measured on a real repository: five scans at 100, then the fix. The
    // window has to end with the current scan, or the clean scan is told its
    // risk "remained above 50".
    const history = makeHistory([100, 100, 5, 15, 100, 100, 100, 100, 100, 100]);
    const rules = analyzeRiskTrend(history, 0).map((f) => f.rule);
    expect(rules).not.toContain("RISK_STAGNATION_HIGH");
    expect(rules).not.toContain("RISK_TREND_INCREASING");
    // Control: the same history with a still-high current scan keeps both.
    const still = analyzeRiskTrend(makeHistory([10, 10, 10, 10, 10, 100, 100, 100, 100, 100]), 100).map((f) => f.rule);
    expect(still).toContain("RISK_STAGNATION_HIGH");
    expect(still).toContain("RISK_TREND_INCREASING");
  });

  it("does not report a rising trend or a degrading trajectory when this scan dropped", () => {
    // A climb that the current scan has just ended. The recent average is
    // still carried by the earlier scans, and the fitted slope by the climb.
    const climb = makeHistory([10, 12, 14, 16, 18, 55, 60, 65, 70, 75]);
    const rules = [...analyzeRiskTrend(climb, 0), ...forecastRisk(climb, 0)].map((f) => f.rule);
    expect(rules).not.toContain("RISK_TREND_INCREASING");
    expect(rules).not.toContain("RISK_TRAJECTORY_DEGRADING");
    // A steep, long climb keeps the fitted slope above 5 even with this scan
    // in the window (+6.2 for 30 after 0..90); only this scan sitting below
    // the window's average (48) shows it is not a rise.
    const steep = makeHistory([0, 10, 20, 30, 40, 50, 60, 70, 80, 90]);
    expect(forecastRisk(steep, 30).map((f) => f.rule)).not.toContain("RISK_TRAJECTORY_DEGRADING");
    expect(forecastRisk(steep, 60).map((f) => f.rule)).toContain("RISK_TRAJECTORY_DEGRADING");
    // Control: the climb continuing into this scan keeps both.
    const rising = [...analyzeRiskTrend(climb, 80), ...forecastRisk(climb, 80)].map((f) => f.rule);
    expect(rising).toContain("RISK_TREND_INCREASING");
    expect(rising).toContain("RISK_TRAJECTORY_DEGRADING");
  });

  it("should return empty for stable low risk", () => {
    const history = makeHistory([5, 6, 4, 5, 6]);
    const findings = analyzeRiskTrend(history, 5);
    expect(findings).toHaveLength(0);
  });

  it("should return empty for insufficient history", () => {
    const findings = analyzeRiskTrend([makeHistory([10])[0]], 10);
    expect(findings).toHaveLength(0);
  });

  it("should determine risk trend direction", () => {
    expect(getRiskTrend(makeHistory([10, 20, 30]))).toBe("increasing");
    expect(getRiskTrend(makeHistory([30, 20, 10]))).toBe("decreasing");
    expect(getRiskTrend(makeHistory([20, 21, 20]))).toBe("stable");
  });
});
