import { describe, it, expect } from "vitest";
import { analyzeRiskTrend, getRiskTrend } from "../continuous-monitor.js";
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
