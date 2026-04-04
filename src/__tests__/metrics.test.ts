import { describe, it, expect } from "vitest";
import { calculateMetrics } from "../metrics.js";
import type { Finding, RiskHistoryEntry, TriageDecision } from "../types.js";

describe("Metrics", () => {
  it("should calculate open critical/high counts", () => {
    const findings: Finding[] = [
      { rule: "A", description: "", severity: "critical", recommendation: "" },
      { rule: "B", description: "", severity: "high", recommendation: "" },
      { rule: "C", description: "", severity: "info", recommendation: "" },
    ];
    const m = calculateMetrics(findings, [], []);
    expect(m.openCritical).toBe(1);
    expect(m.openHigh).toBe(1);
  });

  it("should exclude resolved findings from open counts", () => {
    const findings: Finding[] = [
      { rule: "A", description: "", severity: "critical", recommendation: "" },
    ];
    const decisions: TriageDecision[] = [
      { findingRule: "A", status: "resolved", decidedAt: new Date().toISOString() },
    ];
    const m = calculateMetrics(findings, [], decisions);
    expect(m.openCritical).toBe(0);
  });

  it("should calculate SLA compliance rate", () => {
    const decisions: TriageDecision[] = [
      { findingRule: "A", status: "resolved", decidedAt: "" },
      { findingRule: "B", status: "triaged", decidedAt: "" },
    ];
    const m = calculateMetrics([], [], decisions);
    expect(m.slaComplianceRate).toBe(50);
  });

  it("should detect risk trend", () => {
    const history: RiskHistoryEntry[] = [
      { timestamp: "", score: 10, findingsCount: 1, criticalCount: 0 },
      { timestamp: "", score: 20, findingsCount: 2, criticalCount: 0 },
      { timestamp: "", score: 40, findingsCount: 4, criticalCount: 1 },
    ];
    const m = calculateMetrics([], history, []);
    expect(m.riskTrend).toBe("increasing");
  });

  it("should identify top risk contributors", () => {
    const findings: Finding[] = [
      { rule: "EVAL_ATOB", description: "", severity: "critical", recommendation: "" },
      { rule: "EVAL_ATOB", description: "", severity: "critical", recommendation: "" },
      { rule: "OTHER", description: "", severity: "high", recommendation: "" },
    ];
    const m = calculateMetrics(findings, [], []);
    expect(m.topRiskContributors[0]).toBe("EVAL_ATOB");
  });

  it("should return 100% compliance when no decisions", () => {
    const m = calculateMetrics([], [], []);
    expect(m.slaComplianceRate).toBe(100);
  });
});
