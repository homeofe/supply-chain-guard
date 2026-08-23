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

  // The old assertion here read `resolved` + `triaged` with empty decidedAt
  // values as 50 percent, which was a RESOLUTION rate wearing the SLA name.
  // Under the single definition in src/sla-engine.ts, `triaged` past its
  // deadline is the only thing that lowers the rate, and the arithmetic is
  // driven by breaches rather than by how far along the workflow an item is.
  it("counts a breached decision against the rate and an open one for it", () => {
    const day = 24 * 60 * 60 * 1000;
    const decisions: TriageDecision[] = [
      {
        findingRule: "A_CRITICAL",
        status: "triaged",
        decidedAt: new Date(Date.now() - 30 * day).toISOString(),
      },
      {
        findingRule: "B_CRITICAL",
        status: "triaged",
        decidedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
      },
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

  // Replaces the assertion that pinned the third defect in the issue: an empty
  // decision set used to report 100, so a project that had never adopted triage
  // was indistinguishable from one with a perfect record. `null` says "not
  // measured", and stays a present key in JSON output where `undefined` would
  // be dropped.
  it("reports null, not 100, when there are no decisions to measure", () => {
    const m = calculateMetrics([], [], []);
    expect(m.slaComplianceRate).toBeNull();
  });
});
