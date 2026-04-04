import { describe, it, expect } from "vitest";
import { checkTriageGovernance } from "../triage-engine.js";
import type { Finding, TriageDecision } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" = "critical"): Finding {
  return { rule, description: "test", severity, recommendation: "fix" };
}

describe("Triage Engine", () => {
  it("should flag critical findings without owner", () => {
    const findings = [makeFinding("EVAL_ATOB")];
    const decisions: TriageDecision[] = [];
    const gov = checkTriageGovernance(findings, decisions);
    expect(gov.some((f) => f.rule === "CRITICAL_FINDING_NO_OWNER")).toBe(true);
  });

  it("should not flag when critical findings have owners", () => {
    const findings = [makeFinding("EVAL_ATOB")];
    const decisions: TriageDecision[] = [{
      findingRule: "EVAL_ATOB", status: "triaged", owner: "security-team",
      decidedAt: new Date().toISOString(),
    }];
    const gov = checkTriageGovernance(findings, decisions);
    expect(gov.some((f) => f.rule === "CRITICAL_FINDING_NO_OWNER")).toBe(false);
  });

  it("should flag risk acceptances without expiry", () => {
    const decisions: TriageDecision[] = [{
      findingRule: "HEX_ARRAY", status: "accepted-risk", reason: "Low risk",
      decidedAt: new Date().toISOString(),
    }];
    const gov = checkTriageGovernance([], decisions);
    expect(gov.some((f) => f.rule === "RISK_ACCEPTED_WITHOUT_EXPIRY")).toBe(true);
  });

  it("should flag expired risk acceptances", () => {
    const decisions: TriageDecision[] = [{
      findingRule: "HEX_ARRAY", status: "accepted-risk",
      decidedAt: "2025-01-01T00:00:00Z", dueDate: "2025-06-01T00:00:00Z",
    }];
    const gov = checkTriageGovernance([], decisions);
    expect(gov.some((f) => f.rule === "RISK_ACCEPTANCE_EXPIRED")).toBe(true);
  });

  it("should flag stale findings in triage", () => {
    const decisions: TriageDecision[] = [{
      findingRule: "EVAL_ATOB", status: "triaged",
      decidedAt: new Date(Date.now() - 40 * 86400000).toISOString(),
    }];
    const gov = checkTriageGovernance([], decisions);
    expect(gov.some((f) => f.rule === "STALE_CRITICAL_FINDING")).toBe(true);
  });

  it("should return empty for clean state", () => {
    const gov = checkTriageGovernance([], []);
    expect(gov).toHaveLength(0);
  });
});
