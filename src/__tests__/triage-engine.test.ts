import { describe, it, expect } from "vitest";
import { checkTriageGovernance } from "../triage-engine.js";
import type { Finding, TriageDecision } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" = "critical"): Finding {
  return { rule, description: "test", severity, recommendation: "fix" };
}

describe("Triage Engine", () => {
  // v5.2.20: CRITICAL_FINDING_NO_OWNER only fires for projects that have
  // actually opted into triage (i.e. recorded at least one decision). Firing
  // it by default would cascade a HIGH finding on every critical FP for
  // projects that never use the triage system - exactly what happened during
  // the self-scan in v5.2.19.
  it("should NOT flag critical-without-owner when no triage decisions exist", () => {
    const findings = [makeFinding("EVAL_ATOB")];
    const decisions: TriageDecision[] = [];
    const gov = checkTriageGovernance(findings, decisions);
    expect(gov.some((f) => f.rule === "CRITICAL_FINDING_NO_OWNER")).toBe(false);
  });

  it("should flag critical-without-owner when triage system is in use", () => {
    // Project has a decision for one rule but a new critical finding (HEX_ARRAY)
    // appeared without an assigned owner. Now the meta-finding is meaningful.
    const findings = [makeFinding("EVAL_ATOB"), makeFinding("HEX_ARRAY")];
    const decisions: TriageDecision[] = [{
      findingRule: "EVAL_ATOB", status: "triaged", owner: "security-team",
      decidedAt: new Date().toISOString(),
    }];
    const gov = checkTriageGovernance(findings, decisions);
    expect(gov.some((f) => f.rule === "CRITICAL_FINDING_NO_OWNER")).toBe(true);
  });

  it("should not flag when all critical findings have owners", () => {
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
