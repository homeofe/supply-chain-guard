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

  // ── Ownership is scoped to (rule, file), the same way metrics are ──────
  //
  // This check and calculateMetrics read the same decisions array on the same
  // scan. They used to key it at different widths, so one report could say
  // "openCritical: 0" beside "2 critical finding(s) have no assigned owner".
  // Both now ask src/triage-scope.ts. See
  // https://github.com/homeofe/supply-chain-guard/issues/171
  //
  // Fixtures below need a `file` on the findings: with one finding per rule and
  // no file anywhere, a rule-keyed lookup and a (rule, file)-keyed lookup give
  // identical answers, which is why the cases above cannot see the difference.

  it("should flag a critical finding in a file the decision does not name", () => {
    const findings: Finding[] = [
      { ...makeFinding("EVAL_ATOB"), file: "src/a.js" },
      { ...makeFinding("EVAL_ATOB"), file: "src/b.js" },
    ];
    const decisions: TriageDecision[] = [{
      findingRule: "EVAL_ATOB", findingFile: "src/a.js", status: "triaged", owner: "security-team",
      decidedAt: new Date().toISOString(),
    }];
    const gov = checkTriageGovernance(findings, decisions);
    expect(gov.some((f) => f.rule === "CRITICAL_FINDING_NO_OWNER")).toBe(true);
  });

  it("should treat a decision with no findingFile as owning the rule everywhere", () => {
    // Behaviour change shipped with the shared scope rule. The previous key
    // joined `file ?? ""`, so a rule-wide decision matched only findings that
    // carry no file and every instance in a real file stayed "unowned". An
    // absent findingFile means the decision is not scoped to a file at all.
    const findings: Finding[] = [
      { ...makeFinding("EVAL_ATOB"), file: "src/a.js" },
      { ...makeFinding("EVAL_ATOB"), file: "src/b.js" },
    ];
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
