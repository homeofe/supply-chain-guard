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

  it("includes the current scan in the trend window (issue 206)", () => {
    // Two previous scans at 40. Without the current score the window is only
    // two points and reports stable. With a collapsed current score of 0 the
    // window is 40, 40, 0 and must report decreasing. That is the moment the
    // KPI used to disagree with RISK_TREND_SPIKE in the same report.
    const history: RiskHistoryEntry[] = [
      { timestamp: "", score: 40, findingsCount: 4, criticalCount: 1 },
      { timestamp: "", score: 40, findingsCount: 4, criticalCount: 1 },
    ];
    expect(calculateMetrics([], history, []).riskTrend).toBe("stable");
    expect(calculateMetrics([], history, [], undefined, 0).riskTrend).toBe("decreasing");
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

// ── Triage scope: a decision identifies a (rule, file) pair ──────────────
//
// Regression cover for the class "a key narrower than the thing it identifies
// silently merges rows". calculateMetrics built its resolved set from
// findingRule alone, so resolving one instance of a rule removed every
// instance of that rule from openCritical and openHigh, including instances in
// files nobody had looked at.
//
// Every case below needs at least TWO findings of the SAME rule in DIFFERENT
// files. With one instance per rule, a rule-keyed set and a (rule, file)-keyed
// set are mathematically indistinguishable, which is why the six cases above
// stayed green for the four months the defect was present. A case with one
// instance per rule is not cover for this defect, it is cover next to it.
describe("Metrics: a triage decision is scoped to (rule, file)", () => {
  const at = (rule: string, file: string | undefined, severity: "critical" | "high"): Finding => ({
    rule,
    description: "",
    severity,
    recommendation: "",
    file,
  });

  const resolved = (findingRule: string, findingFile: string | undefined): TriageDecision => ({
    findingRule,
    findingFile,
    status: "resolved",
    decidedAt: "2026-08-22T10:00:00.000Z",
  });

  it("POSITIVE CONTROL: with no decisions, every instance of the rule is open", () => {
    // Proves the two-instance fixture itself counts to 2, so a later 2 is a
    // measurement and not an artefact of the fixture being empty.
    const findings = [
      at("IOC_C2_DOMAIN", "src/a.ts", "critical"),
      at("IOC_C2_DOMAIN", "src/b.ts", "critical"),
    ];
    expect(calculateMetrics(findings, [], []).openCritical).toBe(2);
  });

  it("resolving one file leaves the other file of the same rule open", () => {
    const findings = [
      at("IOC_C2_DOMAIN", "src/a.ts", "critical"),
      at("IOC_C2_DOMAIN", "src/b.ts", "critical"),
    ];
    const decisions = [resolved("IOC_C2_DOMAIN", "src/a.ts")];
    expect(calculateMetrics(findings, [], decisions).openCritical).toBe(1);
  });

  it("worked example: three files, one resolved, two still open", () => {
    const findings = [
      at("IOC_C2_DOMAIN", "src/a.ts", "critical"),
      at("IOC_C2_DOMAIN", "src/b.ts", "critical"),
      at("IOC_C2_DOMAIN", "src/c.ts", "critical"),
    ];
    const decisions = [resolved("IOC_C2_DOMAIN", "src/a.ts")];
    expect(calculateMetrics(findings, [], decisions).openCritical).toBe(2);
  });

  it("openHigh is scoped the same way as openCritical", () => {
    const findings = [
      at("INSTALL_HOOK_NETWORK", "src/a.ts", "high"),
      at("INSTALL_HOOK_NETWORK", "src/b.ts", "high"),
    ];
    const decisions = [resolved("INSTALL_HOOK_NETWORK", "src/a.ts")];
    expect(calculateMetrics(findings, [], decisions).openHigh).toBe(1);
  });

  it("a decision naming a file that has no finding resolves nothing", () => {
    // A decision left behind after its file was deleted or renamed. It matches
    // no finding, so it must not remove any finding from the counts.
    const findings = [
      at("IOC_C2_DOMAIN", "src/a.ts", "critical"),
      at("IOC_C2_DOMAIN", "src/b.ts", "critical"),
    ];
    const decisions = [resolved("IOC_C2_DOMAIN", "vendor/not-scanned.js")];
    expect(calculateMetrics(findings, [], decisions).openCritical).toBe(2);
  });

  it("topRiskContributors still names a rule that has open instances left", () => {
    const findings = [
      at("IOC_C2_DOMAIN", "src/a.ts", "critical"),
      at("IOC_C2_DOMAIN", "src/b.ts", "critical"),
    ];
    const decisions = [resolved("IOC_C2_DOMAIN", "src/a.ts")];
    expect(calculateMetrics(findings, [], decisions).topRiskContributors).toEqual([
      "IOC_C2_DOMAIN",
    ]);
  });

  // ── The documented fallbacks, each pinned by its own case ──────────────

  it("a decision with NO findingFile resolves every instance of the rule", () => {
    // Rule-wide fallback. This is the behaviour the pre-existing case
    // "should exclude resolved findings from open counts" exercises, stated
    // here with more than one file so it cannot be confused with the collapse.
    const findings = [
      at("IOC_C2_DOMAIN", "src/a.ts", "critical"),
      at("IOC_C2_DOMAIN", "src/b.ts", "critical"),
    ];
    const decisions = [resolved("IOC_C2_DOMAIN", undefined)];
    expect(calculateMetrics(findings, [], decisions).openCritical).toBe(0);
  });

  it("an EMPTY findingFile is file-scoped, and its file is the finding with no file", () => {
    // Absent and empty are different on purpose. undefined means "not scoped
    // to a file"; "" means "scoped to the finding that carries no file", which
    // is what a project-level finding looks like. Reading findingFile for
    // truthiness instead of for undefined would silently promote this decision
    // to rule-wide and take the src/a.ts instance with it.
    const findings = [
      at("IOC_C2_DOMAIN", undefined, "critical"),
      at("IOC_C2_DOMAIN", "src/a.ts", "critical"),
    ];
    const decisions = [resolved("IOC_C2_DOMAIN", "")];
    expect(calculateMetrics(findings, [], decisions).openCritical).toBe(1);
  });

  it("only a RESOLVED decision removes a finding from the open counts", () => {
    const findings = [at("IOC_C2_DOMAIN", "src/a.ts", "critical")];
    const decisions: TriageDecision[] = [
      { findingRule: "IOC_C2_DOMAIN", findingFile: "src/a.ts", status: "triaged", decidedAt: "" },
    ];
    expect(calculateMetrics(findings, [], decisions).openCritical).toBe(1);
  });
});
