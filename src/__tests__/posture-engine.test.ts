import { describe, it, expect } from "vitest";
import { calculateOrgPosture } from "../posture-engine.js";
import type { ScanReport } from "../types.js";

function makeReport(score: number, findings: ScanReport["findings"] = []): ScanReport {
  return {
    tool: "test", timestamp: "", target: "", scanType: "directory", durationMs: 0,
    findings, summary: {
      totalFiles: 10, filesScanned: 10,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: 0, low: 0, info: 0,
    },
    score, riskLevel: score > 60 ? "critical" : "low", recommendations: [],
  };
}

describe("Posture Engine", () => {
  it("should calculate org posture score", () => {
    const reports = new Map<string, ScanReport>();
    reports.set("repo1", makeReport(20));
    reports.set("repo2", makeReport(80));
    const posture = calculateOrgPosture("test-org", reports);
    expect(posture.overallPostureScore).toBe(50);
    expect(posture.reposScanned).toBe(2);
  });

  it("should identify top risky repos", () => {
    const reports = new Map<string, ScanReport>();
    reports.set("safe-repo", makeReport(5));
    reports.set("risky-repo", makeReport(90));
    const posture = calculateOrgPosture("test-org", reports);
    expect(posture.topRiskyRepos[0].repo).toBe("risky-repo");
  });

  it("should detect systemic policy drift", () => {
    const reports = new Map<string, ScanReport>();
    for (let i = 0; i < 6; i++) {
      reports.set(`repo${i}`, makeReport(30, [
        { rule: "GHA_UNPINNED_ACTION", description: "test", severity: "high", recommendation: "fix" },
      ]));
    }
    const posture = calculateOrgPosture("test-org", reports);
    expect(posture.systemicFindings.some((f) => f.rule === "ORG_SYSTEMIC_POLICY_DRIFT")).toBe(true);
  });

  it("should track recurring risky packages", () => {
    const reports = new Map<string, ScanReport>();
    reports.set("repo1", makeReport(40, [
      { rule: "TYPOSQUAT_LEVENSHTEIN", description: '"lodas" is...', severity: "high", recommendation: "" },
    ]));
    reports.set("repo2", makeReport(40, [
      { rule: "TYPOSQUAT_LEVENSHTEIN", description: '"lodas" is...', severity: "high", recommendation: "" },
    ]));
    const posture = calculateOrgPosture("test-org", reports);
    expect(posture.recurringPackages.length).toBeGreaterThan(0);
  });
});
