import { describe, it, expect } from "vitest";
import { calculateTrustBreakdown } from "../trust-breakdown.js";
import type { Finding } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" | "medium" | "low" = "high"): Finding {
  return { rule, description: "test", severity, recommendation: "test" };
}

describe("Trust Breakdown", () => {
  it("should return high scores for clean package", () => {
    const tb = calculateTrustBreakdown([], "clean-package", true);
    expect(tb.overallScore).toBeGreaterThan(80);
    expect(tb.publisherTrust.score).toBe(100);
    expect(tb.codeQuality.score).toBe(100);
    expect(tb.dependencyTrust.score).toBe(100);
    expect(tb.releaseProcess.score).toBe(100);
  });

  it("should penalize maintainer change", () => {
    const findings = [makeFinding("PUBLISH_MAINTAINER_CHANGE", "critical")];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.publisherTrust.score).toBeLessThan(70);
  });

  it("should penalize critical findings in code quality", () => {
    const findings = [
      makeFinding("EVAL_ATOB", "critical"),
      makeFinding("EVAL_BUFFER", "critical"),
    ];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.codeQuality.score).toBeLessThan(60);
  });

  it("should penalize known bad versions", () => {
    const findings = [makeFinding("IOC_KNOWN_BAD_VERSION", "critical")];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.dependencyTrust.score).toBeLessThanOrEqual(50);
  });

  it("does not penalize informational lockfile inventory observations", () => {
    const findings: Finding[] = [
      {
        rule: "LOCKFILE_ORPHANED_DEPENDENCY",
        description: "normal npm transitive inventory",
        severity: "info",
        recommendation: "review",
      },
    ];
    const tb = calculateTrustBreakdown(findings, "test", true, "directory");
    expect(tb.dependencyTrust.score).toBe(100);
    expect(tb.overallScore).toBe(100);
  });

  it("should penalize suspicious releases", () => {
    const findings = [
      makeFinding("RELEASE_EXE_ARTIFACT", "critical"),
      makeFinding("RELEASE_7Z_ARCHIVE"),
    ];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.releaseProcess.score).toBeLessThan(80);
  });

  it("should give zero publisher trust for known malicious accounts", () => {
    const findings = [makeFinding("REPO_KNOWN_MALICIOUS_ACCOUNT", "critical")];
    const tb = calculateTrustBreakdown(findings, "test", false);
    expect(tb.publisherTrust.score).toBe(0);
  });

  it("should include indicators with status", () => {
    const findings = [makeFinding("EVAL_ATOB", "critical")];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.codeQuality.indicators.length).toBeGreaterThan(0);
    expect(tb.codeQuality.indicators.some((i) => i.status === "red")).toBe(true);
  });

  it("should weight overall score correctly", () => {
    // Overall = publisher*0.4 + code*0.3 + dep*0.2 + release*0.1
    const tb = calculateTrustBreakdown([], "test", true);
    const expected = Math.round(100 * 0.4 + 100 * 0.3 + 100 * 0.2 + 100 * 0.1);
    expect(tb.overallScore).toBe(expected);
  });

  // ── Issue #202: Directory scan trust breakdown renormalisation & unassessed dimensions ──
  it("does not assert publisher or release process facts on a directory scan", () => {
    const tb = calculateTrustBreakdown([], "local-dir", true, "directory");
    expect(tb.publisherTrust.assessed).toBe(false);
    expect(tb.releaseProcess.assessed).toBe(false);

    // Indicators must not emit affirmative claims about unexamined metadata
    const allPublisherDetails = tb.publisherTrust.indicators.map((i) => i.detail).join(" ");
    expect(allPublisherDetails).not.toContain("Established publisher account");
    expect(allPublisherDetails).not.toContain("No recent maintainer changes");
    expect(allPublisherDetails).toContain("Not assessed");

    const allReleaseDetails = tb.releaseProcess.indicators.map((i) => i.detail).join(" ");
    expect(allReleaseDetails).not.toContain("Clean release artifacts");
    expect(allReleaseDetails).toContain("Not assessed");
  });

  it("renormalises overall trust score in a directory scan so malware is not bounded by 50", () => {
    // Infostealer fixture findings: DEAD_DROP_STEAM, EVAL_ATOB, VIDAR_BROWSER_THEFT
    const findings = [
      makeFinding("DEAD_DROP_STEAM", "critical"),
      makeFinding("EVAL_ATOB", "critical"),
      makeFinding("VIDAR_BROWSER_THEFT", "critical"),
    ];
    const tb = calculateTrustBreakdown(findings, "local-malware", true, "directory");

    // Code quality is heavily penalized
    expect(tb.codeQuality.score).toBeLessThanOrEqual(30);

    // Overall score is renormalised over Code Quality (0.3) + Dependency Trust (0.2)
    // with sum of weights = 0.5. It must NOT land at 85/100 or be bounded above 50!
    expect(tb.overallScore).toBeLessThanOrEqual(58);
    expect(tb.overallScore).not.toBe(85);
  });

  it("renders [not assessed] in text report format for directory scan", async () => {
    const { formatReport } = await import("../reporter.js");
    const findings = [
      makeFinding("DEAD_DROP_STEAM", "critical"),
      makeFinding("EVAL_ATOB", "critical"),
      makeFinding("VIDAR_BROWSER_THEFT", "critical"),
    ];
    const tb = calculateTrustBreakdown(findings, "local-malware", true, "directory");
    const mockReport: any = {
      tool: "supply-chain-guard@5.28.1",
      target: "local-malware",
      scanType: "directory",
      timestamp: new Date().toISOString(),
      findings,
      trustBreakdown: tb,
      summary: { totalFiles: 5, filesScanned: 5, critical: 3, high: 0, medium: 0, low: 0, info: 0 },
      score: 90,
      riskLevel: "critical",
      recommendations: ["Remove the file"],
      durationMs: 50,
      version: "5.28.1",
    };
    const rendered = formatReport(mockReport, "text");
    expect(rendered).toContain("Publisher     \x1b[2m[not assessed]\x1b[0m");
    expect(rendered).toContain("Release       \x1b[2m[not assessed]\x1b[0m");
    expect(rendered).not.toMatch(/Publisher\s+100\/100/);
    expect(rendered).not.toMatch(/Release\s+100\/100/);
  });
});
