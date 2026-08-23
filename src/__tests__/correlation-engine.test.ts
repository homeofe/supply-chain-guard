import { describe, it, expect } from "vitest";
import { correlateFindings, CORRELATION_RULES } from "../correlation-engine.js";
import type { Finding } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" | "medium" = "high"): Finding {
  return {
    rule,
    description: `Test finding for ${rule}`,
    severity,
    recommendation: "Test recommendation",
  };
}

describe("Correlation Engine", () => {
  it("should detect GlassWorm campaign cluster", () => {
    const findings = [
      makeFinding("GLASSWORM_MARKER", "critical"),
      makeFinding("EVAL_ATOB", "critical"),
      makeFinding("ENV_EXFILTRATION"),
    ];
    const result = correlateFindings(findings);
    expect(result.incidents.length).toBeGreaterThan(0);
    expect(result.incidents[0].name).toBe("GlassWorm Campaign");
    expect(result.incidents[0].severity).toBe("critical");
  });

  it("should detect Claude Code leak campaign", () => {
    const findings = [
      makeFinding("CAMPAIGN_CLAUDE_LURE", "critical"),
      makeFinding("RELEASE_EXE_ARTIFACT", "critical"),
      makeFinding("DEAD_DROP_STEAM", "critical"),
    ];
    const result = correlateFindings(findings);
    expect(result.incidents.some((i) => i.name.includes("Claude Code"))).toBe(true);
  });

  it("should detect npm account takeover", () => {
    const findings = [
      makeFinding("PUBLISH_MAINTAINER_CHANGE", "critical"),
      makeFinding("INSTALL_HOOK_NETWORK", "critical"),
    ];
    const result = correlateFindings(findings);
    expect(result.incidents.some((i) => i.name.includes("Account Takeover") || i.name.includes("Package Hijack"))).toBe(true);
  });

  it("should detect fake repo malware", () => {
    const findings = [
      makeFinding("README_LURE_CRACK", "critical"),
      makeFinding("RELEASE_EXE_ARTIFACT", "critical"),
      makeFinding("REPO_RECENT_CREATION"),
    ];
    const result = correlateFindings(findings);
    expect(result.incidents.some((i) => i.name.includes("Fake Repository"))).toBe(true);
  });

  it("should boost confidence on correlated findings", () => {
    const findings = [
      makeFinding("DEAD_DROP_STEAM", "critical"),
      makeFinding("VIDAR_BROWSER_THEFT"),
    ];
    const result = correlateFindings(findings);
    expect(findings[0].confidence).toBeGreaterThan(0.8);
    expect(result.incidents.length).toBeGreaterThan(0);
  });

  // ── Issue #203: Match-strength confidence calibration & indicator counts ──
  it("reports higher confidence for full match than for minimum match on the same rule", () => {
    // Claude Code Leak Campaign requires minMatch=2 of 4 rules:
    // CAMPAIGN_CLAUDE_LURE, RELEASE_EXE_ARTIFACT, DEAD_DROP_STEAM, VIDAR_BROWSER_THEFT
    const minMatchFindings = [
      makeFinding("DEAD_DROP_STEAM", "critical"),
      makeFinding("VIDAR_BROWSER_THEFT", "critical"),
    ];
    const minResult = correlateFindings(minMatchFindings);
    const minIncident = minResult.incidents.find((i) => i.name.includes("Claude Code"));
    expect(minIncident).toBeDefined();

    const fullMatchFindings = [
      makeFinding("CAMPAIGN_CLAUDE_LURE", "critical"),
      makeFinding("RELEASE_EXE_ARTIFACT", "critical"),
      makeFinding("DEAD_DROP_STEAM", "critical"),
      makeFinding("VIDAR_BROWSER_THEFT", "critical"),
    ];
    const fullResult = correlateFindings(fullMatchFindings);
    const fullIncident = fullResult.incidents.find((i) => i.name.includes("Claude Code"));
    expect(fullIncident).toBeDefined();

    // Strict ordering assertion: full match must be strictly greater than minimum match
    expect(fullIncident!.confidence).toBeGreaterThan(minIncident!.confidence);
    expect(fullIncident!.confidence).toBe(1.0);
    expect(minIncident!.confidence).toBeLessThan(1.0);

    // Indicator count assertions
    expect(minIncident!.matchedIndicatorsCount).toBe(2);
    expect(minIncident!.totalIndicatorsCount).toBe(4);
    expect(fullIncident!.matchedIndicatorsCount).toBe(4);
    expect(fullIncident!.totalIndicatorsCount).toBe(4);
  });

  it("ensures only a small minority of correlation rules report 100% confidence on minimum match", () => {
    // Collect every rule and test its confidence on minimum match
    let count100 = 0;
    let totalTested = 0;

    for (const rule of CORRELATION_RULES) {
      const minMatch = rule.minMatch ?? rule.rules.length;
      const matched = rule.rules.slice(0, minMatch);
      // Ensure strong requirement is met if applicable
      if (rule.requireAnyOf && !rule.requireAnyOf.some((r: string) => matched.includes(r))) {
        matched[0] = rule.requireAnyOf[0];
      }
      const findings = matched.map((r: string) => makeFinding(r, "critical"));
      const res = correlateFindings(findings);
      const inc = res.incidents.find((i) => i.name === rule.incident);
      if (inc) {
        totalTested++;
        if (inc.confidence === 1.0) count100++;
      }
    }

    expect(totalTested).toBeGreaterThanOrEqual(15);
    // Only rules with minMatch === total (e.g. 2 of 2) should report 100% on minimum match
    expect(count100 / totalTested).toBeLessThanOrEqual(0.25);
  });

  it("should calculate risk boost", () => {
    const findings = [
      makeFinding("GLASSWORM_MARKER", "critical"),
      makeFinding("EVAL_ATOB", "critical"),
    ];
    const result = correlateFindings(findings);
    expect(result.riskBoost).toBeGreaterThan(0);
    expect(result.riskBoost).toBeLessThanOrEqual(30);
  });

  it("should generate insights", () => {
    const findings = [
      makeFinding("CAMPAIGN_AI_TOOL_LURE", "critical"),
      makeFinding("RELEASE_EXE_ARTIFACT", "critical"),
    ];
    const result = correlateFindings(findings);
    expect(result.insights.length).toBeGreaterThan(0);
  });

  it("should return empty for uncorrelated findings", () => {
    const findings = [
      makeFinding("CONFIG_UNSAFE_PERM", "medium"),
      makeFinding("DOCKER_NPM_GLOBAL", "medium"),
    ];
    const result = correlateFindings(findings);
    expect(result.incidents).toHaveLength(0);
    expect(result.riskBoost).toBe(0);
  });

  it("should sort incidents by confidence descending", () => {
    const findings = [
      makeFinding("GLASSWORM_MARKER", "critical"),
      makeFinding("EVAL_ATOB", "critical"),
      makeFinding("CAMPAIGN_CLAUDE_LURE", "critical"),
      makeFinding("RELEASE_EXE_ARTIFACT", "critical"),
      makeFinding("DEAD_DROP_STEAM", "critical"),
    ];
    const result = correlateFindings(findings);
    for (let i = 1; i < result.incidents.length; i++) {
      expect(result.incidents[i].confidence).toBeLessThanOrEqual(result.incidents[i - 1].confidence);
    }
  });

  it("should set correlationId on matched findings", () => {
    const findings = [
      makeFinding("GHOSTSOCKS_SOCKS5", "critical"),
      makeFinding("PROXY_BACKCONNECT"),
    ];
    correlateFindings(findings);
    expect(findings[0].correlationId).toBeTruthy();
    expect(findings[0].correlationId).toBe(findings[1].correlationId);
  });

  it("should include narrative in incidents", () => {
    const findings = [
      makeFinding("TYPOSQUAT_LEVENSHTEIN"),
      makeFinding("INSTALL_HOOK_NETWORK", "critical"),
    ];
    const result = correlateFindings(findings);
    if (result.incidents.length > 0) {
      expect(result.incidents[0].narrative.length).toBeGreaterThan(10);
    }
  });

  it("should compound Cordyceps CI/CD composition symptoms into one incident (v5.7)", () => {
    const findings = [
      makeFinding("GHA_PWN_REQUEST_CHECKOUT", "critical"),
      makeFinding("GHA_CROSS_WORKFLOW_ARTIFACT_TRUST", "critical"),
    ];
    const result = correlateFindings(findings);
    expect(result.incidents.some((i) => i.name.includes("Cordyceps"))).toBe(true);
    const incident = result.incidents.find((i) => i.name.includes("Cordyceps"));
    expect(incident?.severity).toBe("critical");
  });

  it("should NOT fabricate a Cordyceps incident from two benign hygiene findings (v5.7 fix)", () => {
    // GHA_PRIVILEGED_TRIGGER and GHA_PERMS_DEFAULT_BROAD always co-occur on an
    // ordinary pull_request_target bot with no permissions block. Without a
    // genuinely-independent strong signal, this must NOT escalate to a critical
    // composition incident.
    const findings = [
      makeFinding("GHA_PRIVILEGED_TRIGGER", "medium"),
      makeFinding("GHA_PERMS_DEFAULT_BROAD", "medium"),
    ];
    const result = correlateFindings(findings);
    expect(result.incidents.some((i) => i.name.includes("Cordyceps"))).toBe(false);
  });

  it("correlates untrusted prompt + public post into the GitLost incident", () => {
    const findings = [
      makeFinding("GHA_AGENT_UNTRUSTED_PROMPT", "critical"),
      makeFinding("GHA_AGENT_PUBLIC_POST", "high"),
    ];
    const result = correlateFindings(findings);
    const inc = result.incidents.find((i) => i.name.includes("GitLost"));
    expect(inc).toBeDefined();
    expect(inc!.severity).toBe("critical");
  });

  it("does NOT fire the GitLost incident on medium hygiene rules alone", () => {
    const findings = [
      makeFinding("AGENTIC_WF_UNTRUSTED_TRIGGER", "medium"),
      makeFinding("GHA_AGENT_NO_AUTHOR_GATE", "medium"),
    ];
    const result = correlateFindings(findings);
    expect(result.incidents.some((i) => i.name.includes("GitLost"))).toBe(false);
  });
});
