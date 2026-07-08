import { describe, it, expect } from "vitest";
import { correlateFindings } from "../correlation-engine.js";
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
    expect(result.incidents[0]?.confidence).toBeGreaterThan(0.8);
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
