import { describe, it, expect } from "vitest";
import { calculateRiskDimensions } from "../risk-engine.js";
import type { Finding } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" | "medium" = "high"): Finding {
  return { rule, description: "test", severity, recommendation: "test" };
}

describe("Risk Engine", () => {
  it("should return zero dimensions for no findings", () => {
    const dims = calculateRiskDimensions([]);
    expect(dims.overallScore).toBe(0);
    expect(dims.codeRisk).toBe(0);
    expect(dims.dependencyRisk).toBe(0);
    expect(dims.repoTrust).toBe(0);
    expect(dims.ciCdRisk).toBe(0);
  });

  it("should score code risk findings", () => {
    const dims = calculateRiskDimensions([
      makeFinding("EVAL_ATOB", "critical"),
      makeFinding("GLASSWORM_MARKER", "critical"),
    ]);
    expect(dims.codeRisk).toBeGreaterThan(0);
    expect(dims.overallScore).toBeGreaterThan(0);
  });

  it("should score dependency risk findings", () => {
    const dims = calculateRiskDimensions([
      makeFinding("IOC_KNOWN_BAD_VERSION", "critical"),
      makeFinding("TYPOSQUAT_LEVENSHTEIN"),
    ]);
    expect(dims.dependencyRisk).toBeGreaterThan(0);
  });

  it("should score CI/CD risk findings", () => {
    const dims = calculateRiskDimensions([
      makeFinding("GHA_CURL_PIPE_EXEC", "critical"),
      makeFinding("DOCKER_CURL_PIPE", "critical"),
    ]);
    expect(dims.ciCdRisk).toBeGreaterThan(0);
  });

  it("should count threat intel matches", () => {
    const dims = calculateRiskDimensions([
      makeFinding("THREAT_INTEL_MATCH", "critical"),
      makeFinding("IOC_KNOWN_C2_DOMAIN", "critical"),
    ]);
    expect(dims.threatIntelMatches).toBe(2);
  });

  it("should boost confidence with correlated findings", () => {
    const findings = [makeFinding("EVAL_ATOB", "critical")];
    findings[0].correlationId = "incident-1";
    const dims = calculateRiskDimensions(findings);
    expect(dims.confidence).toBeGreaterThan(0.5);
  });

  it("should cap overall score at 100", () => {
    const manyFindings = Array.from({ length: 50 }, () =>
      makeFinding("EVAL_ATOB", "critical"),
    );
    const dims = calculateRiskDimensions(manyFindings);
    expect(dims.overallScore).toBeLessThanOrEqual(100);
  });

  it("should not count info findings in confidence", () => {
    const dims = calculateRiskDimensions([
      { rule: "TRUST_LICENSE_PRESENT", description: "test", severity: "info", recommendation: "test" },
    ]);
    expect(dims.confidence).toBe(0.5);
  });
});
