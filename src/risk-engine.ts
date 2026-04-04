/**
 * Adaptive risk scoring engine (v4.5).
 *
 * Multi-dimensional risk scoring that considers repo trust, code risk,
 * dependency risk, CI/CD risk, and threat intelligence matches.
 * Produces a weighted overall score with confidence.
 */

import type { Finding, RiskDimensions, Severity } from "./types.js";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 10,
  high: 6,
  medium: 3,
  low: 1,
  info: 0,
};

/**
 * Calculate multi-dimensional risk score from findings.
 */
export function calculateRiskDimensions(findings: Finding[]): RiskDimensions {
  const repoTrust = calcDimension(findings, [
    "REPO_", "README_LURE_", "RELEASE_", "CAMPAIGN_", "TRUST_",
  ]);
  const codeRisk = calcDimension(findings, [
    "EVAL_", "FUNCTION_ATOB", "INVISIBLE_UNICODE", "HIGH_ENTROPY",
    "GLASSWORM", "VIDAR_", "GHOSTSOCKS", "DROPPER_", "DEAD_DROP_",
    "TEMPLATE_LITERAL", "PROXY_HANDLER", "IMPORT_EXPRESSION",
    "STEGANOGRAPHY", "SVG_SCRIPT", "RTL_OVERRIDE", "CODE_",
  ]);
  const dependencyRisk = calcDimension(findings, [
    "IOC_KNOWN_BAD_VERSION", "TYPOSQUAT_", "DEP_", "LOCKFILE_",
    "MALICIOUS_PACKAGE", "INSTALL_HOOK_", "PUBLISH_", "PACKAGE_",
  ]);
  const ciCdRisk = calcDimension(findings, [
    "GHA_", "CI_", "DOCKER_", "IAC_", "CONFIG_",
  ]);
  const threatIntelMatches = findings.filter(
    (f) => f.rule === "THREAT_INTEL_MATCH" || f.rule.startsWith("IOC_KNOWN_"),
  ).length;

  // Weighted overall (code risk heaviest, then deps, then repo, then CI)
  const raw =
    codeRisk * 0.35 +
    dependencyRisk * 0.30 +
    repoTrust * 0.20 +
    ciCdRisk * 0.15;
  const overallScore = Math.min(100, Math.round(raw));

  // Confidence based on number of findings and correlations
  const totalFindings = findings.filter((f) => f.severity !== "info").length;
  const correlatedFindings = findings.filter((f) => f.correlationId).length;
  let confidence = 0.5;
  if (totalFindings > 0) confidence = Math.min(1.0, 0.5 + totalFindings * 0.05);
  if (correlatedFindings > 0) confidence = Math.min(1.0, confidence + 0.1);
  if (threatIntelMatches > 0) confidence = Math.min(1.0, confidence + 0.15);

  return {
    repoTrust,
    codeRisk,
    dependencyRisk,
    ciCdRisk,
    threatIntelMatches,
    overallScore,
    confidence: Math.round(confidence * 100) / 100,
  };
}

/**
 * Calculate risk score for a single dimension based on matching rule prefixes.
 */
function calcDimension(findings: Finding[], prefixes: string[]): number {
  let score = 0;
  for (const f of findings) {
    const matches = prefixes.some((p) => f.rule.startsWith(p));
    if (matches) {
      const confidence = f.confidence ?? 1.0;
      score += SEVERITY_WEIGHTS[f.severity] * confidence;
    }
  }
  return Math.min(100, Math.round(score));
}
