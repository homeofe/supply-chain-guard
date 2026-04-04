/**
 * Active validation framework (v4.7).
 *
 * Provides controlled, optional verification of suspicious artifacts
 * in a safe analysis environment. Static-only by default.
 */

import type { Finding, ValidationMode, ConfidenceTier } from "./types.js";

/**
 * Validate findings by upgrading confidence based on validation mode.
 * In static-only mode, this just assigns confidence tiers.
 * In safe-validate mode, it would run sandboxed checks (future).
 */
export function validateFindings(
  findings: Finding[],
  mode: ValidationMode = "static-only",
): Finding[] {
  for (const f of findings) {
    // Assign confidence tier based on existing evidence
    const tier = determineConfidenceTier(f);

    if (mode === "static-only") {
      // Just assign tier metadata
      f.rationale = f.rationale ?? buildRationale(f, tier);
      f.evidence = f.evidence ?? buildEvidence(f);
    }

    if (mode === "safe-validate" || mode === "detonate-isolated") {
      // In real implementation, this would trigger sandbox analysis
      // For now, mark as validation-ready
      f.rationale = `[${tier}] ${f.rationale ?? buildRationale(f, tier)}`;
    }
  }

  return findings;
}

/**
 * Determine the confidence tier for a finding.
 */
function determineConfidenceTier(f: Finding): ConfidenceTier {
  // Threat intel matches are highest confidence
  if (f.rule.startsWith("IOC_KNOWN_") || f.rule === "THREAT_INTEL_MATCH") {
    return "confirmed";
  }

  // Correlated findings (part of an incident cluster)
  if (f.correlationId) {
    return "correlated";
  }

  // High-confidence heuristic patterns
  if (f.confidence && f.confidence >= 0.9) {
    return "validated";
  }

  return "heuristic";
}

/**
 * Build a human-readable rationale for why this finding was flagged.
 */
function buildRationale(f: Finding, tier: ConfidenceTier): string {
  const tierDesc: Record<ConfidenceTier, string> = {
    heuristic: "Detected by pattern matching",
    correlated: "Correlated with other findings in an incident cluster",
    validated: "High-confidence match with strong indicators",
    confirmed: "Matched against confirmed threat intelligence",
  };

  return `${tierDesc[tier]}. ${f.description}`;
}

/**
 * Build evidence string from finding metadata.
 */
function buildEvidence(f: Finding): string {
  const parts: string[] = [];
  if (f.file) parts.push(`File: ${f.file}${f.line ? `:${f.line}` : ""}`);
  if (f.match) parts.push(`Match: ${f.match}`);
  if (f.confidence) parts.push(`Confidence: ${Math.round(f.confidence * 100)}%`);
  if (f.correlationId) parts.push(`Incident: ${f.correlationId}`);
  return parts.join(" | ");
}

/**
 * Promote or demote finding confidence based on validation results.
 */
export function promoteConfidence(
  finding: Finding,
  validationResult: "confirmed" | "inconclusive" | "negative",
): Finding {
  switch (validationResult) {
    case "confirmed":
      finding.confidence = Math.min(1.0, (finding.confidence ?? 0.8) + 0.15);
      finding.rationale = `[VALIDATED] ${finding.rationale ?? finding.description}`;
      break;
    case "negative":
      finding.confidence = Math.max(0.1, (finding.confidence ?? 0.8) - 0.3);
      finding.rationale = `[REDUCED] Validation did not confirm behavior. ${finding.rationale ?? ""}`;
      break;
    case "inconclusive":
      // No change
      break;
  }
  return finding;
}
