/**
 * Correlation engine (v4.2) — CORE FEATURE.
 *
 * Aggregates individual findings into incident-level clusters.
 * Links related findings, boosts confidence, generates attack narratives,
 * and reduces noise by grouping related indicators.
 */

import type { Finding, Severity, IncidentCluster } from "./types.js";

// ---------------------------------------------------------------------------
// Correlation rule definitions
// ---------------------------------------------------------------------------

interface CorrelationRule {
  /** Rule IDs that must be present (at least `minMatch` of them) */
  rules: string[];
  /** Minimum number of rules that must match (default: all) */
  minMatch?: number;
  /**
   * If set, the incident only fires when at least one of these "strong" rule
   * IDs is among the matches. Guards against a cluster being satisfied entirely
   * by weak/always-co-occurring hygiene signals (v5.7).
   */
  requireAnyOf?: string[];
  /** Incident name when triggered */
  incident: string;
  /** Resulting severity */
  severity: Severity;
  /** Confidence boost per finding (+0.0 to +0.3) */
  confidenceBoost: number;
  /** Attack narrative template */
  narrative: string;
}

const CORRELATION_RULES: CorrelationRule[] = [
  // --- Known campaigns ---
  {
    rules: ["GLASSWORM_MARKER", "EVAL_ATOB", "ENV_EXFILTRATION", "SOLANA_MAINNET"],
    minMatch: 2,
    incident: "GlassWorm Campaign",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "Multiple GlassWorm indicators detected. This matches the GlassWorm supply-chain malware campaign that uses Solana blockchain for C2 communication.",
  },
  {
    rules: ["CAMPAIGN_CLAUDE_LURE", "RELEASE_EXE_ARTIFACT", "DEAD_DROP_STEAM", "VIDAR_BROWSER_THEFT"],
    minMatch: 2,
    incident: "Claude Code Leak Campaign (Vidar/GhostSocks)",
    severity: "critical",
    confidenceBoost: 0.30,
    narrative: "Matches the April 2026 fake Claude Code campaign distributing Vidar stealer and GhostSocks proxy via GitHub releases with star-farmed repos.",
  },
  {
    rules: ["SHAI_HULUD_WORM", "SHAI_HULUD_CRED_STEAL", "INSTALL_HOOK_NPMRC_READ"],
    minMatch: 2,
    incident: "Shai-Hulud npm Worm",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "Self-replicating npm worm that steals .npmrc tokens and publishes infected copies of packages.",
  },

  // --- Infostealer chains ---
  {
    rules: ["DEAD_DROP_STEAM", "DEAD_DROP_TELEGRAM", "VIDAR_BROWSER_THEFT", "VIDAR_WALLET_THEFT", "DROPPER_TEMP_EXEC"],
    minMatch: 2,
    incident: "Infostealer Infection (Vidar/Lumma/RedLine)",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "Multiple infostealer indicators: dead-drop resolvers for C2, browser credential theft, and crypto wallet targeting. Likely Vidar, Lumma, or RedLine stealer.",
  },
  {
    rules: ["GHOSTSOCKS_SOCKS5", "PROXY_BACKCONNECT", "DROPPER_TEMP_EXEC"],
    minMatch: 2,
    incident: "Proxy Malware (GhostSocks)",
    severity: "critical",
    confidenceBoost: 0.20,
    narrative: "SOCKS5 proxy infrastructure detected. Infected machines are enrolled as residential proxy nodes for criminal traffic routing.",
  },

  // --- Supply-chain attack chains ---
  {
    rules: ["PUBLISH_MAINTAINER_CHANGE", "INSTALL_HOOK_NETWORK", "IOC_KNOWN_C2_DOMAIN"],
    minMatch: 2,
    incident: "npm Account Takeover",
    severity: "critical",
    confidenceBoost: 0.30,
    narrative: "Maintainer change combined with new install hooks contacting known C2 infrastructure. Strong indicator of npm account compromise.",
  },
  {
    rules: ["PUBLISH_MAINTAINER_CHANGE", "PUBLISH_SCRIPT_ADDED", "INSTALL_HOOK_ENV_HARVEST"],
    minMatch: 2,
    incident: "npm Package Hijack (Credential Theft)",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "Package maintainer changed and install scripts added that harvest environment variables. Classic account-takeover-to-credential-theft chain.",
  },
  {
    rules: ["TYPOSQUAT_LEVENSHTEIN", "INSTALL_HOOK_NETWORK", "ENV_EXFILTRATION"],
    minMatch: 2,
    incident: "Typosquatting Attack with Data Exfiltration",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "Typosquatted package name combined with install-time network access and environment exfiltration. Active data theft via name confusion.",
  },

  // --- Fake repo chains ---
  {
    rules: ["README_LURE_CRACK", "RELEASE_EXE_ARTIFACT", "REPO_RECENT_CREATION", "REPO_SINGLE_COMMIT"],
    minMatch: 2,
    incident: "Fake Repository Malware Distribution",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "Recently created repository with piracy/crack lures and executable releases. Classic fake-repo malware distribution pattern.",
  },
  {
    rules: ["CAMPAIGN_AI_TOOL_LURE", "RELEASE_EXE_ARTIFACT", "RELEASE_7Z_ARCHIVE"],
    minMatch: 2,
    incident: "Fake AI Tool Campaign",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "Matches the 2026 campaign impersonating 25+ AI tool brands to distribute infostealers via GitHub releases.",
  },

  // --- CI/CD poisoning ---
  {
    rules: ["GHA_CURL_PIPE_EXEC", "GHA_SECRET_CURL", "GHA_UNPINNED_ACTION"],
    minMatch: 2,
    incident: "CI/CD Pipeline Poisoning",
    severity: "critical",
    confidenceBoost: 0.20,
    narrative: "GitHub Actions workflow downloads and executes remote code while accessing secrets. CI/CD pipeline compromise risk.",
  },

  // --- Cordyceps CI/CD composition (v5.7) ---
  // The single-file GHA symptoms are individually valid YAML; the attack lives
  // in how they compose. Any two of these together is a strong signal that a
  // workflow is exploitable through a trust boundary crossing.
  {
    rules: [
      "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST",
      "GHA_PWN_REQUEST_CHECKOUT",
      "GHA_GITHUB_SCRIPT_INJECTION",
      "GHA_PRIVILEGED_TRIGGER",
      "GHA_SCRIPT_INJECTION",
      "GHA_PERMS_WRITE_ALL",
      "GHA_PERMS_DEFAULT_BROAD",
    ],
    minMatch: 2,
    // The two hygiene rules (GHA_PRIVILEGED_TRIGGER, GHA_PERMS_DEFAULT_BROAD)
    // always co-occur on an ordinary pull_request_target bot, so 2-of-7 alone
    // would false-fire a critical incident on benign repos. Require at least one
    // genuinely-independent strong signal to corroborate.
    requireAnyOf: [
      "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST",
      "GHA_PWN_REQUEST_CHECKOUT",
      "GHA_GITHUB_SCRIPT_INJECTION",
      "GHA_SCRIPT_INJECTION",
      "GHA_PERMS_WRITE_ALL",
    ],
    incident: "Cordyceps CI/CD Composition Attack",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative:
      "Multiple GitHub Actions trust-boundary weaknesses combine into an exploitable chain: a privileged " +
      "trigger runs attacker-influenced input or artifacts with secrets and a write token. This matches the " +
      "Cordyceps composition pattern (novee.security, 2026) - no single line is wrong, but together they " +
      "allow code execution or secret theft across a workflow trust boundary.",
  },

  // --- GitLost-class agentic workflow exfiltration posture (v5.10) ---
  // An AI agent that ingests untrusted issue/PR text, holds a cross-repo token,
  // and can post publicly is the GitLost lethal trifecta (Noma, July 2026). Any
  // two of these together is a strong static signal of the vulnerable posture.
  {
    rules: [
      "GHA_AGENT_UNTRUSTED_PROMPT",
      "GHA_AGENT_PUBLIC_POST",
      "GHA_AGENT_CROSS_REPO_TOKEN",
      "GHA_AGENT_NO_AUTHOR_GATE",
      "AGENTIC_WF_UNTRUSTED_TRIGGER",
      "AGENTIC_WF_PUBLIC_POST_TOOL",
      "AGENTIC_WF_BROAD_ACCESS",
    ],
    minMatch: 2,
    // The medium hygiene rules (NO_AUTHOR_GATE, UNTRUSTED_TRIGGER) co-occur on
    // ordinary triage bots, so 2-of-N alone would false-fire. Require at least
    // one rule that proves the agent actually ingests untrusted input OR can
    // post publicly (mirrors the Cordyceps requireAnyOf guard).
    requireAnyOf: [
      "GHA_AGENT_UNTRUSTED_PROMPT",
      "GHA_AGENT_PUBLIC_POST",
      "AGENTIC_WF_PUBLIC_POST_TOOL",
    ],
    incident: "GitLost-class Agentic Workflow Exfiltration Posture",
    severity: "critical",
    confidenceBoost: 0.2,
    narrative:
      "An AI-agent workflow ingests attacker-controllable issue/PR text, can reach cross-repo data, " +
      "and can post publicly - the GitLost lethal trifecta (Noma Security, July 2026). An unauthenticated " +
      "attacker who files an issue could prompt-inject the agent into leaking private repository contents " +
      "through a public comment. Scope the token to one repo, gate on author trust, and remove public-write.",
  },

  // --- Obfuscation + exfil = malware ---
  {
    rules: ["EVAL_ATOB", "HIGH_ENTROPY_STRING", "ENV_EXFILTRATION", "DEAD_DROP_TELEGRAM"],
    minMatch: 3,
    incident: "Obfuscated Malware with C2",
    severity: "critical",
    confidenceBoost: 0.20,
    narrative: "Heavy code obfuscation combined with data exfiltration and dead-drop C2 resolution. Confirmed malicious payload.",
  },

  // --- Secrets exposure ---
  {
    rules: ["SECRETS_AWS_KEY", "SECRETS_GITHUB_TOKEN", "SECRETS_PRIVATE_KEY", "SECRETS_NPM_TOKEN", "SECRETS_SSH_KEY_READ"],
    minMatch: 2,
    incident: "Multi-Credential Exposure",
    severity: "critical",
    confidenceBoost: 0.15,
    narrative: "Multiple credential types exposed in code. Either a secrets leak or targeted credential harvesting malware.",
  },

  // --- Lockfile + IOC = compromised dependency ---
  {
    rules: ["IOC_KNOWN_BAD_VERSION", "IOC_KNOWN_C2_DOMAIN"],
    minMatch: 2,
    incident: "Known Compromised Dependency",
    severity: "critical",
    confidenceBoost: 0.30,
    narrative: "Known-bad package version detected alongside C2 infrastructure. This dependency has been confirmed compromised.",
  },

  // --- v4.4: Secret exfiltration chains ---
  {
    rules: ["SECRETS_AWS_KEY", "ENV_EXFILTRATION", "INSTALL_HOOK_NETWORK"],
    minMatch: 2,
    incident: "Secret Exfiltration Chain",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "Credentials detected in code combined with network exfiltration capability. Active secret theft in progress.",
  },
  {
    rules: ["INSTALL_HOOK_ENV_HARVEST", "INSTALL_HOOK_NETWORK", "INSTALL_HOOK_OBFUSCATED"],
    minMatch: 2,
    incident: "Install Hook Secret Exfiltration",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "Install script harvests secrets and sends them over the network with obfuscation. Classic supply-chain credential theft.",
  },
  {
    rules: ["GHA_SECRET_CURL", "GHA_BASE64_EXEC", "GHA_UNPINNED_ACTION"],
    minMatch: 2,
    incident: "CI Secret Exfiltration Chain",
    severity: "critical",
    confidenceBoost: 0.25,
    narrative: "GitHub Actions workflow exfiltrates secrets via network with encoded payloads. CI/CD credential theft.",
  },
];

// ---------------------------------------------------------------------------
// Correlation result
// ---------------------------------------------------------------------------

export interface CorrelationResult {
  /** Grouped incident clusters */
  incidents: IncidentCluster[];
  /** Risk score boost from correlations (0-30) */
  riskBoost: number;
  /** Human-readable insights */
  insights: string[];
}

// ---------------------------------------------------------------------------
// Main correlation function
// ---------------------------------------------------------------------------

/**
 * Correlate findings into incident clusters.
 */
export function correlateFindings(findings: Finding[]): CorrelationResult {
  const ruleSet = new Set(findings.map((f) => f.rule));
  const incidents: IncidentCluster[] = [];
  let riskBoost = 0;
  const insights: string[] = [];
  let clusterId = 0;

  for (const rule of CORRELATION_RULES) {
    const minMatch = rule.minMatch ?? rule.rules.length;
    const matchedRules = rule.rules.filter((r) => ruleSet.has(r));
    const strongPresent =
      !rule.requireAnyOf || rule.requireAnyOf.some((r) => ruleSet.has(r));

    if (matchedRules.length >= minMatch && strongPresent) {
      const id = `incident-${++clusterId}`;

      // Collect all findings matching this correlation
      const clusterFindings = findings.filter((f) => matchedRules.includes(f.rule));

      // Boost confidence on matched findings
      for (const f of clusterFindings) {
        f.correlationId = id;
        f.confidence = Math.min(1.0, (f.confidence ?? 0.8) + rule.confidenceBoost);
      }

      // Calculate compound confidence
      const avgConfidence = clusterFindings.reduce(
        (sum, f) => sum + (f.confidence ?? 0.8), 0,
      ) / clusterFindings.length;

      incidents.push({
        id,
        name: rule.incident,
        severity: rule.severity,
        confidence: Math.min(1.0, avgConfidence),
        findings: clusterFindings,
        narrative: rule.narrative,
        indicators: matchedRules,
      });

      riskBoost += Math.round(rule.confidenceBoost * 30);
      insights.push(
        `${rule.incident}: ${matchedRules.length}/${rule.rules.length} indicators matched (confidence ${(avgConfidence * 100).toFixed(0)}%)`,
      );
    }
  }

  // Cap risk boost at 30
  riskBoost = Math.min(30, riskBoost);

  // Sort by confidence descending
  incidents.sort((a, b) => b.confidence - a.confidence);

  return { incidents, riskBoost, insights };
}
