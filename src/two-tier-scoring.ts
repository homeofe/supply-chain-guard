/**
 * Two-Tier Gated Verdict and Risk Scoring Engine
 *
 * Architecture:
 * - Tier 1: Threat & Attack-Chain Gate (Binary Blocker)
 *   Immediate verdict CRITICAL / REJECT (exit code 1, skipping formula calculation) if:
 *   - Confirmed malware signature matches (OSV Malicious Database, GlassWorm, Shai-Hulud)
 *   - Complete attack chain: Ingress/Hook Execution + Access/Token Read + Exfiltration
 *   - Hardcoded C2 address, Discord/Telegram exfiltration URL, or malicious Solana Program ID
 *
 * - Tier 2: Hygiene & Risk Scoring (0 to 100 for clean but vulnerable packages)
 *   Evaluates packages that pass Tier 1 using orthogonal vectors:
 *   - Exploitability Vector: S_vuln = max_{v in V} ( CVSS_v * 10 * sqrt(EPSS_v) ), with CISA KEV => EPSS := 1.0
 *   - Heuristic Vector (S_heur): Accrued baseline indicators capped at 100. Scaled by 1.3 if two correlated
 *     indicators interact without completing a full Tier 1 kill-switch.
 *   - Governance Vector (S_hyg): S_hyg = 10 * (10 - Scorecard) * M_slsa
 *     (Scorecard range 0.0-10.0, fallback 3.0; M_slsa: 0.4 for SLSA L3, 0.7 for SLSA L1/L2, 1.0 for unverified)
 *   - Composite Risk Score: CRS = min(100, 0.35 * S_vuln + 0.45 * S_heur + 0.20 * S_hyg)
 *
 * Thresholds & Exit Codes:
 * - Tier 1 Hit or CRS 80 to 100: CRITICAL (Exit code 2, build blocker)
 * - CRS 55 to 79: HIGH (Exit code 1, review required)
 * - CRS 30 to 54: MEDIUM (Exit code 0, log audit warning)
 * - CRS 0 to 29: LOW (Exit code 0, pass)
 *
 * The codes match getReportExitCode(): 2 is the stronger "critical" verdict and 1 is
 * "high". They were the other way round while this was being written, which would
 * have inverted the meaning of exit 2 for every consumer the moment --two-tier was
 * enabled. Do not swap them back without a CHANGELOG entry calling out the break.
 *
 * The exit code also carries a severity floor: it is never weaker than the default
 * severity gate. Without external vulnerability inputs S_vuln is 0, so the CRS
 * ceiling is 0.45 * 100 + 0.20 * S_hyg, which cannot reach the 80 CRITICAL
 * threshold. Three critical findings that miss Tier 1 score CRS 54.5 (MEDIUM), and
 * without the floor --two-tier would exit 0 where the default gate exits 2.
 */

import type {
  ConfirmedMalwareInput,
  Finding,
  IncidentCluster,
  Severity,
  TwoTierOptions,
  TwoTierVerdict,
  VulnerabilityScoreInput,
} from "./types.js";
import { SCORE_EXCLUDED_RULES } from "./types.js";

// ---------------------------------------------------------------------------
// Rule classifications for Tier 1 Gate
// ---------------------------------------------------------------------------

/** Malware rules: OSV, GlassWorm, Shai-Hulud, confirmed malicious packages */
const CONFIRMED_MALWARE_RULES = new Set([
  "OSV_MALICIOUS_PACKAGE",
  "MALICIOUS_PACKAGE",
  "IOC_KNOWN_MALWARE_FILE_DIGEST",
  "GLASSWORM_MARKER",
  "GLASSWORM_STAGE2_DOMAIN",
  "GLASSWORM_OBFUSCATED",
  "GLASSWORM_LOADER",
  // INVISIBLE_UNICODE is deliberately NOT here. Zero-width characters are a high
  // heuristic, not a signature: the project's own high-but-not-critical fixture is a
  // clean package plus a U+200B string, and listing it made that fixture a build
  // blocker. Only confirmed signatures belong in this set.
  "SHAI_HULUD_WORM",
  "SHAI_HULUD_CRED_STEAL",
  "SHAI_HULUD_REPLICATION",
]);

/**
 * Ingress / Hook execution rules.
 *
 * The three stage sets below are DISJOINT, and classifyChainStage() assigns every
 * rule to at most one of them. The kill-switch needs three distinct signals, so a
 * rule that sat in two sets let two findings complete a three-stage chain: an
 * install hook that makes a network call plus any secrets finding read as
 * ingress + access + exfiltration. Before adding a rule here, check it is not
 * already in ACCESS_TOKEN_RULES or EXFILTRATION_RULES.
 */
const INGRESS_HOOK_RULES = new Set([
  "INSTALL_HOOK_PREINSTALL",
  "INSTALL_HOOK_POSTINSTALL",
  "INSTALL_HOOK_EXEC",
  "INSTALL_HOOK_SHELL",
  "INSTALL_HOOK_DOWNLOAD_EXEC",
  "INSTALL_HOOK_OBFUSCATED",
  "INSTALL_HOOK_PERSISTENCE_WRITE",
  // INSTALL_HOOK_NETWORK is exfiltration, INSTALL_HOOK_NPMRC_READ and
  // INSTALL_HOOK_ENV_HARVEST are access. They are not repeated here.
  "SCRIPT_EXECUTION",
  "GHA_PWN_REQUEST_CHECKOUT",
  "GHA_CURL_PIPE_EXEC",
  "DROPPER_TEMP_EXEC",
]);

/** Access / Credential / Token read rules */
const ACCESS_TOKEN_RULES = new Set([
  "INSTALL_HOOK_NPMRC_READ",
  "INSTALL_HOOK_ENV_HARVEST",
  "SECRETS_NPM_TOKEN",
  "SECRETS_AWS_KEY",
  "SECRETS_GITHUB_TOKEN",
  "SECRETS_SSH_KEY_READ",
  "SECRETS_PRIVATE_KEY",
  "NPM_TOKEN_ACCESS",
  "GHA_SECRET_CURL",
  "VIDAR_BROWSER_THEFT",
  "VIDAR_WALLET_THEFT",
]);

/** Exfiltration rules: network egress, dead-drops, Solana C2 transfers */
const EXFILTRATION_RULES = new Set([
  "ENV_EXFILTRATION",
  "INSTALL_HOOK_NETWORK",
  "DEAD_DROP_TELEGRAM",
  "DEAD_DROP_DISCORD",
  "DISCORD_WEBHOOK_EXFIL",
  "TELEGRAM_BOT_EXFIL",
  "TELEGRAM_EXFIL",
  "DISCORD_EXFIL",
  "IOC_KNOWN_C2_DOMAIN",
  "IOC_KNOWN_C2_IP",
  "IOC_KNOWN_C2_WALLET",
  "BEACON_C2_ENDPOINT",
  // GHA_SECRET_CURL is classified as access (it names the secret read); it is not
  // repeated here, or a workflow with one finding would cover two stages.
]);

/** Hardcoded C2 infrastructure rules */
const HARDCODED_C2_RULES = new Set([
  "IOC_KNOWN_C2_DOMAIN",
  "IOC_KNOWN_C2_IP",
  "IOC_KNOWN_C2_WALLET",
  "BEACON_C2_ENDPOINT",
  "GHOSTSOCKS_SOCKS5",
]);

/** Discord / Telegram exfiltration rules */
const DISCORD_TELEGRAM_EXFIL_RULES = new Set([
  "DEAD_DROP_TELEGRAM",
  "DEAD_DROP_DISCORD",
  "DISCORD_WEBHOOK_EXFIL",
  "TELEGRAM_BOT_EXFIL",
  "TELEGRAM_EXFIL",
  "DISCORD_EXFIL",
]);

/** Malicious Solana Program rules */
const MALICIOUS_SOLANA_RULES = new Set([
  "IOC_KNOWN_C2_WALLET",
]);

/** Discord and Telegram exfiltration patterns */
const DISCORD_EXFIL_PATTERN = /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\//i;
const TELEGRAM_EXFIL_PATTERN = /https?:\/\/api\.telegram\.org\/bot[0-9]+:[a-zA-Z0-9_-]+/i;

// ---------------------------------------------------------------------------
// Baseline severity weights for Heuristic Vector (0-100)
// ---------------------------------------------------------------------------

const BASELINE_SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 2,
  info: 0,
};

// ---------------------------------------------------------------------------
// Tier 1 Gate Evaluation
// ---------------------------------------------------------------------------

export interface Tier1Result {
  blocked: boolean;
  reasons: string[];
}

type ChainStage = "ingress" | "access" | "exfiltration";

/**
 * Assign a rule to AT MOST ONE attack-chain stage.
 *
 * The complete-chain condition counts distinct stages, so a rule that could be read
 * as two of them has to resolve to one or two findings will satisfy three stages.
 * Precedence runs exfiltration, then access, then ingress: a rule that names an
 * egress or a credential read is never also counted as the hook that started the
 * chain. The prefix fallbacks stay so rules not listed in a set still classify, but
 * they are only reached after the earlier stages have declined the rule.
 */
function classifyChainStage(rule: string): ChainStage | undefined {
  if (
    EXFILTRATION_RULES.has(rule) ||
    rule.includes("EXFIL") ||
    rule.includes("EXFILTRATION") ||
    rule === "IOC_KNOWN_C2_DOMAIN" ||
    rule === "IOC_KNOWN_C2_IP" ||
    rule === "IOC_KNOWN_C2_WALLET"
  ) {
    return "exfiltration";
  }
  if (ACCESS_TOKEN_RULES.has(rule) || rule.startsWith("SECRETS_") || rule === "NPM_TOKEN_ACCESS") {
    return "access";
  }
  if (
    INGRESS_HOOK_RULES.has(rule) ||
    rule.startsWith("INSTALL_HOOK_") ||
    rule.startsWith("SCRIPT_EXECUTION")
  ) {
    return "ingress";
  }
  return undefined;
}

/** Collect the distinct attack-chain stages a set of rules covers. */
function collectChainStages(rules: Iterable<string>): Set<ChainStage> {
  const stages = new Set<ChainStage>();
  for (const rule of rules) {
    const stage = classifyChainStage(rule);
    if (stage) stages.add(stage);
  }
  return stages;
}

/**
 * Evaluate Tier 1 Threat & Attack-Chain Gate.
 * Binary blocker that produces an immediate CRITICAL / REJECT verdict without formula dilution.
 */
export function evaluateTier1Gate(
  findings: Finding[],
  incidents: IncidentCluster[] = [],
  confirmedMalware: ConfirmedMalwareInput[] = [],
): Tier1Result {
  const reasons: string[] = [];
  const rules = new Set(findings.map((f) => f.rule));

  // Condition 1: Confirmed malware signature matches
  for (const f of findings) {
    const rule = f.rule;
    // Only confirmed signatures block here. `f.category === "malware"` used to be part
    // of this test, but that category is a bucket label about 30 rules across 14
    // scanner modules set, not a confirmation: INSTALL_HOOK_OBFUSCATED carries it and
    // fires on any install hook containing `Buffer.from(`, so an ordinary package was
    // rejected as confirmed malware. Category belongs to Tier 2 scoring, not the gate.
    const isMalware =
      CONFIRMED_MALWARE_RULES.has(rule) ||
      rule.startsWith("GLASSWORM_") ||
      rule.startsWith("SHAI_HULUD_") ||
      rule.startsWith("OSV_MAL_");

    if (isMalware) {
      reasons.push(
        `Confirmed malware signature: ${rule} (${f.description || "Identified malware payload or campaign signature"})`,
      );
    }
  }

  for (const malware of confirmedMalware) {
    reasons.push(
      `Confirmed malicious package: ${malware.packageName}${malware.packageVersion ? `@${malware.packageVersion}` : ""} (${malware.id}, ${malware.source.name})`,
    );
  }

  // Condition 2: Complete attack chain detected
  // Ingress/Hook Execution + Access/Token Read + Exfiltration
  const correlatedFindings = new Map<string, Finding[]>();
  for (const finding of findings) {
    const ids = new Set([...(finding.correlationIds ?? []), ...(finding.correlationId ? [finding.correlationId] : [])]);
    for (const id of ids) {
      // The correlation engine can assign one incident ID to repository-wide
      // indicators in unrelated files. Tier 1 needs actual local linkage, so a
      // shared ID is necessary but not sufficient: complete the chain only
      // within one source file or workflow document.
      const scope = finding.file ?? "<unknown>";
      const scopedId = `${id}\u0000${scope}`;
      const members = correlatedFindings.get(scopedId) ?? [];
      members.push(finding);
      correlatedFindings.set(scopedId, members);
    }
  }
  for (const [scopedId, members] of correlatedFindings) {
    const stages = collectChainStages(members.map((finding) => finding.rule));
    if (stages.has("ingress") && stages.has("access") && stages.has("exfiltration")) {
      const id = scopedId.slice(0, scopedId.indexOf("\u0000"));
      reasons.push(`Complete attack chain detected (${id}, correlated): Ingress/Hook Execution + Access/Token Read + Exfiltration`);
    }
  }

  // Also check correlated incident clusters for completed high-severity chains
  for (const incident of incidents) {
    const incidentFiles = new Set(incident.findings.map((finding) => finding.file ?? "<unknown>"));
    if (
      incident.severity === "critical" &&
      Array.isArray(incident.findings) &&
      incident.findings.length >= 3 &&
      incidentFiles.size === 1 &&
      incident.indicators.length >= 3
    ) {
      const incidentRules = new Set(incident.findings.map((finding) => finding.rule));
      const indicatorsMatchEvidence = incident.indicators.every((indicator) => incidentRules.has(indicator));
      const incStages = collectChainStages(incidentRules);
      if (indicatorsMatchEvidence && incStages.has("ingress") && incStages.has("access") && incStages.has("exfiltration")) {
        reasons.push(`Correlated attack chain incident: ${incident.name} (${incident.narrative})`);
      }
    }
  }

  // Condition 3: Hardcoded C2 address, Discord/Telegram exfil URL, or malicious Solana Program ID
  for (const f of findings) {
    if (HARDCODED_C2_RULES.has(f.rule)) {
      reasons.push(`Hardcoded C2 infrastructure identified: ${f.rule} (${f.description})`);
    }

    if (DISCORD_TELEGRAM_EXFIL_RULES.has(f.rule)) {
      reasons.push(`Discord/Telegram exfiltration endpoint detected: ${f.rule} (${f.description})`);
    } else if (f.match) {
      if (DISCORD_EXFIL_PATTERN.test(f.match)) {
        reasons.push(`Hardcoded Discord webhook exfiltration URL detected: ${f.rule}`);
      } else if (TELEGRAM_EXFIL_PATTERN.test(f.match)) {
        reasons.push(`Hardcoded Telegram Bot exfiltration URL detected: ${f.rule}`);
      }
    }

    if (MALICIOUS_SOLANA_RULES.has(f.rule)) {
      reasons.push(`Malicious Solana Program ID or drainer transfer identified: ${f.rule} (${f.description})`);
    }
  }

  // Deduplicate reasons
  const uniqueReasons = [...new Set(reasons)];
  return {
    blocked: uniqueReasons.length > 0,
    reasons: uniqueReasons,
  };
}

// ---------------------------------------------------------------------------
// Tier 2 Vector Calculations
// ---------------------------------------------------------------------------

/**
 * Exploitability Vector:
 * S_vuln = max_{v in V} ( CVSS_v * 10 * sqrt(EPSS_v) )
 * (If v in CISA KEV, set EPSS_v := 1.0)
 */
export function calculateExploitabilityVector(
  vulnerabilities: VulnerabilityScoreInput[] = [],
): number {
  if (vulnerabilities.length === 0) return 0;

  let maxScore = 0;
  for (const v of vulnerabilities) {
    const rawCvss = typeof v.cvss === "number" && Number.isFinite(v.cvss) ? v.cvss : 0;
    const cvss = Math.max(0, Math.min(10.0, rawCvss));

    let epss = typeof v.epss === "number" && Number.isFinite(v.epss) ? Math.max(0, Math.min(1.0, v.epss)) : 0;
    if (v.inCisaKev) {
      epss = 1.0;
    }

    const score = cvss * 10 * Math.sqrt(epss);
    if (score > maxScore) {
      maxScore = score;
    }
  }

  return Math.min(100, Math.round(maxScore * 100) / 100);
}

/**
 * External advisory data is allowed to be incomplete, but incompleteness must
 * never be interpreted as evidence of low risk. Keep the published CRS formula
 * intact and independently require review when a known-exploited advisory is
 * present or when either scoring dimension is unknown.
 */
function vulnerabilityReviewRequired(
  vulnerabilities: VulnerabilityScoreInput[] = [],
): boolean {
  return vulnerabilities.some((v) =>
    v.inCisaKev === true ||
    !(typeof v.cvss === "number" && Number.isFinite(v.cvss)) ||
    !(typeof v.epss === "number" && Number.isFinite(v.epss)),
  );
}

/**
 * Heuristic Vector:
 * S_heur: Accrued baseline indicators capped at 100.
 * If two correlated indicators interact without completing a full Tier 1 kill-switch,
 * scale sum by factor 1.3.
 */
export function calculateHeuristicVector(
  findings: Finding[],
  incidents: IncidentCluster[] = [],
): { score: number; correlatedInteraction: boolean } {
  // Deduplicate by rule to not double-count indicators that the engine already bundles into composite findings
  const maxByRule = new Map<string, Severity>();
  for (const f of findings) {
    if (f.severity === "info" || SCORE_EXCLUDED_RULES.has(f.rule)) continue;
    const existing = maxByRule.get(f.rule);
    if (!existing || BASELINE_SEVERITY_WEIGHTS[f.severity] > BASELINE_SEVERITY_WEIGHTS[existing]) {
      maxByRule.set(f.rule, f.severity);
    }
  }

  let baselineSum = 0;
  for (const severity of maxByRule.values()) {
    baselineSum += BASELINE_SEVERITY_WEIGHTS[severity];
  }

  // Check if two correlated indicators interact without completing Tier 1
  let correlatedInteraction = false;
  if (incidents.length > 0) {
    // Incident cluster exists, meaning >= 2 correlated rules co-occurred
    correlatedInteraction = true;
  } else {
    // Check if at least 2 findings share correlation IDs or interact in correlation rules
    const correlatedCount = findings.filter(
      (f) => Boolean(f.correlationId) || (Array.isArray(f.correlationIds) && f.correlationIds.length > 0),
    ).length;
    if (correlatedCount >= 2) {
      correlatedInteraction = true;
    }
  }

  const multiplier = correlatedInteraction ? 1.3 : 1.0;
  const scaled = baselineSum * multiplier;
  const score = Math.min(100, Math.round(scaled * 100) / 100);

  return { score, correlatedInteraction };
}

/**
 * Governance Vector:
 * S_hyg = 10 * (10 - Scorecard) * M_slsa
 * (OpenSSF Scorecard range 0.0 to 10.0, fallback to 3.0 on timeout/missing data;
 * M_slsa: 0.4 for SLSA L3, 0.7 for SLSA L1/L2, 1.0 for unverified)
 */
export function calculateGovernanceVector(
  scorecard = 3.0,
  slsaLevel = 0,
): { score: number; mSlsa: number; scorecardUsed: number } {
  const safeScorecard = Number.isFinite(scorecard)
    ? Math.max(0.0, Math.min(10.0, scorecard))
    : 3.0;

  let mSlsa = 1.0;
  if (slsaLevel >= 3) {
    mSlsa = 0.4;
  } else if (slsaLevel === 1 || slsaLevel === 2) {
    mSlsa = 0.7;
  }

  const raw = 10 * (10.0 - safeScorecard) * mSlsa;
  const score = Math.min(100, Math.max(0, Math.round(raw * 100) / 100));

  return { score, mSlsa, scorecardUsed: safeScorecard };
}

/**
 * Composite Risk Score:
 * CRS = min(100, 0.35 * S_vuln + 0.45 * S_heur + 0.20 * S_hyg)
 */
export function calculateCompositeRiskScore(
  sVuln: number,
  sHeur: number,
  sHyg: number,
): number {
  const raw = 0.35 * sVuln + 0.45 * sHeur + 0.20 * sHyg;
  return Math.min(100, Math.max(0, Math.round(raw * 100) / 100));
}

// ---------------------------------------------------------------------------
// Main Two-Tier Evaluator
// ---------------------------------------------------------------------------

/**
 * Lowest exit code the plain severity counts already justify.
 *
 * Mirrors the default branch of getReportExitCode(): a critical finding is 2, a high
 * finding is 1. The two-tier verdict is floored against this so enabling --two-tier
 * can never turn a report that blocks today into a pass.
 */
function severityExitFloor(findings: Finding[]): 0 | 1 | 2 {
  let floor: 0 | 1 | 2 = 0;
  for (const f of findings) {
    if (f.severity === "info") continue;
    if (f.severity === "critical") return 2;
    if (f.severity === "high") floor = 1;
  }
  return floor;
}

/**
 * Evaluate complete Two-Tier Gated Verdict and compute risk scores.
 */
export function evaluateTwoTierVerdict(
  findings: Finding[],
  incidents: IncidentCluster[] = [],
  options: TwoTierOptions = {},
): TwoTierVerdict {
  // 1. Tier 1: Threat & Attack-Chain Gate (Binary Blocker)
  const tier1 = evaluateTier1Gate(findings, incidents, options.confirmedMalware);
  if (tier1.blocked) {
    // Immediate verdict CRITICAL / REJECT, exit code 2, skipping formula calculation
    return {
      tier: 1,
      verdict: "CRITICAL / REJECT",
      tier1Blocked: true,
      tier1Reasons: tier1.reasons,
      level: "CRITICAL",
      compositeRiskLevel: "CRITICAL",
      exitCode: 2,
      vulnerabilitiesEvaluated: options.vulnerabilities?.length ?? 0,
    };
  }

  // 2. Tier 2: Hygiene & Risk Scoring (0 to 100)
  const sVuln = calculateExploitabilityVector(options.vulnerabilities);
  const { score: sHeur } = calculateHeuristicVector(findings, incidents);
  const { score: sHyg, mSlsa, scorecardUsed } = calculateGovernanceVector(
    options.scorecard,
    options.slsaLevel,
  );

  const crs = calculateCompositeRiskScore(sVuln, sHeur, sHyg);

  // 3. Thresholds & Exit Codes
  // - CRS 80 to 100: CRITICAL (Exit code 2, build blocker)
  // - CRS 55 to 79: HIGH (Exit code 1, review required)
  // - CRS 30 to 54: MEDIUM (Exit code 0, log audit warning)
  // - CRS 0 to 29: LOW (Exit code 0, pass)
  let level: TwoTierVerdict["level"];
  let compositeRiskLevel: TwoTierVerdict["level"];
  let verdict: TwoTierVerdict["verdict"];
  let exitCode: 0 | 1 | 2;

  if (crs >= 80) {
    level = compositeRiskLevel = "CRITICAL";
    verdict = "CRITICAL / REJECT";
    exitCode = 2;
  } else if (crs >= 55) {
    level = compositeRiskLevel = "HIGH";
    verdict = "HIGH / REVIEW_REQUIRED";
    exitCode = 1;
  } else if (crs >= 30) {
    level = compositeRiskLevel = "MEDIUM";
    verdict = "MEDIUM / AUDIT_WARNING";
    exitCode = 0;
  } else {
    level = compositeRiskLevel = "LOW";
    verdict = "LOW / PASS";
    exitCode = 0;
  }

  // The CRS level describes the score. The exit code additionally answers "may this
  // build proceed", and that answer must never be softer than the plain severity
  // counts already give, or enabling --two-tier would silently lower the bar.
  const floor = severityExitFloor(findings);
  if (floor > exitCode) {
    exitCode = floor;
  }
  if (vulnerabilityReviewRequired(options.vulnerabilities) && exitCode === 0) {
    exitCode = 1;
  }
  if (options.partialScan && exitCode === 0) exitCode = 1;

  if (exitCode === 2) {
    level = "CRITICAL";
    verdict = "CRITICAL / REJECT";
  } else if (exitCode === 1) {
    level = "HIGH";
    verdict = "HIGH / REVIEW_REQUIRED";
  }

  return {
    tier: 2,
    verdict,
    tier1Blocked: false,
    exploitabilityScore: sVuln,
    heuristicScore: sHeur,
    governanceScore: sHyg,
    compositeRiskScore: crs,
    compositeRiskLevel,
    level,
    exitCode,
    vulnerabilitiesEvaluated: options.vulnerabilities?.length ?? 0,
    scorecardUsed,
    slsaMultiplierUsed: mSlsa,
  };
}

/**
 * Get process exit code from a TwoTierVerdict.
 */
export function getTwoTierExitCode(verdict: TwoTierVerdict): 0 | 1 | 2 {
  return verdict.exitCode;
}
