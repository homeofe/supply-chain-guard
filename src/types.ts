/**
 * supply-chain-guard type definitions
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  /** Unique rule identifier */
  rule: string;
  /** Human-readable description of the finding */
  description: string;
  /** Severity level */
  severity: Severity;
  /** File path relative to scan root (if applicable) */
  file?: string;
  /** Line number (if applicable) */
  line?: number;
  /** Matched content snippet */
  match?: string;
  /** Recommendation for remediation */
  recommendation: string;
  /** Confidence score 0.0-1.0 (v4.2) */
  confidence?: number;
  /**
   * Finding category (v4.2). "disclosure" covers internal topology leaking
   * into a published repository (hostnames, private addresses, non-public
   * forge URLs, developer paths) as opposed to a credential or a payload.
   */
  category?: "malware" | "supply-chain" | "config" | "trust" | "info" | "disclosure";
  /** Correlation cluster ID (v4.2) */
  correlationId?: string;
  /** Why this was flagged (v4.4) */
  rationale?: string;
  /** Evidence snippet (v4.4) */
  evidence?: string;
  /** Whether suppressed by policy/baseline (v4.4) */
  suppressed?: boolean;
}

export interface ScanReport {
  /** Tool name and version */
  tool: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** What was scanned (path, URL, package name) */
  target: string;
  /** Type of scan performed */
  scanType: "directory" | "github" | "npm" | "pypi" | "solana" | "cargo" | "go" | "docker";
  /** Duration in milliseconds */
  durationMs: number;
  /** All findings */
  findings: Finding[];
  /** Summary statistics */
  summary: ScanSummary;
  /** Overall risk score (0-100) */
  score: number;
  /** Risk level derived from score */
  riskLevel: "clean" | "low" | "medium" | "high" | "critical";
  /** Actionable recommendations */
  recommendations: string[];
  /** Correlated incident clusters (v4.2) */
  incidents?: IncidentCluster[];
  /** Trust breakdown for npm/pypi packages (v4.2) */
  trustBreakdown?: TrustBreakdown;
  /** Number of findings suppressed by policy/baseline (v4.4) */
  suppressedCount?: number;
  /** Whether scan completed fully (v4.4) */
  partialScan?: boolean;
  /** Threat timeline for forensics (v4.5) */
  timeline?: TimelineEvent[];
  /** Adaptive risk dimensions (v4.5) */
  riskDimensions?: RiskDimensions;
  /** Remediation plan (v4.6) */
  remediations?: Remediation[];
  /** Fix suggestions (v4.6) */
  fixSuggestions?: FixSuggestion[];
  /** Incident playbooks (v4.6) */
  playbooks?: Playbook[];
  /** Attack graph (v4.7) */
  attackGraph?: AttackGraph;
  /** Risk history trend (v4.8) */
  riskHistory?: RiskHistoryEntry[];
  /** Security metrics (v4.8) */
  metrics?: SecurityMetrics;
  /** CycloneDX 1.6 SBOM document generated from dependency inventory (v4.9) */
  sbomDocument?: SbomDocument;
  /** SLSA provenance level 0-3 (v4.9) */
  slsaLevel?: number;
}

// ---------------------------------------------------------------------------
// v4.9 SBOM & SLSA types
// ---------------------------------------------------------------------------

export interface SbomComponent {
  type: "library" | "application" | "framework";
  name: string;
  version: string;
  /**
   * Package URL, canonical per the purl specification
   * (`pkg:npm/express@4.18.3`, `pkg:npm/%40types/node@22.0.0`).
   *
   * OPTIONAL, and the absence carries meaning. A purl is emitted only when a
   * canonical one can be derived from the component's name. When it cannot, the
   * field is left out and the component carries a
   * `supply-chain-guard:sbom:purl-unavailable` property naming the reason,
   * rather than an identifier that is well-formed and wrong. A consumer can
   * therefore tell "here is the identifier" from "no identifier could be
   * derived"; before this was optional the two were indistinguishable.
   */
  purl?: string;
  hashes?: Array<{ alg: "SHA-256" | "SHA-512" | "SHA-1"; content: string }>;
  licenses?: string[];
  scope?: "required" | "optional" | "excluded";
  /**
   * CycloneDX component properties (name/value pairs). Used here to record why
   * a field that a reader expects is absent, so that absence is a statement in
   * the document rather than a gap in it.
   */
  properties?: Array<{ name: string; value: string }>;
}

export interface VexStatement {
  /** CVE or finding ID */
  id: string;
  source?: { name: string; url?: string };
  analysis: {
    state: "not_affected" | "affected" | "fixed" | "under_investigation";
    justification?: string;
    detail?: string;
  };
  affects?: Array<{ ref: string; versions?: string[] }>;
}

export interface SbomDocument {
  bomFormat: "CycloneDX";
  specVersion: "1.6";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { components: Array<{ type: string; name: string; version: string }> };
    component: { type: string; name: string; "bom-ref": string };
  };
  components: SbomComponent[];
  vulnerabilities?: VexStatement[];
}

// ---------------------------------------------------------------------------
// v4.7 Attack Graph & Validation types
// ---------------------------------------------------------------------------

export type GraphNodeType =
  | "repo" | "release" | "package" | "workflow" | "script"
  | "secret" | "ioc" | "maintainer" | "registry" | "artifact";

export type GraphEdgeType =
  | "depends_on" | "downloads" | "executes" | "publishes"
  | "references" | "exfiltrates" | "resolves_to"
  | "inherits_trust_from" | "violates_policy";

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  risk?: number;
  findings?: string[];
}

export interface GraphEdge {
  source: string;
  target: string;
  type: GraphEdgeType;
  label?: string;
  risk?: number;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  paths: AttackPath[];
}

export interface AttackPath {
  id: string;
  description: string;
  severity: Severity;
  confidence: number;
  nodeIds: string[];
}

export type ConfidenceTier = "heuristic" | "correlated" | "validated" | "confirmed";

export type ValidationMode = "static-only" | "safe-validate" | "detonate-isolated";

// ---------------------------------------------------------------------------
// v4.8 Continuous Risk Management types
// ---------------------------------------------------------------------------

export type FindingStatus =
  | "new" | "triaged" | "accepted-risk" | "in-remediation" | "resolved" | "false-positive";

export interface RiskHistoryEntry {
  timestamp: string;
  score: number;
  findingsCount: number;
  criticalCount: number;
}

export interface TriageDecision {
  findingRule: string;
  findingFile?: string;
  status: FindingStatus;
  owner?: string;
  team?: string;
  reason?: string;
  decidedAt: string;
  dueDate?: string;
}

export interface SlaConfig {
  critical: string;
  high: string;
  medium: string;
}

export interface SecurityMetrics {
  mttrCritical?: number;
  openCritical: number;
  openHigh: number;
  slaComplianceRate: number;
  riskTrend: "increasing" | "stable" | "decreasing";
  topRiskContributors: string[];
}

// ---------------------------------------------------------------------------
// v4.5 Threat Intelligence & Risk types
// ---------------------------------------------------------------------------

export interface TimelineEvent {
  event: string;
  rule?: string;
  timestamp: string;
  severity?: Severity;
}

export interface RiskDimensions {
  repoTrust: number;
  codeRisk: number;
  dependencyRisk: number;
  ciCdRisk: number;
  threatIntelMatches: number;
  overallScore: number;
  confidence: number;
}

// ---------------------------------------------------------------------------
// v4.6 Remediation & Response types
// ---------------------------------------------------------------------------

export interface Remediation {
  id: string;
  title: string;
  description: string;
  priority: "low" | "medium" | "high" | "critical";
  category: "dependency" | "ci" | "repo" | "release" | "secret" | "policy";
  steps: string[];
  automated: boolean;
  riskReduction?: number;
}

export interface FixSuggestion {
  targetFile: string;
  changeType: "replace" | "remove" | "insert" | "policy";
  before?: string;
  after?: string;
  explanation: string;
}

export interface Playbook {
  incidentType: string;
  severity: Severity;
  summary: string;
  immediateActions: string[];
  investigationSteps: string[];
  remediationSteps: string[];
  preventionMeasures: string[];
}

export interface PolicyException {
  rule: string;
  scope?: string;
  reason: string;
  owner?: string;
  expires?: string;
}

export interface ThreatIntelSource {
  name: string;
  url: string;
  trustLevel: "low" | "medium" | "high";
  lastUpdated?: string;
}

// ---------------------------------------------------------------------------
// v4.4 Policy configuration
// ---------------------------------------------------------------------------

export interface PolicyConfig {
  rules?: {
    disable?: string[];
    severityOverrides?: Record<string, Severity>;
  };
  allowlist?: {
    packages?: string[];
    domains?: string[];
    githubOrgs?: string[];
  };
  suppress?: Array<{
    rule: string;
    reason: string;
    /** Optional file glob: suppress the rule only under this path (v5.13). */
    path?: string;
  }>;
  baseline?: {
    file?: string;
  };
  /** Path globs whose matching files are skipped by the scanner walk (v5.13). */
  ignore?: string[];
  /** Internal-disclosure deny-list (see InternalDisclosurePolicy). */
  internalDisclosure?: InternalDisclosurePolicy;
  /** Validation problems collected while parsing (v5.3, fail-closed config validation) */
  warnings?: PolicyWarning[];
}

/**
 * Deny-list configuration for the internal-disclosure rule family.
 *
 * The built-in shape rules (INTERNAL_PRIVATE_IP, INTERNAL_HOSTNAME,
 * INTERNAL_GIT_REMOTE, ...) need none of this. This section exists for the
 * names that only the project itself knows, and it solves the paradox that a
 * list of internal hostnames committed to a public repository IS the leak:
 * `hashedTerms` is publishable, `externalFile` is never published, and
 * `patterns` is for repositories that are private anyway.
 */
export interface InternalDisclosurePolicy {
  /**
   * sha256 digests (lowercase hex) of internal terms, normalised as
   * `term.trim().toLowerCase()` before hashing. Publishable: the digest hides
   * the term from casual reading and from grep. It is NOT proof against
   * somebody who guesses candidate values and hashes them, which a hostname
   * invites - set `hashSalted` and SCG_INTERNAL_HASH_SALT for that. Matches
   * whole tokens only.
   */
  hashedTerms?: string[];
  /**
   * Declares that `hashedTerms` were generated with the salt held in the
   * SCG_INTERNAL_HASH_SALT environment variable. Without the declaration a
   * missing salt would simply match nothing, which looks exactly like a clean
   * repository; with it, the missing salt is reported as
   * INTERNAL_DENYLIST_UNAVAILABLE.
   */
  hashSalted?: boolean;
  /**
   * Plaintext literals or `/regex/flags` entries kept in the committed config.
   * Only for repositories that are private, or terms that are not sensitive.
   */
  patterns?: string[];
  /**
   * Path to an UNPUBLISHED file (gitignored, or provisioned by CI) holding one
   * entry per line. Matches from it are reported redacted. The
   * SCG_INTERNAL_DISCLOSURE_FILE environment variable does the same thing
   * without touching the config file at all.
   */
  externalFile?: string;
}

/** Rule ids emitted for policy config validation problems (v5.3) */
export type PolicyWarningRule =
  | "POLICY_UNKNOWN_KEY"
  | "POLICY_SUPPRESSION_NO_REASON"
  | "POLICY_MALFORMED_RULE_ID"
  | "POLICY_INVALID_INTERNAL_TERM";

/**
 * A problem found while parsing .supply-chain-guard.yml (v5.3).
 *
 * A security tool whose config silently ignores a typo like "supress:"
 * fails open: the user believes a policy is active when it is not.
 * These warnings are converted into findings by applyPolicy().
 */
export interface PolicyWarning {
  /** Detection rule id this warning maps to */
  rule: PolicyWarningRule;
  /** What exactly is wrong, naming the offending key or value */
  message: string;
  /** 1-based line number in the config file (if known) */
  line?: number;
  /** Config file name, e.g. ".supply-chain-guard.yml" (set by loadPolicyConfig) */
  file?: string;
}

export interface ScanSummary {
  totalFiles: number;
  filesScanned: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanOptions {
  /** Target path, URL, or package name */
  target: string;
  /** Output format */
  format: "text" | "json" | "markdown" | "sarif" | "sbom" | "html" | "badge" | "gitlab" | "junit";
  /** Only report findings at or above this severity */
  minSeverity?: Severity;
  /** Exclude specific rules */
  excludeRules?: string[];
  /** Maximum directory depth */
  maxDepth?: number;
  /** Optional lower cap for expanded filesystem entries (hard-capped by the scanner) */
  maxEntries?: number;
  /** Baseline file path (v4.4) */
  baselineFile?: string;
  /** Policy config file path (v4.4) */
  policyFile?: string;
  /** Only scan changed files since commit (v4.5) */
  sinceCommit?: string;
  /** Skip writing risk history to .scg-history/ (--no-history) */
  noHistory?: boolean;
  /** Compare local package.json version against the npm registry 'latest' (network, opt-in) (v5.9) */
  checkRegistry?: boolean;
}

export interface NpmPackageInfo {
  name: string;
  version: string;
  description?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  repository?: { url?: string } | string;
  author?: string | { name?: string; email?: string };
}

export interface SolanaTransaction {
  signature: string;
  blockTime: number | null;
  memo: string | null;
  err: unknown;
}

export interface SolanaMonitorOptions {
  /** Wallet address to monitor */
  address: string;
  /** Polling interval in seconds */
  interval: number;
  /** Maximum number of transactions to check per poll */
  limit: number;
  /** Output format */
  format: "text" | "json";
}

/**
 * One exact correlation produced by a dependency-free structural matcher.
 *
 * Offsets are absolute UTF-16 code-unit offsets into the scanned content.
 * `end` is exclusive. Evidence is deliberately bounded so a correlation
 * across a minified multi-megabyte line cannot leak that whole line into a
 * report.
 */
export interface CorrelatedPatternMatch {
  start: number;
  end: number;
  evidence: string;
}

/**
 * A near-linear structural matcher for patterns that correlate two or more
 * code events. The engine applies spansLines and file/path guards centrally.
 */
export type CorrelatedPatternMatcher = (
  content: string,
) => Iterable<CorrelatedPatternMatch>;
/** A near-linear whole-file corroboration predicate for PatternEntry metadata. */
export type FileContentRequirementMatcher = (content: string) => boolean;

export interface PatternEntry {
  /** Pattern name or identifier */
  name: string;
  /** Regex pattern string */
  pattern: string;
  /** What this pattern detects */
  description: string;
  /** Severity if matched */
  severity: Severity;
  /** Rule ID */
  rule: string;
  /** If set, only apply this pattern to files with these extensions (e.g. [".svg"]) */
  onlyExtensions?: string[];
  /** If set, only apply this pattern to files whose path matches this regex (e.g. README/docs) */
  onlyFilePattern?: RegExp;
  /** If set, skip files whose path matches this regex (e.g. /\.min\.(js|css)$/ or /\.ya?ml$/) */
  notFilePattern?: RegExp;
  /** If true, skip files that look like test/spec/mock/fixture files */
  notTestFile?: boolean;
  /**
   * Optional VALUE-level guard (v5.18). The regex decides the SHAPE of a match
   * (`token = "..."`); this decides whether the captured VALUE is actually
   * dangerous. Return false to drop the match. Without it a rule can only ever
   * assert "something of this shape exists here", which is how
   * IAC_HARDCODED_SECRET came to flag `password = "${REDIS_PASSWORD}"`.
   */
  valueFilter?: (value: string) => boolean;
  /** Capture group handed to valueFilter (default 1). */
  valueGroup?: number;
  /**
   * Optional FILE-level guard (v5.22). The line regex says "this shape appears
   * here"; this says "and the rest of the file corroborates it". The finding is
   * emitted only when the WHOLE file content also matches.
   *
   * This exists because the worst false positives in this scanner were rules
   * whose regex asserted something true of perfectly ordinary code: the literal
   * string `npm publish` in a release script, the word `SOCKS5` in a proxy
   * config, `.npmrc` in a CI helper. No path- or value-level guard can fix that,
   * because the matched text really is present and really is innocent. What
   * separates the malicious case is CORROBORATION elsewhere in the file - a
   * spawn, a credential read, an exfil call.
   *
   * Use it only where the corroborating signal is intrinsic to the attack, not
   * incidental. A guard an attacker can drop (by splitting the payload across
   * files) weakens detection, so pair it with an exact-match pin in the feed,
   * ioc-blocklist or patterns where one exists.
   */
  requiresInFile?: RegExp;
  /**
   * Near-linear equivalent of requiresInFile for corroboration that requires
   * boolean composition or other logic unsafe to encode with broad regex gaps.
   */
  requiresInFileMatcher?: FileContentRequirementMatcher;
  /**
   * Optional multi-line window size (v5.23). How many consecutive lines the
   * engine may join when evaluating this pattern.
   *
   * Default is 1: match each line in isolation (the pre-v5.23 behaviour). A
   * value of N > 1 enables a bounded sliding window of N lines, with the `s`
   * (dotAll) flag so `.*` can bridge ideas WITHIN that window only. Whole-file
   * matching with dotAll is intentionally NOT offered: a rule like
   * `(?:TEMP|TMP).*(?:exec|spawn)` would then pair a tmpdir on line 3 with an
   * exec on line 900, which is the false-positive shape v5.22 eliminated and
   * would scale with file size.
   *
   * Opt-in per rule. Hard-capped at load time (see MAX_SPANS_LINES). Pair with
   * requiresInFile / valueFilter wherever the multi-line form risks ordinary
   * code.
   */
  spansLines?: number;
  /**
   * Exact structural matcher for correlations that cannot safely be expressed
   * as an unbounded JavaScript regex over an admitted multi-megabyte file.
   */
  correlatedMatcher?: CorrelatedPatternMatcher;
}

export interface WatchlistEntry {
  /** Solana wallet address */
  address: string;
  /** Human-readable label for this wallet */
  name: string;
  /** ISO 8601 timestamp when added */
  addedAt: string;
}

export interface WatchlistConfig {
  entries: WatchlistEntry[];
}

export interface WatchlistAlert {
  address: string;
  name: string;
  txid: string;
  memo: string;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// v4.2 Correlation & Trust types
// ---------------------------------------------------------------------------

export interface IncidentCluster {
  /** Unique cluster ID */
  id: string;
  /** Human-readable incident name */
  name: string;
  /** Highest severity in cluster */
  severity: Severity;
  /** Compound confidence (0.0-1.0) */
  confidence: number;
  /** Findings in this cluster */
  findings: Finding[];
  /** Auto-generated attack narrative */
  narrative: string;
  /** Rule IDs involved */
  indicators: string[];
}

export interface TrustIndicator {
  name: string;
  status: "green" | "yellow" | "red";
  detail: string;
}

export interface TrustBreakdown {
  publisherTrust: { score: number; indicators: TrustIndicator[] };
  codeQuality: { score: number; indicators: TrustIndicator[] };
  dependencyTrust: { score: number; indicators: TrustIndicator[] };
  releaseProcess: { score: number; indicators: TrustIndicator[] };
  overallScore: number;
}

export const SEVERITY_SCORES: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 2,
  info: 1,
};
