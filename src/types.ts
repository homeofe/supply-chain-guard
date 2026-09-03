/**
 * supply-chain-guard type definitions
 */

// Type-only, so it is erased at compile time and creates no runtime cycle with
// slsa-verifier.ts (which imports Finding from here).
import type { SLSAAssessment } from "./slsa-verifier.js";

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
  /**
   * Correlation cluster ID (v4.2).
   *
   * Single-valued and therefore lossy: a finding can be an indicator of more
   * than one incident. It is kept for consumers that already read it and is
   * always `correlationIds[0]`. Read `correlationIds` to get every incident the
   * finding belongs to.
   */
  correlationId?: string;
  /**
   * Every incident this finding is an indicator of (v5.30).
   *
   * Before v5.30 only `correlationId` existed and the correlation loop
   * overwrote it, so a finding listed under two incidents reported membership
   * in whichever one was written last - an evidence record whose own members
   * pointed at a different record.
   */
  correlationIds?: string[];
  /** Why this was flagged (v4.4) */
  rationale?: string;
  /** Evidence snippet (v4.4) */
  evidence?: string;
  /** Whether suppressed by policy/baseline (v4.4) */
  suppressed?: boolean;
  /**
   * The reason the project's policy declared for suppressing this finding
   * (v5.29). Set only when `.supply-chain-guard.yml` carried an explicit
   * non-empty `reason:` for the matching `suppress:` entry, so an absent value
   * means "no reason was recorded", never "reason unknown to us". Carried into
   * the SBOM VEX statement for the suppression.
   */
  suppressionReason?: string;
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
  /**
   * What the loaded policy config turned off for this scan (v5.29).
   * Present only when the config actually narrowed the scan.
   */
  policyEffect?: PolicyEffect;
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
  /**
   * What `slsaLevel` was computed from, and which checks were never run (unreleased).
   *
   * The number alone cannot express "not assessed", which is what let an
   * unsigned attestation and a commented-out publish step both render as a full
   * green 3/3. Renderers that show the level must show this beside it.
   */
  slsaAssessment?: SLSAAssessment;
  /** Git commit hash of scanned working tree (v5.29, issue #208) */
  commit?: string;
  /** Git branch name of scanned working tree (v5.29, issue #208) */
  branch?: string;
  /** Git remote repository URL of scanned working tree (v5.29, issue #208) */
  repositoryUri?: string;
  /** Detection set version, entry count, generation date and cache merge status (v5.29, issue #208) */
  detectionSet?: DetectionSetProvenance;
}

/**
 * Metadata identifying the threat intelligence / detection set in effect for a scan (v5.29, issue #208).
 */
export interface DetectionSetProvenance {
  /** Package version of the bundled feed */
  bundledVersion: string;
  /** Number of entries in the bundled feed */
  bundledEntryCount: number;
  /** Generation timestamp of the feed */
  generatedAt?: string;
  /** Whether a refreshed local cache was merged into the active feed */
  cacheMerged: boolean;
  /** Effective total entry count (bundled + fresh cache) */
  effectiveEntryCount: number;
  /** Cache file path if merged */
  cachePath?: string;
  /** Cache refresh timestamp if merged */
  cacheRefreshedAt?: string;
}

// ---------------------------------------------------------------------------
// v4.9 SBOM & SLSA types
// ---------------------------------------------------------------------------

/**
 * One CycloneDX 1.6 licence entry (v5.29).
 *
 * The three shapes are not interchangeable. `license.id` is constrained by the
 * spec to the SPDX identifier enum, `expression` is an unconstrained SPDX
 * expression string, and `license.name` is free text for anything that is
 * neither. See `encodeLicense()` in src/sbom-generator.ts for which input maps
 * to which, and why an unrecognised identifier must not be emitted as an id.
 */
export type SbomLicenseEntry =
  | { license: { id: string } }
  | { license: { name: string } }
  | { expression: string };

/** CycloneDX name/value property, used to record what was not assessed. */
export interface SbomProperty {
  name: string;
  value: string;
}

export interface SbomComponent {
  type: "library" | "application" | "framework";
  /**
   * Identifier other parts of the document reference (v5.29). Required,
   * because without it no `dependencies` relationship can name the component.
   */
  "bom-ref": string;
  name: string;
  /**
   * Resolved version (v5.30: optional).
   *
   * Omitted when the source could not resolve one - the package.json fallback
   * reading a range such as `^1.2.3`, a dist-tag such as `latest`, or a git
   * specifier. CycloneDX 1.6 requires only `type` and `name` on a component, so
   * an absent version is schema-valid, and a `supply-chain-guard:version`
   * property on the same component records why it is absent. A range printed in
   * this field would read as a factual claim about what ships.
   */
  version?: string;
  /**
   * Package URL (v5.30: optional).
   *
   * Emitted only alongside a resolved `version`: a purl carrying a range, a
   * dist-tag or a truncated specifier is not the identifier any consumer will
   * match on, so nothing is emitted rather than something unmatchable.
   */
  purl?: string;
  /**
   * Integrity digests, HEX encoded (v5.30).
   *
   * CycloneDX 1.6 constrains `hashes[].content` to a hexadecimal digest.
   * npm's lockfile `integrity` field is base64 (Subresource Integrity), so the
   * generator decodes it; a digest whose decoded length does not match its
   * algorithm is dropped and counted rather than emitted.
   */
  hashes?: Array<{ alg: "SHA-256" | "SHA-384" | "SHA-512" | "SHA-1"; content: string }>;
  /**
   * Declared licences (v5.29). Absent means the source manifest declared none;
   * in that case a `supply-chain-guard:license` property records that the field
   * was not assessed rather than leaving the absence unexplained.
   */
  licenses?: SbomLicenseEntry[];
  scope?: "required" | "optional" | "excluded";
  properties?: SbomProperty[];
}

/**
 * One node of the CycloneDX dependency graph (v5.29).
 *
 * `dependsOn: []` is a positive statement that the component declares no
 * dependencies. A component that has NO entry in the document's `dependencies`
 * array makes no statement at all, which is how the package.json fallback
 * records that transitive edges were never assessed.
 */
export interface SbomDependency {
  ref: string;
  dependsOn: string[];
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
  /**
   * Free-form name/value pairs on the vulnerability entry (v5.30).
   *
   * CycloneDX 1.6 defines `affects[].ref` as a reference to a bom-ref in the
   * same document and gives a vulnerability no field for a source location, so
   * the file and line a finding came from are recorded here while `affects`
   * keeps pointing at a component that actually exists. Incident membership is
   * carried here too, one entry per incident the finding belongs to.
   */
  properties?: SbomProperty[];
}

/**
 * One CycloneDX 1.6 annotation (v5.30).
 *
 * The slot the spec provides for commentary about other objects in the same
 * document, which is what a correlated incident is: a statement about a set of
 * vulnerability entries rather than an inventory fact. `subjects` are bom-refs
 * of entries in this document, so an incident is reachable from the entries it
 * groups and vice versa.
 */
export interface SbomAnnotation {
  "bom-ref": string;
  subjects: string[];
  annotator: { component: { type: string; name: string; version: string } };
  timestamp: string;
  text: string;
}

export interface SbomDocument {
  bomFormat: "CycloneDX";
  specVersion: "1.6";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { components: Array<{ type: string; name: string; version: string }> };
    component: {
      type: string;
      name: string;
      /**
       * Version of the subject (v5.29). Omitted, together with `purl`, when no
       * package.json declared one; `metadata.properties` then carries a
       * `supply-chain-guard:sbom:subject-version` entry saying so, because a
       * placeholder version on the one component that identifies the product
       * is worse than an absent one.
       */
      version?: string;
      purl?: string;
      "bom-ref": string;
    };
    /** Records what the generator could and could not assess (v5.29). */
    properties?: SbomProperty[];
  };
  components: SbomComponent[];
  /**
   * Dependency graph (v5.29). Absent when no manifest was found at all. See
   * SbomDependency for the difference between an empty `dependsOn` and a
   * missing entry.
   */
  dependencies?: SbomDependency[];
  vulnerabilities?: VexStatement[];
  /**
   * Correlated incidents, one annotation each (v5.30). Absent when the scan
   * correlated nothing, which is a different statement from an empty array.
   */
  annotations?: SbomAnnotation[];
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
  openCritical: number;
  openHigh: number;
  /**
   * Percentage of measurable triage decisions that are inside their SLA, or
   * `null` when there is nothing to measure.
   *
   * Computed from the single definition in `src/sla-engine.ts`. When the value
   * is non-null it is 100 if and only if `checkSlaCompliance` reports zero
   * breaches over the same decisions. The qualifier is required, and an earlier
   * draft of this comment omitted it: zero breaches alone does not imply 100,
   * because an empty decision set and a set whose every `decidedAt` is
   * unparseable each report zero breaches and a rate of `null`. In one
   * direction the implication needs no qualifier: 100 implies zero breaches.
   *
   * `null` means no measurement: no triage decisions were recorded, or every
   * recorded decision has an unparseable `decidedAt`. It does NOT mean zero
   * and it does not mean full compliance. Previously this field returned the
   * flattering `100` for an empty decision set, which made a project that had
   * never adopted triage indistinguishable from one with a perfect record.
   *
   * BREAKING for TypeScript consumers reading this field: the type widened
   * from `number` to `number | null`. Narrow with an explicit null check.
   * `mttrCritical` was removed from this interface in the same change. It was
   * declared optional and was assigned `undefined` unconditionally, so no
   * consumer can ever have received a value from it.
   */
  slaComplianceRate: number | null;
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
    /**
     * Written justification per disabled rule id, from the mapping form
     * `disable: { RULE_ID: "why" }` (v5.29). A rule id present in `disable`
     * but absent here was declared without a reason, which is reported as
     * POLICY_DISABLE_NO_REASON.
     */
    disableReasons?: Record<string, string>;
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
    /**
     * True when `reason` holds the parser's placeholder rather than a reason
     * the user wrote (v5.29). The parser fills in a placeholder so that later
     * code always has a string, which means a non-empty `reason` alone does
     * not prove the user justified anything. Consumers that publish the reason
     * (the SBOM VEX statements) must check this flag before quoting it as the
     * project's own words.
     */
    reasonPlaceholder?: boolean;
  }>;
  baseline?: {
    file?: string;
  };
  /** Path globs whose matching files are skipped by the scanner walk (v5.13). */
  ignore?: string[];
  /**
   * Written justification per ignore glob, from the mapping form
   * `ignore: { "dist/**": "why" }` (v5.29). A glob present in `ignore` but
   * absent here was declared without a reason: POLICY_IGNORE_NO_REASON.
   */
  ignoreReasons?: Record<string, string>;
  /** Internal-disclosure deny-list (see InternalDisclosurePolicy). */
  internalDisclosure?: InternalDisclosurePolicy;
  /** Validation problems collected while parsing (v5.3, fail-closed config validation) */
  warnings?: PolicyWarning[];
  /**
   * Basename of the config file this policy was parsed from, e.g.
   * ".supply-chain-guard.yml" (set by loadPolicyConfig, v5.29). Reported so a
   * reader can find the file that narrowed the scan.
   */
  sourceFile?: string;
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
  | "POLICY_INVALID_INTERNAL_TERM"
  | "POLICY_DISABLE_NO_REASON"
  | "POLICY_IGNORE_NO_REASON";

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

/**
 * One thing a policy config switched off: a rule id, or a path glob, with the
 * written justification when the config supplied one (v5.29).
 */
export interface PolicyEffectEntry {
  /** Rule id, or path glob for `ignoredGlobs` */
  id: string;
  /** Written justification from the config; absent when none was given */
  reason?: string;
}

/**
 * The effective policy for a scan: what the loaded config removed from the
 * result, named rather than counted (v5.29, issue 168).
 *
 * `suppressedCount` alone could not answer the only question that matters when
 * a report comes back clean: WHAT was turned off. A count of 1 reads the same
 * whether a noisy informational rule or the critical rule that would have
 * failed the gate was disabled, and the `ignore:` form produced no count at
 * all because it prunes files before any rule runs. Every output format
 * renders this block, so a narrowed scan can no longer be mistaken for a clean
 * one in whichever format the reader happens to be looking at.
 *
 * This carries policy METADATA only. Suppressed FINDINGS stay out of the
 * machine formats, which is the separate and still-standing v5.2.40 rule.
 */
export interface PolicyEffect {
  /** Config file the policy was read from, e.g. ".supply-chain-guard.yml" */
  configFile: string;
  /** Rule ids switched off by `rules.disable`: their findings never appear */
  disabledRules: PolicyEffectEntry[];
  /** Path globs under `ignore:`: matching files are never opened */
  ignoredGlobs: PolicyEffectEntry[];
  /** Rule ids named by `suppress` entries */
  suppressedRules: PolicyEffectEntry[];
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
  /** Use bundled feed only without merging refreshed local cache (--hermetic) */
  hermetic?: boolean;
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
  /** Number of indicators matched (v5.29) */
  matchedIndicatorsCount?: number;
  /** Total number of indicators defined in the correlation rule (v5.29) */
  totalIndicatorsCount?: number;
}

export interface TrustIndicator {
  name: string;
  status: "green" | "yellow" | "red";
  detail: string;
}

export interface TrustDimension {
  score: number;
  indicators: TrustIndicator[];
  /** Whether this dimension was actively assessed in the current scan mode */
  assessed?: boolean;
}

export interface TrustBreakdown {
  publisherTrust: TrustDimension;
  codeQuality: TrustDimension;
  dependencyTrust: TrustDimension;
  releaseProcess: TrustDimension;
  overallScore: number;
}

export const SEVERITY_SCORES: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 2,
  info: 1,
};
