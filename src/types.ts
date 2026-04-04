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
  /** Finding category (v4.2) */
  category?: "malware" | "supply-chain" | "config" | "trust" | "info";
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
  }>;
  baseline?: {
    file?: string;
  };
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
  format: "text" | "json" | "markdown" | "sarif" | "sbom" | "html";
  /** Only report findings at or above this severity */
  minSeverity?: Severity;
  /** Exclude specific rules */
  excludeRules?: string[];
  /** Maximum directory depth */
  maxDepth?: number;
  /** Baseline file path (v4.4) */
  baselineFile?: string;
  /** Policy config file path (v4.4) */
  policyFile?: string;
  /** Only scan changed files since commit (v4.5) */
  sinceCommit?: string;
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
  medium: 8,
  low: 3,
  info: 1,
};
