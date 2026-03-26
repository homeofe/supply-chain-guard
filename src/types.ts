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
}

export interface ScanReport {
  /** Tool name and version */
  tool: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** What was scanned (path, URL, package name) */
  target: string;
  /** Type of scan performed */
  scanType: "directory" | "github" | "npm" | "pypi" | "solana";
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
  format: "text" | "json" | "markdown" | "sarif";
  /** Only report findings at or above this severity */
  minSeverity?: Severity;
  /** Exclude specific rules */
  excludeRules?: string[];
  /** Maximum directory depth */
  maxDepth?: number;
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

export const SEVERITY_SCORES: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 1,
};
