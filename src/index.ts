/**
 * supply-chain-guard
 *
 * Open-source supply-chain security scanner for npm, PyPI, and VS Code extensions.
 * Detects GlassWorm and similar malware campaigns.
 */

export { scan } from "./scanner.js";
export { scanNpmPackage } from "./npm-scanner.js";
export { scanPypiPackage } from "./pypi-scanner.js";
export { scanVscodeExtension } from "./vscode-scanner.js";
export { scanDependencyConfusion } from "./dependency-confusion.js";
export { monitorWallet, checkWallet, formatAlert } from "./solana-monitor.js";
export { formatReport } from "./reporter.js";
export { checkLockfile } from "./lockfile-checker.js";
export { scanGitHubActionsWorkflows } from "./github-actions-scanner.js";
export type {
  Finding,
  ScanReport,
  ScanOptions,
  ScanSummary,
  Severity,
  NpmPackageInfo,
  SolanaMonitorOptions,
  SolanaTransaction,
  PatternEntry,
} from "./types.js";
