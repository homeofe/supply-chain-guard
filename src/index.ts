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
export {
  monitorWallet,
  checkWallet,
  formatAlert,
  loadWatchlist,
  saveWatchlist,
  addToWatchlist,
  removeFromWatchlist,
  listWatchlist,
  monitorWatchlist,
} from "./solana-monitor.js";
export { formatReport } from "./reporter.js";
export { checkLockfile } from "./lockfile-checker.js";
export { scanGitHubActionsWorkflows } from "./github-actions-scanner.js";
export { scanDockerFiles, scanDockerFile } from "./dockerfile-scanner.js";
export { scanConfigFiles, scanConfigFile } from "./config-scanner.js";
export { scanGitSecurity } from "./git-scanner.js";
export { analyzeEntropy, shannonEntropy } from "./entropy.js";
export { scanCargoFiles } from "./cargo-scanner.js";
export { scanGoFiles } from "./go-scanner.js";
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
  WatchlistEntry,
  WatchlistConfig,
  WatchlistAlert,
} from "./types.js";
