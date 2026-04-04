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
export { checkIOCBlocklist, checkBadVersion } from "./ioc-blocklist.js";
export { analyzeGitHubTrust, parseGitHubUrl, scanReadmeLures } from "./github-trust-scanner.js";
export { analyzeInstallHooks } from "./install-hook-scanner.js";
export { analyzeDependencyRisks, levenshtein } from "./dependency-risk-analyzer.js";
export { analyzePublishingAnomalies } from "./publishing-anomaly-detector.js";
export { scanReleaseArtifacts } from "./release-scanner.js";
export { correlateFindings } from "./correlation-engine.js";
export { calculateTrustBreakdown } from "./trust-breakdown.js";
export { loadPolicyConfig, applyPolicy, applyBaseline, saveBaseline } from "./policy-engine.js";
export { detectTrustSignals } from "./trust-signals.js";
export { loadThreatIntel, updateThreatFeed, checkThreatIntel } from "./threat-intel.js";
export { calculateRiskDimensions } from "./risk-engine.js";
export { getChangedFiles } from "./diff-scanner.js";
export { listOrgRepos, analyzeOrgFindings } from "./org-scanner.js";
export { generateRemediations, generateFixSuggestions } from "./remediation-engine.js";
export { generatePlaybooks } from "./playbooks.js";
export { checkDependencyGovernance } from "./dependency-governance.js";
export { exportIncidentBundle, exportIncidentMarkdown, exportCsvSummary } from "./soc-exporter.js";
export { buildAttackGraph, exportGraphMermaid } from "./attack-graph.js";
export { validateFindings, promoteConfidence } from "./active-validation.js";
export { modelWorkflows } from "./workflow-modeler.js";
export { checkHoneytokenAccess, getHoneytokenEnv } from "./secret-simulator.js";
export { calculateOrgPosture } from "./posture-engine.js";
export { loadRiskHistory, saveRiskHistory, analyzeRiskTrend } from "./continuous-monitor.js";
export { loadTriageDecisions, saveTriageDecisions, checkTriageGovernance } from "./triage-engine.js";
export { checkSlaCompliance } from "./sla-engine.js";
export { forecastRisk } from "./risk-forecast.js";
export { calculateMetrics } from "./metrics.js";
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
