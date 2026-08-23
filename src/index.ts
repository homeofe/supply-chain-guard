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
export {
  checkLockfile,
  checkNpmLockfile,
  checkPnpmLockfile,
  checkYarnLockfile,
  checkBunLockfile,
} from "./lockfile-checker.js";
export { scanGitHubActionsWorkflows } from "./github-actions-scanner.js";
export { scanDockerFiles, scanDockerFile } from "./dockerfile-scanner.js";
export { scanConfigFiles, scanConfigFile } from "./config-scanner.js";
export { scanGitSecurity } from "./git-scanner.js";
export {
  scanInternalDisclosure,
  loadInternalDisclosureConfig,
  emptyInternalDisclosureRuntime,
  hashInternalTerm,
  normalizeInternalTerm,
  candidateTokens,
  isDocumentationFile,
  classifyFileSurface,
  isRuleArmedOnSurface,
  classifyIPv4,
  isPrivateAddressLeak,
  isUniqueLocalIPv6,
  isWellKnownInfraValue,
  isInternalHost,
  isSingleLabelHost,
  severityForHost,
  isNonPublicForgeHost,
  isPersonalAccountName,
  isDevPathContextOk,
  isHostnameLexicalContextOk,
  buildLineIndex,
  lineAtOffset,
  INTERNAL_DISCLOSURE_PATTERNS,
  INTERNAL_DISCLOSURE_ENV,
  INTERNAL_HASH_SALT_ENV,
  MAX_LINE_LENGTH,
  MAX_FINDINGS_PER_RULE,
  MAX_FINDINGS_PER_FILE,
} from "./internal-disclosure.js";
export { analyzeEntropy, shannonEntropy } from "./entropy.js";
export { scanCargoFiles } from "./cargo-scanner.js";
export { scanGoFiles } from "./go-scanner.js";
export { scanRubyGemsFiles } from "./rubygems-scanner.js";
export { scanComposerFiles } from "./composer-scanner.js";
export { scanNuGetFiles } from "./nuget-scanner.js";
export { checkIOCBlocklist, checkBadVersion, checkFileDigest } from "./ioc-blocklist.js";
export { analyzeGitHubTrust, parseGitHubUrl, scanReadmeLures } from "./github-trust-scanner.js";
export { analyzeInstallHooks } from "./install-hook-scanner.js";
export { analyzeDependencyRisks, levenshtein } from "./dependency-risk-analyzer.js";
export { analyzePublishingAnomalies, evaluateVersionDrift, checkRegistryVersionDrift, fetchNpmLatest } from "./publishing-anomaly-detector.js";
export { scanReleaseArtifacts } from "./release-scanner.js";
export { correlateFindings } from "./correlation-engine.js";
export { calculateTrustBreakdown } from "./trust-breakdown.js";
export { loadPolicyConfig, applyPolicy, applyBaseline, describePolicyEffect, saveBaseline } from "./policy-engine.js";
export { detectTrustSignals } from "./trust-signals.js";
// getBundledFeedRef is the read-only companion to getBundledFeed: same entries,
// one stable frozen array instead of a fresh copy per call, so an identity-keyed
// lookup index built over it survives. Exported because an embedder that hands
// getBundledFeed() to a matcher hits exactly the defect issue 177 records.
export { loadThreatIntel, updateThreatFeed, checkThreatIntel, matchPackageIOC, getBundledFeed, getBundledFeedRef, FEED_REMOTE_LIMITS, type FeedLimitOverrides } from "./threat-intel.js";
export {
  feedStats,
  refreshFeed,
  parseFeedPayload,
  DEFAULT_FEED_URL,
  feedFreshness,
  feedStalenessFindings,
  FEED_STALE_AFTER_DAYS,
  FEED_STALE_RULE,
  type FeedFreshness,
} from "./feed.js";
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
export { scanWorkflowGraph } from "./workflow-graph.js";
export { parseWorkflow } from "./workflow-ast.js";
export { scanOpenClawPlugin } from "./openclaw-plugin-scanner.js";
export { checkHoneytokenAccess, getHoneytokenEnv } from "./secret-simulator.js";
export { calculateOrgPosture } from "./posture-engine.js";
// readRiskHistory / readTriageDecisions distinguish an absent store from an
// unreadable one; loadRiskHistory / loadTriageDecisions are the deprecated
// wrappers that cannot, kept because they are already published API.
export {
  readRiskHistory,
  loadRiskHistory,
  saveRiskHistory,
  analyzeRiskTrend,
  riskHistoryUnreadableFinding,
  RiskHistoryUnreadableError,
} from "./continuous-monitor.js";
export type { RiskHistoryRead, RiskHistoryUnreadableReason } from "./continuous-monitor.js";
export {
  readTriageDecisions,
  loadTriageDecisions,
  saveTriageDecisions,
  checkTriageGovernance,
  triageStoreUnreadableFinding,
} from "./triage-engine.js";
export type { TriageDecisionsRead, TriageDecisionsUnreadableReason } from "./triage-engine.js";
export { readJsonArrayStore } from "./state-dir.js";
export type { StateStoreRead, StateStoreStatus, StateStoreUnreadableReason } from "./state-dir.js";
// Exported so a library consumer computing its own view of the triage store
// (the store has no CLI surface, so a consumer is the only way to use it) asks
// the same scope rule this package's own metrics and governance checks ask,
// rather than hand-rolling a third answer. See docs/triage-decisions.md.
export { buildTriageScope, type TriageScope } from "./triage-scope.js";
export { checkSlaCompliance } from "./sla-engine.js";
export { forecastRisk } from "./risk-forecast.js";
export { calculateMetrics } from "./metrics.js";
export {
  generateSbomDocument,
  describeInventoryCoverage,
  detectUninventoriedManifests,
  exactVersionOf,
  parseIntegrity,
  resolveNpmAlias,
  lockfileEntryName,
} from "./sbom-generator.js";
export { verifySLSA, getSLSALevel, parseAttestation } from "./slsa-verifier.js";
export { toOsvRecords, parsePackageValue } from "./osv-export.js";
export { scanPypiDependencyConfusion } from "./dependency-confusion.js";
export { scanMcpConfigs, scanMcpConfigContent, hasMcpConfigFiles, MCP_CONFIG_FILES } from "./mcp-scanner.js";
export {
  scanAgentSkillFiles,
  scanSkillContent,
  scanAgentSettingsContent,
  scanEditorTasksContent,
} from "./skills-scanner.js";
export { handleMcpMessage, handleMcpLine, startMcpServer } from "./mcp-server.js";
export {
  analyzeInstallCommand,
  runInstallGuard,
  extractInstallSpecs,
  parseSpecToken,
  resolveManagerBinary,
  SUPPORTED_MANAGERS,
} from "./install-guard.js";
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
  PolicyConfig,
  PolicyEffect,
  PolicyEffectEntry,
  InternalDisclosurePolicy,
  WatchlistEntry,
  WatchlistConfig,
  WatchlistAlert,
  SbomAnnotation,
  SbomDocument,
  SbomComponent,
  SbomDependency,
  SbomLicenseEntry,
  SbomProperty,
  VexStatement,
} from "./types.js";
