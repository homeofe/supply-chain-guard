/**
 * Core file scanner
 *
 * Scans local directories and GitHub repos for supply-chain malware indicators.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execSync, execFileSync } from "node:child_process";
import type { Finding, ScanOptions, ScanReport, ScanSummary, Severity } from "./types.js";
import { SEVERITY_SCORES } from "./types.js";
import {
  FILE_PATTERNS,
  CAMPAIGN_PATTERNS,
  SUSPICIOUS_FILES,
  SUSPICIOUS_SCRIPTS,
  AUTO_RUN_LIFECYCLE_HOOKS,
  SCANNABLE_EXTENSIONS,
  MAX_FILE_SIZE,
  makeOversizedSkipFinding,
  BINARY_EXTENSIONS,
  BINARY_DOWNLOAD_PATTERNS,
  KNOWN_NATIVE_PACKAGES,
  BEACON_MINER_PATTERNS,
  BUILD_TOOL_PATTERNS,
  BUILD_CONFIG_FILES,
  MONOREPO_PATTERNS,
  CAMPAIGN_PATTERNS_V2,
  OBFUSCATION_PATTERNS_V2,
  IAC_PATTERNS,
  truncateMatch,
} from "./patterns.js";
import {
  maskMixedCommentsPreservingStrings,
} from "./correlated-pattern-matchers.js";
import { matchBareNpmIOC, resolveNpmAlias } from "./install-guard.js";
import { TEST_FILE_PATTERN } from "./pattern-applicability.js";
import {
  hasPartialScanFinding,
  matchPatternInFile,
  matchPatternInSemanticText,
  normalizePublicCoveragePath,
  recordUnreadablePath,
} from "./pattern-scanner.js";
import type { FeedIOC } from "./threat-intel.js";
import { checkLockfile } from "./lockfile-checker.js";
import {
  collectExtractedFiles,
  DEFAULT_EXTRACTED_WALK_MAX_ENTRIES,
} from "./extracted-file-walker.js";
import { scanGitHubActionsWorkflows } from "./github-actions-scanner.js";
import { scanAgenticWorkflows } from "./agentic-workflow-scanner.js";
import { isDockerFile, scanDockerFile } from "./dockerfile-scanner.js";
import { isConfigFile, scanConfigFile } from "./config-scanner.js";
import {
  loadInternalDisclosureConfig,
  scanInternalDisclosure,
} from "./internal-disclosure.js";
import { scanGitSecurity } from "./git-scanner.js";
import { analyzeEntropy } from "./entropy.js";
import { scanCargoFiles, isCargoFile } from "./cargo-scanner.js";
import { scanGoFiles } from "./go-scanner.js";
import { scanRubyGemsFiles } from "./rubygems-scanner.js";
import { scanComposerFiles } from "./composer-scanner.js";
import { scanNuGetFiles, hasNuGetFiles } from "./nuget-scanner.js";
import { scanPythonLockfiles } from "./python-lockfile-scanner.js";
import { checkIOCBlocklist, checkBadVersion, checkFileDigest } from "./ioc-blocklist.js";
import { analyzeGitHubTrust, parseGitHubUrl, scanReadmeLures } from "./github-trust-scanner.js";
import {
  INFOSTEALER_PATTERNS,
  LURE_PATTERNS,
  PROMPT_INJECTION_PATTERNS,
  C2_EXTENDED_PATTERNS,
  SECRETS_PATTERNS,
} from "./patterns.js";
import { analyzeInstallHooks, extractInstallScripts } from "./install-hook-scanner.js";
import { analyzeDependencyRisks } from "./dependency-risk-analyzer.js";
import { correlateFindings } from "./correlation-engine.js";
import { calculateTrustBreakdown } from "./trust-breakdown.js";
import { loadPolicyConfig, applyPolicy, applyBaseline, applyInlineSuppressions, describePolicyEffect, matchGlob } from "./policy-engine.js";
import { detectTrustSignals } from "./trust-signals.js";
import { loadThreatIntel, checkThreatIntel, isInertThreatFeedFile } from "./threat-intel.js";
import { calculateRiskDimensions } from "./risk-engine.js";
import { getChangedFiles } from "./diff-scanner.js";
import { generateRemediations, generateFixSuggestions } from "./remediation-engine.js";
import { generatePlaybooks } from "./playbooks.js";
import { buildAttackGraph } from "./attack-graph.js";
import { validateFindings } from "./active-validation.js";
import { modelWorkflows } from "./workflow-modeler.js";
import { scanWorkflowGraph } from "./workflow-graph.js";
import { scanOpenClawPlugin } from "./openclaw-plugin-scanner.js";
import { feedFreshness, feedStalenessFindings } from "./feed.js";
import { checkRegistryVersionDrift } from "./publishing-anomaly-detector.js";
import { readRiskHistory, riskHistoryUnreadableFinding, analyzeRiskTrend, saveRiskHistory, getRiskTrend } from "./continuous-monitor.js";
import { readTriageDecisions, triageStoreUnreadableFinding, checkTriageGovernance } from "./triage-engine.js";
import { forecastRisk } from "./risk-forecast.js";
import { calculateMetrics } from "./metrics.js";
import {
  OBFUSCATION_V3_PATTERNS,
  PROVENANCE_PATTERNS,
} from "./patterns.js";
import { generateSbomDocument } from "./sbom-generator.js";
import { verifySLSA, getSLSALevel } from "./slsa-verifier.js";
import { scanPypiDependencyConfusion } from "./dependency-confusion.js";
import { scanMcpConfigs, hasMcpConfigFiles } from "./mcp-scanner.js";
import { scanAgentSkillFiles } from "./skills-scanner.js";

const TOOL_VERSION = "5.28.1";

/**
 * Exact files that contain this package's own inert detector definitions or
 * regression fixtures.
 * This allowlist is consulted only when the target is this package's physical
 * install root or a clone that this scanner initiated from the exact canonical
 * HTTPS repository URL. Basenames, suffixes, package metadata, and Git config
 * are never trust boundaries.
 */
const SELF_SCAN_INERT_FILES = new Set([
  "src/active-validation.ts",
  "src/attack-graph.ts",
  "src/broad-gap-pattern-matchers.ts",
  "src/config-scanner.ts",
  "src/correlation-engine.ts",
  "src/dependency-confusion.ts",
  "src/github-trust-scanner.ts",
  "src/install-hook-scanner.ts",
  "src/ioc-blocklist.ts",
  "src/patterns.ts",
  "src/playbooks.ts",
  "src/remediation-engine.ts",
  "src/reporter.ts",
  "src/scanner.ts",
  "src/secret-simulator.ts",
  "src/threat-intel.ts",
  "src/workflow-modeler.ts",
  "src/__tests__/beacon-miner.test.ts",
  "src/__tests__/campaigns.test.ts",
  "src/__tests__/core-broad-gap-matchers.test.ts",
  // Real go: IOC (github.com/BufferZoneCorp/...) used as a go.sum fixture.
  "src/__tests__/go-scanner.test.ts",
  "src/__tests__/infostealer-patterns.test.ts",
  "src/__tests__/ioc-blocklist.test.ts",
  "src/__tests__/issue-24-ioc-evasion.test.ts",
  "src/__tests__/issue-54-hardening.test.ts",
  "src/__tests__/mcp-scanner.test.ts",
  // Real C2 domain IOC used as a fixture for the MCP indicator lookup and the
  // policy domain-allowlist suppression tests (they need a genuine feed IOC).
  "src/__tests__/mcp-server.test.ts",
  "src/__tests__/policy-engine.test.ts",
  // Uses a real bundled C2 domain as a fixture to test own-source recognition.
  "src/__tests__/self-scan-recognition.test.ts",
  "src/__tests__/threat-intel.test.ts",
]);

/**
 * TypeScript's exact runtime/declaration outputs for inert source modules.
 *
 * Keep generated code globally scannable. Only the compiled counterparts of
 * explicitly reviewed source definitions are inert during this package's own
 * scan. Test fixtures are intentionally excluded because tsconfig does not
 * compile them, and an arbitrary dist path must never inherit their exemption.
 */
const SELF_SCAN_INERT_COMPILED_FILES = new Set(
  [...SELF_SCAN_INERT_FILES]
    .filter(
      (relativePath) =>
        relativePath.startsWith("src/") &&
        !relativePath.startsWith("src/__tests__/") &&
        relativePath.endsWith(".ts"),
    )
    .flatMap((relativePath) => {
      const modulePath = relativePath.slice("src/".length, -".ts".length);
      return [`dist/${modulePath}.js`, `dist/${modulePath}.d.ts`];
    }),
);

function isSelfScanInertFile(relativePath: string): boolean {
  const normalizedPath = relativePath.replace(/\\/g, "/");
  return (
    SELF_SCAN_INERT_FILES.has(normalizedPath) ||
    SELF_SCAN_INERT_COMPILED_FILES.has(normalizedPath)
  );
}

/**
 * Pattern literals in this matcher module deliberately spell out signatures
 * that the public scanner detects. Suppress only those exact rule definitions
 * in a scanner-trusted own checkout. A same-named third-party file, or any
 * unrelated rule in this file, remains fully scannable.
 */
const SELF_SCAN_INERT_PATTERN_RULES = new Map<string, ReadonlySet<string>>([
  [
    "src/broad-gap-pattern-matchers.ts",
    new Set([
      "XZ_BUILD_INJECT",
      "CODECOV_EXFIL",
      "VIDAR_WALLET_THEFT",
      "DROPPER_ANTIVM",
      "SHAI_HULUD_WORM",
    ]),
  ],
  [
    "dist/broad-gap-pattern-matchers.js",
    new Set([
      "XZ_BUILD_INJECT",
      "CODECOV_EXFIL",
      "VIDAR_WALLET_THEFT",
      "DROPPER_ANTIVM",
      "SHAI_HULUD_WORM",
    ]),
  ],
]);

function isSelfScanInertPatternRule(
  relativePath: string,
  rule: string,
): boolean {
  const normalizedPath = relativePath.replace(/\\/g, "/");
  return SELF_SCAN_INERT_PATTERN_RULES.get(normalizedPath)?.has(rule) ?? false;
}

/** Detect test / spec / fixture / mock files. Shared constant (was duplicated inline). */
const TEST_FILE_REGEX = TEST_FILE_PATTERN;

const SCANNER_PACKAGE_ROOT = fs.realpathSync(path.resolve(__dirname, ".."));

function isOwnPackageRoot(scanDir: string): boolean {
  try {
    return fs.realpathSync(scanDir) === SCANNER_PACKAGE_ROOT;
  } catch {
    return false;
  }
}

/**
 * Only the original target supplied to this scanner can establish trust for a
 * separate checkout. package.json and .git/config both live inside the scanned
 * trust boundary and are therefore forgeable. The clone path reaches this
 * predicate only after the generic GitHub URL validator has accepted it.
 */
function isCanonicalOwnCloneTarget(target: string): boolean {
  return /^https:\/\/github\.com\/homeofe\/supply-chain-guard(?:\.git)?\/?$/.test(target);
}

/**
 * Scan a local directory or GitHub repo for malware indicators.
 */
export async function scan(options: ScanOptions): Promise<ScanReport> {
  const startTime = Date.now();
  const target = options.target;
  let scanDir = target;
  let scanType: ScanReport["scanType"] = "directory";
  let tempDir: string | null = null;
  let scannerInitiatedOwnClone = false;

  // If target is a GitHub URL, clone it
  if (target.startsWith("https://github.com/")) {
    // Strict allowlist for the clone target: reject anything that is not a
    // clean https GitHub repo URL, so a crafted value cannot inject shell
    // metacharacters or git options into the clone below.
    if (
      !/^https:\/\/github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(?:\.git)?\/?$/.test(
        target,
      )
    ) {
      throw new Error(
        `Refusing to clone: not a valid GitHub repository URL: ${target}`,
      );
    }
    scannerInitiatedOwnClone = isCanonicalOwnCloneTarget(target);
    scanType = "github";
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-"));
    const cloneDir = path.join(tempDir, "repo");
    try {
      // execFileSync runs git directly without a shell, so the URL can never
      // be interpreted as a command.
      execFileSync("git", ["clone", "--depth", "1", target, cloneDir], {
        stdio: "pipe",
      });
    } catch {
      throw new Error(`Failed to clone repository: ${target}`);
    }
    scanDir = cloneDir;
  }

  // Validate directory exists
  if (!fs.existsSync(scanDir)) {
    throw new Error(`Target directory does not exist: ${scanDir}`);
  }

  const stat = fs.statSync(scanDir);
  if (!stat.isDirectory()) {
    throw new Error(`Target is not a directory: ${scanDir}`);
  }

  const scanningOwnPackage = isOwnPackageRoot(scanDir) || scannerInitiatedOwnClone;

  // Load policy up front: its `ignore:` globs prune the scanner walk, and the
  // same object is reused for the suppression passes further down.
  const policy = loadPolicyConfig(scanDir);
  const ignoreGlobs = policy?.ignore ?? [];
  // v5.29 (issue 168): record WHAT the config turns off, not just how many
  // findings it removed. `ignore:` never reached suppressedCount at all, since
  // it prunes files here, before any rule runs; a scan narrowed that way used
  // to be indistinguishable from a clean one in every output format.
  const policyEffect = policy ? describePolicyEffect(policy) : undefined;

  // Collect files (v4.5: diff mode filters to changed files only). Coverage
  // failures are held separately so policy.ignore can remove out-of-scope
  // directory failures before they become report findings.
  const pathCoverageFindings: Finding[] = [];
  let allFiles = collectFiles(
    scanDir,
    options.maxDepth ?? 20,
    0,
    pathCoverageFindings,
    scanDir,
    options.maxEntries,
  );

  // Config `ignore:` path globs: drop matching files from the scan (v5.13).
  if (ignoreGlobs.length > 0) {
    allFiles = allFiles.filter((f) => {
      const rel = path.relative(scanDir, f).replace(/\\/g, "/");
      return !ignoreGlobs.some((glob) => matchGlob(glob, rel));
    });
    for (let i = pathCoverageFindings.length - 1; i >= 0; i--) {
      const rel = pathCoverageFindings[i]!.file ?? ".";
      if (rel === ".") continue;
      if (
        ignoreGlobs.some(
          (glob) =>
            matchGlob(glob, rel) ||
            matchGlob(glob, `${rel}/__scg_ignored__`),
        )
      ) {
        pathCoverageFindings.splice(i, 1);
      }
    }
  }

  if (options.sinceCommit && fs.existsSync(path.join(scanDir, ".git"))) {
    const changedFiles = new Set(getChangedFiles(scanDir, options.sinceCommit));
    if (changedFiles.size > 0) {
      allFiles = allFiles.filter((f) => changedFiles.has(f));
    }
  }

  // v4.5: Load threat intelligence feed
  const threatFeed = loadThreatIntel();

  // Internal-disclosure deny-list. Loaded once: the hashed terms come from the
  // committed policy file, the plaintext patterns from an unpublished file or
  // the SCG_INTERNAL_DISCLOSURE_FILE environment variable. With nothing
  // configured this is inert and only the built-in shape rules run.
  const internalDisclosure = loadInternalDisclosureConfig(scanDir, policy);

  let findings: Finding[] = [
    ...pathCoverageFindings,
    ...internalDisclosure.loadFindings,
  ];

  // Scan each file
  let filesScanned = 0;
  for (const filePath of allFiles) {
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath);
    const relativePath = path.relative(scanDir, filePath).replace(/\\/g, "/");

    // Check suspicious file names
    checkSuspiciousFileName(basename, relativePath, findings);

    // Check for unexpected binary/native addon files (T-007)
    if (BINARY_EXTENSIONS.has(ext)) {
      checkBinaryFile(relativePath, findings);
    }

    // Digest match against KNOWN_MALICIOUS_HASHES, computed over the RAW BYTES.
    //
    // Runs BEFORE the SCANNABLE_EXTENSIONS gate on purpose. Hashing needs no
    // parser, and most of that collection describes compiled payloads that
    // carry no scannable extension, so they never reach the content scanners
    // at all. Gating this on the extension list would leave exactly the
    // artefacts the digests were collected for unreachable.
    //
    // Reading a file the content pass would otherwise skip is new I/O, which
    // is why the same MAX_FILE_SIZE ceiling applies. A payload padded past
    // that ceiling would no longer match its published digest anyway.
    //
    // The buffer is reused for the UTF-8 decode below, so a scannable file is
    // still read exactly once.
    let fileBytes: Buffer | undefined;
    try {
      if (fs.statSync(filePath).size <= MAX_FILE_SIZE) {
        fileBytes = fs.readFileSync(filePath);
        findings.push(...checkFileDigest(fileBytes, relativePath));
      }
    } catch {
      // Leave fileBytes undefined and stay silent here: the oversized and
      // unreadable paths below own that accounting, and reporting it twice
      // would double-count a single file.
      fileBytes = undefined;
    }

    // Tracks whether the internal-disclosure pass already ran for this file.
    // Dockerfiles and package-manager configs are read in the block below and
    // some of them (.yarnrc.yml) also carry a scannable extension, so without
    // this guard those files would be reported twice.
    let internalDisclosureScanned = false;

    // Scan Docker/Config files inline (v4.0). Keep I/O separate from analysis
    // so an analyzer defect is never mislabeled as an unreadable path. These
    // extensionless targets are first-class scanned files and obey the same
    // size/read contract as extension-based source files.
    let prefetchedContent: string | undefined;
    const inlineContentTarget = isDockerFile(basename) || isConfigFile(basename);
    if (inlineContentTarget) {
      let inlineStat: fs.Stats;
      try {
        inlineStat = fs.statSync(filePath);
      } catch {
        recordUnreadablePath(findings, relativePath);
        continue;
      }
      if (inlineStat.size > MAX_FILE_SIZE) {
        findings.push(makeOversizedSkipFinding(relativePath, inlineStat.size));
        continue;
      }
      try {
        prefetchedContent =
          fileBytes !== undefined
            ? fileBytes.toString("utf-8")
            : fs.readFileSync(filePath, "utf-8");
      } catch {
        recordUnreadablePath(findings, relativePath);
        continue;
      }

      if (isDockerFile(basename)) {
        findings.push(...scanDockerFile(prefetchedContent, relativePath));
      }
      if (isConfigFile(basename)) {
        findings.push(...scanConfigFile(prefetchedContent, relativePath));
      }
      // A Dockerfile FROM line and an .npmrc registry line are two of the
      // most common places an internal host name reaches a public repo, and
      // neither file carries a scannable extension.
      findings.push(
        ...scanInternalDisclosure(
          prefetchedContent,
          relativePath,
          internalDisclosure,
        ),
      );
      internalDisclosureScanned = true;
    }

    // Successfully analyzed extensionless Docker/config targets count once.
    if (!SCANNABLE_EXTENSIONS.has(ext)) {
      if (prefetchedContent !== undefined) filesScanned++;
      continue;
    }

    // Skip large files - but never silently (issue #54): an oversized
    // scannable file is a coverage gap an attacker can create on purpose
    // (pad a payload past the limit to dodge content scanning).
    let fileStat: fs.Stats;
    try {
      fileStat = fs.statSync(filePath);
    } catch {
      recordUnreadablePath(findings, relativePath);
      continue;
    }
    if (fileStat.size > MAX_FILE_SIZE) {
      findings.push(makeOversizedSkipFinding(relativePath, fileStat.size));
      continue;
    }

    let content: string;
    if (prefetchedContent !== undefined) {
      content = prefetchedContent;
    } else {
      try {
        content =
          fileBytes !== undefined
            ? fileBytes.toString("utf-8")
            : fs.readFileSync(filePath, "utf-8");
      } catch {
        recordUnreadablePath(findings, relativePath);
        continue;
      }
    }
    filesScanned++;

    // Skip supply-chain-guard's own published threat-feed data (feed.json /
    // threat-feed.json): it intentionally carries raw IOC values as inert,
    // structurally-validated detection data. Any deviation from the strict
    // feed schema fails the check and the file is scanned normally.
    if (isInertThreatFeedFile(relativePath, content)) continue;

    // Check file content patterns
    checkFilePatterns(
      content,
      relativePath,
      findings,
      scanningOwnPackage,
    );

    // Internal topology disclosure: private addresses, internal-only
    // hostnames, non-public forge URLs, developer paths, plus the
    // configured deny-list. Reported at medium/low, so the family cannot
    // change the exit code of an existing --fail-on high pipeline.
    if (!internalDisclosureScanned) {
      findings.push(
        ...scanInternalDisclosure(content, relativePath, internalDisclosure),
      );
    }

    // Check build tool configs for plugin risks (v4.0)
    if (BUILD_CONFIG_FILES.has(basename)) {
      checkBuildToolPatterns(content, relativePath, findings);
    }

    // Check workspace/monorepo patterns (v4.0)
    if (basename === "package.json" && relativePath === "package.json") {
      checkMonorepoPatterns(content, relativePath, findings);
    }

    // Check beacon and miner patterns (T-008)
    checkBeaconMinerPatterns(content, relativePath, findings, scanningOwnPackage);

    // Entropy analysis for obfuscated payloads (v4.0)
    const entropyFindings = analyzeEntropy(content, relativePath);
    findings.push(...entropyFindings);

    // IOC blocklist + threat-intel checks skip only reviewed scanner
    // definition/fixture paths and exact TypeScript-compiled counterparts.
    const isOwnDefinitionOrFixture =
      scanningOwnPackage && isSelfScanInertFile(relativePath);
    if (!isOwnDefinitionOrFixture) {
      const iocFindings = checkIOCBlocklist(content, relativePath);
      findings.push(...iocFindings);

      const tiFindings = checkThreatIntel(content, relativePath, threatFeed);
      findings.push(...tiFindings);
    }

    // README / doc-file lure pattern scanning (v4.1, scope expanded v5.2.20)
    // Covers README, CHANGELOG, CONTRIBUTING, DESCRIPTION, release-notes -
    // matches LURE_PATTERNS' onlyFilePattern. Previously only `readme*`
    // files were routed here, but the LURE patterns themselves are scoped
    // to all of these. After v5.2.20 removed LURE_PATTERNS from the
    // general checkFilePatterns sweep (dedupe fix), scanReadmeLures became
    // the sole entry point so it now covers the full doc-file family.
    if (/^(?:readme|changelog|contributing|description|release[-_]notes)/i.test(basename)) {
      const lureFindings = scanReadmeLures(content, relativePath);
      findings.push(...lureFindings);
    }

    // Check package.json specifically (skip test fixture directories)
    const normPkgPath = relativePath.replace(/\\/g, "/");
    if (basename === "package.json" && !TEST_FILE_REGEX.test(normPkgPath)) {
      checkPackageJson(content, relativePath, findings);
      // Check for binary download patterns in install scripts (T-007)
      checkBinaryDownloadScripts(content, relativePath, findings);
      // Check for known-bad package versions (v4.1)
      checkKnownBadVersions(content, relativePath, findings);
      // Flag dependency names matching a known-malicious/typosquat pattern.
      // Closes the gap where a directory scan of your own repo did not catch
      // a known-bad dependency (only the `npm <pkg>` path did). Patterns are
      // anchored, so only exact malicious names match.
      checkMaliciousDependencyNames(content, relativePath, findings, threatFeed);

      // Deep install hook analysis (v4.2)
      const hookScripts = extractInstallScripts(content);
      if (hookScripts) {
        const hookFindings = analyzeInstallHooks(hookScripts, relativePath);
        findings.push(...hookFindings);
      }

      // Dependency risk analysis (v4.2)
      try {
        const pkg = JSON.parse(content) as Record<string, unknown>;
        const allDeps = {
          ...(pkg.dependencies as Record<string, string> | undefined),
          ...(pkg.devDependencies as Record<string, string> | undefined),
        };
        if (Object.keys(allDeps).length > 0) {
          const depFindings = analyzeDependencyRisks(allDeps, relativePath);
          findings.push(...depFindings);
        }
      } catch { /* not valid JSON */ }
    }

    // Check package-lock.json for known-bad versions (v4.1)
    if (basename === "package-lock.json") {
      checkLockfileBadVersions(content, relativePath, findings, threatFeed);
    }
  }

  // Check git commit dates if it's a git repo
  if (fs.existsSync(path.join(scanDir, ".git"))) {
    checkGitDateAnomalies(scanDir, findings);
  }

  // Check lockfile integrity (T-006)
  const lockfileFindings = checkLockfile(scanDir);
  findings.push(...lockfileFindings);

  // Check GitHub Actions workflows (#9)
  const ghaFindings = scanGitHubActionsWorkflows(scanDir);
  findings.push(...ghaFindings);

  // v5.10: GitHub Agentic Workflow (gh-aw) markdown files (.github/workflows/*.md)
  findings.push(...scanAgenticWorkflows(scanDir));

  // v4.9: SLSA provenance verification
  findings.push(...verifySLSA(scanDir));

  // v4.9: PyPI dependency confusion (if requirements.txt / pyproject.toml present)
  try {
    const pypiConfusion = await scanPypiDependencyConfusion(scanDir);
    findings.push(...pypiConfusion);
  } catch { /* skip if offline */ }

  // v5.9: opt-in registry version-drift (source package.json vs npm 'latest').
  // Network call, so off by default; --check-registry enables it. Offline-safe.
  if (options.checkRegistry) {
    try {
      findings.push(...(await checkRegistryVersionDrift(scanDir)));
    } catch { /* offline / registry error: skip */ }
  }

  // GitHub trust signal analysis (v4.1)
  if (scanType === "github") {
    const parsed = parseGitHubUrl(target);
    if (parsed) {
      const trustFindings = analyzeGitHubTrust(parsed.owner, parsed.repo);
      findings.push(...trustFindings);
    }
  }

  // Docker and package-manager config files were already scanned inline in the
  // policy-filtered file walk. A second directory pass duplicated findings and
  // bypassed ignore globs.

  // Explicit specialized targets perform their own tri-state path probes.
  // Calling them without existsSync gates preserves the distinction between an
  // absent optional target and a target whose stat/read operation failed.
  findings.push(...scanGitSecurity(scanDir));
  findings.push(...scanCargoFiles(scanDir));
  findings.push(...scanGoFiles(scanDir));
  findings.push(...scanRubyGemsFiles(scanDir));
  findings.push(...scanComposerFiles(scanDir));

  // NuGet discovery is a root-directory optimization that deliberately opens
  // the scanner on enumeration failure so scanNuGetFiles can report coverage.
  if (hasNuGetFiles(scanDir)) {
    findings.push(...scanNuGetFiles(scanDir));
  }

  findings.push(...scanPythonLockfiles(scanDir));

  // Check MCP server configs (.mcp.json / .cursor/mcp.json / .vscode/mcp.json /
  // claude_desktop_config.json / .gemini/settings.json)
  if (hasMcpConfigFiles(scanDir)) {
    const mcpFindings = scanMcpConfigs(scanDir);
    findings.push(...mcpFindings);
  }
  // Check AI agent skill / rules files (.claude, .cursorrules, CLAUDE.md, ...)
  // The main walk skips .claude/ - this scanner does its own targeted traversal.
  const skillFindings = scanAgentSkillFiles(scanDir);
  findings.push(...skillFindings);

  // v5.7: OpenClaw plugin manifest posture (only fires if openclaw.plugin.json present)
  findings.push(...scanOpenClawPlugin(scanDir));

  // v4.7: Workflow execution modeling
  const wfFindings = modelWorkflows(scanDir);
  findings.push(...wfFindings);

  // v5.7: Cross-workflow trust-boundary analysis (Cordyceps composition attacks).
  // Runs across ALL workflow files - catches the producer->consumer artifact
  // escalation that the single-file GHA scanner and modeler cannot see.
  const wfGraphFindings = scanWorkflowGraph(scanDir);
  findings.push(...wfGraphFindings);

  // v4.4: Detect positive trust signals (only for GitHub repo scans)
  if (scanType === "github") {
    const trustSignals = detectTrustSignals(scanDir);
    findings.push(...trustSignals);
  }

  // Report the age of the rule set this scan actually matched against. Every
  // other finding describes the scanned repository; this one describes what
  // the scanner was able to look for, which until now no output carried. It is
  // measured over `threatFeed` (the merged bundled + refreshed-cache list that
  // checkThreatIntel and matchPackageIOC consumed above), so a consumer that
  // refreshes the feed is reported current even on an old pin, and a consumer
  // on a frozen pin is told so instead of receiving another green check.
  // Carries no `file`, so the path-ignore filter below leaves it in place.
  findings.push(...feedStalenessFindings(feedFreshness(threatFeed)));

  // Apply path ignores to out-of-band scanners too. The primary file walk was
  // pruned before scanning, but Git/lockfile/agent scanners discover their own
  // targets and must honor the same path contract, including coverage findings.
  if (ignoreGlobs.length > 0) {
    findings = findings.filter((finding) => {
      if (!finding.file) return true;
      const relative = finding.file.replace(/\\/g, "/");
      if (finding.rule === "PATH_SCAN_INCOMPLETE" && relative === ".") {
        return true;
      }
      return !ignoreGlobs.some(
        (glob) =>
          matchGlob(glob, relative) ||
          matchGlob(glob, `${relative}/__scg_ignored__`),
      );
    });
  }

  // The primary walk and specialized scanners may report the same failed path.
  // Keep one public coverage signal per normalized relative path.
  const seenIncompletePaths = new Set<string>();
  findings = findings.filter((finding) => {
    if (finding.rule !== "PATH_SCAN_INCOMPLETE") return true;
    const publicPath = normalizePublicCoveragePath(finding.file ?? ".");
    if (seenIncompletePaths.has(publicPath)) return false;
    seenIncompletePaths.add(publicPath);
    finding.file = publicPath;
    return true;
  });

  // Preserve completeness independently of policy, baseline, or severity filters.
  // A user may hide the informational finding, but that cannot turn a partial
  // evaluation into a complete report.
  let partialScan = hasPartialScanFinding(findings);

  // v4.7: Active validation (assign confidence tiers, rationale, evidence)
  validateFindings(findings);

  // v5.4.2: Apply policy BEFORE all downstream analytics. Correlation, trust
  // breakdown, trend/forecast and governance previously consumed raw findings,
  // so policy-suppressed findings leaked into "incidents" (a clean report
  // showed a 100%-confidence worm incident built from suppressed FPs) and the
  // trend check compared a pre-suppression score against the post-suppression
  // history (guaranteed phantom RISK_TREND_SPIKE on the second scan of any
  // repo with suppressions). Same bug class as the v5.2.40 SARIF/SBOM leak.
  let suppressedCount = 0;

  // Inline // scg-ignore-next-line RULE / # scg-ignore-next-line RULE comments:
  // drop a finding when the source line directly above it carries the directive.
  const inlineResult = applyInlineSuppressions(findings, scanDir);
  findings = inlineResult.findings;
  suppressedCount += inlineResult.suppressedCount;

  if (policy) {
    const policyResult = applyPolicy(findings, policy);
    findings = policyResult.findings;
    suppressedCount += policyResult.suppressedCount;
  }
  // Policy validation findings are materialized by applyPolicy(), so refresh
  // the snapshot before later filters can hide a coverage-breaking warning.
  partialScan ||= hasPartialScanFinding(findings);

  // v4.2: Correlation engine - link findings into incidents
  const correlation = correlateFindings(findings);

  // v4.2: Trust breakdown (for directory/github scans with package.json)
  const hasLockfile = fs.existsSync(path.join(scanDir, "package-lock.json"));
  const trustBreakdown = calculateTrustBreakdown(findings, target, hasLockfile);

  // v4.8: Continuous risk monitoring (scores are now post-suppression,
  // matching what saveRiskHistory persists)
  //
  // An absent history is a first scan and stays silent. A history file that
  // exists but cannot be read is lost evidence, and it must not be reported as
  // the same clean empty baseline: every trend and forecast rule below then
  // finds nothing while the scan still reports success, which is how a corrupt
  // state file flipped the default gate from fail to pass with the scanned code
  // unchanged. This read is deliberately NOT gated on `--no-history`: that flag
  // suppresses the write only, so a corrupt file still degrades this verdict
  // and still has to be reported.
  //
  // `partialScan` is set here rather than left to `hasPartialScanFinding`
  // because the second policy pass and the severity filter below both run after
  // this point and can remove the finding. That is the same reasoning as the
  // refresh above: a suppression filter may hide a finding, and may never turn
  // incomplete coverage into a complete clean verdict. Setting the flag here
  // also keeps the save at the end of this function from overwriting the
  // unreadable file, which is what preserves the recoverable entries in it.
  const historyRead = readRiskHistory(scanDir);
  const riskHistory = historyRead.entries;
  if (historyRead.status === "unreadable") partialScan = true;

  const trendFindings = analyzeRiskTrend(riskHistory, calculateScore(findings));
  findings.push(...trendFindings);
  const forecastFindings = forecastRisk(riskHistory, calculateScore(findings));
  findings.push(...forecastFindings);

  // Pushed after the two analyzers, not before, so the current score they are
  // given is a score of the scanned project and never includes this finding
  // about the scanner's own state file. Today that ordering cannot change an
  // outcome, because an unreadable history yields zero entries and both
  // analyzers return early on a short history; the ordering is here so that
  // stays true if either early return is ever relaxed.
  if (historyRead.status === "unreadable") {
    findings.push(riskHistoryUnreadableFinding(historyRead.reason ?? "read-failed"));
  }

  // v4.8: Triage governance checks
  //
  // Same three-way read as the history above, and for the same measured reason:
  // a truncated triage store took this scan from exit 1 with two high findings
  // to exit 0 with none, and reported metrics.slaComplianceRate 100 where the
  // intact store gave 0. See src/triage-engine.ts for the measurement.
  const triageRead = readTriageDecisions(scanDir);
  const triageDecisions = triageRead.entries;
  if (triageRead.status === "unreadable") partialScan = true;

  const govFindings = checkTriageGovernance(findings, triageDecisions);
  findings.push(...govFindings);

  // Pushed after checkTriageGovernance for the same reason as the history
  // finding above: the governance rules read the findings list, so a finding
  // about the scanner's own state file is kept out of the input they judge.
  if (triageRead.status === "unreadable") {
    findings.push(triageStoreUnreadableFinding(triageRead.reason ?? "read-failed"));
  }

  // v5.4.2: Second policy pass over the late-added findings (trend, forecast,
  // governance) so rules like RISK_TREND_SPIKE stay suppressible. Findings
  // removed by the first pass are already gone; this only affects the
  // additions above.
  if (policy) {
    const latePass = applyPolicy(findings, policy);
    findings = latePass.findings;
    suppressedCount += latePass.suppressedCount;
  }

  // v4.4: Apply baseline (if configured)
  const baselineFile = options.baselineFile ?? policy?.baseline?.file;
  if (baselineFile) {
    const baselinePath = path.isAbsolute(baselineFile)
      ? baselineFile
      : path.join(scanDir, baselineFile);
    const baselineResult = applyBaseline(findings, baselinePath);
    findings = baselineResult.findings;
    suppressedCount += baselineResult.suppressedCount;
  }

  // Filter by severity and excluded rules
  const filteredFindings = filterFindings(findings, options);

  // Calculate summary and score (with correlation risk boost)
  const summary = calculateSummary(allFiles.length, filesScanned, filteredFindings);
  const baseScore = calculateScore(filteredFindings);
  const score = Math.min(100, baseScore + correlation.riskBoost);
  const riskLevel = getRiskLevel(score);
  const recommendations = generateRecommendations(filteredFindings, partialScan);

  // v4.8: Calculate metrics and save history
  const metrics = calculateMetrics(filteredFindings, riskHistory, triageDecisions);

  // Save risk history for trend tracking (skip temp dirs; --no-history lets
  // read-only callers like the pre-commit hook avoid writing state into the
  // scanned repo). Partial results are not comparable measurements and must
  // never become a zero-score baseline for later trend/forecast analysis.
  if (!tempDir && !options.noHistory && !partialScan) {
    try { saveRiskHistory(scanDir, { timestamp: new Date().toISOString(), score, findings: filteredFindings, summary, riskLevel, recommendations, target, scanType, tool: `supply-chain-guard v${TOOL_VERSION}`, durationMs: Date.now() - startTime }); } catch { /* skip */ }
  }

  // Cleanup temp directory
  if (tempDir) {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }

  return {
    tool: `supply-chain-guard v${TOOL_VERSION}`,
    timestamp: new Date().toISOString(),
    target,
    scanType,
    durationMs: Date.now() - startTime,
    findings: filteredFindings,
    summary,
    score,
    riskLevel,
    recommendations,
    incidents: correlation.incidents.length > 0 ? correlation.incidents : undefined,
    trustBreakdown,
    suppressedCount: suppressedCount > 0 ? suppressedCount : undefined,
    policyEffect,
    partialScan: partialScan || undefined,
    riskDimensions: calculateRiskDimensions(filteredFindings),
    remediations: generateRemediations(filteredFindings),
    fixSuggestions: generateFixSuggestions(filteredFindings),
    playbooks: correlation.incidents.length > 0
      ? generatePlaybooks(correlation.incidents)
      : undefined,
    attackGraph: filteredFindings.length > 0
      ? buildAttackGraph(filteredFindings, target)
      : undefined,
    riskHistory: riskHistory.length > 0 ? riskHistory : undefined,
    metrics,
    // v4.9: CycloneDX 1.6 SBOM from actual dependency inventory
    sbomDocument: generateSbomDocument(scanDir, filteredFindings),
    // v4.9: SLSA provenance level
    slsaLevel: getSLSALevel(scanDir),
  };
}

/**
 * Recursively collect all files in a directory.
 */
function collectFiles(
  dir: string,
  maxDepth: number,
  _depth = 0,
  findings: Finding[] = [],
  _rootDir = dir,
  maxEntries?: number,
): string[] {
  const excludedDirectories = new Set([
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".claude",
    ".scg-history",
    ".scg-cache",
  ]);
  return collectExtractedFiles(dir, findings, {
    maxDepth,
    maxEntries: maxEntries === undefined
      ? DEFAULT_EXTRACTED_WALK_MAX_ENTRIES
      : Math.min(maxEntries, DEFAULT_EXTRACTED_WALK_MAX_ENTRIES),
    shouldEnterDirectory: (name) => !excludedDirectories.has(name),
  });
}
/**
 * Check if a filename matches known suspicious patterns.
 */
function checkSuspiciousFileName(
  basename: string,
  relativePath: string,
  findings: Finding[],
): void {
  for (const suspicious of SUSPICIOUS_FILES) {
    const hits = matchPatternInSemanticText(
      suspicious,
      basename,
      relativePath,
      findings,
    );
    if (hits && hits.length > 0) {
      findings.push({
        rule: suspicious.rule,
        description: suspicious.description,
        severity: suspicious.severity,
        file: relativePath,
        recommendation: `Inspect ${relativePath} manually. This filename is commonly associated with malware campaigns.`,
      });
    }
  }
}

/**
 * Scan file content against known malicious patterns.
 */
function checkFilePatterns(
  content: string,
  relativePath: string,
  findings: Finding[],
  scanningOwnPackage: boolean,
): void {
  // Note: LURE_PATTERNS deliberately excluded here. README-style files are
  // already covered by scanReadmeLures() in github-trust-scanner.ts (called
  // earlier in scanDirectory). Including them in this loop produced duplicate
  // findings for every README hit (same rule+file+line+match, different
  // recommendation text). v5.2.20 dedupe fix.
  const allPatterns = [
    ...FILE_PATTERNS,
    ...CAMPAIGN_PATTERNS,
    ...CAMPAIGN_PATTERNS_V2,
    ...OBFUSCATION_PATTERNS_V2,
    ...IAC_PATTERNS,
    ...INFOSTEALER_PATTERNS,
    ...PROMPT_INJECTION_PATTERNS,
    ...C2_EXTENDED_PATTERNS,
    ...SECRETS_PATTERNS,
    ...OBFUSCATION_V3_PATTERNS,
    ...PROVENANCE_PATTERNS,
  ];

  for (const pattern of allPatterns) {
    const hits = matchPatternInFile(
      pattern,
      content,
      relativePath,
      findings,
      "g",
    );
    for (const hit of hits ?? []) {
      if (
        scanningOwnPackage &&
        isSelfScanInertPatternRule(relativePath, pattern.rule)
      ) {
        continue;
      }
      findings.push({
        rule: pattern.rule,
        description: pattern.description,
        severity: pattern.severity,
        file: relativePath,
        line: hit.line,
        match: truncateMatch(hit.text),
        recommendation: getRecommendation(pattern.rule),
      });
    }
  }
}

/**
 * Check package.json for suspicious install scripts.
 */
function checkPackageJson(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return;
  }

  const scripts = pkg.scripts as Record<string, string> | undefined;
  if (!scripts) return;

  // Shared with npm-scanner.ts and install-hook-scanner.ts so the three paths
  // cannot drift apart again; see AUTO_RUN_LIFECYCLE_HOOKS for why each name
  // is in the list and why prepublishOnly is not.
  for (const hook of AUTO_RUN_LIFECYCLE_HOOKS) {
    const script = scripts[hook];
    if (!script) continue;

    // Check against suspicious script patterns
    for (const pattern of SUSPICIOUS_SCRIPTS) {
      const hits = matchPatternInFile(
        pattern,
        script,
        relativePath,
        findings,
        "i",
      );
      if (hits && hits.length > 0) {
        findings.push({
          rule: pattern.rule,
          description: `${hook}: ${pattern.description}`,
          severity: pattern.severity,
          file: relativePath,
          match: truncateMatch(`${hook}: ${script}`),
          recommendation: `Review the ${hook} script in ${relativePath}. Suspicious install scripts are a primary vector for supply-chain attacks.`,
        });
      }
    }

    // Flag any non-trivial postinstall/preinstall
    if (
      (hook === "postinstall" || hook === "preinstall") &&
      script.length > 50 &&
      !findings.some(
        (f) =>
          f.file === relativePath &&
          f.rule.startsWith("SCRIPT_"),
      )
    ) {
      findings.push({
        rule: "COMPLEX_INSTALL_SCRIPT",
        description: `Complex ${hook} script detected (${script.length} chars). Long install scripts warrant manual review.`,
        severity: "low",
        file: relativePath,
        match: truncateMatch(`${hook}: ${script}`),
        recommendation: `Review the ${hook} script to ensure it only performs expected build/setup operations.`,
      });
    }
  }
}

/**
 * Check for git commit date anomalies (committer date much newer than author date).
 */
function checkGitDateAnomalies(dir: string, findings: Finding[]): void {
  try {
    const log = execFileSync(
      "git",
      ["-C", dir, "log", "--format=%H|%aI|%cI", "-20"],
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );

    const lines = log.trim().split("\n").filter(Boolean);

    for (const line of lines) {
      const [hash, authorDate, committerDate] = line.split("|");
      if (!hash || !authorDate || !committerDate) continue;

      const authorTime = new Date(authorDate).getTime();
      const committerTime = new Date(committerDate).getTime();
      const diffHours = (committerTime - authorTime) / (1000 * 60 * 60);

      // Flag if committer date is more than 30 days newer than author date
      if (diffHours > 30 * 24) {
        findings.push({
          rule: "GIT_DATE_ANOMALY",
          description: `Git commit date anomaly: committer date is ${Math.round(diffHours / 24)} days newer than author date. This can indicate repository history manipulation.`,
          severity: "medium",
          match: `commit ${hash?.substring(0, 8)}: authored ${authorDate}, committed ${committerDate}`,
          recommendation:
            "Investigate the commit history. Large gaps between author and committer dates may indicate a hijacked or manipulated repository.",
        });
      }
    }
  } catch {
    // Not a git repo or git not available
  }
}

/**
 * Check for unexpected binary/native addon files (T-007).
 */
function checkBinaryFile(relativePath: string, findings: Finding[]): void {
  // Check if the binary belongs to a known native package
  const parts = relativePath.split(/[/\\]/);
  const isKnownNative = parts.some((part) => KNOWN_NATIVE_PACKAGES.has(part));

  if (isKnownNative) {
    findings.push({
      rule: "BINARY_KNOWN_NATIVE",
      description: `Binary file "${relativePath}" belongs to a known native addon package.`,
      severity: "info",
      file: relativePath,
      recommendation:
        "This is expected for known native addon packages. Verify the package is intentionally included.",
    });
  } else {
    findings.push({
      rule: "BINARY_UNEXPECTED",
      description: `Unexpected binary/native file detected: "${relativePath}". Binary files in npm packages are unusual unless the package is a known native addon.`,
      severity: "high",
      file: relativePath,
      recommendation:
        "Inspect this binary file. Legitimate npm packages rarely include precompiled binaries unless they are known native addon packages (e.g., sharp, better-sqlite3).",
    });
  }
}

/**
 * Check package.json install scripts for binary download patterns (T-007).
 */
function checkBinaryDownloadScripts(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return;
  }

  const scripts = pkg.scripts as Record<string, string> | undefined;
  if (!scripts) return;

  const pkgName = (pkg.name as string) ?? "";
  const isKnownNative = KNOWN_NATIVE_PACKAGES.has(pkgName);

  const installHooks = ["preinstall", "postinstall", "install"];

  for (const hook of installHooks) {
    const script = scripts[hook];
    if (!script) continue;

    for (const pattern of BINARY_DOWNLOAD_PATTERNS) {
      const hits = matchPatternInFile(
        pattern,
        script,
        relativePath,
        findings,
        "i",
      );
      if (hits && hits.length > 0) {
        findings.push({
          rule: pattern.rule,
          description: `${hook}: ${pattern.description}${isKnownNative ? " (known native package)" : ""}`,
          severity: isKnownNative ? "info" : pattern.severity,
          file: relativePath,
          match: truncateMatch(`${hook}: ${script}`),
          recommendation: isKnownNative
            ? `This is expected for ${pkgName}. Native packages commonly download prebuilt binaries.`
            : `Review the ${hook} script. Binary downloads in install scripts can be a supply-chain attack vector.`,
        });
      }
    }
  }
}

/**
 * Scan file content for beacon and crypto miner patterns (T-008).
 */
function checkBeaconMinerPatterns(
  content: string,
  relativePath: string,
  findings: Finding[],
  scanningOwnPackage: boolean,
): void {
  for (const pattern of BEACON_MINER_PATTERNS) {
    const hits = matchPatternInFile(
      pattern,
      content,
      relativePath,
      findings,
      "gi",
    );
    for (const hit of hits ?? []) {
      findings.push({
        rule: pattern.rule,
        description: pattern.description,
        severity: pattern.severity,
        file: relativePath,
        line: hit.line,
        match: truncateMatch(hit.text),
        recommendation: getRecommendation(pattern.rule),
      });
    }
  }

  // Multi-line protestware check: locale/timezone on one line, destructive on nearby lines
  checkMultiLineProtestware(content, relativePath, findings, scanningOwnPackage);
}

/**
 * Check for protestware patterns spanning multiple lines.
 * Looks for locale/timezone checks within 15 lines of destructive operations.
 */
function checkMultiLineProtestware(
  content: string,
  relativePath: string,
  findings: Finding[],
  scanningOwnPackage: boolean,
): void {
  // Only this package or an identity-verified checkout may suppress exact
  // definition/fixture paths and compiled counterparts. Basenames never qualify.
  if (scanningOwnPackage && isSelfScanInertFile(relativePath)) return;

  const PROXIMITY = 15;
  const PROXIMITY_CHARS = 512;
  const alreadyFound = findings.some(
    (finding) =>
      finding.rule === "PROTESTWARE_LOCALE_DESTRUCT" &&
      finding.file === relativePath,
  );
  if (alreadyFound) return;

  // Comments and regex literals cannot provide either side of the correlation.
  // Keep string values visible for geo comparisons and destructive shell calls;
  // a second same-length view blanks them only while matching block structure.
  const searchableContent = maskMixedCommentsPreservingStrings(content);
  const structureCharacters = searchableContent.split("");
  let quote: "'" | '"' | "`" | undefined;
  for (let index = 0; index < structureCharacters.length; index++) {
    const character = structureCharacters[index]!;
    if (quote === undefined) {
      if (character === "'" || character === '"' || character === "`") {
        quote = character;
        structureCharacters[index] = " ";
      }
      continue;
    }

    if (character === "\\") {
      structureCharacters[index] = " ";
      if (
        index + 1 < structureCharacters.length &&
        structureCharacters[index + 1] !== "\n" &&
        structureCharacters[index + 1] !== "\r"
      ) {
        structureCharacters[++index] = " ";
      }
      continue;
    }
    if (character === quote) {
      structureCharacters[index] = " ";
      quote = undefined;
      continue;
    }
    if (character === "\n" || character === "\r") {
      if (quote !== "`") quote = undefined;
    } else {
      structureCharacters[index] = " ";
    }
  }
  const structureContent = structureCharacters.join("");
  const lines = content.split("\n");
  const structureLines = structureContent.split("\n");

  const lineStarts = [0];
  for (let index = 0; index < content.length; index++) {
    if (content[index] === "\n") lineStarts.push(index + 1);
  }
  const lineAt = (offset: number): number => {
    let low = 0;
    let high = lineStarts.length;
    while (low + 1 < high) {
      const middle = Math.floor((low + high) / 2);
      if (lineStarts[middle]! <= offset) low = middle;
      else high = middle;
    }
    return low;
  };

  // Precompute delimiter ownership once. Re-scanning from every nested control
  // header makes deeply nested/minified files quadratic.
  const parenClosings = new Map<number, number>();
  const braceClosings = new Map<number, number>();
  const parenStack: number[] = [];
  const braceStack: number[] = [];
  for (let index = 0; index < structureContent.length; index++) {
    const character = structureContent[index];
    if (character === "(") parenStack.push(index);
    else if (character === ")") {
      const open = parenStack.pop();
      if (open !== undefined) parenClosings.set(open, index);
    } else if (character === "{") braceStack.push(index);
    else if (character === "}") {
      const open = braceStack.pop();
      if (open !== undefined) braceClosings.set(open, index);
    }
  }

  const localePattern =
    /(?:\blocale\b|\btimezone\b|\btimeZone\b|Intl\.DateTimeFormat|\bgetTimezone\b|\bcountry(?:Code|_code|_name)?\b)/i;
  const localeIdentifierPattern =
    /\b(?:locale|timezone|timeZone|tz|getTimezone|country|countryCode|country_code|country_name|region)\b/g;
  const assignmentPattern =
    /(?<![.\w$])([A-Za-z_$][\w$]*)\s*=(?!=|>)/;

  interface LocaleBinding {
    availableOffset: number;
    sourceLine?: number;
    evidenceOffset?: number;
  }
  const localeBindings = new Map<string, LocaleBinding[]>();
  const noteLocaleBinding = (
    name: string,
    availableOffset: number,
    sourceLine: number | undefined,
    evidenceOffset: number | undefined,
  ): void => {
    const bindings = localeBindings.get(name) ?? [];
    if (bindings.at(-1)?.availableOffset === availableOffset) {
      bindings[bindings.length - 1] = { availableOffset, sourceLine, evidenceOffset };
    } else {
      bindings.push({ availableOffset, sourceLine, evidenceOffset });
    }
    localeBindings.set(name, bindings);
  };
  const derivedIdentifiers = new Map<
    string,
    { sourceLine: number; evidenceOffset: number }
  >();
  for (let line = 0; line < structureLines.length; line++) {
    const lineSource = structureLines[line] ?? "";
    let segmentStart = 0;
    while (segmentStart <= lineSource.length) {
      const semicolon = lineSource.indexOf(";", segmentStart);
      const segmentEnd = semicolon === -1 ? lineSource.length : semicolon + 1;
      const source = lineSource.slice(segmentStart, segmentEnd);
      const availableOffset = lineStarts[line]! + segmentEnd;
      const assignment = assignmentPattern.exec(source);
      const assignmentName = assignment?.[1];
      const identifiers = new Set<string>();
      localeIdentifierPattern.lastIndex = 0;
      let identifier: RegExpExecArray | null;
      while ((identifier = localeIdentifierPattern.exec(source)) !== null) {
        identifiers.add(identifier[0]);
      }

      const localeEvidence = localePattern.exec(source);
      if (localeEvidence) {
        if (assignmentName) identifiers.add(assignmentName);
        const evidenceOffset =
          lineStarts[line]! + segmentStart + localeEvidence.index + localeEvidence[0].length;
        for (const name of identifiers) {
          derivedIdentifiers.set(name, { sourceLine: line, evidenceOffset });
          noteLocaleBinding(name, availableOffset, line, evidenceOffset);
        }
      } else if (assignmentName) {
        const rhs = source.slice((assignment?.index ?? 0) + assignment![0].length);
        const sourceTokens = new Set(
          rhs.match(/[A-Za-z_$][\w$]*/g) ?? [],
        );
        let derivedSource:
          | { sourceLine: number; evidenceOffset: number }
          | undefined;
        for (const token of sourceTokens) {
          const candidate = derivedIdentifiers.get(token);
          if (
            candidate &&
            line - candidate.sourceLine <= PROXIMITY &&
            availableOffset - candidate.evidenceOffset <= PROXIMITY_CHARS &&
            (!derivedSource || candidate.evidenceOffset > derivedSource.evidenceOffset)
          ) {
            derivedSource = candidate;
          }
        }
        if (!derivedSource) {
          derivedIdentifiers.delete(assignmentName);
          noteLocaleBinding(assignmentName, availableOffset, undefined, undefined);
        } else {
          const nextSource = {
            sourceLine: derivedSource.sourceLine,
            evidenceOffset: availableOffset,
          };
          derivedIdentifiers.set(assignmentName, nextSource);
          noteLocaleBinding(
            assignmentName,
            availableOffset,
            nextSource.sourceLine,
            nextSource.evidenceOffset,
          );
        }
      }

      if (semicolon === -1) break;
      segmentStart = segmentEnd;
    }
  }

  interface GeoGate {
    sourceLine: number;
    sourceOffset: number;
    bodyStart: number;
    bodyEnd: number;
  }
  const geoGates: GeoGate[] = [];
  const localeBindingAt = (
    name: string,
    gateOffset: number,
  ): LocaleBinding | undefined => {
    const bindings = localeBindings.get(name);
    if (!bindings || bindings.length === 0) return undefined;
    let low = 0;
    let high = bindings.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (bindings[middle]!.availableOffset <= gateOffset) low = middle + 1;
      else high = middle;
    }
    return low === 0 ? undefined : bindings[low - 1];
  };
  const controlPattern = /\b(if|switch|while)\s*\(/g;
  let control: RegExpExecArray | null;
  while ((control = controlPattern.exec(structureContent)) !== null) {
    const open = control.index + control[0].lastIndexOf("(");
    const close = parenClosings.get(open);
    if (close === undefined) break;
    controlPattern.lastIndex = close + 1;

    const gateLine = lineAt(control.index);
    const conditionStructure = structureContent.slice(open + 1, close);
    const discriminatesByValue =
      control[1] === "switch" ||
      /(?:===?|!==?|\.\s*(?:includes|has|test|match|startsWith|endsWith)\s*\(|\bin\b)/.test(
        conditionStructure,
      );
    if (!discriminatesByValue) continue;

    const conditionIdentifiers = new Set(
      conditionStructure.match(/[A-Za-z_$][\w$]*/g) ?? [],
    );
    let localeSourceLine: number | undefined;
    let localeSourceOffset: number | undefined;
    for (const name of conditionIdentifiers) {
      const binding = localeBindingAt(name, control.index);
      if (
        binding?.sourceLine !== undefined &&
        binding.evidenceOffset !== undefined &&
        gateLine - binding.sourceLine <= PROXIMITY &&
        control.index - binding.evidenceOffset <= PROXIMITY_CHARS &&
        (localeSourceOffset === undefined || binding.evidenceOffset > localeSourceOffset)
      ) {
        localeSourceLine = binding.sourceLine;
        localeSourceOffset = binding.evidenceOffset;
      }
    }
    const directLocaleEvidence = localePattern.exec(conditionStructure);
    if (localeSourceLine === undefined && directLocaleEvidence) {
      localeSourceLine = gateLine;
      localeSourceOffset =
        open + 1 + directLocaleEvidence.index + directLocaleEvidence[0].length;
    }
    if (localeSourceLine === undefined || localeSourceOffset === undefined) continue;

    let bodyStart = close + 1;
    while (bodyStart < structureContent.length && /\s/.test(structureContent[bodyStart]!)) {
      bodyStart++;
    }
    let bodyEnd: number;
    if (structureContent[bodyStart] === "{") {
      const closeBrace = braceClosings.get(bodyStart);
      if (closeBrace === undefined) continue;
      bodyStart++;
      bodyEnd = closeBrace;
    } else {
      const semicolon = structureContent.indexOf(";", bodyStart);
      const newline = structureContent.indexOf("\n", bodyStart);
      const candidates = [semicolon === -1 ? undefined : semicolon + 1, newline]
        .filter((value): value is number => value !== undefined && value !== -1);
      bodyEnd = candidates.length > 0
        ? Math.min(...candidates)
        : structureContent.length;
    }
    geoGates.push({
      sourceLine: localeSourceLine,
      sourceOffset: localeSourceOffset,
      bodyStart,
      bodyEnd,
    });
  }

  const destructivePattern =
    /(?:\bfs\s*\.\s*(?:rmSync|rm|unlinkSync|unlink|rmdirSync|rmdir|truncateSync|truncate|ftruncateSync|ftruncate)\s*\(|\brimraf\s*\(|\bprocess\s*\.\s*exit\s*\(|\bexecSync\s*\(\s*["'`](?:rm|del|format|dd\s))/gi;
  interface ActiveGeoGate {
    gate: GeoGate;
    bestSourceGate: GeoGate;
  }
  const activeGates: ActiveGeoGate[] = [];
  let nextGateIndex = 0;
  let destructive: RegExpExecArray | null;
  while ((destructive = destructivePattern.exec(searchableContent)) !== null) {
    // The lexical structure view blanks string contents. A signal beginning on
    // a blanked character is documentation/data, not an executable call.
    if (!/[A-Za-z_$]/.test(structureContent[destructive.index] ?? "")) continue;
    const destructiveStart = destructive.index;
    const destructiveLine = lineAt(destructiveStart);

    while (
      nextGateIndex < geoGates.length &&
      geoGates[nextGateIndex]!.bodyStart <= destructiveStart
    ) {
      const gate = geoGates[nextGateIndex++]!;
      while (
        activeGates.length > 0 &&
        activeGates.at(-1)!.gate.bodyEnd <= gate.bodyStart
      ) {
        activeGates.pop();
      }
      const previousBest = activeGates.at(-1)?.bestSourceGate;
      activeGates.push({
        gate,
        bestSourceGate:
          !previousBest || gate.sourceOffset >= previousBest.sourceOffset
            ? gate
            : previousBest,
      });
    }
    while (
      activeGates.length > 0 &&
      activeGates.at(-1)!.gate.bodyEnd <= destructiveStart
    ) {
      activeGates.pop();
    }
    const gate = activeGates.at(-1)?.bestSourceGate;
    if (
      !gate ||
      destructiveLine - gate.sourceLine > PROXIMITY ||
      destructiveStart - gate.sourceOffset > PROXIMITY_CHARS
    ) continue;

    findings.push({
      rule: "PROTESTWARE_PROXIMITY",
      description: `Locale/timezone gate (line ${gate.sourceLine + 1}) controls destructive code (line ${destructiveLine + 1}). This conditional pattern is common in protestware.`,
      severity: "high",
      file: relativePath,
      line: gate.sourceLine + 1,
      match: truncateMatch(
        `locale: "${(lines[gate.sourceLine] ?? "").trim()}" ... destruct: "${(lines[destructiveLine] ?? "").trim()}"`,
      ),
      recommendation:
        "Review the surrounding code. Protestware uses locale/geo checks to selectively destroy data or crash for targeted users.",
    });
    return;
  }
}

/**
 * Check package.json dependencies for known-bad versions (v4.1).
 */
function checkKnownBadVersions(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return;
  }

  const allDeps = {
    ...(pkg.dependencies as Record<string, string> | undefined),
    ...(pkg.devDependencies as Record<string, string> | undefined),
  };

  for (const [name, versionRange] of Object.entries(allDeps)) {
    if (!versionRange) continue;
    // Extract exact version from range (e.g., "^1.14.1" → "1.14.1")
    const version = versionRange.replace(/^[\^~>=<]*/, "");
    const finding = checkBadVersion(name, version, "npm");
    if (finding) {
      findings.push({ ...finding, file: relativePath });
    }
  }
}

/**
 * Check package-lock.json for known-bad resolved versions (v4.1).
 */
/**
 * Match every RESOLVED lockfile version against both curated sources (T-016).
 *
 * KNOWN_BAD_NPM_VERSIONS was already checked here, so the scan path has always
 * done exact name@version matching. It simply never consulted the threat feed,
 * where the great majority of package IOCs are version-pinned - so those entries
 * were reachable through `guard` and not through `scan`, the more visible surface.
 *
 * The lockfile is the only correct source. A package.json dependency value is a
 * RANGE, not a version, and the callers that pass `undefined` to matchBareNpmIOC
 * do so because they genuinely have no version in hand; they are not defects to
 * be "fixed" by forcing version-awareness where the data does not exist.
 *
 * False-positive surface, measured before this shipped rather than asserted:
 * every pinned npm IOC in the feed matched against 10,615 resolved dependencies
 * across 43 repositories produced ZERO hits. It is exact equality, so the only
 * way it fires wrongly is a wrong pin in the feed, which is a data-quality
 * question already governed by the bare-name audit discipline.
 */
function checkLockfileBadVersions(
  content: string,
  relativePath: string,
  findings: Finding[],
  feed: FeedIOC[],
): void {
  let lock: Record<string, unknown>;
  try {
    lock = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return;
  }

  // lockfile v2+ uses "packages" key
  const packages = lock.packages as Record<string, { version?: string }> | undefined;
  if (packages) {
    for (const [pkgPath, entry] of Object.entries(packages)) {
      if (!pkgPath || !entry?.version) continue;
      // Extract package name from path (e.g., "node_modules/axios" → "axios")
      const name = pkgPath.replace(/^node_modules\//, "").replace(/^.*node_modules\//, "");
      if (!name) continue;
      const finding = checkBadVersion(name, entry.version, "npm");
      if (finding) {
        findings.push({ ...finding, file: relativePath });
        continue; // one finding per dependency; the blocklist is the more specific source
      }
      pushPinnedFeedFinding(name, entry.version, relativePath, findings, feed);
    }
  }

  // lockfile v1 uses "dependencies" key
  const deps = lock.dependencies as Record<string, { version?: string }> | undefined;
  if (deps && !packages) {
    for (const [name, entry] of Object.entries(deps)) {
      if (!entry?.version) continue;
      const finding = checkBadVersion(name, entry.version, "npm");
      if (finding) {
        findings.push({ ...finding, file: relativePath });
        continue;
      }
      pushPinnedFeedFinding(name, entry.version, relativePath, findings, feed);
    }
  }
}

/**
 * One feed finding for a resolved lockfile dependency, or nothing.
 *
 * Bare-name feed entries are deliberately NOT reported from here. They already
 * fire through checkMaliciousDependencyNames on the package.json path, and a
 * lockfile lists every transitive dependency, so emitting them again would
 * double-report each one and multiply it across the tree.
 */
function pushPinnedFeedFinding(
  name: string,
  version: string,
  relativePath: string,
  findings: Finding[],
  feed: FeedIOC[],
): void {
  const ioc = matchBareNpmIOC(name, version, feed);
  if (!ioc) return;
  // A bare-name entry matches ANY version, so it would have hit regardless of
  // the lockfile. Only an entry pinned to this exact version is new information.
  if (ioc.value.lastIndexOf("@") <= 0) return;

  const attrib = ioc.campaign ? ` (campaign: ${ioc.campaign})` : "";
  findings.push({
    rule: "LOCKFILE_MALICIOUS_VERSION",
    description: `Lockfile resolves "${name}" to ${version}, a version listed in the threat feed as malicious${attrib}.`,
    severity: "critical",
    confidence: ioc.confidence ?? 0.95,
    category: "supply-chain",
    file: relativePath,
    match: `${name}@${version}`,
    recommendation: `Remove ${name}@${version}. Update the lockfile to a clean version and rotate any credentials the install may have had access to.`,
  });
}

/**
 * Check build tool config files for suspicious plugin patterns (v4.0).
 */
function checkBuildToolPatterns(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  for (const pattern of BUILD_TOOL_PATTERNS) {
    const hits = matchPatternInFile(
      pattern,
      content,
      relativePath,
      findings,
      "gi",
    );
    for (const hit of hits ?? []) {
      findings.push({
        rule: pattern.rule,
        description: pattern.description,
        severity: pattern.severity,
        file: relativePath,
        line: hit.line,
        match: truncateMatch(hit.text),
        recommendation: getRecommendation(pattern.rule),
      });
    }
  }
}

/**
 * Check root package.json for monorepo/workspace risks (v4.0).
 */
/**
 * Flag dependency names in a package.json that are EXACT known-malicious
 * packages in the threat feed (matchBareNpmIOC: bare-name = any version).
 * Runs on a directory scan so a victim scanning their own repo learns they
 * depend on a flagged package (previously only the `npm <pkg>` path checked).
 *
 * Matches the feed's exact IOC names, NOT the broad MALICIOUS_PACKAGE_PATTERNS
 * heuristics (those flag "any unknown-scope package" and would false-positive
 * on legitimate deps like @vitest/coverage-v8 - caught during v5.10.1 review).
 */
function checkMaliciousDependencyNames(
  content: string,
  file: string,
  findings: Finding[],
  feed: FeedIOC[],
): void {
  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(content);
  } catch {
    return;
  }
  // Collect the package that is actually INSTALLED for each entry, not the key.
  // An npm alias ("utils": "npm:chalk-tempalte@1.0.0") installs the target while
  // the key is arbitrary attacker-chosen text, so keying off Object.keys() alone
  // let a known-malicious package scan completely clean.
  const candidates = new Map<string, { name: string; version?: string; alias?: string }>();
  for (const group of [
    pkg.dependencies,
    pkg.devDependencies,
    pkg.optionalDependencies,
    pkg.peerDependencies,
  ]) {
    for (const [key, spec] of Object.entries(group ?? {})) {
      const alias = resolveNpmAlias(spec);
      const candidate = alias
        ? { name: alias.name, version: alias.version, alias: key }
        : { name: key, version: undefined as string | undefined };
      candidates.set(`${candidate.name}@${candidate.version ?? ""}`, candidate);
    }
  }

  for (const { name, version, alias } of candidates.values()) {
    const ioc = matchBareNpmIOC(name, version, feed);
    if (ioc) {
      const attrib = ioc.campaign ? ` (campaign: ${ioc.campaign})` : "";
      const via = alias ? ` (installed via the npm alias "${alias}")` : "";
      findings.push({
        rule: "MALICIOUS_DEPENDENCY",
        description: `Dependency "${name}" is a known-malicious package in the threat feed${attrib}${via}`,
        severity: "critical",
        confidence: ioc.confidence ?? 0.95,
        category: "supply-chain",
        file,
        match: alias ?? name,
        recommendation: `Remove "${alias ?? name}" immediately and rotate any secrets exposed while it was installed.`,
      });
    }
  }
}

function checkMonorepoPatterns(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return;
  }

  // Only check if it has workspaces
  if (!pkg.workspaces) return;

  for (const pattern of MONOREPO_PATTERNS) {
    const hits = matchPatternInFile(
      pattern,
      content,
      relativePath,
      findings,
      "gi",
    );
    for (const hit of hits ?? []) {
      findings.push({
        rule: pattern.rule,
        description: pattern.description,
        severity: pattern.severity,
        file: relativePath,
        line: hit.line,
        match: truncateMatch(hit.text),
        recommendation: getRecommendation(pattern.rule),
      });
    }
  }
}

/**
 * Filter findings based on scan options.
 */
function filterFindings(findings: Finding[], options: ScanOptions): Finding[] {
  const severityOrder: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };

  let filtered = findings;

  if (options.minSeverity) {
    const minLevel = severityOrder[options.minSeverity] ?? 0;
    filtered = filtered.filter(
      (f) => (severityOrder[f.severity] ?? 0) >= minLevel,
    );
  }

  if (options.excludeRules?.length) {
    const excluded = new Set(options.excludeRules);
    filtered = filtered.filter((f) => !excluded.has(f.rule));
  }

  return filtered;
}

/**
 * Calculate summary statistics.
 */
function calculateSummary(
  totalFiles: number,
  filesScanned: number,
  findings: Finding[],
): ScanSummary {
  return {
    totalFiles,
    filesScanned,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };
}

/**
 * Calculate overall risk score (0-100).
 * Each unique rule contributes at most once (its highest severity instance),
 * preventing repeated instances of the same moderate rule from dominating the score.
 */
// Meta/governance findings that fire because other findings exist - excluded from
// score to prevent circular inflation (they don't represent independent risk signals).
export const SCORE_EXCLUDED_RULES: ReadonlySet<string> = new Set([
  "CRITICAL_FINDING_NO_OWNER",
  "RISK_STAGNATION_HIGH",
]);

function calculateScore(findings: Finding[]): number {
  // Deduplicate by rule - take the highest-severity instance per rule.
  // Skip meta-governance findings that would circularly inflate the score.
  const maxByRule = new Map<string, Severity>();
  for (const finding of findings) {
    if (SCORE_EXCLUDED_RULES.has(finding.rule)) continue;
    const current = maxByRule.get(finding.rule);
    if (!current || SEVERITY_SCORES[finding.severity] > SEVERITY_SCORES[current]) {
      maxByRule.set(finding.rule, finding.severity);
    }
  }
  let score = 0;
  for (const severity of maxByRule.values()) {
    score += SEVERITY_SCORES[severity];
  }
  return Math.min(100, score);
}

/**
 * Derive risk level from score.
 */
function getRiskLevel(score: number): ScanReport["riskLevel"] {
  if (score === 0) return "clean";
  if (score <= 10) return "low";
  if (score <= 30) return "medium";
  if (score <= 60) return "high";
  return "critical";
}

/**
 * Generate human-readable recommendations.
 */
function generateRecommendations(
  findings: Finding[],
  partialScan = false,
): string[] {
  const recommendations: string[] = [];
  const rules = new Set(findings.map((f) => f.rule));

  if (rules.has("GLASSWORM_MARKER")) {
    recommendations.push(
      "CRITICAL: GlassWorm malware marker detected. Quarantine this code immediately and audit all downstream dependencies.",
    );
  }
  if (rules.has("EVAL_ATOB") || rules.has("EVAL_BUFFER") || rules.has("FUNCTION_ATOB")) {
    recommendations.push(
      "CRITICAL: Encoded code execution detected. This is a strong indicator of malicious obfuscation. Do not run this code.",
    );
  }
  if (rules.has("INVISIBLE_UNICODE")) {
    recommendations.push(
      "Review files with invisible Unicode characters. These can hide malicious code in otherwise normal-looking files.",
    );
  }
  if (rules.has("FILE_TOO_LARGE_SKIPPED")) {
    recommendations.push(
      "One or more files exceeded the 5 MB scan limit and were NOT content-scanned. Inspect them manually - oversized files can be used to smuggle payloads past size-limited scanners.",
    );
  }
  if (rules.has("SOLANA_MAINNET") || rules.has("HELIUS_RPC")) {
    recommendations.push(
      "Solana blockchain references detected. If this project has no legitimate blockchain functionality, this may indicate C2 communication via the Solana blockchain.",
    );
  }
  if (
    rules.has("SCRIPT_CURL_EXEC") ||
    rules.has("SCRIPT_WGET_EXEC") ||
    rules.has("SCRIPT_NODE_INLINE")
  ) {
    recommendations.push(
      "Dangerous install scripts detected. These scripts download and execute remote code, which is a common supply-chain attack vector.",
    );
  }
  if (rules.has("GIT_DATE_ANOMALY")) {
    recommendations.push(
      "Git commit date anomalies detected. Verify the repository history has not been manipulated.",
    );
  }
  if (rules.has("ENV_EXFILTRATION") || rules.has("DNS_EXFILTRATION")) {
    recommendations.push(
      "Potential data exfiltration patterns detected. Environment variables may be sent to external servers.",
    );
  }

  // Campaign-specific recommendations
  if (rules.has("XZ_GET_CPUID") || rules.has("XZ_LZMA_CRC64") || rules.has("XZ_BUILD_INJECT") || rules.has("XZ_OBFUSCATED_TEST")) {
    recommendations.push(
      "CRITICAL: XZ Utils backdoor indicators detected (CVE-2024-3094). Verify xz/liblzma versions and inspect build scripts for unauthorized modifications.",
    );
  }
  if (rules.has("CODECOV_CURL_BASH") || rules.has("CODECOV_EXFIL")) {
    recommendations.push(
      "Codecov supply-chain attack indicators detected. Avoid piping remote scripts to shell. Use pinned checksums for CI uploader binaries.",
    );
  }
  if (rules.has("SUNBURST_DGA") || rules.has("SUNBURST_ORION_CLASS") || rules.has("SUNBURST_DELAYED_EXEC")) {
    recommendations.push(
      "CRITICAL: SolarWinds SUNBURST indicators detected. Quarantine immediately. Check for DGA domains and unusual delayed execution patterns.",
    );
  }
  if (rules.has("UAPARSER_MINER") || rules.has("UAPARSER_PREINSTALL_DL")) {
    recommendations.push(
      "CRITICAL: ua-parser-js hijack indicators detected. Check for crypto miner binaries and suspicious preinstall script downloads.",
    );
  }
  if (rules.has("COA_RC_SDD_DLL") || rules.has("COA_RC_POSTINSTALL")) {
    recommendations.push(
      "CRITICAL: coa/rc npm hijack indicators detected. Check for sdd.dll references and encoded postinstall payloads. Pin dependency versions.",
    );
  }
  if (rules.has("DPRK_VALIDATE_SDK")) {
    recommendations.push(
      "CRITICAL: DPRK @validate-sdk/v2 indicator detected. April 2026 campaign delivered AI-inserted malicious npm dependencies. Remove the package and audit all AI-suggested dependencies.",
    );
  }
  if (rules.has("LOFYSTEALER_MARKER") || rules.has("LOFYGANG_MINECRAFT_LURE")) {
    recommendations.push(
      "CRITICAL: LofyGang / LofyStealer (GrabBot) indicators detected. April 2026 campaign targets Minecraft players via fake hack tools. Do not run any associated binaries.",
    );
  }

  // Lockfile recommendations (T-006)
  if (
    rules.has("LOCKFILE_MISSING_INTEGRITY") ||
    rules.has("LOCKFILE_INVALID_INTEGRITY") ||
    rules.has("LOCKFILE_SHORT_INTEGRITY")
  ) {
    recommendations.push(
      "Lockfile integrity issues detected. Run `npm install` with a modern npm version to regenerate integrity hashes.",
    );
  }
  if (rules.has("LOCKFILE_HTTP_RESOLVED")) {
    recommendations.push(
      "Packages resolving over plain HTTP detected. Update resolved URLs to HTTPS to prevent MITM attacks.",
    );
  }
  if (rules.has("LOCKFILE_VERSION_DOWNGRADE")) {
    recommendations.push(
      "Lockfile uses an outdated version. Upgrade with `npm install` using npm 7+ for stronger security guarantees.",
    );
  }

  // Binary detection recommendations (T-007)
  if (rules.has("BINARY_UNEXPECTED")) {
    recommendations.push(
      "Unexpected binary files detected. Inspect them carefully. Legitimate npm packages rarely ship precompiled binaries.",
    );
  }
  if (rules.has("BINARY_DIRECT_DOWNLOAD")) {
    recommendations.push(
      "Install scripts download binary files directly. This is a supply-chain risk. Verify the download source.",
    );
  }

  // Beacon/miner recommendations (T-008)
  if (
    rules.has("MINER_STRATUM_PROTOCOL") ||
    rules.has("MINER_POOL_DOMAIN") ||
    rules.has("MINER_LIBRARY_REF")
  ) {
    recommendations.push(
      "CRITICAL: Cryptocurrency miner indicators detected. This package likely contains a hidden miner. Do NOT install.",
    );
  }
  if (rules.has("BEACON_INTERVAL_FETCH") || rules.has("BEACON_TIMEOUT_FETCH")) {
    recommendations.push(
      "Network beacon patterns detected. Periodic outbound requests may indicate C2 communication or data exfiltration.",
    );
  }
  if (
    rules.has("PROTESTWARE_LOCALE_DESTRUCT") ||
    rules.has("PROTESTWARE_GEOIP_DESTRUCT") ||
    rules.has("PROTESTWARE_PROXIMITY")
  ) {
    recommendations.push(
      "CRITICAL: Protestware patterns detected. This code targets users by geographic location with destructive operations.",
    );
  }

  // GitHub Actions workflow recommendations (#9)
  if (
    rules.has("GHA_CURL_PIPE_EXEC") ||
    rules.has("GHA_WGET_PIPE_EXEC") ||
    rules.has("GHA_CURL_DOWNLOAD_EXEC") ||
    rules.has("GHA_WGET_DOWNLOAD_EXEC")
  ) {
    recommendations.push(
      "CI workflow fetches and executes remote content. Pin scripts by checksum or use pinned GitHub Actions instead.",
    );
  }
  if (
    rules.has("GHA_SECRET_CURL") ||
    rules.has("GHA_SECRET_WGET") ||
    rules.has("GHA_SECRET_EXFIL_MULTILINE")
  ) {
    recommendations.push(
      "CRITICAL: Secrets may be exfiltrated via network commands in CI workflows. Audit all workflow steps that combine secrets with curl/wget.",
    );
  }
  if (rules.has("GHA_UNPINNED_ACTION")) {
    recommendations.push(
      "Unpinned GitHub Actions detected. Pin actions to commit SHAs to prevent supply-chain attacks via mutable branch references.",
    );
  }
  if (
    rules.has("GHA_BASE64_PAYLOAD") ||
    rules.has("GHA_BASE64_EXEC")
  ) {
    recommendations.push(
      "Base64 encoded payloads in CI workflows are suspicious. Decode and inspect the content before allowing execution.",
    );
  }

  // Docker recommendations (v4.0)
  if (rules.has("DOCKER_CURL_PIPE")) {
    recommendations.push(
      "CRITICAL: Dockerfile pipes remote content to shell. Download, verify checksum, then execute.",
    );
  }
  // All three base-image verdicts share one remediation, so all three must
  // reach it. DOCKER_TAG_NOT_DIGEST was the tier that could otherwise be the
  // only finding in a report and leave that report with no recommendation.
  if (
    rules.has("DOCKER_UNPINNED_BASE") ||
    rules.has("DOCKER_NO_TAG") ||
    rules.has("DOCKER_TAG_NOT_DIGEST")
  ) {
    recommendations.push(
      "Pin Docker base images by digest (FROM image@sha256:...) to ensure reproducible and tamper-proof builds.",
    );
  }
  if (rules.has("DOCKER_SECRETS_BUILD")) {
    recommendations.push(
      "Remove hardcoded secrets from Dockerfile. Use BuildKit secrets or runtime environment variables.",
    );
  }

  // Config file recommendations (v4.0)
  if (rules.has("CONFIG_HTTP_REGISTRY")) {
    recommendations.push(
      "CRITICAL: Package manager uses HTTP registry. Switch to HTTPS to prevent MITM attacks.",
    );
  }
  if (rules.has("CONFIG_AUTH_TOKEN_EXPOSED")) {
    recommendations.push(
      "CRITICAL: Auth tokens found in config files. Rotate tokens immediately and use environment variables.",
    );
  }

  // Git recommendations (v4.0)
  if (rules.has("GIT_HOOK_DOWNLOAD") || rules.has("GIT_HOOK_ENCODED")) {
    recommendations.push(
      "Suspicious git hooks detected. Remove hooks that download or decode content. Use pre-commit frameworks instead.",
    );
  }

  // Build tool recommendations (v4.0)
  if (rules.has("BUILD_ENV_EXFIL")) {
    recommendations.push(
      "CRITICAL: Build config may exfiltrate environment secrets. Audit build tool plugins and configurations.",
    );
  }

  // Campaign recommendations (v4.0)
  if (rules.has("SHAI_HULUD_WORM") || rules.has("SHAI_HULUD_CRED_STEAL")) {
    recommendations.push(
      "CRITICAL: Shai-Hulud worm indicators detected. This self-replicating malware steals npm tokens. Quarantine and rotate all npm credentials.",
    );
  }

  // IaC recommendations (v4.0)
  if (rules.has("IAC_HARDCODED_SECRET")) {
    recommendations.push(
      "CRITICAL: Hardcoded secrets in IaC files. Use secret managers (Vault, AWS Secrets Manager) or encrypted variables.",
    );
  }

  // Entropy recommendations (v4.0)
  if (rules.has("HIGH_ENTROPY_STRING")) {
    recommendations.push(
      "High-entropy strings detected. Decode and inspect these strings for hidden payloads or encoded malware.",
    );
  }

  // Cargo/Go recommendations (v4.0)
  if (rules.has("CARGO_BUILD_RS_EXEC") || rules.has("CARGO_PROC_MACRO_NETWORK")) {
    recommendations.push(
      "Suspicious Rust build.rs or proc-macro code detected. Build scripts and macros run with full privileges at compile time.",
    );
  }
  if (rules.has("GO_INIT_EXEC")) {
    recommendations.push(
      "Go init() functions with command execution detected. init() runs automatically on import.",
    );
  }

  // RubyGems/Composer/NuGet recommendations
  if (
    rules.has("RUBY_MALICIOUS_GEM") ||
    rules.has("COMPOSER_MALICIOUS_PACKAGE") ||
    rules.has("NUGET_MALICIOUS_PACKAGE")
  ) {
    recommendations.push(
      "CRITICAL: Dependencies match threat-intelligence package IOCs. Remove them immediately, rotate credentials exposed to installs, and audit affected systems.",
    );
  }
  if (
    rules.has("RUBY_GEM_HTTP_SOURCE") ||
    rules.has("COMPOSER_HTTP_REPOSITORY") ||
    rules.has("NUGET_HTTP_FEED")
  ) {
    recommendations.push(
      "Package sources served over plain http detected. Switch all registries/feeds to https to prevent in-transit tampering.",
    );
  }

  // Infostealer / dead-drop recommendations (v4.1)
  if (rules.has("DEAD_DROP_STEAM") || rules.has("DEAD_DROP_TELEGRAM") || rules.has("DEAD_DROP_PASTEBIN")) {
    recommendations.push(
      "CRITICAL: Dead-drop resolver patterns detected. Infostealers (Vidar, Lumma, RedLine) use Steam/Telegram/Pastebin to retrieve C2 addresses. Quarantine this code.",
    );
  }
  if (rules.has("VIDAR_BROWSER_THEFT") || rules.has("VIDAR_WALLET_THEFT")) {
    recommendations.push(
      "CRITICAL: Infostealer credential/wallet theft patterns detected. This code targets browser data and cryptocurrency wallets.",
    );
  }
  if (rules.has("GHOSTSOCKS_SOCKS5") || rules.has("PROXY_BACKCONNECT")) {
    recommendations.push(
      "CRITICAL: Proxy/backconnect malware detected. GhostSocks turns infected machines into residential proxy nodes for criminal infrastructure.",
    );
  }
  if (rules.has("DROPPER_TEMP_EXEC")) {
    recommendations.push(
      "CRITICAL: Dropper/loader behavior detected - writing and executing files in temporary directories.",
    );
  }

  // IOC blocklist recommendations (v4.1)
  if (
    rules.has("IOC_KNOWN_C2_DOMAIN") ||
    rules.has("IOC_KNOWN_C2_IP") ||
    rules.has("IOC_KNOWN_DEAD_DROP") ||
    rules.has("IOC_KNOWN_C2_WALLET")
  ) {
    recommendations.push(
      "CRITICAL: Known malicious infrastructure (C2/dead-drop) detected in code. This is a confirmed threat indicator.",
    );
  }
  if (rules.has("IOC_KNOWN_BAD_VERSION")) {
    recommendations.push(
      "CRITICAL: Known compromised package version detected. Remove immediately and upgrade to a clean version.",
    );
  }

  // Lure / fake repo recommendations (v4.1)
  if (rules.has("CAMPAIGN_CLAUDE_LURE") || rules.has("CAMPAIGN_AI_TOOL_LURE")) {
    recommendations.push(
      "CRITICAL: This matches the 2026 fake AI tool malware campaign distributing Vidar/GhostSocks. Do NOT execute any code or binaries.",
    );
  }
  if (rules.has("README_LURE_CRACK") || rules.has("RELEASE_NAME_LURE")) {
    recommendations.push(
      "This repository uses piracy/crack language - a strong indicator of malware distribution. Do not download or use.",
    );
  }

  // GitHub trust recommendations (v4.1)
  if (rules.has("REPO_KNOWN_MALICIOUS_ACCOUNT")) {
    recommendations.push(
      "CRITICAL: This repository belongs to a known malicious GitHub account. Do not use any code from this source.",
    );
  }
  if (rules.has("RELEASE_EXE_ARTIFACT")) {
    recommendations.push(
      "CRITICAL: Executable files in GitHub releases. This is the primary distribution vector for the 2026 fake AI tool campaign.",
    );
  }

  if (partialScan) {
    recommendations.unshift(
      "WARNING: Scan incomplete because one or more configured checks or files could not be evaluated. Resolve coverage gaps before treating this result as clean.",
    );
  }
  if (recommendations.length === 0 && findings.length > 0) {
    recommendations.push(
      "Review the listed findings and assess whether they represent legitimate functionality or potential threats.",
    );
  }
  if (findings.length === 0 && !partialScan) {
    recommendations.push("No malicious indicators detected. The scanned code appears clean.");
  }

  return recommendations;
}

/**
 * Get a recommendation string for a specific rule.
 */
function getRecommendation(rule: string): string {
  const map: Record<string, string> = {
    GLASSWORM_MARKER:
      "Quarantine this code immediately. This is a known GlassWorm campaign indicator.",
    INVISIBLE_UNICODE:
      "Inspect this file in a hex editor. Invisible characters may hide malicious code.",
    EVAL_ATOB:
      "Do not execute this code. Decode the base64 content to inspect what would be evaluated.",
    EVAL_BUFFER:
      "Do not execute this code. Inspect the Buffer contents to see the hidden payload.",
    FUNCTION_ATOB:
      "Do not execute this code. The Function constructor with encoded content is a strong malware indicator.",
    EVAL_HEX:
      "Do not execute this code. Decode the hex string to inspect the hidden payload.",
    EXEC_ENCODED:
      "Review what this exec call is decoding and running.",
    SOLANA_MAINNET:
      "If this project has no blockchain functionality, this reference may indicate C2 communication.",
    HELIUS_RPC:
      "Helius RPC references in non-blockchain projects are suspicious. Investigate.",
    HEX_ARRAY:
      "Large hex arrays may contain obfuscated payloads. Decode and inspect.",
    CHARCODE_OBFUSCATION:
      "String construction from character codes is a common obfuscation technique.",
    ENV_EXFILTRATION:
      "This pattern combines environment variable access with network requests, which is a data exfiltration indicator.",
    DNS_EXFILTRATION:
      "DNS-based exfiltration encodes data in DNS queries. This is a covert data theft technique.",
    // Campaign-specific rules
    XZ_GET_CPUID:
      "This matches the XZ Utils backdoor (CVE-2024-3094). The _get_cpuid function was used to hook into sshd. Verify liblzma provenance.",
    XZ_LZMA_CRC64:
      "lzma_crc64 was the hijacked symbol in CVE-2024-3094. Ensure your xz/liblzma is from a trusted source.",
    XZ_BUILD_INJECT:
      "Build system injection matching the XZ Utils attack pattern. Inspect configure.ac and m4 macros for unauthorized changes.",
    XZ_OBFUSCATED_TEST:
      "Obfuscated test file extraction pattern matching CVE-2024-3094. Check test fixtures for hidden payloads.",
    CODECOV_CURL_BASH:
      "Piping curl output to bash is inherently risky. Use checksummed binary downloads instead.",
    CODECOV_EXFIL:
      "Codecov uploader was compromised to exfiltrate CI secrets. Verify uploader integrity and rotate exposed credentials.",
    SUNBURST_DGA:
      "avsvmcloud.com is the known SUNBURST C2 domain. This is a critical indicator of compromise.",
    SUNBURST_ORION_CLASS:
      "OrionImprovementBusinessLayer is the SUNBURST backdoor namespace. Quarantine this code immediately.",
    SUNBURST_DELAYED_EXEC:
      "Long sleep/timeout delays are a SUNBURST evasion technique to bypass sandbox analysis. Investigate the purpose of this delay.",
    UAPARSER_MINER:
      "This matches the ua-parser-js crypto miner pattern. Check for jsextension binaries and unauthorized downloads.",
    UAPARSER_PREINSTALL_DL:
      "Preinstall scripts downloading executables match the ua-parser-js hijack pattern. Review and remove.",
    COA_RC_SDD_DLL:
      "sdd.dll is the payload from the coa/rc npm hijack. This is a critical indicator of compromise.",
    COA_RC_POSTINSTALL:
      "Encoded postinstall payloads match the coa/rc npm hijack pattern. Pin dependencies and audit install scripts.",
    BEACON_INTERVAL_FETCH:
      "Periodic network requests (setInterval + fetch) can be C2 beacons. Verify this is legitimate functionality.",
    BEACON_TIMEOUT_FETCH:
      "Delayed network requests may be beacons with jitter. Investigate the target URL.",
    MINER_STRATUM_PROTOCOL:
      "Stratum protocol is exclusively used for cryptocurrency mining. This is a strong malware indicator.",
    MINER_POOL_DOMAIN:
      "Known mining pool domain detected. Do not run this code.",
    MINER_CONFIG_KEYS:
      "Mining configuration parameters detected. This code may be configuring a cryptocurrency miner.",
    MINER_LIBRARY_REF:
      "Cryptocurrency miner library referenced. Do not run this code.",
    BEACON_WEBSOCKET_EXTERNAL:
      "WebSocket to external host detected. Verify this is expected for the package.",
    PROTESTWARE_LOCALE_DESTRUCT:
      "Protestware detected: locale/geo check combined with destructive operations. Do not run.",
    PROTESTWARE_GEOIP_DESTRUCT:
      "GeoIP-based protestware detected. Do not run this code.",
    PROTESTWARE_PROXIMITY:
      "Locale check near destructive code. Review carefully for protestware patterns.",
    BINARY_UNEXPECTED:
      "Unexpected binary file in package. Inspect with a hex editor or disassembler.",
    BINARY_DIRECT_DOWNLOAD:
      "Binary download in install script. Verify the download source is trusted.",
    // GitHub Actions rules (#9)
    GHA_CURL_PIPE_EXEC:
      "Do not pipe remote content directly to a shell in CI. Download, verify checksum, then execute.",
    GHA_WGET_PIPE_EXEC:
      "Do not pipe remote content directly to a shell in CI. Download, verify checksum, then execute.",
    GHA_SECRET_CURL:
      "Secrets sent to external URLs via curl may indicate credential exfiltration.",
    GHA_SECRET_WGET:
      "Secrets sent to external URLs via wget may indicate credential exfiltration.",
    GHA_UNPINNED_ACTION:
      "Pin GitHub Actions to commit SHAs instead of mutable branch references.",
    GHA_BASE64_PAYLOAD:
      "Base64 encoded payloads in CI workflows are suspicious. Decode and inspect.",
    GHA_BASE64_EXEC:
      "Base64 decoded content piped to shell is a common attack vector.",
    // v4.0 rules
    BUILD_PLUGIN_DOWNLOAD:
      "Build plugin downloads external code. Verify the source is trusted.",
    BUILD_PLUGIN_EXEC:
      "Build config executes system commands. Ensure this is expected build behavior.",
    BUILD_ENV_EXFIL:
      "Build config combines env vars with network. This can exfiltrate secrets during build.",
    BUILD_DYNAMIC_REQUIRE:
      "Dynamic require in build config can load unexpected modules.",
    WORKSPACE_ROOT_POSTINSTALL:
      "Root postinstall scripts in monorepos affect all workspaces. Audit carefully.",
    WORKSPACE_PRIVATE_PUBLISH:
      "Non-private workspace with publishConfig may unintentionally be published.",
    SHAI_HULUD_WORM:
      "CRITICAL: Self-publishing pattern matches the Shai-Hulud npm worm. Quarantine immediately.",
    SHAI_HULUD_CRED_STEAL:
      "npm credential access detected. This matches the Shai-Hulud worm's token theft pattern.",
    PROTESTWARE_IP_GEO_V2:
      "IP geolocation combined with destructive ops. Advanced protestware targeting.",
    TEMPLATE_LITERAL_EXEC:
      "eval with template literals can hide complex expressions. Inspect the template.",
    PROXY_HANDLER_TRAP:
      "Proxy handler traps can intercept all operations. Review for data interception.",
    IMPORT_EXPRESSION:
      "Dynamic import() with computed URL can load attacker-controlled modules.",
    WASM_SUSPICIOUS:
      "WebAssembly loaded from external source. Verify the WASM module is trusted.",
    STEGANOGRAPHY_DECODE:
      "Base64 decoding of image/font data suggests steganographic payload extraction.",
    SVG_SCRIPT_INJECTION:
      "SVG with embedded scripts can execute JavaScript. Sanitize SVG files.",
    RTL_OVERRIDE:
      "RTL override characters can disguise file names and code. Inspect in a hex editor.",
    IAC_INLINE_SCRIPT:
      "IaC provisioner pipes remote content to shell. Download, verify, then execute.",
    IAC_EXTERNAL_MODULE:
      "Terraform module from non-standard source. Use registry modules or pin by hash.",
    IAC_HARDCODED_SECRET:
      "Remove hardcoded secrets. Use Terraform variables with sensitive=true or a secret manager.",
    IAC_REMOTE_EXEC:
      "remote-exec provisioner runs commands on remote resources. Audit the commands.",
    HIGH_ENTROPY_FILE:
      "High-entropy file may contain obfuscated or compressed payloads.",
    HIGH_ENTROPY_STRING:
      "High-entropy string likely contains encoded payload. Decode and inspect.",
    // v4.1 rules
    DEAD_DROP_STEAM:
      "CRITICAL: Steam profile used as dead-drop resolver for C2. This is a Vidar/Lumma stealer indicator.",
    DEAD_DROP_TELEGRAM:
      "CRITICAL: Telegram channel used as dead-drop resolver. This is a known infostealer C2 technique.",
    DEAD_DROP_PASTEBIN:
      "Pastebin URL may be a dead-drop resolver for malware C2 configuration.",
    DEAD_DROP_DNS_TXT:
      "DNS TXT lookups can be used as covert C2 channels by malware.",
    VIDAR_BROWSER_THEFT:
      "Browser credential file access matches infostealer behavior. Quarantine this code.",
    VIDAR_WALLET_THEFT:
      "Crypto wallet file access detected. Infostealers target these paths for fund theft.",
    GHOSTSOCKS_SOCKS5:
      "SOCKS5 proxy protocol detected. GhostSocks malware creates residential proxy nodes.",
    PROXY_BACKCONNECT:
      "Backconnect/reverse proxy registration. Infected machines become proxy infrastructure.",
    DROPPER_TEMP_EXEC:
      "Temp directory write + execute pattern. This is classic dropper/loader behavior.",
    DROPPER_ANTIVM:
      "Anti-VM/anti-debug checks indicate sandbox evasion. Malware avoids analysis environments.",
    DROPPER_SLEEP_EVASION:
      "Long sleep before execution evades sandbox time limits. Common in infostealers.",
    README_LURE_LEAKED:
      "README uses 'leaked' language. Verify project legitimacy before using.",
    README_LURE_CRACK:
      "README promises cracked/unlocked software. This is almost certainly malware.",
    README_LURE_URGENCY:
      "Urgency language pressures quick downloads. Classic social engineering.",
    CAMPAIGN_CLAUDE_LURE:
      "CRITICAL: Claude Code lure matches April 2026 Vidar/GhostSocks campaign.",
    CAMPAIGN_AI_TOOL_LURE:
      "CRITICAL: Fake AI tool lure matches 2026 multi-brand malware campaign.",
    FAKE_AI_TOOL_LURE:
      "Suspicious executable naming pattern. Verify file origin and integrity.",
    IOC_KNOWN_C2_DOMAIN:
      "Known malicious C2 domain. Quarantine immediately.",
    IOC_KNOWN_C2_IP:
      "Known malicious C2 IP address. Quarantine immediately.",
    IOC_KNOWN_DEAD_DROP:
      "Known dead-drop resolver URL. This is used to retrieve malware C2 addresses.",
    IOC_KNOWN_C2_WALLET:
      "Known C2 blockchain address. Treat referencing code as malicious.",
    IOC_KNOWN_MALWARE_HASH:
      "This hash matches known malware. Do not execute associated files.",
    IOC_KNOWN_MALICIOUS_ACCOUNT:
      "Reference to known malicious GitHub account. Do not use code from this source.",
    IOC_KNOWN_BAD_VERSION:
      "This package version is known to contain malware. Remove and upgrade immediately.",
    REPO_KNOWN_MALICIOUS_ACCOUNT:
      "This GitHub account distributes malware. Do not use.",
    REPO_NEW_ACCOUNT:
      "New GitHub account. Verify maintainer identity.",
    REPO_RECENT_CREATION:
      "New repo with many stars. Likely star-farming.",
    REPO_STAR_FORK_RATIO:
      "Unusual star/fork ratio indicates bot activity.",
    REPO_FEW_CONTRIBUTORS:
      "Few contributors on popular repo. May be fake.",
    REPO_NO_ISSUES:
      "Issues disabled or empty on popular repo. Red flag.",
    REPO_SINGLE_COMMIT:
      "Single-commit repo with stars. Strong malware indicator.",
    RELEASE_EXE_ARTIFACT:
      "Do NOT download. Executables in GitHub releases are a primary malware vector.",
    RELEASE_7Z_ARCHIVE:
      "Compressed archives bypass AV detection. Inspect before extracting.",
    RELEASE_SIZE_ANOMALY:
      "Unusually large release artifact. Verify this is expected.",
    RELEASE_NAME_LURE:
      "Release name contains piracy/crack language. Almost always malware.",
  };

  return map[rule] ?? "Review this finding manually and assess the risk.";
}

// truncateMatch is imported from patterns.ts (shared with the multi-line engine).
