/**
 * Core file scanner
 *
 * Scans local directories and GitHub repos for supply-chain malware indicators.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";
import type { Finding, ScanOptions, ScanReport, ScanSummary } from "./types.js";
import { SEVERITY_SCORES } from "./types.js";
import {
  FILE_PATTERNS,
  CAMPAIGN_PATTERNS,
  SUSPICIOUS_FILES,
  SUSPICIOUS_SCRIPTS,
  SCANNABLE_EXTENSIONS,
  MAX_FILE_SIZE,
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
} from "./patterns.js";
import { checkLockfile } from "./lockfile-checker.js";
import { scanGitHubActionsWorkflows } from "./github-actions-scanner.js";
import { scanDockerFiles, isDockerFile, scanDockerFile } from "./dockerfile-scanner.js";
import { scanConfigFiles, isConfigFile, scanConfigFile } from "./config-scanner.js";
import { scanGitSecurity } from "./git-scanner.js";
import { analyzeEntropy } from "./entropy.js";
import { scanCargoFiles, isCargoFile } from "./cargo-scanner.js";
import { scanGoFiles } from "./go-scanner.js";
import { checkIOCBlocklist, checkBadVersion } from "./ioc-blocklist.js";
import { analyzeGitHubTrust, parseGitHubUrl, scanReadmeLures } from "./github-trust-scanner.js";
import {
  INFOSTEALER_PATTERNS,
  LURE_PATTERNS,
} from "./patterns.js";

const TOOL_VERSION = "4.1.0";

/**
 * Scan a local directory or GitHub repo for malware indicators.
 */
export async function scan(options: ScanOptions): Promise<ScanReport> {
  const startTime = Date.now();
  const target = options.target;
  let scanDir = target;
  let scanType: ScanReport["scanType"] = "directory";
  let tempDir: string | null = null;

  // If target is a GitHub URL, clone it
  if (target.startsWith("https://github.com/")) {
    scanType = "github";
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-"));
    try {
      execSync(`git clone --depth 1 "${target}" "${tempDir}/repo"`, {
        stdio: "pipe",
      });
    } catch {
      throw new Error(`Failed to clone repository: ${target}`);
    }
    scanDir = path.join(tempDir, "repo");
  }

  // Validate directory exists
  if (!fs.existsSync(scanDir)) {
    throw new Error(`Target directory does not exist: ${scanDir}`);
  }

  const stat = fs.statSync(scanDir);
  if (!stat.isDirectory()) {
    throw new Error(`Target is not a directory: ${scanDir}`);
  }

  // Collect files
  const allFiles = collectFiles(scanDir, options.maxDepth ?? 20);
  const findings: Finding[] = [];

  // Scan each file
  let filesScanned = 0;
  for (const filePath of allFiles) {
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath);
    const relativePath = path.relative(scanDir, filePath);

    // Check suspicious file names
    checkSuspiciousFileName(basename, relativePath, findings);

    // Check for unexpected binary/native addon files (T-007)
    if (BINARY_EXTENSIONS.has(ext)) {
      checkBinaryFile(relativePath, findings);
    }

    // Scan Docker/Config files inline (v4.0)
    if (isDockerFile(basename) || isConfigFile(basename)) {
      try {
        const content = fs.readFileSync(filePath, "utf-8");
        if (isDockerFile(basename)) {
          findings.push(...scanDockerFile(content, relativePath));
        }
        if (isConfigFile(basename)) {
          findings.push(...scanConfigFile(content, relativePath));
        }
      } catch { /* skip */ }
    }

    // Only scan content of known file types
    if (!SCANNABLE_EXTENSIONS.has(ext)) continue;

    // Skip large files
    const fileStat = fs.statSync(filePath);
    if (fileStat.size > MAX_FILE_SIZE) continue;

    filesScanned++;

    try {
      const content = fs.readFileSync(filePath, "utf-8");

      // Check file content patterns
      checkFilePatterns(content, relativePath, findings);

      // Check build tool configs for plugin risks (v4.0)
      if (BUILD_CONFIG_FILES.has(basename)) {
        checkBuildToolPatterns(content, relativePath, findings);
      }

      // Check workspace/monorepo patterns (v4.0)
      if (basename === "package.json" && relativePath === "package.json") {
        checkMonorepoPatterns(content, relativePath, findings);
      }

      // Check beacon and miner patterns (T-008)
      checkBeaconMinerPatterns(content, relativePath, findings);

      // Entropy analysis for obfuscated payloads (v4.0)
      const entropyFindings = analyzeEntropy(content, relativePath);
      findings.push(...entropyFindings);

      // IOC blocklist check (v4.1)
      const iocFindings = checkIOCBlocklist(content, relativePath);
      findings.push(...iocFindings);

      // README lure pattern scanning (v4.1)
      if (basename.toLowerCase().startsWith("readme")) {
        const lureFindings = scanReadmeLures(content, relativePath);
        findings.push(...lureFindings);
      }

      // Check package.json specifically
      if (basename === "package.json") {
        checkPackageJson(content, relativePath, findings);
        // Check for binary download patterns in install scripts (T-007)
        checkBinaryDownloadScripts(content, relativePath, findings);
        // Check for known-bad package versions (v4.1)
        checkKnownBadVersions(content, relativePath, findings);
      }

      // Check package-lock.json for known-bad versions (v4.1)
      if (basename === "package-lock.json") {
        checkLockfileBadVersions(content, relativePath, findings);
      }
    } catch {
      // Skip files that can't be read (binary, permissions, etc.)
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

  // GitHub trust signal analysis (v4.1)
  if (scanType === "github") {
    const parsed = parseGitHubUrl(target);
    if (parsed) {
      const trustFindings = analyzeGitHubTrust(parsed.owner, parsed.repo);
      findings.push(...trustFindings);
    }
  }

  // Check Dockerfile / container configs (v4.0)
  const dockerFindings = scanDockerFiles(scanDir);
  findings.push(...dockerFindings);

  // Check package manager config files (v4.0)
  const configFindings = scanConfigFiles(scanDir);
  findings.push(...configFindings);

  // Check git hooks and submodules (v4.0)
  if (fs.existsSync(path.join(scanDir, ".git"))) {
    const gitSecFindings = scanGitSecurity(scanDir);
    findings.push(...gitSecFindings);
  }

  // Check Cargo/Rust files (v4.0)
  if (fs.existsSync(path.join(scanDir, "Cargo.toml"))) {
    const cargoFindings = scanCargoFiles(scanDir);
    findings.push(...cargoFindings);
  }

  // Check Go module files (v4.0)
  if (fs.existsSync(path.join(scanDir, "go.mod"))) {
    const goFindings = scanGoFiles(scanDir);
    findings.push(...goFindings);
  }

  // Filter by severity and excluded rules
  const filteredFindings = filterFindings(findings, options);

  // Calculate summary and score
  const summary = calculateSummary(allFiles.length, filesScanned, filteredFindings);
  const score = calculateScore(filteredFindings);
  const riskLevel = getRiskLevel(score);
  const recommendations = generateRecommendations(filteredFindings);

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
  };
}

/**
 * Recursively collect all files in a directory.
 */
function collectFiles(dir: string, maxDepth: number, depth = 0): string[] {
  if (depth > maxDepth) return [];

  const files: string[] = [];
  let entries: fs.Dirent[];

  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return files;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    // Skip common non-relevant directories
    if (entry.isDirectory()) {
      if (
        entry.name === "node_modules" ||
        entry.name === ".git" ||
        entry.name === "dist" ||
        entry.name === "build" ||
        entry.name === ".next" ||
        entry.name === "__pycache__" ||
        entry.name === ".venv" ||
        entry.name === "venv"
      ) {
        continue;
      }
      files.push(...collectFiles(fullPath, maxDepth, depth + 1));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }

  return files;
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
    const regex = new RegExp(suspicious.pattern);
    if (regex.test(basename)) {
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
): void {
  const lines = content.split("\n");
  const allPatterns = [
    ...FILE_PATTERNS,
    ...CAMPAIGN_PATTERNS,
    ...CAMPAIGN_PATTERNS_V2,
    ...OBFUSCATION_PATTERNS_V2,
    ...IAC_PATTERNS,
    ...INFOSTEALER_PATTERNS,
    ...LURE_PATTERNS,
  ];

  for (const pattern of allPatterns) {
    const regex = new RegExp(pattern.pattern, "g");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = regex.exec(line);
      if (match) {
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: relativePath,
          line: i + 1,
          match: truncateMatch(match[0]),
          recommendation: getRecommendation(pattern.rule),
        });
        // Reset regex lastIndex for next line
        regex.lastIndex = 0;
      }
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

  const dangerousHooks = ["preinstall", "postinstall", "preuninstall", "postuninstall"];

  for (const hook of dangerousHooks) {
    const script = scripts[hook];
    if (!script) continue;

    // Check against suspicious script patterns
    for (const pattern of SUSPICIOUS_SCRIPTS) {
      const regex = new RegExp(pattern.pattern, "i");
      if (regex.test(script)) {
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
    const log = execSync(
      `git -C "${dir}" log --format="%H|%aI|%cI" -20 2>/dev/null`,
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
  const parts = relativePath.split(path.sep);
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
      const regex = new RegExp(pattern.pattern, "i");
      if (regex.test(script)) {
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
): void {
  const lines = content.split("\n");

  for (const pattern of BEACON_MINER_PATTERNS) {
    const regex = new RegExp(pattern.pattern, "gi");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const match = regex.exec(line);
      if (match) {
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: relativePath,
          line: i + 1,
          match: truncateMatch(match[0]),
          recommendation: getRecommendation(pattern.rule),
        });
        regex.lastIndex = 0;
      }
    }
  }

  // Multi-line protestware check: locale/timezone on one line, destructive on nearby lines
  checkMultiLineProtestware(content, relativePath, findings);
}

/**
 * Check for protestware patterns spanning multiple lines.
 * Looks for locale/timezone checks within 15 lines of destructive operations.
 */
function checkMultiLineProtestware(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  const lines = content.split("\n");
  const PROXIMITY = 15;

  const localePattern =
    /(?:locale|timezone|timeZone|Intl\.DateTimeFormat|getTimezone|country_code|country_name)/i;
  const destructivePattern =
    /(?:fs\.(?:rm|rmdir|unlink|writeFile)|process\.exit|child_process|execSync|rimraf|fs\.rmdirSync|fs\.unlinkSync|fs\.rmSync)/i;

  const localeLines: number[] = [];
  const destructiveLines: number[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (localePattern.test(line)) localeLines.push(i);
    if (destructivePattern.test(line)) destructiveLines.push(i);
  }

  // Check if any locale line is within PROXIMITY of a destructive line
  for (const localeLine of localeLines) {
    for (const destructiveLine of destructiveLines) {
      if (
        Math.abs(localeLine - destructiveLine) <= PROXIMITY &&
        localeLine !== destructiveLine
      ) {
        // Avoid duplicating if we already found a single-line match
        const alreadyFound = findings.some(
          (f) =>
            f.rule === "PROTESTWARE_LOCALE_DESTRUCT" &&
            f.file === relativePath,
        );
        if (!alreadyFound) {
          findings.push({
            rule: "PROTESTWARE_PROXIMITY",
            description: `Locale/timezone check (line ${localeLine + 1}) found near destructive code (line ${destructiveLine + 1}). This proximity pattern is common in protestware.`,
            severity: "high",
            file: relativePath,
            line: localeLine + 1,
            match: truncateMatch(
              `locale: "${(lines[localeLine] ?? "").trim()}" ... destruct: "${(lines[destructiveLine] ?? "").trim()}"`,
            ),
            recommendation:
              "Review the surrounding code. Protestware uses locale/geo checks to selectively destroy data or crash for targeted users.",
          });
        }
        return; // One finding per file is enough
      }
    }
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
function checkLockfileBadVersions(
  content: string,
  relativePath: string,
  findings: Finding[],
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
      }
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
      }
    }
  }
}

/**
 * Check build tool config files for suspicious plugin patterns (v4.0).
 */
function checkBuildToolPatterns(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  const lines = content.split("\n");

  for (const pattern of BUILD_TOOL_PATTERNS) {
    const regex = new RegExp(pattern.pattern, "gi");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const match = regex.exec(line);
      if (match) {
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: relativePath,
          line: i + 1,
          match: truncateMatch(match[0]),
          recommendation: getRecommendation(pattern.rule),
        });
        regex.lastIndex = 0;
      }
    }
  }
}

/**
 * Check root package.json for monorepo/workspace risks (v4.0).
 */
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

  const lines = content.split("\n");

  for (const pattern of MONOREPO_PATTERNS) {
    const regex = new RegExp(pattern.pattern, "gi");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const match = regex.exec(line);
      if (match) {
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: relativePath,
          line: i + 1,
          match: truncateMatch(match[0]),
          recommendation: getRecommendation(pattern.rule),
        });
        regex.lastIndex = 0;
      }
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
 */
function calculateScore(findings: Finding[]): number {
  let score = 0;
  for (const finding of findings) {
    score += SEVERITY_SCORES[finding.severity];
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
function generateRecommendations(findings: Finding[]): string[] {
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
  if (rules.has("DOCKER_UNPINNED_BASE") || rules.has("DOCKER_NO_TAG")) {
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
      "CRITICAL: Dropper/loader behavior detected — writing and executing files in temporary directories.",
    );
  }

  // IOC blocklist recommendations (v4.1)
  if (rules.has("IOC_KNOWN_C2_DOMAIN") || rules.has("IOC_KNOWN_C2_IP") || rules.has("IOC_KNOWN_DEAD_DROP")) {
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
      "This repository uses piracy/crack language — a strong indicator of malware distribution. Do not download or use.",
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

  if (recommendations.length === 0 && findings.length > 0) {
    recommendations.push(
      "Review the listed findings and assess whether they represent legitimate functionality or potential threats.",
    );
  }
  if (findings.length === 0) {
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

/**
 * Truncate a match string for display.
 */
function truncateMatch(match: string, maxLen = 120): string {
  if (match.length <= maxLen) return match;
  return match.substring(0, maxLen) + "...";
}
