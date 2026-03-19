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
} from "./patterns.js";

const TOOL_VERSION = "1.0.0";

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

      // Check package.json specifically
      if (basename === "package.json") {
        checkPackageJson(content, relativePath, findings);
      }
    } catch {
      // Skip files that can't be read (binary, permissions, etc.)
    }
  }

  // Check git commit dates if it's a git repo
  if (fs.existsSync(path.join(scanDir, ".git"))) {
    checkGitDateAnomalies(scanDir, findings);
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
  const allPatterns = [...FILE_PATTERNS, ...CAMPAIGN_PATTERNS];

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
