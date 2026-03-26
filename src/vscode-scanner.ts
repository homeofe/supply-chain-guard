/**
 * VS Code Extension Scanner
 *
 * Scans .vsix files (VS Code extensions) for supply-chain malware indicators.
 * Accepts a local .vsix file path or a VS Code Marketplace extension ID.
 * .vsix files are ZIP archives containing the extension code.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as https from "node:https";
import { execSync } from "node:child_process";
import type { Finding, ScanReport, ScanSummary, Severity } from "./types.js";
import { SEVERITY_SCORES } from "./types.js";
import { FILE_PATTERNS, SCANNABLE_EXTENSIONS, MAX_FILE_SIZE } from "./patterns.js";

const TOOL_VERSION = "1.0.0";

// VS Code Marketplace API endpoint
const MARKETPLACE_API = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery";

// Activation events that are suspicious (run without user action)
const SUSPICIOUS_ACTIVATION_EVENTS = [
  "*",                     // activates on everything
  "onStartupFinished",     // activates after VS Code starts
  "onUri",                 // activates on URI open (can be triggered externally)
];

// Suspicious node APIs frequently abused in malicious extensions
const EXTENSION_DANGER_PATTERNS: Array<{
  pattern: string;
  description: string;
  severity: Severity;
  rule: string;
}> = [
  {
    pattern: "\\beval\\s*\\(",
    description: "eval() call detected in extension code",
    severity: "high",
    rule: "VSCODE_EVAL",
  },
  {
    pattern: "\\bnew\\s+Function\\s*\\(",
    description: "Function constructor detected in extension code (dynamic code execution)",
    severity: "high",
    rule: "VSCODE_FUNCTION_CONSTRUCTOR",
  },
  {
    pattern: "\\bchild_process\\b",
    description: "child_process module usage detected in extension",
    severity: "medium",
    rule: "VSCODE_CHILD_PROCESS",
  },
  {
    pattern: "\\bexecSync\\b|\\bexec\\s*\\(|\\bspawnSync\\b|\\bspawn\\s*\\(",
    description: "Process execution detected in extension code",
    severity: "medium",
    rule: "VSCODE_EXEC",
  },
  {
    pattern: "\\brequire\\s*\\(\\s*['\"]https?['\"]\\s*\\)|\\bfetch\\s*\\(|\\baxios\\b|\\bnode-fetch\\b|\\bgot\\b",
    description: "Network request capability detected in extension",
    severity: "low",
    rule: "VSCODE_NETWORK",
  },
  {
    pattern: "\\bprocess\\.env\\b",
    description: "Environment variable access detected in extension",
    severity: "low",
    rule: "VSCODE_ENV_ACCESS",
  },
  {
    pattern: "\\bfs\\.writeFile|\\bfs\\.writeFileSync|\\bfs\\.appendFile",
    description: "File write operation detected in extension",
    severity: "low",
    rule: "VSCODE_FILE_WRITE",
  },
  {
    pattern: "\\bBuffer\\.from\\s*\\([^)]+,\\s*['\"](?:base64|hex)['\"]\\s*\\)",
    description: "Encoded buffer construction detected (potential payload decoding)",
    severity: "medium",
    rule: "VSCODE_ENCODED_BUFFER",
  },
  {
    pattern: "\\batob\\s*\\(|\\bbtoa\\s*\\(",
    description: "Base64 encoding/decoding detected in extension",
    severity: "medium",
    rule: "VSCODE_BASE64",
  },
];

// Patterns indicating obfuscated code
const OBFUSCATION_PATTERNS: Array<{
  pattern: string;
  description: string;
  severity: Severity;
  rule: string;
}> = [
  {
    pattern: "(?:_0x[0-9a-fA-F]{4,}\\s*[=\\[,]\\s*){3,}",
    description: "JavaScript obfuscator variable naming pattern detected",
    severity: "high",
    rule: "VSCODE_OBFUSCATED_VARS",
  },
  {
    pattern: "\\[\\s*(?:'[^']{1,4}'|\"[^\"]{1,4}\")\\s*(?:,\\s*(?:'[^']{1,4}'|\"[^\"]{1,4}\")\\s*){20,}\\]",
    description: "Large string array detected (common in obfuscated code)",
    severity: "medium",
    rule: "VSCODE_STRING_ARRAY",
  },
  {
    pattern: "(?:\\\\x[0-9a-fA-F]{2}){10,}",
    description: "Hex-encoded string sequence detected in extension",
    severity: "medium",
    rule: "VSCODE_HEX_STRINGS",
  },
  {
    pattern: "String\\.fromCharCode\\s*\\(\\s*(?:\\d+\\s*,\\s*){5,}",
    description: "String.fromCharCode with many arguments (obfuscation)",
    severity: "medium",
    rule: "VSCODE_CHARCODE",
  },
];

export interface VscodeScanOptions {
  /** .vsix file path or extension ID (publisher.name) */
  target: string;
  /** Output format */
  format: "text" | "json" | "markdown" | "sarif";
  /** Minimum severity to report */
  minSeverity?: Severity;
}

/**
 * Scan a VS Code extension (.vsix file or marketplace ID).
 */
export async function scanVscodeExtension(
  options: VscodeScanOptions,
): Promise<ScanReport> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  let vsixPath = options.target;
  let tempDownload: string | null = null;

  // If target looks like an extension ID (publisher.name), download from marketplace
  if (!vsixPath.endsWith(".vsix") && vsixPath.includes(".")) {
    console.log(`  Downloading extension ${vsixPath} from VS Code Marketplace...`);
    const downloadDir = fs.mkdtempSync(path.join("/tmp", "scg-vscode-dl-"));
    tempDownload = downloadDir;
    vsixPath = await downloadVsixFromMarketplace(vsixPath, downloadDir);
  }

  // Validate the .vsix file exists
  if (!fs.existsSync(vsixPath)) {
    throw new Error(`VSIX file not found: ${vsixPath}`);
  }

  // Extract and scan the vsix (it's a zip)
  const extractDir = fs.mkdtempSync(path.join("/tmp", "scg-vscode-"));

  try {
    // Extract using unzip (vsix is a zip file)
    execSync(`unzip -q -o "${vsixPath}" -d "${extractDir}"`, { stdio: "pipe" });

    // Collect all files
    const allFiles = collectFilesRecursive(extractDir);

    // Scan package.json for suspicious metadata
    scanExtensionManifest(extractDir, findings);

    // Scan extension source files
    let filesScanned = 0;
    for (const filePath of allFiles) {
      const ext = path.extname(filePath).toLowerCase();
      const basename = path.basename(filePath);
      const relativePath = path.relative(extractDir, filePath);

      // Scan JS/TS files and JSON config
      if (!SCANNABLE_EXTENSIONS.has(ext)) continue;

      const fileStat = fs.statSync(filePath);
      if (fileStat.size > MAX_FILE_SIZE) continue;

      filesScanned++;

      try {
        const content = fs.readFileSync(filePath, "utf-8");

        // Check against VS Code specific danger patterns
        checkVscodePatterns(content, relativePath, findings);

        // Check against obfuscation patterns
        checkObfuscationPatterns(content, relativePath, findings);

        // Check against general malware patterns
        checkGeneralPatterns(content, relativePath, findings);
      } catch {
        // Skip unreadable files
      }
    }

    // Filter by severity
    const filteredFindings = filterFindings(findings, options.minSeverity);

    // Calculate results
    const summary = calculateSummary(allFiles.length, filesScanned, filteredFindings);
    const score = calculateScore(filteredFindings);
    const riskLevel = getRiskLevel(score);
    const recommendations = generateVscodeRecommendations(filteredFindings, options.target);

    return {
      tool: `supply-chain-guard v${TOOL_VERSION}`,
      timestamp: new Date().toISOString(),
      target: options.target,
      scanType: "directory",
      durationMs: Date.now() - startTime,
      findings: filteredFindings,
      summary,
      score,
      riskLevel,
      recommendations,
    };
  } finally {
    // Cleanup
    fs.rmSync(extractDir, { recursive: true, force: true });
    if (tempDownload) {
      fs.rmSync(tempDownload, { recursive: true, force: true });
    }
  }
}

/**
 * Download a .vsix from the VS Code Marketplace.
 */
async function downloadVsixFromMarketplace(
  extensionId: string,
  destDir: string,
): Promise<string> {
  const [publisher, name] = extensionId.split(".");
  if (!publisher || !name) {
    throw new Error(
      `Invalid extension ID format: "${extensionId}". Expected format: publisher.extensionName`,
    );
  }

  // Use the direct download URL pattern
  const downloadUrl = `https://${publisher}.gallery.vsassets.io/_apis/public/gallery/publisher/${publisher}/extension/${name}/latest/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage`;

  const vsixPath = path.join(destDir, `${extensionId}.vsix`);
  await downloadFile(downloadUrl, vsixPath);

  // Verify it's a valid file (at least check size)
  const stat = fs.statSync(vsixPath);
  if (stat.size < 100) {
    throw new Error(
      `Downloaded file is too small (${stat.size} bytes). Extension "${extensionId}" may not exist on the marketplace.`,
    );
  }

  return vsixPath;
}

/**
 * Scan the extension manifest (package.json inside the vsix).
 */
function scanExtensionManifest(extractDir: string, findings: Finding[]): void {
  // The package.json is typically at extension/package.json inside a vsix
  const manifestPaths = [
    path.join(extractDir, "extension", "package.json"),
    path.join(extractDir, "package.json"),
  ];

  let manifestPath: string | null = null;
  let manifest: Record<string, unknown> | null = null;

  for (const mp of manifestPaths) {
    if (fs.existsSync(mp)) {
      try {
        manifest = JSON.parse(fs.readFileSync(mp, "utf-8")) as Record<string, unknown>;
        manifestPath = mp;
        break;
      } catch {
        // Invalid JSON
      }
    }
  }

  if (!manifest || !manifestPath) return;

  const relativePath = path.basename(path.dirname(manifestPath)) + "/package.json";

  // Check activation events
  const activationEvents = manifest.activationEvents as string[] | undefined;
  if (activationEvents && Array.isArray(activationEvents)) {
    for (const event of activationEvents) {
      if (SUSPICIOUS_ACTIVATION_EVENTS.includes(event)) {
        findings.push({
          rule: "VSCODE_SUSPICIOUS_ACTIVATION",
          description: `Suspicious activationEvent "${event}" detected. Extension activates without explicit user action.`,
          severity: event === "*" ? "high" : "medium",
          file: relativePath,
          match: `activationEvents: ["${event}"]`,
          recommendation:
            event === "*"
              ? "The wildcard activation event means this extension runs on EVERY VS Code event. This is unusual and potentially dangerous."
              : `The "${event}" activation event means this extension runs automatically. Verify this is necessary for the extension's functionality.`,
        });
      }
    }
  }

  // Check for suspicious scripts in package.json
  const scripts = manifest.scripts as Record<string, string> | undefined;
  if (scripts) {
    const dangerousHooks = ["postinstall", "preinstall", "install"];
    for (const hook of dangerousHooks) {
      if (scripts[hook]) {
        findings.push({
          rule: "VSCODE_INSTALL_SCRIPT",
          description: `Extension has a "${hook}" script in package.json`,
          severity: "medium",
          file: relativePath,
          match: `${hook}: ${scripts[hook]?.substring(0, 120)}`,
          recommendation: `Review the ${hook} script. Extensions should not need install scripts for normal operation.`,
        });
      }
    }
  }

  // Check for excessive permissions via contributes
  const contributes = manifest.contributes as Record<string, unknown> | undefined;
  if (contributes) {
    // Check for terminal profile contributions (can run arbitrary commands)
    if (contributes.terminal || contributes.terminals) {
      findings.push({
        rule: "VSCODE_TERMINAL_CONTRIBUTION",
        description: "Extension contributes terminal profiles (can execute commands)",
        severity: "low",
        file: relativePath,
        recommendation: "Review the terminal contributions to ensure they are legitimate.",
      });
    }
  }

  // Check for suspicious capabilities in extension manifest
  const capabilities = manifest.capabilities as Record<string, unknown> | undefined;
  if (capabilities) {
    const untrustedWorkspaces = capabilities.untrustedWorkspaces as Record<string, unknown> | undefined;
    if (untrustedWorkspaces) {
      const supported = untrustedWorkspaces.supported;
      if (supported === true || supported === "limited") {
        // This is actually good practice, not suspicious
      }
    }
  }
}

/**
 * Check file content against VS Code specific danger patterns.
 */
function checkVscodePatterns(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  const lines = content.split("\n");

  for (const pattern of EXTENSION_DANGER_PATTERNS) {
    const regex = new RegExp(pattern.pattern, "g");

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
          recommendation: getVscodeRecommendation(pattern.rule),
        });
        regex.lastIndex = 0;
      }
    }
  }
}

/**
 * Check for code obfuscation patterns.
 */
function checkObfuscationPatterns(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  for (const pattern of OBFUSCATION_PATTERNS) {
    const regex = new RegExp(pattern.pattern, "g");
    const match = regex.exec(content);
    if (match) {
      // Find the line number
      const beforeMatch = content.substring(0, match.index);
      const lineNumber = beforeMatch.split("\n").length;

      findings.push({
        rule: pattern.rule,
        description: pattern.description,
        severity: pattern.severity,
        file: relativePath,
        line: lineNumber,
        match: truncateMatch(match[0]),
        recommendation: "Obfuscated code in VS Code extensions is a red flag. Legitimate extensions typically ship readable source code.",
      });
    }
  }
}

/**
 * Check against general malware patterns from patterns.ts.
 */
function checkGeneralPatterns(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  const lines = content.split("\n");

  for (const pattern of FILE_PATTERNS) {
    const regex = new RegExp(pattern.pattern, "g");

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
          recommendation: `Found in VS Code extension. ${pattern.description}`,
        });
        regex.lastIndex = 0;
      }
    }
  }
}

/**
 * Filter findings by minimum severity.
 */
function filterFindings(findings: Finding[], minSeverity?: Severity): Finding[] {
  if (!minSeverity) return findings;

  const severityOrder: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };

  const minLevel = severityOrder[minSeverity] ?? 0;
  return findings.filter((f) => (severityOrder[f.severity] ?? 0) >= minLevel);
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
 * Calculate overall risk score.
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
 * Get recommendation for a VS Code specific rule.
 */
function getVscodeRecommendation(rule: string): string {
  const map: Record<string, string> = {
    VSCODE_EVAL: "eval() in extensions can execute arbitrary code. Verify this is necessary and not processing untrusted input.",
    VSCODE_FUNCTION_CONSTRUCTOR: "The Function constructor enables dynamic code execution. This is rarely needed in legitimate extensions.",
    VSCODE_CHILD_PROCESS: "child_process usage allows running system commands. Verify the extension needs this capability.",
    VSCODE_EXEC: "Process execution can run arbitrary system commands. Verify this is expected behavior.",
    VSCODE_NETWORK: "Network requests may exfiltrate data or download payloads. Check what URLs are being contacted.",
    VSCODE_ENV_ACCESS: "Environment variable access may be used to harvest credentials or system information.",
    VSCODE_FILE_WRITE: "File write operations could be used to drop malware payloads.",
    VSCODE_ENCODED_BUFFER: "Encoded buffers may contain hidden payloads. Decode and inspect the content.",
    VSCODE_BASE64: "Base64 encoding/decoding may be used to hide malicious content.",
  };
  return map[rule] ?? "Review this finding manually.";
}

/**
 * Generate VS Code specific recommendations.
 */
function generateVscodeRecommendations(
  findings: Finding[],
  target: string,
): string[] {
  const recommendations: string[] = [];
  const rules = new Set(findings.map((f) => f.rule));

  if (rules.has("VSCODE_SUSPICIOUS_ACTIVATION")) {
    recommendations.push(
      "Extension uses suspicious activation events that cause it to run automatically. Only install if you trust the publisher.",
    );
  }
  if (rules.has("VSCODE_OBFUSCATED_VARS") || rules.has("VSCODE_STRING_ARRAY")) {
    recommendations.push(
      "CAUTION: Obfuscated code detected. Legitimate VS Code extensions rarely obfuscate their source. This is a strong indicator of malicious intent.",
    );
  }
  if (rules.has("VSCODE_EVAL") || rules.has("VSCODE_FUNCTION_CONSTRUCTOR")) {
    recommendations.push(
      "Dynamic code execution (eval/Function) detected. This can be used to execute hidden payloads at runtime.",
    );
  }
  if (rules.has("VSCODE_CHILD_PROCESS") || rules.has("VSCODE_EXEC")) {
    recommendations.push(
      "Extension can execute system commands. Verify this is required for its stated functionality.",
    );
  }
  if (
    rules.has("GLASSWORM_MARKER") ||
    rules.has("EVAL_ATOB") ||
    rules.has("EVAL_BUFFER")
  ) {
    recommendations.push(
      "CRITICAL: Known malware patterns detected in this extension. Do NOT install it.",
    );
  }
  if (findings.some((f) => f.severity === "critical")) {
    recommendations.push(
      `CRITICAL findings in extension "${target}". Uninstall immediately if already installed.`,
    );
  }
  if (findings.length === 0) {
    recommendations.push(
      `No malicious indicators found in "${target}". The extension appears safe based on known patterns.`,
    );
  }

  return recommendations;
}

/**
 * Download a file from a URL, following redirects.
 */
function downloadFile(url: string, dest: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const doRequest = (requestUrl: string, redirects = 0): void => {
      if (redirects > 5) {
        reject(new Error("Too many redirects"));
        return;
      }

      const urlObj = new URL(requestUrl);
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: urlObj.pathname + urlObj.search,
        method: "GET",
        headers: {
          "User-Agent": "supply-chain-guard/1.0.0",
          Accept: "application/octet-stream",
        },
      };

      https
        .get(options, (response) => {
          if (
            (response.statusCode === 302 || response.statusCode === 301) &&
            response.headers.location
          ) {
            doRequest(response.headers.location, redirects + 1);
            return;
          }
          if (response.statusCode !== 200) {
            reject(
              new Error(
                `Download failed with status ${response.statusCode} for ${requestUrl}`,
              ),
            );
            return;
          }
          response.pipe(file);
          file.on("finish", () => {
            file.close();
            resolve();
          });
        })
        .on("error", (err) => {
          file.close();
          fs.unlinkSync(dest);
          reject(err);
        });
    };

    doRequest(url);
  });
}

/**
 * Recursively collect files.
 */
function collectFilesRecursive(dir: string): string[] {
  const files: string[] = [];
  let entries: fs.Dirent[];

  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return files;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name !== "node_modules") {
      files.push(...collectFilesRecursive(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Truncate a match string for display.
 */
function truncateMatch(match: string, maxLen = 120): string {
  if (match.length <= maxLen) return match;
  return match.substring(0, maxLen) + "...";
}
