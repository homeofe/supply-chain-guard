/**
 * PyPI package scanner
 *
 * Downloads and analyzes PyPI packages without installing them.
 * Checks for suspicious install hooks, obfuscated code, and known malicious patterns.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as https from "node:https";
import { execSync } from "node:child_process";
import type { Finding, ScanReport, ScanOptions } from "./types.js";
import { SEVERITY_SCORES } from "./types.js";
import {
  FILE_PATTERNS,
  PYPI_FILE_PATTERNS,
  PYPI_INSTALL_HOOK_PATTERNS,
  PYPI_SETUP_FILES,
  PYPI_TYPOSQUAT_PATTERNS,
  PYTHON_EXTENSIONS,
  SCANNABLE_EXTENSIONS,
  MAX_FILE_SIZE,
} from "./patterns.js";

const TOOL_VERSION = "1.0.0";
const PYPI_API = "https://pypi.org/pypi";

interface PyPIPackageResponse {
  info?: {
    name?: string;
    version?: string;
    summary?: string;
    author?: string;
    home_page?: string;
    project_urls?: Record<string, string>;
  };
  urls?: PyPIReleaseFile[];
}

interface PyPIReleaseFile {
  filename: string;
  url: string;
  packagetype: string;
  size: number;
  digests?: { sha256?: string; md5?: string };
}

/**
 * Scan a PyPI package by name.
 */
export async function scanPypiPackage(
  packageName: string,
  options: Omit<ScanOptions, "target"> & { target?: string },
): Promise<ScanReport> {
  const startTime = Date.now();
  const findings: Finding[] = [];

  // Fetch package metadata from PyPI
  const metadata = await fetchPyPIMetadata(packageName);
  const version = metadata.info?.version;
  if (!version) {
    throw new Error(`Could not determine latest version for ${packageName}`);
  }

  const displayName = metadata.info?.name ?? packageName;

  // Check package metadata for suspicious indicators
  checkPackageMetadata(metadata, findings);

  // Find an sdist (.tar.gz) to download and scan
  const sdist = findSdist(metadata.urls ?? []);
  if (sdist) {
    await downloadAndScanSdist(sdist.url, findings);
  } else {
    // If no sdist, try a wheel
    const wheel = findWheel(metadata.urls ?? []);
    if (wheel) {
      await downloadAndScanWheel(wheel.url, findings);
    } else {
      findings.push({
        rule: "PYPI_NO_SOURCE",
        description: "No source distribution (sdist) or wheel found. Cannot scan package contents.",
        severity: "info",
        recommendation: "The package has no downloadable artifacts to scan.",
      });
    }
  }

  // Calculate results
  const summary = {
    totalFiles: 0,
    filesScanned: 0,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  let score = 0;
  for (const finding of findings) {
    score += SEVERITY_SCORES[finding.severity];
  }
  score = Math.min(100, score);

  const riskLevel =
    score === 0
      ? ("clean" as const)
      : score <= 10
        ? ("low" as const)
        : score <= 30
          ? ("medium" as const)
          : score <= 60
            ? ("high" as const)
            : ("critical" as const);

  return {
    tool: `supply-chain-guard v${TOOL_VERSION}`,
    timestamp: new Date().toISOString(),
    target: `${displayName}==${version}`,
    scanType: "pypi",
    durationMs: Date.now() - startTime,
    findings,
    summary,
    score,
    riskLevel,
    recommendations: generatePypiRecommendations(findings, displayName),
  };
}

/**
 * Fetch package metadata from the PyPI JSON API.
 */
async function fetchPyPIMetadata(
  packageName: string,
): Promise<PyPIPackageResponse> {
  const url = `${PYPI_API}/${encodeURIComponent(packageName)}/json`;

  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { Accept: "application/json" } }, (res) => {
        if (res.statusCode === 404) {
          reject(new Error(`Package not found on PyPI: ${packageName}`));
          return;
        }
        if (res.statusCode !== 200) {
          reject(
            new Error(
              `PyPI API returned status ${res.statusCode} for ${packageName}`,
            ),
          );
          return;
        }

        let data = "";
        res.on("data", (chunk: Buffer) => {
          data += chunk.toString();
        });
        res.on("end", () => {
          try {
            resolve(JSON.parse(data) as PyPIPackageResponse);
          } catch {
            reject(new Error("Failed to parse PyPI API response"));
          }
        });
      })
      .on("error", reject);
  });
}

/**
 * Check package metadata for suspicious indicators.
 */
function checkPackageMetadata(
  metadata: PyPIPackageResponse,
  findings: Finding[],
): void {
  const info = metadata.info;
  if (!info) return;

  // Check for very new packages with no homepage or repo
  if (!info.home_page && !info.project_urls) {
    findings.push({
      rule: "PYPI_NO_REPO",
      description:
        "Package has no homepage or project URLs. Legitimate packages typically link to a repository.",
      severity: "low",
      recommendation:
        "Verify the package author and origin. Malicious packages often lack project links.",
    });
  }
}

/**
 * Find a source distribution (sdist) from release files.
 */
function findSdist(urls: PyPIReleaseFile[]): PyPIReleaseFile | undefined {
  return urls.find(
    (u) =>
      u.packagetype === "sdist" ||
      u.filename.endsWith(".tar.gz") ||
      u.filename.endsWith(".tar.bz2") ||
      u.filename.endsWith(".zip"),
  );
}

/**
 * Find a wheel from release files.
 */
function findWheel(urls: PyPIReleaseFile[]): PyPIReleaseFile | undefined {
  return urls.find(
    (u) => u.packagetype === "bdist_wheel" || u.filename.endsWith(".whl"),
  );
}

/**
 * Download and scan an sdist (.tar.gz).
 */
async function downloadAndScanSdist(
  url: string,
  findings: Finding[],
): Promise<void> {
  const tempDir = fs.mkdtempSync(path.join("/tmp", "scg-pypi-"));
  const archivePath = path.join(tempDir, "package.tar.gz");

  try {
    await downloadFile(url, archivePath);

    const extractDir = path.join(tempDir, "extracted");
    fs.mkdirSync(extractDir, { recursive: true });

    // Determine archive type and extract
    if (url.endsWith(".zip") || url.includes(".zip")) {
      execSync(`unzip -q "${archivePath}" -d "${extractDir}"`, {
        stdio: "pipe",
      });
    } else {
      execSync(`tar xzf "${archivePath}" -C "${extractDir}"`, {
        stdio: "pipe",
      });
    }

    scanExtractedFiles(extractDir, findings);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Download and scan a wheel (.whl is a zip file).
 */
async function downloadAndScanWheel(
  url: string,
  findings: Finding[],
): Promise<void> {
  const tempDir = fs.mkdtempSync(path.join("/tmp", "scg-pypi-"));
  const wheelPath = path.join(tempDir, "package.whl");

  try {
    await downloadFile(url, wheelPath);

    const extractDir = path.join(tempDir, "extracted");
    fs.mkdirSync(extractDir, { recursive: true });
    execSync(`unzip -q "${wheelPath}" -d "${extractDir}"`, { stdio: "pipe" });

    scanExtractedFiles(extractDir, findings);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Scan extracted package files for malicious patterns.
 */
function scanExtractedFiles(
  extractDir: string,
  findings: Finding[],
): void {
  const files = collectFilesRecursive(extractDir);

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath);
    const relativePath = path.relative(extractDir, filePath);
    const isPython = PYTHON_EXTENSIONS.has(ext);
    const isSetupFile = PYPI_SETUP_FILES.has(basename);

    // Only scan known file types
    if (!SCANNABLE_EXTENSIONS.has(ext) && !isPython) continue;

    const stat = fs.statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) continue;

    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }

    const lines = content.split("\n");

    // Apply general file patterns (catches obfuscation, eval/atob, etc.)
    for (const pattern of FILE_PATTERNS) {
      const regex = new RegExp(pattern.pattern, "g");
      for (let i = 0; i < lines.length; i++) {
        const match = regex.exec(lines[i] ?? "");
        if (match) {
          findings.push({
            rule: pattern.rule,
            description: pattern.description,
            severity: pattern.severity,
            file: relativePath,
            line: i + 1,
            match: match[0].substring(0, 120),
            recommendation: `Found in PyPI package. ${pattern.description}`,
          });
          regex.lastIndex = 0;
        }
      }
    }

    // Apply PyPI-specific patterns to Python files and setup files
    if (isPython || isSetupFile) {
      for (const pattern of PYPI_FILE_PATTERNS) {
        const regex = new RegExp(pattern.pattern, "g");
        for (let i = 0; i < lines.length; i++) {
          const match = regex.exec(lines[i] ?? "");
          if (match) {
            // Boost severity if found in setup.py
            const severity =
              isSetupFile && pattern.severity === "medium"
                ? "high"
                : pattern.severity;
            findings.push({
              rule: pattern.rule,
              description: isSetupFile
                ? `[${basename}] ${pattern.description}`
                : pattern.description,
              severity,
              file: relativePath,
              line: i + 1,
              match: match[0].substring(0, 120),
              recommendation: isSetupFile
                ? `Found in ${basename}, which runs during installation. This is a high-risk location for malicious code.`
                : `Review this code carefully. ${pattern.description}`,
            });
            regex.lastIndex = 0;
          }
        }
      }

      // Check for install hook overrides in setup files
      if (isSetupFile) {
        for (const pattern of PYPI_INSTALL_HOOK_PATTERNS) {
          const regex = new RegExp(pattern.pattern, "g");
          for (let i = 0; i < lines.length; i++) {
            const match = regex.exec(lines[i] ?? "");
            if (match) {
              findings.push({
                rule: pattern.rule,
                description: pattern.description,
                severity: pattern.severity,
                file: relativePath,
                line: i + 1,
                match: match[0].substring(0, 120),
                recommendation: `Custom install commands in ${basename} execute code during pip install. Verify the command class is benign.`,
              });
              regex.lastIndex = 0;
            }
          }
        }

        // File-level combined analysis for setup files
        analyzeSetupFileContext(content, relativePath, findings);
      }
    }
  }
}

/**
 * Analyze a setup file for combined suspicious patterns.
 *
 * Performs file-level analysis to detect when a setup.py defines custom
 * install hooks AND contains dangerous code (subprocess, obfuscated
 * execution, or network downloads).
 */
export function analyzeSetupFileContext(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  const hasCmdclass = /cmdclass\s*=/.test(content);
  const hasInstallClassOverride =
    /class\s+\w+\s*\(\s*(?:install|develop)\s*\)/.test(content);
  const hasDangerousHook = hasCmdclass || hasInstallClassOverride;

  if (!hasDangerousHook) {
    // Still check install_requires even without cmdclass
    checkInstallRequires(content, relativePath, findings);
    return;
  }

  const hasSubprocess =
    /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(/.test(
      content,
    );
  const hasOsSystem = /os\.system\s*\(/.test(content);
  const hasExec = /\bexec\s*\(/.test(content);
  const hasEval = /\beval\s*\(/.test(content);
  const hasUrllib = /urllib\.request\.urlopen\s*\(/.test(content);
  const hasRequests = /requests\.(?:get|post)\s*\(/.test(content);
  const hasBase64Decode = /base64\.b64decode\s*\(/.test(content);
  const hasMarshalLoads = /marshal\.loads\s*\(/.test(content);

  if (hasSubprocess || hasOsSystem) {
    findings.push({
      rule: "PYPI_HOOK_SYSTEM_EXEC",
      description:
        "Custom install hook with system command execution (subprocess/os.system in setup file with cmdclass)",
      severity: "critical",
      file: relativePath,
      recommendation:
        "Setup file defines custom install commands that execute system commands. This code runs during pip install.",
    });
  }

  if ((hasExec || hasEval) && (hasBase64Decode || hasMarshalLoads)) {
    findings.push({
      rule: "PYPI_HOOK_OBFUSCATED_EXEC",
      description:
        "Custom install hook with obfuscated code execution (base64/marshal + exec/eval in setup file with cmdclass)",
      severity: "critical",
      file: relativePath,
      recommendation:
        "Setup file defines custom install commands with obfuscated payload execution. Do NOT install this package.",
    });
  }

  if (hasUrllib || hasRequests) {
    findings.push({
      rule: "PYPI_HOOK_DOWNLOAD",
      description:
        "Custom install hook with network download (urllib/requests in setup file with cmdclass)",
      severity: "critical",
      file: relativePath,
      recommendation:
        "Setup file defines custom install commands that download from the network. This code runs during pip install.",
    });
  }

  checkInstallRequires(content, relativePath, findings);
}

/**
 * Check install_requires for known typosquatted package names.
 */
export function checkInstallRequires(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  const requiresMatch = content.match(
    /install_requires\s*=\s*\[([\s\S]*?)\]/,
  );
  if (!requiresMatch?.[1]) return;

  const requiresBlock = requiresMatch[1];
  const nameMatches = [...requiresBlock.matchAll(/['"]([^'"]+)['"]/g)];

  for (const m of nameMatches) {
    // Strip version specifiers to get the bare package name
    const pkgName = (m[1] ?? "").split(/[>=<!~;]/)[0]?.trim();
    if (!pkgName) continue;

    for (const pattern of PYPI_TYPOSQUAT_PATTERNS) {
      if (new RegExp(pattern).test(pkgName)) {
        findings.push({
          rule: "PYPI_TYPOSQUAT_DEP",
          description: `Suspicious dependency "${pkgName}" in install_requires matches a known typosquatting pattern`,
          severity: "high",
          file: relativePath,
          match: pkgName,
          recommendation: `Verify "${pkgName}" is the intended package. Typosquatted package names are a common supply-chain attack vector.`,
        });
        break;
      }
    }
  }
}

/**
 * Download a file from a URL, following redirects.
 */
function downloadFile(url: string, dest: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const makeRequest = (requestUrl: string, redirectCount: number): void => {
      if (redirectCount > 5) {
        reject(new Error("Too many redirects"));
        return;
      }

      const protocol = requestUrl.startsWith("https") ? https : https;
      const file = fs.createWriteStream(dest);

      protocol
        .get(requestUrl, (response) => {
          if (
            response.statusCode === 302 ||
            response.statusCode === 301 ||
            response.statusCode === 307
          ) {
            const redirectUrl = response.headers.location;
            file.close();
            if (redirectUrl) {
              makeRequest(redirectUrl, redirectCount + 1);
            } else {
              reject(new Error("Redirect without location header"));
            }
            return;
          }

          if (response.statusCode !== 200) {
            file.close();
            reject(
              new Error(`Download failed with status ${response.statusCode}`),
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
          try {
            fs.unlinkSync(dest);
          } catch {
            // ignore cleanup errors
          }
          reject(err);
        });
    };

    makeRequest(url, 0);
  });
}

/**
 * Recursively collect files from a directory.
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
    if (
      entry.isDirectory() &&
      entry.name !== "__pycache__" &&
      entry.name !== ".git" &&
      entry.name !== "node_modules" &&
      entry.name !== ".tox" &&
      entry.name !== ".venv" &&
      entry.name !== "venv"
    ) {
      files.push(...collectFilesRecursive(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Generate recommendations for PyPI package scan.
 */
function generatePypiRecommendations(
  findings: Finding[],
  packageName: string,
): string[] {
  const recommendations: string[] = [];
  const rules = new Set(findings.map((f) => f.rule));

  if (
    rules.has("PYPI_EXEC_ENCODED") ||
    rules.has("PYPI_EVAL_ENCODED")
  ) {
    recommendations.push(
      "CRITICAL: Obfuscated code execution detected. Do NOT install this package until the encoded payload is decoded and reviewed.",
    );
  }
  if (rules.has("PYPI_SUSPICIOUS_INDEX")) {
    recommendations.push(
      "CRITICAL: Package references a non-PyPI package index. This is a strong indicator of dependency confusion or a malicious package source.",
    );
  }
  if (
    rules.has("PYPI_OS_SYSTEM") ||
    rules.has("PYPI_SUBPROCESS")
  ) {
    recommendations.push(
      "System command execution detected in package files. If found in setup.py, this code runs during pip install. Review the commands carefully.",
    );
  }
  if (
    rules.has("PYPI_CUSTOM_INSTALL") ||
    rules.has("PYPI_CUSTOM_DEVELOP") ||
    rules.has("PYPI_CUSTOM_EGG_INFO")
  ) {
    recommendations.push(
      "Custom install command classes detected in setup.py. These override pip's install process and can execute arbitrary code. Use --no-build-isolation cautiously.",
    );
  }
  if (
    rules.has("PYPI_IMPORT_BASE64") ||
    rules.has("PYPI_IMPORT_MARSHAL")
  ) {
    recommendations.push(
      "Hidden imports of encoding/obfuscation modules detected. These are commonly used to hide malicious payloads in Python packages.",
    );
  }
  if (
    rules.has("PYPI_ENV_EXFILTRATION") ||
    rules.has("PYPI_HOSTNAME_EXFIL")
  ) {
    recommendations.push(
      "Data exfiltration patterns detected. The package may collect system information and send it to external servers.",
    );
  }
  if (
    rules.has("PYPI_HOOK_SYSTEM_EXEC") ||
    rules.has("PYPI_HOOK_DOWNLOAD")
  ) {
    recommendations.push(
      "CRITICAL: Custom install hook executes system commands or downloads from the network. This code runs automatically during pip install.",
    );
  }
  if (rules.has("PYPI_HOOK_OBFUSCATED_EXEC")) {
    recommendations.push(
      "CRITICAL: Custom install hook contains obfuscated code execution. Do NOT install this package.",
    );
  }
  if (rules.has("PYPI_TYPOSQUAT_DEP")) {
    recommendations.push(
      "Suspicious dependencies detected in install_requires. Verify all dependency names are spelled correctly and are the intended packages.",
    );
  }
  if (rules.has("PYPI_EXEC_MARSHAL") || rules.has("PYPI_MARSHAL_LOADS")) {
    recommendations.push(
      "Bytecode deserialization via marshal detected. This is an advanced obfuscation technique used to hide malicious payloads.",
    );
  }
  if (rules.has("PYPI_NO_REPO")) {
    recommendations.push(
      `Package "${packageName}" has no linked repository. Consider verifying the author's identity before installing.`,
    );
  }

  if (findings.some((f) => f.severity === "critical")) {
    recommendations.push(
      "CRITICAL findings detected. Do NOT install this package until all findings are investigated.",
    );
  }

  if (findings.length === 0) {
    recommendations.push(
      `No malicious indicators found in ${packageName}. The package appears safe based on known patterns.`,
    );
  }

  return recommendations;
}
