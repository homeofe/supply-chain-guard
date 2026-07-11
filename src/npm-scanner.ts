/**
 * npm package scanner
 *
 * Downloads and analyzes npm packages without installing them.
 * Checks for suspicious scripts, obfuscated code, and known malicious patterns.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as https from "node:https";
import type { Finding, NpmPackageInfo, ScanReport, ScanOptions } from "./types.js";
import { SEVERITY_SCORES } from "./types.js";
import { extractTarGz } from "./archive-extractor.js";
import {
  FILE_PATTERNS,
  SUSPICIOUS_SCRIPTS,
  MALICIOUS_PACKAGE_PATTERNS,
  SCANNABLE_EXTENSIONS,
  MAX_FILE_SIZE,
} from "./patterns.js";

const TOOL_VERSION = "1.0.0";
const NPM_REGISTRY = "https://registry.npmjs.org";

interface NpmRegistryResponse {
  "dist-tags"?: { latest?: string; [key: string]: string | undefined };
  versions?: Record<string, NpmVersionData>;
}

interface NpmVersionData {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  dist?: { tarball?: string };
  [key: string]: unknown;
}

/**
 * Scan an npm package by name.
 */
export async function scanNpmPackage(
  packageName: string,
  options: Omit<ScanOptions, "target"> & { target?: string },
): Promise<ScanReport> {
  const startTime = Date.now();
  const findings: Finding[] = [];

  // Check package name against known malicious patterns
  checkPackageName(packageName, findings);

  // Fetch package metadata from registry
  const metadata = await fetchPackageMetadata(packageName);
  const latestVersion = metadata["dist-tags"]?.latest;
  if (!latestVersion) {
    throw new Error(`Could not determine latest version for ${packageName}`);
  }

  const versionData = metadata.versions?.[latestVersion];
  if (!versionData) {
    throw new Error(`Version data not found for ${packageName}@${latestVersion}`);
  }

  // Check package.json scripts
  checkPackageScripts(versionData as NpmVersionData, findings);

  // Check dependencies against known malicious packages
  checkDependencies(versionData as NpmVersionData, findings);

  // Download and scan tarball
  const tarballUrl = (versionData as NpmVersionData).dist?.tarball;
  if (tarballUrl) {
    await downloadAndScanTarball(tarballUrl, findings);
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

  const riskLevel = score === 0
    ? "clean" as const
    : score <= 10
      ? "low" as const
      : score <= 30
        ? "medium" as const
        : score <= 60
          ? "high" as const
          : "critical" as const;

  return {
    tool: `supply-chain-guard v${TOOL_VERSION}`,
    timestamp: new Date().toISOString(),
    target: `${packageName}@${latestVersion}`,
    scanType: "npm",
    durationMs: Date.now() - startTime,
    findings,
    summary,
    score,
    riskLevel,
    recommendations: generateNpmRecommendations(findings, packageName),
  };
}

/**
 * Check if the package name matches known malicious patterns.
 */
function checkPackageName(name: string, findings: Finding[]): void {
  for (const pattern of MALICIOUS_PACKAGE_PATTERNS) {
    const regex = new RegExp(pattern);
    if (regex.test(name)) {
      findings.push({
        rule: "MALICIOUS_PACKAGE_NAME",
        description: `Package name "${name}" matches a known malicious or typosquatting pattern`,
        severity: "high",
        recommendation: `Verify this is the package you intended to use. Known typosquatting packages exist with similar names.`,
      });
      break;
    }
  }
}

/**
 * Check package.json scripts for suspicious entries.
 */
function checkPackageScripts(
  pkg: NpmVersionData,
  findings: Finding[],
): void {
  const scripts = pkg.scripts;
  if (!scripts) return;

  const dangerousHooks = ["preinstall", "postinstall", "preuninstall", "postuninstall"];

  for (const hook of dangerousHooks) {
    const script = scripts[hook];
    if (!script) continue;

    for (const pattern of SUSPICIOUS_SCRIPTS) {
      const regex = new RegExp(pattern.pattern, "i");
      if (regex.test(script)) {
        findings.push({
          rule: pattern.rule,
          description: `npm ${hook}: ${pattern.description}`,
          severity: pattern.severity,
          file: "package.json",
          match: `${hook}: ${script}`,
          recommendation: `Review the ${hook} script before installing this package.`,
        });
      }
    }
  }
}

/**
 * Check dependencies against known malicious package patterns.
 */
function checkDependencies(
  pkg: NpmVersionData,
  findings: Finding[],
): void {
  const allDeps: string[] = [];

  const deps = pkg.dependencies;
  const devDeps = pkg.devDependencies;

  if (deps) allDeps.push(...Object.keys(deps));
  if (devDeps) allDeps.push(...Object.keys(devDeps));

  for (const dep of allDeps) {
    for (const pattern of MALICIOUS_PACKAGE_PATTERNS) {
      const regex = new RegExp(pattern);
      if (regex.test(dep)) {
        findings.push({
          rule: "MALICIOUS_DEPENDENCY",
          description: `Dependency "${dep}" matches a known malicious or typosquatting pattern`,
          severity: "high",
          file: "package.json",
          recommendation: `Verify that "${dep}" is a legitimate package and not a typosquat.`,
        });
        break;
      }
    }
  }
}

/**
 * Fetch package metadata from the npm registry.
 */
async function fetchPackageMetadata(
  packageName: string,
): Promise<NpmRegistryResponse> {
  const url = `${NPM_REGISTRY}/${encodeURIComponent(packageName)}`;

  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { Accept: "application/json" } }, (res) => {
        if (res.statusCode === 404) {
          reject(new Error(`Package not found: ${packageName}`));
          return;
        }
        if (res.statusCode !== 200) {
          reject(
            new Error(
              `npm registry returned status ${res.statusCode} for ${packageName}`,
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
            resolve(JSON.parse(data) as NpmRegistryResponse);
          } catch {
            reject(new Error("Failed to parse npm registry response"));
          }
        });
      })
      .on("error", reject);
  });
}

/**
 * Download tarball and scan its contents.
 */
async function downloadAndScanTarball(
  tarballUrl: string,
  findings: Finding[],
): Promise<void> {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-npm-"));
  const tarballPath = path.join(tempDir, "package.tgz");

  try {
    // Download tarball
    await downloadFile(tarballUrl, tarballPath);

    // Extract tarball
    const extractDir = path.join(tempDir, "extracted");
    fs.mkdirSync(extractDir, { recursive: true });
    extractTarGz(tarballPath, extractDir);

    // Scan extracted files
    const files = collectFilesRecursive(extractDir);

    for (const filePath of files) {
      const ext = path.extname(filePath).toLowerCase();
      if (!SCANNABLE_EXTENSIONS.has(ext)) continue;

      const stat = fs.statSync(filePath);
      if (stat.size > MAX_FILE_SIZE) continue;

      try {
        const content = fs.readFileSync(filePath, "utf-8");
        const relativePath = path.relative(extractDir, filePath);

        for (const pattern of FILE_PATTERNS) {
          const regex = new RegExp(pattern.pattern, "g");
          const lines = content.split("\n");

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
                recommendation: `Found in published npm tarball. ${pattern.description}`,
              });
              regex.lastIndex = 0;
            }
          }
        }
      } catch {
        // Skip unreadable files
      }
    }
  } finally {
    // Cleanup
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Download a file from a URL.
 */
function downloadFile(url: string, dest: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, (response) => {
        // Handle redirects
        if (response.statusCode === 302 || response.statusCode === 301) {
          const redirectUrl = response.headers.location;
          if (redirectUrl) {
            file.close();
            downloadFile(redirectUrl, dest).then(resolve, reject);
            return;
          }
        }
        response.pipe(file);
        file.on("finish", () => {
          file.close();
          resolve();
        });
      })
      .on("error", (err) => {
        fs.unlinkSync(dest);
        reject(err);
      });
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
 * Generate recommendations for npm package scan.
 */
function generateNpmRecommendations(
  findings: Finding[],
  packageName: string,
): string[] {
  const recommendations: string[] = [];

  if (findings.some((f) => f.rule === "MALICIOUS_PACKAGE_NAME")) {
    recommendations.push(
      `The package name "${packageName}" matches known malicious patterns. Verify this is the intended package.`,
    );
  }
  if (findings.some((f) => f.rule.startsWith("SCRIPT_"))) {
    recommendations.push(
      "Suspicious install scripts detected. Use --ignore-scripts when installing: npm install --ignore-scripts",
    );
  }
  if (findings.some((f) => f.severity === "critical")) {
    recommendations.push(
      "CRITICAL findings detected. Do NOT install this package until the findings are investigated.",
    );
  }
  if (findings.some((f) => f.rule === "MALICIOUS_DEPENDENCY")) {
    recommendations.push(
      "This package depends on packages matching known malicious patterns. Audit the full dependency tree.",
    );
  }
  if (findings.length === 0) {
    recommendations.push(
      `No malicious indicators found in ${packageName}. The package appears safe based on known patterns.`,
    );
  }

  return recommendations;
}
