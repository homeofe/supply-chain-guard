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
  makeOversizedSkipFinding,
} from "./patterns.js";
import { parseGitHubUrl } from "./github-trust-scanner.js";

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
  repository?: unknown;
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

  // Corroborate the claimed source repository (starjacking): a package that
  // points its `repository` at a popular project it does not own inherits that
  // project's trust/stars. Network-requiring, so best-effort; never throws.
  await checkRepositoryClaim(packageName, versionData as NpmVersionData, findings);

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

// ---------------------------------------------------------------------------
// Repository-claim corroboration (starjacking) - v5.16.0
// ---------------------------------------------------------------------------

/** Tokens too generic to prove two package names refer to the same project. */
const GENERIC_NAME_TOKENS = new Set([
  "js", "ts", "lib", "libs", "core", "sdk", "api", "utils", "util", "common",
  "node", "cli", "app", "client", "server", "plugin", "tool", "tools", "kit",
  "pkg", "package", "module", "src", "www", "web", "main", "index", "project",
]);

/** Split a package name into significant lowercase tokens (scope stripped). */
function significantTokens(name: string): Set<string> {
  const unscoped = name.replace(/^@[^/]+\//, "");
  return new Set(
    unscoped
      .toLowerCase()
      .split(/[-_./@]+/)
      .filter((t) => t.length >= 3 && !GENERIC_NAME_TOKENS.has(t)),
  );
}

/**
 * Two package names are "related" (likely the same project) if they share any
 * significant token, so `cool-lib` published from the `cool-project` repo is
 * not flagged. Purely a false-positive guard.
 */
function namesAreRelated(a: string, b: string): boolean {
  const ta = significantTokens(a);
  for (const t of significantTokens(b)) if (ta.has(t)) return true;
  return false;
}

/**
 * Normalize the many shapes of a package.json `repository` field to a GitHub
 * owner/repo (+ monorepo subdirectory), or null when it is not a GitHub repo.
 */
export function parseRepositoryField(
  repository: unknown,
): { owner: string; repo: string; directory?: string } | null {
  let url: string | undefined;
  let directory: string | undefined;
  if (typeof repository === "string") {
    url = repository;
  } else if (repository && typeof repository === "object") {
    const r = repository as { url?: unknown; directory?: unknown };
    if (typeof r.url === "string") url = r.url;
    if (typeof r.directory === "string") directory = r.directory;
  }
  if (!url) return null;

  // Shorthand forms: "github:owner/repo", "owner/repo".
  const shorthand = url.match(/^(?:github:)?([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/);
  if (shorthand && !url.includes("://") && !url.includes("github.com")) {
    const parsed = parseGitHubUrl(`github.com/${shorthand[1]}/${shorthand[2]}`);
    return parsed ? { ...parsed, directory } : null;
  }

  const parsed = parseGitHubUrl(url);
  return parsed ? { ...parsed, directory } : null;
}

/** GET a URL over HTTPS, resolving null on any non-200 / error (never throws). */
function httpsGetTextOrNull(url: string): Promise<string | null> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v: string | null): void => {
      if (!settled) { settled = true; resolve(v); }
    };
    try {
      const req = https.get(url, { headers: { Accept: "application/json", "User-Agent": "supply-chain-guard" } }, (res) => {
        if (res.statusCode !== 200) {
          res.resume?.();
          done(null);
          return;
        }
        let data = "";
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_FILE_SIZE) { done(null); req.destroy?.(); return; }
          data += chunk.toString();
        });
        res.on("end", () => done(data));
        res.on("error", () => done(null));
      });
      // Bound the wait so a hung/slow host cannot stall the whole npm scan.
      req.setTimeout?.(10_000, () => { done(null); req.destroy?.(); });
      req.on("error", () => done(null));
    } catch {
      done(null);
    }
  });
}

/**
 * Corroborate a package's claimed source repository (starjacking detection).
 *
 * A malicious package can set `repository` to a popular project's URL to inherit
 * its trust score and stars. We fetch the claimed repo's root package.json and
 * flag ONLY the high-confidence borrowed-trust case: the repo publishes a
 * DIFFERENT, unrelated package and is not a monorepo containing this one.
 *
 * Deliberately conservative (best-effort, medium severity) - every ambiguous or
 * benign case is left unflagged:
 *   - no repository field, or a non-GitHub host           -> skip
 *   - repository.directory set (a monorepo subdirectory)  -> skip (legit)
 *   - the repo declares `workspaces` (a monorepo)         -> skip (legit)
 *   - the repo could not be fetched (404/private/network) -> skip
 *   - the repo's package.json name equals this package    -> skip (corroborated)
 *   - the names share a significant token (same project)  -> skip
 */
export async function checkRepositoryClaim(
  packageName: string,
  versionData: { repository?: unknown },
  findings: Finding[],
): Promise<void> {
  const claim = parseRepositoryField(versionData.repository);
  if (!claim) return;
  // A monorepo subdirectory legitimately means the root name differs.
  if (claim.directory) return;

  // The package's scope matching the repo owner is a strong ownership signal: an
  // org publishing @acme/* from github.com/acme/<mono> is the common legit case
  // (and the dominant pnpm/lerna monorepo layout). Cheap, no fetch. Skip.
  const scope = packageName.match(/^@([^/]+)\//)?.[1];
  if (scope && scope.toLowerCase() === claim.owner.toLowerCase()) return;

  // If either name reduces to no SIGNIFICANT token (e.g. "core"/"cli"/"@x/api"),
  // relatedness cannot be judged, so unrelatedness cannot be proven - skip
  // rather than emit a maximally-FP-prone flag (v5.16.0 gate finding).
  if (significantTokens(packageName).size === 0) return;

  const body = await httpsGetTextOrNull(
    `https://raw.githubusercontent.com/${claim.owner}/${claim.repo}/HEAD/package.json`,
  );
  if (body === null) return; // unfetchable: too benign to flag

  let repoPkg: { name?: unknown; workspaces?: unknown; private?: unknown };
  try {
    repoPkg = JSON.parse(body) as { name?: unknown; workspaces?: unknown; private?: unknown };
  } catch {
    return;
  }
  // Monorepo / workspace-root signals: a root that declares `workspaces`, or is
  // marked private (the near-universal marker of an unpublished monorepo root
  // that legitimately publishes many differently-named member packages).
  if (repoPkg.workspaces !== undefined) return;
  if (repoPkg.private === true) return;

  const repoName = typeof repoPkg.name === "string" ? repoPkg.name : undefined;
  if (!repoName) return; // no name to compare
  if (repoName === packageName) return; // corroborated
  if (significantTokens(repoName).size === 0) return; // repo name too generic to judge
  if (namesAreRelated(packageName, repoName)) return; // likely the same project

  // Last-resort monorepo check (only on the would-flag path, so no latency on
  // the common case): pnpm/lerna monorepos leave the package.json workspaces key
  // empty. If a workspace manifest exists in the repo, treat it as a monorepo.
  for (const manifest of ["pnpm-workspace.yaml", "lerna.json"]) {
    const m = await httpsGetTextOrNull(
      `https://raw.githubusercontent.com/${claim.owner}/${claim.repo}/HEAD/${manifest}`,
    );
    if (m !== null) return;
  }

  findings.push({
    rule: "STARJACKING_SUSPECTED",
    description:
      `Package "${packageName}" claims repository github.com/${claim.owner}/${claim.repo}, but that ` +
      `repository publishes a different, unrelated package ("${repoName}") and is not a monorepo ` +
      "containing this one - the repository may be borrowed to inherit its stars/trust.",
    severity: "medium",
    confidence: 0.7,
    category: "supply-chain",
    file: "package.json",
    recommendation:
      `Verify that github.com/${claim.owner}/${claim.repo} is really the source of "${packageName}". ` +
      "Starjacking points a malicious package at a popular project's repo to inflate trust scores; " +
      "confirm the repo actually builds and publishes this package before trusting it.",
  });
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
    scanExtractedNpmFiles(extractDir, findings);
  } finally {
    // Cleanup
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Scan the extracted tarball contents for malicious patterns.
 * Exported for tests (the download path needs network; this walker does not).
 */
export function scanExtractedNpmFiles(
  extractDir: string,
  findings: Finding[],
): void {
  const files = collectFilesRecursive(extractDir);

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    if (!SCANNABLE_EXTENSIONS.has(ext)) continue;

    const stat = fs.statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) {
      // Surface the skip instead of silently dropping coverage (issue #54).
      findings.push(makeOversizedSkipFinding(path.relative(extractDir, filePath), stat.size));
      continue;
    }

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
