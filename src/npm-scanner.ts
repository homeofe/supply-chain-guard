/**
 * npm package scanner
 *
 * Downloads and analyzes npm packages without installing them.
 * Checks for suspicious scripts, obfuscated code, and known malicious patterns.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash, timingSafeEqual } from "node:crypto";
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
  truncateMatch,
} from "./patterns.js";
import { parseGitHubUrl } from "./github-trust-scanner.js";
import { hasPartialScanFinding, matchPatternInFile, recordUnreadablePath } from "./pattern-scanner.js";
import { collectExtractedFiles } from "./extracted-file-walker.js";
import { getBundledFeed } from "./threat-intel.js";
import { matchBareNpmIOC } from "./install-guard.js";
import {
  downloadHttpsFile,
  fetchHttpsBuffer,
  RemoteHttpStatusError,
} from "./remote-download.js";

const TOOL_VERSION = "5.26.0";
const NPM_REGISTRY = "https://registry.npmjs.org";
const NPM_REGISTRY_HOST = "registry.npmjs.org";
const RAW_GITHUB_HOST = "raw.githubusercontent.com";
const RAW_GITHUB_TIMEOUT_MS = 10_000;

function assertAllowedNpmRegistryUrl(rawUrl: string): void {
  const url = new URL(rawUrl);
  if (url.hostname.toLowerCase() !== NPM_REGISTRY_HOST || url.port !== "") {
    throw new Error(
      `npm registry request refused non-official host "${url.host}"; ` +
        `allowed host: ${NPM_REGISTRY_HOST}`,
    );
  }
}

function assertAllowedRawGitHubUrl(rawUrl: string): void {
  const url = new URL(rawUrl);
  if (url.hostname.toLowerCase() !== RAW_GITHUB_HOST || url.port !== "") {
    throw new Error(
      `GitHub repository corroboration refused non-official host "${url.host}"; ` +
        `allowed host: ${RAW_GITHUB_HOST}`,
    );
  }
}

/** Public and testable acquisition bounds for npm registry data. */
export const NPM_REMOTE_LIMITS = Object.freeze({
  metadataBytes: 32 * 1024 * 1024,
  artifactBytes: 256 * 1024 * 1024,
  timeoutMs: 30_000,
  maxRedirects: 5,
});

interface NpmRegistryResponse {
  "dist-tags"?: { latest?: string; [key: string]: string | undefined };
  versions?: Record<string, NpmVersionData>;
}

interface NpmVersionData {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  dist?: NpmDistInfo;
  repository?: unknown;
  [key: string]: unknown;
}

export interface NpmDistInfo {
  tarball?: string;
  integrity?: string;
  shasum?: string;
}

/** Testable package-coverage contract shared by the network scan path. */
export function recordNpmNoArtifact(findings: Finding[]): void {
  findings.push({
    rule: "NPM_NO_ARTIFACT",
    description:
      "Registry metadata does not provide a package tarball, so package contents could not be scanned.",
    severity: "info",
    recommendation:
      "Treat this result as partial and inspect a trustworthy package artifact before use.",
  });
}

/** Record that bytes were scanned but registry metadata could not authenticate them. */
export function recordNpmUnverifiedArtifact(findings: Finding[]): void {
  findings.push({
    rule: "PATH_SCAN_INCOMPLETE",
    description:
      "The npm tarball was scanned, but registry metadata supplied neither dist.integrity nor dist.shasum, so the downloaded bytes could not be authenticated.",
    severity: "info",
    recommendation:
      "Verify the package artifact independently before treating this scan as complete.",
  });
}

export function filterNpmFindings(
  findings: Finding[],
  minSeverity: ScanOptions["minSeverity"],
): { filteredFindings: Finding[]; partialScan: boolean } {
  const severityOrder: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  const partialScan = hasPartialScanFinding(findings);
  const minimum = severityOrder[minSeverity ?? "info"] ?? 0;
  return {
    filteredFindings: findings.filter(
      (finding) => (severityOrder[finding.severity] ?? 0) >= minimum,
    ),
    partialScan,
  };
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
  let fileCounts = { totalFiles: 0, filesScanned: 0 };
  const dist = (versionData as NpmVersionData).dist;
  const tarballUrl = dist?.tarball;
  if (tarballUrl) {
    fileCounts = await downloadAndScanTarball(tarballUrl, findings, dist);
  } else {
    recordNpmNoArtifact(findings);
  }

  // Snapshot completeness before a severity filter can hide its informational
  // transparency finding, matching the PyPI scanner contract.
  const { filteredFindings, partialScan } = filterNpmFindings(
    findings,
    options.minSeverity,
  );

  // Calculate results
  const summary = {
    totalFiles: fileCounts.totalFiles,
    filesScanned: fileCounts.filesScanned,
    critical: filteredFindings.filter((f) => f.severity === "critical").length,
    high: filteredFindings.filter((f) => f.severity === "high").length,
    medium: filteredFindings.filter((f) => f.severity === "medium").length,
    low: filteredFindings.filter((f) => f.severity === "low").length,
    info: filteredFindings.filter((f) => f.severity === "info").length,
  };

  let score = 0;
  for (const finding of filteredFindings) {
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
    findings: filteredFindings,
    summary,
    score,
    riskLevel,
    recommendations: generateNpmRecommendations(filteredFindings, packageName, partialScan),
    partialScan: partialScan || undefined,
  };
}

/**
 * Check if the package name matches known malicious patterns.
 */
function checkPackageName(name: string, findings: Finding[]): void {
  // Exact-match first. This path used to rely entirely on name-shape regexes,
  // which is why it needed a scoped catch-all that flagged 94% of all scoped
  // packages. The bundled feed gives an exact verdict for every curated name,
  // scoped or not, with no false-positive surface.
  const ioc = matchBareNpmIOC(name, undefined, getBundledFeed());
  if (ioc) {
    const attrib = ioc.campaign ? ` (campaign: ${ioc.campaign})` : "";
    findings.push({
      rule: "MALICIOUS_PACKAGE_NAME",
      description: `Package "${name}" is a known-malicious package in the threat feed${attrib}`,
      severity: "critical",
      confidence: ioc.confidence ?? 0.95,
      recommendation: `Do not install "${name}". Rotate any secrets exposed while it was installed.`,
    });
    return;
  }

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
      const hits = matchPatternInFile(
        pattern,
        script,
        "package.json",
        findings,
        "i",
      );
      if (hits && hits.length > 0) {
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

  const feed = getBundledFeed();
  for (const dep of allDeps) {
    const depIoc = matchBareNpmIOC(dep, undefined, feed);
    if (depIoc) {
      const attrib = depIoc.campaign ? ` (campaign: ${depIoc.campaign})` : "";
      findings.push({
        rule: "MALICIOUS_DEPENDENCY",
        description: `Dependency "${dep}" is a known-malicious package in the threat feed${attrib}`,
        severity: "critical",
        confidence: depIoc.confidence ?? 0.95,
        file: "package.json",
        recommendation: `Remove "${dep}" immediately and rotate any exposed secrets.`,
      });
      continue;
    }
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

/** Fetch a raw GitHub manifest within the same bounded transport policy. */
async function fetchRawGitHubTextOrNull(url: string): Promise<string | null> {
  try {
    const response = await fetchHttpsBuffer(url, {
      maxBytes: MAX_FILE_SIZE,
      timeoutMs: RAW_GITHUB_TIMEOUT_MS,
      maxRedirects: NPM_REMOTE_LIMITS.maxRedirects,
      headers: { Accept: "application/json", "User-Agent": "supply-chain-guard" },
      validateUrl: assertAllowedRawGitHubUrl,
    });
    return response.body.toString("utf8");
  } catch {
    return null;
  }
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

  const body = await fetchRawGitHubTextOrNull(
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
    const m = await fetchRawGitHubTextOrNull(
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
  let response;
  try {
    response = await fetchHttpsBuffer(url, {
      maxBytes: NPM_REMOTE_LIMITS.metadataBytes,
      timeoutMs: NPM_REMOTE_LIMITS.timeoutMs,
      maxRedirects: NPM_REMOTE_LIMITS.maxRedirects,
      headers: { Accept: "application/json", "User-Agent": "supply-chain-guard" },
      validateUrl: assertAllowedNpmRegistryUrl,
    });
  } catch (error) {
    if (error instanceof RemoteHttpStatusError) {
      if (error.statusCode === 404) {
        throw new Error(`Package not found: ${packageName}`);
      }
      throw new Error(
        `npm registry returned status ${error.statusCode ?? "unknown"} for ${packageName}`,
      );
    }
    throw error;
  }

  try {
    return JSON.parse(response.body.toString("utf8")) as NpmRegistryResponse;
  } catch {
    throw new Error("Failed to parse npm registry response");
  }
}

/**
 * Download tarball and scan its contents.
 */
async function downloadAndScanTarball(
  tarballUrl: string,
  findings: Finding[],
  dist: NpmDistInfo,
): Promise<{ totalFiles: number; filesScanned: number }> {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-npm-"));
  const tarballPath = path.join(tempDir, "package.tgz");

  try {
    // Download tarball
    await downloadHttpsFile(tarballUrl, tarballPath, {
      maxBytes: NPM_REMOTE_LIMITS.artifactBytes,
      timeoutMs: NPM_REMOTE_LIMITS.timeoutMs,
      maxRedirects: NPM_REMOTE_LIMITS.maxRedirects,
      headers: {
        Accept: "application/octet-stream",
        "User-Agent": "supply-chain-guard",
      },
      validateUrl: assertAllowedNpmRegistryUrl,
    });
    if (!(await verifyNpmDistIntegrity(tarballPath, dist))) {
      throw new Error("Downloaded npm tarball does not match dist.integrity/dist.shasum");
    }

    if (
      typeof dist.integrity !== "string" &&
      typeof dist.shasum !== "string"
    ) {
      recordNpmUnverifiedArtifact(findings);
    }

    // Extract tarball
    const extractDir = path.join(tempDir, "extracted");
    fs.mkdirSync(extractDir, { recursive: true });
    extractTarGz(tarballPath, extractDir);

    // Scan extracted files
    return scanExtractedNpmFiles(extractDir, findings);
  } finally {
    // Cleanup
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

const SRI_ALGORITHM_STRENGTH = {
  sha256: 1,
  sha384: 2,
  sha512: 3,
} as const;

type SriAlgorithm = keyof typeof SRI_ALGORITHM_STRENGTH;

interface SriDigest {
  algorithm: SriAlgorithm;
  digest: Buffer;
}

function parseStrongestSriDigests(integrity: string): SriDigest[] {
  const parsed: SriDigest[] = [];
  for (const token of integrity.trim().split(/\s+/)) {
    const match = token.match(/^(sha256|sha384|sha512)-([^?]+)(?:\?.*)?$/i);
    if (!match) continue;
    const algorithm = match[1]!.toLowerCase() as SriAlgorithm;
    const encoded = match[2]!.replace(/-/g, "+").replace(/_/g, "/");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) continue;
    const digest = Buffer.from(encoded, "base64");
    const expectedLength = algorithm === "sha256" ? 32 : algorithm === "sha384" ? 48 : 64;
    if (digest.length !== expectedLength) continue;
    parsed.push({ algorithm, digest });
  }
  const strongest = parsed.reduce(
    (max, entry) => Math.max(max, SRI_ALGORITHM_STRENGTH[entry.algorithm]),
    0,
  );
  return parsed.filter(
    (entry) => SRI_ALGORITHM_STRENGTH[entry.algorithm] === strongest,
  );
}

function hashFile(
  filePath: string,
  algorithms: ReadonlySet<string>,
): Promise<Map<string, Buffer>> {
  return new Promise((resolve, reject) => {
    const hashes = new Map(
      [...algorithms].map((algorithm) => [algorithm, createHash(algorithm)]),
    );
    const stream = fs.createReadStream(filePath);
    stream.on("data", (chunk: Buffer) => {
      for (const hash of hashes.values()) hash.update(chunk);
    });
    stream.on("error", reject);
    stream.on("end", () => {
      resolve(new Map([...hashes].map(([algorithm, hash]) => [algorithm, hash.digest()])));
    });
  });
}

/** Verify every npm registry digest that is present, strongest SRI algorithm first. */
export async function verifyNpmDistIntegrity(
  tarballPath: string,
  dist: Pick<NpmDistInfo, "integrity" | "shasum">,
): Promise<boolean> {
  const integrityPresent = typeof dist.integrity === "string";
  const shasumPresent = typeof dist.shasum === "string";
  if (!integrityPresent && !shasumPresent) return true;

  const sri = integrityPresent ? parseStrongestSriDigests(dist.integrity!) : [];
  if (integrityPresent && sri.length === 0) return false;
  if (shasumPresent && !/^[a-f0-9]{40}$/i.test(dist.shasum!)) return false;

  const algorithms = new Set<string>(sri.map((entry) => entry.algorithm));
  if (shasumPresent) algorithms.add("sha1");
  const actual = await hashFile(tarballPath, algorithms);

  if (sri.length > 0) {
    const sriMatches = sri.some((entry) => {
      const digest = actual.get(entry.algorithm);
      return digest !== undefined && timingSafeEqual(digest, entry.digest);
    });
    if (!sriMatches) return false;
  }
  if (shasumPresent) {
    const sha1 = actual.get("sha1");
    if (!sha1 || sha1.toString("hex") !== dist.shasum!.toLowerCase()) return false;
  }
  return true;
}

/**
 * Scan the extracted tarball contents for malicious patterns.
 * Exported for tests (the download path needs network; this walker does not).
 */
export function scanExtractedNpmFiles(
  extractDir: string,
  findings: Finding[],
): { totalFiles: number; filesScanned: number } {
  const files = collectExtractedFiles(extractDir, findings);
  let filesScanned = 0;

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    if (!SCANNABLE_EXTENSIONS.has(ext)) continue;

    let stat: fs.Stats;
    try {
      stat = fs.statSync(filePath);
    } catch {
      recordUnreadablePath(findings, path.relative(extractDir, filePath));
      continue;
    }
    if (stat.size > MAX_FILE_SIZE) {
      // Surface the skip instead of silently dropping coverage (issue #54).
      findings.push(makeOversizedSkipFinding(path.relative(extractDir, filePath), stat.size));
      continue;
    }

    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      recordUnreadablePath(findings, path.relative(extractDir, filePath));
      continue;
    }
    const relativePath = path.relative(extractDir, filePath);
    filesScanned++;

    for (const pattern of FILE_PATTERNS) {
      const hits = matchPatternInFile(
        pattern,
        content,
        relativePath,
        findings,
        "g",
      );
      for (const hit of hits ?? []) {
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: relativePath,
          line: hit.line,
          match: truncateMatch(hit.text),
          recommendation: `Found in published npm tarball. ${pattern.description}`,
        });
      }
    }
  }
  return { totalFiles: files.length, filesScanned };
}

/**
 * Recursively collect files.
 */
/**
 * Generate recommendations for npm package scan.
 */
function generateNpmRecommendations(
  findings: Finding[],
  packageName: string,
  partialScan = false,
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
  if (partialScan) {
    recommendations.unshift(
      "WARNING: Scan incomplete because one or more package files could not be evaluated. Resolve coverage gaps before treating this package as safe.",
    );
  }
  if (findings.length === 0 && !partialScan) {
    recommendations.push(
      `No malicious indicators found in ${packageName}. The package appears safe based on known patterns.`,
    );
  }

  return recommendations;
}
