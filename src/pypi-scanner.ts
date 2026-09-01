/**
 * PyPI package scanner
 *
 * Downloads and analyzes PyPI packages without installing them.
 * Checks for suspicious install hooks, obfuscated code, and known malicious patterns.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { createHash } from "node:crypto";
import type { Finding, ScanReport, ScanOptions } from "./types.js";
import { SEVERITY_SCORES } from "./types.js";
import { extractTar, extractZip } from "./archive-extractor.js";
import {
  FILE_PATTERNS,
  PYPI_FILE_PATTERNS,
  PYPI_INSTALL_HOOK_PATTERNS,
  PYPI_SETUP_FILES,
  PYPI_TYPOSQUAT_PATTERNS,
  PYTHON_EXTENSIONS,
  SCANNABLE_EXTENSIONS,
  MAX_FILE_SIZE,
  makeOversizedSkipFinding,
  makePackageCoverageFindings,
  truncateMatch,
} from "./patterns.js";
import { hasPartialScanFinding, matchPatternInFile, recordUnreadablePath } from "./pattern-scanner.js";
import { collectExtractedFiles } from "./extracted-file-walker.js";
import {
  downloadHttpsFile,
  fetchHttpsBuffer,
  RemoteHttpStatusError,
} from "./remote-download.js";

const TOOL_VERSION = "6.0.9";
const PYPI_API = "https://pypi.org/pypi";
const PYPI_METADATA_HOST = "pypi.org";
const PYPI_ARTIFACT_HOST = "files.pythonhosted.org";

function assertAllowedPyPIUrl(
  rawUrl: string,
  expectedHost: string,
  requestKind: "metadata" | "artifact",
): void {
  const url = new URL(rawUrl);
  if (url.hostname.toLowerCase() !== expectedHost || url.port !== "") {
    throw new Error(
      `PyPI ${requestKind} request refused non-official host "${url.host}"; ` +
        `allowed host: ${expectedHost}`,
    );
  }
}

function assertAllowedPyPIMetadataUrl(rawUrl: string): void {
  assertAllowedPyPIUrl(rawUrl, PYPI_METADATA_HOST, "metadata");
}

function assertAllowedPyPIArtifactUrl(rawUrl: string): void {
  assertAllowedPyPIUrl(rawUrl, PYPI_ARTIFACT_HOST, "artifact");
}

/** Public and testable acquisition bounds for PyPI registry data. */
export const PYPI_REMOTE_LIMITS = Object.freeze({
  metadataBytes: 8 * 1024 * 1024,
  artifactBytes: 256 * 1024 * 1024,
  timeoutMs: 30_000,
  maxRedirects: 5,
});

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

export interface PyPIReleaseFile {
  filename: string;
  url: string;
  packagetype: string;
  size: number;
  digests?: { sha256?: string; md5?: string };
}

interface FileCounts {
  totalFiles: number;
  filesScanned: number;
}

export type PyPIArtifactScanner = (
  artifact: PyPIReleaseFile,
  findings: Finding[],
  expectedSha256?: string,
) => Promise<FileCounts>;

export class PyPIArtifactAcquisitionError extends Error {
  constructor(readonly artifactFilename: string) {
    super(`Could not download, verify, or extract PyPI artifact: ${artifactFilename}`);
    this.name = "PyPIArtifactAcquisitionError";
  }
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

  // PyPI releases can ship different code in their sdist and platform wheels.
  // Scan every downloadable artifact for the latest release, not just the
  // first sdist (or first wheel when no sdist exists).
  const fileCounts = await scanPypiReleaseArtifacts(
    metadata.urls ?? [],
    findings,
  );

  // Match the npm and directory contracts: no opened package files is a
  // coverage finding, never an implicit clean verdict.
  findings.push(
    ...makePackageCoverageFindings(fileCounts.totalFiles, fileCounts.filesScanned),
  );

  // Capture coverage before minimum-severity filtering can hide an
  // informational transparency finding such as PYPI_NO_SOURCE.
  const partialScan = hasPartialScanFinding(findings);
  const severityOrder: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  const minimum = severityOrder[options.minSeverity ?? "info"] ?? 0;
  const filteredFindings = findings.filter(
    (finding) => (severityOrder[finding.severity] ?? 0) >= minimum,
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
    findings: filteredFindings,
    summary,
    score,
    riskLevel,
    recommendations: generatePypiRecommendations(filteredFindings, displayName, partialScan),
    partialScan: partialScan || undefined,
  };
}

/**
 * Fetch package metadata from the PyPI JSON API.
 */
async function fetchPyPIMetadata(
  packageName: string,
): Promise<PyPIPackageResponse> {
  const url = `${PYPI_API}/${encodeURIComponent(packageName)}/json`;
  let response;
  try {
    response = await fetchHttpsBuffer(url, {
      maxBytes: PYPI_REMOTE_LIMITS.metadataBytes,
      timeoutMs: PYPI_REMOTE_LIMITS.timeoutMs,
      maxRedirects: PYPI_REMOTE_LIMITS.maxRedirects,
      headers: { Accept: "application/json", "User-Agent": "supply-chain-guard" },
      validateUrl: assertAllowedPyPIMetadataUrl,
    });
  } catch (error) {
    if (error instanceof RemoteHttpStatusError) {
      if (error.statusCode === 404) {
        throw new Error(`Package not found on PyPI: ${packageName}`);
      }
      throw new Error(
        `PyPI API returned status ${error.statusCode ?? "unknown"} for ${packageName}`,
      );
    }
    throw error;
  }

  try {
    return JSON.parse(response.body.toString("utf8")) as PyPIPackageResponse;
  } catch {
    throw new Error("Failed to parse PyPI API response");
  }
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

type PyPIArtifactKind = "sdist" | "wheel";

function getPyPIArtifactKind(
  artifact: PyPIReleaseFile,
): PyPIArtifactKind | undefined {
  const filename = artifact.filename.toLowerCase();
  if (artifact.packagetype === "bdist_wheel") return "wheel";
  if (artifact.packagetype === "sdist") return "sdist";
  if (filename.endsWith(".whl")) return "wheel";
  if (
    filename.endsWith(".tar.gz") ||
    filename.endsWith(".tar.bz2") ||
    filename.endsWith(".zip")
  ) {
    return "sdist";
  }
  return undefined;
}

function getArtifactIdentity(
  artifact: PyPIReleaseFile,
  index: number,
): string {
  const normalizedFilename = artifact.filename.replace(/\\/g, "/");
  const basename = normalizedFilename.split("/").pop() || "artifact";
  const safeBasename = basename.replace(/[^A-Za-z0-9._+-]/g, "_");
  return `artifacts/${String(index + 1).padStart(3, "0")}-${safeBasename}`;
}

function appendArtifactFindings(
  destination: Finding[],
  artifactFindings: Finding[],
  artifactIdentity: string,
): void {
  for (const finding of artifactFindings) {
    const subpath = (finding.file ?? "")
      .split(/[\\/]+/)
      .filter((segment) => segment.length > 0 && segment !== "." && segment !== "..")
      .join("/");
    destination.push({
      ...finding,
      file: subpath ? `${artifactIdentity}/${subpath}` : artifactIdentity,
    });
  }
}

function normalizeArtifactUrl(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  try {
    const parsed = new URL(trimmed);
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return trimmed;
  }
}

interface PyPIArtifactGroup {
  expectedSha256?: string;
  candidates: PyPIReleaseFile[];
}

type Sha256Metadata =
  | { kind: "missing" }
  | { kind: "malformed"; raw: string }
  | { kind: "valid"; value: string };

function getSha256Metadata(artifact: PyPIReleaseFile): Sha256Metadata {
  const raw = artifact.digests?.sha256;
  if (raw === undefined) return { kind: "missing" };
  const normalized = raw.trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(normalized)
    ? { kind: "valid", value: normalized }
    : { kind: "malformed", raw: normalized };
}

/**
 * PyPI metadata can repeat one file record or expose multiple CDN aliases for
 * the same digest. Preserve every distinct alias in an identity group so a
 * broken first URL cannot hide working bytes at a later URL.
 */
function groupReleaseArtifacts(
  releaseFiles: PyPIReleaseFile[],
): PyPIArtifactGroup[] {
  const artifacts = releaseFiles.filter(
    (artifact) => getPyPIArtifactKind(artifact) !== undefined,
  );

  // A digestless duplicate may bridge a registry URL to its one unambiguous
  // SHA-256 identity. Never collapse two different valid digests merely because
  // metadata reuses a URL: inconsistent metadata must cause extra scanning, not
  // a false negative.
  const digestsByUrl = new Map<string, Set<string>>();
  for (const artifact of artifacts) {
    const url = normalizeArtifactUrl(artifact.url);
    const sha256 = getSha256Metadata(artifact);
    if (url === undefined || sha256.kind !== "valid") continue;
    const digests = digestsByUrl.get(url) ?? new Set<string>();
    digests.add(sha256.value);
    digestsByUrl.set(url, digests);
  }

  const groupsByIdentity = new Map<string, PyPIArtifactGroup>();
  const candidateKeysByIdentity = new Map<string, Set<string>>();
  for (const [index, artifact] of artifacts.entries()) {
    const url = normalizeArtifactUrl(artifact.url);
    const sha256 = getSha256Metadata(artifact);
    const urlDigests = url === undefined ? undefined : digestsByUrl.get(url);
    const bridgedSha256 = sha256.kind === "valid"
      ? sha256.value
      : sha256.kind === "missing" && urlDigests?.size === 1
        ? urlDigests.values().next().value
        : undefined;

    // Malformed digest metadata is deliberately kept outside a valid-digest
    // group. Conflicting valid digests sharing a URL likewise have distinct
    // SHA identities. Both cases favor an extra scan/partial result over
    // accidentally deduplicating away potentially different release bytes.
    const identity = bridgedSha256 !== undefined
      ? `sha256:${bridgedSha256}`
      : sha256.kind === "malformed" && url !== undefined
        ? `malformed:${sha256.raw}:${url}`
        : sha256.kind === "missing" && url !== undefined
          ? `digestless:${url}`
          : `record:${index}`;

    let group = groupsByIdentity.get(identity);
    if (group === undefined) {
      group = {
        expectedSha256: bridgedSha256,
        candidates: [],
      };
      groupsByIdentity.set(identity, group);
      candidateKeysByIdentity.set(identity, new Set<string>());
    }

    // URL fragments do not identify different download bytes, but extraction
    // behavior also depends on filename/kind metadata. Only collapse records
    // that are equivalent on both dimensions so a bad first archive label
    // cannot hide a later, correct interpretation of the same URL and digest.
    const normalizedFilename = artifact.filename
      .trim()
      .replace(/\\/g, "/")
      .toLowerCase();
    const artifactKind = getPyPIArtifactKind(artifact)!;
    const candidateKey = url === undefined
      ? `record:${index}`
      : `url:${url}|kind:${artifactKind}|filename:${normalizedFilename}`;
    const candidateKeys = candidateKeysByIdentity.get(identity)!;
    if (!candidateKeys.has(candidateKey)) {
      candidateKeys.add(candidateKey);
      group.candidates.push(artifact);
    }
  }

  return [...groupsByIdentity.values()];
}
/**
 * Scan every source distribution and wheel exposed for the latest release.
 * The scanner dependency is injectable so artifact enumeration and aggregation
 * can be regression-tested without network access or archive tooling.
 */
export async function scanPypiReleaseArtifacts(
  releaseFiles: PyPIReleaseFile[],
  findings: Finding[],
  scanArtifact: PyPIArtifactScanner = downloadAndScanArtifact,
): Promise<FileCounts> {
  const artifactGroups = groupReleaseArtifacts(releaseFiles);
  const totals: FileCounts = { totalFiles: 0, filesScanned: 0 };

  if (artifactGroups.length === 0) {
    findings.push({
      rule: "PYPI_NO_SOURCE",
      description: "No source distribution (sdist) or wheel found. Cannot scan package contents.",
      severity: "info",
      recommendation: "The package has no downloadable artifacts to scan.",
    });
    return totals;
  }

  for (const [index, group] of artifactGroups.entries()) {
    const representative = group.candidates[0]!;
    const failureArtifactIdentity = getArtifactIdentity(representative, index);
    let scanned = false;

    for (const artifact of group.candidates) {
      const artifactFindings: Finding[] = [];
      try {
        const counts = await scanArtifact(
          artifact,
          artifactFindings,
          group.expectedSha256,
        );
        totals.totalFiles += counts.totalFiles;
        totals.filesScanned += counts.filesScanned;
        const scannedArtifactIdentity = getArtifactIdentity(artifact, index);
        appendArtifactFindings(findings, artifactFindings, scannedArtifactIdentity);
        if (group.expectedSha256 === undefined) {
          appendArtifactFindings(findings, [{
            rule: "PATH_SCAN_INCOMPLETE",
            description: `PyPI artifact "${artifact.filename}" was scanned, but registry metadata did not provide a valid SHA-256 identity, so the downloaded bytes could not be authenticated.`,
            severity: "info",
            recommendation:
              "Verify this artifact's identity independently before treating the package as safe.",
          }], scannedArtifactIdentity);
        }
        scanned = true;
        break;
      } catch (error) {
        // Acquisition, archive, and digest failures may be alias-specific.
        // Scanner logic failures are operational errors and must propagate.
        if (!(error instanceof PyPIArtifactAcquisitionError)) throw error;
      }
    }

    if (!scanned) {
      appendArtifactFindings(findings, [{
        rule: "PATH_SCAN_INCOMPLETE",
        description: `PyPI artifact "${representative.filename}" could not be downloaded, SHA-256 verified, or extracted from any registry alias, so its contents were not scanned.`,
        severity: "info",
        recommendation:
          "Retry the scan and inspect this release artifact independently before treating the package as safe.",
      }], failureArtifactIdentity);
    }
  }

  return totals;
}

async function downloadAndScanArtifact(
  artifact: PyPIReleaseFile,
  findings: Finding[],
  expectedSha256?: string,
): Promise<FileCounts> {
  return getPyPIArtifactKind(artifact) === "wheel"
    ? downloadAndScanWheel(artifact, findings, expectedSha256)
    : downloadAndScanSdist(artifact, findings, expectedSha256);
}

/**
 * Verify an on-disk artifact without loading it into memory.
 */
export function verifyArtifactSha256(
  artifactPath: string,
  expectedSha256: string,
): Promise<boolean> {
  if (!/^[a-f0-9]{64}$/i.test(expectedSha256)) {
    return Promise.resolve(false);
  }

  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = fs.createReadStream(artifactPath);
    stream.on("data", (chunk: Buffer) => {
      hash.update(chunk);
    });
    stream.on("error", reject);
    stream.on("end", () => {
      resolve(hash.digest("hex") === expectedSha256.toLowerCase());
    });
  });
}


/** Download, extract, and scan one source distribution. */
async function downloadAndScanSdist(
  artifact: PyPIReleaseFile,
  findings: Finding[],
  expectedSha256?: string,
): Promise<FileCounts> {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pypi-"));
  const archivePath = path.join(tempDir, "package.archive");

  try {
    const extractDir = path.join(tempDir, "extracted");
    try {
      await downloadHttpsFile(artifact.url, archivePath, {
        maxBytes: PYPI_REMOTE_LIMITS.artifactBytes,
        timeoutMs: PYPI_REMOTE_LIMITS.timeoutMs,
        maxRedirects: PYPI_REMOTE_LIMITS.maxRedirects,
        headers: {
          Accept: "application/octet-stream",
          "User-Agent": "supply-chain-guard",
        },
        validateUrl: assertAllowedPyPIArtifactUrl,
      });
      if (
        expectedSha256 !== undefined &&
        !(await verifyArtifactSha256(archivePath, expectedSha256))
      ) {
        throw new PyPIArtifactAcquisitionError(artifact.filename);
      }
      fs.mkdirSync(extractDir, { recursive: true });
      if (artifact.filename.toLowerCase().endsWith(".zip")) {
        extractZip(archivePath, extractDir);
      } else {
        extractTar(archivePath, extractDir);
      }
    } catch (error) {
      if (error instanceof PyPIArtifactAcquisitionError) throw error;
      throw new PyPIArtifactAcquisitionError(artifact.filename);
    }

    // Scanner logic errors must remain operational failures, not be mislabeled
    // as an artifact coverage problem.
    return scanExtractedFiles(extractDir, findings);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

/** Download, extract, and scan one wheel. */
async function downloadAndScanWheel(
  artifact: PyPIReleaseFile,
  findings: Finding[],
  expectedSha256?: string,
): Promise<FileCounts> {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pypi-"));
  const wheelPath = path.join(tempDir, "package.whl");

  try {
    const extractDir = path.join(tempDir, "extracted");
    try {
      await downloadHttpsFile(artifact.url, wheelPath, {
        maxBytes: PYPI_REMOTE_LIMITS.artifactBytes,
        timeoutMs: PYPI_REMOTE_LIMITS.timeoutMs,
        maxRedirects: PYPI_REMOTE_LIMITS.maxRedirects,
        headers: {
          Accept: "application/octet-stream",
          "User-Agent": "supply-chain-guard",
        },
        validateUrl: assertAllowedPyPIArtifactUrl,
      });
      if (
        expectedSha256 !== undefined &&
        !(await verifyArtifactSha256(wheelPath, expectedSha256))
      ) {
        throw new PyPIArtifactAcquisitionError(artifact.filename);
      }
      fs.mkdirSync(extractDir, { recursive: true });
      extractZip(wheelPath, extractDir);
    } catch (error) {
      if (error instanceof PyPIArtifactAcquisitionError) throw error;
      throw new PyPIArtifactAcquisitionError(artifact.filename);
    }

    return scanExtractedFiles(extractDir, findings);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Scan extracted package files for malicious patterns.
 * Exported for tests (the download paths need network; this walker does not).
 */
export function scanExtractedFiles(
  extractDir: string,
  findings: Finding[],
): { totalFiles: number; filesScanned: number } {
  const files = collectExtractedFiles(extractDir, findings, {
    shouldEnterDirectory: (name) =>
      name !== "__pycache__" &&
      name !== ".git" &&
      name !== "node_modules" &&
      name !== ".tox" &&
      name !== ".venv" &&
      name !== "venv",
  });
  let filesScanned = 0;

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath);
    const relativePath = path.relative(extractDir, filePath);
    const isPython = PYTHON_EXTENSIONS.has(ext);
    const isSetupFile = PYPI_SETUP_FILES.has(basename);

    // Only scan known file types
    if (!SCANNABLE_EXTENSIONS.has(ext) && !isPython) continue;

    let stat: fs.Stats;
    try {
      stat = fs.statSync(filePath);
    } catch {
      recordUnreadablePath(findings, relativePath);
      continue;
    }
    if (stat.size > MAX_FILE_SIZE) {
      // Surface the skip instead of silently dropping coverage (issue #54).
      findings.push(makeOversizedSkipFinding(relativePath, stat.size));
      continue;
    }

    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      recordUnreadablePath(findings, relativePath);
      continue;
    }
    filesScanned++;

    // Apply general file patterns (catches obfuscation, eval/atob, etc.)
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
          recommendation: `Found in PyPI package. ${pattern.description}`,
        });
      }
    }

    // Apply PyPI-specific patterns to Python files and setup files
    if (isPython || isSetupFile) {
      for (const pattern of PYPI_FILE_PATTERNS) {
        const hits = matchPatternInFile(
          pattern,
          content,
          relativePath,
          findings,
          "g",
        );
        for (const hit of hits ?? []) {
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
            line: hit.line,
            match: truncateMatch(hit.text),
            recommendation: isSetupFile
              ? `Found in ${basename}, which runs during installation. This is a high-risk location for malicious code.`
              : `Review this code carefully. ${pattern.description}`,
          });
        }
      }

      // Check for install hook overrides in setup files
      if (isSetupFile) {
        for (const pattern of PYPI_INSTALL_HOOK_PATTERNS) {
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
              recommendation: `Custom install commands in ${basename} execute code during pip install. Verify the command class is benign.`,
            });
          }
        }

        // File-level combined analysis for setup files
        analyzeSetupFileContext(content, relativePath, findings);
      }
    }
  }
  return { totalFiles: files.length, filesScanned };
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
 * Recursively collect files from a directory.
 */
/**
 * Generate recommendations for PyPI package scan.
 */
function generatePypiRecommendations(
  findings: Finding[],
  packageName: string,
  partialScan = false,
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

  if (partialScan) {
    recommendations.unshift(
      "WARNING: Scan incomplete because one or more package checks or files could not be evaluated. Resolve coverage gaps before treating this package as safe.",
    );
  }
  if (findings.length === 0 && !partialScan) {
    recommendations.push(
      `No malicious indicators found in ${packageName}. The package appears safe based on known patterns.`,
    );
  }

  return recommendations;
}
