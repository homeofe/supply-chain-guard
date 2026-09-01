/**
 * VS Code Extension Scanner
 *
 * Scans .vsix files (VS Code extensions) for supply-chain malware indicators.
 * Accepts a local .vsix file path or an extension ID resolved against the
 * VS Code Marketplace (default) or the Open VSX registry.
 * .vsix files are ZIP archives containing the extension code.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Finding, PatternEntry, ScanReport, ScanSummary, Severity } from "./types.js";
import { SEVERITY_SCORES } from "./types.js";
import { ArchiveSecurityError, extractZip } from "./archive-extractor.js";
import {
  FILE_PATTERNS,
  SCANNABLE_EXTENSIONS,
  MAX_FILE_SIZE,
  makeOversizedSkipFinding,
  makePackageCoverageFindings,
  truncateMatch,
  validatePatternSet,
} from "./patterns.js";
import { hasPartialScanFinding, matchPatternInFile, recordUnreadablePath } from "./pattern-scanner.js";
import {
  collectExtractedFiles,
  readContainedExtractedUtf8File,
} from "./extracted-file-walker.js";
import {
  downloadHttpsFile,
  fetchHttpsBuffer,
  RemoteHttpStatusError,
} from "./remote-download.js";

const TOOL_VERSION = "6.0.9";

/** Public and testable acquisition bounds for extension registry data. */
export const VSCODE_REMOTE_LIMITS = Object.freeze({
  metadataBytes: 2 * 1024 * 1024,
  artifactBytes: 256 * 1024 * 1024,
  timeoutMs: 30_000,
  maxRedirects: 5,
});

// VS Code Marketplace API endpoint
const MARKETPLACE_API = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery";

// Open VSX registry REST API base (https://open-vsx.org/api/{namespace}/{name})
const OPENVSX_API_BASE = "https://open-vsx.org/api";

// Hosts a .vsix download resolved via Open VSX may legitimately live on.
// The public open-vsx.org instance serves files either directly from the
// registry host or from its Azure Blob storage account
// (openvsxorg.blob.core.windows.net, see the eclipse-openvsx deployment and
// mirror-mode documentation). Everything else is refused: a compromised or
// spoofed metadata response must not be able to point the scanner at an
// arbitrary download host.
const OPENVSX_ALLOWED_HOSTS = [
  "open-vsx.org",
  "openvsxorg.blob.core.windows.net",
];

interface ParsedVscodeExtensionId {
  publisher: string;
  name: string;
}

// Registry IDs are identifiers, never URL or filesystem syntax. Keeping both
// segments ASCII-only also makes the publisher safe to use as a DNS label.
const VSCODE_EXTENSION_ID_PATTERN =
  /^([A-Za-z0-9][A-Za-z0-9_-]{0,127})\.([A-Za-z0-9][A-Za-z0-9_-]{0,127})$/;

function parseVscodeExtensionId(extensionId: string): ParsedVscodeExtensionId {
  const match = extensionId.match(VSCODE_EXTENSION_ID_PATTERN);
  if (!match) {
    throw new Error(
      `Invalid extension ID format: "${extensionId}". Expected format: publisher.extensionName using only letters, numbers, hyphens, and underscores`,
    );
  }
  return { publisher: match[1]!, name: match[2]! };
}

/** Pin Marketplace downloads to the publisher endpoint and Microsoft's documented CDN. */
function assertAllowedMarketplaceUrl(
  rawUrl: string,
  publisher: string,
  context: string,
): void {
  let urlObj: URL;
  try {
    urlObj = new URL(rawUrl);
  } catch {
    throw new Error(`VS Code Marketplace ${context} is not a valid URL: ${rawUrl}`);
  }

  if (urlObj.protocol !== "https:") {
    throw new Error(
      `VS Code Marketplace ${context} must use https:, got "${urlObj.protocol}" (${rawUrl}). Refusing to fetch.`,
    );
  }
  if (urlObj.username || urlObj.password || urlObj.port) {
    throw new Error(
      `VS Code Marketplace ${context} has unexpected credentials or port (${rawUrl}). Refusing to fetch.`,
    );
  }

  const hostname = urlObj.hostname.toLowerCase();
  const publisherHost = `${publisher.toLowerCase()}.gallery.vsassets.io`;
  const marketplaceCdnSuffix = ".gallerycdn.vsassets.io";
  const allowed =
    hostname === publisherHost ||
    (hostname.endsWith(marketplaceCdnSuffix) &&
      hostname.length > marketplaceCdnSuffix.length);
  if (!allowed) {
    throw new Error(
      `VS Code Marketplace ${context} points at non-allowlisted host "${hostname}" (${rawUrl}). Refusing to fetch.`,
    );
  }
}

/**
 * Validate that an Open VSX related URL is https: and points at an exact
 * allowlisted host. Throws a descriptive error
 * otherwise. Applied to the files.download URL from the metadata response
 * and re-applied on every redirect hop of the Open VSX download path.
 * Marketplace downloads use their own Microsoft-host allowlist above.
 */
function assertAllowedOpenVsxUrl(rawUrl: string, context: string): void {
  let urlObj: URL;
  try {
    urlObj = new URL(rawUrl);
  } catch {
    throw new Error(`Open VSX ${context} is not a valid URL: ${rawUrl}`);
  }

  if (urlObj.protocol !== "https:") {
    throw new Error(
      `Open VSX ${context} must use https:, got "${urlObj.protocol}" (${rawUrl}). Refusing to fetch.`,
    );
  }
  if (urlObj.username || urlObj.password) {
    throw new Error(
      `Open VSX ${context} must not contain credentials (${rawUrl}). Refusing to fetch.`,
    );
  }
  if (urlObj.port) {
    throw new Error(
      `Open VSX ${context} must use the default HTTPS port (${rawUrl}). Refusing to fetch.`,
    );
  }

  const hostname = urlObj.hostname.toLowerCase();
  const allowed = OPENVSX_ALLOWED_HOSTS.includes(hostname);
  if (!allowed) {
    throw new Error(
      `Open VSX ${context} points at non-allowlisted host "${hostname}" (${rawUrl}). ` +
        `Allowed hosts: ${OPENVSX_ALLOWED_HOSTS.join(", ")}. Refusing to fetch.`,
    );
  }
}

/** Supported extension registries for extension-ID targets. */
export type VscodeRegistry = "marketplace" | "openvsx";

// Activation events that are suspicious (run without user action)
const SUSPICIOUS_ACTIVATION_EVENTS = [
  "*",                     // activates on everything
  "onStartupFinished",     // activates after VS Code starts
  "onUri",                 // activates on URI open (can be triggered externally)
];

const VSCODE_PATTERN_WHITESPACE = /\s/u;

function skipVscodePatternWhitespace(content: string, start: number): number {
  let index = start;
  while (
    index < content.length &&
    content[index] !== "\n" &&
    VSCODE_PATTERN_WHITESPACE.test(content[index]!)
  ) {
    index += 1;
  }
  return index;
}

function encodedBufferSuffixComma(content: string, close: number): number {
  let cursor = close;
  while (
    cursor > 0 &&
    content[cursor - 1] !== "\n" &&
    VSCODE_PATTERN_WHITESPACE.test(content[cursor - 1]!)
  ) {
    cursor -= 1;
  }

  if (content[cursor - 1] !== "'" && content[cursor - 1] !== '"') return -1;
  cursor -= 1;

  if (cursor >= 6 && content.slice(cursor - 6, cursor) === "base64") {
    cursor -= 6;
  } else if (cursor >= 3 && content.slice(cursor - 3, cursor) === "hex") {
    cursor -= 3;
  } else {
    return -1;
  }

  // The source regex deliberately permits mixed quote characters.
  if (content[cursor - 1] !== "'" && content[cursor - 1] !== '"') return -1;
  cursor -= 1;

  while (
    cursor > 0 &&
    content[cursor - 1] !== "\n" &&
    VSCODE_PATTERN_WHITESPACE.test(content[cursor - 1]!)
  ) {
    cursor -= 1;
  }
  return content[cursor - 1] === "," ? cursor - 1 : -1;
}

const vscodeEncodedBufferMatcher: NonNullable<
  PatternEntry["correlatedMatcher"]
> = function* (content) {
  const tokens = /Buffer\.from|\)|\n/g;
  let firstPrefix: { start: number; bodyStart: number } | undefined;
  let matchedPhysicalLine = false;
  let token: RegExpExecArray | null;

  while ((token = tokens.exec(content)) !== null) {
    if (token[0] === "\n") {
      firstPrefix = undefined;
      matchedPhysicalLine = false;
      continue;
    }
    if (matchedPhysicalLine) continue;

    if (token[0] === ")") {
      const comma = encodedBufferSuffixComma(content, token.index);
      if (firstPrefix && firstPrefix.bodyStart < comma) {
        const end = token.index + 1;
        yield {
          start: firstPrefix.start,
          end,
          // Findings historically expose truncateMatch(regexMatch), so
          // normalize here before the structural evidence-size guard.
          evidence: truncateMatch(content.slice(firstPrefix.start, end)),
        };
        matchedPhysicalLine = true;
      }
      // [^)] cannot cross this close parenthesis, successful or otherwise.
      firstPrefix = undefined;
      continue;
    }

    const previous = content[token.index - 1];
    if (previous !== undefined && /[A-Za-z0-9_]/.test(previous)) continue;

    const afterLiteral = token.index + token[0].length;
    const open = skipVscodePatternWhitespace(content, afterLiteral);
    if (content[open] === "(" && !firstPrefix) {
      firstPrefix = { start: token.index, bodyStart: open + 1 };
    }
    // Do not make the token regex rescan whitespace already classified above.
    tokens.lastIndex = open + (content[open] === "(" ? 1 : 0);
  }
};

function parseShortQuotedArrayElement(
  content: string,
  start: number,
  lineEnd: number,
): number {
  const quote = content[start];
  if (quote !== "'" && quote !== '"') return -1;

  let cursor = start + 1;
  let length = 0;
  while (
    cursor < lineEnd &&
    content[cursor] !== quote &&
    length < 4
  ) {
    cursor += 1;
    length += 1;
  }
  return length >= 1 && content[cursor] === quote ? cursor + 1 : -1;
}

function parseVscodeStringArrayAt(
  content: string,
  start: number,
  lineEnd: number,
): number {
  let cursor = skipVscodePatternWhitespace(content, start + 1);
  cursor = parseShortQuotedArrayElement(content, cursor, lineEnd);
  if (cursor === -1) return -1;

  let elements = 1;
  while (cursor <= lineEnd) {
    cursor = skipVscodePatternWhitespace(content, cursor);
    if (elements >= 21 && content[cursor] === "]") return cursor + 1;
    if (content[cursor] !== ",") return -1;

    cursor = skipVscodePatternWhitespace(content, cursor + 1);
    cursor = parseShortQuotedArrayElement(content, cursor, lineEnd);
    if (cursor === -1) return -1;
    elements = Math.min(21, elements + 1);
  }
  return -1;
}

const vscodeStringArrayMatcher: NonNullable<
  PatternEntry["correlatedMatcher"]
> = function* (content) {
  let lineStart = 0;
  while (lineStart <= content.length) {
    const newline = content.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? content.length : newline;
    let candidate = content.indexOf("[", lineStart);

    while (candidate !== -1 && candidate < lineEnd) {
      const end = parseVscodeStringArrayAt(content, candidate, lineEnd);
      if (end !== -1) {
        yield {
          start: candidate,
          end,
          evidence: truncateMatch(content.slice(candidate, end)),
        };
        break;
      }
      candidate = content.indexOf("[", candidate + 1);
    }

    if (newline === -1) break;
    lineStart = newline + 1;
  }
};

export const VSCODE_STRING_ARRAY_PATTERN: Omit<PatternEntry, "name"> = {
  pattern: "\\[\\s*(?:'[^']{1,4}'|\"[^\"]{1,4}\")\\s*(?:,\\s*(?:'[^']{1,4}'|\"[^\"]{1,4}\")\\s*){20,}\\]",
  description: "Large string array detected (common in obfuscated code)",
  severity: "medium",
  rule: "VSCODE_STRING_ARRAY",
  correlatedMatcher: vscodeStringArrayMatcher,
};

export const VSCODE_ENCODED_BUFFER_PATTERN: Omit<PatternEntry, "name"> = {
  pattern: "\\bBuffer\\.from\\s*\\([^)]+,\\s*['\"](?:base64|hex)['\"]\\s*\\)",
  description: "Encoded buffer construction detected (potential payload decoding)",
  severity: "medium",
  rule: "VSCODE_ENCODED_BUFFER",
  correlatedMatcher: vscodeEncodedBufferMatcher,
};

// Suspicious node APIs frequently abused in malicious extensions
const EXTENSION_DANGER_PATTERNS: Array<Omit<PatternEntry, "name">> = [
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
  VSCODE_ENCODED_BUFFER_PATTERN,
  {
    pattern: "\\batob\\s*\\(|\\bbtoa\\s*\\(",
    description: "Base64 encoding/decoding detected in extension",
    severity: "medium",
    rule: "VSCODE_BASE64",
  },
];

// Patterns indicating obfuscated code
const OBFUSCATION_PATTERNS: Array<Omit<PatternEntry, "name">> = [
  {
    pattern: "(?:_0x[0-9a-fA-F]{4,}\\s*[=\\[,]\\s*){3,}",
    description: "JavaScript obfuscator variable naming pattern detected",
    severity: "high",
    rule: "VSCODE_OBFUSCATED_VARS",
  },
  VSCODE_STRING_ARRAY_PATTERN,
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

validatePatternSet("EXTENSION_DANGER_PATTERNS", EXTENSION_DANGER_PATTERNS);
validatePatternSet("OBFUSCATION_PATTERNS", OBFUSCATION_PATTERNS);

export interface VscodeScanOptions {
  /** .vsix file path or extension ID (publisher.name) */
  target: string;
  /** Output format */
  format: "text" | "json" | "markdown" | "sarif" | "sbom";
  /** Minimum severity to report */
  minSeverity?: Severity;
  /** Registry to resolve extension IDs against (default: marketplace) */
  registry?: VscodeRegistry;
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

  const registry: VscodeRegistry = options.registry ?? "marketplace";
  let extractDir: string | null = null;

  try {
    // If target looks like an extension ID (publisher.name), download from the registry
    if (!vsixPath.endsWith(".vsix") && vsixPath.includes(".")) {
      // Reject URL and path syntax before the identifier is logged or used.
      parseVscodeExtensionId(vsixPath);
      const registryLabel = registry === "openvsx" ? "Open VSX" : "VS Code Marketplace";
      console.error(`  Downloading extension ${vsixPath} from ${registryLabel}...`);
      const downloadDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-vscode-dl-"));
      tempDownload = downloadDir;
      vsixPath = await downloadVsix(vsixPath, downloadDir, registry);
    }

    // Validate the .vsix file exists
    if (!fs.existsSync(vsixPath)) {
      throw new Error(`VSIX file not found: ${vsixPath}`);
    }

    // Extract and scan the vsix (it's a zip)
    extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-vscode-"));

    // VSIX is a zip file. The helper uses an argv array so metacharacters in a
    // user-supplied path are never interpreted by a command shell.
    let archiveExtracted = false;
    try {
      extractZip(vsixPath, extractDir, true);
      archiveExtracted = true;
    } catch (error) {
      // Hostile archives are an expected scanner input, not an operational
      // failure. Do not expose the validator's detail because it can contain a
      // malicious member or link target. Unexpected implementation and I/O
      // errors still propagate to the caller.
      if (!(error instanceof ArchiveSecurityError)) throw error;
      recordUnreadablePath(findings, ".");
    }

    let fileCounts = { totalFiles: 0, filesScanned: 0 };
    if (archiveExtracted) {
      // Collect before manifest analysis so unreadable-directory coverage findings
      // retain their established ordering in the report.
      const allFiles = collectExtractedFiles(extractDir, findings);

      // Scan package.json for suspicious metadata
      scanExtensionManifest(extractDir, allFiles, findings);

      fileCounts = scanExtractedVscodeFiles(
        extractDir,
        findings,
        allFiles,
      );
    }

    // A VSIX whose contents were never opened must not receive an affirmative
    // clean verdict. This is the same contract as npm, PyPI, and directories.
    findings.push(
      ...makePackageCoverageFindings(fileCounts.totalFiles, fileCounts.filesScanned),
    );

    const partialScan = hasPartialScanFinding(findings);

    // Filter by severity
    const filteredFindings = filterFindings(findings, options.minSeverity);

    // Calculate results
    const summary = calculateSummary(fileCounts.totalFiles, fileCounts.filesScanned, filteredFindings);
    const score = calculateScore(filteredFindings);
    const riskLevel = getRiskLevel(score);
    const recommendations = generateVscodeRecommendations(filteredFindings, options.target, partialScan);

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
      partialScan: partialScan || undefined,
    };
  } finally {
    // Cleanup
    if (extractDir) {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
    if (tempDownload) {
      fs.rmSync(tempDownload, { recursive: true, force: true });
    }
  }
}

/**
 * Download a .vsix from the configured registry.
 */
async function downloadVsix(
  extensionId: string,
  destDir: string,
  registry: VscodeRegistry,
): Promise<string> {
  const { publisher } = parseVscodeExtensionId(extensionId);
  const downloadUrl = await resolveVsixDownloadUrl(extensionId, registry);

  // Each acquisition has a private temp directory. A constant basename keeps
  // registry-controlled text out of filesystem path resolution on every OS.
  const vsixPath = path.join(destDir, "extension.vsix");
  // Re-validate the initial URL and every redirect before requesting it.
  const validateHop =
    registry === "openvsx"
      ? (hopUrl: string): void => assertAllowedOpenVsxUrl(hopUrl, "download hop")
      : (hopUrl: string): void =>
          assertAllowedMarketplaceUrl(hopUrl, publisher, "download hop");
  await downloadFile(downloadUrl, vsixPath, validateHop);

  // Verify it's a valid file (at least check size)
  const stat = fs.statSync(vsixPath);
  if (stat.size < 100) {
    const registryLabel = registry === "openvsx" ? "Open VSX registry" : "marketplace";
    throw new Error(
      `Downloaded file is too small (${stat.size} bytes). Extension "${extensionId}" may not exist on the ${registryLabel}.`,
    );
  }

  return vsixPath;
}

/**
 * Resolve the .vsix download URL for an extension ID on a given registry.
 *
 * - marketplace: deterministic gallery.vsassets.io URL pattern (no metadata request)
 * - openvsx: fetches https://open-vsx.org/api/{namespace}/{name} and reads files.download
 *
 * The .vsix analysis itself is registry-agnostic; only this URL construction branches.
 */
export async function resolveVsixDownloadUrl(
  extensionId: string,
  registry: VscodeRegistry = "marketplace",
): Promise<string> {
  const { publisher, name } = parseVscodeExtensionId(extensionId);

  if (registry === "openvsx") {
    const metadata = await fetchOpenVsxMetadata(publisher, name);
    const files = metadata.files as Record<string, unknown> | undefined;
    const download = files?.download;
    if (typeof download !== "string" || download.length === 0) {
      throw new Error(
        `Open VSX metadata for "${extensionId}" does not contain a download URL (files.download).`,
      );
    }
    assertAllowedOpenVsxUrl(download, "download URL (files.download)");
    return download;
  }

  // Use the direct download URL pattern. Identifier parsing excludes URL
  // syntax, and the path segments remain explicitly encoded.
  const marketplaceUrl = new URL(`https://${publisher}.gallery.vsassets.io/`);
  marketplaceUrl.pathname =
    `/_apis/public/gallery/publisher/${encodeURIComponent(publisher)}` +
    `/extension/${encodeURIComponent(name)}` +
    "/latest/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage";
  return marketplaceUrl.toString();
}

/**
 * Fetch extension metadata from the Open VSX registry REST API.
 */
function fetchOpenVsxMetadata(
  namespace: string,
  name: string,
): Promise<Record<string, unknown>> {
  const metadataUrl = `${OPENVSX_API_BASE}/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`;
  return fetchHttpsBuffer(metadataUrl, {
    maxBytes: VSCODE_REMOTE_LIMITS.metadataBytes,
    timeoutMs: VSCODE_REMOTE_LIMITS.timeoutMs,
    maxRedirects: VSCODE_REMOTE_LIMITS.maxRedirects,
    headers: {
      "User-Agent": `supply-chain-guard/${TOOL_VERSION}`,
      Accept: "application/json",
    },
    validateUrl: (hopUrl, { redirectCount }) => {
      assertAllowedOpenVsxUrl(
        hopUrl,
        redirectCount === 0 ? "metadata URL" : "metadata redirect",
      );
    },
  }).then((response) => {
    try {
      return JSON.parse(response.body.toString("utf8")) as Record<string, unknown>;
    } catch {
      throw new Error(`Open VSX returned invalid JSON for ${response.finalUrl}`);
    }
  }).catch((error: unknown) => {
    if (error instanceof RemoteHttpStatusError) {
      if (error.statusCode === 404) {
        throw new Error(
          `Extension "${namespace}.${name}" not found on Open VSX (HTTP 404). Check the extension ID or try --registry marketplace.`,
        );
      }
      throw new Error(
        `Open VSX metadata request failed with status ${error.statusCode ?? "unknown"} for ${error.url}`,
      );
    }
    throw error;
  });
}

function recordOversizedVscodeFile(
  findings: Finding[],
  relativePath: string,
  sizeBytes: number,
): void {
  const publicPath = relativePath.replace(/\\/g, "/");
  if (findings.some((finding) =>
    finding.rule === "FILE_TOO_LARGE_SKIPPED" &&
    (finding.file ?? "").replace(/\\/g, "/") === publicPath
  )) return;
  findings.push(makeOversizedSkipFinding(publicPath, sizeBytes));
}
/**
 * Scan the extension manifest (package.json inside the vsix).
 */
function scanExtensionManifest(
  extractDir: string,
  collectedFiles: readonly string[],
  findings: Finding[],
): void {
  const filesByPublicPath = new Map(
    collectedFiles.map((filePath) => [
      path.relative(extractDir, filePath).replace(/\\/g, "/"),
      filePath,
    ]),
  );

  let relativePath: string | null = null;
  let manifest: Record<string, unknown> | null = null;
  for (const candidate of ["extension/package.json", "package.json"]) {
    const manifestPath = filesByPublicPath.get(candidate);
    if (!manifestPath) continue;
    const content = readContainedExtractedUtf8File(
      extractDir,
      manifestPath,
      findings,
      {
        maxBytes: MAX_FILE_SIZE,
        onOversized: (sizeBytes) =>
          recordOversizedVscodeFile(findings, candidate, sizeBytes),
      },
    );
    if (content === null) continue;
    try {
      manifest = JSON.parse(content) as Record<string, unknown>;
      relativePath = candidate;
      break;
    } catch {
      // Invalid JSON is not an I/O coverage failure.
    }
  }

  if (!manifest || !relativePath) return;
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
  for (const pattern of EXTENSION_DANGER_PATTERNS) {
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
        recommendation: getVscodeRecommendation(pattern.rule),
      });
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
    const hits = matchPatternInFile(
      pattern,
      content,
      relativePath,
      findings,
      "g",
    );
    const hit = hits?.[0];
    if (!hit) continue;

    findings.push({
      rule: pattern.rule,
      description: pattern.description,
      severity: pattern.severity,
      file: relativePath,
      line: hit.line,
      match: truncateMatch(hit.text),
      recommendation: "Obfuscated code in VS Code extensions is a red flag. Legitimate extensions typically ship readable source code.",
    });
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
        recommendation: `Found in VS Code extension. ${pattern.description}`,
      });
    }
  }
}

/**
 * Scan all files shipped inside an extracted VSIX, including bundled
 * dependencies under node_modules. Exported as a portable archive-walker seam.
 */
export function scanExtractedVscodeFiles(
  extractDir: string,
  findings: Finding[],
  collectedFiles?: readonly string[],
): { totalFiles: number; filesScanned: number } {
  const files = collectedFiles ?? collectExtractedFiles(extractDir, findings);
  let filesScanned = 0;
  for (const filePath of files) {
    if (scanExtractedVscodeFile(extractDir, filePath, findings)) {
      filesScanned++;
    }
  }
  return { totalFiles: files.length, filesScanned };
}

/** Scan one extracted VSIX file. Exported for portable I/O coverage tests. */
export function scanExtractedVscodeFile(
  extractDir: string,
  filePath: string,
  findings: Finding[],
): boolean {
  const ext = path.extname(filePath).toLowerCase();
  const relativePath = path.relative(extractDir, filePath);
  if (!SCANNABLE_EXTENSIONS.has(ext)) return false;

  let fileStat: fs.Stats;
  try {
    fileStat = fs.statSync(filePath);
  } catch {
    recordUnreadablePath(findings, relativePath);
    return false;
  }
  if (fileStat.size > MAX_FILE_SIZE) {
    recordOversizedVscodeFile(findings, relativePath, fileStat.size);
    return false;
  }

  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    recordUnreadablePath(findings, relativePath);
    return false;
  }

  checkVscodePatterns(content, relativePath, findings);
  checkObfuscationPatterns(content, relativePath, findings);
  checkGeneralPatterns(content, relativePath, findings);
  return true;
}

/** Filter findings by minimum severity. */
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
  partialScan = false,
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
  if (partialScan) {
    recommendations.unshift(
      "WARNING: Scan incomplete because one or more extension files could not be evaluated. Resolve coverage gaps before treating this extension as safe.",
    );
  }
  if (findings.length === 0 && !partialScan) {
    recommendations.push(
      `No malicious indicators found in "${target}". The extension appears safe based on known patterns.`,
    );
  }

  return recommendations;
}

/**
 * Download a file from a URL, following redirects.
 *
 * When a validateHop callback is given it runs on the initial URL and on
 * every redirect target before the request is made; a thrown error aborts
 * the download (used to pin Open VSX downloads to allowlisted hosts).
 */
function downloadFile(
  url: string,
  dest: string,
  validateHop?: (hopUrl: string) => void,
): Promise<void> {
  return downloadHttpsFile(url, dest, {
    maxBytes: VSCODE_REMOTE_LIMITS.artifactBytes,
    timeoutMs: VSCODE_REMOTE_LIMITS.timeoutMs,
    maxRedirects: VSCODE_REMOTE_LIMITS.maxRedirects,
    headers: {
      "User-Agent": `supply-chain-guard/${TOOL_VERSION}`,
      Accept: "application/octet-stream",
    },
    validateUrl: validateHop
      ? (hopUrl): void => validateHop(hopUrl)
      : undefined,
  }).then(() => undefined).catch((error: unknown) => {
    if (error instanceof RemoteHttpStatusError) {
      throw new Error(
        `Download failed with status ${error.statusCode ?? "unknown"} for ${error.url}`,
      );
    }
    throw error;
  });
}

/**
 * Recursively collect files.
 */
// truncateMatch is imported from patterns.ts (shared with the multi-line engine).
