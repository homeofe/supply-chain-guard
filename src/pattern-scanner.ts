/**
 * One production entry point for PatternEntry file scans.
 *
 * Keeping applicability, regex evaluation, value filtering, and coverage
 * reporting together prevents scanners from giving the same file different
 * verdicts or silently treating an incomplete evaluation as clean.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";
import {
  matchPatternInContent,
  type PatternCoverageLimitation,
  type PatternMatchResult,
} from "./patterns.js";
import {
  isPatternApplicableToFile,
  satisfiesPatternContentRequirement,
} from "./pattern-applicability.js";

export type FilePattern = Pick<
  PatternEntry,
  | "pattern"
  | "rule"
  | "spansLines"
  | "correlatedMatcher"
  | "valueFilter"
  | "valueGroup"
  | "onlyExtensions"
  | "onlyFilePattern"
  | "notFilePattern"
  | "notTestFile"
  | "requiresInFile"
  | "requiresInFileMatcher"
>;

export type PatternMatchOptions = Parameters<typeof matchPatternInContent>[3];

const COVERAGE_LIMITATION_LABELS: Record<PatternCoverageLimitation, string> = {
  "invalid-pattern": "the rule could not be compiled",
  "line-limit": "the pathological physical-line safety limit was reached",
  "regex-attempt-limit": "the pathological pattern-evaluation safety limit was reached",
  "overlong-range-tiled": "an overlong line or logical window required bounded overlapping tiles",
  "matcher-error": "the rule-specific structural matcher failed",
  "invalid-matcher-result": "the structural matcher returned invalid offsets, evidence, or metadata",
};

/**
 * Coverage signals that mean a report is not a complete clean verdict.
 *
 * Keep this intentionally narrow: optional-network posture warnings do not
 * make a scan partial, but a configured source, rule, or deny-list that could
 * not be evaluated does.
 */
export const PARTIAL_SCAN_RULES: ReadonlySet<string> = new Set([
  "FILE_TOO_LARGE_SKIPPED",
  "PATTERN_SCAN_INCOMPLETE",
  "PATH_SCAN_INCOMPLETE",
  "INTERNAL_DISCLOSURE_TRUNCATED",
  "PYPI_NO_SOURCE",
  "NPM_NO_ARTIFACT",
  "INTERNAL_DENYLIST_UNAVAILABLE",
  "INTERNAL_DENYLIST_INVALID_ENTRY",
  "INTERNAL_DENYLIST_REFUSED",
  "POLICY_INVALID_INTERNAL_TERM",
  // A state store that exists but does not parse is a configured source that
  // could not be evaluated, which is the exact test above. Trend, forecast and
  // triage governance silently produce nothing from one, so without these two
  // entries a report reconstructed from JSON would classify itself as a
  // complete clean scan.
  "RISK_HISTORY_UNREADABLE",
  "TRIAGE_STORE_UNREADABLE",
]);

/**
 * Record a filesystem coverage gap without exposing an exception, OS username,
 * or private absolute path in the public report.
 */
export function normalizePublicCoveragePath(relativePath: string): string {
  let normalized = relativePath.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
  const segments = normalized.split("/");
  if (
    normalized.startsWith("/") ||
    /^[A-Za-z]:\//.test(normalized) ||
    segments.includes("..")
  ) {
    return ".";
  }
  normalized = segments.filter((segment) => segment && segment !== ".").join("/");
  return normalized || ".";
}

const unreadablePathsByFindings = new WeakMap<Finding[], Set<string>>();

export function recordUnreadablePath(
  findings: Finding[],
  relativePath: string,
): void {
  const publicPath = normalizePublicCoveragePath(relativePath);
  let seenPaths = unreadablePathsByFindings.get(findings);
  if (seenPaths === undefined) {
    seenPaths = new Set(
      findings
        .filter((finding) => finding.rule === "PATH_SCAN_INCOMPLETE")
        .map((finding) => normalizePublicCoveragePath(finding.file ?? ".")),
    );
    unreadablePathsByFindings.set(findings, seenPaths);
  }
  if (seenPaths.has(publicPath)) return;
  seenPaths.add(publicPath);

  findings.push({
    rule: "PATH_SCAN_INCOMPLETE",
    description:
      "An in-scope path could not be read, enumerated, or reached within the configured depth or traversal-work limit, so its contents were not fully scanned.",
    severity: "info",
    confidence: 1,
    category: "info",
    file: publicPath,
    match: "incomplete path coverage",
    recommendation:
      "Treat this result as partial, not clean. Restore read access or reduce the path shape, then run the scan again.",
  });
}
function isMissingPathError(error: unknown): boolean {
  if (error === null || typeof error !== "object") return false;
  return (error as NodeJS.ErrnoException).code === "ENOENT";
}

export interface OptionalFileReadOptions {
  maxBytes?: number;
  onOversized?: (sizeBytes: number) => void;
}

/**
 * Probe a statically known optional file. Absence is expected; a stat failure
 * for any other reason is an incomplete-coverage finding.
 */
interface ContainedPath {
  realPath: string;
  stat: fs.Stats;
}

/**
 * The containment predicate for the whole scanner: a target is inside a root
 * only when the relative path from the root to it neither is absolute nor
 * climbs out. `startsWith` on the root string would accept a sibling directory
 * that merely shares a prefix, so the relative form is the one to use.
 *
 * Exported because every reader of a caller-named path needs exactly this
 * predicate; a second, slightly different copy is how a containment gap gets
 * reintroduced.
 */
export function isContainedPath(rootRealPath: string, targetRealPath: string): boolean {
  const relative = path.relative(rootRealPath, targetRealPath);
  return relative === "" ||
    (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

/**
 * An optional missing leaf is safe only when its nearest existing lexical
 * ancestor resolves inside the explicit trusted root. This distinguishes a
 * genuinely absent config from a path hidden behind a broken or escaping
 * parent symlink.
 */
export function hasContainedExistingAncestor(
  scanRoot: string,
  absolutePath: string,
): boolean {
  const lexicalRoot = path.resolve(scanRoot);
  const lexicalTarget = path.resolve(absolutePath);
  if (!isContainedPath(lexicalRoot, lexicalTarget)) return false;

  let rootRealPath: string;
  try {
    rootRealPath = fs.realpathSync(lexicalRoot);
  } catch {
    return false;
  }

  let cursor = path.dirname(lexicalTarget);
  while (isContainedPath(lexicalRoot, cursor)) {
    try {
      fs.lstatSync(cursor);
    } catch (error) {
      if (!isMissingPathError(error)) return false;
      if (cursor === lexicalRoot) break;
      const parent = path.dirname(cursor);
      if (parent === cursor) break;
      cursor = parent;
      continue;
    }

    try {
      const ancestorRealPath = fs.realpathSync(cursor);
      return isContainedPath(rootRealPath, ancestorRealPath);
    } catch {
      // The lexical ancestor exists but cannot be resolved. In particular,
      // do not climb past a dangling parent symlink and misclassify the
      // optional leaf as an ordinary absence under the trusted root.
      return false;
    }
  }
  return false;
}
function resolveContainedPath(
  scanRoot: string,
  absolutePath: string,
  relativePath: string,
  findings: Finding[],
  expected: "file" | "directory",
  absenceAllowed: boolean,
): ContainedPath | null {
  try {
    fs.lstatSync(absolutePath);
  } catch (error) {
    const safeOptionalAbsence =
      absenceAllowed &&
      isMissingPathError(error) &&
      hasContainedExistingAncestor(scanRoot, absolutePath);
    if (!safeOptionalAbsence) recordUnreadablePath(findings, relativePath);
    return null;
  }

  try {
    const rootRealPath = fs.realpathSync(scanRoot);
    const realPath = fs.realpathSync(absolutePath);
    if (!isContainedPath(rootRealPath, realPath)) {
      recordUnreadablePath(findings, relativePath);
      return null;
    }
    const stat = fs.statSync(realPath);
    const correctType = expected === "file" ? stat.isFile() : stat.isDirectory();
    if (!correctType) {
      recordUnreadablePath(findings, relativePath);
      return null;
    }
    return { realPath, stat };
  } catch {
    recordUnreadablePath(findings, relativePath);
    return null;
  }
}

export function optionalFileExists(
  scanRoot: string,
  absolutePath: string,
  relativePath: string,
  findings: Finding[],
): boolean {
  return resolveContainedPath(
    scanRoot,
    absolutePath,
    relativePath,
    findings,
    "file",
    true,
  ) !== null;
}

export function readOptionalUtf8File(
  scanRoot: string,
  absolutePath: string,
  relativePath: string,
  findings: Finding[],
  options: OptionalFileReadOptions = {},
): string | null {
  const resolved = resolveContainedPath(
    scanRoot,
    absolutePath,
    relativePath,
    findings,
    "file",
    true,
  );
  if (!resolved) return null;
  if (options.maxBytes !== undefined && resolved.stat.size > options.maxBytes) {
    options.onOversized?.(resolved.stat.size);
    return null;
  }
  try {
    return fs.readFileSync(resolved.realPath, "utf-8");
  } catch {
    recordUnreadablePath(findings, relativePath);
    return null;
  }
}

export function readDiscoveredUtf8File(
  scanRoot: string,
  absolutePath: string,
  relativePath: string,
  findings: Finding[],
  options: OptionalFileReadOptions = {},
): string | null {
  const resolved = resolveContainedPath(
    scanRoot,
    absolutePath,
    relativePath,
    findings,
    "file",
    false,
  );
  if (!resolved) return null;
  if (options.maxBytes !== undefined && resolved.stat.size > options.maxBytes) {
    options.onOversized?.(resolved.stat.size);
    return null;
  }
  try {
    return fs.readFileSync(resolved.realPath, "utf-8");
  } catch {
    recordUnreadablePath(findings, relativePath);
    return null;
  }
}

export function listOptionalDirectory(
  scanRoot: string,
  absolutePath: string,
  relativePath: string,
  findings: Finding[],
): fs.Dirent[] | null {
  const resolved = resolveContainedPath(
    scanRoot,
    absolutePath,
    relativePath,
    findings,
    "directory",
    true,
  );
  if (!resolved) return null;
  try {
    return fs.readdirSync(resolved.realPath, { withFileTypes: true });
  } catch {
    recordUnreadablePath(findings, relativePath);
    return null;
  }
}

export function listDiscoveredDirectory(
  scanRoot: string,
  absolutePath: string,
  relativePath: string,
  findings: Finding[],
): fs.Dirent[] | null {
  const resolved = resolveContainedPath(
    scanRoot,
    absolutePath,
    relativePath,
    findings,
    "directory",
    false,
  );
  if (!resolved) return null;
  try {
    return fs.readdirSync(resolved.realPath, { withFileTypes: true });
  } catch {
    recordUnreadablePath(findings, relativePath);
    return null;
  }
}
export function isPartialScanFinding(
  finding: Pick<Finding, "rule">,
): boolean {
  return PARTIAL_SCAN_RULES.has(finding.rule);
}

export function hasPartialScanFinding(
  findings: ReadonlyArray<Pick<Finding, "rule">>,
): boolean {
  return findings.some(isPartialScanFinding);
}

/**
 * Add one transparency finding per affected file. All rules see the same file
 * shape, so repeating the same limit for every rule would only bury the useful
 * signal in noise.
 */
function recordIncompleteCoverage(
  findings: Finding[],
  relativePath: string,
  patternRule: string,
  result: PatternMatchResult,
): void {
  if (result.coverage.complete) return;
  if (
    findings.some(
      (finding) =>
        finding.rule === "PATTERN_SCAN_INCOMPLETE" &&
        finding.file === relativePath,
    )
  ) {
    return;
  }

  const limitations = result.coverage.limitations
    .map((limitation) => COVERAGE_LIMITATION_LABELS[limitation])
    .join("; ");
  const stoppedAt = result.coverage.stoppedAtLine
    ? ` Coverage stopped at physical line ${result.coverage.stoppedAtLine}.`
    : "";

  findings.push({
    rule: "PATTERN_SCAN_INCOMPLETE",
    description:
      `Pattern scanning was incomplete for this file while evaluating ${patternRule}: ${limitations}.` +
      stoppedAt,
    severity: "info",
    confidence: 1.0,
    category: "info",
    file: relativePath,
    line: result.coverage.stoppedAtLine,
    match: result.coverage.limitations.join(", "),
    recommendation:
      "Treat this result as partial, not clean. Inspect the file manually or reduce its pathological size/line shape so every pattern can be evaluated completely.",
  });
}

/**
 * Evaluate a PatternEntry against text extracted from a known agent-facing
 * field (for example an MCP description or workflow instruction body).
 *
 * File/path gates are intentionally irrelevant after the owning scanner has
 * selected the semantic field. Corroboration, line spans, value filters, and
 * coverage reporting still apply and may not be silently discarded.
 */
export function matchPatternInSemanticText(
  pattern: FilePattern,
  text: string,
  sourcePath: string,
  findings: Finding[],
  flags = "g",
): PatternMatchResult | null {
  if (!satisfiesPatternContentRequirement(pattern, text)) return null;

  const result = matchPatternInContent(pattern, text, flags);
  recordIncompleteCoverage(findings, sourcePath, pattern.rule, result);
  return result;
}
/**
 * Evaluate one pattern against one file with the complete PatternEntry contract.
 * Returns null when file/path metadata intentionally makes the pattern
 * inapplicable. Any safety-bound limitation becomes a deduplicated finding.
 */
export function matchPatternInFile(
  pattern: FilePattern,
  content: string,
  relativePath: string,
  findings: Finding[],
  flags = "g",
  options?: PatternMatchOptions,
): PatternMatchResult | null {
  if (!isPatternApplicableToFile(pattern, content, relativePath)) return null;

  const result = matchPatternInContent(pattern, content, flags, options);
  recordIncompleteCoverage(findings, relativePath, pattern.rule, result);
  return result;
}
