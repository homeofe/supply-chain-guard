/**
 * Known malicious patterns database
 *
 * This file is designed to be regularly updated as new threats emerge.
 * Add new patterns, wallet addresses, or domain patterns as they are discovered.
 */

import type { Finding, PatternEntry, Severity } from "./types.js";
import {
  CORRELATED_PATTERN_MATCHERS,
  hasShaiHuludCredentialFlowSignals,
  maskMixedCommentsPreservingStrings,
  matchCharacterCodeObfuscation,
} from "./correlated-pattern-matchers.js";
import {
  createCoreBroadGapMatchers,
  hasDropperPayloadPreparation,
  hasShaiHuludCorroboration,
} from "./broad-gap-pattern-matchers.js";
import { hasBroadUnboundedConsumingGap } from "./regex-complexity.js";
export { isPatternApplicableToFile } from "./pattern-applicability.js";

/** Matches the scanner's own source files — used to prevent self-scan false positives. */
const SCANNER_SRC = /(?:patterns|scanner|playbooks|correlation-engine|ioc-blocklist|threat-intel|remediation-engine|secret-simulator|workflow-modeler|config-scanner|install-hook-scanner|github-trust-scanner|dependency-confusion|attack-graph|reporter|active-validation|solana-monitor|solana-watchlist|slsa-verifier|sbom-generator)\.(ts|js)$/;

// v5.2.21: documentation files (.md/.markdown/.txt/.rst) legitimately discuss
// malware markers as part of threat-intel write-ups, changelog entries, blog
// posts, and academic research. Patterns that match source-code-embedded
// markers (campaign signatures, IOC strings, infostealer paths, C2 references)
// must skip these to avoid flagging discussion as malware.
//
// Used together with SCANNER_SRC via SCANNER_SRC_OR_DOCS. Patterns whose
// design is to fire on documentation (LURE_PATTERNS, PROMPT_INJECTION_PATTERNS)
// keep plain SCANNER_SRC and stay on their onlyFilePattern scope.
const BENIGN_DOC_FILES = /\.(md|markdown|txt|rst)$/i;
const SCANNER_SRC_OR_DOCS = new RegExp(
  `(?:${SCANNER_SRC.source})|(?:${BENIGN_DOC_FILES.source})`,
  "i",
);

// ---------------------------------------------------------------------------
// Value inspection (v5.18)
// ---------------------------------------------------------------------------

/**
 * Apply a pattern's optional VALUE-level guard to a regex match.
 * Returns true when the match should be reported.
 *
 * Every loop that iterates PatternEntry[] calls this, so a pattern's
 * `valueFilter` can never be silently skipped by one scanner while being
 * honoured by another.
 */
export function isPatternMatchAccepted(
  pattern: Pick<PatternEntry, "valueFilter" | "valueGroup">,
  match: RegExpMatchArray,
): boolean {
  if (!pattern.valueFilter) return true;
  return pattern.valueFilter(match[pattern.valueGroup ?? 1] ?? "");
}

// ---------------------------------------------------------------------------
// Bounded multi-line pattern engine (v5.23)
// ---------------------------------------------------------------------------

/**
 * Hard cap on PatternEntry.spansLines. Larger windows approach whole-file
 * matching and reintroduce the false-positive class that v5.22 removed.
 * Validated at module load.
 */
export const MAX_SPANS_LINES = 20;

/**
 * Character budget for unvalidated regex invocations. Shipped broad-gap rules
 * use exact structural matchers. Load-validated, single-line regexes without a
 * broad unbounded consuming gap run exactly over the admitted line; unvalidated
 * callers retain transparent bounded tiling and explicit partial coverage.
 */
export const MAX_SPAN_WINDOW_CHARS = 4096;

const EXACT_VALIDATED_SINGLE_LINE_PATTERNS = new WeakSet<object>();

/**
 * Overlap between adjacent regex tiles. Any match shorter than or equal to the
 * overlap is fully visible in at least one tile, including matches that cross a
 * tile boundary. Unbounded matches whose endpoints are farther apart cannot be
 * proven equivalent to whole-window matching, so the result reports partial
 * coverage whenever tiling is required.
 */
export const PATTERN_TILE_OVERLAP_CHARS = 2048;

/**
 * A file below MAX_FILE_SIZE can still contain millions of one-character
 * physical lines. That shape is not normal source code and multiplying it by
 * every registered rule would make the scanner itself a denial-of-service
 * target. Ordinary files retain full coverage; pathological files report the
 * exact line where coverage stopped through PatternMatchResult.coverage.
 */
export const MAX_PHYSICAL_LINES_PER_PATTERN = 250_000;

/**
 * Secondary ceiling for tiled regex invocations. This is deliberately above
 * MAX_PHYSICAL_LINES_PER_PATTERN so normal one-tile-per-line scans never hit
 * it. It only protects oversized/hostile inputs with many long tiled ranges.
 */
export const MAX_MATCH_ATTEMPTS_PER_PATTERN = 300_000;

/** One accepted match of a pattern against file content. */
export interface PatternHit {
  /** 1-based line number where the match STARTS. */
  line: number;
  /** Raw regex text or bounded structural evidence for reports. */
  text: string;
  /** Full regex match array (for valueFilter / capture groups). */
  match: RegExpMatchArray;
}

export type PatternCoverageLimitation =
  | "invalid-pattern"
  | "line-limit"
  | "regex-attempt-limit"
  | "overlong-range-tiled"
  | "matcher-error"
  | "invalid-matcher-result";

/**
 * Coverage information for one pattern evaluation.
 *
 * `complete` means the result is exactly equivalent to evaluating every
 * logical line/window in full. It is false when work was omitted or when an
 * overlong range had to be tiled: tiling sees late and boundary-crossing
 * triggers, but no finite overlap can prove equivalence for an unbounded `.*`.
 */
export interface PatternMatchCoverage {
  complete: boolean;
  limitations: PatternCoverageLimitation[];
  regexAttempts: number;
  totalLines: number;
  /** First physical line whose logical window was not fully evaluated. */
  stoppedAtLine?: number;
  /** Number of overlong logical ranges inspected with overlapping tiles. */
  tiledRanges: number;
}

/**
 * Array-compatible return value. Existing callers can keep iterating hits,
 * while coverage-sensitive callers must inspect `.coverage` and surface a
 * partial scan instead of silently treating omitted work as clean.
 */
export type PatternMatchResult = PatternHit[] & {
  readonly coverage: PatternMatchCoverage;
};

/**
 * Truncate a match string for display in SARIF, JSON and annotations.
 * Multi-line hits are collapsed to a single readable line so a whole window
 * cannot leak into a report. Invisible Unicode is rendered as a code point so
 * evidence never disappears into an empty string.
 */
export function truncateMatch(match: string, maxLen = 120): string {
  let readable = "";
  for (const char of match) {
    const codePoint = char.codePointAt(0)!;
    if (char === " " || char === "\t" || char === "\r" || char === "\n" ||
        char === "\f" || char === "\v") {
      readable += " ";
    } else if (/\s/u.test(char) || /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(char)) {
      readable += `<U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}>`;
    } else {
      readable += char;
    }
  }

  const collapsed = readable.replace(/ +/g, " ").trim();
  if (collapsed.length === 0 && match.length > 0) {
    return "<invisible Unicode>";
  }
  if (collapsed.length <= maxLen) return collapsed;
  return collapsed.substring(0, maxLen) + "...";
}

interface IndexedPatternContent {
  content: string;
  lineStarts: number[];
  lineEnds: number[];
  totalLines: number;
}

// Scanners evaluate many rules sequentially against the same immutable string.
// Keep only the most recent bounded line index so each file is indexed once
// rather than allocating a fresh `content.split("\n")` array for every pattern.
let cachedPatternContent: IndexedPatternContent | undefined;

function indexPatternContent(content: string): IndexedPatternContent {
  if (cachedPatternContent?.content === content) return cachedPatternContent;

  const lineStarts: number[] = [];
  const lineEnds: number[] = [];
  const storedLineLimit = MAX_PHYSICAL_LINES_PER_PATTERN + MAX_SPANS_LINES;
  let start = 0;
  let totalLines = 0;
  while (true) {
    const newline = content.indexOf("\n", start);
    if (lineStarts.length < storedLineLimit) {
      lineStarts.push(start);
      lineEnds.push(newline === -1 ? content.length : newline);
    }
    totalLines++;
    if (newline === -1) break;
    start = newline + 1;
  }

  cachedPatternContent = { content, lineStarts, lineEnds, totalLines };
  return cachedPatternContent;
}

function createPatternMatchResult(totalLines: number): PatternMatchResult {
  const result = [] as PatternHit[] as PatternMatchResult;
  Object.defineProperty(result, "coverage", {
    value: {
      complete: true,
      limitations: [],
      regexAttempts: 0,
      totalLines,
      tiledRanges: 0,
    } satisfies PatternMatchCoverage,
    enumerable: false,
  });
  return result;
}

function addCoverageLimitation(
  coverage: PatternMatchCoverage,
  limitation: PatternCoverageLimitation,
): void {
  coverage.complete = false;
  if (!coverage.limitations.includes(limitation)) {
    coverage.limitations.push(limitation);
  }
}

/** Map an absolute character offset to its containing physical line. */
function lineIndexAtOffset(lineStarts: number[], offset: number): number {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low <= high) {
    const middle = (low + high) >>> 1;
    if (lineStarts[middle]! <= offset) {
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return Math.max(0, high);
}

/** Maximum evidence a structural matcher may place in a report hit. */
export const MAX_CORRELATED_EVIDENCE_CHARS = 240;

function evaluateCorrelatedPattern(
  pattern: Pick<
    PatternEntry,
    "spansLines" | "valueFilter" | "valueGroup" | "correlatedMatcher"
  >,
  content: string,
  indexed: IndexedPatternContent,
  hits: PatternMatchResult,
  seenStartLines: Set<number>,
  spans: number,
  options?: {
    skipLine?: (line: string, index: number) => boolean;
  },
): PatternMatchResult {
  const matcher = pattern.correlatedMatcher!;
  const lineLimit = Math.min(
    indexed.totalLines,
    MAX_PHYSICAL_LINES_PER_PATTERN,
  );

  // A start on the last admitted line may legitimately consume the remainder
  // of its spansLines window. Keep that bounded look-ahead, but never accept a
  // match whose start is beyond the admitted physical-line limit.
  const lastAdmittedLine = Math.min(
    indexed.totalLines - 1,
    lineLimit + spans - 2,
  );
  const admittedEnd = lastAdmittedLine + 1 < indexed.totalLines
    ? indexed.lineStarts[lastAdmittedLine + 1]!
    : content.length;
  const admittedContent = content.slice(0, admittedEnd);

  // Structural matches do not expose regex capture groups. Refuse an
  // incompatible valueFilter loudly instead of silently bypassing it.
  if (pattern.valueFilter) {
    addCoverageLimitation(hits.coverage, "invalid-matcher-result");
  } else {
    hits.coverage.regexAttempts++;
    let yielded = 0;
    try {
      for (const candidate of matcher(admittedContent)) {
        yielded++;
        if (yielded > MAX_MATCH_ATTEMPTS_PER_PATTERN) {
          addCoverageLimitation(hits.coverage, "regex-attempt-limit");
          hits.coverage.stoppedAtLine = 1;
          break;
        }

        if (
          !Number.isInteger(candidate.start) ||
          !Number.isInteger(candidate.end) ||
          candidate.start < 0 ||
          candidate.end <= candidate.start ||
          candidate.end > admittedContent.length ||
          typeof candidate.evidence !== "string" ||
          candidate.evidence.length === 0 ||
          candidate.evidence.length > MAX_CORRELATED_EVIDENCE_CHARS
        ) {
          addCoverageLimitation(hits.coverage, "invalid-matcher-result");
          continue;
        }

        const startLineIndex = lineIndexAtOffset(
          indexed.lineStarts,
          candidate.start,
        );
        if (startLineIndex >= lineLimit) continue;

        const endLineIndex = lineIndexAtOffset(
          indexed.lineStarts,
          candidate.end - 1,
        );
        if (endLineIndex - startLineIndex + 1 > spans) continue;

        const startLine = startLineIndex + 1;
        if (seenStartLines.has(startLine)) continue;
        const skipped = options?.skipLine?.(
          content.slice(
            indexed.lineStarts[startLineIndex]!,
            indexed.lineEnds[startLineIndex]!,
          ),
          startLineIndex,
        ) ?? false;
        if (skipped) continue;

        const syntheticMatch = [candidate.evidence] as unknown as RegExpMatchArray;
        syntheticMatch.index = candidate.start;
        syntheticMatch.input = admittedContent;

        seenStartLines.add(startLine);
        hits.push({
          line: startLine,
          text: candidate.evidence,
          match: syntheticMatch,
        });
      }
    } catch {
      // A custom matcher is production code, but fail closed if it throws or
      // returns a non-iterable value. Other rules must still run.
      addCoverageLimitation(hits.coverage, "matcher-error");
    }
  }

  if (indexed.totalLines > MAX_PHYSICAL_LINES_PER_PATTERN) {
    addCoverageLimitation(hits.coverage, "line-limit");
    hits.coverage.stoppedAtLine = MAX_PHYSICAL_LINES_PER_PATTERN + 1;
  }

  return hits;
}
const TILE_CONTEXT_CHARS = 1;
const TILE_CORE_CHARS = MAX_SPAN_WINDOW_CHARS - (TILE_CONTEXT_CHARS * 2);
const TILE_STEP_CHARS = TILE_CORE_CHARS - PATTERN_TILE_OVERLAP_CHARS;

interface OwnedRegexMatch {
  match: RegExpMatchArray;
  absoluteStart: number;
}

interface RegexBoundarySensitivity {
  mayInspectLeft: boolean;
  mayInspectRight: boolean;
}

/**
 * Identify assertions that can observe a truncated tile boundary without
 * consuming up to it. Anchors inside character classes and escaped literals
 * are ignored. A non-final/non-initial tile with one of these assertions is
 * accepted only where the boundary can be validated safely.
 */
function analyzeRegexBoundarySensitivity(source: string): RegexBoundarySensitivity {
  let inCharacterClass = false;
  let mayInspectLeft = false;
  let mayInspectRight = false;
  for (let index = 0; index < source.length; index++) {
    const char = source[index]!;
    if (char === "\\") {
      index++;
      continue;
    }
    if (char === "[") {
      inCharacterClass = true;
      continue;
    }
    if (char === "]" && inCharacterClass) {
      inCharacterClass = false;
      continue;
    }
    if (inCharacterClass) continue;
    if (char === "^") mayInspectLeft = true;
    else if (char === "$") mayInspectRight = true;
    else if (source.startsWith("(?<=", index) || source.startsWith("(?<!", index)) {
      mayInspectLeft = true;
    } else if (source.startsWith("(?=", index) || source.startsWith("(?!", index)) {
      mayInspectRight = true;
    }
    if (mayInspectLeft && mayInspectRight) break;
  }
  return { mayInspectLeft, mayInspectRight };
}

/**
 * Execute a regex against one bounded tile and return its first match whose
 * start belongs to that tile. Adjacent context plus assertion-sensitivity
 * guards prevent a truncated slice from inventing ^/$/lookaround semantics.
 */
function firstOwnedMatch(
  regex: RegExp,
  input: string,
  inputStart: number,
  ownedStart: number,
  ownedEnd: number,
  continuation: string,
  artificialStart: boolean,
  boundarySensitivity: RegexBoundarySensitivity,
  accept: (match: RegExpMatchArray, absoluteStart: number) => boolean,
): OwnedRegexMatch | undefined {
  regex.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    if (match[0] === "") {
      // Empty matches are not findings. Advance explicitly so a global regex
      // cannot loop forever at the same index.
      regex.lastIndex = Math.max(regex.lastIndex, (match.index ?? 0) + 1);
      continue;
    }

    const localEnd = (match.index ?? 0) + match[0].length;
    const touchesArtificialEof = continuation.length > 0 && (
      localEnd === input.length ||
      (!regex.multiline && (
        (localEnd === input.length - 1 && /[\n\r\u2028\u2029]/u.test(input.at(-1) ?? "")) ||
        (localEnd === input.length - 2 && input.endsWith("\r\n"))
      ))
    );
    if (
      (artificialStart && boundarySensitivity.mayInspectLeft) ||
      (continuation.length > 0 && boundarySensitivity.mayInspectRight)
    ) {
      // An anchor or lookaround may have inspected a truncated side even when
      // the consumed match ends elsewhere. The overlong range is already
      // reported as partial; dropping the unverifiable candidate prevents a
      // synthetic-boundary false positive.
      continue;
    }
    if (touchesArtificialEof) {
      // Re-run only this boundary candidate with real following content. A
      // fixed match remains byte-for-byte identical; a greedy match or local
      // boundary assertion changes or disappears when the slice is extended.
      const resumeAt = regex.lastIndex;
      regex.lastIndex = match.index ?? 0;
      const probe = regex.exec(input + continuation);
      regex.lastIndex = resumeAt;
      if (
        !probe ||
        (probe.index ?? 0) !== (match.index ?? 0) ||
        probe[0] !== match[0]
      ) {
        continue;
      }
      // The same full match can legitimately expose different captures once
      // real following context is present (for example, a word-boundary
      // alternation). Acceptance/valueFilter must observe the real-context
      // result, not captures produced at synthetic EOF.
      match = probe;
    }

    const absoluteStart = inputStart + (match.index ?? 0);
    if (
      absoluteStart >= ownedStart &&
      absoluteStart < ownedEnd &&
      accept(match, absoluteStart)
    ) {
      return { match, absoluteStart };
    }
  }
  return undefined;
}

/**
 * Match a single pattern against file content using a bounded sliding line
 * window.
 *
 * - `spansLines` defaults to 1: inspect one physical line at a time.
 * - `spansLines` > 1: inspect that many consecutive lines with the `s`
 *   (dotAll) flag so `.*` can bridge ideas inside the window, then slide by one
 *   line. Findings are deduplicated by start-line so overlapping windows do
 *   not emit the same hit twice.
 * - Shipped broad-gap rules use exact structural matchers over admitted
 *   content. Load-validated safe single-line regexes run over the exact line;
 *   unvalidated or multi-line regex callers use overlapping bounded tiles and
 *   receive an explicit partial-coverage signal.
 *
 * Regex evaluation always applies `isPatternMatchAccepted` (valueFilter). Structural
 * matcher metadata forbids valueFilter because it has no regex capture groups. Callers own
 * `isPatternApplicableToFile` and path/extension filters - those are
 * file-level and must run before this.
 *
 * @param flags Base regex flags. `g` is always enforced for lastIndex hygiene;
 *   `s` is added automatically when spansLines > 1.
 */
export function matchPatternInContent(
  pattern: Pick<PatternEntry, "pattern" | "spansLines" | "valueFilter" | "valueGroup" | "correlatedMatcher">,
  content: string,
  flags = "g",
  options?: {
    /** Skip a physical line before matching (e.g. config-file comments). */
    skipLine?: (line: string, index: number) => boolean;
  },
): PatternMatchResult {
  const rawSpans = pattern.spansLines ?? 1;
  const spans = Math.max(1, Math.min(rawSpans, MAX_SPANS_LINES));
  const indexed = indexPatternContent(content);
  const { lineStarts, lineEnds } = indexed;
  const hits = createPatternMatchResult(indexed.totalLines);
  const seenStartLines = new Set<number>();

  // Build flags: always global; add dotAll only inside multi-line windows.
  let useFlags = flags.includes("g") ? flags : flags + "g";
  if (spans > 1 && !useFlags.includes("s")) useFlags += "s";

  let regex: RegExp;
  try {
    regex = new RegExp(pattern.pattern, useFlags);
  } catch {
    // Load-time validation should have caught this. Keep later rules alive but
    // make the failed evaluation explicit to coverage-sensitive callers.
    addCoverageLimitation(hits.coverage, "invalid-pattern");
    return hits;
  }

  const boundarySensitivity = analyzeRegexBoundarySensitivity(regex.source);

  if (pattern.correlatedMatcher) {
    return evaluateCorrelatedPattern(
      pattern,
      content,
      indexed,
      hits,
      seenStartLines,
      spans,
      options,
    );
  }

  const lineLimit = Math.min(indexed.totalLines, MAX_PHYSICAL_LINES_PER_PATTERN);
  for (let i = 0; i < lineLimit; i++) {
    const rangeStart = lineStarts[i]!;
    const lastLineIndex = spans === 1
      ? i
      : Math.min(i + spans - 1, indexed.totalLines - 1);
    const rangeEnd = lineEnds[lastLineIndex]!;

    if (spans === 1 && options?.skipLine) {
      const line = content.slice(rangeStart, rangeEnd);
      if (options.skipLine(line, i)) continue;
    }

    const rangeLength = rangeEnd - rangeStart;
    if (rangeLength === 0) continue;
    const exactValidatedSingleLine =
      spans === 1 && EXACT_VALIDATED_SINGLE_LINE_PATTERNS.has(pattern);
    const tiled =
      !exactValidatedSingleLine && rangeLength > MAX_SPAN_WINDOW_CHARS;
    if (tiled) {
      hits.coverage.tiledRanges++;
      addCoverageLimitation(hits.coverage, "overlong-range-tiled");
    }

    let coreStart = rangeStart;
    while (coreStart < rangeEnd) {
      if (hits.coverage.regexAttempts >= MAX_MATCH_ATTEMPTS_PER_PATTERN) {
        addCoverageLimitation(hits.coverage, "regex-attempt-limit");
        hits.coverage.stoppedAtLine = i + 1;
        return hits;
      }

      const coreEnd = tiled
        ? Math.min(rangeEnd, coreStart + TILE_CORE_CHARS)
        : rangeEnd;
      const finalTile = coreEnd === rangeEnd;
      const ownedEnd = finalTile
        ? rangeEnd
        : Math.min(rangeEnd, coreStart + TILE_STEP_CHARS);
      const inputStart = coreStart === rangeStart
        ? coreStart
        : coreStart - TILE_CONTEXT_CHARS;
      const inputEnd = finalTile
        ? coreEnd
        : Math.min(rangeEnd, coreEnd + TILE_CONTEXT_CHARS);
      const input = content.slice(inputStart, inputEnd);

      hits.coverage.regexAttempts++;
      const owned = firstOwnedMatch(
        regex,
        input,
        inputStart,
        coreStart,
        ownedEnd,
        finalTile ? "" : content.slice(inputEnd, Math.min(rangeEnd, inputEnd + 2)),
        inputStart > rangeStart,
        boundarySensitivity,
        (candidate, absoluteStart) => {
          const startLineIndex = spans === 1
            ? i
            : lineIndexAtOffset(lineStarts, absoluteStart);
          const startLine = startLineIndex + 1;
          if (seenStartLines.has(startLine)) return false;

          const skipped = options?.skipLine?.(
            content.slice(lineStarts[startLineIndex]!, lineEnds[startLineIndex]!),
            startLineIndex,
          ) ?? false;
          return !skipped && isPatternMatchAccepted(pattern, candidate);
        },
      );
      if (owned) {
        const startLineIndex = spans === 1
          ? i
          : lineIndexAtOffset(lineStarts, owned.absoluteStart);
        const startLine = startLineIndex + 1;
        seenStartLines.add(startLine);
        hits.push({
          line: startLine,
          text: owned.match[0],
          match: owned.match,
        });
      }

      if (finalTile) break;
      coreStart += TILE_STEP_CHARS;
    }
  }

  if (indexed.totalLines > MAX_PHYSICAL_LINES_PER_PATTERN) {
    addCoverageLimitation(hits.coverage, "line-limit");
    hits.coverage.stoppedAtLine = MAX_PHYSICAL_LINES_PER_PATTERN + 1;
  }

  return hits;
}

// ---------------------------------------------------------------------------
// Near-linear single-line matchers for repeated-prefix regex rules
// ---------------------------------------------------------------------------

const LINEAR_EVIDENCE_CHARS = 240;
type StructuralMatch = ReturnType<NonNullable<PatternEntry["correlatedMatcher"]>> extends Iterable<infer T> ? T : never;

function makeStructuralMatch(content: string, start: number, end: number): StructuralMatch {
  const raw = content.slice(start, end);
  if (raw.length <= LINEAR_EVIDENCE_CHARS) return { start, end, evidence: raw };
  const marker = " ... ";
  const remaining = LINEAR_EVIDENCE_CHARS - marker.length;
  const left = Math.ceil(remaining / 2);
  return {
    start,
    end,
    evidence: raw.slice(0, left) + marker + raw.slice(raw.length - (remaining - left)),
  };
}

const isDotLineTerminator = (value: string): boolean =>
  value === "\r" || value === "\u2028" || value === "\u2029";
const isPatternWhitespace = (value: string | undefined): boolean =>
  value !== undefined && /\s/u.test(value);

/**
 * Skip the whitespace visible to a regex invocation on one physical line.
 * LF is the engine's physical-line delimiter and is not part of that input;
 * standalone CR/U+2028/U+2029 remain visible and may be consumed by `\s`.
 */
function skipPatternWhitespace(
  content: string,
  start: number,
): { end: number; crossedDotLineTerminator: boolean } {
  let index = start;
  let crossedDotLineTerminator = false;
  while (content[index] !== "\n" && isPatternWhitespace(content[index])) {
    if (isDotLineTerminator(content[index]!)) crossedDotLineTerminator = true;
    index++;
  }
  return { end: index, crossedDotLineTerminator };
}

function commandPipeExecutableLength(content: string, start: number): number {
  const tail = content.slice(start, start + 4).toLowerCase();
  if (tail.startsWith("bash") || tail.startsWith("node")) return 4;
  return tail.startsWith("sh") ? 2 : 0;
}

function makeCommandPipeMatcher(command: "curl" | "wget"): NonNullable<PatternEntry["correlatedMatcher"]> {
  return (content) => {
    const token = new RegExp(`${command}|\\||\\n|[\\r\\u2028\\u2029]`, "gi");
    const results: StructuralMatch[] = [];
    let commandStart = -1;
    let best: { start: number; end: number } | undefined;
    const flushPhysicalLine = (): void => {
      if (best) results.push(makeStructuralMatch(content, best.start, best.end));
      best = undefined;
      commandStart = -1;
    };
    let event: RegExpExecArray | null;
    while ((event = token.exec(content)) !== null) {
      const value = event[0]!;
      if (value === "\n") {
        flushPhysicalLine();
        continue;
      }
      if (isDotLineTerminator(value)) {
        commandStart = -1;
        continue;
      }
      if (value !== "|") {
        const whitespace = skipPatternWhitespace(content, event.index + value.length);
        if (whitespace.end > event.index + value.length) {
          if (commandStart === -1 || whitespace.crossedDotLineTerminator) {
            commandStart = event.index;
          }
          // Whitespace swallowed by `\s+` cannot also act as an `.*` barrier.
          token.lastIndex = whitespace.end;
        }
        continue;
      }
      if (commandStart === -1) continue;
      const whitespace = skipPatternWhitespace(content, event.index + 1);
      const length = commandPipeExecutableLength(content, whitespace.end);
      if (length > 0) {
        const candidate = { start: commandStart, end: whitespace.end + length };
        if (
          !best ||
          candidate.start < best.start ||
          (candidate.start === best.start && candidate.end > best.end)
        ) {
          best = candidate;
        }
      }
    }
    flushPhysicalLine();
    return results;
  };
}

const scriptCurlExecMatcher = makeCommandPipeMatcher("curl");
const scriptWgetExecMatcher = makeCommandPipeMatcher("wget");

const codecovCurlBashMatcher: NonNullable<PatternEntry["correlatedMatcher"]> = (content) => {
  const token = /curl|codecov\.io|\||\n/g;
  const results: StructuralMatch[] = [];
  let curlStart = -1;
  let sawCodecov = false;
  let best: { start: number; end: number } | undefined;
  const record = (start: number, end: number): void => {
    if (
      !best ||
      start < best.start ||
      (start === best.start && end > best.end)
    ) {
      best = { start, end };
    }
  };
  const flushPhysicalLine = (): void => {
    if (best) results.push(makeStructuralMatch(content, best.start, best.end));
    best = undefined;
    curlStart = -1;
    sawCodecov = false;
  };
  let event: RegExpExecArray | null;
  while ((event = token.exec(content)) !== null) {
    const value = event[0]!;
    if (value === "\n") {
      flushPhysicalLine();
      continue;
    }
    if (value === "curl") {
      const whitespace = skipPatternWhitespace(content, event.index + value.length);
      if (whitespace.end > event.index + value.length) {
        if (curlStart === -1) curlStart = event.index;
        token.lastIndex = whitespace.end;
      }
    } else if (value === "codecov.io") {
      if (curlStart !== -1) sawCodecov = true;
    } else {
      if (curlStart !== -1 && sawCodecov) {
        const whitespace = skipPatternWhitespace(content, event.index + 1);
        const tail = content.slice(whitespace.end, whitespace.end + 4);
        const length = tail.startsWith("bash") ? 4 : tail.startsWith("sh") ? 2 : 0;
        if (length > 0) {
          record(curlStart, whitespace.end + length);
        }
      }
      // Both [^|]* segments stop at every pipe, successful or not.
      curlStart = -1;
      sawCodecov = false;
    }
  }
  flushPhysicalLine();
  return results;
};

const uaParserMinerMatcher: NonNullable<PatternEntry["correlatedMatcher"]> = (content) => {
  // Keep the marker alternative in source-regex order. At
  // `jsextension.exe`, JavaScript selects the earlier `jsextension` branch.
  const token = /jsextension|jsextension\.exe|__package\.json|https?:\/\/|curl|wget|\n|[\r\u2028\u2029]/g;
  const results: StructuralMatch[] = [];
  let markerStart = -1;
  let transportStart = -1;
  let best: { start: number; end: number } | undefined;
  const record = (start: number, end: number): void => {
    if (
      !best ||
      start < best.start ||
      (start === best.start && end > best.end)
    ) {
      best = { start, end };
    }
  };
  const resetDotSegment = (): void => {
    markerStart = -1;
    transportStart = -1;
  };
  const flushPhysicalLine = (): void => {
    if (best) results.push(makeStructuralMatch(content, best.start, best.end));
    best = undefined;
    resetDotSegment();
  };
  let event: RegExpExecArray | null;
  while ((event = token.exec(content)) !== null) {
    const value = event[0]!;
    if (value === "\n") {
      flushPhysicalLine();
      continue;
    }
    if (isDotLineTerminator(value)) {
      resetDotSegment();
      continue;
    }
    if (value === "jsextension.exe" || value === "jsextension" || value === "__package.json") {
      if (transportStart !== -1) {
        record(transportStart, event.index + value.length);
      }
      if (markerStart === -1) markerStart = event.index;
    } else {
      if (markerStart !== -1) {
        record(markerStart, event.index + value.length);
      }
      if (transportStart === -1) transportStart = event.index;
    }
  }
  flushPhysicalLine();
  return results;
};

const binaryDirectDownloadMatcher: NonNullable<PatternEntry["correlatedMatcher"]> = (content) => {
  const token = /curl|wget|\.(?:dylib|node|dll|exe|so)|\n|[\r\u2028\u2029]/gi;
  const results: StructuralMatch[] = [];
  let commandStart = -1;
  let best: { start: number; end: number } | undefined;
  const record = (start: number, end: number): void => {
    if (
      !best ||
      start < best.start ||
      (start === best.start && end > best.end)
    ) {
      best = { start, end };
    }
  };
  const flushPhysicalLine = (): void => {
    if (best) results.push(makeStructuralMatch(content, best.start, best.end));
    best = undefined;
    commandStart = -1;
  };
  let event: RegExpExecArray | null;
  while ((event = token.exec(content)) !== null) {
    const value = event[0]!;
    if (value === "\n") {
      flushPhysicalLine();
      continue;
    }
    if (isDotLineTerminator(value)) {
      commandStart = -1;
      continue;
    }
    const lower = value.toLowerCase();
    if (lower === "curl" || lower === "wget") {
      const whitespace = skipPatternWhitespace(content, event.index + value.length);
      if (whitespace.end > event.index + value.length) {
        if (commandStart === -1 || whitespace.crossedDotLineTerminator) {
          commandStart = event.index;
        }
        token.lastIndex = whitespace.end;
      }
      continue;
    }
    if (commandStart === -1) continue;
    const next = content[event.index + value.length];
    if (next === undefined || next === "\n" || isPatternWhitespace(next) || next === '"' || next === "'") {
      const consumesSuffix = next !== undefined && next !== "\n";
      record(commandStart, event.index + value.length + (consumesSuffix ? 1 : 0));
    }
  }
  flushPhysicalLine();
  return results;
};

const MINER_POOL_LABEL_SOURCE =
  "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const MINER_POOL_KNOWN_DOMAIN_CORE =
  `(?:${MINER_POOL_LABEL_SOURCE}\\.)*` +
  "(?:nanopool|ethermine|f2pool|viabtc|antpool|poolin|slushpool|nicehash|minergate|hashflare|2miners|flexpool|ezil|hiveon)\\.(?:com|org|net|io)";
const MINER_POOL_GENERIC_DOMAIN_CORE =
  "(?:pool|mining|mine|hashrate)\\." +
  `(?:${MINER_POOL_LABEL_SOURCE}\\.)+` +
  "(?:com|org|net|io)";
const MINER_POOL_DOMAIN_SOURCE =
  "(?<![A-Za-z0-9_.-])" +
  "(?=[A-Za-z0-9.-]{1,253}(?![A-Za-z0-9_.-]))" +
  `(?:${MINER_POOL_KNOWN_DOMAIN_CORE}|${MINER_POOL_GENERIC_DOMAIN_CORE})` +
  "(?![A-Za-z0-9_.-])";
const MINER_POOL_KNOWN_DOMAIN =
  new RegExp(`^(?:${MINER_POOL_KNOWN_DOMAIN_CORE})$`, "i");
const MINER_POOL_CONTEXT_SOURCE =
  "\\b(?:stratum|xmrig|cpuminer|minerd|coinhive|cryptonight|randomx|pool_address|pool_password|mining_address)\\b";
const MINER_POOL_CONTEXT_MAX_GAP = 512;

const minerPoolDomainMatcher: NonNullable<PatternEntry["correlatedMatcher"]> = (content) => {
  const domain = new RegExp(MINER_POOL_DOMAIN_SOURCE, "gi");
  const context = new RegExp(MINER_POOL_CONTEXT_SOURCE, "gi");
  const results: StructuralMatch[] = [];
  const contextContent = maskMixedCommentsPreservingStrings(content);
  let lineStart = 0;

  while (lineStart <= content.length) {
    const newline = content.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? content.length : newline;
    const searchableLine = contextContent.slice(lineStart, lineEnd);
    domain.lastIndex = 0;
    context.lastIndex = 0;
    let contextEvent = context.exec(searchableLine);
    let latestContextEnd = Number.NEGATIVE_INFINITY;

    let event: RegExpExecArray | null;
    while ((event = domain.exec(searchableLine)) !== null) {
      const domainStart = event.index;
      const domainEnd = domainStart + event[0].length;
      let hasNearbyMiningContext =
        domainStart - latestContextEnd <= MINER_POOL_CONTEXT_MAX_GAP;

      while (
        !hasNearbyMiningContext &&
        contextEvent !== null &&
        contextEvent.index <= domainEnd + MINER_POOL_CONTEXT_MAX_GAP
      ) {
        const contextStart = contextEvent.index;
        const contextEnd = contextStart + contextEvent[0].length;
        const intervalGap = Math.max(
          domainStart - contextEnd,
          contextStart - domainEnd,
          0,
        );
        hasNearbyMiningContext = intervalGap <= MINER_POOL_CONTEXT_MAX_GAP;
        latestContextEnd = Math.max(latestContextEnd, contextEnd);
        contextEvent = context.exec(searchableLine);
      }

      if (MINER_POOL_KNOWN_DOMAIN.test(event[0]) || hasNearbyMiningContext) {
        const start = lineStart + event.index;
        results.push(
          makeStructuralMatch(content, start, start + event[0].length),
        );
        break;
      }
    }

    if (newline === -1) break;
    lineStart = newline + 1;
  }
  return results;
};

const STRONG_MINING_CONFIG_KEYS = new Set([
  "pool_address",
  "pool_password",
  "mining_address",
]);
const WEAK_MINING_CONFIG_KEY_BITS = new Map([
  ["wallet", 1 << 0],
  ["worker", 1 << 1],
  ["hashrate", 1 << 2],
  ["coin", 1 << 3],
  ["algo", 1 << 4],
]);
const MINING_CONFIG_SCOPE_REPORTED = 1 << 8;

interface QuotedMiningConfigToken {
  end: number;
  value?: string;
}

/**
 * Read one quoted token without interpreting escaped spellings as key names.
 * The returned end is always monotonic, including for an unclosed string.
 */
function readQuotedMiningConfigToken(
  content: string,
  start: number,
  quote: string,
): QuotedMiningConfigToken {
  let index = start + 1;
  let escaped = false;
  while (index < content.length) {
    const char = content[index]!;
    if (char === "\\") {
      escaped = true;
      index = Math.min(content.length, index + 2);
      continue;
    }
    if (char === quote) {
      return {
        end: index + 1,
        value: escaped ? undefined : content.slice(start + 1, index),
      };
    }
    index++;
  }
  return { end: content.length };
}

/**
 * Match mining configuration evidence structurally and in one pass.
 *
 * The three mining-specific keys are strong enough to stand alone. Common
 * vocabulary such as `worker` and `wallet` must contribute three distinct keys
 * to the same brace-delimited object. Comment and regex text is blanked by the
 * same-length shared lexical view, while quoted values remain available for
 * exact key parsing.
 */
const miningConfigKeysMatcher: NonNullable<PatternEntry["correlatedMatcher"]> =
  function* (content) {
    const searchableContent = maskMixedCommentsPreservingStrings(content);
    const scopeStates: number[] = [];
    let previousSignificant = "";
    let index = 0;

    while (index < searchableContent.length) {
      const char = searchableContent[index]!;
      if (/\s/.test(char)) {
        index++;
        continue;
      }

      if (char === "'" || char === '"' || char === "`") {
        const token = readQuotedMiningConfigToken(
          searchableContent,
          index,
          char,
        );
        const tokenStart = index;
        index = token.end;

        // Template literals are values, not object keys. For ordinary quoted
        // tokens, require the exact object-key position and a following colon.
        let colon = index;
        while (
          colon < searchableContent.length &&
          /\s/.test(searchableContent[colon]!)
        ) {
          colon++;
        }
        const key =
          char === "`" ||
            scopeStates.length === 0 ||
            (previousSignificant !== "{" && previousSignificant !== ",") ||
            searchableContent[colon] !== ":"
            ? undefined
            : token.value?.toLowerCase();

        if (key !== undefined) {
          const scopeIndex = scopeStates.length - 1;
          const state = scopeStates[scopeIndex]!;
          if (STRONG_MINING_CONFIG_KEYS.has(key)) {
            if ((state & MINING_CONFIG_SCOPE_REPORTED) === 0) {
              scopeStates[scopeIndex] = state | MINING_CONFIG_SCOPE_REPORTED;
              yield makeStructuralMatch(content, tokenStart, colon + 1);
            }
          } else {
            const bit = WEAK_MINING_CONFIG_KEY_BITS.get(key);
            if (bit !== undefined) {
              const priorWeakKeys = state & ~MINING_CONFIG_SCOPE_REPORTED;
              let nextState = state | bit;
              if (
                (state & MINING_CONFIG_SCOPE_REPORTED) === 0 &&
                (priorWeakKeys & (priorWeakKeys - 1)) !== 0 &&
                (priorWeakKeys & bit) === 0
              ) {
                nextState |= MINING_CONFIG_SCOPE_REPORTED;
                scopeStates[scopeIndex] = nextState;
                yield makeStructuralMatch(content, tokenStart, colon + 1);
              } else {
                scopeStates[scopeIndex] = nextState;
              }
            }
          }
          previousSignificant = ":";
          index = colon + 1;
          continue;
        }

        previousSignificant = "value";
        continue;
      }

      if (char === "{") {
        scopeStates.push(0);
      } else if (char === "}") {
        scopeStates.pop();
      }
      previousSignificant = char;
      index++;
    }
  };

const CHARCODE_OBFUSCATION_SOURCE =
  "(?:(?:\\\\x[0-9a-fA-F]{2}){5,}|" +
  "String\\s*\\.\\s*fromCharCode\\s*\\()";
const PROXY_REMOTE_SCHEME_SOURCE =
  "socks[45]?://" +
  "(?:[^\\s/@]+(?::[^\\s/@]*)?@)?" +
  "(?:\\[[0-9a-fA-F:.]+\\]|[A-Za-z0-9.-]+)(?::\\d{1,5})?";

function proxyEndpointHost(endpoint: string): string {
  const schemeEnd = endpoint.indexOf("//");
  if (schemeEnd === -1) return "";
  let authority = endpoint.slice(schemeEnd + 2).split(/[\\/\s]/, 1)[0] ?? "";
  const userInfoEnd = authority.lastIndexOf("@");
  if (userInfoEnd !== -1) authority = authority.slice(userInfoEnd + 1);

  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    return close === -1 ? "" : authority.slice(1, close);
  }

  const colon = authority.lastIndexOf(":");
  if (colon !== -1 && /^\d{1,5}$/.test(authority.slice(colon + 1))) {
    return authority.slice(0, colon);
  }
  return authority;
}

function proxyIpv4Component(value: string): number | undefined {
  let radix = 10;
  let digits = value;
  if (/^0x[0-9a-f]+$/i.test(value)) {
    radix = 16;
    digits = value.slice(2);
  } else if (/^0[0-7]+$/.test(value)) {
    radix = 8;
    digits = value.slice(1);
  } else if (!/^\d+$/.test(value)) {
    return undefined;
  }

  const parsed = Number.parseInt(digits || "0", radix);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

/** Normalize the one- through four-component IPv4 forms accepted by inet_aton. */
function proxyIpv4Value(value: string): number | undefined {
  const parts = value.split(".");
  if (parts.length === 0 || parts.length > 4) return undefined;
  const components = parts.map(proxyIpv4Component);
  if (components.some((part) => part === undefined)) return undefined;
  const numbers = components as number[];

  let normalized: number;
  if (numbers.length === 1) {
    normalized = numbers[0]!;
    if (normalized > 0xffff_ffff) return undefined;
  } else if (numbers.length === 2) {
    if (numbers[0]! > 0xff || numbers[1]! > 0xff_ffff) return undefined;
    normalized = numbers[0]! * 0x100_0000 + numbers[1]!;
  } else if (numbers.length === 3) {
    if (
      numbers[0]! > 0xff ||
      numbers[1]! > 0xff ||
      numbers[2]! > 0xffff
    ) {
      return undefined;
    }
    normalized =
      numbers[0]! * 0x100_0000 +
      numbers[1]! * 0x1_0000 +
      numbers[2]!;
  } else {
    if (numbers.some((part) => part > 0xff)) return undefined;
    normalized =
      numbers[0]! * 0x100_0000 +
      numbers[1]! * 0x1_0000 +
      numbers[2]! * 0x100 +
      numbers[3]!;
  }
  return normalized;
}

function proxyIpv4FirstOctet(value: number): number {
  return Math.floor(value / 0x100_0000);
}

function proxyIpv6Words(value: string): number[] | undefined {
  let address = value;
  const dottedSuffixStart = address.lastIndexOf(":");
  if (address.includes(".")) {
    if (dottedSuffixStart === -1) return undefined;
    const ipv4 = proxyIpv4Value(address.slice(dottedSuffixStart + 1));
    if (ipv4 === undefined) return undefined;
    address =
      `${address.slice(0, dottedSuffixStart)}:` +
      `${Math.floor(ipv4 / 0x1_0000).toString(16)}:` +
      `${(ipv4 % 0x1_0000).toString(16)}`;
  }

  const halves = address.split("::");
  if (halves.length > 2) return undefined;
  const parseHalf = (half: string): number[] | undefined => {
    if (half === "") return [];
    const words: number[] = [];
    for (const part of half.split(":")) {
      if (!/^[0-9a-f]{1,4}$/i.test(part)) return undefined;
      words.push(Number.parseInt(part, 16));
    }
    return words;
  };

  const left = parseHalf(halves[0] ?? "");
  const right = parseHalf(halves[1] ?? "");
  if (!left || !right) return undefined;
  if (halves.length === 1) return left.length === 8 ? left : undefined;

  const omitted = 8 - left.length - right.length;
  if (omitted < 1) return undefined;
  return [...left, ...new Array<number>(omitted).fill(0), ...right];
}

function isLoopbackOrWildcardProxyHost(value: string): boolean {
  const host = value.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;

  const ipv4 = proxyIpv4Value(host);
  if (ipv4 !== undefined) {
    const firstOctet = proxyIpv4FirstOctet(ipv4);
    return firstOctet === 0 || firstOctet === 127;
  }

  const ipv6 = proxyIpv6Words(host);
  if (!ipv6) return false;
  const allZero = ipv6.every((word) => word === 0);
  const loopback =
    ipv6.slice(0, 7).every((word) => word === 0) && ipv6[7] === 1;
  if (allZero || loopback) return true;

  const ipv4Compatible = ipv6.slice(0, 6).every((word) => word === 0);
  const ipv4Mapped =
    ipv6.slice(0, 5).every((word) => word === 0) && ipv6[5] === 0xffff;
  if (!ipv4Compatible && !ipv4Mapped) return false;

  const embeddedIpv4 = ipv6[6]! * 0x1_0000 + ipv6[7]!;
  const firstOctet = proxyIpv4FirstOctet(embeddedIpv4);
  return firstOctet === 0 || firstOctet === 127;
}

function isLoopbackOrWildcardIpv4Evidence(
  content: string,
  start: number,
  value: string,
): boolean {
  let tokenStart = start;
  let tokenEnd = start + value.length;
  while (tokenStart > 0 && /[\d.]/.test(content[tokenStart - 1]!)) tokenStart--;
  while (tokenEnd < content.length && /[\d.]/.test(content[tokenEnd]!)) tokenEnd++;
  const ipv4 = proxyIpv4Value(content.slice(tokenStart, tokenEnd));
  if (ipv4 === undefined) return false;
  const firstOctet = proxyIpv4FirstOctet(ipv4);
  return firstOctet === 0 || firstOctet === 127;
}

const proxyBackconnectMatcher: NonNullable<PatternEntry["correlatedMatcher"]> = (content) => {
  const results: StructuralMatch[] = [];
  const searchableContent = maskMixedCommentsPreservingStrings(content);
  interface QueueRange { start: number; end: number }
  interface ResidentialProxyRange extends QueueRange { proxyStart: number }
  interface RankedRange extends QueueRange {
    priority: number;
    pivots: readonly number[];
  }

  const socks: QueueRange[] = [];
  const backconnects: QueueRange[] = [];
  const residentials: QueueRange[] = [];
  const residentialProxies: ResidentialProxyRange[] = [];
  const proxies: QueueRange[] = [];
  let socksHead = 0;
  let backconnectHead = 0;
  let residentialHead = 0;
  let residentialProxyHead = 0;
  let proxyHead = 0;
  let best: RankedRange | undefined;

  const pathIsEarlier = (
    next: readonly number[],
    current: readonly number[],
  ): boolean => {
    for (let index = 0; index < Math.min(next.length, current.length); index++) {
      if (next[index] !== current[index]) return next[index]! < current[index]!;
    }
    return next.length < current.length;
  };
  const record = (
    start: number,
    end: number,
    priority: number,
    pivots: readonly number[],
  ): void => {
    if (
      !best ||
      start < best.start ||
      (start === best.start && (
        priority < best.priority ||
        (priority === best.priority && (
          pathIsEarlier(pivots, best.pivots) ||
          (pivots.length === best.pivots.length &&
            pivots.every((pivot, index) => pivot === best!.pivots[index]) &&
            end > best.end)
        ))
      ))
    ) {
      best = { start, end, priority, pivots: [...pivots] };
    }
  };
  const trimQueue = <T extends QueueRange>(
    queue: T[],
    head: number,
    position: number,
  ): number => {
    while (head < queue.length && position - queue[head]!.end > 512) head++;
    if (head > 1_024 && head * 2 > queue.length) {
      queue.splice(0, head);
      return 0;
    }
    return head;
  };
  const trimChains = (position: number): void => {
    socksHead = trimQueue(socks, socksHead, position);
    backconnectHead = trimQueue(backconnects, backconnectHead, position);
    residentialHead = trimQueue(residentials, residentialHead, position);
    residentialProxyHead = trimQueue(
      residentialProxies,
      residentialProxyHead,
      position,
    );
    proxyHead = trimQueue(proxies, proxyHead, position);
  };
  const resetChains = (): void => {
    socks.length = 0;
    backconnects.length = 0;
    residentials.length = 0;
    residentialProxies.length = 0;
    proxies.length = 0;
    socksHead = 0;
    backconnectHead = 0;
    residentialHead = 0;
    residentialProxyHead = 0;
    proxyHead = 0;
  };
  const flushPhysicalLine = (): void => {
    if (best) results.push(makeStructuralMatch(content, best.start, best.end));
    best = undefined;
    resetChains();
  };

  // Independent zero-width streams preserve overlapping starts. A consuming
  // union loses `1.2.3.4` when `:12341` first consumes its leading digit, and
  // it cannot expose the two-octet residential endpoint beside a full IPv4.
  const streams = [
    {
      kind: "scheme",
      regex: new RegExp(`(?=(${PROXY_REMOTE_SCHEME_SOURCE}))`, "g"),
    },
    { kind: "socks", regex: /(?=(\bsocks[45]\b))/g },
    { kind: "back_connect", regex: /(?=(back_connect))/g },
    { kind: "backconnect", regex: /(?=(backconnect))/g },
    { kind: "residential", regex: /(?=(residential))/g },
    { kind: "proxy", regex: /(?=(proxy))/g },
    { kind: "checkin", regex: /(?=(checkin))/g },
    { kind: "port", regex: /(?=(:\d{4,5}))/g },
    {
      kind: "fullIpv4",
      regex: /(?=(\d{1,3}(?:\.\d{1,3}){3}))/g,
    },
    { kind: "partialIpv4", regex: /(?=(\d{1,3}\.\d{1,3}))/g },
  ] as const;
  const events = streams.map(({ regex }) => {
    regex.lastIndex = 0;
    return regex.exec(searchableContent);
  });
  const barrier = /[\n\r]/g;
  let barrierEvent = barrier.exec(searchableContent);

  while (true) {
    let eventStart = barrierEvent?.index ?? Number.POSITIVE_INFINITY;
    for (const event of events) {
      if (event && event.index < eventStart) eventStart = event.index;
    }
    if (!Number.isFinite(eventStart)) break;
    trimChains(eventStart);

    for (let streamIndex = 0; streamIndex < streams.length; streamIndex++) {
      const event = events[streamIndex];
      if (!event || event.index !== eventStart) continue;
      const stream = streams[streamIndex]!;
      const value = event[1]!;
      const end = eventStart + value.length;

      switch (stream.kind) {
        case "scheme":
          if (!isLoopbackOrWildcardProxyHost(proxyEndpointHost(value))) {
            record(eventStart, end, 0, [eventStart]);
          }
          break;
        case "socks":
          // A complete socks:// authority is owned by the scheme branch. Do not
          // let its protocol token seed the looser same-line fallback after a
          // local or wildcard endpoint was deliberately rejected.
          if (searchableContent.slice(end, end + 3) !== "://") {
            socks.push({ start: eventStart, end });
          }
          break;
        case "back_connect":
          record(eventStart, end, 4, [eventStart]);
          break;
        case "backconnect":
          backconnects.push({ start: eventStart, end });
          break;
        case "residential":
          residentials.push({ start: eventStart, end });
          break;
        case "proxy": {
          const residential = residentials[residentialHead];
          if (residential) {
            residentialProxies.push({
              start: residential.start,
              end,
              proxyStart: eventStart,
            });
          }
          proxies.push({ start: eventStart, end });
          break;
        }
        case "checkin": {
          const proxy = proxies[proxyHead];
          if (proxy) record(proxy.start, end, 5, [eventStart]);
          break;
        }
        case "port": {
          const backconnect = backconnects[backconnectHead];
          if (backconnect) record(backconnect.start, end, 2, [eventStart]);
          break;
        }
        case "fullIpv4": {
          const socksPrefix = socks[socksHead];
          if (socksPrefix && !isLoopbackOrWildcardIpv4Evidence(content, eventStart, value)) {
            record(socksPrefix.start, end, 1, [eventStart]);
          }
          break;
        }
        case "partialIpv4": {
          const residentialProxy = residentialProxies[residentialProxyHead];
          if (residentialProxy && !isLoopbackOrWildcardIpv4Evidence(content, eventStart, value)) {
            record(
              residentialProxy.start,
              end,
              3,
              [residentialProxy.proxyStart, eventStart],
            );
          }
          break;
        }
      }

      stream.regex.lastIndex = eventStart + 1;
      events[streamIndex] = stream.regex.exec(searchableContent);
    }

    if (barrierEvent?.index === eventStart) {
      if (barrierEvent[0] === "\n") flushPhysicalLine();
      else resetChains();
      barrierEvent = barrier.exec(searchableContent);
    }
  }
  flushPhysicalLine();
  return results;
};
interface OrderedSameLineToken {
  text: string;
  word?: boolean;
}

interface OrderedSameLineState {
  nextToken: number;
  nextAt: number;
  start: number;
  end: number;
}

const isRegExpWordCharacter = (value: string | undefined): boolean =>
  value !== undefined && /[A-Za-z0-9_]/.test(value);

function orderedTokenAt(
  content: string,
  index: number,
  token: OrderedSameLineToken,
): boolean {
  if (!content.startsWith(token.text, index)) return false;
  if (!token.word) return true;
  return !isRegExpWordCharacter(content[index - 1]) &&
    !isRegExpWordCharacter(content[index + token.text.length]);
}

/**
 * Match fixed ordered token sequences separated by `.*` on one JavaScript
 * regex line. Each character and sequence is considered a constant number of
 * times; repeated prefixes cannot restart a scan. CR/LF/U+2028/U+2029 retain
 * native dot semantics, while findings remain deduplicated per physical LF
 * line just like matchPatternInContent.
 */
function makeOrderedSameLineMatcher(
  sequences: ReadonlyArray<ReadonlyArray<OrderedSameLineToken>>,
): NonNullable<PatternEntry["correlatedMatcher"]> {
  return (content) => {
    const results: StructuralMatch[] = [];
    const states: OrderedSameLineState[] = sequences.map(() => ({
      nextToken: 0,
      nextAt: 0,
      start: -1,
      end: -1,
    }));
    let matchedPhysicalLine = false;

    const resetStates = (): void => {
      for (const state of states) {
        state.nextToken = 0;
        state.nextAt = 0;
        state.start = -1;
        state.end = -1;
      }
    };
    const flushSegment = (): void => {
      if (matchedPhysicalLine) {
        resetStates();
        return;
      }
      let selected = -1;
      for (let sequence = 0; sequence < states.length; sequence++) {
        const state = states[sequence]!;
        if (state.end === -1) continue;
        if (selected === -1 || state.start < states[selected]!.start) {
          selected = sequence;
        }
      }
      if (selected !== -1) {
        const state = states[selected]!;
        results.push(makeStructuralMatch(content, state.start, state.end));
        matchedPhysicalLine = true;
      }
      resetStates();
    };

    for (let index = 0; index <= content.length; index++) {
      const char = content[index];
      if (index === content.length || char === "\n" || isDotLineTerminator(char ?? "")) {
        flushSegment();
        if (char === "\n") matchedPhysicalLine = false;
        continue;
      }
      if (matchedPhysicalLine) continue;

      for (let sequence = 0; sequence < sequences.length; sequence++) {
        const tokens = sequences[sequence]!;
        const state = states[sequence]!;
        if (state.nextToken === tokens.length) {
          const finalToken = tokens[tokens.length - 1]!;
          if (index >= state.nextAt && orderedTokenAt(content, index, finalToken)) {
            state.end = index + finalToken.text.length;
            state.nextAt = state.end;
          }
          continue;
        }

        const token = tokens[state.nextToken]!;
        if (index < state.nextAt || !orderedTokenAt(content, index, token)) continue;
        if (state.nextToken === 0) state.start = index;
        state.nextToken++;
        state.nextAt = index + token.text.length;
        if (state.nextToken === tokens.length) state.end = state.nextAt;
      }
    }

    return results;
  };
}

const xzObfuscatedTestMatcher = makeOrderedSameLineMatcher([
  [
    { text: "tests/files/" },
    { text: ".xz" },
    { text: "head", word: true },
    { text: "tr", word: true },
  ],
  [
    { text: "xz", word: true },
    { text: "-d" },
    { text: "|" },
    { text: "head", word: true },
    { text: "-c" },
  ],
]);

const iacInlineScriptMatcher: NonNullable<PatternEntry["correlatedMatcher"]> = (content) => {
  const token = /provisioner|user_data|inline|curl|wget|\||\n|[\r\u2028\u2029]/g;
  const results: StructuralMatch[] = [];
  let markerStart = -1;
  let commandStart = -1;
  let bestStart = -1;
  let bestEnd = -1;

  const recordCandidate = (start: number, end: number): void => {
    if (bestStart === -1 || start < bestStart || (start === bestStart && end > bestEnd)) {
      bestStart = start;
      bestEnd = end;
    }
  };
  const flushPhysicalLine = (): void => {
    if (bestStart !== -1) {
      results.push(makeStructuralMatch(content, bestStart, bestEnd));
    }
    markerStart = -1;
    commandStart = -1;
    bestStart = -1;
    bestEnd = -1;
  };

  let event: RegExpExecArray | null;
  while ((event = token.exec(content)) !== null) {
    const value = event[0]!;
    if (value === "\n") {
      flushPhysicalLine();
      continue;
    }
    if (isDotLineTerminator(value)) {
      markerStart = -1;
      commandStart = -1;
      continue;
    }
    if (value === "provisioner" || value === "user_data" || value === "inline") {
      if (markerStart === -1) markerStart = event.index;
      continue;
    }
    if (value === "curl" || value === "wget") {
      if (markerStart === -1) continue;
      const whitespace = skipPatternWhitespace(content, event.index + value.length);
      if (whitespace.end > event.index + value.length) {
        if (whitespace.crossedDotLineTerminator) {
          // Only this command's `\s+` may cross the terminator. Older command
          // paths and the marker-to-command `.*` cannot survive beyond it.
          commandStart = markerStart;
          markerStart = -1;
        } else if (commandStart === -1) {
          commandStart = markerStart;
        }
        token.lastIndex = whitespace.end;
      }
      continue;
    }
    if (commandStart === -1) continue;
    const whitespace = skipPatternWhitespace(content, event.index + 1);
    const tail = content.slice(whitespace.end, whitespace.end + 4);
    const executableLength = tail.startsWith("bash") ? 4 : tail.startsWith("sh") ? 2 : 0;
    if (executableLength > 0) {
      recordCandidate(commandStart, whitespace.end + executableLength);
      token.lastIndex = whitespace.end + executableLength;
      if (whitespace.crossedDotLineTerminator) {
        // Selecting a later pipe would put this terminator inside `.*`, where
        // dot cannot consume it. Preserve the completed candidate, but expire
        // both active prefixes before scanning the following segment.
        markerStart = -1;
        commandStart = -1;
      }
    }
  }
  flushPhysicalLine();
  return results;
};

/**
 * Values that are references to a secret rather than a secret: shell and
 * make variables (`$FOO`, `${FOO}`), command substitution (`$(...)`, backticks),
 * template expressions (`${{ ... }}`, `{{ ... }}`, `<%= ... %>`, `#{...}`),
 * and Windows-style `%FOO%`.
 */
const VALUE_IS_REFERENCE =
  /\$\{|\$\(|\$[A-Za-z_]|`|\{\{|<%|#\{|%[A-Za-z_][A-Za-z0-9_]*%/;

/**
 * A namespace/prefix template rather than a complete credential:
 * `trust_pat_`, `sk_live_`, `ghp_`. A real credential never ends on its
 * separator - the random part is missing because it is added at runtime.
 */
const VALUE_IS_PREFIX_TEMPLATE = /[_\-:./]$/;

/** A filesystem path (e.g. `private_key = "/etc/ssl/private/server.key"`). */
const VALUE_IS_PATH =
  /^(?:\.{1,2}[\\/]|~[\\/]|[A-Za-z]:[\\/])|^\/(?:[\w.@+-]+\/)+[\w.@+-]+$/;

/**
 * Documentation placeholders. Matched as a whole word or as a prefix, never as
 * a bare substring: `AKIAIOSFODNN7EXAMPLE` has the right shape for a real AWS
 * key and stays reported.
 */
const VALUE_IS_PLACEHOLDER =
  /^(?:test|example|dummy|sample|placeholder|changeme|change_me|your_|your-|my_|my-|todo|replace|insert|redacted|fake|notreal|mock|xxx|<)|\b(?:example|placeholder|changeme|redacted|dummy|your[_-]\w+|todo|fixme)\b/i;

/** Literals that carry no secret at all. */
const VALUE_IS_EMPTY_LITERAL = /^(?:null|none|nil|undefined|false|true|0|-)$/i;

/**
 * True when a quoted value assigned to a secret-looking key is a real embedded
 * credential rather than a reference, a placeholder or a prefix constant.
 *
 * IAC_HARDCODED_SECRET used to match the assignment SHAPE alone
 * (`token\s*=\s*"<8+ chars>"`) and never looked at the value, so it reported
 * every one of these as a CRITICAL hardcoded secret:
 *
 *     password = "${REDIS_PASSWORD}"          # a shell variable
 *     password = "$(openssl rand -base64 32)" # a freshly GENERATED password
 *     const token = "trust_pat_"              # a namespace prefix constant
 *
 * The checks below are deliberately structural: each one identifies a value
 * that CANNOT be a credential, so nothing that could be one is dropped.
 */
export function isLikelyRealSecretValue(value: string): boolean {
  const v = value.trim();
  if (v.length < 8) return false;
  if (VALUE_IS_REFERENCE.test(v)) return false;
  if (VALUE_IS_PREFIX_TEMPLATE.test(v)) return false;
  if (VALUE_IS_PATH.test(v)) return false;
  if (VALUE_IS_PLACEHOLDER.test(v)) return false;
  if (VALUE_IS_EMPTY_LITERAL.test(v)) return false;
  return true;
}
const CORE_BROAD_GAP_MATCHERS = createCoreBroadGapMatchers(isLikelyRealSecretValue);


// ---------------------------------------------------------------------------
// File-based detection patterns
// ---------------------------------------------------------------------------

export const FILE_PATTERNS: PatternEntry[] = [
  // GlassWorm marker
  {
    name: "glassworm-marker",
    pattern: "lzcdrtfxyqiplpd",
    description: "GlassWorm campaign marker variable detected",
    severity: "critical",
    rule: "GLASSWORM_MARKER",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },

  // Invisible Unicode characters (zero-width spaces, joiners, etc.)
  // v5.10: the surrogate-pair alternative \uDB40[\uDC00-\uDC7F] covers the
  // Unicode Tags block (U+E0000..U+E007F) used for ASCII smuggling - invisible
  // instructions encoded for an LLM agent that a human reviewer cannot see.
  {
    name: "invisible-unicode",
    pattern:
      "(?:[\\u200B\\u200C\\u200D\\u2060\\uFEFF\\u00AD\\u034F\\u061C\\u180E\\u2028\\u2029\\u202A-\\u202E\\u2066-\\u2069]|\\uDB40[\\uDC00-\\uDC7F]){3,}",
    description:
      "Suspicious invisible Unicode characters detected (potential code obfuscation or ASCII smuggling)",
    severity: "high",
    rule: "INVISIBLE_UNICODE",
    notTestFile: true,
  },

  // Encoded eval/exec patterns
  {
    name: "eval-atob",
    pattern: "eval\\s*\\(\\s*atob\\s*\\(",
    description: "Base64-encoded eval detected (common malware obfuscation)",
    severity: "critical",
    rule: "EVAL_ATOB",
    notTestFile: true,
  },
  {
    name: "eval-buffer-from",
    pattern: "eval\\s*\\(\\s*Buffer\\.from\\s*\\(",
    description:
      "Buffer-encoded eval detected (common malware obfuscation in Node.js)",
    severity: "critical",
    rule: "EVAL_BUFFER",
    notTestFile: true,
  },
  {
    name: "new-function-atob",
    pattern: "new\\s+Function\\s*\\(\\s*atob\\s*\\(",
    description:
      "Base64-encoded Function constructor detected (malware obfuscation)",
    severity: "critical",
    rule: "FUNCTION_ATOB",
    notTestFile: true,
  },
  {
    name: "eval-buffer-hex",
    pattern: "eval\\s*\\(\\s*Buffer\\.from\\s*\\([^)]+,\\s*['\"]hex['\"]\\s*\\)",
    description: "Hex-encoded eval detected",
    severity: "critical",
    rule: "EVAL_HEX",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.EVAL_HEX,
    notTestFile: true,
  },
  {
    name: "exec-encoded",
    pattern:
      "exec\\s*\\(\\s*(?:atob|Buffer\\.from|decodeURIComponent)\\s*\\(",
    description: "Encoded exec call detected",
    severity: "high",
    rule: "EXEC_ENCODED",
    notTestFile: true,
  },

  // Solana C2 references
  {
    name: "solana-mainnet",
    pattern: "mainnet-beta\\.solana\\.com",
    description: "Solana mainnet RPC reference detected (potential C2 channel)",
    severity: "medium",
    rule: "SOLANA_MAINNET",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "helius-rpc",
    pattern: "helius(?:-rpc)?\\.(?:com|dev)",
    description:
      "Helius Solana RPC reference detected (used in GlassWorm C2)",
    severity: "medium",
    rule: "HELIUS_RPC",
    notTestFile: true,
  },

  // Obfuscation patterns
  {
    name: "hex-string-array",
    pattern:
      "\\[\\s*(?:0x[0-9a-fA-F]+\\s*,\\s*){10,}",
    description: "Large hex array detected (potential obfuscated payload)",
    severity: "medium",
    rule: "HEX_ARRAY",
    notTestFile: true,
  },
  {
    name: "string-char-concat",
    pattern: CHARCODE_OBFUSCATION_SOURCE,
    description:
      "Encoded character construction flows into a dynamic execution sink",
    severity: "medium",
    rule: "CHARCODE_OBFUSCATION",
    spansLines: 8,
    correlatedMatcher: matchCharacterCodeObfuscation,
    notTestFile: true,
  },

  // Network exfiltration
  {
    name: "env-exfil",
    pattern:
      "process\\.env\\b[^;\\n]*(?:fetch\\s*\\(|https?\\.(?:get|request)|axios|\\bgot\\s*[.(]|node-fetch)|(?:fetch\\s*\\(|https?\\.(?:get|request)|axios|\\bgot\\s*[.(]|node-fetch)[^;\\n]*process\\.env\\b",
    description:
      "Environment variable access combined with network request (data exfiltration pattern)",
    severity: "high",
    rule: "ENV_EXFILTRATION",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.ENV_EXFILTRATION,
    notTestFile: true,
  },
  {
    name: "dns-exfil",
    pattern: "dns\\.resolve.*process\\.env",
    description: "DNS-based data exfiltration pattern detected",
    severity: "high",
    rule: "DNS_EXFILTRATION",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.DNS_EXFILTRATION,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Suspicious file names
// ---------------------------------------------------------------------------

/** Files that are suspicious by name alone */
export const SUSPICIOUS_FILES: Array<{
  pattern: string;
  description: string;
  severity: Severity;
  rule: string;
}> = [
  {
    pattern: "^i\\.js$",
    description:
      "Suspicious i.js file (commonly used as GlassWorm payload dropper)",
    severity: "high",
    rule: "SUSPICIOUS_I_JS",
  },
  {
    pattern: "^init\\.json$",
    description:
      "init.json persistence file (used by GlassWorm for configuration persistence)",
    severity: "high",
    rule: "SUSPICIOUS_INIT_JSON",
  },
];

// ---------------------------------------------------------------------------
// Suspicious npm scripts
// ---------------------------------------------------------------------------

/** Package.json script patterns that are suspicious */
export const SUSPICIOUS_SCRIPTS: PatternEntry[] = [
  {
    name: "postinstall-curl",
    pattern: "curl\\s+.*\\|\\s*(?:bash|sh|node)",
    description: "postinstall script downloads and executes remote code",
    severity: "critical",
    rule: "SCRIPT_CURL_EXEC",
    correlatedMatcher: scriptCurlExecMatcher,
    notTestFile: true,
  },
  {
    name: "postinstall-wget",
    pattern: "wget\\s+.*\\|\\s*(?:bash|sh|node)",
    description: "postinstall script downloads and executes remote code",
    severity: "critical",
    rule: "SCRIPT_WGET_EXEC",
    correlatedMatcher: scriptWgetExecMatcher,
    notTestFile: true,
  },
  {
    name: "postinstall-node-e",
    pattern: "node\\s+-e\\s+[\"'].*(?:http|https|fetch|require)",
    description:
      "postinstall script executes inline Node.js with network access",
    severity: "high",
    rule: "SCRIPT_NODE_INLINE",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.SCRIPT_NODE_INLINE,
    notTestFile: true,
  },
  {
    name: "postinstall-encoded",
    pattern: "(?:atob|Buffer\\.from|base64)",
    description: "postinstall script contains encoding/decoding operations",
    severity: "high",
    rule: "SCRIPT_ENCODED",
    notTestFile: true,
  },
  {
    name: "preinstall-exec",
    pattern: "(?:exec|spawn|execSync)\\s*\\(",
    description: "preinstall script executes system commands",
    severity: "medium",
    rule: "SCRIPT_PREINSTALL_EXEC",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Known malicious npm package name patterns
// ---------------------------------------------------------------------------

/** Patterns matching known malicious or typosquatting package names */
export const MALICIOUS_PACKAGE_PATTERNS: string[] = [
  // Fake Paysafe / Skrill / Neteller payment SDKs (Socket, July 8, 2026) - 13
  // npm packages (v1.0.0-1.0.3) impersonating non-existent official payment
  // SDKs; anchored so only these exact names match, never legitimate wrappers.
  "^(paysafe-checkout|paysafe-vault|paysafe-js|paysafe-api|paysafe-node|paysafe-cards|paysafe-fraud|paysafe-kyc|paysafe-payments|skrill|skrill-sdk|skrill-payments|neteller)$",
  // Typosquatting common packages
  "^(lodas|1odash|l0dash|lodash-es-utils)$",
  "^(cros-env|cross-env-shell|crossenv)$",
  "^(bable-cli|babelcli)$",
  "^(event-streem|event_stream)$",

  // GlassWorm campaign packages (pattern: random-looking names)
  "^[a-z]{20,}$", // Very long single-word lowercase names

  // DPRK AI-inserted npm malware (April 2026)
  "^@validate-sdk\\/v2$",

  // BufferZoneCorp poisoned Ruby gems (May 2026)
  "^knot-(activesupport-logger|devise-jwt-helper|rack-session-store|rails-assets-pipeline|rspec-formatter-json|date-utils-rb|simple-formatter)$",

  // BufferZoneCorp sleeper Go modules (May 2026)
  "^github\\.com/BufferZoneCorp/(go-metrics-sdk|go-weather-sdk|go-retryablehttp|go-stdlib-ext|grpc-client|net-helper|config-loader|log-core|go-envconfig)$",

  // ZiChatBot PyPI campaign (May 2026)
  // Drops terminate.dll/terminate.so + uses Zulip REST APIs as C2; potential APT32/OceanLotus link
  "^(uuid32-utils|colorinal|termncolor)$",

  // Phantom Bot DDoS + Shai-Hulud clone npm infostealer (deadcode09284814, May 2026)
  // Four packages from publisher deadcode09284814 carrying leaked Shai-Hulud worm source +
  // Golang Phantom Bot DDoS module (HTTP/TCP/UDP flood + TCP reset). 2,678 combined downloads.
  "^(chalk-tempalte|axois-utils|color-style-utils)$",
  "^@deadcode09284814\\/axios-util$",

  // Nx Console nrwl.angular-console v18.95.0 - compromised VS Code extension (May 18, 2026)
  // Listed for direct name match in extensions.json / dependency manifests.
  "^nrwl\\.angular-console$",

  // TrapDoor cross-ecosystem credential stealer - npm packages (May 25, 2026)
  // 21 malicious npm packages from actor ddjidd564 targeting AI/DeFi/Web3 devs.
  // Reported by The Hacker News May 25, 2026; sibling PyPI/Crates.io waves.
  "^(async-pipeline-builder|build-scripts-utils|chain-key-validator|crypto-credential-scanner|defi-env-auditor|defi-threat-scanner|deployment-key-auditor|dev-env-bootstrapper|eth-wallet-sentinel|llm-context-compressor|mnemonic-safety-check|model-switch-router|node-setup-helpers|project-init-tools|prompt-engineering-toolkit|solidity-deploy-guard|token-usage-tracker|wallet-backup-verifier|wallet-security-checker|web3-secrets-detector|workspace-config-loader)$",

  // Polymarket impersonation - typosquats of Polymarket SDK (May 22, 2026)
  // Publisher polymarketdev; wallet-key exfiltration via Cloudflare Worker.
  "^polymarket-(trading-cli|terminal|trade|auto-trade|copy-trading|bot|claude-code|ai-agent|trader)$",

  // Malware-Slop npm infostealer (OX Security via The Hacker News, May 27, 2026)
  // Fully malicious package by actor unplowed3584; uploads Claude AI user-directory files to GitHub.
  "^mouse5212-super-formatter$",

  // codexui-android npm Codex token stealer (Aikido, disclosed May 27, 2026)
  // Legitimate-looking Codex remote-UI package; since 0.1.82 every invocation XOR-encrypts
  // the OpenAI Codex auth file (key "anyclaw2026") + base64 + POST to sentry.anyclaw.store.
  "^codexui-android$",

  // vpmdhaj cloud-secret npm cluster (Socket via The Hacker News, May 28-29, 2026)
  // 14 npm typosquats of OpenSearch / ElasticSearch / DevOps / env-config libraries
  // by actor "vpmdhaj" (a39155771@gmail.com); preinstall hooks harvest AWS creds,
  // HashiCorp Vault tokens, npm tokens, CI/CD secrets. Published alongside the
  // Sicoob.Sdk NuGet impersonation. Scoped @vpmdhaj/* names + unscoped typosquats.
  "^@vpmdhaj\\/(devops-tools|elastic-helper|opensearch-setup|search-setup)$",
  "^(app-config-utility|elastic-opensearch-helper|env-config-manager|opensearch-config-utility|opensearch-security-scanner|opensearch-setup|opensearch-setup-tool|search-cluster-setup|search-engine-setup|vpmdhaj-opensearch-setup)$",

  // June 2026 npm infostealer cluster (The Hacker News Weekly Recap, June 8, 2026)
  // turbo-axios / faster-axios: trojanized axios copies whose postinstall hooks deploy
  // Epsilon Stealer. cms-store-ren: exfiltrates harvested data to Telegram via an exposed
  // bot API token. parsimonius: typosquat of "parsimonious" deploying a Telegram-based
  // backdoor (published to both npm and PyPI; ~2,474 downloads before removal).
  "^(turbo-axios|faster-axios|cms-store-ren|parsimonius)$",

  // ThreatsDay Bulletin npm cluster (The Hacker News, June 11, 2026)
  // tw-style-utils: poisoned npm package delivering the cross-platform SStar Agent
  // RAT (Windows + macOS), distributed via the star45674/smart-contract-engineer-role
  // fake job-assignment lure. ambar-src: fully malicious npm package (Tenable) whose
  // download count was artificially "pumped" to 50,000+ in three days.
  "^(tw-style-utils|ambar-src)$",

  // Arch Linux AUR mass hijack npm dropper (The Hacker News + BleepingComputer, June 12, 2026)
  // 400+ Arch User Repository packages had their build scripts rewritten with preinstall
  // hooks that download and run the fully malicious npm package atomic-lockfile, which
  // installs a credential stealer + eBPF rootkit. atomic-lockfile@1.4.2 was published
  // 2026-06-10 and pulled by npm security 2026-06-12 (replaced by the 0.0.1-security
  // holding placeholder). Bare-name indicator: the package has no legitimate history.
  "^atomic-lockfile$",

  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // easy-day-js is an attacker-created dayjs clone (no legitimate history) injected as a
  // dependency into 141 republished @mastra packages via compromised maintainer "ehindero".
  // Its postinstall hook drops a cross-platform Node.js crypto-stealer RAT. Microsoft
  // attributes to Sapphire Sleet/BlueNoroff (also behind the April 2026 axios hijack).
  "^easy-day-js$",

  // NastyC2 npm framework (THN ThreatsDay Bulletin, June 18, 2026)
  // Three fully malicious npm packages bundling NastyC2, a Rust post-exploitation implant
  // (80+ commands: credential harvesting, AD attacks, container escape, cloud-metadata
  // theft, fileless execution). Bare names; each package has no legitimate purpose.
  "^(node-ci-utils|win-env-setup|macos-ci-utils)$",

  // PostCSS-impersonation npm packages deliver Windows RAT (The Hacker News, June 23, 2026)
  // Malicious npm packages posing as PostCSS tooling deliver a Windows-based remote access
  // trojan. aes-decode-runner-pro (145 downloads) + postcss-min are fully malicious; bare names.
  "^(postcss-min|aes-decode-runner-pro)$",

  // Contagious Interview "Fake Font" npm + Go wave / InvisibleFerret (The Hacker News, June 29, 2026)
  // DPRK Contagious Interview operation. Two attacker-uploaded npm packages and a cluster of
  // 16 Go modules conceal a hidden VS Code task ("eslint-check") plus a JavaScript payload
  // disguised as a web font (public/fonts/fa-solid-400.woff2) that deploys the InvisibleFerret
  // Python backdoor, using TronGrid/Aptos blockchain transactions as a dead-drop resolver.
  // The npm packages were uploaded 2026-05-25 and removed - bare-name indicators with no
  // legitimate history. The font filename and task name are deliberately NOT used as
  // signatures: both collide with legitimate FontAwesome assets / lint tasks (false positives).
  "^(html-to-gutenberg|fetch-page-assets)$",
  "^github\\.com/(lambda-platform/(lambda|ebarimt-rest-api|dan)|reauheau/goaubio|glacialspring/(go-winsparkle|static)|bm-197/chill|naol7/dist-task-scheduler|anatoli-derese/a2sv-excercise|amantsehay/a2sv-go-course|dexbotsdev/uniswap-v2-v3-arbitrage|zainirfan13/graphql-client|hngi/team-fierce-backend-golang|rickt/slack-weather-bot|Barsu5489/commerce|Setsu548/Logistic)$",

  // Contagious Interview Rollup polyfill npm packages (Lazarus, DPRK) (The Hacker News / JFrog, July 3, 2026)
  // Six attacker-uploaded npm packages masquerading as Rollup polyfill tooling to facilitate
  // remote access + developer-secret theft. Fresh DPRK Contagious Interview wave; C2 216.126.236.244
  // (in ioc-blocklist). Each package is fully malicious with no legitimate history - bare names.
  "^(rollup-packages-polyfill-core|rollup-runtime-polyfill-core|rollup-plugin-polyfill-connect|quirky-token|react-icon-svgs|swift-parse-stream)$",

  // ViteVenom - malicious Vite npm packages w/ blockchain C2 (Checkmarx via The Hacker News, July 18, 2026)
  // Threat actor "SuccessKey"; expansion of ChainVeil. Seven scoped packages impersonating the
  // "@vitejs/*" namespace (published June 29-July 3, 2026) whose payload runs at IMPORT time and
  // delivers a RAT via a Tron/Aptos/BNB Smart Chain blockchain C2. Fully malicious, no legitimate
  // history - anchored to these exact names (the broad scoped catch-all below would also match, but
  // the directory-scan MALICIOUS_DEPENDENCY path uses the exact feed names, so pin them explicitly).
  "^(@uw010010\\/vite-tree|@vite-tab\\/tab|@vite-ln\\/build-ts|@vite-mcp\\/vite-type|@vite-pro\\/vite-ui|@vitets\\/vite-ts|@vite-ts\\/vite-ui)$",

  // ChainVeil - predecessor wave of the ViteVenom campaign above (Checkmarx Zero, June 16, 2026;
  // package list + versions corroborated by OpenSourceMalware, July 17, 2026, which ties both waves
  // to the DPRK/Lazarus PolinRider campaign via shared Tron/Aptos addresses and XOR decryption keys).
  // Nine typosquats of Tailwind / Sass / TypeORM / rate-limiter libraries carrying the same 77 KB RAT
  // and four-tier Tron/Aptos/BNB Smart Chain C2. All nine now resolve to npm "security holding
  // package" placeholders (registry-verified 2026-07-27), i.e. npm removed them as malware and no
  // legitimate release history exists under these names - so bare names are safe here. The typosquat
  // TARGETS (tailwind-merge, rate-limiter-flexible, typeorm) are legitimate and are NOT matched.
  "^(tailwindcss-animatics|tailwindcss-animates-kit|tailwindcss-merge|sass-formats|sass-format|clsx-tailwind|typeorm-encrypt|rate-limit-flexible|rate-limits-flexible)$",

  // SleeperGem - malicious RubyGems releases (StepSecurity via The Hacker News, July 20, 2026)
  // Only the pure impersonation gem is anchored here. It carries no legitimate history in any
  // registry, so a bare name is safe. The campaign's other two gems (Dendreo,
  // fastlane-plugin-run_tests_firebase_testlab) are hijacked REAL gems - they are version-pinned
  // in the feed instead, because a bare name here would flag every clean install of them.
  "^git_credential_manager$",

  // Apex macOS infostealer npm packages (safedep / The Hacker News, July 22, 2026)
  // Postinstall dropper delivering an AMOS-family macOS infostealer while installing a
  // working forked coding agent as cover. npm removed @apexfdn/apex; the operator
  // re-published the identical payload as @copilot-mcp/apex ~11h later (the scope borrows
  // GitHub Copilot's credibility without belonging to GitHub) and churned 20+ versions in
  // 8h - so block by name, not version. Both are fully malicious with no legitimate history.
  // Anchored explicitly: although the scoped catch-all below would also match, the directory
  // scan's exact-name path relies on pinned names (same rationale as the ViteVenom block).
  "^(@apexfdn\\/apex|@copilot-mcp\\/apex)$",

  // NeoShadow (Aikido, detected 2025-12-30, published 2026-01-05; packages corroborated by
  // o3.security MAL-2026-334). Four Windows-targeting typosquats published by npm account
  // cjh97123, carrying a JS loader that executes its payload via MSBuild and resolves the live
  // C2 from an Ethereum contract. All four resolve to npm "security holding package"
  // placeholders (registry-verified 2026-07-29), i.e. npm removed them as malware and no
  // legitimate release history exists under these names - so bare names are safe. The typosquat
  // TARGETS (viem, crypto, tailwindcss, @supabase/supabase-js) are legitimate and are NOT
  // matched: note the unscoped "supabase-js" is the squat, the real package is scoped.
  "^(viem-js|cyrpto|tailwin|supabase-js)$",

  // SANDWORM_MODE / "Echoes of Shai-Hulud" npm worm (Socket + OX Security, 2026-02-20).
  // Token-stealing worm that injects malicious MCP servers into Claude Code / Cursor / VS Code
  // and detonates 48h after install. All 19 names resolve to npm "security holding package"
  // placeholders (registry-verified 2026-07-29), so no legitimate release history exists and
  // bare names are safe. Both sources publish versions, but the names are fully malicious
  // rather than hijacked, so name-level blocking is the stronger pin (the two write-ups
  // disagree on suport-color's version: Socket says 1.0.1, OX says 0.1.1). The typosquat
  // TARGETS (claude-code, crypto, hardhat, rimraf, supports-color, viem, yargs) are legitimate
  // and are NOT matched.
  "^(claud-code|cloude-code|cloude|crypto-locale|crypto-reader-info|detect-cache|format-defaults|hardhta|locale-loader-pro|naniod|node-native-bridge|opencraw|parse-compat|rimarf|scan-store|secp256|suport-color|veim|yarsg)$",

  // NOTE: there is deliberately NO scoped-package catch-all here.
  // A rule of the shape "^@(?!<allowlist>)/.*$" matched 94% of every scoped
  // package on npm, so `scg npm <any scoped package>` exited 1 with riskLevel
  // critical. The allowlist could never keep up either: "vitejs" was listed but
  // not "vitest", so @vitest/* was flagged, while "types" accidentally
  // prefix-matched "typescript" and silently exempted @typescript-eslint/*.
  // Scoped malware is now caught by EXACT NAME through the bundled feed in
  // npm-scanner.ts, which covers every curated npm name instead of only scoped
  // ones and cannot produce a false positive.
];

// ---------------------------------------------------------------------------
// Campaign-specific patterns (real-world supply-chain attacks)
// ---------------------------------------------------------------------------

export const CAMPAIGN_PATTERNS: PatternEntry[] = [
  // --- XZ Utils Backdoor (CVE-2024-3094) ---
  {
    name: "xz-get-cpuid",
    pattern: "_get_cpuid",
    description:
      "XZ Utils backdoor indicator: _get_cpuid function (CVE-2024-3094 payload hook)",
    severity: "critical",
    rule: "XZ_GET_CPUID",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "xz-lzma-crc64",
    pattern: "lzma_crc64",
    description:
      "XZ Utils backdoor indicator: lzma_crc64 function reference (CVE-2024-3094 hijacked symbol)",
    severity: "high",
    rule: "XZ_LZMA_CRC64",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "xz-build-inject",
    pattern:
      "gl_cv_host_cpu_c_abi.*=.*configure\\.ac|AM_CONDITIONAL.*\\bgl_INIT\\b|m4/.*\\.m4.*ifnot",
    description:
      "XZ Utils backdoor indicator: build system injection pattern in configure.ac/m4 macros",
    severity: "high",
    rule: "XZ_BUILD_INJECT",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.XZ_BUILD_INJECT,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "xz-obfuscated-test",
    pattern:
      "tests/files/.*\\.xz.*\\bhead\\b.*\\btr\\b|\\bxz\\b.*-d.*\\|.*\\bhead\\b.*-c",
    description:
      "XZ Utils backdoor indicator: obfuscated test file extraction pattern (hidden payload in test fixtures)",
    severity: "high",
    rule: "XZ_OBFUSCATED_TEST",
    correlatedMatcher: xzObfuscatedTestMatcher,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Codecov Bash Uploader ---
  {
    name: "codecov-curl-bash",
    pattern:
      "curl\\s+[^|]*codecov\\.io[^|]*\\|\\s*(?:bash|sh)",
    description:
      "Codecov bash uploader pattern: curl from codecov.io piped to shell (supply-chain risk vector)",
    severity: "high",
    rule: "CODECOV_CURL_BASH",
    correlatedMatcher: codecovCurlBashMatcher,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "codecov-exfil",
    pattern:
      "codecov[^;]*(?:ENV|TOKEN|SECRET|CREDENTIAL|PASSWORD|API_KEY)|(?:ENV|TOKEN|SECRET|CREDENTIAL|PASSWORD|API_KEY)[^;]*codecov",
    description:
      "Codecov exfiltration indicator: environment secrets referenced alongside codecov operations",
    severity: "high",
    rule: "CODECOV_EXFIL",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.CODECOV_EXFIL,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- SolarWinds SUNBURST ---
  {
    name: "sunburst-dga",
    pattern: "avsvmcloud\\.com",
    description:
      "SolarWinds SUNBURST indicator: DGA C2 domain avsvmcloud.com detected",
    severity: "critical",
    rule: "SUNBURST_DGA",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "sunburst-orion-class",
    pattern: "OrionImprovementBusinessLayer",
    description:
      "SolarWinds SUNBURST indicator: OrionImprovementBusinessLayer class name (backdoor namespace)",
    severity: "critical",
    rule: "SUNBURST_ORION_CLASS",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "sunburst-delayed-exec",
    pattern:
      "(?:Thread\\.Sleep|setTimeout|sleep)\\s*\\([^)]*?(?:[0-9]{7,}|\\d+\\s*\\*\\s*(?:3600|86400|60\\s*\\*\\s*60))",
    description:
      "SUNBURST-style delayed execution: sleep/timeout exceeding 1 hour (evasion technique to avoid sandbox analysis)",
    severity: "high",
    rule: "SUNBURST_DELAYED_EXEC",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.SUNBURST_DELAYED_EXEC,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- ua-parser-js hijack ---
  {
    name: "uaparser-miner",
    pattern:
      "(?:jsextension|jsextension\\.exe|__package\\.json).*(?:curl|wget|https?://)|(?:curl|wget|https?://).*(?:jsextension|jsextension\\.exe|__package\\.json)",
    description:
      "ua-parser-js hijack indicator: crypto miner download pattern (jsextension binary)",
    severity: "critical",
    rule: "UAPARSER_MINER",
    correlatedMatcher: uaParserMinerMatcher,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "uaparser-preinstall-download",
    pattern:
      "preinstall[\"']?\\s*:\\s*[\"'][^\"']*(?:curl|wget)\\s+https?://[^\"']*(?:\\.exe|\\.sh|\\.bat)",
    description:
      "ua-parser-js hijack indicator: preinstall script downloading executables from external domains",
    severity: "critical",
    rule: "UAPARSER_PREINSTALL_DL",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.UAPARSER_PREINSTALL_DL,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026) ---
  {
    name: "checkmarx-shai-hulud-third-coming",
    pattern: "Shai-Hulud:?\\s*The\\s+Third\\s+Coming",
    description:
      "Shai-Hulud Third Coming marker detected. Signature string used by the April 2026 Bitwarden CLI / Checkmarx KICS supply-chain breach to label exfiltration repositories.",
    severity: "critical",
    rule: "CHECKMARX_SHAI_HULUD_V3",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "checkmarx-mcp-addon",
    pattern: "mcpAddon\\.js",
    description:
      "Reference to mcpAddon.js. This is the hidden 'MCP addon' loader downloaded by the compromised Checkmarx KICS extensions in April 2026.",
    severity: "critical",
    rule: "CHECKMARX_MCP_ADDON",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "bitwarden-cli-loader",
    pattern: "\\b(?:bw_setup|bw1)\\.js\\b",
    description:
      "Reference to bw_setup.js or bw1.js. Loader and credential-stealing payload from the @bitwarden/cli@2026.4.0 hijack (April 2026).",
    severity: "critical",
    rule: "BITWARDEN_CLI_LOADER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- LofyGang / LofyStealer (April 2026) ---
  {
    name: "lofystealer-marker",
    pattern: "\\b(?:LofyStealer|GrabBot)\\b",
    description:
      "LofyStealer / GrabBot marker detected. Brazilian LofyGang campaign (April 2026) targeting Minecraft players with infostealer disguised as Minecraft hacks.",
    severity: "critical",
    rule: "LOFYSTEALER_MARKER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "lofygang-minecraft-lure",
    pattern: "(?:minecraft|mc)[\\s\\-_]*(?:hack|cheat|client|loader)\\b[^\\n]{0,100}\\b(?:steal|grab|exfil|token|password|wallet)",
    description:
      "Minecraft hack lure combined with credential/wallet theft language. LofyGang campaign distribution pattern.",
    severity: "high",
    rule: "LOFYGANG_MINECRAFT_LURE",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- DPRK AI-inserted npm malware (April 2026) ---
  {
    name: "dprk-validate-sdk",
    pattern: "@validate-sdk\\/v2",
    description:
      "Reference to @validate-sdk/v2 detected. DPRK-linked malicious npm package (April 2026) inserted as a dependency by Claude Opus LLM in social engineering attacks.",
    severity: "critical",
    rule: "DPRK_VALIDATE_SDK",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- ZiChatBot PyPI campaign (May 2026) ---
  {
    name: "zichatbot-package-name",
    pattern: "\\b(?:uuid32-utils|colorinal|termncolor)\\b",
    description:
      "Reference to ZiChatBot PyPI campaign package (uuid32-utils, colorinal, termncolor). May 2026 campaign suspected linked to APT32/OceanLotus, dropping terminate.dll/terminate.so via PyPI install.",
    severity: "critical",
    rule: "ZICHATBOT_PACKAGE",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Mini Shai-Hulud / TeamPCP supply chain worm (April 2026) ---
  {
    name: "mini-shai-hulud-marker",
    pattern: "A\\s+Mini\\s+Shai-Hulud\\s+has\\s+Appeared",
    description:
      "Mini Shai-Hulud campaign marker detected. Signature description string used by the April 2026 SAP CAP / PyTorch Lightning / Intercom worm to label dead-drop GitHub repositories.",
    severity: "critical",
    rule: "MINI_SHAI_HULUD_MARKER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "mini-shai-hulud-bun-loader",
    pattern: "[\"'`/\\\\\\s\\[]\\s*(?:setup\\.mjs|execution\\.js)\\b",
    description:
      "Reference to setup.mjs or execution.js detected. Loader filenames used by the Mini Shai-Hulud preinstall worm to download Bun runtime and execute the credential stealer payload.",
    severity: "high",
    rule: "MINI_SHAI_HULUD_LOADER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "mini-shai-hulud-preinstall-bun",
    pattern: "preinstall[\"']?\\s*:\\s*[\"'][^\"']*\\bbun\\b[^\"']*(?:setup\\.mjs|execution\\.js)",
    description:
      "preinstall script invoking Bun on setup.mjs or execution.js. Direct fingerprint of the Mini Shai-Hulud worm's npm hijack chain.",
    severity: "critical",
    rule: "MINI_SHAI_HULUD_PREINSTALL",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.MINI_SHAI_HULUD_PREINSTALL,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Mini Shai-Hulud @antv / Nx Console / actions-cool wave (May 2026) ---
  // Triple-wave TeamPCP attack: @antv ecosystem (637 versions), Nx Console
  // nrwl.angular-console 18.95.0 VS Code extension, and actions-cool/issues-helper +
  // actions-cool/maintain-one-comment GitHub Action tag redirection. Persistence backdoor
  // installs `cat.py` Python daemon under kitty/kitty-monitor naming, polling GitHub Search
  // for dead-drop commands with marker query "firedalazer".
  {
    name: "antv-wave-kitty-cat-py",
    pattern: "(?:kitty/cat\\.py|com\\.user\\.kitty-monitor|kitty-monitor\\.service)",
    description:
      "Reference to kitty/cat.py Python backdoor or kitty-monitor persistence service. Persistence chain dropped by the May 2026 Mini Shai-Hulud @antv / Nx Console wave (TeamPCP).",
    severity: "critical",
    rule: "ANTV_WAVE_KITTY_PERSISTENCE",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "antv-wave-firedalazer-deaddrop",
    pattern: "firedalazer",
    description:
      "Reference to 'firedalazer' marker. GitHub Search API dead-drop query string used by the Nx Console 18.95.0 backdoor (May 2026 Mini Shai-Hulud wave).",
    severity: "critical",
    rule: "ANTV_WAVE_FIREDALAZER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "antv-wave-otel-c2-masquerade",
    pattern: "m-kosche\\.com[^\"']*api/public/otel/v1/traces",
    description:
      "Mini Shai-Hulud @antv wave C2 exfiltration endpoint masquerading as an OpenTelemetry traces collector at t.m-kosche.com (May 2026).",
    severity: "critical",
    rule: "ANTV_WAVE_OTEL_C2",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.ANTV_WAVE_OTEL_C2,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- DPRK OtterCookie Node.js stealer (May 22, 2026) ---
  // SANS ISC diary 33006. Sample uploaded to VT as "extracted-decoded.js"; obfuscator.io-style;
  // targets 41 crypto-wallet Chrome extensions and 200+ sensitive file patterns. Exfil to
  // 216.126.225.243 ports 8085 (browser creds) / 8086 (file uploads) / 8087 (WebSocket reverse shell).
  {
    name: "ottercookie-hmac-key",
    pattern: "SuperStr0ngSecret@\\)@\\^",
    description:
      "Reference to 'SuperStr0ngSecret@)@^' detected. Hardcoded HMAC-SHA256 key embedded in the DPRK OtterCookie Node.js stealer (SANS ISC 33006, May 2026). Highly specific fingerprint.",
    severity: "critical",
    rule: "OTTERCOOKIE_HMAC_KEY",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "ottercookie-notify-endpoint",
    pattern: "216\\.126\\.225\\.243:808[567](?:/api/notify)?",
    description:
      "Reference to 216.126.225.243:8085/8086/8087 detected. DPRK OtterCookie stealer C2 endpoints (browser creds / file uploads / WebSocket reverse shell at /api/notify).",
    severity: "critical",
    rule: "OTTERCOOKIE_C2_ENDPOINT",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- SleeperGem malicious RubyGems releases (July 20, 2026) ---
  // StepSecurity / Aikido via The Hacker News. The gem loader pulls deploy.sh plus a native
  // binary from an attacker account on git.disroot.org (a legitimate public Forgejo instance -
  // only the attacker's path is a signature, never the bare host), then plants a setuid root
  // copy of the system shell at a path that mimics a networking utility. The dropped daemon
  // dir (~/.local/share/gcm) is deliberately NOT a signature: the real Git Credential Manager
  // uses it too.
  {
    name: "sleepergem-payload-host",
    pattern: "git\\.disroot\\.org/git-ecosystem",
    description:
      "Reference to the git.disroot.org/git-ecosystem Forgejo account detected. SleeperGem second-stage payload host (deploy.sh + native daemon) impersonating an official ecosystem account (July 2026).",
    severity: "critical",
    rule: "SLEEPERGEM_PAYLOAD_HOST",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "sleepergem-setuid-ping6",
    pattern: "/usr/local/sbin/ping6",
    description:
      "Reference to /usr/local/sbin/ping6 detected. SleeperGem plants a setuid root copy of the system shell at this path to mimic a networking utility; the real ping6 ships in /bin or /usr/bin, never /usr/local/sbin.",
    severity: "high",
    rule: "SLEEPERGEM_SETUID_SHELL",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Megalodon GitHub Actions workflow injection (May 22, 2026) ---
  // 5,718 malicious commits to 5,561 GitHub repositories in 6 hours via throwaway accounts
  // forged as "build-bot", "auto-ci", "ci-bot", "pipeline-bot". Injected workflows ran
  // base64-encoded bash that exfiltrated CI env vars, AWS / GCP credentials, SSH private keys,
  // OIDC tokens, Docker / Kubernetes / Terraform configs to 216.126.225.129:8443.
  {
    name: "megalodon-c2-endpoint",
    pattern: "216\\.126\\.225\\.129(?::8443)?",
    description:
      "Reference to 216.126.225.129:8443 detected. Megalodon GitHub Actions workflow-injection C2 (May 2026); collects base64-encoded CI secrets, AWS/GCP credentials, SSH keys, OIDC tokens, and source-code secrets.",
    severity: "critical",
    rule: "MEGALODON_C2_ENDPOINT",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- coa/rc npm hijack ---
  {
    name: "coa-rc-sdd-dll",
    pattern: "sdd\\.dll",
    description:
      "coa/rc npm hijack indicator: reference to sdd.dll payload (trojanized npm package artifact)",
    severity: "critical",
    rule: "COA_RC_SDD_DLL",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "coa-rc-postinstall-encoded",
    pattern:
      "postinstall[\"']?\\s*:\\s*[\"'][^\"']*(?:compile\\.js|(?:Buffer|atob).*(?:exec|spawn|child_process))",
    description:
      "coa/rc npm hijack indicator: postinstall script with encoded payload execution",
    severity: "critical",
    rule: "COA_RC_POSTINSTALL",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.COA_RC_POSTINSTALL,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Miasma / @redhat-cloud-services Mini Shai-Hulud variant (June 2026) ---
  // BleepingComputer + Socket.dev disclosed (June 1, 2026) that 32 packages under
  // Red Hat's @redhat-cloud-services namespace were trojanized (96 versions) via a
  // compromised Red Hat employee GitHub account + abused GitHub Actions workflow.
  // Payload is a Shai-Hulud descendant labelled "Miasma: The Spreading Blight",
  // preinstall runs a ~4.2 MB node index.js stealing GitHub Actions secrets, AWS
  // and GCP and Azure credentials, HashiCorp Vault tokens, Kubernetes SA tokens,
  // npm and PyPI publishing tokens, SSH keys, Docker creds, GPG keys, and .env
  // files. Exfiltration into ~309 attacker-controlled GitHub repos.
  {
    name: "miasma-spreading-blight-marker",
    pattern: "Miasma:?\\s*The\\s+Spreading\\s+Blight",
    description:
      "Miasma campaign marker detected. Signature string used by the June 2026 @redhat-cloud-services Mini Shai-Hulud variant to label dead-drop GitHub repositories.",
    severity: "critical",
    rule: "MIASMA_SPREADING_BLIGHT_MARKER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Miasma LeoPlatform / GitHub Actions wave (The Hacker News, June 26, 2026) ---
  // Latest evolution of the Mini Shai-Hulud / Miasma / Hades worm family. Compromised
  // npm maintainer "czirker" republished the LeoPlatform / RStreams SDK + hexo-* packages
  // (version-pinned in ioc-blocklist), propagated to Go, and abused the
  // codfish/semantic-release-action GitHub Action. "RevokeAndItGoesKaboom" is the unique
  // token-relay marker for the current iteration (firedalazer remains the GitHub commit-
  // polling string, already covered by ANTV_WAVE_FIREDALAZER).
  {
    name: "miasma-leo-revoke-kaboom-marker",
    pattern: "RevokeAndItGoesKaboom",
    description:
      "Reference to 'RevokeAndItGoesKaboom' detected. Token-relay marker used by the June 2026 Miasma LeoPlatform Mini Shai-Hulud wave (czirker-compromised leo-* / rstreams-* npm packages).",
    severity: "critical",
    rule: "MIASMA_LEO_REVOKE_KABOOM",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
];

// ---------------------------------------------------------------------------
// PyPI-specific patterns (Python supply-chain attacks)
// ---------------------------------------------------------------------------

/** Patterns for detecting malicious code in Python packages */
export const PYPI_FILE_PATTERNS: PatternEntry[] = [
  // System command execution in setup files
  {
    name: "setup-os-system",
    pattern: "os\\.system\\s*\\(",
    description: "os.system() call detected in package file (potential code execution during install)",
    severity: "high",
    rule: "PYPI_OS_SYSTEM",
    notTestFile: true,
  },
  {
    name: "setup-subprocess",
    pattern: "subprocess\\.(?:call|run|Popen|check_output|check_call)\\s*\\(",
    description: "subprocess execution detected in package file (potential code execution during install)",
    severity: "high",
    rule: "PYPI_SUBPROCESS",
    notTestFile: true,
  },

  // Encoded execution
  {
    name: "python-exec-encoded",
    pattern: "exec\\s*\\(\\s*(?:base64\\.b64decode|codecs\\.decode|bytes\\.fromhex)\\s*\\(",
    description: "exec() with encoded/decoded content detected (obfuscated code execution)",
    severity: "critical",
    rule: "PYPI_EXEC_ENCODED",
    notTestFile: true,
  },
  {
    name: "python-eval-encoded",
    pattern: "eval\\s*\\(\\s*(?:base64\\.b64decode|codecs\\.decode|bytes\\.fromhex)\\s*\\(",
    description: "eval() with encoded/decoded content detected (obfuscated code execution)",
    severity: "critical",
    rule: "PYPI_EVAL_ENCODED",
    notTestFile: true,
  },
  {
    name: "python-exec-compile",
    pattern: "exec\\s*\\(\\s*compile\\s*\\(",
    description: "exec(compile()) detected (dynamic code compilation and execution)",
    severity: "high",
    rule: "PYPI_EXEC_COMPILE",
    notTestFile: true,
  },

  // Base64 import smuggling
  {
    name: "python-import-base64",
    pattern: "__import__\\s*\\(\\s*['\"]base64['\"]\\s*\\)",
    description: "__import__('base64') detected (hidden import often used for payload decoding)",
    severity: "high",
    rule: "PYPI_IMPORT_BASE64",
    notTestFile: true,
  },
  {
    name: "python-import-codecs",
    pattern: "__import__\\s*\\(\\s*['\"]codecs['\"]\\s*\\)",
    description: "__import__('codecs') detected (hidden import for obfuscation)",
    severity: "medium",
    rule: "PYPI_IMPORT_CODECS",
    notTestFile: true,
  },
  {
    name: "python-import-marshal",
    pattern: "__import__\\s*\\(\\s*['\"]marshal['\"]\\s*\\)",
    description: "__import__('marshal') detected (bytecode-level obfuscation)",
    severity: "high",
    rule: "PYPI_IMPORT_MARSHAL",
    notTestFile: true,
  },

  // Network activity in setup files
  {
    name: "python-urllib-setup",
    pattern: "urllib\\.request\\.urlopen\\s*\\(",
    description: "urllib.request.urlopen() detected (network access, potential payload download)",
    severity: "high",
    rule: "PYPI_URLLIB_FETCH",
    notTestFile: true,
  },
  {
    name: "python-requests-setup",
    pattern: "requests\\.(?:get|post)\\s*\\(",
    description: "requests.get/post() detected (network access during install)",
    severity: "medium",
    rule: "PYPI_REQUESTS_FETCH",
    notTestFile: true,
  },

  // Suspicious pip install in setup.py
  {
    name: "python-pip-install-url",
    pattern: "pip\\s+install\\s+(?:--index-url|--extra-index-url|-i)\\s+https?://(?!pypi\\.org)",
    description: "pip install from non-PyPI URL detected (potential malicious package index)",
    severity: "critical",
    rule: "PYPI_SUSPICIOUS_INDEX",
    notTestFile: true,
  },
  {
    name: "python-pip-install-git",
    pattern: "pip\\s+install\\s+git\\+https?://",
    description: "pip install from git URL in setup file (unverified dependency source)",
    severity: "medium",
    rule: "PYPI_GIT_DEPENDENCY",
    notTestFile: true,
  },

  // Data exfiltration patterns in Python
  {
    name: "python-env-exfil",
    pattern: "os\\.environ\\b[^;\\n]*(?:urllib|requests|http\\.client|socket)",
    description: "Environment variable access combined with network activity (data exfiltration pattern)",
    severity: "high",
    rule: "PYPI_ENV_EXFILTRATION",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.PYPI_ENV_EXFILTRATION,
    notTestFile: true,
  },
  {
    name: "python-hostname-exfil",
    pattern: "socket\\.gethostname\\s*\\(\\)[^;\\n]*(?:urllib|requests|http)",
    description: "Hostname collection combined with network activity (reconnaissance/exfiltration)",
    severity: "high",
    rule: "PYPI_HOSTNAME_EXFIL",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.PYPI_HOSTNAME_EXFIL,
    notTestFile: true,
  },

  // Install command class override
  {
    name: "python-install-class-override",
    pattern: "class\\s+\\w+\\s*\\(\\s*(?:install|develop|bdist_egg|egg_info|sdist)\\s*\\)",
    description: "Custom command class inheriting from setuptools install/develop command",
    severity: "medium",
    rule: "PYPI_INSTALL_CLASS_OVERRIDE",
    notTestFile: true,
  },

  // marshal.loads (bytecode deserialization)
  {
    name: "python-marshal-loads",
    pattern: "marshal\\.loads\\s*\\(",
    description: "marshal.loads() detected (bytecode deserialization, common obfuscation)",
    severity: "high",
    rule: "PYPI_MARSHAL_LOADS",
    notTestFile: true,
  },

  // exec with marshal.loads
  {
    name: "python-exec-marshal",
    pattern: "exec\\s*\\(\\s*marshal\\.loads\\s*\\(",
    description: "exec(marshal.loads()) detected (executing deserialized bytecode payload)",
    severity: "critical",
    rule: "PYPI_EXEC_MARSHAL",
    notTestFile: true,
  },

  // base64.b64decode whose result is actually passed to exec (same line or a
  // short multi-line block). Anchoring exec at a statement boundary prevents
  // comments and string literals from turning a defensive mention into code.
  {
    name: "python-b64decode-exec-combined",
    pattern:
      "(?:" +
      "(?:^|[\\n;:])[ \\t]*exec\\s*\\(\\s*base64\\.b64decode\\s*\\([^\\n)]*\\)(?:\\.decode\\s*\\([^\\n)]*\\))?\\s*\\)" +
      "|" +
      "(?:^|\\n)[ \\t]*([A-Za-z_]\\w*)(?:[ \\t]*:[^=\\n]+)?[ \\t]*=[ \\t]*base64\\.b64decode\\s*\\([^\\n)]*\\)[\\s\\S]*?(?:[\\n;:])[ \\t]*exec\\s*\\(\\s*\\1(?:\\.decode\\s*\\([^\\n)]*\\))?\\s*(?:,|\\))" +
      ")",
    description: "base64.b64decode combined with exec (obfuscated execution)",
    severity: "critical",
    rule: "PYPI_B64_EXEC_COMBINED",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.PYPI_B64_EXEC_COMBINED,
    // decode then exec is almost always two statements. 4 lines is enough for
    // an assignment + blank line + exec without spanning half a module.
    spansLines: 4,
    notTestFile: true,
  },
];

/** Setup file names to check for install hooks */
export const PYPI_SETUP_FILES = new Set([
  "setup.py",
  "setup.cfg",
  "pyproject.toml",
]);

/** Suspicious install hook patterns in setup.py */
export const PYPI_INSTALL_HOOK_PATTERNS: PatternEntry[] = [
  {
    name: "setup-cmdclass-install",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]install['\"]",
    description: "Custom install command class detected (code runs during pip install)",
    severity: "medium",
    rule: "PYPI_CUSTOM_INSTALL",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_INSTALL,
    // cmdclass={ 'install': ... } is almost always pretty-printed.
    spansLines: 6,
    notTestFile: true,
  },
  {
    name: "setup-cmdclass-develop",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]develop['\"]",
    description: "Custom develop command class detected (code runs during pip install -e)",
    severity: "medium",
    rule: "PYPI_CUSTOM_DEVELOP",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_DEVELOP,
    spansLines: 6,
    notTestFile: true,
  },
  {
    name: "setup-cmdclass-egg-info",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]egg_info['\"]",
    description: "Custom egg_info command class detected (code runs during package metadata generation)",
    severity: "medium",
    rule: "PYPI_CUSTOM_EGG_INFO",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_EGG_INFO,
    spansLines: 6,
    notTestFile: true,
  },
  {
    name: "setup-cmdclass-sdist",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]sdist['\"]",
    description: "Custom sdist command class detected (code runs during source distribution build)",
    severity: "low",
    rule: "PYPI_CUSTOM_SDIST",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_SDIST,
    spansLines: 6,
    notTestFile: true,
  },
  {
    name: "setup-cmdclass-build-ext",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]build_ext['\"]",
    description: "Custom build_ext command class detected (code runs during native extension build)",
    severity: "low",
    rule: "PYPI_CUSTOM_BUILD_EXT",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_BUILD_EXT,
    spansLines: 6,
    notTestFile: true,
  },
];

/** Python file extensions to scan */
export const PYTHON_EXTENSIONS = new Set([
  ".py",
  ".pyw",
  ".pyi",
]);

/** Known typosquatted PyPI package name patterns */
export const PYPI_TYPOSQUAT_PATTERNS: string[] = [
  // Fake Paysafe payment SDKs on PyPI (Socket, July 8, 2026) - 4 packages
  // (v1.0.0). PyPI normalizes "-" and "_", so both separators are matched.
  "^(paysafe[-_](kyc|payments|sdk|api))$",
  // Typosquats of popular PyPI packages
  "^(reqeusts|requsets|r3quests|reequests|requets)$",
  "^(crypt0graphy|crytography|cryptograhpy)$",
  "^(python-dateutill|python3-dateutil|py-dateutil)$",
  "^(numppy|numpi|numpie)$",
  "^(pandsa|pands)$",
  "^(djang0|dajngo|djnago)$",
  "^(urlib3|urllib33)$",
  "^(colourama|colrama|coloram)$",
  "^(setuptool|setuptoolss)$",
  "^(flaskk|flaask|fl4sk)$",

  // TrapDoor cross-ecosystem credential stealer - PyPI packages (May 25, 2026)
  // 7 malicious PyPI packages from the same actor (ddjidd564) operating the npm /
  // Crates.io waves; targets DeFi / Web3 / Solidity / Ethereum developer tooling.
  "^(cryptowallet-safety|data-pipeline-check|defi-risk-scanner|env-loader-cli|eth-security-auditor|git-config-sync|solidity-build-guard)$",

  // parsimonius: PyPI typosquat of "parsimonious" deploying a Telegram-based backdoor
  // (also published to npm; The Hacker News Weekly Recap, June 8, 2026).
  "^parsimonius$",

  // ChocoPoC RAT / fake PoC exploit repos (The Hacker News, July 2, 2026)
  // Malicious PyPI packages carrying the ChocoPoC data-stealing trojan, distributed
  // via fake Python PoC exploit repos targeting vulnerability researchers. skytext / frint
  // are the current wave; slogsec / logcrypt.cryptography are the same actor's late-2025
  // packages. Compiled payloads gradient.so (Linux) / gradient.pyd (Windows); upload server
  // 91.132.163.78 (in ioc-blocklist). Bare names - fully malicious with no legitimate history.
  "^(frint|skytext|slogsec|logcrypt\\.cryptography)$",

  // Very long single-word lowercase names
  "^[a-z]{20,}$",
];

// ---------------------------------------------------------------------------
// Binary / native addon detection (T-007)
// ---------------------------------------------------------------------------

/** File extensions that indicate binary/native addons */
export const BINARY_EXTENSIONS = new Set([
  ".node",
  ".so",
  ".dll",
  ".dylib",
  ".exe",
  ".bin",
]);

/** Patterns in install scripts that indicate prebuilt binary downloads */
export const BINARY_DOWNLOAD_PATTERNS: PatternEntry[] = [
  {
    name: "node-pre-gyp",
    pattern: "node-pre-gyp\\s+install",
    description: "node-pre-gyp prebuilt binary download detected in install script",
    severity: "medium",
    rule: "BINARY_PREGYP_DOWNLOAD",
    notTestFile: true,
  },
  {
    name: "prebuild-install",
    pattern: "prebuild-install|prebuildify",
    description: "Prebuilt binary installer detected in install script",
    severity: "medium",
    rule: "BINARY_PREBUILD_INSTALL",
    notTestFile: true,
  },
  {
    name: "binary-download-curl",
    pattern:
      "(?:curl|wget)\\s+.*\\.(?:node|so|dll|dylib|exe)(?:\\s|$|[\"'])",
    description: "Install script downloads a binary/native file directly",
    severity: "high",
    rule: "BINARY_DIRECT_DOWNLOAD",
    correlatedMatcher: binaryDirectDownloadMatcher,
    notTestFile: true,
  },
  {
    name: "node-gyp-rebuild",
    pattern: "node-gyp\\s+rebuild",
    description: "Native addon compilation via node-gyp detected",
    severity: "low",
    rule: "BINARY_NATIVE_COMPILE",
    notTestFile: true,
  },
];

/** Known legitimate packages that use native addons */
export const KNOWN_NATIVE_PACKAGES = new Set([
  "better-sqlite3",
  "sharp",
  "canvas",
  "bcrypt",
  "argon2",
  "sqlite3",
  "node-sass",
  "fsevents",
  "esbuild",
  "lightningcss",
  "swc",
  "@swc/core",
  "turbo",
  "@parcel/watcher",
  "keytar",
  "node-pty",
  "bufferutil",
  "utf-8-validate",
  "cpu-features",
  "microtime",
  "farmhash",
  "xxhash-addon",
  "deasync",
  "sodium-native",
  "leveldown",
  "lmdb",
  "libsql",
  "re2",
  "node-datachannel",
  "unix-dgram",
]);

// ---------------------------------------------------------------------------
// Network beacon and crypto miner detection (T-008)
// ---------------------------------------------------------------------------

export const BEACON_MINER_PATTERNS: PatternEntry[] = [
  // Beacon patterns: periodic network calls
  {
    name: "beacon-setinterval-fetch",
    pattern:
      "setInterval\\s*\\(.*(?:fetch|https?\\.(?:get|request)|axios|got|node-fetch|XMLHttpRequest)",
    description:
      "Periodic network request detected (setInterval + fetch). This is a common beacon pattern for C2 communication.",
    severity: "medium",
    rule: "BEACON_INTERVAL_FETCH",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.BEACON_INTERVAL_FETCH,
    notFilePattern: /\.min\.(js|css)$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },
  {
    name: "beacon-settimeout-fetch",
    pattern:
      "setTimeout\\s*\\(.*(?:fetch|https?\\.(?:get|request)|axios|got|node-fetch)",
    description:
      "Delayed network request detected (setTimeout + fetch). May be a beacon with jitter.",
    severity: "medium",
    rule: "BEACON_TIMEOUT_FETCH",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.BEACON_TIMEOUT_FETCH,
    notTestFile: true,
  },

  // Crypto miner patterns
  {
    name: "stratum-protocol",
    pattern:
      "stratum\\+(?:tcp|ssl|tls)://",
    description:
      "Stratum mining pool protocol reference detected. This is used exclusively for cryptocurrency mining.",
    severity: "critical",
    rule: "MINER_STRATUM_PROTOCOL",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "mining-pool-domain",
    pattern: MINER_POOL_DOMAIN_SOURCE,
    description:
      "Known mining pool domain detected. This package may contain a cryptocurrency miner.",
    severity: "critical",
    rule: "MINER_POOL_DOMAIN",
    correlatedMatcher: minerPoolDomainMatcher,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "mining-config-keys",
    pattern:
      "(?:^|[,{])\\s*([\"'`])(?:wallet|worker|pool_address|pool_password|mining_address|hashrate|coin|algo)\\1\\s*:",
    description:
      "Mining-specific configuration keys detected in one object scope. This may be a cryptocurrency miner configuration.",
    severity: "high",
    rule: "MINER_CONFIG_KEYS",
    correlatedMatcher: miningConfigKeysMatcher,
    notFilePattern: /\.json$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },
  {
    name: "coinhive-reference",
    pattern:
      "coinhive|cryptonight|monero\\.(?:crypto|mine)|xmrig|xmr-stak",
    description:
      "Cryptocurrency miner library reference detected (CoinHive, XMRig, etc.).",
    severity: "critical",
    rule: "MINER_LIBRARY_REF",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // Suspicious WebSocket connections
  {
    name: "websocket-external",
    pattern:
      "new\\s+WebSocket\\s*\\(\\s*[\"'`]wss?://(?!localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)",
    description:
      "WebSocket connection to external host detected. Verify this is expected for the package's functionality.",
    severity: "medium",
    rule: "BEACON_WEBSOCKET_EXTERNAL",
    notTestFile: true,
  },

  // Protestware patterns: locale/timezone checks + destructive actions
  {
    name: "protestware-locale-destructive",
    pattern:
      "(?:locale|timezone|timeZone|country|getTimezone|Intl\\.DateTimeFormat).*(?:fs\\.(?:rm|rmdir|unlink|truncate|ftruncate)|process\\.exit|child_process|execSync|rimraf)",
    description:
      "Locale/timezone check followed by destructive code. This is a protestware pattern that targets users by geography.",
    severity: "critical",
    rule: "PROTESTWARE_LOCALE_DESTRUCT",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.PROTESTWARE_LOCALE_DESTRUCT,
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "protestware-geo-ip",
    pattern:
      "(?:geoip|ip-api|ipinfo|freegeoip|ipgeolocation).*(?:fs\\.(?:rm|rmdir|unlink)|process\\.exit|execSync)",
    description:
      "GeoIP lookup combined with destructive operations detected. This is a protestware/geo-targeted attack pattern.",
    severity: "critical",
    rule: "PROTESTWARE_GEOIP_DESTRUCT",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.PROTESTWARE_GEOIP_DESTRUCT,
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// File extensions to scan
// ---------------------------------------------------------------------------

export const SCANNABLE_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
  ".mjs",
  ".cjs",
  ".py",
  ".sh",
  ".bash",
  ".json",
  ".yml",
  ".yaml",
  ".toml",
  ".rs",
  ".go",
  ".tf",
  ".hcl",
  ".svg",
  ".md",
]);

/** Maximum file size to scan (in bytes). Files larger than this are skipped. */
export const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

/**
 * Structured finding for an oversized scannable file (issue #54). Before
 * v5.12.0 the core, VSIX, npm, and PyPI scanners silently `continue`d past
 * files above MAX_FILE_SIZE - a coverage gap an attacker can create on
 * purpose by padding a payload past the limit. severity "info" is a
 * transparency signal: it never affects exit codes (only high/critical do)
 * and can be filtered with --min-severity or --exclude FILE_TOO_LARGE_SKIPPED.
 * The oversized body is never read; only fs.stat metadata is reported.
 */
export function makeOversizedSkipFinding(
  relativePath: string,
  sizeBytes: number,
): Finding {
  const sizeMb = (sizeBytes / (1024 * 1024)).toFixed(1);
  const limitMb = (MAX_FILE_SIZE / (1024 * 1024)).toFixed(0);
  return {
    rule: "FILE_TOO_LARGE_SKIPPED",
    description: `File exceeds the ${limitMb} MB scan limit (${sizeMb} MB) - content was NOT scanned`,
    severity: "info",
    confidence: 1.0,
    category: "info",
    file: relativePath,
    recommendation:
      "This file was skipped by content scanning because of its size. Inspect it manually or verify it is a legitimate large asset - oversized files can be used to smuggle payloads past size-limited scanners.",
  };
}

// ---------------------------------------------------------------------------
// Build tool config patterns (v4.0)
// ---------------------------------------------------------------------------

export const BUILD_TOOL_PATTERNS: PatternEntry[] = [
  {
    name: "build-plugin-download",
    pattern:
      "(?:require|import)\\s*\\(?[\"'][^\"']+[\"']\\)?[^;]*(?:fetch|https?\\.get|axios|got|download)",
    description:
      "Build config plugin downloads code from an external URL during build.",
    severity: "high",
    rule: "BUILD_PLUGIN_DOWNLOAD",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.BUILD_PLUGIN_DOWNLOAD,
    notTestFile: true,
  },
  {
    name: "build-plugin-exec",
    pattern:
      "(?:child_process|execSync|spawnSync|exec)\\b",
    description:
      "Build config executes system commands. Verify this is expected build behavior.",
    severity: "high",
    rule: "BUILD_PLUGIN_EXEC",
    notTestFile: true,
  },
  {
    name: "build-env-exfil",
    pattern:
      "process\\.env\\b.*(?:fetch|https?\\.(?:get|request)|axios|got)|(?:fetch|https?\\.(?:get|request)|axios|got).*process\\.env",
    description:
      "Build config reads environment variables near network requests (potential secret exfiltration).",
    severity: "critical",
    rule: "BUILD_ENV_EXFIL",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.BUILD_ENV_EXFIL,
    notTestFile: true,
  },
  {
    name: "build-dynamic-require",
    pattern:
      "require\\s*\\(\\s*(?:process\\.env|`|\\+)",
    description:
      "Dynamic require with variable input in build config. Can load unexpected modules.",
    severity: "medium",
    rule: "BUILD_DYNAMIC_REQUIRE",
    notTestFile: true,
  },
];

/** Build config file names */
export const BUILD_CONFIG_FILES = new Set([
  "webpack.config.js",
  "webpack.config.ts",
  "webpack.config.mjs",
  "rollup.config.js",
  "rollup.config.ts",
  "rollup.config.mjs",
  "vite.config.js",
  "vite.config.ts",
  "vite.config.mjs",
  "next.config.js",
  "next.config.ts",
  "next.config.mjs",
  "esbuild.config.js",
  "esbuild.config.mjs",
  "turbo.json",
  "babel.config.js",
  "babel.config.json",
  ".babelrc",
]);

// ---------------------------------------------------------------------------
// Monorepo / workspace patterns (v4.0)
// ---------------------------------------------------------------------------

export const MONOREPO_PATTERNS: PatternEntry[] = [
  {
    name: "workspace-root-postinstall",
    pattern:
      '"postinstall"\\s*:\\s*"[^"]*(?:curl|wget|node\\s+-e|bash|sh\\s+-c)',
    description:
      "Root-level postinstall in monorepo workspace. Affects all workspace packages.",
    severity: "high",
    rule: "WORKSPACE_ROOT_POSTINSTALL",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.WORKSPACE_ROOT_POSTINSTALL,
    notTestFile: true,
  },
  {
    name: "workspace-private-publish",
    pattern:
      '"private"\\s*:\\s*false[^}]*"publishConfig"',
    description:
      "Workspace package marked as non-private with publishConfig. Verify it should be public.",
    severity: "high",
    rule: "WORKSPACE_PRIVATE_PUBLISH",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.WORKSPACE_PRIVATE_PUBLISH,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// New campaign signatures (v4.0 - 2025/2026)
// ---------------------------------------------------------------------------

export const CAMPAIGN_PATTERNS_V2: PatternEntry[] = [
  // Shai-Hulud npm Worm
  {
    name: "shai-hulud-self-replicate",
    pattern:
      "child_process.*npm.*publish|(?:npm\\s+publish|\\bnpm\\b[^\\n]*\\bpublish\\b)",
    description:
      "Self-publishing pattern detected. The Shai-Hulud worm replicates by publishing infected packages via npm.",
    severity: "critical",
    rule: "SHAI_HULUD_WORM",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.SHAI_HULUD_WORM,
    onlyExtensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash"],
    // A bare "npm publish" string is a RELEASE SCRIPT, not a worm: every library
    // repo has one, and this rule made all of them critical on sight. The worm
    // signature is publishing PROGRAMMATICALLY with STOLEN credentials, so the
    // file must also show credential access AND process execution. The campaign's
    // package@version set is pinned exactly in KNOWN_BAD_NPM_VERSIONS regardless,
    // so an install of a real Shai-Hulud release blocks on the pin, not on this.
    requiresInFileMatcher: hasShaiHuludCorroboration,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "shai-hulud-npmrc-steal",
    pattern:
      "\\.npmrc|npm_config_userconfig|NPM_TOKEN",
    description:
      "npm credentials access pattern. The Shai-Hulud worm steals .npmrc tokens to publish malicious packages.",
    severity: "high",
    rule: "SHAI_HULUD_CRED_STEAL",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL,
    spansLines: 8,
    onlyExtensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash"],
    requiresInFileMatcher: hasShaiHuludCredentialFlowSignals,
    // One authoritative structural matcher owns its language-specific linear
    // branches and source-to-sink decision. A second metadata regex or duplicate
    // rule entry could silently diverge from that contract.
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  // Expanded protestware
  {
    name: "protestware-ip-geo-destruct",
    pattern:
      "(?:ip-api|ipinfo|geoip-lite|maxmind|MaxMind|geoip2|GeoIP2?).*" +
      "(?:" +
      "\\b(?:unlink(?:Sync)?|rmdir(?:Sync)?|rm(?:Sync)?)\\s*\\(\\s*" +
      "(?![^)\\n]*(?:temp|tmp|archive|cache|download|\\.mmdb\\b))" +
      "(?=[^)\\n]*(?:[\"'](?:/(?!/?(?:tmp|var/tmp)(?:/|[\"']))|[A-Za-z]:[\\\\/])|process\\.cwd\\s*\\(|__dirname|homedir\\s*\\(|HOME|USERPROFILE))" +
      "|\\brm\\s+-rf\\s+(?:[\"']?(?:/(?!tmp(?:/|\\s|[\"']))|~|\\$HOME|%USERPROFILE%|[A-Za-z]:[\\\\/])|process\\.cwd\\s*\\(\\)|__dirname)" +
      "|\\bdel\\s+/[a-z]*\\s+(?:[A-Za-z]:[\\\\/]|%USERPROFILE%)" +
      "|\\bformat\\s+c:" +
      ")",
    description:
      "IP geolocation combined with destructive file operations. Advanced protestware pattern.",
    severity: "critical",
    rule: "PROTESTWARE_IP_GEO_V2",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.PROTESTWARE_IP_GEO_V2,
    // Geo lookup then destructive call is often two statements in a branch.
    spansLines: 8,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
];

// ---------------------------------------------------------------------------
// Extended obfuscation patterns (v4.0)
// ---------------------------------------------------------------------------

export const OBFUSCATION_PATTERNS_V2: PatternEntry[] = [
  {
    name: "template-literal-exec",
    pattern:
      "eval\\s*\\(\\s*`",
    description:
      "eval() with template literal. Template literals can hide complex expressions.",
    severity: "high",
    rule: "TEMPLATE_LITERAL_EXEC",
    notTestFile: true,
  },
  {
    name: "proxy-handler-trap",
    pattern:
      "new\\s+Proxy\\s*\\([^)]*\\{[^}]*(?:get|set|apply|construct)\\s*:[^}]*?" +
      "(?:\\beval\\s*\\(|\\bnew\\s+Function\\b|\\bfetch\\s*\\(|\\baxios(?:\\.\\w+)?\\s*\\(|\\bXMLHttpRequest\\s*\\(|\\bchild_process\\.(?:exec(?:File)?(?:Sync)?|spawn(?:Sync)?)\\s*\\(|\\bexecSync\\s*\\(|\\batob\\s*\\()",
    description:
      "Proxy handler trap detected. Proxy objects can intercept and modify all object operations.",
    severity: "high",
    rule: "PROXY_HANDLER_TRAP",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.PROXY_HANDLER_TRAP,
    // new Proxy(target, { get: ... }) is routinely pretty-printed across 2-4
    // lines. spansLines:5 covers that formatting without pairing a Proxy on
    // line 1 with an unrelated handler 50 lines later.
    spansLines: 5,
    // new Proxy({}, { get, set }) is a plain ES6 idiom used by prisma, vitest,
    // jiti and playwright-core. It is only interesting when the trap body does
    // something hostile, so require an exfil / eval / execution signal. A bare
    // process.env[key] read is normal in Vitest's import.meta.env proxy and is
    // not hostile without a sink in the same trap.
    requiresInFile:
      /\b(?:eval\s*\(|new\s+Function|fetch\s*\(|axios|XMLHttpRequest|child_process|execSync|atob\s*\()/,
    notFilePattern: /\.min\.(js|css)$|(?:\/static\/js\/|\/vendor\/|\/public\/js\/|\/assets\/js\/).*\.js$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },
  {
    name: "dynamic-import-expression",
    pattern:
      "import\\s*\\(\\s*(?:`[^`]*\\$\\{|\\+|process\\.env|String\\.fromCharCode)",
    description:
      "Dynamic import() with computed URL (template literal with expression, env variable, or string construction). Can load modules from attacker-controlled sources.",
    severity: "medium",
    rule: "IMPORT_EXPRESSION",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.IMPORT_EXPRESSION,
    notTestFile: true,
  },
  {
    name: "wasm-instantiate-external",
    pattern:
      "WebAssembly\\.instantiate(?:Streaming)?\\s*\\(\\s*(?:fetch|https?|new\\s+URL)",
    description:
      "WebAssembly loaded from external source. WASM modules can execute arbitrary code.",
    severity: "medium",
    rule: "WASM_SUSPICIOUS",
    notTestFile: true,
  },
  {
    name: "steganography-decode",
    pattern:
      "(?:atob|Buffer\\.from)\\s*\\([^)]*(?:\\.png|\\.jpg|\\.gif|\\.bmp|\\.ico|\\.svg|\\.woff|\\.ttf)",
    description:
      "Base64 decoding applied to image/font file content. Potential steganographic payload extraction.",
    severity: "high",
    rule: "STEGANOGRAPHY_DECODE",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.STEGANOGRAPHY_DECODE,
    notTestFile: true,
  },
  {
    name: "svg-script-injection",
    pattern:
      "<script[^>]*>[\\s\\S]*?</script>|\\bon\\w+\\s*=\\s*[\"']",
    description:
      "SVG file contains <script> tag or event handler. SVG files can execute JavaScript.",
    severity: "high",
    rule: "SVG_SCRIPT_INJECTION",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.SVG_SCRIPT_INJECTION,
    onlyExtensions: [".svg"],
    notTestFile: true,
  },
  {
    name: "rtl-override",
    pattern:
      "\\u202E|\\u2066|\\u2067|\\u2068|\\u2069",
    description:
      "Right-to-left override character detected. Can be used to disguise file extensions or code meaning.",
    severity: "high",
    rule: "RTL_OVERRIDE",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// IaC / Terraform patterns (v4.0)
// ---------------------------------------------------------------------------

export const IAC_PATTERNS: PatternEntry[] = [
  {
    name: "iac-inline-script-curl",
    pattern:
      "(?:provisioner|user_data|inline).*(?:curl|wget)\\s+.*\\|\\s*(?:bash|sh)",
    description:
      "Terraform/IaC provisioner downloads and executes remote code.",
    severity: "high",
    rule: "IAC_INLINE_SCRIPT",
    correlatedMatcher: iacInlineScriptMatcher,
    notTestFile: true,
  },
  {
    name: "iac-external-module",
    pattern:
      'source\\s*=\\s*"(?:https?://|git::|s3::|gcs::)(?!(?:github\\.com/hashicorp|registry\\.terraform\\.io))',
    description:
      "Terraform module from a non-standard source. Modules from untrusted sources can contain backdoors.",
    severity: "medium",
    rule: "IAC_EXTERNAL_MODULE",
    notTestFile: true,
  },
  {
    name: "iac-hardcoded-secret",
    // The regex finds the assignment SHAPE; isLikelyRealSecretValue() decides
    // whether the captured VALUE can be a credential at all (v5.18). Group 1 is
    // the value.
    pattern:
      '(?:password|secret_key|access_key|api_key|private_key|token)\\s*=\\s*"(?!(?:test|example|dummy|placeholder|your_|TODO|REPLACE|<|changeme|secret_here|xxx|none|null|false|true)[^"]*")([^"]{8,})"',
    description:
      "Hardcoded secret in IaC configuration file. Secrets should use variables or secret managers.",
    severity: "critical",
    rule: "IAC_HARDCODED_SECRET",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.IAC_HARDCODED_SECRET,
    notTestFile: true,
  },
  {
    name: "iac-remote-exec",
    pattern:
      'provisioner\\s+"remote-exec"',
    description:
      "Terraform remote-exec provisioner. Executes commands on remote resources.",
    severity: "medium",
    rule: "IAC_REMOTE_EXEC",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Infostealer / dropper / proxy malware patterns (v4.1)
// ---------------------------------------------------------------------------

export const INFOSTEALER_PATTERNS: PatternEntry[] = [
  // Dead-drop resolver patterns
  {
    name: "dead-drop-steam",
    pattern:
      "steamcommunity\\.com/profiles/\\d+",
    description:
      "Steam Community profile URL in code. Infostealers (Vidar, Lumma) use Steam profiles as dead-drop resolvers to retrieve C2 addresses.",
    severity: "critical",
    rule: "DEAD_DROP_STEAM",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "dead-drop-telegram",
    pattern:
      "(?:telegram\\.me|t\\.me)/[a-zA-Z0-9_]+",
    description:
      "Telegram channel/user URL in code. Used as dead-drop resolver for C2 address retrieval by Vidar and similar stealers.",
    severity: "critical",
    rule: "DEAD_DROP_TELEGRAM",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "dead-drop-pastebin",
    pattern:
      "(?:pastebin\\.com|hastebin\\.com|ghostbin\\.com|paste\\.ee|rentry\\.co)/(?:raw/)?[a-zA-Z0-9]+",
    description:
      "Pastebin-like service URL in code. Often used as dead-drop resolver for malware C2 configuration.",
    severity: "high",
    rule: "DEAD_DROP_PASTEBIN",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "dead-drop-dns-txt",
    pattern:
      "(?:nslookup|dig)\\s+.*\\bTXT\\b|dns\\.resolveTxt|resolver\\.query.*TXT",
    description:
      "DNS TXT record lookup detected. Malware uses DNS TXT records as covert C2 channels.",
    severity: "medium",
    rule: "DEAD_DROP_DNS_TXT",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.DEAD_DROP_DNS_TXT,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // Browser credential theft patterns
  {
    name: "vidar-browser-theft",
    pattern:
      "(?:AppData[/\\\\](?:Local|Roaming)[/\\\\](?:Google|Mozilla|BraveSoftware|Microsoft[/\\\\]Edge)|Library[/\\\\]Application Support[/\\\\](?:Firefox|Google[/\\\\]Chrome|BraveSoftware)|\\.mozilla[/\\\\]firefox|\\.config[/\\\\](?:google-chrome|chromium)).*(?:Login Data|Cookies|Web Data|Local State|key4\\.db|logins\\.json)",
    description:
      "Browser credential/cookie file access pattern. Infostealers (Vidar, Lumma, RedLine) steal browser data from these paths.",
    severity: "high",
    rule: "VIDAR_BROWSER_THEFT",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.VIDAR_BROWSER_THEFT,
    notFilePattern: /\.min\.(js|css)$|(?:patterns|scanner|playbooks|correlation-engine|ioc-blocklist|threat-intel|remediation-engine|secret-simulator|workflow-modeler|config-scanner|install-hook-scanner|github-trust-scanner|dependency-confusion|attack-graph|reporter|active-validation|solana-monitor|solana-watchlist|slsa-verifier|sbom-generator)\.(ts|js)$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },

  // Crypto wallet theft patterns
  {
    name: "vidar-wallet-theft",
    pattern:
      "(?:Exodus|exodus|MetaMask|metamask|Phantom|phantom|Atomic|Electrum|electrum|Coinomi|Trust.*Wallet).*(?:wallet|keystore|vault|seed|mnemonic)|wallet\\.dat",
    description:
      "Cryptocurrency wallet file/directory access. Infostealers target wallet files for fund theft.",
    severity: "high",
    rule: "VIDAR_WALLET_THEFT",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.VIDAR_WALLET_THEFT,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // SOCKS5 proxy / backconnect patterns
  {
    name: "ghostsocks-socks5",
    pattern:
      "\\x05[\\x00-\\x03]|socks_version\\s*[=:]\\s*5|connect_socks",
    description:
      "SOCKS5 protocol implementation detail (binary handshake or connect_socks call). GhostSocks and similar malware turn infected machines into residential proxies. The bare word SOCKS5 and socks5:// URLs are NOT matched - those appear in ordinary proxy configuration; socks5:// is covered by PROXY_BACKCONNECT.",
    severity: "critical",
    rule: "GHOSTSOCKS_SOCKS5",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "proxy-backconnect",
    pattern:
      "(?:" + PROXY_REMOTE_SCHEME_SOURCE +
      "|\\bsocks[45]\\b[^\\r\\n]{0,512}?\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" +
      "|backconnect[^\\r\\n]{0,512}?:\\d{4,5}" +
      "|residential[^\\r\\n]{0,512}?proxy[^\\r\\n]{0,512}?\\d{1,3}\\.\\d{1,3}" +
      "|back_connect|proxy[^\\r\\n]{0,512}?checkin)",
    description:
      "Reverse proxy/backconnect pattern. Infected machines are registered as proxy nodes for criminal infrastructure.",
    severity: "high",
    rule: "PROXY_BACKCONNECT",
    correlatedMatcher: proxyBackconnectMatcher,
    notFilePattern: /\.min\.(js|css)$|(?:patterns|scanner|playbooks|correlation-engine|ioc-blocklist|threat-intel|remediation-engine|secret-simulator|workflow-modeler|config-scanner|install-hook-scanner|github-trust-scanner|dependency-confusion|attack-graph|reporter|active-validation|solana-monitor|solana-watchlist|slsa-verifier|sbom-generator)\.(ts|js)$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },

  // Dropper / loader patterns
  {
    name: "dropper-temp-exec",
    pattern:
      "(?:" +
      // A declared temp/executable path must be passed to both the write and
      // execution calls. The optional string prefix covers execSync("node " + path).
      "(?:^|[\\n;])[ \\t]*(?:(?:const|let|var)[ \\t]+)?([A-Za-z_$][\\w$]*)[ \\t]*=[ \\t]*[^\\n;]*(?:\\b(?:TEMP|TMP|AppData)\\b|tmp(?:dir)?[ \\t]*\\(|tempfile|[\\\\/](?:tmp|temp)[\\\\/]|\\.(?:exe|bat|cmd|ps1)(?![A-Za-z0-9_]))[^\\n;]*;?[\\s\\S]*?\\b(?:writeFile(?:Sync)?|write_bytes|saveFile)\\s*\\(\\s*\\1\\b[^\\n;]*[\\s\\S]*?\\b(?:exec(?:File)?(?:Sync)?|spawn(?:Sync)?|ShellExecute|CreateProcess|system)\\s*\\(\\s*(?:[\"'][^\"'\\n]*[\"'][ \\t]*\\+[ \\t]*)?\\1\\b" +
      "|" +
      // Direct expressions are correlated by the executable basename. Requiring
      // a real execution call also prevents ".exe" from matching ".execSync".
      "\\b(?:writeFile(?:Sync)?|write_bytes|saveFile)\\s*\\([^\\n;]*?[\"'](?:[^\"'\\n]*[\\\\/])?([^\"'\\\\/\\n]+\\.(?:exe|bat|cmd|ps1)(?![A-Za-z0-9_]))[\"'][^\\n;]*[\\s\\S]*?\\b(?:exec(?:File)?(?:Sync)?|spawn(?:Sync)?|ShellExecute|CreateProcess|system)\\s*\\([^\\n;]*?\\2(?![A-Za-z0-9_])" +
      ")",
    description:
      "Dropper pattern: writing and executing files in temporary directories.",
    severity: "critical",
    rule: "DROPPER_TEMP_EXEC",
    correlatedMatcher: CORRELATED_PATTERN_MATCHERS.DROPPER_TEMP_EXEC,
    // writeFileSync(tmpdir) then execSync a few lines later is the real shape;
    // a one-line form is rare. 6 lines covers the common dropper layout without
    // pairing an early tmpdir reference with a distant spawn.
    spansLines: 6,
    // Writing into os.tmpdir() and running it is exactly how tsx, jiti, prisma and
    // playwright cache-compile. A dropper is distinguished by the payload being
    // FETCHED or DECODED first rather than generated from local source.
    requiresInFileMatcher: hasDropperPayloadPreparation,
    notFilePattern: /\.json$|(?:patterns|scanner|playbooks|correlation-engine|ioc-blocklist|threat-intel|remediation-engine|secret-simulator|workflow-modeler|config-scanner|install-hook-scanner|github-trust-scanner|dependency-confusion|attack-graph|reporter|active-validation|solana-monitor|solana-watchlist|slsa-verifier|sbom-generator)\.(ts|js)$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },
  {
    name: "dropper-antivm",
    pattern:
      "(?:VMware|VirtualBox|VBOX|QEMU|Hyper-V|Xen|Parallels).*(?:detect|check|exit)|(?:GetTickCount|IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebuggerPresent)",
    description:
      "Anti-VM/anti-debug evasion technique. Malware checks for sandbox environments before executing payloads.",
    severity: "high",
    rule: "DROPPER_ANTIVM",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.DROPPER_ANTIVM,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "dropper-sleep-evasion",
    pattern:
      "(?:sleep|Sleep|usleep|nanosleep|time\\.sleep|Thread\\.sleep|Start-Sleep)\\s*\\(\\s*(?:[0-9]{5,}|\\d+\\s*\\*\\s*(?:60|1000|60000))",
    description:
      "Long sleep before execution. Droppers delay to evade sandbox time limits (SUNBURST/Vidar technique).",
    severity: "high",
    rule: "DROPPER_SLEEP_EVASION",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
];

// ---------------------------------------------------------------------------
// Fake AI-tool / SEO lure patterns (v4.1 - Claude Code campaign)
// ---------------------------------------------------------------------------

export const LURE_PATTERNS: PatternEntry[] = [
  {
    name: "readme-lure-leaked",
    pattern:
      "(?:leaked|exposed|dumped)\\s+(?:source|code|src|binary|build)",
    description:
      "README contains 'leaked source/code' language. This is a common social engineering lure for malware distribution.",
    severity: "high",
    rule: "README_LURE_LEAKED",
    onlyFilePattern: /(?:^|[/\\])(?:README|CHANGELOG|DESCRIPTION|CONTRIBUTING|release[-_]notes)[^/\\]*$/i,
    notTestFile: true,
  },
  {
    name: "readme-lure-crack",
    pattern:
      "\\b(?:crack(?:ed)?|keygen|license\\s*bypass|no\\s*(?:message\\s*)?limits?|unlock(?:ed)?\\s*(?:features?|enterprise|pro|premium))\\b",
    description:
      "README contains crack/keygen/unlock language. Malware repos promise premium features to lure downloads.",
    severity: "critical",
    rule: "README_LURE_CRACK",
    onlyFilePattern: /(?:^|[/\\])(?:README|CHANGELOG|DESCRIPTION|CONTRIBUTING|release[-_]notes)[^/\\]*$/i,
    notTestFile: true,
  },
  {
    name: "readme-lure-urgency",
    pattern:
      "(?:download|get|grab)\\s+(?:before|quickly|fast|now|while).*(?:removed|taken down|deleted|gone|available)",
    description:
      "README uses urgency language to pressure downloads. Classic social engineering tactic.",
    severity: "medium",
    rule: "README_LURE_URGENCY",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.README_LURE_URGENCY,
    onlyFilePattern: /(?:^|[/\\])(?:README|CHANGELOG|DESCRIPTION|CONTRIBUTING|release[-_]notes)[^/\\]*$/i,
    notTestFile: true,
  },
  {
    name: "campaign-claude-lure",
    pattern:
      "(?:claude\\s*code|anthropic).*(?:leaked|cracked|unlocked|free|exposed|rebuilt)",
    description:
      "Claude Code lure detected. The April 2026 campaign distributed Vidar/GhostSocks via fake 'leaked Claude Code' repos.",
    severity: "critical",
    rule: "CAMPAIGN_CLAUDE_LURE",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.CAMPAIGN_CLAUDE_LURE,
    notTestFile: true,
    // Stay on .md - lure patterns target malicious READMEs by design.
    notFilePattern: SCANNER_SRC,
  },
  {
    name: "campaign-ai-tool-lure",
    pattern:
      "(?:copilot|cursor|devin|openai|chatgpt|gemini|claude|windsurf|openclaw).*(?:leaked|cracked|free\\s*download|source\\s*dump)",
    description:
      "Fake AI tool lure detected. The 2026 campaign impersonated 25+ software brands to distribute malware.",
    severity: "critical",
    rule: "CAMPAIGN_AI_TOOL_LURE",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.CAMPAIGN_AI_TOOL_LURE,
    notTestFile: true,
    notFilePattern: SCANNER_SRC,
  },
  {
    name: "fake-exe-in-release",
    pattern:
      "(?:_x64|_x86|_amd64|_arm64|Setup|Install)\\.(?:exe|msi|bat|cmd|ps1|7z|rar)",
    description:
      "Suspicious executable/archive filename pattern matching malware campaign naming conventions.",
    severity: "high",
    rule: "FAKE_AI_TOOL_LURE",
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Prompt-injection patterns targeting downstream LLM coding agents (v5.2.19)
//
// When attackers compromise an npm/PyPI package, they used to target the human
// developer who reads the README. Increasingly they target the *AI coding
// agent* that reads the README on the developer's behalf (Claude Code, Cursor,
// Copilot, etc.). These patterns flag known LLM-control tokens and role
// markers embedded in package documentation where they have no business being.
//
// Scope: README / CHANGELOG / DESCRIPTION / CONTRIBUTING / release notes only.
// The same tokens are legitimate in actual LLM toolkit source code, so we do
// not scan general .ts/.js/.py source for them.
// ---------------------------------------------------------------------------

// v5.10: also cover issue/PR templates. They are prefilled into the very
// issue/PR bodies that AI agents ingest, so an LLM control token planted in a
// template is a pre-positioned injection against downstream agents. The
// ISSUE_TEMPLATE alternative matches files INSIDE that directory (bug_report.md).
const DOC_FILE_PATTERN = /(?:^|[/\\])(?:README|CHANGELOG|DESCRIPTION|CONTRIBUTING|release[-_]notes|PULL_REQUEST_TEMPLATE|SUPPORT)[^/\\]*$|[/\\]ISSUE_TEMPLATE[/\\][^/\\]+$/i;

export const PROMPT_INJECTION_PATTERNS: PatternEntry[] = [
  {
    name: "prompt-injection-system-reminder",
    // Matches Anthropic / Claude Code harness style: <system-reminder>...</system-reminder>
    // Also catches the opening tag alone since closing tags can be malformed.
    pattern: "<\\s*/?\\s*system[-_](?:reminder|prompt|message|instruction)\\s*>",
    description:
      "Anthropic-style <system-reminder> / <system-prompt> tag in package documentation. These tokens are processed as authoritative instructions by Claude-family LLMs reading the README - a prompt-injection attack on downstream AI coding agents.",
    severity: "high",
    rule: "PROMPT_INJECTION_SYSTEM_REMINDER",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
  {
    name: "prompt-injection-chatml",
    // Matches OpenAI / Llama 2+ / Mistral ChatML: <|im_start|>system ... <|im_end|>
    pattern: "<\\|\\s*im_(?:start|end|sep)\\s*\\|>",
    description:
      "ChatML role-control token (<|im_start|> / <|im_end|>) in package documentation. Used by OpenAI GPT, Llama, Mistral, and Qwen models as role-boundary markers - a prompt-injection attack on downstream AI agents.",
    severity: "high",
    rule: "PROMPT_INJECTION_CHATML",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
  {
    name: "prompt-injection-inst-tag",
    // Matches Mistral / Llama instruction-tuning tags: [INST] ... [/INST]
    // Word-boundary on both sides to avoid matching prose like "configure [INST]ance".
    pattern: "\\[\\s*/?\\s*INST\\s*\\]",
    description:
      "Mistral/Llama instruction tag ([INST] or [/INST]) in package documentation. These tokens delimit user instructions in Mistral and Llama instruction-tuned models - a prompt-injection attack on downstream AI agents.",
    severity: "high",
    rule: "PROMPT_INJECTION_INST_TAG",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
  {
    name: "prompt-injection-role-token",
    // Matches generic role tokens: <|system|>, <|user|>, <|assistant|>, <|developer|>
    pattern: "<\\|\\s*(?:system|user|assistant|developer|function|tool)\\s*\\|>",
    description:
      "Generic role-control token (<|system|>, <|user|>, <|assistant|>) in package documentation. Used by Phi, Gemma, Granite, and other local LLMs to switch conversational role - a prompt-injection attack on downstream AI agents.",
    severity: "high",
    rule: "PROMPT_INJECTION_ROLE_TOKEN",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
  {
    name: "prompt-injection-override-prose",
    // Natural-language jailbreak phrases. Case-insensitive. Require the
    // imperative form to avoid matching documentation ABOUT prompt injection
    // (e.g. "we discuss how attackers ignore previous instructions").
    pattern:
      "(?:^|[.!?\\n]\\s*)(?:please\\s+)?(?:ignore|disregard|forget|override)\\s+(?:all\\s+)?(?:previous|prior|above|earlier|the\\s+system)\\s+(?:instructions?|prompts?|messages?|rules?|directives?|context)",
    description:
      "Natural-language prompt-injection override ('ignore previous instructions', 'disregard the system prompt', etc.) in package documentation. Classic jailbreak phrasing aimed at downstream AI agents reading the README.",
    severity: "high",
    rule: "PROMPT_INJECTION_OVERRIDE_PROSE",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Extended C2 + Secrets patterns (v4.2)
// ---------------------------------------------------------------------------

export const C2_EXTENDED_PATTERNS: PatternEntry[] = [
  {
    name: "c2-doh-resolver",
    pattern:
      "(?:cloudflare-dns\\.com|dns\\.google|dns\\.quad9\\.net)/dns-query|application/dns-json|application/dns-message",
    description:
      "DNS-over-HTTPS (DoH) resolver in code. Malware uses DoH to resolve C2 domains while bypassing network monitoring.",
    severity: "medium",
    rule: "C2_DOH_RESOLVER",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "dead-drop-gist",
    pattern:
      "gist\\.github(?:usercontent)?\\.com/[a-zA-Z0-9_-]+/[a-f0-9]{20,}",
    description:
      "GitHub Gist used as dead-drop resolver. Gists store C2 configuration that changes without updating malware code.",
    severity: "high",
    rule: "DEAD_DROP_GIST",
    // A gist URL in a comment is a CITATION. A dead drop is FETCHED, so require a
    // download context in the file. The 20-hex id floor rejects the short
    // all-digit legacy gist ids that made ordinary links match.
    requiresInFile:
      /\b(?:fetch\s*\(|axios|https?\.(?:get|request)|XMLHttpRequest|node-fetch|curl\s|wget\s|requests\.|urllib|execSync|child_process)|\/raw\//,
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "c2-dynamic-config",
    pattern:
      "(?:fetch|https?\\.get|axios\\.get|got)\\s*\\([^)]*(?:config|settings|update|check|beacon|ping|heartbeat)[^)]*\\).*(?:eval|exec|Function|spawn)",
    description:
      "Dynamic config fetch followed by code execution. Runtime C2 command pattern.",
    severity: "high",
    rule: "C2_DYNAMIC_CONFIG",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.C2_DYNAMIC_CONFIG,
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "c2-websocket-dynamic",
    pattern:
      "new\\s+WebSocket\\s*\\(\\s*(?:\\+|atob|Buffer\\.from|decodeURI|String\\.fromCharCode)",
    description:
      "WebSocket URL built by decoding or concatenation. Hides the C2 server address. Plain template interpolation is NOT matched: that is ordinary frontend code, already covered at medium by BEACON_WEBSOCKET_EXTERNAL.",
    severity: "high",
    rule: "C2_WEBSOCKET_DYNAMIC",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
];

export const SECRETS_PATTERNS: PatternEntry[] = [
  {
    name: "secrets-aws-key",
    pattern:
      "(?:AKIA|ASIA)([A-Z0-9]{16})",
    description:
      "AWS Access Key ID detected. Hardcoded AWS credentials can be used for unauthorized access.",
    severity: "critical",
    rule: "SECRETS_AWS_KEY",
    // Real AWS key bodies are random. A padded, repetitive run is binary noise,
    // not a credential: this fired on "AKIAAAB0AAAAAAAAAKMA" inside an emscripten
    // WASM blob. Same distinct-character defence KNOWN_C2_WALLETS uses.
    valueFilter: (v) => new Set(v).size >= 8,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-github-token",
    pattern:
      "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}",
    description:
      "GitHub personal access token detected. Exposed tokens grant repository access.",
    severity: "critical",
    rule: "SECRETS_GITHUB_TOKEN",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-private-key",
    pattern:
      "-----BEGIN\\s+(?:RSA|EC|OPENSSH|DSA|PGP)\\s+PRIVATE\\s+KEY-----",
    description:
      "Private key embedded in code. Exposed private keys compromise authentication and encryption.",
    severity: "critical",
    rule: "SECRETS_PRIVATE_KEY",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-ssh-key-read",
    pattern:
      "(?:readFile|readFileSync|open|cat|type).*\\.ssh[/\\\\](?:id_rsa|id_ed25519|id_ecdsa|id_dsa|identity)(?:[^a-z]|$)",
    description:
      "Code reads SSH private key files. Infostealers exfiltrate SSH keys for lateral movement.",
    severity: "critical",
    rule: "SECRETS_SSH_KEY_READ",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.SECRETS_SSH_KEY_READ,
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-npm-token",
    pattern:
      "npm_[A-Za-z0-9]{36}",
    description:
      "npm automation token detected. Exposed tokens allow publishing malicious package versions.",
    severity: "critical",
    rule: "SECRETS_NPM_TOKEN",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-generic-api-key",
    pattern:
      "(?:api_key|apikey|api_secret|secret_key|auth_token)\\s*[=:]\\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]",
    description:
      "Generic API key or secret detected in code.",
    severity: "high",
    rule: "SECRETS_GENERIC_API_KEY",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
];

// ---------------------------------------------------------------------------
// Advanced obfuscation v2 patterns (v4.5)
// ---------------------------------------------------------------------------

export const OBFUSCATION_V3_PATTERNS: PatternEntry[] = [
  {
    name: "code-split-string-obfuscation",
    pattern:
      "(?:['\"][a-zA-Z]{1,3}['\"]\\s*\\+\\s*){5,}",
    description:
      "String built by concatenating many small fragments. This technique hides suspicious strings from static analysis.",
    severity: "high",
    rule: "CODE_SPLIT_STRING_OBFUSCATION",
    notTestFile: true,
  },
  {
    name: "code-multi-layer-encoding",
    pattern:
      "(?:atob|Buffer\\.from|decodeURIComponent|unescape)\\s*\\(\\s*(?:atob|Buffer\\.from|decodeURIComponent|unescape)",
    description:
      "Multi-layer encoding detected (decode inside decode). Malware uses nested encoding to evade detection.",
    severity: "critical",
    rule: "CODE_MULTI_LAYER_ENCODING",
    notTestFile: true,
  },
  {
    name: "code-runtime-deobfuscation",
    pattern:
      "(?:setInterval|setTimeout|requestAnimationFrame)\\s*\\([^)]*(?:eval|Function|exec)",
    description:
      "Delayed runtime deobfuscation. Code deobfuscates and executes payload after a delay to evade analysis.",
    severity: "high",
    rule: "CODE_RUNTIME_DEOBFUSCATION",
    correlatedMatcher: CORE_BROAD_GAP_MATCHERS.CODE_RUNTIME_DEOBFUSCATION,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Provenance & integrity signals (v4.5)
// ---------------------------------------------------------------------------

export const PROVENANCE_PATTERNS: PatternEntry[] = [
  {
    name: "provenance-missing-sig",
    pattern:
      '"integrity"\\s*:\\s*""',
    description:
      "Empty integrity hash in lockfile. Package integrity cannot be verified.",
    severity: "medium",
    rule: "PROVENANCE_MISSING",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Load-time validation (v5.22)
// ---------------------------------------------------------------------------

/**
 * Every PatternEntry array that any scanner iterates.
 *
 * Kept explicit rather than discovered, so a new array must be registered here
 * deliberately and cannot quietly skip validation.
 */
export type ValidatablePattern = {
  pattern: string;
  rule: string;
  name?: string;
  spansLines?: number;
  correlatedMatcher?: PatternEntry["correlatedMatcher"];
  valueFilter?: PatternEntry["valueFilter"];
  requiresInFile?: PatternEntry["requiresInFile"];
  requiresInFileMatcher?: PatternEntry["requiresInFileMatcher"];
};

export interface PatternValidationOptions {
  /** Specialized engines validate syntax/invariants but do not use this runner. */
  execution?: "shared-pattern-engine" | "specialized-engine";
}

export const ALL_PATTERN_SETS: ReadonlyArray<readonly [string, ReadonlyArray<ValidatablePattern>]> = [
  ["FILE_PATTERNS", FILE_PATTERNS],
  ["SUSPICIOUS_FILES", SUSPICIOUS_FILES],
  ["SUSPICIOUS_SCRIPTS", SUSPICIOUS_SCRIPTS],
  ["CAMPAIGN_PATTERNS", CAMPAIGN_PATTERNS],
  ["PYPI_FILE_PATTERNS", PYPI_FILE_PATTERNS],
  ["PYPI_INSTALL_HOOK_PATTERNS", PYPI_INSTALL_HOOK_PATTERNS],
  ["BINARY_DOWNLOAD_PATTERNS", BINARY_DOWNLOAD_PATTERNS],
  ["BEACON_MINER_PATTERNS", BEACON_MINER_PATTERNS],
  ["BUILD_TOOL_PATTERNS", BUILD_TOOL_PATTERNS],
  ["MONOREPO_PATTERNS", MONOREPO_PATTERNS],
  ["CAMPAIGN_PATTERNS_V2", CAMPAIGN_PATTERNS_V2],
  ["OBFUSCATION_PATTERNS_V2", OBFUSCATION_PATTERNS_V2],
  ["IAC_PATTERNS", IAC_PATTERNS],
  ["INFOSTEALER_PATTERNS", INFOSTEALER_PATTERNS],
  ["LURE_PATTERNS", LURE_PATTERNS],
  ["PROMPT_INJECTION_PATTERNS", PROMPT_INJECTION_PATTERNS],
  ["C2_EXTENDED_PATTERNS", C2_EXTENDED_PATTERNS],
  ["SECRETS_PATTERNS", SECRETS_PATTERNS],
  ["OBFUSCATION_V3_PATTERNS", OBFUSCATION_V3_PATTERNS],
  ["PROVENANCE_PATTERNS", PROVENANCE_PATTERNS],
];

/** Every rule id the pattern tables can emit, for coverage assertions. */
export const ALL_PATTERN_RULES: readonly string[] = ALL_PATTERN_SETS.flatMap(
  ([, set]) => set.map((p) => p.rule),
);

/**
 * Compile a pattern set at module load and reject metadata that would otherwise
 * fail or silently narrow a scan only when a matching file is encountered.
 * Scanner-local sets call this same function from their defining module.
 */
export function validatePatternSet(
  setName: string,
  set: ReadonlyArray<ValidatablePattern>,
  options: PatternValidationOptions = {},
): void {
  const exactCandidates: object[] = [];
  for (const entry of set) {
    if (entry.pattern.length === 0) {
      throw new Error(
        `${setName}: pattern for rule "${entry.rule}" is empty, which matches every line.`,
      );
    }
    try {
      new RegExp(entry.pattern, "g");
    } catch (err) {
      throw new Error(
        `${setName}: pattern for rule "${entry.rule}" (name "${entry.name ?? "unnamed"}") is not a valid regular expression: ` +
          `${err instanceof Error ? err.message : String(err)}. ` +
          "Refusing to load: an invalid pattern silently disables every rule after it.",
      );
    }

    const spans = entry.spansLines ?? 1;
    if (typeof spans !== "number" || !Number.isInteger(spans) || spans < 1) {
      throw new Error(
        `${setName}: rule "${entry.rule}" has invalid spansLines=${String(spans)} (need integer >= 1).`,
      );
    }
    if (spans > MAX_SPANS_LINES) {
      throw new Error(
        `${setName}: rule "${entry.rule}" spansLines=${spans} exceeds MAX_SPANS_LINES=${MAX_SPANS_LINES}. ` +
          "Large windows approach whole-file matching and reintroduce cross-file-region false positives.",
      );
    }

    const hasBroadGap = hasBroadUnboundedConsumingGap(entry.pattern);
    if (hasBroadGap && !entry.correlatedMatcher) {
      throw new Error(
        `${setName}: rule "${entry.rule}" contains a broad unbounded consuming gap and must declare a correlatedMatcher. ` +
          "Refusing to evaluate that regex over an attacker-controlled long line.",
      );
    }
    if (
      entry.requiresInFile &&
      hasBroadUnboundedConsumingGap(entry.requiresInFile.source)
    ) {
      throw new Error(
        `${setName}: rule "${entry.rule}" has a broad requiresInFile regex. ` +
          "Replace it with a denial-of-service-safe requiresInFileMatcher.",
      );
    }
    if (spans > 1 && !entry.correlatedMatcher) {
      throw new Error(
        `${setName}: multi-line rule "${entry.rule}" must declare a correlatedMatcher. ` +
          "Unbounded regex correlation cannot provide exact, denial-of-service-safe coverage on admitted minified files.",
      );
    }
    if (entry.correlatedMatcher && entry.valueFilter) {
      throw new Error(
        `${setName}: rule "${entry.rule}" combines correlatedMatcher with valueFilter, ` +
          "but structural matches do not expose regex capture groups.",
      );
    }
    if (spans > 1) {
      try {
        new RegExp(entry.pattern, "gs");
      } catch (err) {
        throw new Error(
          `${setName}: multi-line form of rule "${entry.rule}" failed to compile with the s flag: ` +
            `${err instanceof Error ? err.message : String(err)}.`,
        );
      }
    }

    if (
      (options.execution ?? "shared-pattern-engine") === "shared-pattern-engine" &&
      spans === 1 &&
      !entry.correlatedMatcher &&
      !hasBroadGap
    ) {
      exactCandidates.push(entry);
    }
  }

  // Register only after the complete set validates. A rejected test/plugin set
  // must not partially change how an earlier entry is executed.
  for (const entry of exactCandidates) {
    EXACT_VALIDATED_SINGLE_LINE_PATTERNS.add(entry);
  }
}

/** Validate raw regex-string tables that do not carry PatternEntry metadata. */
export function validateRegexStringSet(
  setName: string,
  set: ReadonlyArray<string>,
): void {
  for (let index = 0; index < set.length; index++) {
    const pattern = set[index]!;
    if (pattern.length === 0) {
      throw new Error(`${setName}[${index}] is empty, which matches every value.`);
    }
    try {
      new RegExp(pattern, "g");
    } catch (err) {
      throw new Error(
        `${setName}[${index}] is not a valid regular expression: ` +
          `${err instanceof Error ? err.message : String(err)}.`,
      );
    }
  }
}

for (const [setName, set] of ALL_PATTERN_SETS) {
  validatePatternSet(setName, set);
}

// A duplicate rule id across the core tables makes exclusions, policy and
// remediation ambiguous. Scanner-specific specialized engines may deliberately
// use several shapes for one logical rule and validate those in their module.
const duplicateCoreRules = ALL_PATTERN_RULES.filter(
  (rule, index) => ALL_PATTERN_RULES.indexOf(rule) !== index,
);
if (duplicateCoreRules.length > 0) {
  throw new Error(
    `Duplicate core pattern rule ids: ${[...new Set(duplicateCoreRules)].join(", ")}`,
  );
}

validateRegexStringSet("MALICIOUS_PACKAGE_PATTERNS", MALICIOUS_PACKAGE_PATTERNS);
validateRegexStringSet("PYPI_TYPOSQUAT_PATTERNS", PYPI_TYPOSQUAT_PATTERNS);
