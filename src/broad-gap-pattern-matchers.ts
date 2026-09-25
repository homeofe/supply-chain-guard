import type {
  CorrelatedPatternMatch,
  CorrelatedPatternMatcher,
} from "./types.js";
import { escapeRegExp } from "./text-lines.js";

const MAX_EVIDENCE_CHARS = 240;

function structuralMatch(
  content: string,
  start: number,
  end: number,
): CorrelatedPatternMatch {
  const raw = content.slice(start, end);
  if (raw.length <= MAX_EVIDENCE_CHARS) return { start, end, evidence: raw };
  const separator = " ... ";
  const remaining = MAX_EVIDENCE_CHARS - separator.length;
  const left = Math.ceil(remaining / 2);
  return {
    start,
    end,
    evidence:
      raw.slice(0, left) + separator + raw.slice(raw.length - (remaining - left)),
  };
}

const LF = 1 << 0;
const DOT_TERMINATOR = 1 << 1;
const SEMICOLON = 1 << 2;
const DOUBLE_QUOTE = 1 << 3;
const SINGLE_QUOTE = 1 << 4;
const RIGHT_PAREN = 1 << 5;
const RIGHT_BRACE = 1 << 6;
const BACKTICK = 1 << 7;
const RIGHT_ANGLE = 1 << 8;

interface GapSpec {
  barrierMask: number;
  minChars?: number;
  /** Maximum admitted distance from the previous token's end. */
  maxChars?: number;
}

const GAP_DOT: GapSpec = { barrierMask: LF | DOT_TERMINATOR };
const GAP_SEMICOLON: GapSpec = { barrierMask: LF | SEMICOLON };
const GAP_QUOTES: GapSpec = { barrierMask: LF | DOUBLE_QUOTE | SINGLE_QUOTE };
const GAP_DOUBLE_QUOTE: GapSpec = { barrierMask: LF | DOUBLE_QUOTE };
const GAP_RIGHT_PAREN: GapSpec = { barrierMask: LF | RIGHT_PAREN };
const GAP_RIGHT_BRACE: GapSpec = { barrierMask: LF | RIGHT_BRACE };
const GAP_BACKTICK: GapSpec = { barrierMask: LF | BACKTICK };
const GAP_QUOTES_ONE: GapSpec = {
  barrierMask: GAP_QUOTES.barrierMask,
  minChars: 1,
};
const PROTESTWARE_MAX_GAP_CHARS = 512;
const GAP_DOT_PROTESTWARE: GapSpec = {
  barrierMask: GAP_DOT.barrierMask,
  maxChars: PROTESTWARE_MAX_GAP_CHARS,
};


const WS0 = String.raw`[^\S\n]*`;
const WS1 = String.raw`[^\S\n]+`;

/**
 * Network transport for the beacon rules, shared with their pattern strings in
 * patterns.ts so matcher and regex cannot drift. Identifier boundaries and a
 * call shape keep `fetchNotifications` and `forgotPassword` out, while member
 * calls such as `axios.post(` and `got.get(` still count.
 */
// VIDAR_WALLET_THEFT operands, shared with the pattern string. A wallet name
// must not sit inside a longer word and the target must not run on into one;
// a plural or a following `_`, `.`, `/` or capital still counts. (A line
// comment, not JSDoc: JSDoc is copied into dist/*.d.ts, and example paths
// here would make the published declaration file match this very rule.)
export const WALLET_NAME_SOURCE =
  String.raw`(?:Exodus|exodus|MetaMask|metamask|Phantom|phantom|Atomic|Electrum|electrum|Coinomi)`;
export const WALLET_TARGET_SOURCE =
  String.raw`(?:wallet|keystore|vault|seed|mnemonic)s?(?![a-z])`;

export const BEACON_TRANSPORT_SOURCE =
  String.raw`(?:\bfetch${WS0}\(|\b(?:axios|got)(?:${WS0}\.${WS0}[A-Za-z]{1,16})?${WS0}\(|\bhttps?\.(?:get|request)${WS0}\(|\bnode-fetch\b|\bXMLHttpRequest\b)`;

interface OrderedSequenceSpec {
  tokens: readonly string[];
  gaps: readonly GapSpec[];
  /** Mirrors top-level regex alternation order. */
  priority?: number;
  /**
   * Token position selected after a common greedy prefix gap. Candidates with
   * the rightmost viable start at this position win before branch priority.
   */
  greedyBranchToken?: number;
  /** Greedy gaps select the last viable final token; lazy gaps select first. */
  finalMode?: "first" | "last";
}

interface OrderedSequenceState {
  /** Stage k means tokens 0..k-1 were consumed and token k is awaited. */
  active: boolean[];
  starts: number[];
  ends: number[];
  greedyStarts: number[];
  /** A lazy-final or single-token sequence has already found its first match. */
  done: boolean;
}

interface ScheduledStage {
  sequenceIndex: number;
  stage: number;
  start: number;
  end: number;
  greedyStart: number;
}

interface Candidate {
  start: number;
  end: number;
  priority: number;
  greedyStart?: number;
}

function characterBarrierBit(character: string): number {
  if (character === "\n") return LF;
  if (character === "\r" || character === "\u2028" || character === "\u2029") {
    return DOT_TERMINATOR;
  }
  if (character === ";") return SEMICOLON;
  if (character === '"') return DOUBLE_QUOTE;
  if (character === "'") return SINGLE_QUOTE;
  if (character === ")") return RIGHT_PAREN;
  if (character === "}") return RIGHT_BRACE;
  if (character === "`") return BACKTICK;
  if (character === ">") return RIGHT_ANGLE;
  return 0;
}

function barrierBits(value: string): number {
  let bits = 0;
  for (const character of value) bits |= characterBarrierBit(character);
  return bits;
}

function barrierClass(mask: number): string {
  let body = "";
  if ((mask & LF) !== 0) body += "\\n";
  if ((mask & DOT_TERMINATOR) !== 0) body += "\\r\\u2028\\u2029";
  if ((mask & SEMICOLON) !== 0) body += ";";
  if ((mask & DOUBLE_QUOTE) !== 0) body += '"';
  if ((mask & SINGLE_QUOTE) !== 0) body += "'";
  if ((mask & RIGHT_PAREN) !== 0) body += "\\)";
  if ((mask & RIGHT_BRACE) !== 0) body += "}";
  if ((mask & BACKTICK) !== 0) body += "`";
  if ((mask & RIGHT_ANGLE) !== 0) body += ">";
  return `[${body}]`;
}

function betterCandidate(current: Candidate | undefined, next: Candidate): boolean {
  if (current === undefined || next.start < current.start) return true;
  if (next.start > current.start) return false;
  if (
    next.greedyStart !== undefined &&
    current.greedyStart !== undefined &&
    next.greedyStart !== current.greedyStart
  ) {
    return next.greedyStart > current.greedyStart;
  }
  return next.priority < current.priority ||
    (next.priority === current.priority && next.end > current.end);
}

function createSequenceState(tokenCount: number): OrderedSequenceState {
  return {
    active: new Array<boolean>(tokenCount).fill(false),
    starts: new Array<number>(tokenCount).fill(-1),
    ends: new Array<number>(tokenCount).fill(0),
    greedyStarts: new Array<number>(tokenCount).fill(-1),
    done: false,
  };
}

function resetSequenceState(state: OrderedSequenceState): void {
  state.active.fill(false);
  state.done = false;
}

function activateStage(
  state: OrderedSequenceState,
  stage: number,
  start: number,
  end: number,
  greedyStart: number,
): void {
  // Once two paths are active, the earlier overall start is exactly the path a
  // regex engine tries first. For a shared start, a later common-greedy branch
  // anchor dominates; otherwise the earlier end permits every continuation the
  // later end does. Completed fallback candidates have already been recorded.
  if (
    !state.active[stage] ||
    start < state.starts[stage]! ||
    (start === state.starts[stage] && (
      greedyStart > state.greedyStarts[stage]! ||
      (greedyStart === state.greedyStarts[stage]! && end < state.ends[stage]!)
    ))
  ) {
    state.active[stage] = true;
    state.starts[stage] = start;
    state.ends[stage] = end;
    state.greedyStarts[stage] = greedyStart;
  }
}

/**
 * Compile fixed/safe token regexes into one event stream. The constant-size
 * prefix-stage NFA retains earlier stages while trying later tokens, which is
 * required when adjacent gaps have different barriers (for example a quote-
 * bounded gap followed by a dot-bounded gap). Repeated prefixes therefore do
 * not restart a scan or discard a still-viable fallback.
 */
function makeOrderedEventMatcher(
  sequences: readonly OrderedSequenceSpec[],
  caseInsensitive = false,
): CorrelatedPatternMatcher {
  for (const sequence of sequences) {
    if (
      sequence.tokens.length === 0 ||
      sequence.gaps.length !== sequence.tokens.length - 1 ||
      sequence.gaps.some((gap) =>
        (gap.minChars !== undefined && (
          !Number.isInteger(gap.minChars) ||
          gap.minChars < 0
        )) ||
        (gap.maxChars !== undefined && (
          !Number.isInteger(gap.maxChars) ||
          gap.maxChars < 0 ||
          gap.maxChars < (gap.minChars ?? 0)
        ))
      ) ||
      (sequence.greedyBranchToken !== undefined && (
        sequence.greedyBranchToken < 0 ||
        sequence.greedyBranchToken >= sequence.tokens.length
      ))
    ) {
      throw new Error("Invalid ordered matcher sequence");
    }
  }

  const tokenSources: string[] = [];
  const tokenIds = new Map<string, number>();
  const tokenized = sequences.map((sequence) => ({
    ...sequence,
    tokenIds: sequence.tokens.map((source) => {
      let id = tokenIds.get(source);
      if (id === undefined) {
        id = tokenSources.length;
        tokenSources.push(source);
        tokenIds.set(source, id);
      }
      return id;
    }),
  }));
  let usedBarriers = LF;
  for (const sequence of sequences) {
    for (const gap of sequence.gaps) usedBarriers |= gap.barrierMask;
  }

  // Each token gets an independent zero-width stream. This preserves events
  // whose starts overlap another token (`fetchttps`, `axiosetTimeout`) and
  // same-start alternatives without replaying barriers inside an already
  // consumed token. The number of streams is fixed per shipped rule.
  const tokenRegexes = tokenSources.map((source) =>
    new RegExp(`(?=(${source}))`, caseInsensitive ? "gi" : "g"));
  const barrierRegex = new RegExp(barrierClass(usedBarriers), "g");

  return (content) => {
    const results: CorrelatedPatternMatch[] = [];
    const states = tokenized.map((sequence) =>
      createSequenceState(sequence.tokenIds.length));
    const scheduledStages: ScheduledStage[] = [];
    let best: Candidate | undefined;

    const record = (
      sequenceIndex: number,
      start: number,
      end: number,
      greedyStart: number,
    ): void => {
      const sequence = tokenized[sequenceIndex]!;
      const candidate: Candidate = {
        start,
        end,
        priority: sequence.priority ?? sequenceIndex,
      };
      if (sequence.greedyBranchToken !== undefined) {
        candidate.greedyStart = greedyStart;
      }
      if (betterCandidate(best, candidate)) best = candidate;
    };
    const resetAll = (): void => {
      for (const state of states) resetSequenceState(state);
      scheduledStages.length = 0;
    };
    const activateScheduled = (through: number): void => {
      let write = 0;
      for (const scheduled of scheduledStages) {
        if (scheduled.end <= through) {
          const state = states[scheduled.sequenceIndex]!;
          if (!state.done) {
            activateStage(
              state,
              scheduled.stage,
              scheduled.start,
              scheduled.end,
              scheduled.greedyStart,
            );
          }
        } else {
          scheduledStages[write++] = scheduled;
        }
      }
      scheduledStages.length = write;
    };
    const expireBoundedStages = (through: number): void => {
      for (let index = 0; index < states.length; index++) {
        const sequence = tokenized[index]!;
        const state = states[index]!;
        if (state.done) continue;
        for (let stage = 1; stage < sequence.tokenIds.length; stage++) {
          const maxChars = sequence.gaps[stage - 1]!.maxChars;
          if (
            state.active[stage] &&
            maxChars !== undefined &&
            through - state.ends[stage]! > maxChars
          ) {
            state.active[stage] = false;
          }
        }
      }
    };
    const flushLine = (): void => {
      if (best) results.push(structuralMatch(content, best.start, best.end));
      best = undefined;
      resetAll();
    };

    const tokenEvents = tokenRegexes.map((regex) => {
      regex.lastIndex = 0;
      return regex.exec(content);
    });
    barrierRegex.lastIndex = 0;
    let barrierEvent = barrierRegex.exec(content);

    while (true) {
      let eventStart = barrierEvent?.index ?? Number.POSITIVE_INFINITY;
      for (const event of tokenEvents) {
        if (event && event.index < eventStart) eventStart = event.index;
      }
      if (!Number.isFinite(eventStart)) break;
      // Expire an older prefix before activating a newer scheduled one. Without
      // this ordering, the NFA's normal earliest-start preference can leave an
      // out-of-range prefix blocking a later, locally correlated prefix.
      expireBoundedStages(eventStart);
      activateScheduled(eventStart);

      // Process every token beginning here before the barrier at the same
      // position. A closing quote can therefore satisfy its token position,
      // while the barrier still invalidates paths that did not consume it.
      for (let eventToken = 0; eventToken < tokenEvents.length; eventToken++) {
        const event = tokenEvents[eventToken];
        if (!event || event.index !== eventStart) continue;
        const value = event[1]!;
        const eventEnd = eventStart + value.length;

        for (let index = 0; index < states.length; index++) {
          const sequence = tokenized[index]!;
          const state = states[index]!;
          if (state.done) continue;
          const finalMode = sequence.finalMode ??
            (sequence.tokenIds.length === 1 ? "first" : "last");

          for (let stage = sequence.tokenIds.length - 1; stage >= 1; stage--) {
            if (
              !state.active[stage] ||
              eventToken !== sequence.tokenIds[stage]
            ) {
              continue;
            }
            const gap = sequence.gaps[stage - 1]!;
            const gapChars = eventStart - state.ends[stage]!;
            if (
              gapChars < (gap.minChars ?? 0) ||
              (gap.maxChars !== undefined && gapChars > gap.maxChars)
            ) {
              continue;
            }

            const greedyStart = sequence.greedyBranchToken === stage
              ? eventStart
              : state.greedyStarts[stage]!;
            if (stage === sequence.tokenIds.length - 1) {
              record(index, state.starts[stage]!, eventEnd, greedyStart);
              if (finalMode === "first") state.done = true;
            } else {
              scheduledStages.push({
                sequenceIndex: index,
                stage: stage + 1,
                start: state.starts[stage]!,
                end: eventEnd,
                greedyStart,
              });
            }
          }

          if (!state.done && eventToken === sequence.tokenIds[0]) {
            const greedyStart = sequence.greedyBranchToken === 0
              ? eventStart
              : -1;
            if (sequence.tokenIds.length === 1) {
              record(index, eventStart, eventEnd, greedyStart);
              state.done = true;
            } else {
              scheduledStages.push({
                sequenceIndex: index,
                stage: 1,
                start: eventStart,
                end: eventEnd,
                greedyStart,
              });
            }
          }
        }

        // Lookahead matches are zero-width. Resume one code unit after this
        // start so the same token source can also report overlapping matches.
        tokenRegexes[eventToken]!.lastIndex = eventStart + 1;
        tokenEvents[eventToken] = tokenRegexes[eventToken]!.exec(content);
      }

      if (barrierEvent?.index === eventStart) {
        const bits = characterBarrierBit(barrierEvent[0]!);
        if ((bits & LF) !== 0) {
          flushLine();
        } else {
          for (let index = 0; index < states.length; index++) {
            const sequence = tokenized[index]!;
            const state = states[index]!;
            if (state.done) continue;
            for (let stage = 1; stage < sequence.tokenIds.length; stage++) {
              // A token transition becomes active at the token's end. Ignore
              // barriers physically inside that consumed token, but apply the
              // same character to every older path whose gap already began.
              if (
                state.active[stage] &&
                eventStart >= state.ends[stage]! &&
                (sequence.gaps[stage - 1]!.barrierMask & bits) !== 0
              ) {
                state.active[stage] = false;
              }
            }
          }
        }
        barrierEvent = barrierRegex.exec(content);
      }
    }
    flushLine();
    return results;
  };
}
/** Merge independently tokenized top-level alternatives without overlap loss. */
function mergeAlternativeMatchers(
  alternatives: readonly {
    matcher: CorrelatedPatternMatcher;
    priority: number;
  }[],
): CorrelatedPatternMatcher {
  return (content) => {
    const streams = alternatives.map(({ matcher, priority }) => ({
      matches: [...matcher(content)],
      priority,
      index: 0,
    }));
    const results: CorrelatedPatternMatch[] = [];
    let acceptedLineStart = -1;

    while (true) {
      let selected = -1;
      let selectedCandidate: Candidate | undefined;
      for (let index = 0; index < streams.length; index++) {
        const stream = streams[index]!;
        const match = stream.matches[stream.index];
        if (!match) continue;
        const candidate = {
          start: match.start,
          end: match.end,
          priority: stream.priority,
        };
        if (betterCandidate(selectedCandidate, candidate)) {
          selected = index;
          selectedCandidate = candidate;
        }
      }
      if (selected === -1 || !selectedCandidate) break;
      streams[selected]!.index++;

      const lineStart = content.lastIndexOf("\n", selectedCandidate.start - 1) + 1;
      if (lineStart === acceptedLineStart) continue;
      results.push(structuralMatch(
        content,
        selectedCandidate.start,
        selectedCandidate.end,
      ));
      acceptedLineStart = lineStart;
    }

    return results;
  };
}
function forEachPhysicalLine(
  content: string,
  visit: (start: number, end: number) => void,
): void {
  let start = 0;
  while (true) {
    const newline = content.indexOf("\n", start);
    const end = newline === -1 ? content.length : newline;
    visit(start, end);
    if (newline === -1) break;
    start = newline + 1;
  }
}

function isWhitespace(character: string | undefined): boolean {
  return character !== undefined && /\s/.test(character);
}

function evalHexMatcher(content: string): CorrelatedPatternMatch[] {
  const results: CorrelatedPatternMatch[] = [];
  const prefix = new RegExp(String.raw`eval${WS0}\(${WS0}Buffer\.from${WS0}\(`, "g");

  forEachPhysicalLine(content, (lineStart, lineEnd) => {
    const line = content.slice(lineStart, lineEnd);
    prefix.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = prefix.exec(line)) !== null) {
      const bodyStart = match.index + match[0].length;
      const close = line.indexOf(")", bodyStart);
      if (close === -1) break;

      let cursor = close - 1;
      while (cursor >= bodyStart && isWhitespace(line[cursor])) cursor--;
      const closingQuote = line[cursor];
      const hasHex =
        (closingQuote === '"' || closingQuote === "'") &&
        cursor >= bodyStart + 4 &&
        line.slice(cursor - 3, cursor) === "hex" &&
        (line[cursor - 4] === '"' || line[cursor - 4] === "'");
      if (hasHex) {
        cursor -= 5;
        while (cursor >= bodyStart && isWhitespace(line[cursor])) cursor--;
        if (cursor > bodyStart && line[cursor] === ",") {
          results.push(structuralMatch(
            content,
            lineStart + match.index,
            lineStart + close + 1,
          ));
          return;
        }
      }

      prefix.lastIndex = close + 1;
    }
  });

  return results;
}

function iacHardcodedSecretMatcher(
  content: string,
  valueGuard: (value: string) => boolean,
): CorrelatedPatternMatch[] {
  const results: CorrelatedPatternMatch[] = [];
  const prefix = new RegExp(
    String.raw`(?:password|secret_key|access_key|api_key|private_key|token)${WS0}=${WS0}"`,
    "g",
  );
  const disallowedShapePrefix =
    /^(?:test|example|dummy|placeholder|your_|TODO|REPLACE|<|changeme|secret_here|xxx|none|null|false|true)/;

  forEachPhysicalLine(content, (lineStart, lineEnd) => {
    const line = content.slice(lineStart, lineEnd);
    prefix.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = prefix.exec(line)) !== null) {
      const valueStart = match.index + match[0].length;
      const close = line.indexOf('"', valueStart);
      if (close === -1) {
        prefix.lastIndex = match.index + 1;
        continue;
      }
      const value = line.slice(valueStart, close);
      if (
        value.length >= 8 &&
        !disallowedShapePrefix.test(value) &&
        valueGuard(value)
      ) {
        results.push(structuralMatch(
          content,
          lineStart + match.index,
          lineStart + close + 1,
        ));
        return;
      }
      // Resume inside a rejected outer assignment: another secret-looking key
      // can begin in its value and is a valid later regex start.
      prefix.lastIndex = match.index + 1;
    }
  });

  return results;
}

function shaiHuludMatcher(content: string): CorrelatedPatternMatch[] {
  const token = /child_process|npm|publish|\n|[\r\u2028\u2029]/g;
  const results: CorrelatedPatternMatch[] = [];
  let childStart = -1;
  let childSawNpm = false;
  let wordNpmStart = -1;
  let best: Candidate | undefined;

  const isWord = (character: string | undefined): boolean =>
    character !== undefined && /[A-Za-z0-9_]/.test(character);
  const record = (candidate: Candidate): void => {
    if (betterCandidate(best, candidate)) best = candidate;
  };
  const resetDotSegment = (): void => {
    childStart = -1;
    childSawNpm = false;
  };
  const flushLine = (): void => {
    if (best) results.push(structuralMatch(content, best.start, best.end));
    best = undefined;
    wordNpmStart = -1;
    resetDotSegment();
  };

  let event: RegExpExecArray | null;
  while ((event = token.exec(content)) !== null) {
    const value = event[0]!;
    if (value === "\n") {
      flushLine();
      continue;
    }
    if (value === "\r" || value === "\u2028" || value === "\u2029") {
      resetDotSegment();
      continue;
    }
    if (value === "child_process") {
      if (childStart === -1) childStart = event.index;
      continue;
    }
    if (value === "npm") {
      if (childStart !== -1) childSawNpm = true;
      const wordNpm =
        !isWord(content[event.index - 1]) &&
        !isWord(content[event.index + value.length]);
      if (wordNpm && wordNpmStart === -1) wordNpmStart = event.index;

      let whitespaceEnd = event.index + value.length;
      while (content[whitespaceEnd] !== "\n" && isWhitespace(content[whitespaceEnd])) {
        whitespaceEnd++;
      }
      if (
        whitespaceEnd > event.index + value.length &&
        content.startsWith("publish", whitespaceEnd)
      ) {
        record({ start: event.index, end: whitespaceEnd + 7, priority: 1 });
      }
      continue;
    }

    if (childStart !== -1 && childSawNpm) {
      record({ start: childStart, end: event.index + value.length, priority: 0 });
    }
    const wordPublish =
      !isWord(content[event.index - 1]) &&
      !isWord(content[event.index + value.length]);
    if (wordPublish && wordNpmStart !== -1) {
      record({ start: wordNpmStart, end: event.index + value.length, priority: 2 });
    }
  }
  flushLine();
  return results;
}

const SHAI_CREDENTIAL_SIGNAL =
  /(?:\.npmrc|NPM_TOKEN|npm_config_userconfig|_authToken|process\.env)/;
const SHAI_EXECUTION_SIGNAL =
  /(?:child_process|execSync|spawnSync|execFile|spawn\s*\(|subprocess|os\.system)/;

/**
 * Whole-file Shai-Hulud corroboration without repeated-prefix correlations.
 * This is deliberately symmetric: the legacy reverse-order branch accidentally
 * omitted process.env, although execution-before-credential-access is equally
 * suspicious and common in helper-oriented code.
 */
export function hasShaiHuludCorroboration(content: string): boolean {
  return SHAI_CREDENTIAL_SIGNAL.test(content) && SHAI_EXECUTION_SIGNAL.test(content);
}

const DROPPER_SIMPLE_PREPARATION_SIGNAL =
  /\b(?:fetch\s*\(|axios|https?\.(?:get|request)|XMLHttpRequest|node-fetch|curl\s|wget\s|urllib|requests\.|atob\s*\(|powershell)|chmod/;
const DROPPER_BUFFER_EVENT = /Buffer\.from\s*\(|base64|\)/g;

/**
 * Whole-file dropper corroboration with exact parity for the legacy
 * `Buffer.from\([^)]*base64` branch and linear repeated-prefix behaviour.
 */
export function hasDropperPayloadPreparation(content: string): boolean {
  if (DROPPER_SIMPLE_PREPARATION_SIGNAL.test(content)) return true;

  DROPPER_BUFFER_EVENT.lastIndex = 0;
  let insideBufferCall = false;
  let event: RegExpExecArray | null;
  while ((event = DROPPER_BUFFER_EVENT.exec(content)) !== null) {
    if (event[0] === ")") {
      insideBufferCall = false;
    } else if (event[0] === "base64") {
      if (insideBufferCall) {
        DROPPER_BUFFER_EVENT.lastIndex = 0;
        return true;
      }
    } else {
      insideBufferCall = true;
    }
  }
  DROPPER_BUFFER_EVENT.lastIndex = 0;
  return false;
}

// ---------------------------------------------------------------------------
// Per-hit severity signals. The scanner calls these once per reported hit on
// the same content, so the per-file work is memoised on the last content seen.
// ---------------------------------------------------------------------------

interface ContentMemo {
  content: string;
  lineStarts?: number[];
  regexConstants?: Map<string, { kind: string; body: string; flags: string }[]>;
  guardedImportEvaluations: number;
}

let contentMemo: ContentMemo | undefined;

function memoFor(content: string): ContentMemo {
  if (contentMemo === undefined || contentMemo.content !== content) {
    contentMemo = { content, guardedImportEvaluations: 0 };
  }
  return contentMemo;
}

/** Offsets [start, end) of a 1-based physical line, or undefined past the end. */
function lineBounds(content: string, line: number): [number, number] | undefined {
  const memo = memoFor(content);
  if (memo.lineStarts === undefined) {
    const starts = [0];
    let at = content.indexOf("\n");
    while (at !== -1) {
      starts.push(at + 1);
      at = content.indexOf("\n", at + 1);
    }
    memo.lineStarts = starts;
  }
  const start = memo.lineStarts[line - 1];
  if (start === undefined) return undefined;
  const next = memo.lineStarts[line];
  return [start, next === undefined ? content.length : next - 1];
}

/**
 * Beyond this many template imports per file every further hit keeps the
 * rule's own severity. It bounds the guard search on hostile input, and it
 * fails towards the pre-guard verdict rather than towards info.
 */
const MAX_GUARDED_IMPORT_EVALUATIONS = 256;
/** How far before an import its guard may sit. Longer functions stay medium. */
const IMPORT_GUARD_WINDOW_CHARS = 2000;

const IMPORT_TEMPLATE_START = /import[^\S\n]*\([^\S\n]*`/g;
/**
 * A specifier with a static relative or alias prefix, exactly one bare
 * identifier, and a static suffix ending in a file extension.
 */
const GUARDABLE_SPECIFIER =
  /^((?:\.\.?\/|@[A-Za-z0-9_-]{1,64}\/)[A-Za-z0-9_@/.-]{0,200})\$\{[^\S\n]*([A-Za-z_$][\w$]{0,63})[^\S\n]*\}([A-Za-z0-9_/.-]{0,200}\.[A-Za-z0-9]{1,10})$/;
const REGEX_LITERAL = String.raw`/((?:\\.|\[[^\]\n]{0,100}\]|[^/\\\[\n]){1,200})/([a-z]{0,6})`;
const IMPORT_GUARD = new RegExp(
  String.raw`if\s*\(\s*(!\s*)?(?:([A-Za-z_$][\w$]{0,63})|${REGEX_LITERAL})\.test\(\s*([A-Za-z_$][\w$]{0,63})\s*\)\s*\)`,
  "g",
);
const REGEX_CONSTANT = new RegExp(
  String.raw`(?<![\w$.])(const|let|var)\s+([A-Za-z_$][\w$]{0,63})\s*=\s*${REGEX_LITERAL}`,
  "g",
);

function isAlnumRangeSafe(from: string, to: string): boolean {
  const sameClass = (re: RegExp) => re.test(from) && re.test(to);
  return from <= to && (sameClass(/^[a-z]$/) || sameClass(/^[A-Z]$/) || sameClass(/^[0-9]$/));
}

/**
 * True when an anchored regex can only accept [A-Za-z0-9_-]. That excludes
 * `/`, `\`, `.` and `%` (a percent-encoded dot segment still resolves), so an
 * accepted value cannot leave the static prefix's directory. Anything outside
 * this small grammar, including alternation, groups and negated classes, is
 * refused rather than interpreted.
 */
export function isPathSafeAllowlistRegex(body: string, flags: string): boolean {
  if (!/^[isu]*$/.test(flags)) return false;
  if (body.length < 3 || body[0] !== "^" || body[body.length - 1] !== "$") return false;
  let i = 1;
  const end = body.length - 1;
  let atoms = 0;
  const isLiteral = (ch: string | undefined) => ch !== undefined && /^[A-Za-z0-9_-]$/.test(ch);
  while (i < end) {
    const ch = body[i]!;
    if (ch === "[") {
      if (body[i + 1] === "^") return false;
      i++;
      let members = 0;
      while (i < end && body[i] !== "]") {
        const c = body[i]!;
        if (c === "\\") {
          if (!/^[wd_-]$/.test(body[i + 1] ?? "")) return false;
          i += 2;
        } else if (body[i + 1] === "-" && body[i + 2] !== undefined && body[i + 2] !== "]") {
          if (!isAlnumRangeSafe(c, body[i + 2]!)) return false;
          i += 3;
        } else if (isLiteral(c)) {
          i++;
        } else {
          return false;
        }
        members++;
      }
      if (body[i] !== "]" || members === 0) return false;
      i++;
    } else if (ch === "\\") {
      if (!/^[wd]$/.test(body[i + 1] ?? "")) return false;
      i += 2;
    } else if (isLiteral(ch)) {
      i++;
    } else {
      return false;
    }
    atoms++;
    const quantifier = /^(?:[*+?]|\{\d{1,4}(?:,\d{0,4})?\})/.exec(body.slice(i, end));
    if (quantifier) i += quantifier[0].length;
  }
  return atoms > 0 && i === end;
}

function regexConstants(content: string): Map<string, { kind: string; body: string; flags: string }[]> {
  const memo = memoFor(content);
  if (memo.regexConstants === undefined) {
    const found = new Map<string, { kind: string; body: string; flags: string }[]>();
    REGEX_CONSTANT.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = REGEX_CONSTANT.exec(content)) !== null) {
      const list = found.get(match[2]!) ?? [];
      list.push({ kind: match[1]!, body: match[3]!, flags: match[4]! });
      found.set(match[2]!, list);
    }
    REGEX_CONSTANT.lastIndex = 0;
    memo.regexConstants = found;
  }
  return memo.regexConstants;
}

/**
 * Brace depth never drops below zero and no nested function starts. Braces in
 * strings, templates and comments are skipped, so a `"{"` cannot balance the
 * `}` that closes the guard's function. Anything this small lexer cannot
 * follow (an unterminated literal, a bare `/` that may open a regex literal
 * holding a quote) refuses the downgrade instead of guessing.
 */
function staysInSameFunction(segment: string, minDepth: number): boolean {
  if (/\bfunction\b|=>/.test(segment)) return false;
  let depth = 0;
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i]!;
    if (ch === '"' || ch === "'" || ch === "`") {
      i++;
      while (i < segment.length && segment[i] !== ch) {
        if (segment[i] === "\\") i++;
        i++;
      }
      if (i >= segment.length) return false;
    } else if (ch === "/" && segment[i + 1] === "/") {
      const newline = segment.indexOf("\n", i);
      i = newline === -1 ? segment.length : newline;
    } else if (ch === "/" && segment[i + 1] === "*") {
      const close = segment.indexOf("*/", i + 2);
      if (close === -1) return false;
      i = close + 1;
    } else if (ch === "/") {
      return false;
    } else if (ch === "{") {
      depth++;
    } else if (ch === "}" && --depth < minDepth) {
      return false;
    }
  }
  return true;
}

function isReassigned(segment: string, id: string): boolean {
  // A JavaScript identifier, so "$" was the only metacharacter it could hold
  // and escaping just that was correct; the shared helper removes the question.
  const name = escapeRegExp(id);
  return new RegExp(
    String.raw`(?<![\w$.])${name}\s*(?:(?:[-+*/%&|^]|\*\*|<<|>>>?|\?\?|&&|\|\|)?=(?![=>])|\+\+|--)|(?:\+\+|--)\s*${name}(?![\w$])|\b(?:of|in)\s+${name}\b|(?:let|const|var)\s+${name}(?![\w$])`,
  ).test(segment);
}

function isGuardedTemplateImport(content: string, importStart: number, specifierStart: number): boolean {
  const close = content.indexOf("`", specifierStart);
  if (close === -1 || close - specifierStart > 512) return false;
  if (!/^[^\S\n]*\)/.test(content.slice(close + 1, close + 64))) return false;
  const spec = GUARDABLE_SPECIFIER.exec(content.slice(specifierStart, close));
  if (!spec) return false;
  const id = spec[2]!;

  const windowStart = Math.max(0, importStart - IMPORT_GUARD_WINDOW_CHARS);
  const window = content.slice(windowStart, importStart);
  IMPORT_GUARD.lastIndex = 0;
  let guard: RegExpExecArray | null = null;
  let match: RegExpExecArray | null;
  while ((match = IMPORT_GUARD.exec(window)) !== null) {
    if (match[5] === id) guard = match;
  }
  IMPORT_GUARD.lastIndex = 0;
  if (!guard) return false;

  let body = guard[3];
  let flags = guard[4] ?? "";
  if (guard[2] !== undefined) {
    const defs = regexConstants(content).get(guard[2]);
    if (!defs || defs.length !== 1 || defs[0]!.kind !== "const") return false;
    body = defs[0]!.body;
    flags = defs[0]!.flags;
  }
  if (body === undefined || !isPathSafeAllowlistRegex(body, flags)) return false;

  const after = window.slice(guard.index + guard[0].length);
  if (isReassigned(after, id)) return false;
  if (guard[1] !== undefined) {
    // `if (!RE.test(id)) throw|return` exits before the import is reached.
    if (!/^\s*\{?\s*(?:throw|return)\b/.test(after)) return false;
    return staysInSameFunction(after, 0);
  }
  // `if (RE.test(id)) return import(...)` or the import inside that block.
  if (/^\s*return\s*$/.test(after)) return true;
  const block = /^\s*\{/.exec(after);
  if (!block) return false;
  return staysInSameFunction(after.slice(block[0].length), 0);
}

/**
 * True when every template import() on a hit line has a static prefix and
 * extension, interpolates one bare identifier, and that identifier was tested
 * earlier in the same function against an anchored allowlist that admits no
 * path characters. IMPORT_EXPRESSION then reports at info.
 */
export function isAllowlistGuardedImportLine(content: string, line: number): boolean {
  const bounds = lineBounds(content, line);
  if (!bounds) return false;
  const memo = memoFor(content);
  const text = content.slice(bounds[0], bounds[1]);
  IMPORT_TEMPLATE_START.lastIndex = 0;
  let seen = 0;
  let match: RegExpExecArray | null;
  while ((match = IMPORT_TEMPLATE_START.exec(text)) !== null) {
    if (++memo.guardedImportEvaluations > MAX_GUARDED_IMPORT_EVALUATIONS) {
      IMPORT_TEMPLATE_START.lastIndex = 0;
      return false;
    }
    seen++;
    const importStart = bounds[0] + match.index;
    if (!isGuardedTemplateImport(content, importStart, importStart + match[0].length)) {
      IMPORT_TEMPLATE_START.lastIndex = 0;
      return false;
    }
  }
  IMPORT_TEMPLATE_START.lastIndex = 0;
  return seen > 0;
}

export const CORE_BROAD_GAP_RULES = [
  "EVAL_HEX",
  "ENV_EXFILTRATION",
  "DNS_EXFILTRATION",
  "SCRIPT_NODE_INLINE",
  "XZ_BUILD_INJECT",
  "CODECOV_EXFIL",
  "SUNBURST_DELAYED_EXEC",
  "UAPARSER_PREINSTALL_DL",
  "MINI_SHAI_HULUD_PREINSTALL",
  "ANTV_WAVE_OTEL_C2",
  "COA_RC_POSTINSTALL",
  "PYPI_ENV_EXFILTRATION",
  "PYPI_HOSTNAME_EXFIL",
  "BEACON_INTERVAL_FETCH",
  "BEACON_TIMEOUT_FETCH",
  "PROTESTWARE_LOCALE_DESTRUCT",
  "PROTESTWARE_GEOIP_DESTRUCT",
  "BUILD_PLUGIN_DOWNLOAD",
  "BUILD_ENV_EXFIL",
  "WORKSPACE_ROOT_POSTINSTALL",
  "WORKSPACE_PRIVATE_PUBLISH",
  "SHAI_HULUD_WORM",
  "IMPORT_EXPRESSION",
  "STEGANOGRAPHY_DECODE",
  "SVG_SCRIPT_INJECTION",
  "IAC_HARDCODED_SECRET",
  "DEAD_DROP_DNS_TXT",
  "VIDAR_BROWSER_THEFT",
  "VIDAR_WALLET_THEFT",
  "DROPPER_ANTIVM",
  "README_LURE_URGENCY",
  "CAMPAIGN_CLAUDE_LURE",
  "CAMPAIGN_AI_TOOL_LURE",
  "C2_DYNAMIC_CONFIG",
  "SECRETS_SSH_KEY_READ",
  "CODE_RUNTIME_DEOBFUSCATION",
] as const;

export type CoreBroadGapRule = typeof CORE_BROAD_GAP_RULES[number];

export function createCoreBroadGapMatchers(
  isLikelyRealSecretValue: (value: string) => boolean,
): Readonly<Record<CoreBroadGapRule, CorrelatedPatternMatcher>> {
  const transport =
    String.raw`(?:fetch${WS0}\(|https?\.(?:get|request)|axios|\bgot${WS0}[.(]|node-fetch)`;
  const pythonTransport = String.raw`(?:urllib|requests|http\.client|socket)`;
  const beaconTransport = BEACON_TRANSPORT_SOURCE;

  return {
    EVAL_HEX: evalHexMatcher,
    ENV_EXFILTRATION: makeOrderedEventMatcher([
      {
        tokens: [String.raw`process\.env\b`, transport],
        gaps: [GAP_SEMICOLON],
        priority: 0,
      },
      {
        tokens: [transport, String.raw`process\.env\b`],
        gaps: [GAP_SEMICOLON],
        priority: 1,
      },
    ]),
    DNS_EXFILTRATION: makeOrderedEventMatcher([{
      tokens: [String.raw`dns\.resolve`, String.raw`process\.env`],
      gaps: [GAP_DOT],
    }]),
    SCRIPT_NODE_INLINE: makeOrderedEventMatcher([{
      tokens: [
        String.raw`node${WS1}-e${WS1}["']`,
        String.raw`(?:http|https|fetch|require)`,
      ],
      gaps: [GAP_DOT],
    }], true),
    XZ_BUILD_INJECT: makeOrderedEventMatcher([
      {
        tokens: [String.raw`gl_cv_host_cpu_c_abi`, "=", String.raw`configure\.ac`],
        gaps: [GAP_DOT, GAP_DOT],
        priority: 0,
      },
      {
        tokens: [String.raw`AM_CONDITIONAL`, String.raw`\bgl_INIT\b`],
        gaps: [GAP_DOT],
        priority: 1,
      },
      {
        tokens: ["m4/", String.raw`\.m4`, "ifnot"],
        gaps: [GAP_DOT, GAP_DOT],
        priority: 2,
      },
    ]),
    CODECOV_EXFIL: makeOrderedEventMatcher([
      {
        tokens: ["codecov", String.raw`(?:ENV|TOKEN|SECRET|CREDENTIAL|PASSWORD|API_KEY)`],
        gaps: [GAP_SEMICOLON],
        priority: 0,
      },
      {
        tokens: [String.raw`(?:ENV|TOKEN|SECRET|CREDENTIAL|PASSWORD|API_KEY)`, "codecov"],
        gaps: [GAP_SEMICOLON],
        priority: 1,
      },
    ]),
    SUNBURST_DELAYED_EXEC: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:Thread\.Sleep|setTimeout|sleep)${WS0}\(`,
        String.raw`(?:[0-9]{7,}|\d+${WS0}\*${WS0}(?:3600|86400|60${WS0}\*${WS0}60))`,
      ],
      gaps: [GAP_RIGHT_PAREN],
      finalMode: "first",
    }]),
    UAPARSER_PREINSTALL_DL: makeOrderedEventMatcher([{
      tokens: [
        String.raw`preinstall["']?${WS0}:${WS0}["']`,
        String.raw`(?:curl|wget)${WS1}https?://`,
        String.raw`(?:\.exe|\.sh|\.bat)`,
      ],
      gaps: [GAP_QUOTES, GAP_QUOTES],
    }]),
    MINI_SHAI_HULUD_PREINSTALL: makeOrderedEventMatcher([{
      tokens: [
        String.raw`preinstall["']?${WS0}:${WS0}["']`,
        String.raw`\bbun\b`,
        String.raw`(?:setup\.mjs|execution\.js)`,
      ],
      gaps: [GAP_QUOTES, GAP_QUOTES],
    }]),
    ANTV_WAVE_OTEL_C2: makeOrderedEventMatcher([{
      tokens: [String.raw`m-kosche\.com`, "api/public/otel/v1/traces"],
      gaps: [GAP_QUOTES],
    }]),
    COA_RC_POSTINSTALL: makeOrderedEventMatcher([
      {
        tokens: [
          String.raw`postinstall["']?${WS0}:${WS0}["']`,
          String.raw`compile\.js`,
        ],
        gaps: [GAP_QUOTES],
        priority: 0,
        greedyBranchToken: 1,
      },
      {
        tokens: [
          String.raw`postinstall["']?${WS0}:${WS0}["']`,
          String.raw`(?:Buffer|atob)`,
          String.raw`(?:exec|spawn|child_process)`,
        ],
        gaps: [GAP_QUOTES, GAP_DOT],
        // The common [^"']* prefix gap is greedy: choose the rightmost branch
        // pivot first, then use source-order priority at that pivot.
        priority: 1,
        greedyBranchToken: 1,
      },
    ]),
    PYPI_ENV_EXFILTRATION: makeOrderedEventMatcher([{
      tokens: [String.raw`os\.environ\b`, pythonTransport],
      gaps: [GAP_SEMICOLON],
    }]),
    PYPI_HOSTNAME_EXFIL: makeOrderedEventMatcher([{
      tokens: [String.raw`socket\.gethostname${WS0}\(\)`, String.raw`(?:urllib|requests|http)`],
      gaps: [GAP_SEMICOLON],
    }]),
    BEACON_INTERVAL_FETCH: makeOrderedEventMatcher([{
      tokens: [String.raw`setInterval${WS0}\(`, beaconTransport],
      gaps: [GAP_DOT],
    }], true),
    BEACON_TIMEOUT_FETCH: makeOrderedEventMatcher([{
      tokens: [String.raw`setTimeout${WS0}\(`, beaconTransport],
      gaps: [GAP_DOT],
    }], true),
    PROTESTWARE_LOCALE_DESTRUCT: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:locale|timezone|timeZone|country|getTimezone|Intl\.DateTimeFormat)`,
        String.raw`(?:fs\.(?:rm|rmdir|unlink|truncate|ftruncate)|process\.exit|child_process|execSync|rimraf)`,
      ],
      gaps: [GAP_DOT_PROTESTWARE],
    }], true),
    PROTESTWARE_GEOIP_DESTRUCT: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:geoip|ip-api|ipinfo|freegeoip|ipgeolocation)`,
        String.raw`(?:fs\.(?:rm|rmdir|unlink)|process\.exit|execSync)`,
      ],
      gaps: [GAP_DOT_PROTESTWARE],
    }], true),
    BUILD_PLUGIN_DOWNLOAD: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:require|import)${WS0}\(?["']`,
        String.raw`["']\)?`,
        String.raw`(?:fetch|https?\.get|axios|got|download)`,
      ],
      gaps: [GAP_QUOTES_ONE, GAP_SEMICOLON],
    }], true),
    BUILD_ENV_EXFIL: mergeAlternativeMatchers([
      {
        matcher: makeOrderedEventMatcher([{
          tokens: [String.raw`process\.env\b`, String.raw`(?:fetch|https?\.(?:get|request)|axios|got)`],
          gaps: [GAP_DOT],
        }], true),
        priority: 0,
      },
      {
        matcher: makeOrderedEventMatcher([{
          tokens: [String.raw`(?:fetch|https?\.(?:get|request)|axios|got)`, String.raw`process\.env`],
          gaps: [GAP_DOT],
        }], true),
        priority: 1,
      },
    ]),
    WORKSPACE_ROOT_POSTINSTALL: makeOrderedEventMatcher([{
      tokens: [
        String.raw`"postinstall"${WS0}:${WS0}"`,
        String.raw`(?:curl|wget|node${WS1}-e|bash|sh${WS1}-c)`,
      ],
      gaps: [GAP_DOUBLE_QUOTE],
    }], true),
    WORKSPACE_PRIVATE_PUBLISH: makeOrderedEventMatcher([{
      tokens: [String.raw`"private"${WS0}:${WS0}false`, String.raw`"publishConfig"`],
      gaps: [GAP_RIGHT_BRACE],
    }], true),
    SHAI_HULUD_WORM: shaiHuludMatcher,
    IMPORT_EXPRESSION: makeOrderedEventMatcher([
      {
        tokens: [String.raw`import${WS0}\(${WS0}\``, String.raw`\$\{`],
        gaps: [GAP_BACKTICK],
        priority: 0,
      },
      {
        tokens: [String.raw`import${WS0}\(${WS0}(?:\+|process\.env|String\.fromCharCode|(?:req|request)\.(?:query|params|body|headers)\b)`],
        gaps: [],
        priority: 1,
      },
    ]),
    STEGANOGRAPHY_DECODE: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:atob|Buffer\.from)${WS0}\(`,
        String.raw`(?:\.png|\.jpg|\.gif|\.bmp|\.ico|\.svg|\.woff|\.ttf)`,
      ],
      gaps: [GAP_RIGHT_PAREN],
    }]),
    SVG_SCRIPT_INJECTION: makeOrderedEventMatcher([
      {
        // The opening tag alone: see the svg-script-injection entry in
        // patterns.ts for why the end tag is no longer required.
        tokens: [String.raw`<(?:[\w.-]+:)?script(?![\w.:-])`],
        gaps: [],
        priority: 0,
      },
      {
        tokens: [String.raw`\bon\w+${WS0}=${WS0}["']`],
        gaps: [],
        priority: 1,
      },
    // Case-insensitive, matching the pattern's character classes.
    ], true),
    IAC_HARDCODED_SECRET: (content) =>
      iacHardcodedSecretMatcher(content, isLikelyRealSecretValue),
    DEAD_DROP_DNS_TXT: mergeAlternativeMatchers([
      {
        matcher: makeOrderedEventMatcher([{
          tokens: [String.raw`(?:nslookup|dig)${WS1}`, String.raw`\bTXT\b`],
          gaps: [GAP_DOT],
        }]),
        priority: 0,
      },
      {
        matcher: makeOrderedEventMatcher([{
          tokens: [String.raw`dns\.resolveTxt`],
          gaps: [],
        }]),
        priority: 1,
      },
      {
        matcher: makeOrderedEventMatcher([{
          tokens: [String.raw`resolver\.query`, "TXT"],
          gaps: [GAP_DOT],
        }]),
        priority: 2,
      },
    ]),
    VIDAR_BROWSER_THEFT: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:AppData[/\\](?:Local|Roaming)[/\\](?:Google|Mozilla|BraveSoftware|Microsoft[/\\]Edge)|Library[/\\]Application Support[/\\](?:Firefox|Google[/\\]Chrome|BraveSoftware)|\.mozilla[/\\]firefox|\.config[/\\](?:google-chrome|chromium))`,
        String.raw`(?:Login Data|Cookies|Web Data|Local State|key4\.db|logins\.json)`,
      ],
      gaps: [GAP_DOT],
    }]),
    VIDAR_WALLET_THEFT: mergeAlternativeMatchers([
      {
        matcher: makeOrderedEventMatcher([
          {
            tokens: [
              `(?<![A-Za-z])${WALLET_NAME_SOURCE}(?![a-z])`,
              WALLET_TARGET_SOURCE,
            ],
            gaps: [GAP_DOT],
            priority: 0,
          },
          {
            tokens: [String.raw`(?<![A-Za-z])Trust(?![a-z])`, "Wallet", WALLET_TARGET_SOURCE],
            gaps: [GAP_DOT, GAP_DOT],
            priority: 0,
          },
        ]),
        priority: 0,
      },
      {
        matcher: makeOrderedEventMatcher([{
          tokens: [String.raw`wallet\.dat`],
          gaps: [],
        }]),
        priority: 1,
      },
    ]),
    DROPPER_ANTIVM: makeOrderedEventMatcher([
      {
        tokens: [
          String.raw`(?:VMware|VirtualBox|VBOX|QEMU|Hyper-V|Xen|Parallels)`,
          String.raw`(?:detect|check|exit)`,
        ],
        gaps: [GAP_DOT],
        priority: 0,
      },
      {
        tokens: [String.raw`(?:GetTickCount|IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebuggerPresent)`],
        gaps: [],
        priority: 1,
      },
    ]),
    README_LURE_URGENCY: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:download|get|grab)${WS1}(?:before|quickly|fast|now|while)`,
        String.raw`(?:removed|taken down|deleted|gone|available)`,
      ],
      gaps: [GAP_DOT],
    }], true),
    CAMPAIGN_CLAUDE_LURE: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:claude${WS0}code|anthropic)`,
        String.raw`(?:leaked|cracked|unlocked|free|exposed|rebuilt)`,
      ],
      gaps: [GAP_DOT],
    }], true),
    CAMPAIGN_AI_TOOL_LURE: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:copilot|cursor|devin|openai|chatgpt|gemini|claude|windsurf|openclaw)`,
        String.raw`(?:leaked|cracked|free${WS0}download|source${WS0}dump)`,
      ],
      gaps: [GAP_DOT],
    }], true),
    C2_DYNAMIC_CONFIG: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:fetch|https?\.get|axios\.get|got)${WS0}\(`,
        String.raw`(?:config|settings|update|check|beacon|ping|heartbeat)`,
        String.raw`\)`,
        String.raw`(?:eval|exec|Function|spawn)`,
      ],
      gaps: [GAP_RIGHT_PAREN, GAP_RIGHT_PAREN, GAP_DOT],
    }]),
    SECRETS_SSH_KEY_READ: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:readFile|readFileSync|open|cat|type)`,
        String.raw`\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa|id_dsa|identity)(?:[^a-z\n]|(?=\n|$))`,
      ],
      gaps: [GAP_DOT],
    }]),
    CODE_RUNTIME_DEOBFUSCATION: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:setInterval|setTimeout|requestAnimationFrame)${WS0}\(`,
        String.raw`(?:eval|Function|exec)`,
      ],
      gaps: [GAP_RIGHT_PAREN],
    }]),
  };
}