import type {
  CorrelatedPatternMatch,
  CorrelatedPatternMatcher,
} from "./types.js";

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
}

const GAP_DOT: GapSpec = { barrierMask: LF | DOT_TERMINATOR };
const GAP_LINE: GapSpec = { barrierMask: LF };
const GAP_SEMICOLON: GapSpec = { barrierMask: LF | SEMICOLON };
const GAP_QUOTES: GapSpec = { barrierMask: LF | DOUBLE_QUOTE | SINGLE_QUOTE };
const GAP_DOUBLE_QUOTE: GapSpec = { barrierMask: LF | DOUBLE_QUOTE };
const GAP_RIGHT_PAREN: GapSpec = { barrierMask: LF | RIGHT_PAREN };
const GAP_RIGHT_BRACE: GapSpec = { barrierMask: LF | RIGHT_BRACE };
const GAP_BACKTICK: GapSpec = { barrierMask: LF | BACKTICK };
const GAP_RIGHT_ANGLE: GapSpec = { barrierMask: LF | RIGHT_ANGLE };
const GAP_QUOTES_ONE: GapSpec = {
  barrierMask: GAP_QUOTES.barrierMask,
  minChars: 1,
};


const WS0 = String.raw`[^\S\n]*`;
const WS1 = String.raw`[^\S\n]+`;

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
            if (eventStart < state.ends[stage]! + (gap.minChars ?? 0)) continue;

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
  const beaconTransport =
    String.raw`(?:fetch|https?\.(?:get|request)|axios|got|node-fetch|XMLHttpRequest)`;

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
        String.raw`(?:fs\.(?:rm|rmdir|unlink|writeFile)|process\.exit|child_process|execSync|rimraf)`,
      ],
      gaps: [GAP_DOT],
    }], true),
    PROTESTWARE_GEOIP_DESTRUCT: makeOrderedEventMatcher([{
      tokens: [
        String.raw`(?:geoip|ip-api|ipinfo|freegeoip|ipgeolocation)`,
        String.raw`(?:fs\.(?:rm|rmdir|unlink)|process\.exit|execSync)`,
      ],
      gaps: [GAP_DOT],
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
        tokens: [String.raw`import${WS0}\(${WS0}(?:\+|process\.env|String\.fromCharCode)`],
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
        tokens: ["<script", ">", String.raw`</script>`],
        gaps: [GAP_RIGHT_ANGLE, GAP_LINE],
        priority: 0,
        finalMode: "first",
      },
      {
        tokens: [String.raw`\bon\w+${WS0}=${WS0}["']`],
        gaps: [],
        priority: 1,
      },
    ]),
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
              String.raw`(?:Exodus|exodus|MetaMask|metamask|Phantom|phantom|Atomic|Electrum|electrum|Coinomi)`,
              String.raw`(?:wallet|keystore|vault|seed|mnemonic)`,
            ],
            gaps: [GAP_DOT],
            priority: 0,
          },
          {
            tokens: ["Trust", "Wallet", String.raw`(?:wallet|keystore|vault|seed|mnemonic)`],
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