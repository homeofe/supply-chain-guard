import type {
  CorrelatedPatternMatch,
  CorrelatedPatternMatcher,
} from "./types.js";

const MAX_EVIDENCE_CHARS = 240;
const REPORT_PREFIX_CHARS = 120;

function structuralMatch(
  content: string,
  start: number,
  end: number,
): CorrelatedPatternMatch {
  const raw = content.slice(start, end);
  if (raw.length <= MAX_EVIDENCE_CHARS) return { start, end, evidence: raw };

  // The workflow reporter exposes the first 120 characters. Preserve that
  // prefix exactly while still retaining bounded tail context for other users
  // of the shared matcher.
  const separator = " ... ";
  const tailLength = MAX_EVIDENCE_CHARS - REPORT_PREFIX_CHARS - separator.length;
  return {
    start,
    end,
    evidence:
      raw.slice(0, REPORT_PREFIX_CHARS) +
      separator +
      raw.slice(raw.length - tailLength),
  };
}

interface TokenEvent {
  start: number;
  end: number;
}

type TokenEventFactory = (content: string) => Iterable<TokenEvent>;

function fixedToken(source: string): TokenEventFactory {
  return function* fixedTokenEvents(content: string): Iterable<TokenEvent> {
    // Zero-width matching reports overlapping starts, which is required for
    // exact RegExp search semantics (for example the `sh` inside `bash`).
    const regex = new RegExp(`(?=(${source}))`, "gi");
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const value = match[1]!;
      if (value.length === 0) {
        throw new Error("Workflow structural token must consume input");
      }
      yield { start: match.index, end: match.index + value.length };
      regex.lastIndex = match.index + 1;
    }
  };
}

function isRegexWhitespace(character: string | undefined): boolean {
  return character !== undefined && /\s/.test(character);
}

/** Exact, linear tokenization of `-o\s+\S+` under the legacy `i` flag. */
function* outputFileTokens(content: string): Iterable<TokenEvent> {
  for (let start = 0; start + 1 < content.length; start++) {
    if (content[start] !== "-" || content[start + 1]!.toLowerCase() !== "o") {
      continue;
    }

    let cursor = start + 2;
    const whitespaceStart = cursor;
    while (content[cursor] !== "\n" && isRegexWhitespace(content[cursor])) {
      cursor++;
    }
    if (cursor === whitespaceStart || !content[cursor] || isRegexWhitespace(content[cursor])) {
      continue;
    }

    while (content[cursor] && !isRegexWhitespace(content[cursor])) cursor++;
    yield { start, end: cursor };
  }
}

/**
 * Exact tokenization of `${{ secrets.<non-empty> }}` without repeatedly
 * searching a long unterminated body from every `${{` prefix.
 *
 * Every candidate before the first `}` shares that same closing decision, so
 * each prefix is queued once and resolved once. Emitting nested candidates is
 * necessary when a transport token sits between their starts: the outer secret
 * is then before the transport while the inner secret remains a valid final
 * token. Total work and storage remain linear in the input size.
 */
function* secretExpressionTokens(
  content: string,
  includeNestedStarts = false,
): Iterable<TokenEvent> {
  const prefix = /(?=(\$\{\{[^\S\n]*secrets\.))/gi;
  const closeOrLine = /[}\n]/g;
  let prefixEvent = prefix.exec(content);
  let closeEvent = closeOrLine.exec(content);
  const pendingStarts: number[] = [];
  const pendingBodyStarts: number[] = [];

  while (prefixEvent || closeEvent) {
    const prefixStart = prefixEvent?.index ?? Number.POSITIVE_INFINITY;
    const closeStart = closeEvent?.index ?? Number.POSITIVE_INFINITY;

    if (prefixStart < closeStart) {
      pendingStarts.push(prefixStart);
      pendingBodyStarts.push(prefixStart + prefixEvent![1]!.length);
      prefix.lastIndex = prefixStart + 1;
      prefixEvent = prefix.exec(content);
      continue;
    }

    if (closeEvent![0] === "\n") {
      pendingStarts.length = 0;
      pendingBodyStarts.length = 0;
    } else {
      if (content[closeStart + 1] === "}") {
        for (let index = 0; index < pendingStarts.length; index++) {
          if (pendingBodyStarts[index]! < closeStart) {
            yield { start: pendingStarts[index]!, end: closeStart + 2 };
            if (!includeNestedStarts) break;
          }
        }
      }
      // `[^}]+` cannot backtrack past this brace. A single brace invalidates
      // every pending prefix; a doubled brace closes them all at the same end.
      pendingStarts.length = 0;
      pendingBodyStarts.length = 0;
    }
    closeEvent = closeOrLine.exec(content);
  }
}

const LF = 1 << 0;
const DOT_TERMINATOR = 1 << 1;
const PIPE = 1 << 2;
const SINGLE_QUOTE = 1 << 3;
const DOUBLE_QUOTE = 1 << 4;

interface GapSpec {
  barrierMask: number;
}

const GAP_DOT: GapSpec = { barrierMask: LF | DOT_TERMINATOR };
const GAP_PIPE: GapSpec = { barrierMask: LF | PIPE };
const GAP_QUOTES: GapSpec = {
  barrierMask: LF | SINGLE_QUOTE | DOUBLE_QUOTE,
};

function barrierBit(character: string): number {
  if (character === "\n") return LF;
  if (character === "\r" || character === "\u2028" || character === "\u2029") {
    return DOT_TERMINATOR;
  }
  if (character === "|") return PIPE;
  if (character === "'") return SINGLE_QUOTE;
  if (character === '"') return DOUBLE_QUOTE;
  return 0;
}

interface ScheduledStage {
  stage: number;
  start: number;
  end: number;
}

interface Candidate {
  start: number;
  end: number;
  finalStart: number;
}

/**
 * Constant-stage event NFA for one ordered, single-line correlation. Token
 * events are consumed atomically, so a CR/U+2028/U+2029 inside `\s+`, `\S+`,
 * or a secret expression is not mistaken for a barrier in the following gap.
 */
function orderedMatcher(
  tokens: readonly TokenEventFactory[],
  gaps: readonly GapSpec[],
): CorrelatedPatternMatcher {
  if (tokens.length < 2 || gaps.length !== tokens.length - 1) {
    throw new Error("Invalid workflow structural matcher");
  }

  return (content) => {
    const active = new Array<boolean>(tokens.length).fill(false);
    const starts = new Array<number>(tokens.length).fill(-1);
    const ends = new Array<number>(tokens.length).fill(0);
    const scheduled: ScheduledStage[] = [];
    const results: CorrelatedPatternMatch[] = [];
    let best: Candidate | undefined;

    const activate = (stage: number, start: number, end: number): void => {
      // An earlier overall start is what RegExp#exec tries first. With a shared
      // start, an earlier gap start admits every continuation a later one does;
      // consumed-token barriers are retained separately in `scheduled`.
      if (
        !active[stage] ||
        start < starts[stage]! ||
        (start === starts[stage] && end < ends[stage]!)
      ) {
        active[stage] = true;
        starts[stage] = start;
        ends[stage] = end;
      }
    };
    const activateScheduled = (through: number): void => {
      let write = 0;
      for (const pending of scheduled) {
        if (pending.end <= through) {
          activate(pending.stage, pending.start, pending.end);
        } else {
          scheduled[write++] = pending;
        }
      }
      scheduled.length = write;
    };
    const record = (start: number, end: number, finalStart: number): void => {
      const candidate = { start, end, finalStart };
      if (
        !best ||
        candidate.start < best.start ||
        (candidate.start === best.start && (
          candidate.finalStart > best.finalStart ||
          (candidate.finalStart === best.finalStart && candidate.end > best.end)
        ))
      ) {
        best = candidate;
      }
    };
    const resetLine = (): void => {
      active.fill(false);
      scheduled.length = 0;
    };
    const flushLine = (): void => {
      if (best) results.push(structuralMatch(content, best.start, best.end));
      best = undefined;
      resetLine();
    };

    const streams = tokens.map((factory) => {
      const iterator = factory(content)[Symbol.iterator]();
      return { iterator, event: iterator.next().value as TokenEvent | undefined };
    });
    const barrier = /[\n\r\u2028\u2029|'"]/g;
    let barrierEvent = barrier.exec(content);

    while (true) {
      let eventStart = barrierEvent?.index ?? Number.POSITIVE_INFINITY;
      for (const stream of streams) {
        if (stream.event && stream.event.start < eventStart) {
          eventStart = stream.event.start;
        }
      }
      if (!Number.isFinite(eventStart)) break;

      activateScheduled(eventStart);

      // Descending stages prevent one token event from satisfying two adjacent
      // positions. All tokens at this offset are processed before its barrier.
      for (let tokenIndex = 0; tokenIndex < streams.length; tokenIndex++) {
        const stream = streams[tokenIndex]!;
        const event = stream.event;
        if (!event || event.start !== eventStart) continue;

        for (let stage = tokens.length - 1; stage >= 1; stage--) {
          if (!active[stage] || tokenIndex !== stage || event.start < ends[stage]!) {
            continue;
          }
          if (stage === tokens.length - 1) {
            record(starts[stage]!, event.end, event.start);
          } else {
            scheduled.push({
              stage: stage + 1,
              start: starts[stage]!,
              end: event.end,
            });
          }
        }

        if (tokenIndex === 0) {
          scheduled.push({ stage: 1, start: event.start, end: event.end });
        }
        stream.event = stream.iterator.next().value as TokenEvent | undefined;
      }

      if (barrierEvent?.index === eventStart) {
        const bit = barrierBit(barrierEvent[0]!);
        if (bit === LF) {
          flushLine();
        } else {
          for (let stage = 1; stage < tokens.length; stage++) {
            if (
              active[stage] &&
              eventStart >= ends[stage]! &&
              (gaps[stage - 1]!.barrierMask & bit) !== 0
            ) {
              active[stage] = false;
            }
          }
        }
        barrierEvent = barrier.exec(content);
      }
    }

    flushLine();
    return results;
  };
}

const WS0 = String.raw`[^\S\n]*`;
const WS1 = String.raw`[^\S\n]+`;
const SHELLS = String.raw`(?:bash|sh|zsh|node|python|perl|ruby)`;
const DOWNLOAD_TERMINAL = String.raw`(?:bash|sh|chmod${WS1}\+x)`;
const SECRET_OR_ENV_PREFIX = String.raw`\$\{\{${WS0}(?:secrets|env)\.`;

function commandPipe(command: "curl" | "wget"): CorrelatedPatternMatcher {
  return orderedMatcher(
    [fixedToken(`${command}${WS1}`), fixedToken(String.raw`\|${WS0}${SHELLS}`)],
    [GAP_PIPE],
  );
}

function downloadThenExecute(command: "curl" | "wget"): CorrelatedPatternMatcher {
  return orderedMatcher(
    [
      fixedToken(`${command}${WS1}`),
      outputFileTokens,
      fixedToken("&&"),
      fixedToken(DOWNLOAD_TERMINAL),
    ],
    [GAP_DOT, GAP_DOT, GAP_DOT],
  );
}

function secretThenTransport(transport: "curl" | "wget"): CorrelatedPatternMatcher {
  return orderedMatcher(
    [secretExpressionTokens, fixedToken(transport)],
    [GAP_DOT],
  );
}

const allSecretExpressionTokens: TokenEventFactory = (content) =>
  secretExpressionTokens(content, true);

function transportThenSecret(transport: "curl" | "wget"): CorrelatedPatternMatcher {
  return orderedMatcher(
    [fixedToken(transport), allSecretExpressionTokens],
    [GAP_DOT],
  );
}

export const WORKFLOW_BROAD_GAP_MATCHERS = {
  CURL_PIPE_EXEC: commandPipe("curl"),
  WGET_PIPE_EXEC: commandPipe("wget"),
  CURL_DOWNLOAD_EXEC: downloadThenExecute("curl"),
  WGET_DOWNLOAD_EXEC: downloadThenExecute("wget"),
  SECRET_TO_CURL: secretThenTransport("curl"),
  CURL_TO_SECRET: transportThenSecret("curl"),
  SECRET_TO_WGET: secretThenTransport("wget"),
  WGET_TO_SECRET: transportThenSecret("wget"),
  BASE64_EXEC: orderedMatcher(
    [
      fixedToken(String.raw`base64${WS1}(?:-d|--decode)${WS0}`),
      fixedToken(String.raw`\|${WS0}(?:bash|sh|node|python)`),
    ],
    [GAP_DOT],
  ),
  ENV_EXFIL: orderedMatcher(
    [
      fixedToken(String.raw`curl\b`),
      fixedToken(String.raw`(?:-d|--data|--data-raw|-H|--header)`),
      fixedToken(SECRET_OR_ENV_PREFIX),
    ],
    [GAP_QUOTES, GAP_QUOTES],
  ),
  SELF_MODIFY: orderedMatcher(
    [
      fixedToken(String.raw`(?:echo|tee|cat|cp|mv|write)`),
      fixedToken(String.raw`\.github[\\/]workflows[\\/]`),
    ],
    [GAP_DOT],
  ),
} as const satisfies Readonly<Record<string, CorrelatedPatternMatcher>>;
