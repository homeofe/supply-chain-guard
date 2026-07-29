import type {
  CorrelatedPatternMatch,
  CorrelatedPatternMatcher,
} from "./types.js";

const MAX_EVIDENCE_CHARS = 240;

type LexMode = "javascript" | "python" | "mixed";

interface CallRange {
  name: string;
  start: number;
  open: number;
  argStart: number;
  argEnd: number;
  end: number;
}

interface AssignmentState {
  position: number;
  qualified: boolean;
}

const isIdentifierStart = (char: string | undefined): boolean =>
  char !== undefined && /[A-Za-z_$]/.test(char);

const isIdentifierPart = (char: string | undefined): boolean =>
  char !== undefined && /[A-Za-z0-9_$]/.test(char);

function mixedHashIsPrivateIdentifier(content: string, start: number): boolean {
  if (!isIdentifierStart(content[start + 1])) return false;
  let end = start + 2;
  while (isIdentifierPart(content[end])) end++;
  while (content[end] === " " || content[end] === "\t") end++;

  const next = content[end];
  if (next === "=" || next === ";" || next === "}" || next === undefined || next === "\n" || next === "\r") {
    return true;
  }
  if (next !== "(") return false;

  let depth = 1;
  for (let index = end + 1; index < content.length; index++) {
    const char = content[index]!;
    if (char === "\n" || char === "\r") return false;
    if (char === "(") depth++;
    else if (char === ")" && --depth === 0) {
      const body = skipWhitespace(content, index + 1);
      return content[body] === "{";
    }
  }
  return false;
}

const blankPreservingLines = (value: string): string =>
  value.replace(/[^\r\n]/g, " ");

/**
 * Produce a same-length lexical view. Comments are always blanked; strings can
 * also be blanked when callers need to recognise executable tokens only.
 * JavaScript template quasis are strings, but `${...}` interpolation bodies
 * remain code and are scanned recursively.
 */
function maskLexical(
  content: string,
  mode: LexMode,
  maskStrings: boolean,
): string {
  const parts: string[] = [];
  let copiedThrough = 0;

  const blank = (start: number, end: number): void => {
    if (start > copiedThrough) parts.push(content.slice(copiedThrough, start));
    parts.push(blankPreservingLines(content.slice(start, end)));
    copiedThrough = end;
  };

  const scanLineComment = (start: number): number => {
    let end = start;
    while (end < content.length && content[end] !== "\n" && content[end] !== "\r") end++;
    blank(start, end);
    return end;
  };

  const scanBlockComment = (start: number): number => {
    const closing = content.indexOf("*/", start + 2);
    const end = closing === -1 ? content.length : closing + 2;
    blank(start, end);
    return end;
  };

  const scanQuoted = (start: number, quote: string): number => {
    const triple =
      mode !== "javascript" &&
      content[start + 1] === quote &&
      content[start + 2] === quote;
    let end = start + (triple ? 3 : 1);
    while (end < content.length) {
      if (content[end] === "\\") {
        end = Math.min(content.length, end + 2);
        continue;
      }
      if (triple) {
        if (content[end] === quote && content[end + 1] === quote && content[end + 2] === quote) {
          end += 3;
          break;
        }
      } else {
        if (content[end] === quote) {
          end++;
          break;
        }
        if (content[end] === "\n" || content[end] === "\r") break;
      }
      end++;
    }
    if (maskStrings) blank(start, end);
    return end;
  };

  const scanTemplateExpression = (start: number): number => {
    let depth = 1;
    let index = start;
    while (index < content.length) {
      const char = content[index]!;
      const next = content[index + 1];
      if (char === "/" && next === "/") {
        index = scanLineComment(index);
        continue;
      }
      if (char === "/" && next === "*") {
        index = scanBlockComment(index);
        continue;
      }
      if (char === "'" || char === '"') {
        index = scanQuoted(index, char);
        continue;
      }
      if (char === "`") {
        index = scanTemplate(index);
        continue;
      }
      if (char === "{") depth++;
      else if (char === "}" && --depth === 0) return index + 1;
      index++;
    }
    return content.length;
  };

  const scanTemplate = (start: number): number => {
    let literalStart = start;
    let index = start + 1;
    while (index < content.length) {
      if (content[index] === "\\") {
        index = Math.min(content.length, index + 2);
        continue;
      }
      if (content[index] === "`") {
        if (maskStrings) blank(literalStart, index + 1);
        return index + 1;
      }
      if (content[index] === "$" && content[index + 1] === "{") {
        if (maskStrings) blank(literalStart, index + 1);
        index = scanTemplateExpression(index + 2);
        literalStart = index;
        continue;
      }
      index++;
    }
    if (maskStrings) blank(literalStart, content.length);
    return content.length;
  };

  let index = 0;
  let mixedBraceDepth = 0;
  let pendingMixedClass = false;
  const mixedClassDepths: number[] = [];
  while (index < content.length) {
    const char = content[index]!;
    const next = content[index + 1];

    if ((mode === "javascript" || mode === "mixed") && char === "/" && next === "/") {
      index = scanLineComment(index);
      continue;
    }
    if ((mode === "javascript" || mode === "mixed") && char === "/" && next === "*") {
      index = scanBlockComment(index);
      continue;
    }

    const mixedPrivateIdentifier =
      mode === "mixed" &&
      mixedClassDepths[mixedClassDepths.length - 1] === mixedBraceDepth &&
      mixedHashIsPrivateIdentifier(content, index);
    const hashIsComment =
      char === "#" &&
      (mode === "python" ||
        (mode === "mixed" &&
          !mixedPrivateIdentifier &&
          (index === 0 || /\s/.test(content[index - 1]!) || content[index - 1] === ";")));
    if (hashIsComment) {
      index = scanLineComment(index);
      continue;
    }

    if (char === "'" || char === '"') {
      index = scanQuoted(index, char);
      continue;
    }
    if ((mode === "javascript" || mode === "mixed") && char === "`") {
      index = scanTemplate(index);
      continue;
    }

    if (mode === "mixed") {
      if (isIdentifierStart(char)) {
        let end = index + 1;
        while (isIdentifierPart(content[end])) end++;
        if (
          content.slice(index, end) === "class" &&
          content[index - 1] !== "."
        ) {
          pendingMixedClass = true;
        }
        index = end;
        continue;
      }
      if (char === "{") {
        mixedBraceDepth++;
        if (pendingMixedClass) mixedClassDepths.push(mixedBraceDepth);
        pendingMixedClass = false;
      } else if (char === "}") {
        if (mixedClassDepths[mixedClassDepths.length - 1] === mixedBraceDepth) {
          mixedClassDepths.pop();
        }
        if (mixedBraceDepth > 0) mixedBraceDepth--;
      } else if (pendingMixedClass && (char === ":" || char === ";")) {
        // Python class headers end in `:`; property names such as `class:`
        // are not JavaScript class declarations either.
        pendingMixedClass = false;
      }
    }
    index++;
  }

  if (copiedThrough === 0) return content;
  if (copiedThrough < content.length) parts.push(content.slice(copiedThrough));
  return parts.join("");
}
function boundedEvidence(content: string, start: number, end: number): string {
  const raw = content.slice(start, end);
  if (raw.length <= MAX_EVIDENCE_CHARS) return raw;
  const marker = " ... ";
  const remaining = MAX_EVIDENCE_CHARS - marker.length;
  const left = Math.ceil(remaining / 2);
  return raw.slice(0, left) + marker + raw.slice(raw.length - (remaining - left));
}

function correlation(content: string, start: number, end: number): CorrelatedPatternMatch {
  return {
    start,
    end,
    evidence: boundedEvidence(content, start, end),
  };
}

function skipWhitespace(value: string, start: number, end = value.length): number {
  let index = start;
  while (index < end && /\s/.test(value[index]!)) index++;
  return index;
}

function lowerBound(values: readonly number[], target: number): number {
  let low = 0;
  let high = values.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (values[middle]! < target) low = middle + 1;
    else high = middle;
  }
  return low;
}

function latestBefore<T extends { position: number }>(
  values: readonly T[] | undefined,
  target: number,
): T | undefined {
  if (!values || values.length === 0) return undefined;
  let low = 0;
  let high = values.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (values[middle]!.position < target) low = middle + 1;
    else high = middle;
  }
  return low === 0 ? undefined : values[low - 1];
}

function readCall(mask: string, name: string, start: number, open: number): CallRange | undefined {
  let parentheses = 1;
  let brackets = 0;
  let braces = 0;
  let argEnd = -1;

  for (let index = open + 1; index < mask.length; index++) {
    switch (mask[index]) {
      case "(":
        parentheses++;
        break;
      case ")":
        parentheses--;
        if (parentheses === 0) {
          return {
            name,
            start,
            open,
            argStart: open + 1,
            argEnd: argEnd === -1 ? index : argEnd,
            end: index + 1,
          };
        }
        break;
      case "[":
        brackets++;
        break;
      case "]":
        if (brackets > 0) brackets--;
        break;
      case "{":
        braces++;
        break;
      case "}":
        if (braces > 0) braces--;
        break;
      case ",":
        if (parentheses === 1 && brackets === 0 && braces === 0 && argEnd === -1) {
          argEnd = index;
        }
        break;
    }
  }

  return undefined;
}

/**
 * Visit every completed watched call, including calls nested in another watched
 * call. Candidate discovery and delimiter matching advance monotonically over
 * the mask, so deeply nested or unclosed call prefixes remain O(n).
 *
 * Calls are emitted inner-first as their closing parenthesis is encountered.
 * That mirrors JavaScript/Python argument evaluation and lets stateful
 * consumers observe a nested write before a later sibling execution.
 */
function forEachCompletedCall(
  mask: string,
  names: readonly string[],
  visit: (call: CallRange) => void,
): void {
  if (names.length === 0) return;

  const orderedNames = names
    .slice()
    .sort((left, right) => right.length - left.length);
  const nameIndexes = new Map(orderedNames.map((name, index) => [name, index]));
  const alternatives = orderedNames
    .map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|");
  const candidate = new RegExp(`\\b(${alternatives})\\s*\\(`, "g");
  let next = candidate.exec(mask);
  let nextOpen = next
    ? next.index + next[0].lastIndexOf("(")
    : -1;

  // Flat numeric frames avoid an object per nested call on multi-megabyte
  // hostile inputs. Each watched frame stores the delimiter state needed to
  // identify its first argument and matching close.
  const PAREN_DEPTH = 0;
  const NAME_INDEX = 1;
  const CALL_START = 2;
  const CALL_OPEN = 3;
  const BRACKET_DEPTH = 4;
  const BRACE_DEPTH = 5;
  const ARG_END = 6;
  const FRAME_WIDTH = 7;
  const frames: number[] = [];

  let parentheses = 0;
  let brackets = 0;
  let braces = 0;

  for (let index = 0; index < mask.length; index++) {
    const char = mask[index]!;
    if (char === "(") {
      parentheses++;
      if (index === nextOpen && next) {
        frames.push(
          parentheses,
          nameIndexes.get(next[1]!)!,
          next.index,
          index,
          brackets,
          braces,
          -1,
        );
        next = candidate.exec(mask);
        nextOpen = next
          ? next.index + next[0].lastIndexOf("(")
          : -1;
      }
      continue;
    }

    if (char === ")") {
      const frame = frames.length - FRAME_WIDTH;
      if (frame >= 0 && frames[frame + PAREN_DEPTH] === parentheses) {
        const open = frames[frame + CALL_OPEN]!;
        const firstArgumentEnd = frames[frame + ARG_END]!;
        visit({
          name: orderedNames[frames[frame + NAME_INDEX]!]!,
          start: frames[frame + CALL_START]!,
          open,
          argStart: open + 1,
          argEnd: firstArgumentEnd === -1 ? index : firstArgumentEnd,
          end: index + 1,
        });
        frames.length = frame;
      }
      if (parentheses > 0) parentheses--;
      continue;
    }

    if (char === "[") {
      brackets++;
      continue;
    }
    if (char === "]") {
      if (brackets > 0) brackets--;
      continue;
    }
    if (char === "{") {
      braces++;
      continue;
    }
    if (char === "}") {
      if (braces > 0) braces--;
      continue;
    }
    if (char !== ",") continue;

    const frame = frames.length - FRAME_WIDTH;
    if (
      frame >= 0 &&
      frames[frame + PAREN_DEPTH] === parentheses &&
      frames[frame + BRACKET_DEPTH] === brackets &&
      frames[frame + BRACE_DEPTH] === braces &&
      frames[frame + ARG_END] === -1
    ) {
      frames[frame + ARG_END] = index;
    }
  }
}
function findMatchingBrace(mask: string, open: number): number | undefined {
  let depth = 1;
  for (let index = open + 1; index < mask.length; index++) {
    if (mask[index] === "{") depth++;
    else if (mask[index] === "}" && --depth === 0) return index;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// PyPI custom cmdclass matchers
// ---------------------------------------------------------------------------

interface QuotedValueRange {
  valueStart: number;
  valueEnd: number;
  after: number;
}

function readQuotedValue(value: string, start: number): QuotedValueRange | undefined {
  const quote = value[start];
  if (quote !== "'" && quote !== '"') return undefined;
  const triple = value[start + 1] === quote && value[start + 2] === quote;
  const valueStart = start + (triple ? 3 : 1);
  let end = valueStart;
  while (end < value.length) {
    if (value[end] === "\\") {
      end = Math.min(value.length, end + 2);
      continue;
    }
    if (triple) {
      if (value[end] === quote && value[end + 1] === quote && value[end + 2] === quote) {
        return { valueStart, valueEnd: end, after: end + 3 };
      }
    } else {
      if (value[end] === quote) {
        return { valueStart, valueEnd: end, after: end + 1 };
      }
      if (value[end] === "\n" || value[end] === "\r") {
        return { valueStart, valueEnd: end, after: end };
      }
    }
    end++;
  }
  return { valueStart, valueEnd: end, after: end };
}

function cmdclassMatcher(key: string): CorrelatedPatternMatcher {
  return (content) => {
    const codeMask = maskLexical(content, "python", true);
    const commentsMask = maskLexical(content, "python", false);
    const candidate = /\bcmdclass\s*=\s*\{/g;
    const results: CorrelatedPatternMatch[] = [];
    let next = candidate.exec(codeMask);
    let nextOpen = next
      ? next.index + next[0].lastIndexOf("{")
      : -1;

    const ROOT_DEPTH = 0;
    const MATCH_START = 1;
    const EMITTED = 2;
    const FRAME_WIDTH = 3;
    const frames: number[] = [];
    let braces = 0;

    for (let index = 0; index < codeMask.length;) {
      const quoted = readQuotedValue(commentsMask, index);
      if (quoted) {
        const frame = frames.length - FRAME_WIDTH;
        if (
          frame >= 0 &&
          frames[frame + ROOT_DEPTH] === braces &&
          frames[frame + EMITTED] === 0 &&
          quoted.valueEnd - quoted.valueStart === key.length &&
          content.startsWith(key, quoted.valueStart)
        ) {
          const colon = skipWhitespace(codeMask, quoted.after);
          if (codeMask[colon] === ":") {
            results.push(correlation(
              content,
              frames[frame + MATCH_START]!,
              colon + 1,
            ));
            frames[frame + EMITTED] = 1;
          }
        }
        index = Math.max(index + 1, quoted.after);
        continue;
      }

      const char = codeMask[index]!;
      if (char === "{") {
        braces++;
        if (index === nextOpen && next) {
          frames.push(braces, next.index, 0);
          next = candidate.exec(codeMask);
          nextOpen = next
            ? next.index + next[0].lastIndexOf("{")
            : -1;
        }
      } else if (char === "}") {
        const frame = frames.length - FRAME_WIDTH;
        if (frame >= 0 && frames[frame + ROOT_DEPTH] === braces) {
          frames.length = frame;
        }
        if (braces > 0) braces--;
      }
      index++;
    }

    return results;
  };
}
// ---------------------------------------------------------------------------
// PyPI base64 decode -> exec matcher
// ---------------------------------------------------------------------------

const PYTHON_ASSIGNMENT = /^\s*([A-Za-z_]\w*)\s*(?::[^=]*)?=(?!=)/;
const B64_DECODE_START = /^\s*base64\s*\.\s*b64decode\s*\(/;
const PYTHON_EXEC = /\bexec\s*\(\s*(?:base64\s*\.\s*b64decode\s*\(|([A-Za-z_]\w*))/g;

function isUnindentedPythonLine(content: string, position: number): boolean {
  let lineStart = position;
  while (lineStart > 0 && content[lineStart - 1] !== "\n" && content[lineStart - 1] !== "\r") {
    lineStart--;
  }
  const first = content[lineStart];
  return first !== " " && first !== "\t" && first !== "\f";
}

function matchPythonStatement(
  content: string,
  mask: string,
  start: number,
  end: number,
  decodedVariables: Map<string, { start: number; decodeEnd: number }>,
  results: CorrelatedPatternMatch[],
): void {
  const statement = mask.slice(start, end);
  const assignment = PYTHON_ASSIGNMENT.exec(statement);
  if (assignment) {
    const variable = assignment[1]!;
    const variableLocal = assignment[0].indexOf(variable);
    const rightHandSide = statement.slice(assignment[0].length);
    const decode = B64_DECODE_START.exec(rightHandSide);
    if (decode) {
      decodedVariables.set(variable, {
        start: start + variableLocal,
        decodeEnd: start + assignment[0].length + decode[0].length,
      });
    } else if (isUnindentedPythonLine(content, start)) {
      // An unindented reassignment is textually unconditional at module
      // scope. Indented suite assignments may never execute (if/try/loop/
      // nested function), so conservatively retain the viable decoded state.
      decodedVariables.delete(variable);
    }
  }

  PYTHON_EXEC.lastIndex = 0;
  let execution: RegExpExecArray | null;
  while ((execution = PYTHON_EXEC.exec(statement)) !== null) {
    const previous = execution.index === 0 ? "" : statement[execution.index - 1]!;
    if (previous === "." || isIdentifierPart(previous)) continue;

    const variable = execution[1];
    if (variable === undefined) {
      results.push(correlation(
        content,
        start + execution.index,
        start + execution.index + execution[0].length,
      ));
      continue;
    }

    const decoded = decodedVariables.get(variable);
    if (decoded) {
      results.push(correlation(
        content,
        decoded.start,
        start + execution.index + execution[0].length,
      ));
    }
  }
}

const pythonBase64ExecMatcher: CorrelatedPatternMatcher = (content) => {
  const mask = maskLexical(content, "python", true);
  const decodedVariables = new Map<string, { start: number; decodeEnd: number }>();
  const results: CorrelatedPatternMatch[] = [];
  let start = 0;
  let parentheses = 0;
  let brackets = 0;
  let braces = 0;

  for (let index = 0; index <= mask.length; index++) {
    const char = mask[index];
    if (char === "(") parentheses++;
    else if (char === ")" && parentheses > 0) parentheses--;
    else if (char === "[") brackets++;
    else if (char === "]" && brackets > 0) brackets--;
    else if (char === "{") braces++;
    else if (char === "}" && braces > 0) braces--;

    const boundary =
      index === mask.length ||
      ((char === ";" || char === "\n" || char === "\r") &&
        parentheses === 0 && brackets === 0 && braces === 0);
    if (!boundary) continue;
    if (index > start) matchPythonStatement(content, mask, start, index, decodedVariables, results);
    start = index + 1;
  }

  return results;
};

// ---------------------------------------------------------------------------
// JavaScript Proxy handler trap matcher
// ---------------------------------------------------------------------------

const HOSTILE_TRAP_OPERATION = /\b(?:eval)\s*\(|\bnew\s+Function\b|\bfetch\s*\(|\baxios(?:\.\w+)?\s*\(|\bXMLHttpRequest\s*\(|\bchild_process\s*\.\s*(?:exec(?:File)?(?:Sync)?|spawn(?:Sync)?)\s*\(|\bexecSync\s*\(|\batob\s*\(|\bprocess\s*\.\s*env\s*\[/g;
const TRAP_NAMES = new Set(["get", "set", "apply", "construct"]);

interface ProxyTrapKey {
  name: string;
  start: number;
  end: number;
}

/**
 * Read an exact quoted Proxy trap name without unmasking the property's value.
 * Trap names are at most nine characters, so malformed or unrelated strings
 * are rejected after bounded work.
 */
function quotedProxyTrapKey(
  lexicalMask: string,
  start: number,
  limit: number,
): ProxyTrapKey | undefined {
  const quote = lexicalMask[start];
  if (quote !== "'" && quote !== '"') return undefined;

  let name = "";
  const maxNameLength = "construct".length;
  for (let index = start + 1; index < limit; index++) {
    const char = lexicalMask[index]!;
    if (char === quote) {
      return TRAP_NAMES.has(name)
        ? { name, start, end: index + 1 }
        : undefined;
    }
    if (
      char === "\\" ||
      char === "\n" ||
      char === "\r" ||
      name.length >= maxNameLength
    ) {
      return undefined;
    }
    name += char;
  }
  return undefined;
}

function proxyTrapKeyAt(
  codeMask: string,
  lexicalMask: string,
  start: number,
  limit: number,
): ProxyTrapKey | undefined {
  const char = codeMask[start];
  if (isIdentifierStart(char)) {
    let end = start + 1;
    while (isIdentifierPart(codeMask[end])) end++;
    const name = codeMask.slice(start, end);
    return TRAP_NAMES.has(name) ? { name, start, end } : undefined;
  }

  const quoted = quotedProxyTrapKey(lexicalMask, start, limit);
  if (quoted) return quoted;

  if (char !== "[") return undefined;
  const quotedStart = skipWhitespace(lexicalMask, start + 1, limit);
  const computed = quotedProxyTrapKey(lexicalMask, quotedStart, limit);
  if (!computed) return undefined;
  const close = skipWhitespace(lexicalMask, computed.end, limit);
  return lexicalMask[close] === "]"
    ? { name: computed.name, start, end: close + 1 }
    : undefined;
}
interface ProxyHandlerBounds {
  open: number;
  close: number;
}

function newProxyStart(mask: string, proxyStart: number): number | undefined {
  let index = proxyStart - 1;
  if (index < 0 || !/\s/.test(mask[index]!)) return undefined;
  while (index >= 0 && /\s/.test(mask[index]!)) index--;

  const wordEnd = index + 1;
  while (index >= 0 && /[A-Za-z0-9_]/.test(mask[index]!)) index--;
  const wordStart = index + 1;
  return mask.slice(wordStart, wordEnd) === "new"
    ? wordStart
    : undefined;
}

function proxyHandlerBounds(mask: string, call: CallRange): ProxyHandlerBounds | undefined {
  if (call.argEnd === call.end - 1) return undefined;

  const handlerOpen = skipWhitespace(mask, call.argEnd + 1, call.end - 1);
  if (mask[handlerOpen] !== "{") return undefined;
  const close = findMatchingBrace(mask, handlerOpen);
  if (close === undefined || close >= call.end) return undefined;
  return { open: handlerOpen, close };
}
function objectValueEnd(mask: string, start: number, objectClose: number): number {
  let parentheses = 0;
  let brackets = 0;
  let braces = 0;
  for (let index = start; index < objectClose; index++) {
    const char = mask[index]!;
    if (char === "(") parentheses++;
    else if (char === ")" && parentheses > 0) parentheses--;
    else if (char === "[") brackets++;
    else if (char === "]" && brackets > 0) brackets--;
    else if (char === "{") braces++;
    else if (char === "}" && braces > 0) braces--;
    else if (char === "," && parentheses === 0 && brackets === 0 && braces === 0) return index;
  }
  return objectClose;
}

function hostileTrapOffset(
  codeMask: string,
  lexicalMask: string,
  handlerOpen: number,
  handlerClose: number,
): { start: number; end: number } | undefined {
  let depth = 1;
  for (let index = handlerOpen + 1; index < handlerClose;) {
    const char = codeMask[index]!;
    if (char === "{") {
      depth++;
      index++;
      continue;
    }
    if (char === "}") {
      depth--;
      index++;
      continue;
    }
    if (depth !== 1) {
      index++;
      continue;
    }

    const key = proxyTrapKeyAt(codeMask, lexicalMask, index, handlerClose);
    if (!key) {
      if (isIdentifierStart(char)) {
        do index++; while (isIdentifierPart(codeMask[index]));
      } else {
        index++;
      }
      continue;
    }

    const separator = skipWhitespace(codeMask, key.end, handlerClose);
    let valueStart: number | undefined;
    let valueEnd: number | undefined;
    if (codeMask[separator] === ":") {
      valueStart = separator + 1;
      valueEnd = objectValueEnd(codeMask, valueStart, handlerClose);
    } else if (codeMask[separator] === "(") {
      const signature = readCall(codeMask, key.name, key.start, separator);
      if (signature) {
        const bodyOpen = skipWhitespace(codeMask, signature.end, handlerClose);
        if (codeMask[bodyOpen] === "{") {
          const bodyClose = findMatchingBrace(codeMask, bodyOpen);
          if (bodyClose !== undefined && bodyClose <= handlerClose) {
            valueStart = bodyOpen + 1;
            valueEnd = bodyClose;
          }
        }
      }
    }

    if (valueStart !== undefined && valueEnd !== undefined) {
      HOSTILE_TRAP_OPERATION.lastIndex = valueStart;
      const hostile = HOSTILE_TRAP_OPERATION.exec(codeMask);
      if (hostile && hostile.index < valueEnd) {
        return { start: hostile.index, end: hostile.index + hostile[0].length };
      }
      index = Math.max(key.end, valueEnd + 1);
    } else {
      index = key.end;
    }
  }
  return undefined;
}

const proxyHandlerMatcher: CorrelatedPatternMatcher = (content) => {
  const codeMask = maskLexical(content, "javascript", true);
  const lexicalMask = maskLexical(content, "javascript", false);
  const results: CorrelatedPatternMatch[] = [];

  forEachCompletedCall(codeMask, ["Proxy"], (call) => {
    const proxyStart = newProxyStart(codeMask, call.start);
    if (proxyStart === undefined) return;
    const handler = proxyHandlerBounds(codeMask, call);
    if (!handler) return;

    const hostile = hostileTrapOffset(
      codeMask,
      lexicalMask,
      handler.open,
      handler.close,
    );
    if (hostile) results.push(correlation(content, proxyStart, hostile.end));
  });

  return results.sort((left, right) => left.start - right.start || left.end - right.end);
};// ---------------------------------------------------------------------------
// GeoIP -> sensitive destructive operation matcher
// ---------------------------------------------------------------------------

const GEO_SIGNAL = /\b(?:ip-api|ipinfo|geoip(?:-lite|2)?|maxmind|GeoIP2?)\b/gi;
const DESTRUCTIVE_CALLS = [
  "unlink", "unlinkSync", "rmdir", "rmdirSync", "rm", "rmSync",
];
const EXECUTION_CALLS = [
  "exec", "execSync", "execFile", "execFileSync", "system", "spawn", "spawnSync",
];
const SAFE_CLEANUP_TARGET = /(?:\b(?:temp|tmp|archive|cache|download)\b|\.mmdb\b|[\\/]var[\\/]tmp(?:[\\/]|$)|[\\/]tmp(?:[\\/]|$))/i;
const SENSITIVE_TARGET = /(?:["'`]\s*(?:\/(?!\/?(?:tmp|var\/tmp)(?:[\/"'`]|$))|[A-Za-z]:[\\/])|\bprocess\s*\.\s*cwd\s*\(|\b__dirname\b|\bhomedir\s*\(|\b(?:HOME|USERPROFILE)\b|\$HOME|%USERPROFILE%)/i;
const SENSITIVE_SHELL = /(?:\brm\s+-rf\s+(?:["'`]?(?:\/(?!tmp(?:[\/\s"'`]|$))|~|\$HOME|[A-Za-z]:[\\/]))|\bdel\s+\/[a-z]*\s+(?:[A-Za-z]:[\\/]|%USERPROFILE%)|\bformat\s+c:)/i;

function isSensitiveCallTarget(content: string, call: CallRange): boolean {
  const target = content.slice(call.argStart, call.argEnd);
  return !SAFE_CLEANUP_TARGET.test(target) && SENSITIVE_TARGET.test(target);
}

function isSensitiveShell(text: string): boolean {
  return !SAFE_CLEANUP_TARGET.test(text) && SENSITIVE_SHELL.test(text);
}

const protestwareGeoMatcher: CorrelatedPatternMatcher = (content) => {
  const codeMask = maskLexical(content, "mixed", true);
  const commentsMask = maskLexical(content, "mixed", false);
  const geoPositions: number[] = [];
  const results: CorrelatedPatternMatch[] = [];
  const emitted = new Set<string>();
  let geo: RegExpExecArray | null;
  GEO_SIGNAL.lastIndex = 0;
  while ((geo = GEO_SIGNAL.exec(commentsMask)) !== null) geoPositions.push(geo.index);
  if (geoPositions.length === 0) return results;

  const addDestruction = (position: number, end: number): void => {
    const insertion = lowerBound(geoPositions, position);
    if (insertion === 0) return;
    const geoPosition = geoPositions[insertion - 1]!;
    const key = `${geoPosition}:${position}`;
    if (emitted.has(key)) return;
    emitted.add(key);
    results.push(correlation(content, geoPosition, end));
  };

  forEachCompletedCall(codeMask, DESTRUCTIVE_CALLS, (call) => {
    if (isSensitiveCallTarget(content, call)) addDestruction(call.start, call.end);
  });

  forEachCompletedCall(codeMask, EXECUTION_CALLS, (call) => {
    const command = content.slice(call.argStart, call.argEnd);
    if (isSensitiveShell(command)) addDestruction(call.start, call.end);
  });

  SENSITIVE_SHELL.lastIndex = 0;
  const shellPattern = new RegExp(SENSITIVE_SHELL.source, "gi");
  let shell: RegExpExecArray | null;
  while ((shell = shellPattern.exec(codeMask)) !== null) {
    addDestruction(shell.index, shell.index + shell[0].length);
  }

  return results.sort((left, right) => left.start - right.start || left.end - right.end);
};

// ---------------------------------------------------------------------------
// Dropper write -> execute matcher
// ---------------------------------------------------------------------------

const WRITE_CALLS = ["writeFile", "writeFileSync", "write_bytes", "saveFile"];
const REAL_EXECUTION_CALLS = [
  "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync",
  "ShellExecute", "CreateProcess", "system",
];
const PATH_ASSIGNMENT = /\b(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*))\s*=(?!=|>)/g;
const TEMP_OR_EXECUTABLE = /\b(?:TEMP|TMP|AppData)\b|tmp(?:dir)?\s*\(|\btempfile\b|[\\/](?:tmp|temp)[\\/]|\.(?:exe|bat|cmd|ps1)(?![A-Za-z0-9_])/gi;
const EXECUTABLE_BASENAME = /(?:^|[\\/"'`\s+])([^\\/"'`\s+]+\.(?:exe|bat|cmd|ps1))(?![A-Za-z0-9_])/gi;

function collectAssignments(
  codeMask: string,
  semanticMask: string,
): Map<string, AssignmentState[]> {
  const signalPositions: number[] = [];
  TEMP_OR_EXECUTABLE.lastIndex = 0;
  let signal: RegExpExecArray | null;
  while ((signal = TEMP_OR_EXECUTABLE.exec(semanticMask)) !== null) signalPositions.push(signal.index);

  const assignments = new Map<string, AssignmentState[]>();
  PATH_ASSIGNMENT.lastIndex = 0;
  let assignment: RegExpExecArray | null;
  let cachedBoundary = -1;
  while ((assignment = PATH_ASSIGNMENT.exec(codeMask)) !== null) {
    const variable = assignment[1] ?? assignment[2]!;
    const equals = assignment.index + assignment[0].lastIndexOf("=");
    if (equals >= cachedBoundary) {
      const semicolon = codeMask.indexOf(";", equals + 1);
      const newline = codeMask.indexOf("\n", equals + 1);
      const carriage = codeMask.indexOf("\r", equals + 1);
      const candidates = [semicolon, newline, carriage].filter((value) => value !== -1);
      cachedBoundary = candidates.length === 0 ? codeMask.length : Math.min(...candidates);
    }
    const signalIndex = lowerBound(signalPositions, equals + 1);
    const qualified = signalIndex < signalPositions.length && signalPositions[signalIndex]! < cachedBoundary;
    const states = assignments.get(variable) ?? [];
    states.push({ position: assignment.index, qualified });
    assignments.set(variable, states);
  }
  return assignments;
}

function pathIdentities(
  content: string,
  codeMask: string,
  call: CallRange,
  assignments: ReadonlyMap<string, AssignmentState[]>,
): Set<string> {
  const identities = new Set<string>();
  const codeArgument = codeMask.slice(call.argStart, call.argEnd);
  const identifier = /[A-Za-z_$][\w$]*/g;
  let token: RegExpExecArray | null;
  while ((token = identifier.exec(codeArgument)) !== null) {
    const state = latestBefore(assignments.get(token[0]), call.start);
    if (state?.qualified) identities.add(`var:${token[0]}@${state.position}`);
  }

  const rawArgument = content.slice(call.argStart, call.argEnd);
  EXECUTABLE_BASENAME.lastIndex = 0;
  let executable: RegExpExecArray | null;
  while ((executable = EXECUTABLE_BASENAME.exec(rawArgument)) !== null) {
    identities.add(`file:${executable[1]!.toLowerCase()}`);
  }
  return identities;
}

const dropperTempExecMatcher: CorrelatedPatternMatcher = (content) => {
  const codeMask = maskLexical(content, "mixed", true);
  const semanticMask = maskLexical(content, "mixed", false);
  const assignments = collectAssignments(codeMask, semanticMask);
  const writes = new Map<string, CallRange>();
  const results: CorrelatedPatternMatch[] = [];
  const emitted = new Set<string>();

  const callNames = [...WRITE_CALLS, ...REAL_EXECUTION_CALLS];
  const writeNames = new Set(WRITE_CALLS);
  forEachCompletedCall(codeMask, callNames, (call) => {
    const identities = pathIdentities(content, codeMask, call, assignments);
    if (writeNames.has(call.name)) {
      for (const identity of identities) writes.set(identity, call);
      return;
    }

    for (const identity of identities) {
      const write = writes.get(identity);
      if (!write || write.end > call.start) continue;
      const key = `${write.start}:${call.start}`;
      if (emitted.has(key)) continue;
      emitted.add(key);
      results.push(correlation(content, write.start, call.end));
    }
  });

  return results;
};

type CorrelatedRule =
  | "PYPI_B64_EXEC_COMBINED"
  | "PYPI_CUSTOM_INSTALL"
  | "PYPI_CUSTOM_DEVELOP"
  | "PYPI_CUSTOM_EGG_INFO"
  | "PYPI_CUSTOM_SDIST"
  | "PYPI_CUSTOM_BUILD_EXT"
  | "PROTESTWARE_IP_GEO_V2"
  | "PROXY_HANDLER_TRAP"
  | "DROPPER_TEMP_EXEC";

export const CORRELATED_PATTERN_MATCHERS = {
  PYPI_B64_EXEC_COMBINED: pythonBase64ExecMatcher,
  PYPI_CUSTOM_INSTALL: cmdclassMatcher("install"),
  PYPI_CUSTOM_DEVELOP: cmdclassMatcher("develop"),
  PYPI_CUSTOM_EGG_INFO: cmdclassMatcher("egg_info"),
  PYPI_CUSTOM_SDIST: cmdclassMatcher("sdist"),
  PYPI_CUSTOM_BUILD_EXT: cmdclassMatcher("build_ext"),
  PROTESTWARE_IP_GEO_V2: protestwareGeoMatcher,
  PROXY_HANDLER_TRAP: proxyHandlerMatcher,
  DROPPER_TEMP_EXEC: dropperTempExecMatcher,
} as const satisfies Record<CorrelatedRule, CorrelatedPatternMatcher>;