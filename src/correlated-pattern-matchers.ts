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
  lastArgStart: number;
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

function mixedSlashBelongsToUrl(content: string, slash: number): boolean {
  if (content[slash - 1] !== ":") return false;
  let schemeStart = slash - 2;
  const minimum = Math.max(0, slash - 34);
  while (schemeStart >= minimum && /[A-Za-z0-9+.-]/.test(content[schemeStart]!)) schemeStart--;
  return /^[A-Za-z][A-Za-z0-9+.-]*$/.test(content.slice(schemeStart + 1, slash - 1));
}
const blankPreservingLines = (value: string): string =>
  value.replace(/[^\r\n]/g, " ");
const REGEX_PREFIX_KEYWORDS = new Set([
  "await",
  "case",
  "delete",
  "do",
  "else",
  "in",
  "instanceof",
  "new",
  "of",
  "return",
  "throw",
  "typeof",
  "void",
  "yield",
]);
const REGEX_CONTROL_HEADER_KEYWORDS = new Set(["if", "for", "while", "with"]);

/**
 * A slash begins a JavaScript regex only where an expression may begin. This
 * deliberately treats identifiers, values, and closing delimiters as division
 * contexts while admitting operators, opening delimiters, prefix keywords, and
 * the statement position immediately after a completed control-flow header.
 */
function mayStartRegexLiteral(
  content: string,
  start: number,
  controlHeaderClosings: ReadonlySet<number>,
): boolean {
  let index = start - 1;
  while (index >= 0 && /\s/.test(content[index]!)) index--;
  if (index < 0) return true;

  const previous = content[index]!;
  if (
    previous === "~" &&
    (index === 0 || content[index - 1] === "@" || /\s/.test(content[index - 1]!))
  ) {
    return false;
  }
  if (previous === ")" && controlHeaderClosings.has(index)) return true;
  if (")]}".includes(previous) || previous === "." || previous === "'" || previous === '"' || previous === "`") {
    return false;
  }
  if (isIdentifierPart(previous)) {
    const end = index + 1;
    while (index >= 0 && isIdentifierPart(content[index])) index--;
    return REGEX_PREFIX_KEYWORDS.has(content.slice(index + 1, end));
  }
  if (/\d/.test(previous)) return false;
  return "([{:;,=!?&|+-*%^~<>".includes(previous);
}
/**
 * Produce a same-length lexical view. Comments are always blanked; strings can
 * also be blanked when callers need to recognise executable tokens only.
 * JavaScript template quasis are strings, but `${...}` interpolation bodies
 * remain code and are scanned recursively.
 */
interface LexicalMaskOptions {
  mixedHashCommentsAnywhere?: boolean;
}

function maskLexical(
  content: string,
  mode: LexMode,
  maskStrings: boolean,
  options: LexicalMaskOptions = {},
): string {
  const hasLexicalDelimiter =
    mode === "python"
      ? /['"#]/.test(content)
      : mode === "javascript"
        ? /['"`/]/.test(content)
        : /['"`/#]/.test(content);
  if (!hasLexicalDelimiter) return content;

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
  const scanRegexLiteral = (start: number): number | undefined => {
    let index = start + 1;
    let inCharacterClass = false;
    while (index < content.length) {
      const char = content[index]!;
      if (char === "\n" || char === "\r") return undefined;
      if (char === "\\") {
        index = Math.min(content.length, index + 2);
        continue;
      }
      if (char === "[") {
        inCharacterClass = true;
      } else if (char === "]" && inCharacterClass) {
        inCharacterClass = false;
      } else if (char === "/" && !inCharacterClass) {
        index++;
        while (index < content.length && /[A-Za-z]/.test(content[index]!)) index++;
        blank(start, index);
        return index;
      }
      index++;
    }
    return undefined;
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

  const controlParentheses: boolean[] = [];
  const controlHeaderClosings = new Set<number>();
  let previousCodeIdentifier: string | undefined;
  const noteIdentifier = (start: number, end: number): void => {
    let previous = start - 1;
    while (previous >= 0 && /\s/.test(content[previous]!)) previous--;
    previousCodeIdentifier = content[previous] === "."
      ? undefined
      : content.slice(start, end);
  };
  const notePunctuation = (char: string, position: number): void => {
    if (char === "(") {
      controlParentheses.push(
        previousCodeIdentifier !== undefined &&
        REGEX_CONTROL_HEADER_KEYWORDS.has(previousCodeIdentifier),
      );
    } else if (char === ")") {
      if (controlParentheses.pop() === true) controlHeaderClosings.add(position);
    }
    if (!/\s/.test(char)) previousCodeIdentifier = undefined;
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
      if (char === "/" && mayStartRegexLiteral(content, index, controlHeaderClosings)) {
        const regexEnd = scanRegexLiteral(index);
        if (regexEnd !== undefined) {
          index = regexEnd;
          continue;
        }
      }
      if (char === "'" || char === '"') {
        index = scanQuoted(index, char);
        continue;
      }
      if (char === "`") {
        previousCodeIdentifier = undefined;
        index = scanTemplate(index);
        continue;
      }
      if (isIdentifierStart(char)) {
        let end = index + 1;
        while (isIdentifierPart(content[end])) end++;
        noteIdentifier(index, end);
        index = end;
        continue;
      }
      if (char === "{") depth++;
      else if (char === "}" && --depth === 0) {
        previousCodeIdentifier = undefined;
        return index + 1;
      }
      notePunctuation(char, index);
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
  const mixedParameterExpansionDepths: number[] = [];
  while (index < content.length) {
    const char = content[index]!;
    const next = content[index + 1];

    if (
      (mode === "javascript" || mode === "mixed") &&
      char === "/" &&
      next === "/" &&
      !(mode === "mixed" && mixedSlashBelongsToUrl(content, index))
    ) {
      index = scanLineComment(index);
      continue;
    }
    if ((mode === "javascript" || mode === "mixed") && char === "/" && next === "*") {
      index = scanBlockComment(index);
      continue;
    }
    if (
      (mode === "javascript" || mode === "mixed") &&
      char === "/" &&
      !(mode === "mixed" && mixedSlashBelongsToUrl(content, index)) &&
      mayStartRegexLiteral(content, index, controlHeaderClosings)
    ) {
      const regexEnd = scanRegexLiteral(index);
      if (regexEnd !== undefined) {
        index = regexEnd;
        continue;
      }
    }

    const activeMixedClassDepth = mixedClassDepths[mixedClassDepths.length - 1];
    const mixedParameterExpansion =
      mode === "mixed" && mixedParameterExpansionDepths.length > 0;
    const mixedPrivateIdentifier =
      mode === "mixed" &&
      char === "#" &&
      activeMixedClassDepth !== undefined &&
      ((content[index - 1] === "." && isIdentifierStart(content[index + 1])) ||
        (activeMixedClassDepth === mixedBraceDepth &&
          mixedHashIsPrivateIdentifier(content, index)));
    const hashIsComment =
      char === "#" &&
      (mode === "python" ||
        (mode === "mixed" &&
          !mixedPrivateIdentifier &&
          !mixedParameterExpansion &&
          (options.mixedHashCommentsAnywhere === true ||
            index === 0 ||
            /\s/.test(content[index - 1]!) ||
            content[index - 1] === ";")));
    if (hashIsComment) {
      index = scanLineComment(index);
      continue;
    }

    if (char === "'" || char === '"') {
      previousCodeIdentifier = undefined;
      index = scanQuoted(index, char);
      continue;
    }
    if ((mode === "javascript" || mode === "mixed") && char === "`") {
      previousCodeIdentifier = undefined;
      index = scanTemplate(index);
      continue;
    }

    if (isIdentifierStart(char)) {
      let end = index + 1;
      while (isIdentifierPart(content[end])) end++;
      if (
        mode === "mixed" &&
        content.slice(index, end) === "class" &&
        content[index - 1] !== "."
      ) {
        pendingMixedClass = true;
      }
      noteIdentifier(index, end);
      index = end;
      continue;
    }
    if (mode === "mixed") {
      if (char === "{") {
        mixedBraceDepth++;
        if (content[index - 1] === "$") mixedParameterExpansionDepths.push(mixedBraceDepth);
        if (pendingMixedClass) mixedClassDepths.push(mixedBraceDepth);
        pendingMixedClass = false;
      } else if (char === "}") {
        if (mixedParameterExpansionDepths.at(-1) === mixedBraceDepth) {
          mixedParameterExpansionDepths.pop();
        }
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
    notePunctuation(char, index);
    index++;
  }
  if (copiedThrough === 0) return content;
  if (copiedThrough < content.length) parts.push(content.slice(copiedThrough));
  return parts.join("");
}

/** Same-length mixed-language view with comments and regex literals blanked. */
export function maskMixedCommentsPreservingStrings(content: string): string {
  return maskLexical(content, "mixed", false, { mixedHashCommentsAnywhere: true });
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
  let lastArgStart = open + 1;

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
            lastArgStart,
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
        if (parentheses === 1 && brackets === 0 && braces === 0) {
          if (argEnd === -1) argEnd = index;
          lastArgStart = index + 1;
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
  const LAST_ARG_START = 7;
  const FRAME_WIDTH = 8;
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
          index + 1,
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
          lastArgStart: frames[frame + LAST_ARG_START]!,
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
      frames[frame + BRACE_DEPTH] === braces
    ) {
      if (frames[frame + ARG_END] === -1) frames[frame + ARG_END] = index;
      frames[frame + LAST_ARG_START] = index + 1;
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

const HOSTILE_TRAP_OPERATION = /\b(?:eval)\s*\(|\bnew\s+Function\b|\bfetch\s*\(|\baxios(?:\.\w+)?\s*\(|\bXMLHttpRequest\s*\(|\bchild_process\s*\.\s*(?:exec(?:File)?(?:Sync)?|spawn(?:Sync)?)\s*\(|\bexecSync\s*\(|\batob\s*\(/g;
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

// ---------------------------------------------------------------------------
// npm credential source -> network sink matcher
// ---------------------------------------------------------------------------

interface CredentialSourceRange {
  start: number;
  end: number;
}

interface FunctionScope {
  declarationStart: number;
  start: number;
  end: number;
  kind: "function" | "catch" | "block";
  parameters: ReadonlySet<string>;
  bindings: Set<string>;
  parent?: FunctionScope;
}

interface CredentialAssignmentState extends AssignmentState {
  variable: string;
  sourceStart?: number;
  alias?: string;
  scope?: FunctionScope;
}

interface CredentialUse {
  position: number;
  sourceStart: number;
}

interface ShellFunctionScope {
  start: number;
  end: number;
  parent?: ShellFunctionScope;
}

interface ShellCredentialState {
  position: number;
  qualified: boolean;
  sourceStart?: number;
  scope?: ShellFunctionScope;
}

interface ShellCredentialHistory {
  global: ShellCredentialState[];
  scoped: Map<ShellFunctionScope, ShellCredentialState[]>;
}

const CREDENTIAL_READ_CALLS = [
  "readFile",
  "readFileSync",
  "createReadStream",
  "open",
  "read_text",
];
const NETWORK_SINK_CALLS = [
  "fetch",
  "nodeFetch",
  "axios",
  "request",
  "get",
  "post",
  "put",
  "patch",
  "send",
  "urlopen",
];
const NPM_CREDENTIAL_PATH = /(?:\.npmrc(?![A-Za-z0-9_.\\/\-])|\bnpm_config_userconfig\b)/i;
const NPM_CREDENTIAL_SOURCE_SIGNAL =
  /(?:\.npmrc\b|\bnpm_config_userconfig\b|\bNPM_TOKEN\b)/i;
const NPM_TOKEN_ACCESS =
  /\b(?:(?:process|Bun)\s*\.\s*env\s*(?:\.\s*NPM_TOKEN\b|\[\s*["'`]\s*NPM_TOKEN\s*["'`]\s*\])|Deno\s*\.\s*env\s*\.\s*get\s*\(\s*["'`]\s*NPM_TOKEN\s*["'`]\s*\)|os\s*\.\s*(?:environ\s*\[\s*["'`]\s*NPM_TOKEN\s*["'`]\s*\]|getenv\s*\(\s*["'`]\s*NPM_TOKEN\s*["'`]\s*\)))/g;
/**
 * Shared coarse gate for the SHAI-HULUD credential-flow rule.
 *
 * This deliberately admits every source/sink spelling handled by the
 * authoritative structural matcher. It is used both as PatternEntry metadata
 * and inside that matcher so the two entry points cannot drift apart.
 */
export function hasShaiHuludCredentialFlowSignals(content: string): boolean {
  return (
    NPM_CREDENTIAL_SOURCE_SIGNAL.test(content) &&
    /\b(?:fetch|nodeFetch|axios|request|get|post|put|patch|send|urlopen|curl|wget)\b/.test(
      content,
    )
  );
}

function normalizeCredentialSources(
  sources: CredentialSourceRange[],
): CredentialSourceRange[] {
  sources.sort((left, right) => left.start - right.start || right.end - left.end);
  const normalized: CredentialSourceRange[] = [];
  for (const source of sources) {
    const previous = normalized.at(-1);
    if (previous && source.start >= previous.start && source.end <= previous.end) {
      continue;
    }
    normalized.push(source);
  }
  return normalized;
}

function receiverExpression(mask: string, callStart: number): string | undefined {
  let end = callStart;
  let index = callStart - 1;
  while (index >= 0 && /\s/.test(mask[index]!)) index--;
  if (mask[index] !== ".") return undefined;
  index--;
  while (index >= 0 && /[A-Za-z0-9_$?.\s]/.test(mask[index]!)) index--;
  const receiver = mask.slice(index + 1, end - 1).replace(/[\s?]/g, "");
  return receiver || undefined;
}

function pathlibNpmrcReceiverStart(
  semanticMask: string,
  callStart: number,
): number | undefined {
  const prefixStart = Math.max(0, callStart - 512);
  const prefix = semanticMask.slice(prefixStart, callStart);
  const receivers = [
    /(?:\bpathlib\s*\.\s*)?\bPath\s*\(\s*(["'`])[^"'`\r\n]*\.npmrc\1\s*\)\s*\.\s*$/i,
    /(?:\bpathlib\s*\.\s*)?\bPath\s*\.\s*home\s*\(\s*\)\s*\.\s*joinpath\s*\(\s*(["'`])\.npmrc\1\s*\)\s*\.\s*$/i,
    /\(\s*(?:\bpathlib\s*\.\s*)?\bPath\s*\.\s*home\s*\(\s*\)\s*\/\s*(["'`])\.npmrc\1\s*\)\s*\.\s*$/i,
  ];
  for (const receiver of receivers) {
    const match = receiver.exec(prefix);
    if (!match) continue;
    const pathOffset = match[0].search(/(?:pathlib\s*\.\s*)?Path\b/i);
    const pathStart = match.index + pathOffset;
    let previous = pathStart - 1;
    while (previous >= 0 && /\s/.test(prefix[previous]!)) previous--;
    if (
      previous >= 0 &&
      (prefix[previous] === "." || prefix[previous] === "?" || isIdentifierPart(prefix[previous]))
    ) {
      continue;
    }
    return prefixStart + match.index;
  }
  return undefined;
}
/**
 * Identify executable npm credential sources. A literal `.npmrc` in a deny
 * list or declaration comment is not a source: it must be the path consumed by
 * a read API. NPM_TOKEN must likewise be read through a runtime environment API.
 */
function collectNpmCredentialSources(
  codeMask: string,
  semanticMask: string,
): CredentialSourceRange[] {
  const sources: CredentialSourceRange[] = [];

  NPM_TOKEN_ACCESS.lastIndex = 0;
  let token: RegExpExecArray | null;
  while ((token = NPM_TOKEN_ACCESS.exec(semanticMask)) !== null) {
    if (!isIdentifierStart(codeMask[token.index])) continue;
    sources.push({ start: token.index, end: token.index + token[0].length });
  }

  forEachCompletedCall(codeMask, CREDENTIAL_READ_CALLS, (call) => {
    let pathStart = call.argStart;
    let pathEnd = call.argEnd;
    if (call.name === "read_text") {
      const receiverStart = pathlibNpmrcReceiverStart(semanticMask, call.start);
      if (receiverStart === undefined) return;
      pathStart = receiverStart;
      pathEnd = call.end;
    } else {
      const firstArgument = semanticMask.slice(call.argStart, call.argEnd);
      if (!NPM_CREDENTIAL_PATH.test(firstArgument)) return;
    }
    sources.push({ start: pathStart, end: pathEnd });
  });

  return normalizeCredentialSources(sources);
}

function assignmentRhsEnds(mask: string, starts: readonly number[]): number[] {
  const ends = new Array<number>(starts.length).fill(mask.length);
  if (starts.length === 0) return ends;

  const pending = new Map<string, number[]>();
  const key = (parentheses: number, brackets: number, braces: number): string =>
    `${parentheses}:${brackets}:${braces}`;
  const finish = (
    parentheses: number,
    brackets: number,
    braces: number,
    end: number,
  ): void => {
    const depthKey = key(parentheses, brackets, braces);
    const indexes = pending.get(depthKey);
    if (!indexes) return;
    for (const assignmentIndex of indexes) ends[assignmentIndex] = end;
    pending.delete(depthKey);
  };

  let parentheses = 0;
  let brackets = 0;
  let braces = 0;
  let assignmentIndex = 0;
  for (let index = 0; index < mask.length; index++) {
    while (assignmentIndex < starts.length && starts[assignmentIndex]! <= index) {
      const depthKey = key(parentheses, brackets, braces);
      const indexes = pending.get(depthKey) ?? [];
      indexes.push(assignmentIndex++);
      pending.set(depthKey, indexes);
    }

    switch (mask[index]) {
      case "(":
        parentheses++;
        break;
      case ")":
        finish(parentheses, brackets, braces, index);
        if (parentheses > 0) parentheses--;
        break;
      case "[":
        brackets++;
        break;
      case "]":
        finish(parentheses, brackets, braces, index);
        if (brackets > 0) brackets--;
        break;
      case "{":
        braces++;
        break;
      case "}":
        finish(parentheses, brackets, braces, index);
        if (braces > 0) braces--;
        break;
      case ",":
      case ";":
      case "\n":
      case "\r":
        finish(parentheses, brackets, braces, index);
        break;
    }
  }

  return ends;
}

function simpleAliasInRange(
  mask: string,
  start: number,
  end: number,
): string | undefined {
  let index = skipWhitespace(mask, start, end);
  if (!isIdentifierStart(mask[index])) return undefined;
  const aliasStart = index++;
  while (index < end && isIdentifierPart(mask[index])) index++;
  const alias = mask.slice(aliasStart, index);
  index = skipWhitespace(mask, index, end);
  return index === end ? alias : undefined;
}
function matchingBraces(mask: string): Map<number, number> {
  const stack: number[] = [];
  const pairs = new Map<number, number>();
  for (let index = 0; index < mask.length; index++) {
    if (mask[index] === "{") stack.push(index);
    else if (mask[index] === "}") {
      const open = stack.pop();
      if (open !== undefined) pairs.set(open, index + 1);
    }
  }
  return pairs;
}

function splitTopLevel(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let parentheses = 0;
  let brackets = 0;
  let braces = 0;
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    if (char === "(") parentheses++;
    else if (char === ")" && parentheses > 0) parentheses--;
    else if (char === "[") brackets++;
    else if (char === "]" && brackets > 0) brackets--;
    else if (char === "{") braces++;
    else if (char === "}" && braces > 0) braces--;
    else if (char === "," && parentheses === 0 && brackets === 0 && braces === 0) {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}

function topLevelCharacter(value: string, character: string): number {
  let parentheses = 0;
  let brackets = 0;
  let braces = 0;
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    if (char === "(") parentheses++;
    else if (char === ")" && parentheses > 0) parentheses--;
    else if (char === "[") brackets++;
    else if (char === "]" && brackets > 0) brackets--;
    else if (char === "{") braces++;
    else if (char === "}" && braces > 0) braces--;
    else if (char === character && parentheses === 0 && brackets === 0 && braces === 0) {
      return index;
    }
  }
  return -1;
}

function balancedPatternEnd(value: string, start: number): number {
  const opening = value[start];
  const closing = opening === "{" ? "}" : "]";
  let depth = 1;
  for (let index = start + 1; index < value.length; index++) {
    if (value[index] === opening) depth++;
    else if (value[index] === closing && --depth === 0) return index;
  }
  return value.length - 1;
}

function collectBindingNames(value: string, names: Set<string>): void {
  let binding = value.trim().replace(/^\.\.\./, "").trim();
  if (binding.length === 0) return;

  if (binding[0] === "{" || binding[0] === "[") {
    const close = balancedPatternEnd(binding, 0);
    const entries = splitTopLevel(binding.slice(1, close));
    for (const entryValue of entries) {
      const entry = entryValue.trim();
      if (entry.length === 0) continue;
      if (binding[0] === "{") {
        const colon = topLevelCharacter(entry, ":");
        if (colon !== -1) {
          collectBindingNames(entry.slice(colon + 1), names);
          continue;
        }
      }
      const equals = topLevelCharacter(entry, "=");
      collectBindingNames(equals === -1 ? entry : entry.slice(0, equals), names);
    }
    return;
  }

  const match = /^([A-Za-z_$][\w$]*)/.exec(binding);
  if (match?.[1]) names.add(match[1]);
}

function parameterNames(value: string): ReadonlySet<string> {
  const names = new Set<string>();
  for (const parameter of splitTopLevel(value)) collectBindingNames(parameter, names);
  return names;
}

function expressionScopeEnd(mask: string, start: number): number {
  let parentheses = 0;
  let brackets = 0;
  let braces = 0;
  for (let index = start; index < mask.length; index++) {
    const char = mask[index]!;
    if (char === "(") parentheses++;
    else if (char === ")") {
      if (parentheses === 0 && brackets === 0 && braces === 0) return index;
      if (parentheses > 0) parentheses--;
    } else if (char === "[") brackets++;
    else if (char === "]") {
      if (parentheses === 0 && brackets === 0 && braces === 0) return index;
      if (brackets > 0) brackets--;
    } else if (char === "{") braces++;
    else if (char === "}") {
      if (parentheses === 0 && brackets === 0 && braces === 0) return index;
      if (braces > 0) braces--;
    } else if (
      parentheses === 0 && brackets === 0 && braces === 0 &&
      (char === "," || char === ";" || char === "\n" || char === "\r")
    ) {
      return index;
    }
  }
  return mask.length;
}

function indentationWidth(value: string): number {
  let width = 0;
  for (const char of value) width += char === "\t" ? 8 : 1;
  return width;
}

function pythonSuiteEnd(mask: string, headerEnd: number, indentation: number): number {
  let lineEnd = headerEnd;
  while (lineEnd < mask.length && mask[lineEnd] !== "\n" && mask[lineEnd] !== "\r") lineEnd++;
  const inlineBody = skipWhitespace(mask, headerEnd, lineEnd);
  if (inlineBody < lineEnd) return lineEnd;

  let lineStart = lineEnd;
  if (mask[lineStart] === "\r" && mask[lineStart + 1] === "\n") lineStart += 2;
  else if (lineStart < mask.length) lineStart++;

  for (let cursor = lineStart; cursor < mask.length;) {
    let cursorEnd = cursor;
    while (cursorEnd < mask.length && mask[cursorEnd] !== "\n" && mask[cursorEnd] !== "\r") cursorEnd++;
    let first = cursor;
    while (first < cursorEnd && (mask[first] === " " || mask[first] === "\t")) first++;
    if (first < cursorEnd && indentationWidth(mask.slice(cursor, first)) <= indentation) return cursor;
    if (mask[cursorEnd] === "\r" && mask[cursorEnd + 1] === "\n") cursor = cursorEnd + 2;
    else cursor = cursorEnd + 1;
  }
  return mask.length;
}

function collectFunctionScopes(codeMask: string): FunctionScope[] {
  const scopes: FunctionScope[] = [];
  const bracePairs = matchingBraces(codeMask);
  const pushScope = (
    declarationStart: number,
    start: number,
    end: number,
    rawParameters: string,
    kind: FunctionScope["kind"] = "function",
  ): void => {
    const parameters = parameterNames(rawParameters);
    scopes.push({
      declarationStart,
      start,
      end,
      kind,
      parameters,
      bindings: new Set(parameters),
    });
  };
  const addBracedScopes = (
    regex: RegExp,
    rejectControls = false,
    kind: FunctionScope["kind"] = "function",
  ): void => {
    let event: RegExpExecArray | null;
    while ((event = regex.exec(codeMask)) !== null) {
      if (rejectControls) {
        const beforeParameters = event[0].slice(0, event[0].lastIndexOf("("));
        const name = /([A-Za-z_$][\w$]*)\s*$/.exec(beforeParameters)?.[1];
        if (name && new Set(["if", "for", "while", "switch", "catch", "with", "function"]).has(name)) {
          continue;
        }
      }
      const open = event.index + event[0].lastIndexOf("{");
      const end = bracePairs.get(open);
      if (end === undefined) continue;
      pushScope(event.index, open, end, event[1] ?? "", kind);
    }
  };

  addBracedScopes(/\b(?:async\s+)?function\s*\*?(?:\s+[A-Za-z_$][\w$]*)?\s*\(([^()\r\n]*)\)\s*(?:\:\s*[^={\r\n]+)?\s*\{/g);
  addBracedScopes(/\(([^()\r\n]*)\)\s*(?:\:\s*[^={\r\n]+)?\s*=>\s*\{/g);
  addBracedScopes(/\b([A-Za-z_$][\w$]*)\s*=>\s*\{/g);
  addBracedScopes(/(?:^|[{},;])\s*(?:(?:public|private|protected|static|abstract|override|async|get|set)\s+)*(?:\*\s*)?(?:[A-Za-z_$#][\w$#]*|\[[^\]\r\n]+\])\s*\(([^()\r\n]*)\)\s*(?:\:\s*[^={\r\n]+)?\s*\{/gm, true);
  addBracedScopes(/\bcatch\s*\(([^()\r\n]*)\)\s*\{/g, false, "catch");

  const addConciseScopes = (regex: RegExp): void => {
    let event: RegExpExecArray | null;
    while ((event = regex.exec(codeMask)) !== null) {
      const bodyStart = event.index + event[0].length;
      pushScope(
        event.index,
        bodyStart,
        expressionScopeEnd(codeMask, bodyStart),
        event[1] ?? "",
      );
    }
  };
  addConciseScopes(/\(([^()\r\n]*)\)\s*(?:\:\s*[^=\r\n]+)?\s*=>(?![ \t]*\{)[ \t]*/g);
  addConciseScopes(/\b([A-Za-z_$][\w$]*)\s*=>(?![ \t]*\{)[ \t]*/g);

  const pythonDef = /^([ \t]*)(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(([^()\r\n]*)\)\s*(?:->[^:\r\n]+)?\s*:/gm;
  let definition: RegExpExecArray | null;
  while ((definition = pythonDef.exec(codeMask)) !== null) {
    const headerEnd = definition.index + definition[0].length;
    let lineEnd = headerEnd;
    while (lineEnd < codeMask.length && codeMask[lineEnd] !== "\n" && codeMask[lineEnd] !== "\r") lineEnd++;
    const inlineBody = skipWhitespace(codeMask, headerEnd, lineEnd);
    let bodyStart = inlineBody;
    if (inlineBody === lineEnd) {
      bodyStart = lineEnd;
      if (codeMask[bodyStart] === "\r" && codeMask[bodyStart + 1] === "\n") bodyStart += 2;
      else if (bodyStart < codeMask.length) bodyStart++;
    }
    pushScope(
      definition.index + (definition[1]?.length ?? 0),
      bodyStart,
      pythonSuiteEnd(codeMask, headerEnd, indentationWidth(definition[1] ?? "")),
      definition[2] ?? "",
    );
  }

  const pythonLambda = /\blambda\s+([^:\r\n]*):[ \t]*/g;
  let lambda: RegExpExecArray | null;
  while ((lambda = pythonLambda.exec(codeMask)) !== null) {
    const bodyStart = lambda.index + lambda[0].length;
    pushScope(
      lambda.index,
      bodyStart,
      expressionScopeEnd(codeMask, bodyStart),
      lambda[1] ?? "",
    );
  }

  const lexicalDeclarationPositions = collectVariableBindingDeclarations(codeMask)
    .filter((declaration) => declaration.kind === "lexical" && declaration.names.size > 0)
    .map((declaration) => declaration.position);
  const claimedBraces = new Set(scopes.map((scope) => scope.start));
  const orderedBraces = [...bracePairs.entries()].sort((left, right) => left[0] - right[0]);
  for (const [open, end] of orderedBraces) {
    if (claimedBraces.has(open)) continue;
    const insideIndex = lowerBound(lexicalDeclarationPositions, open + 1);
    const hasLexicalDeclarationInside =
      (lexicalDeclarationPositions[insideIndex] ?? Number.POSITIVE_INFINITY) < end;
    const beforeIndex = lowerBound(lexicalDeclarationPositions, open) - 1;
    const closestDeclarationBefore = beforeIndex >= 0
      ? lexicalDeclarationPositions[beforeIndex]!
      : -1;
    if (
      !hasLexicalDeclarationInside &&
      closestDeclarationBefore < Math.max(0, open - 1_024)
    ) {
      continue;
    }

    let previous = open - 1;
    while (previous >= 0 && /\s/.test(codeMask[previous]!)) previous--;

    let declarationStart: number | undefined;
    let loopStart: number | undefined;
    if (previous < 0 || codeMask[previous] === ";" || codeMask[previous] === "{" || codeMask[previous] === "}") {
      declarationStart = open;
    } else if (codeMask[previous] === ")") {
      const prefixStart = Math.max(0, open - 1_024);
      const prefix = codeMask.slice(prefixStart, open);
      const loop = /(?:^|[^\w$.])for\s+(?:await\s+)?\([^{}]*\)\s*$/.exec(prefix);
      loopStart = loop
        ? prefixStart + loop.index + loop[0].lastIndexOf("for")
        : undefined;
      declarationStart = loopStart ?? open;
    } else if (isIdentifierPart(codeMask[previous])) {
      const wordEnd = previous + 1;
      while (previous >= 0 && isIdentifierPart(codeMask[previous])) previous--;
      const word = codeMask.slice(previous + 1, wordEnd);
      if (new Set(["do", "else", "finally", "static", "try"]).has(word)) {
        declarationStart = open;
      }
    }
    if (declarationStart === undefined) continue;
    if (
      !hasLexicalDeclarationInside &&
      (loopStart === undefined || closestDeclarationBefore < loopStart)
    ) {
      continue;
    }
    pushScope(declarationStart, declarationStart, end, "", "block");
    claimedBraces.add(open);
  }  scopes.sort((left, right) => left.start - right.start || right.end - left.end);
  const active: FunctionScope[] = [];
  for (const scope of scopes) {
    while (active.length > 0 && active.at(-1)!.end <= scope.start) active.pop();
    scope.parent = active.at(-1);
    active.push(scope);
  }
  return scopes;
}

interface BindingDeclaration {
  position: number;
  kind: "var" | "lexical";
  names: Set<string>;
}

interface VariableDeclarationContext {
  declaration: BindingDeclaration;
  parentheses: number;
  brackets: number;
  braces: number;
  expectingBinding: boolean;
}

function collectVariableBindingDeclarations(codeMask: string): BindingDeclaration[] {
  const declarations: BindingDeclaration[] = [];
  const contexts: VariableDeclarationContext[] = [];
  let parentheses = 0;
  let brackets = 0;
  let braces = 0;
  let previousToken: string | undefined;
  const declarationStartTokens = new Set([
    "\n", ";", "{", "}", "(", ")", ":",
    "declare", "do", "else", "export", "for", "if", "while",
  ]);

  for (let index = 0; index < codeMask.length; index++) {
    const char = codeMask[index]!;
    const context = contexts.at(-1);
    if (context?.expectingBinding) {
      if (/\s/.test(char) || (char === "." && codeMask.slice(index, index + 3) === "...")) {
        continue;
      }
      if (isIdentifierStart(char)) {
        let end = index + 1;
        while (isIdentifierPart(codeMask[end])) end++;
        const binding = codeMask.slice(index, end);
        context.declaration.names.add(binding);
        context.expectingBinding = false;
        previousToken = binding;
        index = end - 1;
        continue;
      }
      if (char === "{" || char === "[") {
        const end = balancedPatternEnd(codeMask, index);
        collectBindingNames(codeMask.slice(index, end + 1), context.declaration.names);
        context.expectingBinding = false;
      }
    }

    if (isIdentifierStart(char)) {
      let end = index + 1;
      while (isIdentifierPart(codeMask[end])) end++;
      const word = codeMask.slice(index, end);
      let previous = index - 1;
      while (previous >= 0 && /\s/.test(codeMask[previous]!)) previous--;
      let next = end;
      while (next < codeMask.length && (codeMask[next] === " " || codeMask[next] === "\t")) next++;
      const canStartDeclaration =
        previousToken === undefined || declarationStartTokens.has(previousToken);
      const hasBindingFollower =
        isIdentifierStart(codeMask[next]) ||
        codeMask[next] === "{" ||
        codeMask[next] === "[" ||
        codeMask[next] === "\n" ||
        codeMask[next] === "\r";
      if (
        (word === "const" || word === "let" || word === "var") &&
        codeMask[previous] !== "." &&
        canStartDeclaration &&
        hasBindingFollower
      ) {
        const declaration: BindingDeclaration = {
          position: index,
          kind: word === "var" ? "var" : "lexical",
          names: new Set<string>(),
        };
        declarations.push(declaration);
        contexts.push({
          declaration,
          parentheses,
          brackets,
          braces,
          expectingBinding: true,
        });
      }
      previousToken = word;
      index = end - 1;
      continue;
    }

    const active = contexts.at(-1);
    if (
      active &&
      active.parentheses === parentheses &&
      active.brackets === brackets &&
      active.braces === braces
    ) {
      if (char === ",") active.expectingBinding = true;
      else if (char === ";" || char === "\n" || char === "\r") contexts.pop();
      else if (
        (char === ")" && parentheses > 0) ||
        (char === "]" && brackets > 0) ||
        (char === "}" && braces > 0)
      ) {
        contexts.pop();
      }
    }

    if (char === "(") parentheses++;
    else if (char === ")" && parentheses > 0) parentheses--;
    else if (char === "[") brackets++;
    else if (char === "]" && brackets > 0) brackets--;
    else if (char === "{") braces++;
    else if (char === "}" && braces > 0) braces--;

    if (char === "\n" || char === "\r") previousToken = "\n";
    else if (!/\s/.test(char)) previousToken = char;
  }
  return declarations;
}
function bodyScopeOwnersAtPositions(
  scopes: readonly FunctionScope[],
  positions: readonly number[],
): Array<FunctionScope | undefined> {
  const ordered = [...scopes].sort(
    (left, right) => left.start - right.start || right.end - left.end,
  );
  const active: FunctionScope[] = [];
  const owners: Array<FunctionScope | undefined> = [];
  let scopeIndex = 0;
  for (const position of positions) {
    while (scopeIndex < ordered.length && ordered[scopeIndex]!.start <= position) {
      const scope = ordered[scopeIndex++]!;
      while (active.length > 0 && active.at(-1)!.end <= scope.start) active.pop();
      active.push(scope);
    }
    while (active.length > 0 && active.at(-1)!.end <= position) active.pop();
    owners.push(active.at(-1));
  }
  return owners;
}

function collectPredeclaredBindings(
  codeMask: string,
  scopes: readonly FunctionScope[],
): ReadonlySet<string> {
  const declarations = collectVariableBindingDeclarations(codeMask);
  let event: RegExpExecArray | null;
  const namedDeclaration = /\b(function|class)\s*\*?\s*([A-Za-z_$][\w$]*)/g;
  while ((event = namedDeclaration.exec(codeMask)) !== null) {
    declarations.push({
      position: event.index,
      kind: event[1] === "function" ? "var" : "lexical",
      names: new Set([event[2]!]),
    });
  }

  declarations.sort((left, right) => left.position - right.position);
  const owners = bodyScopeOwnersAtPositions(
    scopes,
    declarations.map((declaration) => declaration.position),
  );
  const globals = new Set<string>();
  for (let index = 0; index < declarations.length; index++) {
    const declaration = declarations[index]!;
    let owner = owners[index];
    if (declaration.kind === "var") {
      while (owner && owner.kind !== "function") owner = owner.parent;
    }
    const destination = owner?.bindings ?? globals;
    for (const name of declaration.names) destination.add(name);
  }
  return globals;
}

function bindingIsVisible(
  name: string,
  scope: FunctionScope | undefined,
  globals: ReadonlySet<string>,
): boolean {
  for (let current = scope; current; current = current.parent) {
    if (current.bindings.has(name)) return true;
  }
  return globals.has(name);
}
function ownershipScopesAtPositions(
  scopes: readonly FunctionScope[],
  positions: readonly number[],
): Array<FunctionScope | undefined> {
  const orderedScopes = [...scopes].sort(
    (left, right) => left.declarationStart - right.declarationStart || right.end - left.end,
  );
  const activeScopes: FunctionScope[] = [];
  const owners: Array<FunctionScope | undefined> = [];
  let scopeIndex = 0;

  for (const position of positions) {
    while (
      scopeIndex < orderedScopes.length &&
      orderedScopes[scopeIndex]!.declarationStart <= position
    ) {
      const scope = orderedScopes[scopeIndex++]!;
      while (activeScopes.length > 0 && activeScopes.at(-1)!.end <= scope.declarationStart) {
        activeScopes.pop();
      }
      activeScopes.push(scope);
    }
    while (activeScopes.length > 0 && activeScopes.at(-1)!.end <= position) {
      activeScopes.pop();
    }
    owners.push(activeScopes.at(-1));
  }
  return owners;
}
interface FunctionScopeEvent {
  position: number;
  type: "enter" | "exit";
  scope: FunctionScope;
}

interface ActiveCredentialBinding {
  scope?: FunctionScope;
  state: CredentialAssignmentState;
}

function collectCredentialAssignments(
  codeMask: string,
  sources: readonly CredentialSourceRange[],
  scopes: readonly FunctionScope[],
): CredentialAssignmentState[] {
  const candidates: Array<{
    variable: string;
    position: number;
    rhsStart: number;
    scope?: FunctionScope;
  }> = [];
  const sourceOwners = ownershipScopesAtPositions(
    scopes,
    sources.map((source) => source.start),
  );
  const sourcesByScope = new Map<
    FunctionScope | undefined,
    { ranges: CredentialSourceRange[]; starts: number[] }
  >();
  for (let index = 0; index < sources.length; index++) {
    const owner = sourceOwners[index];
    const scoped = sourcesByScope.get(owner) ?? { ranges: [], starts: [] };
    scoped.ranges.push(sources[index]!);
    scoped.starts.push(sources[index]!.start);
    sourcesByScope.set(owner, scoped);
  }
  const ownershipScopes = [...scopes].sort(
    (left, right) =>
      left.declarationStart - right.declarationStart || right.end - left.end,
  );
  const activeScopes: FunctionScope[] = [];
  let scopeIndex = 0;

  PATH_ASSIGNMENT.lastIndex = 0;
  let assignment: RegExpExecArray | null;
  while ((assignment = PATH_ASSIGNMENT.exec(codeMask)) !== null) {
    if (codeMask[assignment.index - 1] === ".") continue;

    while (
      scopeIndex < ownershipScopes.length &&
      ownershipScopes[scopeIndex]!.declarationStart <= assignment.index
    ) {
      const scope = ownershipScopes[scopeIndex++]!;
      while (activeScopes.length > 0 && activeScopes.at(-1)!.end <= scope.declarationStart) {
        activeScopes.pop();
      }
      activeScopes.push(scope);
    }
    while (activeScopes.length > 0 && activeScopes.at(-1)!.end <= assignment.index) {
      activeScopes.pop();
    }
    const scope = activeScopes.at(-1);
    const equals = assignment.index + assignment[0].lastIndexOf("=");
    const bareVariable = assignment[1] ?? assignment[2]!;
    candidates.push({
      variable: codeMask[assignment.index - 1] === "#"
        ? `#${bareVariable}`
        : bareVariable,
      position: scope && assignment.index < scope.start ? scope.start : assignment.index,
      rhsStart: equals + 1,
      scope,
    });
  }

  const boundaries = assignmentRhsEnds(
    codeMask,
    candidates.map((candidate) => candidate.rhsStart),
  );
  const assignments: CredentialAssignmentState[] = [];
  for (let index = 0; index < candidates.length; index++) {
    const candidate = candidates[index]!;
    const boundary = boundaries[index]!;
    const scopedSources = sourcesByScope.get(candidate.scope);
    const sourceIndex = lowerBound(scopedSources?.starts ?? [], candidate.rhsStart);
    const source = scopedSources?.ranges[sourceIndex];
    const qualified =
      source !== undefined &&
      source.start < boundary &&
      source.end <= boundary;
    assignments.push({
      variable: candidate.variable,
      position: candidate.position,
      qualified,
      sourceStart: qualified ? source.start : undefined,
      alias: qualified
        ? undefined
        : simpleAliasInRange(codeMask, candidate.rhsStart, boundary),
      scope: candidate.scope,
    });
  }

  return assignments;
}
/**
 * Resolve every tracked identifier through one monotonic merge of lexical
 * scope boundaries and assignment events. Each assignment, scope boundary,
 * and identifier is consumed once. No use allocates a position array or scans
 * backward through older states, so assignment-heavy files remain near-linear.
 */
function collectCredentialUses(
  codeMask: string,
  assignments: readonly CredentialAssignmentState[],
  scopes: readonly FunctionScope[],
  globalBindings: ReadonlySet<string>,
): CredentialUse[] {
  if (assignments.length === 0) return [];

  const scopeEvents: FunctionScopeEvent[] = scopes.flatMap((scope) => [
    { position: scope.start, type: "enter" as const, scope },
    { position: scope.end, type: "exit" as const, scope },
  ]);
  scopeEvents.sort((left, right) => {
    if (left.position !== right.position) return left.position - right.position;
    if (left.type !== right.type) return left.type === "exit" ? -1 : 1;
    return left.type === "enter"
      ? right.scope.end - left.scope.end
      : right.scope.start - left.scope.start;
  });

  const activeBindings = new Map<string, ActiveCredentialBinding[]>();
  const scopeVariables = new Map<FunctionScope, Set<string>>();
  const bind = (
    variable: string,
    scope: FunctionScope | undefined,
    state: CredentialAssignmentState,
  ): void => {
    const stack = activeBindings.get(variable) ?? [];
    const current = stack.at(-1);
    if (current && current.scope === scope) {
      current.state = state;
    } else {
      stack.push({ scope, state });
      activeBindings.set(variable, stack);
      if (scope) {
        const variables = scopeVariables.get(scope) ?? new Set<string>();
        variables.add(variable);
        scopeVariables.set(scope, variables);
      }
    }
  };

  for (const variable of globalBindings) {
    bind(variable, undefined, {
      variable,
      position: 0,
      qualified: false,
    });
  }

  let scopeEventIndex = 0;
  let assignmentIndex = 0;
  const applyScopeEvent = (event: FunctionScopeEvent): void => {
    if (event.type === "enter") {
      for (const variable of event.scope.bindings) {
        bind(variable, event.scope, {
          variable: variable,
          position: event.scope.start,
          qualified: false,
          scope: event.scope,
        });
      }
      return;
    }

    for (const variable of scopeVariables.get(event.scope) ?? []) {
      const stack = activeBindings.get(variable);
      if (stack?.at(-1)?.scope !== event.scope) continue;
      stack.pop();
      if (stack.length === 0) activeBindings.delete(variable);
    }
    scopeVariables.delete(event.scope);
  };

  const applyEventsThrough = (position: number): void => {
    while (true) {
      const scopeEvent = scopeEvents[scopeEventIndex];
      const assignment = assignments[assignmentIndex];
      const scopePosition = scopeEvent?.position ?? Number.POSITIVE_INFINITY;
      const assignmentPosition = assignment?.position ?? Number.POSITIVE_INFINITY;
      const nextPosition = Math.min(scopePosition, assignmentPosition);
      if (nextPosition > position) return;

      if (scopePosition <= assignmentPosition) {
        applyScopeEvent(scopeEvent!);
        scopeEventIndex++;
      } else {
        const event = assignment!;
        const aliasState = event.alias === undefined
          ? undefined
          : activeBindings.get(event.alias)?.at(-1)?.state;
        const resolved =
          !event.qualified && aliasState?.qualified && aliasState.sourceStart !== undefined
            ? {
                ...event,
                qualified: true,
                sourceStart: aliasState.sourceStart,
              }
            : event;
        bind(event.variable, event.scope, resolved);
        assignmentIndex++;
      }
    }
  };

  const uses: CredentialUse[] = [];
  const identifier = /[A-Za-z_$][\w$]*/g;
  let token: RegExpExecArray | null;
  while ((token = identifier.exec(codeMask)) !== null) {
    applyEventsThrough(token.index);
    const before = codeMask[token.index - 1];
    if (before === ".") continue;
    const bindingName = before === "#" ? `#${token[0]}` : token[0];
    const state = activeBindings.get(bindingName)?.at(-1)?.state;
    if (!state?.qualified || state.sourceStart === undefined) continue;
    if (state.scope && (token.index < state.scope.start || token.index >= state.scope.end)) {
      continue;
    }

    const after = skipWhitespace(codeMask, token.index + token[0].length);
    if (codeMask[after] === ":" || codeMask[after] === "=") continue;

    uses.push({ position: token.index, sourceStart: state.sourceStart });
  }
  return uses;
}
function isFunctionDeclaration(mask: string, callStart: number): boolean {
  let index = callStart - 1;
  while (index >= 0 && /\s/.test(mask[index]!)) index--;
  const wordEnd = index + 1;
  while (index >= 0 && isIdentifierPart(mask[index])) index--;
  return mask.slice(index + 1, wordEnd) === "function";
}

function collectExplicitNetworkClients(mask: string): ReadonlySet<string> {
  const clients = new Set<string>();
  const declaration = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+(?:XMLHttpRequest|WebSocket)\b/g;
  let event: RegExpExecArray | null;
  while ((event = declaration.exec(mask)) !== null) clients.add(event[1]!.toLowerCase());
  return clients;
}

const COMMONJS_HTTP_MODULES = new Set(["http", "https", "node:http", "node:https"]);
const COMMONJS_REQUEST_MODULES = new Set(["axios", "got"]);

function commonJsModuleReceiver(
  semanticMask: string,
  callStart: number,
): string | undefined {
  const prefix = semanticMask.slice(Math.max(0, callStart - 192), callStart);
  const required = /\brequire\s*\(\s*["'`]([^"'`\r\n]+)["'`]\s*\)\s*\.\s*$/.exec(prefix);
  if (!required) return undefined;
  const requireStart = required.index + required[0].indexOf("require");
  let previous = requireStart - 1;
  while (previous >= 0 && /\s/.test(prefix[previous]!)) previous--;
  if (
    previous >= 0 &&
    (prefix[previous] === "." || prefix[previous] === "?" || isIdentifierPart(prefix[previous]))
  ) {
    return undefined;
  }
  return required[1]?.toLowerCase();
}

function commonJsNetworkMethod(moduleName: string, method: string): boolean {
  if (COMMONJS_REQUEST_MODULES.has(moduleName)) {
    return method === "request" || method === "get" || method === "post" ||
      method === "put" || method === "patch";
  }
  return COMMONJS_HTTP_MODULES.has(moduleName) &&
    (method === "request" || method === "get");
}

type NetworkBindingKind = "client" | "fetch" | "http" | "request" | "urllib";

interface NetworkBindingProvenance {
  globals: ReadonlyMap<string, NetworkBindingKind>;
  scopes: ReadonlyMap<FunctionScope, ReadonlyMap<string, NetworkBindingKind>>;
}

interface NetworkBindingCandidate {
  position: number;
  name: string;
  kind: NetworkBindingKind;
}

function networkBindingKind(moduleName: string): NetworkBindingKind | undefined {
  const normalized = moduleName.toLowerCase();
  if (new Set(["axios", "got", "requests"]).has(normalized)) return "request";
  if (new Set(["http", "https", "node:http", "node:https"]).has(normalized)) return "http";
  if (new Set(["node-fetch", "cross-fetch", "isomorphic-fetch"]).has(normalized)) return "fetch";
  if (normalized === "urllib.request") return "urllib";
  return undefined;
}

function collectNetworkBindingProvenance(
  codeMask: string,
  semanticMask: string,
  scopes: readonly FunctionScope[],
): NetworkBindingProvenance {
  const candidates: NetworkBindingCandidate[] = [];
  const collect = (
    regex: RegExp,
    nameGroup: number,
    moduleGroup: number,
  ): void => {
    let event: RegExpExecArray | null;
    while ((event = regex.exec(semanticMask)) !== null) {
      const firstCode = event.index + (event[0].search(/[A-Za-z]/));
      if (!isIdentifierStart(codeMask[firstCode])) continue;
      const kind = networkBindingKind(event[moduleGroup]!);
      if (!kind) continue;
      candidates.push({ position: event.index, name: event[nameGroup]!, kind });
    }
  };

  collect(
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["'`]([^"'`\r\n]+)["'`]\s*\)/g,
    1,
    2,
  );
  collect(
    /\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+["'`]([^"'`\r\n]+)["'`]/g,
    1,
    2,
  );
  collect(
    /\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+["'`]([^"'`\r\n]+)["'`]/g,
    1,
    2,
  );

  const clientDeclaration = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+(?:XMLHttpRequest|WebSocket)\b/g;
  let client: RegExpExecArray | null;
  while ((client = clientDeclaration.exec(codeMask)) !== null) {
    candidates.push({
      position: client.index,
      name: client[1]!,
      kind: "client",
    });
  }

  const pythonImport = /^\s*import\s+(requests|urllib\.request)(?:\s+as\s+([A-Za-z_]\w*))?/gm;
  let python: RegExpExecArray | null;
  while ((python = pythonImport.exec(semanticMask)) !== null) {
    const keyword = python.index + python[0].indexOf("import");
    if (codeMask.slice(keyword, keyword + 6) !== "import") continue;
    candidates.push({
      position: keyword,
      name: python[2] ?? python[1]!.split(".")[0]!,
      kind: networkBindingKind(python[1]!)!,
    });
  }
  const pythonFrom = /^\s*from\s+urllib\s+import\s+request(?:\s+as\s+([A-Za-z_]\w*))?/gm;
  while ((python = pythonFrom.exec(semanticMask)) !== null) {
    const keyword = python.index + python[0].indexOf("from");
    if (codeMask.slice(keyword, keyword + 4) !== "from") continue;
    candidates.push({
      position: keyword,
      name: python[1] ?? "request",
      kind: "urllib",
    });
  }

  candidates.sort((left, right) => left.position - right.position);
  const owners = bodyScopeOwnersAtPositions(
    scopes,
    candidates.map((candidate) => candidate.position),
  );
  const globals = new Map<string, NetworkBindingKind>();
  const byScope = new Map<FunctionScope, Map<string, NetworkBindingKind>>();
  for (let index = 0; index < candidates.length; index++) {
    const candidate = candidates[index]!;
    const owner = owners[index];
    if (!owner) {
      globals.set(candidate.name, candidate.kind);
      continue;
    }
    const bindings = byScope.get(owner) ?? new Map<string, NetworkBindingKind>();
    bindings.set(candidate.name, candidate.kind);
    byScope.set(owner, bindings);
  }
  return { globals, scopes: byScope };
}

interface NetworkBindingResolution {
  bound: boolean;
  kind?: NetworkBindingKind;
}

function resolveNetworkBinding(
  name: string,
  scope: FunctionScope | undefined,
  globalBindings: ReadonlySet<string>,
  provenance: NetworkBindingProvenance,
): NetworkBindingResolution {
  for (let current = scope; current; current = current.parent) {
    const kind = provenance.scopes.get(current)?.get(name);
    if (kind !== undefined) return { bound: true, kind };
    if (current.bindings.has(name)) return { bound: true };
  }
  const kind = provenance.globals.get(name);
  if (kind !== undefined) return { bound: true, kind };
  return { bound: globalBindings.has(name) };
}

function provenNetworkMethod(kind: NetworkBindingKind, method: string): boolean {
  if (kind === "request") {
    return method === "axios" || method === "request" || method === "get" ||
      method === "post" || method === "put" || method === "patch";
  }
  if (kind === "http") return method === "request" || method === "get";
  if (kind === "urllib") return method === "urlopen";
  if (kind === "client") return method === "send";
  return method === "fetch" || method === "nodeFetch";
}
function isNetworkSinkCall(
  codeMask: string,
  semanticMask: string,
  call: CallRange,
  explicitClients: ReadonlySet<string>,
  scope: FunctionScope | undefined,
  globalBindings: ReadonlySet<string>,
  provenance: NetworkBindingProvenance,
): boolean {
  if (isFunctionDeclaration(codeMask, call.start)) return false;
  const rawReceiver = receiverExpression(codeMask, call.start);
  const receiver = rawReceiver?.toLowerCase();
  const commonJsModule = commonJsModuleReceiver(semanticMask, call.start);
  if (commonJsModule !== undefined) {
    return !bindingIsVisible("require", scope, globalBindings) &&
      commonJsNetworkMethod(commonJsModule, call.name);
  }

  if (rawReceiver === undefined) {
    const resolution = resolveNetworkBinding(
      call.name,
      scope,
      globalBindings,
      provenance,
    );
    if (resolution.bound) {
      return resolution.kind !== undefined &&
        provenNetworkMethod(resolution.kind, call.name);
    }
  } else {
    const root = rawReceiver.split(".")[0]!;
    const resolution = resolveNetworkBinding(
      root,
      scope,
      globalBindings,
      provenance,
    );
    if (resolution.bound) {
      if (resolution.kind === undefined) return false;
      const exactReceiver = rawReceiver === root ||
        (resolution.kind === "urllib" && rawReceiver === `${root}.request`);
      return exactReceiver && provenNetworkMethod(resolution.kind, call.name);
    }
  }

  if (call.name === "fetch" || call.name === "nodeFetch" || call.name === "axios") {
    return receiver === undefined || receiver === "window" || receiver === "globalthis";
  }
  if (call.name === "request") {
    return receiver === undefined ||
      receiver === "http" ||
      receiver === "https" ||
      receiver === "axios" ||
      receiver === "requests";
  }
  if (call.name === "urlopen") {
    return receiver === "urllib" || receiver === "urllib.request";
  }
  if (call.name === "send") {
    return receiver !== undefined && explicitClients.has(receiver);
  }
  if (call.name === "get" || call.name === "post" || call.name === "put" || call.name === "patch") {
    return receiver === "axios" ||
      receiver === "requests" ||
      receiver === "got" ||
      receiver === "http" ||
      receiver === "https";
  }
  return false;
}
function credentialFlowStart(
  sources: readonly CredentialSourceRange[],
  sourceStarts: readonly number[],
  uses: readonly CredentialUse[],
  usePositions: readonly number[],
  start: number,
  end: number,
): number | undefined {
  const directIndex = lowerBound(sourceStarts, start);
  const direct = sources[directIndex];
  if (direct && direct.start < end && direct.end <= end) return direct.start;

  const useIndex = lowerBound(usePositions, start);
  const use = uses[useIndex];
  return use && use.position < end ? use.sourceStart : undefined;
}

/**
 * Correlate an actual npm credential read with the network call that consumes
 * it. Whole-file coincidence is never sufficient: source and sink must share a
 * direct value flow, and assignments respect top-level comma boundaries and
 * lexical function/parameter scope.
 */
const shaiHuludProgramCredentialStealMatcher: CorrelatedPatternMatcher = (content) => {
  if (
    !NPM_CREDENTIAL_SOURCE_SIGNAL.test(content) ||
    !/\b(?:fetch|nodeFetch|axios|request|get|post|put|patch|send|urlopen)\s*\(/.test(content)
  ) {
    return [];
  }

  const strictMixed = { mixedHashCommentsAnywhere: true } as const;
  const codeMask = maskLexical(content, "mixed", true, strictMixed);
  const semanticMask = maskLexical(content, "mixed", false, strictMixed);
  const sources = collectNpmCredentialSources(codeMask, semanticMask);
  if (sources.length === 0) return [];

  const scopes = collectFunctionScopes(codeMask);
  const globalBindings = collectPredeclaredBindings(codeMask, scopes);
  const assignments = collectCredentialAssignments(codeMask, sources, scopes);
  const uses = collectCredentialUses(
    codeMask,
    assignments,
    scopes,
    globalBindings,
  );
  const sourceStarts = sources.map((source) => source.start);
  const usePositions = uses.map((use) => use.position);
  const explicitClients = collectExplicitNetworkClients(codeMask);
  const provenance = collectNetworkBindingProvenance(codeMask, semanticMask, scopes);
  const results: CorrelatedPatternMatch[] = [];
  const emitted = new Set<string>();
  const calls: CallRange[] = [];
  forEachCompletedCall(codeMask, NETWORK_SINK_CALLS, (call) => calls.push(call));
  calls.sort((left, right) => left.start - right.start || left.end - right.end);
  const owners = ownershipScopesAtPositions(
    scopes,
    calls.map((call) => call.start),
  );

  for (let index = 0; index < calls.length; index++) {
    const call = calls[index]!;
    if (!isNetworkSinkCall(
      codeMask,
      semanticMask,
      call,
      explicitClients,
      owners[index],
      globalBindings,
      provenance,
    )) continue;
    const sourceStart = credentialFlowStart(
      sources,
      sourceStarts,
      uses,
      usePositions,
      call.open + 1,
      call.end - 1,
    );
    if (sourceStart === undefined) continue;
    const key = `${sourceStart}:${call.start}`;
    if (emitted.has(key)) continue;
    emitted.add(key);
    results.push(correlation(content, sourceStart, call.end));
  }

  return results.sort((left, right) => left.start - right.start || left.end - right.end);
};
const CHARACTER_CODE_EXECUTION_CALLS = [
  "eval",
  "setTimeout",
  "setInterval",
  "Function",
  "exec",
  "execSync",
  "spawn",
  "system",
  "runInContext",
  "runInNewContext",
  "runInThisContext",
];

function isCharacterCodeNumberList(
  codeMask: string,
  start: number,
  end: number,
): boolean {
  let index = start;
  let count = 0;
  const skipSpace = (): void => {
    while (index < end && /\s/.test(codeMask[index]!)) index++;
  };

  skipSpace();
  while (index < end) {
    if (codeMask[index] === "0" && (codeMask[index + 1] === "x" || codeMask[index + 1] === "X")) {
      index += 2;
      const digitsStart = index;
      while (index < end && /[0-9a-fA-F]/.test(codeMask[index]!)) index++;
      if (index === digitsStart) return false;
    } else {
      const digitsStart = index;
      while (index < end && /\d/.test(codeMask[index]!)) index++;
      if (index === digitsStart) return false;
    }

    count++;
    skipSpace();
    if (index === end) break;
    if (codeMask[index] !== ",") return false;
    index++;
    skipSpace();
    if (index === end) return false;
  }

  return count >= 5;
}

function collectCharacterCodeSources(
  codeMask: string,
  semanticMask: string,
): CredentialSourceRange[] {
  const sources: CredentialSourceRange[] = [];

  forEachCompletedCall(codeMask, ["fromCharCode"], (call) => {
    if (receiverExpression(codeMask, call.start) !== "String") return;
    if (!isCharacterCodeNumberList(codeMask, call.argStart, call.end - 1)) return;
    sources.push({ start: call.start, end: call.end });
  });

  let searchFrom = 0;
  while (searchFrom < semanticMask.length) {
    const start = semanticMask.indexOf("\\x", searchFrom);
    if (start === -1) break;
    let end = start;
    let count = 0;
    while (
      end + 3 < semanticMask.length &&
      semanticMask[end] === "\\" &&
      semanticMask[end + 1] === "x" &&
      /[0-9a-fA-F]/.test(semanticMask[end + 2]!) &&
      /[0-9a-fA-F]/.test(semanticMask[end + 3]!)
    ) {
      count++;
      end += 4;
    }
    if (count >= 5) sources.push({ start, end });
    searchFrom = end > start ? end : start + 2;
  }

  return normalizeCredentialSources(sources);
}

interface OffsetRange {
  start: number;
  end: number;
}

function topLevelRanges(mask: string, start: number, end: number): OffsetRange[] {
  const ranges: OffsetRange[] = [];
  let rangeStart = start;
  let parentheses = 0;
  let brackets = 0;
  let braces = 0;
  for (let index = start; index < end; index++) {
    const char = mask[index]!;
    if (char === "(") parentheses++;
    else if (char === ")" && parentheses > 0) parentheses--;
    else if (char === "[") brackets++;
    else if (char === "]" && brackets > 0) brackets--;
    else if (char === "{") braces++;
    else if (char === "}" && braces > 0) braces--;
    else if (
      char === "," && parentheses === 0 && brackets === 0 && braces === 0
    ) {
      ranges.push({ start: rangeStart, end: index });
      rangeStart = index + 1;
    }
  }
  ranges.push({ start: rangeStart, end });
  return ranges;
}

function spawnShellCommandRange(
  codeMask: string,
  semanticMask: string,
  call: CallRange,
): OffsetRange | undefined {
  if (call.name !== "spawn") return undefined;
  const arguments_ = topLevelRanges(codeMask, call.open + 1, call.end - 1);
  if (arguments_.length < 2) return undefined;
  const executable = semanticMask.slice(arguments_[0]!.start, arguments_[0]!.end).trim();
  const shell = /^(?:["'`])(?:ba|da|z|k)?sh(?:\.exe)?(?:["'`])$/i.test(executable) ||
    /^(?:["'`])(?:cmd|powershell|pwsh)(?:\.exe)?(?:["'`])$/i.test(executable);
  if (!shell) return undefined;

  const list = arguments_[1]!;
  let listStart = skipWhitespace(codeMask, list.start, list.end);
  let listEnd = list.end;
  while (listEnd > listStart && /\s/.test(codeMask[listEnd - 1]!)) listEnd--;
  if (codeMask[listStart] !== "[" || codeMask[listEnd - 1] !== "]") return undefined;
  const elements = topLevelRanges(codeMask, listStart + 1, listEnd - 1);
  for (let index = 0; index + 1 < elements.length; index++) {
    const flag = semanticMask.slice(elements[index]!.start, elements[index]!.end).trim();
    if (!/^(?:["'`])(?:-c|\/c|-command)(?:["'`])$/i.test(flag)) continue;
    return elements[index + 1];
  }
  return undefined;
}
function isFunctionValuedTimerArgument(mask: string, call: CallRange): boolean {
  if (call.name !== "setTimeout" && call.name !== "setInterval") return false;
  const argument = mask.slice(call.argStart, call.argEnd);
  return /^\s*(?:(?:async\s+)?function\b|(?:async\s+)?(?:\([^()\r\n]*\)|[A-Za-z_$][\w$]*)\s*=>)/.test(argument) ||
    /^\s*[A-Za-z_$][\w$]*(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*)*\s*\.\s*bind\s*\(/.test(argument);
}
function isCharacterCodeExecutionSink(mask: string, call: CallRange): boolean {
  if (isFunctionDeclaration(mask, call.start)) return false;
  const receiver = receiverExpression(mask, call.start)?.toLowerCase();

  if (
    call.name === "eval" ||
    call.name === "setTimeout" ||
    call.name === "setInterval" ||
    call.name === "Function"
  ) {
    return receiver === undefined || receiver === "window" || receiver === "globalthis";
  }
  if (
    call.name === "runInContext" ||
    call.name === "runInNewContext" ||
    call.name === "runInThisContext"
  ) {
    return receiver === "vm";
  }
  if (call.name === "exec" || call.name === "execSync" || call.name === "spawn") {
    return receiver === undefined ||
      receiver === "child_process" ||
      receiver === "childprocess" ||
      receiver === "cp" ||
      receiver === "shell" ||
      receiver === "shelljs";
  }
  if (call.name === "system") {
    return receiver === undefined || receiver === "os" || receiver === "shell";
  }
  return false;
}

/**
 * Correlate an uncapped encoded-character source with the dynamic execution
 * sink that consumes it. Strings and comments remain available as source data,
 * but only executable sink tokens from the lexical code mask can complete a
 * finding. This keeps quoted documentation inert without a detector-size cap.
 */
export const matchCharacterCodeObfuscation: CorrelatedPatternMatcher = (content) => {
  if (
    (!content.includes("\\x") && !/\bString\s*\.\s*fromCharCode\s*\(/.test(content)) ||
    !/\b(?:eval|setTimeout|setInterval|Function|exec|execSync|spawn|system|runInContext|runInNewContext|runInThisContext)\s*\(/.test(content)
  ) {
    return [];
  }

  const strictMixed = { mixedHashCommentsAnywhere: true } as const;
  const codeMask = maskLexical(content, "mixed", true, strictMixed);
  const semanticMask = maskLexical(content, "mixed", false, strictMixed);
  const sources = collectCharacterCodeSources(codeMask, semanticMask);
  if (sources.length === 0) return [];

  const scopes = collectFunctionScopes(codeMask);
  const globalBindings = collectPredeclaredBindings(codeMask, scopes);
  const assignments = collectCredentialAssignments(codeMask, sources, scopes);
  const uses = collectCredentialUses(
    codeMask,
    assignments,
    scopes,
    globalBindings,
  );
  const sourceStarts = sources.map((source) => source.start);
  const usePositions = uses.map((use) => use.position);
  const results: CorrelatedPatternMatch[] = [];
  const emitted = new Set<string>();

  forEachCompletedCall(codeMask, CHARACTER_CODE_EXECUTION_CALLS, (call) => {
    if (!isCharacterCodeExecutionSink(codeMask, call)) return;
    if (isFunctionValuedTimerArgument(codeMask, call)) return;
    const ranges: OffsetRange[] = call.name === "Function"
      ? [{ start: call.lastArgStart, end: call.end - 1 }]
      : [{ start: call.argStart, end: call.argEnd }];
    const shellCommand = spawnShellCommandRange(codeMask, semanticMask, call);
    if (shellCommand) ranges.push(shellCommand);

    let sourceStart: number | undefined;
    for (const range of ranges) {
      sourceStart = credentialFlowStart(
        sources,
        sourceStarts,
        uses,
        usePositions,
        range.start,
        range.end,
      );
      if (sourceStart !== undefined) break;
    }
    if (sourceStart === undefined) return;
    const key = `${sourceStart}:${call.start}`;
    if (emitted.has(key)) return;
    emitted.add(key);
    results.push(correlation(content, sourceStart, call.end));
  });

  return results.sort((left, right) => left.start - right.start || left.end - right.end);
};
const SHELL_NPM_TOKEN = /\$(?:NPM_TOKEN\b|\{\s*NPM_TOKEN(?:\s*(?::?[-=?])[^}\r\n]{0,256})?\s*\})/g;
const SHELL_VARIABLE_EXPANSION = /\$(?:\{\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s*(?::?[-=?])[^}\r\n]{0,256})?\s*\}|([A-Za-z_][A-Za-z0-9_]*))/g;
const SHELL_NPMRC_READ = /(?:\b(?:cat|head|tail|sed|awk)\b[^\r\n;|&]{0,512}|(?:<|@)[^\r\n;|&]{0,512})(?:\.npmrc(?![A-Za-z0-9_.\\/\-])|\$(?:\{\s*npm_config_userconfig\s*\}|npm_config_userconfig\b))/gi;

interface ShellLexicalInfo {
  executable: Uint8Array;
  expandableDollar: Uint8Array;
}

interface ShellExecutionContext {
  kind: "paren" | "backtick";
  outerQuote: "'" | '"' | undefined;
  depth: number;
}

function shellLexicalInfo(content: string): ShellLexicalInfo {
  const executable = new Uint8Array(content.length);
  const expandableDollar = new Uint8Array(content.length);
  const contexts: ShellExecutionContext[] = [];
  let quote: "'" | '"' | undefined;

  for (let index = 0; index < content.length; index++) {
    executable[index] = contexts.length > 0 || quote === undefined ? 1 : 0;
    const char = content[index]!;
    if (char === "\\" && quote !== "'") {
      if (index + 1 < content.length) {
        executable[index + 1] = executable[index];
        index++;
      }
      continue;
    }
    if (char === "$" && quote !== "'") expandableDollar[index] = 1;

    if (quote === "'") {
      if (char === "'") quote = undefined;
      continue;
    }
    if (quote === '"') {
      if (char === '"') {
        quote = undefined;
        continue;
      }
      if (char !== "`" && !(char === "$" && content[index + 1] === "(")) continue;
    }

    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "`" || (char === "$" && content[index + 1] === "(")) {
      const kind = char === "`" ? "backtick" : "paren";
      contexts.push({ kind, outerQuote: quote, depth: 1 });
      quote = undefined;
      if (kind === "paren") {
        if (index + 1 < content.length) executable[index + 1] = 1;
        index++;
      }
      continue;
    }

    const context = contexts.at(-1);
    if (!context || quote !== undefined) continue;
    if (context.kind === "backtick" && char === "`") {
      quote = contexts.pop()!.outerQuote;
    } else if (context.kind === "paren") {
      if (char === "(") context.depth++;
      else if (char === ")" && --context.depth === 0) {
        quote = contexts.pop()!.outerQuote;
      }
    }
  }
  return { executable, expandableDollar };
}

function collectShellFunctionScopes(
  content: string,
  lexical: ShellLexicalInfo,
): ShellFunctionScope[] {
  const braceStack: number[] = [];
  const bracePairs = new Map<number, number>();
  for (let index = 0; index < content.length; index++) {
    if (lexical.executable[index] !== 1) continue;
    if (content[index] === "{") {
      braceStack.push(index);
    } else if (content[index] === "}") {
      const open = braceStack.pop();
      if (open !== undefined) bracePairs.set(open, index);
    }
  }

  const scopes: ShellFunctionScope[] = [];
  const declaration = /(?:^|[;{}\n\r])\s*(?:(?:function[ \t]+[A-Za-z_][A-Za-z0-9_]*(?:[ \t]*\(\s*\))?)|(?:[A-Za-z_][A-Za-z0-9_]*[ \t]*\(\s*\)))[ \t]*\{/g;
  let event: RegExpExecArray | null;
  while ((event = declaration.exec(content)) !== null) {
    const open = event.index + event[0].lastIndexOf("{");
    if (lexical.executable[open] !== 1) continue;
    const end = bracePairs.get(open);
    if (end === undefined) continue;
    scopes.push({ start: open + 1, end });
  }

  scopes.sort((left, right) => left.start - right.start || right.end - left.end);
  const active: ShellFunctionScope[] = [];
  for (const scope of scopes) {
    while (active.length > 0 && active.at(-1)!.end <= scope.start) active.pop();
    scope.parent = active.at(-1);
    active.push(scope);
  }
  return scopes;
}

function shellScopeOwnersAtPositions(
  scopes: readonly ShellFunctionScope[],
  positions: readonly number[],
): Array<ShellFunctionScope | undefined> {
  const active: ShellFunctionScope[] = [];
  const owners: Array<ShellFunctionScope | undefined> = [];
  let scopeIndex = 0;
  for (const position of positions) {
    while (scopeIndex < scopes.length && scopes[scopeIndex]!.start <= position) {
      const scope = scopes[scopeIndex++]!;
      while (active.length > 0 && active.at(-1)!.end <= scope.start) active.pop();
      active.push(scope);
    }
    while (active.length > 0 && active.at(-1)!.end <= position) active.pop();
    owners.push(active.at(-1));
  }
  return owners;
}

function addShellCredentialState(
  histories: Map<string, ShellCredentialHistory>,
  variable: string,
  state: ShellCredentialState,
): void {
  const history = histories.get(variable) ?? {
    global: [],
    scoped: new Map<ShellFunctionScope, ShellCredentialState[]>(),
  };
  if (state.scope === undefined) {
    history.global.push(state);
  } else {
    const states = history.scoped.get(state.scope) ?? [];
    states.push(state);
    history.scoped.set(state.scope, states);
  }
  histories.set(variable, history);
}

function latestVisibleShellState(
  history: ShellCredentialHistory | undefined,
  target: number,
  scope: ShellFunctionScope | undefined,
): ShellCredentialState | undefined {
  if (!history) return undefined;
  let latest = latestBefore(history.global, target);
  for (let current = scope; current; current = current.parent) {
    const scoped = latestBefore(history.scoped.get(current), target);
    if (scoped && (!latest || scoped.position > latest.position)) latest = scoped;
  }
  return latest;
}

interface ShellVariableReference {
  variable: string;
  dollar: number;
}

function simpleShellVariableReference(
  rhs: string,
  absoluteStart: number,
  lexical: ShellLexicalInfo,
): ShellVariableReference | undefined {
  let start = 0;
  let end = rhs.length;
  while (start < end && /\s/.test(rhs[start]!)) start++;
  while (end > start && /\s/.test(rhs[end - 1]!)) end--;
  if (rhs.charCodeAt(start) === 39) return undefined;
  if (rhs[start] === '"') {
    if (rhs[end - 1] !== '"') return undefined;
    start++;
    end--;
  }

  const value = rhs.slice(start, end);
  SHELL_VARIABLE_EXPANSION.lastIndex = 0;
  const expansion = SHELL_VARIABLE_EXPANSION.exec(value);
  if (!expansion || expansion.index !== 0 || expansion[0].length !== value.length) {
    return undefined;
  }
  const dollar = absoluteStart + start;
  if (lexical.expandableDollar[dollar] !== 1) return undefined;
  return { variable: expansion[1] ?? expansion[2]!, dollar };
}
function shellSignalStarts(
  value: string,
  absoluteStart: number,
  lexical: ShellLexicalInfo,
): number[] {
  const starts: number[] = [];
  const collect = (regex: RegExp): void => {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(value)) !== null) {
      const dollar = match[0].indexOf("$");
      const absoluteDollar = dollar === -1 ? -1 : absoluteStart + match.index + dollar;
      if (absoluteDollar !== -1 && lexical.expandableDollar[absoluteDollar] !== 1) continue;
      starts.push(absoluteStart + match.index);
    }
  };
  collect(SHELL_NPM_TOKEN);
  collect(SHELL_NPMRC_READ);
  return [...new Set(starts)].sort((left, right) => left - right);
}

function shellSignalStart(
  value: string,
  absoluteStart: number,
  lexical: ShellLexicalInfo,
): number | undefined {
  return shellSignalStarts(value, absoluteStart, lexical)[0];
}

function shellAssignmentRhsEnd(
  content: string,
  start: number,
  lexical: ShellLexicalInfo,
): number {
  let parentheses = 0;
  let inBacktick = false;
  for (let index = start; index < content.length; index++) {
    if (lexical.executable[index] !== 1) continue;
    const char = content[index]!;
    if (char === "`") {
      inBacktick = !inBacktick;
      continue;
    }
    if (inBacktick) continue;
    if (char === "(") {
      parentheses++;
    } else if (char === ")") {
      if (parentheses === 0) return index;
      parentheses--;
    } else if (
      parentheses === 0 &&
      (char === ";" || char === "&" || char === "|" || char === "\n" || char === "\r")
    ) {
      return index;
    }
  }
  return content.length;
}

function collectShellCredentialAssignments(
  semanticMask: string,
  lexical: ShellLexicalInfo,
  scopes: readonly ShellFunctionScope[],
): Map<string, ShellCredentialHistory> {
  interface AssignmentCandidate {
    position: number;
    variable: string;
    rhsStart: number;
    rhsEnd: number;
  }

  const candidates: AssignmentCandidate[] = [];
  const assignment = /(?:^|[;&|{}()\n\r`])\s*(?:(?:export|local|readonly|declare|typeset)(?:[ \t]+-{1,2}[A-Za-z]+)*[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*/g;
  let event: RegExpExecArray | null;
  while ((event = assignment.exec(semanticMask)) !== null) {
    const variable = event[1]!;
    const equals = event.index + event[0].lastIndexOf("=");
    const variablePosition = event.index + event[0].lastIndexOf(variable, event[0].lastIndexOf("="));
    if (lexical.executable[variablePosition] !== 1) continue;
    const rhsStart = equals + 1;
    candidates.push({
      position: variablePosition,
      variable,
      rhsStart,
      rhsEnd: shellAssignmentRhsEnd(semanticMask, rhsStart, lexical),
    });
  }

  const owners = shellScopeOwnersAtPositions(
    scopes,
    candidates.map((candidate) => candidate.position),
  );
  const histories = new Map<string, ShellCredentialHistory>();
  for (let index = 0; index < candidates.length; index++) {
    const candidate = candidates[index]!;
    const rhs = semanticMask.slice(candidate.rhsStart, candidate.rhsEnd);
    let sourceStart = shellSignalStart(rhs, candidate.rhsStart, lexical);
    if (sourceStart === undefined) {
      const alias = simpleShellVariableReference(rhs, candidate.rhsStart, lexical);
      if (alias) {
        const state = latestVisibleShellState(
          histories.get(alias.variable),
          candidate.position,
          owners[index],
        );
        if (state?.qualified && state.sourceStart !== undefined) {
          sourceStart = state.sourceStart;
        }
      }
    }
    addShellCredentialState(histories, candidate.variable, {
      position: candidate.position,
      qualified: sourceStart !== undefined,
      sourceStart,
      scope: owners[index],
    });
  }
  return histories;
}

function shellPipelineSourceStart(
  logicalMask: string,
  commandStart: number,
  commandName: string,
  commandText: string,
  lexical: ShellLexicalInfo,
): number | undefined {
  const consumesStdin = commandName === "curl"
    ? /(?:^|\s)(?:(?:--data|--data-binary|-d)(?:\s+|\s*=\s*)@-|(?:--upload-file|-T)(?:\s+|\s*=\s*)-)(?=\s|$)/.test(commandText)
    : /(?:^|\s)--post-file(?:\s+|\s*=\s*)-(?=\s|$)/.test(commandText);
  if (!consumesStdin) return undefined;

  let segmentStart = commandStart;
  while (segmentStart > 0) {
    const previous = logicalMask[segmentStart - 1]!;
    if (previous === ";" || previous === "&" || previous === "\n" || previous === "\r") break;
    segmentStart--;
  }
  const prefix = logicalMask.slice(segmentStart, commandStart);
  const pipe = prefix.lastIndexOf("|");
  if (pipe === -1) return undefined;
  return shellSignalStart(prefix.slice(0, pipe), segmentStart, lexical);
}

function shellSourceIsOutputOnly(
  commandName: string,
  commandText: string,
  relativeSource: number,
): boolean {
  const before = commandText.slice(0, relativeSource);
  const optionalOpeningQuote = `["']?`;
  if (commandName === "curl") {
    return new RegExp(
      `(?:^|\\s)(?:-o|--output|--output-dir|-w|--write-out|--stderr|--trace|--trace-ascii|-D|--dump-header)(?:\\s+|\\s*=\\s*)${optionalOpeningQuote}$`,
    ).test(before);
  }
  return new RegExp(
    `(?:^|\\s)(?:-O|--output-document|-o|--output-file|-a|--append-output|--directory-prefix)(?:\\s+|\\s*=\\s*)${optionalOpeningQuote}$`,
  ).test(before);
}

/** Shell-specific source-to-curl/wget flow, path-gated by its own PatternEntry. */
const shaiHuludShellCredentialStealMatcher: CorrelatedPatternMatcher = (content) => {
  if (
    !NPM_CREDENTIAL_SOURCE_SIGNAL.test(content) ||
    !/\b(?:curl|wget)\b/.test(content)
  ) {
    return [];
  }

  const semanticMask = maskLexical(content, "mixed", false);
  const logicalMask = semanticMask.replace(/\\(?:\r\n|\n|\r)/g, (continuation) =>
    " ".repeat(continuation.length),
  );
  const lexical = shellLexicalInfo(logicalMask);
  const scopes = collectShellFunctionScopes(logicalMask, lexical);
  const assignments = collectShellCredentialAssignments(
    logicalMask,
    lexical,
    scopes,
  );
  const results: CorrelatedPatternMatch[] = [];
  const command = /(?:^|[;&|\n(`])\s*(?:(?:if|then|do|sudo|env|command|nohup)\s+)*(curl|wget)\b[^\r\n]*/g;
  const commands: RegExpExecArray[] = [];
  let event: RegExpExecArray | null;
  while ((event = command.exec(logicalMask)) !== null) commands.push(event);
  const commandStarts = commands.map(
    (candidate) => candidate.index + candidate[0].indexOf(candidate[1]!),
  );
  const commandScopes = shellScopeOwnersAtPositions(scopes, commandStarts);

  for (let commandIndex = 0; commandIndex < commands.length; commandIndex++) {
    event = commands[commandIndex]!;
    const commandName = event[1]!;
    const commandStart = commandStarts[commandIndex]!;
    if (lexical.executable[commandStart] !== 1) continue;
    const commandEnd = event.index + event[0].length;
    const commandText = logicalMask.slice(commandStart, commandEnd);
    let sourceStart = shellSignalStarts(commandText, commandStart, lexical).find(
      (candidate) => !shellSourceIsOutputOnly(
        commandName,
        commandText,
        candidate - commandStart,
      ),
    );
    if (sourceStart === undefined) {
      sourceStart = shellPipelineSourceStart(
        logicalMask,
        commandStart,
        commandName,
        commandText,
        lexical,
      );
    }

    if (sourceStart === undefined) {
      SHELL_VARIABLE_EXPANSION.lastIndex = 0;
      let use: RegExpExecArray | null;
      while ((use = SHELL_VARIABLE_EXPANSION.exec(commandText)) !== null) {
        const absoluteUse = commandStart + use.index;
        if (lexical.expandableDollar[absoluteUse] !== 1) continue;
        if (shellSourceIsOutputOnly(commandName, commandText, use.index)) continue;
        const variable = use[1] ?? use[2]!;
        const state = latestVisibleShellState(
          assignments.get(variable),
          commandStart,
          commandScopes[commandIndex],
        );
        if (state?.qualified && state.sourceStart !== undefined) {
          sourceStart = state.sourceStart;
          break;
        }
      }
    }

    if (sourceStart !== undefined) {
      results.push(correlation(content, sourceStart, commandEnd));
    }
  }
  return results;
};/** One authoritative rule with linear program-language and shell branches. */
const shaiHuludCredentialStealMatcher: CorrelatedPatternMatcher = (content) => {
  if (!hasShaiHuludCredentialFlowSignals(content)) return [];
  const results = [
    ...shaiHuludProgramCredentialStealMatcher(content),
    ...shaiHuludShellCredentialStealMatcher(content),
  ];
  const emitted = new Set<string>();
  return results
    .filter((match) => {
      const key = `${match.start}:${match.end}`;
      if (emitted.has(key)) return false;
      emitted.add(key);
      return true;
    })
    .sort((left, right) => left.start - right.start || left.end - right.end);
};
type CorrelatedRule =
  | "PYPI_B64_EXEC_COMBINED"
  | "PYPI_CUSTOM_INSTALL"
  | "PYPI_CUSTOM_DEVELOP"
  | "PYPI_CUSTOM_EGG_INFO"
  | "PYPI_CUSTOM_SDIST"
  | "PYPI_CUSTOM_BUILD_EXT"
  | "SHAI_HULUD_CRED_STEAL"
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
  SHAI_HULUD_CRED_STEAL: shaiHuludCredentialStealMatcher,
  PROTESTWARE_IP_GEO_V2: protestwareGeoMatcher,
  PROXY_HANDLER_TRAP: proxyHandlerMatcher,
  DROPPER_TEMP_EXEC: dropperTempExecMatcher,
} as const satisfies Record<CorrelatedRule, CorrelatedPatternMatcher>;