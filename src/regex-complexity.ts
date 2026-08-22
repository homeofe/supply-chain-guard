/**
 * Return whether a regular-expression source contains an explicitly broad,
 * unbounded consuming gap.
 *
 * This is intentionally a conservative static classifier, not a complete
 * regular-expression parser. It recognizes only the release-invariant forms
 * that are unambiguously broad (`.*`, `.+`, quantified negated classes,
 * shorthand-complement classes, and equivalent unbounded group wrappers).
 * It does not attempt to prove general regular-expression complexity.
 */
export function hasBroadUnboundedConsumingGap(source: string): boolean {
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];

    // The next code unit is escaped, so it cannot open a class or be a
    // wildcard/quantifier token at this level.
    if (character === "\\") {
      index += 1;
      continue;
    }

    if (character === "[") {
      const classEnd = findCharacterClassEnd(source, index);
      if (classEnd === -1) {
        break;
      }

      if (hasUnboundedQuantifierAt(source, classEnd + 1)) {
        const bodyStart = index + 1;
        const isNegated = source[bodyStart] === "^";
        if (
          isNegated ||
          hasComplementaryShorthandPair(source, bodyStart, classEnd)
        ) {
          return true;
        }
      }

      index = classEnd;
      continue;
    }

    if (character === "(") {
      const groupEnd = findGroupEnd(source, index);
      if (groupEnd === -1) {
        break;
      }
      if (
        hasUnboundedQuantifierAt(source, groupEnd + 1) &&
        groupContainsBroadConsumer(source, index + 1, groupEnd)
      ) {
        return true;
      }
      continue;
    }

    if (
      character === "." &&
      hasUnboundedQuantifierAt(source, index + 1)
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Return whether a regular-expression source quantifies a group that already
 * contains a variable quantifier, for example `(a+)+`, `(a*)*` or `(a?)+`.
 *
 * That shape is what makes a non-matching input take exponential time to fail:
 * the engine can partition the same characters between the inner and the outer
 * quantifier in exponentially many ways, and it tries all of them before
 * reporting no match. A pattern of 8 characters is enough to occupy a CPU for
 * minutes.
 *
 * Like `hasBroadUnboundedConsumingGap` this is a conservative static
 * classifier, not a proof of complexity. It answers ONE question, and the two
 * ways it is wrong both matter to a caller.
 *
 * It OVER-rejects. A fixed repetition such as `{2}` is not treated as variable
 * (it has exactly one way to match, so it cannot create the ambiguity), but
 * `(x{2,3})+` is refused even though its blow-up is milder than `(x+)+`. More
 * importantly it refuses the ordinary domain-chain shape
 * `(?:[a-z0-9-]+\.)+corp\.example`, which is linear in practice because the
 * inner class cannot match the separator, and which is how most people write an
 * internal hostname. `[a-z0-9.-]+\.corp\.example` is the accepted rewrite.
 *
 * It also UNDER-rejects, and this is the half a reader must not assume away: a
 * `false` here is NOT a certificate that the source is safe to run. Ambiguity
 * that comes from overlapping alternation is invisible to it, so `(a|a)+$`,
 * `(a|ab)+$` and `(\d|\d\d)+$` are all accepted and all catastrophic; so is a
 * bounded outer repetition such as `(a+){2,30}$`, because `{n,m}` is not read
 * as unbounded. Measured, `/(a|a)+$/` against a non-matching line of 27
 * characters spends about 16 seconds in one `exec`. Deciding this properly
 * needs the NFA, not a scan of the source, so callers must not rely on a
 * `false` as a time bound. Tracked on
 * https://github.com/homeofe/supply-chain-guard/issues/169.
 *
 * Callers use it where a refusal is reported as a visible finding and the
 * author can rewrite the entry, never to silently drop input.
 */
export function hasNestedUnboundedQuantifier(source: string): boolean {
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];

    if (character === "\\") {
      index += 1;
      continue;
    }

    if (character === "[") {
      const classEnd = findCharacterClassEnd(source, index);
      if (classEnd === -1) break;
      index = classEnd;
      continue;
    }

    if (character === "(") {
      const groupEnd = findGroupEnd(source, index);
      if (groupEnd === -1) break;
      if (
        hasUnboundedQuantifierAt(source, groupEnd + 1) &&
        containsVariableQuantifier(source, groupBodyStart(source, index), groupEnd)
      ) {
        return true;
      }
      // Fall through into the group rather than skipping past it: an accepted
      // outer group can still hold the offending pair deeper down.
      continue;
    }
  }

  return false;
}

/**
 * First offset of a group's body. `(?:`, `(?=`, `(?!`, `(?<=`, `(?<!` and
 * `(?<name>` all open a group, and the `?` in them is a prefix, not a
 * quantifier. Reading it as one would refuse every grouped alternation anybody
 * writes.
 */
function groupBodyStart(source: string, groupStart: number): number {
  if (source[groupStart + 1] !== "?") return groupStart + 1;

  const marker = source[groupStart + 2];
  if (marker === ":" || marker === "=" || marker === "!") return groupStart + 3;
  if (marker === "<") {
    const lookbehind = source[groupStart + 3];
    if (lookbehind === "=" || lookbehind === "!") return groupStart + 4;
    const nameEnd = source.indexOf(">", groupStart + 3);
    if (nameEnd !== -1) return nameEnd + 1;
  }
  return groupStart + 2;
}

/**
 * Whether a group body holds a quantifier that can match a variable number of
 * times.
 */
function containsVariableQuantifier(
  source: string,
  bodyStart: number,
  groupEnd: number,
): boolean {
  for (let index = bodyStart; index < groupEnd; index += 1) {
    const character = source[index];

    if (character === "\\") {
      index += 1;
      continue;
    }

    if (character === "[") {
      const classEnd = findCharacterClassEnd(source, index);
      if (classEnd === -1 || classEnd >= groupEnd) return false;
      index = classEnd;
      continue;
    }

    if (character === "(") {
      index = groupBodyStart(source, index) - 1;
      continue;
    }

    if (character === "*" || character === "+" || character === "?") return true;
    if (character === "{" && isVariableRepetitionAt(source, index)) return true;
  }

  return false;
}

/**
 * Whether `{...}` at this offset is a repetition with a variable count, that is
 * `{n,}` or `{n,m}`. A fixed `{n}` is excluded on purpose: it matches exactly n
 * times, so it adds no ambiguity for an outer quantifier to explore.
 */
function isVariableRepetitionAt(source: string, index: number): boolean {
  if (source[index] !== "{") return false;

  let cursor = index + 1;
  const minimumStart = cursor;
  while (isDigitAt(source, cursor)) cursor += 1;
  if (cursor === minimumStart || source[cursor] !== ",") return false;

  cursor += 1;
  if (source[cursor] === "}") return true;

  const maximumStart = cursor;
  while (isDigitAt(source, cursor)) cursor += 1;
  return cursor !== maximumStart && source[cursor] === "}";
}

function isDigitAt(source: string, index: number): boolean {
  const code = source.charCodeAt(index);
  return code >= 48 && code <= 57;
}

function hasUnboundedQuantifierAt(source: string, index: number): boolean {
  const token = source[index];
  if (token === "*" || token === "+") return true;
  if (token !== "{") return false;

  let cursor = index + 1;
  const minimumStart = cursor;
  while (
    cursor < source.length &&
    source.charCodeAt(cursor) >= 48 &&
    source.charCodeAt(cursor) <= 57
  ) {
    cursor += 1;
  }
  if (cursor === minimumStart || source[cursor] !== ",") return false;
  cursor += 1;
  return source[cursor] === "}";
}

function findGroupEnd(source: string, groupStart: number): number {
  let depth = 1;

  for (let index = groupStart + 1; index < source.length; index += 1) {
    if (source[index] === "\\") {
      index += 1;
      continue;
    }
    if (source[index] === "[") {
      const classEnd = findCharacterClassEnd(source, index);
      if (classEnd === -1) return -1;
      index = classEnd;
      continue;
    }
    if (source[index] === "(") {
      depth += 1;
    } else if (source[index] === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }

  return -1;
}

function groupContainsBroadConsumer(
  source: string,
  bodyStart: number,
  groupEnd: number,
): boolean {
  const shorthands = new Set<string>();
  let hasAlternation = false;

  for (let index = bodyStart; index < groupEnd; index += 1) {
    const character = source[index];
    if (character === "\\") {
      const escaped = source[index + 1];
      if (
        escaped === "s" ||
        escaped === "S" ||
        escaped === "d" ||
        escaped === "D" ||
        escaped === "w" ||
        escaped === "W"
      ) {
        shorthands.add(escaped);
      }
      index += 1;
      continue;
    }
    if (character === "[") {
      const classEnd = findCharacterClassEnd(source, index);
      if (classEnd === -1) return false;
      const classBodyStart = index + 1;
      if (
        source[classBodyStart] === "^" ||
        hasComplementaryShorthandPair(source, classBodyStart, classEnd)
      ) {
        return true;
      }
      index = classEnd;
      continue;
    }
    if (character === ".") return true;
    if (character === "|") hasAlternation = true;
  }

  return hasAlternation && hasComplementaryShorthands(shorthands);
}

function findCharacterClassEnd(source: string, classStart: number): number {
  for (let index = classStart + 1; index < source.length; index += 1) {
    if (source[index] === "\\") {
      index += 1;
      continue;
    }
    if (source[index] === "]") {
      return index;
    }
  }

  return -1;
}

function hasComplementaryShorthandPair(
  source: string,
  bodyStart: number,
  classEnd: number,
): boolean {
  const shorthands = new Set<string>();

  for (let index = bodyStart; index < classEnd; index += 1) {
    if (source[index] !== "\\") {
      continue;
    }

    const escaped = source[index + 1];
    if (
      escaped === "s" ||
      escaped === "S" ||
      escaped === "d" ||
      escaped === "D" ||
      escaped === "w" ||
      escaped === "W"
    ) {
      shorthands.add(escaped);
    }
    index += 1;
  }

  return hasComplementaryShorthands(shorthands);
}

function hasComplementaryShorthands(shorthands: ReadonlySet<string>): boolean {
  return (
    (shorthands.has("s") && shorthands.has("S")) ||
    (shorthands.has("d") && shorthands.has("D")) ||
    (shorthands.has("w") && shorthands.has("W"))
  );
}
