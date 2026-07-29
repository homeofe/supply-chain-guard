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
