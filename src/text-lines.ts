/**
 * Linear-time text helpers for manifest parsers.
 *
 * Every input here is attacker-controlled and may be up to MAX_FILE_SIZE.
 * Counting newlines from offset 0 for each hit, or stripping comments with
 * /\s+#.*$/ (which backtracks over every whitespace run that is not followed
 * by "#"), made a crafted 1-5 MB manifest take minutes to hours. These helpers
 * are linear in the input (line lookups are a binary search over newline
 * offsets computed once per text).
 */

let cachedText: string | undefined;
let cachedStarts: number[] = [];

/** Offsets at which each line starts, computed once per distinct text. */
function lineStarts(text: string): number[] {
  if (text === cachedText) return cachedStarts;
  const starts = [0];
  for (let i = text.indexOf("\n"); i >= 0; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  cachedText = text;
  cachedStarts = starts;
  return starts;
}

/** 1-based line number of a character offset. */
export function lineAtOffset(text: string, offset: number): number {
  const starts = lineStarts(text);
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/** 1-based line of the first occurrence of `needle`, else 1. */
export function lineOfNeedle(text: string, needle: string): number {
  const idx = text.indexOf(needle);
  return idx < 0 ? 1 : lineAtOffset(text, idx);
}

/**
 * Blank every closed XML comment, keeping newlines so offsets and line numbers
 * survive. `/<!--[\s\S]*?-->/g` rescans to the end of the text from every
 * "<!--" that has no "-->", which took 30 s on 313 KB of them; this walks the
 * text once. An unclosed "<!--" is left as it is, as the regex left it.
 */
export function blankXmlComments(text: string): string {
  let out = "";
  let from = 0;
  for (let open = text.indexOf("<!--"); open >= 0; open = text.indexOf("<!--", from)) {
    const close = text.indexOf("-->", open + 4);
    if (close < 0) break;
    out += text.slice(from, open) + text.slice(open, close + 3).replace(/[^\n]/g, " ");
    from = close + 3;
  }
  return out + text.slice(from);
}

/**
 * Remove a trailing "  # comment" (a "#" preceded by whitespace) and the
 * whitespace before it. Same result as `line.replace(/\s+#.*$/, "")` on real
 * input, in linear time.
 */
export function stripHashComment(line: string): string {
  for (let i = line.indexOf("#"); i > 0; i = line.indexOf("#", i + 1)) {
    const prev = line.charCodeAt(i - 1);
    if (prev === 0x20 || prev === 0x09) return line.slice(0, i).trimEnd();
  }
  return line;
}
