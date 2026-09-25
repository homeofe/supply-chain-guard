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
 * Remove a trailing "  # comment" (a "#" preceded by a space or tab, the YAML
 * and TOML rule) and the whitespace before it, in linear time. Same result as
 * `line.replace(/[ \t]+#.*$/, "")` followed by `trimEnd()`, which
 * property-parsers.test.ts checks on generated input.
 *
 * A "#" in column 0 is not a trailing comment, but it must not end the scan:
 * the loop used to stop there (`i > 0` as its condition), so "#a #b" came back
 * whole while the regex gives "#a". The property test found it.
 */
export function stripHashComment(line: string): string {
  for (let i = line.indexOf("#"); i >= 0; i = line.indexOf("#", i + 1)) {
    if (i === 0) continue;
    const prev = line.charCodeAt(i - 1);
    if (prev === 0x20 || prev === 0x09) return line.slice(0, i).trimEnd();
  }
  return line;
}

/**
 * Remove a trailing run of the given characters. Same result as
 * `text.replace(/[chars]+$/, "")`, in linear time: that regex restarts at every
 * run that is not at the end, so a long run followed by one other character
 * is quadratic.
 */
export function trimTrailing(text: string, chars: string | RegExp): string {
  const trims = typeof chars === "string" ? (ch: string) => chars.includes(ch) : (ch: string) => chars.test(ch);
  let end = text.length;
  while (end > 0 && trims(text[end - 1]!)) end--;
  return text.slice(0, end);
}

/** Remove a leading run of the given characters; see trimTrailing. */
export function trimLeading(text: string, chars: string): string {
  let start = 0;
  while (start < text.length && chars.includes(text[start]!)) start++;
  return text.slice(start);
}
