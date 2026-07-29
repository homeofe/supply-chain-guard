import { describe, it, expect } from "vitest";
import {
  ALL_PATTERN_RULES,
  ALL_PATTERN_SETS,
  MAX_SPANS_LINES,
  validatePatternSet,
} from "../patterns.js";
import { hasBroadUnboundedConsumingGap } from "../regex-complexity.js";
import * as fs from "node:fs";
import * as path from "node:path";

/**
 * A malformed regex in the pattern table used to be a SILENT, TOTAL loss of
 * content scanning.
 *
 * scanner.ts compiles `new RegExp(pattern.pattern, "g")` inside a per-file
 * `try { ... } catch { skip }`. One invalid pattern therefore threw on the first
 * file, was swallowed, and suppressed every content rule ordered after it, for
 * every file in the scan, while the process still exited 0. Measured before the
 * fix: a single invalid entry placed first took a scan from 21 findings to 1 and
 * reported success.
 *
 * patterns.ts now compiles every pattern at module load and throws. These tests
 * pin that behaviour.
 */
describe("pattern table validation", () => {
  it("compiles every shipped pattern", () => {
    // Importing the module at all runs the load-time validation. Reaching this
    // line means all of them compiled.
    expect(ALL_PATTERN_RULES.length).toBeGreaterThan(100);
  });

  it("exposes non-empty, globally unique core rule ids", () => {
    expect(ALL_PATTERN_RULES.every((rule) => rule.length > 0)).toBe(true);
    expect(new Set(ALL_PATTERN_RULES).size).toBe(ALL_PATTERN_RULES.length);
  });

  it("requires an exact structural matcher for every shipped multi-line rule", () => {
    const multiLine = ALL_PATTERN_SETS.flatMap(([, set]) =>
      set.filter((entry) => (entry.spansLines ?? 1) > 1),
    );

    expect(multiLine).toHaveLength(9);
    expect(multiLine.every((entry) => typeof entry.correlatedMatcher === "function")).toBe(true);
  });

  it("wires every shipped broad-gap regex to a structural matcher", () => {
    const broad = ALL_PATTERN_SETS.flatMap(([, set]) =>
      set.filter((entry) => hasBroadUnboundedConsumingGap(entry.pattern)),
    );

    expect(broad.length).toBeGreaterThan(40);
    expect(broad.every((entry) => typeof entry.correlatedMatcher === "function")).toBe(true);
    expect(
      ALL_PATTERN_SETS.flatMap(([, set]) => set).filter(
        (entry) =>
          entry.requiresInFile &&
          hasBroadUnboundedConsumingGap(entry.requiresInFile.source),
      ),
    ).toEqual([]);
  });

  it("registers every exported PatternEntry array for validation", () => {
    // The validation list is explicit so a new array cannot quietly skip it.
    // This test fails if someone exports a new pattern array without adding it.
    const source = fs.readFileSync(path.resolve(__dirname, "..", "patterns.ts"), "utf8");

    const exported = [...source.matchAll(/^export const ([A-Z_0-9]+): PatternEntry\[\]/gm)].map(
      (m) => m[1],
    );
    const registered = [
      ...source.matchAll(/^\s*\["([A-Z_0-9]+)", [A-Z_0-9]+\],$/gm),
    ].map((m) => m[1]);

    expect(exported.length).toBeGreaterThan(10);
    const missing = exported.filter((name) => !registered.includes(name));
    expect(missing, `unvalidated pattern arrays: ${missing.join(", ")}`).toEqual([]);
  });

  it("rejects invalid pattern metadata through the production validator", () => {
    expect(() =>
      validatePatternSet("TEST", [{ pattern: "exec(", rule: "BAD_RULE" }]),
    ).toThrow(/BAD_RULE.*not a valid regular expression/s);
    expect(() =>
      validatePatternSet("TEST", [{ pattern: "", rule: "EMPTY_RULE" }]),
    ).toThrow(/EMPTY_RULE.*empty/s);
    expect(() =>
      validatePatternSet("TEST", [{
        pattern: "foo.*bar",
        rule: "MISSING_MATCHER",
        spansLines: 2,
      }]),
    ).toThrow(/MISSING_MATCHER.*correlatedMatcher/s);
    expect(() =>
      validatePatternSet("TEST", [{
        pattern: "foo.*bar",
        rule: "SINGLE_LINE_BROAD",
      }]),
    ).toThrow(/SINGLE_LINE_BROAD.*broad.*correlatedMatcher/s);
    expect(() =>
      validatePatternSet("TEST", [{
        pattern: "foo.*bar",
        rule: "STRUCTURAL_BROAD",
        correlatedMatcher: () => [],
      }]),
    ).not.toThrow();
    expect(() =>
      validatePatternSet("TEST", [{
        pattern: "safe",
        rule: "BROAD_FILE_GUARD",
        requiresInFile: /foo.*bar/,
      }]),
    ).toThrow(/BROAD_FILE_GUARD.*requiresInFile.*requiresInFileMatcher/s);
    expect(() =>
      validatePatternSet("TEST", [{
        pattern: "safe",
        rule: "STRUCTURAL_FILE_GUARD",
        requiresInFileMatcher: (content) => content.includes("foo") && content.includes("bar"),
      }]),
    ).not.toThrow();
    expect(() =>
      validatePatternSet("TEST", [{
        pattern: "foo",
        rule: "OVER_CAP",
        spansLines: MAX_SPANS_LINES + 1,
      }]),
    ).toThrow(/OVER_CAP.*exceeds MAX_SPANS_LINES/s);
    expect(() =>
      validatePatternSet("TEST", [{ pattern: "\\bfetch\\s*\\(", rule: "GOOD_RULE" }]),
    ).not.toThrow();
  });
});
