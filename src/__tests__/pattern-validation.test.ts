import { describe, it, expect } from "vitest";
import { ALL_PATTERN_RULES } from "../patterns.js";
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

  it("exposes every rule id exactly once per entry", () => {
    expect(ALL_PATTERN_RULES.every((r) => typeof r === "string" && r.length > 0)).toBe(true);
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

  it("rejects an invalid regex loudly rather than silently disabling rules", () => {
    // Mirrors exactly what the load-time loop does. If this ever stops throwing,
    // the silent-blindness failure mode is back.
    const bad = "exec(";
    expect(() => new RegExp(bad, "g")).toThrow();

    const validate = (pattern: string, rule: string) => {
      try {
        new RegExp(pattern, "g");
      } catch (err) {
        throw new Error(
          `pattern for rule "${rule}" is not a valid regular expression: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
      if (pattern.length === 0) {
        throw new Error(`pattern for rule "${rule}" is empty`);
      }
    };

    expect(() => validate(bad, "BAD_RULE")).toThrow(/BAD_RULE.*not a valid regular expression/s);
    expect(() => validate("", "EMPTY_RULE")).toThrow(/EMPTY_RULE.*empty/s);
    expect(() => validate("\\bfetch\\s*\\(", "GOOD_RULE")).not.toThrow();
  });
});
