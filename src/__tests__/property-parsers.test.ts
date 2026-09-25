import { describe, it, expect } from "vitest";
import fc from "fast-check";

import {
  lineAtOffset,
  lineOfNeedle,
  blankXmlComments,
  stripHashComment,
  trimTrailing,
  trimLeading,
} from "../text-lines.js";
import { parseWorkflow, stripYamlComments } from "../workflow-ast.js";
import { isoToEpoch } from "../../scripts/feed-partition.mjs";

// Property-based tests for the code that reads attacker-controlled text.
//
// Every scanned manifest, lockfile and workflow is chosen by whoever wrote the
// repository being scanned, so these functions see adversarial input by design.
// The linear-time helpers in text-lines.ts each replaced a regex that went
// quadratic on crafted input, and each doc comment claims "same result as" that
// regex. An example-based test can only check the inputs someone thought of;
// these check the claim on thousands of generated ones, with the old regex as
// the oracle.
//
// The seed is fixed so a CI run is reproducible and a red build always names a
// failing input. To explore beyond it, run with SCG_FC_SEED=<n> (and raise
// SCG_FC_RUNS); a new counterexample then becomes a named regression case here.

const seed = Number(process.env.SCG_FC_SEED ?? 20260925);
const numRuns = Number(process.env.SCG_FC_RUNS ?? 1000);
const params = { seed, numRuns };

/** Text drawn from the characters these parsers actually branch on. */
const parserText = fc.string({
  unit: fc.constantFrom("a", "b", " ", "\t", "\n", "\r", "#", "<", "!", "-", ">", "x", ":"),
  maxLength: 200,
});
/** Anything at all, including astral and control characters. */
const anyText = fc.string({ unit: "binary", maxLength: 300 });

describe("text-lines: linear-time helpers agree with the regexes they replaced", () => {
  it("lineAtOffset equals the naive newline count for every offset", () => {
    fc.assert(
      fc.property(anyText, fc.nat(), (text, n) => {
        const offset = n % (text.length + 1);
        expect(lineAtOffset(text, offset)).toBe(text.slice(0, offset).split("\n").length);
      }),
      params,
    );
  });

  it("lineOfNeedle names the line of the first occurrence, or 1", () => {
    fc.assert(
      fc.property(parserText, parserText, (text, needle) => {
        const idx = text.indexOf(needle);
        const expected = idx < 0 ? 1 : text.slice(0, idx).split("\n").length;
        expect(lineOfNeedle(text, needle)).toBe(expected);
      }),
      params,
    );
  });

  it("blankXmlComments equals the regex it replaced, and preserves length and newlines", () => {
    const oracle = (t: string) => t.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
    fc.assert(
      fc.property(parserText, (text) => {
        const out = blankXmlComments(text);
        expect(out).toBe(oracle(text));
        expect(out.length).toBe(text.length);
        expect([...out].map((c, i) => c === "\n" || text[i] !== "\n")).not.toContain(false);
      }),
      params,
    );
  });

  it("stripHashComment: regression cases the property test found", () => {
    // Shrunk counterexample from the first run of the property below: a "#" in
    // column 0 ended the scan, so the trailing comment after it survived.
    expect(stripHashComment("#\t#")).toBe("#");
    expect(stripHashComment("#a #b")).toBe("#a");
    // Unchanged behaviour, as controls.
    expect(stripHashComment("image: x # pinned")).toBe("image: x");
    expect(stripHashComment("url: https://h/#frag")).toBe("url: https://h/#frag");
    expect(stripHashComment("#")).toBe("#");
  });

  it("stripHashComment equals line.replace(/[ \\t]+#.*$/, '') then trimEnd on space/tab text", () => {
    fc.assert(
      fc.property(
        fc.string({ unit: fc.constantFrom("a", "b", " ", "\t", "#", ":"), maxLength: 120 }),
        (line) => {
          const m = /[ \t]#/.exec(line);
          const expected = m ? line.slice(0, m.index + 1).trimEnd() : line;
          expect(stripHashComment(line)).toBe(expected);
        },
      ),
      params,
    );
  });

  it("trimTrailing and trimLeading equal the anchored regexes they replaced", () => {
    const chars = fc.string({ unit: fc.constantFrom("a", " ", "\t", "\n", ",", ";"), minLength: 1, maxLength: 3 });
    const esc = (s: string) => s.replace(/[\\\]^-]/g, "\\$&");
    fc.assert(
      fc.property(parserText, chars, (text, set) => {
        expect(trimTrailing(text, set)).toBe(text.replace(new RegExp(`[${esc(set)}]+$`), ""));
        expect(trimLeading(text, set)).toBe(text.replace(new RegExp(`^[${esc(set)}]+`), ""));
      }),
      params,
    );
  });
});

describe("workflow parser: total on arbitrary input", () => {
  it("parseWorkflow and stripYamlComments never throw, whatever the text", () => {
    fc.assert(
      fc.property(fc.oneof(anyText, parserText), (text) => {
        expect(() => stripYamlComments(text)).not.toThrow();
        expect(() => parseWorkflow(text)).not.toThrow();
      }),
      params,
    );
  });

  it("stripYamlComments never changes the number of lines", () => {
    fc.assert(
      fc.property(parserText, (text) => {
        expect(stripYamlComments(text).split("\n").length).toBe(text.split("\n").length);
      }),
      params,
    );
  });
});

describe("feed partition dates", () => {
  it("isoToEpoch round-trips every real calendar date", () => {
    fc.assert(
      fc.property(fc.date({ min: new Date("1970-01-01"), max: new Date("2099-12-31"), noInvalidDate: true }), (d) => {
        const iso = d.toISOString().slice(0, 10);
        expect(isoToEpoch(iso)).toBe(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
      }),
      params,
    );
  });

  it("isoToEpoch accepts nothing that is not exactly YYYY-MM-DD, and no rolled-over date", () => {
    // Date-shaped strings with any digits (month 13, day 31 in February, year 0)
    // alongside arbitrary text: random text alone almost never looks like a date.
    const pad = (n: number, w: number) => String(n).padStart(w, "0");
    const dateLike = fc
      .tuple(fc.integer({ min: 0, max: 9999 }), fc.integer({ min: 0, max: 99 }), fc.integer({ min: 0, max: 99 }))
      .map(([y, m, d]) => `${pad(y, 4)}-${pad(m, 2)}-${pad(d, 2)}`);
    fc.assert(
      fc.property(fc.oneof(anyText, dateLike), (text) => {
        const epoch = isoToEpoch(text);
        if (epoch !== null) {
          expect(text).toMatch(/^\d{4}-\d{2}-\d{2}$/);
          expect(new Date(epoch).toISOString().slice(0, 10)).toBe(text);
        }
      }),
      params,
    );
  });
});
