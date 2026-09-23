import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import * as entropy from "../entropy.js";
import { analyzeEntropy } from "../entropy.js";
import { performanceBudget } from "./performance-budget.js";

const B64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Every base64 symbol equally often, so entropy sits at the 6.0 ceiling. */
function uniformBase64(length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += B64[(i * 37) % 64];
  return out;
}

const PAYLOAD = uniformBase64(640);
const rules = (content: string, file = "src/logo.ts") =>
  analyzeEntropy(content, file).map((finding) => finding.rule);

describe("HIGH_ENTROPY_STRING data URI exemption", () => {
  it.each([
    ["image/png", `export const LOGO = "data:image/png;base64,${PAYLOAD}";\n`],
    ["font/woff2", `@font-face { src: url(data:font/woff2;base64,${PAYLOAD}); }\n`],
    ["application/font-woff (legacy)", `@font-face { src: url(data:application/font-woff;base64,${PAYLOAD}); }\n`],
    ["application/x-font-ttf (legacy)", `@font-face { src: url(data:application/x-font-ttf;base64,${PAYLOAD}); }\n`],
  ])("an inlined %s data URI produces no entropy finding at any severity", (_type, content) => {
    expect(rules(content)).toEqual([]);
  });

  it("still reports a payload that merely sits on the same line as an image data URI", () => {
    const content =
      `const a = "data:image/png;base64,${PAYLOAD}"; const b = "${uniformBase64(200)}";\n`;
    expect(rules(content)).toContain("HIGH_ENTROPY_STRING");
  });

  it("reports a bare 200-character base64 string at high", () => {
    const content = `${"// padding line\n".repeat(40)}const P = "${uniformBase64(200)}";\n`;
    const found = analyzeEntropy(content, "src/p.ts")
      .filter((finding) => finding.rule === "HIGH_ENTROPY_STRING");
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe("high");
  });

  // image/svg+xml is a document that can carry script, so it is not exempt.
  it.each(["text/javascript", "application/octet-stream", "image/svg+xml"])(
    "reports a %s data URI in the per-string pass",
    (type) => {
      const content = `const s = "data:${type};base64,${PAYLOAD}";\n`;
      expect(rules(content)).toContain("HIGH_ENTROPY_STRING");
    },
  );

  it.each(["text/javascript", "application/octet-stream"])(
    "no longer hides a %s data URI from the file-level pass",
    (type) => {
      // The file is almost entirely the payload, so only an exemption keeps it
      // below the file threshold. Before the shared exemption every media type
      // was stripped here.
      const content = `s="data:${type};base64,${PAYLOAD}"\n`;
      expect(rules(content)).toContain("HIGH_ENTROPY_FILE");
    },
  );

  it("shares one exemption function between the file-level and per-string passes", () => {
    const strip = (entropy as Record<string, unknown>).stripExemptDataUris;
    expect(typeof strip).toBe("function");
    const fn = strip as (content: string) => string;
    expect(fn(`x "data:image/png;base64,${PAYLOAD}" y`)).toBe(`x "" y`);
    expect(fn(`x "data:font/ttf;base64,${PAYLOAD}" y`)).toBe(`x "" y`);
    const js = `x "data:text/javascript;base64,${PAYLOAD}" y`;
    expect(fn(js)).toBe(js);
    // The replacement never removes a newline, so line numbers stay exact.
    const twoLines = `a "data:image/png;base64,${PAYLOAD}"\nb`;
    expect(fn(twoLines).split("\n")).toHaveLength(2);
  });

  it("keeps the exemption linear on a 5 MiB adversarial line", { timeout: performanceBudget(20_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const unit = "data:image/png;base64data:image/";
    const content = unit.repeat(Math.ceil(fiveMiB / unit.length)).slice(0, fiveMiB);
    const started = performance.now();
    analyzeEntropy(content, "src/big.js");
    expect(performance.now() - started).toBeLessThan(performanceBudget(5_000));
  });
});
