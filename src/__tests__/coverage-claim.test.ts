import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
// @ts-expect-error - plain ESM build script, no type declarations
import { ecosystemsWithData, renderList, load } from "../../scripts/generate-coverage-table.mjs";

const ROOT = path.join(__dirname, "..", "..");

// The "N ecosystems" claim counts only ecosystems whose indicators actually
// ship. A tested matcher with nothing to match is named separately and never
// inside that number.
describe("ecosystem coverage claim", () => {
  const coverage = {
    ecosystems: [
      { id: "a", label: "Alpha", prefixes: ["alpha"] },
      { id: "b", label: "Beta", prefixes: ["beta"] },
      { id: "n", label: "npm", prefixes: [""] },
    ],
  };

  it("counts an ecosystem only when the bundle or the catalog carries an indicator", () => {
    const split = ecosystemsWithData(coverage, ["alpha:x@1"], ["left-pad-evil"]);
    expect(split.withData.map((e: { id: string }) => e.id)).toEqual(["a", "n"]);
    expect(split.without.map((e: { id: string }) => e.id)).toEqual(["b"]);
  });

  it("does not count a prefixed entry as npm", () => {
    const split = ecosystemsWithData(coverage, ["alpha:x@1"], []);
    expect(split.without.map((e: { id: string }) => e.id)).toEqual(["b", "n"]);
  });

  it("writes the matcher-only count without the word the claims gate reads", () => {
    const text = renderList(coverage, ["alpha:x@1"], []);
    expect(text.match(/(\d+)\s+ecosystems\b/gi)).toEqual(["1 ecosystems"]);
    expect(text).toContain("for 2 more: Beta and npm.");
  });

  // An ecosystem whose only indicators need a format no current tool writes
  // (Homebrew: the legacy Brewfile.lock.json) ships data but is not covered.
  it("lists a limited ecosystem separately and never counts it", () => {
    const limitedCoverage = {
      ecosystems: [
        { id: "a", label: "Alpha", prefixes: ["alpha"] },
        { id: "h", label: "Homebrew", prefixes: ["homebrew"], limitation: "needs a legacy lock file" },
      ],
    };
    const split = ecosystemsWithData(limitedCoverage, ["alpha:x", "homebrew:t/f@1.0"], []);
    expect(split.withData.map((e: { id: string }) => e.id)).toEqual(["a"]);
    expect(split.limited.map((e: { id: string }) => e.id)).toEqual(["h"]);
    const text = renderList(limitedCoverage, ["alpha:x", "homebrew:t/f@1.0"], []);
    expect(text.match(/(\d+)\s+ecosystems\b/gi)).toEqual(["1 ecosystems"]);
    expect(text).toContain("Homebrew has a tested matcher and ships an indicator, but is not counted: needs a legacy lock file.");
  });

  it("agrees on the real data: count script, generated README list and advertised claim", () => {
    const { coverage: real, bundleValues, catalogValues } = load();
    const shipped = ecosystemsWithData(real, bundleValues, catalogValues).withData.length;

    const counted = execFileSync(process.execPath, [path.join(ROOT, "scripts", "count-ecosystems.mjs")], {
      cwd: ROOT,
      encoding: "utf8",
    });
    expect(Number(counted)).toBe(shipped);

    const readme = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
    expect(readme).toContain(`Known-malicious indicators ship for ${shipped} ecosystems:`);

    const config = JSON.parse(fs.readFileSync(path.join(ROOT, "aahp.config.json"), "utf8"));
    const claim = config.claims.find((c: { id: string }) => c.id === "ecosystem count");
    expect(claim.advertised).toBe(shipped);
  });
});
