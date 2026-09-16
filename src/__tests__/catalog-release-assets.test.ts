import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

const WORKFLOW = path.resolve(__dirname, "..", "..", ".github", "workflows", "ci.yml");
const ci = fs.readFileSync(WORKFLOW, "utf8");

/** The `release:` job body, from its key to the next top-level job key. */
const releaseJob = (() => {
  const start = ci.indexOf("\n  release:");
  expect(start).toBeGreaterThan(-1);
  const rest = ci.slice(start + 1);
  const next = rest.search(/\n {2}[a-z][a-z0-9-]*:\n/);
  return next === -1 ? rest : rest.slice(0, next);
})();

describe("the release job publishes the catalog assets", () => {
  it("builds them before creating the release", () => {
    const build = releaseJob.indexOf("node scripts/generate-catalog.mjs");
    const create = releaseJob.indexOf("gh release create");
    expect(build).toBeGreaterThan(-1);
    expect(create).toBeGreaterThan(-1);
    expect(build).toBeLessThan(create);
  });

  // ORDER WITHIN THE BUILD STEP IS THE WHOLE POINT. --check compares the
  // COMMITTED digest module against what the committed catalog produces. Run
  // after the generator has rewritten that file, it compares the generator's
  // output to itself and can never fail, so a release could ship a digest that
  // does not describe the assets beside it. Every client would then refuse the
  // download, and the anchor is compiled into the package, so it cannot be
  // corrected without a new version.
  it("verifies the committed digest BEFORE regenerating it", () => {
    const check = releaseJob.indexOf("node scripts/generate-catalog.mjs --check");
    expect(check).toBeGreaterThan(-1);

    const after = releaseJob.slice(check + "node scripts/generate-catalog.mjs --check".length);
    const generate = after.indexOf("node scripts/generate-catalog.mjs");
    expect(generate).toBeGreaterThan(-1);
  });

  it("attaches the index and every shard to the release", () => {
    expect(releaseJob).toContain("catalog-index.json");
    expect(releaseJob).toContain("catalog-*.json.gz");
  });

  // Releases on this repository are immutable, so there is no later step that
  // could attach a forgotten asset. The upload has to happen in the same
  // command that creates the release.
  it("uploads them in the create command, not a later step", () => {
    const create = releaseJob.indexOf("gh release create");
    const command = releaseJob.slice(create, releaseJob.indexOf("env:", create));
    expect(command).toContain("catalog-index.json");
    expect(command).toContain("catalog-*.json.gz");
  });

  it("gives the job a node it can run the generator with", () => {
    expect(releaseJob).toContain("actions/setup-node@");
  });

  // The generator must stay dependency-free, because the release job does not
  // run `npm ci`. An import of anything outside node: and its own siblings
  // would fail only at release time, on a tag, where the version is already
  // burned and the tag cannot be moved.
  it("keeps the generator runnable without an install", () => {
    const generator = fs.readFileSync(
      path.resolve(__dirname, "..", "..", "scripts", "generate-catalog.mjs"),
      "utf8",
    );
    const imports = [...generator.matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const specifier of imports) {
      expect(specifier.startsWith("node:") || specifier.startsWith("./")).toBe(true);
    }
  });
});
