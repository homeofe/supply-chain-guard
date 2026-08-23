/**
 * Issue 195 in the layout where it matters most.
 *
 * The fix names the manifests the generator found but did not read, so a
 * document asserting "no components" cannot be mistaken for a measurement. It
 * originally looked only at `path.join(projectDir, file)`.
 *
 * A monorepo keeps `pyproject.toml` and `Cargo.toml` under `packages/*` or
 * `services/*`, never at the root - and a monorepo is the layout most likely to
 * hold more than one ecosystem in the first place. So the root-only check
 * reported nothing exactly where the defect was worst, while the README stated
 * that every such file is named.
 *
 * These tests pin the walk, and its bounds. The bounds matter as much as the
 * walk: an unbounded directory traversal inside a scanner is how a fix becomes
 * the slowest part of a scan, and then gets switched off.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { detectUninventoriedManifests } from "../sbom-generator.js";

describe("uninventoried manifests are found below the top level", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-mono-"));
    fs.mkdirSync(path.join(dir, "packages", "api"), { recursive: true });
    fs.mkdirSync(path.join(dir, "services", "worker"), { recursive: true });
    fs.mkdirSync(path.join(dir, "node_modules", "junk"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), '{"name":"mono","version":"1.0.0"}');
    fs.writeFileSync(path.join(dir, "packages", "api", "pyproject.toml"), "[project]");
    fs.writeFileSync(path.join(dir, "services", "worker", "Cargo.toml"), "[package]");
    fs.writeFileSync(path.join(dir, "node_modules", "junk", "pyproject.toml"), "[project]");
  });

  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("names a nested PyPI and a nested Cargo manifest", () => {
    const found = detectUninventoriedManifests(dir);
    expect(found.some((f) => f.startsWith("packages/api/pyproject.toml"))).toBe(true);
    expect(found.some((f) => f.startsWith("services/worker/Cargo.toml"))).toBe(true);
    expect(found.some((f) => f.includes("(PyPI)"))).toBe(true);
    expect(found.some((f) => f.includes("(Cargo)"))).toBe(true);
  });

  it("does not report anything inside node_modules", () => {
    // Reporting a dependency's own manifest would make the sentence useless in
    // any real project: it would always fire, and always about someone else's
    // code.
    const found = detectUninventoriedManifests(dir);
    expect(found.some((f) => f.includes("node_modules"))).toBe(false);
  });

  it("reports paths relative to the project, never absolute", () => {
    // The same rule the coverage-gap reporting follows: an absolute path here
    // would carry the OS username into a published document.
    for (const entry of detectUninventoriedManifests(dir)) {
      expect(entry.startsWith("/")).toBe(false);
      expect(/^[A-Za-z]:/.test(entry)).toBe(false);
    }
  });

  it("stops at the depth ceiling rather than walking an arbitrarily deep tree", () => {
    // Buried one level past the ceiling. If this ever starts being reported the
    // bound has been raised or removed, and that is a performance decision
    // someone should make deliberately rather than discover in a slow scan.
    const deep = path.join(dir, "a", "b", "c", "d", "e");
    fs.mkdirSync(deep, { recursive: true });
    fs.writeFileSync(path.join(deep, "go.mod"), "module x");
    const found = detectUninventoriedManifests(dir);
    expect(found.some((f) => f.includes("a/b/c/d/e/go.mod"))).toBe(false);
  });

  it("control: a project with no such manifest reports none", () => {
    // Without this, "found two" and "the walk never ran" would be told apart
    // only by the two positive assertions above, and a walk that returned
    // everything would satisfy them just as well.
    const plain = fs.mkdtempSync(path.join(os.tmpdir(), "scg-plain-"));
    try {
      fs.writeFileSync(path.join(plain, "package.json"), '{"name":"x","version":"1.0.0"}');
      expect(detectUninventoriedManifests(plain)).toEqual([]);
    } finally {
      fs.rmSync(plain, { recursive: true, force: true });
    }
  });
});
