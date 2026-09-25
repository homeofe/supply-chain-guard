import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import {
  ALL_PATTERN_SETS,
  isPatternApplicableToFile,
  matchPatternInContent,
  resolvePatternSeverity,
} from "../patterns.js";
import type { PatternEntry, Severity } from "../types.js";
import { performanceBudget } from "./performance-budget.js";

const entry = (): PatternEntry => {
  const found = ALL_PATTERN_SETS
    .flatMap(([, set]) => set)
    .find((candidate) => candidate.rule === "IMPORT_EXPRESSION");
  if (!found) throw new Error("IMPORT_EXPRESSION is not shipped");
  return found as PatternEntry;
};

function severities(content: string, file = "src/loader.ts"): Severity[] {
  const rule = entry();
  if (!isPatternApplicableToFile(rule, content, file)) return [];
  return matchPatternInContent(rule, content, "g")
    .map((hit) => resolvePatternSeverity(rule, content, hit));
}

const guarded = (cls: string, order: "before" | "after" = "before") => {
  const guard = '  if (!SLUG.test(slug)) throw new Error("unknown module");';
  const load = "  return import(`@content/modules/${slug}/index.mdx`);";
  return [
    `const SLUG = /^${cls}$/;`,
    "export async function load(slug: string) {",
    ...(order === "before" ? [guard, load] : [load, guard]),
    "}",
  ].join("\n");
};

describe("IMPORT_EXPRESSION honours an anchored allowlist guard", () => {
  it("reports the allowlisted template import at info", () => {
    expect(severities(guarded("[a-z0-9][a-z0-9-]*"))).toEqual(["info"]);
  });

  it("accepts a relative prefix and an inline regex guard", () => {
    const content = [
      "export function page(name) {",
      "  if (!/^[\\w-]+$/.test(name)) { return null; }",
      "  return import(`./pages/${name}.js`);",
      "}",
    ].join("\n");
    expect(severities(content)).toEqual(["info"]);
  });

  it("reports import(req.query.m) at medium", () => {
    expect(severities("app.get('/m', async (req) => import(req.query.m));")).toEqual(["medium"]);
  });

  it("reports an unguarded template import at medium", () => {
    expect(severities("export const load = (name) => import(`./${name}.js`);")).toEqual(["medium"]);
  });

  it("reports the reproduction at medium when the class admits dot and slash", () => {
    expect(severities(guarded("[a-z0-9./-]+"))).toEqual(["medium"]);
  });

  it("reports the reproduction at medium when the guard follows the import", () => {
    expect(severities(guarded("[a-z0-9][a-z0-9-]*", "after"))).toEqual(["medium"]);
  });

  it.each([
    ["an unanchored guard", "const SLUG = /[a-z0-9-]+/;"],
    ["a multiline-flag guard", "const SLUG = /^[a-z0-9-]+$/m;"],
    ["a negated class", "const SLUG = /^[^/]+$/;"],
    ["a range spanning the dot", "const SLUG = /^[+-9a-z]+$/;"],
    ["an alternation", "const SLUG = /^(?:a|..\\/b)$/;"],
    ["a reassignable guard", "let SLUG = /^[a-z0-9-]+$/;"],
  ])("reports %s at medium", (_label, definition) => {
    const content = [
      definition,
      "export async function load(slug: string) {",
      '  if (!SLUG.test(slug)) throw new Error("unknown module");',
      "  return import(`@content/modules/${slug}/index.mdx`);",
      "}",
    ].join("\n");
    expect(severities(content)).toEqual(["medium"]);
  });

  it.each([
    ["a guard in another function", [
      "function check(slug) { if (!SLUG.test(slug)) throw new Error(); }",
      "export function load(slug) { return import(`./m/${slug}.js`); }",
    ]],
    ["a guard in another method balanced by a brace in a string", [
      "class Loader {",
      '  check(slug) { if (!SLUG.test(slug)) throw "{"; }',
      "  load(slug) { return import(`./m/${slug}.js`); }",
      "}",
    ]],
    ["a guard in another method hidden behind a regex literal quote", [
      "class Loader {",
      "  check(slug) { if (!SLUG.test(slug)) throw 1; const q = /'/; }",
      "  load(slug) { const r = /'/; return import(`./m/${slug}.js`); }",
      "}",
    ]],
    ["a guard that does not exit", [
      "export function load(slug) {",
      "  if (!SLUG.test(slug)) console.warn(slug);",
      "  return import(`./m/${slug}.js`);",
      "}",
    ]],
    ["a reassignment after the guard", [
      "export function load(slug) {",
      "  if (!SLUG.test(slug)) throw new Error();",
      "  slug = decodeURIComponent(slug);",
      "  return import(`./m/${slug}.js`);",
      "}",
    ]],
    ["a member expression in the template", [
      "export function load(o) {",
      "  if (!SLUG.test(o.slug)) throw new Error();",
      "  return import(`./m/${o.slug}.js`);",
      "}",
    ]],
    ["a concatenation after the template", [
      "export function load(slug, tail) {",
      "  if (!SLUG.test(slug)) throw new Error();",
      "  return import(`./m/${slug}.js` + tail);",
      "}",
    ]],
    ["no static extension suffix", [
      "export function load(slug) {",
      "  if (!SLUG.test(slug)) throw new Error();",
      "  return import(`./m/${slug}`);",
      "}",
    ]],
    ["no static prefix", [
      "export function load(slug) {",
      "  if (!SLUG.test(slug)) throw new Error();",
      "  return import(`${slug}/index.js`);",
      "}",
    ]],
    ["a second interpolation", [
      "export function load(slug, ext) {",
      "  if (!SLUG.test(slug)) throw new Error();",
      "  return import(`./m/${slug}.${ext}`);",
      "}",
    ]],
  ])("reports %s at medium", (_label, body) => {
    const content = ["const SLUG = /^[a-z0-9-]+$/;", ...body].join("\n");
    expect(severities(content)).toEqual(["medium"]);
  });

  it("resolves severity in bounded time on a 5 MiB file of guarded imports", { timeout: performanceBudget(30_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const head = "const S = /^[a-z]+$/;\nfunction f(a) {\nif (!S.test(a)) throw 1;\n";
    const unit = "import(`./m/${a}.js`); // " + "x".repeat(40) + "\n";
    const content = head + unit.repeat(Math.ceil(fiveMiB / unit.length));
    const rule = entry();
    const hits = matchPatternInContent(rule, content, "g");
    expect(hits.length).toBeGreaterThan(1000);
    const started = performance.now();
    for (const hit of hits) resolvePatternSeverity(rule, content, hit);
    expect(performance.now() - started).toBeLessThan(performanceBudget(5_000));
  });
});
