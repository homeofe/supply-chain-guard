/**
 * The coverage claim, as a test.
 *
 * For every package ecosystem and every file format the README says is read,
 * a bundled threat-feed indicator is written into that format, at the scan
 * root AND one directory down, and a real directory scan must report it.
 *
 * This exists because two gaps shipped while every per-parser unit test was
 * green (measured 2026-09-23): requirements.txt / pyproject.toml / Cargo.toml /
 * go.mod / packages.config were not matched at all, and Ruby, Composer, NuGet,
 * Cargo and Go matched NOTHING outside the scan root. A parser test cannot see
 * either; only the real scan path can.
 *
 * Indicators come from the live bundle (first entry of the needed shape), so
 * the test keeps exercising real data as the feed changes.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { getBundledFeed } from "../threat-intel.js";

const feed = getBundledFeed();

type Dep = { name: string; version: string };

/** First bundled entry for a prefix: a version pin, or a whole-name entry. */
function pick(prefix: string, shape: "pinned" | "bare", nameRe: RegExp): Dep {
  for (const i of feed) {
    if (i.type !== "package" || !i.value.startsWith(prefix)) continue;
    const rest = i.value.slice(prefix.length);
    const at = rest.lastIndexOf("@");
    if (shape === "pinned" && at > 0) {
      const d = { name: rest.slice(0, at), version: rest.slice(at + 1) };
      if (nameRe.test(d.name) && /^v?\d/.test(d.version)) return d;
    }
    if (shape === "bare" && at <= 0 && nameRe.test(rest)) return { name: rest, version: "1.0.0" };
  }
  throw new Error(`bundle has no ${shape} ${prefix} entry matching ${nameRe}`);
}

interface Row {
  ecosystem: string;
  format: string;
  rule: string;
  files: (d: Dep) => Record<string, string>;
  dep: () => Dep;
}

const PY = /^[a-z0-9][a-z0-9_.-]*$/i;
const ROWS: Row[] = [
  { ecosystem: "pypi", format: "requirements.txt", rule: "PYTHON_MALICIOUS_PACKAGE",
    dep: () => pick("pypi:", "pinned", PY), files: (d) => ({ "requirements.txt": `${d.name}==${d.version}\n` }) },
  { ecosystem: "pypi", format: "pyproject.toml", rule: "PYTHON_MALICIOUS_PACKAGE",
    dep: () => pick("pypi:", "bare", PY),
    files: (d) => ({ "pyproject.toml": `[project]\nname = "x"\nversion = "1.0"\ndependencies = ["${d.name}"]\n` }) },
  { ecosystem: "pypi", format: "poetry.lock", rule: "PYTHON_MALICIOUS_PACKAGE",
    dep: () => pick("pypi:", "pinned", PY), files: (d) => ({ "poetry.lock": `[[package]]\nname = "${d.name}"\nversion = "${d.version}"\n` }) },
  { ecosystem: "ruby", format: "Gemfile", rule: "RUBY_MALICIOUS_GEM",
    dep: () => pick("ruby:", "bare", PY), files: (d) => ({ Gemfile: `source "https://rubygems.org"\ngem "${d.name}"\n` }) },
  { ecosystem: "ruby", format: "Gemfile.lock", rule: "RUBY_MALICIOUS_GEM",
    dep: () => pick("ruby:", "pinned", PY),
    files: (d) => ({ "Gemfile.lock": `GEM\n  remote: https://rubygems.org/\n  specs:\n    ${d.name} (${d.version})\n\nPLATFORMS\n  ruby\n` }) },
  { ecosystem: "composer", format: "composer.json", rule: "COMPOSER_MALICIOUS_PACKAGE",
    dep: () => pick("composer:", "bare", /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/), files: (d) => ({ "composer.json": JSON.stringify({ require: { [d.name]: "*" } }) }) },
  { ecosystem: "composer", format: "composer.lock", rule: "COMPOSER_MALICIOUS_PACKAGE",
    dep: () => pick("composer:", "bare", /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/),
    files: (d) => ({ "composer.lock": JSON.stringify({ packages: [{ name: d.name, version: d.version }], "packages-dev": [] }) }) },
  { ecosystem: "nuget", format: "packages.lock.json", rule: "NUGET_MALICIOUS_PACKAGE",
    dep: () => pick("nuget:", "pinned", /^[A-Za-z0-9_.-]+$/),
    files: (d) => ({ "packages.lock.json": JSON.stringify({ version: 1, dependencies: { "net8.0": { [d.name]: { type: "Direct", requested: `[${d.version}, )`, resolved: d.version } } } }) }) },
  { ecosystem: "nuget", format: "*.csproj", rule: "NUGET_MALICIOUS_PACKAGE",
    dep: () => pick("nuget:", "pinned", /^[A-Za-z0-9_.-]+$/),
    files: (d) => ({ "App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="${d.name}" Version="${d.version}" /></ItemGroup></Project>` }) },
  { ecosystem: "nuget", format: "packages.config", rule: "NUGET_MALICIOUS_PACKAGE",
    dep: () => pick("nuget:", "pinned", /^[A-Za-z0-9_.-]+$/),
    files: (d) => ({ "packages.config": `<?xml version="1.0" encoding="utf-8"?>\n<packages>\n  <package id="${d.name}" version="${d.version}" targetFramework="net48" />\n</packages>\n` }) },
  { ecosystem: "cargo", format: "Cargo.toml", rule: "CARGO_MALICIOUS_CRATE",
    dep: () => pick("cargo:", "bare", /^[a-z0-9_-]+$/i),
    files: (d) => ({ "Cargo.toml": `[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\n${d.name} = "1"\n` }) },
  { ecosystem: "cargo", format: "Cargo.lock", rule: "CARGO_MALICIOUS_CRATE",
    dep: () => pick("cargo:", "pinned", /^[a-z0-9_-]+$/i),
    files: (d) => ({ "Cargo.lock": `version = 3\n\n[[package]]\nname = "${d.name}"\nversion = "${d.version}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n` }) },
  { ecosystem: "go", format: "go.mod", rule: "GO_MALICIOUS_MODULE",
    dep: () => pick("go:", "bare", /^[a-z0-9.-]+\.[a-z]+\/\S+$/i),
    files: (d) => ({ "go.mod": `module example.com/x\n\ngo 1.22\n\nrequire ${d.name} v1.0.0\n` }) },
  { ecosystem: "go", format: "go.sum", rule: "GO_MALICIOUS_MODULE",
    dep: () => pick("go:", "bare", /^[a-z0-9.-]+\.[a-z]+\/\S+$/i),
    files: (d) => ({ "go.mod": "module example.com/x\n\ngo 1.22\n", "go.sum": `${d.name} v1.0.0 h1:${"A".repeat(43)}=\n` }) },
];

let root: string;
beforeAll(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-matrix-")); });
afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

describe.each(ROWS.flatMap((r) => [{ ...r, where: "root" }, { ...r, where: "nested" }]))(
  "$ecosystem $format ($where)",
  ({ ecosystem, format, rule, files, dep, where }) => {
    it(`reports ${rule}`, async () => {
      const d = dep();
      const dir = path.join(root, `${ecosystem}-${format.replace(/[^a-z0-9]+/gi, "_")}-${where}`);
      const target = where === "root" ? dir : path.join(dir, "services", "app");
      fs.mkdirSync(target, { recursive: true });
      for (const [f, c] of Object.entries(files(d))) fs.writeFileSync(path.join(target, f), c);
      const report = await scan({ target: dir, format: "json", noHistory: true });
      const hits = report.findings.filter((f) => f.rule === rule);
      expect(hits.length, `${ecosystem} ${format} ${where}: ${d.name}`).toBeGreaterThanOrEqual(1);
      // Reported once per file, never twice through two dispatch paths.
      const perFile = new Map<string, number>();
      for (const h of hits) perFile.set(h.file, (perFile.get(h.file) ?? 0) + 1);
      for (const [file, n] of perFile) expect(n, `${file} reported ${n} times`).toBe(1);
    });
  },
);
