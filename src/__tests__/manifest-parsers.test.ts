/**
 * Edge cases of the manifest parsers added on 2026-09-23 (packages.config,
 * Cargo.toml dependency tables, go.mod require/replace) and of the nested
 * dispatcher. coverage-matrix.test.ts proves the end-to-end path; these pin
 * the shapes a real manifest takes that the matrix fixtures do not.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scanPackagesConfigContent } from "../nuget-scanner.js";
import { scanCargoTomlDependencies } from "../cargo-scanner.js";
import { scanGoModDependencies } from "../go-scanner.js";
import { isNestedManifest } from "../nested-manifests.js";
import { scan } from "../scanner.js";
import { getBundledFeed, type FeedIOC } from "../threat-intel.js";

const matches = (findings: { match?: string }[]) => findings.map((f) => f.match);

describe("packages.config", () => {
  const FEED: FeedIOC[] = [{ type: "package", value: "nuget:Evil.Pkg@2.0.0", severity: "critical", confidence: 1.0 }];

  it("matches <package id version> entries in any attribute order", () => {
    const xml = [
      '<?xml version="1.0" encoding="utf-8"?>',
      '<packages>',
      '  <package version="2.0.0" id="Evil.Pkg" targetFramework="net48" />',
      '  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />',
      '</packages>',
    ].join("\n");
    const found = scanPackagesConfigContent(xml, "packages.config", FEED);
    expect(matches(found)).toEqual(["Evil.Pkg@2.0.0"]);
    expect(found[0]?.line).toBe(3);
  });

  it("does not match another version, and never reads the <packages> root as a package", () => {
    const xml = '<packages id="Evil.Pkg" version="2.0.0">\n  <package id="Evil.Pkg" version="2.0.1" />\n</packages>';
    expect(scanPackagesConfigContent(xml, "packages.config", FEED)).toEqual([]);
  });
});

describe("Cargo.toml dependency tables", () => {
  const FEED: FeedIOC[] = [{ type: "package", value: "cargo:evil-crate", severity: "critical", confidence: 1.0 }];
  const scanToml = (toml: string) => matches(scanCargoTomlDependencies(toml, "Cargo.toml", FEED));

  it("reads every dependency table kind", () => {
    for (const header of ["[dependencies]", "[dev-dependencies]", "[build-dependencies]", "[workspace.dependencies]",
      "[target.'cfg(windows)'.dependencies]", '[target."x86_64-pc-windows-gnu".dependencies]']) {
      expect(scanToml(`${header}\nevil-crate = "1"\n`), header).toEqual(["evil-crate"]);
    }
  });

  // A renamed dependency fetches the crate named by `package`, whatever the key.
  it("looks up a renamed dependency by the crate actually fetched", () => {
    expect(scanToml('[dependencies]\ninnocent = { version = "1", package = "evil-crate" }\n')).toEqual(["evil-crate"]);
    expect(scanToml('[dependencies]\nevil-crate = { version = "1", package = "serde" }\n')).toEqual([]);
  });

  it("reads the single-dependency table form, including a rename", () => {
    expect(scanToml('[dependencies.evil-crate]\nversion = "1"\n')).toEqual(["evil-crate"]);
    expect(scanToml('[dependencies.innocent]\nversion = "1"\npackage = "evil-crate"\n\n[features]\nx = []\n')).toEqual(["evil-crate"]);
  });

  it("ignores [package], [features] and other tables", () => {
    expect(scanToml('[package]\nname = "evil-crate"\n\n[features]\nevil-crate = []\n')).toEqual([]);
  });
});

describe("go.mod", () => {
  const FEED: FeedIOC[] = [
    { type: "package", value: "go:example.com/evil/mod", severity: "critical", confidence: 1.0 },
    { type: "package", value: "go:example.com/pinned/mod@v1.2.3", severity: "critical", confidence: 1.0 },
  ];
  const scanMod = (mod: string) => matches(scanGoModDependencies(mod, "go.mod", FEED));

  it("reads single-line and block requires, with // comments", () => {
    const mod = [
      "module example.com/app",
      "",
      "require example.com/evil/mod v0.1.0 // indirect",
      "require (",
      "\texample.com/pinned/mod v1.2.3",
      "\tgolang.org/x/text v0.14.0 // indirect",
      ")",
    ].join("\n");
    expect(scanMod(mod)).toEqual(["example.com/evil/mod@v0.1.0", "example.com/pinned/mod@v1.2.3"]);
  });

  it("honours version pins", () => {
    expect(scanMod("require example.com/pinned/mod v1.2.4\n")).toEqual([]);
  });

  // A trailing comment on the block header must not stop the block opening,
  // and a commented-out dependency is not a dependency.
  it("opens a block whose header carries a comment, and skips commented-out lines", () => {
    const mod = [
      "require ( // pinned for FIPS",
      "\t// example.com/pinned/mod v1.2.3",
      "\texample.com/evil/mod v0.2.0",
      ")",
    ].join("\n");
    expect(scanMod(mod)).toEqual(["example.com/evil/mod@v0.2.0"]);
  });

  // The replace TARGET is what gets built.
  it("reads the target of a replace directive", () => {
    expect(scanMod("replace golang.org/x/text => example.com/evil/mod v0.0.1\n")).toEqual(["example.com/evil/mod@v0.0.1"]);
    expect(scanMod("replace (\n\texample.com/evil/mod => ./local\n)\n")).toEqual([]);
  });
});

describe("nested dispatch", () => {
  it("takes nested manifests of all five ecosystems, never the root", () => {
    for (const f of ["svc/Gemfile", "svc/Gemfile.lock", "svc/composer.json", "svc/composer.lock", "src/App/App.csproj",
      "src/App/packages.config", "src/App/PACKAGES.LOCK.JSON", "crates/x/Cargo.toml", "crates/x/Cargo.lock", "cmd/go.mod", "cmd/go.sum"]) {
      expect(isNestedManifest(f), f).toBe(true);
    }
    for (const f of ["Gemfile", "composer.json", "App.csproj", "Cargo.toml", "go.mod"]) {
      expect(isNestedManifest(f), f).toBe(false);
    }
  });

  // vendor/ and target/ hold copies of installed dependencies.
  it("skips vendor/ and target/", () => {
    for (const f of ["vendor/acme/lib/composer.json", "app/vendor/github.com/x/go.mod", "target/package/x/Cargo.toml"]) {
      expect(isNestedManifest(f), f).toBe(false);
    }
  });
});

describe("vendor/ exclusion through a real scan", () => {
  let dir: string;
  beforeAll(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-vendor-")); });
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("does not re-report a vendored copy's manifest", async () => {
    const bare = getBundledFeed().find((i) => i.type === "package" && i.value.startsWith("composer:") && i.value.lastIndexOf("@") <= 0)!;
    const name = bare.value.slice("composer:".length);
    fs.mkdirSync(path.join(dir, "vendor", "acme", "lib"), { recursive: true });
    fs.writeFileSync(path.join(dir, "vendor", "acme", "lib", "composer.json"), JSON.stringify({ require: { [name]: "*" } }));
    const report = await scan({ target: dir, format: "json", noHistory: true });
    expect(report.findings.filter((f) => f.rule === "COMPOSER_MALICIOUS_PACKAGE")).toEqual([]);
  });
});
