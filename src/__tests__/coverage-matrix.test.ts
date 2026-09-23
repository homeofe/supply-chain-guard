/**
 * The coverage claim, as a test.
 *
 * src/ecosystem-coverage.json declares every ecosystem and file format the
 * README says is read. For each declared pair this test writes an indicator
 * into that format, at the scan root AND one directory down, runs a real
 * directory scan, and requires the declared rule to report it exactly once
 * per file. A declared pair without a fixture here fails, and so does a
 * fixture that is not declared: the claim and the proof cannot drift apart.
 *
 * Indicators: the first bundled feed entry of the needed shape where the
 * bundle has one (this also checks the real data against the matcher);
 * otherwise a synthetic entry delivered through the scanner's real feed-cache
 * path (`<cacheDir>/threat-feed.json`, the file `feed refresh` writes), so
 * loading, validation, merging, dispatch and matching are all exercised.
 *
 * History: two whole classes of gap shipped while every per-parser unit test
 * was green (2026-09-23): manifests that were never read, and five ecosystems
 * that matched nothing outside the scan root. Only a real scan sees either.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { getBundledFeed, splitPackageIOCValue, type FeedIOC } from "../threat-intel.js";
import { checkBadVersion } from "../ioc-blocklist.js";
import coverage from "../ecosystem-coverage.json" with { type: "json" };

const bundle = getBundledFeed();

type Dep = { name: string; version: string };
type Source = { kind: "bundled"; dep: Dep } | { kind: "synthetic"; dep: Dep; entry: FeedIOC };

/** First bundled entry for a prefix, pinned or whole-name, whose name passes `ok`. */
function bundled(prefix: string, shape: "pinned" | "bare", ok: (name: string, version: string) => boolean = () => true): Dep | undefined {
  for (const i of bundle) {
    if (i.type !== "package") continue;
    if (prefix ? !i.value.startsWith(`${prefix}:`) : i.value.includes(":")) continue;
    const rest = prefix ? i.value.slice(prefix.length + 1) : i.value;
    // The production splitter, so the matrix can never read a value differently
    // from the matcher (it once saw email-shaped Firefox ids as "pinned").
    const split = splitPackageIOCValue(prefix, rest);
    if (shape === "pinned" && split.version !== undefined) {
      const d = { name: split.name, version: split.version };
      if (ok(d.name, d.version)) return d;
    }
    if (shape === "bare" && split.version === undefined && ok(rest, "1.0.0")) return { name: rest, version: "1.0.0" };
  }
  return undefined;
}

function source(prefix: string, shape: "pinned" | "bare", fallback: Dep, ok?: (n: string, v: string) => boolean): Source {
  const dep = bundled(prefix, shape, ok);
  if (dep) return { kind: "bundled", dep };
  const value = `${prefix ? `${prefix}:` : ""}${fallback.name}${shape === "pinned" ? `@${fallback.version}` : ""}`;
  return { kind: "synthetic", dep: fallback, entry: { type: "package", value, severity: "critical", confidence: 1.0 } };
}

const semver = (_n: string, v: string) => /^\d+\.\d+\.\d+$/.test(v);
const npmName = (n: string) => /^[a-z0-9][a-z0-9-]*$/.test(n);
const npmPinned = (n: string, v: string) => npmName(n) && semver(n, v) && checkBadVersion(n, v, "npm") === null;
const PY = (n: string) => /^[a-z0-9][a-z0-9_.-]*$/i.test(n);
const SRI = `sha512-${"A".repeat(86)}==`;

interface Fixture {
  rule: string;
  src: () => Source;
  files: (d: Dep) => Record<string, string>;
  /** GitHub reads workflows only at the repository root. */
  rootOnly?: boolean;
}

const FIXTURES: Record<string, Fixture> = {
  // ---------------------------------------------------------------- npm
  "npm|package.json": { rule: "MALICIOUS_DEPENDENCY", src: () => source("", "bare", { name: "scg-fixture-npm", version: "1.0.0" }, npmName),
    files: (d) => ({ "package.json": JSON.stringify({ name: "x", version: "1.0.0", dependencies: { [d.name]: "^1.0.0" } }) }) },
  "npm|package-lock.json": { rule: "LOCKFILE_MALICIOUS_VERSION", src: () => source("", "pinned", { name: "scg-fixture-npm", version: "1.0.0" }, npmPinned),
    files: (d) => ({ "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
      "package-lock.json": JSON.stringify({ name: "x", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "x" }, [`node_modules/${d.name}`]: { version: d.version, resolved: `https://registry.npmjs.org/${d.name}/-/x.tgz`, integrity: SRI } } }) }) },
  "npm|yarn.lock": { rule: "LOCKFILE_MALICIOUS_VERSION", src: () => source("", "pinned", { name: "scg-fixture-npm", version: "1.0.0" }, npmPinned),
    files: (d) => ({ "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
      "yarn.lock": `# yarn lockfile v1\n\n${d.name}@^${d.version}:\n  version "${d.version}"\n  resolved "https://registry.yarnpkg.com/${d.name}/-/${d.name}-${d.version}.tgz#abc"\n  integrity ${SRI}\n` }) },
  "npm|pnpm-lock.yaml": { rule: "LOCKFILE_MALICIOUS_VERSION", src: () => source("", "pinned", { name: "scg-fixture-npm", version: "1.0.0" }, npmPinned),
    files: (d) => ({ "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
      "pnpm-lock.yaml": `lockfileVersion: '9.0'\n\npackages:\n\n  ${d.name}@${d.version}:\n    resolution: {integrity: ${SRI}}\n` }) },
  "npm|bun.lock": { rule: "LOCKFILE_MALICIOUS_VERSION", src: () => source("", "pinned", { name: "scg-fixture-npm", version: "1.0.0" }, npmPinned),
    files: (d) => ({ "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
      "bun.lock": JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "x" } }, packages: { [d.name]: [`${d.name}@${d.version}`, "", {}, SRI] } }) }) },
  // ---------------------------------------------------------------- pypi
  "pypi|requirements.txt": { rule: "PYTHON_MALICIOUS_PACKAGE", src: () => source("pypi", "pinned", { name: "scg-fixture-py", version: "1.0.0" }, PY),
    files: (d) => ({ "requirements.txt": `${d.name}==${d.version}\n` }) },
  "pypi|pyproject.toml": { rule: "PYTHON_MALICIOUS_PACKAGE", src: () => source("pypi", "bare", { name: "scg-fixture-py", version: "1.0.0" }, PY),
    files: (d) => ({ "pyproject.toml": `[project]\nname = "x"\nversion = "1.0"\ndependencies = ["${d.name}"]\n` }) },
  "pypi|poetry.lock": { rule: "PYTHON_MALICIOUS_PACKAGE", src: () => source("pypi", "pinned", { name: "scg-fixture-py", version: "1.0.0" }, PY),
    files: (d) => ({ "poetry.lock": `[[package]]\nname = "${d.name}"\nversion = "${d.version}"\n` }) },
  "pypi|uv.lock": { rule: "PYTHON_MALICIOUS_PACKAGE", src: () => source("pypi", "pinned", { name: "scg-fixture-py", version: "1.0.0" }, PY),
    files: (d) => ({ "uv.lock": `version = 1\n\n[[package]]\nname = "${d.name}"\nversion = "${d.version}"\n` }) },
  "pypi|Pipfile.lock": { rule: "PYTHON_MALICIOUS_PACKAGE", src: () => source("pypi", "pinned", { name: "scg-fixture-py", version: "1.0.0" }, PY),
    files: (d) => ({ "Pipfile.lock": JSON.stringify({ _meta: {}, default: { [d.name]: { version: `==${d.version}` } } }) }) },
  // ---------------------------------------------------------------- ruby
  "ruby|Gemfile": { rule: "RUBY_MALICIOUS_GEM", src: () => source("ruby", "bare", { name: "scg-fixture-gem", version: "1.0.0" }, PY),
    files: (d) => ({ Gemfile: `source "https://rubygems.org"\ngem "${d.name}"\n` }) },
  "ruby|Gemfile.lock": { rule: "RUBY_MALICIOUS_GEM", src: () => source("ruby", "pinned", { name: "scg-fixture-gem", version: "1.0.0" }, PY),
    files: (d) => ({ "Gemfile.lock": `GEM\n  remote: https://rubygems.org/\n  specs:\n    ${d.name} (${d.version})\n\nPLATFORMS\n  ruby\n` }) },
  // ---------------------------------------------------------------- composer
  "composer|composer.json": { rule: "COMPOSER_MALICIOUS_PACKAGE", src: () => source("composer", "bare", { name: "scg/fixture", version: "1.0.0" }),
    files: (d) => ({ "composer.json": JSON.stringify({ require: { [d.name]: "*" } }) }) },
  "composer|composer.lock": { rule: "COMPOSER_MALICIOUS_PACKAGE", src: () => source("composer", "bare", { name: "scg/fixture", version: "1.0.0" }),
    files: (d) => ({ "composer.lock": JSON.stringify({ packages: [{ name: d.name, version: d.version }], "packages-dev": [] }) }) },
  // ---------------------------------------------------------------- nuget
  "nuget|packages.lock.json": { rule: "NUGET_MALICIOUS_PACKAGE", src: () => source("nuget", "pinned", { name: "Scg.Fixture", version: "1.0.0" }),
    files: (d) => ({ "packages.lock.json": JSON.stringify({ version: 1, dependencies: { "net8.0": { [d.name]: { type: "Direct", requested: `[${d.version}, )`, resolved: d.version } } } }) }) },
  "nuget|*.csproj": { rule: "NUGET_MALICIOUS_PACKAGE", src: () => source("nuget", "pinned", { name: "Scg.Fixture", version: "1.0.0" }),
    files: (d) => ({ "App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="${d.name}" Version="${d.version}" /></ItemGroup></Project>` }) },
  "nuget|packages.config": { rule: "NUGET_MALICIOUS_PACKAGE", src: () => source("nuget", "pinned", { name: "Scg.Fixture", version: "1.0.0" }),
    files: (d) => ({ "packages.config": `<?xml version="1.0"?>\n<packages>\n  <package id="${d.name}" version="${d.version}" />\n</packages>\n` }) },
  // ---------------------------------------------------------------- cargo
  "cargo|Cargo.toml": { rule: "CARGO_MALICIOUS_CRATE", src: () => source("cargo", "bare", { name: "scg-fixture-crate", version: "1.0.0" }),
    files: (d) => ({ "Cargo.toml": `[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\n${d.name} = "1"\n` }) },
  "cargo|Cargo.lock": { rule: "CARGO_MALICIOUS_CRATE", src: () => source("cargo", "pinned", { name: "scg-fixture-crate", version: "1.0.0" }),
    files: (d) => ({ "Cargo.lock": `version = 3\n\n[[package]]\nname = "${d.name}"\nversion = "${d.version}"\n` }) },
  // ---------------------------------------------------------------- go
  "go|go.mod": { rule: "GO_MALICIOUS_MODULE", src: () => source("go", "bare", { name: "example.com/scg/fixture", version: "1.0.0" }, (n) => /\.[a-z]+\//i.test(n)),
    files: (d) => ({ "go.mod": `module example.com/x\n\ngo 1.22\n\nrequire ${d.name} v1.0.0\n` }) },
  "go|go.sum": { rule: "GO_MALICIOUS_MODULE", src: () => source("go", "bare", { name: "example.com/scg/fixture", version: "1.0.0" }, (n) => /\.[a-z]+\//i.test(n)),
    files: (d) => ({ "go.mod": "module example.com/x\n\ngo 1.22\n", "go.sum": `${d.name} v1.0.0 h1:${"A".repeat(43)}=\n` }) },
  // ---------------------------------------------------------------- maven
  ...Object.fromEntries(([
    ["pom.xml", (d: Dep) => { const [g, a] = d.name.split(":"); return { "pom.xml": `<project><dependencies><dependency><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${d.version}</version></dependency></dependencies></project>` }; }],
    ["gradle.lockfile", (d: Dep) => ({ "gradle.lockfile": `${d.name}:${d.version}=runtimeClasspath\n` })],
    ["build.gradle", (d: Dep) => ({ "build.gradle": `dependencies {\n  implementation '${d.name}:${d.version}'\n}\n` })],
    ["build.gradle.kts", (d: Dep) => ({ "build.gradle.kts": `dependencies {\n  implementation("${d.name}:${d.version}")\n}\n` })],
    ["libs.versions.toml", (d: Dep) => ({ "gradle/libs.versions.toml": `[libraries]\nx = "${d.name}:${d.version}"\n` })],
    ["build.sbt", (d: Dep) => { const [g, a] = d.name.split(":"); return { "build.sbt": `libraryDependencies += "${g}" % "${a}" % "${d.version}"\n` }; }],
    ["maven_install.json", (d: Dep) => ({ "maven_install.json": JSON.stringify({ version: "2", artifacts: { [d.name]: { version: d.version } } }) })],
  ] as const).map(([fmt, files]) => [`maven|${fmt}`, { rule: "MAVEN_MALICIOUS_PACKAGE", src: () => source("maven", "pinned", { name: "com.scg:fixture", version: "1.0.0" }), files }])),
  // ---------------------------------------------------------------- pub
  "pub|pubspec.lock": { rule: "PUB_MALICIOUS_PACKAGE", src: () => source("pub", "pinned", { name: "scg_fixture", version: "1.0.0" }),
    files: (d) => ({ "pubspec.lock": `packages:\n  ${d.name}:\n    dependency: "direct main"\n    description:\n      name: ${d.name}\n      url: "https://pub.dev"\n    source: hosted\n    version: "${d.version}"\n` }) },
  "pub|pubspec.yaml": { rule: "PUB_MALICIOUS_PACKAGE", src: () => source("pub", "pinned", { name: "scg_fixture", version: "1.0.0" }),
    files: (d) => ({ "pubspec.yaml": `name: app\ndependencies:\n  ${d.name}: ${d.version}\n` }) },
  // ---------------------------------------------------------------- registry ecosystems
  "swift|Package.resolved": { rule: "SWIFT_MALICIOUS_PACKAGE", src: () => source("swift", "pinned", { name: "github.com/scg-fixture/evil-pkg", version: "1.0.0" }),
    files: (d) => ({ "Package.resolved": JSON.stringify({ pins: [{ identity: "x", kind: "remoteSourceControl", location: `https://${d.name}.git`, state: { version: d.version } }], version: 2 }) }) },
  "swift|Package.swift": { rule: "SWIFT_MALICIOUS_PACKAGE", src: () => source("swift", "pinned", { name: "github.com/scg-fixture/evil-pkg", version: "1.0.0" }),
    files: (d) => ({ "Package.swift": `let package = Package(dependencies: [\n  .package(url: "https://${d.name}.git", exact: "${d.version}"),\n])\n` }) },
  "cocoapods|Podfile.lock": { rule: "COCOAPODS_MALICIOUS_POD", src: () => source("cocoapods", "pinned", { name: "scgfixturepod", version: "1.0.0" }),
    files: (d) => ({ "Podfile.lock": `PODS:\n  - ${d.name} (${d.version})\n\nDEPENDENCIES:\n  - ${d.name}\n` }) },
  "cocoapods|Podfile": { rule: "COCOAPODS_MALICIOUS_POD", src: () => source("cocoapods", "pinned", { name: "scgfixturepod", version: "1.0.0" }),
    files: (d) => ({ Podfile: `target 'App' do\n  pod '${d.name}', '${d.version}'\nend\n` }) },
  "hex|mix.lock": { rule: "HEX_MALICIOUS_PACKAGE", src: () => source("hex", "pinned", { name: "scg_fixture", version: "1.0.0" }),
    files: (d) => ({ "mix.lock": `%{\n  "${d.name}": {:hex, :${d.name}, "${d.version}", "abc", [:mix], [], "hexpm", "def"},\n}\n` }) },
  "hex|mix.exs": { rule: "HEX_MALICIOUS_PACKAGE", src: () => source("hex", "pinned", { name: "scg_fixture", version: "1.0.0" }),
    files: (d) => ({ "mix.exs": `defp deps do\n  [{:${d.name}, "== ${d.version}"}]\nend\n` }) },
  "cran|renv.lock": { rule: "CRAN_MALICIOUS_PACKAGE", src: () => source("cran", "pinned", { name: "scgFixture", version: "1.0.0" }),
    files: (d) => ({ "renv.lock": JSON.stringify({ Packages: { [d.name]: { Package: d.name, Version: d.version, Source: "Repository", Repository: "CRAN" } } }) }) },
  "cran|DESCRIPTION": { rule: "CRAN_MALICIOUS_PACKAGE", src: () => source("cran", "pinned", { name: "scgFixture", version: "1.0.0" }),
    files: (d) => ({ DESCRIPTION: `Package: app\nImports: ${d.name} (== ${d.version})\n` }) },
  "conan|conan.lock": { rule: "CONAN_MALICIOUS_PACKAGE", src: () => source("conan", "pinned", { name: "scgfixture", version: "1.0.0" }),
    files: (d) => ({ "conan.lock": JSON.stringify({ version: "0.5", requires: [`${d.name}/${d.version}#abc%1`] }) }) },
  "conan|conanfile.txt": { rule: "CONAN_MALICIOUS_PACKAGE", src: () => source("conan", "pinned", { name: "scgfixture", version: "1.0.0" }),
    files: (d) => ({ "conanfile.txt": `[requires]\n${d.name}/${d.version}\n` }) },
  "conan|conanfile.py": { rule: "CONAN_MALICIOUS_PACKAGE", src: () => source("conan", "pinned", { name: "scgfixture", version: "1.0.0" }),
    files: (d) => ({ "conanfile.py": `class App(ConanFile):\n    def requirements(self):\n        self.requires("${d.name}/${d.version}")\n` }) },
  "terraform|*.tf (required_providers)": { rule: "TERRAFORM_MALICIOUS_PROVIDER", src: () => source("terraform", "bare", { name: "scg-fixture/provider", version: "1.0.0" }),
    files: (d) => ({ "versions.tf": `terraform {\n  required_providers {\n    x = { source = "${d.name}" }\n  }\n}\n` }) },
  "terraform|.terraform.lock.hcl": { rule: "TERRAFORM_MALICIOUS_PROVIDER", src: () => source("terraform", "bare", { name: "scg-fixture/provider", version: "1.0.0" }),
    files: (d) => ({ ".terraform.lock.hcl": `provider "registry.terraform.io/${d.name}" {\n  version = "1.0.0"\n}\n` }) },
  "tfmodule|*.tf (module)": { rule: "TERRAFORM_MALICIOUS_MODULE", src: () => source("tfmodule", "pinned", { name: "scg-fixture/vpc/aws", version: "1.0.0" }),
    files: (d) => ({ "main.tf": `module "vpc" {\n  source  = "${d.name}"\n  version = "${d.version}"\n}\n` }) },
  "tfmodule|.terraform/modules/modules.json": { rule: "TERRAFORM_MALICIOUS_MODULE", src: () => source("tfmodule", "pinned", { name: "scg-fixture/vpc/aws", version: "1.0.0" }),
    files: (d) => ({ ".terraform/modules/modules.json": JSON.stringify({ Modules: [{ Key: "vpc", Source: `registry.terraform.io/${d.name}`, Version: d.version, Dir: ".terraform/modules/vpc" }] }) }) },
  "helm|Chart.yaml": { rule: "HELM_MALICIOUS_CHART", src: () => source("helm", "pinned", { name: "charts.scg-fixture.example/stable/evil", version: "1.0.0" }),
    files: (d) => { const i = d.name.lastIndexOf("/"); return { "Chart.yaml": `apiVersion: v2\nname: app\ndependencies:\n  - name: ${d.name.slice(i + 1)}\n    version: ${d.version}\n    repository: https://${d.name.slice(0, i)}\n` }; } },
  "helm|Chart.lock": { rule: "HELM_MALICIOUS_CHART", src: () => source("helm", "pinned", { name: "charts.scg-fixture.example/stable/evil", version: "1.0.0" }),
    files: (d) => { const i = d.name.lastIndexOf("/"); return { "Chart.lock": `dependencies:\n- name: ${d.name.slice(i + 1)}\n  repository: https://${d.name.slice(0, i)}\n  version: ${d.version}\ndigest: sha256:abc\n` }; } },
  "ansible|requirements.yml": { rule: "ANSIBLE_MALICIOUS_CONTENT", src: () => source("ansible", "pinned", { name: "scgfixture.evil", version: "1.0.0" }),
    files: (d) => ({ "requirements.yml": `collections:\n  - name: ${d.name}\n    version: ${d.version}\n` }) },
  "ansible|galaxy.yml": { rule: "ANSIBLE_MALICIOUS_CONTENT", src: () => source("ansible", "pinned", { name: "scgfixture.evil", version: "1.0.0" }),
    files: (d) => ({ "galaxy.yml": `namespace: me\nname: x\ndependencies:\n  ${d.name}: '${d.version}'\n` }) },
  "docker|Dockerfile": { rule: "DOCKER_MALICIOUS_IMAGE", src: () => source("docker", "pinned", { name: "scgfixture/evil", version: "6.6.6" }, (_n, v) => !v.startsWith("sha256:")),
    files: (d) => ({ Dockerfile: `FROM ${d.name}:${d.version}\n` }) },
  "docker|docker-compose.yml": { rule: "DOCKER_MALICIOUS_IMAGE", src: () => source("docker", "pinned", { name: "scgfixture/evil", version: "6.6.6" }, (_n, v) => !v.startsWith("sha256:")),
    files: (d) => ({ "docker-compose.yml": `services:\n  x:\n    image: ${d.name}:${d.version}\n` }) },
  "docker|Kubernetes manifest (image:)": { rule: "DOCKER_MALICIOUS_IMAGE", src: () => source("docker", "pinned", { name: "scgfixture/evil", version: "6.6.6" }, (_n, v) => !v.startsWith("sha256:")),
    files: (d) => ({ "deployment.yaml": `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: x\n          image: ${d.name}:${d.version}\n` }) },
  "actions|.github/workflows/*.yml": { rule: "GHA_KNOWN_MALICIOUS_SHA", rootOnly: true, src: () => source("actions", "pinned", { name: "scg/fixture-action", version: "a".repeat(40) }),
    files: (d) => ({ ".github/workflows/ci.yml": `on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ${d.name}@${d.version}\n` }) },
  "actions|action.yml (composite)": { rule: "GHA_KNOWN_MALICIOUS_SHA", src: () => source("actions", "pinned", { name: "scg/fixture-action", version: "a".repeat(40) }),
    files: (d) => ({ "action.yml": `name: x\nruns:\n  using: composite\n  steps:\n    - uses: ${d.name}@${d.version}\n` }) },
  "homebrew|Brewfile": { rule: "HOMEBREW_MALICIOUS_PACKAGE", src: () => source("homebrew", "bare", { name: "scg-fixture/tools/evil", version: "1.0.0" }),
    files: (d) => ({ Brewfile: `brew "${d.name}"\n` }) },
  "homebrew|Brewfile.lock.json": { rule: "HOMEBREW_MALICIOUS_PACKAGE", src: () => source("homebrew", "pinned", { name: "scg-fixture/tools/evil", version: "1.0.0" }),
    files: (d) => ({ "Brewfile.lock.json": JSON.stringify({ entries: { brew: { [d.name]: { version: d.version } } } }) }) },
  "vscode|.vscode/extensions.json": { rule: "VSCODE_MALICIOUS_EXTENSION", src: () => source("vscode", "bare", { name: "scgfixture.evil", version: "1.0.0" }),
    files: (d) => ({ ".vscode/extensions.json": JSON.stringify({ recommendations: [d.name] }) }) },
  "vscode|devcontainer.json": { rule: "VSCODE_MALICIOUS_EXTENSION", src: () => source("vscode", "pinned", { name: "scgfixture.evil", version: "1.0.0" }),
    files: (d) => ({ ".devcontainer/devcontainer.json": JSON.stringify({ customizations: { vscode: { extensions: [`${d.name}@${d.version}`] } } }) }) },
  "vscode|installed extension package.json": { rule: "VSCODE_MALICIOUS_EXTENSION", src: () => source("vscode", "pinned", { name: "scgfixture.evil", version: "1.0.0" }),
    files: (d) => { const [pub, name] = d.name.split("."); return { [`${d.name}-${d.version}/package.json`]: JSON.stringify({ name, publisher: pub, version: d.version, engines: { vscode: "^1.80.0" } }) }; } },
  "browser|Chromium policy JSON": { rule: "BROWSER_MALICIOUS_EXTENSION", src: () => source("chrome", "bare", { name: "abcdefghijklmnopabcdefghijklmnop", version: "1.0.0" }),
    files: (d) => ({ "policies/managed/extensions.json": JSON.stringify({ ExtensionInstallForcelist: [`${d.name};https://clients2.google.com/service/update2/crx`] }) }) },
  "browser|Firefox policies.json": { rule: "BROWSER_MALICIOUS_EXTENSION", src: () => source("firefox", "bare", { name: "evil@scg-fixture.example", version: "1.0.0" }),
    files: (d) => ({ "distribution/policies.json": JSON.stringify({ policies: { ExtensionSettings: { [d.name]: { installation_mode: "force_installed" } } } }) }) },
  "browser|installed Chromium extension": { rule: "BROWSER_MALICIOUS_EXTENSION", src: () => source("chrome", "pinned", { name: "abcdefghijklmnopabcdefghijklmnop", version: "1.0.0" }),
    files: (d) => ({ [`Default/Extensions/${d.name}/${d.version}_0/manifest.json`]: JSON.stringify({ manifest_version: 3, name: "x", version: d.version }) }) },
  "browser|Firefox extension manifest": { rule: "BROWSER_MALICIOUS_EXTENSION", src: () => source("firefox", "bare", { name: "evil@scg-fixture.example", version: "1.0.0" }),
    files: (d) => ({ "addon/manifest.json": JSON.stringify({ manifest_version: 2, version: "1.0.0", browser_specific_settings: { gecko: { id: d.name } } }) }) },
  "jetbrains|.idea/externalDependencies.xml": { rule: "JETBRAINS_MALICIOUS_PLUGIN", src: () => source("jetbrains", "bare", { name: "com.scgfixture.evil", version: "1.0.0" }),
    files: (d) => ({ ".idea/externalDependencies.xml": `<project version="4">\n  <component name="ExternalDependencies">\n    <plugin id="${d.name}" />\n  </component>\n</project>\n` }) },
  "jetbrains|META-INF/plugin.xml": { rule: "JETBRAINS_MALICIOUS_PLUGIN", src: () => source("jetbrains", "bare", { name: "com.scgfixture.evil", version: "1.0.0" }),
    files: (d) => ({ "src/main/resources/META-INF/plugin.xml": `<idea-plugin>\n  <id>${d.name}</id>\n  <version>1.0.0</version>\n</idea-plugin>\n` }) },
};

const declared = coverage.ecosystems.flatMap((e) => e.formats.map((f) => `${e.id}|${f}`));

describe("the declaration and the proof cannot drift", () => {
  it("every declared (ecosystem, format) pair has a fixture", () => {
    expect(declared.filter((k) => !(k in FIXTURES)), "claimed in ecosystem-coverage.json, never proven").toEqual([]);
  });
  it("every fixture is declared", () => {
    expect(Object.keys(FIXTURES).filter((k) => !declared.includes(k)), "proven but not claimed").toEqual([]);
  });
  it("every declared rule is emitted by some fixture", () => {
    const fixtureRules = new Set(Object.values(FIXTURES).map((f) => f.rule));
    const declaredRules = coverage.ecosystems.flatMap((e) => e.rules);
    // npm declares three rules; the lockfile whole-name rule is proven in lockfile-feed.test.ts.
    expect(declaredRules.filter((r) => !fixtureRules.has(r) && r !== "LOCKFILE_MALICIOUS_PACKAGE")).toEqual([]);
  });
});

let root: string;
beforeAll(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-matrix-")); });
afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

const rows = declared.filter((k) => k in FIXTURES).flatMap((key) => {
  const fx = FIXTURES[key]!;
  const src = fx.src();
  const where = fx.rootOnly ? ["root"] : ["root", "nested"];
  return where.map((w) => ({ key, where: w, fx, src }));
});

describe.each(rows)("$key ($where)", ({ key, where, fx, src }) => {
  it(`reports ${fx.rule} (${src.kind} indicator)`, async () => {
    const dir = path.join(root, `${key.replace(/[^a-z0-9]+/gi, "_")}-${where}`);
    const target = where === "root" ? dir : path.join(dir, "services", "app");
    for (const [f, c] of Object.entries(fx.files(src.dep))) {
      fs.mkdirSync(path.dirname(path.join(target, f)), { recursive: true });
      fs.writeFileSync(path.join(target, f), c);
    }
    let cacheDir: string | undefined;
    if (src.kind === "synthetic") {
      cacheDir = path.join(root, `cache-${key.replace(/[^a-z0-9]+/gi, "_")}-${where}`);
      fs.mkdirSync(cacheDir, { recursive: true });
      fs.writeFileSync(path.join(cacheDir, "threat-feed.json"), JSON.stringify({ timestamp: new Date().toISOString(), entries: [src.entry] }));
    }
    const report = await scan({ target: dir, format: "json", noHistory: true, cacheDir });
    const hits = report.findings.filter((f) => f.rule === fx.rule);
    expect(hits.length, `${key} ${where}: ${src.dep.name}`).toBeGreaterThanOrEqual(1);
    const perFile = new Map<string, number>();
    for (const h of hits) perFile.set(h.file, (perFile.get(h.file) ?? 0) + 1);
    for (const [file, n] of perFile) expect(n, `${file} reported ${n} times`).toBe(1);
  });
});
