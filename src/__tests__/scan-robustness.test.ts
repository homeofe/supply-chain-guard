/**
 * Inputs that made a whole scan quadratic, or made it reject, through the
 * ecosystem matchers. Each runs end to end through scan(), so the routing to
 * the matcher is exercised too. At 1 MiB a quadratic path takes minutes and a
 * linear one well under a second.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { performanceBudget } from "./performance-budget.js";

const N = 1024 * 1024;

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-robust-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(dir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

describe("scan() stays linear on long runs in manifests", () => {
  it.each([
    ["a pubspec.lock URL ending in a run of slashes", "pubspec.lock", `packages:\n  foo:\n    description:\n      name: foo\n      url: "https://a%${"/".repeat(N)}x"\n    version: "1.0.0"\n`],
    ["a pubspec hosted URL ending in a run of slashes", "pubspec.yaml", `name: x\ndependencies:\n  foo:\n    hosted: https://a%${"/".repeat(N)}x\n    version: 1.0.0\n`],
    ["an unclosed pubspec flow map with a run of spaces", "pubspec.yaml", `name: x\ndependencies: {a${" ".repeat(N)}x\n`],
    ["a Helm repository ending in a run of slashes", "Chart.yaml", `apiVersion: v2\nname: x\ndependencies:\n  - name: foo\n    version: 1.0.0\n    repository: oci://${"/".repeat(N)}x\n`],
    ["a SwiftPM URL with a run of slashes", "Package.swift", `let p = Package(dependencies: [.package(url: "https://github.com/a/b${"/".repeat(N)}x", exact: "1.0.0")])\n`],
    ["an image registry with a run of slashes", "values.yaml", `image:\n  registry: a${"/".repeat(N)}x\n  repository: nginx\n  tag: "1.0"\n`],
    ["a Terraform line of label characters without an opening brace", "main.tf", `${"a-".repeat(N / 2)}}\n`],
    ["deeply nested Terraform blocks followed by many lines", "main.tf", "{".repeat(N / 2) + "\n".repeat(N / 2)],
    ["a `for (` with a run of spaces above a DNS lookup", "index.js", `for(${" ".repeat(N)}!\nconst r = await dns.resolveTxt(q);\n`],
    ["a pom tag name of dotted segments", "pom.xml", `<project>\n<${"a.".repeat(N / 2)}\n`],
    ["pom closing tags that match no open element", "pom.xml", `<project>${"<a>".repeat(N / 8)}${"</b>".repeat(N / 8)}</project>`],
    ["a pom version of unclosed property references", "pom.xml", `<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${"${".repeat(N / 2)}</version></dependency></dependencies></project>`],
    ["an sbt dependency followed by a run of tabs", "build.sbt", `libraryDependencies += "com.a" %% "b" % "1.0"${"\t".repeat(N)}!\n`],
    ["an sbt cross with a run of spaces", "build.sbt", `libraryDependencies += "com.a" %% "b" % "1.0" cross${" ".repeat(N)}!\n`],
    ["a requirements option followed by a run of tabs", "requirements-dev.txt", `requests==2.0.0 --${"\t".repeat(N)}!\n`],
    ["a pnpm lockfile line with a run of spaces", "pnpm-lock.yaml", `lockfileVersion: '9.0'\npackages:\n  a${" ".repeat(N)}x\n`],
    ["a classic yarn.lock line with a run of spaces", "yarn.lock", `# yarn lockfile v1\n\n"a${" ".repeat(N)}x\n`],
    ["a berry yarn.lock line with a run of spaces", "yarn.lock", `__metadata:\n  version: 8\n\n"a${" ".repeat(N)}x\n`],
  ])("%s", { timeout: performanceBudget(120_000) }, async (_label, file, content) => {
    write(file, content);
    const started = performance.now();
    await scan({ target: dir, format: "json" });
    expect(performance.now() - started).toBeLessThan(performanceBudget(20_000));
  });
});

describe("scan() returns instead of rejecting", () => {
  it("expands Dockerfile ARGs only up to a bound", { timeout: performanceBudget(120_000) }, async () => {
    write("Dockerfile", `ARG A=${"x".repeat(4096)}\nFROM ${"$A".repeat(1_000_000)}\n`);
    const report = await scan({ target: dir, format: "json" });
    expect(Array.isArray(report.findings)).toBe(true);
  });

  it.each(["packages.config", "sub/packages.config"])(
    "reports a known-malicious NuGet package listed on every line of a 5 MiB %s",
    { timeout: performanceBudget(120_000) },
    async (file) => {
      // One finding per line: collecting them must not spread an input-sized
      // array into a call, and the attack graph must not copy it per finding.
      write(file, "<package id='Sicoob.Sdk'version='2.0.0'\n".repeat(131_000));
      const started = performance.now();
      const report = await scan({ target: dir, format: "json" });
      expect(report.findings.filter((f) => f.rule === "NUGET_MALICIOUS_PACKAGE").length).toBe(131_000);
      expect(performance.now() - started).toBeLessThan(performanceBudget(30_000));
    },
  );

  it("counts nuget.config lines in linear time for many plain-http feeds", { timeout: performanceBudget(120_000) }, async () => {
    write("nuget.config", `<configuration>\n${'<add key="k" value="http://a.example/v3/index.json" />\n'.repeat(60_000)}</configuration>\n`);
    const started = performance.now();
    const report = await scan({ target: dir, format: "json" });
    const lines = report.findings.filter((f) => f.file === "nuget.config").map((f) => f.line);
    expect(lines.slice(0, 2)).toEqual([2, 3]);
    expect(performance.now() - started).toBeLessThan(performanceBudget(30_000));
  });
});
