import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { performanceBudget } from "./performance-budget.js";
import { scan } from "../scanner.js";
import { checkDependencyGovernance, isTrustedResolved } from "../dependency-governance.js";
import { encodeNpmPackageName } from "../publishing-anomaly-detector.js";
import { KNOWN_C2_DOMAINS, checkIOCBlocklist } from "../ioc-blocklist.js";
import { generateFixSuggestions, parseUsesRef } from "../remediation-engine.js";
import { parseRepositoryField } from "../npm-scanner.js";
import { stripBase64DataUris } from "../entropy.js";
import { escapeCmdShellArg } from "../install-guard.js";
import {
  hasDownloadExecChain,
  mentionsHostRuntime,
  mentionsHostRuntimePath,
} from "../install-hook-scanner.js";
import { classifyFileSurface, isPersonalAccountName } from "../internal-disclosure.js";
import { firstQuotedSlashRef } from "../policy-engine.js";
import { isPythonManifest } from "../python-lockfile-scanner.js";
import { DOWNLOAD_EXEC_REGEXES, HOOK_SHELL_RC_WRITE_REGEX } from "../skills-scanner.js";

// Regression tests for the findings of the first CodeQL analysis of main
// (2026-09-25). The equivalence of each ReDoS rewrite with the expression it
// replaced is in property-parsers.test.ts; this file holds the behaviour the
// fixes change and the input sizes they must survive.

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});
const tmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "scg-codeql-"));
  dirs.push(d);
  return d;
};

describe("a lockfile cannot pass a foreign host off as the npm registry", () => {
  it("trusts the registries by exact host, and file: as before", () => {
    expect(isTrustedResolved("https://registry.npmjs.org/a/-/a-1.0.0.tgz")).toBe(true);
    expect(isTrustedResolved("https://registry.yarnpkg.com/a/-/a-1.0.0.tgz")).toBe(true);
    expect(isTrustedResolved("file:../vendor/a")).toBe(true);
  });

  it("rejects a host that merely starts with the registry's name", () => {
    for (const resolved of [
      "https://registry.npmjs.org.attacker.example/a/-/a-1.0.0.tgz",
      "https://registry.yarnpkg.com.attacker.example/a.tgz",
      "https://registry.npmjs.org@attacker.example/a.tgz",
      "https://user:pw@registry.npmjs.org/a.tgz",
      "https://registry.npmjs.org:8443/a.tgz",
      "http://registry.npmjs.org/a.tgz",
      "https://attacker.example/https://registry.npmjs.org/a.tgz",
      "not a url",
    ]) {
      expect(isTrustedResolved(resolved), resolved).toBe(false);
    }
  });

  it("reports the lookalike host through checkDependencyGovernance", () => {
    const lock = (resolved: string) =>
      JSON.stringify({ packages: { "node_modules/a": { version: "1.0.0", resolved } } });
    const rules = (resolved: string) =>
      checkDependencyGovernance({}, lock(resolved), "package-lock.json").map((f) => f.rule);
    expect(rules("https://registry.npmjs.org.attacker.example/a/-/a-1.0.0.tgz")).toContain(
      "DEPENDENCY_UNTRUSTED_SOURCE",
    );
    expect(rules("https://registry.npmjs.org/a/-/a-1.0.0.tgz")).not.toContain("DEPENDENCY_UNTRUSTED_SOURCE");
  });
});

describe("a scanned package name cannot steer the registry lookup", () => {
  it("encodes a scoped name as one path segment, as the registry expects", () => {
    expect(encodeNpmPackageName("@scope/name")).toBe("@scope%2Fname");
    expect(encodeNpmPackageName("plain")).toBe("plain");
  });

  it("keeps a traversal attempt inside its own segment", () => {
    const url = new URL(`https://registry.npmjs.org/${encodeNpmPackageName("@a/../../x")}`);
    expect(url.pathname).toBe("/@a%2F..%2F..%2Fx");
    // Control: the old encoding (first "/" only) resolved to a different package.
    const old = new URL(`https://registry.npmjs.org/@${"a/../../x".replace("/", "%2F")}`);
    expect(old.pathname).toBe("/x");
  });
});

describe("C2 domains match only themselves", () => {
  const domain = KNOWN_C2_DOMAINS.find((d) => /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(d) && d.split(".").length >= 3)!;
  const flagged = (content: string) =>
    checkIOCBlocklist(content, "src/app.js").some(
      (f) => f.rule === "IOC_KNOWN_C2_DOMAIN" && f.description.endsWith(`: ${domain}`),
    );

  it("still finds the domain itself", () => {
    expect(domain).toBeDefined();
    expect(flagged(`fetch("https://${domain}/x")`)).toBe(true);
  });

  it("treats every dot literally", () => {
    expect(flagged(`fetch("https://${domain.replace(/\./g, "X")}/x")`)).toBe(false);
  });
});

describe("SVG script detection finds every script element", () => {
  const svgRules = async (body: string) => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "logo.svg"), `<svg xmlns="http://www.w3.org/2000/svg">${body}</svg>\n`);
    const report = await scan({ target: dir, format: "json", noHistory: true });
    return report.findings.filter((f) => f.rule === "SVG_SCRIPT_INJECTION").length;
  };

  it("finds an upper-case <SCRIPT> block and ONLOAD handler", async () => {
    expect(await svgRules("<SCRIPT>alert(1)</SCRIPT>")).toBeGreaterThan(0);
    expect(await svgRules('<rect ONLOAD="alert(1)"/>')).toBeGreaterThan(0);
  });

  // Each of these raised nothing while the rule needed <script> and </script>
  // on one line (measured through scan() before the change).
  it.each([
    ["a multi-line script", "\n<script>\nalert(1)\n</script>\n"],
    ["a CDATA script", '\n<script type="text/javascript"><![CDATA[\n  alert(1)\n]]></script>\n'],
    ["an end tag with a space", "<script>alert(1)</script >"],
    ["an end tag broken across lines", "<script>alert(1)</script\n>"],
    ["a self-closing external script", '<script href="data:text/javascript,alert(1)"/>'],
    ["a namespace-prefixed script", '<svg:script xmlns:svg="http://www.w3.org/2000/svg">alert(1)</svg:script>'],
  ])("finds %s", async (_name, body) => {
    expect(await svgRules(body)).toBeGreaterThan(0);
  });

  it("still finds lower case, and stays quiet on a clean SVG", async () => {
    expect(await svgRules("<script>alert(1)</script>")).toBeGreaterThan(0);
    expect(await svgRules('<rect width="10" height="10"/>')).toBe(0);
    expect(await svgRules("<text>&lt;script&gt; is escaped text</text>")).toBe(0);
  });
});

describe("an unpinned action gets its fix suggestion", () => {
  it("builds it from a real finding, which carries no uses: key", async () => {
    const dir = tmp();
    fs.mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".github", "workflows", "ci.yml"),
      "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n",
    );
    const report = await scan({ target: dir, format: "json", noHistory: true });
    const finding = report.findings.find((f) => f.rule === "GHA_UNPINNED_ACTION");
    expect(finding?.match).toBe("actions/checkout@main");
    // The old parser required "uses:" in the match, so this was always empty.
    expect(finding?.match).not.toContain("uses:");
    const fix = generateFixSuggestions(report.findings).find((f) => f.before.includes("actions/checkout"));
    expect(fix?.before).toBe("uses: actions/checkout@main");
    expect(fix?.after).toBe("uses: actions/checkout@<commit-sha> # main");
  });

  it("parses both shapes and refuses a truncated match", () => {
    expect(parseUsesRef("actions/checkout@main")).toEqual({ action: "actions/checkout", ref: "main" });
    expect(parseUsesRef("- uses: owner/repo/path@dev")).toEqual({ action: "owner/repo/path", ref: "dev" });
    expect(parseUsesRef(`${"a".repeat(120)}...`)).toBeNull();
    expect(parseUsesRef("no-ref-here")).toBeNull();
  });
});

describe("repository shorthand", () => {
  it("resolves owner/repo and a repository named github.com", () => {
    expect(parseRepositoryField("owner/repo")).toEqual({ owner: "owner", repo: "repo" });
    expect(parseRepositoryField("github:owner/repo")).toEqual({ owner: "owner", repo: "repo" });
    expect(parseRepositoryField("owner/github.com")).toEqual({ owner: "owner", repo: "github.com" });
  });

  it("treats a dotted owner slot as a host", () => {
    expect(parseRepositoryField("github.com/owner")).toBeNull();
    expect(parseRepositoryField("gitlab.com/owner")).toBeNull();
    expect(parseRepositoryField("https://github.com/owner/repo")).toEqual({ owner: "owner", repo: "repo" });
  });
});

// The input shapes CodeQL named for each alert, at the 5 MB scan limit. Each
// original expression took minutes to hours on these (measured on Linux:
// e.g. 40 s for 500 KB of "data:", 8.7 s for 100 KB of "-" before a letter).
const MiB5 = 5 * 1024 * 1024;
const fill = (unit: string, prefix = "", suffix = "") =>
  prefix + unit.repeat(Math.floor((MiB5 - prefix.length - suffix.length) / unit.length)) + suffix;

describe("the rewrites stay linear on 5 MB of CodeQL's attack inputs", () => {
  const cases: Array<[string, () => unknown]> = [
    ["#11 data-URI strip", () => stripBase64DataUris(fill("data:"))],
    ["#12 cmd escaping", () => escapeCmdShellArg("\\".repeat(1024 * 1024))],
    ["#13 download then exec", () => hasDownloadExecChain(fill("curl"))],
    ["#14 exec then download", () => hasDownloadExecChain(fill("exec"))],
    ["#15 host runtime path", () => mentionsHostRuntimePath(fill("node_modules/"))],
    ["#15 host runtime dispatch", () => mentionsHostRuntime(fill("dispatch-"))],
    ["#16 account-name trim", () => isPersonalAccountName(fill("-", "a", "x"))],
    ["#17 example artifact", () => classifyFileSurface(fill(".tpl.", "tpl.", "/"))],
    ["#22 quoted action ref", () => firstQuotedSlashRef(fill("!/", '"'))],
    ["#23 requirements basename", () => isPythonManifest(fill("-constraints-", "constraints-"))],
    ["#24 uses: ref", () => parseUsesRef(fill(" ", "uses:"))],
    ["#25 iex(iwr)", () => DOWNLOAD_EXEC_REGEXES.some((re) => re.test(fill(" ", "iex(")))],
    ["#26 rc-file write", () => HOOK_SHELL_RC_WRITE_REGEX.test(fill(">!", ">"))],
  ];

  for (const [name, run] of cases) {
    it(name, { timeout: performanceBudget(20_000) }, () => {
      const started = performance.now();
      run();
      expect(performance.now() - started).toBeLessThan(performanceBudget(5_000));
    });
  }
});
