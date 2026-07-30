import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { performance } from "node:perf_hooks";
import * as fs from "node:fs";
import * as path from "node:path";
import { matchCharacterCodeObfuscation } from "../correlated-pattern-matchers.js";
import { BEACON_MINER_PATTERNS, matchPatternInContent } from "../patterns.js";
import { scan } from "../scanner.js";

describe("precision regressions for structural threat patterns", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-precision-patterns-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  async function rulesFor(file: string, content: string): Promise<Set<string>> {
    fs.writeFileSync(path.join(tempDir, file), content);
    const report = await scan({ target: tempDir, format: "text" });
    return new Set(report.findings.map((finding) => finding.rule));
  }

  it("rejects bundle tokens separated by an overlong pseudo-hostname", async () => {
    const bundleShape = `const width = Pool.length${"x".repeat(30_000)}r.com;`;
    const rules = await rulesFor("bundle.js", bundleShape);
    expect(rules.has("MINER_POOL_DOMAIN")).toBe(false);
  });

  it.each([
    "pool.ntp.org",
    "pool.api.example.com",
    "pool.db.example.net",
    "mining.telemetry.example.org",
  ])("rejects an ordinary generic pool-shaped hostname without mining context: %s", async (hostname) => {
    const rules = await rulesFor(
      "ordinary-service.js",
      `const endpoint = "https://${hostname}/v1/status";`,
    );
    expect(rules.has("MINER_POOL_DOMAIN")).toBe(false);
  });

  it("does not borrow mining context from a source comment", async () => {
    const rules = await rulesFor(
      "ordinary-service.js",
      'const endpoint = "https://pool.api.example.com"; // stratum example',
    );
    expect(rules.has("MINER_POOL_DOMAIN")).toBe(false);
  });

  it.each([
    [
      "a generic domain comment beside executable mining context",
      'const protocol = "stratum"; // example: pool.api.example.com',
    ],
    [
      "a known mining domain comment",
      "// Historical IOC example: eu.nanopool.org",
    ],
  ])("rejects %s", async (_name, source) => {
    const rules = await rulesFor("ordinary-comments.js", source);
    expect(rules.has("MINER_POOL_DOMAIN")).toBe(false);
  });

  it("retains a known mining pool without a separate context token", async () => {
    const rules = await rulesFor(
      "miner.js",
      'const endpoint = "https://eu.nanopool.org/api/v1/status";',
    );
    expect(rules.has("MINER_POOL_DOMAIN")).toBe(true);
  });

  it("retains a bounded contiguous mining hostname", async () => {
    const rules = await rulesFor(
      "miner.js",
      'const endpoint = "stratum+tcp://pool.worker.example.com:4444";',
    );
    expect(rules.has("MINER_POOL_DOMAIN")).toBe(true);
  });

  it("bounds generic pool context at 512 characters", () => {
    const pattern = BEACON_MINER_PATTERNS.find(
      (entry) => entry.rule === "MINER_POOL_DOMAIN",
    );
    expect(pattern).toBeDefined();

    const atBoundary = `stratum${" ".repeat(512)}pool.worker.example.com`;
    const overBoundary = `stratum${" ".repeat(513)}pool.worker.example.com`;
    expect(matchPatternInContent(pattern!, atBoundary)).toHaveLength(1);
    expect(matchPatternInContent(pattern!, overBoundary)).toEqual([]);
  });

  it.each([
    "eth-eu1.nanopool.org",
    "us1.ethermine.org",
    "btc.f2pool.com",
    [63, 63, 63, 48].map((length) => "a".repeat(length)).join(".") + ".nanopool.org",
  ])("retains a known mining pool behind valid subdomain labels: %s", async (hostname) => {
    const rules = await rulesFor(
      "miner.js",
      `const endpoint = "stratum+tcp://${hostname}:4444";`,
    );
    expect(rules.has("MINER_POOL_DOMAIN")).toBe(true);
  });

  it.each([
    `${"a".repeat(64)}.nanopool.org`,
    "bad-.nanopool.org",
    `${Array.from({ length: 4 }, () => "a".repeat(63)).join(".")}.nanopool.org`,
    "eth-eu1.nanopool.org.evil.example",
  ])("rejects an invalid or overlong mining-pool hostname: %s", async (hostname) => {
    const rules = await rulesFor(
      "ordinary.js",
      `const endpoint = "stratum+tcp://${hostname}:4444";`,
    );
    expect(rules.has("MINER_POOL_DOMAIN")).toBe(false);
  });

  it("keeps rejected generic pool hostnames linear on 5 MiB", { timeout: 10_000 }, () => {
    const pattern = BEACON_MINER_PATTERNS.find(
      (entry) => entry.rule === "MINER_POOL_DOMAIN",
    );
    expect(pattern).toBeDefined();

    const size = 5 * 1024 * 1024;
    const unit = 'const endpoint="https://pool.ntp.org/status";';
    const source = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
    const started = performance.now();
    expect([...matchPatternInContent(pattern!, source)]).toEqual([]);
    expect(performance.now() - started).toBeLessThan(5_000);
  });

  it("rejects switch labels that happen to use a mining key name", async () => {
    const rules = await rulesFor(
      "dispatcher.js",
      'switch (kind) { case "worker": return runWorker(); default: return idle(); }',
    );
    expect(rules.has("MINER_CONFIG_KEYS")).toBe(false);
  });

  it.each([
    ["quoted handler type", 'type Handlers = { "worker": () => void };'],
    ["ordinary job object", 'const job = {"worker":"background","status":"ready"};'],
    ["ordinary metrics object", 'const metrics = {"hashrate":requestsPerSecond};'],
    [
      "ordinary scheduler object",
      'const job = {"worker":webWorker,"algo":"round-robin"};',
    ],
    [
      "two-key handler type",
      'type Handlers = {"worker": Worker, "algo": Algorithm};',
    ],
    [
      "two-key destructuring pattern",
      'const {"worker": worker, "wallet": wallet} = config;',
    ],
    [
      "separate weak-key objects",
      'const job = {"worker":"background"}; const account = {"wallet":"primary"};',
    ],
    ["one repeated weak key", 'const aliases = {"worker":"a","worker":"b"};'],
    [
      "comment and stringified objects",
      'const job = {"worker":"background"}; /* {"wallet":"x"} */ const docs = \'{"wallet":"x","coin":"btc"}\';',
    ],
  ])("rejects insufficient or separately scoped weak mining keys in a %s", async (_name, source) => {
    const rules = await rulesFor("ordinary-config.js", source);
    expect(rules.has("MINER_CONFIG_KEYS")).toBe(false);
  });

  it("retains three distinct weak mining keys in the same object", async () => {
    const rules = await rulesFor(
      "miner-config.js",
      'const config = {"worker":"rig-1","wallet":"4Abc123xyz","algo":"randomx"};',
    );
    expect(rules.has("MINER_CONFIG_KEYS")).toBe(true);
  });

  it("retains one strong mining-specific key", async () => {
    const rules = await rulesFor(
      "miner-config.js",
      'const config = {"pool_address":"stratum.invalid:4444"};',
    );
    expect(rules.has("MINER_CONFIG_KEYS")).toBe(true);
  });

  it("keeps mining-key object correlation linear on 5 MiB", { timeout: 10_000 }, () => {
    const pattern = BEACON_MINER_PATTERNS.find(
      (entry) => entry.rule === "MINER_CONFIG_KEYS",
    );
    expect(pattern).toBeDefined();

    const size = 5 * 1024 * 1024;
    const unit = 'const job={"worker":webWorker,"algo":"round-robin"};';
    const source = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
    const started = performance.now();
    expect([...matchPatternInContent(pattern!, source)]).toEqual([]);
    expect(performance.now() - started).toBeLessThan(5_000);
  });

  it("rejects proxy indicators in documentation comments", async () => {
    const rules = await rulesFor(
      "proxy-guide.js",
      [
        "// back_connect registers an agent with the controller",
        "/* Example only: socks5://proxy.invalid:1080 */",
      ].join("\n"),
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(false);
  });

  it("rejects loopback SOCKS endpoints", async () => {
    const rules = await rulesFor(
      "local-proxy.js",
      'const endpoint = "socks5://127.0.0.1:1080";',
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(false);
  });

  it("does not reuse a rejected local scheme as a fallback socks signal", async () => {
    const rules = await rulesFor(
      "local-proxy-and-dns.js",
      'const proxy = "socks5://127.0.0.1:1080"; const dns = "8.8.8.8";',
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(false);
  });

  it("rejects a local proxy even when its userinfo is IP-shaped", async () => {
    const rules = await rulesFor(
      "local-proxy-userinfo.js",
      'const proxy = "socks5://8.8.8.8@127.0.0.1:1080";',
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(false);
  });

  it("retains external proxy endpoints and behavioral registration", async () => {
    const rules = await rulesFor(
      "proxy-agent.js",
      'const endpoint = "socks5://proxy.invalid:1080"; proxy.checkin(endpoint);',
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(true);
  });
  it("retains a remote hostname beginning with localhost", async () => {
    const rules = await rulesFor(
      "lookalike-proxy.js",
      'const endpoint = "socks5://localhost.evil.example:1080";',
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(true);
  });

  it("retains authenticated external proxy endpoints", async () => {
    const rules = await rulesFor(
      "authenticated-proxy.js",
      'const endpoint = "socks5://user:pass@proxy.invalid:1080";',
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(true);
  });

  it.each([
    "socks5://localhost:1080",
    "socks5://api.localhost:1080",
    "socks5://0:1080",
    "socks5://127.1:1080",
    "socks5://127.0.1:1080",
    "socks5://127.1.2.3:1080",
    "socks5://0177.0.0.1:1080",
    "socks5://user:pass@127.0.0.1:1080",
    "socks5://0.0.0.0:1080",
    "socks5://[::1]:1080",
    "socks5://[0:0:0:0:0:0:0:1]:1080",
    "socks5://[0000:0000:0000:0000:0000:0000:0000:0000]:1080",
    "socks5://[0:0:0:0:0:0:0000:0001]:1080",
    "socks5://[::ffff:127.1.2.3]:1080",
  ])("rejects local or wildcard proxy endpoint %s", async (endpoint) => {
    const rules = await rulesFor(
      "local-proxy.js",
      `const endpoint = "${endpoint}";`,
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(false);
  });

  it.each([
    "socks5://128.1:1080",
    "socks5://user:pass@192.0.2.10:1080",
    "socks5://[2001:db8::1]:1080",
  ])("retains a remote numeric proxy endpoint %s", async (endpoint) => {
    const rules = await rulesFor(
      "remote-proxy.js",
      `const endpoint = "${endpoint}";`,
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(true);
  });

  it("keeps a proxy literal in a JavaScript private field visible", async () => {
    const rules = await rulesFor(
      "private-field.js",
      'class C { #proxy = "socks5://evil.invalid:1080"; endpoint() { return this.#proxy; } }',
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(true);
  });

  it("rejects a proxy literal in a template-interpolation comment", async () => {
    const rules = await rulesFor(
      "template-comment.js",
      [
        "const rendered = `${(() => {",
        "  /* socks5://evil.invalid:1080 */",
        "  return 1;",
        "})()}`;",
      ].join("\n"),
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(false);
  });

  it("rejects a proxy literal after a no-space Python comment marker", async () => {
    const rules = await rulesFor(
      "python-comment.py",
      "x=1# socks5://evil.invalid:1080\nprint(x)",
    );
    expect(rules.has("PROXY_BACKCONNECT")).toBe(false);
  });

  it("does not treat npm-cli-login as a credential value source", async () => {
    const rules = await rulesFor(
      "login-helper.js",
      'import login from "npm-cli-login"; fetch("/health"); void login;',
    );
    expect(rules.has("SHAI_HULUD_CRED_STEAL")).toBe(false);
  });

  it("rejects sequential CP437/codepage lookup tables", async () => {
    const table = Array.from(
      { length: 32 },
      (_, code) => `\\x${code.toString(16).padStart(2, "0")}`,
    ).join("");
    const rules = await rulesFor(
      "codepage.js",
      `export const CP437_DECODE_TABLE = "${table}";`,
    );
    expect(rules.has("CHARCODE_OBFUSCATION")).toBe(false);
  });

  it("retains directly executed character escapes", async () => {
    const rules = await rulesFor(
      "encoded-loader.js",
      String.raw`eval("\x61\x6c\x65\x72\x74\x28\x31\x29")`,
    );
    expect(rules.has("CHARCODE_OBFUSCATION")).toBe(true);
  });

  it("retains assigned fromCharCode payloads passed to an execution sink", async () => {
    const rules = await rulesFor(
      "assigned-loader.js",
      [
        "const payload = String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41);",
        "eval(payload);",
      ].join("\n"),
    );
    expect(rules.has("CHARCODE_OBFUSCATION")).toBe(true);
  });
  it.each([1_024, 1_025])(
    "does not cap an executed fromCharCode payload at %i arguments",
    async (count) => {
      const values = Array.from({ length: count }, () => "65").join(",");
      const rules = await rulesFor(
        `encoded-${count}.js`,
        `eval(String.fromCharCode(${values}));`,
      );
      expect(rules.has("CHARCODE_OBFUSCATION")).toBe(true);
    },
  );

  it("rejects encoded execution text inside quoted documentation", async () => {
    const source = String.raw`const docs = "eval(\x61\x6c\x65\x72\x74)";`;
    const rules = await rulesFor("quoted-docs.js", source);
    expect(rules.has("CHARCODE_OBFUSCATION")).toBe(false);
  });

  it("does not treat RegExp.exec as a dynamic execution sink", async () => {
    const rules = await rulesFor(
      "regexp.js",
      "const regex = /a/; regex.exec(String.fromCharCode(97, 98, 99, 100, 101));",
    );
    expect(rules.has("CHARCODE_OBFUSCATION")).toBe(false);
  });

  it("stays linear on a 5 MiB unclosed fromCharCode near miss", { timeout: 10_000 }, () => {
    const size = 5 * 1024 * 1024;
    const prefix = "eval(String.fromCharCode(";
    const source = (prefix + "65,".repeat(Math.ceil((size - prefix.length) / 3))).slice(0, size);
    const started = performance.now();
    expect([...matchCharacterCodeObfuscation(source)]).toEqual([]);
    expect(performance.now() - started).toBeLessThan(5_000);
  });
});