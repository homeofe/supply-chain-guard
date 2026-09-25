/**
 * The per-hit severity of pattern rules, through a real directory scan.
 *
 * IMPORT_EXPRESSION reports at info only behind an anchored allowlist guard
 * (patterns.ts resolvePatternSeverity). The unit tests of that function do not
 * prove the scanner uses it: this does. C2_DOH_RESOLVER / DEAD_DROP_DNS_TXT
 * keep their declared medium: an encoder or decoder in another file cannot be
 * seen from the file that makes the lookup, so no same-file signal may lower
 * them.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";

let dir: string;
beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-sev-"));
});
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

async function severities(file: string, content: string, rule: string): Promise<string[]> {
  const target = path.join(dir, path.basename(file, path.extname(file)));
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, file), content);
  const report = await scan({ target, format: "json", noHistory: true });
  return report.findings.filter((f) => f.rule === rule).map((f) => f.severity);
}

describe("DNS rules keep their declared severity", () => {
  it("reports a DNSKEY lookup over DoH and an SPF lookup at medium, as before", async () => {
    // Ordinary lookups in this file; the data could be encoded in another one.
    expect(await severities(
      "dnssec.ts",
      'export async function keys(domain: string) {\n  const r = await fetch("https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=DNSKEY");\n  return r.json();\n}\n',
      "C2_DOH_RESOLVER",
    )).toEqual(["medium"]);
    expect(await severities(
      "spf.js",
      'const dns = require("dns");\nfunction spf(domain, cb) {\n  dns.resolveTxt(domain, (err, records) => cb(records.flat().find((r) => r.startsWith("v=spf1"))));\n}\nmodule.exports = { spf };\n',
      "DEAD_DROP_DNS_TXT",
    )).toEqual(["medium"]);
  });
});

describe("IMPORT_EXPRESSION is info only behind an anchored allowlist guard", () => {
  it("the guarded template import is info, the unguarded one medium", async () => {
    const guarded = await severities(
      "loader.ts",
      'const SLUG = /^[a-z0-9][a-z0-9-]*$/;\nexport async function load(slug: string) {\n  if (!SLUG.test(slug)) throw new Error("unknown module");\n  return import(`@content/modules/${slug}/index.mdx`);\n}\n',
      "IMPORT_EXPRESSION",
    );
    expect(guarded).toEqual(["info"]);

    const unguarded = await severities(
      "plugin.ts",
      "export async function load(name: string) {\n  return import(`./${name}.js`);\n}\n",
      "IMPORT_EXPRESSION",
    );
    expect(unguarded).toEqual(["medium"]);
  });
});
