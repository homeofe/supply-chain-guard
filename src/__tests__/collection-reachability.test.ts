/**
 * Reachability guards for IOC data.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Three defects of the same shape shipped and went unnoticed for months:
 *
 *   1. KNOWN_C2_WALLETS was exported from patterns.ts and imported by NOTHING.
 *      It looked like the home for wallet indicators and detected nothing, and
 *      a real published indicator was skipped on the strength of that illusion.
 *   2. KNOWN_MALICIOUS_GITHUB_ACCOUNTS was compared with the wrong case
 *      handling, so 6 of its 26 entries could never match on the repo-owner path.
 *   3. checkBadVersion looked PyPI names up raw, so "LiteLLM" missed while
 *      "litellm" hit, even though PyPI considers them one project.
 *
 * The common thread is DATA THAT LOOKS LIKE COVERAGE BUT IS NEVER REACHED, with
 * nothing failing to say so. Every other test in this repo asserts that a
 * specific known input produces a specific finding, which cannot catch an entry
 * nobody thought to write a test for. These guards are data-driven off the
 * collections themselves, so a new entry is covered the moment it is added.
 *
 * HONEST SCOPE - read before trusting these:
 *   - Guard A is a DEAD-SYMBOL linter, not a reachability prover. It asserts a
 *     collection is referenced somewhere outside its own declaration. If that
 *     single reference sits inside a function no caller ever invokes, Guard A
 *     still passes. It would have caught defect 1, and NOT defects 2 or 3.
 *   - Guard C proves an entry produces its rule through the real scan-path
 *     function. It would have caught defects 2 and 3. It would NOT have caught
 *     defect 1, because that collection was EMPTY, so a per-entry loop iterates
 *     zero times and passes vacuously. Only Guard A catches an empty dead list.
 *   - Guard D is the only one asserting a negative. Every other guard is
 *     monotonic in matches and therefore structurally blind to OVER-matching,
 *     which is the failure that gets a scanner switched off.
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkIOCBlocklist,
  checkBadVersion,
  isKnownMaliciousAccount,
  KNOWN_C2_DOMAINS,
  KNOWN_C2_IPS,
  KNOWN_DEAD_DROPS,
  KNOWN_MALICIOUS_HASHES,
  KNOWN_MALICIOUS_GITHUB_ACCOUNTS,
  KNOWN_C2_WALLETS,
  KNOWN_BAD_NPM_VERSIONS,
  KNOWN_BAD_PYPI_VERSIONS,
} from "../ioc-blocklist.js";
import { getBundledFeed, matchPackageIOC, checkThreatIntel } from "../threat-intel.js";
import { matchBareNpmIOC } from "../install-guard.js";

const SRC_DIR = fileURLToPath(new URL("..", import.meta.url));

function readSrcFiles(): Array<{ file: string; text: string }> {
  const out: Array<{ file: string; text: string }> = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".ts")) {
        out.push({ file: path.relative(SRC_DIR, full), text: fs.readFileSync(full, "utf-8") });
      }
    }
  };
  walk(SRC_DIR);
  return out;
}

describe("collection reachability", () => {
  const files = readSrcFiles();

  // -------------------------------------------------------------------------
  // Guard A - no exported collection is dead
  // -------------------------------------------------------------------------

  it("every exported collection in src/ is referenced outside its declaration", () => {
    // A 6-line declaration window, because some collections declare their type
    // across several lines before the "=" (e.g. `export const X: Array<{`).
    const declared: Array<{ name: string; file: string }> = [];
    for (const { file, text } of files) {
      if (file.includes("__tests__")) continue;
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const m = /^export const ([A-Z][A-Z0-9_]{2,})\b/.exec(lines[i]!);
        if (!m) continue;
        const window = lines.slice(i, i + 6).join("\n");
        if (/[:=]\s*(\[|\{|new Set|new Map|Array<|Record<)/.test(window)) {
          declared.push({ name: m[1]!, file });
        }
      }
    }
    expect(declared.length).toBeGreaterThan(20);

    const dead: string[] = [];
    for (const { name, file } of declared) {
      let refs = 0;
      for (const f of files) {
        // A re-export from index.ts is not a read, so it does not count.
        if (f.file === "index.ts") continue;
        const matches = f.text.match(new RegExp(`\\b${name}\\b`, "g"));
        if (!matches) continue;
        refs += matches.length;
        // Discount the declaration itself.
        if (f.file === file) refs -= 1;
      }
      if (refs <= 0) dead.push(`${file}: ${name}`);
    }

    expect(dead, `exported but never read: ${dead.join(", ")}`).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Guard B - every package feed entry is reachable by a matcher some caller invokes
  // -------------------------------------------------------------------------

  it("every package feed entry is reachable by an invoked matcher", () => {
    const feed = getBundledFeed();
    // The ecosystems any real caller passes: the file scanners plus the offline
    // MCP ioc_lookup enum. Kept as a literal so that widening it is a conscious
    // act reviewed alongside the code that makes the ecosystem reachable.
    const REACHABLE = new Set([
      "npm", "pypi", "ruby", "composer", "nuget", "cargo", "go", "jenkins",
    ]);

    const unreachable: string[] = [];
    for (const ioc of feed) {
      if (ioc.type !== "package") continue;
      const colon = ioc.value.indexOf(":");

      if (colon > 0) {
        const eco = ioc.value.substring(0, colon).toLowerCase();
        const rest = ioc.value.substring(colon + 1);
        const at = rest.lastIndexOf("@");
        const name = at > 0 ? rest.substring(0, at) : rest;
        const version = at > 0 ? rest.substring(at + 1) : undefined;
        if (!REACHABLE.has(eco)) {
          unreachable.push(`${ioc.value} (no caller passes ecosystem "${eco}")`);
          continue;
        }
        if (!matchPackageIOC(eco, name, version, feed)) {
          unreachable.push(`${ioc.value} (matchPackageIOC does not match its own entry)`);
        }
      } else {
        // Unprefixed entries are npm-namespace and matched by the bare matcher.
        const at = ioc.value.lastIndexOf("@");
        const name = at > 0 ? ioc.value.substring(0, at) : ioc.value;
        const version = at > 0 ? ioc.value.substring(at + 1) : undefined;
        if (!matchBareNpmIOC(name, version, feed)) {
          unreachable.push(`${ioc.value} (matchBareNpmIOC does not match its own entry)`);
        }
      }
    }

    expect(
      unreachable,
      `feed entries that ship as detection but can never fire:\n${unreachable.join("\n")}`,
    ).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Guard C - every blocklist entry fires its rule through the real scan path
  // -------------------------------------------------------------------------

  it("every ioc-blocklist entry fires its rule through the real scan path", () => {
    const failures: string[] = [];
    const fires = (content: string, file: string, rule: string) =>
      checkIOCBlocklist(content, file).some((f) => f.rule === rule);

    for (const domain of KNOWN_C2_DOMAINS) {
      // Wildcards are a matcher feature, not a literal; substitute a sample.
      const sample = domain.replace(/\*/g, "sample");
      if (!fires(`const c2 = "https://${sample}/x";`, "c2.ts", "IOC_KNOWN_C2_DOMAIN")) {
        failures.push(`KNOWN_C2_DOMAINS: ${domain}`);
      }
    }
    for (const ip of KNOWN_C2_IPS) {
      if (!fires(`connect("${ip}", 443);`, "c2.ts", "IOC_KNOWN_C2_IP")) {
        failures.push(`KNOWN_C2_IPS: ${ip}`);
      }
    }
    for (const drop of KNOWN_DEAD_DROPS) {
      if (!fires(`fetch("${drop}");`, "c2.ts", "IOC_KNOWN_DEAD_DROP")) {
        failures.push(`KNOWN_DEAD_DROPS: ${drop}`);
      }
    }
    for (const hash of Object.keys(KNOWN_MALICIOUS_HASHES)) {
      if (!fires(`// sha256: ${hash}`, "c2.ts", "IOC_KNOWN_MALWARE_HASH")) {
        failures.push(`KNOWN_MALICIOUS_HASHES: ${hash}`);
      }
    }
    for (const address of Object.keys(KNOWN_C2_WALLETS)) {
      if (!fires(`const w = "${address}";`, "c2.ts", "IOC_KNOWN_C2_WALLET")) {
        failures.push(`KNOWN_C2_WALLETS: ${address}`);
      }
    }
    for (const account of KNOWN_MALICIOUS_GITHUB_ACCOUNTS) {
      if (!fires(`git clone https://github.com/${account}/x`, "c2.sh", "IOC_KNOWN_MALICIOUS_ACCOUNT")) {
        failures.push(`KNOWN_MALICIOUS_GITHUB_ACCOUNTS: ${account}`);
      }
    }
    for (const [name, entry] of Object.entries(KNOWN_BAD_NPM_VERSIONS)) {
      for (const v of entry.versions) {
        if (!checkBadVersion(name, v, "npm")) failures.push(`KNOWN_BAD_NPM_VERSIONS: ${name}@${v}`);
      }
    }
    for (const [name, entry] of Object.entries(KNOWN_BAD_PYPI_VERSIONS)) {
      for (const v of entry.versions) {
        if (!checkBadVersion(name, v, "pypi")) failures.push(`KNOWN_BAD_PYPI_VERSIONS: ${name}@${v}`);
      }
    }

    expect(failures, `blocklist entries that do not fire:\n${failures.join("\n")}`).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Targeted normalization probes.
  // Only where the equivalence rule is externally documented AND was violated.
  // A generic "case-mutated names must not match" probe is deliberately absent:
  // it would cement the implementer's own assumption rather than test it.
  // -------------------------------------------------------------------------

  it("malicious GitHub accounts match case-insensitively", () => {
    // GitHub logins are case-insensitive, so a mixed-case entry must match any
    // casing. Six entries were provably unreachable before this was fixed.
    for (const account of KNOWN_MALICIOUS_GITHUB_ACCOUNTS) {
      for (const variant of [account, account.toLowerCase(), account.toUpperCase()]) {
        expect(isKnownMaliciousAccount(variant), variant).toBe(true);
      }
    }
  });

  it("PyPI bad-version names match under PEP 503 normalization", () => {
    // PyPI collapses runs of "-", "_" and "." and is case-insensitive.
    for (const [name, entry] of Object.entries(KNOWN_BAD_PYPI_VERSIONS)) {
      const v = entry.versions[0]!;
      for (const variant of [name.toUpperCase(), name.replace(/-/g, "_"), name.replace(/-/g, ".")]) {
        expect(checkBadVersion(variant, v, "pypi"), `${variant}@${v}`).not.toBeNull();
      }
    }
  });

  // -------------------------------------------------------------------------
  // Guard D - the negative. Everything above is monotonic in matches.
  // -------------------------------------------------------------------------

  it("a benign-code corpus produces zero threat-intel or blocklist findings", () => {
    const feed = getBundledFeed();
    const corpus: Array<[string, string]> = [
      [
        "package.json",
        JSON.stringify(
          { name: "app", version: "1.0.0", dependencies: { react: "^18.0.0", lodash: "^4.17.21" } },
          null,
          2,
        ),
      ],
      [
        "src/config.ts",
        [
          'import { readFileSync } from "node:fs";',
          "const dir = process.env.CONFIG_DIR ?? Object.keys({}).length;",
          "export const opts = { url: import.meta.url, raw: String.raw`x` };",
          "export function load() { return JSON.stringify(readFileSync(dir)); }",
        ].join("\n"),
      ],
      ["README.md", "# app\n\nRun `npm install` then `npm start`.\n"],
      ["Dockerfile", "FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD [\"node\", \"dist/cli.js\"]\n"],
      [".gitmodules", '[submodule "vendor"]\n\tpath = vendor\n\turl = https://github.com/expressjs/express.git\n'],
    ];

    const noise: string[] = [];
    for (const [file, content] of corpus) {
      for (const f of checkThreatIntel(content, file, feed)) {
        noise.push(`${file}: THREAT_INTEL ${f.rule} ${f.description}`);
      }
      for (const f of checkIOCBlocklist(content, file)) {
        noise.push(`${file}: BLOCKLIST ${f.rule} ${f.description}`);
      }
    }

    expect(noise, `benign code produced findings:\n${noise.join("\n")}`).toEqual([]);
  });
});
