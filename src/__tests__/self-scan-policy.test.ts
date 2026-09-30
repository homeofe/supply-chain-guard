import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { applyPolicy, loadPolicyConfig } from "../policy-engine.js";
import type { Finding, PolicyConfig } from "../types.js";

// .supply-chain-guard.yml suppresses the IOC rules on this repository's own IOC
// definitions, so that a scanner of ANOTHER version (an installed release run
// against a newer checkout) does not report the threat feed, the blocklist and
// the tests quoting them as thousands of critical findings. The scanner's
// content-addressed self-recognition (src/self-scan-trust.ts) covers only the
// same-version case.
//
// What must stay true, and is held here:
//   - every such entry is scoped by rule AND path; no IOC rule is switched off
//     for the tree
//   - the same indicator in any other file still reports
//   - every suppressed path names a file this repository actually has, so a
//     rename cannot leave a stale entry behind silently

const ROOT = path.resolve(__dirname, "..", "..");
const IOC_RULES = [
  "THREAT_INTEL_MATCH",
  "IOC_KNOWN_C2_DOMAIN",
  "IOC_KNOWN_C2_IP",
  "IOC_KNOWN_C2_WALLET",
  "IOC_KNOWN_DEAD_DROP",
  "IOC_KNOWN_MALICIOUS_ACCOUNT",
  "IOC_KNOWN_MALWARE_HASH",
];

const policy = loadPolicyConfig(ROOT) as PolicyConfig;
const finding = (rule: string, file: string): Finding => ({
  rule,
  file,
  description: "test finding",
  severity: "critical",
  recommendation: "none",
});
const suppressed = (rule: string, file: string) =>
  applyPolicy([finding(rule, file)], policy).findings.length === 0;

describe("the repository's self-scan policy", () => {
  it("loads", () => {
    expect(policy).not.toBeNull();
    expect(policy.suppress?.length ?? 0).toBeGreaterThan(0);
  });

  it("never suppresses an IOC rule without a path", () => {
    const bare = (policy.suppress ?? []).filter((s) => IOC_RULES.includes(s.rule) && s.path === undefined);
    expect(bare).toEqual([]);
  });

  it("suppresses the IOC rules on the feed and the blocklist, source and build", () => {
    for (const file of ["src/threat-intel.ts", "dist/threat-intel.js", "src/ioc-blocklist.ts", "dist/ioc-blocklist.js"]) {
      for (const rule of ["THREAT_INTEL_MATCH", "IOC_KNOWN_C2_DOMAIN", "IOC_KNOWN_MALWARE_HASH", "IOC_KNOWN_DEAD_DROP"]) {
        expect(suppressed(rule, file), `${rule} on ${file}`).toBe(true);
      }
    }
  });

  it("still reports the same indicator anywhere else in the tree (control)", () => {
    const elsewhere = [
      "src/scanner.ts",
      "dist/scanner.js",
      "scripts/import-threat-feed.mjs",
      "package.json",
      "README.md",
      ".github/workflows/ci.yml",
      "src/__tests__/scanner.test.ts",
      "src/threat-intel.ts.bak",
      "vendor/src/threat-intel.ts",
      "dist/threat-intel.js.map",
    ];
    for (const file of elsewhere) {
      for (const rule of IOC_RULES) {
        expect(suppressed(rule, file), `${rule} on ${file}`).toBe(false);
      }
    }
  });

  it("does not switch off other rules on the suppressed files", () => {
    for (const rule of ["EVAL_ATOB", "CODECOV_EXFIL", "INSTALL_SCRIPT_CURL", "OBFUSCATED_HEX"]) {
      expect(suppressed(rule, "src/threat-intel.ts"), rule).toBe(false);
      expect(suppressed(rule, "dist/ioc-blocklist.js"), rule).toBe(false);
    }
  });

  it("names only files this repository has", () => {
    const missing: string[] = [];
    for (const s of policy.suppress ?? []) {
      if (s.path === undefined || /[*?]/.test(s.path)) continue;
      // dist/ is the gitignored tsc output of src/, so a dist entry stands for
      // its source module.
      const source = s.path.startsWith("dist/")
        ? s.path.replace(/^dist\//, "src/").replace(/\.js$/, ".ts")
        : s.path;
      if (!fs.existsSync(path.join(ROOT, source))) missing.push(`${s.rule} ${s.path}`);
    }
    expect(missing).toEqual([]);
  });
});
