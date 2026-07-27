import { describe, it, expect } from "vitest";
import {
  checkIOCBlocklist,
  checkBadVersion,
  KNOWN_C2_DOMAINS,
  KNOWN_C2_IPS,
  KNOWN_DEAD_DROPS,
  KNOWN_MALICIOUS_HASHES,
  KNOWN_BAD_NPM_VERSIONS,
  KNOWN_BAD_PYPI_VERSIONS,
  KNOWN_C2_WALLETS,
} from "../ioc-blocklist.js";

describe("IOC Blocklist", () => {
  describe("checkIOCBlocklist", () => {
    it("should detect known C2 domains", () => {
      const content = 'const url = "https://rti.cargomanbd.com/api/collect";';
      const findings = checkIOCBlocklist(content, "malware.js");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_C2_DOMAIN")).toBe(true);
    });

    it("should detect known C2 IPs", () => {
      const content = 'connect("147.45.197.92", 443);';
      const findings = checkIOCBlocklist(content, "backdoor.js");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_C2_IP")).toBe(true);
    });

    it("should detect known dead-drop resolver URLs", () => {
      const content = 'fetch("https://steamcommunity.com/profiles/76561198721263282")';
      const findings = checkIOCBlocklist(content, "resolver.js");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_DEAD_DROP")).toBe(true);
    });

    it("should detect known malware hashes", () => {
      const content = "hash: 77c73bd5e7625b7f691bc00a1b561a0f";
      const findings = checkIOCBlocklist(content, "config.json");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_MALWARE_HASH")).toBe(true);
    });

    it("should detect known malicious GitHub accounts", () => {
      const content = 'git clone https://github.com/idbzoomh1/repo';
      const findings = checkIOCBlocklist(content, "script.sh");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT")).toBe(true);
    });

    it("should return empty for clean content", () => {
      const content = 'const x = "hello world";';
      const findings = checkIOCBlocklist(content, "clean.js");
      expect(findings).toHaveLength(0);
    });

    it("should have populated blocklists", () => {
      expect(KNOWN_C2_DOMAINS.length).toBeGreaterThan(0);
      expect(KNOWN_C2_IPS.length).toBeGreaterThan(0);
      expect(KNOWN_DEAD_DROPS.length).toBeGreaterThan(0);
      expect(Object.keys(KNOWN_MALICIOUS_HASHES).length).toBeGreaterThan(0);
    });
  });

  describe("checkBadVersion", () => {
    it("should detect known-bad axios version", () => {
      const finding = checkBadVersion("axios", "1.14.1", "npm");
      expect(finding).not.toBeNull();
      expect(finding!.rule).toBe("IOC_KNOWN_BAD_VERSION");
      expect(finding!.severity).toBe("critical");
    });

    it("should detect known-bad ua-parser-js version", () => {
      const finding = checkBadVersion("ua-parser-js", "0.7.29", "npm");
      expect(finding).not.toBeNull();
    });

    it("should detect known-bad event-stream version", () => {
      const finding = checkBadVersion("event-stream", "3.3.6", "npm");
      expect(finding).not.toBeNull();
    });

    it("should detect known-bad coa version", () => {
      const finding = checkBadVersion("coa", "2.0.3", "npm");
      expect(finding).not.toBeNull();
    });

    it("should not flag clean versions", () => {
      const finding = checkBadVersion("axios", "1.7.0", "npm");
      expect(finding).toBeNull();
    });

    it("should not flag unknown packages", () => {
      const finding = checkBadVersion("express", "4.18.2", "npm");
      expect(finding).toBeNull();
    });

    it("should have npm bad versions populated", () => {
      expect(Object.keys(KNOWN_BAD_NPM_VERSIONS).length).toBeGreaterThan(5);
    });
  });

  // -------------------------------------------------------------------------
  // PyPI name normalization (PEP 503)
  // -------------------------------------------------------------------------

  describe("PyPI name normalization", () => {
    // PyPI treats names case-insensitively and collapses -, _ and . runs, so
    // "LiteLLM==1.82.7" in a requirements.txt is the same project as "litellm".
    // The raw lookup missed every non-canonical spelling.
    const pypiName = Object.keys(KNOWN_BAD_PYPI_VERSIONS)[0]!;
    const pypiVersion = KNOWN_BAD_PYPI_VERSIONS[pypiName]!.versions[0]!;

    it("flags the canonical spelling", () => {
      expect(checkBadVersion(pypiName, pypiVersion, "pypi")).not.toBeNull();
    });

    it("flags an upper-cased spelling of the same project", () => {
      expect(checkBadVersion(pypiName.toUpperCase(), pypiVersion, "pypi")).not.toBeNull();
    });

    it("flags a separator variant of the same project", () => {
      // PEP 503 collapses runs of -, _ and . to a single "-".
      const variant = pypiName.replace(/-/g, "_");
      expect(checkBadVersion(variant, pypiVersion, "pypi")).not.toBeNull();
    });

    it("still does not flag a clean version of a blocked PyPI project", () => {
      expect(checkBadVersion(pypiName.toUpperCase(), "0.0.0-clean", "pypi")).toBeNull();
    });

    it("does not normalize npm, whose names are case-sensitive at the registry", () => {
      // Widening a match is only safe when the registry itself considers the
      // two names identical. npm does not, so an upper-cased npm name must NOT
      // resolve to a different, blocked package.
      const npmName = Object.keys(KNOWN_BAD_NPM_VERSIONS)[0]!;
      const npmVersion = KNOWN_BAD_NPM_VERSIONS[npmName]!.versions[0]!;
      expect(checkBadVersion(npmName, npmVersion, "npm")).not.toBeNull();
      if (npmName !== npmName.toUpperCase()) {
        expect(checkBadVersion(npmName.toUpperCase(), npmVersion, "npm")).toBeNull();
      }
    });
  });

  // -------------------------------------------------------------------------
  // Known C2 blockchain wallets
  // -------------------------------------------------------------------------

  describe("KNOWN_C2_WALLETS", () => {
    const addresses = Object.keys(KNOWN_C2_WALLETS);

    it("is populated", () => {
      expect(addresses.length).toBeGreaterThan(0);
    });

    it("detects a known C2 wallet referenced in source", () => {
      const address = addresses[0]!;
      const findings = checkIOCBlocklist(`const payout = "${address}";`, "payout.ts");
      const hit = findings.find((f) => f.rule === "IOC_KNOWN_C2_WALLET");
      expect(hit).toBeDefined();
      expect(hit?.severity).toBe("critical");
    });

    it("detects an Aptos address written with the 0x prefix", () => {
      // Addresses are stored without "0x" so a prefixed literal still matches.
      const hex = addresses.find((a) => /^[0-9a-f]{64}$/i.test(a));
      expect(hex, "expected a bare-hex wallet entry").toBeDefined();
      const findings = checkIOCBlocklist(`const acct = "0x${hex}";`, "c2.ts");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_C2_WALLET")).toBe(true);
    });

    it("matches case-insensitively", () => {
      const hex = addresses.find((a) => /^[0-9a-f]{64}$/i.test(a))!;
      const findings = checkIOCBlocklist(`"0x${hex.toUpperCase()}"`, "c2.ts");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_C2_WALLET")).toBe(true);
    });

    it("does NOT flag unrelated hex of the same shape", () => {
      // This is the false-positive that a shape/regex matcher would produce and
      // literal matching must not: a plain 64-hex value is indistinguishable
      // from a git object id, a keccak digest, or an Ethereum tx hash.
      const unrelated = "a".repeat(8) + "b".repeat(8) + "c".repeat(24) + "d".repeat(24);
      expect(unrelated).toHaveLength(64);
      const findings = checkIOCBlocklist(
        `const txHash = "0x${unrelated}";\nconst gitSha = "${unrelated}";`,
        "chain.ts",
      );
      expect(findings.some((f) => f.rule === "IOC_KNOWN_C2_WALLET")).toBe(false);
    });

    it("does NOT flag a wallet mentioned in a research write-up", () => {
      const address = addresses[0]!;
      const findings = checkIOCBlocklist(`The C2 wallet is ${address}.`, "docs/report.md");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_C2_WALLET")).toBe(false);
    });

    it("rejects short and low-entropy entries at load time", () => {
      // The runtime floor exists because the realistic ingest mistake is a
      // short-form address (Aptos renders framework accounts as "0x1"), which
      // would substring-match essentially every file. A unit test over a fixed
      // fixture list cannot catch a value nobody added to the fixture.
      for (const address of addresses) {
        const body = address.startsWith("0x") ? address.slice(2) : address;
        expect(body.length, address).toBeGreaterThanOrEqual(32);
        expect(new Set(body).size, address).toBeGreaterThanOrEqual(12);
      }
    });

    it("does not collide with the malware-hash blocklist", () => {
      // Independent loops with no cross-loop dedupe would double-report.
      for (const address of addresses) {
        const body = address.startsWith("0x") ? address.slice(2) : address;
        expect(Object.keys(KNOWN_MALICIOUS_HASHES)).not.toContain(body.toLowerCase());
      }
    });
  });
});
