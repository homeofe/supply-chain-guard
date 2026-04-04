import { describe, it, expect } from "vitest";
import {
  checkIOCBlocklist,
  checkBadVersion,
  KNOWN_C2_DOMAINS,
  KNOWN_C2_IPS,
  KNOWN_DEAD_DROPS,
  KNOWN_MALICIOUS_HASHES,
  KNOWN_BAD_NPM_VERSIONS,
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
});
