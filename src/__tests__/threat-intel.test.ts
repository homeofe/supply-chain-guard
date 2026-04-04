import { describe, it, expect } from "vitest";
import { loadThreatIntel, checkThreatIntel } from "../threat-intel.js";
import type { FeedIOC } from "../threat-intel.js";

describe("Threat Intelligence", () => {
  it("should load bundled threat feed", () => {
    const feed = loadThreatIntel();
    expect(feed.length).toBeGreaterThan(5);
    expect(feed.some((i) => i.family === "Vidar")).toBe(true);
    expect(feed.some((i) => i.family === "GhostSocks")).toBe(true);
  });

  it("should detect known C2 domain from feed", () => {
    const feed = loadThreatIntel();
    const content = 'const c2 = "https://rti.cargomanbd.com/api/data";';
    const findings = checkThreatIntel(content, "malware.js", feed);
    expect(findings.some((f) => f.rule === "THREAT_INTEL_MATCH")).toBe(true);
    expect(findings[0]?.description).toContain("Vidar");
  });

  it("should detect known C2 IP from feed", () => {
    const feed = loadThreatIntel();
    const content = 'connect("147.45.197.92", 443);';
    const findings = checkThreatIntel(content, "backdoor.js", feed);
    expect(findings.some((f) => f.rule === "THREAT_INTEL_MATCH")).toBe(true);
  });

  it("should detect known hash from feed", () => {
    const feed = loadThreatIntel();
    const content = "sha256: 77c73bd5e7625b7f691bc00a1b561a0f";
    const findings = checkThreatIntel(content, "config.json", feed);
    expect(findings.some((f) => f.rule === "THREAT_INTEL_MATCH")).toBe(true);
  });

  it("should return empty for clean content", () => {
    const feed = loadThreatIntel();
    const content = 'const x = "hello world";';
    const findings = checkThreatIntel(content, "clean.js", feed);
    expect(findings).toHaveLength(0);
  });

  it("should include confidence and category", () => {
    const feed = loadThreatIntel();
    const content = 'fetch("https://rti.cargomanbd.com")';
    const findings = checkThreatIntel(content, "test.js", feed);
    expect(findings[0]?.confidence).toBeGreaterThan(0);
    expect(findings[0]?.category).toBe("malware");
  });

  it("should skip package-type IOCs in content check", () => {
    const feed: FeedIOC[] = [
      { type: "package", value: "axios@1.14.1", severity: "critical", confidence: 1.0 },
    ];
    const content = "axios@1.14.1";
    const findings = checkThreatIntel(content, "test.js", feed);
    expect(findings).toHaveLength(0); // Packages checked separately
  });
});
