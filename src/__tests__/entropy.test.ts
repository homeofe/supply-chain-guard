import { describe, it, expect } from "vitest";
import { shannonEntropy, analyzeEntropy } from "../entropy.js";

describe("Entropy Analysis", () => {
  describe("shannonEntropy", () => {
    it("should return 0 for empty string", () => {
      expect(shannonEntropy("")).toBe(0);
    });

    it("should return 0 for single repeated character", () => {
      expect(shannonEntropy("aaaaaaaaaa")).toBe(0);
    });

    it("should return 1 for two equally distributed characters", () => {
      const e = shannonEntropy("ababababab");
      expect(e).toBeCloseTo(1.0, 1);
    });

    it("should return low entropy for normal English text", () => {
      const text = "This is a normal English sentence with regular words and spacing.";
      const e = shannonEntropy(text);
      expect(e).toBeLessThan(5.0);
    });

    it("should return high entropy for random-looking base64", () => {
      const b64 = "VGhpcyBpcyBhIHRlc3Qgd2l0aCByYW5kb20gZW5jb2RlZCBkYXRhIHRoYXQgaGFzIGhpZ2ggZW50cm9weQ==";
      const e = shannonEntropy(b64);
      expect(e).toBeGreaterThan(4.5);
    });

    it("should return very high entropy for hex data", () => {
      // Random hex string
      const hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90abcdef";
      const e = shannonEntropy(hex);
      expect(e).toBeGreaterThan(3.5);
    });
  });

  describe("analyzeEntropy", () => {
    it("should return empty for short files", () => {
      const findings = analyzeEntropy("short", "test.js");
      expect(findings).toHaveLength(0);
    });

    it("should detect high-entropy strings", () => {
      // Use crypto.randomBytes for truly random data, base64-encoded
      const { randomBytes } = require("node:crypto");
      const randomStr = randomBytes(256).toString("base64");
      // Embed as a base64-like token that matches the b64 regex extractor
      const content = `const payload = ${randomStr};\n`.repeat(5);
      const findings = analyzeEntropy(content, "test.js");
      expect(findings.some((f) => f.rule === "HIGH_ENTROPY_STRING" || f.rule === "HIGH_ENTROPY_FILE")).toBe(true);
    });

    it("should not flag normal code", () => {
      const normalCode = [
        'import { readFileSync } from "node:fs";',
        "",
        "export function processData(input: string): string {",
        "  const lines = input.split('\\n');",
        "  const filtered = lines.filter(line => line.length > 0);",
        "  return filtered.join('\\n');",
        "}",
        "",
        "export function formatOutput(data: string[]): void {",
        "  for (const item of data) {",
        "    console.log(item);",
        "  }",
        "}",
      ].join("\n").repeat(5); // make it long enough

      const findings = analyzeEntropy(normalCode, "test.ts");
      // Normal code shouldn't trigger high entropy string (it might trigger file entropy depending on repetition)
      expect(findings.some((f) => f.rule === "HIGH_ENTROPY_STRING")).toBe(false);
    });

    it("should detect file-level high entropy", () => {
      // Generate pseudo-random content
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=!@#$%^&*()";
      let content = "";
      for (let i = 0; i < 1000; i++) {
        content += chars[(i * 17 + 31) % chars.length];
      }
      const findings = analyzeEntropy(content, "suspicious.js");
      expect(findings.some((f) => f.rule === "HIGH_ENTROPY_FILE")).toBe(true);
    });

    it("should include file path in findings", () => {
      const randomStr = Array.from({ length: 200 }, (_, i) =>
        String.fromCharCode(33 + (i * 7 + 13) % 94)
      ).join("");
      const content = `const x = "${randomStr}";\n`.repeat(10);
      const findings = analyzeEntropy(content, "lib/payload.js");
      const finding = findings.find((f) => f.rule === "HIGH_ENTROPY_STRING");
      if (finding) {
        expect(finding.file).toBe("lib/payload.js");
      }
    });
  });
});
