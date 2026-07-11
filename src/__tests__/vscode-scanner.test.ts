import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";
import { scanVscodeExtension } from "../vscode-scanner.js";

/**
 * Helper: create a minimal .vsix (zip) file from a directory structure.
 */
function createVsix(dir: string, files: Record<string, string>): string {
  const extDir = path.join(dir, "extension");
  fs.mkdirSync(extDir, { recursive: true });

  for (const [filePath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, filePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
  }

  // Also create [Content_Types].xml (required for vsix)
  fs.writeFileSync(
    path.join(dir, "[Content_Types].xml"),
    '<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
  );

  const vsixPath = path.join(dir, "test-extension.vsix");
  execSync(`cd "${dir}" && zip -q -r "${vsixPath}" .`, { stdio: "pipe" });
  return vsixPath;
}

describe("VS Code Extension Scanner", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-vscode-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("should return a clean report for a safe extension", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "safe-extension",
        version: "1.0.0",
        publisher: "testpub",
        engines: { vscode: "^1.70.0" },
        activationEvents: ["onLanguage:javascript"],
        main: "./extension.js",
      }),
      "extension/extension.js": `
const vscode = require('vscode');
function activate(context) {
  console.log('Extension activated');
}
module.exports = { activate };
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    expect(report.score).toBe(0);
    expect(report.riskLevel).toBe("clean");
    expect(report.findings).toHaveLength(0);
  });

  it("should detect suspicious activationEvent '*'", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "wildcard-ext",
        version: "1.0.0",
        publisher: "testpub",
        activationEvents: ["*"],
        main: "./extension.js",
      }),
      "extension/extension.js": "module.exports = { activate() {} };",
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const finding = report.findings.find(
      (f) => f.rule === "VSCODE_SUSPICIOUS_ACTIVATION",
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
    expect(finding?.description).toContain("*");
  });

  it("should detect onStartupFinished activationEvent", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "startup-ext",
        version: "1.0.0",
        publisher: "testpub",
        activationEvents: ["onStartupFinished"],
        main: "./extension.js",
      }),
      "extension/extension.js": "module.exports = { activate() {} };",
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const finding = report.findings.find(
      (f) => f.rule === "VSCODE_SUSPICIOUS_ACTIVATION",
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("should detect eval() in extension code", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "eval-ext",
        version: "1.0.0",
        publisher: "testpub",
        main: "./extension.js",
      }),
      "extension/extension.js": `
function activate(context) {
  const code = getCode();
  eval(code);
}
module.exports = { activate };
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const finding = report.findings.find((f) => f.rule === "VSCODE_EVAL");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("should detect child_process usage", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "exec-ext",
        version: "1.0.0",
        publisher: "testpub",
        main: "./extension.js",
      }),
      "extension/extension.js": `
const child_process = require('child_process');
function activate() {
  child_process.execSync('whoami');
}
module.exports = { activate };
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const cpFinding = report.findings.find(
      (f) => f.rule === "VSCODE_CHILD_PROCESS",
    );
    expect(cpFinding).toBeDefined();
    expect(cpFinding?.severity).toBe("medium");

    const execFinding = report.findings.find(
      (f) => f.rule === "VSCODE_EXEC",
    );
    expect(execFinding).toBeDefined();
  });

  it("should detect obfuscated code patterns", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "obfuscated-ext",
        version: "1.0.0",
        publisher: "testpub",
        main: "./extension.js",
      }),
      "extension/extension.js": `
var _0xabc1 = _0xdef2, _0x1234 = _0x5678, _0xabcd = _0xef01, _0x9999 = _0x8888;
function _0xabc1() { return _0xdef2[_0x1234]; }
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const finding = report.findings.find(
      (f) => f.rule === "VSCODE_OBFUSCATED_VARS",
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("should detect network request capabilities", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "network-ext",
        version: "1.0.0",
        publisher: "testpub",
        main: "./extension.js",
      }),
      "extension/extension.js": `
const https = require('https');
function activate() {
  fetch('https://evil.com/data');
}
module.exports = { activate };
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const finding = report.findings.find(
      (f) => f.rule === "VSCODE_NETWORK",
    );
    expect(finding).toBeDefined();
  });

  it("should detect base64 encoding usage", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "base64-ext",
        version: "1.0.0",
        publisher: "testpub",
        main: "./extension.js",
      }),
      "extension/extension.js": `
function activate() {
  const payload = atob("dGVzdA==");
  const data = Buffer.from("aGVsbG8=", "base64").toString();
}
module.exports = { activate };
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const b64Finding = report.findings.find(
      (f) => f.rule === "VSCODE_BASE64",
    );
    expect(b64Finding).toBeDefined();

    const bufFinding = report.findings.find(
      (f) => f.rule === "VSCODE_ENCODED_BUFFER",
    );
    expect(bufFinding).toBeDefined();
  });

  it("should detect hex-encoded strings", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "hex-ext",
        version: "1.0.0",
        publisher: "testpub",
        main: "./extension.js",
      }),
      "extension/extension.js": `
const payload = "\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64\\x21";
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const finding = report.findings.find(
      (f) => f.rule === "VSCODE_HEX_STRINGS",
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("should detect postinstall scripts in extension package.json", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "install-script-ext",
        version: "1.0.0",
        publisher: "testpub",
        main: "./extension.js",
        scripts: {
          postinstall: "node setup.js",
        },
      }),
      "extension/extension.js": "module.exports = { activate() {} };",
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const finding = report.findings.find(
      (f) => f.rule === "VSCODE_INSTALL_SCRIPT",
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("should handle non-existent vsix file", async () => {
    await expect(
      scanVscodeExtension({
        target: "/nonexistent/file.vsix",
        format: "text",
      }),
    ).rejects.toThrow("VSIX file not found");
  });

  it("should detect GlassWorm markers in extension code", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "glassworm-ext",
        version: "1.0.0",
        publisher: "testpub",
        main: "./extension.js",
      }),
      "extension/extension.js": `
const lzcdrtfxyqiplpd = true;
eval(atob("dGVzdA=="));
module.exports = { activate() {} };
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    // Should detect the GlassWorm marker via general patterns
    const marker = report.findings.find(
      (f) => f.rule === "GLASSWORM_MARKER",
    );
    expect(marker).toBeDefined();
    expect(marker?.severity).toBe("critical");

    // Should detect eval(atob()) via general patterns
    const evalAtob = report.findings.find((f) => f.rule === "EVAL_ATOB");
    expect(evalAtob).toBeDefined();
  });

  it("should generate appropriate recommendations", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "suspicious-ext",
        version: "1.0.0",
        publisher: "testpub",
        activationEvents: ["*"],
        main: "./extension.js",
      }),
      "extension/extension.js": `
var _0xabc1 = _0xdef2, _0x1234 = _0x5678, _0xabcd = _0xef01, _0x9999 = _0x8888;
eval("test");
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    expect(report.recommendations.length).toBeGreaterThan(0);
    expect(
      report.recommendations.some((r) => r.includes("activation events")),
    ).toBe(true);
    expect(
      report.recommendations.some((r) => r.includes("Obfuscated")),
    ).toBe(true);
  });

  it("should respect minSeverity filter", async () => {
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "mixed-severity-ext",
        version: "1.0.0",
        publisher: "testpub",
        activationEvents: ["onStartupFinished"],
        main: "./extension.js",
      }),
      "extension/extension.js": `
const https = require('https');
eval("dangerous");
fetch('https://example.com');
`,
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
      minSeverity: "high",
    });

    // Should only have high or above severity findings
    expect(
      report.findings.every(
        (f) => f.severity === "high" || f.severity === "critical",
      ),
    ).toBe(true);
  });

  // issue #54 regression: oversized files inside a VSIX are surfaced, not
  // silently skipped. Requires the zip binary like the rest of this suite.
  it("should surface an oversized file inside the extension (FILE_TOO_LARGE_SKIPPED)", async () => {
    const { MAX_FILE_SIZE } = await import("../patterns.js");
    const vsixPath = createVsix(tempDir, {
      "extension/package.json": JSON.stringify({
        name: "big-file-ext",
        version: "1.0.0",
        publisher: "testpub",
        engines: { vscode: "^1.70.0" },
        activationEvents: ["onLanguage:javascript"],
        main: "./extension.js",
      }),
      "extension/extension.js": "module.exports = { activate() {} };",
      "extension/bundle.js": "x".repeat(MAX_FILE_SIZE + 1),
    });

    const report = await scanVscodeExtension({
      target: vsixPath,
      format: "text",
    });

    const skip = report.findings.find((f) => f.rule === "FILE_TOO_LARGE_SKIPPED");
    expect(skip).toBeDefined();
    expect(skip?.severity).toBe("info");
    expect(skip?.file).toContain("bundle.js");
  });
});
