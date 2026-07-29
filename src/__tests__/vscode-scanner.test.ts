import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync, execSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import {
  scanVscodeExtension,
  scanExtractedVscodeFile,
  scanExtractedVscodeFiles,
  VSCODE_ENCODED_BUFFER_PATTERN,
  VSCODE_STRING_ARRAY_PATTERN,
} from "../vscode-scanner.js";
import { MAX_FILE_SIZE, matchPatternInContent, truncateMatch } from "../patterns.js";
import type { Finding } from "../types.js";

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

  it("scans bundled dependencies shipped inside an extracted VSIX", () => {
    const bundledFile = path.join(
      tempDir,
      "extension",
      "node_modules",
      "bundled-dependency",
      "index.js",
    );
    fs.mkdirSync(path.dirname(bundledFile), { recursive: true });
    fs.writeFileSync(bundledFile, 'eval(atob("cGF5bG9hZA=="));');

    const findings: Finding[] = [];
    const counts = scanExtractedVscodeFiles(tempDir, findings);

    expect(counts).toEqual({ totalFiles: 1, filesScanned: 1 });
    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule: "EVAL_ATOB",
          file: expect.stringMatching(
            /extension[\\/]node_modules[\\/]bundled-dependency[\\/]index\.js$/,
          ),
        }),
      ]),
    );
  });

  it.skipIf(process.platform === "win32")(
    "bounds an oversized extension manifest and reports one partial finding",
    async () => {
      const oversizedManifest = JSON.stringify({
        activationEvents: ["*"],
        padding: "x".repeat(MAX_FILE_SIZE),
      });
      const vsixPath = createVsix(tempDir, {
        "extension/package.json": oversizedManifest,
      });

      const report = await scanVscodeExtension({ target: vsixPath, format: "json" });
      const oversized = report.findings.filter((finding) =>
        finding.rule === "FILE_TOO_LARGE_SKIPPED" &&
        finding.file === "extension/package.json"
      );

      expect(oversized).toHaveLength(1);
      expect(report.partialScan).toBe(true);
      expect(report.findings.some((finding) =>
        finding.rule === "VSCODE_SUSPICIOUS_ACTIVATION" ||
        finding.rule === "VSCODE_INSTALL_SCRIPT"
      )).toBe(false);
    },
  );
  it.skipIf(process.platform === "win32")(
    "rejects an external manifest symlink without leaking or analyzing outside content",
    async () => {
      const staging = path.join(tempDir, "external-staging");
      const extensionDir = path.join(staging, "extension");
      fs.mkdirSync(extensionDir, { recursive: true });
      const secretMarker = "OUTSIDE_MANIFEST_SECRET_7f6a";
      const outsideManifest = path.join(tempDir, "outside-package.json");
      fs.writeFileSync(outsideManifest, JSON.stringify({
        activationEvents: ["*"],
        scripts: { postinstall: `echo ${secretMarker}` },
      }));
      fs.symlinkSync(outsideManifest, path.join(extensionDir, "package.json"), "file");
      fs.writeFileSync(path.join(staging, "[Content_Types].xml"), "<Types />");
      const vsixPath = path.join(tempDir, "external-manifest.vsix");
      execFileSync("zip", ["-q", "-y", "-r", vsixPath, "."], { cwd: staging });

      const report = await scanVscodeExtension({ target: vsixPath, format: "json" });

      expect(report.partialScan).toBe(true);
      expect(report.findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          rule: "PATH_SCAN_INCOMPLETE",
          file: "extension/package.json",
        }),
      ]));
      expect(report.findings.some((finding) =>
        finding.rule === "VSCODE_SUSPICIOUS_ACTIVATION" ||
        finding.rule === "VSCODE_INSTALL_SCRIPT",
      )).toBe(false);
      expect(JSON.stringify(report)).not.toContain(secretMarker);
    },
  );

  it.skipIf(process.platform === "win32")(
    "analyzes an internal manifest symlink under its public package.json path",
    async () => {
      const staging = path.join(tempDir, "internal-staging");
      const extensionDir = path.join(staging, "extension");
      fs.mkdirSync(extensionDir, { recursive: true });
      fs.writeFileSync(
        path.join(extensionDir, "manifest.json"),
        JSON.stringify({ activationEvents: ["*"] }),
      );
      fs.symlinkSync("manifest.json", path.join(extensionDir, "package.json"), "file");
      fs.writeFileSync(path.join(staging, "[Content_Types].xml"), "<Types />");
      const vsixPath = path.join(tempDir, "internal-manifest.vsix");
      execFileSync("zip", ["-q", "-y", "-r", vsixPath, "."], { cwd: staging });

      const report = await scanVscodeExtension({ target: vsixPath, format: "json" });

      expect(report.findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          rule: "VSCODE_SUSPICIOUS_ACTIVATION",
          file: "extension/package.json",
        }),
      ]));
    },
  );
  it("surfaces an extracted source stat failure as partial coverage", () => {
    const findings: Finding[] = [];
    const missing = path.join(tempDir, "vanished.js");

    expect(scanExtractedVscodeFile(tempDir, missing, findings)).toBe(false);
    expect(findings).toEqual([
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        severity: "info",
        file: "vanished.js",
      }),
    ]);
  });

  it.skipIf(process.platform === "win32")(
    "surfaces a denied extracted source read as partial coverage",
    (context) => {
      const file = path.join(tempDir, "denied.js");
      fs.writeFileSync(file, "const safe = true;");
      fs.chmodSync(file, 0o000);

      let denied = false;
      try { fs.readFileSync(file); } catch { denied = true; }
      if (!denied) {
        fs.chmodSync(file, 0o600);
        context.skip();
        return;
      }

      try {
        const findings: Finding[] = [];
        expect(scanExtractedVscodeFile(tempDir, file, findings)).toBe(false);
        expect(findings).toEqual([
          expect.objectContaining({
            rule: "PATH_SCAN_INCOMPLETE",
            severity: "info",
            file: "denied.js",
          }),
        ]);
      } finally {
        fs.chmodSync(file, 0o600);
      }
    },
  );

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

  it("preserves encoded Buffer regex matching, starts, lines, and evidence", () => {
    const lines = [
      "Buffer.from(data, 'base64')",
      'Buffer.from \t( value ,\t"hex" \r)',
      '$Buffer.from(x,\'base64")',
      "\u00e9Buffer.from(value, \"hex\")",
      "Buffer.from(value,\u2028'hex'\u2028)",
      "Buffer.from( , 'base64')",
      "Buffer.from(Buffer.from(x, 'hex')",
      "Buffer.from(nope) Buffer.from(x, 'hex')",
      "xBuffer.from(value, 'base64')",
      "_Buffer.from(value, 'base64')",
      "buffer.from(value, 'base64')",
      "Buffer.From(value, 'base64')",
      "Buffer.from(,'base64')",
      "Buffer.from(value), 'base64')",
      "Buffer.from(value, 'BASE64')",
      "Buffer.from(value, 'utf8')",
      "Buffer.from(value, 'base64' extra)",
      "Buffer.from(value,",
      "'base64')",
    ];
    const content = lines.join("\n");
    const baseline = matchPatternInContent(
      { ...VSCODE_ENCODED_BUFFER_PATTERN, correlatedMatcher: undefined },
      content,
      "g",
    );
    const structural = matchPatternInContent(
      VSCODE_ENCODED_BUFFER_PATTERN,
      content,
      "g",
    );
    const lineStarts: number[] = [];
    let offset = 0;
    for (const line of lines) {
      lineStarts.push(offset);
      offset += line.length + 1;
    }

    expect(baseline.map((hit) => hit.line)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(structural.map((hit) => hit.line)).toEqual(
      baseline.map((hit) => hit.line),
    );
    expect(structural.map((hit) => hit.match.index)).toEqual(
      baseline.map(
        (hit) => lineStarts[hit.line - 1]! + (hit.match.index ?? 0),
      ),
    );
    expect(structural.map((hit) => truncateMatch(hit.text))).toEqual(
      baseline.map((hit) => truncateMatch(hit.text)),
    );
    expect(structural.coverage.complete).toBe(true);
    expect(structural.coverage.regexAttempts).toBe(1);
  });

  it(
    "fully evaluates a 5 MiB repeated Buffer.from( near-miss",
    { timeout: 15_000 },
    () => {
      const fiveMiB = 5 * 1024 * 1024;
      const unit = "Buffer.from(";
      const content = unit
        .repeat(Math.ceil(fiveMiB / unit.length))
        .slice(0, fiveMiB);
      const started = performance.now();
      const hits = matchPatternInContent(
        VSCODE_ENCODED_BUFFER_PATTERN,
        content,
        "g",
      );

      expect(hits).toEqual([]);
      expect(hits.coverage.complete).toBe(true);
      expect(hits.coverage.regexAttempts).toBe(1);
      expect(hits.coverage.tiledRanges).toBe(0);
      expect(performance.now() - started).toBeLessThan(5_000);
    },
  );

  it("preserves large string-array regex matching, starts, lines, and evidence", () => {
    const array = (count: number, value = "a") =>
      `[${Array.from({ length: count }, () => `'${value}'`).join(",")}]`;
    const lines = [
      array(21),
      `prefix ${array(25, "abcd")} suffix`,
      `[ \r'a'\u2028,\u2029${Array.from({ length: 20 }, () => '"bc"').join(", ")} ]`,
      array(20),
      `[${Array.from({ length: 21 }, () => "''").join(",")}]`,
      array(21, "abcde"),
      `[${Array.from({ length: 10 }, () => "'a'").join(",")}`,
      `${Array.from({ length: 11 }, () => "'a'").join(",")}]`,
      `${array(21)} ${array(22, "b")}`,
    ];
    const content = lines.join("\n");
    const baseline = matchPatternInContent(
      { ...VSCODE_STRING_ARRAY_PATTERN, correlatedMatcher: undefined },
      content,
      "g",
    );
    const structural = matchPatternInContent(
      VSCODE_STRING_ARRAY_PATTERN,
      content,
      "g",
    );
    const lineStarts: number[] = [];
    let offset = 0;
    for (const line of lines) {
      lineStarts.push(offset);
      offset += line.length + 1;
    }

    expect(structural.map((hit) => hit.line)).toEqual(
      baseline.map((hit) => hit.line),
    );
    expect(structural.map((hit) => hit.match.index)).toEqual(
      baseline.map(
        (hit) => lineStarts[hit.line - 1]! + (hit.match.index ?? 0),
      ),
    );
    expect(structural.map((hit) => truncateMatch(hit.text))).toEqual(
      baseline.map((hit) => truncateMatch(hit.text)),
    );
    expect(structural.coverage.complete).toBe(true);
    expect(structural.coverage.regexAttempts).toBe(1);
  });

  it(
    "fully evaluates a 5 MiB unterminated string array",
    { timeout: 15_000 },
    () => {
      const fiveMiB = 5 * 1024 * 1024;
      const unit = "'abcd',";
      const content = (`[${unit.repeat(Math.ceil(fiveMiB / unit.length))}`)
        .slice(0, fiveMiB);
      const started = performance.now();
      const hits = matchPatternInContent(
        VSCODE_STRING_ARRAY_PATTERN,
        content,
        "g",
      );

      expect(hits).toEqual([]);
      expect(hits.coverage.complete).toBe(true);
      expect(hits.coverage.regexAttempts).toBe(1);
      expect(hits.coverage.tiledRanges).toBe(0);
      expect(performance.now() - started).toBeLessThan(5_000);
    },
  );

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
