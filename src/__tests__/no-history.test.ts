/**
 * Tests for the scan history opt-out (--no-history / ScanOptions.noHistory).
 *
 * The pre-commit hook entry uses --no-history so the hook never writes state
 * (.scg-history/) into the consumer repository it is gating. Library level:
 * scan({ noHistory: true }) must skip saveRiskHistory. CLI level: the
 * commander negated option --no-history must thread through to the scanner.
 * The CLI tests run the compiled dist/cli.js (like cli.test.ts) and skip
 * cleanly when dist has not been built.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../scanner.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../..");
const CLI = path.join(ROOT, "dist", "cli.js");

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-nohist-"));
  fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("ok");\n');
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

const historyDir = () => path.join(tmpDir, ".scg-history");

describe("scan history opt-out (library)", () => {
  it("control: without noHistory, scan writes .scg-history/", async () => {
    await scan({ target: tmpDir, format: "json" });
    expect(fs.existsSync(historyDir())).toBe(true);
  });

  it("with noHistory: true, scan writes no .scg-history/", async () => {
    await scan({ target: tmpDir, format: "json", noHistory: true });
    expect(fs.existsSync(historyDir())).toBe(false);
  });

  it("noHistory: false behaves like the default (history is written)", async () => {
    await scan({ target: tmpDir, format: "json", noHistory: false });
    expect(fs.existsSync(historyDir())).toBe(true);
  });

  it("noHistory does not change the report itself", async () => {
    const report = await scan({ target: tmpDir, format: "json", noHistory: true });
    expect(report.summary).toBeDefined();
    expect(report.score).toBeGreaterThanOrEqual(0);
    expect(report.riskLevel).toBeDefined();
  });
});

describe.skipIf(!fs.existsSync(CLI))("scan history opt-out (CLI --no-history)", () => {
  function cli(args: string[]): { stdout: string; status: number } {
    const result = spawnSync(process.execPath, [CLI, ...args], {
      encoding: "utf-8",
      timeout: 30000,
    });
    return { stdout: result.stdout ?? "", status: result.status ?? 1 };
  }

  it("control: scan without the flag writes .scg-history/", () => {
    const { status } = cli(["scan", tmpDir, "--format", "json"]);
    expect(status).toBe(0);
    expect(fs.existsSync(historyDir())).toBe(true);
  });

  it("scan with --no-history writes no .scg-history/", () => {
    const { status } = cli(["scan", tmpDir, "--format", "json", "--no-history"]);
    expect(status).toBe(0);
    expect(fs.existsSync(historyDir())).toBe(false);
  });

  it("--no-history is documented in scan --help", () => {
    const { stdout, status } = cli(["scan", "--help"]);
    expect(status).toBe(0);
    expect(stdout).toContain("--no-history");
  });
});
