import { beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const childProcess = vi.hoisted(() => ({
  execFileSync: vi.fn(),
}));

vi.mock("node:child_process", () => ({
  execFileSync: childProcess.execFileSync,
}));

import { extractTarGz, extractZip } from "../archive-extractor.js";

describe("archive extraction shell hardening", () => {
  beforeEach(() => {
    childProcess.execFileSync.mockReset();
  });

  it("passes a shell-metacharacter VSIX path as one literal argv element", () => {
    const archivePath = path.join(
      os.tmpdir(),
      "payload$(printf injected).vsix",
    );
    const extractDir = path.join(os.tmpdir(), "extract-target");

    extractZip(archivePath, extractDir, true);

    expect(childProcess.execFileSync).toHaveBeenCalledOnce();
    expect(childProcess.execFileSync).toHaveBeenCalledWith(
      "unzip",
      ["-q", "-o", archivePath, "-d", extractDir],
      { stdio: "pipe" },
    );
  });

  it("uses argv arrays for zip and tar extraction", () => {
    const archivePath = "-package;&.tar.gz";
    const extractDir = "-extract;&";
    const resolvedArchivePath = path.resolve(archivePath);
    const resolvedExtractDir = path.resolve(extractDir);

    extractTarGz(archivePath, extractDir);
    extractZip(archivePath, extractDir);

    expect(childProcess.execFileSync).toHaveBeenNthCalledWith(
      1,
      "tar",
      ["xzf", resolvedArchivePath, "-C", resolvedExtractDir],
      { stdio: "pipe" },
    );
    expect(childProcess.execFileSync).toHaveBeenNthCalledWith(
      2,
      "unzip",
      ["-q", resolvedArchivePath, "-d", resolvedExtractDir],
      { stdio: "pipe" },
    );
  });

  it("keeps production archive scanners free of shell-string execution", () => {
    const sourceRoot = path.resolve(__dirname, "..");
    for (const filename of [
      "vscode-scanner.ts",
      "npm-scanner.ts",
      "pypi-scanner.ts",
    ]) {
      const source = fs.readFileSync(path.join(sourceRoot, filename), "utf8");
      expect(source).not.toMatch(/\bexecSync\b/);
    }
  });
});
