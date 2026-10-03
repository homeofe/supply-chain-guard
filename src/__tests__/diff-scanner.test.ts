import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { getChangedFiles, getChangedFilesResult } from "../diff-scanner.js";
import { scan } from "../scanner.js";

describe("diff-scanner injection hardening", () => {
  it("rejects a sinceCommit with shell metacharacters and does not run git", () => {
    // A crafted ref must never reach git; the guard returns an empty list
    // instead of executing anything.
    expect(getChangedFiles("/tmp", "main; echo pwned")).toEqual([]);
    expect(getChangedFiles("/tmp", "$(touch /tmp/scg-pwned)")).toEqual([]);
    expect(getChangedFiles("/tmp", "`id`")).toEqual([]);
    expect(getChangedFiles("/tmp", "a && rm -rf ~")).toEqual([]);
  });

  it("rejects a sinceCommit that looks like a git option", () => {
    expect(getChangedFiles("/tmp", "--output=/tmp/evil")).toEqual([]);
  });
});

describe("incremental scan result", () => {
  it("reports no changed files without scanning the full tree, and fails on an invalid ref", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-diff-result-"));
    try {
      fs.writeFileSync(path.join(dir, "index.js"), "export const value = 1;\n");
      const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "pipe" });
      git("init", "-q");
      git("config", "user.name", "Test");
      git("config", "user.email", "test@example.invalid");
      git("add", "index.js");
      git("commit", "-qm", "initial");

      expect(getChangedFilesResult(dir, "HEAD")).toEqual({ status: "ok", files: [] });
      const unchanged = await scan({ target: dir, format: "json", sinceCommit: "HEAD", noHistory: true });
      expect(unchanged.summary.filesScanned).toBe(0);
      expect(unchanged.findings.map((finding) => finding.rule)).toContain("DIFF_NO_CHANGES");
      expect(unchanged.findings.map((finding) => finding.rule)).not.toContain("SCAN_ZERO_COVERAGE");

      expect(getChangedFilesResult(dir, "missing-ref").status).toBe("error");
      const invalid = await scan({ target: dir, format: "json", sinceCommit: "missing-ref", noHistory: true });
      expect(invalid.findings.map((finding) => finding.rule)).toContain("DIFF_BASE_UNAVAILABLE");
      expect(invalid.partialScan).toBe(true);
      expect(invalid.summary.filesScanned).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
