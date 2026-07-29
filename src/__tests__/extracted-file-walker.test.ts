import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import type { Finding } from "../types.js";
import {
  collectExtractedFiles,
  readContainedExtractedUtf8File,
} from "../extracted-file-walker.js";
import { extractTarGz, extractZip } from "../archive-extractor.js";
import { scanExtractedNpmFiles } from "../npm-scanner.js";
import { scanExtractedFiles as scanExtractedPypiFiles } from "../pypi-scanner.js";
import { scanExtractedVscodeFiles } from "../vscode-scanner.js";

describe("extracted artifact symlink traversal", () => {
  let root: string;
  beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-links-")); });
  afterEach(() => { fs.rmSync(root, { recursive: true, force: true }); });

  it("uses each internal file symlink's public path for scanner applicability", (context) => {
    const target = path.join(root, "payload.txt");
    fs.writeFileSync(target, 'eval(atob("cGF5bG9hZA=="));\nos.system("id")');
    for (const [name, scan, rule] of [
      ["payload.js", scanExtractedNpmFiles, "EVAL_ATOB"],
      ["setup.py", scanExtractedPypiFiles, "PYPI_OS_SYSTEM"],
      ["extension.js", scanExtractedVscodeFiles, "EVAL_ATOB"],
    ] as const) {
      const link = path.join(root, name);
      try { fs.symlinkSync(target, link, "file"); } catch { context.skip(); return; }
      const findings: Finding[] = [];
      scan(root, findings);
      expect(findings).toEqual(expect.arrayContaining([
        expect.objectContaining({ rule, file: name }),
      ]));
      fs.unlinkSync(link);
    }
  });

  it.skipIf(process.platform === "win32")("preserves and scans symlinks from tar and zip archives", () => {
    const source = path.join(root, "source");
    fs.mkdirSync(source);
    fs.writeFileSync(path.join(source, "payload.txt"), 'eval(atob("eA=="));');
    fs.symlinkSync("payload.txt", path.join(source, "public.js"), "file");

    const tarPath = path.join(root, "artifact.tgz");
    execFileSync("tar", ["czf", tarPath, "-C", source, "."]);
    const tarOut = path.join(root, "tar-out");
    fs.mkdirSync(tarOut);
    extractTarGz(tarPath, tarOut);

    const zipPath = path.join(root, "artifact.zip");
    execFileSync("zip", ["-q", "-y", "-r", zipPath, "."], { cwd: source });
    const zipOut = path.join(root, "zip-out");
    fs.mkdirSync(zipOut);
    extractZip(zipPath, zipOut);

    for (const extracted of [tarOut, zipOut]) {
      const findings: Finding[] = [];
      scanExtractedNpmFiles(extracted, findings);
      expect(findings).toEqual(expect.arrayContaining([
        expect.objectContaining({ rule: "EVAL_ATOB", file: "public.js" }),
      ]));
    }
  });
  it("retains distinct internal directory aliases and rejects cycles, broken links, and escapes", (context) => {
    const realDir = path.join(root, "real");
    fs.mkdirSync(realDir);
    fs.writeFileSync(path.join(realDir, "payload.js"), 'eval(atob("eA=="));');
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "scg-outside-"));
    try {
      try {
        fs.symlinkSync(realDir, path.join(root, "alias"), "dir");
        fs.symlinkSync(root, path.join(realDir, "cycle"), "dir");
        fs.symlinkSync(path.join(root, "missing"), path.join(root, "broken.js"), "file");
        fs.symlinkSync(outside, path.join(root, "escape"), "dir");
      } catch { context.skip(); return; }
      const findings: Finding[] = [];
      const files = collectExtractedFiles(root, findings);
      expect(files.map((file) => path.relative(root, file).replace(/\\/g, "/")))
        .toContain("alias/payload.js");
      expect(findings.filter((finding) => finding.rule === "PATH_SCAN_INCOMPLETE").map((finding) => finding.file).sort())
        .toEqual(["alias/cycle", "broken.js", "escape", "real/cycle"].sort());
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
  it("rejects an oversized contained read before loading its body", () => {
    const oversized = path.join(root, "package.json");
    fs.writeFileSync(oversized, "x".repeat(128));
    const findings: Finding[] = [];
    let observedSize = 0;

    const content = readContainedExtractedUtf8File(
      root,
      oversized,
      findings,
      {
        maxBytes: 64,
        onOversized: (sizeBytes) => { observedSize = sizeBytes; },
      },
    );

    expect(content).toBeNull();
    expect(observedSize).toBe(128);
    expect(findings).toHaveLength(0);
  });
  it("surfaces the configured recursion-depth boundary as partial coverage", () => {
    const tooDeep = path.join(root, "level-0", "level-1");
    fs.mkdirSync(tooDeep, { recursive: true });
    fs.writeFileSync(path.join(tooDeep, "payload.js"), 'eval(atob("eA=="));');

    const findings: Finding[] = [];
    const files = collectExtractedFiles(root, findings, { maxDepth: 1 });

    expect(files).toHaveLength(0);
    expect(findings).toEqual([
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        file: "level-0/level-1",
      }),
    ]);
  });

  it("bounds expanded public aliases in a non-cyclic symlink DAG", (context) => {
    const levelsRoot = path.join(root, "levels");
    fs.mkdirSync(levelsRoot);
    for (let level = 0; level <= 9; level++) {
      fs.mkdirSync(path.join(levelsRoot, String(level)));
    }
    fs.writeFileSync(path.join(levelsRoot, "9", "payload.js"), 'eval(atob("eA=="));');
    try {
      for (let level = 0; level < 9; level++) {
        const levelDir = path.join(levelsRoot, String(level));
        fs.symlinkSync(`../${level + 1}`, path.join(levelDir, "a"), "dir");
        fs.symlinkSync(`../${level + 1}`, path.join(levelDir, "b"), "dir");
      }
    } catch {
      context.skip();
      return;
    }

    const findings: Finding[] = [];
    const files = collectExtractedFiles(root, findings, {
      maxDepth: 64,
      maxEntries: 40,
    });

    expect(files.length).toBeLessThanOrEqual(40);
    expect(findings.filter((finding) => finding.rule === "PATH_SCAN_INCOMPLETE"))
      .toHaveLength(1);
  });
});