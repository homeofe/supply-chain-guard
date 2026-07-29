import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Finding } from "../types.js";
import {
  listDiscoveredDirectory,
  listOptionalDirectory,
  readDiscoveredUtf8File,
  readOptionalUtf8File,
  recordUnreadablePath,
} from "../pattern-scanner.js";
import { scanGitSecurity } from "../git-scanner.js";
import { scanAgentSkillFiles } from "../skills-scanner.js";
import { scanCargoFiles } from "../cargo-scanner.js";
import { scanGoFiles } from "../go-scanner.js";
import { scanRubyGemsFiles } from "../rubygems-scanner.js";
import { scanComposerFiles } from "../composer-scanner.js";
import { scanPythonLockfiles } from "../python-lockfile-scanner.js";
import { scanNuGetFiles } from "../nuget-scanner.js";
import { checkLockfile } from "../lockfile-checker.js";

type Scanner = (dir: string) => Finding[];

interface UnreadableFileCase {
  name: string;
  relativePath: string;
  content: string;
  scan: Scanner;
}

const permissionChecksWork =
  process.platform !== "win32" &&
  typeof process.getuid === "function" &&
  process.getuid() !== 0;

function write(root: string, relativePath: string, content: string): string {
  const absolutePath = path.join(root, ...relativePath.split("/"));
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
  fs.writeFileSync(absolutePath, content, "utf-8");
  return absolutePath;
}

function coverageFindings(findings: Finding[]): Finding[] {
  return findings.filter((finding) => finding.rule === "PATH_SCAN_INCOMPLETE");
}

function expectPrivateDetailsHidden(finding: Finding, root: string): void {
  const rendered = JSON.stringify(finding);
  expect(rendered).not.toContain(root);
  expect(rendered).not.toMatch(/EACCES|EPERM|permission denied/i);
  expect(finding.file).not.toMatch(/^(?:[A-Za-z]:[\\/]|\/)/);
}

describe("specialized scanner I/O coverage", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-specialized-io-"));
  });

  afterEach(() => {
    fs.chmodSync(tmpDir, 0o700);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("treats absent optional targets as absent, not partial", () => {
    const scanners: Scanner[] = [
      scanGitSecurity,
      scanAgentSkillFiles,
      scanCargoFiles,
      scanGoFiles,
      scanRubyGemsFiles,
      scanComposerFiles,
      scanPythonLockfiles,
      scanNuGetFiles,
      checkLockfile,
    ];

    for (const scan of scanners) {
      expect(coverageFindings(scan(tmpDir))).toHaveLength(0);
    }
  });

  it("rejects external specialized symlinks and scans internal ones under the public path", (context) => {
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-outside-specialized-"));
    try {
      const outside = path.join(outsideDir, "outside-build.txt");
      const marker = "OUTSIDE_BUILD_MARKER_4d91";
      fs.writeFileSync(outside, `fn main() { Command::new("${marker}"); }`);
      try { fs.symlinkSync(outside, path.join(tmpDir, "build.rs"), "file"); }
      catch { context.skip(); return; }

      const externalFindings = scanCargoFiles(tmpDir);
      expect(coverageFindings(externalFindings)).toEqual([
        expect.objectContaining({ file: "build.rs" }),
      ]);
      expect(externalFindings.some((finding) => finding.rule === "CARGO_BUILD_RS_EXEC"))
        .toBe(false);
      expect(JSON.stringify(externalFindings)).not.toContain(marker);

      fs.unlinkSync(path.join(tmpDir, "build.rs"));
      write(tmpDir, "internal-payload.txt", 'fn main() { Command::new("id"); }');
      fs.symlinkSync("internal-payload.txt", path.join(tmpDir, "build.rs"), "file");
      const internalFindings = scanCargoFiles(tmpDir);
      expect(internalFindings).toEqual(expect.arrayContaining([
        expect.objectContaining({ rule: "CARGO_BUILD_RS_EXEC", file: "build.rs" }),
      ]));
    } finally {
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });
  it.skipIf(process.platform === "win32")(
    "keeps literal POSIX backslashes from broadening the trusted scan root",
    () => {
      const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-outside-backslash-"));
      try {
        const marker = "OUTSIDE_BACKSLASH_MARKER_b173";
        const outside = path.join(outsideDir, "outside.csproj");
        fs.writeFileSync(
          outside,
          `<Project><RestoreSources>http://${marker}.invalid/feed</RestoreSources></Project>`,
        );
        const publicName = "escape\\payload.csproj";
        fs.symlinkSync(outside, path.join(tmpDir, publicName), "file");

        const findings = scanNuGetFiles(tmpDir);
        expect(coverageFindings(findings)).toEqual([
          expect.objectContaining({ file: "escape/payload.csproj" }),
        ]);
        expect(findings.some((finding) => finding.rule !== "PATH_SCAN_INCOMPLETE"))
          .toBe(false);
        expect(JSON.stringify(findings)).not.toContain(marker);
      } finally {
        fs.rmSync(outsideDir, { recursive: true, force: true });
      }
    },
  );
  it.skipIf(process.platform === "win32")(
    "reports missing optional leaves behind escaping or broken parent symlinks",
    () => {
      const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-outside-parent-"));
      try {
        const parentLink = path.join(tmpDir, "linked-parent");
        fs.symlinkSync(outsideDir, parentLink, "dir");
        const externalFindings: Finding[] = [];
        expect(readOptionalUtf8File(
          tmpDir,
          path.join(parentLink, "missing.json"),
          "linked-parent/missing.json",
          externalFindings,
        )).toBeNull();
        expect(coverageFindings(externalFindings)).toEqual([
          expect.objectContaining({ file: "linked-parent/missing.json" }),
        ]);

        fs.unlinkSync(parentLink);
        fs.symlinkSync(path.join(tmpDir, "missing-target"), parentLink, "dir");
        const brokenFindings: Finding[] = [];
        expect(readOptionalUtf8File(
          tmpDir,
          path.join(parentLink, "missing.json"),
          "linked-parent/missing.json",
          brokenFindings,
        )).toBeNull();
        expect(coverageFindings(brokenFindings)).toEqual([
          expect.objectContaining({ file: "linked-parent/missing.json" }),
        ]);
      } finally {
        fs.rmSync(outsideDir, { recursive: true, force: true });
      }
    },
  );
  it("reports known optional targets that have the wrong filesystem type", () => {
    const fileAsDirectory = path.join(tmpDir, "file-as-directory");
    fs.mkdirSync(fileAsDirectory);
    const fileFindings: Finding[] = [];
    expect(
      readOptionalUtf8File(
        tmpDir,
        fileAsDirectory,
        "file-as-directory",
        fileFindings,
      ),
    ).toBeNull();
    expect(coverageFindings(fileFindings).map((finding) => finding.file))
      .toEqual(["file-as-directory"]);

    const directoryAsFile = write(tmpDir, "directory-as-file", "safe");
    const directoryFindings: Finding[] = [];
    expect(
      listOptionalDirectory(
        tmpDir,
        directoryAsFile,
        "directory-as-file",
        directoryFindings,
      ),
    ).toBeNull();
    expect(coverageFindings(directoryFindings).map((finding) => finding.file))
      .toEqual(["directory-as-file"]);

    fs.mkdirSync(path.join(tmpDir, "Cargo.lock"));
    fs.mkdirSync(path.join(tmpDir, "app.csproj"));
    const cargoCoverage = coverageFindings(scanCargoFiles(tmpDir));
    const nugetCoverage = coverageFindings(scanNuGetFiles(tmpDir));
    expect(cargoCoverage.map((finding) => finding.file)).toContain("Cargo.lock");
    expect(nugetCoverage.map((finding) => finding.file)).toContain("app.csproj");
  });
  it("distinguishes a missing optional path from a discovered path that vanished", () => {
    const optionalFindings: Finding[] = [];
    expect(
      readOptionalUtf8File(
        tmpDir,
        path.join(tmpDir, "missing.txt"),
        "missing.txt",
        optionalFindings,
      ),
    ).toBeNull();
    expect(
      listOptionalDirectory(
        tmpDir,
        path.join(tmpDir, "missing-dir"),
        "missing-dir",
        optionalFindings,
      ),
    ).toBeNull();
    expect(optionalFindings).toHaveLength(0);

    const discoveredFindings: Finding[] = [];
    expect(
      readDiscoveredUtf8File(
        tmpDir,
        path.join(tmpDir, "vanished.txt"),
        "vanished.txt",
        discoveredFindings,
      ),
    ).toBeNull();
    expect(
      listDiscoveredDirectory(
        tmpDir,
        path.join(tmpDir, "vanished-dir"),
        "vanished-dir",
        discoveredFindings,
      ),
    ).toBeNull();
    expect(coverageFindings(discoveredFindings).map((finding) => finding.file))
      .toEqual(["vanished.txt", "vanished-dir"]);
  });

  it("deduplicates coverage findings and never publishes absolute paths", () => {
    const findings: Finding[] = [];
    recordUnreadablePath(findings, "nested/target");
    recordUnreadablePath(findings, "nested\\target");
    recordUnreadablePath(findings, "nested/./target");
    recordUnreadablePath(findings, path.join(tmpDir, "secret"));
    recordUnreadablePath(findings, path.join(tmpDir, "secret"));

    expect(findings).toHaveLength(2);
    expect(findings.map((finding) => finding.file)).toEqual(["nested/target", "."]);
    for (const finding of findings) expectPrivateDetailsHidden(finding, tmpDir);
  });

  it("surfaces skill traversal depth truncation with the deepest relative directory", () => {
    const parts = Array.from({ length: 10 }, (_, index) => `level-${index}`);
    write(
      tmpDir,
      `.claude/skills/${parts.join("/")}/SKILL.md`,
      "<|im_start|>system hidden beyond the traversal limit",
    );

    const findings = scanAgentSkillFiles(tmpDir);
    const coverage = coverageFindings(findings);
    expect(coverage).toHaveLength(1);
    expect(coverage[0]?.file).toBe(
      `.claude/skills/${parts.slice(0, 9).join("/")}`,
    );
    expect(findings.some((finding) => finding.rule === "SKILL_PROMPT_INJECTION"))
      .toBe(false);
  });

  it("keeps successful reads with malformed content out of I/O coverage", () => {
    write(tmpDir, "composer.lock", "{not-json");
    write(tmpDir, "Pipfile.lock", "{not-json");
    write(tmpDir, "packages.lock.json", "{not-json");
    write(tmpDir, "package-lock.json", "{not-json");

    expect(coverageFindings(scanComposerFiles(tmpDir))).toHaveLength(0);
    expect(coverageFindings(scanPythonLockfiles(tmpDir))).toHaveLength(0);
    expect(coverageFindings(scanNuGetFiles(tmpDir))).toHaveLength(0);
    const lockFindings = checkLockfile(tmpDir);
    expect(coverageFindings(lockFindings)).toHaveLength(0);
    expect(lockFindings.some((finding) => finding.rule === "LOCKFILE_PARSE_ERROR"))
      .toBe(true);
  });

  it.skipIf(!permissionChecksWork)(
    "reports unreadable explicit files across every specialized scanner",
    () => {
      const cases: UnreadableFileCase[] = [
        {
          name: "gitmodules",
          relativePath: ".gitmodules",
          content: "[submodule \"x\"]\nurl = https://example.com/x",
          scan: scanGitSecurity,
        },
        {
          name: "git hook",
          relativePath: ".git/hooks/pre-commit",
          content: "#!/bin/sh\necho safe",
          scan: scanGitSecurity,
        },
        {
          name: "agent command",
          relativePath: ".claude/commands/release.md",
          content: "Release instructions",
          scan: scanAgentSkillFiles,
        },
        {
          name: "agent skill",
          relativePath: ".claude/skills/release/SKILL.md",
          content: "Release skill",
          scan: scanAgentSkillFiles,
        },
        {
          name: "agent memory",
          relativePath: ".claude/memory/project.md",
          content: "Project memory",
          scan: scanAgentSkillFiles,
        },
        {
          name: "agent settings",
          relativePath: ".claude/settings.json",
          content: "{}",
          scan: scanAgentSkillFiles,
        },
        {
          name: "extensionless agent rules",
          relativePath: ".cursorrules",
          content: "Project rules",
          scan: scanAgentSkillFiles,
        },
        {
          name: "Cargo lock",
          relativePath: "Cargo.lock",
          content: "version = 3",
          scan: scanCargoFiles,
        },
        {
          name: "Go module",
          relativePath: "go.mod",
          content: "module example.test/app\ngo 1.24",
          scan: scanGoFiles,
        },
        {
          name: "Go checksum lock",
          relativePath: "go.sum",
          content: "example.test/lib v1.0.0 h1:abc",
          scan: scanGoFiles,
        },
        {
          name: "Gemfile",
          relativePath: "Gemfile",
          content: "source \"https://rubygems.org\"",
          scan: scanRubyGemsFiles,
        },
        {
          name: "Gemfile lock",
          relativePath: "Gemfile.lock",
          content: "GEM",
          scan: scanRubyGemsFiles,
        },
        {
          name: "Composer lock",
          relativePath: "composer.lock",
          content: "{}",
          scan: scanComposerFiles,
        },
        {
          name: "Poetry lock",
          relativePath: "poetry.lock",
          content: "[[package]]\nname = \"safe\"\nversion = \"1.0.0\"",
          scan: scanPythonLockfiles,
        },
        {
          name: "uv lock",
          relativePath: "uv.lock",
          content: "[[package]]\nname = \"safe\"\nversion = \"1.0.0\"",
          scan: scanPythonLockfiles,
        },
        {
          name: "Pipfile lock",
          relativePath: "Pipfile.lock",
          content: "{}",
          scan: scanPythonLockfiles,
        },
        {
          name: "NuGet lock",
          relativePath: "packages.lock.json",
          content: "{}",
          scan: scanNuGetFiles,
        },
        {
          name: "NuGet project",
          relativePath: "app.csproj",
          content: "<Project />",
          scan: scanNuGetFiles,
        },
        {
          name: "NuGet config",
          relativePath: "nuget.config",
          content: "<configuration />",
          scan: scanNuGetFiles,
        },
        {
          name: "npm lock",
          relativePath: "package-lock.json",
          content: '{"lockfileVersion":3,"packages":{}}',
          scan: checkLockfile,
        },
        {
          name: "pnpm lock",
          relativePath: "pnpm-lock.yaml",
          content: "lockfileVersion: '9.0'\npackages:\n",
          scan: checkLockfile,
        },
        {
          name: "Yarn lock",
          relativePath: "yarn.lock",
          content: "# yarn lockfile v1\n",
          scan: checkLockfile,
        },
        {
          name: "Bun lock",
          relativePath: "bun.lock",
          content: '{"packages":{}}',
          scan: checkLockfile,
        },
      ];

      for (const fixture of cases) {
        const caseDir = path.join(tmpDir, fixture.name.replace(/\W+/g, "-"));
        fs.mkdirSync(caseDir, { recursive: true });
        const target = write(
          caseDir,
          fixture.relativePath,
          fixture.content,
        );
        fs.chmodSync(target, 0o000);
        try {
          const coverage = coverageFindings(fixture.scan(caseDir));
          expect(coverage, fixture.name).toHaveLength(1);
          expect(coverage[0]?.file, fixture.name).toBe(fixture.relativePath);
          expectPrivateDetailsHidden(coverage[0]!, caseDir);
        } finally {
          fs.chmodSync(target, 0o600);
        }
      }
    },
  );

  it.skipIf(!permissionChecksWork)(
    "reports unreadable specialized directories without duplicate or private details",
    () => {
      const cases: Array<{
        name: string;
        relativeDir: string;
        prepare?: (root: string) => void;
        scan: Scanner;
        expected: string;
      }> = [
        {
          name: "git hooks directory",
          relativeDir: ".git/hooks",
          scan: scanGitSecurity,
          expected: ".git/hooks",
        },
        {
          name: "agent commands directory",
          relativeDir: ".claude/commands",
          scan: scanAgentSkillFiles,
          expected: ".claude/commands",
        },
        {
          name: "agent skills directory",
          relativeDir: ".claude/skills",
          scan: scanAgentSkillFiles,
          expected: ".claude/skills",
        },
        {
          name: "agent memory directory",
          relativeDir: ".claude/memory",
          scan: scanAgentSkillFiles,
          expected: ".claude/memory",
        },
        {
          name: "Rust proc macro source directory",
          relativeDir: "src",
          prepare: (root) => write(root, "Cargo.toml", "[lib]\nproc-macro = true"),
          scan: scanCargoFiles,
          expected: "src",
        },
        {
          name: "Go command source directory",
          relativeDir: "cmd",
          prepare: (root) =>
            write(root, "go.mod", "module example.test/app\ngo 1.24"),
          scan: scanGoFiles,
          expected: "cmd",
        },
      ];

      for (const fixture of cases) {
        const caseDir = path.join(tmpDir, fixture.name.replace(/\W+/g, "-"));
        fs.mkdirSync(caseDir, { recursive: true });
        fixture.prepare?.(caseDir);
        const targetDir = path.join(caseDir, ...fixture.relativeDir.split("/"));
        fs.mkdirSync(targetDir, { recursive: true });
        write(caseDir, `${fixture.relativeDir}/target.txt`, "safe");
        fs.chmodSync(targetDir, 0o000);
        try {
          const coverage = coverageFindings(fixture.scan(caseDir));
          expect(coverage, fixture.name).toHaveLength(1);
          expect(coverage[0]?.file, fixture.name).toBe(fixture.expected);
          expectPrivateDetailsHidden(coverage[0]!, caseDir);
        } finally {
          fs.chmodSync(targetDir, 0o700);
        }
      }

      const nugetRoot = path.join(tmpDir, "nuget-root");
      fs.mkdirSync(nugetRoot);
      write(nugetRoot, "app.csproj", "<Project />");
      fs.chmodSync(nugetRoot, 0o000);
      try {
        const coverage = coverageFindings(scanNuGetFiles(nugetRoot));
        expect(coverage).toHaveLength(1);
        expect(coverage[0]?.file).toBe(".");
        expectPrivateDetailsHidden(coverage[0]!, nugetRoot);
      } finally {
        fs.chmodSync(nugetRoot, 0o700);
      }
    },
  );
});