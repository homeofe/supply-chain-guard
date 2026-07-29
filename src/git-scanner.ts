/**
 * Git security scanner.
 *
 * Detects supply-chain risks in git hooks, .gitmodules, and
 * repository configuration.
 */


import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";
import {
  MAX_CORRELATED_EVIDENCE_CHARS,
  truncateMatch,
  validatePatternSet,
} from "./patterns.js";
import {
  listOptionalDirectory,
  matchPatternInFile,
  readDiscoveredUtf8File,
  readOptionalUtf8File,
} from "./pattern-scanner.js";

// ---------------------------------------------------------------------------
// Git hook patterns
// ---------------------------------------------------------------------------

interface GitStructuralMatch {
  start: number;
  end: number;
  evidence: string;
}

type GitMatchRange = Pick<GitStructuralMatch, "start" | "end">;

function preferGitMatch(
  current: GitMatchRange | undefined,
  candidate: GitMatchRange,
): GitMatchRange {
  if (!current || candidate.start < current.start) return candidate;
  if (candidate.start === current.start && candidate.end > current.end) {
    return candidate;
  }
  return current;
}

const gitHookDownloadMatcher: NonNullable<
  PatternEntry["correlatedMatcher"]
> = function* (content) {
  let lineStart = 0;
  while (lineStart <= content.length) {
    const newline = content.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? content.length : newline;
    const line = content.slice(lineStart, lineEnd);
    const tokens = /(?:curl|wget|fetch)\s+|https?:\/\/|[\r\u2028\u2029]/gi;
    let downloadStart = -1;
    let best: GitMatchRange | undefined;
    let token: RegExpExecArray | null;

    while ((token = tokens.exec(line)) !== null) {
      const value = token[0]!;
      if (/^[\r\u2028\u2029]$/u.test(value)) {
        downloadStart = -1;
      } else if (/^https?:\/\//i.test(value)) {
        if (downloadStart !== -1) {
          best = preferGitMatch(best, {
            start: downloadStart,
            end: tokens.lastIndex,
          });
        }
      } else if (
        downloadStart === -1 ||
        /[\r\u2028\u2029]/u.test(value)
      ) {
        // The source's \s+ may legally consume a dot terminator, but an older
        // source cannot cross that same terminator to a later URL.
        downloadStart = token.index;
      }
    }

    if (best) {
      const start = lineStart + best.start;
      const end = lineStart + best.end;
      yield {
        start,
        end,
        evidence: content.slice(
          start,
          Math.min(end, start + MAX_CORRELATED_EVIDENCE_CHARS),
        ),
      };
    }
    if (newline === -1) break;
    lineStart = newline + 1;
  }
};
export const GIT_HOOK_PATTERNS: PatternEntry[] = [
  {
    name: "git-hook-download",
    pattern:
      "(?:curl|wget|fetch)\\s+.*https?://",
    description:
      "Git hook downloads content from a remote URL. Hooks run automatically and can execute arbitrary code.",
    severity: "critical",
    rule: "GIT_HOOK_DOWNLOAD",
    correlatedMatcher: gitHookDownloadMatcher,
  },
  {
    name: "git-hook-eval-exec",
    pattern:
      "\\b(?:eval|exec|execSync|child_process)\\b",
    description:
      "Git hook uses eval/exec to run dynamic code.",
    severity: "high",
    rule: "GIT_HOOK_EXEC",
  },
  {
    name: "git-hook-encoded",
    pattern:
      "base64\\s+-d|atob\\s*\\(|Buffer\\.from\\s*\\(|\\\\x[0-9a-fA-F]{2}\\\\x[0-9a-fA-F]{2}",
    description:
      "Git hook contains encoded/obfuscated content. Legitimate hooks rarely use encoding.",
    severity: "critical",
    rule: "GIT_HOOK_ENCODED",
  },
  {
    name: "git-hook-pipe-shell",
    pattern:
      "\\|\\s*(?:bash|sh|zsh|python|node|perl)\\b",
    description:
      "Git hook pipes content to an interpreter shell.",
    severity: "high",
    rule: "GIT_HOOK_PIPE_SHELL",
  },
];

validatePatternSet("GIT_HOOK_PATTERNS", GIT_HOOK_PATTERNS);

/** Git hook names that auto-execute */
const EXECUTABLE_HOOKS = new Set([
  "pre-commit",
  "prepare-commit-msg",
  "commit-msg",
  "post-commit",
  "pre-rebase",
  "post-rewrite",
  "post-checkout",
  "post-merge",
  "pre-push",
  "pre-receive",
  "update",
  "post-receive",
  "post-update",
  "pre-auto-gc",
]);

// ---------------------------------------------------------------------------
// .gitmodules patterns
// ---------------------------------------------------------------------------

export const GITMODULE_PATTERNS: PatternEntry[] = [
  {
    name: "gitmodule-http",
    pattern: "url\\s*=\\s*http://",
    description:
      "Git submodule uses plain HTTP URL. Submodule content can be intercepted via MITM.",
    severity: "medium",
    rule: "GIT_SUBMODULE_HTTP",
  },
  {
    name: "gitmodule-suspicious-url",
    pattern:
      "url\\s*=\\s*https?://(?!github\\.com|gitlab\\.com|bitbucket\\.org|sr\\.ht)",
    description:
      "Git submodule points to a non-standard hosting provider. Verify this is intentional.",
    severity: "high",
    rule: "GIT_SUBMODULE_SUSPICIOUS",
  },
];

validatePatternSet("GITMODULE_PATTERNS", GITMODULE_PATTERNS);

/**
 * Scan git hooks directory for malicious patterns.
 */
function scanGitHooks(scanRoot: string, gitDir: string, findings: Finding[]): void {
  const hooksDir = path.join(gitDir, "hooks");
  const entries = listOptionalDirectory(scanRoot, hooksDir, ".git/hooks", findings);
  if (entries === null) return;

  for (const entry of entries) {
    if (!entry.isFile() && !entry.isSymbolicLink()) continue;
    // Skip .sample files
    if (entry.name.endsWith(".sample")) continue;

    const hookName = entry.name;
    const isAutoHook = EXECUTABLE_HOOKS.has(hookName);
    const fullPath = path.join(hooksDir, hookName);
    const relativePath = `.git/hooks/${hookName}`;
    const content = readDiscoveredUtf8File(scanRoot, fullPath, relativePath, findings);
    if (content === null) continue;

    for (const pattern of GIT_HOOK_PATTERNS) {
      const hits = matchPatternInFile(
        pattern,
        content,
        relativePath,
        findings,
        "i",
      );
      for (const hit of hits ?? []) {
        findings.push({
          rule: pattern.rule,
          description: `${pattern.description}${isAutoHook ? ` (auto-executing hook: ${hookName})` : ""}`,
          severity: pattern.severity,
          file: relativePath,
          line: hit.line,
          match: truncateMatch(hit.text),
          recommendation: getGitRecommendation(pattern.rule),
        });
      }
    }
  }
}

/**
 * Scan .gitmodules for suspicious submodule URLs.
 */
function scanGitModules(dir: string, findings: Finding[]): void {
  const modulesPath = path.join(dir, ".gitmodules");
  const content = readOptionalUtf8File(
    dir,
    modulesPath,
    ".gitmodules",
    findings,
  );
  if (content === null) return;

  for (const pattern of GITMODULE_PATTERNS) {
    const hits = matchPatternInFile(
      pattern,
      content,
      ".gitmodules",
      findings,
      "i",
    );
    for (const hit of hits ?? []) {
      findings.push({
        rule: pattern.rule,
        description: pattern.description,
        severity: pattern.severity,
        file: ".gitmodules",
        line: hit.line,
        match: truncateMatch(hit.text),
        recommendation: getGitRecommendation(pattern.rule),
      });
    }
  }
}

/**
 * Scan a directory's git configuration for security issues.
 */
export function scanGitSecurity(dir: string): Finding[] {
  const findings: Finding[] = [];

  scanGitHooks(dir, path.join(dir, ".git"), findings);
  scanGitModules(dir, findings);

  return findings;
}

function getGitRecommendation(rule: string): string {
  const map: Record<string, string> = {
    GIT_HOOK_DOWNLOAD:
      "Remove or audit this hook. Git hooks that download remote content can be used for supply-chain attacks.",
    GIT_HOOK_EXEC:
      "Audit the hook's use of eval/exec. Ensure it only runs trusted commands.",
    GIT_HOOK_ENCODED:
      "Decode the encoded content and inspect it. Legitimate hooks do not use obfuscation.",
    GIT_HOOK_PIPE_SHELL:
      "Avoid piping content to shells in git hooks. Write hook logic explicitly.",
    GIT_SUBMODULE_HTTP:
      "Switch submodule URL to HTTPS to prevent man-in-the-middle attacks.",
    GIT_SUBMODULE_SUSPICIOUS:
      "Verify the submodule URL points to a trusted repository.",
  };
  return map[rule] ?? "Review this git configuration manually.";
}
