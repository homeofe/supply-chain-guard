/**
 * Git security scanner.
 *
 * Detects supply-chain risks in git hooks, .gitmodules, and
 * repository configuration.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";

// ---------------------------------------------------------------------------
// Git hook patterns
// ---------------------------------------------------------------------------

export const GIT_HOOK_PATTERNS: PatternEntry[] = [
  {
    name: "git-hook-download",
    pattern:
      "(?:curl|wget|fetch)\\s+.*https?://",
    description:
      "Git hook downloads content from a remote URL. Hooks run automatically and can execute arbitrary code.",
    severity: "critical",
    rule: "GIT_HOOK_DOWNLOAD",
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

/**
 * Scan git hooks directory for malicious patterns.
 */
function scanGitHooks(gitDir: string, findings: Finding[]): void {
  const hooksDir = path.join(gitDir, "hooks");
  if (!fs.existsSync(hooksDir)) return;

  try {
    const entries = fs.readdirSync(hooksDir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isFile()) continue;
      // Skip .sample files
      if (entry.name.endsWith(".sample")) continue;

      const hookName = entry.name;
      const isAutoHook = EXECUTABLE_HOOKS.has(hookName);
      const fullPath = path.join(hooksDir, hookName);
      const relativePath = `.git/hooks/${hookName}`;

      let content: string;
      try {
        content = fs.readFileSync(fullPath, "utf-8");
      } catch {
        continue;
      }

      const lines = content.split("\n");

      for (const pattern of GIT_HOOK_PATTERNS) {
        const regex = new RegExp(pattern.pattern, "i");

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i] ?? "";
          const match = regex.exec(line);
          if (match) {
            findings.push({
              rule: pattern.rule,
              description: `${pattern.description}${isAutoHook ? ` (auto-executing hook: ${hookName})` : ""}`,
              severity: pattern.severity,
              file: relativePath,
              line: i + 1,
              match:
                match[0].length > 120
                  ? match[0].substring(0, 120) + "..."
                  : match[0],
              recommendation: getGitRecommendation(pattern.rule),
            });
          }
        }
      }
    }
  } catch {
    // hooks dir not readable
  }
}

/**
 * Scan .gitmodules for suspicious submodule URLs.
 */
function scanGitModules(dir: string, findings: Finding[]): void {
  const modulesPath = path.join(dir, ".gitmodules");
  if (!fs.existsSync(modulesPath)) return;

  let content: string;
  try {
    content = fs.readFileSync(modulesPath, "utf-8");
  } catch {
    return;
  }

  const lines = content.split("\n");

  for (const pattern of GITMODULE_PATTERNS) {
    const regex = new RegExp(pattern.pattern, "i");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const match = regex.exec(line);
      if (match) {
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: ".gitmodules",
          line: i + 1,
          match:
            match[0].length > 120
              ? match[0].substring(0, 120) + "..."
              : match[0],
          recommendation: getGitRecommendation(pattern.rule),
        });
      }
    }
  }
}

/**
 * Scan a directory's git configuration for security issues.
 */
export function scanGitSecurity(dir: string): Finding[] {
  const findings: Finding[] = [];

  const gitDir = path.join(dir, ".git");
  if (fs.existsSync(gitDir) && fs.statSync(gitDir).isDirectory()) {
    scanGitHooks(gitDir, findings);
  }

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
