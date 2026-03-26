/**
 * GitHub Actions Workflow Scanner
 *
 * Scans .github/workflows/*.yml files for CI/CD pipeline attack indicators
 * including remote code execution, secrets exfiltration, compromised action
 * references, unpinned versions, and encoded payloads.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, Severity } from "./types.js";

/**
 * Patterns for detecting dangerous content in GitHub Actions workflow files.
 */
const WORKFLOW_PATTERNS: Array<{
  pattern: string;
  description: string;
  severity: Severity;
  rule: string;
  flags?: string;
}> = [
  // Remote content piped to shell execution
  {
    pattern: "curl\\s+[^|]*\\|\\s*(?:bash|sh|zsh|node|python|perl|ruby)",
    description: "Remote content fetched with curl and piped to shell execution",
    severity: "high",
    rule: "GHA_CURL_PIPE_EXEC",
  },
  {
    pattern: "wget\\s+[^|]*\\|\\s*(?:bash|sh|zsh|node|python|perl|ruby)",
    description: "Remote content fetched with wget and piped to shell execution",
    severity: "high",
    rule: "GHA_WGET_PIPE_EXEC",
  },
  {
    pattern: "curl\\s+.*-o\\s+\\S+.*&&.*(?:bash|sh|chmod\\s+\\+x)",
    description: "Remote script downloaded and executed in workflow",
    severity: "high",
    rule: "GHA_CURL_DOWNLOAD_EXEC",
  },
  {
    pattern: "wget\\s+.*-O\\s+\\S+.*&&.*(?:bash|sh|chmod\\s+\\+x)",
    description: "Remote script downloaded with wget and executed in workflow",
    severity: "high",
    rule: "GHA_WGET_DOWNLOAD_EXEC",
  },

  // Secrets exfiltration via network
  {
    pattern: "\\$\\{\\{\\s*secrets\\.[^}]+\\}\\}.*curl",
    description: "Secret value passed to curl command (potential exfiltration)",
    severity: "high",
    rule: "GHA_SECRET_CURL",
  },
  {
    pattern: "curl.*\\$\\{\\{\\s*secrets\\.[^}]+\\}\\}",
    description: "Secret value sent via curl request (potential exfiltration)",
    severity: "high",
    rule: "GHA_SECRET_CURL",
  },
  {
    pattern: "\\$\\{\\{\\s*secrets\\.[^}]+\\}\\}.*wget",
    description: "Secret value passed to wget command (potential exfiltration)",
    severity: "high",
    rule: "GHA_SECRET_WGET",
  },
  {
    pattern: "wget.*\\$\\{\\{\\s*secrets\\.[^}]+\\}\\}",
    description: "Secret value sent via wget request (potential exfiltration)",
    severity: "high",
    rule: "GHA_SECRET_WGET",
  },

  // Base64 encoded payloads
  {
    pattern: "echo\\s+[A-Za-z0-9+/=]{20,}\\s*\\|\\s*base64\\s+(?:-d|--decode)",
    description: "Base64 encoded payload decoded and potentially executed in workflow",
    severity: "high",
    rule: "GHA_BASE64_PAYLOAD",
  },
  {
    pattern: "base64\\s+(?:-d|--decode)\\s*.*\\|\\s*(?:bash|sh|node|python)",
    description: "Base64 decoded content piped to shell execution",
    severity: "high",
    rule: "GHA_BASE64_EXEC",
  },
  {
    pattern: "\\batob\\s*\\(",
    description: "JavaScript base64 decoding (atob) in workflow run block",
    severity: "medium",
    rule: "GHA_ATOB_USAGE",
  },

  // Environment variable exfiltration
  {
    pattern: "\\benv\\b.*\\bcurl\\b|\\bcurl\\b.*\\benv\\b",
    description: "Environment variables referenced alongside curl (potential exfiltration)",
    severity: "medium",
    rule: "GHA_ENV_EXFIL",
  },

  // Suspicious shell patterns
  {
    pattern: "\\beval\\s*\\$\\(",
    description: "eval with command substitution in workflow (dynamic code execution)",
    severity: "high",
    rule: "GHA_EVAL_SUBSHELL",
  },
  {
    pattern: "\\beval\\s+[\"']",
    description: "eval of string content in workflow run block",
    severity: "medium",
    rule: "GHA_EVAL_STRING",
  },
];

/** Well-known official or trusted GitHub Action owners. */
const TRUSTED_ACTION_OWNERS = new Set([
  "actions",
  "github",
  "docker",
  "azure",
  "aws-actions",
  "google-github-actions",
  "hashicorp",
  "gradle",
  "ruby",
  "peaceiris",
  "codecov",
  "softprops",
  "peter-evans",
  "JamesIves",
]);

/** Branch-like refs that indicate an unpinned action version. */
const UNPINNED_REF_PATTERN = /^(main|master|dev|develop|latest|HEAD|trunk)$/;

/** Pattern matching a full SHA commit hash (40 hex chars). */
const SHA_PATTERN = /^[0-9a-fA-F]{40}$/;

/**
 * Scan a directory for GitHub Actions workflow files and return findings.
 * Called from the main scanner during directory scans.
 */
export function scanGitHubActionsWorkflows(dir: string): Finding[] {
  const findings: Finding[] = [];
  const workflowDir = path.join(dir, ".github", "workflows");

  if (!fs.existsSync(workflowDir)) {
    return findings;
  }

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(workflowDir, { withFileTypes: true });
  } catch {
    return findings;
  }

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const ext = path.extname(entry.name).toLowerCase();
    if (ext !== ".yml" && ext !== ".yaml") continue;

    const filePath = path.join(workflowDir, entry.name);
    const relativePath = path.join(".github", "workflows", entry.name);

    try {
      const content = fs.readFileSync(filePath, "utf-8");
      scanWorkflowContent(content, relativePath, findings);
    } catch {
      // Skip unreadable files
    }
  }

  return findings;
}

/**
 * Scan workflow file content for suspicious patterns.
 */
function scanWorkflowContent(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  const lines = content.split("\n");

  // Check line-by-line patterns in run: blocks and general content
  checkWorkflowPatterns(lines, relativePath, findings);

  // Check action references (uses: directives)
  checkActionReferences(lines, relativePath, findings);

  // Check for secrets sent to external URLs across multi-line run blocks
  checkSecretsExfiltration(lines, relativePath, findings);
}

/**
 * Check workflow content against known dangerous patterns.
 */
function checkWorkflowPatterns(
  lines: string[],
  relativePath: string,
  findings: Finding[],
): void {
  for (const pattern of WORKFLOW_PATTERNS) {
    const regex = new RegExp(pattern.pattern, pattern.flags ?? "i");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const match = regex.exec(line);
      if (match) {
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: relativePath,
          line: i + 1,
          match: truncateMatch(match[0]),
          recommendation: getWorkflowRecommendation(pattern.rule),
        });
      }
    }
  }
}

/**
 * Check action references for compromised or unpinned actions.
 */
function checkActionReferences(
  lines: string[],
  relativePath: string,
  findings: Finding[],
): void {
  const usesRegex = /^\s*-?\s*uses:\s*([^\s#]+)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const match = usesRegex.exec(line);
    if (!match) continue;

    const actionRef = match[1] ?? "";

    // Skip docker:// and local ./ references
    if (actionRef.startsWith("docker://") || actionRef.startsWith("./")) {
      continue;
    }

    // Parse owner/repo@ref
    const atIndex = actionRef.indexOf("@");
    if (atIndex === -1) continue;

    const actionPath = actionRef.substring(0, atIndex);
    const ref = actionRef.substring(atIndex + 1);
    const owner = actionPath.split("/")[0] ?? "";

    // Check for unpinned versions (branch names instead of SHAs or semver tags)
    if (UNPINNED_REF_PATTERN.test(ref)) {
      findings.push({
        rule: "GHA_UNPINNED_ACTION",
        description: `Action "${actionRef}" uses a branch reference (@${ref}) instead of a pinned commit SHA or version tag. Branch references can be changed at any time.`,
        severity: "medium",
        file: relativePath,
        line: i + 1,
        match: truncateMatch(actionRef),
        recommendation:
          "Pin actions to a specific commit SHA (e.g., @abc123def...) or a version tag (e.g., @v2.1.0) to prevent supply-chain attacks via mutable references.",
      });
    }

    // Check for non-SHA refs (semver tags are acceptable but less secure than SHAs)
    if (!SHA_PATTERN.test(ref) && !UNPINNED_REF_PATTERN.test(ref)) {
      // Only flag non-semver patterns or very short tags as info
      const isSemver = /^v?\d+(\.\d+){0,2}$/.test(ref);
      if (isSemver && !TRUSTED_ACTION_OWNERS.has(owner)) {
        findings.push({
          rule: "GHA_TAG_NOT_SHA",
          description: `Action "${actionRef}" uses a version tag instead of a commit SHA. Tags can be force-pushed to point to different commits.`,
          severity: "low",
          file: relativePath,
          line: i + 1,
          match: truncateMatch(actionRef),
          recommendation:
            "Consider pinning this action to a full commit SHA for maximum security. Tags can be moved to point to malicious code.",
        });
      }
    }

    // Check for non-official/untrusted action owners
    if (!TRUSTED_ACTION_OWNERS.has(owner)) {
      // Only flag as info if it has a SHA pin, medium otherwise
      const isPinnedToSha = SHA_PATTERN.test(ref);
      findings.push({
        rule: "GHA_THIRD_PARTY_ACTION",
        description: `Action "${actionRef}" is from third-party owner "${owner}". Third-party actions can be compromised.`,
        severity: isPinnedToSha ? "info" : "low",
        file: relativePath,
        line: i + 1,
        match: truncateMatch(actionRef),
        recommendation: isPinnedToSha
          ? `Third-party action pinned to SHA. Periodically verify the SHA matches trusted code for "${actionPath}".`
          : `Pin "${actionRef}" to a specific commit SHA and audit the action source code before use.`,
      });
    }
  }
}

/**
 * Check for secrets being sent to external URLs in run blocks.
 * Looks for multi-line run: blocks that contain both secret references
 * and outbound network calls.
 */
function checkSecretsExfiltration(
  lines: string[],
  relativePath: string,
  findings: Finding[],
): void {
  const secretPattern = /\$\{\{\s*secrets\.\w+\s*\}\}/;
  const networkPattern = /\b(?:curl|wget|fetch|nc|ncat|netcat)\b/;
  const envExportPattern = /^\s*\w+:\s*\$\{\{\s*secrets\.\w+/;

  // Track env: blocks that export secrets and subsequent run: blocks
  let inRunBlock = false;
  let runBlockStart = -1;
  let runBlockHasSecrets = false;
  let runBlockHasNetwork = false;
  let runBlockIndent = 0;

  // Also track env-exported secrets at step/job level
  let envSecretsExported = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";

    // Check env: blocks for secret exports
    if (envExportPattern.test(line)) {
      envSecretsExported = true;
    }

    // Detect start of run: block
    const runMatch = /^(\s*)(?:-\s+)?run:\s*[|>]?\s*$/.exec(line);
    const inlineRunMatch = /^(\s*)(?:-\s+)?run:\s+(.+)$/.exec(line);

    if (runMatch) {
      inRunBlock = true;
      runBlockStart = i;
      runBlockIndent = (runMatch[1] ?? "").length;
      runBlockHasSecrets = false;
      runBlockHasNetwork = false;
      continue;
    }

    if (inlineRunMatch) {
      // Single-line run: - already caught by WORKFLOW_PATTERNS
      inRunBlock = false;
      continue;
    }

    if (inRunBlock) {
      // Check if we've left the block (dedented or empty non-continuation)
      const lineIndent = line.length - line.trimStart().length;
      if (line.trim().length > 0 && lineIndent <= runBlockIndent && !/^\s+/.test(line)) {
        // Exited run block
        if (runBlockHasSecrets && runBlockHasNetwork) {
          // Already caught by line-level patterns if on same line;
          // this catches split across lines
          const alreadyFound = findings.some(
            (f) =>
              (f.rule === "GHA_SECRET_CURL" || f.rule === "GHA_SECRET_WGET") &&
              f.file === relativePath &&
              f.line !== undefined &&
              f.line >= runBlockStart + 1 &&
              f.line <= i,
          );
          if (!alreadyFound) {
            findings.push({
              rule: "GHA_SECRET_EXFIL_MULTILINE",
              description: "Secrets and network commands found in the same run block (potential exfiltration across multiple lines)",
              severity: "high",
              file: relativePath,
              line: runBlockStart + 1,
              recommendation:
                "Review this run block. Secrets combined with network commands in the same step can indicate credential exfiltration.",
            });
          }
        }
        inRunBlock = false;
      }

      if (inRunBlock) {
        if (secretPattern.test(line)) runBlockHasSecrets = true;
        if (networkPattern.test(line)) runBlockHasNetwork = true;

        // Also check if env-exported secrets are used with network
        if (envSecretsExported && networkPattern.test(line)) {
          runBlockHasSecrets = true;
        }
      }
    }
  }

  // Handle case where run block extends to end of file
  if (inRunBlock && runBlockHasSecrets && runBlockHasNetwork) {
    const alreadyFound = findings.some(
      (f) =>
        (f.rule === "GHA_SECRET_CURL" || f.rule === "GHA_SECRET_WGET") &&
        f.file === relativePath,
    );
    if (!alreadyFound) {
      findings.push({
        rule: "GHA_SECRET_EXFIL_MULTILINE",
        description: "Secrets and network commands found in the same run block (potential exfiltration across multiple lines)",
        severity: "high",
        file: relativePath,
        line: runBlockStart + 1,
        recommendation:
          "Review this run block. Secrets combined with network commands in the same step can indicate credential exfiltration.",
      });
    }
  }
}

/**
 * Get recommendation text for a workflow-specific rule.
 */
function getWorkflowRecommendation(rule: string): string {
  const map: Record<string, string> = {
    GHA_CURL_PIPE_EXEC:
      "Do not pipe remote content directly to a shell. Download the script, verify its checksum, then execute.",
    GHA_WGET_PIPE_EXEC:
      "Do not pipe remote content directly to a shell. Download the script, verify its checksum, then execute.",
    GHA_CURL_DOWNLOAD_EXEC:
      "Verify downloaded scripts with checksums before execution. Prefer using pinned GitHub Actions instead.",
    GHA_WGET_DOWNLOAD_EXEC:
      "Verify downloaded scripts with checksums before execution. Prefer using pinned GitHub Actions instead.",
    GHA_SECRET_CURL:
      "Secrets should never be sent to external URLs. Review this workflow step for credential exfiltration.",
    GHA_SECRET_WGET:
      "Secrets should never be sent to external URLs via wget. Review this workflow step for credential exfiltration.",
    GHA_BASE64_PAYLOAD:
      "Base64 encoded payloads in CI workflows are suspicious. Decode and inspect the content before running.",
    GHA_BASE64_EXEC:
      "Decoding base64 content and piping to a shell is a common attack vector. Inspect the encoded content.",
    GHA_ATOB_USAGE:
      "Base64 decoding in workflow run blocks may indicate obfuscated payloads. Review the decoded content.",
    GHA_ENV_EXFIL:
      "Environment variables combined with network tools may indicate data exfiltration. Review the workflow step.",
    GHA_EVAL_SUBSHELL:
      "eval with command substitution enables dynamic code execution. This is rarely needed in CI workflows.",
    GHA_EVAL_STRING:
      "eval of string content in workflows can execute injected code. Prefer direct commands.",
  };
  return map[rule] ?? "Review this finding and assess whether it represents legitimate CI/CD functionality.";
}

/**
 * Truncate a match string for display.
 */
function truncateMatch(match: string, maxLen = 120): string {
  if (match.length <= maxLen) return match;
  return match.substring(0, maxLen) + "...";
}
