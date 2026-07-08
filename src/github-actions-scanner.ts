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
import { parseWorkflow, type WfStep, type WfJob } from "./workflow-ast.js";

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

  // Environment variable exfiltration — requires secrets/env passed as DATA (not as URL)
  {
    pattern: "curl\\b[^'\"\\n]*(?:-d|--data|--data-raw|-H|--header)[^'\"\\n]*\\$\\{\\{\\s*(?:secrets|env)\\.",
    description: "Secret or env variable passed as curl request data/header (potential exfiltration)",
    severity: "high",
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

  // ── 2025 attack patterns (PPE, OIDC theft, cache/artifact poisoning) ──

  // Poisoned Pipeline Execution: pull_request_target + unsanitized PR context in run:
  {
    pattern: "\\$\\{\\{\\s*github\\.event\\.pull_request\\.",
    description:
      "Unsanitized pull_request event context used in workflow step — potential Poisoned Pipeline Execution (PPE). " +
      "An attacker-controlled PR can inject arbitrary commands.",
    severity: "critical",
    rule: "GHA_PPE_PULL_TARGET",
  },
  // Script injection via user-controlled context (issue/PR body, PR/commit title,
  // comment body, review body, discussion, PR head ref/label). v5.7 broadened the
  // object list (added comment/review/discussion) and the field list (added
  // label/ref/description) - the pre-v5.7 regex missed the issue_comment vector
  // (github.event.comment.body) entirely.
  {
    pattern: "\\$\\{\\{\\s*github\\.event\\.(?:issue|pull_request|head_commit|commits?|comment|review|discussion)\\.[^}]*(?:body|title|message|name)\\s*\\}\\}",
    description:
      "User-controlled GitHub event data (issue/PR body, comment body, PR title, commit message) injected directly into a run: step — GitHub Actions Script Injection risk",
    severity: "critical",
    rule: "GHA_SCRIPT_INJECTION",
  },
  // OIDC token theft: id-token:write permission combined with outbound network call
  {
    pattern: "id-token:\\s*write",
    description:
      "Workflow requests OIDC id-token:write permission. If combined with unreviewed third-party actions or outbound curl, " +
      "an attacker can steal the OIDC token to impersonate the workflow's cloud identity.",
    severity: "medium",
    rule: "GHA_OIDC_WRITE_PERM",
  },
  // Cache poisoning: cache key derived from PR branch (github.head_ref)
  {
    pattern: "github\\.head_ref",
    description:
      "Cache or artifact key uses github.head_ref (PR branch name). " +
      "An attacker can create a branch named to match a poisoned cache key and inject malicious cached content.",
    severity: "high",
    rule: "GHA_CACHE_POISONING",
  },
  // Artifact injection: download-artifact from a PR-triggered workflow used in release/deploy
  {
    pattern: "actions/download-artifact",
    description:
      "Workflow downloads build artifacts. If artifacts originate from an untrusted PR workflow, " +
      "they may have been tampered with (artifact injection attack).",
    severity: "low",
    rule: "GHA_ARTIFACT_DOWNLOAD",
  },
  // Self-modifying workflow: writing to .github/workflows/
  {
    pattern: "(?:echo|tee|cat|cp|mv|write).*\\.github[\\\\/]workflows[\\\\/]",
    description:
      "Workflow writes to .github/workflows/ — this can persist malicious code by modifying CI pipeline files (supply chain worm pattern)",
    severity: "critical",
    rule: "GHA_SELF_MODIFY",
  },
];

/**
 * Known compromised action commit SHAs.
 * These SHAs are confirmed malicious and should never be used.
 * Sources: GitHub Security Advisories, supply chain incident reports.
 */
const KNOWN_MALICIOUS_ACTION_SHAS = new Map<string, string>([
  // tj-actions/changed-files — compromised September 2025 (GHSA-2025-tj-actions)
  // Exfiltrated CI secrets to attacker-controlled server via public build logs
  ["d8462b4fc879d893f8f3b49843bde065f3f07b82", "tj-actions/changed-files (Sep 2025 compromise)"],
  ["0e58ed8671d6b60d0890c21b07f8835ace038e67", "tj-actions/changed-files (Sep 2025 compromise variant)"],
  // reviewdog/action-setup — compromised as part of tj-actions attack chain
  ["3f401fe1d58fe77e10d665ab713057369b8cdfe4", "reviewdog/action-setup (Sep 2025 attack chain)"],
]);

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

  // v5.7: structural, trigger-aware rules (Cordyceps class) — these need to
  // know which event fires the workflow and what its token can do, which the
  // line-by-line passes above are blind to.
  checkWorkflowAstRules(content, relativePath, findings);

  // v5.10: GitLost-class agent-workflow posture (trigger + agent step + token + public post)
  checkAgentWorkflowRules(content, relativePath, findings);
}

/**
 * v5.10 GitLost-class rules. An AI-agent step that ingests attacker-controllable
 * event text, holds a cross-repo-capable token, and can post publicly is the
 * exact "lethal trifecta" the GitLost disclosure (Noma, July 2026) exploited.
 * We can only see the checked-in POSTURE, never the runtime injection payload,
 * so these are pre-attack hardening warnings, not attack detections.
 */
function checkAgentWorkflowRules(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  let ast;
  try {
    ast = parseWorkflow(content);
  } catch {
    return;
  }

  const triggerSet = new Set(ast.triggers);
  const untrusted = AGENT_UNTRUSTED_TRIGGERS.filter((t) => triggerSet.has(t));
  if (untrusted.length === 0) return; // no attacker-controllable input path

  // Collect agent steps across all jobs.
  const agentSteps: Array<{ step: WfStep; job: WfJob }> = [];
  for (const job of ast.jobs) {
    for (const step of job.steps) {
      if (isAgentStep(step)) agentSteps.push({ step, job });
    }
  }
  if (agentSteps.length === 0) return;

  const canPostPublicly = (job: WfJob): boolean => {
    const scopeWrites = (p: { scopes: Record<string, string>; writeAll: boolean }) =>
      p.writeAll || PUBLIC_POST_SCOPES.some((s) => p.scopes[s] === "write");
    return scopeWrites(ast.permissions) || scopeWrites(job.permissions);
  };

  for (const { step, job } of agentSteps) {
    // GHA_AGENT_UNTRUSTED_PROMPT (critical): agent ingests untrusted event context.
    if (UNTRUSTED_CTX_RE.test(agentStepText(step))) {
      findings.push({
        rule: "GHA_AGENT_UNTRUSTED_PROMPT",
        description:
          `AI-agent step ingests attacker-controllable GitHub event context ` +
          `(issue/PR/comment body or title) as part of its instructions on an untrusted ` +
          `trigger (${untrusted.join(", ")}). This is the core of the GitLost prompt-injection ` +
          `class: the agent cannot distinguish your instructions from an attacker's issue text.`,
        severity: "critical",
        file: relativePath,
        line: step.line,
        recommendation: getWorkflowRecommendation("GHA_AGENT_UNTRUSTED_PROMPT"),
      });
    }

    // GHA_AGENT_PUBLIC_POST (high): the same job can post the agent's output publicly.
    if (canPostPublicly(job)) {
      findings.push({
        rule: "GHA_AGENT_PUBLIC_POST",
        description:
          `AI-agent job on an untrusted trigger (${untrusted.join(", ")}) also holds ` +
          `issues:write / pull-requests:write, so the agent can post its output as a public ` +
          `comment. That comment is the GitLost exfiltration channel: private data the agent ` +
          `read becomes readable by anyone who can see the issue.`,
        severity: "high",
        file: relativePath,
        line: step.line,
        recommendation: getWorkflowRecommendation("GHA_AGENT_PUBLIC_POST"),
      });
    }

    // GHA_AGENT_CROSS_REPO_TOKEN (high): a non-default token is fed to the agent.
    const tokenRefs = [
      step.withToken ?? "",
      step.env?.GH_TOKEN ?? "",
      step.env?.GITHUB_TOKEN ?? "",
    ].join(" ");
    const usesNonDefaultSecret = /\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)[A-Za-z0-9_]+\s*\}\}/.test(tokenRefs);
    if (usesNonDefaultSecret) {
      findings.push({
        rule: "GHA_AGENT_CROSS_REPO_TOKEN",
        description:
          `AI-agent step is handed a custom token secret (not the default GITHUB_TOKEN). ` +
          `A broadly-scoped PAT lets the agent read OTHER repositories, including private ones - ` +
          `the cross-repo read that turns a single-repo prompt injection into an org-wide leak. ` +
          `Verify this token is a fine-grained, single-repository token.`,
        severity: "high",
        file: relativePath,
        line: step.line,
        recommendation: getWorkflowRecommendation("GHA_AGENT_CROSS_REPO_TOKEN"),
      });
    }
  }

  // GHA_AGENT_NO_AUTHOR_GATE (medium): agent driven by an externally-fileable
  // trigger with no author-trust gate anywhere in the file.
  const externallyFileable = EXTERNALLY_FILEABLE_TRIGGERS.some((t) => triggerSet.has(t));
  if (externallyFileable && !AUTHOR_GATE_RE.test(content)) {
    findings.push({
      rule: "GHA_AGENT_NO_AUTHOR_GATE",
      description:
        `AI-agent workflow is triggered by issues/comments (externally fileable by anyone) ` +
        `but has no author-trust gate. An unauthenticated attacker can open an issue and drive ` +
        `the agent - the entry point the GitLost attack used.`,
      severity: "medium",
      file: relativePath,
      line: agentSteps[0]!.step.line,
      recommendation: getWorkflowRecommendation("GHA_AGENT_NO_AUTHOR_GATE"),
    });
  }
}

// ── v5.7 Cordyceps trigger-aware rules ──────────────────────────────────────

/**
 * Triggers that run in the BASE repository context with access to secrets and
 * a read+write GITHUB_TOKEN (unlike plain `pull_request`, which runs in the
 * fork context with a read-only token). These are the elevated-privilege
 * entry points the Cordyceps composition attacks abuse.
 */
const PRIVILEGED_TRIGGERS = [
  "pull_request_target",
  "workflow_run",
  "issue_comment",
  "pull_request_review_comment",
];

/** Triggers where checking out untrusted PR/head code executes it WITH secrets. */
const PWN_CHECKOUT_TRIGGERS = ["pull_request_target", "workflow_run", "issue_comment"];

/**
 * A `with: ref:` value that resolves to attacker-controlled PR/head code.
 * Covers the head ref/sha, the numeric `refs/pull/N/merge|head` form, and
 * indirection through a matrix var / step output / needs output (all common
 * pwn-request evasions). Deliberately excludes the base ref (github.sha /
 * github.ref) which points at the trusted default branch.
 */
const PR_HEAD_REF_RE =
  /github\.head_ref|github\.event\.pull_request\.head|github\.event\.workflow_run\.head|github\.event\.(?:pull_request\.number|number)|refs\/pull\/|\$\{\{\s*(?:matrix|steps|needs)\./;

/** Untrusted context interpolated inside an actions/github-script `script:` body. */
const UNTRUSTED_CTX_RE =
  /\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|discussion|head_commit|commits?)|head_ref|ref_name)\b/;

// ── v5.10 GitLost-class agent-workflow rules ────────────────────────────────

/**
 * Actions that hand control to an autonomous AI agent which then reads workflow
 * inputs (issue/PR/comment text) as instructions. Matched owner/repo prefix,
 * ref-agnostic. This is an allowlist that will grow as new agent actions ship.
 */
const AGENT_ACTION_RE =
  /^(?:anthropics\/claude-code-action|anthropics\/claude-code-base-action|githubnext\/gh-aw|google-github-actions\/run-gemini-cli|google-gemini\/gemini-cli-action|openai\/codex-action)(?:@|$|\/)/i;

/** Agent CLIs invoked from a `run:` block (the non-action form of the same thing). */
const AGENT_CLI_RE =
  /\b(?:claude\s+(?:-p|--print)|copilot\s+(?:-p|suggest|exec)|gemini\s+(?:-p|--prompt)|codex\s+exec|aider\s+(?:--message|-m)\b)/i;

/**
 * Triggers that feed ATTACKER-CONTROLLABLE text (issue/PR/comment/discussion
 * bodies and titles) into the workflow, and hence into an agent step's prompt.
 * `issues`/`issue_comment` are the verified GitLost vectors; the pull_request*
 * and discussion* families are the same class.
 */
const AGENT_UNTRUSTED_TRIGGERS = [
  "issues",
  "issue_comment",
  "pull_request",
  "pull_request_target",
  "pull_request_review",
  "pull_request_review_comment",
  "discussion",
  "discussion_comment",
];

/** Token scopes that let a job post PUBLICLY (the GitLost exfiltration channel). */
const PUBLIC_POST_SCOPES = ["issues", "pull-requests"];

/** Any signal that the workflow gates on WHO triggered it (author trust). */
const AUTHOR_GATE_RE =
  /author_association|github\.actor\b|github\.triggering_actor\b|\.user\.login\b/;

/** Issue/comment triggers where an anonymous external user drives the agent. */
const EXTERNALLY_FILEABLE_TRIGGERS = ["issues", "issue_comment"];

/** True when a step hands control to an AI agent (action form or CLI form). */
function isAgentStep(step: { uses?: string; run?: string }): boolean {
  if (step.uses && AGENT_ACTION_RE.test(step.uses)) return true;
  if (step.run && AGENT_CLI_RE.test(step.run)) return true;
  return false;
}

/** All text an agent step ingests where untrusted context could appear. */
function agentStepText(step: {
  withPrompt?: string; run?: string; env?: Record<string, string>;
}): string {
  const envVals = step.env ? Object.values(step.env).join("\n") : "";
  return [step.withPrompt ?? "", step.run ?? "", envVals].join("\n");
}

/**
 * Structural rules that depend on the workflow's trigger and token model.
 * Parsed once per file via the zero-dependency workflow-ast parser.
 */
function checkWorkflowAstRules(
  content: string,
  relativePath: string,
  findings: Finding[],
): void {
  let ast;
  try {
    ast = parseWorkflow(content);
  } catch {
    return; // never let a parse hiccup break the scan
  }

  const lines = content.split("\n");
  const findLine = (re: RegExp): number | undefined => {
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i] ?? "")) return i + 1;
    }
    return undefined;
  };

  const triggerSet = new Set(ast.triggers);
  const privileged = PRIVILEGED_TRIGGERS.filter((t) => triggerSet.has(t));

  // GHA_PRIVILEGED_TRIGGER — the workflow runs in an elevated context.
  if (privileged.length > 0) {
    findings.push({
      rule: "GHA_PRIVILEGED_TRIGGER",
      description:
        `Workflow is triggered by ${privileged.join(", ")}, which runs in the base repository ` +
        `context with access to secrets and a read/write GITHUB_TOKEN. This is the elevated entry ` +
        `point Cordyceps-style attacks abuse; every step here is security-sensitive.`,
      severity: "low",
      file: relativePath,
      line: findLine(new RegExp(`\\b(?:${privileged.join("|")})\\b`)) ?? 1,
      match: privileged.join(", "),
      recommendation: getWorkflowRecommendation("GHA_PRIVILEGED_TRIGGER"),
    });
  }

  // GHA_PWN_REQUEST_CHECKOUT — privileged trigger checks out attacker PR/head code.
  const hasPwnTrigger = ast.triggers.some((t) => PWN_CHECKOUT_TRIGGERS.includes(t));
  if (hasPwnTrigger) {
    for (const job of ast.jobs) {
      for (const step of job.steps) {
        if (
          step.uses && /checkout/i.test(step.uses) &&
          step.withRef && PR_HEAD_REF_RE.test(step.withRef)
        ) {
          findings.push({
            rule: "GHA_PWN_REQUEST_CHECKOUT",
            description:
              `Privileged workflow checks out attacker-controlled PR/head code ` +
              `(ref: ${truncateMatch(step.withRef, 60)}) and then runs it with secrets in scope. ` +
              `This is the canonical "pwn request" - remote code execution with the maintainer token.`,
            severity: "critical",
            file: relativePath,
            line: step.line,
            match: truncateMatch(step.withRef),
            recommendation: getWorkflowRecommendation("GHA_PWN_REQUEST_CHECKOUT"),
          });
        }
      }
    }
  }

  // GHA_GITHUB_SCRIPT_INJECTION — untrusted context eval'd as JS by github-script.
  for (const job of ast.jobs) {
    for (const step of job.steps) {
      if (
        step.uses && /github-script/i.test(step.uses) &&
        step.withScript && UNTRUSTED_CTX_RE.test(step.withScript)
      ) {
        findings.push({
          rule: "GHA_GITHUB_SCRIPT_INJECTION",
          description:
            `actions/github-script step evaluates untrusted GitHub event context as JavaScript at ` +
            `runtime (code injection). An attacker who controls that context executes arbitrary code ` +
            `with the workflow token.`,
          severity: "high",
          file: relativePath,
          line: step.line,
          recommendation: getWorkflowRecommendation("GHA_GITHUB_SCRIPT_INJECTION"),
        });
      }
    }
  }

  // GHA_PERMS_WRITE_ALL — the token is granted every scope.
  if (ast.permissions.writeAll || ast.jobs.some((j) => j.permissions.writeAll)) {
    findings.push({
      rule: "GHA_PERMS_WRITE_ALL",
      description:
        `Workflow grants "permissions: write-all", giving the GITHUB_TOKEN write access to every scope ` +
        `(contents, packages, actions, pages, deployments...). If any step is compromised, the blast ` +
        `radius is the whole repository.`,
      severity: "high",
      file: relativePath,
      line: findLine(/permissions:\s*write-all/) ?? 1,
      match: "write-all",
      recommendation: getWorkflowRecommendation("GHA_PERMS_WRITE_ALL"),
    });
  }

  // GHA_PERMS_DEFAULT_BROAD — privileged trigger with no explicit least-privilege.
  // Fire when there is no top-level permissions block AND at least one job runs
  // without its own block (inheriting the broad repo default). A single sibling
  // job declaring permissions must not silence the rule for the jobs that don't.
  const topPermsDeclared = ast.permissions.declared;
  const someJobUnprotected =
    ast.jobs.length === 0 || ast.jobs.some((j) => !j.permissions.declared);
  if (privileged.length > 0 && !topPermsDeclared && someJobUnprotected) {
    findings.push({
      rule: "GHA_PERMS_DEFAULT_BROAD",
      description:
        `Privileged workflow (${privileged.join(", ")}) declares no explicit permissions, so the ` +
        `GITHUB_TOKEN falls back to the repository default - frequently read+write across all scopes. ` +
        `Combined with an elevated trigger, that default is loot for a Cordyceps-style compromise.`,
      severity: "medium",
      file: relativePath,
      line: findLine(new RegExp(`\\b(?:${privileged.join("|")})\\b`)) ?? 1,
      recommendation: getWorkflowRecommendation("GHA_PERMS_DEFAULT_BROAD"),
    });
  }
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
      const rawLine = lines[i] ?? "";
      // v5.2.22: strip YAML comments before matching. A comment line
      // mentioning "id-token: write" or "secrets.X" as documentation is
      // not the actual workflow declaring those - it's prose. Without
      // this strip, the v5.2.21 self-scan flagged "id-token: write" in
      // the OIDC explanation comment of ci.yml as a real permission.
      const line = stripYamlComment(rawLine);
      if (!line.trim()) continue;

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
 * Strip a trailing YAML comment from a line. A `#` that is preceded by
 * whitespace or at line start starts a comment; `#` inside quoted strings
 * is preserved. v5.2.22.
 */
function stripYamlComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let j = 0; j < line.length; j++) {
    const ch = line[j];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === "#" && !inSingle && !inDouble) {
      // Comment marker: must be at start of line or preceded by whitespace
      if (j === 0 || /\s/.test(line[j - 1]!)) {
        return line.slice(0, j);
      }
    }
  }
  return line;
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

    // Check against known malicious SHAs (highest priority — always critical)
    if (SHA_PATTERN.test(ref) && KNOWN_MALICIOUS_ACTION_SHAS.has(ref)) {
      findings.push({
        rule: "GHA_KNOWN_MALICIOUS_SHA",
        description: `Action "${actionRef}" references a KNOWN COMPROMISED commit SHA: ${KNOWN_MALICIOUS_ACTION_SHAS.get(ref)}. This SHA is confirmed malicious.`,
        severity: "critical",
        file: relativePath,
        line: i + 1,
        match: truncateMatch(actionRef),
        recommendation:
          "Remove or replace this action immediately. Update to a verified clean version and rotate any secrets " +
          "that may have been exposed during builds using this action.",
      });
    }

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
    GHA_PPE_PULL_TARGET:
      "Avoid using pull_request_target with checkout of PR code or PR context in run steps. " +
      "Use pull_request trigger instead, or sanitize all PR context values before use.",
    GHA_SCRIPT_INJECTION:
      "Never interpolate user-controlled GitHub context (issue body, PR title, commit message) directly into run: steps. " +
      "Store the value in an environment variable first: env: VALUE: ${{ github.event.issue.body }} then use $VALUE.",
    GHA_OIDC_WRITE_PERM:
      "Audit all steps in this workflow when id-token:write is set. Ensure no third-party action or run step " +
      "can exfiltrate the OIDC token. Scope permissions as narrowly as possible.",
    GHA_CACHE_POISONING:
      "Do not use github.head_ref in cache keys for workflows that can be triggered by untrusted PRs. " +
      "Use github.sha or a hash of locked dependency files instead.",
    GHA_ARTIFACT_DOWNLOAD:
      "Verify that downloaded artifacts originate only from trusted, protected workflows. " +
      "Consider adding artifact attestation using actions/attest-build-provenance.",
    GHA_SELF_MODIFY:
      "Workflows must not modify their own or other workflow files. This pattern is used by supply chain worms " +
      "to persist malicious code. Investigate immediately and audit recent workflow file changes.",
    GHA_KNOWN_MALICIOUS_SHA:
      "Replace this action immediately and rotate all secrets accessible during builds that used this action. " +
      "File a security incident report and review all build logs for exfiltrated data.",
    GHA_PRIVILEGED_TRIGGER:
      "Treat every step in this workflow as running with production privileges. Prefer 'pull_request' over " +
      "'pull_request_target' for untrusted contributions, set an explicit least-privilege 'permissions:' block, " +
      "and gate privileged jobs behind manual approval (environments) for first-time contributors.",
    GHA_PWN_REQUEST_CHECKOUT:
      "Never check out PR/head code inside a privileged (pull_request_target/workflow_run) workflow. Move build/test " +
      "of untrusted code to a 'pull_request' workflow (read-only token, no secrets), or split into a privileged job " +
      "that does NOT run the checked-out code. If you must, gate it behind an environment approval.",
    GHA_GITHUB_SCRIPT_INJECTION:
      "Do not interpolate ${{ github.event... }} directly into an actions/github-script 'script:' block - it is eval'd " +
      "as JavaScript. Pass the value through an env var and read process.env inside the script instead.",
    GHA_PERMS_WRITE_ALL:
      "Remove 'permissions: write-all'. Declare the minimal scopes each job needs (e.g. 'contents: read'). Default the " +
      "top-level permissions to read-only and grant write only where required.",
    GHA_PERMS_DEFAULT_BROAD:
      "Add an explicit top-level 'permissions:' block scoped to the minimum (start from 'contents: read'). Privileged " +
      "triggers should never rely on the repository default token, which is often read+write across all scopes.",
    GHA_AGENT_UNTRUSTED_PROMPT:
      "Do not interpolate untrusted event context (github.event.issue/comment/pull_request body or title) " +
      "into an AI-agent prompt. Pass only sanitized, structured fields, gate the job on author_association, " +
      "and treat all issue/PR text as untrusted data the agent must never act on as instructions.",
    GHA_AGENT_PUBLIC_POST:
      "Remove issues:write / pull-requests:write from any job where an AI agent processes untrusted input, " +
      "or split the agent (read-only, no public-write token) from the step that posts. An agent that can both " +
      "read private data and post publicly is a one-step exfiltration channel.",
    GHA_AGENT_CROSS_REPO_TOKEN:
      "Scope the agent's token to the single repository it needs. Prefer the default GITHUB_TOKEN or a " +
      "fine-grained PAT limited to one repo. A broad org/classic PAT lets a prompt-injected agent read every " +
      "private repo it can reach.",
    GHA_AGENT_NO_AUTHOR_GATE:
      "Gate AI-agent jobs triggered by issues/comments on the author's trust level " +
      "(if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.issue.author_association)) " +
      "so anonymous external users cannot drive the agent.",
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
