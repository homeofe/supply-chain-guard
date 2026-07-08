/**
 * GitHub Agentic Workflow (gh-aw) markdown scanner (v5.10).
 *
 * GitHub Agentic Workflows live in `.github/workflows/*.md`: YAML frontmatter
 * (on:/permissions:/engine:/tools:/safe-outputs:) plus a natural-language body
 * that IS the agent's instructions. The legacy .yml-only workflow scanner skips
 * these entirely. The GitLost disclosure (Noma, July 2026) exploited exactly
 * this file shape: an untrusted issue trigger + a public add-comment tool +
 * cross-repo read = private data leaked through a public comment. We can only
 * see the static POSTURE, never the runtime issue payload.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, Severity } from "./types.js";
import { parseWorkflow } from "./workflow-ast.js";
import { PROMPT_INJECTION_PATTERNS } from "./patterns.js";

/** Triggers that feed attacker-controllable text into the agent. */
const UNTRUSTED_TRIGGERS = [
  "issues", "issue_comment", "pull_request", "pull_request_target",
  "pull_request_review", "pull_request_review_comment", "discussion", "discussion_comment",
];

/** gh-aw tool names that post PUBLICLY (the exfiltration channel). */
const PUBLIC_POST_TOOLS = [
  "add-comment", "add-issue-comment", "create-issue", "update-issue",
  "add-pull-request-review-comment", "create-pull-request-review-comment",
];

/**
 * Split a gh-aw markdown file into its YAML frontmatter and body. Returns null
 * when there is no `---` frontmatter fence (i.e. it is an ordinary md file).
 */
function splitFrontmatter(content: string): { frontmatter: string; body: string } | null {
  const norm = content.replace(/\r/g, "");
  if (!norm.startsWith("---\n")) return null;
  const end = norm.indexOf("\n---", 4);
  if (end === -1) return null;
  const frontmatter = norm.slice(4, end);
  const afterFence = norm.indexOf("\n", end + 1);
  const body = afterFence === -1 ? "" : norm.slice(afterFence + 1);
  return { frontmatter, body };
}

function rec(rule: string): string {
  const map: Record<string, string> = {
    AGENTIC_WF_UNTRUSTED_TRIGGER:
      "This Agentic Workflow ingests attacker-controllable issue/PR text by design. Gate it on author " +
      "trust and never let the agent treat that text as instructions.",
    AGENTIC_WF_PUBLIC_POST_TOOL:
      "Remove public-post tools (add-comment/create-issue/...) from Agentic Workflows triggered by untrusted " +
      "input, or scope the agent read-only. Read private + post public is the GitLost exfiltration channel.",
    AGENTIC_WF_BROAD_ACCESS:
      "Scope the agent's token/permissions to the single repository it needs. A cross-repo PAT lets a " +
      "prompt-injected agent read every private repo it can reach.",
    AGENTIC_WF_PROMPT_INJECTION:
      "An LLM control token or override phrase appears in this agent instruction file. Remove it: agents read " +
      "the body verbatim, so embedded control tokens hijack the agent.",
  };
  return map[rule] ?? "Review this Agentic Workflow's posture.";
}

function push(
  findings: Finding[], rule: string, severity: Severity, description: string,
  file: string, line: number,
): void {
  findings.push({ rule, description, severity, file, line, recommendation: rec(rule) });
}

/** Scan `.github/workflows/*.md` gh-aw files under `dir`. */
export function scanAgenticWorkflows(dir: string): Finding[] {
  const findings: Finding[] = [];
  const wfDir = path.join(dir, ".github", "workflows");
  if (!fs.existsSync(wfDir)) return findings;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(wfDir, { withFileTypes: true });
  } catch {
    return findings;
  }

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (path.extname(entry.name).toLowerCase() !== ".md") continue;

    const rel = path.join(".github", "workflows", entry.name).replace(/\\/g, "/");
    let content: string;
    try {
      content = fs.readFileSync(path.join(wfDir, entry.name), "utf-8");
    } catch {
      continue;
    }

    const parts = splitFrontmatter(content);
    if (!parts) continue; // ordinary markdown, not a gh-aw workflow

    scanOne(parts.frontmatter, parts.body, rel, findings);
  }
  return findings;
}

function scanOne(
  frontmatter: string, body: string, rel: string, findings: Finding[],
): void {
  let triggers: string[] = [];
  try {
    triggers = parseWorkflow(frontmatter).triggers ?? [];
  } catch {
    triggers = [];
  }
  const triggerSet = new Set(triggers);
  const untrusted = UNTRUSTED_TRIGGERS.filter((t) => triggerSet.has(t));
  const fmLower = frontmatter.toLowerCase();

  if (untrusted.length > 0) {
    push(findings, "AGENTIC_WF_UNTRUSTED_TRIGGER", "medium",
      `Agentic Workflow triggers on ${untrusted.join(", ")}, feeding attacker-controllable text ` +
      `into the agent's instruction context.`, rel, 1);
  }

  const hasPublicPostTool = PUBLIC_POST_TOOLS.some((t) => fmLower.includes(t));
  if (hasPublicPostTool && untrusted.length > 0) {
    push(findings, "AGENTIC_WF_PUBLIC_POST_TOOL", "high",
      `Agentic Workflow on an untrusted trigger grants a public-post tool (add-comment / create-issue). ` +
      `The agent can post what it read as a public comment: the GitLost exfiltration channel.`, rel, 1);
  }

  // Cross-repo / broad access indicators in frontmatter.
  const hasNonDefaultSecret = /\$\{\{\s*secrets\.(?!github_token\b)[a-z0-9_]+\s*\}\}/i.test(frontmatter);
  const hasRepoList = /^\s*(?:repos|repositories)\s*:/im.test(frontmatter);
  if ((hasNonDefaultSecret || hasRepoList) && untrusted.length > 0) {
    push(findings, "AGENTIC_WF_BROAD_ACCESS", "high",
      `Agentic Workflow on an untrusted trigger shows cross-repo access indicators ` +
      `(custom token secret or explicit repo list). Combined with a public-post tool this is the ` +
      `full GitLost lethal trifecta.`, rel, 1);
  }

  // LLM control tokens hidden in the instruction body.
  const bodyLines = body.split("\n");
  for (const p of PROMPT_INJECTION_PATTERNS) {
    const re = new RegExp(p.pattern, "i");
    for (let i = 0; i < bodyLines.length; i++) {
      if (re.test(bodyLines[i] ?? "")) {
        push(findings, "AGENTIC_WF_PROMPT_INJECTION", "high",
          `LLM control token / override phrase in an Agentic Workflow instruction body ` +
          `(matched ${p.rule}). Agents read the body verbatim.`, rel, i + 1);
        break; // one finding per pattern is enough
      }
    }
  }
}
