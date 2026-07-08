/**
 * AI agent skills / rules-file scanner (v5.3).
 *
 * AI coding agents (Claude Code, Cursor, Copilot, Gemini CLI) read and obey
 * instruction files that no mainstream scanner inspects: .claude/skills,
 * .claude/commands, .cursorrules, CLAUDE.md, AGENTS.md, and friends. The
 * ClawHub audit found 11.9% of published agent skills malicious. These files
 * are a direct instruction channel into the agent, so hidden text, control
 * tokens, download-and-execute recipes, and credential-harvesting steps in
 * them are supply-chain attacks on the developer's AI tooling.
 *
 * False-positive design: rules files legitimately INSTRUCT agents in natural
 * language, so jailbreak-style prose ("ignore previous instructions") is only
 * reported at medium severity with reduced confidence. Raw LLM control
 * TOKENS (<|im_start|>, a fake <system-reminder>) have no legitimate reason
 * to appear in a rules file and stay high severity. Security guidance that
 * NEGATES an action ("never read ~/.ssh/") is not flagged.
 *
 * Note: the core directory walk in scanner.ts deliberately skips .claude/;
 * this module does its own targeted traversal from the scan root.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { PROMPT_INJECTION_PATTERNS, MAX_FILE_SIZE } from "./patterns.js";

// ---------------------------------------------------------------------------
// Target file discovery
// ---------------------------------------------------------------------------

/** Rules files that live directly in the scan root. */
const ROOT_RULES_FILES = ["CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules"];

/** Maximum recursion depth when walking .claude/skills. */
const MAX_SKILL_DEPTH = 8;

// ---------------------------------------------------------------------------
// Detection patterns
// ---------------------------------------------------------------------------

/**
 * LLM control tokens reused from PROMPT_INJECTION_PATTERNS (patterns.ts).
 * The natural-language override-prose pattern is split out and downgraded
 * (see module header) because rules files legitimately instruct agents.
 */
const TOKEN_INJECTION_REGEXES = PROMPT_INJECTION_PATTERNS
  .filter((p) => p.rule !== "PROMPT_INJECTION_OVERRIDE_PROSE")
  .map((p) => ({ name: p.name, regex: new RegExp(p.pattern, "i") }));

const OVERRIDE_PROSE_ENTRY = PROMPT_INJECTION_PATTERNS.find(
  (p) => p.rule === "PROMPT_INJECTION_OVERRIDE_PROSE",
);
const OVERRIDE_PROSE_REGEX = OVERRIDE_PROSE_ENTRY
  ? new RegExp(OVERRIDE_PROSE_ENTRY.pattern, "i")
  : null;

/**
 * Invisible Unicode runs (same character class as the INVISIBLE_UNICODE
 * file pattern in patterns.ts). Requires a run of 3+ so isolated zero-width
 * joiners in emoji sequences do not fire. v5.10: the surrogate-pair alternative
 * \uDB40[\uDC00-\uDC7F] covers the Unicode Tags block (U+E0000..U+E007F) used
 * to smuggle invisible instructions into an agent-read file (ASCII smuggling).
 */
const INVISIBLE_RUN_REGEX =
  /(?:[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u034F\u061C\u180E]|\uDB40[\uDC00-\uDC7F]){3,}/;

/**
 * Bidirectional override/isolate controls (same set as the RTL_OVERRIDE
 * file pattern in patterns.ts). A single occurrence is already suspicious
 * in an agent-read instruction file.
 */
const BIDI_CONTROL_REGEX = /[\u202A-\u202E\u2066-\u2069]/;

/** Characters escaped when rendering an invisible-unicode match snippet. */
const INVISIBLE_ESCAPE_REGEX =
  /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\u00AD\u034F\u061C\u180E]/g;

/** Download-and-execute chains (shell, PowerShell, base64-decode pipe). */
const DOWNLOAD_EXEC_REGEXES: RegExp[] = [
  // curl/wget piped into a shell
  /\b(?:curl|wget)\b[^\n|]*\|[^\n|]*\b(?:sudo\s+)?(?:bash|sh|zsh|dash)\b/i,
  // PowerShell: iwr/irm piped into iex
  /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|[^\n|]*\b(?:iex|invoke-expression)\b/i,
  // PowerShell: iex(iwr ...)
  /\b(?:iex|invoke-expression)\s*\(\s*(?:\(?\s*)?(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b/i,
  // base64 -d | sh
  /\bbase64\s+(?:-d|-D|--decode)\b[^\n|]*\|[^\n|]*\b(?:bash|sh|zsh|dash)\b/i,
];

/** Credential file/path references. */
const CREDENTIAL_PATH_REGEX =
  /\.aws[/\\]credentials|~[/\\]\.ssh\b|\$HOME[/\\]\.ssh\b|\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa|id_dsa)|(?:AppData[/\\]Local[/\\]Google[/\\]Chrome|Library[/\\]Application Support[/\\]Google[/\\]Chrome|\.config[/\\]google-chrome|\.mozilla[/\\]firefox)/i;

/** .npmrc only counts as a credential reference next to token material. */
const NPMRC_REGEX = /\.npmrc\b/i;
const NPMRC_TOKEN_REGEX = /_auth(?:Token)?|\btoken\b|\bcredential/i;

/** Read/collect/send verbs that turn a credential path into an access instruction. */
const CREDENTIAL_VERB_REGEX =
  /\b(?:read|cat|type|print|copy|cp|scp|open|load|dump|collect|grab|harvest|steal|zip|tar|compress|encode|send|upload|post|exfiltrate|transmit|forward|mail|email|curl|wget|fetch)\b/i;

/** Negated guidance ("never read ~/.ssh/") is legitimate security advice. */
const NEGATION_REGEX =
  /\b(?:never|not|don'?t|avoid|forbidden|forbid|prohibit(?:ed|s)?|refuse|without|no)\b/i;

/** Dangerous constructs inside executable settings hooks commands. */
const HOOK_EVAL_REGEX = /\beval\b/;
const HOOK_BASE64_REGEX =
  /\bbase64\s+(?:-d|-D|--decode)\b|\batob\s*\(|frombase64string/i;
const HOOK_SHELL_RC_WRITE_REGEX =
  /(?:>>?|\btee\b(?:\s+-a)?)\s*(?:~|\$HOME|%USERPROFILE%)?[^\s|;&]*\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b/i;

// TODO(v2): skill impersonation heuristic - frontmatter/name containing
// claude|anthropic|openai|copilot while the body downloads binaries. Left out
// of v1: too heuristic, needs a corpus of real skill names to tune against.

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan AI agent skill / rules files under a directory.
 *
 * Targets (relative to dir): .claude/skills/**\/SKILL.md, .claude/commands/*.md,
 * .claude/settings.json, .claude/settings.local.json, .cursorrules,
 * .cursor/rules/*.mdc, .github/copilot-instructions.md, AGENTS.md, CLAUDE.md,
 * GEMINI.md.
 */
export function scanAgentSkillFiles(dir: string): Finding[] {
  const findings: Finding[] = [];

  for (const relPath of collectRulesFiles(dir)) {
    const content = readSmallFile(path.join(dir, relPath));
    if (content === null) continue;
    findings.push(...scanSkillContent(content, relPath));
  }

  for (const relPath of [".claude/settings.json", ".claude/settings.local.json"]) {
    const content = readSmallFile(path.join(dir, relPath));
    if (content === null) continue;
    findings.push(...scanAgentSettingsContent(content, relPath));
  }

  return findings;
}

/**
 * Scan the text of a single skill / command / rules file.
 */
export function scanSkillContent(content: string, relativePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";

    // 1a. Raw LLM control tokens - no legitimate reason in a rules file.
    for (const token of TOKEN_INJECTION_REGEXES) {
      const match = token.regex.exec(line);
      if (match) {
        findings.push({
          rule: "SKILL_PROMPT_INJECTION",
          description:
            `Agent rules file contains a raw LLM control token (${token.name}). ` +
            "Rules files are read verbatim by AI coding agents; embedded role/system " +
            "tokens hijack the agent's instruction context.",
          severity: "high",
          file: relativePath,
          line: i + 1,
          match: truncate(match[0]),
          confidence: 0.9,
          category: "supply-chain",
          recommendation:
            "Remove the control token. A skill or rules file never needs literal LLM role markers.",
        });
        break; // one token finding per line is enough
      }
    }

    // 1b. Jailbreak-style override prose - reduced confidence, because these
    // files legitimately instruct agents in imperative natural language.
    if (OVERRIDE_PROSE_REGEX) {
      const match = OVERRIDE_PROSE_REGEX.exec(line);
      if (match) {
        findings.push({
          rule: "SKILL_PROMPT_INJECTION",
          description:
            "Agent rules file contains override/jailbreak phrasing ('ignore previous " +
            "instructions', ...). Reduced confidence: rules files legitimately instruct " +
            "agents, but overriding PRIOR instructions is a hijack pattern.",
          severity: "medium",
          file: relativePath,
          line: i + 1,
          match: truncate(match[0].trim()),
          confidence: 0.45,
          category: "supply-chain",
          recommendation:
            "Review the instruction. Legitimate rules add guidance; they do not ask the agent to discard its existing instructions.",
        });
      }
    }

    // 2. Invisible / bidi Unicode - hidden-instruction channel for agents.
    if (INVISIBLE_RUN_REGEX.test(line) || BIDI_CONTROL_REGEX.test(line)) {
      findings.push({
        rule: "SKILL_INVISIBLE_UNICODE",
        description:
          "Invisible or bidirectional Unicode characters in an agent rules file. " +
          "Agents read these files verbatim - invisible text is a hidden-instruction " +
          "channel invisible to human reviewers.",
        severity: "critical",
        file: relativePath,
        line: i + 1,
        match: truncate(escapeInvisible(line.trim())),
        confidence: 0.85,
        category: "malware",
        recommendation:
          "Open the file in a hex editor and remove all zero-width and bidi control characters.",
      });
    }

    // 3. Download-and-execute instructions in prose.
    for (const regex of DOWNLOAD_EXEC_REGEXES) {
      const match = regex.exec(line);
      if (match) {
        findings.push({
          rule: "SKILL_DOWNLOAD_EXEC",
          description:
            "Agent rules file instructs downloading and executing remote code " +
            "(curl/wget piped to a shell, iwr|iex, or base64 -d | sh). Agents may run " +
            "this without human review.",
          severity: "high",
          file: relativePath,
          line: i + 1,
          match: truncate(match[0]),
          confidence: 0.8,
          category: "malware",
          recommendation:
            "Never pipe downloads into a shell from an agent instruction file. Pin and vendor the script instead.",
        });
        break;
      }
    }

    // 4. Credential-path references combined with read/send verbs.
    if (!NEGATION_REGEX.test(line) && CREDENTIAL_VERB_REGEX.test(line)) {
      const credentialPath =
        CREDENTIAL_PATH_REGEX.test(line) ||
        (NPMRC_REGEX.test(line) && NPMRC_TOKEN_REGEX.test(line));
      if (credentialPath) {
        findings.push({
          rule: "SKILL_CREDENTIAL_ACCESS",
          description:
            "Agent rules file instructs reading or sending credential files " +
            "(~/.ssh, .aws/credentials, .npmrc tokens, browser profiles). This is " +
            "credential theft via the AI agent.",
          severity: "high",
          file: relativePath,
          line: i + 1,
          match: truncate(line.trim()),
          confidence: 0.7,
          category: "malware",
          recommendation:
            "Remove the instruction. Agents must never be directed to read or transmit credential stores.",
        });
      }
    }
  }

  return findings;
}

/**
 * Scan a .claude/settings.json / settings.local.json for dangerous hook
 * commands. Malformed JSON is ignored (no crash, no findings).
 */
export function scanAgentSettingsContent(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return findings;
  }
  if (parsed === null || typeof parsed !== "object") return findings;

  const hooks = (parsed as Record<string, unknown>).hooks;
  if (hooks === null || hooks === undefined || typeof hooks !== "object") {
    return findings;
  }

  const commands: string[] = [];
  collectHookCommands(hooks, commands, 0);

  for (const command of commands) {
    // Download-and-execute inside an executable hook: critical (the hook
    // runs automatically, no prose ambiguity).
    if (DOWNLOAD_EXEC_REGEXES.some((r) => r.test(command))) {
      findings.push({
        rule: "SKILL_DOWNLOAD_EXEC",
        description:
          "Agent settings hook downloads and executes remote code. Hooks run " +
          "automatically on agent lifecycle events without human review.",
        severity: "critical",
        file: relativePath,
        match: truncate(command),
        confidence: 0.95,
        category: "malware",
        recommendation:
          "Remove the hook. Hook commands must never fetch and execute remote code.",
      });
    }

    const dangerous =
      HOOK_EVAL_REGEX.test(command) ||
      HOOK_BASE64_REGEX.test(command) ||
      HOOK_SHELL_RC_WRITE_REGEX.test(command) ||
      DOWNLOAD_EXEC_REGEXES.some((r) => r.test(command));
    if (dangerous) {
      findings.push({
        rule: "AGENT_HOOK_DANGEROUS_COMMAND",
        description:
          "Agent settings hook contains a dangerous command (eval, base64 decode, " +
          "download-exec pipe, or shell rc file modification). Hooks execute with the " +
          "developer's full privileges.",
        severity: "critical",
        file: relativePath,
        match: truncate(command),
        confidence: 0.9,
        category: "malware",
        recommendation:
          "Audit and remove the hook command. Persistence via shell rc files or obfuscated hook payloads is a compromise indicator.",
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Collect all prose rules files relative to the scan root. */
function collectRulesFiles(dir: string): string[] {
  const files: string[] = [];

  for (const name of ROOT_RULES_FILES) {
    if (isFile(path.join(dir, name))) files.push(name);
  }

  if (isFile(path.join(dir, ".github", "copilot-instructions.md"))) {
    files.push(".github/copilot-instructions.md");
  }

  // .claude/commands/*.md (non-recursive)
  for (const name of listFiles(path.join(dir, ".claude", "commands"))) {
    if (name.toLowerCase().endsWith(".md")) files.push(`.claude/commands/${name}`);
  }

  // .cursor/rules/*.mdc (non-recursive)
  for (const name of listFiles(path.join(dir, ".cursor", "rules"))) {
    if (name.toLowerCase().endsWith(".mdc")) files.push(`.cursor/rules/${name}`);
  }

  // .claude/skills/**/SKILL.md (recursive)
  collectSkillManifests(path.join(dir, ".claude", "skills"), ".claude/skills", files, 0);

  return files;
}

/** Recursively find SKILL.md manifests under .claude/skills. */
function collectSkillManifests(
  absDir: string,
  relDir: string,
  out: string[],
  depth: number,
): void {
  if (depth > MAX_SKILL_DEPTH) return;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(absDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      collectSkillManifests(
        path.join(absDir, entry.name),
        `${relDir}/${entry.name}`,
        out,
        depth + 1,
      );
    } else if (entry.isFile() && entry.name.toUpperCase() === "SKILL.MD") {
      out.push(`${relDir}/${entry.name}`);
    }
  }
}

/** Recursively collect "command" string values from a hooks config block. */
function collectHookCommands(node: unknown, out: string[], depth: number): void {
  if (depth > 12 || node === null || typeof node !== "object") return;

  if (Array.isArray(node)) {
    for (const item of node) collectHookCommands(item, out, depth + 1);
    return;
  }

  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (key === "command" && typeof value === "string") {
      out.push(value);
    } else {
      collectHookCommands(value, out, depth + 1);
    }
  }
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function listFiles(absDir: string): string[] {
  try {
    return fs
      .readdirSync(absDir, { withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => e.name);
  } catch {
    return [];
  }
}

/** Read a file as UTF-8, skipping unreadable or oversized files. */
function readSmallFile(p: string): string | null {
  try {
    const stat = fs.statSync(p);
    if (!stat.isFile() || stat.size > MAX_FILE_SIZE) return null;
    return fs.readFileSync(p, "utf-8");
  } catch {
    return null;
  }
}

/** Render invisible/bidi characters as \uXXXX escapes for the match snippet. */
function escapeInvisible(s: string): string {
  return s
    .replace(
      INVISIBLE_ESCAPE_REGEX,
      (c) => "\\u" + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0"),
    )
    // v5.10: Unicode Tags (U+E0000..U+E007F) arrive as a surrogate pair; render
    // both units so smuggled tag runs are visible in the match snippet.
    .replace(/\uDB40[\uDC00-\uDC7F]/g, (m) =>
      "\\u" + m.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0") +
      "\\u" + m.charCodeAt(1).toString(16).toUpperCase().padStart(4, "0"),
    );
}

function truncate(s: string): string {
  return s.length > 120 ? s.substring(0, 120) + "..." : s;
}
