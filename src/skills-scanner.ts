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
import {
  PROMPT_INJECTION_PATTERNS,
  MAX_FILE_SIZE,
  makeOversizedSkipFinding,
  CHAINDROP_PERSISTENCE_ARTEFACT_REGEX,
  ASSET_EXEC_PATTERN,
} from "./patterns.js";
import {
  listDiscoveredDirectory,
  listOptionalDirectory,
  matchPatternInSemanticText,
  readDiscoveredUtf8File,
  readOptionalUtf8File,
  recordUnreadablePath,
} from "./pattern-scanner.js";
import { stripJsonc } from "./mcp-scanner.js";

// ---------------------------------------------------------------------------
// Target file discovery
// ---------------------------------------------------------------------------

/** Rules / memory files that live directly in the scan root. */
const ROOT_RULES_FILES = [
  "CLAUDE.md",
  "AGENTS.md",
  "GEMINI.md",
  ".cursorrules",
  // Agent long-term memory files - read verbatim by AI agents just like rules
  // files, so the same injection / invisible-unicode pipeline applies.
  "MEMORY.md",
  "AGENTS_MEMORY.md",
];

/** Maximum recursion depth when walking .claude/skills. */
const MAX_SKILL_DEPTH = 8;

/**
 * Maximum public directory entries expanded across both recursive rules-file
 * trees. Symlink aliases retain their public paths, so a small alias DAG can
 * otherwise multiply into exponential work even when no canonical cycle is
 * present.
 */
const MAX_SKILL_WALK_ENTRIES = 10_000;

// ---------------------------------------------------------------------------
// Detection patterns
// ---------------------------------------------------------------------------

/**
 * LLM control tokens reused from PROMPT_INJECTION_PATTERNS (patterns.ts).
 * The natural-language override-prose pattern is split out and downgraded
 * (see module header) because rules files legitimately instruct agents.
 */
const TOKEN_INJECTION_PATTERNS = PROMPT_INJECTION_PATTERNS.filter(
  (pattern) => pattern.rule !== "PROMPT_INJECTION_OVERRIDE_PROSE",
);

const OVERRIDE_PROSE_ENTRY = PROMPT_INJECTION_PATTERNS.find(
  (pattern) => pattern.rule === "PROMPT_INJECTION_OVERRIDE_PROSE",
);

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

/** A download-and-execute match: where it starts and the text it covers. */
export interface DownloadExecMatch {
  index: number;
  text: string;
}

type DownloadExecMatcher = (text: string) => DownloadExecMatch | null;

/**
 * Matches the pipe-chain expressions
 *   first [^\n|]* \| [^\n|]* second
 * (for example `\b(?:curl|wget)\b[^\n|]*\|[^\n|]*\b(?:sudo\s+)?(?:bash|sh)\b`)
 * with the same result as the regex, including the matched text, in linear
 * time. As a regex, `[^\n|]*` rescans to the end of the line from every
 * `curl` of a line that never reaches a `|`: quadratic, 4.5 s for 40,000
 * characters and hours at the 5 MB file cap, on content the scanned package
 * controls (found in the 6.3.0 pre-release review).
 *
 * `first` must be global and `second` sticky. Each `first` match reaches at
 * most one pipe (the first `|` after it, if no newline comes first), and each
 * pipe is evaluated once, so the work is bounded by the text length.
 */
function pipeChainMatcher(first: RegExp, second: RegExp): DownloadExecMatcher {
  return (text) => {
    first.lastIndex = 0;
    let breakAt = -1; // first "|" or "\n" at or after the last match end
    let lastPipe = -1;
    for (let m = first.exec(text); m !== null; m = first.exec(text)) {
      const end = m.index + m[0].length;
      if (end > breakAt) {
        breakAt = end;
        while (breakAt < text.length && text[breakAt] !== "|" && text[breakAt] !== "\n") breakAt++;
      }
      if (breakAt >= text.length || text[breakAt] !== "|" || breakAt === lastPipe) continue;
      lastPipe = breakAt;
      const tail = lastMatchEndInSegment(text, breakAt + 1, second);
      if (tail >= 0) return { index: m.index, text: text.slice(m.index, tail) };
    }
    return null;
  };
}

/**
 * End of the match `[^\n|]*` + `second` makes from `start`: greedy, so the
 * rightmost position in the segment where `second` matches. -1 if none.
 */
function lastMatchEndInSegment(text: string, start: number, second: RegExp): number {
  let segEnd = start;
  while (segEnd < text.length && text[segEnd] !== "|" && text[segEnd] !== "\n") segEnd++;
  for (let i = segEnd; i >= start; i--) {
    second.lastIndex = i;
    const m = second.exec(text);
    if (m) return i + m[0].length;
  }
  return -1;
}

function regexMatcher(re: RegExp): DownloadExecMatcher {
  return (text) => {
    const m = re.exec(text);
    return m ? { index: m.index, text: m[0] } : null;
  };
}

const SHELL_AFTER_PIPE = /\b(?:sudo\s+)?(?:bash|sh|zsh|dash)\b/iy;

/**
 * Download-and-execute chains (shell, PowerShell, base64-decode pipe), in the
 * order a line is checked. Each returns what its reference expression would;
 * property-parsers.test.ts holds them to those expressions.
 */
export const DOWNLOAD_EXEC_MATCHERS: readonly DownloadExecMatcher[] = [
  // curl/wget piped into a shell
  pipeChainMatcher(/\b(?:curl|wget)\b/gi, SHELL_AFTER_PIPE),
  // PowerShell: iwr/irm piped into iex
  pipeChainMatcher(/\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b/gi, /\b(?:iex|invoke-expression)\b/iy),
  // PowerShell: iex(iwr ...). `\s*(?:\(\s*)?` after the paren, not
  // `\s*(?:\(?\s*)?`: the same strings, but in the old form a run of spaces
  // could be split between two quantifiers in every possible way, which is
  // quadratic (CodeQL js/polynomial-redos). Linear as a regex.
  regexMatcher(/\b(?:iex|invoke-expression)\s*\(\s*(?:\(\s*)?(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b/i),
  // base64 -d | sh
  pipeChainMatcher(/\bbase64\s+(?:-d|-D|--decode)\b/gi, SHELL_AFTER_PIPE),
];

/** The first download-and-execute chain in `text`, in matcher order. */
export function findDownloadExec(text: string): DownloadExecMatch | null {
  for (const matcher of DOWNLOAD_EXEC_MATCHERS) {
    const hit = matcher(text);
    if (hit) return hit;
  }
  return null;
}

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
const RC_FILE_NAMES = ["bashrc", "zshrc", "bash_profile", "zprofile", "profile"] as const;
const WHITESPACE = /\s/;

const isWordCode = (c: number): boolean =>
  (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
// ASCII-only case folding: what /i does without the u flag for ASCII literals.
const lowerCode = (c: number): number => (c >= 65 && c <= 90 ? c + 32 : c);
const isPathChar = (ch: string): boolean =>
  ch !== "|" && ch !== ";" && ch !== "&" && ch !== ">" && !WHITESPACE.test(ch);

/** `.bashrc`-style name at `dot`, ending on a word boundary. */
function rcFileAt(text: string, dot: number): boolean {
  for (const name of RC_FILE_NAMES) {
    const end = dot + 1 + name.length;
    if (end > text.length) continue;
    let same = true;
    for (let k = 0; k < name.length && same; k++) {
      same = lowerCode(text.charCodeAt(dot + 1 + k)) === name.charCodeAt(k);
    }
    if (same && (end === text.length || !isWordCode(text.charCodeAt(end)))) return true;
  }
  return false;
}

/** A `tee` word ending just before `end`, with a word boundary on both sides. */
function teeEndsAt(text: string, end: number): boolean {
  if (end < 3) return false;
  if (lowerCode(text.charCodeAt(end - 3)) !== 116 || lowerCode(text.charCodeAt(end - 2)) !== 101
    || lowerCode(text.charCodeAt(end - 1)) !== 101) return false;
  if (end > 3 && isWordCode(text.charCodeAt(end - 4))) return false;
  return end === text.length || !isWordCode(text.charCodeAt(end));
}

/**
 * Whether a command writes to a shell startup file: a redirect (`>`, `>>`)
 * or `tee` / `tee -a` into a path ending in .bashrc, .zshrc, .bash_profile,
 * .zprofile or .profile. Exactly the strings the reference expression
 *   (?:>>?|\btee\b(?:\s+-a)?)\s*(?:~|\$HOME|%USERPROFILE%)?[^\s|;&>]*
 *   \.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b      (flag i)
 * matches, in one pass. As a regex it restarted at every `tee` or `>` of a
 * long path and rescanned the path to its end: quadratic on "tee/tee/..."
 * (4.5 s for 40,000 characters, hours at the 5 MB file cap), which the
 * 6.3.0 pre-release review found after the earlier fix only covered ">>>...".
 * property-parsers.test.ts holds it to the reference expression.
 */
export function writesShellRc(text: string): boolean {
  let pending = false; // an operator precedes, separated only by whitespace
  let teeSpace = false; // that operator is `tee` + whitespace, so `-a` may follow
  const n = text.length;
  let i = 0;
  while (i < n) {
    const ch = text[i]!;
    if (WHITESPACE.test(ch)) { i++; continue; }
    if (ch === ">") { pending = true; teeSpace = false; i++; continue; }
    if (ch === "|" || ch === ";" || ch === "&") { pending = false; teeSpace = false; i++; continue; }

    // A run of path characters: the path can only lie inside one run.
    const start = i;
    let end = i;
    while (end < n && isPathChar(text[end]!)) end++;
    let armed = pending;
    for (let k = start; k < end; k++) {
      if (armed && text[k] === "." && rcFileAt(text, k)) return true;
      // A `tee` inside the run (`x/tee/.bashrc`, `tee.bashrc`) starts a path
      // right after it.
      if (!armed && k + 1 < end && teeEndsAt(text, k + 1)) armed = true;
    }
    const nextIsSpace = end < n && WHITESPACE.test(text[end]!);
    if (nextIsSpace && teeEndsAt(text, end)) {
      pending = true; teeSpace = true;
    } else if (nextIsSpace && teeSpace && end - start === 2 && text[start] === "-"
      && lowerCode(text.charCodeAt(start + 1)) === 97) {
      pending = true; teeSpace = false; // `tee -a <path>`
    } else {
      pending = false; teeSpace = false;
    }
    i = end;
  }
  return false;
}

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

  for (const target of collectRulesFiles(dir, findings)) {
    const options = {
      maxBytes: MAX_FILE_SIZE,
      onOversized: (size: number) =>
        findings.push(makeOversizedSkipFinding(target.relativePath, size)),
    };
    const content = target.discovered
      ? readDiscoveredUtf8File(
          dir,
          path.join(dir, target.relativePath),
          target.relativePath,
          findings,
          options,
        )
      : readOptionalUtf8File(
          dir,
          path.join(dir, target.relativePath),
          target.relativePath,
          findings,
          options,
        );
    if (content === null) continue;
    for (const pushed of scanSkillContent(content, target.relativePath)) findings.push(pushed);
  }

  for (const relPath of [".claude/settings.json", ".claude/settings.local.json"]) {
    const content = readOptionalUtf8File(
      dir,
      path.join(dir, relPath),
      relPath,
      findings,
      {
        maxBytes: MAX_FILE_SIZE,
        onOversized: (size) =>
          findings.push(makeOversizedSkipFinding(relPath, size)),
      },
    );
    if (content === null) continue;
    for (const pushed of scanAgentSettingsContent(content, relPath)) findings.push(pushed);
  }

  // .vscode/tasks.json. Read here rather than in the core walk so it goes
  // through the same dangerous-command battery as an agent hook: an editor task
  // and a lifecycle hook are the same capability, and until now only one of the
  // two was checked.
  for (const relPath of [".vscode/tasks.json"]) {
    const content = readOptionalUtf8File(
      dir,
      path.join(dir, relPath),
      relPath,
      findings,
      {
        maxBytes: MAX_FILE_SIZE,
        onOversized: (size) =>
          findings.push(makeOversizedSkipFinding(relPath, size)),
      },
    );
    if (content === null) continue;
    for (const pushed of scanEditorTasksContent(content, relPath)) findings.push(pushed);
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
    for (const pattern of TOKEN_INJECTION_PATTERNS) {
      const hits = matchPatternInSemanticText(
        pattern,
        line,
        relativePath,
        findings,
        "i",
      );
      const hit = hits?.[0];
      if (!hit) continue;

      findings.push({
        rule: "SKILL_PROMPT_INJECTION",
        description:
          `Agent rules file contains a raw LLM control token (${pattern.name}). ` +
          "Rules files are read verbatim by AI coding agents; embedded role/system " +
          "tokens hijack the agent's instruction context.",
        severity: "high",
        file: relativePath,
        line: i + 1,
        match: truncate(hit.text),
        confidence: 0.9,
        category: "supply-chain",
        recommendation:
          "Remove the control token. A skill or rules file never needs literal LLM role markers.",
      });
      break; // one token finding per line is enough
    }

    // 1b. Jailbreak-style override prose - reduced confidence, because these
    // files legitimately instruct agents in imperative natural language.
    if (OVERRIDE_PROSE_ENTRY) {
      const hits = matchPatternInSemanticText(
        OVERRIDE_PROSE_ENTRY,
        line,
        relativePath,
        findings,
        "i",
      );
      const hit = hits?.[0];
      if (hit) {
        findings.push({
          rule: "SKILL_PROMPT_INJECTION",
          description:
            "Agent rules file contains override/jailbreak phrasing ('ignore previous " +
            "instructions', ...). Reduced confidence: rules files legitimately instruct " +
            "agents, but overriding PRIOR instructions is a hijack pattern.",
          severity: "medium",
          file: relativePath,
          line: i + 1,
          match: truncate(hit.text.trim()),
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
    {
      const match = findDownloadExec(line);
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
          match: truncate(match.text),
          confidence: 0.8,
          category: "malware",
          recommendation:
            "Never pipe downloads into a shell from an agent instruction file. Pin and vendor the script instead.",
        });
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
 *
 * Parsed leniently (comments, trailing commas, BOM), like the editor files: a
 * lenient parse only ever ADDS what a strict one would see, while a strict one
 * turned a single trailing comma into "no hooks at all".
 */
export function scanAgentSettingsContent(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];

  const parsed = parseJsoncObject(content);
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
    if (findDownloadExec(command)) {
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

    // A hook whose command merely launches an already-dropped artefact carries
    // no independently dangerous token, so the battery above cannot see it.
    // That is the realistic ChainDrop shape and it was fully undetected: the
    // core walk excludes `.claude/`, so this content never reaches the pattern
    // table where the artefact literal lives.
    if (CHAINDROP_PERSISTENCE_ARTEFACT_REGEX.test(command)) {
      findings.push({
        rule: "CHAINDROP_GH_TOKEN_MONITOR_PERSISTENCE",
        description:
          "Agent settings hook launches a gh-token-monitor persistence artefact. " +
          "The ChainDrop / Shai-Hulud keyv wave drops that script and chains it from " +
          "an autostart hook so GitHub tokens are re-harvested on every session.",
        severity: "critical",
        file: relativePath,
        match: truncate(command),
        confidence: 0.9,
        category: "malware",
        recommendation:
          "Remove the hook and the dropped artefact, then rotate any GitHub tokens on this machine.",
      });
    }

    const dangerous =
      HOOK_EVAL_REGEX.test(command) ||
      HOOK_BASE64_REGEX.test(command) ||
      writesShellRc(command) ||
      findDownloadExec(command) !== null;
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

interface RulesFileTarget {
  relativePath: string;
  discovered: boolean;
}

/** Collect all prose rules files relative to the scan root. */
function collectRulesFiles(
  dir: string,
  findings: Finding[],
): RulesFileTarget[] {
  const files: RulesFileTarget[] = ROOT_RULES_FILES.map((relativePath) => ({
    relativePath,
    discovered: false,
  }));
  const recursiveWalkState: RecursiveWalkState = {
    expandedEntries: 0,
    budgetExhausted: false,
  };
  files.push({
    relativePath: ".github/copilot-instructions.md",
    discovered: false,
  });

  // .claude/commands/*.md (non-recursive)
  collectFlatFiles(
    dir,
    path.join(dir, ".claude", "commands"),
    ".claude/commands",
    ".md",
    files,
    findings,
  );

  // .cursor/rules/*.mdc (non-recursive)
  collectFlatFiles(
    dir,
    path.join(dir, ".cursor", "rules"),
    ".cursor/rules",
    ".mdc",
    files,
    findings,
  );

  // .claude/skills/**/SKILL.md (recursive)
  collectSkillManifests(
    dir,
    path.join(dir, ".claude", "skills"),
    ".claude/skills",
    files,
    findings,
    0,
    false,
    new Set(),
    recursiveWalkState,
  );

  // Agent memory directories. Agents read these verbatim, so they run through
  // the same scanSkillContent pipeline as CLAUDE.md / AGENTS.md.
  collectMemoryDir(dir, path.join(dir, "memory"), "memory", files, findings);
  collectFlatFiles(
    dir,
    path.join(dir, ".claude", "memory"),
    ".claude/memory",
    ".md",
    files,
    findings,
  );

  // .specstory/**/*.md (recursive; skips node_modules)
  collectMarkdownTree(
    dir,
    path.join(dir, ".specstory"),
    ".specstory",
    files,
    findings,
    0,
    false,
    new Set(),
    recursiveWalkState,
  );

  return files;
}

function collectFlatFiles(
  scanRoot: string,
  absDir: string,
  relDir: string,
  extension: string,
  out: RulesFileTarget[],
  findings: Finding[],
): void {
  const entries = listOptionalDirectory(scanRoot, absDir, relDir, findings);
  if (entries === null) return;
  for (const entry of entries) {
    if ((entry.isFile() || entry.isSymbolicLink()) && entry.name.toLowerCase().endsWith(extension)) {
      out.push({
        relativePath: `${relDir}/${entry.name}`,
        discovered: true,
      });
    }
  }
}

/** Collect memory/*.md plus one level of subdirectories. */
function collectMemoryDir(
  scanRoot: string,
  absDir: string,
  relDir: string,
  out: RulesFileTarget[],
  findings: Finding[],
): void {
  const entries = listOptionalDirectory(scanRoot, absDir, relDir, findings);
  if (entries === null) return;

  for (const entry of entries) {
    if ((entry.isFile() || entry.isSymbolicLink()) && entry.name.toLowerCase().endsWith(".md")) {
      out.push({
        relativePath: `${relDir}/${entry.name}`,
        discovered: true,
      });
    } else if (
      (entry.isDirectory() || entry.isSymbolicLink()) &&
      entry.name !== "node_modules"
    ) {
      const childRelDir = `${relDir}/${entry.name}`;
      const children = listDiscoveredDirectory(
        scanRoot,
        path.join(absDir, entry.name),
        childRelDir,
        findings,
      );
      if (children === null) continue;
      for (const child of children) {
        if ((child.isFile() || child.isSymbolicLink()) && child.name.toLowerCase().endsWith(".md")) {
          out.push({
            relativePath: `${childRelDir}/${child.name}`,
            discovered: true,
          });
        }
      }
    }
  }
}

/** Recursively collect *.md files under a directory, skipping node_modules/.git. */
function collectMarkdownTree(
  scanRoot: string,
  absDir: string,
  relDir: string,
  out: RulesFileTarget[],
  findings: Finding[],
  depth: number,
  discovered: boolean,
  ancestors: ReadonlySet<string>,
  state: RecursiveWalkState,
): void {
  if (state.budgetExhausted) return;
  if (depth > MAX_SKILL_DEPTH) {
    recordUnreadablePath(findings, relDir);
    return;
  }

  const directory = enterRecursiveDirectory(
    scanRoot,
    absDir,
    relDir,
    findings,
    discovered,
    ancestors,
  );
  if (directory === null) return;

  for (const entry of directory.entries) {
    if (!consumeRecursiveWalkEntry(state, findings)) break;
    if (
      entry.isDirectory() ||
      (entry.isSymbolicLink() && !entry.name.toLowerCase().endsWith(".md"))
    ) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      collectMarkdownTree(
        scanRoot,
        path.join(absDir, entry.name),
        `${relDir}/${entry.name}`,
        out,
        findings,
        depth + 1,
        true,
        directory.nextAncestors,
        state,
      );
    } else if ((entry.isFile() || entry.isSymbolicLink()) && entry.name.toLowerCase().endsWith(".md")) {
      out.push({
        relativePath: `${relDir}/${entry.name}`,
        discovered: true,
      });
    }
    if (state.budgetExhausted) break;
  }
}

/** Recursively find SKILL.md manifests under .claude/skills. */
function collectSkillManifests(
  scanRoot: string,
  absDir: string,
  relDir: string,
  out: RulesFileTarget[],
  findings: Finding[],
  depth: number,
  discovered: boolean,
  ancestors: ReadonlySet<string>,
  state: RecursiveWalkState,
): void {
  if (state.budgetExhausted) return;
  if (depth > MAX_SKILL_DEPTH) {
    recordUnreadablePath(findings, relDir);
    return;
  }

  const directory = enterRecursiveDirectory(
    scanRoot,
    absDir,
    relDir,
    findings,
    discovered,
    ancestors,
  );
  if (directory === null) return;

  for (const entry of directory.entries) {
    if (!consumeRecursiveWalkEntry(state, findings)) break;
    if (
      entry.isDirectory() ||
      (entry.isSymbolicLink() && entry.name.toUpperCase() !== "SKILL.MD")
    ) {
      collectSkillManifests(
        scanRoot,
        path.join(absDir, entry.name),
        `${relDir}/${entry.name}`,
        out,
        findings,
        depth + 1,
        true,
        directory.nextAncestors,
        state,
      );
    } else if ((entry.isFile() || entry.isSymbolicLink()) && entry.name.toUpperCase() === "SKILL.MD") {
      out.push({
        relativePath: `${relDir}/${entry.name}`,
        discovered: true,
      });
    }
    if (state.budgetExhausted) break;
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

/**
 * Collect the effective command lines from a VS Code tasks.json.
 *
 * A task's shell invocation is split across `command` and `args`, so the
 * dangerous part usually sits in an argument rather than the command:
 * `{"command": "bash", "args": ["-c", "curl ... | bash"]}`. Joining them back
 * into the line that actually executes is what makes the existing battery see
 * it. Platform overrides (`windows`/`linux`/`osx`) can carry their own
 * command/args and are collected as separate lines.
 *
 * Returns each line paired with whether that task runs automatically on folder
 * open, which is used only to escalate an already-dangerous finding, never to
 * produce one.
 */
function collectTaskCommandLines(
  parsed: unknown,
): { line: string; autoRun: boolean }[] {
  const out: { line: string; autoRun: boolean }[] = [];
  if (parsed === null || typeof parsed !== "object") return out;
  const tasks = (parsed as Record<string, unknown>).tasks;
  if (!Array.isArray(tasks)) return out;

  const renderArgs = (args: unknown): string[] => {
    if (!Array.isArray(args)) return [];
    return args.map((a) => {
      if (typeof a === "string") return a;
      // VS Code allows { value, quoting } argument objects.
      if (a !== null && typeof a === "object") {
        const v = (a as Record<string, unknown>).value;
        if (typeof v === "string") return v;
      }
      return "";
    });
  };

  for (const task of tasks) {
    if (task === null || typeof task !== "object") continue;
    const t = task as Record<string, unknown>;

    const runOptions = t.runOptions;
    const autoRun =
      runOptions !== null &&
      typeof runOptions === "object" &&
      (runOptions as Record<string, unknown>).runOn === "folderOpen";

    // A platform override is MERGED into the task by VS Code: its command or
    // args replace the base ones, the rest is inherited. Judging the override
    // on its own missed `command: "node"` in the base with the asset in
    // `windows.args`.
    const shapes: Record<string, unknown>[] = [t];
    for (const platform of ["windows", "linux", "osx"]) {
      const override = t[platform];
      if (override !== null && typeof override === "object") {
        shapes.push({ ...t, ...(override as Record<string, unknown>) });
      }
    }

    // `command` may also be an object: { value, quoting }.
    const renderCommand = (command: unknown): string => {
      if (typeof command === "string") return command;
      if (command !== null && typeof command === "object") {
        const v = (command as Record<string, unknown>).value;
        if (typeof v === "string") return v;
      }
      return "";
    };

    const seen = new Set<string>();
    for (const shape of shapes) {
      const command = renderCommand(shape.command);
      const args = renderArgs(shape.args);
      const line = [command, ...args].filter(Boolean).join(" ").trim();
      if (line && !seen.has(line)) {
        seen.add(line);
        out.push({ line, autoRun });
      }
    }
  }
  return out;
}

/** See ASSET_EXEC_PATTERN (patterns.ts): the one definition every carrier uses. */
const ASSET_EXEC_REGEX = new RegExp(ASSET_EXEC_PATTERN, "i");

/** The two auto-run command carriers judged here, and how each is worded. */
interface CommandCarrier {
  /** Rule prefix: EDITOR_TASK or DEVCONTAINER. */
  prefix: "EDITOR_TASK" | "DEVCONTAINER";
  /** Subject of every description sentence. */
  subject: string;
  /** Appended when the command runs with no developer action. */
  autoNote: string;
  /** Appended when it runs only when invoked. */
  manualNote: string;
  recommendation: string;
}

const EDITOR_TASK_CARRIER: CommandCarrier = {
  prefix: "EDITOR_TASK",
  subject: "Editor task",
  autoNote:
    " The task is configured with runOn folderOpen, so it executes automatically when the folder is opened, with no developer action.",
  manualNote: " The task runs when invoked.",
  recommendation:
    "Remove the task or its command. Editor tasks execute with the developer's full privileges.",
};

const DEVCONTAINER_CARRIER: CommandCarrier = {
  prefix: "DEVCONTAINER",
  subject: "Dev container lifecycle command",
  autoNote:
    " Lifecycle commands run automatically when the container is created, started or attached; initializeCommand runs on the HOST before the container exists.",
  manualNote: "",
  recommendation:
    "Do not open this repository in a dev container until the command is removed. Lifecycle commands run without a prompt, and initializeCommand runs on the host.",
};

/**
 * Judge one effective command line from an auto-run carrier. Deliberately the
 * command vocabulary that already guards agent hooks, plus the asset-exec
 * disguise, so a tasks.json and a devcontainer.json are held to one standard.
 * `autoRun` only ESCALATES a command already judged dangerous.
 */
function commandLineFinding(
  line: string,
  autoRun: boolean,
  relativePath: string,
  carrier: CommandCarrier,
): Finding | null {
  const note = autoRun ? carrier.autoNote : carrier.manualNote;
  const severity = autoRun ? "critical" : "high";

  if (ASSET_EXEC_REGEX.test(line)) {
    return {
      rule: `${carrier.prefix}_EXECUTES_ASSET`,
      description:
        `${carrier.subject} runs an interpreter on a file named as a font, image or media asset, the disguise used by the Contagious Interview "Fake Font" loader.` +
        note,
      severity,
      file: relativePath,
      match: truncate(line),
      confidence: 0.95,
      category: "malware",
      recommendation:
        `${carrier.recommendation} Inspect the referenced file: an asset that an interpreter executes is code.`,
    };
  }

  const downloadExec = findDownloadExec(line) !== null;
  const dangerous =
    downloadExec ||
    HOOK_EVAL_REGEX.test(line) ||
    HOOK_BASE64_REGEX.test(line) ||
    writesShellRc(line);
  if (!dangerous) return null;

  return {
    rule: downloadExec
      ? `${carrier.prefix}_DOWNLOAD_EXEC`
      : `${carrier.prefix}_DANGEROUS_COMMAND`,
    description:
      (downloadExec
        ? `${carrier.subject} downloads and executes remote code.`
        : `${carrier.subject} contains a dangerous command (eval, base64 decode, download-exec pipe, or shell rc file modification).`) +
      note,
    severity,
    file: relativePath,
    match: truncate(line),
    confidence: 0.9,
    category: "malware",
    recommendation: carrier.recommendation,
  };
}

/** Parse a VS Code-family file the way VS Code does: JSONC, optional BOM. */
function parseJsoncObject(content: string): unknown {
  try {
    return JSON.parse(stripJsonc(content.replace(/^\uFEFF/, "")));
  } catch {
    return undefined;
  }
}

/**
 * Scan a .vscode/tasks.json for dangerous task commands.
 *
 * Deliberately reuses the command vocabulary that already guards agent hooks
 * rather than inventing a heuristic: the identical `curl | bash` string
 * produced two criticals inside .claude/settings.json and nothing at all inside
 * .vscode/tasks.json, with the file confirmed read. That was a recall gap in a
 * file the scanner already opens, not a question of scope.
 *
 * `runOn: folderOpen` only ESCALATES a command already judged dangerous. On its
 * own it is an ordinary and widely used VS Code feature, so it never produces a
 * finding here. Malformed JSON is ignored (no crash, no findings).
 *
 * VS Code reads tasks.json as JSONC, so comments and trailing commas are
 * stripped first. Strict JSON.parse threw on the one trailing comma the real
 * Fake Font loader carries, and every task rule then saw nothing.
 */
export function scanEditorTasksContent(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  for (const { line, autoRun } of collectTaskCommandLines(parseJsoncObject(content))) {
    const finding = commandLineFinding(line, autoRun, relativePath, EDITOR_TASK_CARRIER);
    if (finding) findings.push(finding);
  }
  return findings;
}

/** True for a VS Code multi-root workspace file, at any depth. */
export function isCodeWorkspaceFile(relativePath: string): boolean {
  return relativePath.toLowerCase().endsWith(".code-workspace");
}

/**
 * Scan a *.code-workspace file. Its `tasks` block is a tasks.json document
 * ({ version, tasks: [...] }) and auto-runs on folderOpen exactly like
 * .vscode/tasks.json when the workspace is opened.
 */
export function scanCodeWorkspaceContent(
  content: string,
  relativePath: string,
): Finding[] {
  const doc = parseJsoncObject(content);
  if (doc === null || typeof doc !== "object") return [];
  const findings: Finding[] = [];
  for (const { line, autoRun } of collectTaskCommandLines((doc as Record<string, unknown>).tasks)) {
    const finding = commandLineFinding(line, autoRun, relativePath, EDITOR_TASK_CARRIER);
    if (finding) findings.push(finding);
  }
  return findings;
}

/** devcontainer.json lifecycle keys; every one runs without a prompt. */
const DEVCONTAINER_LIFECYCLE_KEYS = [
  "initializeCommand",
  "onCreateCommand",
  "updateContentCommand",
  "postCreateCommand",
  "postStartCommand",
  "postAttachCommand",
] as const;

/**
 * The effective command lines of a devcontainer.json. A lifecycle command is a
 * string (shell form), an array (exec form, joined back into the line that
 * runs) or an object of named commands run in parallel, each itself a string
 * or an array.
 */
function collectDevcontainerCommandLines(parsed: unknown): string[] {
  if (parsed === null || typeof parsed !== "object") return [];
  const doc = parsed as Record<string, unknown>;
  const lines: string[] = [];
  const render = (value: unknown): void => {
    if (typeof value === "string") {
      if (value.trim()) lines.push(value.trim());
    } else if (Array.isArray(value)) {
      const line = value.filter((a): a is string => typeof a === "string").join(" ").trim();
      if (line) lines.push(line);
    }
  };
  for (const key of DEVCONTAINER_LIFECYCLE_KEYS) {
    const value = doc[key];
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      for (const named of Object.values(value as Record<string, unknown>)) render(named);
    } else {
      render(value);
    }
  }
  return lines;
}

/** True for a dev container definition, at any depth. */
export function isDevcontainerFile(relativePath: string): boolean {
  const base = relativePath.split("/").pop() ?? "";
  return base === "devcontainer.json" || base === ".devcontainer.json";
}

/**
 * Scan a devcontainer.json's lifecycle commands with the editor-task battery.
 * They are the same capability as a folderOpen task, reached through "Reopen
 * in Container" or a Codespace instead, so every one is treated as auto-run.
 */
export function scanDevcontainerCommandsContent(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  for (const line of collectDevcontainerCommandLines(parseJsoncObject(content))) {
    const finding = commandLineFinding(line, true, relativePath, DEVCONTAINER_CARRIER);
    if (finding) findings.push(finding);
  }
  return findings;
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

interface RecursiveWalkState {
  expandedEntries: number;
  budgetExhausted: boolean;
}

interface RecursiveDirectory {
  entries: fs.Dirent[];
  nextAncestors: ReadonlySet<string>;
}

function consumeRecursiveWalkEntry(
  state: RecursiveWalkState,
  findings: Finding[],
): boolean {
  if (state.budgetExhausted) return false;
  if (state.expandedEntries >= MAX_SKILL_WALK_ENTRIES) {
    state.budgetExhausted = true;
    // The limit applies to both recursive trees. Report global incomplete
    // coverage because the first unexpanded public path is not necessarily the
    // only path omitted after the shared budget is exhausted.
    recordUnreadablePath(findings, ".");
    return false;
  }
  state.expandedEntries++;
  return true;
}

function enterRecursiveDirectory(
  scanRoot: string,
  absDir: string,
  relDir: string,
  findings: Finding[],
  discovered: boolean,
  ancestors: ReadonlySet<string>,
): RecursiveDirectory | null {
  let canonicalDir: string;
  let entries: fs.Dirent[] | null;

  if (discovered) {
    // Check the canonical target before enumerating a discovered alias. This
    // stops a symlink back-edge without repeatedly listing the ancestor.
    try {
      canonicalDir = fs.realpathSync(absDir);
    } catch {
      recordUnreadablePath(findings, relDir);
      return null;
    }
    if (ancestors.has(canonicalDir)) {
      recordUnreadablePath(findings, relDir);
      return null;
    }
    entries = listDiscoveredDirectory(scanRoot, absDir, relDir, findings);
  } else {
    // A statically known root is optional. Let the containment helper
    // distinguish ordinary absence from an unreadable or escaping path before
    // canonicalizing it.
    entries = listOptionalDirectory(scanRoot, absDir, relDir, findings);
    if (entries === null) return null;
    try {
      canonicalDir = fs.realpathSync(absDir);
    } catch {
      recordUnreadablePath(findings, relDir);
      return null;
    }
    if (ancestors.has(canonicalDir)) {
      recordUnreadablePath(findings, relDir);
      return null;
    }
  }
  if (entries === null) return null;

  const nextAncestors = new Set(ancestors);
  nextAncestors.add(canonicalDir);
  return { entries, nextAncestors };
}
