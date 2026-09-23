/**
 * Workflow execution modeler (v4.7).
 *
 * Models GitHub Actions workflows as executable chains, tracking
 * secret access, action usage, and data flow paths.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import {
  parseWorkflow,
  classifyWorkflowLines,
  stripYamlComments,
  type WfRegion,
  type WfStep,
  type WfJob,
  type WorkflowAst,
} from "./workflow-ast.js";

/**
 * Commands that move data off the runner. `fetch` counts only as a call, so
 * `git fetch`, `fetch-depth:` and words such as `prefetched` do not.
 */
const NET_CMD_RE = /(?<![\w.-])(?:curl|wget|nc|ncat|netcat)(?![\w-])/;
const FETCH_CALL_RE = /(?<![\w$])fetch\s*\(\s*(?:(['"`])([^'"`\n]*)\1)?/g;

/**
 * Other ways a step sends data out, counted as egress without looking for a
 * loopback target: HTTP clients in Node, Python and PowerShell, and file transfer
 * tools that always reach another host. `scp`/`rsync` count only with a
 * `host:path` argument (see isRemoteCopy), `ssh` only with a destination that
 * is not loopback (see isSshEgress). `gh api` is left out on purpose:
 * a token sent to GitHub's own API is that token's intended audience.
 */
const OTHER_EGRESS_RE =
  /(?<![\w.-])(?:sftp|ftp|socat|telnet|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Send-MailMessage)(?![\w./-])|\b(?:requests|httpx)\s*\.\s*(?:get|post|put|patch|request)\s*\(|\burllib\.request\b|\bNet\.WebClient\b|\brequire[^\S\n]*\([^\S\n]*['"](?:node:)?https?['"][^\S\n]*\)[^\S\n]*\.[^\S\n]*(?:request|get)\b|\bhttps?[^\S\n]*\.[^\S\n]*(?:request|get)[^\S\n]*\(|\baxios[^\S\n]*\.[^\S\n]*(?:post|put|patch|get|request)[^\S\n]*\(|\brequests[^\S\n]*\.[^\S\n]*Session[^\S\n]*\(|\bhttp\.client\b|\burllib3\b|\b(?:github|octokit)[^\S\n]*\.[^\S\n]*request[^\S\n]*\([^\S\n]*['"`](?:[A-Z]+[^\S\n]+)?https?:\/\/(?!api\.github\.com)/i;

/** The `ssh` command word (not `ssh-keygen`, `ssh-add`, `ssh-keyscan`, or a directory `ssh/`). */
const SSH_CMD_RE = /(?<![\w.-])ssh(?![\w./-])/;

/** ssh options that take a value, so the value is not the destination. */
const SSH_VALUE_FLAGS = new Set([
  "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
]);

/** `ssh` to a destination that is not loopback. */
function isSshEgress(segment: string): boolean {
  const cmd = SSH_CMD_RE.exec(segment);
  if (!cmd) return false;
  const words = shellWords(segment.slice(cmd.index + cmd[0].length));
  for (let i = 0; i < words.length; i++) {
    const word = words[i]!;
    if (SSH_VALUE_FLAGS.has(word)) {
      i++;
      continue;
    }
    if (word.startsWith("-")) continue;
    // The first other word is the destination.
    return !isLoopbackTarget(word.replace(/^[^@]*@/, ""));
  }
  return false;
}

/** The `scp`/`rsync` command word; its arguments are read by isRemoteCopy. */
const REMOTE_COPY_CMD_RE = /(?<![\w.-])(?:scp|rsync)(?![\w./-])/;

/**
 * One whole shell word naming a remote path, `[user@]host:path`. Anchored and
 * tested word by word, so its cost is linear in the segment.
 */
const REMOTE_PATH_WORD_RE = /^([\w.-]+@)?([\w-]+(?:\.[\w-]+)*):(?!\/\/)/;

/** Longest word read as a possible remote path. */
const MAX_REMOTE_WORD = 1024;

/**
 * `scp`/`rsync` with a remote argument. A bare one-letter host is a Windows
 * drive (`C:\out`), and options are skipped (`--exclude=a:b`).
 */
function isRemoteCopy(segment: string): boolean {
  const cmd = REMOTE_COPY_CMD_RE.exec(segment);
  if (!cmd) return false;
  for (const word of shellWords(segment.slice(cmd.index + cmd[0].length))) {
    if (word.length > MAX_REMOTE_WORD || word.startsWith("-")) continue;
    const m = REMOTE_PATH_WORD_RE.exec(word);
    if (m && (m[1] !== undefined || m[2]!.length > 1)) return true;
  }
  return false;
}

/**
 * `git push` to a remote that is not GitHub (a URL or `user@host:path`):
 * committed files leave the runner. `origin` and GitHub remotes are the
 * token's own audience.
 */
function isGitPushEgress(segment: string): boolean {
  const m = /(?<![\w.-])git[^\S\n]+push\b/.exec(segment);
  if (!m) return false;
  for (const word of shellWords(segment.slice(m.index + m[0].length))) {
    const url = /^(?:https?|ssh|git):\/\/(?:[^@/\s]*@)?([^/:\s]+)/.exec(word);
    const scp = /^[\w.-]+@([\w.-]+):/.exec(word);
    const host = (url?.[1] ?? scp?.[1] ?? "").toLowerCase();
    if (host !== "" && host !== "github.com" && !host.endsWith(".github.com")) return true;
  }
  return false;
}

/**
 * A command word with shell quoting inside it (`c''url`, `c"u"rl`, `c\url`)
 * reads as the plain word, so quoting cannot hide the tool.
 */
function unquoteWords(segment: string): string {
  return segment
    .replace(/(?<=[\w-])(?:''|"")|(?:''|"")(?=[\w-])/g, "")
    .replace(/(?<=[\w-])(["'])([\w-]{1,32})\1(?=[\w-]|\s|$)/g, "$2")
    .replace(/(?<=[\w-]|^|\s)\\(?=[A-Za-z])/g, "");
}

/**
 * Options whose next argument is a payload, header or local file rather than
 * the destination. Options that redirect traffic (--resolve, --proxy, --url,
 * --connect-to) are deliberately absent, so their value is checked as a target.
 */
const VALUE_FLAGS = new Set([
  "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json",
  "-H", "--header", "-u", "--user", "-F", "--form", "--form-string", "-o", "--output",
  "-X", "--request", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c",
  "--cookie-jar", "-T", "--upload-file", "-w", "--write-out", "-m", "--max-time",
  "--connect-timeout", "--retry", "--retry-delay", "--retry-max-time", "--cacert",
  "--cert", "--key", "-r", "--range", "-D", "--dump-header",
  "-O", "--output-document", "--post-data", "--body-data", "--post-file", "--body-file",
  "-U", "--password", "--http-user", "--http-password", "--output-file", "-P",
  "--directory-prefix", "-t", "--tries", "--timeout", "--method",
]);

/**
 * A loopback target: scheme optional, numeric port only, and no `@` anywhere
 * after the host, because `http://localhost@host.example/` connects to the
 * host after the `@`.
 */
const LOOPBACK_TARGET_RE =
  /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1|0\.0\.0\.0)(?::\d{1,5})?(?:[/?#][^@]*)?$/i;

function isLoopbackTarget(value: string): boolean {
  return LOOPBACK_TARGET_RE.test(value);
}

/** Split a shell segment into words, honouring quotes. Linear in its length. */
function shellWords(text: string): string[] {
  const words: string[] = [];
  let cur = "";
  let quote = "";
  let inWord = false;
  for (const ch of text) {
    if (quote) {
      if (ch === quote) quote = "";
      else cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      inWord = true;
    } else if (ch === " " || ch === "\t") {
      if (inWord) words.push(cur);
      cur = "";
      inWord = false;
    } else {
      cur += ch;
      inWord = true;
    }
  }
  if (inWord) words.push(cur);
  return words;
}

/**
 * True when every destination argument of a curl/wget/nc invocation is a
 * loopback address (bare port numbers allowed for nc). No destination at all,
 * or any other destination, counts as egress.
 */
function argsAreLoopbackOnly(args: string): boolean {
  let skipNext = false;
  let destinations = 0;
  for (const raw of shellWords(args)) {
    const word = raw.replace(/^[()]+|[()]+$/g, "");
    if (skipNext) { skipNext = false; continue; }
    if (word === "") continue;
    if (/^\d*[<>]/.test(word)) {
      // Redirection: `>` alone takes the next word as its file.
      if (/^\d*[<>]+&?$/.test(word)) skipNext = true;
      continue;
    }
    if (word.startsWith("-") && word.length > 1) {
      const eq = word.indexOf("=");
      if (eq < 0) {
        if (VALUE_FLAGS.has(word)) skipNext = true;
        continue;
      }
      if (VALUE_FLAGS.has(word.slice(0, eq))) continue;
      const value = word.slice(eq + 1);
      if (!/^\d+$/.test(value) && !isLoopbackTarget(value)) return false;
      continue;
    }
    if (/^\d+$/.test(word)) continue;
    if (!isLoopbackTarget(word)) return false;
    destinations++;
  }
  return destinations > 0;
}

function segmentHasEgress(raw: string): boolean {
  const segment = unquoteWords(raw);
  if (isGitPushEgress(segment)) return true;
  for (const m of segment.matchAll(FETCH_CALL_RE)) {
    if (m[2] === undefined || !isLoopbackTarget(m[2])) return true;
  }
  if (OTHER_EGRESS_RE.test(segment) || isRemoteCopy(segment) || isSshEgress(segment)) return true;
  const cmd = NET_CMD_RE.exec(segment);
  if (!cmd) return false;
  return !argsAreLoopbackOnly(segment.slice(cmd.index + cmd[0].length));
}

/** Does executed text (a run: or script: body, comments removed) send data out? */
function execTextHasEgress(text: string): boolean {
  const joined = text.replace(/\\\n/g, " ");
  for (const segment of joined.split(/&&|\|\||[;&|\n]/)) {
    if (segmentHasEgress(segment)) return true;
  }
  return false;
}

/**
 * Every form of the secrets context: `secrets.NAME`, `secrets['NAME']`,
 * `secrets["NAME"]`, a computed index, or the whole context (`toJSON(secrets)`,
 * `${{ secrets }}`). Group 1-3 hold a literal name when there is one.
 */
const SECRETS_CONTEXT_RE =
  /(?<![\w.-])secrets(?![\w-])\s*(?:\.\s*([\w-]+)|\[\s*(?:'([^'\n]*)'|"([^"\n]*)")\s*\])?/gi;

/**
 * A secret only tested for presence: compared with an empty string, null or a
 * boolean, or negated (`secrets.X != ''`, `!secrets.X`). The value never
 * leaves the expression.
 */
const SECRET_REF_SOURCE = String.raw`secrets\s*(?:\.\s*[\w-]+|\[\s*(?:'[^'\n]*'|"[^"\n]*")\s*\])`;
const SECRET_PRESENCE_RE = new RegExp(
  String.raw`${SECRET_REF_SOURCE}\s*(?:==|!=)\s*(?:''|""|null|true|false)(?![\w'"])|(?:''|""|null)\s*(?:==|!=)\s*${SECRET_REF_SOURCE}|!{1,2}\s*${SECRET_REF_SOURCE}`,
  "gi",
);

/** The run's own token: `github.token` or `github['token']`. */
const GITHUB_TOKEN_CONTEXT_RE =
  /(?<![\w.-])github\s*(?:\.\s*token|\[\s*(?:'token'|"token")\s*\])(?![\w-])/i;

/**
 * GITHUB_TOKEN is minted per run and governed by `permissions:`, so it is
 * ambient whichever way it is written. Any other name, a computed index or
 * the whole context can reach a stored secret. With `ambientCounts`, the run
 * token counts too: sending it out is itself the danger for exfiltration rules.
 */
function expressionUsesSecret(raw: string, ambientCounts: boolean): boolean {
  const expr = raw.replace(SECRET_PRESENCE_RE, " ");
  if (ambientCounts && GITHUB_TOKEN_CONTEXT_RE.test(expr)) return true;
  for (const m of expr.matchAll(SECRETS_CONTEXT_RE)) {
    if (ambientCounts) return true;
    const name = m[1] ?? m[2] ?? m[3];
    if (name === undefined || name.toUpperCase() !== "GITHUB_TOKEN") return true;
  }
  return false;
}

/**
 * Does any `${{ ... }}` expression in `text` reference a secret, in every
 * expression form of a secret reference? `ambientCounts` decides whether the
 * run's own GITHUB_TOKEN counts. Expressions are found with indexOf so an
 * unclosed one stays linear.
 */
export function textHasSecretReference(text: string, ambientCounts: boolean): boolean {
  let from = 0;
  for (;;) {
    const open = text.indexOf("${{", from);
    if (open < 0) return false;
    const close = text.indexOf("}}", open + 3);
    if (close < 0) return false;
    if (expressionUsesSecret(text.slice(open + 3, close), ambientCounts)) return true;
    from = close + 2;
  }
}

function textHasStoredSecret(text: string): boolean {
  return textHasSecretReference(text, false);
}

function indentOf(line: string): number {
  let n = 0;
  while (n < line.length && line[n] === " ") n++;
  return n;
}

/** Index one past the block that starts at `start` (first dedent to <= its indent). */
function blockEnd(stripped: string[], start: number, limit: number): number {
  const indent = indentOf(stripped[start] ?? "");
  let k = start + 1;
  while (k < limit && (stripped[k]!.trim() === "" || indentOf(stripped[k]!) > indent)) k++;
  return k;
}

function linesText(stripped: string[], regions: WfRegion[], from: number, to: number, want: WfRegion[]): string {
  const out: string[] = [];
  for (let k = from; k < to; k++) if (want.includes(regions[k]!)) out.push(stripped[k]!);
  return out.join("\n");
}


export interface StepScope {
  step: WfStep;
  /** 0-based line range of the step: [s, e) */
  s: number;
  e: number;
  /** the step's `env:` lines, block or inline flow map, comments removed */
  env: string;
}

export interface JobScope {
  job: WfJob;
  /** the job's `env:` and `container:` env lines (a service container's env is excluded) */
  env: string;
  /** the job's `secrets:` block, for a reusable-workflow call */
  reusableSecrets: string;
  /** the job's `strategy:` block, whose matrix values reach the steps as `matrix.*` */
  strategy: string;
  steps: StepScope[];
}

export interface WorkflowScopes {
  ast: WorkflowAst;
  /** comment-stripped lines, same count as the input */
  stripped: string[];
  regions: WfRegion[];
  /** the workflow-level `env:` lines */
  workflowEnv: string;
  jobs: JobScope[];
}

/**
 * The env text in scope at each level of a workflow, read from line regions
 * rather than from the AST's env maps, which hold block maps only and so miss
 * an inline flow map such as `env: { T: "..." }`. One pass per job and one
 * per step over disjoint line ranges, so the whole walk is linear.
 */
export function workflowScopes(content: string): WorkflowScopes {
  const text = content.replace(/\r/g, "");
  const stripped = stripYamlComments(text).split("\n");
  const regions = classifyWorkflowLines(text);
  const ast = parseWorkflow(text);

  const inJob = new Array<boolean>(stripped.length).fill(false);
  const jobRanges = ast.jobs.map((job) => {
    const start = job.line - 1;
    const end = blockEnd(stripped, start, stripped.length);
    for (let k = start; k < end; k++) inJob[k] = true;
    return { start, end };
  });

  const workflowEnv: string[] = [];
  for (let k = 0; k < stripped.length; k++) {
    if (!inJob[k] && regions[k] === "env") workflowEnv.push(stripped[k]!);
  }

  const jobs = ast.jobs.map((job, j): JobScope => {
    const { start, end } = jobRanges[j]!;
    const steps = job.steps.map((step): StepScope => {
      const s = step.line - 1;
      const e = blockEnd(stripped, s, end);
      return { step, s, e, env: linesText(stripped, regions, s, e, ["env"]) };
    });
    const inStep = new Array<boolean>(end - start).fill(false);
    for (const { s, e } of steps) for (let k = s; k < e; k++) inStep[k - start] = true;

    // Job-level keys: only `env:` and `container:` reach the steps. A service
    // container's env belongs to another container.
    let childIndent = -1;
    let topKey = "";
    const env: string[] = [];
    const reusableSecrets: string[] = [];
    const strategy: string[] = [];
    for (let k = start + 1; k < end; k++) {
      const line = stripped[k]!;
      if (inStep[k - start] || line.trim() === "") continue;
      const indent = indentOf(line);
      if (childIndent < 0) childIndent = indent;
      if (indent === childIndent) topKey = /^\s*['"]?([\w-]+)['"]?\s*:/.exec(line)?.[1] ?? "";
      if ((topKey === "env" || topKey === "container") && regions[k] === "env") env.push(line);
      if (topKey === "secrets") reusableSecrets.push(line);
      if (topKey === "strategy") strategy.push(line);
    }
    return { job, env: env.join("\n"), reusableSecrets: reusableSecrets.join("\n"), strategy: strategy.join("\n"), steps };
  });

  return { ast, stripped, regions, workflowEnv: workflowEnv.join("\n"), jobs };
}

/**
 * WORKFLOW_SECRET_TO_UPLOAD_PATH, a whole-file check: a stored secret (not
 * the run's own token, and not one only tested for presence) and, in the same
 * workflow, an outbound call in executed text (`run:`, `script:`; comments
 * removed, loopback calls left out) or an artifact upload. Which step holds
 * the secret is not modelled, so a secret in one step and a health check in
 * another are reported together; the finding asks for a review, not a verdict.
 * With `regions` false the whole text counts as executed: the fallback for a
 * file whose lines could not be classified.
 */
function checkSecretToEgress(content: string, file: string, relPath: string, regions = true): Finding[] {
  const text = content.replace(/\r/g, "");
  const stripped = stripYamlComments(text).split("\n");
  const exec = regions
    ? linesText(stripped, classifyWorkflowLines(text), 0, stripped.length, ["exec"])
    : stripped.join("\n");
  const uploads = stripped.some((l) => /^\s*-?\s*uses:\s*['"]?actions\/upload-artifact(?:@|['"\s]|$)/i.test(l));
  if (!textHasStoredSecret(stripped.join("\n")) || !(uploads || execTextHasEgress(exec))) return [];
  return [{
    rule: "WORKFLOW_SECRET_TO_UPLOAD_PATH",
    description: `Workflow "${file}": a stored secret and an outbound call or artifact upload appear in the same workflow. Verify secrets are not sent to external endpoints.`,
    severity: "medium",
    file: relPath,
    line: 1,
    confidence: 0.6,
    category: "supply-chain",
    recommendation:
      "Scope the secret to the step that needs it, and keep outbound calls and artifact uploads in steps without stored secrets.",
  }];
}

/**
 * Model workflows in a directory and find risky execution paths.
 */
export function modelWorkflows(dir: string): Finding[] {
  const findings: Finding[] = [];
  const workflowDir = path.join(dir, ".github", "workflows");

  if (!fs.existsSync(workflowDir)) return findings;

  let files: string[];
  try {
    files = fs.readdirSync(workflowDir).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"));
  } catch {
    return findings;
  }

  // One file that cannot be read or modelled must not end the loop: every
  // later workflow would go unscanned, and a decoy file could arrange that.
  for (const file of files) {
    const relPath = `.github/workflows/${file}`;
    let content: string;
    try {
      content = fs.readFileSync(path.join(workflowDir, file), "utf-8");
    } catch {
      continue;
    }
    try {
      for (const f of checkSecretToEgress(content, file, relPath)) findings.push(f);
    } catch {
      for (const f of checkSecretToEgress(content, file, relPath, false)) findings.push(f);
    }
    {

      // Check for untrusted actions in release paths.
      // v5.2.23: the unpinned-action check is scoped to actual `uses:`
      // declarations. The earlier regex `/@(?:main|master|latest|dev)\b/`
      // matched any occurrence anywhere in the file - including
      // `npm install -g npm@latest`, which is a Node toolchain install
      // step, not a GitHub Action reference. New regex requires the
      // `uses: <path>@<branch>` form.
      const isReleasePath = /release|publish|deploy|npm.*publish/.test(content);
      const hasUnpinnedAction = /^\s*-?\s*uses:\s+\S+@(?:main|master|latest|dev)\b/im.test(content);

      if (isReleasePath && hasUnpinnedAction) {
        findings.push({
          rule: "WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH",
          description: `Workflow "${file}" is a release/publish pipeline with unpinned actions. Supply-chain risk.`,
          severity: "critical",
          file: relPath,
          confidence: 0.8,
          category: "supply-chain",
          recommendation: "Pin all actions in release workflows to commit SHAs. Release pipelines are high-value targets.",
        });
      }
    }
  }

  return findings;
}
