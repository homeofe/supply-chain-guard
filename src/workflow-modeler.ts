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

/** Largest composite action.yml read when following a local `uses: ./...`. */
const MAX_ACTION_BYTES = 5 * 1024 * 1024;

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
  /(?<![\w.-])(?:sftp|ftp|socat|telnet|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Send-MailMessage)(?![\w./-])|\b(?:requests|httpx)\s*\.\s*(?:get|post|put|patch|request)\s*\(|\burllib\.request\b|\bNet\.WebClient\b|\brequire[^\S\n]*\([^\S\n]*['"](?:node:)?https?['"][^\S\n]*\)[^\S\n]*\.[^\S\n]*(?:request|get)\b|\bhttps?[^\S\n]*\.[^\S\n]*(?:request|get)[^\S\n]*\(|\baxios[^\S\n]*\.[^\S\n]*(?:post|put|patch|get|request)[^\S\n]*\(/i;

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
 * A step that hands what it holds to the later steps of its job through their
 * environment: `$GITHUB_ENV`/`$GITHUB_OUTPUT`, or github-script's
 * `core.exportVariable` / `core.setOutput`.
 */
const PERSISTS_ENV_RE = /GITHUB_(?:ENV|OUTPUT)\b|\bcore\s*\.\s*(?:exportVariable|setOutput)\s*\(/;

/**
 * Where a redirection in one shell word writes to: `>f`, `x>f`, `1>>f`, `>|f`, or
 * `>` with the file as the next word (`""`). `2>`, `>&2`, `=>` and `->` are
 * not file writes of the step's output. `undefined` when the word has none.
 */
function redirectTarget(word: string): string | undefined {
  const at = word.indexOf(">");
  if (at < 0) return undefined;
  const before = word.slice(0, at);
  if (/[=<>-]$/.test(before)) return undefined;
  const fd = /\d*$/.exec(before)![0];
  if (fd !== "" && fd !== "1") return undefined;
  const rest = word.slice(at + (word[at + 1] === ">" || word[at + 1] === "|" ? 2 : 1));
  if (rest.startsWith("&") || rest.startsWith(">")) return undefined;
  return rest;
}

/**
 * Files a step writes: redirection targets, `tee` arguments, PowerShell
 * `Out-File`/`Set-Content`/`Add-Content`, Node `writeFile`/`appendFile` and
 * Python `open(..., "w"|"a"|"x"|"+")`. A target this reader cannot name (a
 * variable, a glob, a computed path) is `null`, unless only its directory is
 * computed, then it is its file name. The runner's own files and
 * devices are left out: `$GITHUB_ENV`/`$GITHUB_OUTPUT` are PERSISTS_ENV_RE's,
 * and the step summary is not readable by later steps.
 */
function fileTargets(exec: string): Array<string | null> {
  const out: Array<string | null> = [];
  const joined = exec.replace(/\\\n/g, " ");
  for (const segment of joined.split(/&&|\|\||[;\n]|(?<!>)\|/)) {
    const words = shellWords(segment);
    for (let i = 0; i < words.length; i++) {
      const word = words[i]!;
      const target = redirectTarget(word);
      if (target !== undefined) {
        const file = target !== "" ? target : words[++i];
        if (file !== undefined) out.push(file);
        continue;
      }
      const tool = word.slice(Math.max(word.lastIndexOf("/"), word.lastIndexOf("\\")) + 1);
      if (tool === "tee") {
        for (let j = i + 1; j < words.length; j++) if (!words[j]!.startsWith("-")) out.push(words[j]!);
        break;
      }
      if (/^(?:Out-File|Set-Content|Add-Content)$/i.test(tool)) {
        for (let j = i + 1; j < words.length; j++) {
          const arg = words[j]!;
          if (/^-(?:FilePath|Path|LiteralPath)$/i.test(arg)) {
            if (words[j + 1] !== undefined) out.push(words[j + 1]!);
            break;
          }
          if (!arg.startsWith("-")) {
            out.push(arg);
            break;
          }
        }
      }
    }
  }
  for (const m of joined.matchAll(/\b(?:writeFile|appendFile)(?:Sync)?[^\S\n]*\([^\S\n]*(?:(['"`])([^'"`\n]{0,512})\1)?/g)) {
    out.push(m[2] ?? null);
  }
  for (const m of joined.matchAll(/\bopen[^\S\n]*\([^\S\n]*(?:(['"])([^'"\n]{0,512})\1|[\w.[\]]{1,128})[^\S\n]*,[^\S\n]*(?:mode[^\S\n]*=[^\S\n]*)?['"]([^'"\n]{0,8})['"]/g)) {
    if (/[wax+]/.test(m[3]!)) out.push(m[2] ?? null);
  }
  return out
    .filter((t) => t === null || !/GITHUB_(?:ENV|OUTPUT|PATH|STEP_SUMMARY)|^\/dev\//.test(t))
    .map((t) => {
      if (t === null || t.trim() === "") return null;
      if (!/[$`*?{}]/.test(t)) return t;
      // `$RUNNER_TEMP/ssh/deploy_key`: the directory is unknown, the name is not.
      const name = t.slice(Math.max(t.lastIndexOf("/"), t.lastIndexOf("\\")) + 1);
      return name !== "" && !/[$`*?{}]/.test(name) ? name : null;
    });
}

/** Most file paths followed per job; past this, any later file read counts. */
const MAX_TAINTED_FILES = 256;

/**
 * Most distinct globs matched per job. Each is compiled and tested against
 * every tainted path, so a flood of distinct globs would be quadratic; past
 * this, a glob counts as covering a tainted file (fail closed).
 */
const MAX_GLOB_EVALUATIONS = 256;

/**
 * Files written after a secret reached them, by full path. A later step reaches
 * one by naming its basename in code (`open('key.txt')`, `$(base64 key.txt)`),
 * or by a shell word naming the file, a directory above it, or a glob that
 * matches it (`tar czf a.tgz dist`, `curl -T "*.txt"`, `zip -r a.zip .`).
 */
class TaintedFiles {
  readonly paths = new Set<string>();
  readonly basenames = new Set<string>();
  readonly dirs = new Set<string>();
  private readonly globAnswers = new Map<string, boolean>();
  private globEvaluations = 0;

  get size(): number {
    return this.paths.size;
  }

  add(target: string): void {
    const path = normalizePath(target);
    if (path === "" || path === ".") return;
    this.paths.add(path);
    this.globAnswers.clear();
    const parts = path.split("/");
    this.basenames.add(parts[parts.length - 1]!);
    for (let i = 1; i < parts.length; i++) this.dirs.add(parts.slice(0, i).join("/"));
  }

  clear(): void {
    this.paths.clear();
    this.basenames.clear();
    this.dirs.clear();
    this.globAnswers.clear();
  }

  /** Does one shell word (a path, a directory, `.` or a glob) cover a tainted file? */
  coveredBy(word: string): boolean {
    const path = normalizePath(word);
    if (path === "") return false;
    if (path === ".") return this.paths.size > 0;
    if (/[*?]/.test(path)) {
      const known = this.globAnswers.get(path);
      if (known !== undefined) return known;
      if (this.globEvaluations >= MAX_GLOB_EVALUATIONS) return this.paths.size > 0;
      this.globEvaluations++;
      const glob = globToRegExp(path);
      let covered = false;
      for (const tainted of this.paths) {
        if (glob.test(tainted) || glob.test(tainted.slice(tainted.lastIndexOf("/") + 1))) {
          covered = true;
          break;
        }
      }
      this.globAnswers.set(path, covered);
      return covered;
    }
    return this.paths.has(path) || this.dirs.has(path);
  }
}

/** `./a//b/` and `a\\b` to `a/b`; `.` stays `.`. */
function normalizePath(word: string): string {
  const path = word.replace(/\\/g, "/").replace(/\/{2,}/g, "/").replace(/^(?:\.\/)+/, "").replace(/\/+$/, "");
  return path === "" && word.startsWith(".") ? "." : path;
}

/** A shell glob (`*`, `**`, `?`) as an anchored RegExp over a normalized path. */
function globToRegExp(glob: string): RegExp {
  let source = "";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === "*") {
      if (glob[i + 1] === "*") {
        source += ".*";
        i++;
      } else source += "[^/]*";
    } else if (ch === "?") source += "[^/]";
    else source += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${source}$`);
}

/** Tokens a file's basename can appear as in code; URLs are removed first. */
const FILE_TOKEN_RE = /[\w.+~-]+/g;
const URL_RE = /\b[a-z][\w+.-]*:\/\/[^\s'"`()<>]*/gi;

/**
 * Commands of a step: split at `&&`, `||`, `;` and newlines, but not at `|`,
 * since a pipe carries data from one command to the next. A heredoc's body
 * stays with the command that reads it (`base64 > f <<EOF` / `$T` / `EOF`).
 */
function commands(exec: string): string[] {
  const out: string[] = [];
  const lines = exec.replace(/\\\n/g, " ").split("\n");
  for (let i = 0; i < lines.length; i++) {
    // An inline value keeps its key in the exec text (`- run: X=$T`).
    let line = lines[i]!.replace(/^\s*(?:-\s+)?(?:run|script)\s*:\s*(?:[|>][-+0-9]*\s*$)?/, "");
    const heredoc = /<<-?[^\S\n]*(['"]?)([A-Za-z_]\w{0,63})\1/.exec(line);
    if (heredoc) {
      const end = heredoc[2]!;
      while (i + 1 < lines.length) {
        const body = lines[++i]!;
        if (body.trim() === end) break;
        line += " " + body;
      }
    }
    out.push(...line.split(/&&|\|\||;/));
  }
  return out;
}

/** `NAME=value`, `export NAME=`, `local NAME=`, `declare NAME=` at a command's start. */
const SHELL_ASSIGN_RE = /^\s*(?:(?:export|local|declare|readonly)\s+)?([A-Za-z_]\w*)=/;

/** A word's value after `key=` (`of=f.bin`), else the word. */
function wordValue(word: string): string {
  const m = /^[\w-]{1,32}=(.+)$/.exec(word);
  return m ? m[1]! : word;
}

/** Does this command read a tainted file: by a basename in its code, or by a path word? */
function commandReadsTainted(command: string, tainted: TaintedFiles): boolean {
  if (tainted.size === 0) return false;
  for (const m of command.replace(URL_RE, " ").matchAll(FILE_TOKEN_RE)) {
    if (tainted.basenames.has(m[0])) return true;
  }
  for (const word of shellWords(command)) {
    if (word.startsWith("-") || word.includes("://") || /[$`{}]/.test(word)) continue;
    if (tainted.coveredBy(wordValue(word))) return true;
  }
  return false;
}

/**
 * Files a command that holds the secret may have written, beyond what
 * fileTargets names: its path-like words (`openssl ... -out enc.bin`,
 * `dd of=f.bin`, `tar czf a.tgz dist`) and quoted file names in inline code
 * (`Path('k.txt').write_text(...)`). Options, URLs and variables are left out.
 */
function commandOutputs(command: string): string[] {
  const out: string[] = [];
  const words = shellWords(command);
  for (let i = 0; i < words.length; i++) {
    const raw = words[i]!;
    // Redirections are fileTargets' (stdout) or not the secret (`2> err.log`).
    const redirect = /^(?:\d*|&)[<>]/.exec(raw);
    if (redirect) {
      if (/^(?:\d*|&)[<>]+[|&]?$/.test(raw)) i++;
      continue;
    }
    const word = wordValue(raw);
    if (word.startsWith("-") || word.includes("://") || /[$`*?{}]/.test(word)) continue;
    if (/[./\\]/.test(word) && /[A-Za-z]/.test(word) && !/\s/.test(word)) out.push(word);
  }
  for (const m of command.matchAll(/(['"])([\w./~-]{1,256}\.[A-Za-z0-9]{1,8})\1/g)) out.push(m[2]!);
  return out;
}

/**
 * The paths an artifact upload names (`with: path:`, inline or as a block
 * list; `!` exclusions skipped). `undefined` when none are stated, which
 * counts as uploading everything.
 */
function uploadPaths(stepLines: string[]): string[] | undefined {
  for (let k = 0; k < stepLines.length; k++) {
    const m = /^(\s*)path\s*:\s*(.*)$/.exec(stepLines[k]!);
    if (!m) continue;
    const inline = m[2]!.trim().replace(/^[|>][-+]?$/, "");
    if (inline !== "") return [inline.replace(/^(['"])(.*)\1$/, "$2")];
    const indent = m[1]!.length;
    const out: string[] = [];
    for (let j = k + 1; j < stepLines.length; j++) {
      const line = stepLines[j]!;
      if (line.trim() === "") continue;
      if (line.length - line.trimStart().length <= indent) break;
      const entry = line.trim().replace(/^-\s*/, "").replace(/^(['"])(.*)\1$/, "$2");
      if (entry !== "" && !entry.startsWith("!")) out.push(entry);
    }
    return out.length > 0 ? out : undefined;
  }
  return undefined;
}

/**
 * `NAME: value` pairs of env text, block or flow form. An unquoted value keeps
 * a whole `${{ ... }}` expression, and a value never starts at the `{` of a
 * flow map, so `env: { T: ... }` yields the pair inside it.
 */
const ENV_PAIR_RE =
  /([A-Za-z_][\w-]*)[ \t]*:[ \t]*("[^"\n]*"|'[^'\n]*'|(?:\$\{\{[^}\n]{0,512}\}\}|\$(?!\{\{)|[^$,{}[\n])*)/g;

/**
 * Commands that write out the whole environment without naming a variable:
 * `printenv`, `env`, a bare `set` (not `set -e`), `export -p`, PowerShell's
 * `env:` drive, `process.env` or `os.environ` taken whole.
 */
const ENV_DUMP_RE =
  /(?<![\w.$-])(?:printenv|env)(?![\w.:=-])|(?<![\w.$-])set(?![\w.=-])(?![^\S\n]+[-+])|\bexport[^\S\n]+-p\b|\b(?:Get-ChildItem|gci|dir|ls)[^\S\n]+env:|\bprocess\.env\b(?![^\S\n]*[.[])|\bos\.environ\b(?![^\S\n]*[.[])/i;

/** Names of the env variables whose value is a stored secret. */
function secretEnvNames(envText: string): string[] {
  const out: string[] = [];
  for (const m of envText.matchAll(ENV_PAIR_RE)) if (textHasStoredSecret(m[2]!)) out.push(m[1]!);
  return out;
}

const IDENTIFIER_RE = /[A-Za-z_]\w*/g;

/** Is one of these variables named in text (`$T`, `${T}`, `$env:T`, `process.env.T`)? */
function mentionsVariable(text: string, names: Set<string>): boolean {
  if (names.size === 0) return false;
  for (const m of text.matchAll(IDENTIFIER_RE)) if (names.has(m[0])) return true;
  return false;
}

/**
 * Forms that read some local file, used only when a secret went to a file
 * whose name the step did not state (fileTargets returned null): curl/wget/
 * PowerShell file arguments (`@file`, `-T`, `--post-file`, `-InFile`),
 * `source`/`.`, any command substitution, a `cat ... |` pipe, an input
 * redirection from a path-like word (not a `1 < 2` comparison), `Get-Content`,
 * Node `readFile`, Python `open(`.
 */
const READS_FILE_RE =
  /(?:^|[\s'"=])@["']?[\w./~$-]|(?:^|\s)(?:-T|--upload-file|--post-file|--body-file|-InFile)(?=[\s=])|(?:^|[\s;&|(])(?:source|\.)[^\S\n]+[\w./~$"'-]|\$\([^\S\n]*[<\w]|\bcat[^\S\n]+[^|;&\n]{0,512}\||(?<![<\d])<(?![<(&=])[^\S\n]*[\w~"'-]{0,256}[./$]|\bGet-Content\b|\b(?:readFile(?:Sync)?|open)[^\S\n]*\(/i;

/** Does executed text read a local file, or send one out? */
function execReadsFile(text: string): boolean {
  const joined = text.replace(/\\\n/g, " ");
  if (READS_FILE_RE.test(joined) || /(?<![\w.-])s?ftp(?![\w.-])/i.test(joined)) return true;
  return joined.split(/&&|\|\||[;&|\n]/).some(isRemoteCopy);
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

function segmentHasEgress(segment: string): boolean {
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

/** The run's own token: `github.token` or `github['token']`. */
const GITHUB_TOKEN_CONTEXT_RE =
  /(?<![\w.-])github\s*(?:\.\s*token|\[\s*(?:'token'|"token")\s*\])(?![\w-])/i;

/**
 * GITHUB_TOKEN is minted per run and governed by `permissions:`, so it is
 * ambient whichever way it is written. Any other name, a computed index or
 * the whole context can reach a stored secret. With `ambientCounts`, the run
 * token counts too: sending it out is itself the danger for exfiltration rules.
 */
function expressionUsesSecret(expr: string, ambientCounts: boolean): boolean {
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

const UPLOAD_ACTION_RE = /^actions\/upload-artifact(?:@|$)/i;

/**
 * Does a local composite action (`uses: ./path`) send data out? Its steps
 * cannot read `secrets` themselves, so what matters is whether the caller
 * hands one in and whether its own run steps make an outbound call.
 */
function localActionHasEgress(root: string, uses: string, cache: Map<string, boolean>): boolean {
  const rel = uses.split("@")[0]!;
  const target = path.resolve(root, rel);
  const base = path.resolve(root);
  if (target !== base && !target.startsWith(base + path.sep)) return false;
  const cached = cache.get(target);
  if (cached !== undefined) return cached;
  let result = false;
  for (const name of ["action.yml", "action.yaml"]) {
    const file = path.join(target, name);
    try {
      if (!fs.statSync(file).isFile() || fs.statSync(file).size > MAX_ACTION_BYTES) continue;
      const content = fs.readFileSync(file, "utf-8").replace(/\r/g, "");
      const regions = classifyWorkflowLines(content);
      const stripped = stripYamlComments(content).split("\n");
      result =
        execTextHasEgress(linesText(stripped, regions, 0, stripped.length, ["exec"])) ||
        stripped.some((l) => /^\s*-?\s*uses:\s*['"]?actions\/upload-artifact(?:@|['"\s]|$)/i.test(l));
      break;
    } catch {
      /* missing or unreadable: no egress known */
    }
  }
  cache.set(target, result);
  return result;
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
 * WORKFLOW_SECRET_TO_UPLOAD_PATH, evaluated per step. A stored secret is in
 * scope for a step when it is referenced in that step's `run:`/`script:` or
 * `env:`, in the job's `env:` (or its container's) or matrix, or in the
 * workflow `env:`. It stays in scope for every later step of the job once a
 * step holding it writes to `$GITHUB_ENV` or `$GITHUB_OUTPUT` (or exports it
 * from github-script). A command holds it when it names the secret or a
 * variable carrying it, dumps the environment, or reads a tainted file; the
 * files such a command writes or names become tainted, by full path. A later
 * outbound call reaches a tainted file by naming it, a directory above it or
 * a matching glob; an upload reaches it when its `path:` covers it. A file
 * whose name the step does not state reaches any later step that reads a
 * file. An artifact upload sends files, not the environment: a secret that
 * is only in the job's or workflow's env reaches it through a file, or
 * through the upload step's own env.
 * The step must itself make an outbound call or upload an artifact. `with:`
 * inputs are ignored except where the step's own code can read them: a local
 * composite action, or a `script:` body. A reusable workflow from another repository that is
 * handed stored secrets is reported too, since its steps are not visible here.
 */
function checkSecretToEgress(
  content: string,
  file: string,
  relPath: string,
  root: string,
  actionCache: Map<string, boolean>,
): Finding[] {
  const { ast, stripped, regions, workflowEnv, jobs } = workflowScopes(content);

  const finding = (line: number, what: string): Finding => ({
    rule: "WORKFLOW_SECRET_TO_UPLOAD_PATH",
    description: `Workflow "${file}": ${what}. Verify secrets are not sent to external endpoints.`,
    severity: "medium",
    file: relPath,
    line,
    confidence: 0.6,
    category: "supply-chain",
    recommendation:
      "Scope the secret to the step that needs it, and keep outbound calls and artifact uploads in steps without stored secrets.",
  });

  // Fail closed: a file whose jobs cannot be parsed keeps the coarse check.
  if (ast.jobs.length === 0) {
    const all = stripped.join("\n");
    const uploads = stripped.some((l) => /^\s*-?\s*uses:\s*['"]?actions\/upload-artifact/i.test(l));
    return textHasStoredSecret(all) && (uploads || execTextHasEgress(all))
      ? [finding(1, "a stored secret and an outbound call or upload appear in a workflow whose jobs could not be parsed")]
      : [];
  }

  const workflowSecret = textHasStoredSecret(workflowEnv);
  const workflowSecretNames = secretEnvNames(workflowEnv);

  const findings: Finding[] = [];
  for (const { job, env, reusableSecrets, strategy, steps } of jobs) {
    const matrixSecret = textHasStoredSecret(strategy);
    const jobSecret = workflowSecret || textHasStoredSecret(env) || matrixSecret;
    const jobSecretNames = [...workflowSecretNames, ...secretEnvNames(env)];
    let carriedEnv = false;
    const tainted = new TaintedFiles();
    let unnamedFile = false;

    if (job.uses && !job.uses.startsWith("./")) {
      if (/^[ \t]*secrets[ \t]*:[ \t]*inherit[ \t]*$/m.test(reusableSecrets) || textHasStoredSecret(reusableSecrets)) {
        findings.push(finding(job.line, `job "${job.id}" passes stored secrets to a reusable workflow from another repository`));
      }
    }

    for (const { step, s, e } of steps) {
      const uses = step.uses ?? "";
      let egress: string | null = null;
      const exec = linesText(stripped, regions, s, e, ["exec"]);
      let stepSecret = textHasStoredSecret(linesText(stripped, regions, s, e, ["env", "exec"]));
      // A script: body (actions/github-script) can read its own with: inputs.
      if (/^actions\/github-script(?:@|$)/i.test(uses)) {
        stepSecret = stepSecret || textHasStoredSecret(stripped.slice(s, e).join("\n"));
      }
      if (UPLOAD_ACTION_RE.test(uses)) {
        egress = "uploads an artifact";
      } else if (uses.startsWith("./") && localActionHasEgress(root, uses, actionCache)) {
        egress = "calls a local action that makes an outbound call";
        stepSecret = stepSecret || textHasStoredSecret(stripped.slice(s, e).join("\n"));
      } else if (execTextHasEgress(exec)) {
        egress = "makes an outbound call";
        stepSecret = stepSecret || textHasStoredSecret(stripped.slice(s, e).join("\n"));
      }
      const stepLines = stripped.slice(s, e);
      const cmds = commands(exec);
      const reads = (command: string): boolean =>
        commandReadsTainted(command, tainted) || (unnamedFile && execReadsFile(command));
      const readsTainted = cmds.some(reads);
      let fileReaches = false;
      if (egress === "uploads an artifact") {
        // Only the named paths are uploaded; none named means everything.
        const paths = uploadPaths(stepLines);
        fileReaches =
          unnamedFile ||
          (tainted.size > 0 &&
            (paths === undefined ||
              paths.some((entry) => {
                if (/\$\{\{/.test(entry)) return true;
                const path = normalizePath(entry);
                return tainted.coveredBy(entry) || [...tainted.paths].some((t) => path.endsWith(`/${t}`));
              })));
      } else if (egress !== null && egress !== "makes an outbound call") {
        // A local action's steps are not read here.
        fileReaches = tainted.size > 0 || unnamedFile;
      } else if (egress !== null) {
        fileReaches = readsTainted;
      }
      const envReaches = egress !== "uploads an artifact" && (jobSecret || carriedEnv);
      if (egress && (stepSecret || envReaches || fileReaches)) {
        findings.push(finding(step.line, `a stored secret is in scope for a step in job "${job.id}" that ${egress}`));
      }

      // Which commands hold the secret: they name it or a variable carrying
      // it, dump the environment, or read a tainted file. After a $GITHUB_ENV
      // export, or in a github-script step with a secret input, the whole step
      // holds it, but then only its explicit file writes are followed.
      const secretNames = new Set([...jobSecretNames, ...secretEnvNames(linesText(stripped, regions, s, e, ["env"]))]);
      const wholeStep = carriedEnv || (/^actions\/github-script(?:@|$)/i.test(uses) && stepSecret);
      // Commands run in order, so a file written by one command is read by the
      // next, and a variable assigned from the secret carries it on.
      const holding: string[] = [];
      for (const command of cmds) {
        const holds =
          textHasStoredSecret(command) ||
          mentionsVariable(command, secretNames) ||
          (secretNames.size > 0 && ENV_DUMP_RE.test(command)) ||
          (matrixSecret && /\bmatrix\s*\./.test(command)) ||
          reads(command);
        if (!holds) continue;
        holding.push(command);
        const assigned = SHELL_ASSIGN_RE.exec(command)?.[1];
        if (assigned !== undefined) secretNames.add(assigned);
        for (const target of [...fileTargets(command), ...commandOutputs(command)]) {
          if (target === null) unnamedFile = true;
          else tainted.add(target);
        }
      }
      if (wholeStep || holding.length > 0) {
        if (wholeStep ? PERSISTS_ENV_RE.test(exec) : holding.some((command) => PERSISTS_ENV_RE.test(command))) {
          carriedEnv = true;
        }
        if (wholeStep) {
          for (const target of fileTargets(exec)) {
            if (target === null) unnamedFile = true;
            else tainted.add(target);
          }
        }
        if (tainted.size > MAX_TAINTED_FILES) {
          tainted.clear();
          unnamedFile = true;
        }
      }
    }
  }
  return findings;
}

/**
 * Model workflows in a directory and find risky execution paths.
 */
export function modelWorkflows(dir: string): Finding[] {
  const findings: Finding[] = [];
  const workflowDir = path.join(dir, ".github", "workflows");

  if (!fs.existsSync(workflowDir)) return findings;
  const actionCache = new Map<string, boolean>();

  try {
    const files = fs.readdirSync(workflowDir).filter((f) =>
      f.endsWith(".yml") || f.endsWith(".yaml"),
    );

    for (const file of files) {
      const fullPath = path.join(workflowDir, file);
      const content = fs.readFileSync(fullPath, "utf-8");
      const relPath = `.github/workflows/${file}`;

      findings.push(...checkSecretToEgress(content, file, relPath, dir, actionCache));

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
  } catch { /* skip */ }

  return findings;
}
