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
 * A step that hands what it holds to the later steps of its job through their
 * environment: `$GITHUB_ENV`/`$GITHUB_OUTPUT`, the legacy `::set-output` /
 * `::set-env` commands, or github-script's `core.exportVariable` /
 * `core.setOutput`.
 */
const PERSISTS_ENV_RE = /GITHUB_(?:ENV|OUTPUT)\b|\bcore\s*\.\s*(?:exportVariable|setOutput)\s*\(|::set-(?:output|env)\b/;

/**
 * Where a redirection in one shell word writes to: `>f`, `x>f`, `1>>f`, `>|f`, or
 * `>` with the file as the next word (`""`). `2>`, `>&2`, `=>` and `->` are
 * not file writes of the step's output. `undefined` when the word has none.
 */
function redirectTarget(word: string): string | undefined {
  const at = word.indexOf(">");
  if (at < 0) return undefined;
  if (at > 0 && "=<>-".includes(word[at - 1]!)) return undefined;
  let digits = at;
  while (digits > 0 && word.charCodeAt(digits - 1) >= 48 && word.charCodeAt(digits - 1) <= 57) digits--;
  const fd = word.slice(digits, at);
  if (fd !== "" && fd !== "1") return undefined;
  const rest = word.slice(at + (word[at + 1] === ">" || word[at + 1] === "|" ? 2 : 1));
  if (rest.startsWith("&") || rest.startsWith(">")) return undefined;
  return rest;
}

/**
 * Files a step writes: redirection targets, `tee` arguments, PowerShell
 * `Out-File`/`Set-Content`/`Add-Content`, Node `writeFile`/`appendFile` and
 * Python `open(..., "w"|"a"|"x"|"+")`. A target this reader cannot name (a
 * variable, a glob, a computed path) is `null`; a path with a computed
 * directory is kept for placePath. The runner's own files and
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
  for (const target of pythonOpenWrites(joined)) out.push(target);
  return out
    .filter((t) => t === null || !/GITHUB_(?:ENV|OUTPUT|PATH|STEP_SUMMARY)|^\/dev\//.test(t))
    .map((t) => (t === null || t.trim() === "" ? null : t));
}

/** Most file paths followed per job; past this, any later file read counts. */
const MAX_TAINTED_FILES = 256;

/** Longest path followed by name; a longer one counts as unnamed. */
const MAX_TAINTED_PATH = 4096;

/** Longest glob matched; a longer one counts as covering (fail closed). */
const MAX_GLOB_LENGTH = 1024;

/**
 * Most distinct globs matched per job. Each is compared with every tainted
 * path, so a flood of distinct globs would be quadratic; past this, a glob
 * counts as covering a tainted file (fail closed).
 */
const MAX_GLOB_EVALUATIONS = 256;

/**
 * Where a written or named path lives:
 *   - "relative": in the workspace (also `$GITHUB_WORKSPACE/x`, and `..`
 *     resolved against the step's working-directory). Only these are inside
 *     an upload of `.` or of a directory.
 *   - "outside": the home directory or an absolute path, reached only by the
 *     same path (`~/.npmrc` and `$HOME/.npmrc` are one key).
 *   - "suffix": under a directory this reader cannot know
 *     (`$RUNNER_TEMP/ssh/deploy_key`, `f'{d}/k.txt'`); followed by what is
 *     written after the variable.
 */
interface PlacedPath {
  kind: "relative" | "outside" | "suffix";
  path: string;
}

/** `$NAME`, `${NAME}`, `${{ expr }}`, `%NAME%`, `{expr}`, `$(cmd)`: a computed part. */
const PATH_VARIABLE_RE = /\$\{\{[^}]*\}\}|\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{[^}]*\}/g;

function placePath(raw: string, workDir: string): PlacedPath | undefined {
  let word = raw.trim();
  // Most words are a plain name: no separator, variable, home or dot segment.
  if (/^[\w+@=:,-][\w.+@=:,-]*$/.test(word) && !word.startsWith(".")) {
    return { kind: "relative", path: workDir === "" ? word : `${workDir}/${word}` };
  }
  word = word.replace(/\\/g, "/");
  if (word === "" || /[*?`]/.test(word)) return undefined;
  // The workspace, spelled as a variable, is the workspace root.
  word = word.replace(/^(?:\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?)(?=\/|$)/, ".");
  // The current directory is the working directory.
  word = word.replace(/^(?:\$\{?PWD\}?|\$\(pwd\))(?=\/|$)/, ".");
  word = word.replace(/^(?:\$\{?HOME\}?|%USERPROFILE%)(?=\/|$)/, "~");
  PATH_VARIABLE_RE.lastIndex = 0;
  if (PATH_VARIABLE_RE.test(word)) {
    // Only the literal part after the last computed part is known.
    PATH_VARIABLE_RE.lastIndex = 0;
    let end = 0;
    for (const m of word.matchAll(PATH_VARIABLE_RE)) end = m.index + m[0].length;
    const rest = word.slice(end);
    if (!rest.startsWith("/")) return undefined;
    const suffix = path.posix.normalize(rest.slice(1)).replace(/\/+$/, "");
    return suffix === "" || suffix === "." || suffix.startsWith("..") ? undefined : { kind: "suffix", path: suffix };
  }
  // A piece of an expression split apart by the shell (`${{`, `}}/x`) is not a path.
  if (/[${}%]/.test(word)) return undefined;
  if (word.startsWith("~")) {
    return { kind: "outside", path: path.posix.normalize(word).replace(/\/+$/, "") };
  }
  if (word.startsWith("/") || /^[A-Za-z]:\//.test(word)) {
    return { kind: "outside", path: path.posix.normalize(word).replace(/\/+$/, "") };
  }
  const joined = path.posix.normalize(workDir === "" ? word : `${workDir}/${word}`).replace(/\/+$/, "");
  if (joined.startsWith("..")) return { kind: "outside", path: joined };
  return { kind: "relative", path: joined === "" ? "." : joined };
}

/** The step's `working-directory:`, relative to the workspace; "" when absent or computed. */
function workingDirectory(stepLines: readonly string[]): string {
  for (const line of stepLines) {
    const m = /^\s*(?:-\s+)?working-directory\s*:\s*(.*?)\s*$/.exec(line);
    if (!m) continue;
    const value = m[1]!.replace(/^(['"])(.*)\1$/, "$2");
    const placed = placePath(value, "");
    return placed?.kind === "relative" && placed.path !== "." ? placed.path : "";
  }
  return "";
}

/**
 * Files written after a secret reached them. A later step reaches one by
 * naming it (as a path word, a directory above it, `.`, or a glob), or, for a
 * dotted file name, by naming it anywhere in code (`open('key.txt')`,
 * `$(base64 key.txt)`).
 */
class TaintedFiles {
  readonly paths = new Set<string>();
  readonly dirs = new Set<string>();
  readonly outside = new Set<string>();
  readonly outsideDirs = new Set<string>();
  readonly suffixes = new Set<string>();
  private readonly suffixBasenames = new Set<string>();
  /** Dotted file names, which may be matched as tokens in code. */
  readonly dottedNames = new Set<string>();
  private readonly globAnswers = new Map<string, boolean>();
  private globEvaluations = 0;

  get size(): number {
    return this.paths.size + this.outside.size + this.suffixes.size;
  }

  /**
   * Follow one written file. False when it cannot be followed by name: a
   * computed or glob path, too long, or the job already follows
   * MAX_TAINTED_FILES. The caller then treats it as an unnamed file.
   */
  add(raw: string, workDir: string): boolean {
    const placed = placePath(raw, workDir);
    if (placed === undefined) return false;
    const { kind, path: p } = placed;
    if (p === ".") return false;
    const set = kind === "relative" ? this.paths : kind === "outside" ? this.outside : this.suffixes;
    if (set.has(p)) return true;
    if (p.length > MAX_TAINTED_PATH || this.size >= MAX_TAINTED_FILES) return false;
    set.add(p);
    this.globAnswers.clear();
    const base = p.slice(p.lastIndexOf("/") + 1);
    if (/\.[A-Za-z0-9]/.test(base)) this.dottedNames.add(base);
    if (kind === "suffix") this.suffixBasenames.add(base);
    const dirs = kind === "relative" ? this.dirs : kind === "outside" ? this.outsideDirs : undefined;
    // Each ancestor is a prefix ending at a "/", so building them is linear.
    if (dirs) for (let at = p.indexOf("/"); at > 0; at = p.indexOf("/", at + 1)) dirs.add(p.slice(0, at));
    return true;
  }

  /** Does one path word (a file, a directory above one, `.` or a glob) cover a tainted file? */
  coveredBy(word: string, workDir: string): boolean {
    if (this.size === 0) return false;
    const trimmed = word.trim().replace(/\\/g, "/");
    if (/[*?]/.test(trimmed) && !/[$%{`]/.test(trimmed)) return this.globCovers(trimmed, workDir);
    const placed = placePath(trimmed, workDir);
    if (placed === undefined) return false;
    const { kind, path: p } = placed;
    if (kind === "relative") {
      if (p === ".") return this.paths.size > 0;
      if (this.paths.has(p) || this.dirs.has(p)) return true;
      return this.suffixMatches(p);
    }
    if (kind === "outside") return this.outside.has(p) || this.outsideDirs.has(p) || this.suffixMatches(p);
    // A computed directory: the same known rest, or a tainted path ending in it.
    return this.suffixes.has(p) || this.suffixMatches(p) || this.paths.has(p);
  }

  /** Does a path end in a tainted suffix (`out/k.txt` against `k.txt`)? */
  private suffixMatches(p: string): boolean {
    const base = p.slice(p.lastIndexOf("/") + 1);
    if (!this.suffixBasenames.has(base)) return false;
    for (const s of this.suffixes) if (p === s || p.endsWith(`/${s}`)) return true;
    return false;
  }

  private globCovers(glob: string, workDir: string): boolean {
    const pattern = path.posix.normalize(workDir === "" ? glob : `${workDir}/${glob}`).replace(/^\.\//, "");
    const known = this.globAnswers.get(pattern);
    if (known !== undefined) return known;
    if (this.globEvaluations >= MAX_GLOB_EVALUATIONS || pattern.length > MAX_GLOB_LENGTH) {
      return this.paths.size + this.suffixes.size > 0;
    }
    this.globEvaluations++;
    let covered = false;
    const bareName = !pattern.includes("/");
    for (const p of [...this.paths, ...this.suffixes]) {
      const base = p.slice(p.lastIndexOf("/") + 1);
      if (globMatches(pattern, p) || (bareName && segmentMatches(pattern, base))) {
        covered = true;
        break;
      }
    }
    this.globAnswers.set(pattern, covered);
    return covered;
  }
}

/**
 * Does one path segment match one glob segment (`*`, `?`, no `/`)? The
 * iterative star match: it backtracks only to the last `*`, so it is at most
 * quadratic in the segment lengths and never exponential.
 */
function segmentMatches(glob: string, text: string): boolean {
  let g = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (g < glob.length && (glob[g] === "?" || glob[g] === text[t])) {
      g++;
      t++;
    } else if (g < glob.length && glob[g] === "*") {
      star = g++;
      mark = t;
    } else if (star >= 0) {
      g = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (g < glob.length && glob[g] === "*") g++;
  return g === glob.length;
}

/**
 * Does a normalized path match a glob? Segment by segment, `**` spanning any
 * number of directories, as a table over path positions: segments times
 * positions, each a segmentMatches.
 */
function globMatches(glob: string, path: string): boolean {
  const parts = path.split("/");
  let reach: boolean[] = new Array<boolean>(parts.length + 1).fill(false);
  reach[0] = true;
  for (const segment of glob.split("/")) {
    const next = new Array<boolean>(parts.length + 1).fill(false);
    if (segment === "**") {
      let seen = false;
      for (let j = 0; j <= parts.length; j++) {
        seen = seen || reach[j]!;
        next[j] = seen;
      }
    } else {
      for (let j = 0; j < parts.length; j++) {
        if (reach[j] && segmentMatches(segment, parts[j]!)) next[j + 1] = true;
      }
    }
    reach = next;
  }
  return reach[parts.length]!;
}

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
    for (const command of line.split(/&&|\|\||;/)) out.push(command);
  }
  return out;
}

/**
 * `NAME=value`, `export NAME=`, `local NAME=`, `declare NAME=` at a command's
 * start (group 1), or `read [-r] NAME` (group 2).
 */
const SHELL_ASSIGN_RE =
  /^\s*(?:(?:export|local|declare|readonly)\s+)?([A-Za-z_]\w*)=|^\s*read\s+(?:-[A-Za-z]+\s+)*([A-Za-z_]\w*)/;

/** `F=$GITHUB_ENV`: a variable that names the runner's env or output file. */
const ENV_FILE_ASSIGN_RE = /^\s*(?:export\s+)?([A-Za-z_]\w*)=["']?\$\{?GITHUB_(?:ENV|OUTPUT)\b/;

/** A word's value after `key=` (`of=f.bin`, `--output=x`), else the word. */
function wordValue(word: string): string {
  const m = /^-{0,2}[\w-]{1,32}=(.+)$/.exec(word);
  return m ? m[1]! : word;
}

/** Tokens a dotted file name can appear as in code; URLs are removed first. */
const FILE_TOKEN_RE = /[\w.+~-]+/g;
const URL_RE = /\b[a-z][\w+.-]*:\/\/[^\s'"`()<>]*/gi;

/** Does this command read a tainted file: a dotted name in its code, or a path word? */
function commandReadsTainted(command: string, tainted: TaintedFiles, workDir: string): boolean {
  if (tainted.size === 0) return false;
  if (tainted.dottedNames.size > 0) {
    for (const m of command.replace(URL_RE, " ").matchAll(FILE_TOKEN_RE)) {
      if (tainted.dottedNames.has(m[0])) return true;
    }
  }
  for (const raw of shellWords(command)) {
    if (raw.startsWith("-") && !raw.includes("=")) continue;
    if (raw.includes("://")) continue;
    const word = wordValue(raw).replace(/^@/, "");
    if (word !== "" && tainted.coveredBy(word, workDir)) return true;
  }
  return false;
}

/** Options whose value is a file the command writes. */
const OUTPUT_FLAGS = new Set([
  "-o", "--output", "-out", "--out", "-O", "--output-file", "--output-document", "--outfile",
  "-outfile", "--out-file", "-OutFile", "-Destination", "--destination",
]);

/** Tools whose last positional argument is where they write. */
const COPY_TOOLS = new Set(["cp", "mv", "install", "ln", "ditto", "copy", "xcopy", "robocopy", "Copy-Item", "Move-Item"]);

/** Tools whose first positional argument is the archive they write. */
const ARCHIVE_TOOLS = new Set(["zip", "jar", "rar"]);

/**
 * Files a command that holds the secret writes, beyond redirections
 * (fileTargets): the value of an output option (`-o`, `-out`, `of=`,
 * `--output=`), the destination of a copy (`cp k.txt bundle`), the archive of
 * `tar -f`/`zip`/`7z a`, and quoted file names in inline code
 * (`Path('k.txt').write_text(...)`). Input files are not outputs: a command
 * that signs, uploads or packages a file does not write the secret into it.
 */
function commandOutputs(command: string): string[] {
  const out: string[] = [];
  const words: string[] = [];
  const all = shellWords(command);
  for (let i = 0; i < all.length; i++) {
    const w = all[i]!;
    // Redirections are fileTargets' (stdout) or not the secret (`2> err.log`).
    if (/^(?:\d*|&)[<>]/.test(w)) {
      if (/^(?:\d*|&)[<>]+[|&]?$/.test(w)) i++;
      continue;
    }
    words.push(w);
  }
  let t = 0;
  while (t < words.length && (/^[A-Za-z_]\w*=/.test(words[t]!) || words[t] === "sudo" || words[t] === "time")) t++;
  const tool = (words[t] ?? "").replace(/^.*[\\/]/, "");
  const args = words.slice(t + 1);
  for (let i = 0; i < args.length; i++) {
    const w = args[i]!;
    if (OUTPUT_FLAGS.has(w) && args[i + 1] !== undefined) out.push(args[++i]!);
    else {
      const m = /^(?:--output|--out|--output-file|--outfile|--output-document|-o|of)=(.+)$/.exec(w);
      if (m) out.push(m[1]!);
    }
  }
  const positional = args.filter((w) => !w.startsWith("-") && !w.includes("://"));
  if (COPY_TOOLS.has(tool) && positional.length >= 2) out.push(positional[positional.length - 1]!);
  if (tool === "tar") {
    for (let i = 0; i < args.length; i++) {
      const w = args[i]!;
      const file = /^--file=(.+)$/.exec(w);
      if (file) out.push(file[1]!);
      else if ((w === "--file" || w === "-f" || (i === 0 && /^-?[A-Za-z]*f[A-Za-z]*$/.test(w))) && args[i + 1] !== undefined) {
        out.push(args[i + 1]!);
      }
    }
  }
  if (ARCHIVE_TOOLS.has(tool) && positional[0] !== undefined) out.push(positional[0]);
  if (/^7za?$/.test(tool) && positional.length >= 2) out.push(positional[1]!);
  for (const m of command.matchAll(/(['"])([\w./~-]{1,256}\.[A-Za-z0-9]{1,8})\1/g)) out.push(m[2]!);
  return out;
}

/**
 * Python `open(path, mode)` calls with a write mode: the literal path (an
 * f-string's braces stay in it, for placePath), or null for a computed path
 * (`os.path.join(...)`). Arguments are split at top-level commas.
 */
function pythonOpenWrites(text: string): Array<string | null> {
  const out: Array<string | null> = [];
  for (const m of text.matchAll(/\bopen[^\S\n]*\(/g)) {
    const args: string[] = [];
    let depth = 1;
    let quote = "";
    let start = m.index + m[0].length;
    const limit = Math.min(text.length, start + 512);
    let i = start;
    for (; i < limit && depth > 0; i++) {
      const ch = text[i]!;
      if (quote) {
        if (ch === "\\") i++;
        else if (ch === quote) quote = "";
      } else if (ch === "'" || ch === '"') quote = ch;
      else if (ch === "(" || ch === "[" || ch === "{") depth++;
      else if (ch === ")" || ch === "]" || ch === "}") depth--;
      else if (ch === "," && depth === 1) {
        args.push(text.slice(start, i).trim());
        start = i + 1;
      }
      if (ch === "\n") break;
    }
    if (depth !== 0) continue;
    args.push(text.slice(start, i - 1).trim());
    const modeArg = args.slice(1).find((a) => /^(?:mode\s*=\s*)?[bBrRuU]{0,2}['"][^'"]*['"]$/.test(a));
    const mode = modeArg ? /['"]([^'"]*)['"]/.exec(modeArg)![1]! : "";
    if (!/[wax+]/.test(mode)) continue;
    const literal = /^[fFrRbBuU]{0,2}(['"])(.*)\1$/.exec(args[0] ?? "");
    out.push(literal ? literal[2]! : null);
  }
  return out;
}

/**
 * Actions that publish files: artifacts, Pages, releases, caches. Their paths
 * are read from `path`, `files`, `publish_dir`, `folder` or `artifacts`.
 * `actions/upload-artifact/merge` only merges artifacts already uploaded.
 */
const PUBLISH_ACTION_RE =
  /^(?:actions\/upload-artifact|actions\/upload-pages-artifact|actions\/cache(?:\/save)?|softprops\/action-gh-release|ncipollo\/release-action|svenstaro\/upload-release-action|peaceiris\/actions-gh-pages|JamesIves\/github-pages-deploy-action)(?:@|$)/i;

/**
 * Actions that fetch credentials and put them in the environment of later
 * steps, with the variable names they are known to set.
 */
const CREDENTIAL_ACTIONS: Array<[RegExp, string[]]> = [
  [/^aws-actions\/configure-aws-credentials(?:@|$)/i, ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]],
  [/^google-github-actions\/auth(?:@|$)/i, ["GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "GOOGLE_GHA_CREDS_PATH"]],
  [/^hashicorp\/vault-action(?:@|$)/i, []],
  [/^azure\/login(?:@|$)/i, []],
  [/^1password\/load-secrets-action(?:@|$)/i, []],
  [/^bitwarden\/sm-action(?:@|$)/i, []],
  [/^dopplerhq\/secrets-fetch-action(?:@|$)/i, []],
  [/^infisical\/secrets-action(?:@|$)/i, []],
  [/^cyberark\/conjur-action(?:@|$)/i, []],
];

/** The paths a publishing step names; `undefined` when none are stated (everything). */
function uploadPaths(stepLines: string[]): string[] | undefined {
  for (let k = 0; k < stepLines.length; k++) {
    const m = /^(\s*)(?:path|files|publish_dir|folder|artifacts|file|asset_path)\s*:\s*(.*)$/.exec(stepLines[k]!);
    if (!m) continue;
    const inline = m[2]!.trim().replace(/^[|>][-+]?$/, "");
    const out: string[] = [];
    const take = (entry: string): void => {
      const e = entry.trim().replace(/^-\s*/, "").replace(/^(['"])(.*)\1$/, "$2").trim();
      if (e !== "" && !e.startsWith("!")) out.push(e);
    };
    if (inline !== "") {
      for (const part of inline.replace(/^(['"])(.*)\1$/, "$2").split(",")) take(part);
    } else {
      const indent = m[1]!.length;
      for (let j = k + 1; j < stepLines.length; j++) {
        const line = stepLines[j]!;
        if (line.trim() === "") continue;
        if (line.length - line.trimStart().length <= indent) break;
        take(line);
      }
    }
    return out.length > 0 ? out : undefined;
  }
  return undefined;
}

/**
 * Does a command print the whole environment? Only as the command itself:
 * `env`, `printenv` or `set` with nothing after them but a pipe or a
 * redirection, `export -p`, PowerShell's `env:` drive, `process.env` or
 * `os.environ` taken whole. `env NODE_ENV=production npm run build`,
 * `set -e`, `python -m venv env` and `kubectl set image` do not.
 */
function isEnvDump(command: string): boolean {
  if (!/env|set|environ/i.test(command)) return false;
  if (/\bexport[^\S\n]+-p\b|\b(?:Get-ChildItem|gci|dir|ls)[^\S\n]+env:|\bprocess\.env\b(?![^\S\n]*[.[])|\bos\.environ\b(?![^\S\n]*[.[])/i.test(command)) {
    return true;
  }
  const words = shellWords(command);
  let i = 0;
  while (i < words.length && (/^[A-Za-z_]\w*=/.test(words[i]!) || words[i] === "sudo")) i++;
  const tool = (words[i] ?? "").replace(/^.*[\\/]/, "");
  if (tool !== "env" && tool !== "printenv" && tool !== "set") return false;
  const next = words[i + 1];
  return next === undefined || /^[|>&]/.test(next);
}

/** Frontend build variables that a bundler inlines into its output. */
const PUBLIC_BUILD_ENV_RE = /^(?:VITE_|NEXT_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_|EXPO_PUBLIC_|VUE_APP_|STORYBOOK_|PUBLIC_)/;

/** A frontend build or static export. */
const BUILD_CMD_RE =
  /\b(?:npm|pnpm|yarn|bun)(?:[^\S\n]+run)?[^\S\n]+(?:build|generate|export)\b|\b(?:vite|next|nuxt|nuxi|gatsby|astro|react-scripts|vue-cli-service|ng|expo)[^\S\n]+(?:build|generate|export)\b/;

/** Variable names a command exports to later steps; empty when they cannot be told. */
function exportedNames(text: string): string[] {
  const names: string[] = [];
  for (const m of text.matchAll(/\bcore\s*\.\s*(?:exportVariable|setOutput)\s*\(\s*['"`]([\w-]+)/g)) names.push(m[1]!);
  for (const m of text.matchAll(/::set-(?:output|env)[^\S\n]+name=([\w-]+)::/g)) names.push(m[1]!);
  if (/GITHUB_(?:ENV|OUTPUT)/.test(text) || />/.test(text)) {
    for (const m of text.matchAll(/(?:^|[\s"'])([A-Za-z_]\w*)=/g)) if (!/^GITHUB_/.test(m[1]!)) names.push(m[1]!);
  }
  return names;
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
 * `NAME: value` pairs of env text, block or flow form. A key starts a line
 * or follows `{` or `,`, so a long word with no colon is read once. An
 * unquoted value keeps a whole `${{ ... }}` expression (single braces inside,
 * as in `format('{0}', ...)`, included), and a value never starts at the `{`
 * of a flow map, so `env: { T: ... }` yields the pair inside it.
 */
const ENV_PAIR_RE =
  /(?:^|[{,])[ \t]*(?:-[ \t]+)?([A-Za-z_][\w-]{0,127})[ \t]*:[ \t]*("[^"\n]*"|'[^'\n]*'|(?:\$\{\{(?:[^}\n]|\}(?!\})){0,512}\}\}|\$(?!\{\{)|[^$,{}[\n])*)/gm;

/** `NAME: |` or `NAME: >-`: a block scalar whose value is on the lines below. */
const BLOCK_SCALAR_KEY_RE = /^([ \t]*)(?:-[ \t]+)?([A-Za-z_][\w-]{0,127})[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*$/;

/** Names of the env variables whose value is a stored secret. */
function secretEnvNames(envText: string): string[] {
  const out: string[] = [];
  for (const m of envText.matchAll(ENV_PAIR_RE)) if (textHasStoredSecret(m[2]!)) out.push(m[1]!);
  // Block scalars; each block's lines are read once, then skipped.
  const lines = envText.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = BLOCK_SCALAR_KEY_RE.exec(lines[i]!);
    if (!m) continue;
    const indent = m[1]!.length;
    let j = i + 1;
    let value = "";
    for (; j < lines.length; j++) {
      const line = lines[j]!;
      if (line.trim() !== "" && line.length - line.trimStart().length <= indent) break;
      value += line + "\n";
    }
    if (textHasStoredSecret(value)) out.push(m[2]!);
    i = j - 1;
  }
  return out;
}

const IDENTIFIER_RE = /[A-Za-z_]\w*/g;

/** Is one of these variables named in text (`$T`, `${T}`, `$env:T`, `process.env.T`)? */
function mentionsVariable(text: string, names: Set<string>, more?: Set<string>): boolean {
  if (names.size === 0 && (more === undefined || more.size === 0)) return false;
  for (const m of text.matchAll(IDENTIFIER_RE)) if (names.has(m[0]) || more?.has(m[0])) return true;
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


/** The executed text of a local composite action, or undefined when it cannot be read. */
function localActionExec(root: string, uses: string, cache: Map<string, string | undefined>): string | undefined {
  const rel = uses.split("@")[0]!;
  const target = path.resolve(root, rel);
  const base = path.resolve(root);
  if (target !== base && !target.startsWith(base + path.sep)) return undefined;
  if (cache.has(target)) return cache.get(target);
  let text: string | undefined;
  for (const name of ["action.yml", "action.yaml"]) {
    const file = path.join(target, name);
    try {
      if (!fs.statSync(file).isFile() || fs.statSync(file).size > MAX_ACTION_BYTES) continue;
      const content = fs.readFileSync(file, "utf-8").replace(/\r/g, "");
      const regions = classifyWorkflowLines(content);
      const lines = stripYamlComments(content).split("\n");
      text = linesText(lines, regions, 0, lines.length, ["exec"]);
      break;
    } catch {
      /* missing or unreadable */
    }
  }
  cache.set(target, text);
  return text;
}

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
  actionTextCache: Map<string, string | undefined> = new Map(),
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
  if (ast.jobs.length === 0) return coarseSecretToEgress(content, file, relPath, "could not be parsed");

  const workflowSecret = textHasStoredSecret(workflowEnv);
  const workflowSecretNames = secretEnvNames(workflowEnv);

  const findings: Finding[] = [];
  for (const { job, env, reusableSecrets, strategy, steps } of jobs) {
    const matrixSecret = textHasStoredSecret(strategy);
    const jobSecret = workflowSecret || textHasStoredSecret(env) || matrixSecret;
    // Variables that carry a secret for every step of the job; exports and
    // credential actions add to it.
    const jobSecretNames = new Set([...workflowSecretNames, ...secretEnvNames(env)]);
    let carriedEnv = false;
    // An export whose variable names cannot be told: later steps hold it wholesale.
    let unknownExport = false;
    const tainted = new TaintedFiles();
    let unnamedFile = false;

    if (job.uses && !job.uses.startsWith("./")) {
      if (/^[ \t]*secrets[ \t]*:[ \t]*inherit[ \t]*$/m.test(reusableSecrets) || textHasStoredSecret(reusableSecrets)) {
        findings.push(finding(job.line, `job "${job.id}" passes stored secrets to a reusable workflow from another repository`));
      }
    }

    for (const { step, s, e } of steps) {
      const uses = step.uses ?? "";
      const stepLines = stripped.slice(s, e);
      // The whole step without its `if:`, which only tests a secret.
      const stepAll = stepLines.filter((l) => !/^\s*(?:-\s+)?if\s*:/.test(l)).join("\n");
      const workDir = workingDirectory(stepLines);
      const exec = linesText(stripped, regions, s, e, ["exec"]);
      const isLocal = uses.startsWith("./");
      const actionExec = isLocal ? localActionExec(root, uses, actionTextCache) : undefined;
      const publishes = PUBLISH_ACTION_RE.test(uses);

      let stepSecret = textHasStoredSecret(linesText(stripped, regions, s, e, ["env", "exec"]));
      // A script: body (actions/github-script) and a local action can read their with: inputs.
      if (isLocal || /^actions\/github-script(?:@|$)/i.test(uses)) {
        stepSecret = stepSecret || textHasStoredSecret(stepAll);
      }
      let egress: string | null = null;
      if (publishes) {
        egress = /^actions\/upload-artifact(?:@|$)/i.test(uses) ? "uploads an artifact" : "publishes files";
      } else if (isLocal && localActionHasEgress(root, uses, actionCache)) {
        egress = "calls a local action that makes an outbound call";
      } else if (execTextHasEgress(exec)) {
        egress = "makes an outbound call";
        stepSecret = stepSecret || textHasStoredSecret(stepAll);
      }

      const cmds = commands(exec);
      const reads = (command: string): boolean =>
        commandReadsTainted(command, tainted, workDir) || (unnamedFile && execReadsFile(command));
      let fileReaches = false;
      if (egress !== null && publishes) {
        // Only the named paths are published; none named means everything.
        const paths = uploadPaths(stepLines);
        fileReaches =
          unnamedFile ||
          (tainted.size > 0 &&
            (paths === undefined || paths.some((entry) => /\$\{\{/.test(entry) || tainted.coveredBy(entry, workDir))));
      } else if (egress !== null && isLocal) {
        // The action's own commands, and the paths the step hands it.
        const actionCmds = actionExec === undefined ? undefined : commands(actionExec);
        fileReaches =
          unnamedFile ||
          (tainted.size > 0 &&
            (actionCmds === undefined ||
              commandReadsTainted(stepAll, tainted, workDir) ||
              actionCmds.some((command) => commandReadsTainted(command, tainted, ""))));
      } else if (egress !== null) {
        fileReaches = cmds.some(reads);
      }
      // An upload or release sends files, not the environment.
      const envReaches = !publishes && (jobSecret || carriedEnv);
      if (egress && (stepSecret || envReaches || fileReaches)) {
        findings.push(finding(step.line, `a stored secret is in scope for a step in job "${job.id}" that ${egress}`));
      }

      // Which commands hold the secret: they name it or a variable carrying
      // it, dump the environment, or read a tainted file. Commands run in
      // order, so a file one writes is read by the next, and a variable
      // assigned from the secret carries it on.
      const secretNames = new Set(secretEnvNames(linesText(stripped, regions, s, e, ["env"])));
      const envFiles = new Set<string>();
      const follow = (targets: Array<string | null>): void => {
        for (const target of targets) if (target === null || !tainted.add(target, workDir)) unnamedFile = true;
      };
      const exportFrom = (text: string): void => {
        carriedEnv = true;
        const names = exportedNames(text);
        if (names.length === 0) unknownExport = true;
        for (const name of names) jobSecretNames.add(name);
      };
      // After an export of unknown names, or in a github-script step with a
      // secret input, the whole step holds it, and its explicit writes are followed.
      const wholeStep = unknownExport || (/^actions\/github-script(?:@|$)/i.test(uses) && stepSecret);
      for (const command of cmds) {
        const envFile = ENV_FILE_ASSIGN_RE.exec(command)?.[1];
        if (envFile !== undefined) envFiles.add(envFile);
        const holds =
          textHasStoredSecret(command) ||
          mentionsVariable(command, jobSecretNames, secretNames) ||
          (jobSecretNames.size + secretNames.size > 0 && isEnvDump(command)) ||
          (matrixSecret && /\bmatrix\s*\./.test(command)) ||
          reads(command);
        if (!holds) continue;
        const assigned = SHELL_ASSIGN_RE.exec(command);
        const name = assigned?.[1] ?? assigned?.[2];
        if (name !== undefined) secretNames.add(name);
        follow([...fileTargets(command), ...commandOutputs(command)]);
        if (PERSISTS_ENV_RE.test(command) || (/>/.test(command) && mentionsVariable(command, envFiles))) exportFrom(command);
      }
      if (wholeStep) {
        follow(fileTargets(exec));
        if (PERSISTS_ENV_RE.test(exec)) exportFrom(exec);
      }
      // A local action handed a secret: what its own commands write or export.
      if (isLocal && stepSecret && actionExec !== undefined) {
        follow(fileTargets(actionExec));
        for (const command of commands(actionExec)) follow(commandOutputs(command));
        if (PERSISTS_ENV_RE.test(actionExec)) exportFrom(actionExec);
      }
      // A bundler inlines public build variables into what it writes.
      if (BUILD_CMD_RE.test(exec) && [...jobSecretNames, ...secretNames].some((n) => PUBLIC_BUILD_ENV_RE.test(n))) {
        unnamedFile = true;
      }
      // Credential actions put what they fetch in the environment of later steps.
      for (const [re, names] of CREDENTIAL_ACTIONS) {
        if (!re.test(uses)) continue;
        carriedEnv = true;
        const mapped = [...stepAll.matchAll(/\|\s*([A-Za-z_]\w*)\s*(?:;|$)/gm)].map((m) => m[1]!);
        const known = [...names, ...mapped];
        if (known.length === 0) unknownExport = true;
        for (const n of known) jobSecretNames.add(n);
      }
    }
  }
  return findings;
}

/**
 * The whole-file check a workflow falls back to when it cannot be modelled
 * step by step: a stored secret and an outbound call or upload anywhere in it.
 */
function coarseSecretToEgress(content: string, file: string, relPath: string, why: string): Finding[] {
  const stripped = stripYamlComments(content.replace(/\r/g, "")).split("\n");
  const all = stripped.join("\n");
  const uploads = stripped.some((l) => /^\s*-?\s*uses:\s*['"]?actions\/upload-artifact/i.test(l));
  if (!textHasStoredSecret(all) || !(uploads || execTextHasEgress(all))) return [];
  return [{
    rule: "WORKFLOW_SECRET_TO_UPLOAD_PATH",
    description: `Workflow "${file}": a stored secret and an outbound call or upload appear in a workflow whose steps ${why}. Verify secrets are not sent to external endpoints.`,
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
  const actionCache = new Map<string, boolean>();

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
      for (const f of checkSecretToEgress(content, file, relPath, dir, actionCache)) findings.push(f);
    } catch {
      for (const f of coarseSecretToEgress(content, file, relPath, "could not be modelled")) findings.push(f);
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
