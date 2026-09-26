/**
 * Workflow execution modeler (v4.7).
 *
 * Models GitHub Actions workflows as executable chains, tracking
 * secret access, action usage, and data flow paths.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { trimLeading, trimTrailing } from "./text-lines.js";
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
  /(?<![\w.-])(?:sftp|ftp|socat|telnet|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Send-MailMessage)(?![\w./-])|\/dev\/(?:tcp|udp)\/|\b(?:requests|httpx)\s*\.\s*(?:get|post|put|patch|request)\s*\(|\burllib\.request\b|\bNet\.WebClient\b|\brequire[^\S\n]*\([^\S\n]*['"](?:node:)?https?['"][^\S\n]*\)[^\S\n]*\.[^\S\n]*(?:request|get)\b|\bhttps?[^\S\n]*\.[^\S\n]*(?:request|get)[^\S\n]*\(|\baxios[^\S\n]*\.[^\S\n]*(?:post|put|patch|get|request)[^\S\n]*\(|\brequests[^\S\n]*\.[^\S\n]*Session[^\S\n]*\(|\bhttp\.client\b|\burllib3\b|\b(?:github|octokit)[^\S\n]*\.[^\S\n]*request[^\S\n]*\([^\S\n]*['"`](?:[A-Z]+[^\S\n]+)?https?:\/\/(?!api\.github\.com)/i;

/**
 * A DNS lookup tool as a command (segment start or `$(`), which carries data out
 * in the name it queries. Only in command position: `dig` and `drill` are also
 * ordinary variable names in a github-script body.
 */
const DNS_TOOL_RE = /(?:^|\$\(|`|\brun:)[^\S\n]*(?:sudo[^\S\n]+)?(?:nslookup|dig|drill|kdig)(?![\w.-])(?![^\S\n]*[=:(.])/;

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
  // An expression holds spaces (`${{ secrets.X }}`): keep it inside its word.
  const rest = segment.slice(m.index + m[0].length).replace(/\$\{\{[^}\n]{0,256}\}\}/g, "EXPR");
  for (const word of shellWords(rest)) {
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
    const word = trimTrailing(trimLeading(raw, "()"), "()");
    if (skipNext) { skipNext = false; continue; }
    if (word === "") continue;
    if (/^\d*[<>]/.test(word)) {
      // Redirection: `>` alone takes the next word as its file.
      if (/^\d*[<>]+&?$/.test(word)) skipNext = true;
      continue;
    }
    if (/^-x./.test(word)) {
      // A proxy written onto its option (`-xhost:3128`) carries the request.
      if (!isLoopbackTarget(word.slice(2))) return false;
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

/** Public registries and GitHub itself: the audience of the tokens a release step holds. */
const PUBLIC_HOSTS = new Set([
  "github.com", "ghcr.io", "registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com",
  "pypi.org", "upload.pypi.org", "test.pypi.org", "files.pythonhosted.org",
]);

function isPublicHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return PUBLIC_HOSTS.has(h) || h.endsWith(".github.com") || h.endsWith(".githubusercontent.com");
}

/**
 * A URL anywhere in executed text; group 1 is its host. Not only a whole shell
 * word: an HTTP client in any language takes it inside a call
 * (`URI("https://host")`, `url:'https://host'`), and no list of clients is
 * complete. `s3://` and `gs://` name a bucket, which is a destination too.
 */
const URL_ANY_RE =
  /(?<![\w.+-])(?:[a-z][\w.-]{0,31}\+)?(?:https?|ftps?|wss?|s3|gs):\/\/(?:[^\s\/@'"`()<>?#\\]{0,256}@)?([^\s\/:?#'"`()<>\\,;]+)/gi;

/**
 * A URL handed to any program (`python send.py https://host ...`,
 * `ruby -e 'Net::HTTP.post(URI("https://host"), ...)'`, a secret in
 * `https://u:TOKEN@host`): the program is not known, so a destination other
 * than loopback or a public registry counts as egress.
 */
function hasUrl(segment: string): boolean {
  for (const m of segment.matchAll(URL_ANY_RE)) {
    if (!isLoopbackTarget(m[1]!) && !isPublicHost(m[1]!)) return true;
  }
  return false;
}

/** Registries whose push is the audience of the credentials a release step holds. */
const PUBLIC_IMAGE_REGISTRIES = new Set([
  "docker.io", "index.docker.io", "registry-1.docker.io", "ghcr.io", "quay.io", "public.ecr.aws",
]);

/** `docker push` (or `podman`/`buildah push`) to a registry that is not a public one. */
function isImagePushEgress(segment: string): boolean {
  const m = /(?<![\w.-])(?:docker|podman|buildah)[^\S\n]+(?:image[^\S\n]+)?push\b/.exec(segment);
  if (!m) return false;
  for (const word of shellWords(segment.slice(m.index + m[0].length))) {
    if (word.startsWith("-")) continue;
    const first = word.split("/")[0]!;
    // A first component with a dot, a port or `localhost` is a registry host.
    if (!word.includes("/") || !/[.:]|^localhost$/.test(first)) return false;
    const host = first.replace(/:\d+$/, "").toLowerCase();
    return !isLoopbackTarget(host) && !PUBLIC_IMAGE_REGISTRIES.has(host);
  }
  return false;
}

/**
 * With a proxy set in the workflow (`HTTPS_PROXY: http://host`), a call to
 * loopback still leaves the runner through the proxy. With `sshAuthOnly`, an
 * `ssh`, `scp` or `rsync` connection is not egress (see secretsAreSshAuthOnly).
 */
function segmentHasEgress(raw: string, proxied: boolean, sshAuthOnly: boolean): boolean {
  const segment = unquoteWords(raw);
  if (isGitPushEgress(segment) || hasUrl(segment) || isImagePushEgress(segment)) return true;
  for (const m of segment.matchAll(FETCH_CALL_RE)) {
    if (proxied || m[2] === undefined || !isLoopbackTarget(m[2])) return true;
  }
  if (OTHER_EGRESS_RE.test(segment) || DNS_TOOL_RE.test(segment)) return true;
  if (!sshAuthOnly && (isRemoteCopy(segment) || isSshEgress(segment))) return true;
  const cmd = NET_CMD_RE.exec(segment);
  if (!cmd) return false;
  return proxied || !argsAreLoopbackOnly(segment.slice(cmd.index + cmd[0].length));
}

/** Does executed text (a run: or script: body, comments removed) send data out? */
function execTextHasEgress(text: string, proxied: boolean, sshAuthOnly = false): boolean {
  // Expressions are masked before the split: `${{ a || 'https://example.invalid' }}` is one
  // value, not two commands.
  const joined = text.replace(/\\\n/g, " ").replace(/\$\{\{[^}\n]{0,256}\}\}/g, "EXPR");
  for (const segment of joined.split(/&&|\|\||[;&|\n]/)) {
    if (segmentHasEgress(segment, proxied, sshAuthOnly)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// SSH authentication is not egress of the key
// ---------------------------------------------------------------------------

/** A reference to one stored secret by name: `secrets.X`, `secrets['X']`, `secrets["X"]`. */
const NAMED_SECRET_SOURCE = String.raw`secrets\s*(?:\.\s*[\w-]+|\[\s*(?:'[\w-]+'|"[\w-]+")\s*\])`;
/** An expression that is exactly one named secret and nothing else. */
const PLAIN_SECRET_EXPR_RE = new RegExp(String.raw`^\s*${NAMED_SECRET_SOURCE}\s*$`);
/**
 * One `VAR: ${{ secrets.X }}` entry of an `env:` mapping, block or flow form.
 * Group 1 is the variable. The value must be the expression alone.
 */
const ENV_SECRET_ENTRY_RE = new RegExp(
  String.raw`(?<![\w-])['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?[ \t]*:[ \t]*(['"]?)\$\{\{\s*${NAMED_SECRET_SOURCE}\s*\}\}\2[ \t]*(?=[,}]|$)`,
  "g",
);
/** The `ssh-private-key:` input of webfactory/ssh-agent, the value alone. */
const AGENT_KEY_INPUT_RE = new RegExp(
  String.raw`^[ \t]*['"]?ssh-private-key['"]?[ \t]*:[ \t]*(['"]?)\$\{\{\s*${NAMED_SECRET_SOURCE}\s*\}\}\1[ \t]*$`,
);
/** Stand-in for an inline `${{ secrets.X }}` in executed text, read as a variable. */
const INLINE_SECRET_VAR = "__SCG_STORED_SECRET__";
/** Words that can stand before a stage's command. */
const LEADING_WORDS = new Set(["if", "then", "elif", "else", "do", "while", "until", "!", "{", "(", "time", "sudo", "command"]);
/** Filters a key may pass through between its source and its file. */
const KEY_FILTERS = new Set(["tr", "base64", "sed", "cat"]);
/**
 * Commands that only handle a key file on the runner. None of them copies its
 * content anywhere (`install` and `cp` can, and are left out on purpose).
 */
const LOCAL_KEY_TOOLS = new Set([
  "chmod", "chown", "rm", "shred", "test", "[", "[[", "ssh-keygen", "ssh-add", "touch", "stat", "ls", "wc",
]);
/** More key files or secret variables than this, and the answer is no. Keeps the check linear. */
const MAX_SSH_AUTH_ITEMS = 8;
/** The ssh-family commands whose identity options name a key file. */
const SSH_FAMILY = new Set(["ssh", "scp", "sftp", "rsync"]);
/** An ssh option or ssh_config directive that names an authentication file. */
const AUTH_FILE_OPTION_RE = /^(?:-o[ \t]*)?(?:IdentityFile|UserKnownHostsFile|GlobalKnownHostsFile|CertificateFile)[ \t]*[= \t]/i;
/** A key ssh loads without `-i`, and the file of trusted host keys. */
const DEFAULT_AUTH_FILE_RE = /(?:^|\/)(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?|known_hosts)$/;

/** Does `word` expand one of `vars` (`$V`, `${V}`, `${V:-}`)? */
function expandsVar(word: string, vars: Set<string>): boolean {
  for (const m of word.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (vars.has(m[1]!)) return true;
  }
  return false;
}

/** The command of a stage: its words after leading keywords and `VAR=value` prefixes. */
function stageCommand(words: string[]): { cmd: string; at: number } {
  let at = 0;
  while (at < words.length && (LEADING_WORDS.has(words[at]!) || /^[A-Za-z_]\w*=/.test(words[at]!))) at++;
  return { cmd: (words[at] ?? "").replace(/^.*\//, ""), at };
}

/** The file a stage writes with `tee`, `>` or `>>` (in that order), or undefined. */
function stageWriteTarget(words: string[], cmd: string, at: number): string | undefined {
  if (cmd === "tee") return words.slice(at + 1).find((w) => !w.startsWith("-") && !w.startsWith(">"));
  for (let i = at; i < words.length; i++) {
    const w = words[i]!;
    if (w === ">" || w === ">>") return words[i + 1];
    if (/^>>?[^>&]/.test(w)) return w.replace(/^>>?/, "");
  }
  return undefined;
}

/** Does `word` name the file whose last path component is `base`? */
function namesFile(word: string, base: string): boolean {
  let from = 0;
  for (;;) {
    const at = word.indexOf(base, from);
    if (at < 0) return false;
    const before = at === 0 ? "" : word[at - 1]!;
    const after = word[at + base.length] ?? "";
    if (!/[\w.-]/.test(before) && !/[\w.-]/.test(after)) return true;
    from = at + 1;
  }
}

/**
 * An inline `run: cmd` line keeps its YAML key in the executed text; the
 * command starts after it. A quoted scalar loses its outer quotes.
 */
function stripRunKey(line: string): string {
  const m = /^[ \t]*(?:-[ \t]+)?['"]?(?:run|script)['"]?[ \t]*:[ \t]*/.exec(line);
  if (!m) return line;
  const value = line.slice(m[0].length).trimEnd();
  const q = value[0];
  return (q === "'" || q === '"') && value.length > 1 && value.endsWith(q) ? value.slice(1, -1) : value;
}

/** Normalize a path for comparison: `${V}` as `$V`, `~` as `$HOME`. */
function normalizePath(p: string): string {
  return p.replace(/\$\{([A-Za-z_]\w*)\}/g, "$$$1").replace(/^~(?=\/|$)/, "$HOME");
}

/**
 * Is `word`, at `index` in a stage of `cmd`, the key file used as an
 * authentication file: the value of `-i`, of an identity or known-hosts
 * option, or of rsync's `-e`/`--rsh` ssh command?
 *
 * The file is recognised by its name, not its whole path: a key written to
 * `"${key_dir}/deploy_key"` in one step is often used as
 * `-i "${DEPLOY_KEY_DIR}/deploy_key"` in the next, the directory handed over
 * through $GITHUB_ENV under another name. This opens nothing: every other
 * appearance of that file name (a copy, `cat`, `<`, an scp source) is matched
 * by name too, and still answers no.
 */
function isAuthFileUse(words: string[], index: number, cmd: string, key: string): boolean {
  const word = words[index]!;
  const prev = words[index - 1] ?? "";
  const base = key.replace(/^.*\//, "");
  const names = (value: string) => normalizePath(value).replace(/^.*\//, "") === base;
  if (prev === "-i" && names(word)) return true;
  if (/^-i[^ \t]/.test(word) && names(word.slice(2))) return true;
  if (AUTH_FILE_OPTION_RE.test(word) && names(word.replace(AUTH_FILE_OPTION_RE, ""))) return true;
  if (prev === "-o" && AUTH_FILE_OPTION_RE.test(word) && names(word.replace(AUTH_FILE_OPTION_RE, ""))) return true;
  if (cmd === "rsync" && (prev === "-e" || prev === "--rsh" || /^(?:-e|--rsh=)/.test(word))) {
    const inner = shellWords(word.replace(/^(?:-e|--rsh=)/, ""));
    return inner[0] === "ssh" && inner.some((_, k) => k > 0 && isAuthFileUse(inner, k, "ssh", key));
  }
  return false;
}

/**
 * Is every stored secret in this workflow used only as SSH authentication?
 * Then an `ssh`, `scp` or `rsync` connection does not send it anywhere: the
 * private key signs a challenge and stays on the runner, and a known_hosts
 * line is only compared. 6.3.0 counted every such connection to a host as
 * egress, so each push-to-deploy workflow whose only secret is its deploy key
 * was reported.
 *
 * Deliberately narrow. A secret counts only when every reference to it is
 *   - an `env:` entry `VAR: ${{ secrets.X }}` (block or flow form), and every
 *     expansion of VAR is a presence test (`[ -z "$VAR" ]`) or the source of a
 *     key write, or
 *   - inline in a key write, or
 *   - the `ssh-private-key:` input of webfactory/ssh-agent.
 * A key write is one pipeline: `printf` or `echo` of the value, through `tr`,
 * `base64`, `sed` or `cat` at most, into `> file`, `>> file`, `tee file` or
 * `ssh-add -`. Each file written that way may then appear only in a key write,
 * a local key tool (`chmod`, `rm`, `test`, `ssh-keygen`, ...), an ssh_config
 * `IdentityFile` line, or as the identity or known-hosts option of an
 * ssh/scp/sftp/rsync call, and it must be one that call authenticates with
 * (such an option, a default `~/.ssh/id_*` key, known_hosts, or `ssh-add`).
 * Anything else, such as `cat key`, `< key`, `scp key host:` or a variable in
 * the remote command, answers false, and ssh/scp/rsync count as before. So
 * does data piped into an ssh-family call, and a copy of a directory that
 * holds a key file (or of the workspace while a key sits in it).
 */
function secretsAreSshAuthOnly(text: string, stripped: string[], regions: WfRegion[], exec: string): boolean {
  const raw = text.split("\n");
  const vars = new Set<string>();
  let ast: WorkflowAst | undefined;
  for (let i = 0; i < raw.length; i++) {
    const region = regions[i];
    // Executed lines keep their text (the shell decides what a comment is
    // there); a YAML comment elsewhere is not a reference.
    const line = region === "exec" ? raw[i]! : (stripped[i] ?? "");
    if (!line.includes("${{") || !textHasStoredSecret(line)) continue;
    if (region === "env") {
      const secretExprs = [...line.matchAll(/\$\{\{([^}\n]{0,256})\}\}/g)].filter((m) => expressionUsesSecret(m[1]!, false));
      const entries = [...line.matchAll(ENV_SECRET_ENTRY_RE)];
      // Every secret expression on the line must be one whole `VAR: secret` entry.
      if (entries.length === 0 || entries.length !== secretExprs.length) return false;
      for (const e of entries) vars.add(e[1]!);
      if (vars.size > MAX_SSH_AUTH_ITEMS) return false;
    } else if (region === "exec") {
      // Inline in executed text: judged by the pipeline it sits in, below.
      for (const m of line.matchAll(/\$\{\{([^}\n]{0,256})\}\}/g)) {
        if (expressionUsesSecret(m[1]!, false) && !PLAIN_SECRET_EXPR_RE.test(m[1]!)) return false;
      }
    } else {
      if (!AGENT_KEY_INPUT_RE.test(line)) return false;
      try {
        ast ??= parseWorkflow(text);
      } catch {
        return false;
      }
      const steps = ast.jobs.flatMap((j) => j.steps).filter((s) => s.line <= i + 1);
      const owner = steps.reduce<WfStep | undefined>((a, s) => (a === undefined || s.line > a.line ? s : a), undefined);
      if (!owner?.uses || !/^webfactory\/ssh-agent@/i.test(owner.uses.trim())) return false;
    }
  }

  // `SendEnv`/`SetEnv` hand environment variables to the server by name, with
  // no `$VAR` in the text: a secret in the step's environment would leave.
  if (/(?<![\w-])(?:SendEnv|SetEnv)(?![\w-])/i.test(exec)) return false;

  const inline = exec
    .split("\n")
    .map(stripRunKey)
    .join("\n")
    .replace(/\$\{\{([^}\n]{0,256})\}\}/g, (_, e: string) =>
      expressionUsesSecret(e, false) ? `$${INLINE_SECRET_VAR}` : "EXPR");
  vars.add(INLINE_SECRET_VAR);
  const pipelines = inline
    .replace(/\\\n/g, " ")
    .split(/&&|\|\||;|\n|(?<![<>])&(?!>)/)
    .map((p) => p.split("|").map((stage) => shellWords(stage)));

  // Pass 1: every expansion of a secret variable is a presence test or a key
  // write, and every variable is written as a key at least once.
  const keyFiles = new Set<string>();
  const written = new Set<string>();
  for (const stages of pipelines) {
    const uses = stages.map((words) => words.some((w) => expandsVar(w, vars)));
    if (!uses.includes(true)) continue;
    const first = stageCommand(stages[0]!);
    const presence =
      stages.length === 1 && ["test", "[", "[["].includes(first.cmd) &&
      stages[0]!.every((w, k) => !expandsVar(w, vars) || stages[0]![k - 1] === "-z" || stages[0]![k - 1] === "-n");
    if (presence) continue;
    const markWritten = (words: string[]) => {
      for (const v of vars) if (words.some((w) => expandsVar(w, new Set([v])))) written.add(v);
    };
    if (!["printf", "echo"].includes(first.cmd) || uses.slice(1).includes(true)) {
      // `ssh-add - <<< "$VAR"`: the value goes to the agent, not to a file.
      const herestring = stages.length === 1 && first.cmd === "ssh-add" && stages[0]!.includes("-") &&
        stages[0]!.every((w, k) => !expandsVar(w, vars) || stages[0]![k - 1] === "<<<");
      if (!herestring) return false;
      markWritten(stages[0]!);
      continue;
    }
    for (let s = 1; s < stages.length; s++) {
      const { cmd } = stageCommand(stages[s]!);
      const last = s === stages.length - 1;
      if (KEY_FILTERS.has(cmd) || (last && (cmd === "tee" || cmd === "ssh-add"))) continue;
      return false;
    }
    const tail = stages[stages.length - 1]!;
    const { cmd, at } = stageCommand(tail);
    markWritten(stages[0]!);
    if (cmd === "ssh-add" && tail.includes("-")) continue;
    const target = stageWriteTarget(tail, cmd, at);
    if (target === undefined || target === "" || target.startsWith("/dev/")) return false;
    keyFiles.add(normalizePath(target));
    if (keyFiles.size > MAX_SSH_AUTH_ITEMS) return false;
  }
  // A secret in the environment that is never written as a key (unused, or only
  // tested for presence) can still be read by any process of its step: there
  // is no evidence it is only a key.
  for (const v of vars) if (v !== INLINE_SECRET_VAR && !written.has(v)) return false;

  // Pass 2: each key file is only written, handled locally, or authenticated
  // with, and at least one ssh-family call or ssh_config line uses it as such.
  const authenticated = new Set<string>();
  for (const key of keyFiles) {
    const base = key.replace(/^.*\//, "");
    if (DEFAULT_AUTH_FILE_RE.test(key)) authenticated.add(key);
    for (const stages of pipelines) {
      for (const words of stages) {
        const { cmd, at } = stageCommand(words);
        // Once per stage, not per word: a stage of many allowed uses stays linear.
        let writesKey: boolean | undefined;
        for (let k = 0; k < words.length; k++) {
          const w = words[k]!;
          if (!namesFile(w, base)) continue;
          // The key write itself: this word is the stage's own target.
          if (writesKey === undefined) {
            const target = stageWriteTarget(words, cmd, at);
            writesKey = target !== undefined && normalizePath(target) === key;
          }
          if (writesKey && normalizePath(w.replace(/^>>?/, "")) === key) continue;
          if (LOCAL_KEY_TOOLS.has(cmd)) {
            if (cmd === "ssh-add") authenticated.add(key);
            continue;
          }
          if (SSH_FAMILY.has(cmd) && isAuthFileUse(words, k, cmd, key)) {
            authenticated.add(key);
            continue;
          }
          // An ssh_config line in a heredoc: `IdentityFile <key>` or `IdentityFile=<key>`.
          const sameFile = (value: string) => normalizePath(value).replace(/^.*\//, "") === base;
          const directive = words.length === 2 && k === 1 && AUTH_FILE_OPTION_RE.test(`${words[0]} `) && sameFile(w);
          const joined = words.length === 1 && AUTH_FILE_OPTION_RE.test(w) && sameFile(w.replace(AUTH_FILE_OPTION_RE, ""));
          if (directive || joined) {
            authenticated.add(key);
            continue;
          }
          return false;
        }
      }
    }
  }
  for (const key of keyFiles) if (!authenticated.has(key)) return false;

  // Pass 3: a connection must not carry a key without naming it. A copy of a
  // directory that holds a key file (`rsync ./ host:`, `scp -r ~/.ssh host:`),
  // or such a directory packed and piped into the connection
  // (`tar c . | ssh host 'tar x'`), sends the key although its name never
  // appears. A key file or secret variable named upstream is already refused
  // by passes 1 and 2, so a pipe that feeds a script (`printf '%s' "$script"
  // | ssh host 'bash -s'`) stays allowed.
  const holdsKey = (w: string) => {
    const source = normalizePath(w).replace(/\/+$/, "");
    for (const key of keyFiles) if (copiesKey(source, key)) return true;
    return false;
  };
  for (const stages of pipelines) {
    // One pass: whether any stage before this one packed a key's directory.
    let upstreamHoldsKey = false;
    for (let s = 0; s < stages.length; s++) {
      const words = stages[s]!;
      const { cmd, at } = stageCommand(words);
      const feedsKey = upstreamHoldsKey;
      upstreamHoldsKey ||= words.some((w) => !w.startsWith("-") && holdsKey(w));
      if (!SSH_FAMILY.has(cmd)) continue;
      if (feedsKey) return false;
      if (cmd === "ssh") continue;
      for (let k = at + 1; k < words.length; k++) {
        const w = words[k]!;
        if ((cmd === "rsync" ? RSYNC_VALUE_FLAGS : SCP_VALUE_FLAGS).has(w)) {
          k++;
          continue;
        }
        if (w.startsWith("-") || REMOTE_PATH_WORD_RE.test(w)) continue;
        if (holdsKey(w)) return false;
      }
    }
  }
  return true;
}

/**
 * Options whose next word is a value, not a path to copy. Kept to the ones
 * certain to take one: a value flag missing here only makes its value checked
 * as a path (more findings), while a wrong entry would skip a real source.
 */
const SCP_VALUE_FLAGS = new Set(["-i", "-P", "-o", "-F", "-J", "-l", "-c", "-S"]);
const RSYNC_VALUE_FLAGS = new Set(["-e", "--rsh"]);

/**
 * Would copying `source` (a local path, normalized, no trailing slash) carry
 * the key file `key`? When it is a directory above the key, or the workspace
 * (`.`, `*`, `$GITHUB_WORKSPACE`) while the key is a relative path in it.
 */
function copiesKey(source: string, key: string): boolean {
  if (source === "" || source === key) return source === key;
  if (key.startsWith(`${source}/`)) return true;
  const relativeKey = !/^[/$~]/.test(key);
  const workspace = source === "." || source === "*" || /^\$GITHUB_WORKSPACE(?:\/\.?)?$/.test(source);
  return relativeKey && workspace;
}

/** A proxy variable set anywhere in the workflow, with its value in group 1. */
const PROXY_VAR_RE = /\b(?:https?|all|ftp)_proxy['"]?[ \t]*[:=][ \t]*['"]?([^\s'",}]+)/gi;

function hasOutboundProxy(text: string): boolean {
  for (const m of text.matchAll(PROXY_VAR_RE)) {
    if (!isLoopbackTarget(m[1]!)) return true;
  }
  return false;
}

/** A step written as a flow map on one line: `- { name: x, run: '...' }`. */
const FLOW_STEP_RE = /^[ \t]*-[ \t]*\{/;
const FLOW_RUN_KEY_RE = /[{,][ \t]*['"]?run['"]?[ \t]*:[ \t]*/;
const FLOW_UPLOAD_RE = /[{,][ \t]*['"]?uses['"]?[ \t]*:[ \t]*['"]?actions\/upload-artifact(?:@|\/|['"\s,}]|$)/i;

/** The `run:` value of a one-line flow-map step, outer quotes removed. */
function flowStepRun(line: string): string {
  const m = FLOW_RUN_KEY_RE.exec(line);
  if (!m) return "";
  const value = line.slice(m.index + m[0].length);
  const q = value[0];
  if (q === "'" || q === '"') {
    const close = value.lastIndexOf(q);
    return close > 0 ? value.slice(1, close) : value.slice(1);
  }
  return value;
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
 * One line with its shell comment removed: `#` at the start of a word and
 * followed by whitespace or the line end, outside quotes, not escaped. Linear
 * in the line.
 */
function stripShellComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === "\\" && quote !== "'") {
      i++;
    } else if (quote) {
      if (ch === quote) quote = "";
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (
      ch === "#" && (i === 0 || line[i - 1] === " " || line[i - 1] === "\t") &&
      (i + 1 === line.length || line[i + 1] === " " || line[i + 1] === "\t")
    ) {
      // Only `# text` is taken as a comment: a JavaScript private field in a
      // github-script body (`#p = fetch(...)`) is code. Leaving `#text` in
      // place can only add text to the check, never hide a command.
      return line.slice(0, i);
    }
  }
  return line;
}

/**
 * The rule's earlier condition, kept as a floor: a `secrets.` expression and a
 * network word or URL anywhere in the file. Every narrowing of it tried so far
 * missed a real exfiltration shape (a client in another language, a URL that
 * fools a host parser, a push to a repository someone else owns, a custom
 * `shell:`), so the finer check below only ever adds to it.
 */
function reportedBefore(content: string): boolean {
  return /\$\{\{\s*secrets\.\w+/.test(content) && /curl|wget|fetch|https?:\/\/|actions\/upload-artifact/.test(content);
}

/**
 * WORKFLOW_SECRET_TO_UPLOAD_PATH, a whole-file check: the earlier condition
 * (see reportedBefore), or a stored secret (not
 * the run's own token, and not one only tested for presence) and, in the same
 * workflow, an outbound call in executed text (`run:`, `script:`; shell
 * comments removed, loopback calls left out; any URL to a host other than
 * loopback, GitHub or a public registry counts) or an artifact upload. Which step holds
 * the secret is not modelled, so a secret in one step and a health check in
 * another are reported together; the finding asks for a review, not a verdict.
 * With `regions` false the whole text counts as executed: the fallback for a
 * file whose lines could not be classified.
 */
function checkSecretToEgress(content: string, file: string, relPath: string, regions = true): Finding[] {
  const text = content.replace(/\r/g, "");
  const stripped = stripYamlComments(text).split("\n");
  // Executed lines keep their shell text; only a shell comment is removed, with
  // quotes and backslash escapes honoured (`echo "a\" #"; curl ...` runs curl).
  const raw = text.split("\n");
  const flowSteps = raw.filter((l) => FLOW_STEP_RE.test(l));
  // Text that runs although it is not under a `run:` key: the anchored values
  // a `run: *alias` expands to, and the arguments of a `docker://` action,
  // which the image's entrypoint executes.
  const aliasRun = /^[ \t]*(?:-[ \t]+)?['"]?(?:run|script)['"]?[ \t]*:[ \t]*\*[\w-]/m.test(text);
  const dockerAction = /^[ \t]*(?:-[ \t]+)?uses:[ \t]*['"]?docker:\/\//m.test(text);
  const indirect = raw.filter(
    (l) => (aliasRun && /(?:^|[\s:,[{-])&[\w-]+[ \t]+\S/.test(l)) ||
      (dockerAction && /^[ \t]*['"]?(?:args|entrypoint)['"]?[ \t]*:/.test(l)),
  );
  const lineRegions = regions ? classifyWorkflowLines(text) : undefined;
  const exec = [
    (lineRegions ? linesText(raw, lineRegions, 0, raw.length, ["exec"]) : text),
    ...flowSteps.map(flowStepRun),
    ...indirect,
  ]
    .join("\n")
    .split("\n")
    .map(stripShellComment)
    .join("\n");
  const uploads =
    stripped.some((l) => /^[ \t]*(?:-[ \t]+)?uses:[ \t]*['"]?actions\/upload-artifact(?:@|\/|['"\s]|$)/i.test(l)) ||
    flowSteps.some((l) => FLOW_UPLOAD_RE.test(l));
  // The secret and the proxy are looked for in the raw text: a YAML comment
  // heuristic that disagrees with the shell's quoting could hide either one
  // (`echo "a\" #"; curl -d "${{ secrets.K }}" ...`), and a secret written only
  // in a comment costs no more than a review.
  // Outbound calls in executed text. An ssh, scp or rsync connection is left out
  // when every stored secret is only its authentication (secretsAreSshAuthOnly);
  // that is asked only when such a connection is what decides, and never for an
  // unclassified file.
  const egress = (): boolean => {
    const proxied = hasOutboundProxy(text);
    if (!execTextHasEgress(exec, proxied)) return false;
    if (!lineRegions || execTextHasEgress(exec, proxied, true)) return true;
    return !secretsAreSshAuthOnly(text, stripped, lineRegions, exec);
  };
  if (!reportedBefore(content) && (!textHasStoredSecret(text) || !(uploads || egress()))) {
    return [];
  }
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
      try {
        for (const f of checkSecretToEgress(content, file, relPath, false)) findings.push(f);
      } catch {
        /* neither reading worked: the release-path check below still runs */
      }
    }
    {

      // Check for untrusted actions in release paths.
      // v5.2.23: the unpinned-action check is scoped to actual `uses:`
      // declarations. The earlier regex `/@(?:main|master|latest|dev)\b/`
      // matched any occurrence anywhere in the file - including
      // `npm install -g npm@latest`, which is a Node toolchain install
      // step, not a GitHub Action reference. New regex requires the
      // `uses: <path>@<branch>` form.
      const isReleasePath = /release|publish|deploy/.test(content);
      const hasUnpinnedAction = /^[ \t]*(?:-[ \t]+)?uses:[ \t]+\S+@(?:main|master|latest|dev)\b/im.test(content);

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
