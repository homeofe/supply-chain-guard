/**
 * Install hook deep analysis scanner (v4.2).
 *
 * Goes beyond basic SUSPICIOUS_SCRIPTS patterns to detect sophisticated
 * install-time attacks: secret harvesting, download-exec chains,
 * obfuscated one-liners, and embedded binary blobs.
 */

import type { Finding } from "./types.js";
import {
  AUTO_RUN_LIFECYCLE_HOOKS,
  type AutoRunLifecycleHook,
} from "./patterns.js";

// ── INSTALL_HOOK_HOST_RUNTIME_PATCH detection ───────────────────────────────
// An install hook that patches/mutates a HOST AGENT RUNTIME (OpenClaw, Hermes,
// Claude Code, ...) - rewriting another installed package's code so the plugin
// can hook into it (e.g. intercept after-tool-call messages). Fires ONLY on the
// combination of a runtime target AND a code-mutation action, so ordinary build
// hooks (node scripts/build.js, npm run build, tsc, patch-package) never match.

// The three host-runtime checks below replace two regular expressions that were
// quadratic on a crafted hook string (CodeQL js/polynomial-redos, measured at
// minutes for a few hundred KB). Each is exact: property-parsers.test.ts runs
// the original expression as the oracle. The shared idea is that every later
// start inside the same run of path characters reaches the same run end as the
// first, so a failed attempt can resume at the run end.

/** Names of agent host runtimes and their internal hook symbols (the linear part). */
const HOST_RUNTIME_WORDS_RE =
  /\b(?:openclaw|hermes|claude[-_ ]?code|claude[-_ ]?desktop|cursor|windsurf|cline|roo[-_ ]?code|aider|continue\.dev)\b|after[-_]tool[-_]call|before[-_]tool[-_]call|hook[-_ ]?event|tool[-_ ]?call[-_ ]?message/i;

const WORD_OR_DASH = /[\w-]/;
const DISPATCH_RE = /dispatch-/gi;

/**
 * `HOST_RUNTIME_WORDS_RE` or `dispatch-[\w-]*\.(?:js|mjs|cjs)` (case-insensitive).
 */
export function mentionsHostRuntime(text: string): boolean {
  if (HOST_RUNTIME_WORDS_RE.test(text)) return true;
  DISPATCH_RE.lastIndex = 0;
  for (let m = DISPATCH_RE.exec(text); m; m = DISPATCH_RE.exec(text)) {
    let j = m.index + m[0].length;
    while (j < text.length && WORD_OR_DASH.test(text[j]!)) j++;
    if (/^\.(?:js|mjs|cjs)/i.test(text.slice(j, j + 4))) return true;
    DISPATCH_RE.lastIndex = Math.max(j, m.index + 1);
  }
  return false;
}

const NODE_MODULES_RE = /node_modules[\\/]/gi;
const PATH_STOP = /[\s'"]/;
const PATH_RUN_RE = /[\w./-]+/g;
const RUNTIME_DIR_RE = /\.(?:openclaw|claude|cursor|windsurf|hermes)\b/gi;

/**
 * A write into another agent runtime's installed code or config directory:
 * `node_modules[\\/][^\s'"]*(?:openclaw|hermes)` or
 * `[~./][\w./-]*\.(?:openclaw|claude|cursor|windsurf|hermes)\b` (case-insensitive).
 */
export function mentionsHostRuntimePath(text: string): boolean {
  NODE_MODULES_RE.lastIndex = 0;
  for (let m = NODE_MODULES_RE.exec(text); m; m = NODE_MODULES_RE.exec(text)) {
    const start = m.index + m[0].length;
    let j = start;
    while (j < text.length && !PATH_STOP.test(text[j]!)) j++;
    if (/openclaw|hermes/i.test(text.slice(start, j))) return true;
    NODE_MODULES_RE.lastIndex = Math.max(j, m.index + 1);
  }
  // The second form needs a start character ("~", ".", "/") before the
  // ".<runtime>" it ends in, inside one run of [\w./-]. "~" is not in that set,
  // so it can only sit directly before a run.
  PATH_RUN_RE.lastIndex = 0;
  for (let run = PATH_RUN_RE.exec(text); run; run = PATH_RUN_RE.exec(text)) {
    const r = run[0];
    const tilde = run.index > 0 && text[run.index - 1] === "~";
    const firstStart = r.search(/[./]/);
    RUNTIME_DIR_RE.lastIndex = 0;
    for (let n = RUNTIME_DIR_RE.exec(r); n; n = RUNTIME_DIR_RE.exec(r)) {
      if (tilde || (firstStart >= 0 && firstStart < n.index)) return true;
      RUNTIME_DIR_RE.lastIndex = n.index + 1;
    }
  }
  return false;
}

const LINE_BREAK_RE = new RegExp("[\\n\\r" + String.fromCharCode(0x2028, 0x2029) + "]", "g");

/**
 * Whether `first` occurs with `then` starting later on the same line: the
 * linear form of `/(?:first).*(?:then)/i`. "." stops at a line break, but the
 * `then` match may run past one (`sh\s` matches "sh\n"), so the text is not
 * split into lines: a `then` match only has to START before the line ends.
 * The leftmost `first` on a line leaves the longest rest of the line, so a
 * line whose leftmost `first` fails cannot succeed with a later one. Both
 * expressions must carry the `g` flag.
 */
export function occursThenOnSameLine(text: string, first: RegExp, then: RegExp): boolean {
  let pos = 0;
  let nextThen = -1;
  while (pos <= text.length) {
    first.lastIndex = pos;
    const m = first.exec(text);
    if (!m) return false;
    const start = m.index + m[0].length;
    LINE_BREAK_RE.lastIndex = start;
    const lineEnd = LINE_BREAK_RE.exec(text)?.index ?? text.length;
    if (nextThen < start) {
      then.lastIndex = start;
      nextThen = then.exec(text)?.index ?? Number.POSITIVE_INFINITY;
    }
    if (nextThen <= lineEnd) return true;
    pos = lineEnd + 1;
  }
  return false;
}

const DOWNLOAD_RE = /curl|wget|fetch/gi;
const EXECUTE_AFTER_DOWNLOAD_RE = /chmod\s+\+x|exec|spawn|child_process|\.\/|bash|sh\s|node\s/gi;
const EXECUTE_RE = /exec|spawn/gi;
const DOWNLOAD_AFTER_EXECUTE_RE = /curl|wget|fetch/gi;

/**
 * A download followed by an execution on the same line, or the reverse: the
 * linear form of `/(?:curl|wget|fetch).*(?:chmod\s+\+x|exec|spawn|child_process
 * |\.\/|bash|sh\s|node\s)/i` or `/(?:exec|spawn).*(?:curl|wget|fetch)/i`.
 */
export function hasDownloadExecChain(script: string): boolean {
  return (
    occursThenOnSameLine(script, DOWNLOAD_RE, EXECUTE_AFTER_DOWNLOAD_RE) ||
    occursThenOnSameLine(script, EXECUTE_RE, DOWNLOAD_AFTER_EXECUTE_RE)
  );
}

/** A code MUTATION (not build-output generation): patch/inject/rewrite/sed -i. */
const CODE_MUTATE_RE =
  /\b(?:patch|inject|mutate|overwrite|rewrite|monkey[-\s]?patch|codemod)\b|\bsed\s+-i\b|\.patch(?:\.sh)?\b/i;

// ── INSTALL_HOOK_PERSISTENCE_WRITE detection ────────────────────────────────
// An install hook that registers code to run AGAIN LATER, independently of the
// package being installed: a launchd agent, a systemd unit, a cron entry, a
// scheduled task, a Windows Run key, a Startup-folder entry, or a Python .pth
// that the interpreter auto-imports.
//
// Scoped deliberately to the package.json lifecycle-script strings this module
// already reads - AUTO_RUN_LIFECYCLE_HOOKS, the same list npm-scanner.ts and
// scanner.ts use. That is the whole reason its false-positive surface is small:
// installing persistence from an install hook has essentially no legitimate
// form, whereas the same commands in ordinary source belong to any service
// manager, installer or devops tool and would false-positive constantly.
//
// It also means the check only sees the hook STRING. A hook that shells out to
// `node scripts/configure.js` hides the call completely, so this raises the cost
// of the attack rather than closing it. Said plainly in the CHANGELOG too.
//
// Each alternative is specific enough to stand alone, or pairs two required
// parts (`schtasks` with `/create`, `site-packages` with `.pth`). Gaps are
// bounded so the expression cannot backtrack pathologically on a long one-liner.

/** Registration of a persistence mechanism with the operating system. */
const PERSISTENCE_WRITE_RE =
  /\blaunchctl\b|\bsystemctl\b[^\n]{0,40}\b(?:enable|link)\b|\bcrontab\b|\bschtasks\b[^\n]{0,60}\/create\b|Library[\\/]+Launch(?:Agents|Daemons)|\.config[\\/]+systemd[\\/]+user|\/etc\/systemd\/system|\/etc\/cron\.[a-z]+|Start\s?Menu[\\/]+Programs[\\/]+Startup|CurrentVersion[\\/]+Run\b|site-packages[^\n]{0,80}\.pth\b/i;

/**
 * Derived from AUTO_RUN_LIFECYCLE_HOOKS rather than hand-listed, so adding a
 * hook to that list cannot leave this scanner reading a stale subset.
 */
type InstallScripts = Partial<Record<AutoRunLifecycleHook, string>>;

/**
 * Deep-analyze install hook scripts from package.json.
 */
export function analyzeInstallHooks(
  scripts: InstallScripts,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const hookNames = AUTO_RUN_LIFECYCLE_HOOKS;

  for (const hook of hookNames) {
    const script = scripts[hook];
    if (!script) continue;

    // Network access in install scripts
    if (/(?:fetch|https?\.(?:get|request|post)|axios|got|node-fetch|urllib|curl|wget)\b/i.test(script)) {
      findings.push({
        rule: "INSTALL_HOOK_NETWORK",
        description: `${hook} script makes network requests. Install scripts should not access the network.`,
        severity: "critical",
        file: relativePath,
        match: truncate(`${hook}: ${script}`),
        confidence: 0.9,
        category: "supply-chain",
        recommendation: "Remove network calls from install scripts. Use explicit build steps instead.",
      });
    }

    // Download + execute chain
    if (hasDownloadExecChain(script)) {
      findings.push({
        rule: "INSTALL_HOOK_DOWNLOAD_EXEC",
        description: `${hook} script downloads and executes code. This is the #1 supply-chain attack vector.`,
        severity: "critical",
        file: relativePath,
        match: truncate(`${hook}: ${script}`),
        confidence: 0.95,
        category: "malware",
        recommendation: "Never download and execute code during npm install. This is almost certainly malicious.",
      });
    }

    // Registering OS-level persistence from an install hook
    if (PERSISTENCE_WRITE_RE.test(script)) {
      findings.push({
        rule: "INSTALL_HOOK_PERSISTENCE_WRITE",
        description: `${hook} script registers OS-level persistence (launchd, systemd, cron, a scheduled task, a Run key, a Startup entry, or an auto-imported .pth). Installing a package should not schedule code to run again later, and this is how a one-shot credential stealer becomes a permanent re-harvester.`,
        severity: "high",
        file: relativePath,
        match: truncate(`${hook}: ${script}`),
        confidence: 0.8,
        category: "malware",
        recommendation: "Do not let a package install persistence at install time. Install with --ignore-scripts, inspect what the hook schedules, and remove any launchd/systemd/cron entry it already created. Background services should be an explicit, user-invoked step.",
      });
    }

    // Host agent runtime patch/mutation (e.g. OpenClaw after-tool-call patching)
    if (
      (mentionsHostRuntime(script) || mentionsHostRuntimePath(script)) &&
      CODE_MUTATE_RE.test(script)
    ) {
      findings.push({
        rule: "INSTALL_HOOK_HOST_RUNTIME_PATCH",
        description: `${hook} script patches or mutates a host agent runtime (OpenClaw/Hermes/Claude Code) during installation. Rewriting another installed package's code to hook into it is a distinct supply-chain risk - it can silently intercept tool calls, conversation messages, or credentials inside the host agent.`,
        severity: "high",
        file: relativePath,
        match: truncate(`${hook}: ${script}`),
        confidence: 0.8,
        category: "supply-chain",
        recommendation: "Do not let a package modify the host agent runtime at install time. Review exactly what the patch changes (tool-call hooks, message capture), install with --ignore-scripts, and inspect any scripts/*.patch.sh before trusting the package. Runtime integration should be an explicit, user-invoked step, not a silent postinstall.",
      });
    }

    // Environment variable harvesting (secrets)
    if (/process\.env\.(?:AWS|GITHUB|NPM|GH_|AZURE|GCP|DOCKER|CI|TRAVIS|CIRCLE|JENKINS|SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)/i.test(script)) {
      findings.push({
        rule: "INSTALL_HOOK_ENV_HARVEST",
        description: `${hook} script accesses sensitive environment variables (secrets, tokens, keys).`,
        severity: "critical",
        file: relativePath,
        match: truncate(`${hook}: ${script}`),
        confidence: 0.85,
        category: "supply-chain",
        recommendation: "Install scripts should never read CI/CD secrets or API tokens.",
      });
    }

    // .npmrc / credential file access
    if (/\.npmrc|npm_config_|_authToken|\.ssh[/\\]|id_rsa|id_ed25519|\.gnupg|\.aws\/credentials/i.test(script)) {
      findings.push({
        rule: "INSTALL_HOOK_NPMRC_READ",
        description: `${hook} script accesses credential files (.npmrc, SSH keys, AWS credentials).`,
        severity: "critical",
        file: relativePath,
        match: truncate(`${hook}: ${script}`),
        confidence: 0.9,
        category: "malware",
        recommendation: "Install scripts must not read credential files. This is credential theft.",
      });
    }

    // .env file access
    if (/\.env\b|dotenv|require\s*\(\s*['"]dotenv/i.test(script)) {
      findings.push({
        rule: "INSTALL_HOOK_DOTENV_READ",
        description: `${hook} script reads .env files. Environment files contain secrets.`,
        severity: "high",
        file: relativePath,
        match: truncate(`${hook}: ${script}`),
        confidence: 0.7,
        category: "supply-chain",
        recommendation: "Install scripts should not load .env files.",
      });
    }

    // Obfuscated script content
    if (/(?:atob|btoa|Buffer\.from|decodeURIComponent|unescape|String\.fromCharCode)\s*\(/i.test(script)) {
      findings.push({
        rule: "INSTALL_HOOK_OBFUSCATED",
        description: `${hook} script contains encoding/decoding operations. Obfuscated install scripts are a strong malware indicator.`,
        severity: "high",
        file: relativePath,
        match: truncate(`${hook}: ${script}`),
        confidence: 0.8,
        category: "malware",
        recommendation: "Decode the obfuscated content and inspect it before running npm install.",
      });
    }

    // Long one-liner (> 500 chars)
    if (script.length > 500 && !script.includes("\n")) {
      findings.push({
        rule: "INSTALL_HOOK_LONG_ONELINER",
        description: `${hook} script is a ${script.length}-character one-liner. Long single-line scripts are often obfuscated malware.`,
        severity: "medium",
        file: relativePath,
        match: truncate(`${hook}: ${script}`),
        confidence: 0.6,
        category: "supply-chain",
        recommendation: "Review this script carefully. Legitimate build scripts are rarely this long on one line.",
      });
    }

    // Embedded binary blob (base64 > 1KB)
    const b64Match = script.match(/[A-Za-z0-9+/=]{1000,}/);
    if (b64Match) {
      findings.push({
        rule: "INSTALL_HOOK_BINARY_BLOB",
        description: `${hook} script contains an embedded binary blob (${b64Match[0].length} chars). Likely an encoded executable payload.`,
        severity: "high",
        file: relativePath,
        match: truncate(`${hook}: ${b64Match[0].substring(0, 60)}...`),
        confidence: 0.85,
        category: "malware",
        recommendation: "Decode this base64 blob and inspect it. Embedded payloads in install scripts are malware.",
      });
    }
  }

  return findings;
}

/**
 * Extract install scripts from parsed package.json content.
 */
export function extractInstallScripts(
  content: string,
): InstallScripts | null {
  try {
    const pkg = JSON.parse(content) as { scripts?: Record<string, string> };
    if (!pkg.scripts) return null;
    const scripts: InstallScripts = {};
    for (const hook of AUTO_RUN_LIFECYCLE_HOOKS) {
      const value = pkg.scripts[hook];
      if (typeof value === "string") scripts[hook] = value;
    }
    return scripts;
  } catch {
    return null;
  }
}

function truncate(s: string, max = 120): string {
  return s.length > max ? s.substring(0, max) + "..." : s;
}
