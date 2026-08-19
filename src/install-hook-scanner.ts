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

/** Names of agent host runtimes and their internal hook symbols. */
const HOST_RUNTIME_RE =
  /\b(?:openclaw|hermes|claude[-_ ]?code|claude[-_ ]?desktop|cursor|windsurf|cline|roo[-_ ]?code|aider|continue\.dev)\b|after[-_]tool[-_]call|before[-_]tool[-_]call|hook[-_ ]?event|tool[-_ ]?call[-_ ]?message|dispatch-[\w-]*\.(?:js|mjs|cjs)/i;

/** A write into another agent runtime's installed code or config directory. */
const HOST_RUNTIME_PATH_RE =
  /node_modules[\\/][^\s'"]*(?:openclaw|hermes)|[~./][\w./-]*\.(?:openclaw|claude|cursor|windsurf|hermes)\b/i;

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
    if (/(?:curl|wget|fetch).*(?:chmod\s+\+x|exec|spawn|child_process|\.\/|bash|sh\s|node\s)/i.test(script) ||
        /(?:exec|spawn).*(?:curl|wget|fetch)/i.test(script)) {
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
      (HOST_RUNTIME_RE.test(script) || HOST_RUNTIME_PATH_RE.test(script)) &&
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
