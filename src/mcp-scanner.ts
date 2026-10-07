/**
 * MCP (Model Context Protocol) server configuration scanner.
 *
 * MCP servers are configured in JSON files checked into repos
 * (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json,
 * .gemini/settings.json) and launched automatically by AI coding agents.
 * That makes them a supply-chain attack surface: a malicious server package
 * (postmark-mcp 1.0.16 was the first documented hostile MCP server;
 * Shai-Hulud 2.0 targeted mcp-server npm packages), a C2-controlled remote
 * endpoint, or a prompt-injection payload in a tool description all execute
 * with the agent's privileges.
 *
 * Checks per configured server:
 * - command/args launching packages (npx/uvx/python -m/node) matched against
 *   the threat-intel feed and the known-bad-version blocklist
 * - remote "url" endpoints matched against the C2/IOC blocklist
 * - plain-http (non-localhost) endpoints
 * - credential-looking env vars forwarded to servers
 * - prompt-injection tokens in description/instructions strings
 * - npx -y with an unpinned package (mutable server, rug-pull enabler)
 *
 * Future work (not in this version): stateful baseline tracking of server
 * definitions across scans to detect rug-pulls - a server whose package
 * version, command, or URL silently changed since the last scan. Requires
 * persisting a baseline like continuous-monitor.ts does for risk history.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import {
  loadThreatIntel,
  matchPackageIOC,
  splitPackageIOCValue,
  type FeedIOC,
} from "./threat-intel.js";
import { checkBadVersion, checkIOCBlocklist } from "./ioc-blocklist.js";
import { PROMPT_INJECTION_PATTERNS } from "./patterns.js";
import { matchPatternInSemanticText, recordUnreadablePath } from "./pattern-scanner.js";

/** MCP config file locations, relative to the scanned directory (never the user home). */
export const MCP_CONFIG_FILES: string[] = [
  ".mcp.json",
  ".cursor/mcp.json",
  ".vscode/mcp.json",
  "claude_desktop_config.json",
  ".gemini/settings.json",
];

/** Env var names that look like forwarded credentials. */
const CREDENTIAL_ENV_REGEX = /TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL/i;

/** Hostnames that are local-only and safe to reach over plain http. */
const LOCALHOST_NAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"]);

interface McpServerEntry {
  command?: unknown;
  args?: unknown;
  url?: unknown;
  env?: unknown;
}

/**
 * Check whether the directory contains any MCP config file.
 */
export function hasMcpConfigFiles(dir: string): boolean {
  return MCP_CONFIG_FILES.some((rel) =>
    fs.existsSync(path.join(dir, ...rel.split("/"))),
  );
}

/**
 * Scan all MCP config files in a directory.
 */
export function scanMcpConfigs(dir: string, feed?: FeedIOC[]): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();

  for (const rel of MCP_CONFIG_FILES) {
    const fullPath = path.join(dir, ...rel.split("/"));
    if (!fs.existsSync(fullPath)) continue;
    try {
      const content = fs.readFileSync(fullPath, "utf-8");
      for (const pushed of scanMcpConfigContent(content, rel, iocFeed)) findings.push(pushed);
    } catch {
      // An unreadable MCP config is a coverage gap, never a clean file.
      recordUnreadablePath(findings, rel);
    }
  }

  return findings;
}

/**
 * Scan the content of a single MCP config file.
 */
export function scanMcpConfigContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(stripJsonc(content)) as Record<string, unknown>;
  } catch {
    // A recognised MCP config that does not parse is a file whose servers were
    // never looked at. Report the gap instead of an empty, clean-looking result.
    recordUnreadablePath(findings, relativePath);
    return findings;
  }
  if (!parsed || typeof parsed !== "object") return findings;

  // .mcp.json / claude_desktop_config.json / .gemini/settings.json use
  // "mcpServers"; .vscode/mcp.json uses "servers". Read both and merge: an
  // empty or non-object "mcpServers" must not hide a populated "servers".
  const serverEntries: Array<[string, unknown]> = [];
  for (const key of ["mcpServers", "servers"]) {
    const group = parsed[key];
    if (!group || typeof group !== "object" || Array.isArray(group)) continue;
    for (const pair of Object.entries(group)) serverEntries.push(pair);
  }

  for (const [serverName, entryRaw] of serverEntries) {
    if (!entryRaw || typeof entryRaw !== "object") continue;
    const entry = entryRaw as McpServerEntry;

    const command = typeof entry.command === "string" ? entry.command : undefined;
    const args = Array.isArray(entry.args)
      ? entry.args.filter((a): a is string => typeof a === "string")
      : [];
    const url = typeof entry.url === "string" ? entry.url : undefined;

    // 1. Malicious server package (threat-intel feed + known-bad versions)
    if (command) {
      for (const spec of packagesOfServer(command, args)) {
        const shown = `${spec.name}${spec.version ? `@${spec.version}` : spec.range ? `@${spec.range}` : ""}`;
        // Exact pin (or none): the feed's own matchers. The bare-name matcher
        // holds npm entries only, so it must not answer for a PyPI package.
        let ioc =
          matchPackageIOC(spec.ecosystem, spec.name, spec.version, iocFeed) ??
          (spec.ecosystem === "npm"
            ? matchUnprefixedPackageIOC(spec.name, spec.version, iocFeed)
            : null);
        let viaRange = false;
        if (!ioc && spec.range) {
          // A dist-tag or range names every version it can resolve to, so a
          // feed entry pinning one of them is a hit even though the launcher
          // does not spell that version out.
          ioc = matchPinnedIOCInRange(spec.ecosystem, spec.name, spec.range, iocFeed);
          viaRange = ioc !== null;
        }
        if (ioc) {
          findings.push({
            rule: "MCP_MALICIOUS_SERVER_PACKAGE",
            description: viaRange
              ? `MCP server "${serverName}" launches ${shown}, which can resolve to known malicious package ${ioc.value}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`
              : `MCP server "${serverName}" launches known malicious package ${shown}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
            severity: viaRange ? "high" : "critical",
            file: relativePath,
            match: truncate(`${command} ${args.join(" ")}`),
            confidence: viaRange ? Math.min(ioc.confidence, 0.6) : ioc.confidence,
            category: "malware",
            recommendation: `Remove the "${serverName}" server entry immediately${viaRange ? " or pin an audited version that is not listed" : ""}. The package matches a threat-intelligence IOC. Rotate any credentials the server had access to.`,
          });
        }

        if (spec.version) {
          const bad = checkBadVersion(spec.name, spec.version, spec.ecosystem);
          if (bad) {
            findings.push({
              rule: "MCP_MALICIOUS_SERVER_PACKAGE",
              description: `MCP server "${serverName}" launches known compromised package version: ${bad.description}`,
              severity: "critical",
              file: relativePath,
              match: truncate(`${command} ${args.join(" ")}`),
              confidence: 1.0,
              category: "malware",
              recommendation: bad.recommendation,
            });
          }
        }

        // 5. npx -y with an unpinned package (hygiene)
        if (
          spec.ecosystem === "npm" &&
          (!spec.version && (!spec.range || spec.range === "latest")) &&
          args.some((a) => a === "-y" || a === "--yes")
        ) {
          findings.push({
            rule: "MCP_UNPINNED_SERVER",
            description: `MCP server "${serverName}" runs "npx -y ${spec.name}" without a pinned version. Every agent start silently installs whatever version is latest on the registry.`,
            severity: "low",
            file: relativePath,
            match: truncate(`${command} ${args.join(" ")}`),
            confidence: 0.9,
            category: "supply-chain",
            recommendation: `Pin the server package to an audited version (npx -y ${spec.name}@x.y.z) so a hijacked release cannot auto-install.`,
          });
        }
      }
    }

    // 2. Remote url endpoints: C2 blocklist + plain http
    if (url) {
      const iocHits = checkIOCBlocklist(url, relativePath);
      if (iocHits.length > 0) {
        findings.push({
          rule: "MCP_C2_ENDPOINT",
          description: `MCP server "${serverName}" points at a known-malicious endpoint: ${iocHits[0]!.description}`,
          severity: "critical",
          file: relativePath,
          match: truncate(url),
          confidence: 0.95,
          category: "malware",
          recommendation: `Remove the "${serverName}" server entry immediately. The endpoint matches the C2/IOC blocklist. Assume any data sent to it is compromised.`,
        });
      } else if (isPlainRemoteEndpoint(url)) {
        findings.push({
          rule: "MCP_HTTP_ENDPOINT",
          description: `MCP server "${serverName}" uses a plain-http remote endpoint (${url}). Tool calls and credentials travel unencrypted and can be tampered with in transit.`,
          severity: "medium",
          file: relativePath,
          match: truncate(url),
          confidence: 0.8,
          category: "config",
          recommendation: "Switch the MCP server URL to https, or bind the server to localhost if it is meant to run locally.",
        });
      }
    }

    // 3. Credential-looking env vars forwarded to the server
    if (entry.env && typeof entry.env === "object" && !Array.isArray(entry.env)) {
      const secretVars = Object.keys(entry.env).filter((k) =>
        CREDENTIAL_ENV_REGEX.test(k),
      );
      if (secretVars.length > 0) {
        const remote = url !== undefined;
        findings.push({
          rule: "MCP_ENV_SECRET_TO_REMOTE",
          description: `MCP server "${serverName}" receives credential-looking env var${secretVars.length > 1 ? "s" : ""} (${secretVars.join(", ")})${remote ? ` and talks to a remote endpoint (${url})` : " via its local command"}.`,
          severity: remote ? "medium" : "low",
          file: relativePath,
          match: truncate(secretVars.join(", ")),
          confidence: remote ? 0.7 : 0.5,
          category: "config",
          recommendation: remote
            ? "Verify the remote endpoint is trusted before forwarding secrets. A hostile MCP server can exfiltrate every env var it receives."
            : "Verify the launched server package is trusted and pinned. Forwarded secrets are readable by the server process.",
        });
      }
    }

    // 4. Prompt-injection tokens in description/instructions strings
    for (const { key, value } of collectInstructionStrings(entryRaw as Record<string, unknown>)) {
      const hit = matchPromptInjection(value, relativePath, findings);
      if (hit) {
        findings.push({
          rule: "MCP_TOOL_DESCRIPTION_INJECTION",
          description: `MCP server "${serverName}" embeds a prompt-injection payload in its "${key}" string: ${hit.description}`,
          severity: "high",
          file: relativePath,
          match: truncate(value),
          confidence: 0.85,
          category: "supply-chain",
          recommendation: "Remove the injected instruction text. MCP descriptions are fed verbatim to the AI agent and can hijack its behavior (tool poisoning).",
        });
        break; // one finding per server entry is enough signal
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Package spec extraction
// ---------------------------------------------------------------------------

interface PackageSpec {
  ecosystem: "npm" | "pypi";
  name: string;
  /** Exact version the launcher pins. */
  version?: string;
  /**
   * A dist-tag or range instead of an exact version (`latest`, `^1.0.16`,
   * `>=1,<2`). It names every version it may resolve to, so a feed entry that
   * pins one of them is a hit.
   */
  range?: string;
}

/** Wrappers can nest (`cmd /c sh -c "env X=1 npx ..."`); bound the unwrapping. */
const MAX_UNWRAP_DEPTH = 6;

function baseCommandName(command: string): string {
  // Normalize "C:\\...\\npx.cmd" / "/usr/local/bin/npx" -> "npx" on any host OS.
  return path
    .basename(command.replace(/\\/g, "/"))
    .replace(/\.(exe|cmd|bat|ps1)$/i, "")
    .toLowerCase();
}

/** Split a shell command line into words, honouring simple quotes. */
function shellWords(text: string): string[] {
  const words: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) words.push(m[1] ?? m[2] ?? m[3] ?? "");
  return words;
}

/**
 * The packages a whole command line launches. Segments chained with `&&`,
 * `||`, `;` or `|` are each unwrapped; leading `NAME=value` assignments are
 * not part of the command.
 */
function packagesOfCommandLine(text: string, depth: number): PackageSpec[] {
  const out: PackageSpec[] = [];
  for (const segment of text.split(/&&|\|\||[;|&\n]/)) {
    const words = shellWords(segment);
    while (words.length > 0 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[0]!)) words.shift();
    if (words.length === 0) continue;
    for (const spec of extractPackageSpecs(words[0]!, words.slice(1), depth + 1)) out.push(spec);
  }
  return out;
}

const SHELL_WRAPPERS = new Set(["sh", "bash", "zsh", "dash", "ash", "ksh", "fish"]);
const TRANSPARENT_PREFIXES = new Set(["exec", "nohup", "command", "time", "nice", "sudo"]);

/** First non-flag argument and the arguments after it (subcommand split). */
function splitSubcommand(
  args: string[],
  valueFlags: ReadonlySet<string>,
): { sub: string | undefined; rest: string[] } {
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith("-")) {
      if (valueFlags.has(a)) i++;
      continue;
    }
    return { sub: a, rest: args.slice(i + 1) };
  }
  return { sub: undefined, rest: [] };
}

const NPX_VALUE_FLAGS: ReadonlySet<string> = new Set([
  "--registry", "--cache", "--userconfig", "--prefix", "--loglevel", "--node-options",
  "--workspace", "-w", "--call", "-c", "--shell", "--otp", "--tag",
]);
const NPX_PACKAGE_FLAGS: ReadonlySet<string> = new Set(["--package", "-p"]);

/**
 * npx / `npm exec` / `pnpm dlx` / `yarn dlx` / `bun x` argument list. The value
 * of a value-taking flag is never the package, and `--package <pkg>` makes the
 * flag value the package (the positional is then the executable to run).
 */
function packagesOfNpxArgs(args: string[]): string[] {
  const packages: string[] = [];
  let positional: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") {
      if (positional === undefined && i + 1 < args.length) positional = args[i + 1];
      break;
    }
    if (a.startsWith("-")) {
      const eq = a.indexOf("=");
      const flag = eq > 0 ? a.substring(0, eq) : a;
      if (NPX_PACKAGE_FLAGS.has(flag)) {
        const value = eq > 0 ? a.substring(eq + 1) : args[++i];
        if (value) packages.push(value);
      } else if (eq < 0 && NPX_VALUE_FLAGS.has(flag)) {
        i++;
      }
      continue;
    }
    if (a.length > 0 && positional === undefined) positional = a;
  }
  if (packages.length > 0) return packages;
  return positional ? [positional] : [];
}

const UVX_VALUE_FLAGS: ReadonlySet<string> = new Set([
  "--python", "-p", "--index-url", "-i", "--extra-index-url", "--index", "--default-index",
  "--find-links", "-f", "--directory", "--project", "--config-file", "--env-file",
  "--with-requirements", "--constraints", "-c", "--overrides", "--refresh-package",
  "--reinstall-package", "--upgrade-package", "-P", "--no-build-package",
  "--no-binary-package", "--python-platform", "--keyring-provider", "--resolution",
  "--prerelease", "--index-strategy", "--exclude-newer", "--cache-dir", "--color",
  "--allow-insecure-host", "--link-mode", "--pip-args", "--suffix",
]);
/** Flags whose value is itself a package to install (`--from`, `--spec`). */
const UVX_SOURCE_FLAGS: ReadonlySet<string> = new Set(["--from", "--spec"]);

function packagesOfUvxArgs(args: string[]): string[] {
  const sources: string[] = [];
  const extras: string[] = [];
  let positional: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") {
      if (positional === undefined && i + 1 < args.length) positional = args[i + 1];
      break;
    }
    if (a.startsWith("-")) {
      const eq = a.indexOf("=");
      const flag = eq > 0 ? a.substring(0, eq) : a;
      const inline = eq > 0 ? a.substring(eq + 1) : undefined;
      if (UVX_SOURCE_FLAGS.has(flag)) {
        const value = inline ?? args[++i];
        if (value) sources.push(value);
      } else if (flag === "--with") {
        const value = inline ?? args[++i];
        if (value) for (const piece of value.split(",")) if (piece) extras.push(piece);
      } else if (inline === undefined && UVX_VALUE_FLAGS.has(flag)) {
        i++;
      }
      continue;
    }
    if (a.length > 0 && positional === undefined) positional = a;
  }
  // With --from/--spec the positional is the executable, not a package.
  const main = sources.length > 0 ? sources : positional ? [positional] : [];
  return [...main, ...extras];
}

/**
 * Extract the packages a server command launches (a launcher can name several,
 * for example `--from pkg` plus `--with other`):
 * - npx/bunx/pnpx <spec>, npm exec, pnpm dlx, yarn dlx, bun x -> npm
 * - uvx/pipx run/uv tool run <spec> (--from/--spec/--with)      -> pypi
 * - python/python3.N/py -m <mod>  -> pypi (module name approximates the package)
 * - node .../node_modules/<pkg>/... -> npm
 * - cmd /c, sh -c, powershell -Command, env, exec: the wrapped command line
 */
function extractPackageSpecs(command: string, args: string[], depth = 0): PackageSpec[] {
  if (depth > MAX_UNWRAP_DEPTH) return [];
  const base = baseCommandName(command);

  if (base === "cmd") {
    const i = args.findIndex((a) => /^\/[ck]$/i.test(a));
    return i >= 0 ? packagesOfCommandLine(args.slice(i + 1).join(" "), depth) : [];
  }
  if (SHELL_WRAPPERS.has(base)) {
    const i = args.findIndex((a) => /^-[A-Za-z]*c[A-Za-z]*$/.test(a));
    return i >= 0 ? packagesOfCommandLine(args.slice(i + 1).join(" "), depth) : [];
  }
  if (base === "powershell" || base === "pwsh") {
    const i = args.findIndex((a) => /^-(c|command)$/i.test(a));
    return i >= 0 ? packagesOfCommandLine(args.slice(i + 1).join(" "), depth) : [];
  }
  if (base === "env") {
    let i = 0;
    while (i < args.length) {
      const a = args[i]!;
      if (a === "-u" || a === "-C" || a === "--unset" || a === "--chdir") { i += 2; continue; }
      if (a.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) { i++; continue; }
      break;
    }
    return i < args.length ? extractPackageSpecs(args[i]!, args.slice(i + 1), depth + 1) : [];
  }
  if (TRANSPARENT_PREFIXES.has(base)) {
    return args.length > 0 ? extractPackageSpecs(args[0]!, args.slice(1), depth + 1) : [];
  }

  const npm = (specs: string[]): PackageSpec[] =>
    specs.map((s) => ({ ecosystem: "npm" as const, ...splitSpec("npm", s) }));
  const pypi = (specs: string[]): PackageSpec[] =>
    specs.map((s) => ({ ecosystem: "pypi" as const, ...splitSpec("pypi", s) }));

  if (base === "npx" || base === "bunx" || base === "pnpx") {
    return npm(packagesOfNpxArgs(args));
  }
  if (base === "npm" || base === "pnpm" || base === "yarn" || base === "bun") {
    const launchers: Record<string, string[]> = {
      npm: ["exec", "x"], pnpm: ["dlx"], yarn: ["dlx"], bun: ["x"],
    };
    const { sub, rest } = splitSubcommand(args, NPX_VALUE_FLAGS);
    return sub !== undefined && launchers[base]!.includes(sub) ? npm(packagesOfNpxArgs(rest)) : [];
  }

  if (base === "uvx") return pypi(packagesOfUvxArgs(args));
  if (base === "pipx") {
    const { sub, rest } = splitSubcommand(args, UVX_VALUE_FLAGS);
    return sub === "run" ? pypi(packagesOfUvxArgs(rest)) : [];
  }
  if (base === "uv") {
    const { sub, rest } = splitSubcommand(args, UVX_VALUE_FLAGS);
    if (sub !== "tool") return [];
    const run = splitSubcommand(rest, UVX_VALUE_FLAGS);
    return run.sub === "run" ? pypi(packagesOfUvxArgs(run.rest)) : [];
  }

  if (/^pythonw?(\d+(\.\d+)*)?$/.test(base) || base === "py") {
    const mIdx = args.indexOf("-m");
    const mod = mIdx >= 0 ? args[mIdx + 1] : undefined;
    if (!mod) return [];
    const specs: PackageSpec[] = [{ ecosystem: "pypi", name: mod }];
    // A dotted module (`pkg.cli`) belongs to its top-level distribution.
    const top = mod.split(".")[0];
    if (top && top !== mod) specs.push({ ecosystem: "pypi", name: top });
    return specs;
  }

  if (base === "node") {
    // node scripts usually point into node_modules; extract the package name.
    for (const arg of args) {
      const norm = arg.replace(/\\/g, "/");
      const idx = norm.lastIndexOf("node_modules/");
      if (idx === -1) continue;
      const rest = norm.substring(idx + "node_modules/".length);
      const parts = rest.split("/");
      const name = parts[0]?.startsWith("@") && parts[1] ? `${parts[0]}/${parts[1]}` : parts[0];
      if (name) return [{ ecosystem: "npm", name }];
    }
    return [];
  }

  return [];
}

/** The packages a server entry launches, including a whole command line given as `command`. */
function packagesOfServer(command: string, args: string[]): PackageSpec[] {
  const direct = extractPackageSpecs(command, args);
  if (direct.length > 0 || !/\s/.test(command)) return direct;
  return packagesOfCommandLine(`${command} ${args.join(" ")}`, 0);
}

/** An exact, concrete version: `1.0.16`, `v1.0.16`, `=1.0.16`, `1.0.0-beta.1`. */
const EXACT_VERSION_REGEX = /^[=v]*\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.+-]+)?$/;

function classifyVersion(raw: string): { version?: string; range?: string } {
  const text = raw.trim();
  if (text === "") return {};
  if (EXACT_VERSION_REGEX.test(text)) return { version: text.replace(/^[=v]+/, "") };
  return { range: text };
}

/**
 * Split "name@1.2.3" / "@scope/name@^1.2" / "name@latest" (npm) and
 * "name==1.2.3" / "name>=1,<2" / "name[extra]" / "name@1.2.3" (pypi) into name
 * plus either an exact version or a range. A leading "@" (npm scope) is not a
 * version separator.
 */
function splitSpec(
  ecosystem: "npm" | "pypi",
  spec: string,
): { name: string; version?: string; range?: string } {
  if (ecosystem === "pypi") {
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$/.exec(spec.trim());
    if (!m) return { name: spec };
    const rest = (m[2] ?? "").trim();
    if (rest === "") return { name: m[1]! };
    if (rest.startsWith("@")) return { name: m[1]!, ...classifyVersion(rest.substring(1)) };
    if (rest.startsWith("===")) return { name: m[1]!, ...classifyVersion(rest.substring(3)) };
    if (rest.startsWith("==") && !rest.includes(",") && !rest.includes("*")) {
      return { name: m[1]!, ...classifyVersion(rest.substring(2)) };
    }
    return { name: m[1]!, range: rest };
  }
  const eq = spec.indexOf("==");
  if (eq > 0) {
    return { name: spec.substring(0, eq), ...classifyVersion(spec.substring(eq + 2)) };
  }
  const at = spec.lastIndexOf("@");
  if (at > 0) {
    return { name: spec.substring(0, at), ...classifyVersion(spec.substring(at + 1)) };
  }
  return { name: spec };
}

// ---------------------------------------------------------------------------
// Version ranges (what a dist-tag or range can resolve to)
// ---------------------------------------------------------------------------

type VersionParts = number[];

const VERSION_TEXT_REGEX =
  /^[=v]*(\d+|[xX*])((?:\.(?:\d+|[xX*]))*)(?:[-+.]?[A-Za-z][0-9A-Za-z.+-]*|[-+][0-9A-Za-z.+-]+)?$/;

function parseVersionParts(text: string): { parts: Array<number | null> } | null {
  const m = VERSION_TEXT_REGEX.exec(text.trim());
  if (!m) return null;
  const pieces = [m[1]!, ...(m[2] ?? "").split(".").filter(Boolean)];
  return { parts: pieces.map((p) => (/^\d+$/.test(p) ? Number(p) : null)) };
}

function compareParts(a: VersionParts, b: VersionParts): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

function fill(parts: Array<number | null>, width = 3): VersionParts {
  const out: number[] = [];
  for (let i = 0; i < Math.max(width, parts.length); i++) out.push(parts[i] ?? 0);
  return out;
}

/** Number of leading concrete components (stops at the first wildcard). */
function concreteLength(parts: Array<number | null>): number {
  const wild = parts.indexOf(null);
  return wild === -1 ? parts.length : wild;
}

/** Smallest version above every version sharing the first `n` components. */
function bump(parts: Array<number | null>, n: number): VersionParts {
  const head = parts.slice(0, n).map((p) => p ?? 0);
  head[head.length - 1] = head[head.length - 1]! + 1;
  return fill(head);
}

type Comparator = (v: VersionParts) => boolean;

/**
 * Comparators of one npm range token (`^1.2.3`, `~1.2`, `>=1`, `1.x`, ...).
 * Returns null when the token is not understood, which callers treat as "may
 * match": a range that cannot be evaluated must not hide a feed entry.
 */
function npmTokenComparators(token: string): Comparator[] | null {
  const m = /^(>=|<=|>|<|=|\^|~>?)?(.*)$/.exec(token);
  if (!m) return null;
  const op = m[1] ?? "";
  const body = m[2]!;
  if (body === "" || body === "*" || /^[xX]$/.test(body)) return [() => true];
  const parsed = parseVersionParts(body);
  if (!parsed) return null;
  const { parts } = parsed;
  const n = concreteLength(parts);
  if (n === 0) return [() => true];
  const lo = fill(parts.slice(0, n));
  switch (op) {
    case "":
    case "=":
      return [(v) => compareParts(v, lo) >= 0, (v) => compareParts(v, bump(parts, n)) < 0];
    case "^": {
      // Bump the left-most non-zero component (^0.2.3 -> <0.3.0, ^0.0.3 -> <0.0.4).
      let at = parts.findIndex((p) => p !== 0);
      if (at === -1 || at >= n) at = n - 1;
      return [(v) => compareParts(v, lo) >= 0, (v) => compareParts(v, bump(parts, at + 1)) < 0];
    }
    case "~":
    case "~>":
      return [
        (v) => compareParts(v, lo) >= 0,
        (v) => compareParts(v, bump(parts, n >= 2 ? 2 : 1)) < 0,
      ];
    case ">=":
      return [(v) => compareParts(v, lo) >= 0];
    case ">":
      return [(v) => compareParts(v, bump(parts, n)) >= 0];
    case "<":
      return [(v) => compareParts(v, lo) < 0];
    case "<=":
      return [(v) => compareParts(v, bump(parts, n)) < 0];
    default:
      return null;
  }
}

function npmRangeMayContain(range: string, version: VersionParts): boolean {
  for (const alternative of range.split("||")) {
    let text = alternative.trim();
    if (text === "" || text === "*" || /^[xX]$/.test(text)) return true;
    // "a - b" hyphen range
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(text);
    if (hyphen) text = `>=${hyphen[1]} <=${hyphen[2]}`;
    // ">= 1.0.0" -> ">=1.0.0"
    text = text.replace(/(>=|<=|>|<|=|\^|~>|~)\s+/g, "$1");
    let satisfied = true;
    for (const token of text.split(/\s+/)) {
      const comparators = npmTokenComparators(token);
      if (comparators === null) continue; // not understood: do not exclude
      if (!comparators.every((c) => c(version))) { satisfied = false; break; }
    }
    if (satisfied) return true;
  }
  return false;
}

function pypiRangeMayContain(range: string, version: VersionParts): boolean {
  for (const clause of range.split(",")) {
    const m = /^\s*(===|==|!=|~=|>=|<=|>|<)\s*(\S+)\s*$/.exec(clause);
    if (!m) continue; // not understood: do not exclude
    const wildcard = m[2]!.endsWith(".*");
    const parsed = parseVersionParts(wildcard ? m[2]!.slice(0, -2) : m[2]!);
    if (!parsed) continue;
    const n = parsed.parts.length;
    const want = fill(parsed.parts.map((p) => p ?? 0), 1);
    switch (m[1]) {
      case "==":
      case "===":
        if (wildcard) {
          if (compareParts(version.slice(0, n), want.slice(0, n)) !== 0) return false;
        } else if (compareParts(version, want) !== 0) return false;
        break;
      case "!=":
        if (compareParts(version, want) === 0) return false;
        break;
      case "~=": {
        const hi = fill(parsed.parts.slice(0, Math.max(1, n - 1)).map((p) => p ?? 0), 1);
        hi[hi.length - 1] = hi[hi.length - 1]! + 1;
        if (compareParts(version, want) < 0 || compareParts(version, hi) >= 0) return false;
        break;
      }
      case ">=": if (compareParts(version, want) < 0) return false; break;
      case ">": if (compareParts(version, want) <= 0) return false; break;
      case "<=": if (compareParts(version, want) > 0) return false; break;
      case "<": if (compareParts(version, want) >= 0) return false; break;
    }
  }
  return true;
}

/**
 * Whether a dist-tag or range can resolve to a pinned bad version. A tag
 * (`latest`, `next`) names whatever the registry points it at, so it may. A
 * range that cannot be evaluated errs towards "may": the alternative is a
 * silent clean result on a launcher that floats.
 */
function rangeMayResolveTo(
  ecosystem: "npm" | "pypi",
  range: string,
  pinned: string,
): boolean {
  const tag = range.trim();
  if (/^[A-Za-z][A-Za-z0-9._-]*$/.test(tag) && !/^[xX]$/.test(tag)) return true;
  const parsed = parseVersionParts(pinned);
  if (!parsed) return false;
  const version = fill(parsed.parts.map((p) => p ?? 0), 1);
  return ecosystem === "npm"
    ? npmRangeMayContain(tag, version)
    : pypiRangeMayContain(tag, version);
}

/**
 * The feed entry that pins a version the given range can resolve to. Exact
 * pins are matched elsewhere; this finds `name@1.0.16` for `name@^1.0.16` or
 * `name@latest`.
 */
function matchPinnedIOCInRange(
  ecosystem: "npm" | "pypi",
  name: string,
  range: string,
  feed: FeedIOC[],
): FeedIOC | null {
  const wantName = ecosystem === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;
  const prefix = `${ecosystem}:`;
  for (const ioc of feed) {
    if (ioc.type !== "package") continue;
    let rest = ioc.value;
    if (rest.toLowerCase().startsWith(prefix)) rest = rest.substring(prefix.length);
    else if (ecosystem !== "npm" || rest.includes(":")) continue;
    const { name: iocName, version: iocVersion } = splitPackageIOCValue(ecosystem, rest);
    if (iocVersion === undefined) continue; // bare-name entries are matched by name already
    const have = ecosystem === "pypi" ? iocName.toLowerCase().replace(/[-_.]+/g, "-") : iocName;
    if (have !== wantName) continue;
    if (rangeMayResolveTo(ecosystem, range, iocVersion)) return ioc;
  }
  return null;
}

/**
 * Match a package against unprefixed feed entries. npm package IOCs in the
 * bundled feed carry no ecosystem prefix (e.g. "postmark-mcp@1.0.16",
 * "@squawk/mcp@0.9.5"); matchPackageIOC() only resolves prefixed entries
 * ("ruby:", "composer:", ...), so npm needs this companion matcher.
 */
function matchUnprefixedPackageIOC(
  name: string,
  version: string | undefined,
  feed: FeedIOC[],
): FeedIOC | null {
  for (const ioc of feed) {
    if (ioc.type !== "package") continue;
    // Skip ecosystem-prefixed entries; npm names never contain ":".
    if (ioc.value.includes(":")) continue;

    const at = ioc.value.lastIndexOf("@");
    const iocName = at > 0 ? ioc.value.substring(0, at) : ioc.value;
    const iocVersion = at > 0 ? ioc.value.substring(at + 1) : undefined;

    if (iocName !== name) continue;
    if (iocVersion === undefined) return ioc; // bare-name IOC: any version
    if (version !== undefined && iocVersion === version) return ioc;
  }
  return null;
}

// ---------------------------------------------------------------------------
// URL / string helpers
// ---------------------------------------------------------------------------

/**
 * Whether a url is an unencrypted (http/ws) endpoint on a non-local host. The
 * decision comes from the WHATWG parse, the way a client reads the string, not
 * from the raw text: a leading space, an embedded tab or newline, `http:\\host`,
 * `http:/host` and `http:host` all reach a remote host over plain http.
 */
function isPlainRemoteEndpoint(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url.trim());
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "ws:") return false;
  const hostname = parsed.hostname.toLowerCase();
  return !(LOCALHOST_NAMES.has(hostname) || hostname.endsWith(".localhost"));
}

/** Upper bound on nodes visited in one server entry (hostile input, no depth cap). */
const MAX_COLLECTED_NODES = 20000;

/**
 * Collect every string anywhere in a server entry, with the nearest object key
 * it sits under. MCP hosts feed description-like strings verbatim to the LLM,
 * and a client reads arrays, deep nesting and any key (`title`, `note`, tool
 * lists), so the carrier is not limited to a few key names. The prompt-injection
 * matcher stays strict (role-control tokens and imperative override phrases),
 * so ordinary descriptions and command arguments stay clean.
 *
 * Iterative, so a deeply nested entry cannot exhaust the call stack.
 */
function collectInstructionStrings(
  obj: Record<string, unknown>,
): Array<{ key: string; value: string }> {
  const out: Array<{ key: string; value: string }> = [];
  const stack: Array<{ key: string; value: unknown }> = [{ key: "", value: obj }];
  let visited = 0;
  while (stack.length > 0 && visited < MAX_COLLECTED_NODES) {
    const { key, value } = stack.pop()!;
    visited++;
    if (typeof value === "string") {
      out.push({ key, value });
    } else if (Array.isArray(value)) {
      for (let i = value.length - 1; i >= 0; i--) stack.push({ key, value: value[i] });
    } else if (value && typeof value === "object") {
      for (const [k, v] of Object.entries(value).reverse()) stack.push({ key: k, value: v });
    }
  }
  return out;
}

/**
 * Run PROMPT_INJECTION_PATTERNS over a config string. File-scope gates
 * (onlyFilePattern/notTestFile) target docs and do not apply here - the
 * string comes out of a parsed MCP config, which is always agent-facing.
 */
function matchPromptInjection(
  text: string,
  relativePath: string,
  findings: Finding[],
): { description: string } | null {
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    const hits = matchPatternInSemanticText(
      pattern,
      text,
      relativePath,
      findings,
      "i",
    );
    if (hits && hits.length > 0) {
      return { description: pattern.description };
    }
  }
  return null;
}

function truncate(value: string): string {
  return value.length > 120 ? value.substring(0, 120) + "..." : value;
}

// ---------------------------------------------------------------------------
// JSONC stripping (replicated from lockfile-checker.ts, where it is private)
// ---------------------------------------------------------------------------

/**
 * Strip JSONC comments and trailing commas so the result parses as strict
 * JSON. String-aware: comment markers and commas inside string literals are
 * preserved. MCP configs are frequently hand-edited and comment-annotated
 * (VS Code parses them as JSONC).
 */
export function stripJsonc(text: string): string {
  // A UTF-8 byte order mark is not JSON whitespace to JSON.parse, yet editors
  // and most clients read through it.
  if (text.charCodeAt(0) === 0xfeff) text = text.substring(1);
  // Pass 1: remove // line comments and /* */ block comments
  let noComments = "";
  let inString = false;
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (inString) {
      noComments += ch;
      if (ch === "\\" && i + 1 < text.length) {
        noComments += text[i + 1]!;
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i++;
      continue;
    }
    if (ch === '"') {
      inString = true;
      noComments += ch;
      i++;
      continue;
    }
    if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    noComments += ch;
    i++;
  }

  // Pass 2: remove trailing commas before } or ]
  let result = "";
  inString = false;
  for (let j = 0; j < noComments.length; j++) {
    const ch = noComments[j]!;
    if (inString) {
      result += ch;
      if (ch === "\\" && j + 1 < noComments.length) {
        result += noComments[j + 1]!;
        j++;
        continue;
      }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      result += ch;
      continue;
    }
    if (ch === ",") {
      let k = j + 1;
      while (k < noComments.length && /\s/.test(noComments[k]!)) k++;
      if (k < noComments.length && (noComments[k] === "}" || noComments[k] === "]")) {
        continue;
      }
    }
    result += ch;
  }
  return result;
}
