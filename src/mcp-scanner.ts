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
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { checkBadVersion, checkIOCBlocklist } from "./ioc-blocklist.js";
import { PROMPT_INJECTION_PATTERNS } from "./patterns.js";

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
export function scanMcpConfigs(dir: string): Finding[] {
  const findings: Finding[] = [];
  const feed = loadThreatIntel();

  for (const rel of MCP_CONFIG_FILES) {
    const fullPath = path.join(dir, ...rel.split("/"));
    if (!fs.existsSync(fullPath)) continue;
    try {
      const content = fs.readFileSync(fullPath, "utf-8");
      findings.push(...scanMcpConfigContent(content, rel, feed));
    } catch { /* skip unreadable file */ }
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
    return findings; // malformed config: nothing to parse
  }
  if (!parsed || typeof parsed !== "object") return findings;

  // .mcp.json / claude_desktop_config.json / .gemini/settings.json use
  // "mcpServers"; .vscode/mcp.json uses "servers".
  const serversRaw = parsed["mcpServers"] ?? parsed["servers"];
  if (!serversRaw || typeof serversRaw !== "object" || Array.isArray(serversRaw)) {
    return findings;
  }

  for (const [serverName, entryRaw] of Object.entries(serversRaw)) {
    if (!entryRaw || typeof entryRaw !== "object") continue;
    const entry = entryRaw as McpServerEntry;

    const command = typeof entry.command === "string" ? entry.command : undefined;
    const args = Array.isArray(entry.args)
      ? entry.args.filter((a): a is string => typeof a === "string")
      : [];
    const url = typeof entry.url === "string" ? entry.url : undefined;

    // 1. Malicious server package (threat-intel feed + known-bad versions)
    if (command) {
      const spec = extractPackageSpec(command, args);
      if (spec) {
        const ioc =
          matchPackageIOC(spec.ecosystem, spec.name, spec.version, iocFeed) ??
          matchUnprefixedPackageIOC(spec.name, spec.version, iocFeed);
        if (ioc) {
          findings.push({
            rule: "MCP_MALICIOUS_SERVER_PACKAGE",
            description: `MCP server "${serverName}" launches known malicious package ${spec.name}${spec.version ? `@${spec.version}` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
            severity: "critical",
            file: relativePath,
            match: truncate(`${command} ${args.join(" ")}`),
            confidence: ioc.confidence,
            category: "malware",
            recommendation: `Remove the "${serverName}" server entry immediately. The package matches a threat-intelligence IOC. Rotate any credentials the server had access to.`,
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
          !spec.version &&
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
      } else if (/^http:\/\//i.test(url) && !isLocalhostUrl(url)) {
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
      const hit = matchPromptInjection(value);
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
  version?: string;
}

/**
 * Extract the package a server command launches:
 * - npx/bunx <spec>          -> npm
 * - uvx/pipx <spec>          -> pypi
 * - python/python3 -m <mod>  -> pypi (module name approximates the package)
 * - node .../node_modules/<pkg>/... -> npm
 */
function extractPackageSpec(command: string, args: string[]): PackageSpec | null {
  // Normalize "C:\\...\\npx.cmd" / "/usr/local/bin/npx" -> "npx"
  const base = path.basename(command).replace(/\.(exe|cmd|bat)$/i, "").toLowerCase();

  if (base === "npx" || base === "bunx") {
    const spec = firstPositionalArg(args);
    return spec ? { ecosystem: "npm", ...splitSpec(spec) } : null;
  }

  if (base === "uvx" || base === "pipx") {
    const spec = firstPositionalArg(args);
    return spec ? { ecosystem: "pypi", ...splitSpec(spec) } : null;
  }

  if (base === "python" || base === "python3" || base === "py") {
    const mIdx = args.indexOf("-m");
    const mod = mIdx >= 0 ? args[mIdx + 1] : undefined;
    return mod ? { ecosystem: "pypi", name: mod } : null;
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
      if (name) return { ecosystem: "npm", name };
    }
    return null;
  }

  return null;
}

/** First arg that is not a flag (skips -y, --yes, --quiet, ...). */
function firstPositionalArg(args: string[]): string | undefined {
  return args.find((a) => a.length > 0 && !a.startsWith("-"));
}

/**
 * Split "name@1.2.3" / "@scope/name@1.2.3" / "name==1.2.3" (pypi style) into
 * name + version. A leading "@" (npm scope) is not a version separator.
 */
function splitSpec(spec: string): { name: string; version?: string } {
  const eq = spec.indexOf("==");
  if (eq > 0) {
    return { name: spec.substring(0, eq), version: spec.substring(eq + 2) };
  }
  const at = spec.lastIndexOf("@");
  if (at > 0) {
    return { name: spec.substring(0, at), version: spec.substring(at + 1) };
  }
  return { name: spec };
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

function isLocalhostUrl(url: string): boolean {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return LOCALHOST_NAMES.has(hostname) || hostname.endsWith(".localhost");
  } catch {
    return false;
  }
}

/**
 * Collect description/instructions-style strings anywhere in a server entry.
 * MCP hosts feed these strings verbatim to the LLM, so they are the natural
 * carrier for tool-poisoning prompt injection.
 */
function collectInstructionStrings(
  obj: Record<string, unknown>,
  depth = 0,
): Array<{ key: string; value: string }> {
  if (depth > 4) return [];
  const out: Array<{ key: string; value: string }> = [];
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === "string" && /^(description|instructions?|prompt|systemPrompt)$/i.test(key)) {
      out.push({ key, value });
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      out.push(...collectInstructionStrings(value as Record<string, unknown>, depth + 1));
    }
  }
  return out;
}

/**
 * Run PROMPT_INJECTION_PATTERNS over a config string. File-scope gates
 * (onlyFilePattern/notTestFile) target docs and do not apply here - the
 * string comes out of a parsed MCP config, which is always agent-facing.
 */
function matchPromptInjection(text: string): { description: string } | null {
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (new RegExp(pattern.pattern, "i").test(text)) {
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
function stripJsonc(text: string): string {
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
