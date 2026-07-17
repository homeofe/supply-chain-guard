/**
 * MCP (Model Context Protocol) server (v5.4).
 *
 * Exposes supply-chain-guard as tools for AI coding agents over the MCP
 * stdio transport: JSON-RPC 2.0, one UTF-8 JSON message per line, stdout
 * carries ONLY protocol JSON, all logging goes to stderr.
 *
 * Zero dependencies: the protocol layer is hand-rolled on node:readline.
 * The message handler (handleMcpMessage / handleMcpLine) is a pure function
 * so tests can exercise the full protocol without child processes.
 *
 * Tools:
 *   - ioc_lookup:       offline package IOC verdict (threat-intel feed + blocklist)
 *   - scan_directory:   full static scan of a local directory
 *   - scan_npm_package: remote scan of an npm package (downloads from registry)
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import { scan } from "./scanner.js";
import { scanNpmPackage } from "./npm-scanner.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { checkBadVersion } from "./ioc-blocklist.js";
import type { ScanReport, Severity } from "./types.js";

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/** Protocol revisions this server understands, newest first. */
export const SUPPORTED_PROTOCOL_VERSIONS = [
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
] as const;

const LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];

export const SERVER_NAME = "supply-chain-guard";

// JSON-RPC 2.0 error codes
const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;

// ---------------------------------------------------------------------------
// Server version (read from package.json so it can never drift)
// ---------------------------------------------------------------------------

function readServerVersion(): string {
  // dist/mcp-server.js -> ../package.json; under vitest the source lives in
  // src/ so the same relative hop works. Fall back to cwd for exotic loaders.
  const candidates: string[] = [];
  try {
    candidates.push(path.join(__dirname, "..", "package.json"));
  } catch {
    /* __dirname unavailable in some ESM runners */
  }
  candidates.push(path.join(process.cwd(), "package.json"));

  for (const candidate of candidates) {
    try {
      const pkg = JSON.parse(fs.readFileSync(candidate, "utf-8")) as {
        name?: string;
        version?: string;
      };
      if (pkg.name === SERVER_NAME && typeof pkg.version === "string") {
        return pkg.version;
      }
    } catch {
      /* try next candidate */
    }
  }
  return "0.0.0";
}

const SERVER_VERSION = readServerVersion();

// ---------------------------------------------------------------------------
// Tool definitions (hand-written JSON Schema, no libraries)
// ---------------------------------------------------------------------------

interface JsonSchemaProperty {
  type: "string";
  description: string;
  enum?: readonly string[];
}

interface ToolInputSchema {
  type: "object";
  properties: Record<string, JsonSchemaProperty>;
  required: readonly string[];
  /**
   * At least one of these argument groups must be fully present (each group is
   * an AND of its keys; the groups are OR-ed). Lets a tool accept alternative
   * argument shapes, e.g. ioc_lookup by (ecosystem+name) OR (indicator).
   */
  requiredAnyOf?: readonly (readonly string[])[];
  additionalProperties: boolean;
}

interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: ToolInputSchema;
}

const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"] as const;
const ECOSYSTEM_VALUES = ["npm", "pypi", "ruby", "composer", "nuget"] as const;

const TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "ioc_lookup",
    description:
      "Offline lookup against supply-chain-guard's bundled threat intelligence " +
      "feed and known-bad version blocklist. No network access. Two modes: pass " +
      "{ecosystem, name} to check a PACKAGE before installing/importing/recommending " +
      "it, or pass {indicator} to check a single domain/url/ip/hash observed in " +
      "code or logs. Returns a malicious/clean verdict with matched campaign and " +
      "malware family details.",
    inputSchema: {
      type: "object",
      properties: {
        ecosystem: {
          type: "string",
          description: "Package ecosystem the name belongs to (package-mode)",
          enum: ECOSYSTEM_VALUES,
        },
        name: {
          type: "string",
          description: "Package name, e.g. 'event-stream' or '@scope/pkg' (package-mode)",
        },
        version: {
          type: "string",
          description:
            "Exact version to check (optional, package-mode). Without it only version-independent IOCs match.",
        },
        indicator: {
          type: "string",
          description:
            "A single domain, url, ip, or hash to look up against the feed (indicator-mode). Use INSTEAD of ecosystem/name.",
        },
      },
      required: [],
      requiredAnyOf: [["ecosystem", "name"], ["indicator"]],
      additionalProperties: false,
    },
  },
  {
    name: "scan_directory",
    description:
      "Run supply-chain-guard's full static malware scan (200+ detection " +
      "rules: obfuscation, install hooks, C2 indicators, lockfile tampering, " +
      "CI/CD abuse) over a local directory. Local filesystem only. Returns a " +
      "compact JSON summary with risk score, findings count by severity, and " +
      "the top findings.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Local directory path to scan",
        },
        minSeverity: {
          type: "string",
          description: "Only report findings at or above this severity (optional)",
          enum: SEVERITY_VALUES,
        },
        since: {
          type: "string",
          description:
            "Only scan files changed since this git commit/ref (optional diff scan, e.g. 'HEAD~1' or a SHA).",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "scan_npm_package",
    description:
      "Scan an npm package WITHOUT installing it. NOTE: this downloads " +
      "metadata and the tarball of the latest published version from the npm " +
      "registry (network access). Also runs the offline IOC lookup for the " +
      "given name (and exact version, if provided; the deep content scan " +
      "always analyzes the latest published version).",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "npm package name, e.g. 'express' or '@scope/pkg'",
        },
        version: {
          type: "string",
          description:
            "Exact version for the offline IOC check (optional). The remote deep scan targets the latest published version regardless.",
        },
      },
      required: ["name"],
      additionalProperties: false,
    },
  },
];

// ---------------------------------------------------------------------------
// IOC lookup (offline)
// ---------------------------------------------------------------------------

/**
 * Feed entries for npm/PyPI packages carry no ecosystem prefix (only
 * ruby:/composer:/nuget:/go:/jenkins: entries do - see matchPackageIOC).
 * This matcher resolves those bare entries for the npm and pypi ecosystems.
 */
const PREFIXED_ECOSYSTEMS = ["ruby:", "composer:", "nuget:", "go:", "jenkins:"];

function matchBarePackageIOC(
  name: string,
  version: string | undefined,
  feed: FeedIOC[],
): FeedIOC | null {
  for (const ioc of feed) {
    if (ioc.type !== "package") continue;
    const lower = ioc.value.toLowerCase();
    if (PREFIXED_ECOSYSTEMS.some((p) => lower.startsWith(p))) continue;

    // Split "name@version" at the last "@"; index 0 means a scoped bare name.
    const at = ioc.value.lastIndexOf("@");
    const iocName = at > 0 ? ioc.value.substring(0, at) : ioc.value;
    const iocVersion = at > 0 ? ioc.value.substring(at + 1) : undefined;

    if (iocName !== name) continue;
    if (iocVersion === undefined) return ioc; // bare-name IOC: any version
    if (version !== undefined && iocVersion === version) return ioc;
  }
  return null;
}

interface IocMatch {
  source: "threat-intel-feed" | "known-bad-versions";
  rule: string;
  severity: Severity;
  confidence: number;
  category: "malware";
  description: string;
  family?: string;
  campaign?: string;
  firstSeen?: string;
}

interface IocLookupResult {
  ecosystem: string;
  name: string;
  version: string | null;
  verdict: "malicious" | "clean";
  matches: IocMatch[];
  checkedAgainst: { feedEntries: number; offline: true };
}

function runIocLookup(
  ecosystem: (typeof ECOSYSTEM_VALUES)[number],
  name: string,
  version?: string,
): IocLookupResult {
  const feed = loadThreatIntel();
  const matches: IocMatch[] = [];

  // 1. Threat-intel feed: ecosystem-prefixed entries (ruby/composer/nuget)
  //    plus bare entries for npm/pypi.
  const feedHit =
    matchPackageIOC(ecosystem, name, version, feed) ??
    (ecosystem === "npm" || ecosystem === "pypi"
      ? matchBarePackageIOC(name, version, feed)
      : null);

  if (feedHit) {
    matches.push({
      source: "threat-intel-feed",
      rule: "THREAT_INTEL_PACKAGE_IOC",
      severity: feedHit.severity,
      confidence: feedHit.confidence,
      category: "malware",
      description: `Package IOC match: ${feedHit.value}`,
      family: feedHit.family,
      campaign: feedHit.campaign,
      firstSeen: feedHit.firstSeen,
    });
  }

  // 2. Known-bad version blocklist (requires an exact version).
  if (version !== undefined) {
    const badVersion = checkBadVersion(name, version, ecosystem);
    if (badVersion) {
      matches.push({
        source: "known-bad-versions",
        rule: badVersion.rule,
        severity: badVersion.severity,
        confidence: 1.0,
        category: "malware",
        description: badVersion.description,
      });
    }
  }

  return {
    ecosystem,
    name,
    version: version ?? null,
    verdict: matches.length > 0 ? "malicious" : "clean",
    matches,
    checkedAgainst: { feedEntries: feed.length, offline: true },
  };
}

interface IndicatorMatch {
  source: "threat-intel-feed";
  type: FeedIOC["type"];
  value: string;
  severity: Severity;
  confidence: number;
  family?: string;
  campaign?: string;
  firstSeen?: string;
}

interface IndicatorLookupResult {
  indicator: string;
  verdict: "malicious" | "clean";
  matches: IndicatorMatch[];
  checkedAgainst: { feedEntries: number; offline: true };
}

/**
 * Look a raw indicator (domain / url / ip / hash) up against the loaded feed.
 * Package IOCs are skipped here - those belong to the ecosystem/name path.
 * Matching is exact (case-insensitive) on the feed value.
 */
function runIndicatorLookup(indicator: string): IndicatorLookupResult {
  const feed = loadThreatIntel();
  const needle = indicator.trim().toLowerCase();
  const matches: IndicatorMatch[] = [];

  for (const ioc of feed) {
    if (ioc.type === "package") continue;
    if (ioc.value.toLowerCase() !== needle) continue;
    matches.push({
      source: "threat-intel-feed",
      type: ioc.type,
      value: ioc.value,
      severity: ioc.severity,
      confidence: ioc.confidence,
      family: ioc.family,
      campaign: ioc.campaign,
      firstSeen: ioc.firstSeen,
    });
  }

  return {
    indicator,
    verdict: matches.length > 0 ? "malicious" : "clean",
    matches,
    checkedAgainst: { feedEntries: feed.length, offline: true },
  };
}

// ---------------------------------------------------------------------------
// Compact scan report (agents want small, structured results)
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function compactReport(report: ScanReport, maxFindings = 20): object {
  const topFindings = [...report.findings]
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
    .slice(0, maxFindings)
    .map((f) => {
      const compact: Record<string, unknown> = {
        rule: f.rule,
        severity: f.severity,
        file: f.file ?? null,
        line: f.line ?? null,
        description: f.description,
        recommendation: f.recommendation,
      };
      // Include the matched snippet, but omit it when large so a big obfuscated
      // blob cannot bloat the agent-facing response.
      if (f.match !== undefined && f.match.length <= 200) {
        compact.match = f.match;
      }
      return compact;
    });

  return {
    target: report.target,
    scanType: report.scanType,
    score: report.score,
    riskLevel: report.riskLevel,
    findingsBySeverity: {
      critical: report.summary.critical,
      high: report.summary.high,
      medium: report.summary.medium,
      low: report.summary.low,
      info: report.summary.info,
    },
    totalFindings: report.findings.length,
    topFindings,
    recommendations: report.recommendations.slice(0, 5),
  };
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

async function runTool(
  toolName: string,
  args: Record<string, unknown>,
): Promise<object> {
  switch (toolName) {
    case "ioc_lookup":
      // Indicator-mode when {indicator} is supplied; otherwise package-mode
      // (ecosystem+name are guaranteed present by the requiredAnyOf validation).
      return args.indicator !== undefined
        ? runIndicatorLookup(args.indicator as string)
        : runIocLookup(
            args.ecosystem as (typeof ECOSYSTEM_VALUES)[number],
            args.name as string,
            args.version as string | undefined,
          );

    case "scan_directory": {
      const report = await scan({
        target: args.path as string,
        format: "json",
        minSeverity: args.minSeverity as Severity | undefined,
        sinceCommit: args.since as string | undefined,
      });
      return compactReport(report);
    }

    case "scan_npm_package": {
      const name = args.name as string;
      const version = args.version as string | undefined;
      const iocLookup = runIocLookup("npm", name, version);
      const report = await scanNpmPackage(name, {
        target: name,
        format: "json",
      });
      return {
        ...compactReport(report),
        iocLookup,
        note:
          version !== undefined
            ? `Deep content scan analyzed the latest published version (${report.target}); the offline IOC lookup used the requested version ${version}.`
            : "Deep content scan analyzed the latest published version.",
      };
    }

    default:
      // Unreachable: tools/call validates the tool name before dispatching.
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

/**
 * Minimal hand-rolled validation of tool arguments against the flat JSON
 * Schemas above (string properties, optional enum, required list).
 * Returns a human-readable problem or null when the arguments are valid.
 */
function validateToolArguments(
  schema: ToolInputSchema,
  args: Record<string, unknown>,
): string | null {
  for (const key of schema.required) {
    if (args[key] === undefined) {
      return `Missing required argument "${key}"`;
    }
  }
  if (schema.requiredAnyOf) {
    const satisfied = schema.requiredAnyOf.some((group) =>
      group.every((key) => args[key] !== undefined),
    );
    if (!satisfied) {
      const groups = schema.requiredAnyOf
        .map((group) => group.map((k) => `"${k}"`).join(" + "))
        .join(" or ");
      return `Provide one of: ${groups}`;
    }
  }
  for (const [key, value] of Object.entries(args)) {
    const prop = schema.properties[key];
    if (!prop) {
      return `Unknown argument "${key}"`;
    }
    if (value === undefined) continue;
    if (typeof value !== "string") {
      return `Argument "${key}" must be a string`;
    }
    if (prop.enum && !prop.enum.includes(value)) {
      return `Argument "${key}" must be one of: ${prop.enum.join(", ")}`;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// JSON-RPC plumbing
// ---------------------------------------------------------------------------

type JsonRpcId = string | number | null;

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: unknown;
  error?: { code: number; message: string };
}

function errorResponse(id: JsonRpcId, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function successResponse(id: JsonRpcId, result: unknown): JsonRpcResponse {
  return { jsonrpc: "2.0", id, result };
}

function buildInitializeResult(params: unknown): object {
  const requested =
    typeof params === "object" && params !== null
      ? (params as { protocolVersion?: unknown }).protocolVersion
      : undefined;

  // Mirror the client's requested revision when we support it; otherwise
  // answer with the latest revision we do support (per MCP version negotiation).
  const protocolVersion =
    typeof requested === "string" &&
    (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
      ? requested
      : LATEST_PROTOCOL_VERSION;

  return {
    protocolVersion,
    capabilities: { tools: {} },
    serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
    instructions:
      "Call ioc_lookup before installing or recommending any package (offline, " +
      "instant). Use scan_directory to vet already-downloaded code and " +
      "scan_npm_package to vet an npm package before adding it as a dependency.",
  };
}

async function handleToolsCall(id: JsonRpcId, params: unknown): Promise<JsonRpcResponse> {
  if (typeof params !== "object" || params === null) {
    return errorResponse(id, INVALID_PARAMS, "Invalid params: expected an object with a tool name");
  }
  const { name, arguments: rawArgs } = params as { name?: unknown; arguments?: unknown };
  if (typeof name !== "string") {
    return errorResponse(id, INVALID_PARAMS, "Invalid params: tool name must be a string");
  }

  const tool = TOOL_DEFINITIONS.find((t) => t.name === name);
  if (!tool) {
    return errorResponse(id, INVALID_PARAMS, `Unknown tool: ${name}`);
  }

  const args = rawArgs ?? {};
  if (typeof args !== "object" || args === null || Array.isArray(args)) {
    return errorResponse(id, INVALID_PARAMS, "Invalid params: arguments must be an object");
  }

  const problem = validateToolArguments(tool.inputSchema, args as Record<string, unknown>);
  if (problem !== null) {
    return errorResponse(id, INVALID_PARAMS, `Invalid arguments for ${name}: ${problem}`);
  }

  try {
    const result = await runTool(name, args as Record<string, unknown>);
    return successResponse(id, {
      content: [{ type: "text", text: JSON.stringify(result) }],
    });
  } catch (err) {
    // Tool execution failures are results with isError, not protocol errors,
    // so the agent can read the failure and react (per MCP tools spec).
    const message = err instanceof Error ? err.message : String(err);
    return successResponse(id, {
      content: [{ type: "text", text: JSON.stringify({ error: message }) }],
      isError: true,
    });
  }
}

/**
 * Handle a single parsed JSON-RPC message. Returns the response object to
 * write to stdout, or null when no response is due (notifications).
 *
 * Pure protocol handler: no stdio, fully unit-testable.
 */
export async function handleMcpMessage(msg: unknown): Promise<object | null> {
  if (typeof msg !== "object" || msg === null || Array.isArray(msg)) {
    return errorResponse(null, INVALID_REQUEST, "Invalid Request: expected a JSON-RPC 2.0 object");
  }

  const req = msg as { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown };
  const hasId = typeof req.id === "string" || typeof req.id === "number";
  const id: JsonRpcId = hasId ? (req.id as string | number) : null;

  if (req.jsonrpc !== "2.0" || typeof req.method !== "string") {
    return errorResponse(id, INVALID_REQUEST, "Invalid Request: jsonrpc must be \"2.0\" and method a string");
  }

  const method = req.method;

  // Notifications never get a response.
  if (method.startsWith("notifications/")) {
    return null;
  }

  switch (method) {
    case "initialize":
      return successResponse(id, buildInitializeResult(req.params));

    case "ping":
      return successResponse(id, {});

    case "tools/list":
      return successResponse(id, { tools: TOOL_DEFINITIONS });

    case "tools/call":
      return handleToolsCall(id, req.params);

    default:
      // Unknown notification (no id): stay silent per JSON-RPC 2.0.
      if (!hasId) return null;
      return errorResponse(id, METHOD_NOT_FOUND, `Method not found: ${method}`);
  }
}

/**
 * Handle one raw line from the stdio transport. Returns the response object
 * or null (blank line / notification). Parse failures yield -32700.
 */
export async function handleMcpLine(line: string): Promise<object | null> {
  const trimmed = line.trim();
  if (trimmed === "") return null;

  let msg: unknown;
  try {
    msg = JSON.parse(trimmed);
  } catch {
    return errorResponse(null, PARSE_ERROR, "Parse error: invalid JSON");
  }
  return handleMcpMessage(msg);
}

// ---------------------------------------------------------------------------
// stdio transport
// ---------------------------------------------------------------------------

/**
 * Start the MCP server on stdio: newline-delimited JSON-RPC on stdin/stdout.
 * All diagnostics go to stderr; stdout carries only protocol messages.
 */
export function startMcpServer(): void {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });

  console.error(
    `${SERVER_NAME} MCP server v${SERVER_VERSION} listening on stdio (tools: ${TOOL_DEFINITIONS.map((t) => t.name).join(", ")})`,
  );

  // Serialize handling so responses keep arrival order even when a scan
  // is still running while the next message comes in.
  let queue: Promise<void> = Promise.resolve();

  rl.on("line", (line) => {
    queue = queue
      .then(async () => {
        const response = await handleMcpLine(line);
        if (response !== null) {
          process.stdout.write(`${JSON.stringify(response)}\n`);
        }
      })
      .catch((err) => {
        console.error(`mcp-server: unexpected error: ${err instanceof Error ? err.message : String(err)}`);
      });
  });

  rl.on("close", () => {
    void queue.then(() => process.exit(0));
  });
}
