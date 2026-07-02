import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  handleMcpMessage,
  handleMcpLine,
  SUPPORTED_PROTOCOL_VERSIONS,
  SERVER_NAME,
} from "../mcp-server.js";
import pkg from "../../package.json";

interface RpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

interface ToolCallResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

async function call(msg: unknown): Promise<RpcResponse> {
  const response = await handleMcpMessage(msg);
  expect(response).not.toBeNull();
  return response as RpcResponse;
}

async function callTool(
  name: string,
  args: Record<string, unknown>,
  id: string | number = 1,
): Promise<RpcResponse> {
  return call({
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name, arguments: args },
  });
}

function parseToolText(response: RpcResponse): Record<string, unknown> {
  const result = response.result as unknown as ToolCallResult;
  expect(Array.isArray(result.content)).toBe(true);
  expect(result.content[0]?.type).toBe("text");
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

describe("MCP Server", () => {
  describe("initialize handshake", () => {
    it("should mirror a supported protocolVersion and report serverInfo", async () => {
      const response = await call({
        jsonrpc: "2.0",
        id: 0,
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "test-client", version: "1.0.0" },
        },
      });

      expect(response.error).toBeUndefined();
      expect(response.id).toBe(0);
      const result = response.result!;
      expect(result.protocolVersion).toBe("2025-03-26");
      expect(result.capabilities).toEqual(
        expect.objectContaining({ tools: {} }),
      );
      expect(result.serverInfo).toEqual({
        name: SERVER_NAME,
        version: pkg.version,
      });
    });

    it("should answer an unsupported protocolVersion with the latest supported one", async () => {
      const response = await call({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "1999-01-01", capabilities: {} },
      });

      const result = response.result!;
      expect(result.protocolVersion).toBe(SUPPORTED_PROTOCOL_VERSIONS[0]);
    });

    it("should return null (no response) for the initialized notification", async () => {
      const response = await handleMcpMessage({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      });
      expect(response).toBeNull();
    });

    it("should respond to ping with an empty result", async () => {
      const response = await call({ jsonrpc: "2.0", id: 7, method: "ping" });
      expect(response.id).toBe(7);
      expect(response.result).toEqual({});
      expect(response.error).toBeUndefined();
    });
  });

  describe("tools/list", () => {
    it("should list exactly the 3 tools with valid input schemas", async () => {
      const response = await call({ jsonrpc: "2.0", id: 2, method: "tools/list" });
      const tools = response.result!.tools as Array<{
        name: string;
        description: string;
        inputSchema: { type: string; properties: object; required: string[] };
      }>;

      expect(tools.map((t) => t.name).sort()).toEqual([
        "ioc_lookup",
        "scan_directory",
        "scan_npm_package",
      ]);

      for (const tool of tools) {
        expect(tool.description.length).toBeGreaterThan(20);
        expect(tool.inputSchema.type).toBe("object");
        expect(Object.keys(tool.inputSchema.properties).length).toBeGreaterThan(0);
        expect(Array.isArray(tool.inputSchema.required)).toBe(true);
      }
    });

    it("should warn about registry downloads in the scan_npm_package description", async () => {
      const response = await call({ jsonrpc: "2.0", id: 3, method: "tools/list" });
      const tools = response.result!.tools as Array<{ name: string; description: string }>;
      const remote = tools.find((t) => t.name === "scan_npm_package")!;
      expect(remote.description.toLowerCase()).toContain("download");
      expect(remote.description.toLowerCase()).toContain("registry");
    });
  });

  describe("ioc_lookup tool", () => {
    it("should flag a bundled known-bad npm version (event-stream@3.3.6)", async () => {
      const response = await callTool("ioc_lookup", {
        ecosystem: "npm",
        name: "event-stream",
        version: "3.3.6",
      });

      const verdict = parseToolText(response);
      expect(verdict.verdict).toBe("malicious");
      const matches = verdict.matches as Array<Record<string, unknown>>;
      expect(matches.length).toBeGreaterThan(0);
      // Bundled feed entry carries campaign details; blocklist a description.
      expect(
        matches.some(
          (m) => m.campaign === "flatmap-stream" || String(m.description).includes("flatmap-stream"),
        ),
      ).toBe(true);
      for (const m of matches) {
        expect(m.category).toBe("malware");
        expect(typeof m.confidence).toBe("number");
      }
    });

    it("should flag an ecosystem-prefixed bundled IOC (ruby sleeper gem)", async () => {
      const response = await callTool("ioc_lookup", {
        ecosystem: "ruby",
        name: "knot-date-utils-rb",
      });

      const verdict = parseToolText(response);
      expect(verdict.verdict).toBe("malicious");
      const matches = verdict.matches as Array<Record<string, unknown>>;
      expect(matches[0]?.family).toBe("SleeperPkg");
    });

    it("should flag a bare-name PyPI IOC without a version (colorinal)", async () => {
      const response = await callTool("ioc_lookup", {
        ecosystem: "pypi",
        name: "colorinal",
      });

      const verdict = parseToolText(response);
      expect(verdict.verdict).toBe("malicious");
    });

    it("should return a clean verdict for a benign package", async () => {
      const response = await callTool("ioc_lookup", {
        ecosystem: "npm",
        name: "left-pad",
        version: "1.3.0",
      });

      const verdict = parseToolText(response);
      expect(verdict.verdict).toBe("clean");
      expect(verdict.matches).toEqual([]);
      const result = response.result as unknown as ToolCallResult;
      expect(result.isError).toBeUndefined();
    });
  });

  describe("scan_directory tool", () => {
    let tempDir: string;

    beforeEach(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-mcp-test-"));
    });

    afterEach(() => {
      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it("should scan a directory containing a malicious file and report findings", async () => {
      fs.writeFileSync(
        path.join(tempDir, "malicious.js"),
        'const lzcdrtfxyqiplpd = "marker";\neval(atob("dGVzdA=="));\n',
      );

      const response = await callTool("scan_directory", { path: tempDir });
      const summary = parseToolText(response);

      expect(summary.riskLevel).not.toBe("clean");
      expect(summary.totalFindings as number).toBeGreaterThan(0);
      const bySeverity = summary.findingsBySeverity as Record<string, number>;
      expect(bySeverity.critical).toBeGreaterThan(0);
      const top = summary.topFindings as Array<{ rule: string; severity: string }>;
      expect(top.length).toBeLessThanOrEqual(20);
      expect(top.some((f) => f.rule === "GLASSWORM_MARKER")).toBe(true);
    });

    it("should return isError for a nonexistent path instead of a protocol error", async () => {
      const response = await callTool("scan_directory", {
        path: path.join(tempDir, "does-not-exist"),
      });

      expect(response.error).toBeUndefined();
      const result = response.result as unknown as ToolCallResult;
      expect(result.isError).toBe(true);
      expect(result.content[0]?.type).toBe("text");
    });

    it("should reject an invalid minSeverity with -32602", async () => {
      const response = await callTool("scan_directory", {
        path: tempDir,
        minSeverity: "catastrophic",
      });
      expect(response.error?.code).toBe(-32602);
    });
  });

  describe("scan_npm_package tool (validation only, no network)", () => {
    it("should reject a missing name with -32602", async () => {
      const response = await callTool("scan_npm_package", {});
      expect(response.error?.code).toBe(-32602);
      expect(response.error?.message).toContain("name");
    });
  });

  describe("protocol errors", () => {
    it("should return -32601 for an unknown method", async () => {
      const response = await call({ jsonrpc: "2.0", id: 9, method: "resources/list" });
      expect(response.error?.code).toBe(-32601);
      expect(response.id).toBe(9);
    });

    it("should return -32700 for unparseable JSON input", async () => {
      const response = (await handleMcpLine('{"jsonrpc": "2.0", not json')) as RpcResponse;
      expect(response.error?.code).toBe(-32700);
      expect(response.id).toBeNull();
    });

    it("should return null for blank lines", async () => {
      expect(await handleMcpLine("   ")).toBeNull();
    });

    it("should return -32600 for a message without jsonrpc/method", async () => {
      const response = await call({ id: 4, hello: "world" });
      expect(response.error?.code).toBe(-32600);
    });

    it("should return -32602 for an unknown tool name", async () => {
      const response = await callTool("delete_everything", {});
      expect(response.error?.code).toBe(-32602);
      expect(response.error?.message).toContain("delete_everything");
    });

    it("should return -32602 for a missing required argument", async () => {
      const response = await callTool("ioc_lookup", { ecosystem: "npm" });
      expect(response.error?.code).toBe(-32602);
      expect(response.error?.message).toContain("name");
    });

    it("should return -32602 for an out-of-enum ecosystem", async () => {
      const response = await callTool("ioc_lookup", {
        ecosystem: "homebrew",
        name: "wget",
      });
      expect(response.error?.code).toBe(-32602);
    });

    it("should stay silent on unknown notifications (no id)", async () => {
      const response = await handleMcpMessage({
        jsonrpc: "2.0",
        method: "some/unknown-notification",
      });
      expect(response).toBeNull();
    });
  });

  describe("id echo correctness", () => {
    it("should echo string ids verbatim", async () => {
      const response = await call({ jsonrpc: "2.0", id: "req-abc-123", method: "ping" });
      expect(response.id).toBe("req-abc-123");
    });

    it("should echo numeric ids verbatim", async () => {
      const response = await call({ jsonrpc: "2.0", id: 42, method: "tools/list" });
      expect(response.id).toBe(42);
    });

    it("should echo the id on error responses too", async () => {
      const response = await call({ jsonrpc: "2.0", id: "err-id", method: "nope" });
      expect(response.id).toBe("err-id");
      expect(response.error?.code).toBe(-32601);
    });
  });

  describe("response shape", () => {
    it("should always stamp jsonrpc 2.0 on responses", async () => {
      const ok = await call({ jsonrpc: "2.0", id: 1, method: "ping" });
      const err = await call({ jsonrpc: "2.0", id: 2, method: "unknown" });
      expect(ok.jsonrpc).toBe("2.0");
      expect(err.jsonrpc).toBe("2.0");
    });

    it("should wrap tool results in an MCP content array", async () => {
      const response = await callTool("ioc_lookup", {
        ecosystem: "npm",
        name: "lodash",
      });
      const result = response.result as unknown as ToolCallResult;
      expect(result.content).toHaveLength(1);
      expect(result.content[0]).toEqual({
        type: "text",
        text: expect.stringContaining('"verdict"'),
      });
    });
  });
});
