import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { PassThrough } from "node:stream";
import type { ScanReport } from "../types.js";

// The scanner is replaced so a "slow scan" is under the test's control.
const scanControl = vi.hoisted(() => ({
  pending: [] as Array<(report: unknown) => void>,
}));

vi.mock("../scanner.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../scanner.js")>();
  return {
    ...original,
    scan: vi.fn(
      () =>
        new Promise((resolve) => {
          scanControl.pending.push(resolve);
        }),
    ),
  };
});

import { startMcpServer, createLineReader, MCP_LIMITS } from "../mcp-server.js";

const EMPTY_REPORT = {
  target: "x",
  scanType: "directory",
  score: 0,
  riskLevel: "clean",
  findings: [],
  recommendations: [],
  summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
} as unknown as ScanReport;

interface Harness {
  input: PassThrough;
  responses: Array<Record<string, unknown>>;
  closed: Promise<void>;
  waitFor(predicate: (r: Record<string, unknown>) => boolean, label: string): Promise<Record<string, unknown>>;
}

function startHarness(): Harness {
  const input = new PassThrough();
  const output = new PassThrough();
  const responses: Array<Record<string, unknown>> = [];
  let buffer = "";
  output.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf-8");
    let nl: number;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      responses.push(JSON.parse(buffer.slice(0, nl)) as Record<string, unknown>);
      buffer = buffer.slice(nl + 1);
    }
  });
  let closeResolve!: () => void;
  const closed = new Promise<void>((resolve) => { closeResolve = resolve; });
  startMcpServer({ input, output, onClose: closeResolve });

  const waitFor: Harness["waitFor"] = async (predicate, label) => {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      const hit = responses.find(predicate);
      if (hit) return hit;
      await new Promise((r) => setTimeout(r, 5));
    }
    throw new Error(`timed out waiting for: ${label}; got ${JSON.stringify(responses)}`);
  };
  return { input, responses, closed, waitFor };
}

const ping = (id: number): string => `${JSON.stringify({ jsonrpc: "2.0", id, method: "ping" })}\n`;

describe("MCP stdio transport", () => {
  let tmp: string;
  const saved = { ...MCP_LIMITS };

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scg-mcp-transport-"));
    scanControl.pending.length = 0;
    vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    Object.assign(MCP_LIMITS, saved);
    fs.rmSync(tmp, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  describe("oversized lines (F26)", () => {
    it("should discard a line over the cap, answer -32700 and keep serving", async () => {
      MCP_LIMITS.maxLineBytes = 1024;
      const h = startHarness();
      h.input.write(ping(1));
      await h.waitFor((r) => r.id === 1, "first ping");

      // 8 KiB of garbage in several chunks, no newline until the end.
      for (let i = 0; i < 8; i++) h.input.write("x".repeat(1024));
      h.input.write("\n");
      h.input.write(ping(2));

      const parseError = await h.waitFor((r) => r.id === null, "parse error");
      expect((parseError.error as { code: number }).code).toBe(-32700);
      // The answer is the line-limit one, not the invalid-JSON one the same bytes would give.
      expect((parseError.error as { message: string }).message).toContain("line limit");
      await h.waitFor((r) => r.id === 2, "ping after the oversized line");
      // One report for one oversized line, not one per chunk.
      expect(h.responses.filter((r) => r.id === null)).toHaveLength(1);
      h.input.end();
      await h.closed;
    });

    it("should discard an oversized line that ends the stream without a newline", async () => {
      MCP_LIMITS.maxLineBytes = 256;
      const h = startHarness();
      h.input.write("y".repeat(2000));
      h.input.end();
      await h.closed;
      const reports = h.responses.filter((r) => r.id === null);
      expect(reports).toHaveLength(1);
      expect((reports[0]!.error as { message: string }).message).toContain("line limit");
    });

    it("should accept a line exactly at the cap", () => {
      const lines: string[] = [];
      const oversize = vi.fn();
      const reader = createLineReader(8, (l) => lines.push(l), oversize);
      reader.push(Buffer.from("12345678\n123456789\nok\n"));
      expect(lines).toEqual(["12345678", "ok"]);
      expect(oversize).toHaveBeenCalledTimes(1);
    });

    it("should reassemble a multi-byte character split across chunks", () => {
      const lines: string[] = [];
      const reader = createLineReader(1024, (l) => lines.push(l), () => undefined);
      const bytes = Buffer.from("héllo ✓\n", "utf-8");
      for (const b of bytes) reader.push(Buffer.from([b]));
      expect(lines).toEqual(["héllo ✓"]);
    });

    it("should deliver a final line that has no trailing newline", () => {
      const lines: string[] = [];
      const reader = createLineReader(1024, (l) => lines.push(l), () => undefined);
      reader.push(Buffer.from("a\nb"));
      reader.end();
      expect(lines).toEqual(["a", "b"]);
    });
  });

  describe("long scans (F11)", () => {
    it("should answer ping, tools/list and ioc_lookup while a scan is still running", async () => {
      const h = startHarness();
      h.input.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 10, method: "tools/call", params: { name: "scan_directory", arguments: { path: tmp } } })}\n`,
      );
      await vi.waitFor(() => expect(scanControl.pending).toHaveLength(1));

      h.input.write(ping(11));
      h.input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 12, method: "tools/list" })}\n`);
      h.input.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 13, method: "tools/call", params: { name: "ioc_lookup", arguments: { indicator: "example.test" } } })}\n`,
      );
      await h.waitFor((r) => r.id === 11, "ping during scan");
      await h.waitFor((r) => r.id === 12, "tools/list during scan");
      await h.waitFor((r) => r.id === 13, "ioc_lookup during scan");
      expect(h.responses.some((r) => r.id === 10)).toBe(false);

      scanControl.pending[0]!(EMPTY_REPORT);
      await h.waitFor((r) => r.id === 10, "scan result");
      h.input.end();
      await h.closed;
    });

    it("should still run scans one at a time, in arrival order", async () => {
      const h = startHarness();
      for (const id of [20, 21]) {
        h.input.write(
          `${JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "scan_directory", arguments: { path: tmp } } })}\n`,
        );
      }
      await vi.waitFor(() => expect(scanControl.pending).toHaveLength(1));
      await new Promise((r) => setTimeout(r, 30));
      expect(scanControl.pending).toHaveLength(1); // the second scan has not started
      scanControl.pending[0]!(EMPTY_REPORT);
      await vi.waitFor(() => expect(scanControl.pending).toHaveLength(2));
      scanControl.pending[1]!(EMPTY_REPORT);
      await h.waitFor((r) => r.id === 21, "second scan");
      expect(h.responses.map((r) => r.id).filter((id) => id === 20 || id === 21)).toEqual([20, 21]);
      h.input.end();
      await h.closed;
    });

    it("should answer a scan that never finishes with an error and move on", async () => {
      MCP_LIMITS.toolTimeoutMs = 50;
      const h = startHarness();
      h.input.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 30, method: "tools/call", params: { name: "scan_directory", arguments: { path: tmp } } })}\n`,
      );
      const timedOut = await h.waitFor((r) => r.id === 30, "timeout answer");
      const result = timedOut.result as { isError?: boolean; content: Array<{ text: string }> };
      expect(result.isError).toBe(true);
      expect(result.content[0]!.text).toContain("did not finish");
      h.input.write(ping(31));
      await h.waitFor((r) => r.id === 31, "ping after timeout");
      h.input.end();
      await h.closed;
    });
  });
});
