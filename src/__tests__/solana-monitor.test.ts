import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

// Create a temp home dir for watchlist isolation (hoisted so vi.mock can use it)
const { TEST_HOME } = vi.hoisted(() => ({
  TEST_HOME: `/tmp/scg-test-home-${process.pid}-${Date.now()}`,
}));

// Mock node:os so the module-level CONFIG_DIR uses our temp dir
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: () => TEST_HOME };
});

// Mock node:https before importing the module
vi.mock("node:https", () => {
  const mockRequest = vi.fn();
  return {
    default: { request: mockRequest },
    request: mockRequest,
  };
});

import * as https from "node:https";
import {
  checkWallet,
  monitorWallet,
  loadWatchlist,
  saveWatchlist,
  addToWatchlist,
  removeFromWatchlist,
  listWatchlist,
  formatAlert,
  __setSleepForTesting,
  type C2Alert,
} from "../solana-monitor.js";

/**
 * Helper: configure the mocked https.request to return a given JSON-RPC response.
 * Supports multiple sequential calls via an array of responses.
 */
function mockRpcResponses(responses: Array<{ result?: unknown; error?: { message: string } }>): void {
  let callIndex = 0;
  const mockedRequest = https.request as ReturnType<typeof vi.fn>;
  mockedRequest.mockImplementation((_opts: unknown, cb: (res: { on: (event: string, handler: (chunk?: Buffer) => void) => void }) => void) => {
    const resp = responses[callIndex] ?? responses[responses.length - 1];
    callIndex++;
    const body = JSON.stringify(resp);

    cb({
      on(event: string, handler: (chunk?: Buffer) => void) {
        if (event === "data") handler(Buffer.from(body));
        if (event === "end") handler();
      },
    });

    return {
      on: vi.fn(),
      write: vi.fn(),
      end: vi.fn(),
    };
  });
}

/**
 * Like mockRpcResponses but lets each entry override HTTP status and headers
 * (so tests can simulate a 429 or a Retry-After header).
 */
function mockRpcResponsesWithStatus(
  responses: Array<{
    status?: number;
    headers?: Record<string, string>;
    body?: { result?: unknown; error?: { code?: number; message: string } };
  }>,
): void {
  let callIndex = 0;
  const mockedRequest = https.request as ReturnType<typeof vi.fn>;
  mockedRequest.mockImplementation((_opts: unknown, cb: (res: unknown) => void) => {
    const resp = responses[callIndex] ?? responses[responses.length - 1];
    callIndex++;
    const body = JSON.stringify(resp.body ?? {});

    cb({
      statusCode: resp.status ?? 200,
      headers: resp.headers ?? {},
      on(event: string, handler: (chunk?: Buffer) => void) {
        if (event === "data") handler(Buffer.from(body));
        if (event === "end") handler();
      },
    });

    return { on: vi.fn(), write: vi.fn(), end: vi.fn() };
  });
}

/**
 * Helper: configure mock to simulate a network error.
 */
function mockRpcError(errorMessage: string): void {
  const mockedRequest = https.request as ReturnType<typeof vi.fn>;
  mockedRequest.mockImplementation((_opts: unknown, _cb: unknown) => {
    const req = {
      on: vi.fn((event: string, handler: (err: Error) => void) => {
        if (event === "error") {
          setTimeout(() => handler(new Error(errorMessage)), 0);
        }
      }),
      write: vi.fn(),
      end: vi.fn(),
    };
    return req;
  });
}

describe("Solana Monitor", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Make rate-limit retries instant by stubbing the sleep helper.
    __setSleepForTesting(() => Promise.resolve());
  });

  afterAll(() => {
    __setSleepForTesting(null);
  });

  // ─── checkWallet ──────────────────────────────────────────

  describe("checkWallet", () => {
    it("should return empty array when no signatures exist", async () => {
      mockRpcResponses([{ result: [] }]);
      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toEqual([]);
    });

    it("should return transactions with memos", async () => {
      mockRpcResponses([
        { result: [{ signature: "sig1" }] },
        {
          result: {
            blockTime: 1700000000,
            transaction: {
              message: {
                instructions: [
                  {
                    programId: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                    parsed: "https://evil.com/payload",
                  },
                ],
              },
            },
          },
        },
      ]);

      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toHaveLength(1);
      expect(results[0].memos).toContain("https://evil.com/payload");
      expect(results[0].signature).toBe("sig1");
      expect(results[0].blockTime).toBe(1700000000);
    });

    it("should skip transactions without memo instructions", async () => {
      mockRpcResponses([
        { result: [{ signature: "sig1" }] },
        {
          result: {
            blockTime: 1700000000,
            transaction: {
              message: {
                instructions: [
                  { programId: "11111111111111111111111111111111", data: "transfer" },
                ],
              },
            },
          },
        },
      ]);

      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toHaveLength(0);
    });

    it("should extract memos from inner instructions", async () => {
      mockRpcResponses([
        { result: [{ signature: "sig1" }] },
        {
          result: {
            blockTime: null,
            transaction: { message: { instructions: [] } },
            meta: {
              innerInstructions: [
                {
                  instructions: [
                    {
                      programId: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                      parsed: "inner-memo-text",
                    },
                  ],
                },
              ],
            },
          },
        },
      ]);

      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toHaveLength(1);
      expect(results[0].memos).toContain("inner-memo-text");
    });

    it("should return null blockTime when missing", async () => {
      mockRpcResponses([
        { result: [{ signature: "sig1" }] },
        {
          result: {
            transaction: {
              message: {
                instructions: [
                  {
                    programId: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                    data: "some-data",
                  },
                ],
              },
            },
          },
        },
      ]);

      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toHaveLength(1);
      expect(results[0].blockTime).toBeNull();
    });

    it("should handle null getTransaction response", async () => {
      mockRpcResponses([
        { result: [{ signature: "sig1" }] },
        { result: null },
      ]);

      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toHaveLength(0);
    });

    it("should handle multiple signatures", async () => {
      mockRpcResponses([
        { result: [{ signature: "sig1" }, { signature: "sig2" }] },
        {
          result: {
            blockTime: 1700000000,
            transaction: {
              message: {
                instructions: [
                  {
                    programId: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                    parsed: "memo1",
                  },
                ],
              },
            },
          },
        },
        {
          result: {
            blockTime: 1700000001,
            transaction: { message: { instructions: [] } },
          },
        },
      ]);

      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toHaveLength(1);
      expect(results[0].memos).toContain("memo1");
    });

    it("should handle RPC errors gracefully", async () => {
      mockRpcResponses([{ error: { message: "Invalid params" } }]);
      await expect(checkWallet("FakeAddr111", 5)).rejects.toThrow("Solana RPC error: Invalid params");
    });

    it("should handle network errors", async () => {
      mockRpcError("ECONNREFUSED");
      await expect(checkWallet("FakeAddr111", 5)).rejects.toThrow("ECONNREFUSED");
    });
  });

  // ─── Rate-limit handling (T-007) ──────────────────────────

  describe("Rate-limit handling", () => {
    it("should retry on HTTP 429 and succeed on the second attempt", async () => {
      mockRpcResponsesWithStatus([
        { status: 429, body: {} },
        { status: 200, body: { result: [] } },
      ]);

      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toEqual([]);
      expect(https.request).toHaveBeenCalledTimes(2);
    });

    it("should retry on JSON-RPC -32005 and succeed", async () => {
      mockRpcResponsesWithStatus([
        { status: 200, body: { error: { code: -32005, message: "Node is behind by 1234 slots" } } },
        { status: 200, body: { result: [] } },
      ]);

      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toEqual([]);
      expect(https.request).toHaveBeenCalledTimes(2);
    });

    it("should honor the Retry-After header when present", async () => {
      const sleepCalls: number[] = [];
      __setSleepForTesting(async (ms) => {
        sleepCalls.push(ms);
      });

      mockRpcResponsesWithStatus([
        { status: 429, headers: { "retry-after": "2" }, body: {} },
        { status: 200, body: { result: [] } },
      ]);

      await checkWallet("FakeAddr111", 5);
      // Retry-After: 2 -> 2000 ms (must override exponential backoff)
      expect(sleepCalls).toEqual([2000]);
    });

    it("should give up after the maximum number of retries", async () => {
      // 6 = 1 initial attempt + 5 retries; mock returns 429 forever.
      mockRpcResponsesWithStatus([
        { status: 429, body: {} },
      ]);

      await expect(checkWallet("FakeAddr111", 5)).rejects.toThrow(
        /HTTP 429|rate limited/i,
      );
      expect(https.request).toHaveBeenCalledTimes(6);
    });

    it("should not retry on non-rate-limit errors", async () => {
      mockRpcResponsesWithStatus([
        { status: 200, body: { error: { code: -32602, message: "Invalid params" } } },
      ]);

      await expect(checkWallet("FakeAddr111", 5)).rejects.toThrow("Invalid params");
      expect(https.request).toHaveBeenCalledTimes(1);
    });

    it("should treat 'too many requests' error messages as rate-limited", async () => {
      mockRpcResponsesWithStatus([
        { status: 200, body: { error: { message: "Too Many Requests" } } },
        { status: 200, body: { result: [] } },
      ]);

      const results = await checkWallet("FakeAddr111", 5);
      expect(results).toEqual([]);
      expect(https.request).toHaveBeenCalledTimes(2);
    });
  });

  // ─── formatAlert ──────────────────────────────────────────

  describe("formatAlert", () => {
    const baseAlert: C2Alert = {
      timestamp: "2026-01-01T00:00:00.000Z",
      wallet: "FakeAddr111",
      signature: "sig123abc",
      memo: "https://evil.com/c2",
      decodedUrls: ["https://evil.com/c2"],
      blockTime: 1700000000,
    };

    it("should format alert with all fields", () => {
      const output = formatAlert(baseAlert);
      expect(output).toContain("C2 MEMO DETECTED");
      expect(output).toContain("FakeAddr111");
      expect(output).toContain("sig123abc");
      expect(output).toContain("https://evil.com/c2");
    });

    it("should include URLs when present", () => {
      const output = formatAlert(baseAlert);
      expect(output).toContain("URLs:");
      expect(output).toContain("https://evil.com/c2");
    });

    it("should not include URLs line when empty", () => {
      const alert: C2Alert = { ...baseAlert, decodedUrls: [] };
      const output = formatAlert(alert);
      expect(output).not.toContain("URLs:");
    });

    it("should include block time when present", () => {
      const output = formatAlert(baseAlert);
      expect(output).toContain("Block:");
    });

    it("should not include block time when null", () => {
      const alert: C2Alert = { ...baseAlert, blockTime: null };
      const output = formatAlert(alert);
      expect(output).not.toContain("Block:");
    });

    it("should display multiple URLs", () => {
      const alert: C2Alert = {
        ...baseAlert,
        decodedUrls: ["https://evil.com/a", "https://evil.com/b"],
      };
      const output = formatAlert(alert);
      expect(output).toContain("https://evil.com/a");
      expect(output).toContain("https://evil.com/b");
    });
  });

  // ─── Watchlist persistence ────────────────────────────────

  describe("Watchlist operations", () => {
    const watchlistPath = path.join(TEST_HOME, ".supply-chain-guard", "watchlist.json");

    beforeEach(() => {
      // Clean watchlist before each test
      if (fs.existsSync(watchlistPath)) {
        fs.unlinkSync(watchlistPath);
      }
    });

    afterAll(() => {
      fs.rmSync(TEST_HOME, { recursive: true, force: true });
    });

    it("should return empty entries when no watchlist exists", () => {
      const config = loadWatchlist();
      expect(config.entries).toEqual([]);
    });

    it("should save and load watchlist", () => {
      const config = {
        entries: [
          { address: "Addr1", name: "Test Wallet", addedAt: "2026-01-01T00:00:00Z" },
        ],
      };
      saveWatchlist(config);
      const loaded = loadWatchlist();
      expect(loaded.entries).toHaveLength(1);
      expect(loaded.entries[0].address).toBe("Addr1");
    });

    it("should add a wallet to the watchlist", () => {
      const entry = addToWatchlist("Addr2", "Wallet Two");
      expect(entry.address).toBe("Addr2");
      expect(entry.name).toBe("Wallet Two");
      expect(entry.addedAt).toBeTruthy();

      const entries = listWatchlist();
      expect(entries).toHaveLength(1);
    });

    it("should throw when adding duplicate address", () => {
      addToWatchlist("Addr3", "First");
      expect(() => addToWatchlist("Addr3", "Second")).toThrow("already on the watchlist");
    });

    it("should remove a wallet from the watchlist", () => {
      addToWatchlist("Addr4", "ToRemove");
      expect(listWatchlist()).toHaveLength(1);

      removeFromWatchlist("Addr4");
      expect(listWatchlist()).toHaveLength(0);
    });

    it("should throw when removing non-existent address", () => {
      expect(() => removeFromWatchlist("NonExistent")).toThrow("not on the watchlist");
    });

    it("should list multiple entries", () => {
      addToWatchlist("A1", "W1");
      addToWatchlist("A2", "W2");
      addToWatchlist("A3", "W3");
      const entries = listWatchlist();
      expect(entries).toHaveLength(3);
    });
  });

  // ─── monitorWallet ────────────────────────────────────────

  describe("monitorWallet", () => {
    it("should set baseline on first poll and not alert", async () => {
      mockRpcResponses([
        { result: [{ signature: "baseline-sig" }] },
        { result: [{ signature: "baseline-sig" }] },
      ]);

      const alerts: C2Alert[] = [];
      const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      const promise = monitorWallet(
        { address: "Addr1", interval: 9999, limit: 5, format: "text" },
        (alert) => alerts.push(alert),
      );

      await new Promise((r) => setTimeout(r, 100));

      expect(alerts).toHaveLength(0);
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("Baseline set"));

      consoleSpy.mockRestore();
    });
  });
});
