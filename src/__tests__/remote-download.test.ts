import { EventEmitter } from "node:events";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Readable } from "node:stream";
import { beforeEach, describe, expect, it, vi } from "vitest";

const httpsMock = vi.hoisted(() => ({ get: vi.fn() }));

vi.mock("node:https", () => ({
  default: { get: httpsMock.get },
  get: httpsMock.get,
}));

import {
  downloadHttpsFile,
  fetchHttpsBuffer,
  RemoteBodyTooLargeError,
  RemoteHttpStatusError,
} from "../remote-download.js";

type ResponseLike = Readable & {
  statusCode: number;
  headers: Record<string, string>;
};

interface ResponseSpec {
  status: number;
  headers?: Record<string, string>;
  chunks?: Buffer[];
}

function makeResponse(spec: ResponseSpec): ResponseLike {
  const response = Readable.from(spec.chunks ?? []) as ResponseLike;
  response.statusCode = spec.status;
  response.headers = spec.headers ?? {};
  return response;
}

function mockResponses(specs: ResponseSpec[]): void {
  let index = 0;
  httpsMock.get.mockImplementation(
    (_options: unknown, callback: (response: ResponseLike) => void) => {
      const request = new EventEmitter() as EventEmitter & {
        destroy: (error?: Error) => void;
        setTimeout: () => void;
      };
      request.setTimeout = vi.fn();
      request.destroy = (error?: Error) => {
        if (error) request.emit("error", error);
      };
      const spec = specs[Math.min(index++, specs.length - 1)]!;
      process.nextTick(() => callback(makeResponse(spec)));
      return request;
    },
  );
}

const LIMITS = {
  maxBytes: 16,
  timeoutMs: 1_000,
  maxRedirects: 2,
};

describe("bounded HTTPS retrieval", () => {
  beforeEach(() => {
    httpsMock.get.mockReset();
  });

  it("rejects non-HTTPS URLs before opening a request", async () => {
    await expect(fetchHttpsBuffer("http://example.test/a", LIMITS)).rejects.toThrow(
      "must use https:",
    );
    expect(httpsMock.get).not.toHaveBeenCalled();
  });

  it("resolves relative redirects and validates every hop", async () => {
    mockResponses([
      { status: 302, headers: { location: "/final" } },
      { status: 200, chunks: [Buffer.from("safe")] },
    ]);
    const hops: string[] = [];
    const result = await fetchHttpsBuffer("https://example.test/start", {
      ...LIMITS,
      validateUrl: (url) => hops.push(url),
    });

    expect(result.body.toString()).toBe("safe");
    expect(result.finalUrl).toBe("https://example.test/final");
    expect(hops).toEqual([
      "https://example.test/start",
      "https://example.test/final",
    ]);
  });

  it("rejects a redirect that downgrades to HTTP before the next request", async () => {
    mockResponses([{
      status: 302,
      headers: { location: "http://example.test/insecure" },
    }]);

    await expect(
      fetchHttpsBuffer("https://example.test/start", LIMITS),
    ).rejects.toThrow("must use https:");
    expect(httpsMock.get).toHaveBeenCalledOnce();
  });

  it("enforces the redirect limit", async () => {
    mockResponses([{ status: 302, headers: { location: "/again" } }]);
    await expect(fetchHttpsBuffer("https://example.test/start", {
      ...LIMITS,
      maxRedirects: 0,
    })).rejects.toThrow("0-redirect limit");
    expect(httpsMock.get).toHaveBeenCalledOnce();
  });

  it("rejects a non-200 final response", async () => {
    mockResponses([{ status: 206, chunks: [Buffer.from("partial")] }]);
    await expect(fetchHttpsBuffer("https://example.test/a", LIMITS)).rejects.toBeInstanceOf(
      RemoteHttpStatusError,
    );
  });

  it("rejects a declared body that exceeds the byte cap", async () => {
    mockResponses([{
      status: 200,
      headers: { "content-length": "17" },
      chunks: [Buffer.from("not-read")],
    }]);
    await expect(fetchHttpsBuffer("https://example.test/a", LIMITS)).rejects.toBeInstanceOf(
      RemoteBodyTooLargeError,
    );
  });

  it("rejects before buffering a chunk that crosses the byte cap", async () => {
    mockResponses([{
      status: 200,
      chunks: [Buffer.alloc(10), Buffer.alloc(7)],
    }]);
    await expect(fetchHttpsBuffer("https://example.test/a", LIMITS)).rejects.toBeInstanceOf(
      RemoteBodyTooLargeError,
    );
  });

  it("removes a partial file when streamed bytes cross the cap", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-remote-test-"));
    const destination = path.join(tempDir, "artifact.bin");
    mockResponses([{
      status: 200,
      chunks: [Buffer.alloc(10), Buffer.alloc(7)],
    }]);
    try {
      await expect(
        downloadHttpsFile("https://example.test/a", destination, LIMITS),
      ).rejects.toBeInstanceOf(RemoteBodyTooLargeError);
      expect(fs.existsSync(destination)).toBe(false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("times out a request that never returns headers", async () => {
    httpsMock.get.mockImplementation(() => {
      const request = new EventEmitter() as EventEmitter & {
        destroy: (error?: Error) => void;
        setTimeout: () => void;
      };
      request.setTimeout = vi.fn();
      request.destroy = (error?: Error) => {
        if (error) request.emit("error", error);
      };
      return request;
    });

    await expect(fetchHttpsBuffer("https://example.test/hang", {
      ...LIMITS,
      timeoutMs: 10,
    })).rejects.toThrow("timed out");
  });

  it("applies the same wall-clock timeout while reading the body", async () => {
    httpsMock.get.mockImplementation(
      (_options: unknown, callback: (response: ResponseLike) => void) => {
        const request = new EventEmitter() as EventEmitter & {
          destroy: (error?: Error) => void;
          setTimeout: () => void;
        };
        request.setTimeout = vi.fn();
        request.destroy = (error?: Error) => {
          if (error) request.emit("error", error);
        };
        const response = new Readable({ read: () => undefined }) as ResponseLike;
        response.statusCode = 200;
        response.headers = {};
        process.nextTick(() => callback(response));
        return request;
      },
    );

    await expect(fetchHttpsBuffer("https://example.test/stalled-body", {
      ...LIMITS,
      timeoutMs: 10,
    })).rejects.toThrow("timed out");
  });

  it("waits for stream cleanup and removes a partial file after timeout", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-remote-timeout-"));
    const destination = path.join(tempDir, "artifact.bin");
    httpsMock.get.mockImplementation(
      (_options: unknown, callback: (response: ResponseLike) => void) => {
        const request = new EventEmitter() as EventEmitter & {
          destroy: (error?: Error) => void;
          setTimeout: () => void;
        };
        request.setTimeout = vi.fn();
        request.destroy = (error?: Error) => {
          if (error) request.emit("error", error);
        };
        let emitted = false;
        const response = new Readable({
          read() {
            if (!emitted) {
              emitted = true;
              this.push(Buffer.from("partial"));
            }
          },
        }) as ResponseLike;
        response.statusCode = 200;
        response.headers = {};
        process.nextTick(() => callback(response));
        return request;
      },
    );

    try {
      await expect(downloadHttpsFile("https://example.test/stalled-file", destination, {
        ...LIMITS,
        timeoutMs: 10,
      })).rejects.toThrow("timed out");
      expect(fs.existsSync(destination)).toBe(false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
