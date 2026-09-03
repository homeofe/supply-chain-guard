/**
 * Issue 170: the remote threat feed is fetched with no timeout and no size cap.
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM feed.test.ts
 *
 * feed.test.ts mocks node:https wholesale and delivers the whole body inside one
 * `process.nextTick`. No test written against that mock can represent a peer that
 * stalls or trickles, which is how six passing refreshFeed tests coexisted with a
 * download that had no deadline at all. A bound is only proved by a peer that
 * misbehaves in real time, so every test here drives a real loopback server over
 * a real socket with real timers.
 *
 * node:https is redirected onto node:http so the server needs no certificate.
 * Everything a deadline depends on - socket, stream, timer, backpressure - is the
 * genuine article; only the TLS layer is not, and TLS has no bearing on whether a
 * request is bounded.
 *
 * HOW TO REDDEN EACH TEST (a test that cannot fail is not coverage):
 *
 *   - "sends headers and then stalls" and "trickles the body forever": restore the
 *     hand-rolled request in src/feed.ts httpsGetBody, or delete the
 *     `const limits` line in refreshFeed so the bounds never reach the download.
 *   - "trickles the body forever" ALONE: delete the absolute body deadline in
 *     src/remote-download.ts readBoundedBody (the `const timer = setTimeout(...)`
 *     and its clearTimeout). The stall test stays green on that mutation because
 *     the socket inactivity backstop still fires. That difference is the point:
 *     an inactivity timer looks like a working fix until the peer keeps sending.
 *   - the Content-Length tests: delete the `refuseOversizedDeclaredBody` call in
 *     src/remote-download.ts, or the `content-length` branch in
 *     src/threat-intel.ts readBoundedBody.
 *   - the streaming-cap tests: delete the `bytes + chunk.length > maxBytes` guard
 *     in src/remote-download.ts, or its twin in src/threat-intel.ts.
 *   - "package defaults" tests: raise FEED_REMOTE_LIMITS.maxBytes.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import type { AddressInfo, Socket } from "node:net";

vi.mock("node:https", async () => {
  const nodeHttp = await import("node:http");
  const get = (
    options: http.RequestOptions,
    callback: (response: http.IncomingMessage) => void,
  ): http.ClientRequest => nodeHttp.get({ ...options, protocol: "http:" }, callback);
  return { default: { get }, get };
});

import { refreshFeed } from "../feed.js";
import { FEED_CACHE_FILE, FEED_REMOTE_LIMITS, updateThreatFeed } from "../threat-intel.js";

/** Short enough to keep the suite fast, long enough to survive a loaded CI box. */
const DEADLINE_MS = 400;
/** Small enough that a few kilobytes cross it. */
const CAP_BYTES = 4096;
/** How long a test waits before declaring a call unbounded. */
const HORIZON_MS = 6000;
const NOT_BOUNDED = "STILL PENDING: the call never settled";
const RESOLVED = "RESOLVED: the call succeeded";

let tmpDir: string;
let servers: http.Server[] = [];
let sockets: Socket[] = [];
let timers: ReturnType<typeof setInterval>[] = [];

interface Peer {
  /** For refreshFeed, which refuses any scheme but https. */
  httpsUrl: string;
  /** For updateThreatFeed, which goes through the global fetch. */
  httpUrl: string;
}

function startPeer(handler: http.RequestListener): Promise<Peer> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.on("connection", (socket) => sockets.push(socket));
    server.listen(0, "127.0.0.1", () => {
      servers.push(server);
      const { port } = server.address() as AddressInfo;
      resolve({
        httpsUrl: `https://127.0.0.1:${port}/feed.json`,
        httpUrl: `http://127.0.0.1:${port}/feed.json`,
      });
    });
  });
}

/**
 * Headers, then silence. The peer never sends a body byte and never ends.
 *
 * flushHeaders() is load-bearing. writeHead() only stores the headers; Node
 * sends them with the first write or with end(). Without the flush this peer
 * would stall BEFORE the response line, which is the connect phase, not the
 * post-headers stall the issue reports.
 */
const headersThenStall: http.RequestListener = (_req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  res.flushHeaders();
};

/**
 * Headers, then one byte every sixth of the deadline, forever. A socket
 * inactivity timeout can never fire against this peer: it is never quiet for a
 * whole timeout window. Only an absolute deadline ends the call.
 */
const trickleForever: http.RequestListener = (_req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  const timer = setInterval(() => res.write("."), Math.floor(DEADLINE_MS / 6));
  timers.push(timer);
  res.on("close", () => clearInterval(timer));
};

/** Declares a length over the cap and then sends nothing at all. */
function declaresBytes(declared: number): http.RequestListener {
  return (_req, res) => {
    res.writeHead(200, {
      "content-type": "application/json",
      "content-length": String(declared),
    });
    res.flushHeaders();
  };
}

/** No declared length (so: chunked), streaming well past any small cap. */
const chunkedPastCap: http.RequestListener = (_req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  const chunk = "x".repeat(1024);
  let sent = 0;
  const pump = (): void => {
    while (sent < CAP_BYTES * 8) {
      sent += chunk.length;
      if (!res.write(chunk)) {
        res.once("drain", pump);
        return;
      }
    }
    res.end();
  };
  pump();
};

/**
 * Race a call against a horizon and return a STRING describing what happened.
 *
 * A bounded call rejects and yields its message. An unbounded one yields
 * NOT_BOUNDED, so "no deadline" fails as a plain assertion mismatch instead of
 * as a test-runner timeout, and the failure message names the defect.
 */
async function settle(call: Promise<unknown>, horizonMs = HORIZON_MS): Promise<string> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const horizon = new Promise<string>((resolve) => {
    timer = setTimeout(() => resolve(NOT_BOUNDED), horizonMs);
  });
  try {
    return await Promise.race([
      call.then(
        () => RESOLVED,
        (err: unknown) => (err instanceof Error ? err.message : String(err)),
      ),
      horizon,
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-issue170-"));
});

afterEach(async () => {
  for (const timer of timers) clearInterval(timer);
  timers = [];
  for (const socket of sockets) socket.destroy();
  sockets = [];
  await Promise.all(
    servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
  servers = [];
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("feed acquisition bounds (issue 170)", () => {
  it("names the default bounds as a frozen constant", () => {
    expect(FEED_REMOTE_LIMITS).toEqual({
      maxBytes: 32 * 1024 * 1024,
      timeoutMs: 30_000,
      maxRedirects: 5,
    });
    expect(Object.isFrozen(FEED_REMOTE_LIMITS)).toBe(true);
  });

  // -------------------------------------------------------------------------
  // refreshFeed: the path `supply-chain-guard feed refresh` runs.
  // -------------------------------------------------------------------------

  it("refreshFeed rejects a peer that sends headers and then stalls", async () => {
    const peer = await startPeer(headersThenStall);
    const started = Date.now();

    const outcome = await settle(refreshFeed(peer.httpsUrl, tmpDir, { timeoutMs: DEADLINE_MS }));

    // The number in the message is the deadline's REMAINING budget at the moment
    // the body read started, so it is 400ms minus the connect time, not a literal
    // 400. The wall clock below is what pins the bound.
    expect(outcome).toMatch(/Failed to refresh threat feed .*timed out after \d+ms/);
    expect(Date.now() - started).toBeLessThan(DEADLINE_MS * 10);
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  }, 20_000);

  it("refreshFeed rejects a peer that trickles the body forever", async () => {
    const peer = await startPeer(trickleForever);
    const started = Date.now();

    const outcome = await settle(refreshFeed(peer.httpsUrl, tmpDir, { timeoutMs: DEADLINE_MS }));

    // Not merely "it rejected": this peer defeats an inactivity timeout by
    // construction, so only an absolute deadline can produce this message.
    expect(outcome).toMatch(/Failed to refresh threat feed .*timed out after \d+ms/);
    expect(Date.now() - started).toBeLessThan(DEADLINE_MS * 10);
  }, 20_000);

  it("refreshFeed refuses a declared Content-Length over the cap before reading a byte", async () => {
    const peer = await startPeer(declaresBytes(CAP_BYTES * 2048));
    const started = Date.now();

    // Only maxBytes is overridden, so the deadline in force is the package
    // default of 30s. The peer sends no body at all. Rejecting in a fraction of
    // a second can therefore only be the declared-length refusal: a streamed
    // byte count would never trip, and the deadline is 30s away.
    const outcome = await settle(refreshFeed(peer.httpsUrl, tmpDir, { maxBytes: CAP_BYTES }));

    expect(outcome).toMatch(/exceeded the 4096-byte limit/);
    expect(Date.now() - started).toBeLessThan(FEED_REMOTE_LIMITS.timeoutMs);
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  }, 20_000);

  it("refreshFeed refuses a chunked body that streams past the cap", async () => {
    const peer = await startPeer(chunkedPastCap);

    const outcome = await settle(refreshFeed(peer.httpsUrl, tmpDir, { maxBytes: CAP_BYTES }));

    expect(outcome).toMatch(/exceeded the 4096-byte limit/);
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  }, 20_000);

  it("refreshFeed applies the package default cap when no override is passed", async () => {
    const peer = await startPeer(declaresBytes(FEED_REMOTE_LIMITS.maxBytes + 1));

    const outcome = await settle(refreshFeed(peer.httpsUrl, tmpDir));

    expect(outcome).toMatch(/exceeded the 33554432-byte limit/);
  }, 20_000);

  it("refreshFeed leaves an existing cache byte-identical when a bound fires", async () => {
    const cachePath = path.join(tmpDir, FEED_CACHE_FILE);
    fs.writeFileSync(
      cachePath,
      JSON.stringify({
        timestamp: new Date().toISOString(),
        entries: [
          {
            type: "domain",
            // Reserved .example TLD: a fixture, not an indicator.
            value: "issue-170-fixture.example",
            severity: "critical",
          },
        ],
      }),
    );
    const before = fs.readFileSync(cachePath);

    const peer = await startPeer(headersThenStall);
    const outcome = await settle(refreshFeed(peer.httpsUrl, tmpDir, { timeoutMs: DEADLINE_MS }));

    expect(outcome).toMatch(/(?:timed out after \d+ms|aborted)/);
    // Failing closed means the protection already in place survives the failure.
    expect(fs.readFileSync(cachePath).equals(before)).toBe(true);
  }, 20_000);

  // -------------------------------------------------------------------------
  // updateThreatFeed: the exported legacy API, on the global fetch.
  // -------------------------------------------------------------------------

  it("updateThreatFeed rejects a peer that sends headers and then stalls", async () => {
    const peer = await startPeer(headersThenStall);

    const outcome = await settle(
      updateThreatFeed(peer.httpUrl, tmpDir, { timeoutMs: DEADLINE_MS }),
    );

    expect(outcome).toBe(
      `Failed to update threat feed: HTTPS request timed out after ${DEADLINE_MS}ms for ${peer.httpUrl}`,
    );
  }, 20_000);

  it("updateThreatFeed rejects a peer that trickles the body forever", async () => {
    const peer = await startPeer(trickleForever);

    const outcome = await settle(
      updateThreatFeed(peer.httpUrl, tmpDir, { timeoutMs: DEADLINE_MS }),
    );

    // undici gives the global fetch a headers timeout and a body INACTIVITY
    // backstop. Neither fires against a peer that keeps sending, which is why
    // this case needs its own deadline and its own test.
    expect(outcome).toBe(
      `Failed to update threat feed: HTTPS request timed out after ${DEADLINE_MS}ms for ${peer.httpUrl}`,
    );
  }, 20_000);

  it("updateThreatFeed refuses a declared Content-Length over the cap before reading a byte", async () => {
    const peer = await startPeer(declaresBytes(CAP_BYTES * 2048));
    const started = Date.now();

    const outcome = await settle(updateThreatFeed(peer.httpUrl, tmpDir, { maxBytes: CAP_BYTES }));

    expect(outcome).toBe(
      `Failed to update threat feed: feed declares ${CAP_BYTES * 2048} bytes, over the ${CAP_BYTES}-byte limit, for ${peer.httpUrl}`,
    );
    expect(Date.now() - started).toBeLessThan(FEED_REMOTE_LIMITS.timeoutMs);
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  }, 20_000);

  it("updateThreatFeed refuses a chunked body that streams past the cap", async () => {
    const peer = await startPeer(chunkedPastCap);

    const outcome = await settle(updateThreatFeed(peer.httpUrl, tmpDir, { maxBytes: CAP_BYTES }));

    expect(outcome).toBe(
      `Failed to update threat feed: feed body exceeded the ${CAP_BYTES}-byte limit for ${peer.httpUrl}`,
    );
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  }, 20_000);

  it("updateThreatFeed applies the package default cap when no override is passed", async () => {
    const peer = await startPeer(declaresBytes(FEED_REMOTE_LIMITS.maxBytes + 1));

    const outcome = await settle(updateThreatFeed(peer.httpUrl, tmpDir));

    expect(outcome).toMatch(/over the 33554432-byte limit/);
  }, 20_000);

  // -------------------------------------------------------------------------
  // The healthy path still works, on both.
  // -------------------------------------------------------------------------

  it("both paths still accept a well-behaved feed within the bounds", async () => {
    const entries = [
      { type: "domain", value: "issue-170-fixture.example", severity: "critical" },
    ];
    const peer = await startPeer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ schema: 1, entries }));
    });
    const legacyPeer = await startPeer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(entries));
    });

    const refreshed = await refreshFeed(peer.httpsUrl, tmpDir, { timeoutMs: DEADLINE_MS });
    expect(refreshed.entryCount).toBe(1);

    const updated = await updateThreatFeed(legacyPeer.httpUrl, tmpDir, {
      timeoutMs: DEADLINE_MS,
    });
    expect(updated.added).toBe(1);
  }, 20_000);
});
