/**
 * Bounded HTTPS retrieval for untrusted registry metadata and artifacts.
 *
 * The callers choose explicit byte, redirect, and wall-clock limits. Redirects
 * are followed manually so every hop is revalidated before a request is made.
 */

import * as fs from "node:fs";
import * as https from "node:https";
import type { IncomingMessage } from "node:http";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export interface RemoteRequestLimits {
  maxBytes: number;
  timeoutMs: number;
  maxRedirects: number;
  headers?: Record<string, string>;
  validateUrl?: (
    url: string,
    context: { redirectCount: number },
  ) => void;
}

export interface RemoteFetchResult<T> {
  body: T;
  bytes: number;
  finalUrl: string;
}

export class RemoteHttpStatusError extends Error {
  constructor(
    readonly statusCode: number | undefined,
    readonly url: string,
  ) {
    super(`HTTPS request failed with status ${statusCode ?? "unknown"} for ${url}`);
    this.name = "RemoteHttpStatusError";
  }
}

export class RemoteBodyTooLargeError extends Error {
  constructor(
    readonly maxBytes: number,
    readonly url: string,
  ) {
    super(`HTTPS response exceeded the ${maxBytes}-byte limit for ${url}`);
    this.name = "RemoteBodyTooLargeError";
  }
}

function validateLimits(limits: RemoteRequestLimits): void {
  if (!Number.isSafeInteger(limits.maxBytes) || limits.maxBytes <= 0) {
    throw new Error("Remote maxBytes must be a positive safe integer");
  }
  if (!Number.isSafeInteger(limits.timeoutMs) || limits.timeoutMs <= 0) {
    throw new Error("Remote timeoutMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(limits.maxRedirects) || limits.maxRedirects < 0) {
    throw new Error("Remote maxRedirects must be a non-negative safe integer");
  }
}

function parseHttpsUrl(rawUrl: string, base?: URL): URL {
  let parsed: URL;
  try {
    parsed = base ? new URL(rawUrl, base) : new URL(rawUrl);
  } catch {
    throw new Error(`Remote URL is invalid: ${rawUrl}`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error(
      `Remote URL must use https:, got "${parsed.protocol}" (${parsed.toString()})`,
    );
  }
  if (parsed.username || parsed.password) {
    throw new Error(`Remote URL must not contain credentials: ${parsed.toString()}`);
  }
  return parsed;
}

function requestOptions(
  url: URL,
  headers: Record<string, string> | undefined,
): https.RequestOptions {
  return {
    protocol: "https:",
    hostname: url.hostname,
    port: url.port || undefined,
    path: `${url.pathname}${url.search}`,
    method: "GET",
    headers,
  };
}

function timeoutError(timeoutMs: number, url: string): Error {
  return new Error(`HTTPS request timed out after ${timeoutMs}ms for ${url}`);
}

function openResponse(
  url: URL,
  headers: Record<string, string> | undefined,
  timeoutMs: number,
): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let request: ReturnType<typeof https.get> | undefined;
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    };
    const timer = setTimeout(() => {
      const error = timeoutError(timeoutMs, url.toString());
      request?.destroy?.(error);
      fail(error);
    }, timeoutMs);

    try {
      request = https.get(requestOptions(url, headers), (response) => {
        if (settled) {
          response.destroy?.();
          return;
        }
        settled = true;
        clearTimeout(timer);
        resolve(response);
      });
      request.on("error", (error) => fail(error));
      request.setTimeout?.(timeoutMs, () => {
        const error = timeoutError(timeoutMs, url.toString());
        request?.destroy?.(error);
        fail(error);
      });
    } catch (error) {
      fail(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

function declaredLength(response: IncomingMessage): bigint | undefined {
  const raw = response.headers?.["content-length"];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== "string" || !/^\d+$/.test(value)) return undefined;
  try {
    return BigInt(value);
  } catch {
    return undefined;
  }
}

function refuseOversizedDeclaredBody(
  response: IncomingMessage,
  maxBytes: number,
  url: string,
): void {
  const length = declaredLength(response);
  if (length !== undefined && length > BigInt(maxBytes)) {
    discardResponse(response);
    throw new RemoteBodyTooLargeError(maxBytes, url);
  }
}

function discardResponse(response: IncomingMessage): void {
  // Redirect and rejected-status bodies are untrusted and unused. Destroy the
  // response instead of draining an unbounded body in the background.
  response.on("error", () => undefined);
  response.destroy?.();
}

async function finalResponse(
  rawUrl: string,
  limits: RemoteRequestLimits,
): Promise<{ response: IncomingMessage; url: URL; deadline: number }> {
  validateLimits(limits);
  const deadline = Date.now() + limits.timeoutMs;
  let current = parseHttpsUrl(rawUrl);
  let redirectCount = 0;

  while (true) {
    limits.validateUrl?.(current.toString(), { redirectCount });
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw timeoutError(limits.timeoutMs, current.toString());
    }

    const response = await openResponse(current, limits.headers, remaining);
    const status = response.statusCode;
    if (status !== undefined && REDIRECT_STATUSES.has(status)) {
      const location = response.headers.location;
      discardResponse(response);
      if (!location) {
        throw new Error(`HTTPS redirect did not provide a Location header for ${current}`);
      }
      if (redirectCount >= limits.maxRedirects) {
        throw new Error(
          `HTTPS request exceeded the ${limits.maxRedirects}-redirect limit for ${rawUrl}`,
        );
      }
      current = parseHttpsUrl(location, current);
      redirectCount++;
      continue;
    }

    if (status !== 200) {
      discardResponse(response);
      throw new RemoteHttpStatusError(status, current.toString());
    }
    refuseOversizedDeclaredBody(response, limits.maxBytes, current.toString());
    return { response, url: current, deadline };
  }
}

function readBoundedBody(
  response: IncomingMessage,
  url: string,
  maxBytes: number,
  timeoutMs: number,
): Promise<{ body: Buffer; bytes: number }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let bytes = 0;
    const chunks: Buffer[] = [];
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve({ body: Buffer.concat(chunks, bytes), bytes });
    };
    const timer = setTimeout(() => {
      const error = timeoutError(timeoutMs, url);
      finish(error);
      response.destroy?.(error);
    }, timeoutMs);

    response.on("error", (error) => finish(error));
    response.on("data", (rawChunk: Buffer | string) => {
      if (settled) return;
      const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
      if (bytes + chunk.length > maxBytes) {
        const error = new RemoteBodyTooLargeError(maxBytes, url);
        finish(error);
        response.destroy?.(error);
        return;
      }
      bytes += chunk.length;
      chunks.push(chunk);
    });
    response.on("end", () => finish());
  });
}

/** Fetch an HTTPS response into memory, rejecting before an over-limit chunk is buffered. */
export async function fetchHttpsBuffer(
  url: string,
  limits: RemoteRequestLimits,
): Promise<RemoteFetchResult<Buffer>> {
  const opened = await finalResponse(url, limits);
  const remaining = opened.deadline - Date.now();
  if (remaining <= 0) {
    opened.response.destroy?.();
    throw timeoutError(limits.timeoutMs, opened.url.toString());
  }
  const result = await readBoundedBody(
    opened.response,
    opened.url.toString(),
    limits.maxBytes,
    remaining,
  );
  return { ...result, finalUrl: opened.url.toString() };
}

/** Stream an HTTPS response to disk through a byte-counting transform. */
export async function downloadHttpsFile(
  url: string,
  destination: string,
  limits: RemoteRequestLimits,
): Promise<Omit<RemoteFetchResult<never>, "body">> {
  const opened = await finalResponse(url, limits);
  const remaining = opened.deadline - Date.now();
  if (remaining <= 0) {
    opened.response.destroy?.();
    throw timeoutError(limits.timeoutMs, opened.url.toString());
  }

  let bytes = 0;
  const limiter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      if (bytes + chunk.length > limits.maxBytes) {
        callback(new RemoteBodyTooLargeError(limits.maxBytes, opened.url.toString()));
        return;
      }
      bytes += chunk.length;
      callback(null, chunk);
    },
  });
  const file = fs.createWriteStream(destination, { flags: "w" });
  let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timeoutTimer = setTimeout(() => {
      const error = timeoutError(limits.timeoutMs, opened.url.toString());
      opened.response.destroy?.(error);
      limiter.destroy(error);
      file.destroy(error);
      reject(error);
    }, remaining);
  });
  const transfer = pipeline(opened.response, limiter, file);

  try {
    await Promise.race([transfer, timeout]);
    return { bytes, finalUrl: opened.url.toString() };
  } catch (error) {
    // A timeout wins the race before the write stream necessarily closes.
    // Wait for pipeline cleanup so Windows can remove the partial file too.
    await transfer.catch(() => undefined);
    try {
      fs.rmSync(destination, { force: true });
    } catch {
      // Best-effort cleanup; preserve the acquisition error.
    }
    throw error;
  } finally {
    if (timeoutTimer !== undefined) clearTimeout(timeoutTimer);
  }
}
