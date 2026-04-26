/**
 * Solana C2 wallet monitor
 *
 * Monitors Solana wallet addresses for transactions containing memo instructions.
 * GlassWorm and similar campaigns encode C2 URLs as Solana transaction memos,
 * making the blockchain an uncensorable command-and-control channel.
 */

import * as https from "node:https";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type {
  SolanaMonitorOptions,
  SolanaTransaction,
  WatchlistConfig,
  WatchlistEntry,
  WatchlistAlert,
} from "./types.js";

const SOLANA_RPC = "https://api.mainnet-beta.solana.com";
const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

// Rate-limit handling for the public Solana RPC (api.mainnet-beta.solana.com
// returns HTTP 429 and JSON-RPC error -32005 when its per-IP quota is exceeded).
const RPC_MAX_RETRIES = 5;
const RPC_BASE_BACKOFF_MS = 1_000;
const RPC_MAX_BACKOFF_MS = 32_000;
const RPC_JITTER_RATIO = 0.25;

// Sleep helper exposed as a module-level binding so tests can stub it without
// having to mock global timers.
let sleepFn: (ms: number) => Promise<void> = (ms) =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Test-only hook: replace the sleep implementation used between RPC retries. */
export function __setSleepForTesting(fn: ((ms: number) => Promise<void>) | null): void {
  sleepFn = fn ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
}

/** Parse a Retry-After header value (seconds or HTTP-date) into milliseconds. */
function parseRetryAfter(value: string | undefined): number | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) {
    return parseInt(trimmed, 10) * 1000;
  }
  const dateMs = Date.parse(trimmed);
  if (!Number.isNaN(dateMs)) {
    return Math.max(0, dateMs - Date.now());
  }
  return null;
}

/** Compute the next backoff delay (exponential with jitter, capped). */
function backoffDelay(attempt: number): number {
  const exp = Math.min(RPC_MAX_BACKOFF_MS, RPC_BASE_BACKOFF_MS * 2 ** attempt);
  const jitter = exp * RPC_JITTER_RATIO * (Math.random() * 2 - 1);
  return Math.max(0, Math.round(exp + jitter));
}

/** Heuristic: is this RPC error a rate-limit signal? */
function isRateLimitError(message: string): boolean {
  return /rate.?limit|too many requests|429|-32005/i.test(message);
}

/** Internal: a structured error thrown from the low-level request layer. */
class RpcRateLimitError extends Error {
  constructor(message: string, readonly retryAfterMs: number | null) {
    super(message);
    this.name = "RpcRateLimitError";
  }
}

interface TransactionDetail {
  signature: string;
  blockTime: number | null;
  memos: string[];
}

/**
 * Monitor a Solana wallet for C2 memo transactions.
 * Runs continuously until stopped.
 */
export async function monitorWallet(
  options: SolanaMonitorOptions,
  onAlert: (alert: C2Alert) => void,
): Promise<void> {
  const { address, interval, limit } = options;
  let lastSignature: string | null = null;

  console.log(`\n  Monitoring Solana wallet: ${address}`);
  console.log(`  Polling interval: ${interval}s | Checking last ${limit} transactions`);
  console.log(`  Press Ctrl+C to stop\n`);

  // Initial fetch to set baseline
  const initial = await getRecentSignatures(address, limit);
  if (initial.length > 0) {
    lastSignature = initial[0]?.signature ?? null;
    console.log(`  Baseline set: ${initial.length} existing transactions`);
    console.log(`  Latest: ${lastSignature}\n`);
  }

  // Poll loop
  const poll = async (): Promise<void> => {
    try {
      const signatures = await getRecentSignatures(address, limit);

      // Find new transactions since last check
      const newSigs: Array<{ signature: string }> = [];
      for (const sig of signatures) {
        if (sig.signature === lastSignature) break;
        newSigs.push(sig);
      }

      if (newSigs.length > 0 && lastSignature !== null) {
        console.log(`  [${new Date().toISOString()}] ${newSigs.length} new transaction(s)`);

        for (const sig of newSigs) {
          const detail = await getTransactionDetail(sig.signature);
          if (detail && detail.memos.length > 0) {
            for (const memo of detail.memos) {
              const alert: C2Alert = {
                timestamp: new Date().toISOString(),
                wallet: address,
                signature: sig.signature,
                memo,
                decodedUrls: extractUrls(memo),
                blockTime: detail.blockTime,
              };

              onAlert(alert);
            }
          }
        }

        lastSignature = newSigs[0]?.signature ?? lastSignature;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`  [${new Date().toISOString()}] Poll error: ${message}`);
    }

    // Schedule next poll
    setTimeout(() => void poll(), interval * 1000);
  };

  await poll();
}

/**
 * One-shot check: get recent transactions and check for memos.
 */
export async function checkWallet(
  address: string,
  limit = 20,
): Promise<TransactionDetail[]> {
  const signatures = await getRecentSignatures(address, limit);
  const results: TransactionDetail[] = [];

  for (const sig of signatures) {
    const detail = await getTransactionDetail(sig.signature);
    if (detail && detail.memos.length > 0) {
      results.push(detail);
    }
  }

  return results;
}

/**
 * Get recent transaction signatures for a wallet.
 */
async function getRecentSignatures(
  address: string,
  limit: number,
): Promise<Array<{ signature: string }>> {
  const response = await solanaRpc("getSignaturesForAddress", [
    address,
    { limit },
  ]);

  if (!Array.isArray(response)) return [];

  return response.map(
    (tx: { signature: string }) => ({ signature: tx.signature }),
  );
}

/**
 * Get full transaction detail and extract memo instructions.
 */
async function getTransactionDetail(
  signature: string,
): Promise<TransactionDetail | null> {
  const response = await solanaRpc("getTransaction", [
    signature,
    { encoding: "jsonParsed", maxSupportedTransactionVersion: 0 },
  ]);

  if (!response) return null;

  const memos: string[] = [];
  const tx = response as {
    blockTime?: number | null;
    transaction?: {
      message?: {
        instructions?: Array<{
          programId?: string;
          parsed?: string;
          data?: string;
        }>;
      };
    };
    meta?: {
      innerInstructions?: Array<{
        instructions?: Array<{
          programId?: string;
          parsed?: string;
          data?: string;
        }>;
      }>;
    };
  };

  // Check main instructions
  const instructions = tx.transaction?.message?.instructions ?? [];
  for (const ix of instructions) {
    if (ix.programId === MEMO_PROGRAM_ID) {
      const memoText = ix.parsed ?? ix.data ?? "";
      if (memoText) memos.push(memoText);
    }
  }

  // Check inner instructions
  const innerInstructions = tx.meta?.innerInstructions ?? [];
  for (const inner of innerInstructions) {
    for (const ix of inner.instructions ?? []) {
      if (ix.programId === MEMO_PROGRAM_ID) {
        const memoText = ix.parsed ?? ix.data ?? "";
        if (memoText) memos.push(memoText);
      }
    }
  }

  return {
    signature,
    blockTime: tx.blockTime ?? null,
    memos,
  };
}

/**
 * Make a JSON-RPC call to the Solana RPC endpoint, retrying on HTTP 429 and
 * JSON-RPC -32005 (rate limited) responses with exponential backoff and
 * Retry-After honoring.
 */
async function solanaRpc(method: string, params: unknown[]): Promise<unknown> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= RPC_MAX_RETRIES; attempt++) {
    try {
      return await solanaRpcOnce(method, params);
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));

      const isRateLimit =
        err instanceof RpcRateLimitError || isRateLimitError(lastError.message);
      if (!isRateLimit || attempt === RPC_MAX_RETRIES) {
        throw lastError;
      }

      const retryAfter =
        err instanceof RpcRateLimitError ? err.retryAfterMs : null;
      const delayMs = retryAfter ?? backoffDelay(attempt);
      console.warn(
        `  [solana-rpc] rate limited (attempt ${attempt + 1}/${RPC_MAX_RETRIES + 1}); ` +
          `retrying in ${Math.round(delayMs / 100) / 10}s`,
      );
      await sleepFn(delayMs);
    }
  }

  throw lastError ?? new Error("Solana RPC: exhausted retries");
}

/**
 * Single attempt at a JSON-RPC call. Throws RpcRateLimitError on HTTP 429 so
 * the caller can apply Retry-After-aware backoff.
 */
function solanaRpcOnce(method: string, params: unknown[]): Promise<unknown> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method,
    params,
  });

  return new Promise((resolve, reject) => {
    const url = new URL(SOLANA_RPC);
    const req = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res: {
        statusCode?: number;
        headers?: Record<string, string | string[] | undefined>;
        on: (event: string, handler: (chunk?: Buffer) => void) => void;
      }) => {
        const status = res.statusCode ?? 200;
        const retryAfterHeader = res.headers?.["retry-after"];
        const retryAfterValue = Array.isArray(retryAfterHeader)
          ? retryAfterHeader[0]
          : retryAfterHeader;

        let data = "";
        res.on("data", (chunk?: Buffer) => {
          if (chunk) data += chunk.toString();
        });
        res.on("end", () => {
          if (status === 429) {
            reject(
              new RpcRateLimitError(
                `Solana RPC HTTP 429 (rate limited)`,
                parseRetryAfter(retryAfterValue),
              ),
            );
            return;
          }

          try {
            const parsed = JSON.parse(data) as {
              result?: unknown;
              error?: { code?: number; message: string };
            };
            if (parsed.error) {
              if (parsed.error.code === -32005 || isRateLimitError(parsed.error.message)) {
                reject(
                  new RpcRateLimitError(
                    `Solana RPC error: ${parsed.error.message}`,
                    parseRetryAfter(retryAfterValue),
                  ),
                );
                return;
              }
              reject(new Error(`Solana RPC error: ${parsed.error.message}`));
              return;
            }
            resolve(parsed.result);
          } catch (parseErr) {
            if (parseErr instanceof RpcRateLimitError) {
              reject(parseErr);
              return;
            }
            reject(new Error("Failed to parse Solana RPC response"));
          }
        });
      },
    );

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * Extract URLs from a memo string.
 */
function extractUrls(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
  return text.match(urlRegex) ?? [];
}

/**
 * Alert structure for detected C2 communications.
 */
export interface C2Alert {
  timestamp: string;
  wallet: string;
  signature: string;
  memo: string;
  decodedUrls: string[];
  blockTime: number | null;
}

/**
 * Format a C2 alert for display.
 */
// -- Watchlist persistence ---------------------------------------------------

const CONFIG_DIR = path.join(os.homedir(), ".supply-chain-guard");
const WATCHLIST_PATH = path.join(CONFIG_DIR, "watchlist.json");

function ensureConfigDir(): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

/**
 * Load the watchlist from disk. Returns an empty list when the file is missing.
 */
export function loadWatchlist(): WatchlistConfig {
  ensureConfigDir();
  if (!fs.existsSync(WATCHLIST_PATH)) {
    return { entries: [] };
  }
  const raw = fs.readFileSync(WATCHLIST_PATH, "utf-8");
  return JSON.parse(raw) as WatchlistConfig;
}

/**
 * Persist the watchlist to disk.
 */
export function saveWatchlist(config: WatchlistConfig): void {
  ensureConfigDir();
  fs.writeFileSync(WATCHLIST_PATH, JSON.stringify(config, null, 2) + "\n");
}

/**
 * Add a wallet to the watchlist.
 */
export function addToWatchlist(address: string, name: string): WatchlistEntry {
  const config = loadWatchlist();
  const existing = config.entries.find((e) => e.address === address);
  if (existing) {
    throw new Error(`Address ${address} is already on the watchlist as "${existing.name}"`);
  }
  const entry: WatchlistEntry = {
    address,
    name,
    addedAt: new Date().toISOString(),
  };
  config.entries.push(entry);
  saveWatchlist(config);
  return entry;
}

/**
 * Remove a wallet from the watchlist.
 */
export function removeFromWatchlist(address: string): void {
  const config = loadWatchlist();
  const idx = config.entries.findIndex((e) => e.address === address);
  if (idx === -1) {
    throw new Error(`Address ${address} is not on the watchlist`);
  }
  config.entries.splice(idx, 1);
  saveWatchlist(config);
}

/**
 * Return all watchlist entries.
 */
export function listWatchlist(): WatchlistEntry[] {
  return loadWatchlist().entries;
}

/**
 * Send an alert payload to a webhook URL via HTTP POST.
 */
function sendWebhookAlert(webhookUrl: string, payload: WatchlistAlert): Promise<void> {
  const body = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const url = new URL(webhookUrl);
    const transport = url.protocol === "https:" ? https : https;
    const req = transport.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        // Consume response data to free up memory
        res.on("data", () => {});
        res.on("end", () => resolve());
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * Monitor all wallets on the watchlist. Polls each wallet and fires alerts
 * for new memo transactions. Optionally forwards alerts to a webhook.
 */
export async function monitorWatchlist(
  options: { interval: number; limit: number; webhookUrl?: string },
  onAlert: (alert: WatchlistAlert) => void,
): Promise<void> {
  const entries = listWatchlist();
  if (entries.length === 0) {
    console.log("\n  Watchlist is empty. Add wallets with: supply-chain-guard watchlist add <address>\n");
    return;
  }

  console.log(`\n  Monitoring ${entries.length} watched wallet(s)`);
  console.log(`  Polling interval: ${options.interval}s | Limit: ${options.limit} tx per wallet`);
  if (options.webhookUrl) {
    console.log(`  Webhook: ${options.webhookUrl}`);
  }
  console.log("  Press Ctrl+C to stop\n");

  // Track the last seen signature per wallet
  const lastSeen = new Map<string, string | null>();

  // Set baselines
  for (const entry of entries) {
    const sigs = await getRecentSignatures(entry.address, options.limit);
    lastSeen.set(entry.address, sigs[0]?.signature ?? null);
    console.log(`  [baseline] ${entry.name} (${entry.address}): ${sigs.length} existing tx`);
  }
  console.log("");

  const poll = async (): Promise<void> => {
    for (const entry of entries) {
      try {
        const sigs = await getRecentSignatures(entry.address, options.limit);
        const prev = lastSeen.get(entry.address) ?? null;

        const newSigs: Array<{ signature: string }> = [];
        for (const sig of sigs) {
          if (sig.signature === prev) break;
          newSigs.push(sig);
        }

        if (newSigs.length > 0 && prev !== null) {
          for (const sig of newSigs) {
            const detail = await getTransactionDetail(sig.signature);
            if (detail && detail.memos.length > 0) {
              for (const memo of detail.memos) {
                const alert: WatchlistAlert = {
                  address: entry.address,
                  name: entry.name,
                  txid: sig.signature,
                  memo,
                  timestamp: new Date().toISOString(),
                };

                onAlert(alert);

                if (options.webhookUrl) {
                  try {
                    await sendWebhookAlert(options.webhookUrl, alert);
                  } catch (err) {
                    const msg = err instanceof Error ? err.message : String(err);
                    console.error(`  [webhook error] ${msg}`);
                  }
                }
              }
            }
          }

          lastSeen.set(entry.address, newSigs[0]?.signature ?? prev);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  [${new Date().toISOString()}] Error polling ${entry.name}: ${msg}`);
      }
    }

    setTimeout(() => void poll(), options.interval * 1000);
  };

  await poll();
}

export function formatAlert(alert: C2Alert): string {
  const lines = [
    "",
    "  ====================================",
    "  !! C2 MEMO DETECTED !!",
    "  ====================================",
    `  Time:      ${alert.timestamp}`,
    `  Wallet:    ${alert.wallet}`,
    `  Signature: ${alert.signature}`,
    `  Memo:      ${alert.memo}`,
  ];

  if (alert.decodedUrls.length > 0) {
    lines.push(`  URLs:      ${alert.decodedUrls.join(", ")}`);
  }

  if (alert.blockTime) {
    lines.push(
      `  Block:     ${new Date(alert.blockTime * 1000).toISOString()}`,
    );
  }

  lines.push("  ====================================", "");
  return lines.join("\n");
}
