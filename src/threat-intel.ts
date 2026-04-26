/**
 * Threat intelligence integration (v4.5).
 *
 * Loads external IOC feeds (JSON), merges with local blocklist,
 * and provides confidence-scored IOC matching with decay.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, ThreatIntelSource } from "./types.js";

// ---------------------------------------------------------------------------
// IOC feed entry
// ---------------------------------------------------------------------------

export interface FeedIOC {
  type: "domain" | "ip" | "url" | "hash" | "package";
  value: string;
  severity: "critical" | "high" | "medium";
  confidence: number;
  family?: string;
  campaign?: string;
  source?: string;
  firstSeen?: string;
  lastSeen?: string;
}

// ---------------------------------------------------------------------------
// Default bundled feed (curated by supply-chain-guard)
// ---------------------------------------------------------------------------

const BUNDLED_FEED: FeedIOC[] = [
  // Claude Code leak campaign (April 2026)
  { type: "domain", value: "rti.cargomanbd.com", severity: "critical", confidence: 1.0, family: "Vidar", campaign: "Claude Code Leak" },
  { type: "ip", value: "147.45.197.92", severity: "critical", confidence: 1.0, family: "GhostSocks", campaign: "Claude Code Leak" },
  { type: "ip", value: "94.228.161.88", severity: "critical", confidence: 1.0, family: "GhostSocks", campaign: "Claude Code Leak" },
  { type: "url", value: "steamcommunity.com/profiles/76561198721263282", severity: "critical", confidence: 1.0, family: "Vidar", campaign: "Dead-drop resolver" },
  { type: "hash", value: "77c73bd5e7625b7f691bc00a1b561a0f", severity: "critical", confidence: 1.0, family: "Vidar", campaign: "ClaudeCode_x64.exe dropper" },
  { type: "hash", value: "9a6ea91491ccb1068b0592402029527f", severity: "critical", confidence: 1.0, family: "Vidar", campaign: "Vidar v18.7 stealer" },
  { type: "hash", value: "3388b415610f4ae018d124ea4dc99189", severity: "critical", confidence: 1.0, family: "GhostSocks", campaign: "GhostSocks proxy" },

  // Compromised npm packages
  { type: "package", value: "axios@1.14.1", severity: "critical", confidence: 1.0, family: "RAT", campaign: "axios hijack" },
  { type: "package", value: "axios@0.30.4", severity: "critical", confidence: 1.0, family: "RAT", campaign: "axios hijack" },
  { type: "package", value: "event-stream@3.3.6", severity: "critical", confidence: 1.0, family: "Backdoor", campaign: "flatmap-stream" },
  { type: "package", value: "ua-parser-js@0.7.29", severity: "critical", confidence: 1.0, family: "Cryptominer", campaign: "ua-parser hijack" },

  // Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)
  { type: "domain", value: "audit.checkmarx.cx", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "Checkmarx KICS Breach", firstSeen: "2026-04-22" },
  { type: "domain", value: "checkmarx.cx", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "Checkmarx KICS Breach", firstSeen: "2026-04-22" },
  { type: "ip", value: "94.154.172.43", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "Checkmarx KICS Breach", firstSeen: "2026-04-22" },
  { type: "ip", value: "91.195.240.123", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "Checkmarx KICS Breach", firstSeen: "2026-04-22" },
  { type: "package", value: "@bitwarden/cli@2026.4.0", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "Bitwarden CLI Hijack", firstSeen: "2026-04-22" },
];

const CACHE_DIR = ".scg-cache";
const FEED_CACHE_FILE = "threat-feed.json";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// ---------------------------------------------------------------------------
// Feed loading
// ---------------------------------------------------------------------------

/**
 * Load and merge IOC feeds. Starts with bundled feed, merges remote if available.
 */
export function loadThreatIntel(
  cacheDir?: string,
  remoteFeedUrl?: string,
): FeedIOC[] {
  let feed = [...BUNDLED_FEED];

  // Try to load cached remote feed
  const cacheBase = cacheDir ?? CACHE_DIR;
  const cachePath = path.join(cacheBase, FEED_CACHE_FILE);
  if (fs.existsSync(cachePath)) {
    try {
      const cached = JSON.parse(fs.readFileSync(cachePath, "utf-8")) as {
        timestamp: string;
        entries: FeedIOC[];
      };
      const age = Date.now() - new Date(cached.timestamp).getTime();
      if (age < CACHE_TTL_MS) {
        feed = mergeFeeds(feed, cached.entries);
      }
    } catch { /* ignore corrupt cache */ }
  }

  return feed;
}

/**
 * Update remote threat feed and cache locally.
 */
export async function updateThreatFeed(
  feedUrl: string,
  cacheDir?: string,
): Promise<{ added: number; total: number }> {
  const cacheBase = cacheDir ?? CACHE_DIR;

  try {
    const response = await fetch(feedUrl);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const entries = (await response.json()) as FeedIOC[];
    if (!Array.isArray(entries)) throw new Error("Invalid feed format");

    fs.mkdirSync(cacheBase, { recursive: true });
    fs.writeFileSync(
      path.join(cacheBase, FEED_CACHE_FILE),
      JSON.stringify({ timestamp: new Date().toISOString(), entries }, null, 2),
    );

    return { added: entries.length, total: BUNDLED_FEED.length + entries.length };
  } catch (err) {
    throw new Error(`Failed to update threat feed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Check content against the threat intelligence feed.
 */
export function checkThreatIntel(
  content: string,
  relativePath: string,
  feed: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const contentLower = content.toLowerCase();

  for (const ioc of feed) {
    if (ioc.type === "package") continue; // Packages checked separately

    const valueLower = ioc.value.toLowerCase();
    const matched =
      ioc.type === "domain"
        ? new RegExp(ioc.value.replace(/\./g, "\\."), "i").test(content)
        : contentLower.includes(valueLower);

    if (matched) {
      // Apply confidence decay (reduce by 10% per 90 days since firstSeen)
      let confidence = ioc.confidence;
      if (ioc.firstSeen) {
        const ageDays = (Date.now() - new Date(ioc.firstSeen).getTime()) / (1000 * 60 * 60 * 24);
        const decayFactor = Math.max(0.3, 1 - (ageDays / 900));
        confidence = Math.round(confidence * decayFactor * 100) / 100;
      }

      findings.push({
        rule: "THREAT_INTEL_MATCH",
        description: `Threat intelligence match: ${ioc.type} "${ioc.value}"${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` — ${ioc.campaign}` : ""}`,
        severity: ioc.severity,
        file: relativePath,
        confidence,
        category: "malware",
        recommendation: `This ${ioc.type} is listed in threat intelligence feeds. ${ioc.family ? `Associated malware family: ${ioc.family}.` : ""} Quarantine and investigate.`,
      });
    }
  }

  return findings;
}

/**
 * Merge two feeds, deduplicating by type+value.
 */
function mergeFeeds(base: FeedIOC[], additions: FeedIOC[]): FeedIOC[] {
  const seen = new Set(base.map((i) => `${i.type}:${i.value}`));
  const merged = [...base];
  for (const entry of additions) {
    const key = `${entry.type}:${entry.value}`;
    if (!seen.has(key)) {
      merged.push(entry);
      seen.add(key);
    }
  }
  return merged;
}
