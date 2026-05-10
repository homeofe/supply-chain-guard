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

  // DPRK AI-inserted npm malware (April 2026)
  { type: "package", value: "@validate-sdk/v2", severity: "critical", confidence: 1.0, family: "RAT", campaign: "DPRK AI-inserted npm", firstSeen: "2026-04-29" },

  // LofyGang / LofyStealer Minecraft campaign (April 2026)
  { type: "package", value: "lofystealer", severity: "critical", confidence: 0.9, family: "LofyStealer", campaign: "LofyGang Minecraft", firstSeen: "2026-04-28" },
  { type: "package", value: "grabbot", severity: "critical", confidence: 0.9, family: "LofyStealer", campaign: "LofyGang Minecraft", firstSeen: "2026-04-28" },

  // Mini Shai-Hulud / TeamPCP supply chain worm (April 2026)
  // SAP CAP npm packages compromised April 29, 2026
  { type: "package", value: "@cap-js/sqlite@2.2.2", severity: "critical", confidence: 1.0, family: "BunStealer", campaign: "Mini Shai-Hulud", firstSeen: "2026-04-29" },
  { type: "package", value: "@cap-js/postgres@2.2.2", severity: "critical", confidence: 1.0, family: "BunStealer", campaign: "Mini Shai-Hulud", firstSeen: "2026-04-29" },
  { type: "package", value: "@cap-js/db-service@2.10.1", severity: "critical", confidence: 1.0, family: "BunStealer", campaign: "Mini Shai-Hulud", firstSeen: "2026-04-29" },
  { type: "package", value: "mbt@1.2.48", severity: "critical", confidence: 1.0, family: "BunStealer", campaign: "Mini Shai-Hulud", firstSeen: "2026-04-29" },
  { type: "package", value: "intercom-client@7.0.4", severity: "critical", confidence: 1.0, family: "BunStealer", campaign: "Mini Shai-Hulud", firstSeen: "2026-04-29" },
  // PyTorch Lightning PyPI compromised April 30, 2026
  { type: "package", value: "lightning@2.6.2", severity: "critical", confidence: 1.0, family: "BunStealer", campaign: "Mini Shai-Hulud", firstSeen: "2026-04-30" },
  { type: "package", value: "lightning@2.6.3", severity: "critical", confidence: 1.0, family: "BunStealer", campaign: "Mini Shai-Hulud", firstSeen: "2026-04-30" },

  // TeamPCP Update 008 / CanisterSprawl npm worm (April 27, 2026)
  // CanisterSprawl uses Internet Computer Protocol (ICP) canister architecture for C2
  { type: "domain", value: "whereisitat.lucyatemysuperbox.space", severity: "critical", confidence: 1.0, family: "CanisterSprawl", campaign: "TeamPCP Update 008", firstSeen: "2026-04-27" },
  { type: "package", value: "xinference@2.6.0", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "TeamPCP Update 008", firstSeen: "2026-04-27" },
  { type: "package", value: "xinference@2.6.1", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "TeamPCP Update 008", firstSeen: "2026-04-27" },
  { type: "package", value: "xinference@2.6.2", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "TeamPCP Update 008", firstSeen: "2026-04-27" },

  // BufferZoneCorp sleeper Ruby gems / Go modules (May 1, 2026)
  // Ruby gems
  { type: "package", value: "ruby:knot-activesupport-logger", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "ruby:knot-devise-jwt-helper", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "ruby:knot-rack-session-store", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "ruby:knot-rails-assets-pipeline", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "ruby:knot-rspec-formatter-json", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "ruby:knot-date-utils-rb", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "ruby:knot-simple-formatter", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  // Go modules
  { type: "package", value: "go:github.com/BufferZoneCorp/go-metrics-sdk", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "go:github.com/BufferZoneCorp/go-weather-sdk", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "go:github.com/BufferZoneCorp/go-retryablehttp", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "go:github.com/BufferZoneCorp/go-stdlib-ext", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "go:github.com/BufferZoneCorp/grpc-client", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "go:github.com/BufferZoneCorp/net-helper", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "go:github.com/BufferZoneCorp/config-loader", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "go:github.com/BufferZoneCorp/log-core", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },
  { type: "package", value: "go:github.com/BufferZoneCorp/go-envconfig", severity: "critical", confidence: 0.95, family: "SleeperPkg", campaign: "BufferZoneCorp Sleeper", firstSeen: "2026-05-01" },

  // EtherRAT - GitHub facades targeting DevOps (April 2026)
  { type: "ip", value: "135.125.255.55", severity: "critical", confidence: 1.0, family: "EtherRAT", campaign: "EtherRAT GitHub Facades", firstSeen: "2026-04-30" },
  { type: "url", value: "0xc12c8d8f9706244eca0acf04e880f10ff4e52522", severity: "critical", confidence: 1.0, family: "EtherRAT", campaign: "EtherRAT smart contract C2", firstSeen: "2026-04-30" },
  { type: "url", value: "0x37ef6e88425613564b2cf8adc496acff4b6481a9", severity: "critical", confidence: 1.0, family: "EtherRAT", campaign: "EtherRAT operator wallet", firstSeen: "2026-04-30" },

  // MacSync Stealer / malicious Homebrew Google ad (May 1, 2026)
  { type: "domain", value: "glowmedaesthetics.com", severity: "critical", confidence: 1.0, family: "MacSync", campaign: "Homebrew Malvertising", firstSeen: "2026-05-01" },
  { type: "hash", value: "a4fcfecc5ac8fa57614b23928a0e9b7aa4f4a3b2b3a8c1772487b46277125571", severity: "critical", confidence: 1.0, family: "MacSync", campaign: "Homebrew Malvertising", firstSeen: "2026-05-01" },
  { type: "hash", value: "0d58616c750fc8530a7e90eee18398ddedd08cc0f4908c863ab650673b9819dd", severity: "critical", confidence: 1.0, family: "MacSync", campaign: "Homebrew Malvertising", firstSeen: "2026-05-01" },
  { type: "hash", value: "86d0c50cab4f394c58976c44d6d7b67a7dfbbb813fbcf622236e183d94fd944f", severity: "critical", confidence: 1.0, family: "MacSync", campaign: "Homebrew Malvertising", firstSeen: "2026-05-01" },

  // DAEMON Tools QUIC RAT supply-chain attack (May 2026)
  // Trojanized DAEMON Tools installers (versions 12.5.0.2421-12.5.0.2434) distributed via official website since April 8, 2026
  // Suspected Chinese-speaking adversary; selective second-stage QUIC RAT deployed to gov/scientific/manufacturing in Russia/Belarus/Thailand
  { type: "domain", value: "env-check.daemontools.cc", severity: "critical", confidence: 1.0, family: "QUIC RAT", campaign: "DAEMON Tools Supply Chain", firstSeen: "2026-04-08" },

  // ZiChatBot PyPI campaign (May 2026)
  // Three PyPI packages dropping terminate.dll (Windows) / terminate.so (Linux); abuses Zulip REST APIs as C2; suspected APT32/OceanLotus
  { type: "package", value: "uuid32-utils", severity: "critical", confidence: 0.95, family: "ZiChatBot", campaign: "ZiChatBot PyPI", firstSeen: "2026-05-07" },
  { type: "package", value: "colorinal", severity: "critical", confidence: 0.95, family: "ZiChatBot", campaign: "ZiChatBot PyPI", firstSeen: "2026-05-07" },
  { type: "package", value: "termncolor", severity: "critical", confidence: 0.95, family: "ZiChatBot", campaign: "ZiChatBot PyPI", firstSeen: "2026-05-07" },

  // Beagle backdoor / fake Claude AI website (May 2026)
  // 505MB Claude-Pro-windows-x64.zip from claude-pro.com delivers DonutLoader -> Beagle via DLL sideloading (NOVupdate.exe + avk.dll)
  { type: "domain", value: "claude-pro.com", severity: "critical", confidence: 1.0, family: "Beagle", campaign: "Fake Claude AI Site", firstSeen: "2026-05-07" },
  { type: "domain", value: "license.claude-pro.com", severity: "critical", confidence: 1.0, family: "Beagle", campaign: "Fake Claude AI Site", firstSeen: "2026-05-07" },
  { type: "ip", value: "8.217.190.58", severity: "critical", confidence: 1.0, family: "Beagle", campaign: "Fake Claude AI Site", firstSeen: "2026-05-07" },

  // TCLBANKER Brazilian banking trojan (May 2026)
  // REF3076 actor; trojanized LogiAiPromptBuilder.exe MSI sideloads screen_retriever_plugin.dll;
  // self-spreads via WhatsApp/Outlook worm modules; targets 59 banks/fintech/crypto platforms
  { type: "domain", value: "campagna1-api.ef971a42.workers.dev", severity: "critical", confidence: 1.0, family: "TCLBANKER", campaign: "TCLBANKER Logitech Trojanizer", firstSeen: "2026-05-07" },
  { type: "domain", value: "documents.ef971a42.workers.dev", severity: "critical", confidence: 1.0, family: "TCLBANKER", campaign: "TCLBANKER Logitech Trojanizer", firstSeen: "2026-05-07" },
  { type: "domain", value: "mxtestacionamentos.com", severity: "critical", confidence: 1.0, family: "TCLBANKER", campaign: "TCLBANKER Logitech Trojanizer", firstSeen: "2026-05-07" },
  { type: "ip", value: "191.96.224.96", severity: "critical", confidence: 1.0, family: "TCLBANKER", campaign: "TCLBANKER Logitech Trojanizer", firstSeen: "2026-05-07" },
  { type: "hash", value: "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626", severity: "critical", confidence: 1.0, family: "TCLBANKER", campaign: "TCLBANKER Logitech Trojanizer", firstSeen: "2026-05-07" },
  { type: "hash", value: "8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059", severity: "critical", confidence: 1.0, family: "TCLBANKER", campaign: "TCLBANKER Logitech Trojanizer", firstSeen: "2026-05-07" },
  { type: "hash", value: "668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40", severity: "critical", confidence: 1.0, family: "TCLBANKER", campaign: "TCLBANKER Logitech Trojanizer", firstSeen: "2026-05-07" },
  { type: "hash", value: "63beb7372098c03baab77e0dfc8e5dca5e0a7420f382708a4df79bed2d900394", severity: "critical", confidence: 1.0, family: "TCLBANKER", campaign: "TCLBANKER Logitech Trojanizer", firstSeen: "2026-05-07" },

  // JDownloader site compromise / Python RAT (May 2026)
  // jdownloader.org "Download Alternative Installer" replaced May 6-7, 2026 with installers signed by
  // bogus "Zipline LLC" / "The Water Team"; Linux ELF binaries 'pkg' and 'systemd-exec'; payload archive disguised as SVG
  { type: "domain", value: "parkspringshotel.com", severity: "critical", confidence: 1.0, family: "PythonRAT", campaign: "JDownloader Site Compromise", firstSeen: "2026-05-06" },
  { type: "domain", value: "auraguest.lk", severity: "critical", confidence: 1.0, family: "PythonRAT", campaign: "JDownloader Site Compromise", firstSeen: "2026-05-06" },
  { type: "domain", value: "checkinnhotels.com", severity: "critical", confidence: 1.0, family: "PythonRAT", campaign: "JDownloader Site Compromise", firstSeen: "2026-05-06" },

  // Fake OpenAI repository on Hugging Face pushing sefirah infostealer (May 2026)
  // Open-OSS/privacy-filter HF repo trended; loader.py + start.bat fetch sefirah final payload
  { type: "domain", value: "recargapopular.com", severity: "critical", confidence: 1.0, family: "sefirah", campaign: "Fake OpenAI Privacy Filter HF", firstSeen: "2026-05-09" },
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
