/**
 * Threat intelligence integration (v4.5).
 *
 * Loads external IOC feeds (JSON), merges with local blocklist,
 * and provides confidence-scored IOC matching with decay.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";

import { CATALOG_DIGEST } from "./catalog-digest.js";
import { displayCachePath, resolveCacheDir } from "./cache-dir.js";
import type { Finding, ThreatIntelSource, DetectionSetProvenance } from "./types.js";

// ---------------------------------------------------------------------------
// IOC feed entry
// ---------------------------------------------------------------------------

export interface FeedIOC {
  type: "domain" | "ip" | "url" | "hash" | "package";
  value: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: number;
  family?: string;
  campaign?: string;
  source?: string;
  firstSeen?: string;
  lastSeen?: string;
}

/** Runtime-valid remote shape before its optional confidence is normalized. */
export type FeedIOCInput = Omit<FeedIOC, "confidence"> & {
  confidence?: number;
};

/**
 * Generation timestamp for the bundled IOC feed (v5.29, issue #208).
 * Pure function of feed updates; preserved across builds.
 */
export const FEED_GENERATED_AT = "2026-10-05T00:00:00.000Z";

// ---------------------------------------------------------------------------
// Default bundled feed (curated by supply-chain-guard)
// ---------------------------------------------------------------------------

const FEED_CHUNK_0: FeedIOC[] = [
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
  { type: "package", value: "pypi:lightning@2.6.2", severity: "critical", confidence: 1.0, family: "BunStealer", campaign: "Mini Shai-Hulud", firstSeen: "2026-04-30" },
  { type: "package", value: "pypi:lightning@2.6.3", severity: "critical", confidence: 1.0, family: "BunStealer", campaign: "Mini Shai-Hulud", firstSeen: "2026-04-30" },

  // TeamPCP Update 008 / CanisterSprawl npm worm (April 27, 2026)
  // CanisterSprawl uses Internet Computer Protocol (ICP) canister architecture for C2
  { type: "domain", value: "whereisitat.lucyatemysuperbox.space", severity: "critical", confidence: 1.0, family: "CanisterSprawl", campaign: "TeamPCP Update 008", firstSeen: "2026-04-27" },

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
  // `pypi:` added 2026-09-26. Stored bare, these sat in the npm namespace, so a
  // PyPI project depending on them got no feed finding and an npm package of
  // the same name would have been flagged (6.3.0 pre-release review; OSV lists
  // colorinal and termncolor as PyPI malware, none of the three on npm).
  { type: "package", value: "pypi:uuid32-utils", severity: "critical", confidence: 0.95, family: "ZiChatBot", campaign: "ZiChatBot PyPI", firstSeen: "2026-05-07" },
  { type: "package", value: "pypi:colorinal", severity: "critical", confidence: 0.95, family: "ZiChatBot", campaign: "ZiChatBot PyPI", firstSeen: "2026-05-07" },
  { type: "package", value: "pypi:termncolor", severity: "critical", confidence: 0.95, family: "ZiChatBot", campaign: "ZiChatBot PyPI", firstSeen: "2026-05-07" },

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

  // Checkmarx Jenkins AST plugin supply chain attack (May 9-11, 2026) - TeamPCP / Mr_Rot13
  // Per SANS ISC diary 32994 (May 18, 2026) and the Checkmarx official confirmation on May 11:
  // tampered Marketplace version 2026.5.09 was exposed from 2026-05-09 01:25 UTC to 2026-05-10 08:47 UTC.
  // Last known-good build 2.0.13-829.vc72453fa_1c16 (2025-12-17). Remediated builds (both 2026-05-09):
  // 2.0.13-848.v76e89de8a_053 and 2.0.13-847.v08c0072b_2fd5. Third Checkmarx compromise in three months.
  { type: "package", value: "jenkins:checkmarx-ast-plugin@2026.5.09", severity: "critical", confidence: 1.0, family: "Infostealer", campaign: "Checkmarx Jenkins AST Plugin Compromise", firstSeen: "2026-05-09" },

  // postmark-mcp MCP server supply-chain compromise (Sep 29, 2025) - first documented malicious MCP server
  // Developer-as-attacker scenario: legitimate package operated cleanly through 1.0.15, then version 1.0.16
  // introduced a hidden BCC of every outbound email to an attacker-controlled address. The change was tiny
  // and functional behavior was preserved. Re-disclosed via Bishop Fox "Otto-Support" supply-chain post,
  // May 13, 2026, as the canonical case of a hostile MCP server.
  { type: "package", value: "postmark-mcp@1.0.16", severity: "critical", confidence: 1.0, family: "MCPHarvest", campaign: "postmark-mcp Hostile MCP Server", firstSeen: "2025-09-29" },

  // MacSync Stealer Claude.ai/Google ads variant (May 10, 2026)
  // Malvertising via Google Ads + Claude.ai shared chat URLs; base64 shell scripts -> gunzip in-memory payload via osascript
  // Checks for Russian/CIS keyboard layouts before execution; harvests browser creds, cookies, macOS Keychain
  { type: "domain", value: "customroofingcontractors.com", severity: "critical", confidence: 1.0, family: "MacSync", campaign: "MacSync Claude.ai Malvertising", firstSeen: "2026-05-10" },
  { type: "domain", value: "bernasibutuwqu2.com", severity: "critical", confidence: 1.0, family: "MacSync", campaign: "MacSync Claude.ai Malvertising", firstSeen: "2026-05-10" },
  { type: "domain", value: "briskinternet.com", severity: "critical", confidence: 1.0, family: "MacSync", campaign: "MacSync Claude.ai Malvertising", firstSeen: "2026-05-10" },
  { type: "hash", value: "ed5ed79a674972d1506dd8d68e8e13658125267ade86bfcb1ab794e2b49e50ac", severity: "critical", confidence: 1.0, family: "MacSync", campaign: "MacSync Claude.ai Malvertising", firstSeen: "2026-05-10" },
  { type: "hash", value: "a833ad989b68dad582a1b591b8cf63466e79c850ff72916cf5d4c4a7f6bc650e", severity: "critical", confidence: 1.0, family: "MacSync", campaign: "MacSync Claude.ai Malvertising", firstSeen: "2026-05-10" },

  // Mini Shai-Hulud Worm / TeamPCP - TanStack/UiPath/Mistral/OpenSearch/Guardrails compromise (May 12, 2026)
  // Self-propagating worm; CVE-2026-45321 (TanStack, CVSS 9.6); commits signed with claude@users.noreply.github.com
  { type: "domain", value: "filev2.getsession.org", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "domain", value: "api.masscan.cloud", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "domain", value: "git-tanstack.com", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "ip", value: "83.142.209.194", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "@opensearch-project/opensearch@3.5.3", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "@opensearch-project/opensearch@3.6.2", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "@opensearch-project/opensearch@3.7.0", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "@opensearch-project/opensearch@3.8.0", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "@squawk/mcp@0.9.5", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "@squawk/weather@0.5.10", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "@squawk/flightplan@0.5.6", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "@tallyui/connector-medusa@1.0.3", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "@tallyui/connector-vendure@1.0.3", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "pypi:guardrails-ai@0.10.1", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "pypi:mistralai@2.4.6", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },

  // node-ipc credential stealer via maintainer email hijack (May 14, 2026)
  // Versions 9.1.6, 9.2.3, 12.0.1 published with 80KB obfuscated CJS payload that harvests 90+ credential
  // categories (AWS/Azure/GCP/SSH/k8s/GitHub CLI/Claude AI/Kiro/Terraform/DB) and exfiltrates via DNS TXT
  // queries to 37.16.75.69. Attack vector: expired atlantis-software.net maintainer email re-registered May 7.
  // 12.0.1 is hash-targeted - inert unless primary module path matches a pre-computed SHA-256 value.
  { type: "package", value: "node-ipc@9.1.6", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "node-ipc Email Hijack", firstSeen: "2026-05-14" },
  { type: "package", value: "node-ipc@9.2.3", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "node-ipc Email Hijack", firstSeen: "2026-05-14" },
  { type: "package", value: "node-ipc@12.0.1", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "node-ipc Email Hijack", firstSeen: "2026-05-14" },
  { type: "domain", value: "sh.azurestaticprovider.net", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "node-ipc Email Hijack", firstSeen: "2026-05-14" },
  { type: "ip", value: "37.16.75.69", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "node-ipc Email Hijack", firstSeen: "2026-05-14" },
  { type: "hash", value: "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144", severity: "critical", confidence: 1.0, family: "CredStealer", campaign: "node-ipc Email Hijack", firstSeen: "2026-05-14" },

  // Additional TanStack wave IOCs surfaced in SANS ISC diary 32994 (TeamPCP campaign through 2026-05-17)
  // router_init.js payload hash + secondary Session messenger exfil node + staging GitHub forks
  { type: "domain", value: "seed1.getsession.org", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "hash", value: "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-11" },

  // Phantom Bot DDoS + leaked Shai-Hulud npm infostealer (May 17-18, 2026)
  // Publisher "deadcode09284814" re-weaponized leaked Shai-Hulud source for an infostealer + Golang
  // Phantom Bot DDoS module (HTTP/TCP/UDP flood, TCP reset). Four packages, 2,678 combined downloads.
  // C2 over localhost.run tunnels (*.lhr.life) plus direct TCP to 80.200.28.28:2222.
  { type: "package", value: "chalk-tempalte", severity: "critical", confidence: 1.0, family: "PhantomBot", campaign: "Phantom Bot npm DDoS", firstSeen: "2026-05-17" },
  { type: "package", value: "@deadcode09284814/axios-util", severity: "critical", confidence: 1.0, family: "PhantomBot", campaign: "Phantom Bot npm DDoS", firstSeen: "2026-05-17" },
  { type: "package", value: "axois-utils", severity: "critical", confidence: 1.0, family: "PhantomBot", campaign: "Phantom Bot npm DDoS", firstSeen: "2026-05-17" },
  { type: "package", value: "color-style-utils", severity: "critical", confidence: 1.0, family: "PhantomBot", campaign: "Phantom Bot npm DDoS", firstSeen: "2026-05-17" },
  { type: "domain", value: "87e0bbc636999b.lhr.life", severity: "critical", confidence: 1.0, family: "PhantomBot", campaign: "Phantom Bot npm DDoS", firstSeen: "2026-05-17" },
  { type: "domain", value: "edcf8b03c84634.lhr.life", severity: "critical", confidence: 1.0, family: "PhantomBot", campaign: "Phantom Bot npm DDoS", firstSeen: "2026-05-17" },
  { type: "ip", value: "80.200.28.28", severity: "critical", confidence: 1.0, family: "PhantomBot", campaign: "Phantom Bot npm DDoS", firstSeen: "2026-05-17" },

  // Mini Shai-Hulud @antv wave + actions-cool GitHub Action tag hijack + Nx Console (May 18-19, 2026)
  // TeamPCP triple-wave: 637 versions across 317 @antv-ecosystem npm packages via compromised atool account,
  // actions-cool/issues-helper + actions-cool/maintain-one-comment tag redirection to imposter commits,
  // and nrwl.angular-console 18.95.0 VS Code extension dropping orphan-commit Bun payload.
  // Shared C2: t.m-kosche.com (masquerades as OpenTelemetry traces endpoint).
  { type: "domain", value: "t.m-kosche.com", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv / actions-cool / Nx Console", firstSeen: "2026-05-18" },
  { type: "hash", value: "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv", firstSeen: "2026-05-19" },
  { type: "package", value: "@antv/g2@5.5.8", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv", firstSeen: "2026-05-19" },
  { type: "package", value: "@antv/g2@5.6.8", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv", firstSeen: "2026-05-19" },
  { type: "package", value: "@antv/g6@5.2.1", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv", firstSeen: "2026-05-19" },
  { type: "package", value: "@antv/g6@5.3.1", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv", firstSeen: "2026-05-19" },
  { type: "package", value: "echarts-for-react@3.1.7", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv", firstSeen: "2026-05-19" },
  { type: "package", value: "echarts-for-react@3.2.7", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv", firstSeen: "2026-05-19" },
  { type: "package", value: "timeago.js@4.1.2", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv", firstSeen: "2026-05-19" },
  { type: "package", value: "timeago.js@4.2.2", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud @antv", firstSeen: "2026-05-19" },
  // Nx Console nrwl.angular-console 18.95.0 (VS Code Marketplace; 2.2M installs, May 18 2026 exposure window 12:36-12:47 UTC)
  { type: "hash", value: "1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Nx Console 18.95.0", firstSeen: "2026-05-18" },
  { type: "hash", value: "b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Nx Console 18.95.0", firstSeen: "2026-05-18" },
  { type: "hash", value: "e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Nx Console 18.95.0", firstSeen: "2026-05-18" },
  // The extension identity itself, version-pinned on both registries (OSV MAL-2026-5161 /
  // MAL-2026-5162). Nx Console is a legitimate, live extension and a HIJACK VICTIM: only the
  // 18.95.0 release is malicious, and it is no longer served (Open VSX 404, verified
  // 2026-09-23). Replaces the npm name pattern for nrwl.angular-console in patterns.ts, which
  // name-blocked the victim and matched no real npm package (registry 404), so it never fired.
  { type: "package", value: "vscode:nrwl.angular-console@18.95.0", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Nx Console 18.95.0", source: "MAL-2026-5161", firstSeen: "2026-05-18" },
  { type: "package", value: "openvsx:nrwl.angular-console@18.95.0", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Nx Console 18.95.0", source: "MAL-2026-5162", firstSeen: "2026-05-18" },
  { type: "hash", value: "43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd8", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Nx Console 18.95.0", firstSeen: "2026-05-18" },

  // Megalodon GitHub Actions workflow injection campaign (May 22, 2026)
  // 5,718 malicious commits pushed to 5,561 GitHub repositories in 6 hours via throwaway accounts
  // forged as "build-bot", "auto-ci", "ci-bot", "pipeline-bot". Injected GitHub Actions workflows
  // ran base64-encoded bash that exfiltrated CI env vars, AWS / GCP creds, SSH private keys,
  // OIDC tokens, Docker/k8s configs, and Terraform credentials to 216.126.225.129:8443.
  { type: "ip", value: "216.126.225.129", severity: "critical", confidence: 1.0, family: "Megalodon", campaign: "Megalodon GitHub Workflow Injection", firstSeen: "2026-05-22" },

  // DPRK OtterCookie Node.js stealer (SANS ISC diary 33006, May 22, 2026)
  // Sample uploaded to VT as "extracted-decoded.js"; obfuscator.io-style; targets 41 crypto-wallet
  // Chrome extensions (MetaMask/Phantom/Coinbase/Ledger) + 200+ sensitive file patterns
  // (.env, .pem, .p12, .jks, SSH keys, seed phrases) across Windows (WSL) / macOS / Linux.
  // Hardcoded HMAC-SHA256 key "SuperStr0ngSecret@)@^". C2 over three ports on 216.126.225.243
  // (8085 creds, 8086 files, 8087 WebSocket reverse shell at /api/notify).
  // Note: 216.126.225.0/24 is shared infrastructure with the Megalodon campaign.
  { type: "ip", value: "216.126.225.243", severity: "critical", confidence: 1.0, family: "OtterCookie", campaign: "DPRK OtterCookie Node.js Stealer", firstSeen: "2026-05-22" },
  { type: "url", value: "216.126.225.243:8087/api/notify", severity: "critical", confidence: 1.0, family: "OtterCookie", campaign: "DPRK OtterCookie Node.js Stealer", firstSeen: "2026-05-22" },
  { type: "hash", value: "049300aa5dd774d6c984779a0570f59610399c71864b5d5c2605906db46ddeb9", severity: "critical", confidence: 1.0, family: "OtterCookie", campaign: "DPRK OtterCookie Node.js Stealer", firstSeen: "2026-05-22" },

  // Laravel-Lang DebugElevator PHP credential stealer (May 23, 2026)
  // Four Composer packages (laravel-lang/{lang,http-statuses,attributes,actions}) had
  // GitHub version tags abused to republish ~700 historical versions with a malicious
  // src/helpers.php carrying a ~5,900-line PHP credential stealer that exfiltrates to
  // flipboxstudio.info/exfil. PDB references developer "Mero" and "claude" in artifacts.
  { type: "domain", value: "flipboxstudio.info", severity: "critical", confidence: 1.0, family: "DebugElevator", campaign: "Laravel-Lang DebugElevator", firstSeen: "2026-05-23" },
  { type: "hash", value: "f0d912c1a72e533417d5e158bb9755f848ec678b6448ae7c8fb6e87da78a3053", severity: "critical", confidence: 1.0, family: "DebugElevator", campaign: "Laravel-Lang DebugElevator", firstSeen: "2026-05-23" },
  { type: "hash", value: "23e779555c21beaed6ae8f1f298daf9b00d603f1a6716ce329332aadcb80fbe2", severity: "critical", confidence: 1.0, family: "DebugElevator", campaign: "Laravel-Lang DebugElevator", firstSeen: "2026-05-23" },
  // Corrected 2026-09-23: the four laravel-lang packages were carried here as WHOLE-NAME
  // blocks. They are HIJACK VICTIMS, not attacker packages: Packagist lists 525 / 71 / 87 / 47
  // versions going back to 2015-2023, laravel-lang/lang shipped a clean release on 2026-09-20,
  // and it has 12.3M downloads. A whole-name block flagged every Laravel project using them as
  // critical. What the incident actually shipped stays detected: the stealer's helpers.php by
  // the two hashes above (file digest in vendor/) and its exfiltration host by domain.

  // Packagist 8-package GitHub-hosted Linux binary attack (May 23, 2026)
  // Coordinated supply-chain hit against 8 Composer packages on Packagist whose dev
  // branches had package.json postinstall hooks added to download a Linux ELF
  // (gvfsd-network) from github.com/parikhpreyash4/systemd-network-helper-aa5c751f and
  // execute it from /tmp/.sshd. Attacker GitHub account removed after disclosure.
  // Attack mixed JS toolchain hooks into PHP projects to bypass Composer-side review.
  // Corrected 2026-09-23: only the DEV BRANCHES of these packages carried the hook, so their
  // tagged releases were never affected, and six of the eight are live with release histories
  // (Packagist, 6 to 143 versions). Those six are no longer name-blocked; the hook itself stays
  // detected through the parikhpreyash4 account in KNOWN_MALICIOUS_GITHUB_ACCOUNTS, which the
  // payload URL names. devdojo/genesis and katanaui/katana are gone from Packagist and keep
  // their name blocks, which can no longer match a clean install.
  { type: "package", value: "composer:devdojo/genesis", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:katanaui/katana", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },

  // TrapDoor cross-ecosystem credential stealer (npm/PyPI/Crates.io, May 25, 2026)
  // Reported by The Hacker News on May 25, 2026. Single actor (ddjidd564) published
  // 34+ malicious packages targeting AI / DeFi / Web3 / Move-on-Sui developers:
  // 21 npm packages, 7 PyPI packages, 6 Crates.io packages. C2 / dead-drop hosted
  // on GitHub Pages at ddjidd564.github.io.
  { type: "domain", value: "ddjidd564.github.io", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  // npm packages (21)
  { type: "package", value: "async-pipeline-builder", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "build-scripts-utils", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "chain-key-validator", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "crypto-credential-scanner", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "defi-env-auditor", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "defi-threat-scanner", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "deployment-key-auditor", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "dev-env-bootstrapper", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "eth-wallet-sentinel", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "llm-context-compressor", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "mnemonic-safety-check", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "model-switch-router", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "node-setup-helpers", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "project-init-tools", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "prompt-engineering-toolkit", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "solidity-deploy-guard", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "token-usage-tracker", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "wallet-backup-verifier", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "wallet-security-checker", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "web3-secrets-detector", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "workspace-config-loader", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  // PyPI packages (7)
  { type: "package", value: "cryptowallet-safety", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "data-pipeline-check", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "defi-risk-scanner", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "env-loader-cli", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "eth-security-auditor", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "git-config-sync", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "solidity-build-guard", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  // Crates.io packages (6) - Sui / Move toolchain typosquats
  { type: "package", value: "cargo:move-analyzer-build", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "cargo:move-compiler-tools", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "cargo:move-project-builder", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "cargo:sui-framework-helpers", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "cargo:sui-move-build-helper", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },
  { type: "package", value: "cargo:sui-sdk-build-utils", severity: "critical", confidence: 1.0, family: "TrapDoor", campaign: "TrapDoor Cross-Ecosystem", firstSeen: "2026-05-25" },

  // Mini Shai-Hulud / TeamPCP - Microsoft-published durabletask PyPI trojanized (May 24, 2026)
  // Per SANS ISC diary 33016 (May 25, 2026): three malicious versions published to PyPI
  // for the officially Microsoft-maintained durabletask package, marking the first
  // confirmed compromise of an upstream Microsoft-signed package in the TeamPCP campaign.
  { type: "package", value: "pypi:durabletask@1.4.1", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", firstSeen: "2026-05-24" },
  { type: "package", value: "pypi:durabletask@1.4.2", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", firstSeen: "2026-05-24" },
  { type: "package", value: "pypi:durabletask@1.4.3", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", firstSeen: "2026-05-24" },

  // Polymarket impersonation npm packages (publisher polymarketdev, May 22, 2026)
  // Surfaced in The Hacker News Megalodon write-up: 9 typosquats of the Polymarket
  // SDK publishing through the polymarketdev account, exfiltrating wallet keys to a
  // Cloudflare Worker at polymarketbot.polymarketdev.workers.dev/v1/wallets/keys.
  { type: "domain", value: "polymarketbot.polymarketdev.workers.dev", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },
  { type: "package", value: "polymarket-trading-cli", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },
  { type: "package", value: "polymarket-terminal", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },
  { type: "package", value: "polymarket-trade", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },
  { type: "package", value: "polymarket-auto-trade", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },
  { type: "package", value: "polymarket-copy-trading", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },
  { type: "package", value: "polymarket-bot", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },
  { type: "package", value: "polymarket-claude-code", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },
  { type: "package", value: "polymarket-ai-agent", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },
  { type: "package", value: "polymarket-trader", severity: "critical", confidence: 1.0, family: "PolymarketStealer", campaign: "Polymarket Typosquat", firstSeen: "2026-05-22" },

  // ACR Stealer fake Claude page / Google Search malvertising (SANS ISC diary 33018, May 26, 2026)
  // Claude-impersonation pages via Google Search ads -> corrupted zip -> PowerShell loader -> ACR Stealer.
  // Base domains stored (attacker-controlled; subdomains rotate). i.ibb.co (legit ImgBB) deliberately omitted.
  { type: "domain", value: "fairpoint29.com", severity: "critical", confidence: 1.0, family: "ACRStealer", campaign: "ACR Stealer Fake Claude Page", firstSeen: "2026-05-26" },
  { type: "domain", value: "primemetricsa.com", severity: "critical", confidence: 1.0, family: "ACRStealer", campaign: "ACR Stealer Fake Claude Page", firstSeen: "2026-05-26" },
  { type: "domain", value: "creativecommunityinfo.art", severity: "critical", confidence: 1.0, family: "ACRStealer", campaign: "ACR Stealer Fake Claude Page", firstSeen: "2026-05-26" },
  { type: "domain", value: "enhanceblabber.cc", severity: "critical", confidence: 1.0, family: "ACRStealer", campaign: "ACR Stealer Fake Claude Page", firstSeen: "2026-05-26" },
  { type: "hash", value: "70b5ecc110e074dbca92932c0e840ea3492ea0a43c3f215b71392c12b02213b2", severity: "critical", confidence: 1.0, family: "ACRStealer", campaign: "ACR Stealer Fake Claude Page", firstSeen: "2026-05-26" },
  { type: "hash", value: "a14c3ecf5eb3d2543358482e43dc765dbf9ee7a4bec7571f5ecb8829ca719692", severity: "critical", confidence: 1.0, family: "ACRStealer", campaign: "ACR Stealer Fake Claude Page", firstSeen: "2026-05-26" },
  { type: "hash", value: "47fa746422f1bf6b7712dc6803378e6a995488007193a7441d790f70d204728f", severity: "critical", confidence: 1.0, family: "ACRStealer", campaign: "ACR Stealer Fake Claude Page", firstSeen: "2026-05-26" },

  // Malware-Slop npm infostealer (OX Security via The Hacker News, May 27, 2026)
  // npm package mouse5212-super-formatter (~676 downloads) masquerades as an archive
  // deployment-sync utility, authenticates to GitHub and recursively uploads files from
  // /mnt/user-data (Claude AI user directory) into repos under attacker account unplowed3584.
  { type: "package", value: "mouse5212-super-formatter", severity: "critical", confidence: 1.0, family: "MalwareSlop", campaign: "Malware-Slop npm", firstSeen: "2026-05-27" },

  // codexui-android npm Codex token stealer (Aikido disclosed May 27, 2026; The Hacker News June 1, 2026)
  // Legitimate-looking Codex remote-UI npm package with 27K-29K weekly downloads.
  // Since 0.1.82 every invocation reads the OpenAI Codex auth file, XOR-encrypts with
  // key "anyclaw2026", base64-encodes and POSTs to sentry.anyclaw.store/startlog.
  // Mobile vector: Android apps "OpenClaw Codex Claude AI Agent" (gptos.intelligence.assistant)
  // and "Codex" (codex.app) run the package in PRoot sandbox and hit the same endpoint.
  { type: "domain", value: "sentry.anyclaw.store", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },
  { type: "package", value: "codexui-android@0.1.82", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },
  { type: "package", value: "codexui-android@0.1.83", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },
  { type: "package", value: "codexui-android@0.1.84", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },
  { type: "package", value: "codexui-android@0.1.85", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },
  { type: "package", value: "codexui-android@0.1.86", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },
  { type: "package", value: "codexui-android@0.1.87", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },
  { type: "package", value: "codexui-android@0.1.88", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },
  { type: "package", value: "codexui-android@0.1.89", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },
  { type: "package", value: "codexui-android@0.1.90", severity: "critical", confidence: 1.0, family: "CodexTokenStealer", campaign: "codexui-android", firstSeen: "2026-05-27" },

  // LiteLLM PyPI supply-chain compromise (TeamPCP; March 24, 2026)
  // Re-disclosed in detail by Trail of Bits "We hardened zizmor" (May 22, 2026) as the
  // canonical case of upstream-CI-dependency poisoning. Compromised PyPI versions
  // 1.82.7 and 1.82.8 dropped litellm_init.pth that auto-runs on every Python startup;
  // three-stage payload (50+ category credential harvester, k8s lateral-movement,
  // persistent backdoor) exfils via HTTPS to models.litellm.cloud and polls
  // checkmarx.zone (Checkmarx brand abuse to bypass DNS allowlists) for second stages.
  // Origin: trojanized Trivy in LiteLLM's own CI/CD security workflow.
  { type: "domain", value: "models.litellm.cloud", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "LiteLLM PyPI Compromise", firstSeen: "2026-03-24" },
  { type: "domain", value: "checkmarx.zone", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "LiteLLM PyPI Compromise", firstSeen: "2026-03-24" },
  { type: "package", value: "pypi:litellm@1.82.7", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "LiteLLM PyPI Compromise", firstSeen: "2026-03-24" },
  { type: "package", value: "pypi:litellm@1.82.8", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "LiteLLM PyPI Compromise", firstSeen: "2026-03-24" },

  // Sicoob.Sdk NuGet impersonation + vpmdhaj npm cloud-secret stealers (Socket via THN, May 28-29, 2026)
  // Single actor "vpmdhaj" (a39155771@gmail.com) ran two parallel waves:
  //   - 5 NuGet versions (Sicoob.Sdk 2.0.0-2.0.4) impersonating a C# SDK for Brazilian
  //     cooperative bank Sicoob; exfiltrates PFX certificates + client IDs + PFX passwords
  //     to a hardcoded Sentry DSN (o4511335034847232.ingest.de.sentry.io/4511337546317904).
  //   - 14 npm packages typosquatting OpenSearch / ElasticSearch / DevOps / env-config
  //     libraries; preinstall hook harvests AWS creds, HashiCorp Vault tokens, npm tokens,
  //     CI/CD secrets. C2 auth via hardcoded X-Secret header "l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1".
  // Supporting GitHub org Sicoob-Cooperativa + contributor joaobcdev tracked in account list.
  { type: "package", value: "nuget:Sicoob.Sdk@2.0.0", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "nuget:Sicoob.Sdk@2.0.1", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "nuget:Sicoob.Sdk@2.0.2", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "nuget:Sicoob.Sdk@2.0.3", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "nuget:Sicoob.Sdk@2.0.4", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "@vpmdhaj/devops-tools", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "@vpmdhaj/elastic-helper", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "@vpmdhaj/opensearch-setup", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "@vpmdhaj/search-setup", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "app-config-utility", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "elastic-opensearch-helper", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "env-config-manager", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "opensearch-config-utility", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "opensearch-security-scanner", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "opensearch-setup", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "opensearch-setup-tool", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "search-cluster-setup", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "search-engine-setup", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },
  { type: "package", value: "vpmdhaj-opensearch-setup", severity: "critical", confidence: 1.0, family: "SicoobStealer", campaign: "vpmdhaj Sicoob/Cloud-Secret", firstSeen: "2026-05-28" },

  // Miasma / @redhat-cloud-services Mini Shai-Hulud variant (BleepingComputer + Socket.dev, June 1, 2026)
  // 32 packages, 96 versions under Red Hat's @redhat-cloud-services namespace trojanized
  // via a compromised Red Hat employee GitHub account abusing a GitHub Actions workflow
  // to auto-publish backdoored versions. Payload is a Shai-Hulud descendant labelled
  // "Miasma: The Spreading Blight"; preinstall runs a ~4.2 MB index.js that steals
  // GitHub Actions secrets, AWS / GCP / Azure credentials, HashiCorp Vault tokens,
  // Kubernetes SA tokens, npm and PyPI publishing tokens, SSH keys, Docker creds,
  // GPG keys, and .env files into ~309 attacker-controlled GitHub repos.
  { type: "package", value: "@redhat-cloud-services/chrome@2.3.1", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma / @redhat-cloud-services", firstSeen: "2026-06-01" },

  // June 2026 npm/PyPI infostealer cluster (The Hacker News Weekly Recap, June 8, 2026)
  // Throwaway-package wave surfaced alongside the GitHub-worm coverage:
  //   - turbo-axios / faster-axios: trojanized axios copies whose postinstall hooks
  //     deploy Epsilon Stealer.
  //   - cms-store-ren: exfiltrates harvested data to Telegram via an exposed bot API token.
  //   - parsimonius: typosquat of "parsimonious" deploying a Telegram-based backdoor
  //     (published to both npm and PyPI; ~2,474 downloads before removal).
  // Bare-name entries: each package is fully malicious, so the name alone is the indicator.
  { type: "package", value: "turbo-axios", severity: "critical", confidence: 0.9, family: "EpsilonStealer", campaign: "THN Weekly Recap npm cluster", firstSeen: "2026-06-08" },
  { type: "package", value: "faster-axios", severity: "critical", confidence: 0.9, family: "EpsilonStealer", campaign: "THN Weekly Recap npm cluster", firstSeen: "2026-06-08" },
  { type: "package", value: "cms-store-ren", severity: "critical", confidence: 0.9, family: "TelegramBackdoor", campaign: "THN Weekly Recap npm cluster", firstSeen: "2026-06-08" },
  // parsimonius is the PyPI member of this cluster (OSV MAL-2026-5151, PyPI;
  // no npm record): `pypi:` added 2026-09-26 for the same reason as ZiChatBot.
  { type: "package", value: "pypi:parsimonius", severity: "critical", confidence: 0.9, family: "TelegramBackdoor", campaign: "THN Weekly Recap npm/PyPI cluster", firstSeen: "2026-06-08" },

  // ThreatsDay Bulletin npm cluster (The Hacker News, June 11, 2026)
  //   - tw-style-utils: poisoned npm package delivering the cross-platform SStar Agent
  //     RAT (Windows + macOS), pushed via the star45674/smart-contract-engineer-role
  //     fake job-assignment lure (GitHub account tracked in ioc-blocklist).
  //   - ambar-src: fully malicious npm package (Tenable) whose download count was
  //     artificially "pumped" to 50,000+ in three days to manufacture credibility.
  // Bare-name entries: each package is fully malicious, so the name alone is the indicator.
  { type: "package", value: "tw-style-utils", severity: "critical", confidence: 0.9, family: "SStarAgent", campaign: "SStar Agent smart-contract-engineer lure", firstSeen: "2026-06-11" },
  { type: "package", value: "ambar-src", severity: "critical", confidence: 0.9, family: "DownloadPumping", campaign: "ThreatsDay ambar-src", firstSeen: "2026-06-11" },

  // Arch Linux AUR mass hijack npm dropper (The Hacker News + BleepingComputer, June 12, 2026)
  //   - atomic-lockfile@1.4.2: fully malicious npm package pulled and executed by preinstall
  //     hooks added to 400+ hijacked Arch User Repository (AUR) build scripts; installs a
  //     credential stealer + eBPF rootkit. Published 2026-06-10, removed by npm security
  //     2026-06-12 (superseded by the 0.0.1-security holding placeholder).
  { type: "package", value: "atomic-lockfile@1.4.2", severity: "critical", confidence: 1.0, family: "AURInfostealer", campaign: "Arch Linux AUR Mass Hijack", firstSeen: "2026-06-12" },

  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // Microsoft-attributed: forgotten-contributor npm account "ehindero" was compromised and
  // used to republish 141 @mastra-scope packages, each gaining the easy-day-js dependency
  // (dayjs clone). Its postinstall hook disables TLS verification, contacts the dropper C2
  // (23.254.164.92:8000 /update/49890878), downloads a stage-2 cross-platform Node.js
  // crypto-stealer RAT (RAT C2 23.254.164.123:443 /49890878). Both C2s Hostwinds-hosted.
  // Representative subset of the 143 compromised package@version pairs recorded.
  { type: "ip", value: "23.254.164.92", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "ip", value: "23.254.164.123", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "hash", value: "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "hash", value: "4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "package", value: "easy-day-js@1.11.22", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "package", value: "@mastra/core@1.42.1", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "package", value: "@mastra/agent-builder@1.0.42", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "package", value: "@mastra/auth@1.0.3", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "package", value: "@mastra/claude@1.0.3", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "package", value: "@mastra/express@1.3.31", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "package", value: "@mastra/openai@1.0.2", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "package", value: "mastra@1.13.1", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },
  { type: "package", value: "create-mastra@1.13.1", severity: "critical", confidence: 1.0, family: "SapphireSleetRAT", campaign: "Mastra npm Scope Takeover", firstSeen: "2026-06-17" },

  // NastyC2 npm framework (The Hacker News ThreatsDay Bulletin, June 18, 2026)
  // Three fully malicious npm packages bundling NastyC2, a Rust post-exploitation implant
  // (80+ commands: credential harvesting, AD attacks, container escape, cloud-metadata
  // theft, fileless execution). No C2 / hashes disclosed in the bulletin.
  { type: "package", value: "node-ci-utils@2.1.4", severity: "critical", confidence: 0.9, family: "NastyC2", campaign: "NastyC2 npm Framework", firstSeen: "2026-06-18" },
  { type: "package", value: "win-env-setup@3.0.6", severity: "critical", confidence: 0.9, family: "NastyC2", campaign: "NastyC2 npm Framework", firstSeen: "2026-06-18" },
  { type: "package", value: "macos-ci-utils@1.0.0", severity: "critical", confidence: 0.9, family: "NastyC2", campaign: "NastyC2 npm Framework", firstSeen: "2026-06-18" },

  // crypto-javascript cross-ecosystem worm (The Hacker News ThreatsDay Bulletin, June 18, 2026)
  // Self-propagating supply-chain worm across Rust/Cargo, Python, CMake, and npm; drops a
  // Monero cryptominer + the "Dirty Frag" Linux kernel LPE exploit. GCC timestamp 2026-04-30.
  { type: "package", value: "crypto-javascript@4.2.5", severity: "critical", confidence: 0.9, family: "CryptoJsWorm", campaign: "crypto-javascript Worm", firstSeen: "2026-06-18" },

  // PostCSS-impersonation npm packages deliver Windows RAT (The Hacker News, June 23, 2026)
  // Malicious npm packages posing as PostCSS tooling deliver a Windows-based remote access
  // trojan. aes-decode-runner-pro (145 downloads) + postcss-min are fully malicious; the feed
  // excerpt disclosed no C2 / hashes / publisher, so the bare package names are the indicators.
  { type: "package", value: "postcss-min", severity: "critical", confidence: 0.9, family: "WindowsRAT", campaign: "PostCSS Tools Windows RAT", firstSeen: "2026-06-23" },
  { type: "package", value: "aes-decode-runner-pro", severity: "critical", confidence: 0.9, family: "WindowsRAT", campaign: "PostCSS Tools Windows RAT", firstSeen: "2026-06-23" },

  // Miasma LeoPlatform / GitHub Actions wave (The Hacker News, June 26, 2026)
  // Latest evolution of the Mini Shai-Hulud / Miasma / Hades worm family. Compromised
  // npm maintainer "czirker" (LeoPlatform) republished the LeoPlatform / RStreams SDK
  // packages + hexo-* plugins with a preinstall credential stealer; the worm also
  // propagated to the Go ecosystem (verana-blockchain) and abused the
  // codfish/semantic-release-action GitHub Action. Dead-drop repos described "Alright
  // Lets See If This Works" (559 repos); token-relay marker "RevokeAndItGoesKaboom".
  { type: "package", value: "leo-sdk@6.0.19", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-streams@2.0.1", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-auth@4.0.6", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-aws@2.0.4", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-cache@1.0.2", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-cdk-lib@0.0.2", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-cli@3.0.3", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-config@1.1.1", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-connector-elasticsearch@2.0.6", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-connector-mongo@3.0.8", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-connector-mysql@3.0.3", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-connector-oracle@2.0.1", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-connector-redshift@3.0.6", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-cron@2.0.2", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "leo-logger@1.0.8", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "rstreams-metrics@2.0.2", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "rstreams-shard-util@1.0.1", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "serverless-leo@3.0.14", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "serverless-convention@2.0.4", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "prism-silq@1.0.1", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "solo-nav@1.0.1", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "hexo-deployer-wrangler@1.0.4", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  { type: "package", value: "hexo-shoka-swiper@0.1.10", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },
  // Go ecosystem propagation - version-pinned (clean upstream versions remain legitimate)
  { type: "package", value: "go:github.com/verana-labs/verana-blockchain@v0.10.1-dev.20", severity: "critical", confidence: 1.0, family: "MiasmaShaiHuludVariant", campaign: "Miasma LeoPlatform", firstSeen: "2026-06-26" },

  // Contagious Interview "Fake Font" npm + Go wave / InvisibleFerret (The Hacker News, June 29, 2026)
  // DPRK Contagious Interview operation. A hidden VS Code task ("eslint-check") plus a JavaScript
  // payload disguised as a web font (public/fonts/fa-solid-400.woff2) drops the InvisibleFerret
  // Python backdoor. TronGrid + Aptos blockchain transactions act as the dead-drop resolver;
  // harvested data is packaged into ZIP archives and uploaded to a C2 server or a runtime-supplied
  // Telegram bot. No file hashes, C2 domains, IPs, or wallet addresses were disclosed.
  //
  // VERSION-PINNED, corrected 2026-08-29. These two npm packages are HIJACK VICTIMS, not
  // attacker-created names: JFrog names exactly one poisoned release each, html-to-gutenberg
  // 4.2.11 and fetch-page-assets 1.2.9, both uploaded 2026-05-25. Both packages are legitimate
  // work by their maintainer and are still live and installable - registry-verified 2026-08-29:
  // html-to-gutenberg has 10 versions from 2025-07-11 to 2026-03-29 and fetch-page-assets has 22
  // from 2024-05-21 to 2026-03-29, with ZERO releases inside the campaign window. They were
  // previously carried as BARE NAMES here and in MALICIOUS_PACKAGE_PATTERNS, which blocked every
  // clean version of both packages: a false positive that shipped from v5.x on 2026-06-29 until
  // this correction. Pinning the two named releases keeps the real artifact detected - a lockfile
  // still holding 4.2.11 or 1.2.9 is exactly what must be caught - without touching clean ones.
  { type: "package", value: "html-to-gutenberg@4.2.11", severity: "critical", confidence: 1.0, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", source: "JFrog Security Research", firstSeen: "2026-06-29" },
  { type: "package", value: "fetch-page-assets@1.2.9", severity: "critical", confidence: 1.0, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", source: "JFrog Security Research", firstSeen: "2026-06-29" },
  // Go modules of the same wave, CORRECTED 2026-09-23. These were 15 whole-name blocks. Every
  // path is a developer repository the wave INFECTED (a backdated commit adding the 799-byte
  // .vscode/tasks.json "eslint-check" loader plus JavaScript posing as
  // public/fonts/fa-solid-400.woff2), not an attacker-created module, so a name block flags the
  // owner's clean history. Measured against the Go module proxy, which keeps module zips:
  // - lambda-platform/lambda is a framework released since 2021: 137 of its 449 versions are
  //   retrievable and ALL are clean, including the 16 published in 2026. Dropped.
  // - the four pinned below are the exact pseudo-versions whose proxy zip carries the loader
  //   (their commit dates are forged, hence 2018-2025 timestamps). A clean restore gets a new
  //   pseudo-version and is not matched.
  // - the other ten have no retrievable version at all (proxy 404, repository deleted or
  //   blocked), so no artifact exists to pin and nothing installable is protected by a name
  //   block. Dropped. A checkout of any of them is still caught by what it contains:
  //   EDITOR_TASK_EXECUTES_ASSET (skills-scanner.ts) flags the loader itself.
  { type: "package", value: "go:github.com/glacialspring/go-winsparkle@v0.0.0-20250402002608-9d703488711b", severity: "critical", confidence: 1.0, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", source: "The Hacker News; loader verified in the Go proxy module zip", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/glacialspring/static@v0.0.0-20181015024211-023dc73bc332", severity: "critical", confidence: 1.0, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", source: "The Hacker News; loader verified in the Go proxy module zip", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/zainirfan13/graphql-client@v0.0.0-20220912215956-d304e79da123", severity: "critical", confidence: 1.0, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", source: "The Hacker News; loader verified in the Go proxy module zip", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/dexbotsdev/uniswap-v2-v3-arbitrage@v0.0.0-20231007040513-b492291579de", severity: "critical", confidence: 1.0, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", source: "The Hacker News; loader verified in the Go proxy module zip", firstSeen: "2026-06-29" },

  // Contagious Interview Rollup polyfill npm packages (Lazarus, DPRK) (The Hacker News / JFrog, July 3, 2026)
  // Fresh DPRK "Contagious Interview" wave: 6 attacker-uploaded npm packages masquerade as
  // Rollup polyfill tooling to facilitate remote access + developer-secret theft. JFrog ties
  // the cluster to prior Lazarus / Contagious Interview activity. C2 on 216.126.236.244 (same
  // 216.126.x range as the OtterCookie / Megalodon DPRK infra). The packages fetch second-stage
  // code via JSONKeeper, a legitimate JSON-paste service abused as a dead-drop (NOT blocked to
  // avoid false positives). Bare-name entries: each package is fully malicious with no legit history.
  { type: "ip", value: "216.126.236.244", severity: "critical", confidence: 1.0, family: "ContagiousInterview", campaign: "Contagious Interview Rollup Polyfill", firstSeen: "2026-07-03" },
  { type: "package", value: "rollup-packages-polyfill-core", severity: "critical", confidence: 0.9, family: "ContagiousInterview", campaign: "Contagious Interview Rollup Polyfill", firstSeen: "2026-07-03" },
  { type: "package", value: "rollup-runtime-polyfill-core", severity: "critical", confidence: 0.9, family: "ContagiousInterview", campaign: "Contagious Interview Rollup Polyfill", firstSeen: "2026-07-03" },
  { type: "package", value: "rollup-plugin-polyfill-connect", severity: "critical", confidence: 0.9, family: "ContagiousInterview", campaign: "Contagious Interview Rollup Polyfill", firstSeen: "2026-07-03" },
  { type: "package", value: "quirky-token", severity: "critical", confidence: 0.9, family: "ContagiousInterview", campaign: "Contagious Interview Rollup Polyfill", firstSeen: "2026-07-03" },
  { type: "package", value: "react-icon-svgs", severity: "critical", confidence: 0.9, family: "ContagiousInterview", campaign: "Contagious Interview Rollup Polyfill", firstSeen: "2026-07-03" },
  { type: "package", value: "swift-parse-stream", severity: "critical", confidence: 0.9, family: "ContagiousInterview", campaign: "Contagious Interview Rollup Polyfill", firstSeen: "2026-07-03" },

  // ChocoPoC RAT / fake PoC exploit repos targeting vulnerability researchers (The Hacker News, July 2, 2026)
  // A data-stealing trojan ("ChocoPoC") is hidden inside fake Python proof-of-concept exploit
  // repositories on GitHub that claim to exploit trending CVEs, targeting the researchers who
  // hunt bugs. Malicious PyPI packages carry the payload (skytext ~2,400 downloads; frint), tied
  // by researchers to the same actor behind the late-2025 slogsec / logcrypt.cryptography packages.
  // Compiled payloads: gradient.so (Linux) / gradient.pyd (Windows). Upload server 91.132.163.78;
  // Mapbox abused as a DoH dead drop (NOT blocked).
  //
  // ECOSYSTEM PREFIX CORRECTED 2026-08-29. Every one of these four is a PyPI package, and the
  // entries were written WITHOUT the `pypi:` prefix, which in this feed means the npm namespace.
  // That inverted them exactly as CLAUDE.md warns: the real PyPI malware was unreachable through
  // the feed, while the npm name of the same string was flagged critical. `frint` is a real npm
  // package - the Frint framework's core plugin, 89 versions published 2016-07-01 to 2018-09-11
  // by six maintainers - so the missing prefix blocked a legitimate ten-year-old library from
  // 2026-07-02 until this correction, and detected nothing in return. PYPI_TYPOSQUAT_PATTERNS
  // already carried these four correctly, which is why the PyPI scanner path was unaffected.
  { type: "ip", value: "91.132.163.78", severity: "critical", confidence: 1.0, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2026-07-02" },
  { type: "package", value: "pypi:frint", severity: "critical", confidence: 0.9, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2026-07-02" },
  { type: "package", value: "pypi:skytext", severity: "critical", confidence: 0.9, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2026-07-02" },
  { type: "package", value: "pypi:slogsec", severity: "critical", confidence: 0.9, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2025-11-01" },
  { type: "package", value: "pypi:logcrypt.cryptography", severity: "critical", confidence: 0.9, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2025-11-01" },

  // PolinRider DPRK supply-chain campaign (Socket / The Hacker News / SecurityWeek, July 6, 2026)
  // North-Korea-linked cluster (Contagious Interview / Famous Chollima), active since Dec 2025,
  // poisoned 108 packages/extensions (162 release artifacts) across npm, Packagist, Go modules and
  // Chrome. Obfuscated JS loaders (hidden in config.js / fake .woff2 fonts, run via VS Code tasks on
  // folder-open) decrypt a second stage fetched over TRON / Aptos / BNB Smart Chain RPC with an
  // embedded XOR key and eval() it, dropping the DEV#POPPER RAT + OmniStealer (credential/browser/
  // wallet theft). Only the concretely enumerated malicious Go module is pinned here (it was a bare
  // name until 2026-09-23, blocking the live project): git2md from the compromised account Xpos587 at
  // v0.0.0-20260503100027-79bdb26ca95d, whose proxy zip carries the loader. The npm/Composer package
  // names and the Chrome extension ID were not publicly enumerated at feed time and are omitted to
  // avoid guessing; git-history rewriting/force-pushes make the accounts' clean history untrustworthy.
  { type: "package", value: "go:github.com/Xpos587/git2md@v0.0.0-20260503100027-79bdb26ca95d", severity: "critical", confidence: 0.95, family: "OmniStealer", campaign: "PolinRider", firstSeen: "2026-07-06" },

  // Fake Paysafe / Skrill / Neteller payment SDKs (Socket, July 8, 2026). 17
  // packages published ~July 7 across npm (13, versions 1.0.0-1.0.3) and PyPI
  // (4, version 1.0.0) impersonate non-existent official payment SDKs: they
  // expose the expected APIs but return fake success responses and exfiltrate
  // every env var matching KEY/SECRET/TOKEN/PASS/AUTH/API (Paysafe/AWS keys,
  // GitHub + npm tokens) via HTTPS POST to an ngrok tunnel. Bare names: the
  // whole package is malicious, so any version matches. These are the 13 OBSERVED
  // npm names; the PyPI-only "paysafe-sdk" is covered by PYPI_TYPOSQUAT_PATTERNS,
  // not this npm-scoped feed (do not re-add it here - it was not seen on npm).
  { type: "package", value: "paysafe-checkout", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "paysafe-vault", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "paysafe-js", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "paysafe-api", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "paysafe-node", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "paysafe-cards", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "paysafe-fraud", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "paysafe-kyc", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "paysafe-payments", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "skrill", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "skrill-sdk", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "skrill-payments", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "package", value: "neteller", severity: "critical", confidence: 0.98, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
  { type: "domain", value: "caliber-spinner-finishing.ngrok-free.dev", severity: "critical", confidence: 0.95, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },

  // Compromised jscrambler npm release (Socket / The Hacker News / OX / StepSecurity, July 11, 2026)
  // jscrambler (~15,800 weekly downloads) + four companion build plugins were hijacked and
  // republished with a native Rust infostealer: a malicious preinstall hook in 8.14.0-8.17.0,
  // then a self-executing dropper in dist/index.js + dist/bin/jscrambler.js from 8.18.0.
  // Payload harvests AWS/GCP/Azure creds, crypto wallets, browser data and AI-tool configs on
  // Windows/macOS/Linux. Version-pinned: legitimate packages; clean 8.13.0, fixed 8.22.0.
  { type: "package", value: "jscrambler@8.14.0", severity: "critical", confidence: 1.0, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "package", value: "jscrambler@8.16.0", severity: "critical", confidence: 1.0, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "package", value: "jscrambler@8.17.0", severity: "critical", confidence: 1.0, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "package", value: "jscrambler@8.18.0", severity: "critical", confidence: 1.0, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "package", value: "jscrambler@8.20.0", severity: "critical", confidence: 1.0, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "package", value: "jscrambler-webpack-plugin@8.6.2", severity: "critical", confidence: 1.0, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "package", value: "gulp-jscrambler@8.6.2", severity: "critical", confidence: 1.0, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "package", value: "grunt-jscrambler@8.5.2", severity: "critical", confidence: 1.0, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "package", value: "jscrambler-metro-plugin@9.0.2", severity: "critical", confidence: 1.0, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "hash", value: "a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60", severity: "critical", confidence: 0.85, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "hash", value: "a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86", severity: "critical", confidence: 0.85, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "hash", value: "fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd", severity: "critical", confidence: 0.85, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "hash", value: "b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903", severity: "critical", confidence: 0.85, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },
  { type: "hash", value: "c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd", severity: "critical", confidence: 0.85, family: "Rust Infostealer", campaign: "jscrambler npm compromise", firstSeen: "2026-07-11" },

  // Injective Labs SDK npm compromise (The Hacker News / BleepingComputer / Socket / Aikido, July 8-10, 2026)
  // Attacker abused the Injective Labs SDK GitHub repo + its OIDC trusted-publisher pipeline to publish
  // @injectivelabs/sdk-ts@1.20.21 with "fake telemetry" that captures wallet private keys + mnemonic seed
  // phrases (base64) and HTTPS-POSTs them to testnet.archival.chain.grpc-web.injective.network. 1.20.21 was
  // pinned across 17 dependent @injectivelabs scoped packages (18 total). Clean version: 1.20.23. Version-pinned.
  { type: "domain", value: "testnet.archival.chain.grpc-web.injective.network", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "hash", value: "103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "hash", value: "9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/sdk-ts@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/utils@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/networks@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/ts-types@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/exceptions@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-base@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-core@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-cosmos@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-private-key@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-evm@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-trezor@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-cosmostation@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-ledger@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-wallet-connect@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-magic@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-strategy@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-turnkey@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },
  { type: "package", value: "@injectivelabs/wallet-cosmos-strategy@1.20.21", severity: "critical", confidence: 1.0, family: "WalletStealer", campaign: "Injective SDK npm compromise", firstSeen: "2026-07-08" },

  // AsyncAPI npm supply-chain compromise (The Hacker News / BleepingComputer / Socket / StepSecurity, July 14-15, 2026)
  // Five malicious versions across four @asyncapi packages published in a ~4h window on 2026-07-14
  // (07:10-11:18 UTC) delivering a credential-stealing multi-stage botnet loader. Second stage pulled
  // from IPFS; C2 over HTTP / Nostr relay / IPFS / BitTorrent DHT / libp2p GossipSub / Ethereum contract.
  // All versions since unpublished. Version-pinned: legitimate packages, only these versions are malicious.
  { type: "url", value: "ipfs.io/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9", severity: "critical", confidence: 1.0, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "package", value: "@asyncapi/generator@3.3.1", severity: "critical", confidence: 1.0, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "package", value: "@asyncapi/generator-helpers@1.1.1", severity: "critical", confidence: 1.0, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "package", value: "@asyncapi/generator-components@0.7.1", severity: "critical", confidence: 1.0, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "package", value: "@asyncapi/specs@6.11.2", severity: "critical", confidence: 1.0, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "package", value: "@asyncapi/specs@6.11.2-alpha.1", severity: "critical", confidence: 1.0, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  // Infrastructure enrichment (2026-07-28): the atomic indicators behind the same
  // campaign, which the advisory databases do not carry. C2 host serves :8080
  // (commands), :8081 (credential upload) and :8091 (proxy management); the
  // Ethereum contract is the blockchain fallback channel. Corroborated by Socket
  // and StepSecurity, except the second IPFS CID and the tarball hashes, which are
  // single-source (StepSecurity and Socket respectively) and carry confidence 0.85.
  { type: "ip", value: "85.137.53.71", severity: "critical", confidence: 1.0, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "url", value: "0x12c37a86a0ed0bebe5d1d6a43e42f07860eac710", severity: "critical", confidence: 1.0, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "url", value: "ipfs.io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf", severity: "critical", confidence: 0.85, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "hash", value: "34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1", severity: "critical", confidence: 0.85, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "hash", value: "082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab", severity: "critical", confidence: 0.85, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "hash", value: "bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4", severity: "critical", confidence: 0.85, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "hash", value: "9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b", severity: "critical", confidence: 0.85, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
  { type: "hash", value: "d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7", severity: "critical", confidence: 0.85, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },

  // PhantomSync npm crypto-wallet stealer (Xygeni, July 15, 2026). SINGLE-SOURCE
  // (Xygeni only; no independent corroboration found) - hence confidence 0.85, not
  // 1.0. Publisher solbuilder_io. 8 generic blockchain-util package names, each
  // malicious at SPECIFIC versions only (name-squat takeover risk), so version-pinned
  // NEVER bare-name. NOTE base58-utils is malicious at 1.0.0/1.0.1/1.0.3 but NOT
  // 1.0.2. Steals ETH/BTC/Solana keys + BIP-39 seeds, exfil to IPFS via Pinata.
  { type: "package", value: "base58-utils@1.0.0", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "base58-utils@1.0.1", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "base58-utils@1.0.3", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "abi-encode@1.0.0", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "abi-encode@1.0.1", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "abi-encode@1.0.2", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "eth-dev@1.0.0", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "eth-dev@1.0.1", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "eth-dev@1.0.2", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "arb-kit@1.0.0", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "arb-kit@1.0.1", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "layer2-sdk@1.0.0", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "layer2-sdk@1.0.1", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "solana-key-utils@1.0.0", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "eth-wallet-helpers@1.0.0", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "package", value: "crypto-validate-lib@1.0.0", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },
  { type: "url", value: "gist.githubusercontent.com/juang55/b298754cb72942b1cdcf02ccd45cde2f/raw/cfg.txt", severity: "critical", confidence: 0.85, family: "WalletStealer", campaign: "PhantomSync npm crypto stealer", firstSeen: "2026-07-15" },

  // Pepesoft NuGet game-cheat surveillance (Socket, July 14, 2026). Publisher
  // pepegit666. The 11 package IDs in the writeup carry a uniform "-x-x" suffix
  // that is a source-side redaction placeholder (absent from a full mirror), NOT
  // an installable id - so NO package entries are ingested (a redacted id blocks
  // nothing; a guessed real id risks false positives). Detection rides on the 32
  // SHA-256 payload hashes (ioc-blocklist KNOWN_MALICIOUS_HASHES) + this network
  // infra. Specific sub-hosts only, never the workers.dev/selcloud.ru apex.
  { type: "domain", value: "calm-voice-9797.888c888x888.workers.dev", severity: "critical", confidence: 0.95, family: "GameCheatSpyware", campaign: "Pepesoft NuGet surveillance", firstSeen: "2026-07-14" },
  { type: "domain", value: "s3.ru-3.storage.selcloud.ru", severity: "high", confidence: 0.9, family: "GameCheatSpyware", campaign: "Pepesoft NuGet surveillance", firstSeen: "2026-07-14" },
  { type: "domain", value: "bots.pepesoft.ru", severity: "critical", confidence: 0.95, family: "GameCheatSpyware", campaign: "Pepesoft NuGet surveillance", firstSeen: "2026-07-14" },
  { type: "ip", value: "196.16.3.71", severity: "high", confidence: 0.9, family: "GameCheatSpyware", campaign: "Pepesoft NuGet surveillance", firstSeen: "2026-07-14" },

  // ViteVenom - malicious Vite npm packages w/ blockchain C2 (Checkmarx via The Hacker News, July 18, 2026)
  // Threat actor "SuccessKey"; expansion of the ChainVeil campaign. Seven scoped packages
  // impersonating the "@vitejs/*" namespace, published June 29-July 3, 2026. Payload runs at
  // IMPORT time (not install time) to evade endpoint detection, and delivers a RAT (reverse
  // shell + credential harvesting + file exfiltration + persistent backdoor) via a four-tier
  // blockchain C2 spanning Tron/Aptos/BNB Smart Chain. All seven are fully malicious with no
  // legitimate history - bare-name IOCs (any version). Specific wallet/contract addresses were
  // not published in extractable form, so none are ingested (a guessed address helps nobody).
  { type: "package", value: "@uw010010/vite-tree", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ViteVenom", firstSeen: "2026-06-29" },
  { type: "package", value: "@vite-tab/tab", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ViteVenom", firstSeen: "2026-06-29" },
  { type: "package", value: "@vite-ln/build-ts", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ViteVenom", firstSeen: "2026-06-29" },
  { type: "package", value: "@vite-mcp/vite-type", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ViteVenom", firstSeen: "2026-06-29" },
  { type: "package", value: "@vite-pro/vite-ui", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ViteVenom", firstSeen: "2026-06-29" },
  { type: "package", value: "@vitets/vite-ts", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ViteVenom", firstSeen: "2026-06-29" },
  { type: "package", value: "@vite-ts/vite-ui", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ViteVenom", firstSeen: "2026-06-29" },

  // ChainVeil - the predecessor wave of ViteVenom above (Checkmarx Zero, June 16, 2026). Nine
  // typosquats of Tailwind / Sass / TypeORM / rate-limiter libraries carrying the same 77 KB RAT
  // and the same four-tier Tron/Aptos/BNB Smart Chain C2. Package names and versions corroborated
  // by OpenSourceMalware (July 17, 2026), which links both waves to the DPRK/Lazarus PolinRider
  // campaign through shared Tron wallets, Aptos address and XOR decryption keys. All nine were
  // confirmed against the npm registry on 2026-07-27 as "security holding package" placeholders
  // (npm removed them as malware), so no legitimate release exists under these names and the
  // bare-name IOCs below cannot flag a clean install. The typosquat TARGETS (tailwind-merge,
  // rate-limiter-flexible, typeorm) are legitimate packages and are deliberately NOT listed.
  // Published versions were all 1.0.x; not version-pinned, because every version is malicious.
  { type: "package", value: "tailwindcss-animatics", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ChainVeil", firstSeen: "2026-06-16" },
  { type: "package", value: "tailwindcss-animates-kit", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ChainVeil", firstSeen: "2026-06-16" },
  { type: "package", value: "tailwindcss-merge", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ChainVeil", firstSeen: "2026-06-16" },
  { type: "package", value: "sass-formats", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ChainVeil", firstSeen: "2026-06-16" },
  { type: "package", value: "sass-format", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ChainVeil", firstSeen: "2026-06-16" },
  { type: "package", value: "clsx-tailwind", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ChainVeil", firstSeen: "2026-06-16" },
  { type: "package", value: "typeorm-encrypt", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ChainVeil", firstSeen: "2026-06-16" },
  { type: "package", value: "rate-limit-flexible", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ChainVeil", firstSeen: "2026-06-16" },
  { type: "package", value: "rate-limits-flexible", severity: "critical", confidence: 0.95, family: "ChainVeil RAT", campaign: "ChainVeil", firstSeen: "2026-06-16" },

  // NadMesh botnet (XLab via The Hacker News, July 2026). Go-based botnet that scans
  // for exposed AI services (Ollama / vLLM / etc.) and CI/CD hosts, harvesting AWS
  // keys and Kubernetes tokens (operator claimed 3,811 unique AWS keys). Network
  // infra + agent-sample hash per XLab's published indicators; no package IOCs
  // (this is a scanning botnet, not a poisoned registry package).
  { type: "domain", value: "cdnorigin.net", severity: "critical", confidence: 0.9, family: "NadMesh", campaign: "NadMesh botnet", firstSeen: "2026-07-17" },
  { type: "ip", value: "209.99.186.235", severity: "critical", confidence: 0.9, family: "NadMesh", campaign: "NadMesh botnet", firstSeen: "2026-07-17" },
  { type: "hash", value: "31c69b3e12936abca770d430066f379ec1d997ec", severity: "critical", confidence: 0.9, family: "NadMesh", campaign: "NadMesh botnet", firstSeen: "2026-07-17" },

  // SleeperGem - three malicious RubyGems releases (StepSecurity / Aikido via The Hacker
  // News, July 20, 2026). A loader gem fetches a second stage from an attacker-controlled
  // Forgejo account, skips execution when ~30 CI env vars (GITHUB_ACTIONS, GITLAB_CI,
  // CIRCLECI, ...) are present so it only detonates on developer laptops, then drops a
  // native daemon plus cron / systemd-user persistence and, with passwordless sudo, a
  // setuid root shell.
  //   - git_credential_manager impersonates Microsoft's Git Credential Manager and has no
  //     legitimate history, but is still pinned per version (2.8.0-2.8.3, July 18, 2026).
  //   - Dendreo and fastlane-plugin-run_tests_firebase_testlab are REAL gems that lay
  //     dormant for years; only the sleeper releases below are malicious, so these must
  //     stay version-pinned - a bare-name IOC would flag every legitimate install.
  { type: "package", value: "ruby:git_credential_manager@2.8.0", severity: "critical", confidence: 0.95, family: "SleeperGem", campaign: "SleeperGem", firstSeen: "2026-07-18" },
  { type: "package", value: "ruby:git_credential_manager@2.8.1", severity: "critical", confidence: 0.95, family: "SleeperGem", campaign: "SleeperGem", firstSeen: "2026-07-18" },
  { type: "package", value: "ruby:git_credential_manager@2.8.2", severity: "critical", confidence: 0.95, family: "SleeperGem", campaign: "SleeperGem", firstSeen: "2026-07-18" },
  { type: "package", value: "ruby:git_credential_manager@2.8.3", severity: "critical", confidence: 0.95, family: "SleeperGem", campaign: "SleeperGem", firstSeen: "2026-07-18" },
  { type: "package", value: "ruby:Dendreo@1.1.3", severity: "critical", confidence: 0.95, family: "SleeperGem", campaign: "SleeperGem", firstSeen: "2026-07-18" },
  { type: "package", value: "ruby:Dendreo@1.1.4", severity: "critical", confidence: 0.95, family: "SleeperGem", campaign: "SleeperGem", firstSeen: "2026-07-18" },
  { type: "package", value: "ruby:fastlane-plugin-run_tests_firebase_testlab@0.3.2", severity: "critical", confidence: 0.95, family: "SleeperGem", campaign: "SleeperGem", firstSeen: "2026-07-18" },
  // Payload host. git.disroot.org itself is a legitimate public Forgejo instance, so only
  // the attacker's account path is ingested - the bare domain is deliberately NOT added to
  // KNOWN_C2_DOMAINS (it would flag every project that legitimately hosts code there).
  { type: "url", value: "git.disroot.org/git-ecosystem", severity: "critical", confidence: 0.9, family: "SleeperGem", campaign: "SleeperGem", firstSeen: "2026-07-18" },

  // cPanel/WHM GitHub Actions abuse campaign (Socket, July 23, 2026). A legitimate
  // developer's 10 Packagist packages had malicious dev-main versions injected with
  // 55-62 GitHub Actions workflow files each; the workflows spin up GitHub-hosted
  // runners, download an arch-specific Linux payload from the C2, and scan for
  // cPanel/WHM servers vulnerable to CVE-2026-41940, harvesting credentials/SSH/Git
  // tokens/cloud keys. Network + hash IOCs only - the maintainer is a victim, so the
  // account and the bare package names are intentionally NOT ingested. The dnshook.site
  // entry is a specific UUID subdomain used for DNS-callback beaconing, not the apex.
  { type: "ip", value: "43.228.157.68", severity: "critical", confidence: 0.95, family: "CPanelScanner", campaign: "cPanel/WHM GitHub Actions abuse", firstSeen: "2026-07-23" },
  { type: "domain", value: "f5b0b742-240a-4811-8a5b-b0ba6060685d.dnshook.site", severity: "critical", confidence: 0.9, family: "CPanelScanner", campaign: "cPanel/WHM GitHub Actions abuse", firstSeen: "2026-07-23" },
  { type: "hash", value: "22f721fd3a81d2e27cbf90a122bb977f630c50b79daa98350f0e57b04dfa81f1", severity: "critical", confidence: 0.95, family: "CPanelScanner", campaign: "cPanel/WHM GitHub Actions abuse", firstSeen: "2026-07-23" },

  // Apex macOS infostealer npm packages (safedep / The Hacker News, July 22, 2026).
  // A postinstall dropper installs an AMOS-family macOS infostealer (AppleScript via
  // osascript; harvests browser creds, 20+ crypto wallets, SSH keys, AWS/Kubernetes
  // creds) while installing a working forked coding agent as cover. npm removed
  // @apexfdn/apex; the operator re-published the same payload as @copilot-mcp/apex
  // ~11h later and churned 20+ versions in 8h. Both are fully malicious with no
  // legitimate history - bare-name IOCs (any version); block the name, not a range.
  { type: "package", value: "@apexfdn/apex", severity: "critical", confidence: 0.95, family: "AMOS Stealer", campaign: "Apex macOS infostealer", firstSeen: "2026-07-22" },
  { type: "package", value: "@copilot-mcp/apex", severity: "critical", confidence: 0.95, family: "AMOS Stealer", campaign: "Apex macOS infostealer", firstSeen: "2026-07-22" },

  // FakeAgent campaign / SectopRAT via fake Claude Desktop app (Huntress / BleepingComputer /
  // Help Net Security, July 21-22, 2026). Bing "Claude Desktop app" ads -> malicious public
  // Claude Artifact -> attacker-registered redirect domains -> trojanized ClaudeDesktop.exe
  // sideloading a malicious libcef.dll = SectopRAT / ArechClient2 infostealer with HVNC.
  // EtherHiding resolves the live C2 via BNB Smart Chain (addresses recorded as type "url",
  // following the EtherRAT precedent). The legitimate claude.ai apex is intentionally excluded.
  { type: "domain", value: "download-app.us", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "domain", value: "claude.ai.download-app.us", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "domain", value: "downloading-api.it.com", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "domain", value: "5ca8758c-02d0-4a72-89c8-d468b66dda41.com", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "domain", value: "polse.us", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "ip", value: "107.189.24.67", severity: "high", confidence: 0.9, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "ip", value: "104.194.133.210", severity: "high", confidence: 0.9, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "ip", value: "45.59.124.17", severity: "high", confidence: 0.9, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "ip", value: "107.189.17.143", severity: "high", confidence: 0.9, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "ip", value: "195.110.58.222", severity: "high", confidence: 0.9, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "ip", value: "191.101.80.211", severity: "high", confidence: 0.9, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "hash", value: "1cd58cfba596da296ab1878d74023e00c399345a1b6c2a0e5446c53563f4e3bb", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "hash", value: "26bae4d7012bf59847ab4036a065419c3d4ca47e020479f55b3b2c6d0d21394a", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "hash", value: "1fe3646d27d286db8123297e06ae7badf3e26f352a04f91b6d82c28869a91664", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "hash", value: "f8acb8f5cf88b77a4c27d7fd6856aa299bb178e85f9963c2fbd447d818da3ed0", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "hash", value: "fd826215add30c1319eefa291b6eaf8ddfa7720cfe816c49aef6fe8a88de7939", severity: "critical", confidence: 0.95, family: "SectopRAT", campaign: "FakeAgent", firstSeen: "2026-07-21" },
  { type: "url", value: "0xe012d0f34cde9b870e9d9ed566ea5f8fd9b92228", severity: "critical", confidence: 0.9, family: "SectopRAT", campaign: "FakeAgent EtherHiding C2", firstSeen: "2026-07-21" },
  { type: "url", value: "0xc1907d7be91f95903ad66d775c397302e7dd9228", severity: "critical", confidence: 0.9, family: "SectopRAT", campaign: "FakeAgent EtherHiding C2", firstSeen: "2026-07-21" },



];

const FEED_CHUNK_1: FeedIOC[] = [


  // NeoShadow npm supply-chain attack (Aikido, detected 2025-12-30, published 2026-01-05).
  // Windows-targeting typosquats published by npm account cjh97123: a JS loader runs its payload
  // through MSBuild, patches ETW, and resolves the live C2 from an Ethereum contract (ChaCha20
  // beacon loop). Packages corroborated by o3.security (MAL-2026-334) and all four are npm
  // "security holding package" placeholders, so bare names carry no false-positive risk.
  // The atomic indicators are single-source (Aikido only), hence confidence 0.85.
  { type: "package", value: "viem-js", severity: "critical", confidence: 0.95, family: "NeoShadow RAT", campaign: "NeoShadow", source: "Aikido, o3.security MAL-2026-334", firstSeen: "2026-01-05" },
  { type: "package", value: "cyrpto", severity: "critical", confidence: 0.95, family: "NeoShadow RAT", campaign: "NeoShadow", source: "Aikido, o3.security", firstSeen: "2026-01-05" },
  { type: "package", value: "tailwin", severity: "critical", confidence: 0.95, family: "NeoShadow RAT", campaign: "NeoShadow", source: "Aikido, o3.security", firstSeen: "2026-01-05" },
  { type: "package", value: "supabase-js", severity: "critical", confidence: 0.95, family: "NeoShadow RAT", campaign: "NeoShadow", source: "Aikido, o3.security", firstSeen: "2026-01-05" },
  { type: "domain", value: "metrics-flow.com", severity: "critical", confidence: 0.85, family: "NeoShadow RAT", campaign: "NeoShadow", source: "Aikido (single-source)", firstSeen: "2026-01-05" },
  { type: "ip", value: "80.78.22.206", severity: "critical", confidence: 0.85, family: "NeoShadow RAT", campaign: "NeoShadow", source: "Aikido (single-source)", firstSeen: "2026-01-05" },
  { type: "hash", value: "012dfb89ebabcb8918efb0952f4a91515048fd3b87558e90fa45a7ded6656c07", severity: "critical", confidence: 0.85, family: "NeoShadow RAT", campaign: "NeoShadow", source: "Aikido (single-source)", firstSeen: "2026-01-05" },
  { type: "url", value: "0x13660fd7edc862377e799b0caf68f99a2939b5cc", severity: "critical", confidence: 0.85, family: "NeoShadow RAT", campaign: "NeoShadow Ethereum C2 resolver", source: "Aikido (single-source)", firstSeen: "2026-01-05" },

  // SANDWORM_MODE / "Echoes of Shai-Hulud" npm worm (Socket + OX Security, 2026-02-20).
  // Steals npm tokens and CI secrets, injects malicious MCP servers into Claude Code / Cursor /
  // VS Code for persistence, and stays dormant for 48h after install before detonating. It
  // re-publishes trojanized versions of victims' own packages with stolen tokens, and injects the
  // attacker-owned ci-quality/code-quality-check@v1 Action into victim workflows. All 19 names
  // are npm "security holding package" placeholders, so bare names are safe. Both vendors publish
  // the same package set and the workers[.]dev C2; the two secondary apexes are Socket-only.
  { type: "package", value: "claud-code", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "cloude-code", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "cloude", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "crypto-locale", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "crypto-reader-info", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "detect-cache", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "format-defaults", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "hardhta", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "locale-loader-pro", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "naniod", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "node-native-bridge", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "opencraw", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "parse-compat", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "rimarf", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "scan-store", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "secp256", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "suport-color", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "veim", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "package", value: "yarsg", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "domain", value: "pkg-metrics.official334.workers.dev", severity: "critical", confidence: 0.95, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket, OX Security", firstSeen: "2026-02-20" },
  { type: "domain", value: "freefan.net", severity: "critical", confidence: 0.85, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket (single-source)", firstSeen: "2026-02-20" },
  { type: "domain", value: "fanfree.net", severity: "critical", confidence: 0.85, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket (single-source)", firstSeen: "2026-02-20" },
  { type: "hash", value: "5440e1a424631192dff1162eebc8af5dc2389e3d3b23bd26e9c012279ae116e4", severity: "critical", confidence: 0.85, family: "SANDWORM_MODE worm", campaign: "SANDWORM_MODE", source: "Socket (single-source)", firstSeen: "2026-02-20" },

  // Bare-name entry added when the DEP_INTERNAL_NAME_PUBLIC suffix heuristic was
  // removed (v5.22.0). That heuristic flagged this package for its NAME SHAPE
  // (anything ending in "-service"), which also hit @babel/helper-plugin-utils and
  // @vue/compiler-core at critical - it was never knowledge, just a coincidence
  // that overlapped a real threat. The knowledge belongs here instead.
  // Registry-verified 2026-07-29: the package is ABSENT from npm (pulled), and the
  // only version ever published is the malicious one, so a bare name cannot flag a
  // clean install. Contrast @convera/ui-shared, which stays VERSION-PINNED at
  // 0.0.2/0.0.3 because its 0.0.1 exists and was never called malicious upstream.
  { type: "package", value: "@tc-core/campus-service", severity: "critical", confidence: 0.95, campaign: "Dependency confusion (scoped)", source: "bundled feed (bare-name promotion, registry-verified 2026-07-29)", firstSeen: "2026-07-29" },


  // Alibaba developer toolchain RAT (Socket, July 2026). Hijacked lib-mtop pulled a
  // config-parser dependency chain that writes .cloud-preferences.json and evaluates
  // the rules inside it, yielding a cross-platform RAT on dev machines and CI runners.
  // The package names are already covered by the advisory-database import above.
  // Single-source (Socket) for the atomic indicators, hence confidence 0.85.
  { type: "domain", value: "xemzqli2vu.ai-app.pub", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "domain", value: "diamond-cli-znsxphqell.cn-shanghai.fcapp.run", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "aone-cli-next.oss-cn-beijing.aliyuncs.com/config/setting.js", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "aone-ai-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli.js", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "aone-ai-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli-deps.tar.gz", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "aone-ai-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "aone-ai-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli.zip", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "aone-kit.oss-cn-beijing.aliyuncs.com/plugins/crypto.js", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "aone-kit.oss-cn-beijing.aliyuncs.com/aone-kit-update/aone-kit.js", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "aone-kit.oss-cn-beijing.aliyuncs.com/aone-kit-update/app.asar", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "github.com/smi1e2u/fast-transform-pipeline", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "url", value: "github.com/smi1e2u/smart-config-manager", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "hash", value: "84a6ccaaab1596139d28e822f40cc99c68d337d4c81d1c6d9692c1d6bb22e4af", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "hash", value: "6044974c633b3a319c31bb32110411520c425e89722a64806528553227e7a50a", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "hash", value: "0910ecfa049738ef3f2540855341a380df89224ff71da94b4c21689fd66f62e3", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "hash", value: "b8b81af76163bdcc5b4f7d8fe6795f164991f8a62678c971db031b9e90a27813", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "hash", value: "ef9a1896eeaae929800eade768276e2240ef252d26d0d96c1950a1a5e1aadb34", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "hash", value: "e5d8350f1540fe91145dc262c455bca7748ad97dafb2d9facd5adebed9f66d2d", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "hash", value: "41957bd0ba2d9c07af2e069f10780fdf6b2102c065bebe0db2136dfe07d67a28", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },
  { type: "hash", value: "33b58598eb317553942e27545982d4c25ce6120eae10e42393746eb0e02ecae9", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },

  // Fake Paysafe / Skrill / Neteller payment SDKs (Socket, July 2026). SHA-256 of the
  // malicious entry points behind the 17 typosquats whose names and C2 tunnel are
  // already pinned above: 52 npm index.js and 4 PyPI __init__.py. Hash set is
  // single-source (Socket); gbhackers corroborates the campaign and the C2 host.
  { type: "hash", value: "ce09810adca70ebec87bc455380ef629ceaa2a0d926149d9115604060167682c", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "b2ea8d69f6792a87327ffde2ee4551bb6b99617f53e1ba71bf9a70f45dbc57ea", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "8a70a5c1075f2dea4db94633ddc64b0d03d0385fdeda7c226acc944331febf43", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "c8b4d17c1f0aa7c50f2fa23d7c328482a4ad2c4da4d600f358ebdf200cbefd83", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "9fd06d823d54183cc91625fdc6decffe8db2863f6499a955656ebdcc089792cf", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "615805652b2f006e69512b90d0d63883d7ae1ede69d86384fd77bd46235b2369", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "6dc672e3bab8bcf80c66b2f95150067fb47429d4cf65eb95215e5f3abc7cade5", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "4a4b5c1bc1e948c853cb0978c07c7b8d1540c7b1ded95f8d5ad25c126cb6c7b0", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "9727c804c4354e481d2ff9d4934bd1b2518293a9ca34a14f5c7ae9d0cd30ce94", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "313853a82bce61052c00e6a6af85b5069e007a76122c727f31661bc636b12f14", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "2cbfc4e4b1de5e68ab81fba7e1b0c711b4d26197b48ea4db6819c9cea223b0ed", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "a0313822513f9b89479f666888a4784a3fc99b4cc4566213dcda66b03b47120c", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "3a0dd3479eaf85b65e5abd63d6451f98506faddee47cf4bebd9f91296abb29f0", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "39371ac7061168dd3d890061267b3875bc4b30dca5e28d40dbc27a4396439ff1", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "c51c0b6c7817443b021aff44d4416c09fd039849db81860b9b5144e789fa3987", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "6e251c3d2bde8fff0487c1eecd359c4a544a09fd708755020e4b1c53ad6b8dd1", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "cd7255730b6a7a3895d622d37d0e8f984d2d280689acef56ff195d663e7723ad", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "5c4faef80c83c7ec0925a4aacb4bddabe82b91066ac41305907ba277cd7b3b85", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "50cb7550224d8d227a0625e7f53be86924d8e057e403b6b91b83ea20df834048", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "1bae9f2fb9866422f07345501fa2cb4c3a99f2652c8c9decdc27ffbf9714e7bc", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "1df8c579ffcbf5527b1856bd1774601a5188b380e442c5a0fbd400bd86a4501b", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "b29973eda4d0c090608c15a976688cad0b2114fdc0dcb89ad37515287ba13aad", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "9e9655f54bfac8a937d78ac506722bae1468ead4cc9ee95b35e0f8ef17ee13d9", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "67e4d6a4f53098e48bfa6ecceeaa754592bc249b83404fcfb8542977ae36dac4", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "1bfa32548676d32b7639d3171e2f9feefba5026dc336968c91f4ae2b152c5410", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "2bc8af4bd2f539630f7800f3491b64c7e2bffe12e955d0d4f03a4f6a4b0018bd", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "eae055c5736366811d2a4b1f78ff206486e7f7445040122efbe023ecd2d20bcc", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "d4ed2d87942fbefa5d7b7f19fb6f2e9bc293c96bf577bb97ed3ca56185abcf25", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "447484c76a06918d7f6f6c6f95ee2bced6dd2e9b282c6f5b92b2b7c0976381d5", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "f43cb68850a2506805d60ff466f54eba331e1cc2a513b329f5121e0c39104418", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "1314fc888ca5b3ea91a04e1f5b63039ffc7fc3832b8d809a28ad549c6f9d4f23", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "af66bc2b516d1ef71af9b6ee9f8f5af0a99fed562b34809cd55071b94c2d1304", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "b157a66826d27512c3618817fee924e53d14cabb2c4c7f454affde37350f55f0", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "2303a74a5fac917279f1078e03a4bfd6afbb89462f97d7344ed10e6e9e9e92b7", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "5242c5086d75a492d14e474de7c8f34b18ec0a8a9ce6d77eec8675a9572d9d23", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "1d567795a366b9edcfef7f1fa2d398b7cb41890dd3b2f3f1f9803de0cdba0c89", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "c2e4483abea830ba8b8230540ace51788d0712bed9006697ddddb9cbf133c151", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "390bca9d70efa42cb792f7f677189821a24527cd4298ab2acb954df0abb5c1c3", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "f7d9865ea3874d2b135eeee0aa0d12fc108d89e1dd706e4e40eb7605b76d35ca", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "2b7696575278e6e223cc44553c687e45afd04df7eb32efbf49b39da64b795982", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "2edb3f162f9676196e818d9b795d599ba119a961ffe98c4866351735980d213d", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "727fe9c1dfa39d6590012e0593c9837c628fc2cd22aa0f4e486b7ed1aec02697", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "8a58e3ed713c1c70f421ab56a18cfb6a120c960d227e495b511c2552f25f188b", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "67eb3bd505ebfffbd73fc3ef0b2976c375df732f0bd0496ed6653c3e2be5a0e5", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "616b41657e9afaa9354fc1a106393373dcbf8aac8455b7d2cbbb44463434528e", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "52a57c502e40b3f9897d0ca32bba6f844b4113f5c017627ea9eba660eb47f405", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "d1889d81cfa99d52017732da9dc52127d03893037874c8671943cede4b8d1bb2", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "a677c02e545941e43f8b21a5761b035e911b53e2c065fea219e0f3462f282fd8", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "e076e13a7e112d364f03bd1ead7abaa83249d544491621254860ab0a73adc9b9", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "c2a69a33b086364ca51b030b6b15e99be46ce8255ddf62839a4fc7f2b34023de", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "5cd62e708ae4393c99579ec1433571998299bf7e2fde9bafeb9a79f8bdf065e9", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "61b61dd25cd8dcc43cd78418f3e3eb3fd9002d9e49961eefb12c1022ce4c3b63", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "c6af37a6739f0d919ab7049caf3a85831cab44bdbea27e0d9de7adec80334e2b", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "b04daeacd1d1c9020cce2a97fa7af83dbedf4e6d17dd12c0f337f32240399785", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "dabb47d75f2efa6a5540661484efa989ccb338f24938b23152f14f3e424b0cb5", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },
  { type: "hash", value: "c2a361a7d8feb95be97c957fc7652d348f4fa9a987bde5f09883f46b65c460f1", severity: "critical", confidence: 0.85, family: "FakePaymentSDK", campaign: "Fake Payment SDK Typosquat", source: "Socket", firstSeen: "2026-07-07" },

  // AsyncAPI npm compromise (Unit 42, July 2026). Two further campaign artifacts
  // beyond the five registry tarballs already pinned above. Single-source (Unit 42).
  { type: "hash", value: "73b44b8724d31f80859018c988e9b033155c5fd8225205a914eda1a11b78a841", severity: "critical", confidence: 0.85, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", source: "Unit 42", firstSeen: "2026-07-14" },
  { type: "hash", value: "f7367ce5509f536a406deecdbb577c60e8585cb2ab77058a86bde6188a609cfd", severity: "critical", confidence: 0.85, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", source: "Unit 42", firstSeen: "2026-07-14" },

];

const FEED_CHUNK_2: FeedIOC[] = [
  // Imported from GitHub Advisory Database (2026-07-17) - see docs/threat-feed-sources.md
  { type: "hash", value: "bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0", severity: "critical", confidence: 0.85, family: "Rust Infostealer", campaign: "jscrambler npm compromise", source: "Socket", firstSeen: "2026-07-11" },


  // Joyfill npm compromise / DEV#POPPER, PolinRider family (Socket + StepSecurity, July 28 2026)
  // Malicious 2773 beta releases of two LEGITIMATE @joyfill packages carry a five-stage chain:
  // in-bundle obfuscated loader -> blockchain C2 resolver (Tron/Aptos/BSC) -> two staged
  // downloaders -> Socket.IO RAT with worm-like self-propagation + staged Python credential
  // stealer. The loader runs at import time, so --ignore-scripts does not prevent execution.
  // Version-pinned, never bare names: both packages are legitimate and still maintained.
  // The advisory databases published only beta.4 and beta.0; these are the remaining four.
  { type: "package", value: "@joyfill/components@4.0.0-rc24-2773-beta.5", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "package", value: "@joyfill/components@4.0.0-rc24-2773-beta.6", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "package", value: "@joyfill/layouts@0.1.2-2773.beta.1", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "package", value: "@joyfill/layouts@0.1.2-2773.beta.2", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  // Stage-3/4 C2 hosts. The blockchain RPC endpoints and ip-api[.]com are shared public
  // infrastructure and are deliberately absent - see the note in ioc-blocklist.ts.
  { type: "ip", value: "166.88.134.62", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "ip", value: "23.27.13.43", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "ip", value: "198.105.127.210", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "ip", value: "23.27.202.27", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "adc4af90540d33cd1e98f44b51482ae9250fbeb97d6f8d7841c81b618cb2c6e6", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "8e8b90dedd456ded0c5748119836e1ca1066112bc569c1b41ca70eb931d1d4dc", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "5f6a92006ca2ea4b464d66fb41af777edce7296939a7c6ee491e2b3cbfe09848", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "bcc93dc55bc7daedf4ca57254f0e7a7f1c40e09851eab98fe10cde801982db17", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "1352ad22c99983d91e600348b7cbf58235131b1ee34cea9f09623206d5b7dea7", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "67c6ef602cc850f10d935fee53fa40440df841adf081563bf4fc2631a71249ce", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "c5742ea1875ecd2360022624149994909cd0546e221e4203dffd01f48de45469", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "cb46f12d70824ea24ed1f8bcf45bf3f86680e02a9089aafc03b27f691be57be3", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "f452f9cfa539f4a1fe25187a99a484391290d5dbaa422ba455edf6b04f81b7d1", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "78f0de8682e0e894a5784eb7e95db4da6088f528918ca3107dd1e76f80a561d8", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "ae7565109fd01b88d82acf7f73ab20709cbc2c9f26fdea13e429ccc87a55d4fb", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "26e679eaf1e9baeb7c55eb48db482301171d4d26e1728544b23734a90dc70e1b", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },
  { type: "hash", value: "2cfede38fb121a71a2f3607474aa8cd588a99f51b37e5e6f0d8cb789fa275032", severity: "critical", confidence: 1.0, family: "PolinRider", campaign: "Joyfill npm Compromise", firstSeen: "2026-07-28" },

  // PointBlank RAT (Xygeni, July 21-31 2026). Windows RAT on PyPI; every version is
  // malicious and the name has no legitimate history, so a bare name. C2 is a JSON bin on
  // npoint[.]io, a legitimate free service that is deliberately NOT ingested, and no bin id
  // was published. Confidence 0.85: single-source (Xygeni, two posts, one vendor).
  // pypi: prefix is load-bearing. A bare value is the npm namespace, so an unprefixed
  // entry here would miss poetry.lock/uv.lock/Pipfile.lock (the actual threat) and fire
  // on an npm dependency of the same name instead.
  { type: "package", value: "pypi:gcli-control", severity: "critical", confidence: 0.85, family: "PointBlank", campaign: "PointBlank PyPI RAT", firstSeen: "2026-07-21" },


  // Fake Corepack install site: infostealer + proxyware aimed at developers (July 2026).
  // Impersonation site for a tool that has no official website; download button chains
  // through malvertising into a fake VPN installer.
  { type: "domain", value: "corepack.org", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket, Gurucul, iTnews", firstSeen: "2026-07-24" },
  { type: "domain", value: "moonlighthathel.org", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket, Gurucul", firstSeen: "2026-07-24" },
  { type: "domain", value: "aifpleasurebeh.org", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket, Gurucul", firstSeen: "2026-07-24" },
  { type: "domain", value: "ghabovethec.info", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket, Gurucul", firstSeen: "2026-07-24" },
  { type: "domain", value: "ukankingwithea.com", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket, Gurucul", firstSeen: "2026-07-24" },
  { type: "domain", value: "beadpie.xyz", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket, Gurucul", firstSeen: "2026-07-24" },
  { type: "domain", value: "yakteam.xyz", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket, Gurucul", firstSeen: "2026-07-24" },
  { type: "domain", value: "openshield.canatrace.com", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket, Gurucul", firstSeen: "2026-07-24" },
  { type: "domain", value: "nostop.go2cloud.org", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket, Gurucul", firstSeen: "2026-07-24" },
  { type: "url", value: "freevpn.win/lps/gbox-lp/index.html", severity: "critical", confidence: 1.0, campaign: "Fake Corepack Site", source: "Socket", firstSeen: "2026-07-24" },

];

const FEED_CHUNK_3: FeedIOC[] = [
];

const FEED_CHUNK_4: FeedIOC[] = [
];

const FEED_CHUNK_5: FeedIOC[] = [

];

const FEED_CHUNK_6: FeedIOC[] = [




  // mrmustard PyPI compromise (StepSecurity + safedep, July 2026). Two independent
  // vendors, so full confidence. The breached maintainer account is deliberately absent:
  // that account is a victim, not an indicator.
  { type: "domain", value: "metrics.femboy.energy", severity: "critical", confidence: 1.0, campaign: "mrmustard PyPI Compromise", source: "StepSecurity, safedep", firstSeen: "2026-07-24" },
  { type: "url", value: "webhook.site/710babde-6ace-47fe-83f4-9688e6548df9", severity: "critical", confidence: 1.0, campaign: "mrmustard PyPI Compromise", source: "StepSecurity, safedep", firstSeen: "2026-07-24" },
  { type: "hash", value: "0404f8590fdaef95280c1d908068f31bf2321fe887faabf0c2329ba67c7203cb", severity: "critical", confidence: 1.0, campaign: "mrmustard PyPI Compromise", source: "safedep", firstSeen: "2026-07-24" },
  { type: "hash", value: "81f0d1291a975d012d1b892cf9967557fdbb1ad4e1ac0545702ad235ace1cac5", severity: "critical", confidence: 1.0, campaign: "mrmustard PyPI Compromise", source: "safedep", firstSeen: "2026-07-24" },

  // Alibaba developer toolchain RAT (Socket, July 2026). The native second-stage binary
  // staged next to aone-kit.js and app.asar; the other eight bucket paths shipped earlier.
  { type: "url", value: "aone-kit.oss-cn-beijing.aliyuncs.com/aone-kit-update/aone-kit-update", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-07-29" },



  // ChainDrop npm worm / "Mini Shai-Hulud" (StepSecurity + Aikido + Socket + Endor Labs,
  // August 4 2026). Four independent vendors published an identical hash set, so full
  // confidence throughout. Every package is a legitimate project whose publisher account
  // was taken over, so each is pinned to the single hijacked version - the compromised
  // publisher accounts themselves are victims and are deliberately not indicators. The
  // dead-drop is an Ethereum contract rather than a URL, so it lives in KNOWN_C2_WALLETS;
  // the feed has no wallet type, matching how the Joyfill resolver contract is handled.
  { type: "domain", value: "npm-cache.com", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "StepSecurity, Aikido, Socket", firstSeen: "2026-08-04" },
  { type: "hash", value: "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "StepSecurity, Aikido, Socket, Endor Labs", firstSeen: "2026-08-04" },
  { type: "hash", value: "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "StepSecurity, Aikido, Socket, Endor Labs", firstSeen: "2026-08-04" },
  { type: "hash", value: "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "StepSecurity, Aikido, Socket, Endor Labs", firstSeen: "2026-08-04" },
  { type: "package", value: "keyv@6.0.0", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "StepSecurity, Aikido, Socket, Endor Labs", firstSeen: "2026-08-04" },
  { type: "package", value: "@keyv/redis@6.0.0", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Socket", firstSeen: "2026-08-04" },
  { type: "package", value: "@keyv/sqlite@6.0.0", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Socket", firstSeen: "2026-08-04" },
  { type: "package", value: "@keyv/mongo@6.0.0", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Socket", firstSeen: "2026-08-04" },
  { type: "package", value: "cacheable@2.5.1", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Aikido, Socket, Endor Labs", firstSeen: "2026-08-04" },
  { type: "package", value: "cacheable-request@13.0.20", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "StepSecurity, Aikido, Socket", firstSeen: "2026-08-04" },
  { type: "package", value: "cache-manager@7.2.10", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "StepSecurity, Aikido, Socket, Endor Labs", firstSeen: "2026-08-04" },
  { type: "package", value: "@cacheable/memory@2.2.1", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Aikido, Socket", firstSeen: "2026-08-04" },
  { type: "package", value: "@cacheable/node-cache@3.1.2", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Aikido, Socket", firstSeen: "2026-08-04" },
  { type: "package", value: "@cacheable/utils@2.5.1", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Aikido, Socket", firstSeen: "2026-08-04" },
  { type: "package", value: "@cacheable/net@2.1.1", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Aikido, Socket", firstSeen: "2026-08-04" },
  { type: "package", value: "flat-cache@6.1.24", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "StepSecurity, Aikido, Socket, Endor Labs", firstSeen: "2026-08-04" },
  { type: "package", value: "file-entry-cache@11.1.6", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "StepSecurity, Aikido, Endor Labs", firstSeen: "2026-08-04" },
  { type: "package", value: "ecto@5.0.1", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Aikido", firstSeen: "2026-08-04" },
  { type: "package", value: "@thiennq/docs-viewer@1.6.2", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Socket", firstSeen: "2026-08-04" },
  { type: "package", value: "@deliveroo/reevent@1.0.1", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Aikido", firstSeen: "2026-08-04" },
  { type: "package", value: "@or-sdk/invitations@1.4.9", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Aikido", firstSeen: "2026-08-04" },
  { type: "package", value: "@picsart/ai-sdk@3.32.2", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Aikido", firstSeen: "2026-08-04" },



  // Alibaba developer toolchain RAT (Socket, August 2026) - hand-added, no advisory exists
  // so the importer cannot reach it. The other 17 packages of this campaign are already
  // bare-name entries above; this one was only tracked as the GitHub dead-drop repo
  // github.com/smi1e2u/fast-transform-pipeline, while the npm package of the same name was
  // published in the same campaign and had no IOC at all. Bare name, no version pin: the
  // source publishes no versions and the name has no legitimate history.
  // Single-source (Socket; The Hacker News reports the same research), hence confidence 0.85.
  { type: "package", value: "fast-transform-pipeline", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Socket", firstSeen: "2026-08-03" },

  // ChainDrop npm worm (Snyk, August 2026) - SHA-256 of the poisoned keyv-6.0.0.tgz tarball.
  // Single-source, hence confidence 0.85. See KNOWN_MALICIOUS_HASHES for why a distribution
  // artefact hash is kept alongside the existing keyv@6.0.0 version pin.
  { type: "hash", value: "d584f9b6af48b7ed1f93713944f033783bf149e1c25e1643eb8c0e9df5dc7782", severity: "critical", confidence: 0.85, campaign: "ChainDrop npm Worm", source: "Snyk", firstSeen: "2026-08-04" },

];

const FEED_CHUNK_7: FeedIOC[] = [
];

const FEED_CHUNK_8: FeedIOC[] = [
];

const FEED_CHUNK_9: FeedIOC[] = [



];

const FEED_CHUNK_10: FeedIOC[] = [

  // GlassWASM - trojanized Open VSX extensions carrying a TinyGo WebAssembly stager
  // (Socket 2026-06-15, corroborated by Corgea). Two impersonation clones of verified VS
  // Code Marketplace extensions were republished on Open VSX by a single throwaway
  // account. The WASM blob ChaCha20-decrypts the host below and pulls a platform-specific
  // stage 2, while its command channel is a Solana dead-drop: it polls mainnet for
  // transactions to an attacker wallet and reads the SPL Memo field. The wallet lives in
  // KNOWN_C2_WALLETS because the feed has no wallet type, matching how the ChainDrop and
  // Joyfill resolver contracts are handled. The extensions themselves are NOT added as
  // package IOCs - a bare value in this feed means the npm namespace, and these are Open
  // VSX identifiers, so they would be routed to the wrong ecosystem; the two VSIX hashes
  // carry that identity instead. Hashes are single-source (Socket); everything else is
  // two-source, hence the lower confidence on the hashes only.
  //
  // Deliberately NOT bounded by the importer's --days advisory window. That window scopes
  // what the importer INGESTS; it says nothing about what the engine must keep detecting.
  // A campaign is not over because its write-up is old, so validated indicators stay in
  // the feed for good. Retention cost is an importer/runtime concern tracked separately.
  { type: "domain", value: "dodod.lat", severity: "critical", confidence: 1.0, campaign: "GlassWASM", source: "Socket, Corgea", firstSeen: "2026-06-15" },
  { type: "url", value: "dodod.lat/darwin/i/_", severity: "critical", confidence: 1.0, campaign: "GlassWASM", source: "Socket", firstSeen: "2026-06-15" },
  { type: "url", value: "dodod.lat/linux/i/_", severity: "critical", confidence: 1.0, campaign: "GlassWASM", source: "Socket", firstSeen: "2026-06-15" },
  { type: "url", value: "dodod.lat/win32/i/_", severity: "critical", confidence: 1.0, campaign: "GlassWASM", source: "Socket", firstSeen: "2026-06-15" },
  { type: "hash", value: "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f", severity: "critical", confidence: 0.85, campaign: "GlassWASM", source: "Socket (single-source)", firstSeen: "2026-06-15" },
  { type: "hash", value: "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58", severity: "critical", confidence: 0.85, campaign: "GlassWASM", source: "Socket (single-source)", firstSeen: "2026-06-15" },
  { type: "hash", value: "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25", severity: "critical", confidence: 0.85, campaign: "GlassWASM", source: "Socket (single-source)", firstSeen: "2026-06-15" },


  // ChainDrop npm worm / "Mini Shai-Hulud" - second indicator wave (Microsoft +
  // Datadog, August 2026). The sibling C2 routers resolved from the same
  // Ethereum contract already carried by KNOWN_C2_WALLETS, four further payload
  // hashes from the later re-obfuscation waves, and the fixed marker names of
  // the GitHub repositories the worm creates under each victim account to
  // exfiltrate. The public Ethereum RPC endpoints the resolver calls
  // (eth-mainnet.nodereal[.]io, go.getblock[.]io, eth.llamarpc[.]com) are
  // deliberately absent: shared legitimate infrastructure, see ioc-blocklist.ts.
  { type: "domain", value: "pypi-get.com", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Microsoft, Datadog", firstSeen: "2026-08-04" },
  { type: "domain", value: "js-mirror.com", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Microsoft, Datadog", firstSeen: "2026-08-04" },
  { type: "domain", value: "awqhnjewqjkl.icu", severity: "critical", confidence: 0.85, campaign: "ChainDrop npm Worm", source: "Datadog", firstSeen: "2026-08-04" },
  { type: "hash", value: "927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Datadog, Socket", firstSeen: "2026-08-04" },
  { type: "hash", value: "14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Datadog", firstSeen: "2026-08-04" },
  { type: "hash", value: "3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Datadog, SlowMist", firstSeen: "2026-08-04" },
  { type: "hash", value: "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7", severity: "critical", confidence: 1.0, campaign: "ChainDrop npm Worm", source: "Datadog, Aikido, Snyk", firstSeen: "2026-08-04" },
  // The two exfiltration-repo marker names ("thebeautifulmarchoftime" and
  // "thebeautifulsnadsoftime") are NOT in this feed. They are bare repository
  // names, not URLs, and IOC_VALUE_SHAPES.url rejects them - correctly, since
  // the feed's url shape is what keeps a remote feed from injecting arbitrary
  // strings. They live in KNOWN_DEAD_DROPS instead, which is substring-matched
  // and has no shape constraint, so detection is unaffected.

  // Alibaba developer toolchain RAT - Corgea's follow-up to Socket's write-up
  // (August 2026). The live raw config path the dependency chain fetches, and a
  // nineteenth staging package neither the advisory databases nor Socket listed.
  // Both single-source; the owning GitHub account is already confirmed
  // attacker-created by Socket. Version-pinned, see ioc-blocklist.ts.
  { type: "url", value: "raw.githubusercontent.com/smi1e2u/smart-config-manager/main/defaults/preferences.json", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Corgea", firstSeen: "2026-08-03" },
  { type: "package", value: "node-data-utils@1.0.1", severity: "critical", confidence: 0.85, family: "AlibabaDevRAT", campaign: "Alibaba Dev Toolchain RAT", source: "Corgea", firstSeen: "2026-08-03" },


  // Flooding Dropper / WEL1DROPPER npm slopsquatting campaign (August 7 2026). The package
  // names arrive through the advisory databases; these are the delivery hosts and payload
  // hashes, which they never publish. The three oob-worker hosts are reported by both
  // OpenSourceMalware and The Hacker News; the package-proxy hosts and the two binary
  // hashes are single-source (OpenSourceMalware), hence 0.85.
  { type: "domain", value: "oob-worker.cf103-070.workers.dev", severity: "critical", confidence: 1.0, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware, The Hacker News", firstSeen: "2026-08-07" },
  { type: "domain", value: "oob-worker.cf102-baf.workers.dev", severity: "critical", confidence: 1.0, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware, The Hacker News", firstSeen: "2026-08-07" },
  { type: "domain", value: "oob-worker.cf99-9b3.workers.dev", severity: "critical", confidence: 1.0, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware, The Hacker News", firstSeen: "2026-08-07" },
  { type: "domain", value: "package-proxy.cf5oobworker.workers.dev", severity: "critical", confidence: 0.85, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware", firstSeen: "2026-08-07" },
  { type: "domain", value: "package-proxy.cf6oobworker.workers.dev", severity: "critical", confidence: 0.85, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware", firstSeen: "2026-08-07" },
  { type: "domain", value: "package-proxy.cf7oobworker.workers.dev", severity: "critical", confidence: 0.85, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware", firstSeen: "2026-08-07" },
  { type: "domain", value: "package-proxy.cf8oobworker.workers.dev", severity: "critical", confidence: 0.85, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware", firstSeen: "2026-08-07" },
  { type: "domain", value: "package-proxy.cf11oobworker.workers.dev", severity: "critical", confidence: 0.85, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware", firstSeen: "2026-08-07" },
  { type: "domain", value: "dl.wel1.ru", severity: "critical", confidence: 1.0, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware, The Hacker News", firstSeen: "2026-08-07" },
  { type: "hash", value: "7e486657f30594afda379b97030252a09a19fe8055e25c9e371544f59bd8e9e3", severity: "critical", confidence: 0.85, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware", firstSeen: "2026-08-07" },
  { type: "hash", value: "c214746c74cae8ece8bdaf69aa05da4db6ce013f9e77452d1eed1a002fd9ba00", severity: "critical", confidence: 0.85, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "OpenSourceMalware", firstSeen: "2026-08-07" },

  // axios maintainer account takeover - UNC1069 / "Sapphire Sleet" (March 31 2026).
  // The axios and plain-crypto-js versions were already pinned in v5.x; this is the
  // C2 and the per-platform implants the advisory databases never published.
  { type: "domain", value: "sfrclak.com", severity: "critical", confidence: 0.95, family: "UNC1069 RAT", campaign: "axios hijack", source: "Aikido, LevelBlue", firstSeen: "2026-03-31" },
  { type: "ip", value: "142.11.206.73", severity: "critical", confidence: 0.95, family: "UNC1069 RAT", campaign: "axios hijack", source: "Aikido, LevelBlue", firstSeen: "2026-03-31" },
  { type: "hash", value: "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a", severity: "critical", confidence: 0.95, family: "UNC1069 RAT", campaign: "axios hijack", source: "Aikido, LevelBlue", firstSeen: "2026-03-31" },
  { type: "hash", value: "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101", severity: "critical", confidence: 0.95, family: "UNC1069 RAT", campaign: "axios hijack", source: "Aikido, LevelBlue", firstSeen: "2026-03-31" },
  { type: "hash", value: "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf", severity: "critical", confidence: 0.95, family: "UNC1069 RAT", campaign: "axios hijack", source: "Aikido, LevelBlue", firstSeen: "2026-03-31" },

  // spellcheckpy / spellcheckerpy PyPI RAT (January 20-21 2026). Backfill of a campaign
  // that was never ingested. Every published version is malicious, so the packages are
  // listed by bare name. Single-source (Aikido), hence 0.85. The "pypi:" prefix is
  // load-bearing - without it these would be read as npm names.
  { type: "package", value: "pypi:spellcheckpy", severity: "critical", confidence: 0.85, family: "Python RAT", campaign: "updatenet", source: "Aikido", firstSeen: "2026-01-20" },
  { type: "package", value: "pypi:spellcheckerpy", severity: "critical", confidence: 0.85, family: "Python RAT", campaign: "updatenet", source: "Aikido", firstSeen: "2026-01-20" },
  { type: "domain", value: "updatenet.work", severity: "critical", confidence: 0.85, family: "Python RAT", campaign: "updatenet", source: "Aikido", firstSeen: "2026-01-20" },
  { type: "ip", value: "172.86.73.139", severity: "critical", confidence: 0.85, family: "Python RAT", campaign: "updatenet", source: "Aikido", firstSeen: "2026-01-20" },


  // TeamPCP telnyx wave + March 2026 npm wave (see src/ioc-blocklist.ts for the
  // full rationale and for the shared hosts deliberately left out).
  { type: "domain", value: "aquasecurtiy.org", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Datadog, Hexastrike", firstSeen: "2026-03-27" },
  { type: "domain", value: "scan.aquasecurtiy.org", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Datadog, Hexastrike", firstSeen: "2026-03-27" },
  { type: "domain", value: "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Datadog, Hexastrike", firstSeen: "2026-03-27" },
  { type: "domain", value: "championships-peoples-point-cassette.trycloudflare.com", severity: "critical", confidence: 0.85, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Datadog", firstSeen: "2026-03-27" },
  { type: "domain", value: "investigation-launches-hearings-copying.trycloudflare.com", severity: "critical", confidence: 0.85, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Datadog", firstSeen: "2026-03-27" },
  { type: "domain", value: "souls-entire-defined-routes.trycloudflare.com", severity: "critical", confidence: 0.85, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Datadog", firstSeen: "2026-03-27" },
  { type: "ip", value: "83.142.209.203", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Datadog, Hexastrike", firstSeen: "2026-03-27" },
  { type: "ip", value: "83.142.209.11", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Datadog, Hexastrike", firstSeen: "2026-03-27" },
  { type: "url", value: "83.142.209.203:8080/ringtone.wav", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Endor Labs, Hexastrike", firstSeen: "2026-03-27" },
  { type: "url", value: "83.142.209.203:8080/hangup.wav", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Endor Labs, Hexastrike", firstSeen: "2026-03-27" },
  { type: "hash", value: "7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Endor Labs, Hexastrike", firstSeen: "2026-03-27" },
  { type: "hash", value: "cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Endor Labs, Hexastrike", firstSeen: "2026-03-27" },
  { type: "hash", value: "23b1ec58649170650110ecad96e5a9490d98146e105226a16d898fbe108139e5", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Endor Labs, Hexastrike", firstSeen: "2026-03-27" },
  { type: "hash", value: "ab4c4aebb52027bf3d2f6b2dcef593a1a2cff415774ea4711f7d6e0aa1451d4e", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Endor Labs, Hexastrike", firstSeen: "2026-03-27" },
  { type: "package", value: "pypi:telnyx@4.87.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Endor Labs, JFrog, OX Security", firstSeen: "2026-03-27" },
  { type: "package", value: "pypi:telnyx@4.87.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP telnyx", source: "Endor Labs, JFrog, OX Security", firstSeen: "2026-03-27" },
  { type: "package", value: "@airtm/uuid-base32@1.0.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-86xp-4fvm-qm2p, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/account-sdk@1.41.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-79wc-g29x-jj3q, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/account-sdk@1.41.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-79wc-g29x-jj3q, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/account-sdk-node@1.40.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-2phg-9x97-9759, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/account-sdk-node@1.40.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-2phg-9x97-9759, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/accounting-sdk@1.27.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-cjxf-3qww-qv9w, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/accounting-sdk@1.27.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-cjxf-3qww-qv9w, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/accounting-sdk@1.27.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-cjxf-3qww-qv9w, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/accounting-sdk-node@1.26.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-qx4v-wwj4-8xmh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/accounting-sdk-node@1.26.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-qx4v-wwj4-8xmh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/api-documentation@1.19.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-wq88-f86r-hgrh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/api-documentation@1.19.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-wq88-f86r-hgrh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/auth-sdk@1.25.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-gj2w-92fr-m7c2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/auth-sdk@1.25.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-gj2w-92fr-m7c2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/auth-sdk-node@1.21.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-8328-7r2v-2fq6, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/auth-sdk-node@1.21.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-8328-7r2v-2fq6, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/billing-sdk@1.56.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-m26r-hvqm-73ff, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/billing-sdk@1.56.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-m26r-hvqm-73ff, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/billing-sdk-node@1.57.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-mw23-j5r9-c8vj, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/billing-sdk-node@1.57.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-mw23-j5r9-c8vj, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/changelog-sdk-node@1.0.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-wcrr-xhm3-j3x9, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/changelog-sdk-node@1.0.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-wcrr-xhm3-j3x9, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/claim-sdk@1.41.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-mjwm-77q5-mrxr, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/claim-sdk@1.41.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-mjwm-77q5-mrxr, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/claim-sdk-node@1.39.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-38x3-f5vr-mvpw, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/claim-sdk-node@1.39.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-38x3-f5vr-mvpw, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/commission-sdk-node@1.0.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-cmfv-mmcw-jpw3, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/commission-sdk-node@1.0.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-cmfv-mmcw-jpw3, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/commission-sdk-node@1.0.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-cmfv-mmcw-jpw3, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/customer-sdk@1.54.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-rgf4-gx75-xrv2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/customer-sdk@1.54.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-rgf4-gx75-xrv2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/customer-sdk@1.54.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-rgf4-gx75-xrv2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/customer-sdk@1.54.4", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-rgf4-gx75-xrv2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/customer-sdk@1.54.5", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-rgf4-gx75-xrv2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/customer-sdk-node@1.55.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-jfwq-4fm4-wwpw, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/customer-sdk-node@1.55.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-jfwq-4fm4-wwpw, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/discount-sdk@1.5.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-3fjh-jjvh-r58h, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/discount-sdk@1.5.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-3fjh-jjvh-r58h, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-sdk@1.45.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-74q8-chvf-xjp2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-sdk@1.45.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-74q8-chvf-xjp2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-sdk-node@1.43.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-5q3v-cjxm-6cgm, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-sdk-node@1.43.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-5q3v-cjxm-6cgm, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-sdk-node@1.43.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-5q3v-cjxm-6cgm, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-sdk-node@1.43.4", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-5q3v-cjxm-6cgm, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-sdk-node@1.43.5", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-5q3v-cjxm-6cgm, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-sdk-node@1.43.6", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-5q3v-cjxm-6cgm, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-uploader@0.0.11", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-jrpm-f5xg-3frj, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/document-uploader@0.0.12", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-jrpm-f5xg-3frj, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/docxtemplater-util@1.1.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-f9m8-w27f-mxr3, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/docxtemplater-util@1.1.4", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-f9m8-w27f-mxr3, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/gdv-sdk@2.6.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-8vmq-w85q-4q4j, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/gdv-sdk@2.6.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-8vmq-w85q-4q4j, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/gdv-sdk-node@2.6.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-gqwm-qw26-8g59, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/gdv-sdk-node@2.6.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-gqwm-qw26-8g59, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/gdv-sdk-node@2.6.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-gqwm-qw26-8g59, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/insurance-sdk@1.97.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-c9rj-gq4m-f5wq, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/insurance-sdk@1.97.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-c9rj-gq4m-f5wq, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/insurance-sdk@1.97.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-c9rj-gq4m-f5wq, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/insurance-sdk@1.97.4", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-c9rj-gq4m-f5wq, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/insurance-sdk@1.97.5", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-c9rj-gq4m-f5wq, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/insurance-sdk@1.97.6", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-c9rj-gq4m-f5wq, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/insurance-sdk-node@1.95.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-h5jq-7px8-v446, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/insurance-sdk-node@1.95.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-h5jq-7px8-v446, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/notification-sdk-node@1.4.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-9538-fpmw-hjpr, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/notification-sdk-node@1.4.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-9538-fpmw-hjpr, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/partner-portal-sdk@1.1.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-hpqp-f9r8-f725, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/partner-portal-sdk@1.1.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-hpqp-f9r8-f725, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/partner-portal-sdk@1.1.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-hpqp-f9r8-f725, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/partner-portal-sdk-node@1.1.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-cxm8-rrjm-28jf, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/partner-portal-sdk-node@1.1.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-cxm8-rrjm-28jf, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/partner-sdk-node@1.19.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-39vv-2g62-pp83, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/partner-sdk-node@1.19.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-39vv-2g62-pp83, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/payment-sdk@1.15.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-96qx-5379-wp39, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/payment-sdk@1.15.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-96qx-5379-wp39, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/payment-sdk-node@1.23.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-4r42-c7jf-m8rf, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/payment-sdk-node@1.23.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-4r42-c7jf-m8rf, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/public-api-sdk@1.33.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-qf6c-xv4h-gxw5, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/public-api-sdk@1.33.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-qf6c-xv4h-gxw5, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/public-api-sdk-node@1.35.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-mvrx-3fqg-4hvh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/public-api-sdk-node@1.35.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-mvrx-3fqg-4hvh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/setting-sdk-node@0.2.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-h7pp-f3cj-j5vh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/setting-sdk-node@0.2.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-h7pp-f3cj-j5vh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/setting-sdk-node@0.2.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-h7pp-f3cj-j5vh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/task-sdk@1.0.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-f568-m9rh-p7xj, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/task-sdk@1.0.4", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-f568-m9rh-p7xj, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/task-sdk-node@1.0.4", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-r27q-f5jw-j5jp, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/tenant-sdk@1.34.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-6w74-x38v-9ffj, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/tenant-sdk@1.34.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-6w74-x38v-9ffj, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/tenant-sdk-node@1.33.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-gmxq-2g92-63xv, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@emilgroup/tenant-sdk-node@1.33.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-gmxq-2g92-63xv, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@leafnoise/mirage@2.0.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-24fv-r862-wg4c, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@opengov/form-builder@0.12.3", severity: "critical", confidence: 0.85, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "Datadog", firstSeen: "2026-03-22" },
  { type: "package", value: "@opengov/form-renderer@0.2.20", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-j3x7-94xp-wf43, Datadog", firstSeen: "2026-04-07" },
  { type: "package", value: "@opengov/form-utils@0.7.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-q4j2-j63f-5vqx, Datadog", firstSeen: "2026-03-22" },
  { type: "package", value: "@opengov/ppf-backend-types@1.141.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-4xcw-mhqm-x332, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@opengov/ppf-eslint-config@0.1.11", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-gc99-m8qp-xm33, Datadog", firstSeen: "2026-03-22" },
  { type: "package", value: "@opengov/qa-record-types-api@1.0.3", severity: "critical", confidence: 0.85, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "Datadog", firstSeen: "2026-03-22" },
  { type: "package", value: "@pypestream/floating-ui-dom@2.15.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-5h9j-3cr5-f9xj, Datadog", firstSeen: "2026-03-22" },
  { type: "package", value: "@teale.io/eslint-config@1.8.9", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-7h5g-m989-54j2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@teale.io/eslint-config@1.8.10", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-7h5g-m989-54j2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@teale.io/eslint-config@1.8.11", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-7h5g-m989-54j2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@teale.io/eslint-config@1.8.12", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-7h5g-m989-54j2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@teale.io/eslint-config@1.8.13", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-7h5g-m989-54j2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@teale.io/eslint-config@1.8.14", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-7h5g-m989-54j2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@teale.io/eslint-config@1.8.15", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-7h5g-m989-54j2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@teale.io/eslint-config@1.8.16", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-7h5g-m989-54j2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "@virtahealth/substrate-root@1.0.1", severity: "critical", confidence: 0.85, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "Datadog", firstSeen: "2026-03-22" },
  { type: "package", value: "babel-plugin-react-pure-component@0.1.6", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-f9q8-fcvg-876p, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "cit-playwright-tests@1.0.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-64p5-3wp7-v4c9, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "eslint-config-ppf@0.128.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-29gm-cwfm-376h, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "eslint-config-service-users@0.0.3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-9h8j-g652-xrg8, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "jest-preset-ppf@0.0.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-8999-rqc4-rjrh, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "opengov-k6-core@1.0.2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-h38m-4w8q-55j2, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "react-autolink-text@2.0.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "react-leaflet-cluster-layer@0.0.4", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-jrfv-73x8-f24x, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "react-leaflet-heatmap-layer@2.0.1", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "GHSA-v4gc-5jfp-x5rj, Datadog, npm registry", firstSeen: "2026-03-22" },
  { type: "package", value: "react-leaflet-marker-layer@0.1.5", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP npm wave", source: "Datadog, npm registry", firstSeen: "2026-03-22" },

];

const FEED_CHUNK_11: FeedIOC[] = [

  // Mini Shai-Hulud / Miasma "Hades" PyPI wave (Socket, corroborated by Endor Labs,
  // O3 Security and Snyk, June 8, 2026). The PyPI branch of the Miasma family: stolen
  // maintainer tokens published one trojanized release per project, using a .pth
  // site-packages hook so the Bun-based credential stealer runs on every Python start.
  // Ten of these are legitimate academic genomics / graph-ML / MCP libraries where only
  // this single release is bad, so the pins are exact. Every version was confirmed gone
  // from the PyPI releases map before ingestion. The pypi: prefix is load-bearing here:
  // a bare value would denote the npm namespace and route these to the wrong resolver.
  { type: "package", value: "pypi:dreamgen@1.8.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:embiggen@0.11.97", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, Endor Labs", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:ensmallen@0.8.101", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, Endor Labs", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:gpsea@0.9.14", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, Endor Labs", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:mem8@6.0.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:mflux-streamlit@0.0.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:mflux-streamlit@0.0.4", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:phenopacket-store-toolkit@0.1.7", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, Endor Labs", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:ppkt2synergy@0.1.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, Endor Labs, Snyk", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:pyphetools@0.9.120", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, Endor Labs", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:ray-mcp-server@0.2.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:instructor-mcp@1.15.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:instructor-mcp@1.15.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:langchain-core-mcp@1.4.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:langchain-core-mcp@1.4.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:openai-mcp@2.41.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:openai-mcp@2.41.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:orchestr8-platform@3.3.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:rlask@3.1.7", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:rsquests@2.34.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:tiktoken-mcp@0.13.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:tiktoken-mcp@0.13.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "package", value: "pypi:tlask@3.1.4", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "hash", value: "6d332f814f15f19758d65026bbfd0a8c49671b319ec77b8fa1b27fc48afff7d9", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },
  { type: "hash", value: "6506d31707a39949f89534bf9705bcf889f1ecae3dbc6f4ff88d67a8be3d01b2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket", firstSeen: "2026-06-08" },

  // Flooding Dropper TXT-record control channel, sibling label to the dl[.] download
  // hosts already tracked in this feed. Single-source (The Hacker News), hence 0.85.
  { type: "domain", value: "c.wel1.ru", severity: "critical", confidence: 0.85, family: "WEL1DROPPER", campaign: "Flooding Dropper", source: "The Hacker News", firstSeen: "2026-08-07" },



  // Miasma "Hades" PyPI wave, developer-tooling cluster (August 2026). Second and
  // larger cluster of the June 8 campaign above: 37 malicious wheel artifacts
  // across 19 further projects, same *-setup.pth startup hook and Bun-based
  // _index.js stealer. Every entry is version-pinned because every package is a
  // legitimate project whose maintainer was compromised.
  //
  // The "pypi:" prefix is load-bearing. A bare value denotes the npm namespace
  // and would route all of these to the wrong resolver, which does not weaken
  // detection but inverts it.
  { type: "package", value: "pypi:bramin@0.0.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:bramin@0.0.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:bramin@0.0.4", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:cmd2func@0.2.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:cmd2func@0.2.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:coolbox@0.4.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:coolbox@0.4.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:dynamo-release@1.5.4", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:executor-engine@0.3.4", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:executor-engine@0.3.5", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:executor-http@0.1.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:executor-http@0.1.4", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:funcdesc@0.2.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:funcdesc@0.2.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:magique@0.6.8", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:magique@0.6.9", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:magique-ai@0.4.4", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:magique-ai@0.4.5", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:mrbios@0.1.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:mrbios@0.1.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:napari-ufish@0.0.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:napari-ufish@0.0.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:nhmpy@2.4.7", severity: "critical", confidence: 0.85, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:nucbox@0.1.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:nucbox@0.1.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:okite@0.0.7", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:okite@0.0.8", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:pantheon-agents@0.6.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:pantheon-agents@0.6.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:pantheon-toolsets@0.5.5", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:pantheon-toolsets@0.5.6", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:rlask@3.1.4", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "StepSecurity", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:rlask@3.1.5", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "StepSecurity", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:rlask@3.1.6", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "StepSecurity", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:spateo-release@1.1.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:synago@0.1.1", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:synago@0.1.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:ufish@0.1.2", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:ufish@0.1.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:uprobe@0.1.3", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },
  { type: "package", value: "pypi:uprobe@0.1.4", severity: "critical", confidence: 1.0, family: "MiniShaiHulud", campaign: "Miasma Hades PyPI", source: "Socket, StepSecurity, Orca", firstSeen: "2026-08-13" },



  // Vellia / Guangnao / lodash-js npm malware cluster (August 2026). Atomic
  // indicators extracted by hand from the OpenSSF malicious-packages write-ups
  // (amazon-inspector); the package@version rows arrived through the importer.
  // Single-source, hence confidence 0.85.
  { type: "domain", value: "hub.client-llm.com", severity: "critical", confidence: 0.85, campaign: "Guangnao agent-proxy AI session hijack", source: "OpenSSF malicious-packages (amazon-inspector), MAL-2026-14047", firstSeen: "2026-08-15" },
  { type: "domain", value: "analytics.baskirill-an.workers.dev", severity: "critical", confidence: 0.85, campaign: "lodash-js Xelis cryptojacker", source: "OpenSSF malicious-packages (amazon-inspector), MAL-2026-14048", firstSeen: "2026-08-15" },
  { type: "domain", value: "registrynpmjs.to", severity: "critical", confidence: 0.85, campaign: "Polymarkets registry lookalike", source: "OpenSSF malicious-packages (amazon-inspector), MAL-2026-14050", firstSeen: "2026-08-15" },
  { type: "url", value: "analytics.baskirill-an.workers.dev/configs/boostydownloader", severity: "critical", confidence: 0.85, campaign: "lodash-js Xelis cryptojacker", source: "OpenSSF malicious-packages (amazon-inspector), MAL-2026-14048", firstSeen: "2026-08-15" },
  { type: "url", value: "registrynpmjs.to/inquirer-14.0.2.tgz", severity: "critical", confidence: 0.85, campaign: "Polymarkets registry lookalike", source: "OpenSSF malicious-packages (amazon-inspector), MAL-2026-14050", firstSeen: "2026-08-15" },
  { type: "url", value: "api.github.com/repos/Vellia-Elyvia/mydb/contents/db.json", severity: "critical", confidence: 0.85, campaign: "velliajs discord.js impersonation", source: "OpenSSF malicious-packages (amazon-inspector), MAL-2026-14051", firstSeen: "2026-08-15" },

];

const FEED_CHUNK_12: FeedIOC[] = [
  // Added by hand rather than by the importer. The 2026-08-14 advisory backfill pushed
  // these two behind ~1,680 queue positions, which is further than --limit 250 can reach
  // before they age out of the --days 14 window, so no later run recovers them. Every
  // other name in that unreachable tail resolves to an npm security-holding stub or a
  // 404; this one is still installable (maintainer intact, five published versions), so
  // it is the only part of the tail with any detection value left. Version-pinned to the
  // two versions the advisory names, not the whole package.
  { type: "package", value: "dakumangalsingh@2.0.1", severity: "critical", confidence: 1.0, source: "GHSA-h2fc-hhv7-4596, MAL-2026-13879", firstSeen: "2026-08-12" },
  { type: "package", value: "dakumangalsingh@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-h2fc-hhv7-4596, MAL-2026-13879", firstSeen: "2026-08-12" },


  // Added by hand (2026-08-17). Live package the --limit 250 head cannot reach before
  // the 2026-08-14 backfill ages it out - see the pin in ioc-blocklist.ts.
  { type: "package", value: "@zinley/orion@1.2.31", severity: "critical", confidence: 1.0, source: "GHSA-jf8m-fw34-6mg8, MAL-2026-1060", firstSeen: "2026-08-17" },
  { type: "package", value: "@zinley/orion@1.2.32", severity: "critical", confidence: 1.0, source: "GHSA-jf8m-fw34-6mg8, MAL-2026-1060", firstSeen: "2026-08-17" },
  { type: "package", value: "@zinley/orion@1.2.34", severity: "critical", confidence: 1.0, source: "GHSA-jf8m-fw34-6mg8, MAL-2026-1060", firstSeen: "2026-08-17" },
  { type: "package", value: "@zinley/orion@1.2.36", severity: "critical", confidence: 1.0, source: "GHSA-jf8m-fw34-6mg8, MAL-2026-1060", firstSeen: "2026-08-17" },
  { type: "package", value: "@zinley/orion@1.2.38", severity: "critical", confidence: 1.0, source: "GHSA-jf8m-fw34-6mg8, MAL-2026-1060", firstSeen: "2026-08-17" },
  { type: "package", value: "@zinley/orion@1.2.39", severity: "critical", confidence: 1.0, source: "GHSA-jf8m-fw34-6mg8, MAL-2026-1060", firstSeen: "2026-08-17" },

  // mgc npm account takeover - UNC1069 / "Sapphire Sleet" WAVESHAPER.V2 (safedep,
  // April 2026). Single-source write-up, hence confidence 0.85, but the implant paths
  // it reports match the axios/UNC1069 hashes already carried in ioc-blocklist.ts.
  { type: "package", value: "mgc@1.2.1", severity: "critical", confidence: 0.85, family: "WaveshaperV2", campaign: "mgc account takeover", source: "safedep", firstSeen: "2026-04-02" },
  { type: "package", value: "mgc@1.2.2", severity: "critical", confidence: 0.85, family: "WaveshaperV2", campaign: "mgc account takeover", source: "safedep", firstSeen: "2026-04-02" },
  { type: "package", value: "mgc@1.2.3", severity: "critical", confidence: 0.85, family: "WaveshaperV2", campaign: "mgc account takeover", source: "safedep", firstSeen: "2026-04-02" },
  { type: "package", value: "mgc@1.2.4", severity: "critical", confidence: 0.85, family: "WaveshaperV2", campaign: "mgc account takeover", source: "safedep", firstSeen: "2026-04-02" },
  { type: "hash", value: "40aa5d412a50db79a814ac5ad65237745727cb4777843d66a760f64285a5a3e6", severity: "critical", confidence: 0.85, family: "WaveshaperV2", campaign: "mgc account takeover", source: "safedep", firstSeen: "2026-04-02" },
  { type: "url", value: "admondtamang.com.np/gate", severity: "critical", confidence: 0.85, family: "WaveshaperV2", campaign: "mgc account takeover", source: "safedep", firstSeen: "2026-04-02" },
  { type: "url", value: "gist.github.com/admondtamang/814132e794e5d007e9b8ebd223a9494f", severity: "critical", confidence: 0.85, family: "WaveshaperV2", campaign: "mgc account takeover", source: "safedep", firstSeen: "2026-04-02" },
  { type: "url", value: "gist.githubusercontent.com/admondtamang/814132e794e5d007e9b8ebd223a9494f/raw/1c5d51c2002f452a4dd58a1a73a9dd90a7fe0297/linux.payload", severity: "critical", confidence: 0.85, family: "WaveshaperV2", campaign: "mgc account takeover", source: "safedep", firstSeen: "2026-04-02" },
  { type: "url", value: "gist.githubusercontent.com/admondtamang/814132e794e5d007e9b8ebd223a9494f/raw/1c5d51c2002f452a4dd58a1a73a9dd90a7fe0297/window.payload", severity: "critical", confidence: 0.85, family: "WaveshaperV2", campaign: "mgc account takeover", source: "safedep", firstSeen: "2026-04-02" },




  // NullReceiver / DPRK "Contagious Interview" npm wave (OpenSourceMalware 2026-08-05,
  // Sonatype Research Labs 2026-08-10). The advisory databases never carried these three,
  // so they are hand-added. agentgui is a live package with 1,110 releases and is pinned
  // to the single trojanized publish; the other two were unpublished with zero surviving
  // versions and no legitimate history, so they are blocked by name.
  { type: "package", value: "agentgui@1.0.1127", severity: "critical", confidence: 1.0, family: "NullReceiver", campaign: "NullReceiver", source: "Sonatype Research Labs, OpenSourceMalware", firstSeen: "2026-08-10" },
  { type: "package", value: "scrollbar-hide-plugin", severity: "critical", confidence: 1.0, family: "NullReceiver", campaign: "NullReceiver", source: "OpenSourceMalware", firstSeen: "2026-08-05" },
  { type: "package", value: "tailwind-animation-founder", severity: "critical", confidence: 1.0, family: "NullReceiver", campaign: "NullReceiver", source: "OpenSourceMalware", firstSeen: "2026-08-05" },



  // ChainDrop npm worm / "Mini Shai-Hulud". Third preinstall-dropper variant,
  // catalogued by Unit 42 as setup.mjs.malicious. Single-source, hence 0.85.
  { type: "hash", value: "b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678", severity: "critical", confidence: 0.85, campaign: "ChainDrop npm Worm", source: "Unit 42", firstSeen: "2026-08-04" },




  // arrayref / proc-macro1 crates.io build-time dropper (August 2026) - atomic
  // indicators from vendor write-ups; the package IOCs came from the advisory
  // import above. See docs/threat-feed-sources.md.
  { type: "package", value: "cargo:proc-macro1", severity: "critical", confidence: 1.0, source: "GHSA-m83q-4x86-96wh, MAL-2026-14338", firstSeen: "2026-08-21" },
  { type: "package", value: "cargo:arrayref@0.3.10", severity: "critical", confidence: 1.0, source: "GHSA-jwh4-228v-r358, MAL-2026-14336", firstSeen: "2026-08-21" },
  { type: "domain", value: "hwsrv-798836.hostwindsdns.com", severity: "critical", confidence: 1.0, campaign: "arrayref Build-Time Dropper", source: "StepSecurity, Wiz", firstSeen: "2026-08-20" },
  { type: "ip", value: "23.254.165.112", severity: "critical", confidence: 1.0, campaign: "arrayref Build-Time Dropper", source: "StepSecurity, Wiz, safedep", firstSeen: "2026-08-20" },
  { type: "ip", value: "23.254.167.107", severity: "critical", confidence: 1.0, campaign: "arrayref Build-Time Dropper", source: "StepSecurity, Wiz", firstSeen: "2026-08-20" },
  { type: "ip", value: "23.254.167.216", severity: "critical", confidence: 1.0, campaign: "arrayref Build-Time Dropper", source: "StepSecurity, Wiz", firstSeen: "2026-08-20" },
  { type: "ip", value: "23.254.167.13", severity: "critical", confidence: 0.85, campaign: "arrayref Build-Time Dropper", source: "Wiz (single-source)", firstSeen: "2026-08-20" },
  { type: "hash", value: "25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae", severity: "critical", confidence: 1.0, campaign: "arrayref Build-Time Dropper", source: "StepSecurity, Wiz", firstSeen: "2026-08-20" },
  { type: "hash", value: "61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4", severity: "critical", confidence: 1.0, campaign: "arrayref Build-Time Dropper", source: "StepSecurity, Wiz", firstSeen: "2026-08-20" },
  { type: "hash", value: "b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436", severity: "critical", confidence: 1.0, campaign: "arrayref Build-Time Dropper", source: "StepSecurity, Wiz", firstSeen: "2026-08-20" },

  // Curated back into the bundle from the 2026-08-21 advisory import.
  // campaigns.test.ts asserts every one of these against getBundledFeed(),
  // so they are a stated offline-detection contract and not ordinary import
  // volume: the bare npm names cover the all-versions resolver, and the two
  // pypi: pairs cover ecosystem routing plus the clean-version negative.
  // They arrived with no curation, so the cutoff advance to 2026-08-22 was
  // about to migrate them out and take four assertions with them. This is a
  // comment block on purpose: rule 3 in feed-migrate.mjs anchors on the
  // comment, and a campaign field alone would not have held them.

  { type: "package", value: "polymarket-trading-developer-tool", severity: "critical", confidence: 1.0, source: "GHSA-qh4r-g8mr-v3xp, MAL-2026-6714", firstSeen: "2026-08-21" },
  { type: "package", value: "kelly-sizing", severity: "critical", confidence: 1.0, source: "GHSA-vj74-3pcr-5p7j, MAL-2026-14354", firstSeen: "2026-08-21" },
  { type: "package", value: "saas-f-testing", severity: "critical", confidence: 1.0, source: "GHSA-fvrj-4h6r-8rcg, MAL-2026-12434", firstSeen: "2026-08-21" },
  { type: "package", value: "pypi:scrambleeer@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-jx7v-9c55-jw2v, MAL-2026-14350", firstSeen: "2026-08-21" },
  { type: "package", value: "pypi:scrambleeer@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-jx7v-9c55-jw2v, MAL-2026-14350", firstSeen: "2026-08-21" },
  { type: "package", value: "pypi:boto4@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-ffh8-mpww-qp8g, MAL-2026-14349", firstSeen: "2026-08-21" },
  { type: "package", value: "pypi:boto4@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-ffh8-mpww-qp8g, MAL-2026-14349", firstSeen: "2026-08-21" },


  // Curated back into the bundle from the 2026-08-22 advisory import.
  // campaigns.test.ts pins these against getBundledFeed(): one published
  // version must match and the neighbouring 0.7.0 must NOT, which is the
  // dependency-confusion negative control for the whole @postman-cse scope.
  // They arrived under an importer batch header with no curation, so the
  // cutoff advance to 2026-08-23 migrated them out and took that assertion
  // with it. Third time this has happened (v6.2.1, v6.2.3, here), and the
  // field scan does not catch it: rule 3 in feed-migrate.mjs anchors on a
  // comment block, and a campaign field alone would not hold these.

  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.8.10", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.8.11", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.9.0", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.9.1", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.0", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.1", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.2", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.3", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.4", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.5", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.6", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.7", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.8", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.10.9", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.11.0", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.11.1", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.11.2", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.11.3", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.11.6", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.11.5", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },
  { type: "package", value: "@postman-cse/okta-aio-linux-arm64@0.11.4", severity: "critical", confidence: 1.0, source: "GHSA-h84r-259m-g3fg, MAL-2026-14357", firstSeen: "2026-08-22" },

  // Curated back into the bundle from the 2026-08-14 to 2026-08-17 advisory
  // imports, at the v6.3.2 cutoff advance to 2026-08-29. campaigns.test.ts
  // asserts these against getBundledFeed(): the Douqiu @hd-team names, the
  // flyteplugins pypi: routing pair and its clean-version negative, the
  // @fleetbo/svro and Shai-Hulud Trinitite @7nohe version pins, the four
  // registry-probed bare names, and the 3layerdipstack family that the
  // anchored rule is measured against (more than 300 bundled names, each at
  // critical rather than the rule's high). They arrived under importer batch
  // headers with no curation, so the advance would have migrated all 468 out
  // and taken seven assertions with them. A comment block on purpose: rule 3
  // in feed-migrate.mjs anchors on the comment, not on a campaign field.

  { type: "package", value: "pypi:flyteplugins-nsight@2.6.10", severity: "critical", confidence: 1.0, source: "GHSA-33m6-gx9h-9qv5, MAL-2026-14583", firstSeen: "2026-08-28" },
  { type: "package", value: "pypi:flyteplugins-agento11y@2.6.10", severity: "critical", confidence: 1.0, source: "GHSA-8cpp-43j8-xg7c, MAL-2026-14581", firstSeen: "2026-08-28" },
  { type: "package", value: "pypi:flyteplugins-redis@2.6.10", severity: "critical", confidence: 1.0, source: "GHSA-23fv-6cgr-766g, MAL-2026-14584", firstSeen: "2026-08-28" },
  { type: "package", value: "pypi:flyteplugins-echo@2.6.10", severity: "critical", confidence: 1.0, source: "GHSA-gcjf-mv7f-ffmf, MAL-2026-14582", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.2", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.3", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.4", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.5", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.6", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.7", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.9", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.10", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.11", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.12", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.13", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.14", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.15", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.16", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.17", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.19", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.20", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.21", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.22", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.23", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.24", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.26", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.27", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.29", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.30", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.31", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.32", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.33", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.34", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.35", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.37", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.38", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.39", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.40", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@fleetbo/svro@0.0.42", severity: "critical", confidence: 1.0, source: "GHSA-4hrx-gqq5-q956, MAL-2026-14586", firstSeen: "2026-08-28" },
  { type: "package", value: "@hd-team/app-impkg-test", severity: "critical", confidence: 1.0, source: "GHSA-hxxw-mprp-h9w7, MAL-2026-14576", firstSeen: "2026-08-27" },
  { type: "package", value: "@hd-team/app-impkg-prod", severity: "critical", confidence: 1.0, source: "GHSA-g7cq-7vcf-rp48, MAL-2026-14575", firstSeen: "2026-08-27" },
  { type: "package", value: "@hd-team/app-dnpkg-prod", severity: "critical", confidence: 1.0, source: "GHSA-35w7-82wv-vwxj, MAL-2026-14571", firstSeen: "2026-08-27" },
  { type: "package", value: "@hd-team/app-dnpkg-three", severity: "critical", confidence: 1.0, source: "GHSA-qwcv-3958-fhq5, MAL-2026-14574", firstSeen: "2026-08-27" },
  { type: "package", value: "@hd-team/app-dnpkg-beta", severity: "critical", confidence: 1.0, source: "GHSA-6p53-v557-745c, MAL-2026-14569", firstSeen: "2026-08-27" },
  { type: "package", value: "@hd-team/app-dnpkg-test", severity: "critical", confidence: 1.0, source: "GHSA-6fm3-xp27-2556, MAL-2026-14573", firstSeen: "2026-08-27" },
  { type: "package", value: "@hd-team/app-dnpkg-ten", severity: "critical", confidence: 1.0, source: "GHSA-q7mf-7f69-7qpr, MAL-2026-14572", firstSeen: "2026-08-27" },
  { type: "package", value: "@hd-team/app-dnpkg-eight", severity: "critical", confidence: 1.0, source: "GHSA-97qc-463w-p2jr, MAL-2026-14570", firstSeen: "2026-08-27" },
  { type: "package", value: "tailwindcss-3d-animate", severity: "critical", confidence: 1.0, source: "GHSA-683p-54mf-9297, MAL-2026-14567", firstSeen: "2026-08-27" },
  { type: "package", value: "inspectstack", severity: "critical", confidence: 1.0, source: "GHSA-xjx7-pff2-34gp, MAL-2026-14560", firstSeen: "2026-08-27" },
  { type: "package", value: "veloq", severity: "critical", confidence: 1.0, source: "GHSA-gccc-9phc-w64p, MAL-2026-14566", firstSeen: "2026-08-27" },
  { type: "package", value: "morglog", severity: "critical", confidence: 1.0, source: "GHSA-v899-gp96-p5rv, MAL-2026-14562", firstSeen: "2026-08-27" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@0.5.4", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@1.6.3", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@0.0.0-365d4eb738d3146583431948d3ba6e27a32556be", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@3.0.3", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@3.0.4", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@1.6.4", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@2.2.2", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@0.0.0-ec7876d6c917dad516ba69bbfafc948b834bf0ab", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "@7nohe/openapi-react-query-codegen@0.5.5", severity: "critical", confidence: 1.0, source: "GHSA-rg27-qr39-ch6w, MAL-2026-15494", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackm7mock", severity: "critical", confidence: 1.0, source: "GHSA-2xmr-4cx4-q8xh, MAL-2026-14827", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackhr3ocw", severity: "critical", confidence: 1.0, source: "GHSA-xcr2-ph6w-v53x, MAL-2026-14774", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackulgnp8", severity: "critical", confidence: 1.0, source: "GHSA-5grf-6834-4gx2, MAL-2026-14949", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcyqc7o", severity: "critical", confidence: 1.0, source: "GHSA-mrwr-vvf3-5cj3, MAL-2026-14716", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackesp1lb", severity: "critical", confidence: 1.0, source: "GHSA-34fw-55mp-c63j, MAL-2026-14743", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackt3wr5f", severity: "critical", confidence: 1.0, source: "GHSA-fjvm-qq3g-pfj8, MAL-2026-14925", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacktfieac", severity: "critical", confidence: 1.0, source: "GHSA-hx6j-pg3c-xp7h, MAL-2026-14929", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackev4sn5", severity: "critical", confidence: 1.0, source: "GHSA-v5hh-fxh9-5jg2, MAL-2026-14745", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjsuvtk", severity: "critical", confidence: 1.0, source: "GHSA-mwhw-pqwx-mcgc, MAL-2026-14791", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackpcv17m", severity: "critical", confidence: 1.0, source: "GHSA-283x-m4wp-8428, MAL-2026-14872", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackru7mfn", severity: "critical", confidence: 1.0, source: "GHSA-fx3x-5gff-392g, MAL-2026-14909", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1lkqg9", severity: "critical", confidence: 1.0, source: "GHSA-gj6j-q87j-rmx5, MAL-2026-14605", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacklgszmx", severity: "critical", confidence: 1.0, source: "GHSA-8gq9-v5rg-4v67, MAL-2026-14820", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkrgcjq", severity: "critical", confidence: 1.0, source: "GHSA-vc65-p3ww-752q, MAL-2026-14805", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackuyd45d", severity: "critical", confidence: 1.0, source: "GHSA-r328-vg5c-g98q, MAL-2026-14954", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1ykdgn", severity: "critical", confidence: 1.0, source: "GHSA-wrm3-cfhh-r2g7, MAL-2026-14608", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvld3fr", severity: "critical", confidence: 1.0, source: "GHSA-7qh7-wh5v-4p7p, MAL-2026-14963", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack6ih5ru", severity: "critical", confidence: 1.0, source: "GHSA-6qfq-f3rx-r2rg, MAL-2026-14642", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack8lj8gm", severity: "critical", confidence: 1.0, source: "GHSA-q89v-f6q7-q4rf, MAL-2026-14664", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvdy7nf", severity: "critical", confidence: 1.0, source: "GHSA-6j5j-jmv3-2vqc, MAL-2026-14960", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvcdkrp", severity: "critical", confidence: 1.0, source: "GHSA-5cqp-h6j9-xhff, MAL-2026-14958", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack2pdlo4", severity: "critical", confidence: 1.0, source: "GHSA-cjx7-rpp8-xjp7, MAL-2026-14610", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackebunld", severity: "critical", confidence: 1.0, source: "GHSA-qvcf-62cq-22gw, MAL-2026-14735", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacko8li9w", severity: "critical", confidence: 1.0, source: "GHSA-3fmf-7gp2-6qh7, MAL-2026-14852", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvnmth1", severity: "critical", confidence: 1.0, source: "GHSA-25h6-8cqx-xgh6, MAL-2026-14965", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack74ooau", severity: "critical", confidence: 1.0, source: "GHSA-f836-85g9-539h, MAL-2026-14649", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackmokfkh", severity: "critical", confidence: 1.0, source: "GHSA-3vjx-v4f5-8553, MAL-2026-14835", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack4pstwd", severity: "critical", confidence: 1.0, source: "GHSA-56jq-5fhp-g3gh, MAL-2026-14626", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackx26ujd", severity: "critical", confidence: 1.0, source: "GHSA-6m22-7jpm-3pwq, MAL-2026-14978", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacktm8xp5", severity: "critical", confidence: 1.0, source: "GHSA-3jj7-p8p6-fjjf, MAL-2026-14933", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvm4qaj", severity: "critical", confidence: 1.0, source: "GHSA-29f5-999f-rvqh, MAL-2026-14964", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqokw95", severity: "critical", confidence: 1.0, source: "GHSA-wmhq-xfpx-rqmp, MAL-2026-14892", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackl52afz", severity: "critical", confidence: 1.0, source: "GHSA-jv27-p77q-fjc3, MAL-2026-14813", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfywqmz", severity: "critical", confidence: 1.0, source: "GHSA-2gr6-mqqx-ch77, MAL-2026-14760", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackpvsk6r", severity: "critical", confidence: 1.0, source: "GHSA-4pfw-969w-75x8, MAL-2026-14881", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5zhcdq", severity: "critical", confidence: 1.0, source: "GHSA-pr38-fgvj-m5mw, MAL-2026-14641", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkpfva6", severity: "critical", confidence: 1.0, source: "GHSA-chrq-p6q9-7c3v, MAL-2026-14804", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkzelo0", severity: "critical", confidence: 1.0, source: "GHSA-hf47-w27p-rfg5, MAL-2026-14809", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackbndk47", severity: "critical", confidence: 1.0, source: "GHSA-f6vp-8xqg-j5rv, MAL-2026-14698", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackhcymwm", severity: "critical", confidence: 1.0, source: "GHSA-w9gm-499c-j4q4, MAL-2026-14771", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacko89fkl", severity: "critical", confidence: 1.0, source: "GHSA-qr5w-pc8v-rw38, MAL-2026-14851", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackr5ga2v", severity: "critical", confidence: 1.0, source: "GHSA-h6qm-wv83-7m6p, MAL-2026-14898", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackoj4nf9", severity: "critical", confidence: 1.0, source: "GHSA-hw8m-f396-69p5, MAL-2026-14859", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackl3yyy", severity: "critical", confidence: 1.0, source: "GHSA-4939-5f2v-6fq9, MAL-2026-14812", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackmu4bxx", severity: "critical", confidence: 1.0, source: "GHSA-jj42-42vv-mmff, MAL-2026-14837", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack71tlcd", severity: "critical", confidence: 1.0, source: "GHSA-66p2-q5q9-qw3c, MAL-2026-14648", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvaovrs", severity: "critical", confidence: 1.0, source: "GHSA-2hpp-55hq-v5cw, MAL-2026-14956", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackwqo67k", severity: "critical", confidence: 1.0, source: "GHSA-qc62-96fr-2g6m, MAL-2026-14974", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacklzflp", severity: "critical", confidence: 1.0, source: "GHSA-pq7p-f8jv-f9jx, MAL-2026-14824", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack97rmzr", severity: "critical", confidence: 1.0, source: "GHSA-cqvj-f289-cg74, MAL-2026-14670", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackoms1fe", severity: "critical", confidence: 1.0, source: "GHSA-7879-xh4g-hwmv, MAL-2026-14861", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackaudu38", severity: "critical", confidence: 1.0, source: "GHSA-p9mm-wfw6-v67m, MAL-2026-14688", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdanp80", severity: "critical", confidence: 1.0, source: "GHSA-p7x3-64wm-pc39, MAL-2026-14721", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackepcy6k", severity: "critical", confidence: 1.0, source: "GHSA-m334-cccc-34j8, MAL-2026-14742", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackbopqb8", severity: "critical", confidence: 1.0, source: "GHSA-q7g9-w697-c8c5, MAL-2026-14699", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfoajna", severity: "critical", confidence: 1.0, source: "GHSA-chxp-34hf-jhcm, MAL-2026-14754", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackrvc9k", severity: "critical", confidence: 1.0, source: "GHSA-f259-r2f6-r3fm, MAL-2026-14910", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackedqpy", severity: "critical", confidence: 1.0, source: "GHSA-pg2q-3xxw-9rx8, MAL-2026-14737", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9ai4f", severity: "critical", confidence: 1.0, source: "GHSA-355j-ch64-9vqj, MAL-2026-14671", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7d0vc", severity: "critical", confidence: 1.0, source: "GHSA-v523-vhv6-gwr5, MAL-2026-14653", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackhyazlk", severity: "critical", confidence: 1.0, source: "GHSA-7qfw-93pf-98fr, MAL-2026-14775", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvtd7og", severity: "critical", confidence: 1.0, source: "GHSA-xjqq-vrg3-cf35, MAL-2026-14967", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackq6h8eq", severity: "critical", confidence: 1.0, source: "GHSA-qpxq-x45w-hxfv, MAL-2026-14886", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackoa1cxf", severity: "critical", confidence: 1.0, source: "GHSA-vcpp-4v3q-pvw3, MAL-2026-14853", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfm45yj", severity: "critical", confidence: 1.0, source: "GHSA-mj82-8qxc-9m2p, MAL-2026-14753", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcfu35", severity: "critical", confidence: 1.0, source: "GHSA-hqrp-gx5g-v2qp, MAL-2026-14706", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacknk2da", severity: "critical", confidence: 1.0, source: "GHSA-3prf-3723-rwv4, MAL-2026-14843", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacktmo3tu", severity: "critical", confidence: 1.0, source: "GHSA-vhq4-m9h9-pqww, MAL-2026-14934", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackba23j", severity: "critical", confidence: 1.0, source: "GHSA-9m4h-577w-hj8v, MAL-2026-14694", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvd6za6", severity: "critical", confidence: 1.0, source: "GHSA-j7x4-2jjr-gqgw, MAL-2026-14959", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacktlt5o", severity: "critical", confidence: 1.0, source: "GHSA-rf8x-7vp9-r7x5, MAL-2026-14932", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackrkxyr1", severity: "critical", confidence: 1.0, source: "GHSA-8527-mhpj-f5f4, MAL-2026-14908", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjj1l0", severity: "critical", confidence: 1.0, source: "GHSA-hv7p-cgwr-qpqq, MAL-2026-14789", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackj3eh2", severity: "critical", confidence: 1.0, source: "GHSA-w982-5hfx-8cvq, MAL-2026-14784", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7u3sgs", severity: "critical", confidence: 1.0, source: "GHSA-43v8-jjq7-9xf4, MAL-2026-14658", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacksh21o", severity: "critical", confidence: 1.0, source: "GHSA-xc5r-2vf9-94qx, MAL-2026-14918", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkl17i", severity: "critical", confidence: 1.0, source: "GHSA-65h5-ffqr-4rwv, MAL-2026-14802", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacknqbfz", severity: "critical", confidence: 1.0, source: "GHSA-m2x3-8gfq-8jqv, MAL-2026-14846", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackx70bgg", severity: "critical", confidence: 1.0, source: "GHSA-x26f-8jgf-5qqp, MAL-2026-14980", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackpsq4vf", severity: "critical", confidence: 1.0, source: "GHSA-mj5h-45qp-f8hm, MAL-2026-14880", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfhcuh", severity: "critical", confidence: 1.0, source: "GHSA-hfqq-jwxh-xfq5, MAL-2026-14750", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackicrmv", severity: "critical", confidence: 1.0, source: "GHSA-6q3p-2jr4-mx57, MAL-2026-14778", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjfp5u", severity: "critical", confidence: 1.0, source: "GHSA-rprm-mjr4-2w83, MAL-2026-14787", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackd8ze8", severity: "critical", confidence: 1.0, source: "GHSA-46mx-vhr5-35xx, MAL-2026-14720", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackuu02ly", severity: "critical", confidence: 1.0, source: "GHSA-7837-mhv3-vf5h, MAL-2026-14952", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkxrxle", severity: "critical", confidence: 1.0, source: "GHSA-9x8g-v6xv-3hw4, MAL-2026-14807", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackihi1o9", severity: "critical", confidence: 1.0, source: "GHSA-3gxm-679f-6qg9, MAL-2026-14781", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackposh4n", severity: "critical", confidence: 1.0, source: "GHSA-mgcp-vrv4-54xx, MAL-2026-14879", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackujt40", severity: "critical", confidence: 1.0, source: "GHSA-rxjr-pwq8-jjvv, MAL-2026-14947", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacks0fpdw", severity: "critical", confidence: 1.0, source: "GHSA-fm8v-fxg4-pv6v, MAL-2026-14913", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackl7gab", severity: "critical", confidence: 1.0, source: "GHSA-jgqp-w6p4-7vqc, MAL-2026-14814", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdit9j", severity: "critical", confidence: 1.0, source: "GHSA-jj92-g485-hgf4, MAL-2026-14727", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack6wovmj", severity: "critical", confidence: 1.0, source: "GHSA-hqhg-265f-87r4, MAL-2026-14647", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack0y4arx", severity: "critical", confidence: 1.0, source: "GHSA-fvwx-2fhw-24q6, MAL-2026-14596", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacksokbgx", severity: "critical", confidence: 1.0, source: "GHSA-8jmw-f6vr-mjcv, MAL-2026-14922", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackr8xy1r", severity: "critical", confidence: 1.0, source: "GHSA-pwhm-854g-8675, MAL-2026-14900", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackoo3m1u", severity: "critical", confidence: 1.0, source: "GHSA-hqp8-28c8-qp6c, MAL-2026-14863", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack8b4dts", severity: "critical", confidence: 1.0, source: "GHSA-27v7-63j6-2p8q, MAL-2026-14662", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacklskknx", severity: "critical", confidence: 1.0, source: "GHSA-x37f-fx6q-gvv9, MAL-2026-14823", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackidjlc", severity: "critical", confidence: 1.0, source: "GHSA-44cv-9rq2-vrcj, MAL-2026-14779", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackub7lk", severity: "critical", confidence: 1.0, source: "GHSA-6v4c-vhqj-9r4f, MAL-2026-14941", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackl3dhz", severity: "critical", confidence: 1.0, source: "GHSA-r8m2-3pr5-98f3, MAL-2026-14811", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqi4id", severity: "critical", confidence: 1.0, source: "GHSA-5p9p-g4p9-qvfv, MAL-2026-14890", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackpbkfvo", severity: "critical", confidence: 1.0, source: "GHSA-frf6-3m73-fq99, MAL-2026-14871", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqqd7f", severity: "critical", confidence: 1.0, source: "GHSA-27fm-2h35-cqvv, MAL-2026-14894", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackrce3qw", severity: "critical", confidence: 1.0, source: "GHSA-999p-mwr6-g4pr, MAL-2026-14904", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7lknl", severity: "critical", confidence: 1.0, source: "GHSA-7vj3-7wf6-vv7c, MAL-2026-14657", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackm7yxnp", severity: "critical", confidence: 1.0, source: "GHSA-pw58-56xh-jvx7, MAL-2026-14828", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1lb2r", severity: "critical", confidence: 1.0, source: "GHSA-xwxm-gwg9-xqx6, MAL-2026-14604", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacknuabm", severity: "critical", confidence: 1.0, source: "GHSA-qf7v-7595-j996, MAL-2026-14849", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkdz8gp", severity: "critical", confidence: 1.0, source: "GHSA-x38c-7v4r-cgmp, MAL-2026-14798", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5vnbm", severity: "critical", confidence: 1.0, source: "GHSA-r47j-m2mw-h2xp, MAL-2026-14639", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacksn9ze", severity: "critical", confidence: 1.0, source: "GHSA-jhw5-j257-gx3w, MAL-2026-14921", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackh5ax7", severity: "critical", confidence: 1.0, source: "GHSA-98mq-46g7-34cx, MAL-2026-14770", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacknlxzr", severity: "critical", confidence: 1.0, source: "GHSA-hv9w-mw4h-xjvf, MAL-2026-14845", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackunyzh", severity: "critical", confidence: 1.0, source: "GHSA-v488-2p9w-px82, MAL-2026-14950", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9thbs", severity: "critical", confidence: 1.0, source: "GHSA-v8h3-xhcm-w72h, MAL-2026-14679", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackn71eil", severity: "critical", confidence: 1.0, source: "GHSA-xgwg-72p8-qmcv, MAL-2026-14839", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7cgotb", severity: "critical", confidence: 1.0, source: "GHSA-v6q7-9hpj-j363, MAL-2026-14652", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackujfdgm", severity: "critical", confidence: 1.0, source: "GHSA-9vf8-m2mx-3rhm, MAL-2026-14946", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackklb52", severity: "critical", confidence: 1.0, source: "GHSA-v389-hjv7-9896, MAL-2026-14803", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7wbw9m", severity: "critical", confidence: 1.0, source: "GHSA-vj5f-x79q-ghmr, MAL-2026-14659", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdsc6gn", severity: "critical", confidence: 1.0, source: "GHSA-pr3v-6m4c-cjvf, MAL-2026-14731", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9umaj", severity: "critical", confidence: 1.0, source: "GHSA-w5jr-qqvf-cj32, MAL-2026-14681", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5f9qf", severity: "critical", confidence: 1.0, source: "GHSA-cp4g-cqjm-2943, MAL-2026-14634", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1qjbr", severity: "critical", confidence: 1.0, source: "GHSA-56qc-h93x-rjmr, MAL-2026-14607", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5aycu", severity: "critical", confidence: 1.0, source: "GHSA-jf2r-wxr2-762h, MAL-2026-14629", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack3i8km", severity: "critical", confidence: 1.0, source: "GHSA-h26h-758h-mjh8, MAL-2026-14615", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkaw1i8", severity: "critical", confidence: 1.0, source: "GHSA-vpjr-83hg-w9q3, MAL-2026-14797", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1igc1l", severity: "critical", confidence: 1.0, source: "GHSA-839v-2x8j-8jcq, MAL-2026-14603", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5eariu", severity: "critical", confidence: 1.0, source: "GHSA-9w8p-p7mj-2pc8, MAL-2026-14632", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfdgka0", severity: "critical", confidence: 1.0, source: "GHSA-cg56-j95w-957c, MAL-2026-14749", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackzhnxi", severity: "critical", confidence: 1.0, source: "GHSA-v4fv-4xjc-x53f, MAL-2026-14996", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackpyqy5", severity: "critical", confidence: 1.0, source: "GHSA-c6xv-66mr-27gr, MAL-2026-14882", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack4ib1jd", severity: "critical", confidence: 1.0, source: "GHSA-9qhp-crrf-xh2c, MAL-2026-14623", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackp5nvj", severity: "critical", confidence: 1.0, source: "GHSA-hq9j-q987-x4mr, MAL-2026-14867", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackyt68w", severity: "critical", confidence: 1.0, source: "GHSA-m43r-pjqg-8c3v, MAL-2026-14992", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackn7fk1", severity: "critical", confidence: 1.0, source: "GHSA-rh65-m8wx-h7xj, MAL-2026-14840", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacky2fxy", severity: "critical", confidence: 1.0, source: "GHSA-7h99-8mgq-5cgg, MAL-2026-14985", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackaho91u", severity: "critical", confidence: 1.0, source: "GHSA-pj6w-3qcm-p5rg, MAL-2026-14687", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack2ya7xz", severity: "critical", confidence: 1.0, source: "GHSA-qxhc-v4g3-g7q6, MAL-2026-14612", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackr7ib9k", severity: "critical", confidence: 1.0, source: "GHSA-mr3w-g49x-qcm3, MAL-2026-14899", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackuldhl", severity: "critical", confidence: 1.0, source: "GHSA-x2xq-9hx9-xqvf, MAL-2026-14948", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9riv6", severity: "critical", confidence: 1.0, source: "GHSA-3f7j-vqqg-hmm8, MAL-2026-14678", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack0ighvf", severity: "critical", confidence: 1.0, source: "GHSA-cxh9-mr4x-44m6, MAL-2026-14595", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5cwu1", severity: "critical", confidence: 1.0, source: "GHSA-j679-9q2c-vx94, MAL-2026-14630", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackwm7sa", severity: "critical", confidence: 1.0, source: "GHSA-v84q-7gfm-x2j5, MAL-2026-14973", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacksihvvg", severity: "critical", confidence: 1.0, source: "GHSA-fvm5-5pp4-c728, MAL-2026-14919", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacksgs6k", severity: "critical", confidence: 1.0, source: "GHSA-8c95-4vj3-38r2, MAL-2026-14917", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackhivao", severity: "critical", confidence: 1.0, source: "GHSA-grp3-78hj-2vcw, MAL-2026-14773", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9umzt", severity: "critical", confidence: 1.0, source: "GHSA-f3g5-3rxq-rm43, MAL-2026-14682", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackthgojd", severity: "critical", confidence: 1.0, source: "GHSA-9q7v-83gp-gc68, MAL-2026-14931", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1eognp", severity: "critical", confidence: 1.0, source: "GHSA-68jj-2g55-rrm2, MAL-2026-14600", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackhykud", severity: "critical", confidence: 1.0, source: "GHSA-2w33-73p2-wwv2, MAL-2026-14776", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackybqdp4", severity: "critical", confidence: 1.0, source: "GHSA-r4ww-49pm-fj7p, MAL-2026-14986", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackctn2v", severity: "critical", confidence: 1.0, source: "GHSA-6rpp-h553-fx3p, MAL-2026-14714", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdcw7ib", severity: "critical", confidence: 1.0, source: "GHSA-8w68-534f-6f54, MAL-2026-14724", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack3hsru3", severity: "critical", confidence: 1.0, source: "GHSA-8274-2rmw-xf5c, MAL-2026-14614", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackrcuf3", severity: "critical", confidence: 1.0, source: "GHSA-6c27-c8m7-w88g, MAL-2026-14905", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacks8qqq", severity: "critical", confidence: 1.0, source: "GHSA-58cj-qmj8-h9w9, MAL-2026-14916", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvb5y6", severity: "critical", confidence: 1.0, source: "GHSA-rvx9-g497-pxgc, MAL-2026-14957", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackelcuhp", severity: "critical", confidence: 1.0, source: "GHSA-pw26-733g-867r, MAL-2026-14740", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjac6a", severity: "critical", confidence: 1.0, source: "GHSA-6cjx-7qq6-j4j5, MAL-2026-14785", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfooret", severity: "critical", confidence: 1.0, source: "GHSA-8fxg-f2fp-x87j, MAL-2026-14755", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackch7e5", severity: "critical", confidence: 1.0, source: "GHSA-j4f6-9x2w-4qg4, MAL-2026-14707", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackpmrxi4", severity: "critical", confidence: 1.0, source: "GHSA-m2v8-fgcp-98wq, MAL-2026-14877", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackolosqh", severity: "critical", confidence: 1.0, source: "GHSA-gvw3-j6vv-2rv6, MAL-2026-14860", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackea57kt", severity: "critical", confidence: 1.0, source: "GHSA-997q-cv25-mw53, MAL-2026-14734", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackubntx", severity: "critical", confidence: 1.0, source: "GHSA-phm8-8x7v-8rhq, MAL-2026-14942", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackba1nq3", severity: "critical", confidence: 1.0, source: "GHSA-7pw2-wcvq-hpf7, MAL-2026-14693", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackxms0j", severity: "critical", confidence: 1.0, source: "GHSA-7v7w-25h3-w457, MAL-2026-14984", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackb1ojqr", severity: "critical", confidence: 1.0, source: "GHSA-whjq-865g-3gvj, MAL-2026-14691", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackzpi9o", severity: "critical", confidence: 1.0, source: "GHSA-5f8x-6fxw-hx9c, MAL-2026-14997", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5vpco", severity: "critical", confidence: 1.0, source: "GHSA-r76v-xg29-24rv, MAL-2026-14640", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackwc0qja", severity: "critical", confidence: 1.0, source: "GHSA-vhqp-3h36-xh55, MAL-2026-14971", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackn2nce", severity: "critical", confidence: 1.0, source: "GHSA-q6r2-hgr3-x29h, MAL-2026-14838", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjw2t3", severity: "critical", confidence: 1.0, source: "GHSA-87gc-w76h-3h38, MAL-2026-14792", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9u8ge", severity: "critical", confidence: 1.0, source: "GHSA-r98p-7g5g-f6pw, MAL-2026-14680", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackmn51k", severity: "critical", confidence: 1.0, source: "GHSA-cp34-3xfx-wrgp, MAL-2026-14834", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackaawov4", severity: "critical", confidence: 1.0, source: "GHSA-8fcj-8vvj-6r49, MAL-2026-14686", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackw1ma2", severity: "critical", confidence: 1.0, source: "GHSA-5mr8-hr34-qhh6, MAL-2026-14969", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqpma84", severity: "critical", confidence: 1.0, source: "GHSA-r9rc-mqgh-c3rr, MAL-2026-14893", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacksu99cs", severity: "critical", confidence: 1.0, source: "GHSA-cg59-c863-69mw, MAL-2026-14923", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackchk77", severity: "critical", confidence: 1.0, source: "GHSA-2g4r-8x35-8p8r, MAL-2026-14708", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvtid3m", severity: "critical", confidence: 1.0, source: "GHSA-8phq-pw76-62ff, MAL-2026-14968", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackj0xnu", severity: "critical", confidence: 1.0, source: "GHSA-frqq-73x3-rcwf, MAL-2026-14783", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack4ilqnj", severity: "critical", confidence: 1.0, source: "GHSA-5x58-fpvh-r4q4, MAL-2026-14625", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjdbrp", severity: "critical", confidence: 1.0, source: "GHSA-4gqj-hqr7-m5h9, MAL-2026-14786", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack3psj0", severity: "critical", confidence: 1.0, source: "GHSA-rw96-5fjp-8rgg, MAL-2026-14617", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvhbhs6", severity: "critical", confidence: 1.0, source: "GHSA-h6x3-jp2r-wcj4, MAL-2026-14961", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7zgtws", severity: "critical", confidence: 1.0, source: "GHSA-4w4v-75jw-r2r8, MAL-2026-14660", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack4ebgmu", severity: "critical", confidence: 1.0, source: "GHSA-8424-9j7f-7c9r, MAL-2026-14621", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackewhns5", severity: "critical", confidence: 1.0, source: "GHSA-gq54-v97g-hgf3, MAL-2026-14746", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackoue8uj", severity: "critical", confidence: 1.0, source: "GHSA-8gh5-vc73-j7cf, MAL-2026-14865", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacklbxr4c", severity: "critical", confidence: 1.0, source: "GHSA-2666-4gcg-4hv7, MAL-2026-14818", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackodswc", severity: "critical", confidence: 1.0, source: "GHSA-m9fx-v4pr-qhh9, MAL-2026-14855", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1ccrm9", severity: "critical", confidence: 1.0, source: "GHSA-rmj6-2672-ww8j, MAL-2026-14599", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackykuowv", severity: "critical", confidence: 1.0, source: "GHSA-c63q-7q7w-834h, MAL-2026-14989", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackoo1jd", severity: "critical", confidence: 1.0, source: "GHSA-h5jh-pmxv-jfg7, MAL-2026-14862", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackf0lda9", severity: "critical", confidence: 1.0, source: "GHSA-g7ww-89hg-97cp, MAL-2026-14747", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjxbse8", severity: "critical", confidence: 1.0, source: "GHSA-vff2-qfrc-cq3m, MAL-2026-14794", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacka1fnr", severity: "critical", confidence: 1.0, source: "GHSA-fj2h-vxqm-89vf, MAL-2026-14684", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackric51a", severity: "critical", confidence: 1.0, source: "GHSA-pvgj-vhxc-w52r, MAL-2026-14907", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackog84a", severity: "critical", confidence: 1.0, source: "GHSA-wpjx-w67c-j7vh, MAL-2026-14856", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacks4wje", severity: "critical", confidence: 1.0, source: "GHSA-hqr9-5qcj-xp32, MAL-2026-14915", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackopdmf", severity: "critical", confidence: 1.0, source: "GHSA-6jr5-626q-7v49, MAL-2026-14864", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackn9ng1d", severity: "critical", confidence: 1.0, source: "GHSA-qh68-wvpj-fc9f, MAL-2026-14842", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackds3oln", severity: "critical", confidence: 1.0, source: "GHSA-8x65-66vh-h766, MAL-2026-14729", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdnbulr", severity: "critical", confidence: 1.0, source: "GHSA-3xvh-x5q8-rj6r, MAL-2026-14728", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcjddnb", severity: "critical", confidence: 1.0, source: "GHSA-6c2p-6gwv-x8jm, MAL-2026-14709", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjgfism", severity: "critical", confidence: 1.0, source: "GHSA-gjw3-f876-rh64, MAL-2026-14788", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackuo78n", severity: "critical", confidence: 1.0, source: "GHSA-55v3-89v4-fhrh, MAL-2026-14951", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacklc7lgg", severity: "critical", confidence: 1.0, source: "GHSA-j43f-hj9h-j45w, MAL-2026-14819", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackm1j2h", severity: "critical", confidence: 1.0, source: "GHSA-wxv2-8w9j-qj72, MAL-2026-14825", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1nz8o", severity: "critical", confidence: 1.0, source: "GHSA-7h5r-3vjr-jrgj, MAL-2026-14606", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5nigd", severity: "critical", confidence: 1.0, source: "GHSA-jvp4-cvxg-3m5f, MAL-2026-14636", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackd80ved", severity: "critical", confidence: 1.0, source: "GHSA-5mm2-mgcm-v24h, MAL-2026-14719", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackmplv5", severity: "critical", confidence: 1.0, source: "GHSA-3j5c-g422-936v, MAL-2026-14836", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackuyb1e", severity: "critical", confidence: 1.0, source: "GHSA-v9qx-wgh7-rwgr, MAL-2026-14953", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackw2pt3", severity: "critical", confidence: 1.0, source: "GHSA-g4pr-j9qq-q6v7, MAL-2026-14970", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack0e2jp", severity: "critical", confidence: 1.0, source: "GHSA-vq77-fxvw-x2mw, MAL-2026-14594", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackogwk1", severity: "critical", confidence: 1.0, source: "GHSA-cqcx-2463-8j92, MAL-2026-14857", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackedh67n", severity: "critical", confidence: 1.0, source: "GHSA-7x44-v37r-gvrf, MAL-2026-14736", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack2u8fh", severity: "critical", confidence: 1.0, source: "GHSA-73jg-xjjp-xp4w, MAL-2026-14611", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackgrzn5z", severity: "critical", confidence: 1.0, source: "GHSA-w6mr-3gcq-ccvw, MAL-2026-14768", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5f0nl", severity: "critical", confidence: 1.0, source: "GHSA-jhc9-cwf2-rhrj, MAL-2026-14633", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackoi4dda", severity: "critical", confidence: 1.0, source: "GHSA-ppf5-c568-772m, MAL-2026-14858", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacklbpy50", severity: "critical", confidence: 1.0, source: "GHSA-57g6-8f33-qmpw, MAL-2026-14817", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack8yfoyr", severity: "critical", confidence: 1.0, source: "GHSA-qcq5-4j48-fmjx, MAL-2026-14668", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqyhks", severity: "critical", confidence: 1.0, source: "GHSA-xc2w-x472-r33f, MAL-2026-14896", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack3jen8", severity: "critical", confidence: 1.0, source: "GHSA-8fj4-53g4-pjq8, MAL-2026-14616", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5hkzmg", severity: "critical", confidence: 1.0, source: "GHSA-r7h3-rxx8-q77x, MAL-2026-14635", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcnxrzk", severity: "critical", confidence: 1.0, source: "GHSA-84hv-qrcf-67v3, MAL-2026-14711", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackmk7pb", severity: "critical", confidence: 1.0, source: "GHSA-v59q-77jf-943g, MAL-2026-14833", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackenjw1i", severity: "critical", confidence: 1.0, source: "GHSA-348c-hj46-j84w, MAL-2026-14741", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9b0cq", severity: "critical", confidence: 1.0, source: "GHSA-m6xp-g64c-r6mh, MAL-2026-14672", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackpmw72s", severity: "critical", confidence: 1.0, source: "GHSA-9pv7-59hv-pfrg, MAL-2026-14878", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackmiputn", severity: "critical", confidence: 1.0, source: "GHSA-c6rj-3gfq-98r2, MAL-2026-14830", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack3h0mt", severity: "critical", confidence: 1.0, source: "GHSA-wrqf-x6gw-wgh4, MAL-2026-14613", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacksz3ee", severity: "critical", confidence: 1.0, source: "GHSA-fjvx-g7r9-rr8q, MAL-2026-14924", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackieh8c", severity: "critical", confidence: 1.0, source: "GHSA-q78j-cwj5-3m64, MAL-2026-14780", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackrygm3", severity: "critical", confidence: 1.0, source: "GHSA-3rm5-rpm9-4w7q, MAL-2026-14911", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackay9drz", severity: "critical", confidence: 1.0, source: "GHSA-qvq9-f39q-qc9h, MAL-2026-14689", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacktfp41b", severity: "critical", confidence: 1.0, source: "GHSA-q55w-95vf-w32j, MAL-2026-14930", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack8e0an", severity: "critical", confidence: 1.0, source: "GHSA-hwgg-q72w-gcq9, MAL-2026-14663", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackujb8p", severity: "critical", confidence: 1.0, source: "GHSA-jwh2-xvx9-6567, MAL-2026-14945", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackn7sxtp", severity: "critical", confidence: 1.0, source: "GHSA-j4hf-ww94-x6cc, MAL-2026-14841", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackxav9q", severity: "critical", confidence: 1.0, source: "GHSA-gf35-7x5w-77pf, MAL-2026-14981", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackhi9md", severity: "critical", confidence: 1.0, source: "GHSA-2w3v-6m74-jj8r, MAL-2026-14772", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack3vept", severity: "critical", confidence: 1.0, source: "GHSA-2695-6wmg-3q44, MAL-2026-14618", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackytruq6", severity: "critical", confidence: 1.0, source: "GHSA-fxr2-3mg9-pr7w, MAL-2026-14993", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1g5cxo", severity: "critical", confidence: 1.0, source: "GHSA-q9pg-284g-mp86, MAL-2026-14602", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackmi10b", severity: "critical", confidence: 1.0, source: "GHSA-4rvp-9hch-hc53, MAL-2026-14829", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackp4yyc", severity: "critical", confidence: 1.0, source: "GHSA-r2qp-3336-6c2q, MAL-2026-14866", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackyq24q", severity: "critical", confidence: 1.0, source: "GHSA-6q43-j35x-r2gv, MAL-2026-14990", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacku2axz", severity: "critical", confidence: 1.0, source: "GHSA-cq9g-f65w-4fcc, MAL-2026-14939", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackq06zyy", severity: "critical", confidence: 1.0, source: "GHSA-jfgr-qc54-2pvf, MAL-2026-14883", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackp6m8ir", severity: "critical", confidence: 1.0, source: "GHSA-7gx2-v2h2-vvq7, MAL-2026-14868", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackra0nf", severity: "critical", confidence: 1.0, source: "GHSA-w2mv-86hg-vpxv, MAL-2026-14901", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfzx88", severity: "critical", confidence: 1.0, source: "GHSA-7q2x-c69j-mjr3, MAL-2026-14761", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcstjn", severity: "critical", confidence: 1.0, source: "GHSA-9xp5-r64p-c52w, MAL-2026-14713", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackbz1nv9", severity: "critical", confidence: 1.0, source: "GHSA-f7mp-399f-w7p9, MAL-2026-14701", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackplila", severity: "critical", confidence: 1.0, source: "GHSA-x8m4-2x8w-pvmq, MAL-2026-14875", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack4dhmdb", severity: "critical", confidence: 1.0, source: "GHSA-5vx8-8v55-45mx, MAL-2026-14619", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackbn5wu", severity: "critical", confidence: 1.0, source: "GHSA-632g-g678-xhfm, MAL-2026-14696", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacktclg9", severity: "critical", confidence: 1.0, source: "GHSA-rgwr-3cq5-85xp, MAL-2026-14928", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdfw3wg", severity: "critical", confidence: 1.0, source: "GHSA-v767-f37f-78gf, MAL-2026-14726", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack6wih1", severity: "critical", confidence: 1.0, source: "GHSA-6qj9-2r94-f9fx, MAL-2026-14646", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackgbshj", severity: "critical", confidence: 1.0, source: "GHSA-c6fg-p458-v3cp, MAL-2026-14764", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackckdy9", severity: "critical", confidence: 1.0, source: "GHSA-877j-7wg2-jvr7, MAL-2026-14710", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackm6i9v", severity: "critical", confidence: 1.0, source: "GHSA-c56c-f2xj-76vm, MAL-2026-14826", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack04tdo", severity: "critical", confidence: 1.0, source: "GHSA-83gx-6qpf-8c2v, MAL-2026-14592", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackyqrxdf", severity: "critical", confidence: 1.0, source: "GHSA-v7r2-5jrg-j5gc, MAL-2026-14991", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack0dsxsc", severity: "critical", confidence: 1.0, source: "GHSA-m4cj-j6pg-2ff3, MAL-2026-14593", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacku0rsp", severity: "critical", confidence: 1.0, source: "GHSA-5j6r-5mhv-2v33, MAL-2026-14938", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackx1zi8p", severity: "critical", confidence: 1.0, source: "GHSA-r6mr-268v-26jr, MAL-2026-14977", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackq0lwcc", severity: "critical", confidence: 1.0, source: "GHSA-82x6-vfhh-x985, MAL-2026-14884", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackic0c5r", severity: "critical", confidence: 1.0, source: "GHSA-j5hx-gx26-c4p2, MAL-2026-14777", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackk83nm", severity: "critical", confidence: 1.0, source: "GHSA-5wff-pp86-vm8j, MAL-2026-14796", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfl4v8", severity: "critical", confidence: 1.0, source: "GHSA-wq4v-9prg-pv8q, MAL-2026-14752", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackiud1lz", severity: "critical", confidence: 1.0, source: "GHSA-6qpf-5v6x-w7xv, MAL-2026-14782", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackgbmd1c", severity: "critical", confidence: 1.0, source: "GHSA-qrcj-cfg8-fpmv, MAL-2026-14763", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackrh52pp", severity: "critical", confidence: 1.0, source: "GHSA-5rw3-crhc-rff3, MAL-2026-14906", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdwrofj", severity: "critical", confidence: 1.0, source: "GHSA-7rhf-hxcf-3cg6, MAL-2026-14732", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacklrswmw", severity: "critical", confidence: 1.0, source: "GHSA-5979-q42h-x364, MAL-2026-14822", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack8xhwdm", severity: "critical", confidence: 1.0, source: "GHSA-g6m6-v6mv-6vqm, MAL-2026-14667", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack6jqkjs", severity: "critical", confidence: 1.0, source: "GHSA-34r6-88wm-vjjc, MAL-2026-14643", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackwexso", severity: "critical", confidence: 1.0, source: "GHSA-jqpc-4583-4v82, MAL-2026-14972", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackb0eeq", severity: "critical", confidence: 1.0, source: "GHSA-gqxp-2823-v2mx, MAL-2026-14690", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackp92wd", severity: "critical", confidence: 1.0, source: "GHSA-86m5-f65q-g4mm, MAL-2026-14869", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcrikda", severity: "critical", confidence: 1.0, source: "GHSA-4hvw-5h77-wcp7, MAL-2026-14712", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackaac4df", severity: "critical", confidence: 1.0, source: "GHSA-5q2h-85xc-8jmc, MAL-2026-14685", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackds5wll", severity: "critical", confidence: 1.0, source: "GHSA-vrg2-p874-98hq, MAL-2026-14730", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqbqwn", severity: "critical", confidence: 1.0, source: "GHSA-r9hv-vxhv-vjj8, MAL-2026-14888", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackc6c5kn", severity: "critical", confidence: 1.0, source: "GHSA-hfx2-q2jq-8wqj, MAL-2026-14702", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackeflbpd", severity: "critical", confidence: 1.0, source: "GHSA-566p-mjv9-v7v6, MAL-2026-14738", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackz54iek", severity: "critical", confidence: 1.0, source: "GHSA-wqvh-59pm-5c2m, MAL-2026-14994", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackrbupl", severity: "critical", confidence: 1.0, source: "GHSA-92rv-wv9f-8m7j, MAL-2026-14902", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7atotw", severity: "critical", confidence: 1.0, source: "GHSA-r9g5-q945-65wv, MAL-2026-14651", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackl21ibf", severity: "critical", confidence: 1.0, source: "GHSA-m47x-cm5j-vhg2, MAL-2026-14810", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqb6ww", severity: "critical", confidence: 1.0, source: "GHSA-5fcf-j78w-9xv6, MAL-2026-14887", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackljpzly", severity: "critical", confidence: 1.0, source: "GHSA-vw4c-ffc9-qvwc, MAL-2026-14821", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackttd2o", severity: "critical", confidence: 1.0, source: "GHSA-vjgx-jr7w-mjg7, MAL-2026-14935", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackzhe5k", severity: "critical", confidence: 1.0, source: "GHSA-v7wv-65v2-8pr6, MAL-2026-14995", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7eu4ry", severity: "critical", confidence: 1.0, source: "GHSA-9vm7-qvf2-pjpr, MAL-2026-14654", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacktc0tq7", severity: "critical", confidence: 1.0, source: "GHSA-r6h3-m7vf-j2g9, MAL-2026-14927", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackl88spb", severity: "critical", confidence: 1.0, source: "GHSA-8x4f-gxg5-6c98, MAL-2026-14815", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfqxcmc", severity: "critical", confidence: 1.0, source: "GHSA-gc8x-pf92-fwrm, MAL-2026-14758", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackr4geh2", severity: "critical", confidence: 1.0, source: "GHSA-fhxh-98j8-m8h4, MAL-2026-14897", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjx20az", severity: "critical", confidence: 1.0, source: "GHSA-rv6j-7rrw-jjf6, MAL-2026-14793", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacknstgz", severity: "critical", confidence: 1.0, source: "GHSA-rg48-h5h7-9p79, MAL-2026-14848", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackyhk67g", severity: "critical", confidence: 1.0, source: "GHSA-p38m-f9q4-c82p, MAL-2026-14987", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacku03hgo", severity: "critical", confidence: 1.0, source: "GHSA-2j2q-m29g-mc9m, MAL-2026-14937", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack4wsms0", severity: "critical", confidence: 1.0, source: "GHSA-p3gr-m5mf-m4gr, MAL-2026-14627", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackxdv18", severity: "critical", confidence: 1.0, source: "GHSA-g4j7-x3mc-x6qx, MAL-2026-14982", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack8nvcr", severity: "critical", confidence: 1.0, source: "GHSA-x532-gg2x-vgfq, MAL-2026-14665", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacksla5p", severity: "critical", confidence: 1.0, source: "GHSA-jx9m-p28q-4g6h, MAL-2026-14920", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackk5ewlo", severity: "critical", confidence: 1.0, source: "GHSA-hr5q-w7wq-5ggw, MAL-2026-14795", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfp5dp", severity: "critical", confidence: 1.0, source: "GHSA-43m5-7fcj-93m9, MAL-2026-14757", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcfbla", severity: "critical", confidence: 1.0, source: "GHSA-9v55-2p5h-vhvm, MAL-2026-14705", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackobk93q", severity: "critical", confidence: 1.0, source: "GHSA-74g7-973p-9r2f, MAL-2026-14854", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkirw0e", severity: "critical", confidence: 1.0, source: "GHSA-w5xr-4p7m-35hx, MAL-2026-14801", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacke2eppx", severity: "critical", confidence: 1.0, source: "GHSA-f38f-m9f6-pw58, MAL-2026-14733", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackmjdc98", severity: "critical", confidence: 1.0, source: "GHSA-hqww-2v7m-gc5x, MAL-2026-14831", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackgqt6yc", severity: "critical", confidence: 1.0, source: "GHSA-v3f7-588v-fh5m, MAL-2026-14767", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackttt4c", severity: "critical", confidence: 1.0, source: "GHSA-q89m-62pr-xmvw, MAL-2026-14936", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqcvl6h", severity: "critical", confidence: 1.0, source: "GHSA-4h77-6hmx-rcw5, MAL-2026-14889", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9j4ke", severity: "critical", confidence: 1.0, source: "GHSA-834q-qjwf-qrgr, MAL-2026-14675", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack2cyinb", severity: "critical", confidence: 1.0, source: "GHSA-x8hm-f9cq-6wh3, MAL-2026-14609", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcaujb", severity: "critical", confidence: 1.0, source: "GHSA-9m27-mxgm-cj8v, MAL-2026-14703", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackgcno4", severity: "critical", confidence: 1.0, source: "GHSA-6hw7-qhjv-4hpr, MAL-2026-14765", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack6kyra", severity: "critical", confidence: 1.0, source: "GHSA-9r43-hhf6-j93j, MAL-2026-14644", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack4iivta", severity: "critical", confidence: 1.0, source: "GHSA-mfw6-7x2g-cggv, MAL-2026-14624", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackmjm6e", severity: "critical", confidence: 1.0, source: "GHSA-rh6m-8wj8-9mpr, MAL-2026-14832", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackpd83be", severity: "critical", confidence: 1.0, source: "GHSA-r8h3-8w9v-frrg, MAL-2026-14873", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackbgh33k", severity: "critical", confidence: 1.0, source: "GHSA-xfq8-w7qh-2qxc, MAL-2026-14695", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackg4okgs", severity: "critical", confidence: 1.0, source: "GHSA-cfcr-hjvf-29r3, MAL-2026-14762", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackefwqm", severity: "critical", confidence: 1.0, source: "GHSA-f8rf-3fff-4922, MAL-2026-14739", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackwu6ij", severity: "critical", confidence: 1.0, source: "GHSA-7xjw-3r9c-8xj5, MAL-2026-14975", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackb68qiv", severity: "critical", confidence: 1.0, source: "GHSA-rw8p-vrvf-pvrh, MAL-2026-14692", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackgyrw9d", severity: "critical", confidence: 1.0, source: "GHSA-q39x-pv4f-78w4, MAL-2026-14769", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9d7ow", severity: "critical", confidence: 1.0, source: "GHSA-7rmc-8xpq-6h8x, MAL-2026-14673", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1a4xg", severity: "critical", confidence: 1.0, source: "GHSA-jjwp-474m-67wv, MAL-2026-14598", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackd3cxf7", severity: "critical", confidence: 1.0, source: "GHSA-5f2q-pw5g-x9pg, MAL-2026-14717", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfkqbp4", severity: "critical", confidence: 1.0, source: "GHSA-ff6f-8mr3-gcww, MAL-2026-14751", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdflm1d", severity: "critical", confidence: 1.0, source: "GHSA-qw95-c8v2-5h42, MAL-2026-14725", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackd4npj", severity: "critical", confidence: 1.0, source: "GHSA-m455-4wgc-cf3w, MAL-2026-14718", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackbxw4k", severity: "critical", confidence: 1.0, source: "GHSA-mrg5-p2gq-9fj9, MAL-2026-14700", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7ezqzp", severity: "critical", confidence: 1.0, source: "GHSA-xw33-p2r3-56v7, MAL-2026-14655", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackbn8wg", severity: "critical", confidence: 1.0, source: "GHSA-v6cx-gmrr-fm3f, MAL-2026-14697", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackuew4bh", severity: "critical", confidence: 1.0, source: "GHSA-69wp-x7mf-38c6, MAL-2026-14944", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack8zg7y", severity: "critical", confidence: 1.0, source: "GHSA-ppmx-rcxg-f87q, MAL-2026-14669", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackesxum", severity: "critical", confidence: 1.0, source: "GHSA-hwxq-3hpv-9grv, MAL-2026-14744", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdb90s", severity: "critical", confidence: 1.0, source: "GHSA-g368-379f-4vgr, MAL-2026-14722", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackggjd8x", severity: "critical", confidence: 1.0, source: "GHSA-g63f-463m-h9r4, MAL-2026-14766", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackudibkf", severity: "critical", confidence: 1.0, source: "GHSA-mc46-27vw-4vfr, MAL-2026-14943", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackjnh4m1", severity: "critical", confidence: 1.0, source: "GHSA-gxph-cp6j-9p53, MAL-2026-14790", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack7ke6fz", severity: "critical", confidence: 1.0, source: "GHSA-99mm-gr34-p8pr, MAL-2026-14656", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackp9bua", severity: "critical", confidence: 1.0, source: "GHSA-799r-86ph-7cvj, MAL-2026-14870", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqszzc", severity: "critical", confidence: 1.0, source: "GHSA-299g-wfxf-8mm2, MAL-2026-14895", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkysrek", severity: "critical", confidence: 1.0, source: "GHSA-89cf-7c2h-2xhg, MAL-2026-14808", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackxlmq6", severity: "critical", confidence: 1.0, source: "GHSA-r79g-8ch6-c8fj, MAL-2026-14983", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackzz0n4", severity: "critical", confidence: 1.0, source: "GHSA-mrx6-9pjc-7p8g, MAL-2026-14998", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvo9oet", severity: "critical", confidence: 1.0, source: "GHSA-q6cp-r5f8-mv4v, MAL-2026-14966", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacks42lb", severity: "critical", confidence: 1.0, source: "GHSA-fpf7-vcpc-6gf4, MAL-2026-14914", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkg0gfy", severity: "critical", confidence: 1.0, source: "GHSA-hm9q-c7r5-2c4h, MAL-2026-14800", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5a7otk", severity: "critical", confidence: 1.0, source: "GHSA-vmc2-fqrw-cjvw, MAL-2026-14628", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcvi67o", severity: "critical", confidence: 1.0, source: "GHSA-gf3j-95fh-m3vv, MAL-2026-14715", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackftd8b", severity: "critical", confidence: 1.0, source: "GHSA-vhfx-9qpf-9xrh, MAL-2026-14759", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackdci73", severity: "critical", confidence: 1.0, source: "GHSA-fwhg-qm9h-6w77, MAL-2026-14723", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack8v1vs", severity: "critical", confidence: 1.0, source: "GHSA-569w-v6jw-6cw3, MAL-2026-14666", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack89dtg", severity: "critical", confidence: 1.0, source: "GHSA-hjg7-4wj8-5xmh, MAL-2026-14661", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackpfnj1", severity: "critical", confidence: 1.0, source: "GHSA-7cf5-7q37-67wx, MAL-2026-14874", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackv4z5q", severity: "critical", confidence: 1.0, source: "GHSA-r78v-vxmx-5x7m, MAL-2026-14955", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackcbatl4", severity: "critical", confidence: 1.0, source: "GHSA-6mq9-4x4v-vq2f, MAL-2026-14704", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack4dhts", severity: "critical", confidence: 1.0, source: "GHSA-mhqw-h859-5hjq, MAL-2026-14620", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkege4f", severity: "critical", confidence: 1.0, source: "GHSA-qvj6-fm47-wvxm, MAL-2026-14799", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack18hkx", severity: "critical", confidence: 1.0, source: "GHSA-gj24-pf9v-f3f2, MAL-2026-14597", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackx4y4fx", severity: "critical", confidence: 1.0, source: "GHSA-r7xp-g6cr-5hpq, MAL-2026-14979", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackf9oik", severity: "critical", confidence: 1.0, source: "GHSA-h5px-cwhq-98vm, MAL-2026-14748", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackuayqn", severity: "critical", confidence: 1.0, source: "GHSA-2cx4-prjh-p6x3, MAL-2026-14940", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9vcxi9", severity: "critical", confidence: 1.0, source: "GHSA-mmm4-jqhv-898j, MAL-2026-14683", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5tuhr5", severity: "critical", confidence: 1.0, source: "GHSA-qqcv-h8w7-6xrc, MAL-2026-14638", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackykas5", severity: "critical", confidence: 1.0, source: "GHSA-rh5c-8829-gw94, MAL-2026-14988", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack4hg6p", severity: "critical", confidence: 1.0, source: "GHSA-x28f-24g5-5m4h, MAL-2026-14622", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackplnt8o", severity: "critical", confidence: 1.0, source: "GHSA-24jc-hpx8-rcvv, MAL-2026-14876", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackrc44f", severity: "critical", confidence: 1.0, source: "GHSA-jc44-fp9g-7w3w, MAL-2026-14903", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacklabm6", severity: "critical", confidence: 1.0, source: "GHSA-qjmr-mq4w-mhjq, MAL-2026-14816", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackq4ek0f", severity: "critical", confidence: 1.0, source: "GHSA-cww2-g8p6-4wcg, MAL-2026-14885", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackwudpnc", severity: "critical", confidence: 1.0, source: "GHSA-g44f-7gvv-m7g8, MAL-2026-14976", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9gdxi6", severity: "critical", confidence: 1.0, source: "GHSA-xq96-238h-36wg, MAL-2026-14674", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackqjq77e", severity: "critical", confidence: 1.0, source: "GHSA-2hp3-336m-rpw7, MAL-2026-14891", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacknk99g", severity: "critical", confidence: 1.0, source: "GHSA-6xh2-x4wr-8889, MAL-2026-14844", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacknqxij", severity: "critical", confidence: 1.0, source: "GHSA-m2cj-2w9g-gv7m, MAL-2026-14847", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9nawzv", severity: "critical", confidence: 1.0, source: "GHSA-76r6-7x8v-w2pv, MAL-2026-14677", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackkx7y2", severity: "critical", confidence: 1.0, source: "GHSA-fxfc-653g-xfvc, MAL-2026-14806", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5dfkei", severity: "critical", confidence: 1.0, source: "GHSA-pp5w-8h4m-rm8h, MAL-2026-14631", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack1ew1w", severity: "critical", confidence: 1.0, source: "GHSA-rmpr-jj7h-qvxv, MAL-2026-14601", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack75faj", severity: "critical", confidence: 1.0, source: "GHSA-f2f9-rhr4-9pw2, MAL-2026-14650", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstacknwgnpw", severity: "critical", confidence: 1.0, source: "GHSA-6jc9-hvw3-g6p4, MAL-2026-14850", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackvkl1hd", severity: "critical", confidence: 1.0, source: "GHSA-fx3g-rp88-5gcm, MAL-2026-14962", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackta7o8u", severity: "critical", confidence: 1.0, source: "GHSA-2xcj-j84x-59r5, MAL-2026-14926", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackfourm4", severity: "critical", confidence: 1.0, source: "GHSA-hjpx-6p66-8wwv, MAL-2026-14756", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstackryyay3", severity: "critical", confidence: 1.0, source: "GHSA-g73h-f6r2-2gqq, MAL-2026-14912", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack6mpbze", severity: "critical", confidence: 1.0, source: "GHSA-px4p-rqq3-34qx, MAL-2026-14645", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack9ma2d", severity: "critical", confidence: 1.0, source: "GHSA-x6v4-m4vf-429h, MAL-2026-14676", firstSeen: "2026-08-28" },
  { type: "package", value: "3layerdipstack5r1sh", severity: "critical", confidence: 1.0, source: "GHSA-3vc4-mrq3-92rr, MAL-2026-14637", firstSeen: "2026-08-28" },
];

const FEED_CHUNK_13: FeedIOC[] = [




  // RedShell / RedC2 4.0 Linux implant, "streak" npm cluster (TrendAI, August 20 2026;
  // package list corroborated by The Hacker News, August 21). Fourteen packages pose as
  // dependency-free calendar and "streak" maths utilities and work as advertised while
  // dist/index.mjs side-loads an ELF implant. Eight of the fourteen already arrived here
  // through the advisory databases; the six below never got a GHSA, so they are added by
  // hand from the vendor write-ups. Vendor-only provenance, hence 0.9. The atomic
  // indicators - the C2 VPS 217[.]60[.]77[.]63 and the implant digest - are
  // single-source and carry 0.85.
  { type: "package", value: "streak-calc-math", severity: "critical", confidence: 0.9, family: "RedShell", campaign: "RedC2", source: "TrendAI, The Hacker News", firstSeen: "2026-08-20" },
  { type: "package", value: "streak-math-abz", severity: "critical", confidence: 0.9, family: "RedShell", campaign: "RedC2", source: "TrendAI, The Hacker News", firstSeen: "2026-08-20" },
  { type: "package", value: "streak-math-metrics", severity: "critical", confidence: 0.9, family: "RedShell", campaign: "RedC2", source: "TrendAI, The Hacker News", firstSeen: "2026-08-20" },
  { type: "package", value: "streak-metricsaz", severity: "critical", confidence: 0.9, family: "RedShell", campaign: "RedC2", source: "TrendAI, The Hacker News", firstSeen: "2026-08-20" },
  { type: "package", value: "streak-metricsazb", severity: "critical", confidence: 0.9, family: "RedShell", campaign: "RedC2", source: "TrendAI, The Hacker News", firstSeen: "2026-08-20" },
  { type: "package", value: "streak-metricazbd", severity: "critical", confidence: 0.9, family: "RedShell", campaign: "RedC2", source: "TrendAI, The Hacker News", firstSeen: "2026-08-20" },
  { type: "ip", value: "217.60.77.63", severity: "critical", confidence: 0.85, family: "RedShell", campaign: "RedC2", source: "TrendAI", firstSeen: "2026-08-20" },
  { type: "hash", value: "4537b1189ce419f1a595cf47216c03f80e9170ce80dad8d9227a1e52f9cb3466", severity: "critical", confidence: 0.85, family: "RedShell", campaign: "RedC2", source: "TrendAI", firstSeen: "2026-08-20" },




  // Douqiu gambling ring npm config server (Panther, May 5 2026). Confirmed verbatim
  // inside the base64 config blob the @hd-team / @yuming2022 packages export.
  // Single-source, hence the reduced confidence.
  { type: "domain", value: "apiyf.dq87771.com", severity: "critical", confidence: 0.85, family: "Douqiu", campaign: "Douqiu npm config server", source: "Panther", firstSeen: "2026-05-05" },


];

const FEED_CHUNK_14: FeedIOC[] = [
  // Imported from GitHub Advisory Database (2026-08-16) - see docs/threat-feed-sources.md

  // npm bin entry harvesting (safedep, August 14 2026). One npm account published 21
  // packages whose names are the BINARY names Google's scoped packages expose, not the
  // package names - so an internal build that calls "ngsw-config" instead of consuming
  // it through @angular/service-worker resolves the public malicious one. The postinstall
  // stager POSTs a host fingerprint to a per-package path. Twenty of the 21 packages
  // arrived through the advisory importer on 2026-08-19 carrying no campaign, which
  // made them eligible to migrate: the v6.2.1 cutoff advance moved all twenty into
  // the catalog and left this block as the only offline coverage. They are now
  // curated with the same campaign at the end of the feed, in the last chunk.
  // Only the atomic infrastructure and the 21st package are added here.
  { type: "domain", value: "jchunt.top", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "safedep", firstSeen: "2026-08-14" },
  { type: "ip", value: "152.53.138.110", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "safedep", firstSeen: "2026-08-14" },
  { type: "package", value: "xbox-one-webdriver-cli@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "safedep", firstSeen: "2026-08-14" },


  // Baileys WhatsApp fork channel-farming campaign (safedep, August 2026). Malicious
  // forks of the Baileys WhatsApp Web library subscribe the installer's paired session
  // to operator-controlled channels and inject the operator's advertising URL into
  // outgoing media. The poisoned package names arrive through the advisory importer;
  // these are the operator indicators, which the advisory databases never carry.
  // The exfiltration host is corroborated by OSV MAL-2026-13470 (ynastore-baileys) in
  // addition to safedep, so it carries full confidence; the remaining two are
  // single-source and carry 0.85. The operator's GitHub account is covered by
  // KNOWN_MALICIOUS_GITHUB_ACCOUNTS instead, which is the matchable home for a
  // handle: a GitHub account appears as github.com/<account> text inside scanned
  // files and as a repository owner on a github scan. FeedIOC has no account type
  // by design, not for want of one. See "What is not an indicator" in
  // .ai/handoff/CONVENTIONS.md, which also records why a registry publisher handle
  // gets no equivalent home.
  { type: "domain", value: "fiora.nixel.my.id", severity: "critical", confidence: 1.0, family: "BaileysChannelFarm", campaign: "Baileys WhatsApp Channel Farming", source: "safedep, OSV MAL-2026-13470", firstSeen: "2026-08-31" },
  { type: "domain", value: "levvicode.cloud", severity: "critical", confidence: 0.85, family: "BaileysChannelFarm", campaign: "Baileys WhatsApp Channel Farming", source: "safedep", firstSeen: "2026-08-31" },
  { type: "url", value: "raw.githubusercontent.com/LevviCodeID/Levi4than/refs/heads/main/levvleys.json", severity: "critical", confidence: 0.85, family: "BaileysChannelFarm", campaign: "Baileys WhatsApp Channel Farming", source: "safedep", firstSeen: "2026-08-31" },

];

const FEED_CHUNK_15: FeedIOC[] = [

];

const FEED_CHUNK_16: FeedIOC[] = [
];

const FEED_CHUNK_17: FeedIOC[] = [
];

const FEED_CHUNK_18: FeedIOC[] = [
];

const FEED_CHUNK_19: FeedIOC[] = [
  // Imported from GitHub Advisory Database (2026-08-18) - see docs/threat-feed-sources.md
  { type: "hash", value: "8e5d1af68ca340ae0c6e8132cb00c686ec2d60502c1994d94ce353d1472ad5a3", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "safedep, Aikido", firstSeen: "2026-08-28" },
  { type: "hash", value: "b49afb7dba04cd99b357ce7c652c823a3707f28e130bd5c6645851a7adc030d6", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "Socket, safedep, Aikido", firstSeen: "2026-08-28" },
  { type: "hash", value: "709af2fdeb50324229e94c44c679a0fab18bd8e17d3864405989c526cbb63ad8", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "safedep, Aikido", firstSeen: "2026-08-28" },
  { type: "hash", value: "59370c67b54a0ccaedd265e2356f04540b2fba1e1845300ef6de4d5437d99380", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "safedep, Aikido", firstSeen: "2026-08-28" },
  { type: "hash", value: "e1f1162ece9a6e6ea21a20399cbf31c563a8149d433a68711f4223870c203d5a", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "safedep, Aikido", firstSeen: "2026-08-28" },
  { type: "hash", value: "b6012b2ff87f08f93ee53921c48db907ddbcf5461b03bb988083b01a36886237", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "safedep, Aikido", firstSeen: "2026-08-28" },
  { type: "hash", value: "778d6f0058045d6a2ab9a7e1d3e3be8e7e6b4d9cc217d13949bf1dfbab759a7c", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "safedep, Aikido", firstSeen: "2026-08-28" },
  { type: "hash", value: "b24d121667f21f492cb9db34fbfd515d5922a8dd30b9c45215c7220abbb10ca8", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "safedep, Aikido", firstSeen: "2026-08-28" },
  { type: "hash", value: "d3246926b20a8d021ed7de0ac8e9eee1dda986088f84ba18f31cb2042a121f5d", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "Socket, safedep", firstSeen: "2026-08-28" },
  { type: "hash", value: "0d58f3434c55842fc41ad99656c20a295d46e7d16f432a122a5a094d7c1de0e2", severity: "critical", confidence: 1.0, family: "Shai-Hulud", campaign: "Trinitite", source: "safedep, Endor Labs", firstSeen: "2026-08-28" },

];

const FEED_CHUNK_20: FeedIOC[] = [

  // Packagist theme spyware chain (Socket, August 31 2026). Thirteen Composer themes
  // aimed at Vietnamese movie and comic streaming sites inject a visitor-fingerprinting
  // JavaScript loader; iPhones on iOS 18.4 through 18.6.x are served a WebKit-to-kernel
  // exploit chain that installs spyware, and the August 12 2026 redeploy added an iOS
  // Keychain wallet-seed stealer. Single-vendor research, hence 0.85 on the atomic
  // indicators. The thirteen package names carry 0.9: every one of them returns 404 from
  // the Packagist metadata API, so the registry has removed them and a bare-name entry
  // cannot reach anything installable. The ophimcms vendor is otherwise legitimate: its
  // package list still holds 20 themes, none of them one of the four named here, so the
  // entries hit the removed packages only and leave the vendor's live catalogue alone.
  { type: "package", value: "composer:vsmov/theme-dy", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:vsmov/theme-rrdyw", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:vsmov/theme-motchill", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:vsmov/theme-vsmov", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:vsphim/theme-heovl", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:vsphim/theme-thempho", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:haiau009/kkphim-legend", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:haiau009/kkphim-motchill", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:chilltvcms/theme-legend", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:ophimcms/theme-dy", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:ophimcms/theme-motchill", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:ophimcms/theme-pcc", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "package", value: "composer:ophimcms/theme-rrdyw", severity: "critical", confidence: 0.9, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "cloudfareintcdn.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "cdn.data-2919.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "cdn.data-2920.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "nqsaaskw.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "abfedgecanme.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "abfdns.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "galedns.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "0liwevrhxdc3s2xk00.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "39rwcybep-20pwozhvdrzzy.net", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "5wg3w278e3oamlohmcinrkh.live", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "dlosdekr1u18msmov51.net", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "ex0x40vmi8qyccxq.net", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "ioa7xqmhiz26fv5e.info", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "isbo31w1o7xk3fztvmgpbv.app", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "jhflt6l0dwminsl494836rb.org", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "kp2-3ur6pe4r8i2hj5.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "ljot1cem6jhzfu53yb9aj3h.app", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "ncalb1rzb2rq5-3zdx1.app", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "ov86ayb0fe4ep2b92-645o.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "qdh71-y6j7vxgw046v4cvgga.live", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "sx3cjniwo1bmtqs0vlj-va2f.app", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "sx8vuz4smtdol7pg.com", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "t9ffxu6zhf915fadjv1.app", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "vutjsf0sd9sdqt2rkzvgzv9a.org", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "w4iunvbdvjof39q-3.net", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "domain", value: "xtpj2bzxip6iq7n3bnz.info", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "ip", value: "23.225.48.20", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "ip", value: "23.225.52.67", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "url", value: "union.macoms.la/jquery.min-3.6.8.js", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "hash", value: "60b6771958cb7e553994ba6752f108575ba70e02d24affb51d8936a17eb0bf5e", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "hash", value: "d9530e8cd79ac7b3d02b04e05426653afca7075fcf7424eec4d59c6e95745933", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "hash", value: "92c7d246d2c163c076f783dcc19f87f5b9b9ac301b106b87a7aaea9346ce0052", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "hash", value: "f2fdfddbc436acc24a654092f5205b2c5bd3208b126b2c2754ac63e7aea22298", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "hash", value: "9d6b58886189c0e23f706c32d3d8dda97b0b6d927ece6de07270813f070295b5", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },
  { type: "hash", value: "de539a63cbe27bbd4a7db30fc796cd6dc5309c02ef5e60a3c5cf0835e5601283", severity: "critical", confidence: 0.85, family: "PackagistThemeSpyware", campaign: "Packagist iOS spyware themes", source: "Socket", firstSeen: "2026-08-31" },


  // Baileys scope-copy cluster (September 2026) - counterfeit scopes of the legitimate
  // WhatsApp library; the upstream @whiskeysockets scope is unaffected and NOT blocked.
  { type: "package", value: "@mrlegendbot/baileys@1.2.4", severity: "critical", confidence: 1.0, source: "GHSA-36cp-4g73-5fp7, MAL-2026-15819", firstSeen: "2026-09-01" },
  { type: "package", value: "@mrlegendbot/baileys@1.2.5", severity: "critical", confidence: 1.0, source: "GHSA-36cp-4g73-5fp7, MAL-2026-15819", firstSeen: "2026-09-01" },
  { type: "package", value: "@systemzero/baileys@1.1.2", severity: "critical", confidence: 1.0, source: "GHSA-qhhx-6r5v-mv3q, MAL-2026-15820", firstSeen: "2026-09-01" },



  // Corroborated advisories that sit inside the 2026-09-02 / 2026-09-04 bulk-backfill
  // days, added by hand so they are not lost when that window ages out. Each was probed
  // against registry.npmjs.org: the two live packages are version-pinned, never name-blocked.
  { type: "package", value: "@bx-ui-framework/authentication@16.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9q5c-jq8f-775p, MAL-2026-15866 (amazon-inspector)", firstSeen: "2026-09-04" },
  { type: "package", value: "eslint-rxjs@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-45hh-8cg6-r5qp, MAL-2026-15812 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-02" },
  { type: "package", value: "n8n-nodes-social-facebook@0.2.0", severity: "critical", confidence: 0.9, source: "MAL-2026-10536 (amazon-inspector)", firstSeen: "2026-07-14" },

  // Imported from GitHub Advisory Database (2026-09-05) - see docs/threat-feed-sources.md
  { type: "package", value: "jwt-logger", severity: "critical", confidence: 0.9, source: "GHSA-rpqx-cp2g-55w5", firstSeen: "2026-09-05" },
  { type: "package", value: "array-scala", severity: "critical", confidence: 0.9, source: "GHSA-rx3f-9hxc-773g", firstSeen: "2026-09-05" },
  { type: "package", value: "pypi:trongridew@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-vjjx-756v-6p3x, MAL-2026-15936 (kam193)", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/i18n", severity: "critical", confidence: 0.9, source: "GHSA-22jr-v88r-5cj6", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/reactive", severity: "critical", confidence: 0.9, source: "GHSA-3ggc-3pw2-c9v9", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/router", severity: "critical", confidence: 0.9, source: "GHSA-j7wp-3648-mh57", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/mask", severity: "critical", confidence: 0.9, source: "GHSA-93j2-q7r7-7qhh", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/throttle", severity: "critical", confidence: 0.9, source: "GHSA-fr62-p59g-hr9f", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/intersect", severity: "critical", confidence: 0.9, source: "GHSA-v8xv-9q46-8h3x", firstSeen: "2026-09-05" },
  { type: "package", value: "@yoannchb/wtf-json", severity: "critical", confidence: 0.9, source: "GHSA-82x7-44x9-7295", firstSeen: "2026-09-05" },
  { type: "package", value: "enqueu", severity: "critical", confidence: 0.9, source: "GHSA-352p-f6j8-qxxh", firstSeen: "2026-09-05" },
  { type: "package", value: "puppeteer-obscura", severity: "critical", confidence: 0.9, source: "GHSA-cxwq-q9c5-424v", firstSeen: "2026-09-05" },
  { type: "package", value: "inner-svg-ts", severity: "critical", confidence: 0.9, source: "GHSA-rx43-xhjx-3xq6", firstSeen: "2026-09-05" },
  { type: "package", value: "pipipe", severity: "critical", confidence: 0.9, source: "GHSA-pmm9-p62g-hvp5", firstSeen: "2026-09-05" },
  { type: "package", value: "@yoannchb/tokenize", severity: "critical", confidence: 0.9, source: "GHSA-4qx6-wqw8-r2qr", firstSeen: "2026-09-05" },
  { type: "package", value: "chrome-speech-recognition", severity: "critical", confidence: 0.9, source: "GHSA-wvfg-ghw3-64q7", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/domy", severity: "critical", confidence: 0.9, source: "GHSA-f553-q356-4cmc", firstSeen: "2026-09-05" },
  { type: "package", value: "drive-album", severity: "critical", confidence: 0.9, source: "GHSA-xwpg-4hvv-jxjq", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/debounce", severity: "critical", confidence: 0.9, source: "GHSA-pp6m-2fxr-qjhf", firstSeen: "2026-09-05" },
  { type: "package", value: "card3d", severity: "critical", confidence: 0.9, source: "GHSA-gggp-h9vj-pw3p", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/anchor", severity: "critical", confidence: 0.9, source: "GHSA-x2rm-5qrx-62mg", firstSeen: "2026-09-05" },
  { type: "package", value: "parallaxy-img", severity: "critical", confidence: 0.9, source: "GHSA-mhp3-rpvj-vrpx", firstSeen: "2026-09-05" },
  { type: "package", value: "@yoannchb/langy", severity: "critical", confidence: 0.9, source: "GHSA-92qv-fgvj-ccf4", firstSeen: "2026-09-05" },
  { type: "package", value: "@domyjs/collapse", severity: "critical", confidence: 0.9, source: "GHSA-39q9-7vqg-3m6w", firstSeen: "2026-09-05" },
  { type: "package", value: "iframe-to-video", severity: "critical", confidence: 0.9, source: "GHSA-hh9g-3hm5-vcch", firstSeen: "2026-09-05" },
  { type: "package", value: "@yoannchb/cattract", severity: "critical", confidence: 0.9, source: "GHSA-76pv-jq47-p439", firstSeen: "2026-09-05" },
  { type: "package", value: "jimg", severity: "critical", confidence: 0.9, source: "GHSA-53xc-j4p4-52q3", firstSeen: "2026-09-05" },
  { type: "package", value: "tempjs-template", severity: "critical", confidence: 0.9, source: "GHSA-5x3v-r6fj-vf2p", firstSeen: "2026-09-05" },
  { type: "package", value: "memov", severity: "critical", confidence: 0.9, source: "GHSA-6q78-8863-ww8m", firstSeen: "2026-09-05" },
  { type: "package", value: "muswish", severity: "critical", confidence: 0.9, source: "GHSA-295f-26rf-f8f4", firstSeen: "2026-09-05" },
  { type: "package", value: "btn-particles", severity: "critical", confidence: 0.9, source: "GHSA-6w56-62pq-vhph", firstSeen: "2026-09-05" },
  { type: "package", value: "onetime-rnd", severity: "critical", confidence: 0.9, source: "GHSA-55h6-2qxg-jvqv", firstSeen: "2026-09-05" },
  { type: "package", value: "google-img-scrap", severity: "critical", confidence: 0.9, source: "GHSA-mwh7-p59x-2f4g", firstSeen: "2026-09-05" },
  { type: "package", value: "json-into-html", severity: "critical", confidence: 0.9, source: "GHSA-xvrp-hmjm-74qr", firstSeen: "2026-09-05" },
  { type: "package", value: "fast-html-dom-parser", severity: "critical", confidence: 0.9, source: "GHSA-4wcx-wjq9-25cr", firstSeen: "2026-09-05" },
  { type: "package", value: "discord-tqr", severity: "critical", confidence: 0.9, source: "GHSA-xp88-72h6-mw9r", firstSeen: "2026-09-05" },
  { type: "package", value: "anime-vostfr", severity: "critical", confidence: 0.9, source: "GHSA-f6c5-36x2-p79p", firstSeen: "2026-09-05" },
  { type: "package", value: "infinity-grid", severity: "critical", confidence: 0.9, source: "GHSA-39fr-j2vr-r24p", firstSeen: "2026-09-05" },
  { type: "package", value: "discord-phub", severity: "critical", confidence: 0.9, source: "GHSA-7693-gh38-7wmj", firstSeen: "2026-09-05" },
  { type: "package", value: "linkpreview-simple", severity: "critical", confidence: 0.9, source: "GHSA-w9q9-gr86-rr73", firstSeen: "2026-09-05" },
  { type: "package", value: "lazy-attr", severity: "critical", confidence: 0.9, source: "GHSA-pm6r-2g8f-89qh", firstSeen: "2026-09-05" },
  { type: "package", value: "trading-bot-utils", severity: "critical", confidence: 0.9, source: "GHSA-2h3c-rw6j-mpq7", firstSeen: "2026-09-05" },
  { type: "package", value: "eth-query-utils", severity: "critical", confidence: 0.9, source: "GHSA-c33f-ppxr-8r7j", firstSeen: "2026-09-05" },
  { type: "package", value: "ens-namehash-utils", severity: "critical", confidence: 0.9, source: "GHSA-qfrg-2m38-35gp", firstSeen: "2026-09-05" },
  { type: "package", value: "gas-price-checker", severity: "critical", confidence: 0.9, source: "GHSA-fw8f-xwq4-q3v8", firstSeen: "2026-09-05" },
  { type: "package", value: "wallet-watcher", severity: "critical", confidence: 1.0, source: "GHSA-jq3q-655j-wjqh, MAL-2026-15871", firstSeen: "2026-09-05" },
  { type: "package", value: "eth-lib-helpers", severity: "critical", confidence: 0.9, source: "GHSA-h3xf-4f7r-v9xf", firstSeen: "2026-09-05" },
  { type: "package", value: "pypi:proxycer@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-qff6-cqrr-65wv, MAL-2026-15935 (kam193)", firstSeen: "2026-09-05" },
  { type: "package", value: "pypi:dbt-sa-cli@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-xf8p-r8w2-fx5m, MAL-2026-15934 (kam193)", firstSeen: "2026-09-05" },

  // Imported from GitHub Advisory Database (2026-09-07) - see docs/threat-feed-sources.md
  { type: "package", value: "scw-mobile", severity: "critical", confidence: 0.9, source: "GHSA-h9g8-rwcg-hpmh", firstSeen: "2026-09-07" },
  { type: "package", value: "base-account-core", severity: "critical", confidence: 0.9, source: "GHSA-vgm8-2vf8-769j", firstSeen: "2026-09-07" },
  { type: "package", value: "cb-wallet-solana-provider", severity: "critical", confidence: 0.9, source: "GHSA-5cg4-38v4-j4vc", firstSeen: "2026-09-07" },
  { type: "package", value: "cb-wallet-metadata", severity: "critical", confidence: 0.9, source: "GHSA-cxwc-958j-45g8", firstSeen: "2026-09-07" },
  { type: "package", value: "cb-wallet-http", severity: "critical", confidence: 1.0, source: "GHSA-mv3f-92cr-83h7, MAL-2026-4507", firstSeen: "2026-09-07" },
  { type: "package", value: "cb-wallet-store", severity: "critical", confidence: 0.9, source: "GHSA-gw4f-3mgw-h64x", firstSeen: "2026-09-07" },
  { type: "package", value: "base-app-data", severity: "critical", confidence: 0.9, source: "GHSA-9hpg-rmwp-vg4p", firstSeen: "2026-09-07" },
  { type: "package", value: "wallet-engine-signing", severity: "critical", confidence: 0.9, source: "GHSA-qw4m-ccr9-7r43", firstSeen: "2026-09-07" },
  { type: "package", value: "cb-wallet-env", severity: "critical", confidence: 0.9, source: "GHSA-m477-pr6m-v2fp", firstSeen: "2026-09-07" },
  { type: "package", value: "cb-wallet-analytics", severity: "critical", confidence: 0.9, source: "GHSA-7944-c265-3ff7", firstSeen: "2026-09-07" },
  { type: "package", value: "cb-wallet-data", severity: "critical", confidence: 1.0, source: "GHSA-7w56-x3g2-57fg, MAL-2026-4506", firstSeen: "2026-09-07" },
  { type: "package", value: "scw-core", severity: "critical", confidence: 0.9, source: "GHSA-fv48-xvcx-h3qh", firstSeen: "2026-09-07" },
  { type: "package", value: "wallet-cds-web", severity: "critical", confidence: 0.9, source: "GHSA-qh9w-32r6-2qpw", firstSeen: "2026-09-07" },
  // Dependency-confusion placeholder campaign, maintainer pr0t31n (September 2026) - siblings above
  { type: "package", value: "omni-channel-oid-frontend@0.0.1", severity: "critical", confidence: 0.9, source: "GHSA-fc5v-8w4f-376c, MAL-2026-15939 (ossf-package-analysis)", firstSeen: "2026-09-06" },
  { type: "package", value: "omni-channel-oid-frontend@9999.0.0", severity: "critical", confidence: 0.9, source: "GHSA-fc5v-8w4f-376c, MAL-2026-15939 (ossf-package-analysis)", firstSeen: "2026-09-06" },
  { type: "package", value: "ocfe-tv-subscription-center-web@0.0.1", severity: "critical", confidence: 0.9, source: "GHSA-4qgp-r5m8-8876, MAL-2026-15941 (ossf-package-analysis)", firstSeen: "2026-09-06" },
  { type: "package", value: "ocfe-tv-subscription-center-web@9999.0.0", severity: "critical", confidence: 0.9, source: "GHSA-4qgp-r5m8-8876, MAL-2026-15941 (ossf-package-analysis)", firstSeen: "2026-09-06" },
  { type: "package", value: "pypi:minecraftmodes@0.3.3", severity: "critical", confidence: 0.9, source: "GHSA-m6v9-5p34-2x37, MAL-2026-15937 (kam193)", firstSeen: "2026-09-06" },

  // Imported from GitHub Advisory Database (2026-08-25) - see docs/threat-feed-sources.md
  { type: "package", value: "krdpass-auth-react-native", severity: "critical", confidence: 1.0, source: "GHSA-3j7p-44mj-76hx, MAL-2026-16042", firstSeen: "2026-09-08" },
  { type: "package", value: "pypi:telegram-helper@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-vxg4-4jxm-7ff9, MAL-2026-16017 (kam193)", firstSeen: "2026-09-07" },
  { type: "package", value: "pypi:telegram-helper@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-vxg4-4jxm-7ff9, MAL-2026-16017 (kam193)", firstSeen: "2026-09-07" },
  { type: "package", value: "@cp-shared-14/frontend-ui@6.3.4", severity: "critical", confidence: 1.0, source: "GHSA-3f8m-gfc3-3g2m, MAL-2026-16015 (ossf-package-analysis)", firstSeen: "2026-09-07" },
  { type: "package", value: "pypi:cv-train@0.0.5", severity: "critical", confidence: 1.0, source: "GHSA-8q25-v7xh-4xvp, MAL-2026-16016 (kam193)", firstSeen: "2026-09-07" },
  { type: "package", value: "pypi:cv-train@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8q25-v7xh-4xvp, MAL-2026-16016 (kam193)", firstSeen: "2026-09-07" },
  { type: "package", value: "@aircanada/components", severity: "critical", confidence: 0.9, source: "GHSA-w6c3-rrw8-wxrx, MAL-2026-16018 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "@aircanada/core", severity: "critical", confidence: 0.9, source: "GHSA-46mp-56rw-qpmm, MAL-2026-16019 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "@aircanada/navigation-handler", severity: "critical", confidence: 0.9, source: "GHSA-356v-pcf2-7958, MAL-2026-16020 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "service-home", severity: "critical", confidence: 0.9, source: "GHSA-m2c9-2v7c-fxf9, MAL-2026-16039 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "op-ts-server-core", severity: "critical", confidence: 0.9, source: "GHSA-cj4c-268v-m597, MAL-2026-16034 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "@idkruan-10/dpd-depconf-probe", severity: "critical", confidence: 0.9, source: "GHSA-994q-v55m-r2mw, MAL-2026-16021 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "redis-type-intel", severity: "critical", confidence: 0.9, source: "GHSA-v9rh-vg7p-gwqm, MAL-2026-16036 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "oscar-redis", severity: "critical", confidence: 0.9, source: "GHSA-c6m6-wr2f-6f63, MAL-2026-16035 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "kiki-baileys", severity: "critical", confidence: 0.9, source: "GHSA-g8cr-3r7q-pcr6, MAL-2026-16033 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "feishu-docx-mcp", severity: "critical", confidence: 0.9, source: "GHSA-q5c6-p5q5-g3px, MAL-2026-16032 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "blueai-cli", severity: "critical", confidence: 0.9, source: "GHSA-c2v5-8c2f-jj54, MAL-2026-16024 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "bmc-i18n-extract-cli", severity: "critical", confidence: 0.9, source: "GHSA-327g-rcr8-hp3p, MAL-2026-16025 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "bmc-translate-utils", severity: "critical", confidence: 0.9, source: "GHSA-997w-vpm2-ww7x, MAL-2026-16026 (ghsa-malware)", firstSeen: "2026-09-07" },
  { type: "package", value: "omni-channel-configurator-wireline-frontend", severity: "critical", confidence: 1.0, source: "GHSA-p429-pvx5-xj55, MAL-2026-16009", firstSeen: "2026-09-07" },
  { type: "package", value: "b2b-frontend-external-library", severity: "critical", confidence: 1.0, source: "GHSA-hmhj-jhrj-285j, MAL-2026-16008", firstSeen: "2026-09-07" },
  { type: "package", value: "@caliperx2/components", severity: "critical", confidence: 1.0, source: "GHSA-4jpr-935q-33r2, MAL-2026-16007", firstSeen: "2026-09-07" },

  // Web3 dev-tooling typosquat campaign, npm accounts ethcompat / sazuki (CYFIRMA,
  // June 11 2026). Eleven packages impersonating Ethereum, Coinbase, Moralis, Hardhat
  // and Stellar tooling; the postinstall stage steals wallet keys, mnemonics and CI
  // secrets and resolves its C2 from an Ethereum contract. Nine of the eleven were
  // STILL live and installable when this was ingested, which is why the block is worth
  // carrying rather than treating as history.
  //
  // Name-blocked, not version-pinned: each name below is either a security-holding stub
  // (ethers-jss, coinbase-wallet-utils, both taken down by npm, so nothing legitimate can
  // be hit) or a single-version package published by a throwaway account whose only
  // release is the malicious one, with the description copied verbatim from the tool it
  // impersonates. moralis-sdk is the one exception and is version-pinned in
  // KNOWN_BAD_NPM_VERSIONS instead, because it has a release the write-up does not name.
  //
  // Single-vendor write-up, so confidence is 0.85 throughout, except moralis-sdk@1.0.1
  // and the two taken-down names, where the npm registry independently corroborates.
  { type: "package", value: "ethers-jss", severity: "critical", confidence: 1.0, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA, npm registry takedown", firstSeen: "2026-06-11" },
  { type: "package", value: "coinbase-wallet-utils", severity: "critical", confidence: 1.0, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA, npm registry takedown", firstSeen: "2026-06-11" },
  { type: "package", value: "moralis-sdk@1.0.1", severity: "critical", confidence: 1.0, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA, npm registry", firstSeen: "2026-06-11" },
  { type: "package", value: "ganach", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "package", value: "solidty", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "package", value: "stelar-sdk", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "package", value: "hardhat-deploy-utils", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "package", value: "web3-deploy-helper", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "package", value: "defi-sdk-core", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "package", value: "ethers-compat", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "package", value: "ethereum-dev-utils", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "ip", value: "193.233.201.21", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "url", value: "pastefy.app/RhPBKGli/raw", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "hash", value: "d94a2444268b339dfda2615f7800322fb318e0a484414bb17016cfcd5eb07c44", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "hash", value: "6585ca0d3e26c20ced638f46f4a89eea924d411b8753d3fcf434663593c7cf0b", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },
  { type: "hash", value: "17bad5ae5b2ac262f5f18854853869840245c344105aa38c7f550ef51d2e5f26", severity: "critical", confidence: 0.85, campaign: "Web3 Dev-Tooling Typosquat", source: "CYFIRMA (single-source)", firstSeen: "2026-06-11" },

  // Fifth member of the AI-coding-CLI impersonation campaign by the npm account
  // imjustbetterxd, whose other four packages this same run imported from GHSA
  // (orbitron-tui, orbitron-cli, agent-free, prime-coding-agent - all published
  // 2026-09-07 with vulnerable_version_range "> 0", i.e. the whole package). Those four
  // advisories describe the campaign as "five AI-coding-CLI impersonations"; this is the
  // fifth. It has no GHSA, only an OpenSSF record, so the rolling 14-day advisory window
  // cannot reach it and the daily importer never proposes it.
  //
  // Name-blocked although MAL-2026-4533 enumerates versions, because the enumeration is
  // NARROWER than the malware set: the name has 41 published versions, every one of them
  // from imjustbetterxd, and only 29 are flagged. Pinning the 29 would leave 12 releases
  // by the same malware author undetected. There is no legitimate history under this name
  // to protect - the package it impersonates is `codebuff`, which is a different name with
  // a different maintainer set entirely.
  { type: "package", value: "codebuff-cli", severity: "critical", confidence: 1.0, campaign: "AI-Coding-CLI Impersonation", source: "MAL-2026-4533 (Amazon Inspector + codelake Research), npm registry", firstSeen: "2026-05-22" },

  // Imported from GitHub Advisory Database (2026-08-26) - see docs/threat-feed-sources.md
  { type: "package", value: "reactlogo-load@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-x694-g6xc-wfjv, MAL-2026-16069 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@fyxzpediaa/baileys@8.1.2", severity: "critical", confidence: 1.0, source: "GHSA-5wxh-fwcf-rv5j, MAL-2026-16070 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "external_deps_enjoyer@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-675v-pqp8-v3wg, MAL-2026-16076 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "easypanel-hosting@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h9xg-5pcf-4xf2, MAL-2026-16075 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "easypanel-deploy@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-m564-m3c9-3gp4, MAL-2026-16074 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "easypanel-agent@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-p4x3-628f-53f8, MAL-2026-16072 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "easypanel-api-client@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-p4hx-gwfg-7g7p, MAL-2026-16073 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "cat-sis2go-utils@99.1.0", severity: "critical", confidence: 1.0, source: "GHSA-h64p-6fgg-pgm9, MAL-2026-16071 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "cat-sis2go-utils@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h64p-6fgg-pgm9, MAL-2026-16071 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "sonmors@2.11.2", severity: "critical", confidence: 1.0, source: "GHSA-vp67-pvcp-4j8j, MAL-2026-16055 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "vinzz-wcli@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-xv3f-69vw-grmg, MAL-2026-16058 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "toru-ultimate@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jg37-3w86-3rx2, MAL-2026-16057 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "gloggo@1.1.3", severity: "critical", confidence: 1.0, source: "GHSA-wmgg-555m-p7h6, MAL-2026-16054 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "gloggo@1.1.4", severity: "critical", confidence: 1.0, source: "GHSA-wmgg-555m-p7h6, MAL-2026-16054 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "gloggo@1.1.2", severity: "critical", confidence: 1.0, source: "GHSA-wmgg-555m-p7h6, MAL-2026-16054 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "tailwind-aspect-styles@0.4.2", severity: "critical", confidence: 1.0, source: "GHSA-r28r-839h-4gqw, MAL-2026-16056 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "file-type-detector@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-cjhh-g8v5-hg5g, MAL-2026-16053 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "file-type-detector@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-cjhh-g8v5-hg5g, MAL-2026-16053 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "rojo-rbx@1.4.3", severity: "critical", confidence: 1.0, source: "GHSA-p55w-6rww-5frg, MAL-2026-16059 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "selfcerts@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2cj2-qj4h-42hp, MAL-2026-16060 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "express-session-timer@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-xf4h-cmpp-qfvf, MAL-2026-16065 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "express-session-timer@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-xf4h-cmpp-qfvf, MAL-2026-16065 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "express-session-timer@1.0.13", severity: "critical", confidence: 1.0, source: "GHSA-xf4h-cmpp-qfvf, MAL-2026-16065 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "express-session-timer@1.0.14", severity: "critical", confidence: 1.0, source: "GHSA-xf4h-cmpp-qfvf, MAL-2026-16065 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "express-session-timer@1.0.16", severity: "critical", confidence: 1.0, source: "GHSA-xf4h-cmpp-qfvf, MAL-2026-16065 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "bx-ui-view@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-hqg3-m33m-mvcr, MAL-2026-16064 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@yongot/canary-mcp-test@3.0.0", severity: "critical", confidence: 1.0, source: "GHSA-469r-xxvx-62x3, MAL-2026-16062 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@yongot/canary-mcp-test@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-469r-xxvx-62x3, MAL-2026-16062 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@yongot/canary-mcp-test@4.0.0", severity: "critical", confidence: 1.0, source: "GHSA-469r-xxvx-62x3, MAL-2026-16062 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@yongot/canary-mcp-isolation@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-7gq6-vvhp-97f4, MAL-2026-16061 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "alloy-graphql@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-5xmm-9965-mvqw, MAL-2026-16063 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@versacode/baileys", severity: "critical", confidence: 0.9, source: "GHSA-fw7g-gr3j-7wf7, MAL-2026-16068 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "@vallensofficial/baileys", severity: "critical", confidence: 0.9, source: "GHSA-gg93-mm5f-23v8, MAL-2026-16067 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "@haimiya/baileys", severity: "critical", confidence: 0.9, source: "GHSA-q246-72rh-fp8w, MAL-2026-16066 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "open-item-validator@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-jfq9-9hf7-gr4x, MAL-2026-16052 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "open-item-validator@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-jfq9-9hf7-gr4x, MAL-2026-16052 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "tailwindcss-aspectratio-styles@0.3.5", severity: "critical", confidence: 1.0, source: "GHSA-4gjp-7xcv-m2gc, MAL-2026-16049 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "tailwindcss-aspectratio-styles@0.3.4", severity: "critical", confidence: 1.0, source: "GHSA-4gjp-7xcv-m2gc, MAL-2026-16049 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "punypump@1.2.4", severity: "critical", confidence: 1.0, source: "GHSA-45jc-2qr4-pmgf, MAL-2026-16048 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "punypump@1.2.5", severity: "critical", confidence: 1.0, source: "GHSA-45jc-2qr4-pmgf, MAL-2026-16048 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "punypump@1.2.2", severity: "critical", confidence: 1.0, source: "GHSA-45jc-2qr4-pmgf, MAL-2026-16048 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "@umschool/analytics@999.0.1", severity: "critical", confidence: 1.0, source: "GHSA-2qmq-f9mj-rwcj, MAL-2026-16051 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "@umschool/analytics@999.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2qmq-f9mj-rwcj, MAL-2026-16051 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "@umschool/analytics@999.0.2", severity: "critical", confidence: 1.0, source: "GHSA-2qmq-f9mj-rwcj, MAL-2026-16051 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "@umschool/analytics@999.0.4", severity: "critical", confidence: 1.0, source: "GHSA-2qmq-f9mj-rwcj, MAL-2026-16051 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "@umschool/analytics@999.0.3", severity: "critical", confidence: 1.0, source: "GHSA-2qmq-f9mj-rwcj, MAL-2026-16051 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "@aspect-adv-ui/consent-manager@2.4.0", severity: "critical", confidence: 1.0, source: "GHSA-2m5c-v74g-r4m8, MAL-2026-16050 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "@aspect-adv-ui/consent-manager@2.4.1", severity: "critical", confidence: 1.0, source: "GHSA-2m5c-v74g-r4m8, MAL-2026-16050 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "@usemosaik/template-react-js@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-8rcc-9ggm-659p, MAL-2026-16047 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-08" },
  { type: "package", value: "i18nexus-tools", severity: "critical", confidence: 1.0, source: "GHSA-9cfw-xh4g-cc2f, MAL-2026-16046 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-08" },
  { type: "package", value: "i18nexus", severity: "critical", confidence: 0.9, source: "GHSA-38hw-f37p-99jj, MAL-2026-16045 (ghsa-malware)", firstSeen: "2026-09-08" },
  { type: "package", value: "@web2apk/baileys", severity: "critical", confidence: 1.0, source: "GHSA-f4f2-cqqp-jcrx, MAL-2026-16043 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-08" },
  { type: "package", value: "cache-cleanup-module@2.6.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16078 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "cache-cleanup-module@2.5.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16078 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "open-item-validator@1.0.2", severity: "critical", confidence: 0.9, source: "MAL-2026-16052 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "open-item-validator@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16052 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "open-item-validator@1.0.4", severity: "critical", confidence: 0.9, source: "MAL-2026-16052 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "open-item-validator@1.0.1", severity: "critical", confidence: 0.9, source: "MAL-2026-16052 (amazon-inspector)", firstSeen: "2026-09-08" },
  { type: "package", value: "server-authorized-cleanup@1.1.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16079 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "chai-as-sleek@7.1.2", severity: "critical", confidence: 0.9, source: "MAL-2026-16077 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "pypi:databricks-webapp-navigation-homepage@999.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16080 (kam193)", firstSeen: "2026-09-09" },
  // Baileys WhatsApp fork channel-farming campaign, skyzopedia leg (Xygeni, September
  // 2026). Single-source, hence confidence 0.85. The two scoped names are bare rather
  // than version-pinned because npm has already taken both down as security holding
  // packages, so no legitimate release can be hit; cloud-baileys is live with a real
  // maintainer and is version-pinned to the two releases the write-up names.
  { type: "url", value: "raw.githubusercontent.com/skyzopedia/Screaper/refs/heads/main/idChannel.json", severity: "critical", confidence: 0.85, source: "Xygeni (single-source)", firstSeen: "2026-09-09" },
  { type: "package", value: "@dappaoffc/baileys-mod", severity: "critical", confidence: 0.85, source: "Xygeni (single-source)", firstSeen: "2026-09-09" },
  { type: "package", value: "@skyzopedia/libsignal-node", severity: "critical", confidence: 0.85, source: "Xygeni (single-source)", firstSeen: "2026-09-09" },
  { type: "package", value: "cloud-baileys@1.1.37", severity: "critical", confidence: 0.85, source: "Xygeni digest 86 (single-source)", firstSeen: "2026-09-09" },
  { type: "package", value: "cloud-baileys@1.1.38", severity: "critical", confidence: 0.85, source: "Xygeni digest 86 (single-source)", firstSeen: "2026-09-09" },

  // Imported from GitHub Advisory Database (2026-08-27) - see docs/threat-feed-sources.md
  { type: "package", value: "@sahril2nd/baileys@1.0.21", severity: "critical", confidence: 1.0, source: "GHSA-j2h4-4g8c-mqh9, MAL-2026-16105 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@neroxkira/vangal-baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8g69-mcxv-f88g, MAL-2026-16103 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@neroxkira/vangal-baileys@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-8g69-mcxv-f88g, MAL-2026-16103 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@nexustechpro/baileys@2.2.7", severity: "critical", confidence: 1.0, source: "GHSA-pv55-pgr3-jjrj, MAL-2026-16104 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@auction-fe/reporting-system", severity: "critical", confidence: 0.9, source: "GHSA-4x79-pcqv-r9rf, MAL-2026-16108 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "@auction-fe/base", severity: "critical", confidence: 0.9, source: "GHSA-w6hj-c25h-wgh7, MAL-2026-16106 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "@auction-fe/ui-kit", severity: "critical", confidence: 0.9, source: "GHSA-2r37-886p-hj65, MAL-2026-16109 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "@auction-fe/portal", severity: "critical", confidence: 0.9, source: "GHSA-qmw2-mp2f-cgg3, MAL-2026-16107 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "@convertics/script", severity: "critical", confidence: 0.9, source: "GHSA-c74p-4c5p-6v9r, MAL-2026-16110 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "pypi:bq-build-probe-vrp-2026@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-f69f-h5mx-9x8p, MAL-2026-16098 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "pypi:bq-sdist-probe-vrp@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-xhgv-6q3g-2824, MAL-2026-16099 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "mfatest2@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2cf3-8wq3-f2xq, MAL-2026-16102 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "mfaby@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-x3f6-cx35-q6mw, MAL-2026-16101 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "discord-mfa-solver@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-f5p4-vw6q-5w28, MAL-2026-16100 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "discord-mfa-solver@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-f5p4-vw6q-5w28, MAL-2026-16100 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "discord-mfa-solver@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-f5p4-vw6q-5w28, MAL-2026-16100 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@umschool/platform@999.0.2", severity: "critical", confidence: 1.0, source: "GHSA-vj55-82hp-jrcm, MAL-2026-16082 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@umschool/platform@999.0.1", severity: "critical", confidence: 1.0, source: "GHSA-vj55-82hp-jrcm, MAL-2026-16082 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@umschool/platform@999.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vj55-82hp-jrcm, MAL-2026-16082 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "twilio-hackerone-poc-b8f21a@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-wpq4-r5p3-386q, MAL-2026-16097 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "twilio-hackerone-poc-b8f21a@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wpq4-r5p3-386q, MAL-2026-16097 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "@staticj/cropperxmjs@1.6.0", severity: "critical", confidence: 1.0, source: "GHSA-8vj5-qr9w-p6p2, MAL-2026-16081 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "soltinel-pro@0.2.1", severity: "critical", confidence: 1.0, source: "GHSA-69g5-q5j6-cxx4, MAL-2026-16096 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "soltinel-pro@0.2.2", severity: "critical", confidence: 1.0, source: "GHSA-69g5-q5j6-cxx4, MAL-2026-16096 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "soltinel-pro@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-69g5-q5j6-cxx4, MAL-2026-16096 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "matrixkit-js@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-j34m-r83h-m38q, MAL-2026-16095 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "gmgn-trading-kit@1.7.0", severity: "critical", confidence: 1.0, source: "GHSA-g6w4-rgw8-65r7, MAL-2026-16094 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "gmgn-trading-kit@1.7.1", severity: "critical", confidence: 1.0, source: "GHSA-g6w4-rgw8-65r7, MAL-2026-16094 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "gmgn-trading-kit@1.7.2", severity: "critical", confidence: 1.0, source: "GHSA-g6w4-rgw8-65r7, MAL-2026-16094 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "sams-text-style", severity: "critical", confidence: 0.9, source: "GHSA-xqx8-w483-rq8x, MAL-2026-16091 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "graphql-js-client-transform", severity: "critical", confidence: 0.9, source: "GHSA-xm59-fwxf-vq6g, MAL-2026-16086 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "sams-run-style", severity: "critical", confidence: 0.9, source: "GHSA-2r8h-5pr4-fr3v, MAL-2026-16090 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "polygon-toolkits-validator", severity: "critical", confidence: 1.0, source: "GHSA-cmwm-j5px-xrpf, MAL-2026-16087 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "raydium-clmm-sdk", severity: "critical", confidence: 0.9, source: "GHSA-cq4p-x9wg-m5wv, MAL-2026-16089 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "crypto-validates", severity: "critical", confidence: 0.9, source: "GHSA-v5v6-h869-g34f, MAL-2026-16085 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "pumpswap-sdk-v1", severity: "critical", confidence: 0.9, source: "GHSA-5qr5-f8q7-r844, MAL-2026-16088 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "vinnleys", severity: "critical", confidence: 1.0, source: "GHSA-p8f8-xjrg-2v4g, MAL-2026-16092 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "amprem-activator", severity: "critical", confidence: 1.0, source: "GHSA-4crw-26f5-4v62, MAL-2026-16084 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "xbailsync", severity: "critical", confidence: 1.0, source: "GHSA-vfrg-29g4-854p, MAL-2026-16093 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "@vnxsync/libsignal-node", severity: "critical", confidence: 0.9, source: "GHSA-369v-phqf-c9g9, MAL-2026-16083 (ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "@fyxzpediaa/baileys@9.1.0", severity: "critical", confidence: 1.0, source: "GHSA-5wxh-fwcf-rv5j, MAL-2026-16070 (amazon-inspector)", firstSeen: "2026-09-09" },
  // Baileys WhatsApp fork credential-theft campaign, lotusbail leg (December 2025).
  // An attacker-authored fork of @whiskeysockets/baileys published by a throwaway
  // account, which kept the real WhatsApp send/receive behaviour working while
  // exfiltrating auth tokens, session keys, message history, contacts and media,
  // and hijacked device linking with a hard-coded pairing code so access survived
  // uninstall. Roughly 56,000 downloads over about seven months. The advisory
  // affects ALL versions and npm has replaced the name with a security holding
  // package, so nothing legitimate can be hit by the bare name. Added by hand
  // because the advisory published 2025-12-23, outside the importer's 14-day
  // window, and no rule elsewhere in the scanner covered it. The upstream
  // WhiskeySockets Baileys maintainers are VICTIMS of the impersonation and are
  // deliberately NOT blocked. No C2 domain, IP or hash is addable: every vendor
  // report states the C2 destination is hidden behind Unicode variable mangling,
  // LZString, Base-91 and AES layers, and none published the decoded value.
  { type: "package", value: "lotusbail", severity: "critical", confidence: 1.0, source: "GHSA-qmh8-v4jq-m242, MAL-2025-192748 (osv+bleepingcomputer+securityweek+thehackernews)", firstSeen: "2025-12-23" },

  // Imported from GitHub Advisory Database (2026-09-11) - see docs/threat-feed-sources.md
  { type: "package", value: "daytona-test-miner", severity: "critical", confidence: 0.9, source: "GHSA-7fxg-v94h-8j5g", firstSeen: "2026-09-11" },
  { type: "package", value: "daytona-test-filereader", severity: "critical", confidence: 0.9, source: "GHSA-f2vx-rj2m-pmp8", firstSeen: "2026-09-11" },
  { type: "package", value: "daytona-test-npm", severity: "critical", confidence: 0.9, source: "GHSA-j8pm-8rv6-xg64", firstSeen: "2026-09-11" },
  // eToro dependency-confusion reconnaissance (GitHub Advisory Database / OpenSSF
  // via amazon-inspector, September 10, 2026). Ten public namesakes of eToro-internal
  // npm packages, every one published at the single lure version 999.0.0 with an empty
  // library stub and a preinstall beacon. The registry settles the shape: all ten were
  // created inside a 31-second window on 2026-09-10 at about 04:02 UTC and unpublished
  // by 04:45, so this is one automated batch, and nothing legitimate has ever occupied
  // these names. Version-pinned rather than name-blocked, because a 999.0.0 lure is the
  // finding and eToro may later publish these names itself. preinstall.js sends an
  // unauthenticated plaintext GET to hxxp://209[.]126[.]81[.]147/etoro-depconf-poce346552f776f/npm/
  // carrying the installer's hostname, username and cwd as path segments.
  { type: "ip", value: "209.126.81.147", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-cp95-g9vf-h9mc, MAL-2026-16114 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "url", value: "209.126.81.147/etoro-depconf-poce346552f776f/npm/", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-cp95-g9vf-h9mc, MAL-2026-16114 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-aggregator@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-qj36-g77p-6w4c, MAL-2026-16111 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-analytics@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-wgc5-frwf-f4r9, MAL-2026-16112 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-api@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-jhx2-c8c9-77m4, MAL-2026-16113 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-auth@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-cp95-g9vf-h9mc, MAL-2026-16114 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-billing@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-6qw8-8vc7-fmj4, MAL-2026-16115 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-builders@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-642v-mmwv-fj8c, MAL-2026-16116 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-cashout@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-4jmj-qv75-33m2, MAL-2026-16117 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-charts@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-rmph-mjrh-89x3, MAL-2026-16118 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-client@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-hcqp-jmx5-mrwx, MAL-2026-16119 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-core@999.0.0", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-9vfj-6pvw-qrqr, MAL-2026-16120 (amazon-inspector)", firstSeen: "2026-09-10" },

  // tailwindcss-contact-forms - @tailwindcss/forms impersonation with an Ethereum
  // dead-drop (GitHub Advisory Database / OpenSSF via amazon-inspector, September 10,
  // 2026). README, repository field and install docs are copied verbatim from
  // @tailwindcss/forms, but the only module is an obfuscator.io-obfuscated loader that
  // imports node:child_process and reads the transaction list of a hardcoded Ethereum
  // address as C2 signalling. The address is in KNOWN_C2_WALLETS; the feed has no wallet
  // type. The public Ethereum RPC providers it enumerates (drpc[.]org, publicnode[.]com,
  // blockscout, blastapi[.]io) are legitimate shared infrastructure and are NOT listed.
  // The exfil endpoint is reassembled from string-array fragments and only its "ut.com/api"
  // tail was recovered, which is not an ingestable value, so it is deliberately omitted.
  // Name-blocked AND version-pinned: the registry shows a security holding stub with no
  // maintainer and ELEVEN unpublished versions (0.5.2 through 0.6.2), a WIDER set than the
  // 0.5.4-0.6.0 the advisory pinned, so the bare name is the accurate call and the pins
  // are the advisory's own narrower claim kept alongside it.
  { type: "package", value: "tailwindcss-contact-forms", severity: "critical", confidence: 1.0, source: "GHSA-844c-c6gj-g72x, MAL-2026-16124", firstSeen: "2026-09-10" },
  { type: "package", value: "tailwindcss-contact-forms@0.5.4", severity: "critical", confidence: 1.0, source: "GHSA-h9xr-6q2x-2v47, MAL-2026-16124 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "tailwindcss-contact-forms@0.5.5", severity: "critical", confidence: 1.0, source: "GHSA-h9xr-6q2x-2v47, MAL-2026-16124 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "tailwindcss-contact-forms@0.5.6", severity: "critical", confidence: 1.0, source: "GHSA-h9xr-6q2x-2v47, MAL-2026-16124 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "tailwindcss-contact-forms@0.5.7", severity: "critical", confidence: 1.0, source: "GHSA-h9xr-6q2x-2v47, MAL-2026-16124 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "tailwindcss-contact-forms@0.5.8", severity: "critical", confidence: 1.0, source: "GHSA-h9xr-6q2x-2v47, MAL-2026-16124 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "tailwindcss-contact-forms@0.5.9", severity: "critical", confidence: 1.0, source: "GHSA-h9xr-6q2x-2v47, MAL-2026-16124 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "tailwindcss-contact-forms@0.6.0", severity: "critical", confidence: 1.0, source: "GHSA-h9xr-6q2x-2v47, MAL-2026-16124 (amazon-inspector)", firstSeen: "2026-09-10" },

  // pinochiomathm - picomatch impersonation staging an AES-wrapped payload from a
  // JSONKeeper paste (GitHub Advisory Database / OpenSSF via amazon-inspector,
  // September 10, 2026). The loader base64-decodes lib/parse.ts.map into parsetmp.js,
  // GETs hxxps://www[.]jsonkeeper[.]com/b/V6NBX with a decoded x-secret-key header,
  // AES-256-CBC-decrypts the response with a hardcoded password and eval()s the
  // plaintext, then unlinks the staged files. Only the attacker's own paste PATH is
  // listed. www[.]jsonkeeper[.]com is a legitimate JSON-paste service and its apex stays
  // unlisted, which is the same call the July 2026 Contagious Interview entry made - the
  // difference is that this advisory published the specific paste id, so the narrow
  // indicator exists here and did not there. micromatch/picomatch are the VICTIMS of the
  // impersonation and are not touched.
  { type: "url", value: "www.jsonkeeper.com/b/V6NBX", severity: "critical", confidence: 1.0, source: "GHSA-cq4w-8cp6-cmvf, MAL-2026-16123 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "pinochiomathm@2.3.2", severity: "critical", confidence: 1.0, source: "GHSA-cq4w-8cp6-cmvf, MAL-2026-16123 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "pinochiomathm@2.3.3", severity: "critical", confidence: 1.0, source: "GHSA-cq4w-8cp6-cmvf, MAL-2026-16123 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "pinochiomathm@2.3.4", severity: "critical", confidence: 1.0, source: "GHSA-cq4w-8cp6-cmvf, MAL-2026-16123 (amazon-inspector)", firstSeen: "2026-09-10" },
  { type: "package", value: "pinochiomathm@2.3.5", severity: "critical", confidence: 1.0, source: "GHSA-cq4w-8cp6-cmvf, MAL-2026-16123 (amazon-inspector)", firstSeen: "2026-09-10" },

  // pypi:websetup - file exfiltration to a Discord webhook (GitHub Advisory Database /
  // OpenSSF via amazon-inspector, September 9, 2026). setup.set() POSTs arbitrary text
  // and the contents of any local file path to a hardcoded Discord webhook whose name
  // Discord itself returns as "backdoor". Nothing runs on install or import. Only the
  // webhook ID PATH is listed, never the discord[.]com apex; the advisory published the
  // id but not the token, and KNOWN_DEAD_DROPS is substring-matched, so the id prefix
  // still matches the full URL in a scanned file. This is the one indicator in today's
  // batch that is still LIVE: PyPI serves websetup 0.1.0 today, so the pin can fire.
  { type: "url", value: "discord.com/api/webhooks/1546817174411288617", severity: "critical", confidence: 1.0, source: "GHSA-v8mm-56q4-h26q, MAL-2026-16121 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "pypi:websetup@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-v8mm-56q4-h26q, MAL-2026-16121 (amazon-inspector)", firstSeen: "2026-09-09" },

  // pypi:pylever - Discord token stealer (GitHub Advisory Database / OpenSSF via
  // amazon-inspector and kam193, campaign 2026-09-pylever, September 10, 2026).
  // Version-pinned across the twelve releases the advisory names. PyPI returns 404 for
  // the name today, so nothing installable is behind it.
  { type: "package", value: "pypi:pylever@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.7", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.8", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.9", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.10", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.11", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:pylever@1.0.12", severity: "critical", confidence: 1.0, source: "GHSA-x38c-f232-xj2x, MAL-2026-16122 (amazon-inspector+kam193)", firstSeen: "2026-09-10" },

  // pypi:lucy-python-script-2030 - browser-data and cloud-credential infostealer on
  // import (GitHub Advisory Database / OpenSSF via kam193, campaign
  // 2026-09-lucy-python-script-2030, September 10, 2026). kam193 notes the shipped code
  // carries mistakes that effectively disarm the exfiltration, which is why it is
  // pinned to the two named releases rather than name-blocked. PyPI returns 404 today.
  { type: "package", value: "pypi:lucy-python-script-2030@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-2q36-rrph-f47p, MAL-2026-16125 (kam193)", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:lucy-python-script-2030@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-2q36-rrph-f47p, MAL-2026-16125 (kam193)", firstSeen: "2026-09-10" },

  // Remaining single-package advisories of 2026-09-10, all name-blocked. Every one was
  // probed against registry.npmjs.org first, because a bare name blocks every version:
  // all four return "security holding package" with 0.0.1-security as the only
  // installable version and their real releases unpublished, so no legitimate release
  // can be hit. The three @yongot names carry npm-support as the maintainer, which is
  // npm's own takedown account rather than a real publisher. pypi:tsshare is 404 on PyPI.
  { type: "package", value: "cat-sis2go-utils", severity: "critical", confidence: 1.0, source: "GHSA-5pwp-vwhm-wm7x, MAL-2026-16071", firstSeen: "2026-09-10" },
  { type: "package", value: "@yongot/canary-mcp-isolation", severity: "critical", confidence: 1.0, source: "GHSA-cr2f-c82j-mj6q, MAL-2026-16061", firstSeen: "2026-09-10" },
  { type: "package", value: "@yongot/canary-mcp-test", severity: "critical", confidence: 1.0, source: "GHSA-qjwm-vq22-4xx8, MAL-2026-16062", firstSeen: "2026-09-10" },
  { type: "package", value: "@yongot/canary-mcp-test-2", severity: "critical", confidence: 0.9, source: "GHSA-93xr-jvm3-jpch", firstSeen: "2026-09-10" },
  { type: "package", value: "pypi:tsshare", severity: "critical", confidence: 0.9, source: "MAL-2026-16044 (amazon-inspector)", firstSeen: "2026-09-04" },

  // Imported from GitHub Advisory Database (2026-08-29) - see docs/threat-feed-sources.md
  { type: "package", value: "pypi:platform-telemetry-client@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7767-763c-fxp3, MAL-2026-16141 (kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "tailwind-form-kit@0.6.4", severity: "critical", confidence: 1.0, source: "GHSA-p7c5-phj5-qm49, MAL-2026-16139 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "cr-bot-common@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mjmf-5pc4-pfrp, MAL-2026-16137 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "greensaver@1.2.1", severity: "critical", confidence: 1.0, source: "GHSA-jfw2-6254-9cwg, MAL-2026-16138 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "greensaver@1.2.3", severity: "critical", confidence: 1.0, source: "GHSA-jfw2-6254-9cwg, MAL-2026-16138 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "greensaver@1.2.2", severity: "critical", confidence: 1.0, source: "GHSA-jfw2-6254-9cwg, MAL-2026-16138 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "tracker-cloudflare@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-f874-m83r-9vqh, MAL-2026-16140 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:transfomers@4.44.2", severity: "critical", confidence: 1.0, source: "GHSA-2p95-qvc5-6rjq, MAL-2026-16136 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:langgrap@0.2.45", severity: "critical", confidence: 1.0, source: "GHSA-crjm-2g45-pq97, MAL-2026-16133 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:openaii@1.55.3", severity: "critical", confidence: 1.0, source: "GHSA-q5h5-h6mj-vhgv, MAL-2026-16135 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:ollamaa@0.4.2", severity: "critical", confidence: 1.0, source: "GHSA-9gv4-vfjg-jjrm, MAL-2026-16134 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:aitextkit-py@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-657v-53xv-3xw9, MAL-2026-16130 (kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:aitextkit-py@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-657v-53xv-3xw9, MAL-2026-16130 (kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:aitextutils-py@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-hm5j-9gw8-8568, MAL-2026-16131 (kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:aitextutils-py@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-hm5j-9gw8-8568, MAL-2026-16131 (kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1359.6", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.0.4", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1337.7", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.0.7", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1359.5", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1338.1", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1359.3", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1338.5", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1338.3", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1337.6", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1339.4", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1359.2", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1339.1", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1339.3", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1338.4", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.0.5", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1360.4", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1337.5", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1339.2", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1338.7", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1359.4", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.0.3", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1337.1", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.0.2", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1360.5", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1360.3", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1338.6", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1337.4", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1338.8", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1359.1", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1339.5", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1360.2", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1337.2", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1337.8", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.0.1", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1349.5", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@221.1.0", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.0.6", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1360.1", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "@nimbusedge/auth@19999.1338.2", severity: "critical", confidence: 1.0, source: "GHSA-gr7r-8wrc-f3mw, MAL-2026-16132 (amazon-inspector)", firstSeen: "2026-09-11" },
  { type: "package", value: "tailwind-form-kit", severity: "critical", confidence: 1.0, source: "GHSA-8p5f-pjcw-69mw, MAL-2026-16139", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:web3-eth-account@0.14.0", severity: "critical", confidence: 1.0, source: "GHSA-6rvw-xw58-h4pf, MAL-2026-16129 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:pymem-win@1.14.0", severity: "critical", confidence: 1.0, source: "GHSA-9q7m-83fp-6g4q, MAL-2026-16128 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:pymem-win@1.14.1", severity: "critical", confidence: 1.0, source: "GHSA-9q7m-83fp-6g4q, MAL-2026-16128 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:pymem-win@1.14.4", severity: "critical", confidence: 1.0, source: "GHSA-9q7m-83fp-6g4q, MAL-2026-16128 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:pymem-win@1.14.5", severity: "critical", confidence: 1.0, source: "GHSA-9q7m-83fp-6g4q, MAL-2026-16128 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:pymem-win@1.14.6", severity: "critical", confidence: 1.0, source: "GHSA-9q7m-83fp-6g4q, MAL-2026-16128 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "pypi:eth-account-web3@0.14.0", severity: "critical", confidence: 1.0, source: "GHSA-wg93-942j-x57j, MAL-2026-16127 (amazon-inspector+kam193)", firstSeen: "2026-09-11" },
  { type: "package", value: "strapi-plugin-vinsoc-1109@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-244v-fw48-794m, MAL-2026-16126 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-11" },
  // Earlier eToro dependency-confusion lures (OpenSSF MAL-2025-41559/41560/41561,
  // re-published into the GitHub Advisory Database on September 10, 2026). Same target
  // and same lure shape as the MAL-2026-161xx wave above, one implausible 999.999.999
  // version each. These three sit inside the 2026-09-10 bulk-migration block that
  // threat-feed-deferred.json postpones, and are lifted out by hand because the rest of
  // this campaign is covered: leaving them behind would make eToro coverage partial.
  // Registry time map confirms one published version each, since unpublished, no
  // maintainer and no legitimate release history.
  { type: "package", value: "etoro-cordova-prove-mobileauth@999.999.999", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-97vm-94j4-jr9q, MAL-2025-41559", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-provema@999.999.999", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-hhg7-rpgf-hx9f, MAL-2025-41561", firstSeen: "2026-09-10" },
  { type: "package", value: "etoro-plaid-widget@999.999.999", severity: "critical", confidence: 1.0, family: "DependencyConfusion", campaign: "eToro Dependency Confusion", source: "GHSA-q2j6-52qg-fqx7, MAL-2025-41560", firstSeen: "2026-09-10" },

  // Imported from GitHub Advisory Database (2026-09-12) - see docs/threat-feed-sources.md
  { type: "package", value: "pypi:python-fork@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-v8v2-jgrm-w335, MAL-2026-16142 (kam193)", firstSeen: "2026-09-12" },
  { type: "package", value: "pypi:python-fork@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-v8v2-jgrm-w335, MAL-2026-16142 (kam193)", firstSeen: "2026-09-12" },


  // openaii PyPI typosquat campaign (kam193 package-campaigns, September 11 2026).
  // Atomic indicators for the five-package campaign whose packages are already in
  // this feed. The advisory databases publish package@version only, so the staging
  // host and the two payload paths come from the campaign write-up alone.
  // Single-source, hence confidence 0.85.
  { type: "package", value: "pypi:chroma-client@0.5.7", severity: "critical", confidence: 1.0, source: "GHSA-qp4x-pg53-7xh8, MAL-2026-16143 (kam193)", firstSeen: "2026-09-13" },
  { type: "ip", value: "167.86.108.190", severity: "critical", confidence: 0.85, campaign: "openaii PyPI Typosquat", source: "kam193", firstSeen: "2026-09-11" },
  { type: "url", value: "167.86.108.190:7788/stage1.py", severity: "critical", confidence: 0.85, campaign: "openaii PyPI Typosquat", source: "kam193", firstSeen: "2026-09-11" },
  { type: "url", value: "167.86.108.190:7788/.lurves-agent.py", severity: "critical", confidence: 0.85, campaign: "openaii PyPI Typosquat", source: "kam193", firstSeen: "2026-09-11" },

  // Imported from GitHub Advisory Database (2026-09-01) - see docs/threat-feed-sources.md
  { type: "package", value: "@biz44/process-runtime-utils@1.1.10", severity: "critical", confidence: 1.0, source: "GHSA-85j9-pqgv-pr94, MAL-2026-16171", firstSeen: "2026-09-14" },
  { type: "package", value: "@biz44/process-runtime-utils@1.1.79", severity: "critical", confidence: 1.0, source: "GHSA-85j9-pqgv-pr94, MAL-2026-16171", firstSeen: "2026-09-14" },
  { type: "package", value: "@biz44/process-runtime-utils@1.1.95", severity: "critical", confidence: 1.0, source: "GHSA-85j9-pqgv-pr94, MAL-2026-16171", firstSeen: "2026-09-14" },
  { type: "package", value: "@biz44/runtime-utils@1.1.11", severity: "critical", confidence: 1.0, source: "GHSA-fc79-g66m-pjph, MAL-2026-16172", firstSeen: "2026-09-14" },
  { type: "package", value: "@biz44/runtime-utils@1.1.13", severity: "critical", confidence: 1.0, source: "GHSA-fc79-g66m-pjph, MAL-2026-16172", firstSeen: "2026-09-14" },
  { type: "package", value: "@biz44/runtime-utils@1.1.81", severity: "critical", confidence: 1.0, source: "GHSA-fc79-g66m-pjph, MAL-2026-16172", firstSeen: "2026-09-14" },
  { type: "package", value: "@biz44/runtime-utils@1.1.96", severity: "critical", confidence: 1.0, source: "GHSA-fc79-g66m-pjph, MAL-2026-16172", firstSeen: "2026-09-14" },
  { type: "package", value: "@biz44/runtime-utils@1.1.100", severity: "critical", confidence: 1.0, source: "GHSA-fc79-g66m-pjph, MAL-2026-16172", firstSeen: "2026-09-14" },
  { type: "package", value: "cargo:logs-update", severity: "critical", confidence: 1.0, source: "GHSA-3hhc-h7ww-gp83, MAL-2026-16164", firstSeen: "2026-09-11" },
  { type: "package", value: "@biz44/id99-client@1.1.100", severity: "critical", confidence: 1.0, source: "GHSA-2r46-q2c6-8xv3, MAL-2026-16170", firstSeen: "2026-09-12" },
  { type: "package", value: "@biz44/id44-client@1.1.44", severity: "critical", confidence: 1.0, source: "GHSA-5j4q-j7xc-mcjq, MAL-2026-16167", firstSeen: "2026-09-12" },
  { type: "package", value: "id79-client@1.1.79", severity: "critical", confidence: 1.0, source: "GHSA-c62r-crr7-5qfm, MAL-2026-16173", firstSeen: "2026-09-12" },
  { type: "package", value: "@biz44/id95-client@1.1.96", severity: "critical", confidence: 1.0, source: "GHSA-h5qm-2mw2-cpj7, MAL-2026-16169", firstSeen: "2026-09-12" },
  { type: "package", value: "@biz44/id79-client@1.1.80", severity: "critical", confidence: 1.0, source: "GHSA-38g4-jrgw-cqgh, MAL-2026-16168", firstSeen: "2026-09-12" },
  { type: "package", value: "@biz44/id12-client@1.1.13", severity: "critical", confidence: 1.0, source: "GHSA-57p7-wfrw-75gv, MAL-2026-16166", firstSeen: "2026-09-12" },
  { type: "package", value: "@biz44/id10-client@1.1.11", severity: "critical", confidence: 1.0, source: "GHSA-3fp9-rc4g-j5v2, MAL-2026-16165", firstSeen: "2026-09-12" },
  { type: "package", value: "n8n-nodes-sysdiag2@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mx46-3mx3-r66x, MAL-2026-16162 (ossf-package-analysis)", firstSeen: "2026-09-14" },
  { type: "package", value: "@yggbrasil/api", severity: "critical", confidence: 0.9, source: "GHSA-cmxv-8vgc-m43c, MAL-2026-16163 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "get-power@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-pjxw-c7p6-x2gq, MAL-2026-16156 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "app-rrhh@999.0.0", severity: "critical", confidence: 1.0, source: "GHSA-c9r8-qhjh-h69j, MAL-2026-16144 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "web-main@22.1.2", severity: "critical", confidence: 1.0, source: "GHSA-mq47-gfmg-59pp, MAL-2026-16153 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "@aiwfm/communitywfm.scripts.api@28.1.28", severity: "critical", confidence: 1.0, source: "GHSA-cj6r-j9c8-88qp, MAL-2026-16146 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "sql-limit-enforcer@10.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vjjr-9qv2-mh33, MAL-2026-16151 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "strapi-plugin-os-info-meeb322k@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-3jh2-p873-gc7r, MAL-2026-16152 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "postgreesqlhelper@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-87qj-rx96-4w66, MAL-2026-16150 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "n8n-nodes-sysdiag@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-mfvv-xhj7-524c, MAL-2026-16147 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "n8n-nodes-sysdiag@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mfvv-xhj7-524c, MAL-2026-16147 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "n8n-nodes-sysdiag@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-mfvv-xhj7-524c, MAL-2026-16147 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "n8n-nodes-sysdiag@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-mfvv-xhj7-524c, MAL-2026-16147 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "n8n-nodes-sysdiag@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-mfvv-xhj7-524c, MAL-2026-16147 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "noblox-asset.js@7.4.2", severity: "critical", confidence: 1.0, source: "GHSA-9pp6-m94w-8jhp, MAL-2026-16148 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "noblox-asset.js@7.6.0", severity: "critical", confidence: 1.0, source: "GHSA-9pp6-m94w-8jhp, MAL-2026-16148 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "noblox-asset.js@7.4.0", severity: "critical", confidence: 1.0, source: "GHSA-9pp6-m94w-8jhp, MAL-2026-16148 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "noblox-asset.js@7.4.1", severity: "critical", confidence: 1.0, source: "GHSA-9pp6-m94w-8jhp, MAL-2026-16148 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "os-info-meeb322k@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5wwx-6p5f-p9vh, MAL-2026-16149 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "concierge-sdk@99.99.101", severity: "critical", confidence: 1.0, source: "GHSA-7gx4-hj9w-hx25, MAL-2026-16145 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "concierge-sdk@99.99.100", severity: "critical", confidence: 1.0, source: "GHSA-7gx4-hj9w-hx25, MAL-2026-16145 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "concierge-sdk@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-7gx4-hj9w-hx25, MAL-2026-16145 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "ultra-ws@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h35p-624w-rrp4, MAL-2026-16155 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "pino-ulid@2.12.3", severity: "critical", confidence: 1.0, source: "GHSA-5qw6-rpv6-623h, MAL-2026-16154", firstSeen: "2026-09-14" },
  { type: "package", value: "afhmxiewpsf@1.0.0", severity: "critical", confidence: 0.9, source: "GHSA-59f6-ch49-395j, MAL-2026-16158 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "afhmxiewpsf@1.0.1", severity: "critical", confidence: 0.9, source: "GHSA-59f6-ch49-395j, MAL-2026-16158 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "afhmxiewpsf@1.0.2", severity: "critical", confidence: 0.9, source: "GHSA-59f6-ch49-395j, MAL-2026-16158 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "afhmxiewpsf@1.0.3", severity: "critical", confidence: 0.9, source: "GHSA-59f6-ch49-395j, MAL-2026-16158 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "afhmxiewpsf@1.0.4", severity: "critical", confidence: 0.9, source: "GHSA-59f6-ch49-395j, MAL-2026-16158 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "afhmxiewpsf@1.0.5", severity: "critical", confidence: 0.9, source: "GHSA-59f6-ch49-395j, MAL-2026-16158 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "meraz-project-tracker", severity: "critical", confidence: 0.9, source: "GHSA-54v8-j59m-366h, MAL-2026-16161 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "@merazmz/project-tracker", severity: "critical", confidence: 0.9, source: "GHSA-x98w-cqq8-v3q2, MAL-2026-16157 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "lpulogin", severity: "critical", confidence: 0.9, source: "GHSA-5823-3hg3-27v8, MAL-2026-16160 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "dilxztech", severity: "critical", confidence: 0.9, source: "GHSA-5wh2-j94m-rwpf, MAL-2026-16159 (ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "discord-mfa-solver@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-f5p4-vw6q-5w28, MAL-2026-16100 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "pino-ulid", severity: "critical", confidence: 0.9, source: "MAL-2026-16154 (amazon-inspector)", firstSeen: "2026-09-14" },

  // Atomic indicators for the 2026-09-14 advisory batch, added by hand: the
  // advisory databases publish package@version only. See src/ioc-blocklist.ts for
  // the per-indicator rationale and the deliberate non-listings (npoint[.]io,
  // webhook[.]site, netlify[.]app, and the Azure IMDS address 169[.]254[.]169[.]254,
  // which concierge-sdk abuses but which is legitimate cloud infrastructure).
  { type: "ip", value: "121.127.33.228", severity: "critical", confidence: 0.85, campaign: "n8n-nodes-sysdiag Credential Exfil", source: "amazon-inspector", firstSeen: "2026-09-14" },
  { type: "url", value: "121.127.33.228:443/api/v1/nodes/compat", severity: "critical", confidence: 0.85, campaign: "n8n-nodes-sysdiag Credential Exfil", source: "amazon-inspector", firstSeen: "2026-09-14" },
  { type: "domain", value: "trlxgames.netlify.app", severity: "critical", confidence: 0.85, campaign: "noblox-asset.js Roblox Typosquat", source: "amazon-inspector", firstSeen: "2026-09-14" },
  { type: "url", value: "trlxgames.netlify.app/TRLX.exe", severity: "critical", confidence: 0.85, campaign: "noblox-asset.js Roblox Typosquat", source: "amazon-inspector", firstSeen: "2026-09-14" },
  { type: "ip", value: "95.216.232.162", severity: "critical", confidence: 0.85, campaign: "pino-ulid RAT", source: "OSV MAL-2026-16154", firstSeen: "2026-09-14" },
  { type: "hash", value: "3a9089e9db3650dd6d1584fae709022002dc34854b961abfb014a90f0a7c6a50", severity: "critical", confidence: 0.85, campaign: "pino-ulid RAT", source: "OSV MAL-2026-16154", firstSeen: "2026-09-14" },
  { type: "ip", value: "103.170.217.184", severity: "critical", confidence: 0.85, campaign: "biz44 npm Campaign", source: "OSSF malicious-packages 1518 (ESTsecurity)", firstSeen: "2026-09-14" },

  // Imported from GitHub Advisory Database (2026-09-02) - see docs/threat-feed-sources.md
  { type: "package", value: "swnwall@1.2.10", severity: "critical", confidence: 1.0, source: "GHSA-8p3w-gp6g-xf77, MAL-2026-16211 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-pencc-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-77mj-c6xm-92j2, MAL-2026-16210 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-ccsuc-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-g2q3-qp84-8cj7, MAL-2026-16209 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "chai-as-agile@2.4.7", severity: "critical", confidence: 1.0, source: "GHSA-5724-m8w6-w6g2, MAL-2026-16207 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "@prime0/inimatch@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-853x-jxp5-rq5c, MAL-2026-16205 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "@prime0/pcomatch@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-736x-m99h-5pfg, MAL-2026-16206 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "tol8t@14.0.0", severity: "critical", confidence: 1.0, source: "GHSA-69x6-h25v-58j2, MAL-2026-16218 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-15" },
  { type: "package", value: "@prime0/alanced-match@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wr38-cc44-847g, MAL-2026-16204 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "tetomood@12.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wwxg-wcx2-44fm, MAL-2026-16216 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "discord-resolvers@3.4.2", severity: "critical", confidence: 1.0, source: "GHSA-m6rp-5w7c-9q45, MAL-2026-16214 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "engin1@1.3.99", severity: "critical", confidence: 1.0, source: "GHSA-8v43-g45f-4c59, MAL-2026-16215 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "pypi:cli-anything-ai-market@1.0.17", severity: "critical", confidence: 1.0, source: "GHSA-94x6-gfxh-v73w, MAL-2026-16212 (amazon-inspector+kam193)", firstSeen: "2026-09-16" },
  { type: "package", value: "pypi:cli-anything-ai-market@1.0.18", severity: "critical", confidence: 1.0, source: "GHSA-94x6-gfxh-v73w, MAL-2026-16212 (amazon-inspector+kam193)", firstSeen: "2026-09-16" },
  { type: "package", value: "tetotest@14.0.0", severity: "critical", confidence: 1.0, source: "GHSA-25v6-77x2-2mwr, MAL-2026-16217 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "pypi:licloud@0.2.7a0", severity: "critical", confidence: 1.0, source: "GHSA-gwqx-5242-h5mw, MAL-2026-16219 (kam193)", firstSeen: "2026-09-16" },
  { type: "package", value: "pypi:licloud@0.2.8", severity: "critical", confidence: 1.0, source: "GHSA-gwqx-5242-h5mw, MAL-2026-16219 (kam193)", firstSeen: "2026-09-16" },
  { type: "package", value: "otel-span-adapter@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-f4c7-58f5-g8r9, MAL-2026-16208 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "otel-span-adapter@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-f4c7-58f5-g8r9, MAL-2026-16208 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "discord-players@3.4.2", severity: "critical", confidence: 1.0, source: "GHSA-qgp7-rhmr-pjmc, MAL-2026-16213 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "plogme@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-q276-hmjg-47qw, MAL-2026-16199", firstSeen: "2026-09-08" },
  { type: "package", value: "plogme@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-q276-hmjg-47qw, MAL-2026-16199", firstSeen: "2026-09-08" },
  { type: "package", value: "plogme@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-q276-hmjg-47qw, MAL-2026-16199", firstSeen: "2026-09-08" },
  { type: "package", value: "plogme@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-q276-hmjg-47qw, MAL-2026-16199", firstSeen: "2026-09-08" },
  { type: "package", value: "pypi:faiss-cpu-avx512@1.9.0", severity: "critical", confidence: 1.0, source: "GHSA-rghm-9c3j-wc97, MAL-2026-16203", firstSeen: "2026-09-14" },
  { type: "package", value: "pypi:faiss-cpu-avx512@1.9.1", severity: "critical", confidence: 1.0, source: "GHSA-rghm-9c3j-wc97, MAL-2026-16203", firstSeen: "2026-09-14" },
  { type: "package", value: "pypi:faiss-cpu-avx512@1.9.2", severity: "critical", confidence: 1.0, source: "GHSA-rghm-9c3j-wc97, MAL-2026-16203", firstSeen: "2026-09-14" },
  { type: "package", value: "pypi:faiss-cpu-avx512@1.9.3", severity: "critical", confidence: 1.0, source: "GHSA-rghm-9c3j-wc97, MAL-2026-16203", firstSeen: "2026-09-14" },
  { type: "package", value: "pypi:faiss-cpu-avx512@1.9.4", severity: "critical", confidence: 1.0, source: "GHSA-rghm-9c3j-wc97, MAL-2026-16203", firstSeen: "2026-09-14" },
  { type: "package", value: "pypi:faiss-cpu-avx512@1.9.5", severity: "critical", confidence: 1.0, source: "GHSA-rghm-9c3j-wc97, MAL-2026-16203", firstSeen: "2026-09-14" },
  { type: "package", value: "pypi:faiss-cpu-avx512@1.9.6", severity: "critical", confidence: 1.0, source: "GHSA-rghm-9c3j-wc97, MAL-2026-16203", firstSeen: "2026-09-14" },
  { type: "package", value: "pypi:faiss-cpu-avx512@1.9.7", severity: "critical", confidence: 1.0, source: "GHSA-rghm-9c3j-wc97, MAL-2026-16203", firstSeen: "2026-09-14" },
  { type: "package", value: "webpackbootstrapscripts@5.110.3", severity: "critical", confidence: 1.0, source: "GHSA-prhx-w9qf-6qqh, MAL-2026-16202", firstSeen: "2026-09-14" },
  { type: "package", value: "@zaka13/thing@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-m9vr-9hpp-v65x, MAL-2026-16200", firstSeen: "2026-09-14" },
  { type: "package", value: "webpackbootstrap5@5.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wvx4-99w4-gwvh, MAL-2026-16201", firstSeen: "2026-09-14" },
  { type: "package", value: "kartykp-prod-oidc-test-pkg@1.0.3", severity: "critical", confidence: 0.9, source: "GHSA-v7jq-fcmp-3w93, MAL-2026-16197 (ghsa-malware)", firstSeen: "2026-09-15" },
  { type: "package", value: "kartykp-prod-oidc-test-pkg@1.0.4", severity: "critical", confidence: 0.9, source: "GHSA-v7jq-fcmp-3w93, MAL-2026-16197 (ghsa-malware)", firstSeen: "2026-09-15" },
  { type: "package", value: "kartykp-token-pkg@1.0.2", severity: "critical", confidence: 0.9, source: "GHSA-6qx5-2w7p-cf29, MAL-2026-16198 (ghsa-malware)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-yayccresh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-rw9q-wchq-m3jv, MAL-2026-16193 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-tryccresh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-cph2-r8rf-9v67, MAL-2026-16190 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-weccresh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-6mvh-5g6x-2jhr, MAL-2026-16192 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-revs01-meeb322k@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-f8wr-jqjq-4vvf, MAL-2026-16185 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "chai-as-crack@7.0.5", severity: "critical", confidence: 1.0, source: "GHSA-9q54-rq2g-8m87, MAL-2026-16196 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-ccresh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-64x7-hw7m-2wrx, MAL-2026-16180 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-proccresh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-46m5-637h-jmhh, MAL-2026-16182 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-revs02-meeb322k@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-c4gc-cwxr-w524, MAL-2026-16186 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-revsh-meeb322k@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-8ccq-6g42-37vx, MAL-2026-16187 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-uicc-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-77cj-57r4-c4fv, MAL-2026-16191 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-rs-meeb322k@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-xjgc-fw8x-c3xj, MAL-2026-16188 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-yesccresh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-3xqj-h67p-8m5w, MAL-2026-16194 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-revs-meeb322k@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-8pr6-ghc9-rm9v, MAL-2026-16184 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-sucresh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-whqm-wv8m-mvmr, MAL-2026-16189 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "alkajsdfoiwqeusdflkjsdf@3.7.3", severity: "critical", confidence: 1.0, source: "GHSA-5cjw-7pgr-hg89, MAL-2026-16174 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-plsresh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-vm7q-xcf2-26r8, MAL-2026-16181 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "strapi-plugin-resh-meeb322k@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-m8xh-7643-8frr, MAL-2026-16183 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "n8n-nodes-buildcheck@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-39q8-5c9h-rj8c, MAL-2026-16177 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "fulfillment-cuprum-auth-widget@3.7.2", severity: "critical", confidence: 1.0, source: "GHSA-wh94-xh5h-j48v, MAL-2026-16176 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "fulfillment-cuprum-auth-widget@3.7.0-rc-37", severity: "critical", confidence: 1.0, source: "GHSA-wh94-xh5h-j48v, MAL-2026-16176 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "fulfillment-cuprum-auth-widget@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wh94-xh5h-j48v, MAL-2026-16176 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "fulfillment-cuprum-auth-widget@3.7.1", severity: "critical", confidence: 1.0, source: "GHSA-wh94-xh5h-j48v, MAL-2026-16176 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "process-tailwind@1.1.99", severity: "critical", confidence: 1.0, source: "GHSA-qm95-54f4-jjg8, MAL-2026-16179 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "csa-mfa@1.1.15", severity: "critical", confidence: 1.0, source: "GHSA-gqh9-2j3v-c5g6, MAL-2026-16175 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-15" },
  { type: "package", value: "csa-mfa@1.1.16", severity: "critical", confidence: 1.0, source: "GHSA-gqh9-2j3v-c5g6, MAL-2026-16175 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-15" },
  { type: "package", value: "process-lhpm@1.1.79", severity: "critical", confidence: 1.0, source: "GHSA-8x79-9h94-vj8g, MAL-2026-16178 (amazon-inspector)", firstSeen: "2026-09-15" },
  { type: "package", value: "tailwind-forms-styles", severity: "critical", confidence: 1.0, source: "GHSA-q8wp-7xrg-83rx, MAL-2026-16195 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-15" },
  { type: "package", value: "bender-rspack-config@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16221 (ossf-package-analysis)", firstSeen: "2026-09-15" },
  { type: "package", value: "jexkcode@1.0.1", severity: "critical", confidence: 0.9, source: "MAL-2026-16220", firstSeen: "2026-09-16" },
  { type: "package", value: "jexkcode@1.1.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16220", firstSeen: "2026-09-16" },
  { type: "package", value: "jexkcode@1.1.1", severity: "critical", confidence: 0.9, source: "MAL-2026-16220", firstSeen: "2026-09-16" },
  { type: "package", value: "jexkcode@1.1.2", severity: "critical", confidence: 0.9, source: "MAL-2026-16220", firstSeen: "2026-09-16" },
  { type: "package", value: "jexkcode@1.1.3", severity: "critical", confidence: 0.9, source: "MAL-2026-16220", firstSeen: "2026-09-16" },
  { type: "package", value: "jexkcode@1.1.4", severity: "critical", confidence: 0.9, source: "MAL-2026-16220", firstSeen: "2026-09-16" },

  // Malicious Strapi CMS plugins targeting the Guardarian crypto platform
  // (safedep, April 3 2026; corroborated by The Hacker News and CyberSecurityNews).
  // Thirty-six sock-puppet package names published from four npm accounts
  // (umarbek1233, kekylf12, tikeqemif26, umar_bektembiev1) between 2026-03-31 and
  // 2026-04-04, carrying eight payload variants: Redis RCE, Docker escape,
  // PostgreSQL theft against guardarian* databases, and a persistent C2 agent at
  // /tmp/.node_gc.js. The same actor is still publishing under this naming scheme:
  // the *-meeb* entries imported for 2026-09-14 through 2026-09-16 are the current
  // wave, so the origin cluster is a live gap rather than history.
  //
  // Every version below comes from the npm registry time map, not from the
  // write-up, which says only "3.6.8 unless noted" and misses four names'
  // extra versions. Every one of these names is now an npm security holding
  // package whose only published versions fall inside the campaign window, so
  // no legitimate release exists on any of them and the pins cannot false-positive.
  { type: "package", value: "strapi-plugin-cron@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-config@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-server@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-database@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-core@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-hooks@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-monitor@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-events@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-logger@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-health@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-sync@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-seed@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-locale@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-form@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-notify@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-sitemap-gen@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-sync@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-cms@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-api@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-recon@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-stage@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-vhost@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-deep@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-finseven@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-hextest@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-cms-tools@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-content-sync@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-debug-tools@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-health-check@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-guardarian-ext@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-advanced-uuid@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-blurhash@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-api@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-api@3.6.9", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-api@3.6.10", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica@1.0.0", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica@3.6.10", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-lite@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-lite@3.6.9", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-lite@3.6.11", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-tools@3.6.8", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-tools@3.6.9", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  { type: "package", value: "strapi-plugin-nordica-tools@3.6.10", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },
  // C2 the implants reach on :9999 (HTTP), :4444 (bash reverse shell) and :8888
  // (Python reverse shell). A rented host carrying only the campaign's own
  // endpoints, not shared CDN edge. Also in KNOWN_C2_IPS.
  { type: "ip", value: "144.31.107.231", severity: "critical", confidence: 0.95, family: "StrapiGuardarianC2", campaign: "strapi-plugin Guardarian targeting", source: "safedep", firstSeen: "2026-04-03" },

  // express-session-js remote-access trojan, Contagious Interview (safedep,
  // April 1 2026; C2 address corroborated by The Hacker News). Typosquat of
  // express-session published by npm account judebelingham, whose version was
  // chosen to read as the next release of the real package (real: 1.18.1).
  // Both published versions are pinned: the name has no legitimate history and
  // is now an npm security holding package. 1.0.0 was pushed on 2026-04-06,
  // after the write-up, and is named only by the registry time map.
  { type: "package", value: "express-session-js@1.19.0", severity: "critical", confidence: 0.95, family: "ContagiousInterview", campaign: "express-session-js RAT", source: "safedep", firstSeen: "2026-04-01" },
  { type: "package", value: "express-session-js@1.0.0", severity: "critical", confidence: 0.95, family: "ContagiousInterview", campaign: "express-session-js RAT", source: "safedep", firstSeen: "2026-04-01" },
  // RAT C2 on :4801 (Socket.IO + API), :4806 (file upload), :4809 (browser DB
  // sync). Also in KNOWN_C2_IPS.
  { type: "ip", value: "216.126.237.71", severity: "critical", confidence: 0.95, family: "ContagiousInterview", campaign: "express-session-js RAT", source: "safedep", firstSeen: "2026-04-01" },
  // Paste holding the ~93KB obfuscated RAT the dropper pulls and runs through
  // Function.constructor on every require(). Path-scoped to the attacker's own
  // paste id: jsonkeeper[.]com is a legitimate JSON-paste service and its apex is
  // deliberately NOT listed, exactly as the pinochiomathm entry decided.
  { type: "url", value: "jsonkeeper.com/b/YY8VI", severity: "critical", confidence: 0.95, family: "ContagiousInterview", campaign: "express-session-js RAT", source: "safedep", firstSeen: "2026-04-01" },
  // Tarball digest (SHA256), round-tripped across two independent fetches.
  { type: "hash", value: "b5cca27ca1d792bd8c46b83fccfa4e5ba38916eb78877a19cbb39392ce98cc39", severity: "critical", confidence: 0.95, family: "ContagiousInterview", campaign: "express-session-js RAT", source: "safedep", firstSeen: "2026-04-01" },

  // Campaign indicators pinned to the BUNDLE, not the catalog.
  //
  // src/__tests__/campaigns.test.ts asserts each of these resolves from
  // getBundledFeed(), which is a deliberate contract: a documented campaign
  // must be detectable from a bare install with no download. They carry no
  // `campaign` or `family` field, so rule 2 could not see that, and the
  // 2026-08-17 cutoff moved them into the catalog. The campaign suite caught
  // it. This comment block is what keeps them here: rule 3 makes an entry
  // beneath a curated header immovable regardless of age.
  //
  // Do not remove this header without moving the entries beneath it somewhere
  // the campaign tests can still reach offline.
  { type: "package", value: "pypi:xinference@2.6.0", severity: "critical", confidence: 1, source: "GHSA-9x96-4gxh-mxx2, MAL-2026-3000", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xinference@2.6.1", severity: "critical", confidence: 1, source: "GHSA-9x96-4gxh-mxx2, MAL-2026-3000", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xinference@2.6.2", severity: "critical", confidence: 1, source: "GHSA-9x96-4gxh-mxx2, MAL-2026-3000", firstSeen: "2026-07-21" },
  { type: "package", value: "@joyfill/layouts@0.1.2-2773.beta.0", severity: "critical", confidence: 1, source: "GHSA-887f-rwr9-wp54, MAL-2026-11161", firstSeen: "2026-07-28" },
  { type: "package", value: "@joyfill/components@4.0.0-rc24-2773-beta.4", severity: "critical", confidence: 1, source: "GHSA-x4p3-wjxx-m4x5, MAL-2026-11160", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:mrmustard@0.7.4", severity: "critical", confidence: 1, source: "GHSA-7h9m-3hvr-pjg2, MAL-2026-11049", firstSeen: "2026-07-28" },
  { type: "package", value: "streak-metrics-math", severity: "critical", confidence: 1, source: "GHSA-57m5-24x9-2xr5, MAL-2026-11388", firstSeen: "2026-07-30" },
  { type: "package", value: "win-env-setup@3.0.5", severity: "critical", confidence: 1, source: "GHSA-v48m-xpmx-rf2x, MAL-2026-7439", firstSeen: "2026-07-27" },
  { type: "package", value: "polymarket-trading-developer-tool@0.1.1", severity: "critical", confidence: 1, source: "GHSA-jj5v-jw2c-3q4q, MAL-2026-6714", firstSeen: "2026-07-27" },
  { type: "package", value: "polymarket-trading-developer-tool@0.1.2", severity: "critical", confidence: 1, source: "GHSA-jj5v-jw2c-3q4q, MAL-2026-6714", firstSeen: "2026-07-27" },
  { type: "package", value: "base58-utils@1.0.5", severity: "critical", confidence: 1, source: "GHSA-p628-p5mv-4xhj, MAL-2026-10606", firstSeen: "2026-07-27" },
  { type: "package", value: "base58-utils@1.0.4", severity: "critical", confidence: 1, source: "GHSA-p628-p5mv-4xhj, MAL-2026-10606", firstSeen: "2026-07-27" },
  { type: "package", value: "macos-ci-utils@1.0.1", severity: "critical", confidence: 1, source: "GHSA-9gfp-2g8v-p678, MAL-2026-6378", firstSeen: "2026-07-27" },
  { type: "package", value: "streak-calc-metrics", severity: "critical", confidence: 1, source: "GHSA-7m7x-hmq7-rwm9, MAL-2026-12311", firstSeen: "2026-08-05" },
  { type: "package", value: "streak-map-cache@1.0.0", severity: "critical", confidence: 1, source: "GHSA-jrfj-4vf7-xrg3, MAL-2026-13459", firstSeen: "2026-08-07" },
  { type: "package", value: "streak-cache-map", severity: "critical", confidence: 1, source: "GHSA-wpj4-68w6-w2fh, MAL-2026-13403", firstSeen: "2026-08-06" },
  { type: "package", value: "map-streak-kit@1.0.0", severity: "critical", confidence: 1, source: "GHSA-2fcq-4c2w-gvm3, MAL-2026-13632", firstSeen: "2026-08-08" },
  { type: "package", value: "streak-map-kit@1.0.0", severity: "critical", confidence: 1, source: "GHSA-qjg3-27xw-6xvr, MAL-2026-13628", firstSeen: "2026-08-07" },
  { type: "package", value: "streak-map-cache", severity: "critical", confidence: 1, source: "GHSA-v2fj-c673-2gjm, MAL-2026-13459", firstSeen: "2026-08-07" },
  { type: "package", value: "streak-kit-map", severity: "critical", confidence: 1, source: "GHSA-6698-9vj2-cgx8, MAL-2026-13519", firstSeen: "2026-08-07" },
  { type: "package", value: "streak-map-kit", severity: "critical", confidence: 1, source: "GHSA-w8wc-wm2m-27hv, MAL-2026-13628", firstSeen: "2026-08-08" },
  { type: "package", value: "map-streak-kit", severity: "critical", confidence: 1, source: "GHSA-m55q-8hc5-f46f, MAL-2026-13632", firstSeen: "2026-08-08" },
  { type: "package", value: "kit-map-vim", severity: "critical", confidence: 1, source: "GHSA-hg96-r46x-6f4w, MAL-2026-13915", firstSeen: "2026-08-12" },
  { type: "package", value: "@velliajs/discord@1.0.5", severity: "critical", confidence: 1, source: "GHSA-5546-mfxg-3v4r, MAL-2026-14051", firstSeen: "2026-08-15" },
  { type: "package", value: "@velliajs/discord@1.0.4", severity: "critical", confidence: 1, source: "GHSA-5546-mfxg-3v4r, MAL-2026-14051", firstSeen: "2026-08-15" },
  { type: "package", value: "@velliajs/discord@1.0.3", severity: "critical", confidence: 1, source: "GHSA-5546-mfxg-3v4r, MAL-2026-14051", firstSeen: "2026-08-15" },
  { type: "package", value: "@velliajs/discord@1.0.6", severity: "critical", confidence: 1, source: "GHSA-5546-mfxg-3v4r, MAL-2026-14051", firstSeen: "2026-08-15" },
  { type: "package", value: "@velliajs/discord@1.0.7", severity: "critical", confidence: 1, source: "GHSA-5546-mfxg-3v4r, MAL-2026-14051", firstSeen: "2026-08-15" },
  { type: "package", value: "fetch-page-assets@1.2.14", severity: "critical", confidence: 1, source: "MAL-2026-6358 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "fetch-page-assets@1.2.13", severity: "critical", confidence: 1, source: "MAL-2026-6358 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "fetch-page-assets@1.2.12", severity: "critical", confidence: 1, source: "MAL-2026-6358 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "fetch-page-assets@1.2.11", severity: "critical", confidence: 1, source: "MAL-2026-6358 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "fetch-page-assets@1.2.10", severity: "critical", confidence: 1, source: "MAL-2026-6358 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "html-to-gutenberg@4.2.14", severity: "critical", confidence: 1, source: "MAL-2026-6359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "html-to-gutenberg@4.2.16", severity: "critical", confidence: 1, source: "MAL-2026-6359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "html-to-gutenberg@4.2.15", severity: "critical", confidence: 1, source: "MAL-2026-6359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "html-to-gutenberg@4.2.13", severity: "critical", confidence: 1, source: "MAL-2026-6359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "html-to-gutenberg@4.2.12", severity: "critical", confidence: 1, source: "MAL-2026-6359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "fetch-page-assets@1.2.15", severity: "critical", confidence: 1, source: "MAL-2026-6358 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "fetch-page-assets@1.2.16", severity: "critical", confidence: 1, source: "MAL-2026-6358 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "html-to-gutenberg@4.2.17", severity: "critical", confidence: 1, source: "MAL-2026-6359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "html-to-gutenberg@4.2.18", severity: "critical", confidence: 1, source: "MAL-2026-6359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "html-to-gutenberg@4.2.19", severity: "critical", confidence: 1, source: "MAL-2026-6359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },
  { type: "package", value: "html-to-gutenberg@4.2.20", severity: "critical", confidence: 1, source: "MAL-2026-6359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-06-24" },

  // Imported from GitHub Advisory Database (2026-09-05) - see docs/threat-feed-sources.md
  { type: "package", value: "pypi:urc@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-3c7m-3qhf-wqrr, MAL-2026-16298 (kam193)", firstSeen: "2026-09-19" },
  { type: "package", value: "keroeltop@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-gg5m-rqpp-c9xf, MAL-2026-16297 (ossf-package-analysis)", firstSeen: "2026-09-18" },
  { type: "package", value: "pypi:py-venv-doctor@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-94w6-hr49-qjm7, MAL-2026-16296 (kam193)", firstSeen: "2026-09-18" },
  { type: "package", value: "pypi:py-venv-doctor@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-94w6-hr49-qjm7, MAL-2026-16296 (kam193)", firstSeen: "2026-09-18" },
  { type: "package", value: "internallib_v949", severity: "critical", confidence: 1.0, source: "GHSA-f863-m366-9cfm, MAL-2026-16294 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-18" },
  { type: "package", value: "@shared-web/utils@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-29f7-pqf4-c94j, MAL-2026-16292 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "tailwindcss-forms-ui@0.5.2", severity: "critical", confidence: 1.0, source: "GHSA-fc5q-m33g-rp9c, MAL-2026-16295 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "chai-as-indexed@7.2.8", severity: "critical", confidence: 1.0, source: "GHSA-727r-6hg5-947x, MAL-2026-16293 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "@shared-runtime/modules@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-g85c-jph7-8q4r, MAL-2026-16291 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "@insiderintelligence/googleadmanager@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-76rx-jxhm-vhww, MAL-2026-16290 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "openmct-heatmap", severity: "critical", confidence: 0.9, source: "GHSA-qx52-2xq4-3x3v, MAL-2026-16287 (ghsa-malware)", firstSeen: "2026-09-18" },
  { type: "package", value: "test899-auth", severity: "critical", confidence: 1.0, source: "GHSA-jf2q-w77c-99vv, MAL-2026-16285 (amazon-inspector+ghsa-malware+ossf-package-analysis)", firstSeen: "2026-09-18" },
  { type: "package", value: "test89-auth", severity: "critical", confidence: 1.0, source: "GHSA-7868-hxr7-g8r6, MAL-2026-16288 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-18" },
  { type: "package", value: "test8999-auth", severity: "critical", confidence: 1.0, source: "GHSA-25wf-vfrc-2r82, MAL-2026-16286 (amazon-inspector+ghsa-malware+ossf-package-analysis)", firstSeen: "2026-09-18" },
  { type: "package", value: "test890-auth", severity: "critical", confidence: 1.0, source: "GHSA-xvpv-wq7p-548c, MAL-2026-16289 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-18" },
  { type: "package", value: "@shared-web/assets@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-vmr9-5w3x-4v98, MAL-2026-16283 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "sinful", severity: "critical", confidence: 0.9, source: "GHSA-2xjj-r8mc-xpf6, MAL-2026-16284 (ghsa-malware)", firstSeen: "2026-09-18" },
  { type: "package", value: "@sanzoffc/baileys@3.0.4", severity: "critical", confidence: 1.0, source: "GHSA-grqc-r63w-6845, MAL-2026-16281 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "tailwindcss-form@0.5.1", severity: "critical", confidence: 1.0, source: "GHSA-xhr7-h7hc-7785, MAL-2026-16282 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "zero-baileys@2.7.0", severity: "critical", confidence: 1.0, source: "GHSA-2q5p-vqh2-8c92, MAL-2026-16280 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "xzvbailsx@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-m364-pjc8-42wc, MAL-2026-16279 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "xzvbailey@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-rg4j-jh5f-w982, MAL-2026-16278 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "xa424234657567@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h7pm-6wh6-7xvw, MAL-2026-16277 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "@lekzo/baileys@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-75mc-fj4c-6pfm, MAL-2026-16276 (amazon-inspector)", firstSeen: "2026-09-18" },
  { type: "package", value: "laycot@1.3.10", severity: "critical", confidence: 1.0, source: "GHSA-rfg6-m87c-vcv3, MAL-2026-16253 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "idx_form_script@999.0.4", severity: "critical", confidence: 1.0, source: "GHSA-82rh-9f4r-4739, MAL-2026-16243 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-16" },
  { type: "package", value: "idx_form_script@999.0.2", severity: "critical", confidence: 1.0, source: "GHSA-82rh-9f4r-4739, MAL-2026-16243 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-16" },
  { type: "package", value: "kartyk-github-single-ver-pkg", severity: "critical", confidence: 0.9, source: "GHSA-4vpr-3r9p-p9fh, MAL-2026-16245 (ghsa-malware)", firstSeen: "2026-09-16" },
  { type: "package", value: "kartyk-github-token-pkg", severity: "critical", confidence: 0.9, source: "GHSA-4rmp-vchm-9gvg, MAL-2026-16246 (ghsa-malware)", firstSeen: "2026-09-16" },
  { type: "package", value: "pkg-rollback-dreed-viced-sonic-ponds", severity: "critical", confidence: 0.9, source: "GHSA-63f3-rmrf-6m9q, MAL-2026-16247 (ghsa-malware)", firstSeen: "2026-09-16" },
  { type: "package", value: "kartyk-github-oidc-test-pkg@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-4vxh-7998-9h4g, MAL-2026-16244", firstSeen: "2026-09-16" },
  { type: "package", value: "kartyk-github-oidc-test-pkg@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-4vxh-7998-9h4g, MAL-2026-16244", firstSeen: "2026-09-16" },
  { type: "package", value: "kartyk-github-oidc-test-pkg", severity: "critical", confidence: 0.9, source: "GHSA-4vxh-7998-9h4g, MAL-2026-16244 (ghsa-malware)", firstSeen: "2026-09-16" },
  { type: "package", value: "pypi:rak-lab-yoav-orca-zrktd2cp5hjmo4x7@9.9.9", severity: "critical", confidence: 1.0, source: "GHSA-2mp7-443g-cw4c, MAL-2026-16241 (amazon-inspector+kam193)", firstSeen: "2026-09-16" },
  { type: "package", value: "pypi:trongappy@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-xr9j-54f9-pcpm, MAL-2026-16242 (amazon-inspector+kam193)", firstSeen: "2026-09-16" },
  { type: "package", value: "pypi:praetorian-mind-rce-test-2026@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-8gcf-3vx7-2wrq, MAL-2026-16240 (amazon-inspector+kam193+ossf-package-analysis)", firstSeen: "2026-09-16" },
  { type: "package", value: "pypi:praetorian-mind-rce-test-2026@0.0.2", severity: "critical", confidence: 1.0, source: "GHSA-8gcf-3vx7-2wrq, MAL-2026-16240 (amazon-inspector+kam193+ossf-package-analysis)", firstSeen: "2026-09-16" },
  { type: "package", value: "pypi:praetorian-mind-rce-test-2026@0.0.3", severity: "critical", confidence: 1.0, source: "GHSA-8gcf-3vx7-2wrq, MAL-2026-16240 (amazon-inspector+kam193+ossf-package-analysis)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-perev-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-293w-xgv2-3qrj, MAL-2026-16236 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-os-rec@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-q676-3wp5-xm49, MAL-2026-16234 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-pysh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-jxxh-j7pf-pvj3, MAL-2026-16239 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-portcc-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-p247-8vcf-jcm5, MAL-2026-16238 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-maylog-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-p65g-47hv-5mfm, MAL-2026-16233 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-osag@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-6jhp-v2xp-285p, MAL-2026-16235 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-honey-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-4373-h9cc-p2hr, MAL-2026-16231 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-persh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-x89g-768f-7xrv, MAL-2026-16237 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-feedmeeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-chmf-v973-774w, MAL-2026-16230 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "@traktis/environment@99.99.1", severity: "critical", confidence: 1.0, source: "GHSA-8w76-frwh-rcpm, MAL-2026-16223 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "@traktis/environment@99.99.2", severity: "critical", confidence: 1.0, source: "GHSA-8w76-frwh-rcpm, MAL-2026-16223 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-ccrev-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-3r87-fhjr-5xhf, MAL-2026-16228 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-ccrec-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-92rg-hf5c-qwp4, MAL-2026-16227 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-listcc-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-5567-73jx-f7g3, MAL-2026-16232 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-cccon-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-75rj-xxh3-3j2q, MAL-2026-16225 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-conresh-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-wqj7-9999-2crf, MAL-2026-16229 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "strapi-plugin-ccip-meeb@3.6.8", severity: "critical", confidence: 1.0, source: "GHSA-8q85-7c4r-6v2c, MAL-2026-16226 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "process-mite@1.1.79", severity: "critical", confidence: 1.0, source: "GHSA-vgjx-m4jg-wrvq, MAL-2026-16224 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "@traktis/core@99.99.2", severity: "critical", confidence: 1.0, source: "GHSA-968f-vpg2-j5xr, MAL-2026-16222 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "@traktis/core@99.99.1", severity: "critical", confidence: 1.0, source: "GHSA-968f-vpg2-j5xr, MAL-2026-16222 (amazon-inspector)", firstSeen: "2026-09-16" },
  { type: "package", value: "sql-limit-enforcer@10.0.1", severity: "critical", confidence: 1.0, source: "GHSA-vjjr-9qv2-mh33, MAL-2026-16151 (amazon-inspector)", firstSeen: "2026-09-14" },
  { type: "package", value: "sql-limit-enforcer@10.0.2", severity: "critical", confidence: 1.0, source: "GHSA-vjjr-9qv2-mh33, MAL-2026-16151 (amazon-inspector)", firstSeen: "2026-09-14" },

  // PhantomRaven LLM-generated npm infostealer (CrowdStrike, September 2026).
  // Curated: carries campaign and family so the whole set stays in the bundle and
  // detectable offline, whatever the partition cutoff does later.
  // Both packages are npm security-holding names today, each with a single
  // unpublished 9.9.0 and no clean release ever, so they are blocked by name.
  //
  // The operator published through nine npm accounts: jpdhellonpm1, jpd15,
  // jpd12, jpd13, npmhell, npmpackagejpd, npmtestdharsh, jpdhackerone11 and
  // packagedharsh. They are recorded HERE, in prose, and deliberately not in a
  // collection: registry publisher identity is unreachable at scan time, so an
  // account entry in either store would be an indicator nothing can match. See
  // "What is not an indicator" in .ai/handoff/CONVENTIONS.md. They are also not
  // folded into source, which means who REPORTED an entry and elsewhere holds
  // researcher and scanner handles.
  { type: "package", value: "transform-jsbi-to-bigint", severity: "critical", confidence: 1.0, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report", firstSeen: "2026-09-15" },
  { type: "package", value: "sort-imports-es6-autofix", severity: "critical", confidence: 1.0, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report", firstSeen: "2026-09-15" },
  { type: "domain", value: "packages.storeartifact.com", severity: "critical", confidence: 1.0, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report", firstSeen: "2026-09-15" },
  { type: "domain", value: "registry.storageartifact.com", severity: "critical", confidence: 1.0, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report", firstSeen: "2026-09-15" },
  { type: "domain", value: "packages.storageartifact.com", severity: "critical", confidence: 1.0, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report", firstSeen: "2026-09-15" },
  { type: "domain", value: "npm.jpartifacts.com", severity: "critical", confidence: 1.0, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report", firstSeen: "2026-09-15" },
  { type: "ip", value: "54.173.15.59", severity: "critical", confidence: 1.0, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report", firstSeen: "2026-09-15" },
  { type: "hash", value: "c31831d47fcbf52ff1f4e61838611916a4276d005a564e69946d5dac04235eed", severity: "critical", confidence: 1.0, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report", firstSeen: "2026-09-15" },
  { type: "hash", value: "95a7dcc6de46826b22c43bee7fc550f3b5e2e6cbc5f33b0c241faf523641cf63", severity: "critical", confidence: 1.0, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report", firstSeen: "2026-09-15" },
  // Single-source: present in the vendor IOC table but not in the independent
  // rendering that reproduced the other two, so confidence is lowered.
  { type: "hash", value: "db3fe46df0a65fe9f8c99d2e11126a032a72e9814e354ce017448ce088a01e02", severity: "critical", confidence: 0.85, family: "PhantomRaven", campaign: "PhantomRaven npm infostealer", source: "CrowdStrike PhantomRaven report (single-source)", firstSeen: "2026-09-15" },

  // Shai-Hulud worm payload republished unchanged after 111 days (September 2026).
  // The four carrier packages and t.m-kosche.com are already in the feed above;
  // this is the payload digest, which was the only part not yet covered.
  { type: "hash", value: "e37e3ddeeaaa9e0c4fdbcb829b4895a6521031c80053fc436625b61e6ee5b1a6", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Shai-Hulud 111-day republish", source: "Aikido + OSV MAL-2026-16026", firstSeen: "2026-09-07" },

  // npm bin entry harvesting (safedep, August 14 2026), the 20 packages that came
  // in through the advisory importer on 2026-08-19. They are curated HERE, with the
  // campaign that pins them in the bundle, because the v6.2.1 cutoff advance to
  // 2026-08-20 migrated every one of them into the catalog and left the campaign
  // one-of-21 detectable offline. The atomic indicators and the 21st package are in
  // the curated block under FEED_CHUNK_14; only the physical chunk differs, since a
  // chunk is a TS2590 workaround and FEED_CHUNK_14 is at capacity.
  //
  // The full set is asserted by campaigns.test.ts, so a later cutoff cannot move
  // them out again without going red.
  { type: "package", value: "bazelisk@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-ppxg-6h6r-xhwx, MAL-2026-14227", firstSeen: "2026-08-19" },
  { type: "package", value: "broadcast-graphics-mcp@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-rh95-w86h-pprv, MAL-2026-14228", firstSeen: "2026-08-19" },
  { type: "package", value: "chrome-enterprise-premium-mcp@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-w6h5-6v7q-884j, MAL-2026-14230", firstSeen: "2026-08-19" },
  { type: "package", value: "chromecast-webdriver-cli@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-x95c-hq44-wmp6, MAL-2026-14231", firstSeen: "2026-08-19" },
  { type: "package", value: "chromeos-webdriver-cli@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-fpp2-m9c8-jrjh, MAL-2026-14232", firstSeen: "2026-08-19" },
  { type: "package", value: "code-assist-mcp@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-79vg-qvmh-c7h2, MAL-2026-14233", firstSeen: "2026-08-19" },
  { type: "package", value: "gaarf@3.2.1", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-vgpc-5h45-gxjm, MAL-2026-14236", firstSeen: "2026-08-19" },
  { type: "package", value: "gaarf-bq@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-mqcc-6rh5-hxfm, MAL-2026-14237", firstSeen: "2026-08-19" },
  { type: "package", value: "gaarf-node@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-x44c-6j8r-28px, MAL-2026-14238", firstSeen: "2026-08-19" },
  { type: "package", value: "gaarf-node-bq@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-mf44-x4mq-gp48, MAL-2026-14239", firstSeen: "2026-08-19" },
  { type: "package", value: "gemini-cli-a2a-server@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-x74f-m7fv-4r68, MAL-2026-14244", firstSeen: "2026-08-19" },
  { type: "package", value: "github-policy-bot@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-6rrf-hp88-jgvw, MAL-2026-14245", firstSeen: "2026-08-19" },
  { type: "package", value: "karma-proxy@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-g89h-hjrj-33rj, MAL-2026-14267", firstSeen: "2026-08-19" },
  { type: "package", value: "localize-extract@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-hhg6-p2wv-g5w2, MAL-2026-14249", firstSeen: "2026-08-19" },
  { type: "package", value: "localize-translate@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-3j79-9c69-968q, MAL-2026-14279", firstSeen: "2026-08-19" },
  { type: "package", value: "ngsw-config@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-87qj-53cx-w424, MAL-2026-14251", firstSeen: "2026-08-19" },
  { type: "package", value: "tfjs-inference@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-697f-wmcx-8jq7, MAL-2026-14192", firstSeen: "2026-08-19" },
  { type: "package", value: "tizen-webdriver-cli@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-cffv-ggq7-fw2q, MAL-2026-13966", firstSeen: "2026-08-13" },
  { type: "package", value: "upload-to-gcp@3.2.1", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-jx3f-5x53-4484, MAL-2026-14067", firstSeen: "2026-08-15" },
  { type: "package", value: "wct-st@1.0.0", severity: "critical", confidence: 1.0, campaign: "npm Bin Entry Harvesting", source: "GHSA-6r3v-5c9p-jv7v, MAL-2026-13990", firstSeen: "2026-08-14" },

  // Imported from GitHub Advisory Database (2026-09-07) - see docs/threat-feed-sources.md
  { type: "package", value: "testmgkregme@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-hc49-rwm2-p2w7, MAL-2026-16317 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "test1sdsd2@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-9mc8-mrvr-f664, MAL-2026-16316 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "test1ro@999.99.99", severity: "critical", confidence: 1.0, source: "GHSA-8rr3-xrmc-xvjf, MAL-2026-16315 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "test1ro@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-8rr3-xrmc-xvjf, MAL-2026-16315 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "test1df23@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-78p9-g7q9-mcjw, MAL-2026-16312 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "test1hh235@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-qrfc-3762-c24w, MAL-2026-16314 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "chai-testing@1.1.4", severity: "critical", confidence: 1.0, source: "GHSA-5jvh-cf7p-qx9w, MAL-2026-16307 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "chat-adapter-matrix@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-2rg8-m9rx-gfhf, MAL-2026-16308 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "test1gg234@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-w7fw-w5xv-5p8v, MAL-2026-16313 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "test12vv36@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-7f39-795r-gxj4, MAL-2026-16311 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "npmscript_tesstalert_unpkg@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-r2rm-wm4f-f55p, MAL-2026-16309 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "npmscript_tesstalert_unpkg@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-r2rm-wm4f-f55p, MAL-2026-16309 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "npx-test-ma980@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-9vj4-6r95-2p6w, MAL-2026-16310 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@nimbusedge2/authxsas@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-8mrv-jcm6-9rv3, MAL-2026-16303 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@nimbusedge2/authxsas1@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-92qm-hjm8-mp6j, MAL-2026-16304 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@nimbusedge2/auth@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-9hmg-mp2c-g9wr, MAL-2026-16302 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@nimbusedge2/x@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-488m-x4jr-5x75, MAL-2026-16305 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@baanx/solana-lib@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-pvh9-27rp-6282, MAL-2026-16300 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@nimbsuedge3/xar@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-rg8r-9wp3-7jrg, MAL-2026-16301 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@nimbusedge2/xa@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-m4pg-jjmc-xgr9, MAL-2026-16306 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@pwaplatform/module-sso-integration@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-26h7-cmv3-wgv6, MAL-2026-16299 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-20" },
  { type: "package", value: "@pwaplatform/module-sso-integration@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-26h7-cmv3-wgv6, MAL-2026-16299 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-20" },
  { type: "package", value: "starbucks-sdk@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16345 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pflag29424@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16342 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "siriusbeyond@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16343 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "sorrawit-dev-helper@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16344 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "keroeltopgg@99.99.99", severity: "critical", confidence: 0.9, source: "MAL-2026-16334 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "feed-widget-helper@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16332 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pf25133@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16339 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pflag14570@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16341 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "commerce-materials@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16330 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "element-plus-vite-cli@2.9.3", severity: "critical", confidence: 0.9, source: "MAL-2026-16331 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "element-plus-vite-cli@2.9.5", severity: "critical", confidence: 0.9, source: "MAL-2026-16331 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "byted-commerce-materials@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16326 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "chai-as-viem@1.1.3", severity: "critical", confidence: 0.9, source: "MAL-2026-16329 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "keroeltopkk@99.99.99", severity: "critical", confidence: 0.9, source: "MAL-2026-16335 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "bulk-add-sdk@1.99.99", severity: "critical", confidence: 0.9, source: "MAL-2026-16325 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "catwrestlingbird@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16327 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@asenfotech/unplugin-element-plus@2.9.5", severity: "critical", confidence: 0.9, source: "MAL-2026-16318 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@asenfotech/unplugin-element-plus@2.9.3", severity: "critical", confidence: 0.9, source: "MAL-2026-16318 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "catwrestlinghuman@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16328 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "my-cdn-script@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16337 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@siriusbeyond/utils@99.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16322 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "action-slack-message-root@1.0.1", severity: "critical", confidence: 0.9, source: "MAL-2026-16323 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@siriusbeyond/auth@99.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16320 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "keroeltopkkk@99.99.99", severity: "critical", confidence: 0.9, source: "MAL-2026-16336 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.1.9", severity: "critical", confidence: 0.9, source: "MAL-2026-16333 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@dbbhk/ui-components@99.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16319 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "better-envforge@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16324 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pf25262@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16340 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pf23727@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16338 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@siriusbeyond/ui@99.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-16321 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.4.105", severity: "critical", confidence: 0.9, source: "MAL-2026-16346 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.3.100", severity: "critical", confidence: 0.9, source: "MAL-2026-16346 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.4.106", severity: "critical", confidence: 0.9, source: "MAL-2026-16346 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.4.103", severity: "critical", confidence: 0.9, source: "MAL-2026-16346 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.4.102", severity: "critical", confidence: 0.9, source: "MAL-2026-16346 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.4.104", severity: "critical", confidence: 0.9, source: "MAL-2026-16346 (amazon-inspector)", firstSeen: "2026-09-21" },

  // Mini Shai-Hulud / TeamPCP durabletask PyPI compromise (MAL-2026-4174,
  // May 2026). The three malicious versions were already pinned above; the
  // atomic infrastructure behind them was not. family and campaign are set so
  // these stay in the bundle and remain detectable with no network.
  { type: "domain", value: "check.git-service.com", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", source: "OSV MAL-2026-4174", firstSeen: "2026-05-19" },
  { type: "ip", value: "160.119.64.3", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", source: "OSV MAL-2026-4174", firstSeen: "2026-05-19" },
  { type: "url", value: "check.git-service.com/rope.pyz", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", source: "OSV MAL-2026-4174", firstSeen: "2026-05-19" },
  { type: "hash", value: "3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", source: "OSV MAL-2026-4174", firstSeen: "2026-05-19" },
  { type: "hash", value: "7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", source: "OSV MAL-2026-4174", firstSeen: "2026-05-19" },
  { type: "hash", value: "5246e60c2ff10ae058abba14ef5ea22432465ad827ec5f5c5572999411d90b80", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", source: "OSV MAL-2026-4174", firstSeen: "2026-05-19" },
  { type: "hash", value: "069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", source: "OSV MAL-2026-4174", firstSeen: "2026-05-19" },
  { type: "package", value: "pypi:rrs@0.3.5", severity: "critical", confidence: 0.9, source: "MAL-2026-16346 (amazon-inspector)", firstSeen: "2026-09-21" },

  // Imported from GitHub Advisory Database (2026-09-08) - see docs/threat-feed-sources.md
  { type: "package", value: "@uol-afiliados/affiliated-config-lib@102.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mh6g-473c-fvhx, MAL-2026-16370 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@zig-design-system/react", severity: "critical", confidence: 0.9, source: "GHSA-rqjq-px4f-2m8r, MAL-2026-16372 (ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "wos-library", severity: "critical", confidence: 0.9, source: "GHSA-mfwv-9gcf-2mww, MAL-2026-16373 (ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@vite-tab/tabui", severity: "critical", confidence: 0.9, source: "GHSA-q5h9-3mvh-45cf, MAL-2026-16371 (ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uh-platform/domain-widget@100.0.0", severity: "critical", confidence: 1.0, source: "GHSA-xh82-8x4m-9w6c, MAL-2026-16359 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@asdfaskdjfksadhfkasf/nadaver2@102.0.0", severity: "critical", confidence: 1.0, source: "GHSA-p368-v58m-82vj, MAL-2026-16357 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:pullgetsage@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-4whg-cvj9-8v3f, MAL-2026-16366 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uh-platform/webcard@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5h99-j25f-5q62, MAL-2026-16362 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "bytepack-probe-a7x3@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pjjj-2389-rwj6, MAL-2026-16364 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "bytepack-probe-a7x3@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-pjjj-2389-rwj6, MAL-2026-16364 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uh-platform/nadaver2@102.0.0", severity: "critical", confidence: 1.0, source: "GHSA-99r3-9hc2-372p, MAL-2026-16361 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uh-platform/nadaver@102.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5r3f-92qc-25rr, MAL-2026-16360 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uh-platform/cloud@101.0.0", severity: "critical", confidence: 1.0, source: "GHSA-g4jv-48fc-mhh2, MAL-2026-16358 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "blue-string-formatter-utilss@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-4g26-86h7-34h3, MAL-2026-16363 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "my-ctf-helper-script-9921@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-qhgh-m36j-h879, MAL-2026-16365 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "math-universe", severity: "critical", confidence: 0.9, source: "GHSA-97cg-r346-fg22, MAL-2026-16367 (ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "mathsbase", severity: "critical", confidence: 0.9, source: "GHSA-v4cx-64j6-84xm, MAL-2026-16369 (ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "mathmain", severity: "critical", confidence: 0.9, source: "GHSA-v6mx-2p6p-3628, MAL-2026-16368 (ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "hardhat-devkit@2.3.6", severity: "critical", confidence: 1.0, source: "GHSA-2wmg-qp72-3736, MAL-2026-16349 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@woodpecker-web-shared/components@2.20.5", severity: "critical", confidence: 1.0, source: "GHSA-8hq6-gvg5-x8wq, MAL-2026-16354 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "gemini-computer-use@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-4cwr-c4gf-f9r4, MAL-2026-16355 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "bnppf-flag-icons@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-r56f-8237-82ch, MAL-2026-16350 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@insiderintelligence/componentlibrary@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-5h4w-mvwx-ff8q, MAL-2026-16353 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "hardhat-base@2.2.2", severity: "critical", confidence: 1.0, source: "GHSA-g59v-28j4-2r85, MAL-2026-16348 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "hardhat-base@2.2.0", severity: "critical", confidence: 1.0, source: "GHSA-g59v-28j4-2r85, MAL-2026-16348 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:starlette-healthchecks@1.3.1", severity: "critical", confidence: 1.0, source: "GHSA-6g46-rqp7-42mp, MAL-2026-16356 (kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:starlette-healthchecks@1.3.2", severity: "critical", confidence: 1.0, source: "GHSA-6g46-rqp7-42mp, MAL-2026-16356 (kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "@baanx/abis@9.9.11", severity: "critical", confidence: 1.0, source: "GHSA-r554-rpx4-qw24, MAL-2026-16351 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@baanx/blockchain-config@9.9.11", severity: "critical", confidence: 1.0, source: "GHSA-7cc3-jjqj-wrm5, MAL-2026-16352 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "radio-player-theme@6.0.0", severity: "critical", confidence: 1.0, source: "GHSA-3rj7-hf4w-jh5c, MAL-2026-16347", firstSeen: "2026-09-19" },
];

const FEED_CHUNK_21: FeedIOC[] = [
  // Imported from GitHub Advisory Database (2026-09-08) - see docs/threat-feed-sources.md
  { type: "package", value: "pypi:rrs@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.1.3", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.1.4", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.1.5", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.1.7", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.1.8", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.2.1", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.2.2", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.3.101", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.4.107", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.4.108", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:rrs@0.4.109", severity: "critical", confidence: 1.0, source: "GHSA-5w9q-gw92-3wq8, MAL-2026-16346 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "npmscript_tesstalert_unpkg@1.1.8", severity: "critical", confidence: 1.0, source: "GHSA-r2rm-wm4f-f55p, MAL-2026-16309 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "npmscript_tesstalert_unpkg@1.1.7", severity: "critical", confidence: 1.0, source: "GHSA-r2rm-wm4f-f55p, MAL-2026-16309 (amazon-inspector)", firstSeen: "2026-09-21" },
  // TraderTraitor FLATROOF / ROOFDECK macOS backdoors (SentinelLabs, September
  // 2026). Curated enrichment, not an advisory-database import: these atomic
  // indicators carry campaign and family so the partition policy keeps them in
  // the bundle and they stay detectable with no network.
  { type: "domain", value: "registry.hashicorp-aws.com", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "domain", value: "registry.hashicorp-aws.io", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "domain", value: "registry.hashicorp-terraform.io", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "domain", value: "technicais.sytes.net", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "domain", value: "storage.hubpage.cloud", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "domain", value: "grenight.com", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "ip", value: "176.97.114.232", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "ip", value: "45.11.59.140", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "ip", value: "85.137.56.245", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "ip", value: "85.137.56.10", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "hash", value: "02df07a173ab03b82a4fb6a08973fff8b1467f28", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "hash", value: "c491d477dbe0ae04e9aed9dbe237144c03f73ec4", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },
  { type: "hash", value: "5728b11d30586bbfc1d8bd12df1c722a06e767a2", severity: "critical", confidence: 1.0, family: "TraderTraitor", campaign: "TraderTraitor FLATROOF/ROOFDECK macOS backdoors", source: "SentinelLabs TraderTraitor report", firstSeen: "2026-09-22" },

  // Imported from GitHub Advisory Database (2026-09-09) - see docs/threat-feed-sources.md
  { type: "package", value: "@test1230504/string-format-helper", severity: "critical", confidence: 0.9, source: "GHSA-9572-4cpv-x2hp", firstSeen: "2026-09-23" },
  { type: "package", value: "@test1230504/probe-7f3k2m-utils", severity: "critical", confidence: 0.9, source: "GHSA-3qx9-8g8p-4mcj", firstSeen: "2026-09-23" },
  { type: "package", value: "@test1230504/test-publish-verify", severity: "critical", confidence: 0.9, source: "GHSA-7m76-mq85-8c7w", firstSeen: "2026-09-23" },
  { type: "package", value: "z-deno-truth-ya1t4m", severity: "critical", confidence: 0.9, source: "GHSA-qff9-mw3p-hg4c", firstSeen: "2026-09-23" },
  { type: "package", value: "z-deno-truth-va499w", severity: "critical", confidence: 0.9, source: "GHSA-76wq-hx78-mw6x", firstSeen: "2026-09-23" },
  { type: "package", value: "z-deno-truth-bwhlsz", severity: "critical", confidence: 0.9, source: "GHSA-f8xr-gjfq-xfcp", firstSeen: "2026-09-23" },
  { type: "package", value: "efhthrthrthregerht@99.9.9", severity: "critical", confidence: 1.0, source: "GHSA-rxg9-j4gc-5m6m, MAL-2026-16436 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "eslint-plugin-i18n-shreddit@99.9.9", severity: "critical", confidence: 1.0, source: "GHSA-h5xr-5j26-q5rm, MAL-2026-16437 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "@vitemirrorte/element-plus-vite-cli@2.9.1", severity: "critical", confidence: 1.0, source: "GHSA-j7hr-ff2j-rgv6, MAL-2026-16433 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "internallib_v497@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-m9ww-2r6q-x632, MAL-2026-16438 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "catqrcodeconverter@99.2.1", severity: "critical", confidence: 1.0, source: "GHSA-f639-24m5-rmxp, MAL-2026-16435 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "catplatebarcodeparser@99.2.1", severity: "critical", confidence: 1.0, source: "GHSA-7h34-v43h-45gc, MAL-2026-16434 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "turbo-ws@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-49rw-43cc-8cmh, MAL-2026-16440 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "n8n-nodes-metricsagent@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-g3pf-m29r-p353, MAL-2026-16445 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "internallib_v550@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-vc8f-vp28-j8g3, MAL-2026-16439 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "moudeva@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8c6q-78vh-4fwp, MAL-2026-16442 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "moidevl@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-x8vv-mr6f-v7gf, MAL-2026-16441 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "n8n-nodes-healthmon@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-j6fv-f788-59cj, MAL-2026-16444 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "my-company-device@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-q4cw-hqw3-j56g, MAL-2026-16443 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "my-company-device@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-q4cw-hqw3-j56g, MAL-2026-16443 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "some-tool-package", severity: "critical", confidence: 0.9, source: "GHSA-55vw-cpj6-w7w8, MAL-2026-16455 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "better-md", severity: "critical", confidence: 0.9, source: "GHSA-r4h9-57fh-5fj3, MAL-2026-16446 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "semver-bump-io", severity: "critical", confidence: 0.9, source: "GHSA-m877-5x7f-7r88, MAL-2026-16453 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "webp-https-errors", severity: "critical", confidence: 0.9, source: "GHSA-gmm9-q3gf-4hfr, MAL-2026-16459 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "solo-async-pipe", severity: "critical", confidence: 0.9, source: "GHSA-j96p-xm58-6233, MAL-2026-16454 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "debounce-throttle-base", severity: "critical", confidence: 0.9, source: "GHSA-g9m6-qcpw-g96x, MAL-2026-16448 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "iso-datetime-core", severity: "critical", confidence: 0.9, source: "GHSA-fc7h-qf7q-qxw4, MAL-2026-16449 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "kamafhbnowct", severity: "critical", confidence: 0.9, source: "GHSA-j87m-pgqx-mpg5, MAL-2026-16450 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "luftzxyuiwgbgsp", severity: "critical", confidence: 0.9, source: "GHSA-cppx-756q-g98p, MAL-2026-16451 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "tib2jcvowuyma", severity: "critical", confidence: 0.9, source: "GHSA-hqgj-c9q6-8qv8, MAL-2026-16456 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "xsjukcnv8low26", severity: "critical", confidence: 0.9, source: "GHSA-6g8g-gw7h-prch, MAL-2026-16460 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "tuxcmdfhjkw", severity: "critical", confidence: 1.0, source: "GHSA-67q5-w9wg-mvvv, MAL-2026-16458 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "mob4zchvuine", severity: "critical", confidence: 0.9, source: "GHSA-f232-pcw4-j7qg, MAL-2026-16452 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "caphsmgiwy", severity: "critical", confidence: 0.9, source: "GHSA-35mc-7f44-62rg, MAL-2026-16447 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "tibcwmpoeafh", severity: "critical", confidence: 0.9, source: "GHSA-vcg8-c5h2-55w6, MAL-2026-16457 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-file-providers", severity: "critical", confidence: 0.9, source: "GHSA-2jrv-g43f-qm7f, MAL-2026-16427 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-commands", severity: "critical", confidence: 0.9, source: "GHSA-cv26-mq7q-h5hq, MAL-2026-16425 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-cli-adapter", severity: "critical", confidence: 0.9, source: "GHSA-hmmw-27v2-3qc8, MAL-2026-16424 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-project", severity: "critical", confidence: 0.9, source: "GHSA-xj44-gx57-mm59, MAL-2026-16432 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-plugin-memory-context", severity: "critical", confidence: 0.9, source: "GHSA-r4qq-8p58-gfpv, MAL-2026-16431 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-evidence", severity: "critical", confidence: 0.9, source: "GHSA-mjfj-x5qx-p7v8, MAL-2026-16426 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-plugin-file-memory", severity: "critical", confidence: 0.9, source: "GHSA-64w5-qg43-54g7, MAL-2026-16430 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-plugin-file-events", severity: "critical", confidence: 0.9, source: "GHSA-6866-wx9h-j2rh, MAL-2026-16429 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-authority", severity: "critical", confidence: 0.9, source: "GHSA-8h24-fp89-4cw3, MAL-2026-16423 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@wizloft/harness-memory", severity: "critical", confidence: 0.9, source: "GHSA-3mjw-625p-wvhf, MAL-2026-16428 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@httttt/mcp-npx-fetch-1", severity: "critical", confidence: 0.9, source: "GHSA-q6m6-3rfx-7f62, MAL-2026-16422 (ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "action-slack-message-root", severity: "critical", confidence: 1.0, source: "GHSA-mrmw-mqq6-fp9w, MAL-2026-16323 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "better-envforge", severity: "critical", confidence: 1.0, source: "GHSA-3h54-43fv-m822, MAL-2026-16324 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "chai-as-viem", severity: "critical", confidence: 1.0, source: "GHSA-88fm-v2m3-mx8x, MAL-2026-16329 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@pwaplatform/module-sso-integration", severity: "critical", confidence: 1.0, source: "GHSA-3gx2-xpw8-x42p, MAL-2026-16299 (amazon-inspector+ghsa-malware+ossf-package-analysis)", firstSeen: "2026-09-20" },
  { type: "package", value: "@uh-platform/webcard", severity: "critical", confidence: 1.0, source: "GHSA-7w7p-g9xr-2v29, MAL-2026-16362 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uol-afiliados/affiliated-config-lib", severity: "critical", confidence: 1.0, source: "GHSA-mx57-mmpv-mwjr, MAL-2026-16370 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uh-platform/nadaver2", severity: "critical", confidence: 1.0, source: "GHSA-x2pw-3pc4-xvh5, MAL-2026-16361 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uh-platform/domain-widget", severity: "critical", confidence: 1.0, source: "GHSA-c842-qvgg-5vpf, MAL-2026-16359 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uh-platform/nadaver", severity: "critical", confidence: 1.0, source: "GHSA-v7wx-gg27-6p9g, MAL-2026-16360 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@asdfaskdjfksadhfkasf/nadaver2", severity: "critical", confidence: 1.0, source: "GHSA-xxcj-347q-8rrr, MAL-2026-16357 (amazon-inspector+ghsa-malware+ossf-package-analysis)", firstSeen: "2026-09-21" },
  { type: "package", value: "@uh-platform/cloud", severity: "critical", confidence: 1.0, source: "GHSA-xrhc-2pph-j3f7, MAL-2026-16358 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:pullgetsage@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-4whg-cvj9-8v3f, MAL-2026-16366 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:pullgetsage@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-4whg-cvj9-8v3f, MAL-2026-16366 (amazon-inspector+kam193)", firstSeen: "2026-09-21" },
  { type: "package", value: "@woodpecker-web-shared/components@4.20.5", severity: "critical", confidence: 1.0, source: "GHSA-8hq6-gvg5-x8wq, MAL-2026-16354 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@woodpecker-web-shared/components@1.20.4", severity: "critical", confidence: 1.0, source: "GHSA-8hq6-gvg5-x8wq, MAL-2026-16354 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "@lekzo/baileys@0.0.7", severity: "critical", confidence: 1.0, source: "GHSA-75mc-fj4c-6pfm, MAL-2026-16276 (amazon-inspector)", firstSeen: "2026-09-18" },
  // Graphalgo campaign spreads to Terraform providers and Go modules (Aikido,
  // September 2026). Curated enrichment, not an advisory-database import: these
  // carry campaign and family so the partition policy keeps them in the bundle.
  // Single-source, hence confidence 0.85. The two Terraform providers are
  // matched by terraform-scanner.ts in .tf, .tf.json and .terraform.lock.hcl;
  // no versions were published, so they are name-level.
  { type: "package", value: "go:gocommunity.io/orderedbtree", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "package", value: "go:gogets.dev/btreex", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "package", value: "terraform:gocommunity-io/dockerd", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "package", value: "terraform:kreuzwenker/docker", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "domain", value: "gocommunity.io", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "domain", value: "gogets.dev", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "domain", value: "portfolio-devs.slack.com", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "domain", value: "portfolio-testers.slack.com", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "domain", value: "mediumstar.slack.com", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "hash", value: "5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },
  { type: "hash", value: "ab01686d87565250fc4989faddb877d793667b07ec217a61cbd798f5695d62f5", severity: "critical", confidence: 0.85, family: "Graphalgo", campaign: "Graphalgo Terraform providers and Go modules", source: "Aikido Graphalgo Terraform/Go write-up (single-source)", firstSeen: "2026-09-22" },

  // VS Code extension kept in the offline bundle (6.4.3 release review). Imported
  // from the GitHub Advisory Database on 2026-09-07 (docs/threat-feed-sources.md),
  // then curated by hand: it is the bundle's only `vscode:` entry, so without this
  // block the cutoff would leave a default offline scan with no VS Code coverage.
  // Whole-extension since 2026-09-23 (was pinned to 1.0.4, the only version the advisory
  // lists): every version the Marketplace still serves (1.0.0, 1.0.1, 1.0.2, 1.0.4) ships the
  // same edrdrill.js beacon to the fronted azure-cdn[.]info host, verified by opening each
  // VSIX, and the publisher name matches that host. No clean release exists to protect.
  { type: "package", value: "vscode:AzureCdnInfo.edrtester", severity: "critical", confidence: 0.9, source: "MAL-2026-16010", firstSeen: "2026-09-03" },

  // Shai-Hulud 2.0 reached Maven Central through mvnpm, which republishes npm packages as
  // Maven artifacts: the trojanized posthog-node 4.18.1 was mirrored as
  // org.mvnpm:posthog-node 4.18.1 (GHSA-5f38-2pgv-jhg6, OSV MAL-2025-191470). Version-pinned:
  // mvnpm and posthog-node are legitimate, only the mirrored worm release is malicious.
  // Curated so the partition policy keeps it bundled, as the offline anchor of the maven:
  // ecosystem.
  { type: "package", value: "maven:org.mvnpm:posthog-node@4.18.1", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Shai-Hulud 2.0 mvnpm mirror", source: "GHSA-5f38-2pgv-jhg6, MAL-2025-191470", firstSeen: "2025-11-26" },

  // tj-actions/changed-files compromise (March 14-15 2025, CVE-2025-30066). The malicious
  // commit was pushed from a fork and every version tag was repointed to it; GitHub has since
  // purged it, but a workflow pinned to it still names it. Tags were restored, so only the SHA
  // is an indicator. Replaces the hardcoded map in github-actions-scanner.ts, whose label
  // said September 2025.
  { type: "package", value: "actions:tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "tj-actions/changed-files compromise", source: "GHSA-mrrh-fwg8-r2c3, StepSecurity, Wiz", firstSeen: "2025-03-14" },

  // reviewdog/action-setup compromise (March 11 2025, CVE-2025-30154), the upstream of the
  // tj-actions incident. The v1 tag pointed at this commit for about two hours; it is off the
  // default branch and its install.sh dumps runner memory. The previously hardcoded
  // 3f401fe1...69b8cdfe4 did not exist: it was a corrupted copy of the CLEAN v1.3.0 commit the
  // tag was reverted to, and is deliberately not listed.
  { type: "package", value: "actions:reviewdog/action-setup@f0d342d24037bb11d26b9bd8496e0808ba32e9ec", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "reviewdog action-setup compromise", source: "CVE-2025-30154, Wiz, StepSecurity", firstSeen: "2025-03-11" },

  // TeamPCP Trivy GitHub Actions compromise (March 19-20 2026, CVE-2026-33634). Every version
  // tag of aquasecurity/trivy-action (0.0.1 to 0.34.2) and seven setup-trivy tags were
  // repointed to imposter commits parented on the then-current clean release. Each SHA was
  // verified 2026-09-23: it exists, has that clean parent, and is not on the default branch.
  // Tags were deleted or re-created clean, so only the SHAs are indicators.
  { type: "package", value: "actions:aquasecurity/setup-trivy@8afa9b9f9183b4e00c46e2b82d34047e3c177bd0", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/setup-trivy@386c0f18ac3d7f2ed33e2d884761119f4024ff8a", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/setup-trivy@384add36b52014a0f99c0ab3a3d58bd47e53d00f", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/setup-trivy@7a4b6f31edb8db48cc22a1d41e298b38c4a6417e", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/setup-trivy@6d8d730153d6151e03549f276faca0275ed9c7b2", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/setup-trivy@99b93c070aac11b52dfc3e41a55cbb24a331ae75", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/setup-trivy@f4436225d8a5fd1715d3c2290d8a50643e726031", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@f77738448eec70113cf711656914b61905b3bd47", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@b9faa60f85f6f780a34b8d0faaf45b3e3966fdda", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@3c615ac0f29e743eda8863377f9776619fd2db76", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@c19401b2f58dc6d2632cb473d44be98dd8292a93", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@4209dcadeaea6a7df69262fef1beeda940881d4d", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@61fbe20b7589e6b61eedcd5fe1e958e1a95fbd13", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@0d49ceb356f7d4735c63bd0d5c7e67665ec7f80c", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@2e7964d59cd24d1fd2aa4d6a5f93b7f09ea96947", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@1d74e4cf63b7cf083cf92bf5923cf037f7011c6b", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@3201ddddd69a1419c6f1511a14c5945ba3217126", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@ea56cd31d82b853932d50f1144e95b21817e52cf", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@f5c9fd927027beaa3760d2a84daa8b00e6e5ee21", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@9738180dd24427b8824445dbbc23c30ffc1cb0d8", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@ef3a510e3f94df3ea9fcd01621155ca5f2c3bf5b", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@bb75a9059c2d5803db49e6ed6c6f7e0b367f96be", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@22e864e71155122e2834eb0c10d0e7e0b8f65aa3", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@6ec7aaf336b7d2593d980908be9bc4fed6d407c6", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@555e7ad4c895c558c7214496df1cd56d1390c516", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@794b6d99daefd5e27ecb33e12691c4026739bf98", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@506d7ff06abc509692c600b5b69b4dc6ceaa4b15", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@91d5e0a13afab54533a95f8019dd7530bd38a071", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@252554b0e1130467f4301ba65c55a9c373508e35", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@9e8968cb83234f0de0217aa8c934a68a317ee518", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@8aa8af3ea1de8e968a3e49a40afb063692ab8eae", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@e53b0483d08da44da9dfe8a84bf2837e5163699b", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@276ca9680f6df9016db12f7c48571e5c4639451d", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@8ae5a08aec3013ee8f6132b2a9012b45002f8eaa", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@820428afeb64484d311211658383ce7f79d31a0a", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@cf19d27c8a7fb7a8bbf1e1000e9318749bcd82cf", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@405e91f329294fb696f55793203abf1f6aba9b40", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@2297a1b967ecc05ba2285eb6af56ab4da554ecae", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@2b1dac84ff12ba56158b3a97e2941a587cb20da9", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@f4f1785be270ae13f36f6a8cfbf6faaae50e660a", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@3d1b5be1589a83fc98b82781c263708b2eb3b47b", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@985447b035c447c1ed45f38fad7ca7a4254cb668", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@85cb72f1e8ee5e6e44488cd6cbdbca94722f96ed", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@38623bf26706d51c45647909dcfb669825442804", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@7f6f0ce52a59bdfc5757c3982aac2353b58f4c73", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@0891663bc55073747be0eb864fbec3727840945d", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@3dffed04dc90cf1c548f40577d642c52241ec76c", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@cf1692a1fc7a47120e6508309765db7e33477946", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@848d665ed24dc1a41f6b4b7c7ffac7693d6b37be", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@fa4209b6182a4c1609ce34d40b67f5cfd7f00f53", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@9092287c0339a8102f91c5a257a7e27625d9d029", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@b7befdc106c600585d3eec87d7e98e1c136839ae", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@9ba3c3cd3b23d033cd91253a9e61a4bf59c8a670", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@fd090040b5f584f4fcbe466878cb204d0735dcf4", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@e0198fd2b6e1679e36d32933941182d9afa82f6f", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@ddb94181dcbc723d96ffc07fddd14d97e4849016", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@b7252377a3d82c73d497bfafa3eabe84de1d02c4", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@66c90331c8b991e7895d37796ac712b5895dda3b", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@c5967f85626795f647d4bf6eb67227f9b79e02f5", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@9c000ba9d482773cbbc2c3544d61b109bc9eb832", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@8cfb9c31cc944da57458555aa398bb99336d5a1f", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@ad623e14ebdfe82b9627811d57b9a39e283d6128", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@8519037888b189f13047371758f7aed2283c6b58", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@fd429cf86db999572f3d9ca7c54561fdf7d388a4", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@19851bef764b57ff95b35e66589f31949eeb229d", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@91e7c2c36dcad14149d8e455b960af62a2ffb275", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@ab6606b76e5a054be08cab3d07da323e90e751e8", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@a9bc513ea7989e3234b395cafb8ed5ccc3755636", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@ddb9da4475c1cef7d5389062bdfdfbdbd1394648", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@18f01febc4c3cd70ce6b94b70e69ab866fc033f5", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@7b955a5ece1e1b085c12dac7ac10e0eb1f5b0d4d", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@d488f4388ff4aa268906e25c2144f1433a4edec2", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@fa78e67c0df002c509bcdea88677fb5e2fe6a9b1", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@a5b4818debf2adbaba872aaffd6a0f64a26449fa", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@6fc874a1f9d65052d4c67a314da1dae914f1daff", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@2a51c5c5bb1fd1f0e134c9754f1702cfa359c3dd", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@ddb6697447a97198bdef9bae00215059eb5e8bc2", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@aa3c46a9643b18125abb8aefc13219014e9c4be8", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@4bdcc5d9ef3ddb42ccc9126e6c07faa3df2807e3", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@b745a35bad072d93a9b83080e9920ec52c6b5a27", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@da73ae0790e458e878b300b57ceb5f81ac573b46", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },
  { type: "package", value: "actions:aquasecurity/trivy-action@7550f14b64c1c724035a075b36e71423719a1f30", severity: "critical", confidence: 1.0, family: "ActionTagHijack", campaign: "TeamPCP Trivy Actions compromise", source: "GHSA-69fq-xp46-6x23, StepSecurity, Wiz", firstSeen: "2026-03-19" },

  // TeamPCP Checkmarx KICS GitHub Action compromise (March 23 2026). All tags repointed to
  // imposter commits parented on the clean v2.1.20. The per-tag list comes from one vendor
  // (Wiz); every SHA was verified 2026-09-23 against the API as above, hence 0.95.
  { type: "package", value: "actions:checkmarx/kics-github-action@45f3749467a6017cb4fb749054b498d149dd5924", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@8e20c7a67bb95632e2040327a355fb97e6014d29", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@93de85c910d859b759cf9185aa78d5a23a4b7000", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@0e7343ba084735863db92b6f8ba2fa9dee604f7c", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@2dc0fa613f6f4c15f26ad98225ad253475681616", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@f00191dd3352c0cd83c6cce4e6bf04b628214dd0", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@e0359b1a253ee66c8018586c3225e6e9cd2d8a4f", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@dc6dbf358998c0c64da83edc8fcd581c12656b19", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@08b9ea97eb292d5e1f9ac2d8e21c0ba32f0fdff0", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@005fb0837553de722f8bf11d98e905dbdde19861", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@a5471d37c656ecd4560e8e0b3977910f27025618", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@121c38fb49c9fc82160245fb6e2a9119db636e4d", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@1e9eeaba37fe0032deba133f598e74dab0ceb3b7", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@c5c07508527fc6a125855eebfb533e64f675bd8e", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@c999dbb9cc904e23675f9929f7e0e51d132879cf", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@4ebf62dd8ff318412b38d19841fc3c8650e294bf", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@3ae9f0d6f8139964635d411149f9b3e0a6eb935e", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@96a0e8eb31c3cce6c495c9a49dd49c881cd17934", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@31fbf5831a2e52429738fdc0cbaa20e57872b6fc", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@fca3a20afcb8ec7f9932c060a236d2a9021fdd2b", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@0f81f132f9f09bb4976d403914a44a1a1eb6158d", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@c0e23718a5074f3b8ad286f37b532e02057af35f", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@d66f0657133bc42f8264458063999bf1910490db", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@e35c9d6a5faffc1c5b3450d0bf09006aa9b9e906", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@2eee333d70fb6e14ce1d4aa73f12058bc5d70193", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@f9641eb512f5c6530d13275903e8a97baf0925f1", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@e8754eebc822b5122e96a6142b28dbc0e179c91c", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@69b3f020390222a9fcb6029ba56533b2fb12f103", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@db942a0dd7e9d1aeac72bc675bdb67f39a688b63", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@208813bf5feca5df9a935363cd426bc914614d0b", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@3fdeadb81fbeddc1453163cc87bc173911fd47e2", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@310734c0ffd29438f6195a24e2cbbacfdc33c9ab", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },
  { type: "package", value: "actions:checkmarx/kics-github-action@b974e53df1e3a2cd22ea90f0ec01882394feede4", severity: "critical", confidence: 0.95, family: "ActionTagHijack", campaign: "TeamPCP KICS Action compromise", source: "Wiz, StepSecurity", firstSeen: "2026-03-23" },

  // universal_file_viewer XCSSET compromise on pub.dev (September 8 2026), the first compromised
  // pub package on record. A legitimate package whose maintainer's machine was infected, so
  // version-pinned: 0.1.5 and 0.1.6 are the two releases the maintainer retracted (pub.dev API,
  // verified 2026-09-23); 0.1.7, the current release, is clean. The archive hashes are pub.dev's
  // archive_sha256 values, which pubspec.lock records. The two C2 hosts are single-source.
  { type: "package", value: "pub:universal_file_viewer@0.1.5", severity: "critical", confidence: 1.0, family: "XCSSET", campaign: "universal_file_viewer XCSSET compromise", source: "Aikido, pub.dev retraction", firstSeen: "2026-09-08" },
  { type: "package", value: "pub:universal_file_viewer@0.1.6", severity: "critical", confidence: 1.0, family: "XCSSET", campaign: "universal_file_viewer XCSSET compromise", source: "pub.dev retraction", firstSeen: "2026-09-08" },
  { type: "hash", value: "5cea38548f03cf44ad03bba44a3c6012782f280bd543a3c555535081353feb04", severity: "critical", confidence: 1.0, family: "XCSSET", campaign: "universal_file_viewer XCSSET compromise", source: "pub.dev archive_sha256", firstSeen: "2026-09-08" },
  { type: "hash", value: "394220c2c0305231fd0f6fd09355634d51acdd87415404b57e7e422af6af3e8d", severity: "critical", confidence: 1.0, family: "XCSSET", campaign: "universal_file_viewer XCSSET compromise", source: "pub.dev archive_sha256", firstSeen: "2026-09-08" },
  { type: "domain", value: "5yotmxcc54l9xda.ru", severity: "critical", confidence: 0.85, family: "XCSSET", campaign: "universal_file_viewer XCSSET compromise", source: "Aikido (single-source)", firstSeen: "2026-09-08" },
  { type: "domain", value: "ejntin6hkjt7gj2.ru", severity: "critical", confidence: 0.85, family: "XCSSET", campaign: "universal_file_viewer XCSSET compromise", source: "Aikido (single-source)", firstSeen: "2026-09-08" },

  // TeamPCP Trivy container images (March 19-23 2026). Tags 0.69.4, 0.69.5 and 0.69.6 only ever
  // held the malicious builds and were deleted, so the TAGS are indicators as well as every
  // index and per-platform digest. All digests appear verbatim in Aqua's advisory
  // GHSA-69fq-xp46-6x23; all tags and digests return 404 on Docker Hub (verified 2026-09-23,
  // with the clean 0.69.3 returning 200). The latest tag was malicious only during the window
  // and is clean now, so it is not listed.
  { type: "package", value: "docker:aquasec/trivy@0.69.4", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:12c702212dee1cbec9471e9261501a3335963321fe76e60e5a715b5acd3c40a2", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:2d7cee41048988eec27615412e7c6e2e21046f2b5faa888c24e11ca6764058ed", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:ae3494bd6ae860d7727116681bd09fc7b20dc994ec7a8105738f0a623ea93427", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:43f46547efd488e56dcf862ed4d7cc342730a803f8d5bec5cac443028fefabef", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@0.69.5", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:5aaa1d7cfa9ca4649d6ffad165435c519dc836fa6e21b729a2174ad10b057d2b", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:95ff680103570179feb0c6667a9b9b2d98c53fa5a9a451265036810390bbe70a", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:4f7a06bb51714713ab308d2f8125f3b09ee1c3ffbba1a5ffd0cc80da95fbb6cc", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:edef8e5816eced552a909b878ff262c0c47776d3297bcc23796ad4cce1e85414", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@0.69.6", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:425cd3e1a2846ac73944e891250377d2b03653e6f028833e30fc00c1abbc6d33", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:dd8beb3b40df080b3fd7f9a0f5a1b02f3692f65c68980f46da8328ce8bb788ef", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:4b22cedea58780ff76735c3e08b9ee8cb5d06c908ffa868152f11d45349eb696", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:9efd59534d2b6b81b8b7a0eeb3ad0e74015f358650e24b9dab00c900d3118593", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  { type: "package", value: "docker:aquasec/trivy@sha256:5e5fb53cf4ce5555171ff5206302ba2f4f66f5381bbf673c354c87a925473f07", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },

  // Checkmarx KICS container images (April 22 2026), same breach as the audit.checkmarx.cx C2
  // entries above. Only v2.1.21 and v2.1.21-debian never held clean content; alpine, debian,
  // v2.1.20, v2.1.20-debian and latest were restored, so for those only the digests are
  // indicators. Two independent secondary sources and no vendor advisory, hence 0.95; every
  // tag and digest returns 404 on Docker Hub (verified 2026-09-23, latest returning 200).
  { type: "package", value: "docker:checkmarx/kics@v2.1.21", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@v2.1.21-debian", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@sha256:2588a44890263a8185bd5d9fadb6bc9220b60245dbcbc4da35e1b62a6f8c230d", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@sha256:d186161ae8e33cd7702dd2a6c0337deb14e2b178542d232129c0da64b1af06e4", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@sha256:415610a42c5b51347709e315f5efb6fffa588b6ebc1b95b24abf28088347791b", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@sha256:222e6bfed0f3bb1937bf5e719a2342871ccd683ff1c0cb967c8e31ea58beaf7b", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@sha256:a6871deb0480e1205c1daff10cedf4e60ad951605fd1a4efaca0a9c54d56d1cb", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@sha256:ff7b0f114f87c67402dfc2459bb3d8954dd88e537b0e459482c04cffa26c1f07", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@sha256:a0d9366f6f0166dcbf92fcdc98e1a03d2e6210e8d7e8573f74d50849130651a0", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@sha256:26e8e9c5e53c972997a278ca6e12708b8788b70575ca013fd30bfda34ab5f48f", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },
  { type: "package", value: "docker:checkmarx/kics@sha256:7391b531a07fccbbeaf59a488e1376cfe5b27aef757430a36d6d3a087c610322", severity: "critical", confidence: 0.95, family: "CredStealer", campaign: "Checkmarx KICS Breach", source: "Socket, Docker", firstSeen: "2026-04-22" },

  // Browser extensions, JetBrains plugins and a Homebrew tap (curated 2026-09-23). Every
  // identity was checked against its store's CURRENT state; the rule decides the block type:
  // a hijacked LEGITIMATE extension is pinned to its malicious version only, an extension its
  // own publisher turned malicious is blocked by id. Curated with campaign/family so the
  // partition policy keeps them bundled and offline.

  // Cyberhaven wave (December 2024): hijacked extensions, malicious version only. Most are
  // live again with clean releases (Chrome Web Store, verified 2026-09-23). Cyberhaven's own
  // version has two sources; the rest come from the Secure Annex table and Sekoia.
  { type: "package", value: "chrome:pajkjnmeojmbapicmbpliphjmcekeaac@24.10.4", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:nnpnnpemnckcfdebeekibpiijlicmpom@2.0.1", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:kkodiihpgodmdankclfibbiphjkfdenh@1.16.2", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:oaikpkmjciadfpddlpjjdapglcihgdle@1.0.12", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:dpggmcodlahmljkhlmpgpdcffdaoccni@1.1.1", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:acmfnomgphggonodopogfbmkneepfgnh@4.00", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:mnhffkhmpnefgklngfmlndmkimimbphc@4.40", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:cedgndijpacnfbdggppddacngjfdkaca@0.0.11", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:egmennebgadmncfjafcemlecimkepcle@2.2.7", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:befflofjcniongenjmbkgkoljhgliihe@2.13.0", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:llimhhconnjiflfimocjggfjdlmlhblm@1.5.7", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:oeiomhmbaapihbilkfkhmlajkeegnjhe@3.18.0", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:ekpkdmohpdnebfedjjfklhpefgpgaaji@1.3", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:eanofdhdfbcalhflpbdipkjjkoimeeod@1.4.9", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:igbodamhgjohafcenbcljfegbipdfjpk@2.3", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:mbindhfolmpijhodmgkloeeppmkhpmhc@1.44", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:hodiladlefdpcbemnbbcpclbmknkiaem@3.1.3", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:ndlbedplllcgconngcnfmkadhokfaaln@2.22.6", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:cplhlgabfijoiabgkigdafklbhhdkahj@1.0.161", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:jiofmdifioeejeilfkpegipdjiopiekl@1.1.61", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:hihblcmlaaademjlakdpicchbjnnnkbo@3.0.2", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:bbdnohkpnbkdkmnkddobeafboooinpla@1.0.1", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:bibjgkidgpfbblifamdlkdlhgihmfohh@0.1.3", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:pkgciiiancapdlpcbppfkmeaieppikkk@1.3.7", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:epikoohpebngmakjinphfiagogjcnddm@2.7.3", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:miglaibdlgminlepgeifekifakochlka@1.4.5", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:ogbhbgkiojdollpjbhbamafmedkeockb@1.8.1", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:bgejafhieobnfpjlpcjjggoboebonfcg@1.1.1", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:epdjhgbipjpbbhoccdeipghoihibnfja@1.4", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:lbneaaedflankmgmfbmaplggbmjjmbae@1.3.8", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:eaijffijbobmnonfhilihbejadplhddo@2.4", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },
  { type: "package", value: "chrome:hmiaoahjllhfgebflooeeefeiafpkfde@1.0.0", severity: "critical", confidence: 0.9, family: "CyberhavenWave", campaign: "Cyberhaven extension compromise wave", source: "Secure Annex, Sekoia", firstSeen: "2024-12-24" },

  // RedDirection (July 2025): the publisher turned 18 long-running extensions malicious by update.
  // All removed from both stores (verified 2026-09-23). Koi, eSentire, itechguides.
  { type: "package", value: "chrome:kgmeffmlnkfnjpgmdndccklfigfhajen", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "chrome:dpdibkjjgbaadnnjhkmmnenkmbnhpobj", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "chrome:gaiceihehajjahakcglkhmdbbdclbnlf", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "chrome:mlgbkfnjdmaoldgagamcnommbbnhfnhf", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "chrome:eckokfcjbjbgjifpcbdmengnabecdakp", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "chrome:mgbhdehiapbjamfgekfpebmhmnmcmemg", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "chrome:cbajickflblmpjodnjoldpiicfmecmif", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "chrome:pdbfcnhlobhoahcamoefbfodpmklgmjm", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "chrome:eokjikchkppnkdipbiggnmlkahcdkikp", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "chrome:ihbiedpeaicgipncdnnkikeehnjiddck", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "edge:jjdajogomggcjifnjgkpghcijgkbcjdi", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "edge:mmcnmppeeghenglmidpmjkaiamcacmgm", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "edge:ojdkklpgpacpicaobnhankbalkkgaafp", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "edge:lodeighbngipjjedfelnboplhgediclp", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "edge:hkjagicdaogfgdifaklcgajmgefjllmd", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "edge:gflkbgebojohihfnnplhbdakoipdbpdm", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "edge:kpilmncnoafddjpnbhepaiilgkdcieaf", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },
  { type: "package", value: "edge:caibdnkmpnjhjdfnomfhijhmebigcelo", severity: "critical", confidence: 1.0, family: "RedDirection", campaign: "RedDirection browser hijack", source: "Koi, eSentire", firstSeen: "2025-07-07" },

  // ShadyPanda (December 2025): publisher-run extensions turned malicious later. Chrome: all 27
  // removed; Edge: the 129 of 132 that Microsoft removed (the 3 still listed are disputed and
  // deliberately NOT included). Single published list (Koi), confirmed by the store removals.
  { type: "package", value: "chrome:eagiakjmjnblliacokhcalebgnhellfi", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:ibiejjpajlfljcgjndbonclhcbdcamai", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:ogjneoecnllmjcegcfpaamfpbiaaiekh", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:jbnopeoocgbmnochaadfnhiiimfpbpmf", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:cdgonefipacceedbkflolomdegncceid", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:gipnpcencdgljnaecpekokmpgnhgpela", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:bpgaffohfacaamplbbojgbiicfgedmoi", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:ineempkjpmbdejmdgienaphomigjjiej", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:nnnklgkfdfbdijeeglhjfleaoagiagig", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:mljmfnkjmcdmongjnnnbbnajjdbojoci", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:llkncpcdceadgibhbedecmkencokjajg", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:nmfbniajnpceakchicdhfofoejhgjefb", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:ijcpbhmpbaafndchbjdjchogaogelnjl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:olaahjgjlhoehkpemnfognpgmkbedodk", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:gnhgdhlkojnlgljamagoigaabdmfhfeg", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:cihbmmokhmieaidfgamioabhhkggnehm", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:lehjnmndiohfaphecnjhopgookigekdk", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:hlcjkaoneihodfmonjnlnnfpdcopgfjk", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:hmhifpbclhgklaaepgbabgcpfgidkoei", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:lnlononncfdnhdfmgpkdfoibmfdehfoj", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:nagbiboibhbjbclhcigklajjdefaiidc", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:ofkopmlicnffaiiabnmnaajaimmenkjn", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:ocffbdeldlbilgegmifiakciiicnoaeo", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:eaokmbopbenbmgegkmoiogmpejlaikea", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:lhiehjmkpbhhkfapacaiheolgejcifgd", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:ondhgmkgppbdnogfiglikgpdkmkaiggk", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "chrome:imdgpklnabbkghcbhmkbjbhcomnfdige", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:enkihkfondbngohnmlefmobdgkpmejha", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ipnidmjhnoipibbinllilgeohohehabl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fnnigcfbmghcefaboigkhfimeolhhbcp", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:nlcebdoehkdiojeahkofcfnolkleembf", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fhababnomjcnhmobbemagohkldaeicad", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:nokknhlkpdfppefncfkdebhgfpfilieo", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ljmcneongnlaecabgneiippeacdoimaa", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:onifebiiejdjncjpjnojlebibonmnhog", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:dbagndmcddecodlmnlcmhheicgkaglpk", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fmgfcpjmmapcjlknncjgmbolgaecngfo", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:kgmlodoegkmpfkbepkfhgeldidodgohd", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hegpgapbnfiibpbkanjemgmdpmmlecbc", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:gkanlgbbnncfafkhlchnadcopcgjkfli", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:oghgaghnofhhoolfneepjneedejcpiic", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fcidgbgogbfdcgijkcfdjcagmhcelpbc", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:nnceocbiolncfljcmajijmeakcdlffnh", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:domfmjgbmkckapepjahpedlpdedmckbj", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:cbkogccidanmoaicgphipbdofakomlak", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:bmlifknbfonkgphkpmkeoahgbhbdhebh", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ghaggkcfafofhcfppignflhlocmcfimd", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hfeialplaojonefabmojhobdmghnjkmf", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:boiciofdokedkpmopjnghpkgdakmcpmb", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ibfpbjfnpcgmiggfildbcngccoomddmj", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:idjhfmgaddmdojcfmhcjnnbhnhbmhipd", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:jhgfinhjcamijjoikplacnfknpchndgb", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:cgjgmbppcoolfkbkjhoogdpkboohhgel", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:afooldonhjnhddgnfahlepchipjennab", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fkbcbgffcclobgbombinljckbelhnpif", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fpokgjmlcemklhmilomcljolhnbaaajk", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hadkldcldaanpomhhllacdmglkoepaed", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:iedkeilnpbkeecjpmkelnglnjpnacnlh", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hjfmkkelabjoojjmjljidocklbibphgl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:dhjmmcjnajkpnbnbpagglbbfpbacoffm", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:cgehahdmoijenmnhinajnojmmlnipckl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fjigdpmfeomndepihcinokhcphdojepm", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:chmcepembfffejphepoongapnlchjgil", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:googojfbnbhbbnpfpdnffnklipgifngn", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fodcokjckpkfpegbekkiallamhedahjd", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:igiakpjhacibmaichhgbagdkjmjbnanl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:omkjakddaeljdfgekdjebbbiboljnalk", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:llilhpmmhicmiaoancaafdgganakopfg", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:nemkiffjklgaooligallbpmhdmmhepll", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:papedehkgfhnagdiempdbhlgcnioofnd", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:glfddenhiaacfmhoiebfeljnfkkkmbjb", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:pkjfghocapckmendmgdmppjccbplccbg", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:gbcjipmcpedgndgdnfofbhgnkmghoamm", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ncapkionddmdmfocnjfcfpnimepibggf", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:klggeioacnkkpdcnapgcoicnblliidmf", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:klgjbnheihgnmimajhohfcldhfpjnahe", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:acogeoajdpgplfhidldckbjkkpgeebod", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ekndlocgcngbpebppapnpalpjfnkoffh", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:elckfehnjdbghpoheamjffpdbbogjhie", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:dmpceopfiajfdnoiebfankfoabfehdpn", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:gpolcigkhldaighngmmmcjldkkiaonbg", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:dfakjobhimnibdmkbgpkijoihplhcnil", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hbghbdhfibifdgnbpaogepnkekonkdgc", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fppchnhginnfabgenhihpncnphhafmac", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ghhddclfklljabeodmcejjjlhoaaiban", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:bppelgkcnhfkicolffhlkbdghdnjdkhi", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ikgaleggljchgbihlaanjbkekmmgccam", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:bdhjinjoglaijpffoamhhnhooeimgoap", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fjioinpkgmlcioajfnncgldldcnabffe", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:opncjjhgbllenobgbfjbblhghmdpmpbj", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:cbijiaccpnkbdpgbmiiipedpepbhioel", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fbbmnieefocnacnecccgmedmcbhlkcpm", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hmbacpfgehmmoloinfmkgkpjoagiogai", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:paghkadkhiladedijgodgghaajppmpcg", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:bafbmfpfepdlgnfkgfbobplkkaoakjcl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:kcpkoopmfjhdpgjohcbgkbjpmbjmhgoi", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:jelgelidmodjpmohbapbghdgcpncahki", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:lfgakdlafdenmaikccbojgcofkkhmolj", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hdfknlljfbdfjdjhfgoonpphpigjjjak", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:kpfbijpdidioaomoecdbfaodhajbcjfl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fckphkcbpgmappcgnfieaacjbknhkhin", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:lhfdakoonenpbggbeephofdlflloghhi", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ljjngehkphcdnnapgciajcdbcpgmpknc", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ejfocpkjndmkbloiobcdhkkoeekcpkik", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ccdimkoieijdbgdlkfjjfncmihmlpanj", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:agdlpnhabjfcbeiempefhpgikapcapjb", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:mddfnhdadbofiifdebeiegecchpkbgdb", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:alknmfpopohfpdpafdmobclioihdkhjh", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hlglicejgohbanllnmnjllajhmnhjjel", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:iaccapfapbjahnhcmkgjjonlccbhdpjl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ehmnkbambjnodfbjcebjffilahbfjdml", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ngbfciefgjgijkkmpalnmhikoojilkob", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:laholcgeblfbgdhkbiidbpiofdcbpeeo", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:njoedigapanaggiabjafnaklppphempm", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:fomlombffdkflbliepgpgcnagolnegjn", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:jpoofbjomdefajdjcimmaoildecebkjc", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:nhdiopbebcklbkpfnhipecgfhdhdbfhb", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:gdnhikbabcflemolpeaaknnieodgpiie", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:bbdioggpbhhodagchciaeaggdponnhpa", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ikajognfijokhbgjdhgpemljgcjclpmn", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:lmnjiioclbjphkggicmldippjojgmldk", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ffgihbmcfcihmpbegcfdkmafaplheknk", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:lgnjdldkappogbkljaiedgogobcgemch", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hiodlpcelfelhpinhgngoopbmclcaghd", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:mnophppbmlnlfobakddidbcgcjakipin", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:jbajdpebknffiaenkdhopebkolgdlfaf", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ejdihbblcbdfobabjfebfjfopenohbjb", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ikkoanocgpdmmiamnkogipbpdpckcahn", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ileojfedpkdbkcchpnghhaebfoimamop", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:akialmafcdmkelghnomeneinkcllnoih", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:eholblediahnodlgigdkdhkkpmbiafoj", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ipokalojgdmhfpagmhnjokidnpjfnfik", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hdpmmcmblgbkllldbccfdejchjlpochf", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:iphacjobmeoknlhenjfiilbkddgaljad", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:jiiggekklbbojgfmdenimcdkmidnfofl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:gkhggnaplpjkghjjcmpmnmidjndojpcn", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:opakkgodhhongnhbdkgjgdlcbknacpaa", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:nkjomoafjgemogbdkhledkoeaflnmgfi", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ebileebbekdcpfjlekjapgmbgpfigled", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:oaacndacaoelmkhfilennooagoelpjop", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ljkgnegaajfacghepjiajibgdpfmcfip", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hgolomhkdcpmbgckhebdhdknaemlbbaa", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:bboeoilakaofjkdmekpgeigieokkpgfn", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:dkkpollfhjoiapcenojlmgempmjekcla", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:emiocjgakibimbopobplmfldkldhhiad", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:nchdmembkfgkejljapneliogidkchiop", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:lljplndkobdgkjilfmfiefpldkhkhbbd", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hofaaigdagglolgiefkbencchnekjejl", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:hohobnhiiohgcipklpncfmjkjpmejjni", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:jocnjcakendmllafpmjailfnlndaaklf", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:bjdclfjlhgcdcpjhmhfggkkfacipilai", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ahebpkbnckhgjmndfjejibjjahjdlhdb", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:enaigkcpmpohpbokbfllbkijmllmpafm", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:bpngofombcjloljkoafhmpcjclkekfbh", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:cacbflgkiidgcekflfgdnjdnaalfmkob", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },
  { type: "package", value: "edge:ibmgdfenfldppaodbahpgcoebmmkdbac", severity: "critical", confidence: 0.9, family: "ShadyPanda", campaign: "ShadyPanda extension campaign", source: "Koi", firstSeen: "2025-12-01" },

  // 108 Chrome extensions with a shared C2 (Socket, April 2026): the 66 removed from the Web Store.
  // The 42 that are live again are deliberately NOT included.
  { type: "package", value: "chrome:aecccajigpipkpioaidignbgbeekglkd", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:akifdnfipbeoonhoeabdicnlcdhghmpn", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:alllblhkgghelnejlggmmgjbkdabidie", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:amkkjdjjgiiamenbopfpdmjcleecjjgg", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:bdnanfggeppmkfhkgmpojkhanoplkacc", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:bfoofgelpmalhcmedaaeogahlmbkopfd", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:bnchgibgpgmlickioneccggfobljmhjc", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:cbfhnceafaenchbefokkngcbnejached", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:cljengcehefhflhoahaambmkknjekjib", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:clpgopiimdjcilllcjncdkoeikkkcfbi", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:cmlbghnlnbjkdgfjlegkbjmadpbmlgjb", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:cnibdhllkgidlgmaoanhkemjeklneolk", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:dbohcpohlgnhgjmfkakoniiplglpfhcb", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:dljlpildgknddpnahppkihgodokfjbnd", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:dlpiookhionidajbiopmaajeckifeehn", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:dmaibhbbpmdihedidicfeigilkbobcog", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:dohenclhhdfljpjlnpjnephpccbdgmmb", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:dpdemambcedffmnkfmkephnhhnclmcio", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:eljfpgehlncincemdmmnebmnlcmfamhm", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:enmmilgindjmffoljaojkcgloakmloen", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:eoklnfefipnjfeknpmigmogeeepddcch", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:fjfhejmbhpabkacpoddjbcfandjoacmb", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:flkdjodmoefccepdihipjdlianmkmhgc", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:fmajpchoiahphjiligpmghnhmabolhoh", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:gaafhblhbnkekenogcjniofhbicchlke", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:gfhcdakcnpahfdealajmhcapnhhablbp", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:gipmochingljoikdjakkdolfcbphmlom", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:haochenfmhglpholokliifmlpafilfdc", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:hdmppejcahhppjhkncagagopecddokpi", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:heljkmdknlfhiecpknceodpbokeipigo", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:hiofkndodabpioiheinoiojjobadpgmj", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:hmlnefhgicedcmebmkjdcogieefbaagl", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:ihbkmfoadnfjgkpdmgcboiehapkiflme", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:ijpgccpmogehkjhdmomckpkfcpbjlmnj", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:imjmnghlhiimodfkdkgnfplhlobehnpm", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:jddinhnhplibccfmniaakhffpjpnaglp", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:jmopjanoebpdbopigcbpjhiigmjolikk", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:jnmmbmkmbkcccpihjgnhjmhhkokfdnfe", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:jodocbbdcdclkhjkibnlfhbmllcpfkfo", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:kahcolfecjbejjjadhjafmihdnifonjf", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:kjnakdbpijigdbfepipnbafnhbcfdkga", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:klglejfbdeipgklgaepnodpjcnhaihkd", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:lefndgfmmbdklidbkeifpgclmpnhcilg", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:lfkknbmaifjomagejflmjklcmpadmmdg", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:ljbgkfbiifhpgpipepnfefijldolkhlm", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:lmcpbhamfpbonaenickjclacodolkbdl", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:lmgenhmehbcolpikplhkoelmagdhoojn", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:maeccdadgnadblfddcmanhpofobhgfme", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:mdcfennpfgkngnibjbpnpaafcjnhcjno", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:mheomooihiffmcgldolenemmplpgoahn", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:mmbbjakjlpmndjlbhihlddgcdppblpka", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:mmecpiobcdbjkaijljohghhpfgngpjmk", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:nbgligggjfgkpphhghhjdoiefbimgooc", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:ncpdkpcgmdhhnmcjgiiifdhefmekdcnf", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:nkacmelgoeejhjgmmgflbcdhonpaplcg", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:nmegibgeklckejdlfhoadhhbgcdjnojb", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:nodobilhjanebkafmpihkpoabiggnnfl", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:oanpifaoclmgmflmddlgkikfaggejobn", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:obifanppcpchlehkjipahhphbcbjekfa", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:ocflhkadmmnlbieoiiekfcdcmjcfeahe", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:oejhnncfanbaogjlbknmlgjpleachclf", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:ogbaedmbbmmipljceodeimlckohbnfan", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:ogogpebnagniggbnkbpjioobomdbmdcj", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:ojkbafekojdcedacileemekjdfdpkbkf", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:phfkdailnomcbcknpdmokejhellbecjb", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },
  { type: "package", value: "chrome:pkghgkfjhjghinikeanecbgjehojfhdg", severity: "critical", confidence: 0.9, family: "Shared-C2 Chrome extensions", campaign: "Socket 108 Chrome extensions", source: "Socket", firstSeen: "2026-04-01" },

  // Firefox 'Offside' wallet-theft add-ons (March-August 2026): attacker-created, every version
  // blocked by Mozilla (AMO blocklist, verified 2026-09-23). Ids compared exactly.
  { type: "package", value: "firefox:bliss-heaven@webbrol.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:bold-page-vault@addonslab.example", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:bright-save-feed@tabtools.org", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:chiro-di-red@tools.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:chiro-redok@webtools.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:cool-block-gear@protools.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:fast-akap-safe@browsertools.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:fast-map-safe@linktools.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:flex-clock-dash@extrakits.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:free-note-bolt@webtools.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:green-fam-heav@browsertool.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:herman-rich@browsertools.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:live-football-scores@live-scores.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:park-static-small@devblogs.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:peters-schools@webtoolbrowser.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:safe-stat-pure@proaddons.net", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:sharp-stat-gear@netplugs.net", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:swift-clip-link@fasttools.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:vibe-timer-fast@extrakits.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{91ac3e4f-1874-409d-b01f-aeb2409a23b8}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{b1f3c8a9-4a2e-4b7c-9e1f-8a3d6c5b4e2f}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{d8a5f7c3-9e4b-2f2a-b1d7-8c7e9f4a2b3c}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{d8a5f7c3-9e4b-4f2a-b1d6-8c7e9f3a2b2c}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{d8a5f7c3-9e9b-2f8a-b1d6-8c1e9f4a2b7c}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{d8a5f9c3-9e4b-4f2a-b1d7-8c7e9f4a2b3c}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{d9a5f9c3-9e4b-2f3a-b2d7-8c8e9f4a2b3c}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{f746f950-bd73-43de-bfe1-add342147853}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:bolt-save-vault@devplugs.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:core-note-nova@webtools.net", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:deep-tip-sharp@browsify.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:fast-zip-true@smartext.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:flex-lab-save@foxplugin.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:gear-save-tip@extrakits.example", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:pure-net-snap@fasttools.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:silver-fox@browser-app.com", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:smart-lab-glow@webkits.co", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{64d210f4-9b7f-489f-8207-e042400041b7}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{842fa1ed-b948-4bf8-b796-21044d3419eb}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{b0043917-9d75-425b-977a-4bb553f2a8ee}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },
  { type: "package", value: "firefox:{d8a5f7c3-9e4b-2f2a-b1d7-8c7e9f4a2b7c}", severity: "critical", confidence: 1.0, family: "OffsideWalletTheft", campaign: "Firefox Offside wallet theft", source: "Socket, Mozilla blocklist", firstSeen: "2026-03-01" },

  // JetBrains Marketplace fake AI-assistant plugins (June 2026): removed by JetBrains, publishers
  // blocked (Marketplace API 403, verified 2026-09-23). ord.cp.code.ai.kit really starts with "ord".
  { type: "package", value: "jetbrains:org.sm.yms.toolkit", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:com.json.simple.kit", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:org.bug.find.tools", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:org.translate.ai.simple", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:com.yy.test.ai.simple", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:com.dev.ai.toolkit", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:com.json.view.simple", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:com.my.git.ai.kit", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:org.check.ai.ds", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:com.review.tool.code", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:org.code.assist.dev.tool", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:com.coder.ai.dpt", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:com.my.code.tools", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:ord.cp.code.ai.kit", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },
  { type: "package", value: "jetbrains:com.dp.git.ai.tool", severity: "critical", confidence: 1.0, family: "AIKeyStealer", campaign: "JetBrains fake AI plugins", source: "JetBrains, StepSecurity", firstSeen: "2026-06-16" },

  // Homebrew: the aquasecurity/trivy tap shipped the TeamPCP-compromised trivy 0.69.4 (Aqua
  // GHSA-69fq-xp46-6x23; tap archived). homebrew-core builds trivy from source and is NOT listed.
  { type: "package", value: "homebrew:aquasecurity/trivy/trivy@0.69.4", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "TeamPCP Trivy image compromise", source: "GHSA-69fq-xp46-6x23", firstSeen: "2026-03-19" },
  // Coder registry compromise (2026-08-31, 07:35-21:45 UTC): an unauthorized origin behind
  // Coder's own module registry served tampered Terraform modules that sent credentials to
  // this lookalike host (GHSA-vx42-ghc9-gw65 in coder/coder, verified 2026-09-23 via the
  // GitHub API; Coder's incident post of 2026-09-04). No module name or version was published,
  // so the host is the only matchable indicator; subdomains (www.) match through it. A
  // single-source IP from a secondary write-up is deliberately NOT included.
  { type: "domain", value: "coder-infra.com", severity: "critical", confidence: 0.95, family: "CoderRegistryStealer", campaign: "Coder registry compromise", source: "GHSA-vx42-ghc9-gw65, Coder incident post", firstSeen: "2026-09-01" },

  // Imported from GitHub Advisory Database (2026-09-10) - see docs/threat-feed-sources.md
  { type: "package", value: "@baanx/solana-lib", severity: "critical", confidence: 1.0, source: "GHSA-5x34-3xqm-3r73, MAL-2026-16300 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@insiderintelligence/componentlibrary", severity: "critical", confidence: 1.0, source: "GHSA-rjh6-qm48-cg84, MAL-2026-16353 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@insiderintelligence/googleadmanager", severity: "critical", confidence: 1.0, source: "GHSA-q699-336h-g385, MAL-2026-16290 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-18" },
  { type: "package", value: "@baanx/domain", severity: "critical", confidence: 0.9, source: "GHSA-qhfc-6rp6-pwv6, MAL-2026-16486 (ghsa-malware)", firstSeen: "2026-09-24" },
  { type: "package", value: "@baanx/blockchain-config", severity: "critical", confidence: 1.0, source: "GHSA-f67m-pjx9-96cv, MAL-2026-16352 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@baanx/abis", severity: "critical", confidence: 1.0, source: "GHSA-598m-93qh-82f9, MAL-2026-16351 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "@baanx/common", severity: "critical", confidence: 0.9, source: "GHSA-27jh-hjhg-vg2p, MAL-2026-16485 (ghsa-malware)", firstSeen: "2026-09-24" },
  { type: "package", value: "@rixxcodex/baileys@8.1.0", severity: "critical", confidence: 1.0, source: "GHSA-fjxf-mv8f-cp6x, MAL-2026-16483 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "@rixxcodex/baileys@8.2.0", severity: "critical", confidence: 1.0, source: "GHSA-fjxf-mv8f-cp6x, MAL-2026-16483 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "@rixxcodex/baileys@8.0.16", severity: "critical", confidence: 1.0, source: "GHSA-fjxf-mv8f-cp6x, MAL-2026-16483 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "@rixxcodex/baileys@8.0.15", severity: "critical", confidence: 1.0, source: "GHSA-fjxf-mv8f-cp6x, MAL-2026-16483 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "pino-testkit@10.4.5", severity: "critical", confidence: 1.0, source: "GHSA-q57p-68r4-fj72, MAL-2026-16484 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "internallib_v463@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-gv94-v8fj-f45c, MAL-2026-16481 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "internallib_v657@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-w2wx-86qr-g533, MAL-2026-16482 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "a-onesite@99.9.9", severity: "critical", confidence: 1.0, source: "GHSA-9j7m-m3w9-mgrc, MAL-2026-16480 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "internallib_v497", severity: "critical", confidence: 1.0, source: "GHSA-94q5-67r5-mwjx, MAL-2026-16438 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "com.apple.unityplugin.storekit@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-6r46-f382-x53p, MAL-2026-16477 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "simplenewnpmpackage@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-mr2p-c47m-85w8, MAL-2026-16479 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "event-hunter@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wwrq-gcqx-rx6p, MAL-2026-16478 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "pypi:memoryos@2.0.34", severity: "critical", confidence: 1.0, source: "GHSA-hxf9-rvj5-h45h, MAL-2026-16475 (amazon-inspector+kam193)", firstSeen: "2026-09-23" },
  { type: "package", value: "@memtensor/memos-cloud-openclaw-plugin@0.1.21", severity: "critical", confidence: 1.0, source: "GHSA-mhjf-v53x-7p87, MAL-2026-16476 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@memtensor/memos-cloud-openclaw-plugin@0.1.23", severity: "critical", confidence: 1.0, source: "GHSA-mhjf-v53x-7p87, MAL-2026-16476 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "@memtensor/memos-cloud-openclaw-plugin@0.1.25", severity: "critical", confidence: 1.0, source: "GHSA-mhjf-v53x-7p87, MAL-2026-16476 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-23" },
  { type: "package", value: "vite-dev-launcher@2.9.4", severity: "critical", confidence: 1.0, source: "GHSA-pg2r-jxrr-mx5j, MAL-2026-16474 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "sea-baileys@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-9xjg-g5r3-xpj8, MAL-2026-16473 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "hachutis@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-9rj9-xh7c-qqh8, MAL-2026-16464 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "hachutis@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9rj9-xh7c-qqh8, MAL-2026-16464 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "helpersutils-dev-tools@1.0.11", severity: "critical", confidence: 1.0, source: "GHSA-w43w-f8m4-5r39, MAL-2026-16465 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "godxxx@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-4wh8-4j9j-8q3r, MAL-2026-16461 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "godzz@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-p6cq-66pp-9r5g, MAL-2026-16462 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "godzzz@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6j9r-v67w-r8w4, MAL-2026-16463 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "domain", value: "8a8acaf167b3.skyleen.fr", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "domain", value: "0b48fafd6fbe.skyleen.fr", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "domain", value: "266297c6df27.skyleen.fr", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "domain", value: "c747d139e7e9.skyleen.fr", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "domain", value: "73376a079d87.skyleen.fr", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "domain", value: "d4f77a3a8cb0.skyleen.fr", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "ip", value: "139.84.223.178", severity: "critical", confidence: 0.85, family: "sckit", campaign: "MemTensor sckit worm", source: "Aikido MemTensor sckit write-up (single-source)", firstSeen: "2026-09-23" },
  { type: "hash", value: "381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "hash", value: "e077c387b223811064b7bbc5a55a0182fca9bf50894f949ff284d4be87d44b26", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "hash", value: "65faf8ccbcf5b34eb4f72c71bf82815fa9c1e2f947b9c898491540e866132c31", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "hash", value: "f8ccdd1da7dff1aef16377a2842bc7acf7c516e32122dd6e42dc4a4e57653fce", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "hash", value: "56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },
  { type: "hash", value: "d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26", severity: "critical", confidence: 0.95, family: "sckit", campaign: "MemTensor sckit worm", source: "SafeDep + Aikido MemTensor sckit write-ups", firstSeen: "2026-09-23" },

  // Imported from GitHub Advisory Database (2026-09-11) - see docs/threat-feed-sources.md
  { type: "package", value: "shoplist-app@993.99.99", severity: "critical", confidence: 1.0, source: "GHSA-9gqc-gwvw-4228, MAL-2026-17185 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "shoplist-app@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-9gqc-gwvw-4228, MAL-2026-17185 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "@airbnb-extended/typescript-config@99.9.1", severity: "critical", confidence: 1.0, source: "GHSA-jc5g-qvp3-6hrx, MAL-2026-17184 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "pypi:tego-managed-agents-test@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-hph5-88qq-frqw, MAL-2026-17183 (amazon-inspector+kam193)", firstSeen: "2026-09-25" },
  { type: "package", value: "app-sca-info-banking@0.0.24", severity: "critical", confidence: 1.0, source: "GHSA-wfg5-3jm7-5p8w, MAL-2026-17182 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-25" },
  { type: "package", value: "pypi:reqparser@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-3gf2-53hg-f395, MAL-2026-17181 (kam193)", firstSeen: "2026-09-25" },
  { type: "package", value: "pypi:reqparser@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-3gf2-53hg-f395, MAL-2026-17181 (kam193)", firstSeen: "2026-09-25" },
  { type: "package", value: "secure-env3@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-w2g5-xcc6-p474, MAL-2026-17178 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "wallet-connect-adapter@1.4.2", severity: "critical", confidence: 1.0, source: "GHSA-39rm-rv2w-366r, MAL-2026-17179 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "n8n-nodes-moonlet-helpers@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-hh4f-fhfw-7vgw, MAL-2026-17176 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "n8n-nodes-moonlet-helpers@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-hh4f-fhfw-7vgw, MAL-2026-17176 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "chromatitle-js@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-93mr-5j8f-6p3w, MAL-2026-17174 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "n8n-nodes-moonlet-utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-f77h-w3rc-2c74, MAL-2026-17177 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "pypi:my-private-pkg@99.1.1", severity: "critical", confidence: 1.0, source: "GHSA-v7x9-wx5x-qrpp, MAL-2026-17180 (amazon-inspector+kam193)", firstSeen: "2026-09-25" },
  { type: "package", value: "pypi:my-private-pkg@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-v7x9-wx5x-qrpp, MAL-2026-17180 (amazon-inspector+kam193)", firstSeen: "2026-09-25" },
  { type: "package", value: "pypi:my-private-pkg@99.11.2", severity: "critical", confidence: 1.0, source: "GHSA-v7x9-wx5x-qrpp, MAL-2026-17180 (amazon-inspector+kam193)", firstSeen: "2026-09-25" },
  { type: "package", value: "better-dotenv3@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-qx8m-mvxg-49m3, MAL-2026-17172 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "n8n-nodes-flowstats@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wm7h-qmp4-782c, MAL-2026-17175 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "agency-test-exercise@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-qwj9-hfhg-j6vh, MAL-2026-17170 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "chromatitle@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7pgp-qm32-53rp, MAL-2026-17173 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "agency-testts@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-75mh-8gwp-9cvf, MAL-2026-17171 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "@alphaspace/core@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5qqj-qfpp-jfqw, MAL-2026-17169 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "@alphaspace/core@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-5qqj-qfpp-jfqw, MAL-2026-17169 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "@alphaspace/core@99.0.2", severity: "critical", confidence: 1.0, source: "GHSA-5qqj-qfpp-jfqw, MAL-2026-17169 (amazon-inspector)", firstSeen: "2026-09-25" },
  { type: "package", value: "pypi:vercel-runtime-python@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-fvc2-927p-99h8, MAL-2026-17168 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:vercel-runtime-python@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-fvc2-927p-99h8, MAL-2026-17168 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:vercel-runtime-python@100.99.99", severity: "critical", confidence: 1.0, source: "GHSA-fvc2-927p-99h8, MAL-2026-17168 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:vercel-runtime-python@100.100.99", severity: "critical", confidence: 1.0, source: "GHSA-fvc2-927p-99h8, MAL-2026-17168 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.7", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.8", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.9", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.13", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.14", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.15", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.16", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.17", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.18", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.19", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.20", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.21", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.22", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.23", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.25", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.26", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.27", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.32", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.28", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.29", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "pypi:prosocks@1.0.30", severity: "critical", confidence: 1.0, source: "GHSA-6v7p-c53r-646f, MAL-2026-17167 (amazon-inspector+kam193)", firstSeen: "2026-09-24" },
  { type: "package", value: "simple-date-formatter-new-15@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-fj2x-7537-68xm, MAL-2026-17161 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "eslint-config-compact-base@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-ghfm-6qx4-q8p4, MAL-2026-17157 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "simple-date-formatter-new-14@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7r88-5m7v-8m5w, MAL-2026-17160 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "aliftech-ui@99.9.9", severity: "critical", confidence: 1.0, source: "GHSA-648v-rwj3-6j2f, MAL-2026-17156 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "simple-date-formatter-new-11@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2v58-3f75-j4jv, MAL-2026-17158 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "@osl-design/react@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-qx4v-776h-xcpw, MAL-2026-17155 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "simple-date-formatter-new-13@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-539g-4gx9-g555, MAL-2026-17159 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "@nf-addons/am-global-header@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-hj7v-p563-fffq, MAL-2026-17154 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "@birbalo/aliftech-ui@99.9.9", severity: "critical", confidence: 1.0, source: "GHSA-383w-gxv7-cg2f, MAL-2026-17153 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "simple-date-formatter-new-16@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-j933-m42r-pjvp, MAL-2026-17162 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "building-build@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-v37c-88px-mm6h, MAL-2026-17164 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "c2-client@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h7qv-4h6m-4g2x, MAL-2026-17165 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "cache-swipper@3.6.0", severity: "critical", confidence: 1.0, source: "GHSA-55m7-mqpg-rv53, MAL-2026-17166 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "cache-swipper@3.5.0", severity: "critical", confidence: 1.0, source: "GHSA-55m7-mqpg-rv53, MAL-2026-17166 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "analytics-widget@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-xpv4-prm5-w6gr, MAL-2026-17163 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "analytics-widget@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-xpv4-prm5-w6gr, MAL-2026-17163 (amazon-inspector)", firstSeen: "2026-09-24" },
  { type: "package", value: "com.apple.unityplugin.storekit@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-6r46-f382-x53p, MAL-2026-16477 (amazon-inspector)", firstSeen: "2026-09-23" },
  { type: "package", value: "feed-widget-helper@1.0.8", severity: "critical", confidence: 1.0, source: "GHSA-fgrp-3g95-g56v, MAL-2026-16332 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "feed-widget-helper@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-fgrp-3g95-g56v, MAL-2026-16332 (amazon-inspector)", firstSeen: "2026-09-21" },

  // 2026-09-22 daily intelligence kept in the offline bundle (6.3.0 pre-release
  // review). The 2026-09-22 catalog window (feed-partition.config.json) was set
  // for the ReversingLabs RubyGems bulk (MAL-2026-16487 to 17152), but a window
  // covers a whole day, so it also sent these 58 fresh records to the catalog:
  // MAL-2026-16374 to 16466 from amazon-inspector, OpenSSF, kam193 and
  // ghsa-malware, among them a malicious MCP server. That left a default offline
  // scan and the default Action blind to three-day-old malware. This comment
  // block curates them, so every later migration keeps them bundled.
  { type: "package", value: "ubiquiti-agents-link-mcp", severity: "critical", confidence: 1.0, source: "GHSA-rqpx-hw2h-g3hc, MAL-2026-16409 (amazon-inspector+ghsa-malware+ossf-package-analysis)", firstSeen: "2026-09-22" },
  { type: "package", value: "test-react-app-in", severity: "critical", confidence: 0.9, source: "GHSA-wm2w-4m2r-mv73, MAL-2026-16374 (ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "test-react-app-out", severity: "critical", confidence: 0.9, source: "GHSA-vx3p-fwmg-p7g8, MAL-2026-16375 (ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "test-react-app-way", severity: "critical", confidence: 0.9, source: "GHSA-264w-9h55-v637, MAL-2026-16376 (ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "pypi:kerokwis@99", severity: "critical", confidence: 1.0, source: "GHSA-9fqg-jm66-pjqf, MAL-2026-16421 (kam193)", firstSeen: "2026-09-22" },
  { type: "package", value: "@tvg-mar/promos-context@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-gmpx-wq8f-4q86, MAL-2026-16412 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "@tvg-mar/utils@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-g5mj-6q8x-7cj6, MAL-2026-16416 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "eslint-config-compact-utils@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-qh87-q3mj-33jx, MAL-2026-16417 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "@tvg-mar/tvg-promos-atomic-ui@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-fvh3-76xv-7978, MAL-2026-16415 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "n8n-nodes-data-transformer-utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w3qc-pff7-wmpv, MAL-2026-16418 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "@tvg-mar/storyblok-bridge@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-r788-p8wq-7672, MAL-2026-16414 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "@tvg-mar/promos-gtm@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-4mmr-x347-r6gv, MAL-2026-16413 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "@gsutevil/hta-stage@1.62.0", severity: "critical", confidence: 1.0, source: "GHSA-95xp-29r3-v466, MAL-2026-16419 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "ruby:kerokwis@99", severity: "critical", confidence: 1.0, source: "GHSA-mh78-3v9h-gh6j, MAL-2026-16420 (ossf-package-analysis)", firstSeen: "2026-09-22" },
  { type: "package", value: "pypi:poly-check-b@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-3324-42r3-w6mm, MAL-2026-16407 (kam193)", firstSeen: "2026-09-22" },
  { type: "package", value: "pypi:crypto-trader-py@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-j8qm-q4hg-mvr7, MAL-2026-16406 (amazon-inspector+kam193)", firstSeen: "2026-09-22" },
  { type: "package", value: "pypi:snap-queue@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-3v8f-m5rm-8mv3, MAL-2026-16408 (amazon-inspector+kam193)", firstSeen: "2026-09-22" },
  { type: "package", value: "ubiquiti-agents-link-mcp@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-f2wc-4v37-6f5h, MAL-2026-16409 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-22" },
  { type: "package", value: "ubiquiti-agents-link-mcp@0.0.2", severity: "critical", confidence: 1.0, source: "GHSA-f2wc-4v37-6f5h, MAL-2026-16409 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-22" },
  { type: "package", value: "ubiquiti-agents-link-mcp@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-f2wc-4v37-6f5h, MAL-2026-16409 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-22" },
  { type: "package", value: "ubiquiti-agents-link-mcp@0.2.1", severity: "critical", confidence: 1.0, source: "GHSA-f2wc-4v37-6f5h, MAL-2026-16409 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-22" },
  { type: "package", value: "pypi:auclean@0.4.2", severity: "critical", confidence: 1.0, source: "GHSA-v257-9gjr-rv2j, MAL-2026-16410 (amazon-inspector+kam193)", firstSeen: "2026-09-22" },
  { type: "package", value: "pypi:auclean@0.4.3", severity: "critical", confidence: 1.0, source: "GHSA-v257-9gjr-rv2j, MAL-2026-16410 (amazon-inspector+kam193)", firstSeen: "2026-09-22" },
  { type: "package", value: "pypi:auclean@0.4.4", severity: "critical", confidence: 1.0, source: "GHSA-v257-9gjr-rv2j, MAL-2026-16410 (amazon-inspector+kam193)", firstSeen: "2026-09-22" },
  { type: "package", value: "ruby:no-fun@999.99.99", severity: "critical", confidence: 1.0, source: "GHSA-662g-6742-cf23, MAL-2026-16411 (ossf-package-analysis)", firstSeen: "2026-09-22" },
  { type: "package", value: "noverojava@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-g77m-jmph-gj8q, MAL-2026-16389 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "noverojava@1.0.9", severity: "critical", confidence: 1.0, source: "GHSA-g77m-jmph-gj8q, MAL-2026-16389 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "@mr-supun-fernando/supunmd-bail@3.0.3", severity: "critical", confidence: 1.0, source: "GHSA-4w3g-g5h8-rw39, MAL-2026-16387 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "oracle-redis@5.11.3", severity: "critical", confidence: 1.0, source: "GHSA-8m7m-r8mw-mvq2, MAL-2026-16390 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "nodetokyo@1.0.8", severity: "critical", confidence: 1.0, source: "GHSA-pwpm-7qvr-qmc7, MAL-2026-16388 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "@mikudeveloper/baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vw8h-q4hc-x8cv, MAL-2026-16386 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "tailwind-form-styles", severity: "critical", confidence: 1.0, source: "GHSA-h48r-xx59-h44r, MAL-2026-16405 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "envforge2", severity: "critical", confidence: 1.0, source: "GHSA-h8xg-3hfp-rx6q, MAL-2026-16392 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "envforge3", severity: "critical", confidence: 1.0, source: "GHSA-7chm-5cxc-2wx2, MAL-2026-16393 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "envparse2", severity: "critical", confidence: 1.0, source: "GHSA-q747-c2cv-gfhj, MAL-2026-16394 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "envparse3", severity: "critical", confidence: 1.0, source: "GHSA-vq77-3r62-c2cx, MAL-2026-16395 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "node-env-buffer", severity: "critical", confidence: 1.0, source: "GHSA-2g29-f3qp-c7gf, MAL-2026-16403 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "sysverify", severity: "critical", confidence: 1.0, source: "GHSA-jpfv-9923-q8rq, MAL-2026-16404 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "ndmckauxuoincv", severity: "critical", confidence: 1.0, source: "GHSA-q5vm-6mhj-qq8c, MAL-2026-16401 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "cloudndmcedu", severity: "critical", confidence: 1.0, source: "GHSA-3r7g-wjh4-5228, MAL-2026-16391 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "ndmcjcxiebysfdb", severity: "critical", confidence: 1.0, source: "GHSA-8344-w2r2-rxp2, MAL-2026-16400 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "ndmcmsujey", severity: "critical", confidence: 1.0, source: "GHSA-fjp4-jprr-4jp6, MAL-2026-16402 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "lufxchwmxwyps", severity: "critical", confidence: 1.0, source: "GHSA-xvmw-wchq-f7p8, MAL-2026-16399 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "fdhcxvnwhjiofv", severity: "critical", confidence: 1.0, source: "GHSA-299v-cwvm-ffx4, MAL-2026-16396 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "luftmvfiwgxydes", severity: "critical", confidence: 1.0, source: "GHSA-j2f6-x53f-2qqf, MAL-2026-16398 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "kambxjowhdsgyw", severity: "critical", confidence: 1.0, source: "GHSA-pmhv-gqr9-wrgr, MAL-2026-16397 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-22" },
  { type: "package", value: "take-home-caller-id@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-2g3j-m32f-cc29, MAL-2026-16382 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "cisco-github-simple@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-2ph4-jf5x-92pp, MAL-2026-16381 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "chai-logger@3.0.2", severity: "critical", confidence: 1.0, source: "GHSA-fv5h-7hj3-xq5r, MAL-2026-16380 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "tldriver@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-ghjj-wrgg-p63j, MAL-2026-16384 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "@tesla-insurance/vinless-quote@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-p853-37gq-hxpj, MAL-2026-16378 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "tlxbnhd@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-jxp9-84h3-hgw4, MAL-2026-16385 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "@user-services/web-components@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-6q28-qx7w-pv4x, MAL-2026-16379 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "mxdriver@0.0.2", severity: "critical", confidence: 1.0, source: "GHSA-5hjc-6hw8-375j, MAL-2026-16383 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "mxdriver@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-5hjc-6hw8-375j, MAL-2026-16383 (amazon-inspector)", firstSeen: "2026-09-22" },
  { type: "package", value: "pypi:cloushaar-poc-exfil-91827@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-6wmc-3vvj-9j5f, MAL-2026-16377 (amazon-inspector+kam193)", firstSeen: "2026-09-22" },
  { type: "package", value: "ruby:wurl_show_data@3.1.42.99", severity: "critical", confidence: 1.0, source: "GHSA-345f-5r88-8j64, MAL-2026-16466 (ossf-package-analysis)", firstSeen: "2026-09-22" },
  { type: "package", value: "eslint-config-compact-utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-qh87-q3mj-33jx, MAL-2026-16417 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-22" },

  // Imported from GitHub Advisory Database (2026-09-12) - see docs/threat-feed-sources.md
  { type: "package", value: "pypi:sherpy@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-74qh-6w69-w7vc, MAL-2026-17188 (kam193)", firstSeen: "2026-09-25" },
  { type: "package", value: "pypi:sherpy@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-74qh-6w69-w7vc, MAL-2026-17188 (kam193)", firstSeen: "2026-09-25" },
  { type: "package", value: "@digift/cli@99.99.100", severity: "critical", confidence: 1.0, source: "GHSA-2394-2grm-2336, MAL-2026-17187 (ossf-package-analysis)", firstSeen: "2026-09-25" },
  { type: "package", value: "@digift/cli@99.99.99", severity: "critical", confidence: 0.9, source: "npm registry: published by the account behind GHSA-2394-2grm-2336 in the same minute as 99.99.100, since unpublished; the advisory lists 99.99.100 only", firstSeen: "2026-09-25" },
  { type: "package", value: "@nubjs/types@0.9.4", severity: "critical", confidence: 0.9, source: "GHSA-7qx8-98q7-66p4, MAL-2026-17186 (ghsa-malware)", firstSeen: "2026-09-25" },

  // Imported from GitHub Advisory Database (2026-09-13) - see docs/threat-feed-sources.md
  { type: "package", value: "pypi:donutautosellsrc@0.3.7", severity: "critical", confidence: 1.0, source: "GHSA-2w77-qp99-3jvq, MAL-2026-17192 (kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:donutautosellsrc@0.3.8", severity: "critical", confidence: 1.0, source: "GHSA-2w77-qp99-3jvq, MAL-2026-17192 (kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:donutautosellsrc@0.3.9", severity: "critical", confidence: 1.0, source: "GHSA-2w77-qp99-3jvq, MAL-2026-17192 (kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:requests-cache-utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mc8h-7wqw-2mcf, MAL-2026-17191 (kam193)", firstSeen: "2026-09-26" },
  { type: "package", value: "cma-self-hosted-sandbox-cf@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wjmh-pc3x-575f, MAL-2026-17190 (amazon-inspector)", firstSeen: "2026-09-26" },
  { type: "package", value: "chai-as-relay@1.2.1", severity: "critical", confidence: 1.0, source: "GHSA-mq79-xj84-m775, MAL-2026-17189 (amazon-inspector)", firstSeen: "2026-09-26" },
  { type: "package", value: "@alphaspace/core@99.0.3", severity: "critical", confidence: 1.0, source: "GHSA-5qqj-qfpp-jfqw, MAL-2026-17169 (amazon-inspector)", firstSeen: "2026-09-25" },

  // Atomic indicators from the per-source analyses of the advisories above (OSV).
  { type: "domain", value: "thisisafalsepositive.st", severity: "critical", confidence: 0.95, campaign: "donutautosellsrc PyPI infostealer", source: "MAL-2026-17192 (kam193); MAL-2026-17195, MAL-2026-17197 (amazon-inspector)", firstSeen: "2026-09-27" },
  { type: "domain", value: "sltnnt.ru", severity: "critical", confidence: 0.85, campaign: "donutautosellsrc PyPI infostealer", source: "MAL-2026-17192 (kam193, single-source)", firstSeen: "2026-09-27" },
  { type: "ip", value: "104.234.65.75", severity: "critical", confidence: 0.85, campaign: "requests-cache-utils PyPI infostealer", source: "MAL-2026-17191 (kam193, single-source)", firstSeen: "2026-09-26" },
  { type: "domain", value: "49bl3t5yt786ymbtth24nnlbs2ytmka9.oastify.com", severity: "critical", confidence: 0.9, campaign: "cma-self-hosted-sandbox-cf install-time recon", source: "MAL-2026-17190 (amazon-inspector)", firstSeen: "2026-09-26" },
  { type: "domain", value: "f5778d1d81cc30c39dcdd0da5ca1d49a.m.pipedream.net", severity: "critical", confidence: 0.9, campaign: "@alphaspace/core install-time recon", source: "MAL-2026-17169 (amazon-inspector)", firstSeen: "2026-09-25" },

  // Imported from GitHub Advisory Database (2026-09-14) - see docs/threat-feed-sources.md
  { type: "package", value: "@consts/links", severity: "critical", confidence: 0.9, source: "GHSA-5rp9-7r4x-3fqp, MAL-2026-17202 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "discord-players", severity: "critical", confidence: 1.0, source: "GHSA-mvg6-qj9g-3j3j, MAL-2026-16213 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-16" },
  { type: "package", value: "discord-resolvers", severity: "critical", confidence: 1.0, source: "GHSA-whmq-ffxc-4jpc, MAL-2026-16214 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-16" },
  { type: "package", value: "@digi-kernel/digi-kernel-constrains", severity: "critical", confidence: 0.9, source: "GHSA-h37m-2c3q-82j8, MAL-2026-17203 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "pypi:aseity@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-pvh9-pfxq-jq5q, MAL-2026-17200 (kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:scrapetools2@1.2.1", severity: "critical", confidence: 1.0, source: "GHSA-frv4-982x-mv7m, MAL-2026-17199 (amazon-inspector)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:scrapetools2@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-frv4-982x-mv7m, MAL-2026-17199 (amazon-inspector)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:scrapetools2@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-frv4-982x-mv7m, MAL-2026-17199 (amazon-inspector)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:scrapetools2@0.2.1", severity: "critical", confidence: 1.0, source: "GHSA-frv4-982x-mv7m, MAL-2026-17199 (amazon-inspector)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:coinscan@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-78pg-cc9h-7rf3, MAL-2026-17197 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:caracas4check@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-8p46-j5h8-w78j, MAL-2026-17198 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:caracas4check@1.1.2", severity: "critical", confidence: 1.0, source: "GHSA-8p46-j5h8-w78j, MAL-2026-17198 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:metrio@999.0.0", severity: "critical", confidence: 1.0, source: "GHSA-ww2h-pjh2-r85q, MAL-2026-17193 (kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:metrio@1000.0.0", severity: "critical", confidence: 1.0, source: "GHSA-ww2h-pjh2-r85q, MAL-2026-17193 (kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:metrio@1001.0.0", severity: "critical", confidence: 1.0, source: "GHSA-ww2h-pjh2-r85q, MAL-2026-17193 (kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:claudedashbord@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-28f3-pmhh-qxcm, MAL-2026-17195 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:claudedashbord@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-28f3-pmhh-qxcm, MAL-2026-17195 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:claudedashbord@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-28f3-pmhh-qxcm, MAL-2026-17195 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:claudedashbord@0.1.3", severity: "critical", confidence: 1.0, source: "GHSA-28f3-pmhh-qxcm, MAL-2026-17195 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:metrics-sdk@999.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vcmr-hgqh-xrh3, MAL-2026-17194 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:metrics-sdk@1000.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vcmr-hgqh-xrh3, MAL-2026-17194 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:metrics-sdk@1001.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vcmr-hgqh-xrh3, MAL-2026-17194 (amazon-inspector+kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "pypi:donutpromotion@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-c2rx-rjgw-p83h, MAL-2026-17196 (kam193)", firstSeen: "2026-09-27" },
  { type: "package", value: "@bb1ptest23/test-paket@1.0.3", severity: "critical", confidence: 0.9, source: "MAL-2026-17201 (ossf-package-analysis)", firstSeen: "2026-09-28" },

  // Atomic indicators from the per-source analyses of the advisories above (OSV).
  { type: "domain", value: "84avt3516s4q1obsv9q0mh4u2l8dw3ks.x9.to", severity: "critical", confidence: 0.9, campaign: "metrics-sdk PyPI dependency-confusion beacon", source: "MAL-2026-17194 (amazon-inspector)", firstSeen: "2026-09-27" },

  // Imported from GitHub Advisory Database (2026-09-15) - see docs/threat-feed-sources.md
  { type: "package", value: "rai6jaisahthaghee5ou-loader-package@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-hhf7-grh4-575w, MAL-2026-17238 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "native-env@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-9p6x-527c-vh8p, MAL-2026-17237 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "hardhat-lock@2.21.0", severity: "critical", confidence: 1.0, source: "GHSA-crqg-xv46-qmmw, MAL-2026-17233 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "pypi:aseitylab@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-jv9w-2v63-767g, MAL-2026-17240 (amazon-inspector+kam193)", firstSeen: "2026-09-28" },
  { type: "package", value: "pypi:aseitylab@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-jv9w-2v63-767g, MAL-2026-17240 (amazon-inspector+kam193)", firstSeen: "2026-09-28" },
  { type: "package", value: "mini-hardhat@1.1.4", severity: "critical", confidence: 1.0, source: "GHSA-wxx2-jv4c-38wh, MAL-2026-17236 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "test-agency-assignment@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-7x83-rfhr-656r, MAL-2026-17239 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "items-validator@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-hvv9-35pw-8qvf, MAL-2026-17235 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "hardhat-zet@2.0.1", severity: "critical", confidence: 1.0, source: "GHSA-qqvr-prmw-6pq2, MAL-2026-17234 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "fabric-native-loader@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h76r-hhqx-cjq3, MAL-2026-17232 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "dotenv-native@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-438j-7xq6-grfr, MAL-2026-17231 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "llm-nebula@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8g48-f52v-xggv, MAL-2026-17230 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "nebulaai-sdk@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-57f4-h93r-jvh6, MAL-2026-17228 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "simple-date-formatter-new-12@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-v6p6-9wrj-f56p, MAL-2026-17229 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "nebula-llm@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5ph8-m4r7-g739, MAL-2026-17227 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "figlet-chalk-render@1.2.1", severity: "critical", confidence: 1.0, source: "GHSA-frpq-rj8q-hpr4, MAL-2026-17226 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "fabric-render-bridge@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-r54m-4q33-rjvr, MAL-2026-17225 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "fabric-asset-pipeline@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-2h5p-2j55-g9r4, MAL-2026-17224 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "fabric-asset-pipeline@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2h5p-2j55-g9r4, MAL-2026-17224 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "chalk-figlet@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-85m5-qg46-qg28, MAL-2026-17223 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "@digift/cli", severity: "critical", confidence: 1.0, source: "GHSA-xp76-38xh-m8wc, MAL-2026-17187 (ghsa-malware+ossf-package-analysis)", firstSeen: "2026-09-25" },
  { type: "package", value: "img-to-native", severity: "critical", confidence: 1.0, source: "GHSA-pv7p-ghgv-268x, MAL-2026-17216 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "native-runner", severity: "critical", confidence: 1.0, source: "GHSA-jxw5-69p3-hpm4, MAL-2026-17218 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "nebulajs-api", severity: "critical", confidence: 1.0, source: "GHSA-2gr6-gxvx-3594, MAL-2026-17220 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "nebula-sdk", severity: "critical", confidence: 1.0, source: "GHSA-fm5g-6rr8-p9vq, MAL-2026-17219 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "vite-plugin-crypto", severity: "critical", confidence: 1.0, source: "GHSA-mh9w-qr45-6wrq, MAL-2026-17222 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "tailwindcss-form-kit", severity: "critical", confidence: 0.9, source: "GHSA-cxrh-669r-w2g9, MAL-2026-17221 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "my-skibidi@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w4g6-rgx4-2wjf, MAL-2026-17217 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "my-skibidi@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-w4g6-rgx4-2wjf, MAL-2026-17217 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "my-skibidi@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-w4g6-rgx4-2wjf, MAL-2026-17217 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "my-skibidi@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-w4g6-rgx4-2wjf, MAL-2026-17217 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "my-skibidi@1.1.2", severity: "critical", confidence: 1.0, source: "GHSA-w4g6-rgx4-2wjf, MAL-2026-17217 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "my-skibidi@1.1.3", severity: "critical", confidence: 1.0, source: "GHSA-w4g6-rgx4-2wjf, MAL-2026-17217 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "my-skibidi@1.1.4", severity: "critical", confidence: 1.0, source: "GHSA-w4g6-rgx4-2wjf, MAL-2026-17217 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "my-skibidi@1.1.5", severity: "critical", confidence: 1.0, source: "GHSA-w4g6-rgx4-2wjf, MAL-2026-17217 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "my-skibidi@1.1.6", severity: "critical", confidence: 1.0, source: "GHSA-w4g6-rgx4-2wjf, MAL-2026-17217 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "git-en-boite-logging@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-33v8-h584-r8xc, MAL-2026-17214 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "eslint-plugin-skywagon-web@100.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pfgw-q545-ch2m, MAL-2026-17215 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "pypi:azure-langchain-example@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-h82v-pqpv-jr3r, MAL-2026-17213 (amazon-inspector+kam193)", firstSeen: "2026-09-28" },
  { type: "package", value: "@wbnr/design-kit", severity: "critical", confidence: 0.9, source: "GHSA-865f-pwj5-p2c5, MAL-2026-17204 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "@wbnr/lottiefiles-loader", severity: "critical", confidence: 0.9, source: "GHSA-94r6-cxjq-fq4r, MAL-2026-17205 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "wbnr-probe-visible-check", severity: "critical", confidence: 0.9, source: "GHSA-65gf-jmp3-4wrc, MAL-2026-17212 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "kalasnik-npm-simple-test", severity: "critical", confidence: 1.0, source: "GHSA-pm4h-xrhq-vh62, MAL-2026-17206 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "kjj81", severity: "critical", confidence: 0.9, source: "GHSA-9f7c-6fp7-9g6x, MAL-2026-17207 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "uuid-date", severity: "critical", confidence: 0.9, source: "GHSA-pqvc-prrc-mv45, MAL-2026-17210 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "riot-private", severity: "critical", confidence: 0.9, source: "GHSA-qgpm-ggcf-4fqm, MAL-2026-17208 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "ultra-ws", severity: "critical", confidence: 1.0, source: "GHSA-rwhp-v7w5-c6cc, MAL-2026-16155 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "discord-mfa-solver", severity: "critical", confidence: 1.0, source: "GHSA-vf4w-775x-ccfh, MAL-2026-16100 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-09" },
  { type: "package", value: "vinzzsync-wacli", severity: "critical", confidence: 0.9, source: "GHSA-rmcq-f7vh-v86v, MAL-2026-17211 (ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "open-item-validator", severity: "critical", confidence: 1.0, source: "GHSA-55qh-42r8-hcgq, MAL-2026-16052 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-08" },
  { type: "package", value: "tanksync", severity: "critical", confidence: 1.0, source: "GHSA-47j4-w95p-wjp7, MAL-2026-17209 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },

  // Imported from GitHub Advisory Database (2026-09-16) - see docs/threat-feed-sources.md
  { type: "package", value: "solidity-lock@2.21.0", severity: "critical", confidence: 1.0, source: "GHSA-8gw4-ghf8-h8pw, MAL-2026-17302 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "stestenv@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-vmw6-6gcq-wqx2, MAL-2026-17309 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "web-vitals-polyfill-core-v1@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-fx3x-h4mr-m28v, MAL-2026-17303 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "tailwind-forms-kit@0.5.1", severity: "critical", confidence: 1.0, source: "GHSA-w873-w35f-2523, MAL-2026-17310 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "mfahelper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vxqj-q8pf-p87h, MAL-2026-17308 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "fabric-mod-utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-rf8p-xrcg-qxhh, MAL-2026-17307 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "esm-dotenv@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-cp5r-vgw5-hxvh, MAL-2026-17305 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "dotenv-precheck@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-f9wq-94v3-cjrp, MAL-2026-17304 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "dotenv-precheck@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-f9wq-94v3-cjrp, MAL-2026-17304 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "dotenv-precheck@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-f9wq-94v3-cjrp, MAL-2026-17304 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "fabric-loader-core@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-xprc-xmv3-4m4p, MAL-2026-17306 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "itsmeeaizat-bailey@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-qj64-qwq4-qcp4, MAL-2026-17311 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "itsmeeaizat-bailey@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-qj64-qwq4-qcp4, MAL-2026-17311 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "itsmeeaizat-bailey@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-qj64-qwq4-qcp4, MAL-2026-17311 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "test-supply-npm-lib-4@3.3.3", severity: "critical", confidence: 1.0, source: "GHSA-94gj-gfw3-p6wc, MAL-2026-17314 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "test-supply-npm-lib-4@3.3.4", severity: "critical", confidence: 1.0, source: "GHSA-94gj-gfw3-p6wc, MAL-2026-17314 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "godsplan@3.0.2", severity: "critical", confidence: 1.0, source: "GHSA-pgx2-9j7q-49rp, MAL-2026-17315", firstSeen: "2026-09-28" },
  { type: "package", value: "booking-tasks@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-r7mc-qwv3-xpf9, MAL-2026-17317 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "developmentstelemetry@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-r4p2-757f-48qf, MAL-2026-17318 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "developmentstelemetry@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-r4p2-757f-48qf, MAL-2026-17318 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:bfox-build-utils@1.0.997", severity: "critical", confidence: 1.0, source: "GHSA-rx43-29mc-6h3f, MAL-2026-17319 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "booking-eligibility@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-gr8q-38vh-pjfv, MAL-2026-17316 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "json-bigint-rs@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-f96g-45hf-3fhj, MAL-2026-17312 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "pixsvg@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-78wv-pm46-pjqf, MAL-2026-17313 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "react-nodejs@19.3.0", severity: "critical", confidence: 1.0, source: "GHSA-wvw7-9m69-qw5x, MAL-2026-17294 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "testosu888@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6cq5-pmgg-hh6g, MAL-2026-17298 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "testosu8887@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-3r9g-2869-h3rj, MAL-2026-17299 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@selfpentest/eslint-pentest-plugin@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-33w6-wqjr-v97m, MAL-2026-17293 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@rutxploit-sec/waves-button-poc@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-47cj-gh5r-6927, MAL-2026-17290 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@rutxploit-sec/waves-button-poc@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-47cj-gh5r-6927, MAL-2026-17290 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@rutxploit-sec/waves-button-poc@3.0.0", severity: "critical", confidence: 1.0, source: "GHSA-47cj-gh5r-6927, MAL-2026-17290 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@rutxploit-sec/subsplash-canny@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-cw47-rffg-xj8x, MAL-2026-17288 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@rutxploit-sec/waves-icons@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6r7q-h4gr-h6xm, MAL-2026-17291 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@selfpentest/bin-confusion@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-63mv-x2gw-8rg2, MAL-2026-17292 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@selfpentest/bin-confusion@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-63mv-x2gw-8rg2, MAL-2026-17292 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@chatunity/baileys@3.2.0", severity: "critical", confidence: 1.0, source: "GHSA-6jgr-8f9m-5rp7, MAL-2026-17287 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@chatunity/baileys@3.2.1", severity: "critical", confidence: 1.0, source: "GHSA-6jgr-8f9m-5rp7, MAL-2026-17287 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@rutxploit-sec/subsplash-google-tag-manager@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-fj9p-g7jm-r7x3, MAL-2026-17289 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "test-agency-assignment-01@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-w4x6-xq5j-ghhh, MAL-2026-17296 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "test-agency-assignment-02@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-rgqv-x3r6-279g, MAL-2026-17297 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "test-agency-assign@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-prg9-6w5p-pqrw, MAL-2026-17295 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "fs-commons@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-72c4-xhr8-m5j8, MAL-2026-17301 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "common-fs@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-r4wp-96g3-9h5r, MAL-2026-17300 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "pypi:queeuees@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-m3mj-98fq-j5r3, MAL-2026-17286 (kam193)", firstSeen: "2026-09-29" },
  { type: "package", value: "@akapaki/baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-374f-3p4p-9qwf, MAL-2026-17285 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@akapaki/baileys@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-374f-3p4p-9qwf, MAL-2026-17285 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@akapaki/baileys@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-374f-3p4p-9qwf, MAL-2026-17285 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/kit-4@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-xv63-6pmj-vwfh, MAL-2026-17265 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/kit@1.99.0", severity: "critical", confidence: 1.0, source: "GHSA-jj87-9224-r2cj, MAL-2026-17263 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/kit-1@1.99.0", severity: "critical", confidence: 1.0, source: "GHSA-9v25-c7fx-23v6, MAL-2026-17264 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "sk-lib-enc", severity: "critical", confidence: 1.0, source: "GHSA-jcvm-p983-rr37, MAL-2026-17284 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@xoxo-momo/kit", severity: "critical", confidence: 1.0, source: "GHSA-668x-2p2f-6963, MAL-2026-17283 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/valuenet", severity: "critical", confidence: 1.0, source: "GHSA-5958-mpfq-wfrj, MAL-2026-17281 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-testing", severity: "critical", confidence: 1.0, source: "GHSA-wc37-mwww-8cwr, MAL-2026-17280 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-shared-infrastructure", severity: "critical", confidence: 1.0, source: "GHSA-xvjm-3hmh-7v4h, MAL-2026-17279 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-partner-registry", severity: "critical", confidence: 1.0, source: "GHSA-757q-42rv-qjcf, MAL-2026-17278 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-infrastructure", severity: "critical", confidence: 1.0, source: "GHSA-rvhw-f5hm-gj2w, MAL-2026-17277 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/lohndateien", severity: "critical", confidence: 1.0, source: "GHSA-xq9r-4rp7-86c2, MAL-2026-17267 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/cdk-constructs", severity: "critical", confidence: 1.0, source: "GHSA-h9qw-wcm3-qrr8, MAL-2026-17258 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-application", severity: "critical", confidence: 1.0, source: "GHSA-wrw4-45wp-75v5, MAL-2026-17271 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-frontend", severity: "critical", confidence: 1.0, source: "GHSA-53w6-j9gv-cv5w, MAL-2026-17276 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-cli", severity: "critical", confidence: 1.0, source: "GHSA-7j4w-rjm5-96qj, MAL-2026-17272 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-config", severity: "critical", confidence: 1.0, source: "GHSA-pgw6-px39-j8m8, MAL-2026-17274 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-core", severity: "critical", confidence: 1.0, source: "GHSA-qgqg-65m8-gvwg, MAL-2026-17275 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/pladddform-codegen", severity: "critical", confidence: 1.0, source: "GHSA-4jh6-g3hw-7qjc, MAL-2026-17273 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/middlewares", severity: "critical", confidence: 1.0, source: "GHSA-5cwm-5j38-r753, MAL-2026-17269 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/organisationsverwaltung", severity: "critical", confidence: 1.0, source: "GHSA-gxrr-r3q5-4429, MAL-2026-17270 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/interfaces", severity: "critical", confidence: 1.0, source: "GHSA-h2q3-6wwv-v7c8, MAL-2026-17262 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/mailer-pladddform", severity: "critical", confidence: 1.0, source: "GHSA-75mr-rmf4-wr8j, MAL-2026-17268 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/gutscheinverwaltung", severity: "critical", confidence: 1.0, source: "GHSA-g4hp-22g7-9hf5, MAL-2026-17261 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/hyper-json-builder", severity: "critical", confidence: 1.0, source: "GHSA-r476-wfgx-8rc7, MAL-2026-17282 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/devtool-configuration", severity: "critical", confidence: 1.0, source: "GHSA-qh4w-rc3m-9898, MAL-2026-17260 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/benefitverwaltung", severity: "critical", confidence: 1.0, source: "GHSA-xvwj-8x3p-gr7w, MAL-2026-17257 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/component-library", severity: "critical", confidence: 1.0, source: "GHSA-cjfr-hq8x-q26q, MAL-2026-17259 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/benefit-sachbezug", severity: "critical", confidence: 1.0, source: "GHSA-jr8j-48fj-734v, MAL-2026-17256 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/benefit-essenszuschuss", severity: "critical", confidence: 1.0, source: "GHSA-2c72-pm8g-m65j, MAL-2026-17253 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/benefit-internetzuschuss", severity: "critical", confidence: 1.0, source: "GHSA-784r-8wmx-42h3, MAL-2026-17254 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/belegerfassung-pladddform", severity: "critical", confidence: 1.0, source: "GHSA-5hfp-jjv9-69q8, MAL-2026-17252 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/benefit-mobilitaet", severity: "critical", confidence: 1.0, source: "GHSA-87h6-fqj7-r5rw, MAL-2026-17255 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/app-gateway-templates", severity: "critical", confidence: 1.0, source: "GHSA-52pw-jwv9-q65v, MAL-2026-17251 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/kit-5", severity: "critical", confidence: 1.0, source: "GHSA-96c4-q73c-c32q, MAL-2026-17266 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/account-management", severity: "critical", confidence: 1.0, source: "GHSA-ppvh-5qcf-3gvr, MAL-2026-17249 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "@hrmony/api-gateway-service-config", severity: "critical", confidence: 1.0, source: "GHSA-36rr-7v5c-qjqv, MAL-2026-17250 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-29" },
  { type: "package", value: "xeprews@5.2.1", severity: "critical", confidence: 1.0, source: "GHSA-v76j-vqp4-68j8, MAL-2026-17248 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exptredd@5.2.1", severity: "critical", confidence: 1.0, source: "GHSA-49qv-wmf6-cj3h, MAL-2026-17247 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exptrdd@5.2.1", severity: "critical", confidence: 1.0, source: "GHSA-56r5-h32g-xrjx, MAL-2026-17245 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exptred@5.2.1", severity: "critical", confidence: 1.0, source: "GHSA-9ggr-p22c-2m4m, MAL-2026-17246 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exprrdd@5.2.1", severity: "critical", confidence: 1.0, source: "GHSA-pf56-8g6j-whr9, MAL-2026-17244 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "express-nodejs@5.2.1", severity: "critical", confidence: 1.0, source: "GHSA-4qvj-qq37-mhw2, MAL-2026-17243 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "express-javascript@5.2.1", severity: "critical", confidence: 1.0, source: "GHSA-2m2v-6g9c-m674, MAL-2026-17242 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exprdd@5.2.1", severity: "critical", confidence: 1.0, source: "GHSA-w7pc-jg8g-2xr4, MAL-2026-17241 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "contoso-login-sim-loader@1.0.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17322 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "dotenv-preflight@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17324 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "cdn-img-fetch@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17320 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "cdn-img-fetch@1.0.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17320 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "cortana-md-engine@1.4.6", severity: "critical", confidence: 0.9, source: "MAL-2026-17323 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "chaienv@1.0.2", severity: "critical", confidence: 0.9, source: "MAL-2026-17321 (amazon-inspector)", firstSeen: "2026-09-30" },

  // Imported from GitHub Advisory Database (2026-09-17) - see docs/threat-feed-sources.md
  { type: "package", value: "my-ctf-helper-script-9921", severity: "critical", confidence: 1.0, source: "GHSA-7mhc-78r2-fgw8, MAL-2026-16365 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "pf25262", severity: "critical", confidence: 1.0, source: "GHSA-3pg3-52vp-54fg, MAL-2026-16340 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "pf23727", severity: "critical", confidence: 1.0, source: "GHSA-p2hc-jmvm-qwc9, MAL-2026-16338 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "pflag14570", severity: "critical", confidence: 1.0, source: "GHSA-qxgf-vc83-fc34, MAL-2026-16341 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "pflag29424", severity: "critical", confidence: 1.0, source: "GHSA-8jr8-g7mm-57m6, MAL-2026-16342 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "pf25133", severity: "critical", confidence: 1.0, source: "GHSA-8f7g-cf69-g5p8, MAL-2026-16339 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.2", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.3", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.3.1", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.3.2", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.3.3", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.3.4", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.3.5", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.3.6", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:friendly-greeting-tools@0.3.7", severity: "critical", confidence: 1.0, source: "GHSA-97c4-9mc7-j7wv, MAL-2026-17416 (amazon-inspector+kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:beautifytext@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-j7g2-8pxv-8gv2, MAL-2026-17417 (kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:beautifytext@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-j7g2-8pxv-8gv2, MAL-2026-17417 (kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:beautifytext@1.0.7", severity: "critical", confidence: 1.0, source: "GHSA-j7g2-8pxv-8gv2, MAL-2026-17417 (kam193)", firstSeen: "2026-09-30" },
  { type: "package", value: "com.epi.e2e_test@1.2.2", severity: "critical", confidence: 1.0, source: "GHSA-76w7-xhq5-w327, MAL-2026-17415 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "levvleys", severity: "critical", confidence: 1.0, source: "GHSA-9q97-jr9x-2qfr, MAL-2026-17397", firstSeen: "2026-09-30" },
  { type: "package", value: "@xayz/baileys", severity: "critical", confidence: 1.0, source: "GHSA-75px-x2r4-9f98, MAL-2026-17384", firstSeen: "2026-09-30" },
  { type: "package", value: "ishumdz-bail", severity: "critical", confidence: 1.0, source: "GHSA-hpmr-5fvg-hvqf, MAL-2026-17393", firstSeen: "2026-09-30" },
  { type: "package", value: "noxleyss", severity: "critical", confidence: 1.0, source: "GHSA-wf8j-w269-5xwv, MAL-2026-17402", firstSeen: "2026-09-30" },
  { type: "package", value: "my-baileys", severity: "critical", confidence: 1.0, source: "GHSA-xgfv-rm5m-vffw, MAL-2026-17400", firstSeen: "2026-09-30" },
  { type: "package", value: "whalibmob", severity: "critical", confidence: 1.0, source: "GHSA-g2qq-9229-mhjq, MAL-2026-17408", firstSeen: "2026-09-30" },
  { type: "package", value: "xzbails", severity: "critical", confidence: 1.0, source: "GHSA-w8fw-prwf-rpmg, MAL-2026-17410", firstSeen: "2026-09-30" },
  { type: "package", value: "xzvbails@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-3x7p-cc3q-4g77, MAL-2026-17411", firstSeen: "2026-09-30" },
  { type: "package", value: "kiyoramarkets@8.0.16", severity: "critical", confidence: 1.0, source: "GHSA-mjx8-f269-h2qf, MAL-2026-17396", firstSeen: "2026-09-30" },
  { type: "package", value: "lilys-baileys", severity: "critical", confidence: 1.0, source: "GHSA-xcqq-823x-hhv7, MAL-2026-17398", firstSeen: "2026-09-30" },
  { type: "package", value: "noxxleys", severity: "critical", confidence: 1.0, source: "GHSA-rqhh-ghpc-p37r, MAL-2026-17403", firstSeen: "2026-09-30" },
  { type: "package", value: "yonzoffic-baileys@8.6.90", severity: "critical", confidence: 1.0, source: "GHSA-j5q9-mf2r-jhf9, MAL-2026-17413", firstSeen: "2026-09-30" },
  { type: "package", value: "syncxbails", severity: "critical", confidence: 1.0, source: "GHSA-hvc6-5q6j-2867, MAL-2026-17407", firstSeen: "2026-09-30" },
  { type: "package", value: "saturn-baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h3r9-cv69-cx87, MAL-2026-17404", firstSeen: "2026-09-30" },
  { type: "package", value: "spencer-baileys@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-r58r-8rfq-ff52, MAL-2026-17406", firstSeen: "2026-09-30" },
  { type: "package", value: "shadowmd@8.6.87", severity: "critical", confidence: 1.0, source: "GHSA-8h9r-v5vf-jvxr, MAL-2026-17405", firstSeen: "2026-09-30" },
  { type: "package", value: "xzvexpzcbailey", severity: "critical", confidence: 1.0, source: "GHSA-fwmc-x797-fpr6, MAL-2026-17412", firstSeen: "2026-09-30" },
  { type: "package", value: "monte-md-baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vxm9-4847-jw5m, MAL-2026-17399", firstSeen: "2026-09-30" },
  { type: "package", value: "yonzofficial", severity: "critical", confidence: 1.0, source: "GHSA-5jww-9h4j-x7w7, MAL-2026-17414", firstSeen: "2026-09-30" },
  { type: "package", value: "noverojs", severity: "critical", confidence: 1.0, source: "GHSA-wj4h-927q-m5xv, MAL-2026-17401", firstSeen: "2026-09-30" },
  { type: "package", value: "kasabaileys", severity: "critical", confidence: 1.0, source: "GHSA-vrqh-8vm7-r584, MAL-2026-17394", firstSeen: "2026-09-30" },
  { type: "package", value: "keithbaileys", severity: "critical", confidence: 1.0, source: "GHSA-mr96-r2xf-grpw, MAL-2026-17395", firstSeen: "2026-09-30" },
  { type: "package", value: "eliteprotech-baileys", severity: "critical", confidence: 1.0, source: "GHSA-jjr8-hv8r-m5x7, MAL-2026-17391", firstSeen: "2026-09-30" },
  { type: "package", value: "xvinleys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vpxr-24w4-56qf, MAL-2026-17409", firstSeen: "2026-09-30" },
  { type: "package", value: "focashi@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-9hx5-4wfr-m32w, MAL-2026-17392", firstSeen: "2026-09-30" },
  { type: "package", value: "@revizahoshii/baileys", severity: "critical", confidence: 1.0, source: "GHSA-fhwq-mfvr-5wxg, MAL-2026-17375", firstSeen: "2026-09-30" },
  { type: "package", value: "@wanzlonely/bails4u", severity: "critical", confidence: 1.0, source: "GHSA-cvfh-2x22-f8xx, MAL-2026-17381", firstSeen: "2026-09-30" },
];

const FEED_CHUNK_22: FeedIOC[] = [
  // Imported from GitHub Advisory Database (2026-09-17) - see docs/threat-feed-sources.md
  { type: "package", value: "@xatancchii/velycxbail@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-fpmr-r559-qrq5, MAL-2026-17383", firstSeen: "2026-09-30" },
  { type: "package", value: "@queenanya/baileys", severity: "critical", confidence: 1.0, source: "GHSA-w659-c49m-62p4, MAL-2026-17373", firstSeen: "2026-09-30" },
  { type: "package", value: "albert-anitabaileys@1.1.13", severity: "critical", confidence: 1.0, source: "GHSA-2435-2rp3-4hx7, MAL-2026-17385", firstSeen: "2026-09-30" },
  { type: "package", value: "@sakataoffc/baileys", severity: "critical", confidence: 1.0, source: "GHSA-cv72-gp3m-2v97, MAL-2026-17379", firstSeen: "2026-09-30" },
  { type: "package", value: "anuaja", severity: "critical", confidence: 1.0, source: "GHSA-g6f9-85p5-hpm9, MAL-2026-17386", firstSeen: "2026-09-30" },
  { type: "package", value: "@revizahoshii/hoshino@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-5hw7-w6pr-4249, MAL-2026-17376", firstSeen: "2026-09-30" },
  { type: "package", value: "@sairidev/baileys-new@0.3.21", severity: "critical", confidence: 1.0, source: "GHSA-xw6v-5999-m5r7, MAL-2026-17378", firstSeen: "2026-09-30" },
  { type: "package", value: "arsya-baileys@9.2.0", severity: "critical", confidence: 1.0, source: "GHSA-324p-wm5r-x38v, MAL-2026-17387", firstSeen: "2026-09-30" },
  { type: "package", value: "@ostyado/baileys", severity: "critical", confidence: 1.0, source: "GHSA-wcr2-cpf3-rj9m, MAL-2026-17372", firstSeen: "2026-09-30" },
  { type: "package", value: "@noxleyss/baileys@1.1.10", severity: "critical", confidence: 1.0, source: "GHSA-fvp5-5pm3-p4pj, MAL-2026-17369", firstSeen: "2026-09-30" },
  { type: "package", value: "@levvicode/baileys", severity: "critical", confidence: 1.0, source: "GHSA-64qg-xmr9-2f4p, MAL-2026-17366", firstSeen: "2026-09-30" },
  { type: "package", value: "@lendkzn/xntaabail@7.0.0", severity: "critical", confidence: 1.0, source: "GHSA-p5cc-9mw3-v97w, MAL-2026-17364", firstSeen: "2026-09-30" },
  { type: "package", value: "bungoma", severity: "critical", confidence: 1.0, source: "GHSA-ww72-pf36-94gj, MAL-2026-17389", firstSeen: "2026-09-30" },
  { type: "package", value: "baileys-xbats", severity: "critical", confidence: 1.0, source: "GHSA-7vgr-9ffm-pcvq, MAL-2026-17388", firstSeen: "2026-09-30" },
  { type: "package", value: "cantarella-baileys", severity: "critical", confidence: 1.0, source: "GHSA-x9p7-rw8c-33cx, MAL-2026-17390", firstSeen: "2026-09-30" },
  { type: "package", value: "@teamolduser/baileys", severity: "critical", confidence: 1.0, source: "GHSA-5r2r-xhj4-34x2, MAL-2026-17380", firstSeen: "2026-09-30" },
  { type: "package", value: "@lendxntaa/baileys", severity: "critical", confidence: 1.0, source: "GHSA-pvw3-cpwh-j97f, MAL-2026-17365", firstSeen: "2026-09-30" },
  { type: "package", value: "@saazkira/baileys", severity: "critical", confidence: 1.0, source: "GHSA-rqcw-rcxf-63pp, MAL-2026-17377", firstSeen: "2026-09-30" },
  { type: "package", value: "@nyzzpedia/baileys-new@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-rmgh-5jhh-hg68, MAL-2026-17370", firstSeen: "2026-09-30" },
  { type: "package", value: "@wenzyx1/bails", severity: "critical", confidence: 1.0, source: "GHSA-2qgj-rvf8-vwqv, MAL-2026-17382", firstSeen: "2026-09-30" },
  { type: "package", value: "@rennnpm/baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8w6p-crxw-qc2m, MAL-2026-17374", firstSeen: "2026-09-30" },
  { type: "package", value: "@nyzzpediaa/baileys-new", severity: "critical", confidence: 1.0, source: "GHSA-vwq4-8q2g-gg4w, MAL-2026-17371", firstSeen: "2026-09-30" },
  { type: "package", value: "@mikudeveloper/grace", severity: "critical", confidence: 1.0, source: "GHSA-mjq2-8p38-g74g, MAL-2026-17367", firstSeen: "2026-09-30" },
  { type: "package", value: "@mivesensei/baileys@0.4.2", severity: "critical", confidence: 1.0, source: "GHSA-hgwp-qvq7-jhff, MAL-2026-17368", firstSeen: "2026-09-30" },
  { type: "package", value: "@ikyyjee/ikyysingle@1.7.8", severity: "critical", confidence: 1.0, source: "GHSA-6wpx-c5rq-xq7g, MAL-2026-17358", firstSeen: "2026-09-30" },
  { type: "package", value: "@jojoxyz/condemnedforce-baileys@2.3.0", severity: "critical", confidence: 1.0, source: "GHSA-9hqm-fc7g-6425, MAL-2026-17360", firstSeen: "2026-09-30" },
  { type: "package", value: "@ikyyjee/ikyysinggle@1.7.7", severity: "critical", confidence: 1.0, source: "GHSA-gf54-gmxf-9wwx, MAL-2026-17357", firstSeen: "2026-09-30" },
  { type: "package", value: "@kxa/xbails@0.0.5", severity: "critical", confidence: 1.0, source: "GHSA-gm5c-7967-vvfr, MAL-2026-17363", firstSeen: "2026-09-30" },
  { type: "package", value: "@ikanngeming/ikannbail", severity: "critical", confidence: 1.0, source: "GHSA-rf69-qjhh-rx9h, MAL-2026-17355", firstSeen: "2026-09-30" },
  { type: "package", value: "@japofc/baileys", severity: "critical", confidence: 1.0, source: "GHSA-xg7c-vv95-m77x, MAL-2026-17359", firstSeen: "2026-09-30" },
  { type: "package", value: "@kelvdra/baileys", severity: "critical", confidence: 1.0, source: "GHSA-qr96-8wf2-prfm, MAL-2026-17362", firstSeen: "2026-09-30" },
  { type: "package", value: "@fhkryxv/baileys-new@0.3.22", severity: "critical", confidence: 1.0, source: "GHSA-4c5h-x65g-5jxx, MAL-2026-17353", firstSeen: "2026-09-30" },
  { type: "package", value: "@hanzofc/baileys", severity: "critical", confidence: 1.0, source: "GHSA-qcfw-cc7v-hqrp, MAL-2026-17354", firstSeen: "2026-09-30" },
  { type: "package", value: "@kanaraa/baileys", severity: "critical", confidence: 1.0, source: "GHSA-prhg-r778-jc6m, MAL-2026-17361", firstSeen: "2026-09-30" },
  { type: "package", value: "@fhkryxv/baileys", severity: "critical", confidence: 1.0, source: "GHSA-wv5j-q989-gpg9, MAL-2026-17352", firstSeen: "2026-09-30" },
  { type: "package", value: "@bottino/baileys", severity: "critical", confidence: 1.0, source: "GHSA-f98g-fwj3-vvxc, MAL-2026-17351", firstSeen: "2026-09-30" },
  { type: "package", value: "@ikyyjee/ikkysingle@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-7pjq-h23c-mpv6, MAL-2026-17356", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/velvetry", severity: "critical", confidence: 1.0, source: "GHSA-g249-pm94-vr27, MAL-2026-17349", firstSeen: "2026-09-30" },
  { type: "package", value: "@badzz88/baileys", severity: "critical", confidence: 1.0, source: "GHSA-rf9x-xcrv-wjmc, MAL-2026-17341", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/teambails", severity: "critical", confidence: 1.0, source: "GHSA-289q-5xqh-ghv5, MAL-2026-17348", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/skyblue@2.1.2", severity: "critical", confidence: 1.0, source: "GHSA-r285-5mh6-5w3v, MAL-2026-17347", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/xtrxbails@0.0.8", severity: "critical", confidence: 1.0, source: "GHSA-2mwq-vxg9-67pm, MAL-2026-17350", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/familyxtrx@0.1.5", severity: "critical", confidence: 1.0, source: "GHSA-8m3x-3r2m-qpw7, MAL-2026-17344", firstSeen: "2026-09-30" },
  { type: "package", value: "@astracode/byles-new", severity: "critical", confidence: 1.0, source: "GHSA-7jgw-q4fr-8pxr, MAL-2026-17340", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/privatebails@1.4.1", severity: "critical", confidence: 1.0, source: "GHSA-4j8c-968c-8p2r, MAL-2026-17346", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/crystalred@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-p97h-939j-wpm5, MAL-2026-17343", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/flowblue@1.5.7", severity: "critical", confidence: 1.0, source: "GHSA-5rx7-7php-xrqp, MAL-2026-17345", firstSeen: "2026-09-30" },
  { type: "package", value: "reactjs-risk@99.17.1", severity: "critical", confidence: 1.0, source: "GHSA-7c65-pwf5-vfcq, MAL-2026-17339 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-30" },
  { type: "package", value: "reactjs-risk@99.17.2", severity: "critical", confidence: 1.0, source: "GHSA-7c65-pwf5-vfcq, MAL-2026-17339 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-30" },
  { type: "package", value: "reactjs-risk@99.9.9", severity: "critical", confidence: 1.0, source: "GHSA-7c65-pwf5-vfcq, MAL-2026-17339 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-30" },
  { type: "package", value: "reactjs-risk@99.17.4", severity: "critical", confidence: 1.0, source: "GHSA-7c65-pwf5-vfcq, MAL-2026-17339 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-30" },
  { type: "package", value: "reactjs-risk@99.12.0", severity: "critical", confidence: 1.0, source: "GHSA-7c65-pwf5-vfcq, MAL-2026-17339 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-30" },
  { type: "package", value: "reactjs-risk@99.17.0", severity: "critical", confidence: 1.0, source: "GHSA-7c65-pwf5-vfcq, MAL-2026-17339 (amazon-inspector+ossf-package-analysis)", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/belbails@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-94fr-7p9q-mmx4, MAL-2026-17342", firstSeen: "2026-09-30" },
  { type: "package", value: "pypi:cleanup-string@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-r9mq-4q39-vw6h, MAL-2026-17325 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "imgbundle@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5p43-g79v-96pj, MAL-2026-17330 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "imgbundle@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-5p43-g79v-96pj, MAL-2026-17330 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "fca-raihan@37.2.5", severity: "critical", confidence: 1.0, source: "GHSA-gmjq-r5g4-xc73, MAL-2026-17328 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "fca-raihan@37.2.6", severity: "critical", confidence: 1.0, source: "GHSA-gmjq-r5g4-xc73, MAL-2026-17328 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "exiouss@5.0.1", severity: "critical", confidence: 1.0, source: "GHSA-gg34-g46w-6hhf, MAL-2026-17327 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "@zeronexcode/baileys@7.0.0-zeronex.8", severity: "critical", confidence: 1.0, source: "GHSA-h49v-c54j-rfw2, MAL-2026-17326", firstSeen: "2026-09-25" },
  { type: "package", value: "runhelper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pxgx-w72j-f3p8, MAL-2026-17332 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "focaleys@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-jfhq-f5v2-pf3m, MAL-2026-17329 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "@cat-gen/material", severity: "critical", confidence: 0.9, source: "GHSA-m7x3-q6r8-p5rg, MAL-2026-17334 (ghsa-malware)", firstSeen: "2026-09-30" },
  { type: "package", value: "@cat-gen/materia", severity: "critical", confidence: 0.9, source: "GHSA-m8g8-xcgx-j6hw, MAL-2026-17333 (ghsa-malware)", firstSeen: "2026-09-30" },
  { type: "package", value: "building-build", severity: "critical", confidence: 1.0, source: "GHSA-2fq4-2r26-qr64, MAL-2026-17164 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-24" },
  { type: "package", value: "feed-widget-helper", severity: "critical", confidence: 1.0, source: "GHSA-r52r-vpcc-38v2, MAL-2026-16332 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "analytics-widget", severity: "critical", confidence: 1.0, source: "GHSA-548g-r2c9-6chm, MAL-2026-17163 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-24" },
  { type: "package", value: "@firelordzuka/pulse-poc", severity: "critical", confidence: 0.9, source: "GHSA-h645-43f8-g987, MAL-2026-17335 (ghsa-malware)", firstSeen: "2026-09-30" },
  { type: "package", value: "link-age-great", severity: "critical", confidence: 0.9, source: "GHSA-jmrg-vr2j-j96x, MAL-2026-17337 (ghsa-malware)", firstSeen: "2026-09-30" },
  { type: "package", value: "link-status-page", severity: "critical", confidence: 0.9, source: "GHSA-5j3f-rr83-xcpq, MAL-2026-17338 (ghsa-malware)", firstSeen: "2026-09-30" },
  { type: "package", value: "web-vitals-polyfill-core-v1", severity: "critical", confidence: 1.0, source: "GHSA-h475-44q2-vfjx, MAL-2026-17303 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-30" },
  { type: "package", value: "@redman89405/my-module", severity: "critical", confidence: 0.9, source: "GHSA-vc53-jhh2-pwf3, MAL-2026-17336 (ghsa-malware)", firstSeen: "2026-09-30" },
  { type: "package", value: "radio-player-theme", severity: "critical", confidence: 1.0, source: "GHSA-pp2v-g64w-gm6f, MAL-2026-16347 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-19" },
  { type: "package", value: "iban-validator-js", severity: "critical", confidence: 0.9, source: "GHSA-wg95-pj2w-mm76, MAL-2026-17331 (ghsa-malware)", firstSeen: "2026-09-30" },
  { type: "package", value: "jexkcode", severity: "critical", confidence: 0.9, source: "GHSA-j72h-3h5h-43v5, MAL-2026-16220 (ghsa-malware)", firstSeen: "2026-09-16" },
  { type: "package", value: "get-power", severity: "critical", confidence: 1.0, source: "GHSA-3g9w-hfq8-vr7p, MAL-2026-16156 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-14" },
  { type: "package", value: "test-supply-npm-lib-4@3.3.6", severity: "critical", confidence: 1.0, source: "GHSA-94gj-gfw3-p6wc, MAL-2026-17314 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "test-supply-npm-lib-4@3.3.5", severity: "critical", confidence: 1.0, source: "GHSA-94gj-gfw3-p6wc, MAL-2026-17314 (amazon-inspector)", firstSeen: "2026-09-30" },
  { type: "package", value: "items-validator@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-hvv9-35pw-8qvf, MAL-2026-17235 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "figlet-chalk-render@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-frpq-rj8q-hpr4, MAL-2026-17226 (amazon-inspector)", firstSeen: "2026-09-28" },
  { type: "package", value: "shadowmd", severity: "critical", confidence: 0.9, source: "MAL-2026-17405", firstSeen: "2026-09-30" },
  { type: "package", value: "yonzoffic-baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17413", firstSeen: "2026-09-30" },
  { type: "package", value: "spencer-baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17406", firstSeen: "2026-09-30" },
  { type: "package", value: "xvinleys", severity: "critical", confidence: 0.9, source: "MAL-2026-17409", firstSeen: "2026-09-30" },
  { type: "package", value: "monte-md-baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17399", firstSeen: "2026-09-30" },
  { type: "package", value: "saturn-baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17404", firstSeen: "2026-09-30" },
  { type: "package", value: "kiyoramarkets", severity: "critical", confidence: 0.9, source: "MAL-2026-17396", firstSeen: "2026-09-30" },
  { type: "package", value: "focashi", severity: "critical", confidence: 0.9, source: "MAL-2026-17392", firstSeen: "2026-09-30" },
  { type: "package", value: "@mivesensei/baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17368", firstSeen: "2026-09-30" },
  { type: "package", value: "@kxa/xbails", severity: "critical", confidence: 0.9, source: "MAL-2026-17363", firstSeen: "2026-09-30" },
  { type: "package", value: "xzvbails", severity: "critical", confidence: 0.9, source: "MAL-2026-17411", firstSeen: "2026-09-30" },
  { type: "package", value: "@jojoxyz/condemnedforce-baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17360", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/familyxtrx", severity: "critical", confidence: 0.9, source: "MAL-2026-17344", firstSeen: "2026-09-30" },
  { type: "package", value: "arsya-baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17387", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/crystalred", severity: "critical", confidence: 0.9, source: "MAL-2026-17343", firstSeen: "2026-09-30" },
  { type: "package", value: "@ikyyjee/ikyysinggle", severity: "critical", confidence: 0.9, source: "MAL-2026-17357", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/flowblue", severity: "critical", confidence: 0.9, source: "MAL-2026-17345", firstSeen: "2026-09-30" },
  { type: "package", value: "@fhkryxv/baileys-new", severity: "critical", confidence: 0.9, source: "MAL-2026-17353", firstSeen: "2026-09-30" },
  { type: "package", value: "@ikyyjee/ikyysingle", severity: "critical", confidence: 0.9, source: "MAL-2026-17358", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/skyblue", severity: "critical", confidence: 0.9, source: "MAL-2026-17347", firstSeen: "2026-09-30" },
  { type: "package", value: "albert-anitabaileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17385", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/xtrxbails", severity: "critical", confidence: 0.9, source: "MAL-2026-17350", firstSeen: "2026-09-30" },
  { type: "package", value: "@nyzzpedia/baileys-new", severity: "critical", confidence: 0.9, source: "MAL-2026-17370", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/belbails", severity: "critical", confidence: 0.9, source: "MAL-2026-17342", firstSeen: "2026-09-30" },
  { type: "package", value: "@ikyyjee/ikkysingle", severity: "critical", confidence: 0.9, source: "MAL-2026-17356", firstSeen: "2026-09-30" },
  { type: "package", value: "@lendkzn/xntaabail", severity: "critical", confidence: 0.9, source: "MAL-2026-17364", firstSeen: "2026-09-30" },
  { type: "package", value: "@xatancchii/velycxbail", severity: "critical", confidence: 0.9, source: "MAL-2026-17383", firstSeen: "2026-09-30" },
  { type: "package", value: "@noxleyss/baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17369", firstSeen: "2026-09-30" },
  { type: "package", value: "@rennnpm/baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17374", firstSeen: "2026-09-30" },
  { type: "package", value: "@bellaxchuu/privatebails", severity: "critical", confidence: 0.9, source: "MAL-2026-17346", firstSeen: "2026-09-30" },
  { type: "package", value: "@revizahoshii/hoshino", severity: "critical", confidence: 0.9, source: "MAL-2026-17376", firstSeen: "2026-09-30" },
  { type: "package", value: "@sairidev/baileys-new", severity: "critical", confidence: 0.9, source: "MAL-2026-17378", firstSeen: "2026-09-30" },
  { type: "package", value: "express-session-timer@1.0.11", severity: "critical", confidence: 0.9, source: "MAL-2026-16065 (amazon-inspector)", firstSeen: "2026-09-09" },
  { type: "package", value: "express-session-timer@1.0.15", severity: "critical", confidence: 0.9, source: "MAL-2026-16065 (amazon-inspector)", firstSeen: "2026-09-09" },

  // GHAPPIER loader (CloudSEK, September 2026): hijacked maintainer account,
  // rewritten release workflow; 0.2.21 only, 0.2.22 is the clean restore.
  { type: "package", value: "@dforge-core/dforge-mcp@0.2.21", severity: "critical", confidence: 1.0, family: "GHAPPIER", campaign: "GHAPPIER loader via npm trusted publishing", source: "CloudSEK GHAPPIER report, Infosecurity Magazine, registry publish times", firstSeen: "2026-09-09" },

  // 2026-09-17 daily intelligence kept in the offline bundle. The 2026-09-17
  // catalog window (feed-partition.config.json) was set for the GitHub Advisory
  // Database bulk migration of the historical OpenSSF corpus (MAL-2025 and older
  // ids, plus MAL-2026 ids up to 12395), but a window covers a whole day, so it
  // also sent these 64 fresh records to the catalog: MAL-2026-16248 to 16275
  // from amazon-inspector, kam193 and ghsa-malware. That left a default offline
  // scan blind to them. This comment block curates them, so every later
  // migration keeps them bundled.
  { type: "package", value: "pypi:requests-auroras@2.34.2", severity: "critical", confidence: 1.0, source: "GHSA-5p5r-2g2v-44x5, MAL-2026-16274 (kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "blue-string-formatter-utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5mc6-ff2p-32qj, MAL-2026-16273 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:requests-triwes@2.34.2", severity: "critical", confidence: 1.0, source: "GHSA-c47p-v854-jfg4, MAL-2026-16275 (kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:requests-asetwe@2.34.2", severity: "critical", confidence: 1.0, source: "GHSA-38mf-xcf2-88cp, MAL-2026-16269 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@1.5.0", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.0", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.1", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.2", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.3", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.5", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.6", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.7", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.8", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.9", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.10", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.11", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.12", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.13", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.14", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.15", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.16", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:pyjstat-smooth@2.5.17", severity: "critical", confidence: 1.0, source: "GHSA-rq89-pjxc-hpf8, MAL-2026-16267 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:index-forum@2.5.4", severity: "critical", confidence: 1.0, source: "GHSA-8466-62v8-x2vr, MAL-2026-16268 (kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "@tink/tink-link-core@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-hvcc-qwg6-972c, MAL-2026-16270 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "test89078-auth@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-x9mp-cqw3-368c, MAL-2026-16271 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "kartykgithub-multiversion-a@1.0.0", severity: "critical", confidence: 0.9, source: "GHSA-p957-4pc7-x6hp, MAL-2026-16272 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "kartykgithub-multiversion-a@1.0.1", severity: "critical", confidence: 0.9, source: "GHSA-p957-4pc7-x6hp, MAL-2026-16272 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "@railone/image-utils@1.1.10", severity: "critical", confidence: 1.0, source: "GHSA-h72c-8fwp-p292, MAL-2026-16261 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "tailwindcss-form-ui@0.5.1", severity: "critical", confidence: 1.0, source: "GHSA-hxjv-cpxc-564m, MAL-2026-16262 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:aiosendletter@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-hc2r-77jq-mjrx, MAL-2026-16264 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:aiosendletter@3.7", severity: "critical", confidence: 1.0, source: "GHSA-hc2r-77jq-mjrx, MAL-2026-16264 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:aiosendletter@3.8", severity: "critical", confidence: 1.0, source: "GHSA-hc2r-77jq-mjrx, MAL-2026-16264 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:aiosendletter@3.9", severity: "critical", confidence: 1.0, source: "GHSA-hc2r-77jq-mjrx, MAL-2026-16264 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:aiosendletter@4.0", severity: "critical", confidence: 1.0, source: "GHSA-hc2r-77jq-mjrx, MAL-2026-16264 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:aiosendletter@4.1", severity: "critical", confidence: 1.0, source: "GHSA-hc2r-77jq-mjrx, MAL-2026-16264 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:aiosendletter@4.3", severity: "critical", confidence: 1.0, source: "GHSA-hc2r-77jq-mjrx, MAL-2026-16264 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:aiosendletter@4.5", severity: "critical", confidence: 1.0, source: "GHSA-hc2r-77jq-mjrx, MAL-2026-16264 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:aiosendletter@4.6", severity: "critical", confidence: 1.0, source: "GHSA-hc2r-77jq-mjrx, MAL-2026-16264 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "tailwindcss-form-utils@0.5.1", severity: "critical", confidence: 1.0, source: "GHSA-fm65-924g-pg2g, MAL-2026-16263 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "@kartyk-github-org/takedown-b", severity: "critical", confidence: 0.9, source: "GHSA-q83w-3hvr-fgg7, MAL-2026-16266 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "@kartyk-github-org/takedown-a", severity: "critical", confidence: 0.9, source: "GHSA-rx76-mcg9-gqc5, MAL-2026-16265 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "confx1789550882@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-x9hr-wrvh-643j, MAL-2026-16260 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "tailwindcss-contact-form@0.5.1", severity: "critical", confidence: 1.0, source: "GHSA-3v8q-9qpf-w44w, MAL-2026-16251 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "ragacateslikodi@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-24c6-54w5-jpg6, MAL-2026-16252 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "ragacateslikodi@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-24c6-54w5-jpg6, MAL-2026-16252 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "ragacateslikodi@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-24c6-54w5-jpg6, MAL-2026-16252 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "ragacateslikodi@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-24c6-54w5-jpg6, MAL-2026-16252 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "ragacateslikodi@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-24c6-54w5-jpg6, MAL-2026-16252 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "ragacateslikodi@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-24c6-54w5-jpg6, MAL-2026-16252 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "ragacateslikodi@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-24c6-54w5-jpg6, MAL-2026-16252 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "pypi:marketing-mcp@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-7m86-6729-5w7h, MAL-2026-16250 (amazon-inspector+kam193)", firstSeen: "2026-09-17" },
  { type: "package", value: "pulse-pwn-9f3a2@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6j5j-5wqf-cv2q, MAL-2026-16254 (amazon-inspector)", firstSeen: "2026-09-17" },
  { type: "package", value: "randompkga", severity: "critical", confidence: 1.0, source: "GHSA-532p-c872-3926, MAL-2026-16255 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "randompkge", severity: "critical", confidence: 0.9, source: "GHSA-rc4q-v4pf-8j7x, MAL-2026-16259 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "randompkgb", severity: "critical", confidence: 0.9, source: "GHSA-vxvv-gh3g-35pj, MAL-2026-16256 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "randompkgd", severity: "critical", confidence: 0.9, source: "GHSA-cqc9-f5fp-r45q, MAL-2026-16258 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "randompkgc", severity: "critical", confidence: 0.9, source: "GHSA-p8m5-fmxm-99f6, MAL-2026-16257 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "kartykgithub-takedown-b@1.0.0", severity: "critical", confidence: 0.9, source: "GHSA-f8wr-9w83-7gmw, MAL-2026-16249 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "kartykgithub-takedown-a@1.0.2", severity: "critical", confidence: 0.9, source: "GHSA-5r64-rpvg-q9rr, MAL-2026-16248 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "kartykgithub-takedown-a@1.0.1", severity: "critical", confidence: 0.9, source: "GHSA-5r64-rpvg-q9rr, MAL-2026-16248 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "kartykgithub-takedown-a@1.0.0", severity: "critical", confidence: 0.9, source: "GHSA-5r64-rpvg-q9rr, MAL-2026-16248 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "kartykgithub-takedown-a@1.0.3", severity: "critical", confidence: 0.9, source: "GHSA-5r64-rpvg-q9rr, MAL-2026-16248 (ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "pulse-pwn-9f3a2", severity: "critical", confidence: 1.0, source: "GHSA-fwr5-cj49-cq4h, MAL-2026-16254 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-17" },
  { type: "package", value: "ragacateslikodi", severity: "critical", confidence: 1.0, source: "GHSA-mjhw-5x2v-v3wg, MAL-2026-16252 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-17" },

  // Imported from GitHub Advisory Database (2026-09-19) - see docs/threat-feed-sources.md
  { type: "package", value: "pypi:voxeval@0.4.2", severity: "critical", confidence: 1.0, source: "GHSA-xmhj-hj4f-c924, MAL-2026-17457 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:voxeval@0.4.3", severity: "critical", confidence: 1.0, source: "GHSA-xmhj-hj4f-c924, MAL-2026-17457 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:voxeval@0.4.4", severity: "critical", confidence: 1.0, source: "GHSA-xmhj-hj4f-c924, MAL-2026-17457 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:voxeval@0.4.5", severity: "critical", confidence: 1.0, source: "GHSA-xmhj-hj4f-c924, MAL-2026-17457 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "@woodpecker-web-shared/components", severity: "critical", confidence: 1.0, source: "GHSA-44hm-95r4-wcrf, MAL-2026-16354 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "bnppf-flag-icons", severity: "critical", confidence: 1.0, source: "GHSA-34p9-xxp2-hv3g, MAL-2026-16350 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "hardhat-zet", severity: "critical", confidence: 1.0, source: "GHSA-mw8r-6m3f-qmg8, MAL-2026-17234 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-28" },
  { type: "package", value: "@smwebserver/static@99.9.1", severity: "critical", confidence: 1.0, source: "GHSA-xh7x-r46x-g84q, MAL-2026-17456 (ossf-package-analysis)", firstSeen: "2026-10-02" },
  { type: "package", value: "translate-base-font", severity: "critical", confidence: 0.9, source: "GHSA-grv5-7wp6-vw6h, MAL-2026-17458 (ghsa-malware)", firstSeen: "2026-10-02" },
  { type: "package", value: "ui.dist.min.js", severity: "critical", confidence: 0.9, source: "GHSA-325f-rjxf-3gm9, MAL-2026-17460 (ghsa-malware)", firstSeen: "2026-10-02" },
  { type: "package", value: "ui-base-colors", severity: "critical", confidence: 0.9, source: "GHSA-qgqx-3mhx-jwx3, MAL-2026-17459 (ghsa-malware)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:dedh-devops-automation@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-mc5h-r7fw-gr4j, MAL-2026-17455 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:dedh-devops-automation@5.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mc5h-r7fw-gr4j, MAL-2026-17455 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:dedh-devops-automation@5.6.0", severity: "critical", confidence: 1.0, source: "GHSA-mc5h-r7fw-gr4j, MAL-2026-17455 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:dedh-devops-automation@5.6.1", severity: "critical", confidence: 1.0, source: "GHSA-mc5h-r7fw-gr4j, MAL-2026-17455 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:dedh-devops-automation@5.6.999", severity: "critical", confidence: 1.0, source: "GHSA-mc5h-r7fw-gr4j, MAL-2026-17455 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:dedh-devops-automation@5.8.0", severity: "critical", confidence: 1.0, source: "GHSA-mc5h-r7fw-gr4j, MAL-2026-17455 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:dedh-devops-automation@5.8.1", severity: "critical", confidence: 1.0, source: "GHSA-mc5h-r7fw-gr4j, MAL-2026-17455 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:dedh-devops-automation@5.9.0", severity: "critical", confidence: 1.0, source: "GHSA-mc5h-r7fw-gr4j, MAL-2026-17455 (kam193)", firstSeen: "2026-10-02" },
  { type: "package", value: "niksinnkatalapp", severity: "critical", confidence: 1.0, source: "GHSA-g37r-cvvp-rj75, MAL-2026-17435", firstSeen: "2026-09-30" },
  { type: "package", value: "@bluewin/utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9ggj-2v34-hwv8, MAL-2026-17437", firstSeen: "2026-10-01" },
  { type: "package", value: "ai-workshop-radio-app", severity: "critical", confidence: 1.0, source: "GHSA-rxfj-38w3-hw2x, MAL-2026-17428", firstSeen: "2026-09-30" },
  { type: "package", value: "live-detection-dashboard", severity: "critical", confidence: 1.0, source: "GHSA-h4cx-hwvc-8mgj, MAL-2026-17434", firstSeen: "2026-09-30" },
  { type: "package", value: "brioche-apl-dev-env", severity: "critical", confidence: 1.0, source: "GHSA-8r2r-7gc9-8vq8, MAL-2026-17432", firstSeen: "2026-09-30" },
  { type: "package", value: "ai-workshop-radio-lambda", severity: "critical", confidence: 1.0, source: "GHSA-427x-rv7c-m3f9, MAL-2026-17429", firstSeen: "2026-09-30" },
  { type: "package", value: "alexa-cybertron-team-code-review-agent", severity: "critical", confidence: 1.0, source: "GHSA-g7c3-m79h-9cqq, MAL-2026-17430", firstSeen: "2026-09-30" },
  { type: "package", value: "danz-bails", severity: "critical", confidence: 1.0, source: "GHSA-83xg-jvg8-96qw, MAL-2026-17444", firstSeen: "2026-10-01" },
  { type: "package", value: "apl-rive-renderer", severity: "critical", confidence: 1.0, source: "GHSA-66jg-9x42-xwh9, MAL-2026-17431", firstSeen: "2026-09-30" },
  { type: "package", value: "xcvrenzcompany", severity: "critical", confidence: 1.0, source: "GHSA-474r-6338-73gj, MAL-2026-17452", firstSeen: "2026-10-01" },
  { type: "package", value: "okra-cloud-cdk", severity: "critical", confidence: 1.0, source: "GHSA-7rq8-hfxr-pxhw, MAL-2026-17436", firstSeen: "2026-09-30" },
  { type: "package", value: "prastzy@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-phvc-2p87-8jf3, MAL-2026-17448", firstSeen: "2026-10-02" },
  { type: "package", value: "@zanta/baileys", severity: "critical", confidence: 1.0, source: "GHSA-44wf-ggpw-qq53, MAL-2026-17443", firstSeen: "2026-10-01" },
  { type: "package", value: "wailib@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w72m-vjx4-9m36, MAL-2026-17451", firstSeen: "2026-10-02" },
  { type: "package", value: "figma-to-apl", severity: "critical", confidence: 1.0, source: "GHSA-fmw8-mrp6-mj68, MAL-2026-17433", firstSeen: "2026-09-30" },
  { type: "package", value: "ai-workshop-maa15-radio", severity: "critical", confidence: 1.0, source: "GHSA-5m79-v4p8-r597, MAL-2026-17427", firstSeen: "2026-09-30" },
  { type: "package", value: "mikuhostt-baileys", severity: "critical", confidence: 1.0, source: "GHSA-p4xf-x6j2-mq3f, MAL-2026-17447", firstSeen: "2026-10-01" },
  { type: "package", value: "luoxy-baileys", severity: "critical", confidence: 1.0, source: "GHSA-rhcf-fwmc-3cm3, MAL-2026-17446", firstSeen: "2026-10-01" },
  { type: "package", value: "prastzyy@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-23mj-w7jj-h63m, MAL-2026-17449", firstSeen: "2026-10-02" },
  { type: "package", value: "rubbydev-crash-baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2cr6-p8h2-g7pv, MAL-2026-17450", firstSeen: "2026-10-02" },
  { type: "package", value: "@fazzcodestudio/wa-web", severity: "critical", confidence: 1.0, source: "GHSA-6c6x-j4h9-g6mh, MAL-2026-17441", firstSeen: "2026-10-01" },
  { type: "package", value: "@smart-dev-wa/baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-x69h-gm3h-2w4q, MAL-2026-17442", firstSeen: "2026-10-02" },
  { type: "package", value: "ichigo-baileys", severity: "critical", confidence: 1.0, source: "GHSA-jmwp-25hp-85hw, MAL-2026-17445", firstSeen: "2026-10-01" },
  { type: "package", value: "@erlanzz/baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pwrr-vrh9-c7gf, MAL-2026-17440", firstSeen: "2026-10-02" },
  { type: "package", value: "@developmentyora/baileyss@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-hr4v-9q47-37m3, MAL-2026-17439", firstSeen: "2026-10-02" },
  { type: "package", value: "@celestial-community/baileys@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vcwh-7gr6-f894, MAL-2026-17438", firstSeen: "2026-10-02" },
  { type: "package", value: "kartykgithub-ph-f@1.0.0", severity: "critical", confidence: 0.9, source: "GHSA-x2m2-w3gv-m5wg, MAL-2026-17426 (ghsa-malware)", firstSeen: "2026-10-02" },
  { type: "package", value: "kartykgithub-ph-e@1.0.0", severity: "critical", confidence: 0.9, source: "GHSA-7hq7-x7ww-7cxr, MAL-2026-17425 (ghsa-malware)", firstSeen: "2026-10-02" },
  { type: "package", value: "kartykgithub-ph-b@0.0.1-security", severity: "critical", confidence: 0.9, source: "GHSA-27m4-jjxc-69wf, MAL-2026-17424 (ghsa-malware)", firstSeen: "2026-10-02" },
  { type: "package", value: "kartykgithub-ph-b@0.0.1-security.0", severity: "critical", confidence: 0.9, source: "GHSA-27m4-jjxc-69wf, MAL-2026-17424 (ghsa-malware)", firstSeen: "2026-10-02" },
  { type: "package", value: "kartykgithub-ph-b@1.0.0", severity: "critical", confidence: 0.9, source: "GHSA-27m4-jjxc-69wf, MAL-2026-17424 (ghsa-malware)", firstSeen: "2026-10-02" },
  { type: "package", value: "pypi:shortneer@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-2wm2-fc38-63vw, MAL-2026-17422 (kam193)", firstSeen: "2026-10-01" },
  { type: "package", value: "illusion-datalab@1.1.1", severity: "critical", confidence: 0.9, source: "GHSA-834w-x8gq-8rmx, MAL-2026-17423 (ghsa-malware)", firstSeen: "2026-10-01" },
  { type: "package", value: "illusion-datalab@1.1.2", severity: "critical", confidence: 0.9, source: "GHSA-834w-x8gq-8rmx, MAL-2026-17423 (ghsa-malware)", firstSeen: "2026-10-01" },
  { type: "package", value: "illusion-datalab@1.1.3", severity: "critical", confidence: 0.9, source: "GHSA-834w-x8gq-8rmx, MAL-2026-17423 (ghsa-malware)", firstSeen: "2026-10-01" },
  { type: "package", value: "illusion-datalab@1.1.4", severity: "critical", confidence: 0.9, source: "GHSA-834w-x8gq-8rmx, MAL-2026-17423 (ghsa-malware)", firstSeen: "2026-10-01" },
  { type: "package", value: "illusion-datalab@1.1.5", severity: "critical", confidence: 0.9, source: "GHSA-834w-x8gq-8rmx, MAL-2026-17423 (ghsa-malware)", firstSeen: "2026-10-01" },
  { type: "package", value: "homestack-cheer@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.1.2", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.1.3", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.1.5", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.1.6", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.1.7", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "homestack-cheer@1.1.8", severity: "critical", confidence: 1.0, source: "GHSA-x567-p88w-3697, MAL-2026-16333 (amazon-inspector+ghsa-malware)", firstSeen: "2026-09-21" },
  { type: "package", value: "pypi:spo365-graph@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jf8h-4jc3-c652, MAL-2026-17421 (kam193)", firstSeen: "2026-10-01" },
  { type: "package", value: "pypi:spo365-graph@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-jf8h-4jc3-c652, MAL-2026-17421 (kam193)", firstSeen: "2026-10-01" },
  { type: "package", value: "pypi:spo365-graph@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-jf8h-4jc3-c652, MAL-2026-17421 (kam193)", firstSeen: "2026-10-01" },
  { type: "package", value: "pypi:spo365-graph@1.1.2", severity: "critical", confidence: 1.0, source: "GHSA-jf8h-4jc3-c652, MAL-2026-17421 (kam193)", firstSeen: "2026-10-01" },
  { type: "package", value: "pypi:friendly-tools@0.1", severity: "critical", confidence: 1.0, source: "GHSA-8hwj-527f-mmvm, MAL-2026-17419 (amazon-inspector+kam193)", firstSeen: "2026-10-01" },
  { type: "package", value: "pypi:friendly-tools@0.2", severity: "critical", confidence: 1.0, source: "GHSA-8hwj-527f-mmvm, MAL-2026-17419 (amazon-inspector+kam193)", firstSeen: "2026-10-01" },
  { type: "package", value: "online-header@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-hg4r-6gv8-6hmj, MAL-2026-17420 (ossf-package-analysis)", firstSeen: "2026-10-01" },
  { type: "package", value: "future-scripts@0.0.2", severity: "critical", confidence: 1.0, source: "GHSA-c9xw-xmvx-ffm7, MAL-2026-17418", firstSeen: "2026-09-30" },
  { type: "package", value: "future-scripts@0.0.3", severity: "critical", confidence: 1.0, source: "GHSA-c9xw-xmvx-ffm7, MAL-2026-17418", firstSeen: "2026-09-30" },
  { type: "package", value: "prastzyy", severity: "critical", confidence: 0.9, source: "MAL-2026-17449", firstSeen: "2026-10-01" },
  { type: "package", value: "prastzy", severity: "critical", confidence: 0.9, source: "MAL-2026-17448", firstSeen: "2026-10-01" },
  { type: "package", value: "@erlanzz/baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17440", firstSeen: "2026-10-01" },
  { type: "package", value: "rubbydev-crash-baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17450", firstSeen: "2026-10-01" },
  { type: "package", value: "wailib", severity: "critical", confidence: 0.9, source: "MAL-2026-17451", firstSeen: "2026-10-01" },
  { type: "package", value: "@smart-dev-wa/baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17442", firstSeen: "2026-10-01" },
  { type: "package", value: "@developmentyora/baileyss", severity: "critical", confidence: 0.9, source: "MAL-2026-17439", firstSeen: "2026-10-01" },
  { type: "package", value: "@celestial-community/baileys", severity: "critical", confidence: 0.9, source: "MAL-2026-17438", firstSeen: "2026-10-01" },
  { type: "package", value: "pypi:voxel-tts@0.5.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17461 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxel-tts@0.5.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17461 (kam193)", firstSeen: "2026-10-03" },
  // Self-deleting anti-proctoring operator (September 2026). Single-source
  // (Xygeni September 2026 digest), no GHSA/OSV record; every name is
  // unpublished on npm. The sibling moidevl@1.0.0 (MAL-2026-16441) is bundled
  // above. Blocked by name: the vendor published no versions.
  { type: "package", value: "amicat", severity: "critical", confidence: 0.85, family: "Self-deleting anti-proctoring operator", source: "Xygeni September 2026 malicious code digest (single-source)", firstSeen: "2026-08-28" },
  { type: "package", value: "bmcat", severity: "critical", confidence: 0.85, family: "Self-deleting anti-proctoring operator", source: "Xygeni September 2026 malicious code digest (single-source)", firstSeen: "2026-08-28" },
  { type: "package", value: "eyevox", severity: "critical", confidence: 0.85, family: "Self-deleting anti-proctoring operator", source: "Xygeni September 2026 malicious code digest (single-source)", firstSeen: "2026-08-28" },
  { type: "package", value: "moidevh", severity: "critical", confidence: 0.85, family: "Self-deleting anti-proctoring operator", source: "Xygeni September 2026 malicious code digest (single-source)", firstSeen: "2026-08-31" },
  { type: "package", value: "moidevk", severity: "critical", confidence: 0.85, family: "Self-deleting anti-proctoring operator", source: "Xygeni September 2026 malicious code digest (single-source)", firstSeen: "2026-08-31" },
  // Strapi plugin "meeb322k" campaign (September 2026): the one member of the
  // Xygeni-listed set with no advisory record; its strapi-plugin-*-meeb322k
  // siblings are bundled above. Single-source, unpublished on npm.
  { type: "package", value: "fs-pwn-meeb322k", severity: "critical", confidence: 0.85, family: "Strapi plugin meeb322k", source: "Xygeni September 2026 malicious code digest (single-source)", firstSeen: "2026-09-14" },
  // MaliciousCorgi (January 2026): file-exfiltration server of two VS Code
  // "AI assistant" extensions. One original analysis (Koi Security), quoted by
  // the Phoenix Security MPI corpus, hence 0.85.
  { type: "domain", value: "aihao123.cn", severity: "critical", confidence: 0.85, campaign: "MaliciousCorgi VS Code AI extension exfiltration", source: "Koi Security MaliciousCorgi report, Phoenix Security MPI corpus", firstSeen: "2026-01-28" },

  // Imported from GitHub Advisory Database (2026-09-20) - see docs/threat-feed-sources.md
  { type: "package", value: "pypi:caoxiltts@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-cxq8-x7f3-hc2x, MAL-2026-17471 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:caoxiltts@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-cxq8-x7f3-hc2x, MAL-2026-17471 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:infrabench@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-jf4p-2v4v-8p64, MAL-2026-17469 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:infrabench@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-jf4p-2v4v-8p64, MAL-2026-17469 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:infrabench@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-jf4p-2v4v-8p64, MAL-2026-17469 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxcpmruntime@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-m88v-2prv-cxqq, MAL-2026-17470 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxcpmui4@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-ch5r-pf97-q38j, MAL-2026-17467 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxcpmkit@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-88g5-8rp2-p28f, MAL-2026-17466 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxcpmeval@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-5r29-p327-w47g, MAL-2026-17465 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxcpmintel@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-89pg-5wh4-xm89, MAL-2026-17468 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxcpmui3@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-g2fc-7mrh-v3hg, MAL-2026-17464 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxcpmtts3@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-7wrq-444c-xg89, MAL-2026-17463 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxcpmtts3@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-7wrq-444c-xg89, MAL-2026-17463 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:voxcpmtts3@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-7wrq-444c-xg89, MAL-2026-17463 (kam193)", firstSeen: "2026-10-03" },
  { type: "package", value: "pypi:echogen@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w6gm-xv6q-cq55, MAL-2026-17462 (kam193)", firstSeen: "2026-10-03" },

  // Imported from GitHub Advisory Database (2026-09-21) - see docs/threat-feed-sources.md
  { type: "package", value: "focus-visible-polyfill-lite@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5h59-r5m3-rf9w, MAL-2026-17491 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "express-fork@5.2.2", severity: "critical", confidence: 1.0, source: "GHSA-5pr8-5p22-ffv8, MAL-2026-17490 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "express-enhanced@5.2.2", severity: "critical", confidence: 1.0, source: "GHSA-qj2f-36rw-2gvm, MAL-2026-17489 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-starting-style-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-64fj-vj54-m8r3, MAL-2026-17488 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-snap-target-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-x6m9-jxjp-c938, MAL-2026-17487 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-light-dark-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-p6p9-mjx4-2fgf, MAL-2026-17481 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-gap-decorations-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-gpfw-fchg-rwjm, MAL-2026-17479 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-relative-color-util@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-63h7-vcf3-9xgh, MAL-2026-17484 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-interop-observer-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h3hx-44p9-q47q, MAL-2026-17480 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "chai-as-testmode@1.4.7", severity: "critical", confidence: 1.0, source: "GHSA-5hx2-mp3m-4gr6, MAL-2026-17473 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-scroll-anchor-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wqfg-33rw-c9rw, MAL-2026-17485 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-logical-prop-shim@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7g6f-95c5-ghgv, MAL-2026-17482 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-field-sizing-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-rmf7-f53x-p8v6, MAL-2026-17478 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-scroll-state-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wwwp-g75q-ww7r, MAL-2026-17486 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-reading-flow-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h7h4-gh2m-xjmq, MAL-2026-17483 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-env-function-shim@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-592h-fp69-gpjf, MAL-2026-17477 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-a11y-contrast-utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-4hxq-p3xc-m5cr, MAL-2026-17475 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "core-js-gnz@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5q2j-22rc-7634, MAL-2026-17474 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "css-anchor-pos-fallback@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-4ppq-v2jm-24mc, MAL-2026-17476 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "wcag-color-a11y-helpers@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-hp8q-m388-6xxg, MAL-2026-17530 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "ultimate-websocket@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w8c4-4fjc-rg48, MAL-2026-17529 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "tiny-viewport-unit-calc@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-q9p4-hv94-cxpj, MAL-2026-17528 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "tiny-dom-focus-trap@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vr8g-34ph-vq26, MAL-2026-17526 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "tiny-css-token-parser@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-gc5p-h89m-743g, MAL-2026-17525 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "tiny-focusgroup-helper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vj2w-9332-v252, MAL-2026-17527 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "tailwindcss-forms-styles@0.5.1", severity: "critical", confidence: 1.0, source: "GHSA-6qrh-6qq7-9xjh, MAL-2026-17524 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "monitoring-agent@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-9q5r-qjph-hpr8, MAL-2026-17515 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "studiocode_tools@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-j79g-9wmp-mcv8, MAL-2026-17523 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "lite-matte@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-4c6x-w3wj-2cr2, MAL-2026-17512 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "studiocode_eligibility@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-chvh-489x-9963, MAL-2026-17522 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "dom-focus-sentinel@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-94wj-mm38-wwhp, MAL-2026-17503 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "hardhat-jsx@2.0.1", severity: "critical", confidence: 1.0, source: "GHSA-w5cp-x835-j7fg, MAL-2026-17507 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "botmaker-cli@0.1.19", severity: "critical", confidence: 1.0, source: "GHSA-h2r5-f9pw-xprr, MAL-2026-17502 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "popover-anchor-polyfill@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-254v-2947-w7m9, MAL-2026-17517 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "postcss-gap-fallback-util@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-35rh-mx8g-vj6f, MAL-2026-17518 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "lite-matterr@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6p6v-j47j-wgcr, MAL-2026-17513 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "rgx33-css-grid-utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-fqp7-jcwh-2jp3, MAL-2026-17520 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "internallib_v275@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-wp69-7q5m-655v, MAL-2026-17510 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "oleh-modal@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-g7w2-c843-wqvj, MAL-2026-17516 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "lite-mater@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-294m-x97c-p7xh, MAL-2026-17511 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "dotenv-promises@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-f39p-674r-wpww, MAL-2026-17505 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "minimal-a11y-contrast-check@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-xhw7-45rg-wv8m, MAL-2026-17514 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "rgx33-flex-layout-core@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w2cr-cx6p-c475, MAL-2026-17521 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "promises-dotenv3@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-3rx7-3cx7-x3hv, MAL-2026-17519 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "hardhat-ftp@2.0.1", severity: "critical", confidence: 1.0, source: "GHSA-85mm-jcj2-w79v, MAL-2026-17506 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "hardhat-roof@2.21.0", severity: "critical", confidence: 1.0, source: "GHSA-99j2-pxrq-hpqc, MAL-2026-17509 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "hardhat-plus@2.21.0", severity: "critical", confidence: 1.0, source: "GHSA-2hcg-vv96-p63m, MAL-2026-17508 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "dotenv-async@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5gq4-v664-5cwf, MAL-2026-17504 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "a11y-tabindex-manager@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6rjc-7w2v-h9mg, MAL-2026-17501 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@kibt/www-nuxt-i18n@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-gh38-mqx9-5mxf, MAL-2026-17498 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@kibt/www-nuxt-i18n@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-gh38-mqx9-5mxf, MAL-2026-17498 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@kibt/www-nuxt-i18n@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-gh38-mqx9-5mxf, MAL-2026-17498 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@kibt/www-nuxt-i18n@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-gh38-mqx9-5mxf, MAL-2026-17498 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@kibt/www-nuxt-i18n@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-gh38-mqx9-5mxf, MAL-2026-17498 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@kibt/www-nuxt-i18n@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-gh38-mqx9-5mxf, MAL-2026-17498 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@kibt/www-nuxt-i18n@3.0.0", severity: "critical", confidence: 1.0, source: "GHSA-gh38-mqx9-5mxf, MAL-2026-17498 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@kibt/www-nuxt-i18n@2.0.1", severity: "critical", confidence: 1.0, source: "GHSA-gh38-mqx9-5mxf, MAL-2026-17498 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@nagular/router@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-cg42-crqv-qjm9, MAL-2026-17500 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@angulra/cli@22.2.1", severity: "critical", confidence: 1.0, source: "GHSA-2gcf-qjvx-w58p, MAL-2026-17495 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@nagular/core@1.0.67", severity: "critical", confidence: 1.0, source: "GHSA-wxf9-85p5-gwhp, MAL-2026-17499 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@babell/core@8.0.6", severity: "critical", confidence: 1.0, source: "GHSA-9hmh-c2v6-5rx3, MAL-2026-17497 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@angularr/core@1.0.67", severity: "critical", confidence: 1.0, source: "GHSA-9rxx-xxjx-v9w8, MAL-2026-17493 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@angularr/router@2.2.0", severity: "critical", confidence: 1.0, source: "GHSA-37mv-mqr9-gv2x, MAL-2026-17494 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@angularr/cli@22.2.1", severity: "critical", confidence: 1.0, source: "GHSA-3954-6vvg-qq74, MAL-2026-17492 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "@angulra/core@1.0.67", severity: "critical", confidence: 1.0, source: "GHSA-836w-242f-9mvg, MAL-2026-17496 (amazon-inspector)", firstSeen: "2026-10-04" },
  { type: "package", value: "pypi:anthropic-sdk@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-xxp4-7566-29xj, MAL-2026-17472 (amazon-inspector+kam193)", firstSeen: "2026-10-04" },
  { type: "package", value: "xeprews@5.2.2", severity: "critical", confidence: 1.0, source: "GHSA-v76j-vqp4-68j8, MAL-2026-17248 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exptredd@5.2.3", severity: "critical", confidence: 1.0, source: "GHSA-49qv-wmf6-cj3h, MAL-2026-17247 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exptredd@5.2.4", severity: "critical", confidence: 1.0, source: "GHSA-49qv-wmf6-cj3h, MAL-2026-17247 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exptred@5.2.2", severity: "critical", confidence: 1.0, source: "GHSA-9ggr-p22c-2m4m, MAL-2026-17246 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exprrdd@5.2.2", severity: "critical", confidence: 1.0, source: "GHSA-pf56-8g6j-whr9, MAL-2026-17244 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "express-nodejs@5.2.2", severity: "critical", confidence: 1.0, source: "GHSA-4qvj-qq37-mhw2, MAL-2026-17243 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "express-javascript@5.2.2", severity: "critical", confidence: 1.0, source: "GHSA-2m2v-6g9c-m674, MAL-2026-17242 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "exprdd@5.2.2", severity: "critical", confidence: 1.0, source: "GHSA-w7pc-jg8g-2xr4, MAL-2026-17241 (amazon-inspector)", firstSeen: "2026-09-29" },
  { type: "package", value: "hardhat-devkit@2.0.1", severity: "critical", confidence: 1.0, source: "GHSA-2wmg-qp72-3736, MAL-2026-16349 (amazon-inspector)", firstSeen: "2026-09-21" },
  { type: "package", value: "css-dwsawd-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17550 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "hardhat-kex@2.0.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17559 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-nbanqq-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17555 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-display-reading-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17549 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@anguar/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17535 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@abgular/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17532 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "abbishal-poc@1.1.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17545 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@angulaar/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17537 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "unified-platform@99.9.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17566 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "typesens@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17565 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "tostpro@100.6.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17564 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "tostpro@100.2.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17564 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-svqggc-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17557 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@anuglar/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17541 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-ayucyz-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17548 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "risk-detection@99.9.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17563 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "insomnia-plugin-api-lint-helper@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17561 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "hardhat-spack@3.0.2", severity: "critical", confidence: 0.9, source: "MAL-2026-17560 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "internallib_v923@1.0.3", severity: "critical", confidence: 0.9, source: "MAL-2026-17562 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-txedrf-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17558 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-mpmdds-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17554 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-ikomdq-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17553 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-gvqmfn-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17551 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-at-scope-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17547 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-ogojwh-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17556 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "css-hgwctv-polyfill@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17552 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "aria-live-region-helper@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17546 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@angulaar/cli@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17536 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@inpeek/odata-angular@99.99.102", severity: "critical", confidence: 0.9, source: "MAL-2026-17543 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@inpeek/odata-angular@99.99.101", severity: "critical", confidence: 0.9, source: "MAL-2026-17543 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@inpeek/odata-angular@99.99.100", severity: "critical", confidence: 0.9, source: "MAL-2026-17543 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@inpeek/odata-angular@99.99.99", severity: "critical", confidence: 0.9, source: "MAL-2026-17543 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@qngular/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17544 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@anngular/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17540 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@anfular/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17533 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@angupar/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17539 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@inpeek/odata@99.99.102", severity: "critical", confidence: 0.9, source: "MAL-2026-17542 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@inpeek/odata@99.99.100", severity: "critical", confidence: 0.9, source: "MAL-2026-17542 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@inpeek/odata@99.99.99", severity: "critical", confidence: 0.9, source: "MAL-2026-17542 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@inpeek/odata@99.99.101", severity: "critical", confidence: 0.9, source: "MAL-2026-17542 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@angjlar/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17534 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "@angulr/core@22.2.1", severity: "critical", confidence: 0.9, source: "MAL-2026-17538 (amazon-inspector)", firstSeen: "2026-10-05" },
  { type: "package", value: "api-nebula@1.0.0", severity: "critical", confidence: 0.9, source: "MAL-2026-17531 (amazon-inspector)", firstSeen: "2026-10-05" },
];

// Composed from the chunks above. A single array literal of this size trips
// TS2590 ("union type that is too complex to represent") in tsc; splitting it
// into capacity-bounded consts and spreading them keeps every entry fully
// typechecked against FeedIOC while staying far under that ceiling.
// scripts/import-threat-feed.mjs appends to the last chunk and starts a new one
// at FEED_CHUNK_CAPACITY entries, so no single literal grows back into TS2590.
const BUNDLED_FEED: FeedIOC[] = [
  ...FEED_CHUNK_0,
  ...FEED_CHUNK_1,
  ...FEED_CHUNK_2,
  ...FEED_CHUNK_3,
  ...FEED_CHUNK_4,
  ...FEED_CHUNK_5,
  ...FEED_CHUNK_6,
  ...FEED_CHUNK_7,
  ...FEED_CHUNK_8,
  ...FEED_CHUNK_9,
  ...FEED_CHUNK_10,
  ...FEED_CHUNK_11,
  ...FEED_CHUNK_12,
  ...FEED_CHUNK_13,
  ...FEED_CHUNK_14,
  ...FEED_CHUNK_15,
  ...FEED_CHUNK_16,
  ...FEED_CHUNK_17,
  ...FEED_CHUNK_18,
  ...FEED_CHUNK_19,
  ...FEED_CHUNK_20,
  ...FEED_CHUNK_21,
  ...FEED_CHUNK_22,
];

// The former default cache directory, relative to the working directory. The
// default is now per user (src/cache-dir.ts, resolveCacheDir), which "feed
// refresh" and loadThreatIntel() both call so they agree on the location.
// Kept exported for API compatibility; nothing in the scanner defaults to it.
export const CACHE_DIR = ".scg-cache";
export const FEED_CACHE_FILE = "threat-feed.json";

/** Where the downloaded catalog is cached, beside the feed cache. */
export const CATALOG_CACHE_FILE = "threat-catalog.json";

/**
 * Why the catalog was not merged.
 *
 * - `absent`       no cache file. The ordinary state before a first refresh.
 * - `unreadable`   present but not parseable as the expected shape.
 * - `version-mismatch` built for a different release of this package.
 * - `digest-mismatch`  built from a different catalog than this release pins.
 * - `corrupt`      the entries do not match the checksum recorded beside them.
 */
export type CatalogUnavailableReason =
  | "absent"
  | "unreadable"
  | "version-mismatch"
  | "digest-mismatch"
  | "corrupt";

/** What the last loadThreatIntel() call found in the on-disk catalog cache. */
export interface CatalogState {
  /** The catalog was present, accepted and merged. */
  available: boolean;
  /** Why not, when it was not. Undefined when available. */
  reason?: CatalogUnavailableReason;
  /** Entries that passed validation and were offered to the merge. */
  entryCount: number;
  /** The version the cache was built for, when it recorded one. */
  cachedVersion?: string;
}
/**
 * How old a refreshed feed cache may get before `feed refresh` is due again.
 *
 * This is a REFRESH-DUE threshold, not an expiry. Until v6.0.6 it was an
 * expiry: a cache older than this was dropped whole and the scan silently fell
 * back to the bundled feed, so a user who ran `feed refresh` weekly was
 * unprotected by it for six days out of seven and was never told. Threat intel
 * is monotonic - a malicious package@version does not stop being malicious
 * because the file describing it is two days old - so discarding it could only
 * ever lower detection. Stale entries are now merged as usual and the staleness
 * is reported through getFeedCacheState() for the CLI to surface.
 */
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Bounds every remote feed acquisition in this package: the `feed refresh`
 * download (feed.ts) and the legacy updateThreatFeed() below both read them, so
 * the two paths cannot drift apart again.
 *
 * A network read with no deadline is an availability dependency on a stranger.
 * The deadline here is ABSOLUTE, not an inactivity timeout: it spans DNS,
 * connect, headers and the body read, which is the only kind that fires on a
 * peer that keeps trickling bytes instead of going silent. The reasoning is the
 * same one written out at solana-monitor.ts, applied to the feed channel.
 *
 * maxBytes is roughly ten times the published feed.json, and matches
 * NPM_REMOTE_LIMITS.metadataBytes. timeoutMs and maxRedirects are the house
 * values already used by npm-scanner.ts, pypi-scanner.ts and vscode-scanner.ts.
 */
export const FEED_REMOTE_LIMITS = Object.freeze({
  maxBytes: 32 * 1024 * 1024,
  timeoutMs: 30_000,
  maxRedirects: 5,
});

/** Per-call relaxation or tightening of FEED_REMOTE_LIMITS. */
export interface FeedLimitOverrides {
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
}

/**
 * Copy of the bundled (compiled-in) IOC feed, without any cached remote
 * entries merged. Used by "feed stats" to distinguish bundled vs effective
 * entry counts; scripts/generate-feed.mjs derives the publishable feed.json
 * from the same array (parsed out of this source file, single source of truth).
 *
 * Returns a FRESH ARRAY on every call, deliberately: callers of this accessor
 * are reporting and export paths that may sort, filter or append. If you only
 * READ the feed - in particular if you hand it to a matcher whose lookup index
 * is memoized on the array's identity - call getBundledFeedRef() instead, or
 * every call rebuilds that index from scratch. See issue 177:
 * https://github.com/homeofe/supply-chain-guard/issues/177
 */
export function getBundledFeed(): FeedIOC[] {
  return [...BUNDLED_FEED];
}

/**
 * The bundled (compiled-in) IOC feed as a SHARED, frozen array: one object
 * identity for the whole process, so an identity-keyed index built over it stays
 * valid. Read-only; use getBundledFeed() if you need an array you may modify.
 *
 * Why this accessor exists. The bare-npm lookup index in install-guard.ts is
 * memoized in a WeakMap keyed on the feed array's IDENTITY (see
 * bareNpmIndexCache). getBundledFeed() hands out a new array per call, so a
 * caller that used it as a scan-time feed source could never hit that cache and
 * rebuilt the whole 12,962-entry index instead. Measured on the npm scanner
 * path before this accessor existed: 2 rebuilds per scanNpmPackage() call, 6
 * across a three-package run in one process, where 1 is sufficient.
 *
 * ENFORCED ASSUMPTION, not a documented one: no caller mutates a bundled feed
 * array in place. Object.freeze makes push/sort/splice/pop throw in strict mode
 * (all compiled output here is strict) rather than silently invalidating every
 * index derived from this array. loadThreatIntel() and getBundledFeed() both
 * take a spread copy before doing anything, so neither is affected.
 *
 * RECORDED DECISION - the freeze is SHALLOW, entry objects are not frozen:
 *   - Cost measured on this feed at 12,962 entries: shallow 0.0014 ms, deep
 *     (freezing every entry) 1.32 ms, paid at first use by every process that
 *     loads this module, including paths that never touch this accessor.
 *   - Risk: entries are shared by reference into the arrays returned by
 *     getBundledFeed() and loadThreatIntel(), both of which this package
 *     exports. Deep-freezing them would turn any embedder that annotates or
 *     normalizes an entry in place from working code into a thrown TypeError,
 *     which is a breaking change for a published library and out of scope for a
 *     performance fix.
 *   - What is therefore NOT guaranteed: mutating ioc.value on an entry after an
 *     index has been built would desynchronize that index from the entries. No
 *     code in src/ does this (checked: no assignment to a feed entry field
 *     outside tests). If that ever changes, deep-freezing here is the fix, and
 *     the 1.32 ms is the price.
 */
export function getBundledFeedRef(): readonly FeedIOC[] {
  return BUNDLED_FEED_REF;
}

const BUNDLED_FEED_REF: readonly FeedIOC[] = Object.freeze(BUNDLED_FEED);

// ---------------------------------------------------------------------------
// Feed loading
// ---------------------------------------------------------------------------

/** Memoized result of loadThreatIntel, keyed on the cache file's identity. */
interface FeedCacheEntry {
  key: string;
  feed: FeedIOC[];
}
let memoizedFeed: FeedCacheEntry | null = null;

/** What the last loadThreatIntel() call found in the on-disk feed cache. */
export interface FeedCacheState {
  /** A readable cache file was present and parsed. */
  present: boolean;
  /** Entries merged from it, after validation. */
  entryCount: number;
  /** Age of the cached document, in ms. Undefined when absent or unparsable. */
  ageMs?: number;
  /** Age exceeds CACHE_TTL_MS: still used, but a refresh is due. */
  stale: boolean;
  /** A cache file existed but its contents could not be used completely. */
  unreadable: boolean;
  /** Timestamp recorded by a parseable cache document. */
  refreshedAt?: string;
}

let lastCacheState: FeedCacheState = { present: false, entryCount: 0, stale: false, unreadable: false };

let lastCatalog: CatalogState = { available: false, reason: "absent", entryCount: 0 };

/**
 * Checksum of a cached catalog's entries, over their canonical JSON.
 *
 * The value written into the cache is checked in two directions: against the
 * entries beside it to catch truncation or edits, and against entriesSha256 in
 * the generated package constant to preserve the verified download's trust
 * after the index and shards have been discarded. A writer can recompute the
 * cache field, but cannot make different entries match the package anchor.
 */
function catalogEntriesChecksum(entries: unknown): string {
  return createHash("sha256").update(JSON.stringify(entries), "utf8").digest("hex");
}

/**
 * State of the catalog cache as of the last loadThreatIntel() call.
 *
 * Separate accessor for the same reason as getFeedCacheState().
 */
export function lastCatalogState(): CatalogState {
  return { ...lastCatalog };
}

/**
 * State of the feed cache as of the last loadThreatIntel() call.
 *
 * Callers use this to tell a user that their refreshed intel is ageing. It is
 * deliberately a separate accessor rather than a field on the returned array,
 * because that array is shared and frozen-by-convention (see loadThreatIntel).
 */
export function getFeedCacheState(): FeedCacheState {
  return { ...lastCacheState };
}

/**
 * Drop the memoized feed (and, with it, the derived package index).
 *
 * Needed by any test that writes a feed cache file and then loads it: two
 * writes inside the same timer tick can share an mtime, and if they also share
 * a byte size the memo key would not change. Production code never refreshes
 * and loads in one process, so this exists for tests and for embedders that
 * manage the cache themselves.
 */
export function resetThreatIntelCache(): void {
  memoizedFeed = null;
}

/**
 * Load and merge IOC feeds. Starts with bundled feed, merges remote if available.
 *
 * MEMOIZED on the cache file's path, mtime, size and TTL window: a single
 * scan() calls this once per scanner family, and re-reading and re-parsing the
 * whole cache document each time is the dominant cost of a scan at a large
 * feed. Call resetThreatIntelCache() to force a re-read.
 *
 * The returned array is SHARED, not a copy - that is what lets the package
 * index stay valid across calls. Treat it as read-only; no caller mutates it.
 */
export function loadThreatIntel(
  cacheDir?: string,
  remoteFeedUrl?: string,
): FeedIOC[] {
  const cacheBase = resolveCacheDir(cacheDir);
  const cachePath = path.join(cacheBase, FEED_CACHE_FILE);

  // Identity of the inputs: which cache file, and what state is it in. stat()
  // is one syscall against a read+parse of the entire document.
  let stamp = "none";
  let stat: fs.Stats | undefined;
  let statFailed = false;
  try {
    stat = fs.statSync(cachePath);
    stamp = `${stat.mtimeMs}:${stat.size}`;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") statFailed = true;
  }
  if (statFailed) stamp = "unreadable";

  // The TTL is evaluated against wall-clock time, so a memo may not outlive the
  // window in which the cache is still considered fresh. Bucket by TTL period
  // so an expiring cache is re-evaluated rather than served stale.
  // The catalog cache is a second input to the same result, so it belongs in
  // the identity. Without it a catalog refresh is invisible until the FEED
  // cache happens to change, and the process keeps serving a feed built before
  // the catalog arrived.
  let catalogStamp = "none";
  try {
    const catalogStat = fs.statSync(path.join(cacheBase, CATALOG_CACHE_FILE));
    catalogStamp = `${catalogStat.mtimeMs}:${catalogStat.size}`;
  } catch { /* no catalog cache file: stamp stays "none" */ }

  const ttlBucket = Math.floor(Date.now() / CACHE_TTL_MS);
  // NUL-separated: no filesystem path can contain the separator, so two
  // different cache identities cannot collide into one key.
  const key = `${cachePath}\u0000${remoteFeedUrl ?? ""}\u0000${stamp}\u0000${catalogStamp}\u0000${ttlBucket}`;

  if (memoizedFeed && memoizedFeed.key === key) return memoizedFeed.feed;

  let feed = [...BUNDLED_FEED];
  let state: FeedCacheState = { present: false, entryCount: 0, stale: false, unreadable: statFailed };

  // Try to load cached remote feed. Age does NOT gate the merge: see
  // CACHE_TTL_MS. A stale cache is reported, never silently discarded.
  if (stat) {
    state.unreadable = true;
    try {
      const cached = JSON.parse(fs.readFileSync(cachePath, "utf-8")) as {
        timestamp: string;
        entries: FeedIOC[];
      };
      const parsedAt = new Date(cached.timestamp).getTime();
      const age = Number.isFinite(parsedAt) ? Date.now() - parsedAt : undefined;
      if (Array.isArray(cached.entries)) {
        // Quarantine invalid entries instead of trusting the cast: cached
        // remote data reaches the per-file scan loop, so a malformed entry
        // must never leave this function (issue #54).
        const remoteEntries = cached.entries
          .filter(isValidFeedIOC)
          .map(normalizeFeedIOC);
        feed = mergeFeeds(feed, remoteEntries);
        state = {
          present: true,
          entryCount: remoteEntries.length,
          ageMs: age,
          stale: age === undefined || age >= CACHE_TTL_MS,
          unreadable: age === undefined || remoteEntries.length !== cached.entries.length,
          ...(age === undefined ? {} : { refreshedAt: cached.timestamp }),
        };
      }
    } catch { /* unreadable remains true; scanner reports partial coverage */ }
  }

  lastCacheState = state;

  // The catalog: historical bulk that left the compiled bundle. Merged AFTER
  // the feed, so mergeFeeds' first-wins rule keeps the bundle and the fresher
  // feed authoritative for any indicator all three carry.
  let catalog: CatalogState = { available: false, reason: "absent", entryCount: 0 };
  const catalogPath = path.join(cacheBase, CATALOG_CACHE_FILE);
  if (catalogStamp !== "none") {
    try {
      const cached = JSON.parse(fs.readFileSync(catalogPath, "utf-8")) as {
        version?: string;
        sha256?: string;
        checksum?: string;
        entries?: FeedIOC[];
      };
      const entriesChecksum = Array.isArray(cached.entries)
        ? catalogEntriesChecksum(cached.entries)
        : undefined;
      if (!Array.isArray(cached.entries)) {
        catalog = { available: false, reason: "unreadable", entryCount: 0 };
      } else if (cached.version !== CATALOG_DIGEST.version) {
        // Built for another release. The catalog is pinned per release, so a
        // mismatch means these entries were selected against a different
        // bundle and the partition between the two is no longer known.
        catalog = {
          available: false,
          reason: "version-mismatch",
          entryCount: 0,
          cachedVersion: cached.version,
        };
      } else if (cached.sha256 !== CATALOG_DIGEST.sha256) {
        catalog = {
          available: false,
          reason: "digest-mismatch",
          entryCount: 0,
          cachedVersion: cached.version,
        };
      } else if (cached.checksum !== entriesChecksum) {
        // REQUIRED, not optional. An earlier version only compared the checksum
        // when the field was present, which made the check trivially avoidable:
        // deleting one line from the cache file skipped verification entirely
        // and the entries merged unread. There are no caches in the wild
        // without it, because this has never shipped, so there is nothing to be
        // tolerant of. A missing checksum is a cache this code did not write.
        // The entries do not match the checksum written beside them. A
        // truncated or edited cache is refused rather than merged: merging a
        // short cache would silently remove indicators, which is the failure
        // mode this whole phase exists to avoid.
        catalog = {
          available: false,
          reason: "corrupt",
          entryCount: 0,
          cachedVersion: cached.version,
        };
      } else if (entriesChecksum !== CATALOG_DIGEST.entriesSha256) {
        // The cache field is self-computed, so matching it only proves that the
        // file is internally consistent. This comparison binds the payload to
        // the exact canonical entries array compiled into the npm package.
        catalog = {
          available: false,
          reason: "digest-mismatch",
          entryCount: 0,
          cachedVersion: cached.version,
        };
      } else {
        // Same quarantine as the feed cache: cached remote data reaches the
        // per-file scan loop, so a malformed entry must never leave here.
        const catalogEntries = cached.entries.filter(isValidFeedIOC).map(normalizeFeedIOC);
        // Keep the count check as a structural assertion after validation. The
        // entries digest above authenticates the raw array; this catches a
        // generated catalog whose entries do not survive the FeedIOC contract.
        const pinned: number = CATALOG_DIGEST.entryCount;
        if (pinned !== 0 && catalogEntries.length !== pinned) {
          catalog = {
            available: false,
            reason: "digest-mismatch",
            entryCount: 0,
            cachedVersion: cached.version,
          };
        } else {
          feed = mergeFeeds(feed, catalogEntries);
          catalog = {
            available: true,
            entryCount: catalogEntries.length,
            cachedVersion: cached.version,
          };
        }
      }
    } catch {
      catalog = { available: false, reason: "unreadable", entryCount: 0 };
    }
  }

  lastCatalog = catalog;

  memoizedFeed = { key, feed };
  return feed;
}

/**
 * Read a fetch Response body under a byte cap, refusing before the chunk that
 * would cross it is buffered.
 *
 * Content-Length is checked first so a declared oversize body is refused before
 * a single byte of it is read, but it is never trusted on its own: it is absent
 * on a chunked response and it describes the COMPRESSED size when the peer sends
 * gzip, which fetch then inflates. The running counter is what actually holds.
 */
async function readBoundedBody(
  response: Response,
  feedUrl: string,
  maxBytes: number,
): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null && /^\d+$/.test(declared) && BigInt(declared) > BigInt(maxBytes)) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(
      `feed declares ${declared} bytes, over the ${maxBytes}-byte limit, for ${feedUrl}`,
    );
  }

  const stream = response.body;
  if (stream === null) throw new Error(`feed response carried no body for ${feedUrl}`);

  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      if (bytes + value.byteLength > maxBytes) {
        throw new Error(`feed body exceeded the ${maxBytes}-byte limit for ${feedUrl}`);
      }
      bytes += value.byteLength;
      chunks.push(value);
    }
  } catch (err) {
    // Tear the socket down rather than leaving an oversized or stalled transfer
    // draining in the background.
    await reader.cancel().catch(() => undefined);
    throw err;
  }

  // Decode ONCE over the whole buffer. Decoding per chunk turns a multi-byte
  // UTF-8 sequence split across a chunk boundary into replacement characters.
  return Buffer.concat(chunks, bytes).toString("utf-8");
}

/**
 * Update remote threat feed and cache locally.
 *
 * Bounded by FEED_REMOTE_LIMITS: an absolute deadline covering the whole
 * request including the body read, and a byte cap applied before the document
 * is parsed. Both fail closed - the download is abandoned and the previous
 * cache, or the bundled feed, stays in effect.
 *
 * `limitOverrides` relaxes or tightens a single dimension per call and leaves
 * the rest at the package defaults.
 */
export async function updateThreatFeed(
  feedUrl: string,
  cacheDir?: string,
  limitOverrides: FeedLimitOverrides = {},
): Promise<{ added: number; total: number }> {
  const cacheBase = resolveCacheDir(cacheDir);
  const { maxBytes, timeoutMs } = { ...FEED_REMOTE_LIMITS, ...limitOverrides };
  // One signal for the whole call. `fetch` alone imposes a headers timeout and
  // (through undici) a body INACTIVITY backstop; neither ever fires on a peer
  // that keeps sending slowly, which is the case this deadline covers.
  const signal = AbortSignal.timeout(timeoutMs);

  try {
    const response = await fetch(feedUrl, { signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const raw = JSON.parse(await readBoundedBody(response, feedUrl, maxBytes)) as unknown;
    if (!Array.isArray(raw)) throw new Error("Invalid feed format");
    // Validate BEFORE caching: entries failing the indicator contract
    // (unknown type, non-string/empty/oversized value) are quarantined so
    // they can never reach a scan via the cache (issue #54).
    const entries = raw.filter(isValidFeedIOC).map(normalizeFeedIOC);

    fs.mkdirSync(cacheBase, { recursive: true });
    fs.writeFileSync(
      path.join(cacheBase, FEED_CACHE_FILE),
      JSON.stringify({ timestamp: new Date().toISOString(), entries }, null, 2),
    );

    return { added: entries.length, total: BUNDLED_FEED.length + entries.length };
  } catch (err) {
    // Ask the signal, not the error. fetch and the body stream report an abort
    // with different names and wordings across runtimes; the signal is the one
    // witness that says whether OUR deadline is what fired.
    const message = signal.aborted
      ? `HTTPS request timed out after ${timeoutMs}ms for ${feedUrl}`
      : err instanceof Error
        ? err.message
        : String(err);
    throw new Error(`Failed to update threat feed: ${message}`);
  }
}

// Keys permitted in a published/cached feed document and in its IOC entries.
// Anything outside these sets means the file is NOT our inert data format and
// must be scanned normally - an attacker cannot smuggle code past the check by
// naming a file feed.json, because any extra key or non-scalar value fails it.
const FEED_DOC_KEYS = new Set(["schema", "kind", "package", "version", "entryCount", "entries", "timestamp", "generatedAt"]);
// Mirrors the FeedIOC interface exactly. It MUST list every field the feed can
// carry: "source" and "lastSeen" are part of FeedIOC, and entries imported from
// upstream advisory databases populate "source" with their provenance (see
// scripts/import-threat-feed.mjs). Leaving a real field out here would make the
// project's own feed.json fail this check and get scanned as ordinary content -
// the v5.4.0 phantom-findings bug.
//
// "note" and "ecosystem" were here as legacy tolerances and were REMOVED, for
// the same reason the list exists: a key that cannot be carried has no business
// widening the exemption. Neither is a field of FeedIOC, so isValidFeedIOC never
// examined them and they were accepted at any length with any control
// character, which is what let a feed-SHAPED file carry arbitrary text through
// this exemption and skip every content scanner.
//
// Measured before removing them, both directions:
//   - no released feed.json carries either key, checked across v5.10.0, v5.20.0,
//     v5.28.0, v6.0.0 and v6.1.3, and 0 of the current 20,969 entries use them;
//   - a cache file cannot carry them either, because refreshFeed() writes what
//     parseFeedPayload() returns, and that is normalizeFeedIOC() output, which
//     rebuilds each entry from FeedIOC fields alone.
// So no document this check is meant to accept can contain them.
const FEED_ENTRY_KEYS = new Set([
  "type", "value", "severity", "confidence", "family", "campaign", "source",
  "firstSeen", "lastSeen",
]);

/**
 * Structural check: is this file supply-chain-guard's own threat-feed data
 * (the published feed.json or the .scg-cache/threat-feed.json cache)?
 *
 * The feed intentionally contains RAW IOC values (domains, IPs, package
 * names) as machine-readable detection data - the same reason the scanner's
 * own source files are IOC-excluded. Without this check, any repo that
 * commits the published feed (or the refresh cache) drowns in phantom
 * criticals from its own protection data (v5.4.0 dogfooding find: 169
 * findings on this repo's feed.json).
 *
 * Strictness is the security property: valid JSON, top-level keys and every
 * entry key from a fixed allowlist, entries hold only inert scalars. Any
 * deviation -> file is scanned like everything else.
 */
export function isInertThreatFeedFile(filename: string, content: string): boolean {
  const base = filename.replace(/\\/g, "/").split("/").pop() ?? "";
  if (base !== "feed.json" && base !== FEED_CACHE_FILE) return false;
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch {
    return false;
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return false;
  const obj = doc as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!FEED_DOC_KEYS.has(key)) return false;
  }
  if (obj.package !== undefined && obj.package !== "supply-chain-guard") return false;
  if (!Array.isArray(obj.entries)) return false;
  for (const entry of obj.entries) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return false;
    for (const [k, v] of Object.entries(entry as Record<string, unknown>)) {
      if (!FEED_ENTRY_KEYS.has(k)) return false;
      if (typeof v !== "string" && typeof v !== "number") return false;
    }
    // The full runtime contract. Key-and-scalar checking alone accepts
    // objects the loader itself would quarantine, so without this the
    // exemption could be claimed by a document that is merely feed-SHAPED
    // rather than an actual feed.
    if (!isValidFeedIOC(entry)) return false;
  }
  return true;
}

/** Basename of the committed catalog store. */
export const CATALOG_FILE = "threat-catalog.jsonl";

/**
 * Exact repository-relative path of the catalog store. The exemption is bound
 * to this path, not merely to the basename: a basename match would let ANY
 * scanned repository place a file with this name at any depth and have it
 * skipped, which is an evasion primitive rather than a convenience.
 */
export const CATALOG_RELATIVE_PATH = "data/threat-catalog.jsonl";

/**
 * Structural check: is this file supply-chain-guard's own catalog store?
 *
 * Same reasoning as isInertThreatFeedFile above, for the JSONL catalog: it
 * holds RAW IOC values as machine-readable detection data, collectFiles() does
 * not exclude data/, and without this check the project's own self-scan drowns
 * in phantom criticals from its own protection data - the v5.4.0 dogfooding
 * bug in a new file shape.
 *
 * Shares FEED_ENTRY_KEYS with the feed check so the two cannot drift apart.
 * Strictness is the security property: every non-empty line must be a JSON
 * object whose every key is allowlisted and whose every value is an inert
 * scalar. Any deviation -> the file is scanned like everything else.
 */
export function isInertThreatCatalogFile(filename: string, content: string): boolean {
  // Exact relative path, not a basename. Without this, any scanned repository
  // could place a file with this name at any depth and have every content
  // scanner skip it.
  if (filename.replace(/\\/g, "/") !== CATALOG_RELATIVE_PATH) return false;

  for (const line of content.split("\n")) {
    if (line.trim() === "") continue;
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      return false;
    }
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return false;

    // Every key allowlisted and every value an inert scalar, as for the feed.
    for (const [k, v] of Object.entries(entry as Record<string, unknown>)) {
      if (!FEED_ENTRY_KEYS.has(k)) return false;
      if (typeof v !== "string" && typeof v !== "number") return false;
    }

    // `note` needs no special case here: it is no longer in FEED_ENTRY_KEYS,
    // so the loop above already rejects it. See the note on that constant.

    // A complete, real FeedIOC. Key-and-scalar checking alone accepts objects
    // that the loader would quarantine, so requiring the full contract is what
    // makes "this is our own inert detection data" an actual claim.
    if (!isValidFeedIOC(entry)) return false;
  }
  return true;
}

/**
 * Check content against the threat intelligence feed.
 */
// v5.2.21: documentation files (.md/.markdown/.txt/.rst) legitimately discuss
// threat-intel IOCs - changelog entries, blog posts, security research.
// Matching threat-intel hashes/domains in docs creates noise without security
// value. Same rationale as patterns.ts BENIGN_DOC_FILES and ioc-blocklist.ts.
const BENIGN_DOC_FILES = /\.(md|markdown|txt|rst)$/i;

// ---------------------------------------------------------------------------
// Indicator contract + hardening (v5.12.0, issue #54)
//
// FeedIOC.value is a LITERAL indicator (a domain, IP, URL, hash, or package
// name), never a regular expression. Before v5.12.0 domain values were
// compiled to RegExp with only dots escaped, so a hostile or malformed remote
// feed value like "(" threw SyntaxError inside the per-file scan loop - the
// per-file catch in scanner.ts swallowed it, silently disabling every check
// that runs after checkThreatIntel for EVERY file while the scan exited
// green. A syntactically valid pattern like "(a+)+b" would instead have been
// .test()-ed against full file contents (ReDoS). Escaping every metacharacter
// makes the compiled regex exactly the literal indicator, closing both paths.
// ---------------------------------------------------------------------------

/** Escape every regex metacharacter so `value` matches only itself. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// An indicator value has no business being longer than this (the longest
// legitimate values are URLs; hashes are 64 chars, domains max 253). Entries
// above the cap are quarantined on load, not compiled or compared.
const MAX_IOC_VALUE_LENGTH = 2048;
const MAX_IOC_METADATA_LENGTH = 512;
const DEFAULT_IOC_CONFIDENCE = 0.95;
const IOC_METADATA_FIELDS = ["family", "campaign", "source"] as const;
const IOC_DATE_FIELDS = ["firstSeen", "lastSeen"] as const;
const IOC_DATE_SHAPE =
  /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2})))?$/;
const IOC_METADATA_CONTROL_CHARS = /[\u0000-\u001f\u007f]/u;

function isValidIocDate(value: string): boolean {
  const match = value.match(IOC_DATE_SHAPE);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(0);
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCFullYear(year, month - 1, day);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return false;
  }
  if (match[4] !== undefined) {
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);
    const offsetHour = Number(match[7] ?? 0);
    const offsetMinute = Number(match[8] ?? 0);
    if (
      hour > 23 ||
      minute > 59 ||
      second > 59 ||
      offsetHour > 23 ||
      offsetMinute > 59
    ) {
      return false;
    }
  }
  return Number.isFinite(Date.parse(value));
}

// Type-aware value shapes: a structurally "valid string" is not enough - a
// domain entry of "(" would (post-escaping) literal-match every file that
// contains a parenthesis, turning a hostile feed into a false-positive
// generator instead of a crash. Each indicator type has a narrow charset.
const IOC_VALUE_SHAPES: Record<string, RegExp> = {
  // RFC-ish hostname: 1..63-character labels joined by dots, a DNS-sized
  // overall value, and a plausible final label (2..63 letters or punycode).
  // The final-label floor rejects tiny code-shaped values such as "e.g",
  // which would otherwise match ordinary property access throughout a repo.
  domain: /^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i,
  // Structural IPv4 (four dotted decimal groups) or IPv6 (>=2 colons, >=1 hex
  // digit, >=7 chars). Charset alone is NOT enough: non-domain values are
  // substring-matched, so a degenerate "." or "e" that passed a charset-only
  // gate would flood every scanned file with critical matches (v5.12.0 gate
  // finding). The IPv6 floor also rejects "::" and "a::", which would
  // substring-match every file using a C++/Rust scope operator; realistic
  // IPv6 blocklist entries ("fe80::1", "2001:db8::1") are 7+ chars. Octet
  // ranges are deliberately not enforced - not security relevant here.
  ip: /^(\d{1,3}(\.\d{1,3}){3}|(?=(?:[^:]*:){2})(?=[^a-f0-9]*[a-f0-9])[0-9a-f:.]{7,})$/i,
  // URL-ish indicator. A charset + length floor is NOT enough: "require(",
  // "process.env" and "module.exports" all pass /^[\x21-\x7e]{8,}$/, and every
  // type:"url" entry is substring-matched against whole file contents at the
  // entry's own severity (see the non-package branch of checkThreatIntel), so
  // one typo - or one hostile remote feed entry - would flag an entire
  // repository as critical. The floor is therefore structural, in three
  // branches:
  //   1. 0x + 40..64 hex: EVM wallet / contract addresses (four ship in the
  //      bundled feed; the Tron and Aptos addresses live in ioc-blocklist.ts
  //      KNOWN_C2_WALLETS instead).
  //   2. scheme:// or protocol-relative // + host, with optional userinfo,
  //      port, path, query or fragment.
  //   3. a bare host that carries a port OR a path/query/fragment.
  // Requiring MORE THAN A BARE HOST is the whole trick: a bare dotted host is
  // structurally identical to a dotted code identifier ("process.env",
  // "Object.keys", "README.md"), so no host-only rule can separate them. A bare
  // host belongs in type:"domain".
  // Non-EVM wallets (Tron "T...", bech32 "bc1q...") are deliberately NOT
  // accepted here: they are opaque base58/bech32 blobs with no structure to
  // floor, and they belong in KNOWN_C2_WALLETS.
  // VERSION-SKEW INVARIANT: this shape may only ever be LOOSENED in a release
  // that does not itself add an entry relying on the looser shape. parseFeedPayload
  // rejects the ENTIRE document on one invalid entry, so shipping both at once
  // makes every client on an older version discard the whole feed on refresh.
  url: /^(?=[\x21-\x7e]{8,}$)(?:0x[0-9a-f]{40,64}|(?:[a-z][a-z0-9+.-]*:)?\/\/(?:[a-z0-9._~%!$&'()*+,;=:-]{1,64}@)?(?:(?:[a-z0-9_-]+\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?:[/?#][\x21-\x7e]*)?|(?:[a-z0-9._~%!$&'()*+,;=:-]{1,64}@)?(?:(?:[a-z0-9_-]+\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5}(?:[/?#][\x21-\x7e]*)?|[/?#][\x21-\x7e]*))$/i,
  // MD5 / SHA-1 / SHA-256 / SHA-512 hex digest.
  hash: /^[0-9a-f]{32,128}$/i,
  // Package coordinates incl. ecosystem prefixes (ruby:, go:github.com/x/y),
  // scopes (@scope/name) and version pins (name@1.2.3): printable, no spaces.
  // Loose is safe here: packages are matched by exact compare, never substring.
  package: /^[\x21-\x7e]+$/,
};

// Severity must be one of the report's known levels: an unknown string would
// flow raw into Finding.severity and break SEVERITY_SCORES lookups (NaN
// score) and summary counting downstream.
const VALID_IOC_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

/**
 * Validity gate for a single feed entry. Remote/cached entries are
 * JSON.parse results cast to FeedIOC without any runtime check, so every
 * consumer-facing load path filters through this. Invalid entries are
 * quarantined (dropped) deterministically instead of crashing a scan or
 * flooding it with garbage-literal matches.
 */
export function isValidFeedIOC(entry: unknown): entry is FeedIOCInput {
  if (entry === null || typeof entry !== "object") return false;
  const e = entry as Partial<FeedIOC>;
  if (
    typeof e.type !== "string" ||
    typeof e.value !== "string" ||
    e.value.length === 0 ||
    e.value.length > MAX_IOC_VALUE_LENGTH ||
    typeof e.severity !== "string" ||
    !VALID_IOC_SEVERITIES.has(e.severity)
  ) {
    return false;
  }
  // confidence is optional in remote feeds; when present it must be a sane number.
  if (e.confidence !== undefined && (typeof e.confidence !== "number" || !(e.confidence >= 0 && e.confidence <= 1))) {
    return false;
  }
  for (const field of IOC_METADATA_FIELDS) {
    const value = e[field];
    if (
      value !== undefined &&
      (typeof value !== "string" ||
        value.length === 0 ||
        value.length > MAX_IOC_METADATA_LENGTH ||
        IOC_METADATA_CONTROL_CHARS.test(value))
    ) {
      return false;
    }
  }
  for (const field of IOC_DATE_FIELDS) {
    const value = e[field];
    if (
      value !== undefined &&
      (typeof value !== "string" ||
        !isValidIocDate(value))
    ) {
      return false;
    }
  }
  if (
    e.firstSeen !== undefined &&
    e.lastSeen !== undefined &&
    Date.parse(e.lastSeen) < Date.parse(e.firstSeen)
  ) {
    return false;
  }
  const shape = IOC_VALUE_SHAPES[e.type];
  return shape !== undefined && shape.test(e.value);
}

/** Convert a runtime-valid remote entry into the internal total FeedIOC shape. */
export function normalizeFeedIOC(entry: FeedIOCInput): FeedIOC {
  const normalized: FeedIOC = {
    type: entry.type,
    value: entry.value,
    severity: entry.severity,
    confidence: entry.confidence ?? DEFAULT_IOC_CONFIDENCE,
  };
  if (entry.family !== undefined) normalized.family = entry.family;
  if (entry.campaign !== undefined) normalized.campaign = entry.campaign;
  if (entry.source !== undefined) normalized.source = entry.source;
  if (entry.firstSeen !== undefined) normalized.firstSeen = entry.firstSeen;
  if (entry.lastSeen !== undefined) normalized.lastSeen = entry.lastSeen;
  return normalized;
}

// Domain regexes are compiled once per unique value, not per scanned file
// (checkThreatIntel runs for every file with the same feed array). A null
// entry records a value whose compilation failed (unreachable after full
// escaping, kept as belt and braces) and fails closed rather than falling back
// to unsafe substring matching.
const domainRegexCache = new Map<string, RegExp | null>();

export function checkThreatIntel(
  content: string,
  relativePath: string,
  feed: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  // Skip documentation files - threat-intel matches there are discussion, not exploitation.
  if (BENIGN_DOC_FILES.test(relativePath)) return findings;
  const contentLower = content.toLowerCase();

  for (const ioc of feed) {
    if (ioc.type === "package") continue; // Packages checked separately

    const valueLower = ioc.value.toLowerCase();
    let matched: boolean;
    if (ioc.type === "domain") {
      let regex = domainRegexCache.get(ioc.value);
      if (regex === undefined) {
        // Bound the cache: a long-running process (MCP server) reloads the
        // feed per scan, and a rotating hostile feed of ever-new values must
        // not grow process memory monotonically (v5.12.0 gate finding).
        if (domainRegexCache.size >= 10_000) domainRegexCache.clear();
        try {
          // A domain IOC matches the exact hostname and its subdomains, but not
          // a longer label ("notexample.com") or a parent-domain lookalike
          // ("example.com.attacker.test"). The leading boundary deliberately
          // permits a dot so "api.example.com" still matches "example.com".
          regex = new RegExp(
            `(?:^|[^a-z0-9_-])${escapeRegExp(ioc.value)}(?![a-z0-9_-]|\\.[a-z0-9_-])`,
            "i",
          );
        } catch {
          // Cannot throw after full escaping; belt and braces so a future
          // edit can never re-introduce the scan-degrading SyntaxError.
          regex = null;
        }
        domainRegexCache.set(ioc.value, regex);
      }
      matched = regex ? regex.test(content) : false;
    } else {
      matched = contentLower.includes(valueLower);
    }

    if (matched) {
      // Apply confidence decay (reduce by 10% per 90 days since firstSeen)
      let confidence = ioc.confidence;
      if (ioc.firstSeen) {
        const ageDays = Math.max(
          0,
          (Date.now() - new Date(ioc.firstSeen).getTime()) /
            (1000 * 60 * 60 * 24),
        );
        const decayFactor = Math.max(0.3, Math.min(1, 1 - (ageDays / 900)));
        confidence = Math.round(confidence * decayFactor * 100) / 100;
      }

      findings.push({
        rule: "THREAT_INTEL_MATCH",
        description: `Threat intelligence match: ${ioc.type} "${ioc.value}"${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
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

// ---------------------------------------------------------------------------
// Ecosystem package IOC matching
// ---------------------------------------------------------------------------

/**
 * Match a package name (and optional exact version) against type:"package"
 * feed entries carrying an ecosystem prefix ("ruby:", "composer:", "nuget:",
 * "go:"). checkThreatIntel() deliberately skips package entries (they would
 * false-positive on file content); ecosystem scanners resolve them here
 * against parsed manifest/lockfile package lists instead.
 *
 * IOC values come in two shapes:
 *   - bare name    ("ruby:knot-date-utils-rb") - matches every version
 *   - name@version ("nuget:Sicoob.Sdk@2.0.0")  - matches only that version
 *
 * Package-name equivalence is ecosystem-specific. NuGet package ids are
 * case-insensitive. PyPI applies PEP 503 normalization: ASCII case is folded
 * and each run of hyphens, underscores, or dots is equivalent. Other
 * registries retain exact name matching here.
 */
export function matchPackageIOC(
  ecosystem: string,
  name: string,
  version?: string,
  feed?: FeedIOC[],
): FeedIOC | null {
  const entries = feed ?? loadThreatIntel();
  const eco = ecosystem.toLowerCase();

  // An ecosystem containing ":" would make the prefix split ambiguous (the
  // index keys on the segment before the FIRST colon). No real ecosystem does,
  // but fall back to the reference scan rather than risk a false negative.
  if (eco.includes(":")) return matchPackageIOCLinear(entries, eco, name, version);

  const wantName = normalizePackageIOCName(eco, name);

  const candidates = getPackageIndex(entries).get(`${eco}:${wantName}`);
  if (!candidates) return null;

  // Candidates are held in original feed order, so "first match wins" is
  // preserved exactly: a bare-name entry hits any version, a versioned entry
  // only its own, and whichever appears first in the feed is returned.
  for (const { ioc, version: iocVersion } of candidates) {
    if (iocVersion === undefined) return ioc; // bare-name IOC: any version
    if (version !== undefined && iocVersion === version) return ioc;
  }

  return null;
}

/**
 * Reference implementation of the package-matching semantics.
 *
 * Retained deliberately: it is the fallback for exotic ecosystem strings, and
 * the parity test asserts the index agrees with it across the whole bundled
 * feed. If the two ever disagree, this one is right by definition.
 */
function matchPackageIOCLinear(
  entries: FeedIOC[],
  eco: string,
  name: string,
  version?: string,
): FeedIOC | null {
  const prefix = `${eco}:`;
  const wantName = normalizePackageIOCName(eco, name);

  for (const ioc of entries) {
    if (ioc.type !== "package") continue;
    if (!ioc.value.toLowerCase().startsWith(prefix)) continue;

    const rest = ioc.value.substring(prefix.length);
    const { name: iocName, version: iocVersion } = splitPackageIOCValue(eco, rest);

    const nameMatches = normalizePackageIOCName(eco, iocName) === wantName;
    if (!nameMatches) continue;

    if (iocVersion === undefined) return ioc;
    if (version !== undefined && iocVersion === version) return ioc;
  }

  return null;
}

/** One indexed candidate: the entry plus its parsed version (undefined = bare). */
interface IndexedIOC {
  ioc: FeedIOC;
  version: string | undefined;
}

/**
 * Lazily-built lookup index over a feed array, keyed by "ecosystem:name".
 *
 * matchPackageIOC used to be a full linear scan of the feed for EVERY package
 * in the dependency tree, allocating a lowercased copy of every entry value on
 * every call: O(deps * feed) with a large constant. That put a ceiling on how
 * far the bundled feed could grow, which in turn capped how many advisories the
 * daily import could take in.
 *
 * Keyed on the feed array identity via a WeakMap, so a caller-supplied feed and
 * the memoized shared feed each get their own index and neither leaks.
 */
const packageIndexCache = new WeakMap<FeedIOC[], Map<string, IndexedIOC[]>>();

/**
 * Ecosystems whose registry treats package identities case-insensitively, so
 * a feed entry and a manifest may spell the same package differently. Every
 * other ecosystem compares exactly: CRAN, Firefox add-on ids and JetBrains
 * plugin ids are case-sensitive, and npm names are too.
 */
export const CASE_INSENSITIVE_PACKAGE_ECOSYSTEMS: ReadonlySet<string> = new Set([
  "nuget",
  "terraform", "tfmodule", // registry addresses (terraform-scanner.ts)
  "vscode", "openvsx", // extension ids (extension-identity.ts)
  "actions", // GitHub owner/repo (github-actions-scanner.ts)
  "docker", // lowercase by the distribution spec (container-image.ts)
  "swift", // repository URLs (ecosystem-registry.ts)
  "cocoapods", "hex", "conan", "helm", "ansible", "homebrew",
  "chrome", "edge", // Chromium extension ids are a-p, lowercase
]);

/**
 * Split the part of a prefixed feed value after "<eco>:" into name and version,
 * at the last "@". The one exception is Firefox: its add-on ids are either a
 * {GUID} or email-shaped ("name@domain"), so the tail after the last "@" is a
 * version only when it looks like one. Splitting blindly read
 * "bliss-heaven@webbrol.com" as name "bliss-heaven", version "webbrol.com", and
 * 28 of the 40 bundled Firefox indicators could never match.
 */
export function splitPackageIOCValue(
  ecosystem: string,
  rest: string,
): { name: string; version: string | undefined } {
  const at = rest.lastIndexOf("@");
  if (at <= 0) return { name: rest, version: undefined };
  const tail = rest.substring(at + 1);
  if (ecosystem === "firefox" && !/^\d[\w.+-]*$/.test(tail)) return { name: rest, version: undefined };
  return { name: rest.substring(0, at), version: tail };
}

function normalizePackageIOCName(ecosystem: string, name: string): string {
  if (ecosystem === "pypi") return name.toLowerCase().replace(/[-_.]+/g, "-");
  if (CASE_INSENSITIVE_PACKAGE_ECOSYSTEMS.has(ecosystem)) return name.toLowerCase();
  return name;
}

function getPackageIndex(entries: FeedIOC[]): Map<string, IndexedIOC[]> {
  const cached = packageIndexCache.get(entries);
  if (cached) return cached;

  const index = new Map<string, IndexedIOC[]>();
  for (const ioc of entries) {
    if (ioc.type !== "package") continue;

    // Ecosystem is the segment before the first ":". Entries without a colon
    // (bare npm names) are unreachable through matchPackageIOC by design, since
    // every lookup prefix ends in one; they are matched by matchBareNpmIOC.
    const colon = ioc.value.indexOf(":");
    if (colon <= 0) continue;
    const entryEco = ioc.value.substring(0, colon).toLowerCase();

    const rest = ioc.value.substring(colon + 1);
    // Split "name@version" (see splitPackageIOCValue). Ecosystem-prefixed names
    // never start with "@" (npm scopes stay unprefixed), so index 0 means bare name.
    const { name: iocName, version: iocVersion } = splitPackageIOCValue(entryEco, rest);

    const keyName = normalizePackageIOCName(entryEco, iocName);
    const key = `${entryEco}:${keyName}`;

    const bucket = index.get(key);
    if (bucket) bucket.push({ ioc, version: iocVersion });
    else index.set(key, [{ ioc, version: iocVersion }]);
  }

  packageIndexCache.set(entries, index);
  return index;
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

/**
 * Get provenance metadata for the active detection set / threat intelligence feed (v5.29, issue #208).
 *
 * `catalogState` is the snapshot the scanner took beside its own load. Pass it
 * whenever one exists: nested scanners may load from another directory, and the
 * provenance must describe the load that produced this scan's findings.
 */
export function getDetectionSetProvenance(
  cacheDir?: string,
  catalogState?: CatalogState,
): DetectionSetProvenance {
  const cacheBase = resolveCacheDir(cacheDir);
  const cachePath = path.join(cacheBase, FEED_CACHE_FILE);

  // Ask the loader for the effective set rather than re-deriving it here.
  // This used to count the bundle alone unless a FRESH feed cache existed, so
  // once the catalog began carrying the historical corpus a merged catalog was
  // reported as no coverage at all: with a stale or absent feed cache the count
  // would read 8,971 while the process was actually matching against 20,969.
  // loadThreatIntel is memoized on the same inputs, so this is a map lookup on
  // the common path rather than a second read.
  const effectiveEntryCount = loadThreatIntel(cacheDir).length;
  // Without a snapshot, the state is the one this load just produced. The memo
  // holds a single entry, so a memo hit is always the load that set it.
  const catalog = catalogState ?? lastCatalogState();
  const catalogEntryCount: number = CATALOG_DIGEST.entryCount;

  const cache = getFeedCacheState();
  const cacheMerged = cache.present;

  return {
    bundledVersion: "6.4.3",
    bundledEntryCount: BUNDLED_FEED.length,
    generatedAt: FEED_GENERATED_AT,
    cacheMerged,
    effectiveEntryCount,
    ...(cacheMerged ? { cachePath: displayCachePath(cachePath), cacheRefreshedAt: cache.refreshedAt } : {}),
    catalog: {
      consulted: catalog.available,
      entryCount: catalogEntryCount,
      ...(catalog.available ? {} : { reason: catalog.reason ?? "absent" }),
    },
  };
}
