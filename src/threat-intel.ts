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
  { type: "package", value: "guardrails-ai@0.10.1", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },
  { type: "package", value: "mistralai@2.4.6", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud TanStack", firstSeen: "2026-05-12" },

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
  { type: "package", value: "composer:laravel-lang/lang", severity: "critical", confidence: 1.0, family: "DebugElevator", campaign: "Laravel-Lang DebugElevator", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:laravel-lang/http-statuses", severity: "critical", confidence: 1.0, family: "DebugElevator", campaign: "Laravel-Lang DebugElevator", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:laravel-lang/attributes", severity: "critical", confidence: 1.0, family: "DebugElevator", campaign: "Laravel-Lang DebugElevator", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:laravel-lang/actions", severity: "critical", confidence: 1.0, family: "DebugElevator", campaign: "Laravel-Lang DebugElevator", firstSeen: "2026-05-23" },

  // Packagist 8-package GitHub-hosted Linux binary attack (May 23, 2026)
  // Coordinated supply-chain hit against 8 Composer packages on Packagist whose dev
  // branches had package.json postinstall hooks added to download a Linux ELF
  // (gvfsd-network) from github.com/parikhpreyash4/systemd-network-helper-aa5c751f and
  // execute it from /tmp/.sshd. Attacker GitHub account removed after disclosure.
  // Attack mixed JS toolchain hooks into PHP projects to bypass Composer-side review.
  { type: "package", value: "composer:moritz-sauer-13/silverstripe-cms-theme", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:crosiersource/crosierlib-base", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:devdojo/wave", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:devdojo/genesis", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:katanaui/katana", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:elitedevsquad/sidecar-laravel", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:r2luna/brain", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },
  { type: "package", value: "composer:baskarcm/tzi-chat-ui", severity: "critical", confidence: 1.0, family: "PHPBinaryDropper", campaign: "Packagist parikhpreyash4 Binary Attack", firstSeen: "2026-05-23" },

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
  { type: "package", value: "durabletask@1.4.1", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", firstSeen: "2026-05-24" },
  { type: "package", value: "durabletask@1.4.2", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", firstSeen: "2026-05-24" },
  { type: "package", value: "durabletask@1.4.3", severity: "critical", confidence: 1.0, family: "ShaiHuludWorm", campaign: "Mini Shai-Hulud durabletask", firstSeen: "2026-05-24" },

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
  { type: "package", value: "litellm@1.82.7", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "LiteLLM PyPI Compromise", firstSeen: "2026-03-24" },
  { type: "package", value: "litellm@1.82.8", severity: "critical", confidence: 1.0, family: "TeamPCPBackdoor", campaign: "LiteLLM PyPI Compromise", firstSeen: "2026-03-24" },

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
  { type: "package", value: "parsimonius", severity: "critical", confidence: 0.9, family: "TelegramBackdoor", campaign: "THN Weekly Recap npm/PyPI cluster", firstSeen: "2026-06-08" },

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
  // DPRK Contagious Interview operation. Two attacker-uploaded npm packages (html-to-gutenberg,
  // fetch-page-assets; uploaded 2026-05-25, since removed) and a cluster of 16 Go modules conceal
  // a hidden VS Code task ("eslint-check") plus a JavaScript payload disguised as a web font
  // (public/fonts/fa-solid-400.woff2) that drops the InvisibleFerret Python backdoor. TronGrid +
  // Aptos blockchain transactions act as the dead-drop resolver; harvested data is packaged into
  // ZIP archives and uploaded to a C2 server or a runtime-supplied Telegram bot. No file hashes,
  // C2 domains, IPs, or wallet addresses were disclosed in the report.
  { type: "package", value: "html-to-gutenberg", severity: "critical", confidence: 0.9, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "fetch-page-assets", severity: "critical", confidence: 0.9, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/lambda-platform/lambda", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/lambda-platform/ebarimt-rest-api", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/lambda-platform/dan", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/reauheau/goaubio", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/glacialspring/go-winsparkle", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/glacialspring/static", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/bm-197/chill", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/naol7/dist-task-scheduler", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/anatoli-derese/a2sv-excercise", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/amantsehay/a2sv-go-course", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/dexbotsdev/uniswap-v2-v3-arbitrage", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/zainirfan13/graphql-client", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/hngi/team-fierce-backend-golang", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/rickt/slack-weather-bot", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/Barsu5489/commerce", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },
  { type: "package", value: "go:github.com/Setsu548/Logistic", severity: "critical", confidence: 0.95, family: "InvisibleFerret", campaign: "Contagious Interview Fake Font", firstSeen: "2026-06-29" },

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
  // Mapbox abused as a DoH dead drop (NOT blocked). Bare-name PyPI entries - fully malicious packages.
  { type: "ip", value: "91.132.163.78", severity: "critical", confidence: 1.0, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2026-07-02" },
  { type: "package", value: "frint", severity: "critical", confidence: 0.9, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2026-07-02" },
  { type: "package", value: "skytext", severity: "critical", confidence: 0.9, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2026-07-02" },
  { type: "package", value: "slogsec", severity: "critical", confidence: 0.9, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2025-11-01" },
  { type: "package", value: "logcrypt.cryptography", severity: "critical", confidence: 0.9, family: "ChocoPoC", campaign: "ChocoPoC Fake PoC Repos", firstSeen: "2025-11-01" },

  // PolinRider DPRK supply-chain campaign (Socket / The Hacker News / SecurityWeek, July 6, 2026)
  // North-Korea-linked cluster (Contagious Interview / Famous Chollima), active since Dec 2025,
  // poisoned 108 packages/extensions (162 release artifacts) across npm, Packagist, Go modules and
  // Chrome. Obfuscated JS loaders (hidden in config.js / fake .woff2 fonts, run via VS Code tasks on
  // folder-open) decrypt a second stage fetched over TRON / Aptos / BNB Smart Chain RPC with an
  // embedded XOR key and eval() it, dropping the DEV#POPPER RAT + OmniStealer (credential/browser/
  // wallet theft). Only the concretely enumerated malicious Go module is pinned here: git2md from
  // the compromised account Xpos587 at v0.0.0-20260503100027-79bdb26ca95d. The npm/Composer package
  // names and the Chrome extension ID were not publicly enumerated at feed time and are omitted to
  // avoid guessing; git-history rewriting/force-pushes make the accounts' clean history untrustworthy.
  { type: "package", value: "go:github.com/Xpos587/git2md", severity: "critical", confidence: 0.95, family: "OmniStealer", campaign: "PolinRider", firstSeen: "2026-07-06" },

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

  // Imported from GitHub Advisory Database (2026-07-19) - see docs/threat-feed-sources.md
  { type: "package", value: "app-node-layer", severity: "critical", confidence: 1.0, source: "GHSA-4xc7-2jx9-rp5j, MAL-2026-11054", firstSeen: "2026-07-24" },
  { type: "package", value: "app-data-ist", severity: "critical", confidence: 1.0, source: "GHSA-wcx6-x67q-wff5, MAL-2026-10994", firstSeen: "2026-07-24" },
  { type: "package", value: "app-data-layer", severity: "critical", confidence: 1.0, source: "GHSA-346c-3w9c-8pmh, MAL-2026-11052", firstSeen: "2026-07-24" },
  { type: "package", value: "app-data-lts", severity: "critical", confidence: 1.0, source: "GHSA-c6xr-m3x3-23fm, MAL-2026-11053", firstSeen: "2026-07-24" },
  { type: "package", value: "eth-slint", severity: "critical", confidence: 1.0, source: "GHSA-xp97-c4c4-7928, MAL-2026-11034", firstSeen: "2026-07-23" },
  { type: "package", value: "eth-base", severity: "critical", confidence: 1.0, source: "GHSA-26h4-2435-hp66, MAL-2026-10413", firstSeen: "2026-07-23" },
  { type: "package", value: "chai-as-stringify", severity: "critical", confidence: 1.0, source: "GHSA-vh7h-h87g-qv6x, MAL-2026-11032", firstSeen: "2026-07-23" },
  { type: "package", value: "yuinpm", severity: "critical", confidence: 1.0, source: "GHSA-vpgm-qmgp-w4h4, MAL-2026-11039", firstSeen: "2026-07-23" },
  { type: "package", value: "svgcraft-core@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-j9vc-q728-qcx4, MAL-2026-6715", firstSeen: "2026-07-23" },
  { type: "package", value: "svgcraft-core@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-j9vc-q728-qcx4, MAL-2026-6715", firstSeen: "2026-07-23" },
  { type: "package", value: "svgcraft-core@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-j9vc-q728-qcx4, MAL-2026-6715", firstSeen: "2026-07-23" },
  { type: "package", value: "svgcraft-core@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-j9vc-q728-qcx4, MAL-2026-6715", firstSeen: "2026-07-23" },
  { type: "package", value: "svgcraft-core@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-j9vc-q728-qcx4, MAL-2026-6715", firstSeen: "2026-07-23" },
  { type: "package", value: "svgcraft-core@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-j9vc-q728-qcx4, MAL-2026-6715", firstSeen: "2026-07-23" },
  { type: "package", value: "svgcraft-core@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-j9vc-q728-qcx4, MAL-2026-6715", firstSeen: "2026-07-23" },
  { type: "package", value: "svgcraft-core@1.0.7", severity: "critical", confidence: 1.0, source: "GHSA-j9vc-q728-qcx4, MAL-2026-6715", firstSeen: "2026-07-23" },
  { type: "package", value: "eth-codergen", severity: "critical", confidence: 1.0, source: "GHSA-87w3-vjw9-8h4w, MAL-2026-11033", firstSeen: "2026-07-23" },
  { type: "package", value: "streak-lib-math", severity: "critical", confidence: 1.0, source: "GHSA-c7rv-9j9g-pqh2, MAL-2026-11036", firstSeen: "2026-07-23" },
  { type: "package", value: "svelte-streak-metrics", severity: "critical", confidence: 1.0, source: "GHSA-fc4x-xfq3-5f35, MAL-2026-11038", firstSeen: "2026-07-23" },
  { type: "package", value: "streak-bucket-lib", severity: "critical", confidence: 1.0, source: "GHSA-rg2p-8587-wx3w, MAL-2026-11035", firstSeen: "2026-07-23" },
  { type: "package", value: "svelte-goal-streak", severity: "critical", confidence: 1.0, source: "GHSA-jw9g-wvg5-7rjg, MAL-2026-11037", firstSeen: "2026-07-23" },
  { type: "package", value: "fs-extra-core", severity: "critical", confidence: 1.0, source: "GHSA-f246-8cf4-26v7, MAL-2026-11027", firstSeen: "2026-07-23" },
  { type: "package", value: "vitest-axios", severity: "critical", confidence: 1.0, source: "GHSA-6v5g-7h35-h33q, MAL-2026-11030", firstSeen: "2026-07-23" },
  { type: "package", value: "cktool-core@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-qm37-v399-r9m5, MAL-2026-10457", firstSeen: "2026-07-23" },
  { type: "package", value: "cktool-core@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-qm37-v399-r9m5, MAL-2026-10457", firstSeen: "2026-07-23" },
  { type: "package", value: "cktool-core@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-qm37-v399-r9m5, MAL-2026-10457", firstSeen: "2026-07-23" },
  { type: "package", value: "cktool-core@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-qm37-v399-r9m5, MAL-2026-10457", firstSeen: "2026-07-23" },
  { type: "package", value: "cktool-core@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-qm37-v399-r9m5, MAL-2026-10457", firstSeen: "2026-07-23" },
  { type: "package", value: "create-kumo-project", severity: "critical", confidence: 1.0, source: "GHSA-7jg3-v58m-2f3p, MAL-2026-11024", firstSeen: "2026-07-23" },
  { type: "package", value: "lychee-norm-cache", severity: "critical", confidence: 1.0, source: "GHSA-pj38-6jj4-4x3p, MAL-2026-11029", firstSeen: "2026-07-23" },
  { type: "package", value: "xrblocks-remote-control", severity: "critical", confidence: 1.0, source: "GHSA-24xr-qqmw-jvvf, MAL-2026-6530", firstSeen: "2026-07-23" },
  { type: "package", value: "da-sc-sdk", severity: "critical", confidence: 1.0, source: "GHSA-vxfh-w38r-2g54, MAL-2026-11025", firstSeen: "2026-07-23" },
  { type: "package", value: "aio-commerce-lib-app", severity: "critical", confidence: 1.0, source: "GHSA-897j-xx2q-x2h9, MAL-2026-11022", firstSeen: "2026-07-23" },
  { type: "package", value: "helix-deploy", severity: "critical", confidence: 1.0, source: "GHSA-fhpm-cq57-j289, MAL-2026-11028", firstSeen: "2026-07-23" },
  { type: "package", value: "eslint-angular-react", severity: "critical", confidence: 1.0, source: "GHSA-jp3x-3mrw-3vwf, MAL-2026-10498", firstSeen: "2026-07-23" },
  { type: "package", value: "vue-demi-fix", severity: "critical", confidence: 1.0, source: "GHSA-p53q-mf26-4h26, MAL-2026-6702", firstSeen: "2026-07-23" },
  { type: "package", value: "mcp-notes-server-poc-praetorian", severity: "critical", confidence: 1.0, source: "GHSA-rfhm-2wfr-r9p2, MAL-2026-10210", firstSeen: "2026-07-23" },
  { type: "package", value: "bs58-88", severity: "critical", confidence: 1.0, source: "GHSA-qj7h-vp7h-8v85, MAL-2026-11023", firstSeen: "2026-07-23" },
  { type: "package", value: "ethers-wallet-package", severity: "critical", confidence: 1.0, source: "GHSA-7pvf-g7jg-rxpj, MAL-2026-4553", firstSeen: "2026-07-23" },
  { type: "package", value: "base65-85x", severity: "critical", confidence: 1.0, source: "GHSA-mv5w-mcrv-wmx9, MAL-2026-6704", firstSeen: "2026-07-23" },
  { type: "package", value: "ethers-wallet-packages", severity: "critical", confidence: 1.0, source: "GHSA-gm49-5q33-vf6f, MAL-2026-4554", firstSeen: "2026-07-23" },
  { type: "package", value: "ethers-packge", severity: "critical", confidence: 1.0, source: "GHSA-67vw-rvv3-mh93, MAL-2026-11026", firstSeen: "2026-07-23" },
  { type: "package", value: "@bcryptln/bcryptjs", severity: "critical", confidence: 1.0, source: "GHSA-qw92-vxcv-397r, MAL-2026-11021", firstSeen: "2026-07-23" },
  { type: "package", value: "@bcryptln/becryptjs", severity: "critical", confidence: 1.0, source: "GHSA-9qhg-2wvw-j95c, MAL-2026-10162", firstSeen: "2026-07-23" },
  { type: "package", value: "encryptstringadmin", severity: "critical", confidence: 1.0, source: "GHSA-x92w-56m5-jchf, MAL-2026-11012", firstSeen: "2026-07-22" },
  { type: "package", value: "encryptstringadmincore", severity: "critical", confidence: 1.0, source: "GHSA-hgfq-c4x3-jx2r, MAL-2026-11013", firstSeen: "2026-07-22" },
  { type: "package", value: "encrypt-string-ttak", severity: "critical", confidence: 1.0, source: "GHSA-mpgp-492w-x7xj, MAL-2026-11011", firstSeen: "2026-07-22" },
  { type: "package", value: "react-tabulix-ui", severity: "critical", confidence: 1.0, source: "GHSA-5jr9-f9w4-93v3, MAL-2026-10988", firstSeen: "2026-07-22" },
  { type: "package", value: "kijai", severity: "critical", confidence: 1.0, source: "GHSA-5mgj-24pj-pj6f, MAL-2026-11014", firstSeen: "2026-07-22" },
  { type: "package", value: "veldora", severity: "critical", confidence: 1.0, source: "GHSA-wxrm-vmq9-jp23, MAL-2026-11018", firstSeen: "2026-07-22" },
  { type: "package", value: "calmora", severity: "critical", confidence: 1.0, source: "GHSA-7wwx-476f-c8gm, MAL-2026-11009", firstSeen: "2026-07-22" },
  { type: "package", value: "vantora", severity: "critical", confidence: 1.0, source: "GHSA-4fm5-fwqx-8r39, MAL-2026-11016", firstSeen: "2026-07-22" },
  { type: "package", value: "calvora", severity: "critical", confidence: 1.0, source: "GHSA-jwm3-4ffq-hr73, MAL-2026-11010", firstSeen: "2026-07-22" },
  { type: "package", value: "veskr", severity: "critical", confidence: 1.0, source: "GHSA-77c3-35xp-6chp, MAL-2026-11019", firstSeen: "2026-07-22" },
  { type: "package", value: "caldryn", severity: "critical", confidence: 1.0, source: "GHSA-h9c8-8wq8-r6q2, MAL-2026-11008", firstSeen: "2026-07-22" },
  { type: "package", value: "vectormark", severity: "critical", confidence: 1.0, source: "GHSA-g48p-2cr5-5hm2, MAL-2026-11017", firstSeen: "2026-07-22" },
  { type: "package", value: "react-tabulix-core", severity: "critical", confidence: 1.0, source: "GHSA-5w4q-8fc9-88f4, MAL-2026-10987", firstSeen: "2026-07-22" },
  { type: "package", value: "react-tabulix-query", severity: "critical", confidence: 1.0, source: "GHSA-4rrq-g9w7-39c3, MAL-2026-11015", firstSeen: "2026-07-22" },
  { type: "package", value: "fastify-bundler", severity: "critical", confidence: 1.0, source: "GHSA-f99h-9jhg-jrxw, MAL-2026-10520", firstSeen: "2026-07-22" },
  { type: "package", value: "svelte-streaks", severity: "critical", confidence: 1.0, source: "GHSA-8vq2-5c69-fm3w, MAL-2026-10983", firstSeen: "2026-07-21" },
  { type: "package", value: "streak-daycount", severity: "critical", confidence: 1.0, source: "GHSA-2v57-6hmf-hpfj, MAL-2026-10982", firstSeen: "2026-07-21" },
  { type: "package", value: "streak-calendar", severity: "critical", confidence: 1.0, source: "GHSA-2p69-mmpj-h84r, MAL-2026-10981", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zmaker@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-qjr9-wxqm-hw3x, MAL-2025-191943", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zmaker@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-qjr9-wxqm-hw3x, MAL-2025-191943", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ztasimb@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9qv9-fv8w-mxh3, MAL-2024-6262", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zlsrc@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-393p-wgrw-6v84, MAL-2025-6626", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zproxy@1.0", severity: "critical", confidence: 1.0, source: "GHSA-jvq5-p4x5-w3j5, MAL-2024-6260", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zlibxjson@8.1", severity: "critical", confidence: 1.0, source: "GHSA-fj54-7cgm-qx3f, MAL-2024-10220", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zlibxjson@8.2", severity: "critical", confidence: 1.0, source: "GHSA-fj54-7cgm-qx3f, MAL-2024-10220", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zenomenallib@2.7.0", severity: "critical", confidence: 1.0, source: "GHSA-v5vg-3v26-7vxh, MAL-2025-47814", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zydnitro@1.0", severity: "critical", confidence: 1.0, source: "GHSA-xchr-mf9x-x664, MAL-2024-6263", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zzzzthisisitwantsafecheckitzzzz@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6mg7-v2ff-2qc5, MAL-2026-2309", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zorosnitro@1.0", severity: "critical", confidence: 1.0, source: "GHSA-jpmj-f7xf-x79g, MAL-2024-6259", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zyqnuutupjerllnbxaeq@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-rmxj-m6h6-jg2q, MAL-2024-6264", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zscaner@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-7h98-3phx-875g, MAL-2025-191944", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zscaner@1.3.0", severity: "critical", confidence: 1.0, source: "GHSA-7h98-3phx-875g, MAL-2025-191944", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:znomig@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7hw8-x7j6-6gg2, MAL-2024-6258", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zproxy2@1.0", severity: "critical", confidence: 1.0, source: "GHSA-694m-65f8-3m7m, MAL-2024-6261", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zero123@9.6", severity: "critical", confidence: 1.0, source: "GHSA-hxjg-gq8r-x2x3, MAL-2024-11752", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zsender@1.2.7", severity: "critical", confidence: 1.0, source: "GHSA-h4mw-6gp8-38jj, MAL-2025-191945", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zlib1g-dev@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-8vrj-mmvq-hp7r, MAL-2025-41804", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zelixnitro@1.0", severity: "critical", confidence: 1.0, source: "GHSA-f98w-9jw4-86gj, MAL-2024-6255", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zhpt1cscoe@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-99xq-r4g7-5h5c, MAL-2024-6257", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zefkopzekfo@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-9ggx-85w3-9w9j, MAL-2024-6254", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zip-me@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-23rq-3mfp-fv93, MAL-2024-12372", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ziphash@0.1.5", severity: "critical", confidence: 1.0, source: "GHSA-4277-hrwh-9pfm, MAL-2026-6", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ziphash@0.1.6", severity: "critical", confidence: 1.0, source: "GHSA-4277-hrwh-9pfm, MAL-2026-6", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zeubilamouche@0.1.4", severity: "critical", confidence: 1.0, source: "GHSA-cfjh-p84g-4ch8, MAL-2024-6256", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zatta@1", severity: "critical", confidence: 1.0, source: "GHSA-mqm3-3jcq-xv7r, MAL-2024-6253", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zhopaorlaaato@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-cqq2-gj5v-42j9, MAL-2025-41802", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zebo@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-gf2w-6wmp-5w44, MAL-2024-11751", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zakuraweb@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-wvvc-76jg-vg59, MAL-2025-191941", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ziugxfbvo@0.1.5", severity: "critical", confidence: 1.0, source: "GHSA-m8qj-cx2w-gp3j, MAL-2026-3228", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zakuchienne@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-qv3m-fjhj-jqw3, MAL-2025-191940", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zlapp@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-62j6-2qv6-r3x2, MAL-2025-6625", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zking@0.2", severity: "critical", confidence: 1.0, source: "GHSA-j5fj-m5x6-2892, MAL-2025-41803", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zking@0.3", severity: "critical", confidence: 1.0, source: "GHSA-j5fj-m5x6-2892, MAL-2025-41803", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zamino@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jv75-25j3-gqr3, MAL-2025-191942", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zamino@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-jv75-25j3-gqr3, MAL-2025-191942", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ziggonext@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-m4c7-rrvr-32mx, MAL-2025-6623", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zipf@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-3cpc-wvqf-ffm6, MAL-2025-6624", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yt-yson-bindings@66.0.4", severity: "critical", confidence: 1.0, source: "GHSA-m94q-8w5h-v8x9, MAL-2024-12371", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yper", severity: "critical", confidence: 1.0, source: "GHSA-jvv2-4pwq-g9mw, MAL-2023-2465", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:your-module-name@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wjpq-7qqj-gfj5, MAL-2025-6622", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:your-module-name@0.1", severity: "critical", confidence: 1.0, source: "GHSA-wjpq-7qqj-gfj5, MAL-2025-6622", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ypsocks", severity: "critical", confidence: 1.0, source: "GHSA-fqqc-x58v-cg38, MAL-2023-2467", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:youreallydontwantthispackage2131@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-gp6c-rjvj-fj3v, MAL-2024-10241", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:youreallydontwantthispackage2131@1", severity: "critical", confidence: 1.0, source: "GHSA-gp6c-rjvj-fj3v, MAL-2024-10241", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zabitog@9.0.1", severity: "critical", confidence: 1.0, source: "GHSA-j279-vpmw-63vw, MAL-2026-654", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:zafira@0.1", severity: "critical", confidence: 1.0, source: "GHSA-mwvw-fc3w-pc43, MAL-2024-6252", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ypthon-binance", severity: "critical", confidence: 1.0, source: "GHSA-wc3f-9qh5-wqw9, MAL-2023-2468", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yzip@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-qw6w-66xx-g6w9, MAL-2025-192468", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:youtubebot@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-v77f-qvxh-j86f, MAL-2024-6251", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:youtubebot@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-v77f-qvxh-j86f, MAL-2024-6251", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ypcodestyle", severity: "critical", confidence: 1.0, source: "GHSA-j7fj-mmff-4pr8, MAL-2023-2464", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:youreallydontwantthispackage2132@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-rr7m-4fgx-j2c8, MAL-2025-5239", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:youtube-new@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-q8r4-xxrq-h7px, MAL-2025-41801", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yt-api-dlp@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-gcfv-55gr-xh44, MAL-2026-6754", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yt-api-dlp@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-gcfv-55gr-xh44, MAL-2026-6754", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yuzo@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-38qh-vg5h-3j68, MAL-2025-48911", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yuzo@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-38qh-vg5h-3j68, MAL-2025-48911", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yuzo@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-38qh-vg5h-3j68, MAL-2025-48911", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yuzo@1.4.3", severity: "critical", confidence: 1.0, source: "GHSA-38qh-vg5h-3j68, MAL-2025-48911", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yyfinance", severity: "critical", confidence: 1.0, source: "GHSA-7rhm-vjwr-qmrp, MAL-2023-2473", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yvper", severity: "critical", confidence: 1.0, source: "GHSA-qpgg-2jf8-jh25, MAL-2023-2472", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ython-binance", severity: "critical", confidence: 1.0, source: "GHSA-4mwc-wwhg-2w5c, MAL-2023-2470", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ytest-cov@0.0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-v289-rrvh-682g, MAL-2025-3020", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ypinstaller", severity: "critical", confidence: 1.0, source: "GHSA-m458-8r93-f7q6, MAL-2023-2466", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@0.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@1.2.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@1.3.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@1.4.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@2.0.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@2.1.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yolov8mini@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-h4m7-fg96-xx35, MAL-2025-3484", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ytorch", severity: "critical", confidence: 1.0, source: "GHSA-xm2p-9pcc-m2vf, MAL-2023-2471", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ypj@0.5", severity: "critical", confidence: 1.0, source: "GHSA-xpfh-v2mw-vvpc, MAL-2025-4274", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ysocks", severity: "critical", confidence: 1.0, source: "GHSA-q52v-7ggh-qrgp, MAL-2023-2469", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ygame", severity: "critical", confidence: 1.0, source: "GHSA-5hg5-hwf7-m867, MAL-2023-2463", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfniance", severity: "critical", confidence: 1.0, source: "GHSA-frrx-r6wq-6pp2, MAL-2023-2462", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfiance", severity: "critical", confidence: 1.0, source: "GHSA-7r3q-wvr8-9xp2, MAL-2023-2447", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xxlsxwriter", severity: "critical", confidence: 1.0, source: "GHSA-j293-gmv9-926q, MAL-2023-2444", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1.1", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1.2", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1.3", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1.4", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1.5", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1.6", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1.7", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1.8", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xuiniadb@1.0", severity: "critical", confidence: 1.0, source: "GHSA-r9wh-9c75-p879, MAL-2025-2013", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xxoo-bale@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-46v8-7x99-g2w6, MAL-2026-3425", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinace", severity: "critical", confidence: 1.0, source: "GHSA-7p76-wm85-5m69, MAL-2023-2451", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yc-depconf-test-807dff@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w656-r5g3-qmwv, MAL-2026-3368", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yc-depconf-test-807dff@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-w656-r5g3-qmwv, MAL-2026-3368", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yellorq@1.0", severity: "critical", confidence: 1.0, source: "GHSA-hvf6-cp3p-j28f, MAL-2024-6249", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yc-as-client@11.11.3", severity: "critical", confidence: 1.0, source: "GHSA-xh86-cchh-g9v3, MAL-2023-1422", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinaance", severity: "critical", confidence: 1.0, source: "GHSA-r6wx-v8wf-777r, MAL-2023-2450", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xwormclient@0.1.3", severity: "critical", confidence: 1.0, source: "GHSA-qf88-7763-5hjm, MAL-2025-191938", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xx-ent-wiki-sm@99.2.2", severity: "critical", confidence: 1.0, source: "GHSA-ff24-vg94-52wq, MAL-2025-191939", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xx-ent-wiki-sm@99.1.2", severity: "critical", confidence: 1.0, source: "GHSA-ff24-vg94-52wq, MAL-2025-191939", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xx-ent-wiki-sm@99.1.1", severity: "critical", confidence: 1.0, source: "GHSA-ff24-vg94-52wq, MAL-2025-191939", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xx-ent-wiki-sm@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-ff24-vg94-52wq, MAL-2025-191939", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfiannce", severity: "critical", confidence: 1.0, source: "GHSA-598g-ph32-mwp8, MAL-2023-2448", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yeahmankema@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8hvp-pp6m-8c3p, MAL-2026-3386", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yeahmankema@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-8hvp-pp6m-8c3p, MAL-2026-3386", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinannce", severity: "critical", confidence: 1.0, source: "GHSA-ffwr-gwrj-xg24, MAL-2023-2457", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinancee", severity: "critical", confidence: 1.0, source: "GHSA-fqqp-chq5-9vcp, MAL-2023-2454", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yffinance", severity: "critical", confidence: 1.0, source: "GHSA-m3jm-hph9-j9rv, MAL-2023-2446", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:ycodestyle", severity: "critical", confidence: 1.0, source: "GHSA-rqx3-xxr2-pc7w, MAL-2023-2445", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yelp-cgeom1@0.1", severity: "critical", confidence: 1.0, source: "GHSA-c3xj-m7hx-mjj7, MAL-2023-8564", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yelp-pkg@1337.0.0", severity: "critical", confidence: 1.0, source: "GHSA-f6pg-w2v6-3cj7, MAL-2025-191666", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yhaplo1@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-6q25-qwrp-28hc, MAL-2026-2536", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinanec", severity: "critical", confidence: 1.0, source: "GHSA-796h-8x9j-2cwg, MAL-2023-2456", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinacne", severity: "critical", confidence: 1.0, source: "GHSA-g8hj-3x3p-p498, MAL-2023-2452", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfiinance", severity: "critical", confidence: 1.0, source: "GHSA-2mf9-gv38-xrpv, MAL-2023-2449", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfnance", severity: "critical", confidence: 1.0, source: "GHSA-7mqx-gg2w-2rjm, MAL-2023-2461", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinnance", severity: "critical", confidence: 1.0, source: "GHSA-9fh3-jr44-89fq, MAL-2023-2459", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinnce", severity: "critical", confidence: 1.0, source: "GHSA-rc32-pp7j-5j6r, MAL-2023-2460", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xyq-drama-skill@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-4q6q-2w3r-cm92, MAL-2026-10681", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xyq-drama-skill@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-4q6q-2w3r-cm92, MAL-2026-10681", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xyq-drama-skill@0.3.0", severity: "critical", confidence: 1.0, source: "GHSA-4q6q-2w3r-cm92, MAL-2026-10681", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yeshsurya@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vf4p-3wqv-fjr3, MAL-2026-2183", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yellyproxies@1.0", severity: "critical", confidence: 1.0, source: "GHSA-w3w4-49m4-5gr3, MAL-2024-6250", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xxx-bale@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2qhr-vm43-8f4v, MAL-2026-3428", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinnace", severity: "critical", confidence: 1.0, source: "GHSA-89mv-vj77-vxmv, MAL-2023-2458", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinane", severity: "critical", confidence: 1.0, source: "GHSA-rx4g-rmv4-3gjf, MAL-2023-2455", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:yfinancce", severity: "critical", confidence: 1.0, source: "GHSA-m657-v6m9-xh57, MAL-2023-2453", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolofyxkotqwko@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-cx5q-pc3c-9pmm, MAL-2025-41796", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xsltproc@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-8339-c9j3-rqv3, MAL-2025-191937", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xsltproc@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8339-c9j3-rqv3, MAL-2025-191937", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolosamsdyhcfa@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-f6rj-q583-g3jx, MAL-2024-6242", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xorg-renderproto@0.11.1", severity: "critical", confidence: 1.0, source: "GHSA-x66f-7x29-8cj8, MAL-2025-41800", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xoloqmotdjpbic@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2rrv-vfwm-xp4p, MAL-2024-6240", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolonavrylpbeb@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2wgc-gq9j-338h, MAL-2025-41797", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xologrekjlqzxj@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-qq48-2hjv-jwv2, MAL-2024-6234", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xoloxwmellxliq@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w6xw-357q-wxh6, MAL-2024-6248", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolowqffntthtb@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vv6w-rjc2-73jw, MAL-2024-6247", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolojgmnizxche@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-fxvc-xh5r-94cc, MAL-2024-6236", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xsilyxd@0.1", severity: "critical", confidence: 1.0, source: "GHSA-5pm9-x4w8-fx7q, MAL-2024-11750", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolosxelwsesnp@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-3rr2-c683-r8xm, MAL-2024-6243", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xololcuakbzbuu@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-g3xw-c6h8-8p7w, MAL-2024-6238", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolomjqalvrpmp@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-44hj-4wx5-g74v, MAL-2024-6239", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolosafhpodvqo@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pwxg-q39x-j28v, MAL-2024-6241", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolofmdvxqvbmp@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-4q46-wp9w-x2g2, MAL-2024-6232", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolobzvfburelm@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-gfpr-w8p8-fwm5, MAL-2024-6229", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xoloyuaezcqixu@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wrxv-89jq-rvq3, MAL-2025-41799", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xoloeduccelifz@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-m2g8-f5j3-q9fw, MAL-2024-6231", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolojbxzzttwpk@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-3w2c-wj2g-rmm8, MAL-2024-6235", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolojhzyppbsow@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8v95-75mg-wp9x, MAL-2024-6237", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolodyntlnewtp@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-p2c2-w97c-27fh, MAL-2024-6230", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xsxwriter", severity: "critical", confidence: 1.0, source: "GHSA-pm4g-3766-h7pc, MAL-2023-2443", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolotcgstfiguu@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5283-xw6m-49qw, MAL-2024-6244", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolovqryjphftd@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-3rwx-67fv-9c77, MAL-2024-6246", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xoloulfkhiyywc@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-52wq-542r-24xm, MAL-2024-6245", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xoloowlowpzeke@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vv7m-34pv-x35w, MAL-2025-41798", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xoloftiqwxxhje@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7vhr-7c8f-mhvj, MAL-2024-6233", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolobwritbrulv@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-44vv-rr72-ppjw, MAL-2024-6228", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxwrier", severity: "critical", confidence: 1.0, source: "GHSA-hjg7-w3rf-j93g, MAL-2023-2427", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xiedemo@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-98gm-r585-gvpp, MAL-2024-6223", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xiedemo@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-98gm-r585-gvpp, MAL-2024-6223", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xolobbbccc@1.0", severity: "critical", confidence: 1.0, source: "GHSA-rw6f-7cv3-g7c9, MAL-2024-6227", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxwrietr", severity: "critical", confidence: 1.0, source: "GHSA-pwhr-7477-qrjx, MAL-2023-2428", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlatency@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-ww38-6653-pfh6, MAL-2024-6224", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxwrter", severity: "critical", confidence: 1.0, source: "GHSA-w7qc-542r-mc85, MAL-2023-2437", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxwwriter", severity: "critical", confidence: 1.0, source: "GHSA-6vc3-gppf-64m9, MAL-2023-2439", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xmlbuilder3@0.0.2", severity: "critical", confidence: 1.0, source: "GHSA-fjxw-m974-7322, MAL-2023-8309", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlxwriter", severity: "critical", confidence: 1.0, source: "GHSA-5cf8-w29p-352g, MAL-2023-2442", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxxwriter", severity: "critical", confidence: 1.0, source: "GHSA-r42g-gg8r-f4v5, MAL-2023-2440", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xforpy@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-p7x3-cvh8-4qx5, MAL-2026-5332", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xforpy@0.0.2", severity: "critical", confidence: 1.0, source: "GHSA-p7x3-cvh8-4qx5, MAL-2026-5332", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xforpy@0.0.3", severity: "critical", confidence: 1.0, source: "GHSA-p7x3-cvh8-4qx5, MAL-2026-5332", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xforpy@0.0.4", severity: "critical", confidence: 1.0, source: "GHSA-p7x3-cvh8-4qx5, MAL-2026-5332", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xllsxwriter", severity: "critical", confidence: 1.0, source: "GHSA-884v-h8c3-mwvv, MAL-2023-2421", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xoloazfgyobkaw@0.0.0", severity: "critical", confidence: 1.0, source: "GHSA-p9px-hrr9-4jfp, MAL-2025-41795", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xmsgpy@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-h6x3-624f-p6j5, MAL-2025-1009", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxwrtier", severity: "critical", confidence: 1.0, source: "GHSA-wv2p-m83v-cfrj, MAL-2023-2438", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxwriterr", severity: "critical", confidence: 1.0, source: "GHSA-qm3g-xcwm-639q, MAL-2023-2432", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxwrriter", severity: "critical", confidence: 1.0, source: "GHSA-4fc5-mc7r-hqvr, MAL-2023-2436", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxwriiter", severity: "critical", confidence: 1.0, source: "GHSA-mjvw-77r5-98hq, MAL-2023-2429", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlsxwriteer", severity: "critical", confidence: 1.0, source: "GHSA-5x27-g9wf-w9h9, MAL-2023-2431", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xmrig-miner@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-c7w6-2836-j839, MAL-2026-1282", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xinference@2.6.0", severity: "critical", confidence: 1.0, source: "GHSA-9x96-4gxh-mxx2, MAL-2026-3000", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xinference@2.6.1", severity: "critical", confidence: 1.0, source: "GHSA-9x96-4gxh-mxx2, MAL-2026-3000", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xinference@2.6.2", severity: "critical", confidence: 1.0, source: "GHSA-9x96-4gxh-mxx2, MAL-2026-3000", firstSeen: "2026-07-21" },
  { type: "package", value: "pypi:xlxswriter", severity: "critical", confidence: 1.0, source: "GHSA-r7w9-93mq-7975, MAL-2023-2441", firstSeen: "2026-07-21" },

  // Imported from GitHub Advisory Database (2026-07-13) - see docs/threat-feed-sources.md
  { type: "package", value: "fluterjs@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-gj4r-435f-67cr, MAL-2026-10532", firstSeen: "2026-07-27" },
  { type: "package", value: "@kalipto/local", severity: "critical", confidence: 1.0, source: "GHSA-653g-2cfx-6gpc, MAL-2026-5922", firstSeen: "2026-07-27" },
  { type: "package", value: "kalipto-runtime", severity: "critical", confidence: 0.9, source: "GHSA-g6f3-9j93-879j", firstSeen: "2026-07-27" },
  { type: "package", value: "npx-whoami-demo", severity: "critical", confidence: 1.0, source: "GHSA-3mmq-8798-7f4v, MAL-2026-5772", firstSeen: "2026-07-27" },
  { type: "package", value: "@ci-lifecycle-test/postinstall-ping", severity: "critical", confidence: 1.0, source: "GHSA-q86v-7cxj-6979, MAL-2026-5723", firstSeen: "2026-07-27" },
  { type: "package", value: "jextic-eclib", severity: "critical", confidence: 1.0, source: "GHSA-fvh5-fhfx-3whm, MAL-2026-5712", firstSeen: "2026-07-27" },
  { type: "package", value: "ap3-components-ui", severity: "critical", confidence: 1.0, source: "GHSA-qhgr-v9vh-3784, MAL-2026-10150", firstSeen: "2026-07-27" },
  { type: "package", value: "@403name/electron-buidler", severity: "critical", confidence: 1.0, source: "GHSA-h23r-x34f-p95m, MAL-2026-5547", firstSeen: "2026-07-27" },
  { type: "package", value: "@403name/ether-js", severity: "critical", confidence: 1.0, source: "GHSA-qgxg-2j6w-jmpx, MAL-2026-5548", firstSeen: "2026-07-27" },
  { type: "package", value: "@403name/fsevent", severity: "critical", confidence: 1.0, source: "GHSA-hp95-92q5-xfvc, MAL-2026-5549", firstSeen: "2026-07-27" },
  { type: "package", value: "@thone33/core-utils", severity: "critical", confidence: 1.0, source: "GHSA-w2wf-8vp4-86mq, MAL-2026-6564", firstSeen: "2026-07-27" },
  { type: "package", value: "@thone33/react-helpers", severity: "critical", confidence: 0.9, source: "GHSA-vxmg-ff8j-2552", firstSeen: "2026-07-27" },
  { type: "package", value: "@thone33/analytics-injector", severity: "critical", confidence: 1.0, source: "GHSA-7mg5-m9qh-r4rp, MAL-2026-6563", firstSeen: "2026-07-27" },
  { type: "package", value: "roblox-api-client", severity: "critical", confidence: 1.0, source: "GHSA-hmpp-mfgc-mq8p, MAL-2026-6097", firstSeen: "2026-07-27" },
  { type: "package", value: "edu-npm-dependency-chain-demo", severity: "critical", confidence: 1.0, source: "GHSA-cqgx-r84j-px55, MAL-2026-5623", firstSeen: "2026-07-27" },
  { type: "package", value: "edu-npm-postinstall-demo2", severity: "critical", confidence: 1.0, source: "GHSA-gqxv-6fpm-5xwx, MAL-2026-5624", firstSeen: "2026-07-27" },
  { type: "package", value: "edu-npm-helper-beta", severity: "critical", confidence: 0.9, source: "GHSA-mm62-vp6v-vqq2", firstSeen: "2026-07-27" },
  { type: "package", value: "edu-npm-helper-alpha", severity: "critical", confidence: 0.9, source: "GHSA-jhpp-p77r-39q6", firstSeen: "2026-07-27" },
  { type: "package", value: "v018-axios-cdntest", severity: "critical", confidence: 1.0, source: "GHSA-cw6g-r53q-23c2, MAL-2026-5529", firstSeen: "2026-07-27" },
  { type: "package", value: "txs-builder", severity: "critical", confidence: 0.9, source: "GHSA-5g95-w82p-69v9", firstSeen: "2026-07-27" },
  { type: "package", value: "txs-runner-lib", severity: "critical", confidence: 0.9, source: "GHSA-65pq-67vr-g3jp", firstSeen: "2026-07-27" },
  { type: "package", value: "txs-random-lib", severity: "critical", confidence: 0.9, source: "GHSA-c2fc-52mv-g5v6", firstSeen: "2026-07-27" },
  { type: "package", value: "txs-sdk-lib", severity: "critical", confidence: 0.9, source: "GHSA-fgmc-rrjh-9m33", firstSeen: "2026-07-27" },
  { type: "package", value: "chai-log", severity: "critical", confidence: 1.0, source: "GHSA-2534-xr99-f4wh, MAL-2026-10426", firstSeen: "2026-07-27" },
  { type: "package", value: "polymarket-stake-maths", severity: "critical", confidence: 1.0, source: "GHSA-x384-v7hw-q48x, MAL-2026-6439", firstSeen: "2026-07-27" },
  { type: "package", value: "log-taker1", severity: "critical", confidence: 1.0, source: "GHSA-35q5-q365-j23w, MAL-2026-6690", firstSeen: "2026-07-27" },
  { type: "package", value: "ts-escrow", severity: "critical", confidence: 1.0, source: "GHSA-fjgh-3fjv-prm3, MAL-2026-6320", firstSeen: "2026-07-27" },
  { type: "package", value: "thidweb", severity: "critical", confidence: 1.0, source: "GHSA-3vx6-4gr6-qj63, MAL-2026-6343", firstSeen: "2026-07-27" },
  { type: "package", value: "therdweb", severity: "critical", confidence: 1.0, source: "GHSA-g2vx-7x66-f2wv, MAL-2026-6342", firstSeen: "2026-07-27" },
  { type: "package", value: "thirdwebb", severity: "critical", confidence: 1.0, source: "GHSA-46px-g2r9-8vcr, MAL-2026-6694", firstSeen: "2026-07-27" },
  { type: "package", value: "thurdweb", severity: "critical", confidence: 1.0, source: "GHSA-vx4c-33rj-4xv8, MAL-2026-6345", firstSeen: "2026-07-27" },
  { type: "package", value: "thirdwebjs", severity: "critical", confidence: 1.0, source: "GHSA-8jr3-m3cj-m436, MAL-2026-6344", firstSeen: "2026-07-27" },
  { type: "package", value: "rainbownkit", severity: "critical", confidence: 1.0, source: "GHSA-vj5m-3jrw-83gx, MAL-2026-6340", firstSeen: "2026-07-27" },
  { type: "package", value: "thirdwb", severity: "critical", confidence: 1.0, source: "GHSA-ccmq-q5j8-hvxc, MAL-2026-6693", firstSeen: "2026-07-27" },
  { type: "package", value: "rainbokit", severity: "critical", confidence: 1.0, source: "GHSA-56vv-8v7m-r49g, MAL-2026-6339", firstSeen: "2026-07-27" },
  { type: "package", value: "ts-escro", severity: "critical", confidence: 1.0, source: "GHSA-5hm9-jj3m-6q76, MAL-2026-6319", firstSeen: "2026-07-27" },
  { type: "package", value: "log-taker", severity: "critical", confidence: 1.0, source: "GHSA-x8v5-5q93-844w, MAL-2026-6338", firstSeen: "2026-07-27" },
  { type: "package", value: "permcserver", severity: "critical", confidence: 1.0, source: "GHSA-vjr2-cx8x-3q2x, MAL-2026-10489", firstSeen: "2026-07-27" },
  { type: "package", value: "permcarmserver", severity: "critical", confidence: 1.0, source: "GHSA-9499-pgrg-v7w7, MAL-2026-10488", firstSeen: "2026-07-27" },
  { type: "package", value: "@vinnxcode/xbailsync", severity: "critical", confidence: 0.9, source: "GHSA-fgwc-g3q5-794p", firstSeen: "2026-07-27" },
  { type: "package", value: "sixbails", severity: "critical", confidence: 0.9, source: "GHSA-8cvc-378h-fwqf", firstSeen: "2026-07-27" },
  { type: "package", value: "@vinnxcode/libsignal-node", severity: "critical", confidence: 0.9, source: "GHSA-v9rv-pgqp-436h", firstSeen: "2026-07-27" },
  { type: "package", value: "@wrenfield/viem", severity: "critical", confidence: 1.0, source: "GHSA-pm4g-83cj-7858, MAL-2026-10571", firstSeen: "2026-07-27" },
  { type: "package", value: "@wrenfield/abitype", severity: "critical", confidence: 1.0, source: "GHSA-6f83-g2m3-3wwr, MAL-2026-10529", firstSeen: "2026-07-27" },
  { type: "package", value: "@ceeferenderer/itg-renderer-sdk", severity: "critical", confidence: 1.0, source: "GHSA-3v4h-w4g3-h6r2, MAL-2026-2407", firstSeen: "2026-07-27" },
  { type: "package", value: "@ceeferenderer/fe-renderer-sdk", severity: "critical", confidence: 1.0, source: "GHSA-mw7m-6vvq-q69p, MAL-2026-2406", firstSeen: "2026-07-27" },
  { type: "package", value: "amanexzyra-baileys", severity: "critical", confidence: 0.9, source: "GHSA-mwwh-7r57-h6v9", firstSeen: "2026-07-27" },
  { type: "package", value: "fazzgram", severity: "critical", confidence: 0.9, source: "GHSA-vjhp-hr8c-42m8", firstSeen: "2026-07-27" },
  { type: "package", value: "@fazzcode/baileys", severity: "critical", confidence: 0.9, source: "GHSA-wqqq-qm88-5433", firstSeen: "2026-07-27" },
  { type: "package", value: "fazzanime", severity: "critical", confidence: 0.9, source: "GHSA-r3jh-34p6-m7xp", firstSeen: "2026-07-27" },
  { type: "package", value: "@sqlite-tag/sql-creator", severity: "critical", confidence: 0.9, source: "GHSA-6vr8-7f3x-9c9r", firstSeen: "2026-07-27" },
  { type: "package", value: "@sqlite-tag/schema-generator", severity: "critical", confidence: 0.9, source: "GHSA-hpc8-vc57-jjcp", firstSeen: "2026-07-27" },
  { type: "package", value: "@sqlite-frame/nodesql", severity: "critical", confidence: 1.0, source: "GHSA-r9rm-52xp-prf4, MAL-2026-10627", firstSeen: "2026-07-27" },
  { type: "package", value: "@sqlite-frame/createsql", severity: "critical", confidence: 0.9, source: "GHSA-723v-4wq3-j58v", firstSeen: "2026-07-27" },
  { type: "package", value: "llama-tokenizer", severity: "critical", confidence: 1.0, source: "GHSA-q4hv-j85h-9h7j, MAL-2026-10163", firstSeen: "2026-07-27" },
  { type: "package", value: "tinymask-js", severity: "critical", confidence: 1.0, source: "GHSA-993g-jhvm-h79j, MAL-2026-10189", firstSeen: "2026-07-27" },
  { type: "package", value: "supertokens-web", severity: "critical", confidence: 1.0, source: "GHSA-m7xr-6cvv-jm79, MAL-2026-10423", firstSeen: "2026-07-27" },
  { type: "package", value: "@equansservices/tool", severity: "critical", confidence: 1.0, source: "GHSA-5v77-3vqq-cv88, MAL-2026-10400", firstSeen: "2026-07-27" },
  { type: "package", value: "hardhat-compile-ethers", severity: "critical", confidence: 1.0, source: "GHSA-rgq3-mp7r-3cq5, MAL-2026-6705", firstSeen: "2026-07-27" },
  { type: "package", value: "express-self-destruct1", severity: "critical", confidence: 0.9, source: "GHSA-4h93-54g6-hm75", firstSeen: "2026-07-27" },
  { type: "package", value: "express-self-destruct2", severity: "critical", confidence: 1.0, source: "GHSA-rjp6-jx87-x8x8, MAL-2026-5554", firstSeen: "2026-07-27" },
  { type: "package", value: "express-self-destruct", severity: "critical", confidence: 1.0, source: "GHSA-wqrx-jfhq-5hx7, MAL-2026-5553", firstSeen: "2026-07-27" },
  { type: "package", value: "@my_name_is_khn/express-security-tool-v1", severity: "critical", confidence: 1.0, source: "GHSA-v624-m435-vmfx, MAL-2026-5551", firstSeen: "2026-07-27" },
  { type: "package", value: "@my_name_is_khn/express-security-tool-v3", severity: "critical", confidence: 1.0, source: "GHSA-pf66-w9wm-c932, MAL-2026-5552", firstSeen: "2026-07-27" },
  { type: "package", value: "express-timer", severity: "critical", confidence: 1.0, source: "GHSA-9vgr-cqvw-qwhx, MAL-2026-5555", firstSeen: "2026-07-27" },
  { type: "package", value: "@my_name_is_khn/express-security-tool-v2", severity: "critical", confidence: 0.9, source: "GHSA-v2gc-c6j4-6gq8", firstSeen: "2026-07-27" },
  { type: "package", value: "@my_name_is_khn/express-security-tool", severity: "critical", confidence: 1.0, source: "GHSA-pmmq-vq8x-p92v, MAL-2026-5550", firstSeen: "2026-07-27" },
  { type: "package", value: "svg-fetcher", severity: "critical", confidence: 1.0, source: "GHSA-36vw-78q8-pj2r, MAL-2026-10427", firstSeen: "2026-07-27" },
  { type: "package", value: "gifuct", severity: "critical", confidence: 1.0, source: "GHSA-829c-v26f-5g9m, MAL-2026-10451", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g-plugin-svg-picker@2.1.46", severity: "critical", confidence: 1.0, source: "GHSA-9wwp-32v6-mhm5, MAL-2026-3953", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-svg-picker@2.2.46", severity: "critical", confidence: 1.0, source: "GHSA-9wwp-32v6-mhm5, MAL-2026-3953", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-dom-interaction@2.2.31", severity: "critical", confidence: 1.0, source: "GHSA-r6w9-92g7-mj3g, MAL-2026-3942", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-dom-interaction@2.3.31", severity: "critical", confidence: 1.0, source: "GHSA-r6w9-92g7-mj3g, MAL-2026-3942", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-device-api@1.7.13", severity: "critical", confidence: 1.0, source: "GHSA-hqjp-pg4j-q8g2, MAL-2026-3917", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-device-api@1.8.13", severity: "critical", confidence: 1.0, source: "GHSA-hqjp-pg4j-q8g2, MAL-2026-3917", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-zdog-svg-renderer@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-3272-5h83-x35h, MAL-2026-3960", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-zdog-svg-renderer@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-3272-5h83-x35h, MAL-2026-3960", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-css-layout-api@1.1.38", severity: "critical", confidence: 1.0, source: "GHSA-hr5f-c8fj-7296, MAL-2026-3915", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-css-layout-api@1.2.38", severity: "critical", confidence: 1.0, source: "GHSA-hr5f-c8fj-7296, MAL-2026-3915", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-webgl-renderer@1.1.26", severity: "critical", confidence: 1.0, source: "GHSA-m4px-jrch-5rv4, MAL-2026-3956", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-webgl-renderer@1.2.26", severity: "critical", confidence: 1.0, source: "GHSA-m4px-jrch-5rv4, MAL-2026-3956", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-web-animations-api@2.2.32", severity: "critical", confidence: 1.0, source: "GHSA-5hr2-f7ww-4623, MAL-2026-3963", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-web-animations-api@2.3.32", severity: "critical", confidence: 1.0, source: "GHSA-5hr2-f7ww-4623, MAL-2026-3963", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-zdog-canvas-renderer@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-3397-xpc6-xq95, MAL-2026-3959", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-zdog-canvas-renderer@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-3397-xpc6-xq95, MAL-2026-3959", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-css-select@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-wh4r-hmcf-hc4p, MAL-2026-3940", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-css-select@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-wh4r-hmcf-hc4p, MAL-2026-3940", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-yoga@2.4.1", severity: "critical", confidence: 1.0, source: "GHSA-3jg5-63vx-5p33, MAL-2026-3958", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-yoga@2.5.1", severity: "critical", confidence: 1.0, source: "GHSA-3jg5-63vx-5p33, MAL-2026-3958", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-webgpu-device@1.10.17", severity: "critical", confidence: 1.0, source: "GHSA-9p48-5jr5-2j4g, MAL-2026-3957", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-webgpu-device@1.11.17", severity: "critical", confidence: 1.0, source: "GHSA-9p48-5jr5-2j4g, MAL-2026-3957", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-box2d@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-gjxq-cxhw-vfxp, MAL-2026-3934", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-box2d@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-gjxq-cxhw-vfxp, MAL-2026-3934", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-matterjs@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-q4h5-6vh5-927v, MAL-2026-3948", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-matterjs@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-q4h5-6vh5-927v, MAL-2026-3948", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-canvaskit-renderer@2.4.1", severity: "critical", confidence: 1.0, source: "GHSA-gcx5-qgpf-g372, MAL-2026-3938", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-canvaskit-renderer@2.5.1", severity: "critical", confidence: 1.0, source: "GHSA-gcx5-qgpf-g372, MAL-2026-3938", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-physx@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-hr7p-82hq-pmmf, MAL-2026-3950", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-physx@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-hr7p-82hq-pmmf, MAL-2026-3950", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-webgl-device@1.10.17", severity: "critical", confidence: 1.0, source: "GHSA-rjh6-2fw9-c9cw, MAL-2026-3955", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-webgl-device@1.11.17", severity: "critical", confidence: 1.0, source: "GHSA-rjh6-2fw9-c9cw, MAL-2026-3955", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-mobile-interaction@1.1.42", severity: "critical", confidence: 1.0, source: "GHSA-f3mw-2vrc-c62j, MAL-2026-3949", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-mobile-interaction@1.2.42", severity: "critical", confidence: 1.0, source: "GHSA-f3mw-2vrc-c62j, MAL-2026-3949", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-pattern@2.1.42", severity: "critical", confidence: 1.0, source: "GHSA-6vp6-xhxc-hjcf, MAL-2026-3929", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-pattern@2.2.42", severity: "critical", confidence: 1.0, source: "GHSA-6vp6-xhxc-hjcf, MAL-2026-3929", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-canvas-picker@2.4.1", severity: "critical", confidence: 1.0, source: "GHSA-rwgc-6v96-rfvv, MAL-2026-3936", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-canvas-picker@2.5.1", severity: "critical", confidence: 1.0, source: "GHSA-rwgc-6v96-rfvv, MAL-2026-3936", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-camera-api@2.1.45", severity: "critical", confidence: 1.0, source: "GHSA-93pv-mgm4-7wjm, MAL-2026-3910", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-camera-api@2.2.45", severity: "critical", confidence: 1.0, source: "GHSA-93pv-mgm4-7wjm, MAL-2026-3910", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-dom-mutation-observer-api@2.1.42", severity: "critical", confidence: 1.0, source: "GHSA-4vpc-9qw7-255h, MAL-2026-3918", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-dom-mutation-observer-api@2.2.42", severity: "critical", confidence: 1.0, source: "GHSA-4vpc-9qw7-255h, MAL-2026-3918", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-css-typed-om-api@1.1.38", severity: "critical", confidence: 1.0, source: "GHSA-qv23-hf2f-8q99, MAL-2026-3916", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-css-typed-om-api@1.2.38", severity: "critical", confidence: 1.0, source: "GHSA-qv23-hf2f-8q99, MAL-2026-3916", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-compat@1.1.11", severity: "critical", confidence: 1.0, source: "GHSA-xfj3-r6mw-5cvx, MAL-2026-3913", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-compat@1.2.11", severity: "critical", confidence: 1.0, source: "GHSA-xfj3-r6mw-5cvx, MAL-2026-3913", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-perf@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-qfx4-mrhx-34p5, MAL-2026-3930", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-perf@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-qfx4-mrhx-34p5, MAL-2026-3930", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-layout-blocklike@1.8.49", severity: "critical", confidence: 1.0, source: "GHSA-j7jx-fcx4-53p7, MAL-2026-3920", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-layout-blocklike@1.9.49", severity: "critical", confidence: 1.0, source: "GHSA-j7jx-fcx4-53p7, MAL-2026-3920", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-annotation@1.3.0", severity: "critical", confidence: 1.0, source: "GHSA-8m6f-w9fv-2mxf, MAL-2026-3933", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-plugin-annotation@1.4.0", severity: "critical", confidence: 1.0, source: "GHSA-8m6f-w9fv-2mxf, MAL-2026-3933", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-web-components@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-vv5x-8828-6xx2, MAL-2026-3964", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/g-web-components@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-vv5x-8828-6xx2, MAL-2026-3964", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-canvas@1.1.5", severity: "critical", confidence: 1.0, source: "GHSA-h6vv-v545-wpvp, MAL-2026-3891", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-canvas@1.2.5", severity: "critical", confidence: 1.0, source: "GHSA-h6vv-v545-wpvp, MAL-2026-3891", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f-wx@1.11.0", severity: "critical", confidence: 1.0, source: "GHSA-gxx8-w6m2-fwrc, MAL-2026-3888", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f-wx@1.12.0", severity: "critical", confidence: 1.0, source: "GHSA-gxx8-w6m2-fwrc, MAL-2026-3888", firstSeen: "2026-07-26" },
  { type: "package", value: "@antstackio/json-to-graphql@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-2m9w-297v-v4x6, MAL-2025-191190", firstSeen: "2026-07-26" },
  { type: "package", value: "@angular_devkit/core@99.1.1", severity: "critical", confidence: 1.0, source: "GHSA-vr8j-6g9x-548m, MAL-2025-6869", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-my@4.1.52", severity: "critical", confidence: 1.0, source: "GHSA-jcpg-w7fw-jv6j, MAL-2026-3894", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-my@4.2.52", severity: "critical", confidence: 1.0, source: "GHSA-jcpg-w7fw-jv6j, MAL-2026-3894", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f6-hammerjs@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-93h7-g78h-gv9j, MAL-2026-3904", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f6-hammerjs@0.2.2", severity: "critical", confidence: 1.0, source: "GHSA-93h7-g78h-gv9j, MAL-2026-3904", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dw-util@1.2.4", severity: "critical", confidence: 1.0, source: "GHSA-m482-p3qg-5gqr, MAL-2026-3878", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dw-util@1.3.4", severity: "critical", confidence: 1.0, source: "GHSA-m482-p3qg-5gqr, MAL-2026-3878", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f6-wx@0.1.7", severity: "critical", confidence: 1.0, source: "GHSA-g643-x2wj-c398, MAL-2026-3907", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f6-wx@0.2.7", severity: "critical", confidence: 1.0, source: "GHSA-g643-x2wj-c398, MAL-2026-3907", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dw-transform@1.2.7", severity: "critical", confidence: 1.0, source: "GHSA-hch4-xprx-2mx2, MAL-2026-3877", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dw-transform@1.3.7", severity: "critical", confidence: 1.0, source: "GHSA-hch4-xprx-2mx2, MAL-2026-3877", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-site@4.1.42", severity: "critical", confidence: 1.0, source: "GHSA-vj9m-5hgc-w93w, MAL-2026-3896", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-site@4.2.42", severity: "critical", confidence: 1.0, source: "GHSA-vj9m-5hgc-w93w, MAL-2026-3896", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f6-alipay@0.1.7", severity: "critical", confidence: 1.0, source: "GHSA-gf92-pwx2-x64f, MAL-2026-3901", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f6-alipay@0.2.7", severity: "critical", confidence: 1.0, source: "GHSA-gf92-pwx2-x64f, MAL-2026-3901", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dipper-hooks@0.3.1", severity: "critical", confidence: 1.0, source: "GHSA-w3wf-qx75-qchc, MAL-2026-3871", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dipper-hooks@0.4.1", severity: "critical", confidence: 1.0, source: "GHSA-w3wf-qx75-qchc, MAL-2026-3871", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/chart-visualization-skills@0.2.3", severity: "critical", confidence: 1.0, source: "GHSA-h9vm-j4w2-f2qv, MAL-2026-3859", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/chart-visualization-skills@0.3.3", severity: "critical", confidence: 1.0, source: "GHSA-h9vm-j4w2-f2qv, MAL-2026-3859", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-wordcloud@5.15.0", severity: "critical", confidence: 1.0, source: "GHSA-3hvp-cf8c-5w96, MAL-2026-3898", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-wordcloud@5.16.0", severity: "critical", confidence: 1.0, source: "GHSA-3hvp-cf8c-5w96, MAL-2026-3898", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/data-wizard@2.1.4", severity: "critical", confidence: 1.0, source: "GHSA-69jf-8xhf-2cfv, MAL-2026-3869", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/data-wizard@2.2.4", severity: "critical", confidence: 1.0, source: "GHSA-69jf-8xhf-2cfv, MAL-2026-3869", firstSeen: "2026-07-26" },
  { type: "package", value: "@antstackio/eslint-config-antstack@0.0.3", severity: "critical", confidence: 1.0, source: "GHSA-xqmj-xphj-x7h3, MAL-2025-191187", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-algorithm@5.8.0", severity: "critical", confidence: 1.0, source: "GHSA-f7g5-9cgp-6878, MAL-2026-3890", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-algorithm@5.9.0", severity: "critical", confidence: 1.0, source: "GHSA-f7g5-9cgp-6878, MAL-2026-3890", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/d3-interpolate@1.1.3", severity: "critical", confidence: 1.0, source: "GHSA-6f69-4vpx-47xh, MAL-2026-3866", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/d3-interpolate@1.2.3", severity: "critical", confidence: 1.0, source: "GHSA-6f69-4vpx-47xh, MAL-2026-3866", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/awards@0.1.9", severity: "critical", confidence: 1.0, source: "GHSA-26gq-5v8w-2h84, MAL-2026-3855", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/awards@0.2.9", severity: "critical", confidence: 1.0, source: "GHSA-26gq-5v8w-2h84, MAL-2026-3855", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-wx@4.1.51", severity: "critical", confidence: 1.0, source: "GHSA-x7rx-wj54-59xp, MAL-2026-3899", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f2-wx@4.2.51", severity: "critical", confidence: 1.0, source: "GHSA-x7rx-wj54-59xp, MAL-2026-3899", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/calendar-heatmap@1.2.2", severity: "critical", confidence: 1.0, source: "GHSA-xhx3-7gj6-3xv3, MAL-2026-3856", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/calendar-heatmap@1.3.2", severity: "critical", confidence: 1.0, source: "GHSA-xhx3-7gj6-3xv3, MAL-2026-3856", firstSeen: "2026-07-26" },
  { type: "package", value: "@antstackio/shelbysam@1.1.7", severity: "critical", confidence: 1.0, source: "GHSA-j7v3-xxhh-942f, MAL-2025-191191", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f-my@1.11.0", severity: "critical", confidence: 1.0, source: "GHSA-68qq-h9p8-pf77, MAL-2026-3884", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f-my@1.12.0", severity: "critical", confidence: 1.0, source: "GHSA-68qq-h9p8-pf77, MAL-2026-3884", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f-charts@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-9jv6-fjwr-9m23, MAL-2026-3881", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/f-charts@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-9jv6-fjwr-9m23, MAL-2026-3881", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dipper-map@1.1.10", severity: "critical", confidence: 1.0, source: "GHSA-gpm5-c9hh-38r4, MAL-2026-3872", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dipper-map@1.2.10", severity: "critical", confidence: 1.0, source: "GHSA-gpm5-c9hh-38r4, MAL-2026-3872", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/data-samples@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-h4ph-jfgx-fm3m, MAL-2026-3867", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/data-samples@1.2.1", severity: "critical", confidence: 1.0, source: "GHSA-h4ph-jfgx-fm3m, MAL-2026-3867", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dipper-component@0.1.4", severity: "critical", confidence: 1.0, source: "GHSA-mjrh-2mcq-w8xq, MAL-2026-3870", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/dipper-component@0.2.4", severity: "critical", confidence: 1.0, source: "GHSA-mjrh-2mcq-w8xq, MAL-2026-3870", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/data-set@0.12.8", severity: "critical", confidence: 1.0, source: "GHSA-x6hv-hhcr-2qx6, MAL-2026-3868", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/data-set@0.13.8", severity: "critical", confidence: 1.0, source: "GHSA-x6hv-hhcr-2qx6, MAL-2026-3868", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/chart-linter@1.2.6", severity: "critical", confidence: 1.0, source: "GHSA-pmg7-4qcw-g3xg, MAL-2026-3857", firstSeen: "2026-07-26" },
  { type: "package", value: "@antv/chart-linter@1.3.6", severity: "critical", confidence: 1.0, source: "GHSA-pmg7-4qcw-g3xg, MAL-2026-3857", firstSeen: "2026-07-26" },
  { type: "package", value: "@antstackio/express-graphql-proxy@0.2.8", severity: "critical", confidence: 1.0, source: "GHSA-5gw8-r2hf-px46, MAL-2025-191188", firstSeen: "2026-07-26" },
  { type: "package", value: "@anchor-ds/core@99.9.0", severity: "critical", confidence: 1.0, source: "GHSA-w4ff-rwjv-9xxj, MAL-2026-1585", firstSeen: "2026-07-26" },
  { type: "package", value: "@andes-tools/colors@999.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9cg3-ff4x-xcww, MAL-2026-6703", firstSeen: "2026-07-26" },
  { type: "package", value: "@andrewstory18/is-real-odd@2.0.3", severity: "critical", confidence: 1.0, source: "GHSA-7h72-59gf-g77p, MAL-2026-10093", firstSeen: "2026-07-26" },
  { type: "package", value: "@amiga-fwk-nodejs/log", severity: "critical", confidence: 1.0, source: "GHSA-8cx5-gjvj-8q8v, MAL-2025-42185", firstSeen: "2026-07-26" },
  { type: "package", value: "@amber-team/react-modal-stack", severity: "critical", confidence: 1.0, source: "GHSA-44rm-8vq6-qhf5, MAL-2025-7065", firstSeen: "2026-07-26" },
  { type: "package", value: "@amber-team/gatsby-plugin-semcore", severity: "critical", confidence: 1.0, source: "GHSA-27jr-546m-cv6p, MAL-2025-7058", firstSeen: "2026-07-26" },
  { type: "package", value: "@al-ui/useappinsights@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9chj-fc74-95g9, MAL-2025-755", firstSeen: "2026-07-26" },
  { type: "package", value: "@al-ui/useappinsights@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-9chj-fc74-95g9, MAL-2025-755", firstSeen: "2026-07-26" },
  { type: "package", value: "@alaska-its/design-tokens@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-56q2-v4w4-rwhm, MAL-2025-756", firstSeen: "2026-07-26" },
  { type: "package", value: "@angular_devkit/build-webpack@99.1.1", severity: "critical", confidence: 1.0, source: "GHSA-qx5g-37g8-5j97, MAL-2025-6870", firstSeen: "2026-07-26" },
  { type: "package", value: "@anhackle/test", severity: "critical", confidence: 1.0, source: "GHSA-w463-76vx-7rjf, MAL-2025-49394", firstSeen: "2026-07-26" },
  { type: "package", value: "@angular_devkit/build_angular@99.1.1", severity: "critical", confidence: 1.0, source: "GHSA-f792-mwpq-wxpf, MAL-2025-6901", firstSeen: "2026-07-26" },
  { type: "package", value: "@angular_devkit/architect@99.1.1", severity: "critical", confidence: 1.0, source: "GHSA-hfv6-3m9v-cwv7, MAL-2025-6900", firstSeen: "2026-07-26" },
  { type: "package", value: "@alphasedboy/game@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9587-gmc9-6qh8, MAL-2026-7034", firstSeen: "2026-07-26" },
  { type: "package", value: "@alphasedboy/game@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-9587-gmc9-6qh8, MAL-2026-7034", firstSeen: "2026-07-26" },
  { type: "package", value: "@alphasedboy/game@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-9587-gmc9-6qh8, MAL-2026-7034", firstSeen: "2026-07-26" },
  { type: "package", value: "@amops/fetch@1.4.1", severity: "critical", confidence: 1.0, source: "GHSA-9r89-xxw7-r4r2, MAL-2024-1660", firstSeen: "2026-07-26" },
  { type: "package", value: "@amber-team/export-events-to-sheet", severity: "critical", confidence: 1.0, source: "GHSA-qxj3-92mx-9r8w, MAL-2025-7056", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/tehpucuk3", severity: "critical", confidence: 1.0, source: "GHSA-pjq9-gjj5-57w2, MAL-2025-181353", firstSeen: "2026-07-26" },
  { type: "package", value: "@aluffyz/discord-botjs@1.4.5", severity: "critical", confidence: 1.0, source: "GHSA-3xgv-2x7h-249r, MAL-2024-1352", firstSeen: "2026-07-26" },
  { type: "package", value: "@aluffyz/discord-botjs@1.4.3", severity: "critical", confidence: 1.0, source: "GHSA-3xgv-2x7h-249r, MAL-2024-1352", firstSeen: "2026-07-26" },
  { type: "package", value: "@aluffyz/discord-botjs@1.4.7", severity: "critical", confidence: 1.0, source: "GHSA-3xgv-2x7h-249r, MAL-2024-1352", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/tehpucuk1", severity: "critical", confidence: 1.0, source: "GHSA-5x43-hcjm-x76h, MAL-2025-181351", firstSeen: "2026-07-26" },
  { type: "package", value: "@amigatechdocs/core", severity: "critical", confidence: 1.0, source: "GHSA-3g7w-jfxp-hv78, MAL-2025-42187", firstSeen: "2026-07-26" },
  { type: "package", value: "@amiga-fwk-nodejs/metrics", severity: "critical", confidence: 1.0, source: "GHSA-g8h2-q3c5-hcm7, MAL-2025-42186", firstSeen: "2026-07-26" },
  { type: "package", value: "@amber-team/figma-utils", severity: "critical", confidence: 1.0, source: "GHSA-2j44-84pc-388j, MAL-2025-7057", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/teagunup99", severity: "critical", confidence: 1.0, source: "GHSA-2x3m-xq5x-jvpc, MAL-2025-181349", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/tea_guntry99", severity: "critical", confidence: 1.0, source: "GHSA-jr8r-fpq3-wq7v, MAL-2025-181346", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/teagunz99", severity: "critical", confidence: 1.0, source: "GHSA-7qh4-3wq2-xhf2, MAL-2025-181350", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/tehpucuk2", severity: "critical", confidence: 1.0, source: "GHSA-fhpq-5j3m-7h3v, MAL-2025-181352", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/tea_gunt99", severity: "critical", confidence: 1.0, source: "GHSA-w4v7-hwhv-m755, MAL-2025-181345", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/susu9", severity: "critical", confidence: 1.0, source: "GHSA-gqx4-r9r4-w5w7, MAL-2025-181344", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/susu8", severity: "critical", confidence: 1.0, source: "GHSA-v4gf-697f-6r73, MAL-2025-181343", firstSeen: "2026-07-26" },
  { type: "package", value: "@alexandrsarioglo/npm-ghost-htb", severity: "critical", confidence: 1.0, source: "GHSA-56qw-6jw4-jm27, MAL-2025-49292", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/teaguntur99", severity: "critical", confidence: 1.0, source: "GHSA-7vrx-gxgf-9x88, MAL-2025-181348", firstSeen: "2026-07-26" },
  { type: "package", value: "@aligntech-cw/alignerfit@9.999.2", severity: "critical", confidence: 1.0, source: "GHSA-4jvv-pv44-h4cp, MAL-2024-1743", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/tea_nextgun", severity: "critical", confidence: 1.0, source: "GHSA-4h2w-43pr-xxqg, MAL-2025-181347", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/susu10", severity: "critical", confidence: 1.0, source: "GHSA-28hw-4x96-fghw, MAL-2025-181335", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucuk9", severity: "critical", confidence: 1.0, source: "GHSA-j4vr-26mm-q9fp, MAL-2025-181332", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/susu11", severity: "critical", confidence: 1.0, source: "GHSA-wcwj-g2hq-6qf8, MAL-2025-181336", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucukharum", severity: "critical", confidence: 1.0, source: "GHSA-7jw3-j44c-3q43, MAL-2025-181333", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucuk11", severity: "critical", confidence: 1.0, source: "GHSA-8pq5-gr7h-rfvm, MAL-2025-181325", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucuk12", severity: "critical", confidence: 1.0, source: "GHSA-643r-p2hc-6r99, MAL-2025-181326", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/kopi3", severity: "critical", confidence: 1.0, source: "GHSA-w6f8-q979-582x, MAL-2025-181318", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok4", severity: "critical", confidence: 1.0, source: "GHSA-qjcv-hp23-v8w2, MAL-2025-181311", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok36", severity: "critical", confidence: 1.0, source: "GHSA-8r73-r6cx-pg2r, MAL-2025-181307", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/susu2", severity: "critical", confidence: 1.0, source: "GHSA-xpwh-mvch-84m8, MAL-2025-181337", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/susu3", severity: "critical", confidence: 1.0, source: "GHSA-h5rh-m63q-9rrx, MAL-2025-181338", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucuk5", severity: "critical", confidence: 1.0, source: "GHSA-8pcg-p4w2-ghxm, MAL-2025-181328", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucuk6", severity: "critical", confidence: 1.0, source: "GHSA-hfvr-cxrp-9q9x, MAL-2025-181330", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok9", severity: "critical", confidence: 1.0, source: "GHSA-vcxv-46gr-q2pf, MAL-2025-181317", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/roti", severity: "critical", confidence: 1.0, source: "GHSA-34v6-3wc6-2r8r, MAL-2025-181334", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok6", severity: "critical", confidence: 1.0, source: "GHSA-6rf2-ggvw-9x87, MAL-2025-181314", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucuk5000", severity: "critical", confidence: 1.0, source: "GHSA-f65p-qmvr-gxcw, MAL-2025-181329", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok40", severity: "critical", confidence: 1.0, source: "GHSA-36hv-m4jj-x8gr, MAL-2025-181312", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucuk10", severity: "critical", confidence: 1.0, source: "GHSA-w8wm-rgj8-239w, MAL-2025-181324", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok7", severity: "critical", confidence: 1.0, source: "GHSA-4c4v-qmw2-w936, MAL-2025-181315", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/kopi7", severity: "critical", confidence: 1.0, source: "GHSA-cmpw-g7mw-cpw8, MAL-2025-181322", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/kopi8", severity: "critical", confidence: 1.0, source: "GHSA-hj4m-ggrm-j2v7, MAL-2025-181323", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok8", severity: "critical", confidence: 1.0, source: "GHSA-2jpw-gw2q-j682, MAL-2025-181316", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/kopi4", severity: "critical", confidence: 1.0, source: "GHSA-wgjj-px45-h9vw, MAL-2025-181319", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok39", severity: "critical", confidence: 1.0, source: "GHSA-v7cf-xfqh-rpfw, MAL-2025-181310", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucuk7", severity: "critical", confidence: 1.0, source: "GHSA-2mv6-4jcm-43v4, MAL-2025-181331", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok37", severity: "critical", confidence: 1.0, source: "GHSA-9rjq-r9cx-gcf7, MAL-2025-181308", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/pucuk4", severity: "critical", confidence: 1.0, source: "GHSA-4mx7-xcf8-pw6w, MAL-2025-181327", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/kopi6", severity: "critical", confidence: 1.0, source: "GHSA-r6wc-gwpr-gc3r, MAL-2025-181321", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok5", severity: "critical", confidence: 1.0, source: "GHSA-7j96-6j2w-xpcx, MAL-2025-181313", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/kopi5", severity: "critical", confidence: 1.0, source: "GHSA-vvq6-x7wm-mm7j, MAL-2025-181320", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/karedok38", severity: "critical", confidence: 1.0, source: "GHSA-wg36-fxvf-gpr2, MAL-2025-181309", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/susu7", severity: "critical", confidence: 1.0, source: "GHSA-hf49-4q7r-cpw4, MAL-2025-181342", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/susu4", severity: "critical", confidence: 1.0, source: "GHSA-w53v-7r4w-ffpv, MAL-2025-181339", firstSeen: "2026-07-26" },
  { type: "package", value: "@akunsansan0/susu6", severity: "critical", confidence: 1.0, source: "GHSA-qhcf-m2pr-8rqw, MAL-2025-181341", firstSeen: "2026-07-26" },

  // Imported from GitHub Advisory Database (2026-07-14) - see docs/threat-feed-sources.md
  { type: "package", value: "pypi:cfgzen@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-r2w6-7pgv-644h, MAL-2026-11094", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:cfgzen@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-r2w6-7pgv-644h, MAL-2026-11094", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:cfgzen@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-r2w6-7pgv-644h, MAL-2026-11094", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:cfgzen@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-r2w6-7pgv-644h, MAL-2026-11094", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:cfgzen@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-r2w6-7pgv-644h, MAL-2026-11094", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:cfgzen@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-r2w6-7pgv-644h, MAL-2026-11094", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:cfgzen@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-r2w6-7pgv-644h, MAL-2026-11094", firstSeen: "2026-07-28" },
  { type: "package", value: "@vaultflow/update-flow", severity: "critical", confidence: 1.0, source: "GHSA-gv55-mvjq-232h, MAL-2026-11097", firstSeen: "2026-07-28" },
  { type: "package", value: "@vaultflow/create-flow", severity: "critical", confidence: 1.0, source: "GHSA-xpp9-qw49-cpw2, MAL-2026-11096", firstSeen: "2026-07-28" },
  { type: "package", value: "motion-forge-css", severity: "critical", confidence: 1.0, source: "GHSA-3v24-55c2-cpp9, MAL-2026-11101", firstSeen: "2026-07-27" },
  { type: "package", value: "truffle-helper@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2cq2-c7vh-j55c, MAL-2026-3716", firstSeen: "2026-07-27" },
  { type: "package", value: "truffle-helper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2cq2-c7vh-j55c, MAL-2026-3716", firstSeen: "2026-07-27" },
  { type: "package", value: "truffle-js@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7cmq-x9fp-ppg5, MAL-2026-3717", firstSeen: "2026-07-27" },
  { type: "package", value: "truffle-js@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7cmq-x9fp-ppg5, MAL-2026-3717", firstSeen: "2026-07-27" },
  { type: "package", value: "web3-core-js@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-f75h-gv5f-cg2x, MAL-2026-3719", firstSeen: "2026-07-27" },
  { type: "package", value: "web3-core-js@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-f75h-gv5f-cg2x, MAL-2026-3719", firstSeen: "2026-07-27" },
  { type: "package", value: "solc-helper@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8mmw-f9x4-8m2v, MAL-2026-3715", firstSeen: "2026-07-27" },
  { type: "package", value: "solc-helper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8mmw-f9x4-8m2v, MAL-2026-3715", firstSeen: "2026-07-27" },
  { type: "package", value: "typography-stylecss@0.7.4", severity: "critical", confidence: 1.0, source: "GHSA-vqg5-mfj2-mmrr, MAL-2026-3776", firstSeen: "2026-07-27" },
  { type: "package", value: "sysbin@1.0.34", severity: "critical", confidence: 1.0, source: "GHSA-jxmp-2j7x-rvwp, MAL-2026-3773", firstSeen: "2026-07-27" },
  { type: "package", value: "rimraf-utils@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-9fg9-r489-hq34, MAL-2026-3772", firstSeen: "2026-07-27" },
  { type: "package", value: "rimraf-utils@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9fg9-r489-hq34, MAL-2026-3772", firstSeen: "2026-07-27" },
  { type: "package", value: "rimraf-utils@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-9fg9-r489-hq34, MAL-2026-3772", firstSeen: "2026-07-27" },
  { type: "package", value: "joi-pack@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-2p7q-46c9-cjgf, MAL-2026-3765", firstSeen: "2026-07-27" },
  { type: "package", value: "joi-pack@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-2p7q-46c9-cjgf, MAL-2026-3765", firstSeen: "2026-07-27" },
  { type: "package", value: "joi-pack@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-2p7q-46c9-cjgf, MAL-2026-3765", firstSeen: "2026-07-27" },
  { type: "package", value: "chalk-utils@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-qfhf-894c-75p7, MAL-2026-3755", firstSeen: "2026-07-27" },
  { type: "package", value: "chalk-utils@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-qfhf-894c-75p7, MAL-2026-3755", firstSeen: "2026-07-27" },
  { type: "package", value: "chalk-utils@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-qfhf-894c-75p7, MAL-2026-3755", firstSeen: "2026-07-27" },
  { type: "package", value: "nock-helper@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-335w-3phj-h2jj, MAL-2026-3766", firstSeen: "2026-07-27" },
  { type: "package", value: "nock-helper@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-335w-3phj-h2jj, MAL-2026-3766", firstSeen: "2026-07-27" },
  { type: "package", value: "nock-helper@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-335w-3phj-h2jj, MAL-2026-3766", firstSeen: "2026-07-27" },
  { type: "package", value: "nock-helper@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-335w-3phj-h2jj, MAL-2026-3766", firstSeen: "2026-07-27" },
  { type: "package", value: "nock-helper@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-335w-3phj-h2jj, MAL-2026-3766", firstSeen: "2026-07-27" },
  { type: "package", value: "ethers-common@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-853h-mq9w-93p4, MAL-2026-3707", firstSeen: "2026-07-27" },
  { type: "package", value: "ethers-common@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-853h-mq9w-93p4, MAL-2026-3707", firstSeen: "2026-07-27" },
  { type: "package", value: "env-threads@1.5.0", severity: "critical", confidence: 1.0, source: "GHSA-j3r8-fm75-pfq7, MAL-2026-3759", firstSeen: "2026-07-27" },
  { type: "package", value: "glob-helper@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-5f9h-7gp2-hg2m, MAL-2026-3764", firstSeen: "2026-07-27" },
  { type: "package", value: "glob-helper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5f9h-7gp2-hg2m, MAL-2026-3764", firstSeen: "2026-07-27" },
  { type: "package", value: "glob-helper@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-5f9h-7gp2-hg2m, MAL-2026-3764", firstSeen: "2026-07-27" },
  { type: "package", value: "glob-helper@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-5f9h-7gp2-hg2m, MAL-2026-3764", firstSeen: "2026-07-27" },
  { type: "package", value: "glob-helper@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5f9h-7gp2-hg2m, MAL-2026-3764", firstSeen: "2026-07-27" },
  { type: "package", value: "glob-helper@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-5f9h-7gp2-hg2m, MAL-2026-3764", firstSeen: "2026-07-27" },
  { type: "package", value: "glob-helper@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-5f9h-7gp2-hg2m, MAL-2026-3764", firstSeen: "2026-07-27" },
  { type: "package", value: "hello-world-pkg-value-value-p@1.0.11", severity: "critical", confidence: 1.0, source: "GHSA-7mhg-447r-w46p, MAL-2026-3714", firstSeen: "2026-07-27" },
  { type: "package", value: "hello-world-pkg-value-value-p@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-7mhg-447r-w46p, MAL-2026-3714", firstSeen: "2026-07-27" },
  { type: "package", value: "dotenvv-tool@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-v6vw-vv5w-p658, MAL-2026-3758", firstSeen: "2026-07-27" },
  { type: "package", value: "dotenvv-tool@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-v6vw-vv5w-p658, MAL-2026-3758", firstSeen: "2026-07-27" },
  { type: "package", value: "dotenvv-tool@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-v6vw-vv5w-p658, MAL-2026-3758", firstSeen: "2026-07-27" },
  { type: "package", value: "dotenvv-tool@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-v6vw-vv5w-p658, MAL-2026-3758", firstSeen: "2026-07-27" },
  { type: "package", value: "dotenvv-tool@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-v6vw-vv5w-p658, MAL-2026-3758", firstSeen: "2026-07-27" },
  { type: "package", value: "exxpress-tool@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-xfj5-439g-p6qm, MAL-2026-3762", firstSeen: "2026-07-27" },
  { type: "package", value: "exxpress-tool@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-xfj5-439g-p6qm, MAL-2026-3762", firstSeen: "2026-07-27" },
];

const FEED_CHUNK_1: FeedIOC[] = [
  { type: "package", value: "exxpress-tool@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-xfj5-439g-p6qm, MAL-2026-3762", firstSeen: "2026-07-27" },
  { type: "package", value: "@design-system-coopeuch/web@999.0.0", severity: "critical", confidence: 1.0, source: "GHSA-4fqj-2fv5-gj83, MAL-2026-3653", firstSeen: "2026-07-27" },
  { type: "package", value: "@design-system-coopeuch/web@999.0.4", severity: "critical", confidence: 1.0, source: "GHSA-4fqj-2fv5-gj83, MAL-2026-3653", firstSeen: "2026-07-27" },
  { type: "package", value: "cdp-core@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-xc49-p4pq-83rq, MAL-2026-3752", firstSeen: "2026-07-27" },
  { type: "package", value: "cdp-core@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-xc49-p4pq-83rq, MAL-2026-3752", firstSeen: "2026-07-27" },
  { type: "package", value: "paysafe-gbp-virtual-assistant-lib-fe@2.0.4", severity: "critical", confidence: 1.0, source: "GHSA-cprr-jmxq-pj2p, MAL-2026-4169", firstSeen: "2026-07-27" },
  { type: "package", value: "boring-avatars-vanilla@1.1.2", severity: "critical", confidence: 1.0, source: "GHSA-37pp-fr38-g266, MAL-2026-4130", firstSeen: "2026-07-27" },
  { type: "package", value: "boring-avatars-vanilla@1.2.2", severity: "critical", confidence: 1.0, source: "GHSA-37pp-fr38-g266, MAL-2026-4130", firstSeen: "2026-07-27" },
  { type: "package", value: "ethers-io@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-rmhg-qfp9-hvvm, MAL-2026-3708", firstSeen: "2026-07-27" },
  { type: "package", value: "ethers-io@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-rmhg-qfp9-hvvm, MAL-2026-3708", firstSeen: "2026-07-27" },
  { type: "package", value: "cache-poisoning-pwn-demo@0.1.29", severity: "critical", confidence: 1.0, source: "GHSA-fg76-6277-9c5c, MAL-2026-3751", firstSeen: "2026-07-27" },
  { type: "package", value: "cache-poisoning-pwn-demo@0.1.27", severity: "critical", confidence: 1.0, source: "GHSA-fg76-6277-9c5c, MAL-2026-3751", firstSeen: "2026-07-27" },
  { type: "package", value: "cache-poisoning-pwn-demo@0.1.28", severity: "critical", confidence: 1.0, source: "GHSA-fg76-6277-9c5c, MAL-2026-3751", firstSeen: "2026-07-27" },
  { type: "package", value: "@webapp-next/store@91.1.0", severity: "critical", confidence: 1.0, source: "GHSA-9frp-9f8j-wj97, MAL-2026-3749", firstSeen: "2026-07-27" },
  { type: "package", value: "chalk-pack@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-v7hx-pp9r-7rvr, MAL-2026-3754", firstSeen: "2026-07-27" },
  { type: "package", value: "chalk-pack@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-v7hx-pp9r-7rvr, MAL-2026-3754", firstSeen: "2026-07-27" },
  { type: "package", value: "vue-template-compiler-plugin@2.7.18", severity: "critical", confidence: 1.0, source: "GHSA-766p-9cxp-2xxh, MAL-2026-3777", firstSeen: "2026-07-27" },
  { type: "package", value: "request-logger-canary@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wx62-h3rg-4284, MAL-2026-3771", firstSeen: "2026-07-27" },
  { type: "package", value: "mcp-echarts@0.8.1", severity: "critical", confidence: 1.0, source: "GHSA-33m7-5xmx-p58p, MAL-2026-4146", firstSeen: "2026-07-27" },
  { type: "package", value: "mcp-echarts@0.9.1", severity: "critical", confidence: 1.0, source: "GHSA-33m7-5xmx-p58p, MAL-2026-4146", firstSeen: "2026-07-27" },
  { type: "package", value: "exxpress-utils@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pjc4-9jjg-gqx4, MAL-2026-3763", firstSeen: "2026-07-27" },
  { type: "package", value: "exxpress-utils@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-pjc4-9jjg-gqx4, MAL-2026-3763", firstSeen: "2026-07-27" },
  { type: "package", value: "exxpress-utils@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-pjc4-9jjg-gqx4, MAL-2026-3763", firstSeen: "2026-07-27" },
  { type: "package", value: "exxpress-utils@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-pjc4-9jjg-gqx4, MAL-2026-3763", firstSeen: "2026-07-27" },
  { type: "package", value: "hardhat-core@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6rxh-8gx9-544x, MAL-2026-3713", firstSeen: "2026-07-27" },
  { type: "package", value: "@pelmnaads/naads-common-logger@19999.0.1", severity: "critical", confidence: 1.0, source: "GHSA-2fqh-pwxg-9x86, MAL-2026-3748", firstSeen: "2026-07-27" },
  { type: "package", value: "prettier-lint-lenz@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pmr5-xc5h-jpmq, MAL-2026-3769", firstSeen: "2026-07-27" },
  { type: "package", value: "prettier-lint-lenz@2.6.4", severity: "critical", confidence: 1.0, source: "GHSA-pmr5-xc5h-jpmq, MAL-2026-3769", firstSeen: "2026-07-27" },
  { type: "package", value: "chai-as-regulated@2.0.12", severity: "critical", confidence: 1.0, source: "GHSA-97qj-8m4x-2m8j, MAL-2026-3753", firstSeen: "2026-07-27" },
  { type: "package", value: "prisma-callback@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-jmvw-wxmr-926c, MAL-2026-3770", firstSeen: "2026-07-27" },
  { type: "package", value: "prisma-callback@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-jmvw-wxmr-926c, MAL-2026-3770", firstSeen: "2026-07-27" },
  { type: "package", value: "prisma-callback@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-jmvw-wxmr-926c, MAL-2026-3770", firstSeen: "2026-07-27" },
  { type: "package", value: "prisma-callback@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jmvw-wxmr-926c, MAL-2026-3770", firstSeen: "2026-07-27" },
  { type: "package", value: "cheerio-tool@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-34x4-g9xm-gjmw, MAL-2026-3756", firstSeen: "2026-07-27" },
  { type: "package", value: "cheerio-tool@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-34x4-g9xm-gjmw, MAL-2026-3756", firstSeen: "2026-07-27" },
  { type: "package", value: "cheerio-tool@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-34x4-g9xm-gjmw, MAL-2026-3756", firstSeen: "2026-07-27" },
  { type: "package", value: "jest-canvas-mock@2.5.3", severity: "critical", confidence: 1.0, source: "GHSA-55pq-j8p6-fr2h, MAL-2026-4136", firstSeen: "2026-07-27" },
  { type: "package", value: "jest-canvas-mock@2.6.3", severity: "critical", confidence: 1.0, source: "GHSA-55pq-j8p6-fr2h, MAL-2026-4136", firstSeen: "2026-07-27" },
  { type: "package", value: "jest-canvas-mock@2.7.3", severity: "critical", confidence: 1.0, source: "GHSA-55pq-j8p6-fr2h, MAL-2026-4136", firstSeen: "2026-07-27" },
  { type: "package", value: "mcp-mermaid@0.5.1", severity: "critical", confidence: 1.0, source: "GHSA-2f6m-69ww-37wv, MAL-2026-4147", firstSeen: "2026-07-27" },
  { type: "package", value: "mcp-mermaid@0.6.1", severity: "critical", confidence: 1.0, source: "GHSA-2f6m-69ww-37wv, MAL-2026-4147", firstSeen: "2026-07-27" },
  { type: "package", value: "@convera/ui-shared@0.0.2", severity: "critical", confidence: 1.0, source: "GHSA-5gr4-vr9v-phc3, MAL-2026-3724", firstSeen: "2026-07-27" },
  { type: "package", value: "@convera/ui-shared@0.0.3", severity: "critical", confidence: 1.0, source: "GHSA-5gr4-vr9v-phc3, MAL-2026-3724", firstSeen: "2026-07-27" },
  { type: "package", value: "@datatrain/passenger-v3@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-gf4f-chpw-g8qh, MAL-2026-3802", firstSeen: "2026-07-27" },
  { type: "package", value: "apex-trading@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-rc69-pqv3-hw66, MAL-2026-3817", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/matrix-util@3.1.4", severity: "critical", confidence: 1.0, source: "GHSA-hgqm-cwrq-xx84, MAL-2026-4067", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/matrix-util@3.2.4", severity: "critical", confidence: 1.0, source: "GHSA-hgqm-cwrq-xx84, MAL-2026-4067", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/react-g@2.2.1", severity: "critical", confidence: 1.0, source: "GHSA-j2fw-8r3j-fg22, MAL-2026-4076", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/react-g@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-j2fw-8r3j-fg22, MAL-2026-4076", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/scale@0.6.2", severity: "critical", confidence: 1.0, source: "GHSA-x2mm-vh3m-65rv, MAL-2026-4083", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/scale@0.7.2", severity: "critical", confidence: 1.0, source: "GHSA-x2mm-vh3m-65rv, MAL-2026-4083", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-mini@2.21.8", severity: "critical", confidence: 1.0, source: "GHSA-q57x-w3gm-5vff, MAL-2026-4046", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-mini@2.22.8", severity: "critical", confidence: 1.0, source: "GHSA-q57x-w3gm-5vff, MAL-2026-4046", firstSeen: "2026-07-27" },
  { type: "package", value: "amapcn@0.2.2", severity: "critical", confidence: 1.0, source: "GHSA-8xch-qgqv-h8fh, MAL-2026-4127", firstSeen: "2026-07-27" },
  { type: "package", value: "amapcn@0.3.2", severity: "critical", confidence: 1.0, source: "GHSA-8xch-qgqv-h8fh, MAL-2026-4127", firstSeen: "2026-07-27" },
  { type: "package", value: "@citi-icg-158830/elemental-chameleon@0.0.0-defensive-callback.1", severity: "critical", confidence: 1.0, source: "GHSA-3x32-552f-fg4j, MAL-2026-3806", firstSeen: "2026-07-27" },
  { type: "package", value: "@citi-icg-158830/elemental-chameleon@0.0.0-defensive-callback", severity: "critical", confidence: 1.0, source: "GHSA-3x32-552f-fg4j, MAL-2026-3806", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/webgpu-graph@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-vgxx-qpq8-rfr7, MAL-2026-4095", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/webgpu-graph@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-vgxx-qpq8-rfr7, MAL-2026-4095", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/xflow-diff@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-g23p-h876-r8q7, MAL-2026-4120", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/xflow-diff@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-g23p-h876-r8q7, MAL-2026-4120", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/word-scale-chart@0.4.4", severity: "critical", confidence: 1.0, source: "GHSA-wrw9-4r4g-qjmh, MAL-2026-4096", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/word-scale-chart@0.5.4", severity: "critical", confidence: 1.0, source: "GHSA-wrw9-4r4g-qjmh, MAL-2026-4096", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/xflow-core@1.1.55", severity: "critical", confidence: 1.0, source: "GHSA-jxh7-8cpr-fw4p, MAL-2026-4119", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/xflow-core@1.2.55", severity: "critical", confidence: 1.0, source: "GHSA-jxh7-8cpr-fw4p, MAL-2026-4119", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-three@2.26.10", severity: "critical", confidence: 1.0, source: "GHSA-gjrp-hvwh-82xh, MAL-2026-4052", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-three@2.27.10", severity: "critical", confidence: 1.0, source: "GHSA-gjrp-hvwh-82xh, MAL-2026-4052", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/x6-react@0.2.26", severity: "critical", confidence: 1.0, source: "GHSA-j8fq-5683-72xr, MAL-2026-4112", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/x6-react@0.3.26", severity: "critical", confidence: 1.0, source: "GHSA-j8fq-5683-72xr, MAL-2026-4112", firstSeen: "2026-07-27" },
  { type: "package", value: "identitysecuretokenserv@10.0.0", severity: "critical", confidence: 1.0, source: "GHSA-rqm7-j2qp-74f2, MAL-2026-4164", firstSeen: "2026-07-27" },
  { type: "package", value: "identitysecuretokenserv@20.0.0", severity: "critical", confidence: 1.0, source: "GHSA-rqm7-j2qp-74f2, MAL-2026-4164", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-pass@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-7qq6-7jfh-7996, MAL-2026-4047", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-pass@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-7qq6-7jfh-7996, MAL-2026-4047", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/x6-angular-shape@3.1.1", severity: "critical", confidence: 1.0, source: "GHSA-hcgp-pc3v-6795, MAL-2026-4098", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/x6-angular-shape@3.2.1", severity: "critical", confidence: 1.0, source: "GHSA-hcgp-pc3v-6795, MAL-2026-4098", firstSeen: "2026-07-27" },
  { type: "package", value: "@tc-core/campus-service@0.0.0-defensive-callback", severity: "critical", confidence: 1.0, source: "GHSA-3hvw-w2fc-p2fg, MAL-2026-3809", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/my-f2-pc@0.2.1", severity: "critical", confidence: 1.0, source: "GHSA-3243-f96w-8pv8, MAL-2026-4071", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/my-f2-pc@0.3.1", severity: "critical", confidence: 1.0, source: "GHSA-3243-f96w-8pv8, MAL-2026-4071", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/narrative-text-editor@0.3.20", severity: "critical", confidence: 1.0, source: "GHSA-rhpv-vmh9-r7h7, MAL-2026-4072", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/narrative-text-editor@0.4.20", severity: "critical", confidence: 1.0, source: "GHSA-rhpv-vmh9-r7h7, MAL-2026-4072", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/stat@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-73r9-92m6-g7j3, MAL-2026-4086", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/stat@0.2.2", severity: "critical", confidence: 1.0, source: "GHSA-73r9-92m6-g7j3, MAL-2026-4086", firstSeen: "2026-07-27" },
  { type: "package", value: "bui-react-10components@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wfj4-qhgr-q7wq, MAL-2026-3804", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/x6-vector@1.5.2", severity: "critical", confidence: 1.0, source: "GHSA-6h7h-5qx3-fvxp, MAL-2026-4115", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/x6-vector@1.6.2", severity: "critical", confidence: 1.0, source: "GHSA-6h7h-5qx3-fvxp, MAL-2026-4115", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/li-aiearth-assets@0.5.7", severity: "critical", confidence: 1.0, source: "GHSA-w68f-5mhr-x4w4, MAL-2026-4059", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/li-aiearth-assets@0.6.7", severity: "critical", confidence: 1.0, source: "GHSA-w68f-5mhr-x4w4, MAL-2026-4059", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/mcp-server-antv@0.2.8", severity: "critical", confidence: 1.0, source: "GHSA-p6wc-j7x7-ff3v, MAL-2026-4068", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/mcp-server-antv@0.3.8", severity: "critical", confidence: 1.0, source: "GHSA-p6wc-j7x7-ff3v, MAL-2026-4068", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/semantic-release-pnpm@1.1.4", severity: "critical", confidence: 1.0, source: "GHSA-fh82-9wq3-484r, MAL-2026-4084", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/semantic-release-pnpm@1.2.4", severity: "critical", confidence: 1.0, source: "GHSA-fh82-9wq3-484r, MAL-2026-4084", firstSeen: "2026-07-27" },
  { type: "package", value: "ai-figure@0.5.0", severity: "critical", confidence: 1.0, source: "GHSA-g36c-rqq5-749v, MAL-2026-4126", firstSeen: "2026-07-27" },
  { type: "package", value: "ai-figure@0.6.0", severity: "critical", confidence: 1.0, source: "GHSA-g36c-rqq5-749v, MAL-2026-4126", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/li-editor@1.7.1", severity: "critical", confidence: 1.0, source: "GHSA-jxqv-r6gx-2v7j, MAL-2026-4062", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/li-editor@1.8.1", severity: "critical", confidence: 1.0, source: "GHSA-jxqv-r6gx-2v7j, MAL-2026-4062", firstSeen: "2026-07-27" },
  { type: "package", value: "gantt-for-react@0.3.0", severity: "critical", confidence: 1.0, source: "GHSA-v2mr-5wmj-q99m, MAL-2026-4135", firstSeen: "2026-07-27" },
  { type: "package", value: "gantt-for-react@0.4.0", severity: "critical", confidence: 1.0, source: "GHSA-v2mr-5wmj-q99m, MAL-2026-4135", firstSeen: "2026-07-27" },
  { type: "package", value: "claude-code-base-action@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-3x98-842h-2764, MAL-2026-3811", firstSeen: "2026-07-27" },
  { type: "package", value: "claude-code-base-action@2.2.2", severity: "critical", confidence: 1.0, source: "GHSA-3x98-842h-2764, MAL-2026-3811", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-scene@2.26.10", severity: "critical", confidence: 1.0, source: "GHSA-pcxj-8wqv-58m4, MAL-2026-4050", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-scene@2.27.10", severity: "critical", confidence: 1.0, source: "GHSA-pcxj-8wqv-58m4, MAL-2026-4050", firstSeen: "2026-07-27" },
  { type: "package", value: "apex-connector@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-h523-58g3-c5vg, MAL-2026-3816", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/x6-components@0.11.7", severity: "critical", confidence: 1.0, source: "GHSA-qcw9-7qh9-h2m3, MAL-2026-4100", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/x6-components@0.12.7", severity: "critical", confidence: 1.0, source: "GHSA-qcw9-7qh9-h2m3, MAL-2026-4100", firstSeen: "2026-07-27" },
  { type: "package", value: "@apps-home-dashboard/events@11.9.1", severity: "critical", confidence: 1.0, source: "GHSA-cjw9-49j6-f3rw, MAL-2026-4160", firstSeen: "2026-07-27" },
  { type: "package", value: "@cap-js/openapi@1.4.1", severity: "critical", confidence: 1.0, source: "GHSA-qj5h-p6mj-66pf, MAL-2026-4161", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/s2-react-components@2.2.2", severity: "critical", confidence: 1.0, source: "GHSA-fm6r-v262-pv5x, MAL-2026-4079", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/s2-react-components@2.3.2", severity: "critical", confidence: 1.0, source: "GHSA-fm6r-v262-pv5x, MAL-2026-4079", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-mapkit@0.6.0", severity: "critical", confidence: 1.0, source: "GHSA-27q6-j7gx-6f8c, MAL-2026-4044", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-mapkit@0.7.0", severity: "critical", confidence: 1.0, source: "GHSA-27q6-j7gx-6f8c, MAL-2026-4044", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-extension-g-layer@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-jmqp-4384-6rv6, MAL-2026-4040", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-extension-g-layer@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-jmqp-4384-6rv6, MAL-2026-4040", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/hierarchy@0.8.1", severity: "critical", confidence: 1.0, source: "GHSA-vcpf-f8qv-hqf6, MAL-2026-4027", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/hierarchy@0.9.1", severity: "critical", confidence: 1.0, source: "GHSA-vcpf-f8qv-hqf6, MAL-2026-4027", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/github-config-cli@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-m34q-fh55-gxcc, MAL-2026-4018", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/github-config-cli@0.3.0", severity: "critical", confidence: 1.0, source: "GHSA-m34q-fh55-gxcc, MAL-2026-4018", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-theme-antd@0.7.11", severity: "critical", confidence: 1.0, source: "GHSA-7ppw-hc3r-gj53, MAL-2026-4017", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-theme-antd@0.8.11", severity: "critical", confidence: 1.0, source: "GHSA-7ppw-hc3r-gj53, MAL-2026-4017", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-xlab@0.2.30", severity: "critical", confidence: 1.0, source: "GHSA-36gc-9c89-8g8v, MAL-2026-4010", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-xlab@0.3.30", severity: "critical", confidence: 1.0, source: "GHSA-36gc-9c89-8g8v, MAL-2026-4010", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-map@2.26.10", severity: "critical", confidence: 1.0, source: "GHSA-fgfq-w3p9-3jxh, MAL-2026-4043", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-map@2.27.10", severity: "critical", confidence: 1.0, source: "GHSA-fgfq-w3p9-3jxh, MAL-2026-4043", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-cli@1.3.11", severity: "critical", confidence: 1.0, source: "GHSA-pf8g-q4hp-r46f, MAL-2026-4011", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-cli@1.4.11", severity: "critical", confidence: 1.0, source: "GHSA-pf8g-q4hp-r46f, MAL-2026-4011", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-mock-data@1.1.5", severity: "critical", confidence: 1.0, source: "GHSA-f5pf-h3hg-693v, MAL-2026-4013", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-mock-data@1.2.5", severity: "critical", confidence: 1.0, source: "GHSA-f5pf-h3hg-693v, MAL-2026-4013", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/interaction@0.2.5", severity: "critical", confidence: 1.0, source: "GHSA-f8fc-v3qj-h7gg, MAL-2026-4030", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/interaction@0.3.5", severity: "critical", confidence: 1.0, source: "GHSA-f8fc-v3qj-h7gg, MAL-2026-4030", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-editor@1.2.13", severity: "critical", confidence: 1.0, source: "GHSA-x9vq-gr6x-v35j, MAL-2026-4039", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/l7-editor@1.3.13", severity: "critical", confidence: 1.0, source: "GHSA-x9vq-gr6x-v35j, MAL-2026-4039", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-sdk-app@1.3.10", severity: "critical", confidence: 1.0, source: "GHSA-c3q3-8jgv-87v5, MAL-2026-4016", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-sdk-app@1.4.10", severity: "critical", confidence: 1.0, source: "GHSA-c3q3-8jgv-87v5, MAL-2026-4016", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-sdk@3.1.0", severity: "critical", confidence: 1.0, source: "GHSA-grcj-f88x-xp63, MAL-2026-4015", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-sdk@3.2.0", severity: "critical", confidence: 1.0, source: "GHSA-grcj-f88x-xp63, MAL-2026-4015", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-public-data@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-m96f-gv5h-rfxh, MAL-2026-4014", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-public-data@1.2.1", severity: "critical", confidence: 1.0, source: "GHSA-m96f-gv5h-rfxh, MAL-2026-4014", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-wx@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-8p28-x8c7-79fq, MAL-2026-3997", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-wx@0.2.1", severity: "critical", confidence: 1.0, source: "GHSA-8p28-x8c7-79fq, MAL-2026-3997", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-neo4j@2.2.15", severity: "critical", confidence: 1.0, source: "GHSA-62vq-xjgj-8hh9, MAL-2026-4006", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-neo4j@2.3.15", severity: "critical", confidence: 1.0, source: "GHSA-62vq-xjgj-8hh9, MAL-2026-4006", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-tugraph-analytics@0.3.15", severity: "critical", confidence: 1.0, source: "GHSA-w792-8wjm-g8q7, MAL-2026-4009", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-tugraph-analytics@0.4.15", severity: "critical", confidence: 1.0, source: "GHSA-w792-8wjm-g8q7, MAL-2026-4009", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-galaxybase@1.3.15", severity: "critical", confidence: 1.0, source: "GHSA-27m2-633c-pw2f, MAL-2026-4002", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-galaxybase@1.4.15", severity: "critical", confidence: 1.0, source: "GHSA-27m2-633c-pw2f, MAL-2026-4002", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-janusgraph@1.2.15", severity: "critical", confidence: 1.0, source: "GHSA-fqw9-vjfp-5hqc, MAL-2026-4005", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-janusgraph@1.3.15", severity: "critical", confidence: 1.0, source: "GHSA-fqw9-vjfp-5hqc, MAL-2026-4005", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-algorithm@2.4.19", severity: "critical", confidence: 1.0, source: "GHSA-4cw9-4w5q-cv9v, MAL-2026-4000", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-algorithm@2.5.19", severity: "critical", confidence: 1.0, source: "GHSA-4cw9-4w5q-cv9v, MAL-2026-4000", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-tugraph@2.2.15", severity: "critical", confidence: 1.0, source: "GHSA-3hj3-73wg-w25f, MAL-2026-4008", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-tugraph@2.3.15", severity: "critical", confidence: 1.0, source: "GHSA-3hj3-73wg-w25f, MAL-2026-4008", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-scene@2.3.21", severity: "critical", confidence: 1.0, source: "GHSA-mgfj-f4wf-c5vm, MAL-2026-4007", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-scene@2.4.21", severity: "critical", confidence: 1.0, source: "GHSA-mgfj-f4wf-c5vm, MAL-2026-4007", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-hugegraph@1.2.15", severity: "critical", confidence: 1.0, source: "GHSA-4xjj-8x22-f2mm, MAL-2026-4004", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-hugegraph@1.3.15", severity: "critical", confidence: 1.0, source: "GHSA-4xjj-8x22-f2mm, MAL-2026-4004", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gatsby-theme@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-hv72-467c-8pwg, MAL-2026-3998", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gatsby-theme@0.3.0", severity: "critical", confidence: 1.0, source: "GHSA-hv72-467c-8pwg, MAL-2026-3998", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-graphscope@2.2.15", severity: "critical", confidence: 1.0, source: "GHSA-xxcr-3pm7-8rhh, MAL-2026-4003", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-graphscope@2.3.15", severity: "critical", confidence: 1.0, source: "GHSA-xxcr-3pm7-8rhh, MAL-2026-4003", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-basic@2.5.40", severity: "critical", confidence: 1.0, source: "GHSA-rfxr-237g-2fr7, MAL-2026-4001", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/gi-assets-basic@2.6.40", severity: "critical", confidence: 1.0, source: "GHSA-rfxr-237g-2fr7, MAL-2026-4001", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g-webgpu-unitchart@0.6.1", severity: "critical", confidence: 1.0, source: "GHSA-prqh-qx4p-m4jw, MAL-2026-3972", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g-webgpu-unitchart@0.7.1", severity: "critical", confidence: 1.0, source: "GHSA-prqh-qx4p-m4jw, MAL-2026-3972", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-element@0.9.25", severity: "critical", confidence: 1.0, source: "GHSA-gp4r-64q7-rx37, MAL-2026-3987", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-element@0.10.25", severity: "critical", confidence: 1.0, source: "GHSA-gp4r-64q7-rx37, MAL-2026-3987", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g-webgpu-raytracer@0.6.1", severity: "critical", confidence: 1.0, source: "GHSA-fhp2-qp3q-7jj4, MAL-2026-3971", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g-webgpu-raytracer@0.7.1", severity: "critical", confidence: 1.0, source: "GHSA-fhp2-qp3q-7jj4, MAL-2026-3971", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-plugin@0.9.25", severity: "critical", confidence: 1.0, source: "GHSA-8mwh-2297-272x, MAL-2026-3992", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-plugin@0.10.25", severity: "critical", confidence: 1.0, source: "GHSA-8mwh-2297-272x, MAL-2026-3992", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-plugin-map-view@0.1.4", severity: "critical", confidence: 1.0, source: "GHSA-mhvm-hmc7-x8xc, MAL-2026-3993", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-plugin-map-view@0.2.4", severity: "critical", confidence: 1.0, source: "GHSA-mhvm-hmc7-x8xc, MAL-2026-3993", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g2-ssr@0.3.0", severity: "critical", confidence: 1.0, source: "GHSA-j3vj-v6mr-hxvp, MAL-2026-3979", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g2-ssr@0.4.0", severity: "critical", confidence: 1.0, source: "GHSA-j3vj-v6mr-hxvp, MAL-2026-3979", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g-webgl-compute@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-mc79-gcgw-jg6h, MAL-2026-3966", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g-webgl-compute@0.2.1", severity: "critical", confidence: 1.0, source: "GHSA-mc79-gcgw-jg6h, MAL-2026-3966", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-mobile@0.2.2", severity: "critical", confidence: 1.0, source: "GHSA-2vpg-jvrh-ffcq, MAL-2026-3990", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-mobile@0.3.2", severity: "critical", confidence: 1.0, source: "GHSA-2vpg-jvrh-ffcq, MAL-2026-3990", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-cli@0.1.4", severity: "critical", confidence: 1.0, source: "GHSA-jx6x-93cv-8j2f, MAL-2026-3984", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-cli@0.2.4", severity: "critical", confidence: 1.0, source: "GHSA-jx6x-93cv-8j2f, MAL-2026-3984", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-extension-3d@0.2.23", severity: "critical", confidence: 1.0, source: "GHSA-pphh-78gq-q7xc, MAL-2026-3988", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-extension-3d@0.3.23", severity: "critical", confidence: 1.0, source: "GHSA-pphh-78gq-q7xc, MAL-2026-3988", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-alipay@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-g4fm-25p9-p368, MAL-2026-3983", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g6-alipay@0.2.1", severity: "critical", confidence: 1.0, source: "GHSA-g4fm-25p9-p368, MAL-2026-3983", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g-webgpu-compiler@0.8.2", severity: "critical", confidence: 1.0, source: "GHSA-ww2q-9pv7-p87q, MAL-2026-3968", firstSeen: "2026-07-27" },
  { type: "package", value: "@antv/g-webgpu-compiler@0.9.2", severity: "critical", confidence: 1.0, source: "GHSA-ww2q-9pv7-p87q, MAL-2026-3968", firstSeen: "2026-07-27" },
  { type: "package", value: "paysafe-gbp-virtual-terminal-lib-fe@3.1.13", severity: "critical", confidence: 1.0, source: "GHSA-w52w-574h-9jjh, MAL-2026-4165", firstSeen: "2026-07-27" },
  { type: "package", value: "paysafe-gbp-virtual-terminal-lib-fe@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-w52w-574h-9jjh, MAL-2026-4165", firstSeen: "2026-07-27" },
  { type: "package", value: "sickle-wrapper@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-q9hg-rjqx-w978, MAL-2026-4178", firstSeen: "2026-07-27" },
  { type: "package", value: "vfat-tools@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mxq3-vfh7-9h3j, MAL-2026-4179", firstSeen: "2026-07-27" },
  { type: "package", value: "pretty-logger-utils@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jfcj-69ch-v65w, MAL-2026-4197", firstSeen: "2026-07-27" },
  { type: "package", value: "pinno-loggers@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-hxwm-gvm7-fq2q, MAL-2026-4196", firstSeen: "2026-07-27" },
  { type: "package", value: "your-unique-package-name1@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wc98-w59p-wwh4, MAL-2026-4737", firstSeen: "2026-07-27" },
  { type: "package", value: "yessir-node@2.2.7", severity: "critical", confidence: 1.0, source: "GHSA-3gc3-2jgx-jcwp, MAL-2026-4736", firstSeen: "2026-07-27" },
  { type: "package", value: "xy-ai-chat@0.0.34", severity: "critical", confidence: 1.0, source: "GHSA-vjg5-jmpf-7994, MAL-2026-4735", firstSeen: "2026-07-27" },
  { type: "package", value: "xy-ai-chat@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-vjg5-jmpf-7994, MAL-2026-4735", firstSeen: "2026-07-27" },
  { type: "package", value: "wrld-dev@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-c4wx-mhpg-qpf5, MAL-2026-4733", firstSeen: "2026-07-27" },
  { type: "package", value: "tax4all-components@0.1.26", severity: "critical", confidence: 0.9, source: "GHSA-228g-vcmq-qp4q", firstSeen: "2026-07-27" },
  { type: "package", value: "sparkecoder@0.1.104", severity: "critical", confidence: 1.0, source: "GHSA-r795-5c6p-x827, MAL-2026-4673", firstSeen: "2026-07-27" },

  // Imported from GitHub Advisory Database (2026-07-15) - see docs/threat-feed-sources.md
  { type: "package", value: "@omniwatch-wick/cli", severity: "critical", confidence: 1.0, source: "GHSA-x4cm-7r6h-pjg3, MAL-2026-10486", firstSeen: "2026-07-29" },
  { type: "package", value: "chain-manager", severity: "critical", confidence: 0.9, source: "GHSA-257g-ggr2-j398", firstSeen: "2026-07-29" },
  { type: "package", value: "chain-analyze", severity: "critical", confidence: 1.0, source: "GHSA-vmj5-cm6w-jrgj, MAL-2026-11133", firstSeen: "2026-07-29" },
  { type: "package", value: "@bowozzz/baileys", severity: "critical", confidence: 0.9, source: "GHSA-f9vh-885g-hv2f", firstSeen: "2026-07-29" },
  { type: "package", value: "toll_free@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-8grw-9ghp-8r94, MAL-2026-11159", firstSeen: "2026-07-29" },
  { type: "package", value: "blots@2.1.0", severity: "critical", confidence: 1.0, source: "GHSA-m24q-pqxm-qhqw, MAL-2026-11158", firstSeen: "2026-07-29" },
  { type: "package", value: "@mypwn/hawkeye@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-28p4-h97c-j397, MAL-2026-11157", firstSeen: "2026-07-29" },
  { type: "package", value: "@joyfill/layouts@0.1.2-2773.beta.0", severity: "critical", confidence: 1.0, source: "GHSA-887f-rwr9-wp54, MAL-2026-11161", firstSeen: "2026-07-28" },
  { type: "package", value: "@joyfill/components@4.0.0-rc24-2773-beta.4", severity: "critical", confidence: 1.0, source: "GHSA-x4p3-wjxx-m4x5, MAL-2026-11160", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:karpatkit@2.1.0", severity: "critical", confidence: 1.0, source: "GHSA-7qg7-6pg7-g63q, MAL-2026-11048", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:karpatkit@2.1.1", severity: "critical", confidence: 1.0, source: "GHSA-7qg7-6pg7-g63q, MAL-2026-11048", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:dev-helper-bg@0.1.3", severity: "critical", confidence: 1.0, source: "GHSA-pcf6-hwj2-m3vw, MAL-2026-10992", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:dev-helper-bg@0.1.4", severity: "critical", confidence: 1.0, source: "GHSA-pcf6-hwj2-m3vw, MAL-2026-10992", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:dev-helper-bg@0.1.6", severity: "critical", confidence: 1.0, source: "GHSA-pcf6-hwj2-m3vw, MAL-2026-10992", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:dev-helper-bg@0.1.7", severity: "critical", confidence: 1.0, source: "GHSA-pcf6-hwj2-m3vw, MAL-2026-10992", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:mrmustard@0.7.4", severity: "critical", confidence: 1.0, source: "GHSA-7h9m-3hvr-pjg2, MAL-2026-11049", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:vtranalytic@9.0.1", severity: "critical", confidence: 1.0, source: "GHSA-29jr-g2qh-hj97, MAL-2026-11156", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:karpatkey@2.1.1", severity: "critical", confidence: 1.0, source: "GHSA-v497-gp55-jwxm, MAL-2026-11047", firstSeen: "2026-07-28" },
  { type: "package", value: "pypi:govapkg@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-pxxf-hj67-hjm5, MAL-2026-11031", firstSeen: "2026-07-28" },
  { type: "package", value: "streak-core-math@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-g827-wm64-px2q, MAL-2026-11149", firstSeen: "2026-07-28" },
  { type: "package", value: "simple-probe-utils@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-9j4g-h77m-3g6m, MAL-2026-11147", firstSeen: "2026-07-28" },
  { type: "package", value: "sigchain-js@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-j78w-wm55-982q, MAL-2026-11146", firstSeen: "2026-07-28" },
  { type: "package", value: "streak-daily-lib@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-456x-5qpf-qrrw, MAL-2026-11150", firstSeen: "2026-07-28" },
  { type: "package", value: "rollup-runtime-core-polyfills@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-j877-m36j-5p92, MAL-2026-11145", firstSeen: "2026-07-28" },
  { type: "package", value: "xerohub-discord-voice-v3@3.0.2", severity: "critical", confidence: 1.0, source: "GHSA-xw2v-59xv-3c84, MAL-2026-11155", firstSeen: "2026-07-28" },
  { type: "package", value: "xerohub-discord-voice-v3@3.0.0", severity: "critical", confidence: 1.0, source: "GHSA-xw2v-59xv-3c84, MAL-2026-11155", firstSeen: "2026-07-28" },
  { type: "package", value: "xerohub-discord-voice-v3@3.0.3", severity: "critical", confidence: 1.0, source: "GHSA-xw2v-59xv-3c84, MAL-2026-11155", firstSeen: "2026-07-28" },
  { type: "package", value: "tidal-embed-player@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-gfxj-v4hg-f5h7, MAL-2026-11152", firstSeen: "2026-07-28" },
  { type: "package", value: "text-line-parser@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-hp3v-hcrw-9mf8, MAL-2026-11151", firstSeen: "2026-07-28" },
  { type: "package", value: "xerohub-discord-voice-v2@1.8.0", severity: "critical", confidence: 1.0, source: "GHSA-3h72-42vm-wphp, MAL-2026-11154", firstSeen: "2026-07-28" },
  { type: "package", value: "triage_bot_using_sdkv3@2.0.1", severity: "critical", confidence: 1.0, source: "GHSA-8pwc-32rm-4cgm, MAL-2026-11153", firstSeen: "2026-07-28" },
  { type: "package", value: "streak-core-lib@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7vpc-qq63-xvwj, MAL-2026-11148", firstSeen: "2026-07-28" },
  { type: "package", value: "api-node-sdk@2.1.6", severity: "critical", confidence: 1.0, source: "GHSA-c836-6399-93jv, MAL-2026-11124", firstSeen: "2026-07-28" },
  { type: "package", value: "array-node-utils@1.0.9", severity: "critical", confidence: 1.0, source: "GHSA-gv25-mh5m-p7gp, MAL-2026-11130", firstSeen: "2026-07-28" },
  { type: "package", value: "react-puller@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pg26-7r73-h7pp, MAL-2026-11144", firstSeen: "2026-07-28" },
  { type: "package", value: "jobber-app-template-react@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-j6qc-95jf-9rqf, MAL-2026-11137", firstSeen: "2026-07-28" },
  { type: "package", value: "basic-vite@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-x36g-6hf7-wr48, MAL-2026-11131", firstSeen: "2026-07-28" },
  { type: "package", value: "kordyn@0.9.16", severity: "critical", confidence: 1.0, source: "GHSA-4mhx-3hm9-cfpf, MAL-2026-11139", firstSeen: "2026-07-28" },
  { type: "package", value: "kordyn@0.9.18", severity: "critical", confidence: 1.0, source: "GHSA-4mhx-3hm9-cfpf, MAL-2026-11139", firstSeen: "2026-07-28" },
  { type: "package", value: "app-soda-layer@2.1.6", severity: "critical", confidence: 1.0, source: "GHSA-2q8x-gg6r-p5hg, MAL-2026-11128", firstSeen: "2026-07-28" },
  { type: "package", value: "bianira-ui@1.27.0", severity: "critical", confidence: 1.0, source: "GHSA-w3r2-397p-xcfw, MAL-2026-11132", firstSeen: "2026-07-28" },
  { type: "package", value: "color-convert-helper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-4682-ww49-563f, MAL-2026-11134", firstSeen: "2026-07-28" },
  { type: "package", value: "api-rust-sdk@2.1.6", severity: "critical", confidence: 1.0, source: "GHSA-4hhr-c99m-jq9f, MAL-2026-11125", firstSeen: "2026-07-28" },
  { type: "package", value: "app-svm-layer@2.1.6", severity: "critical", confidence: 1.0, source: "GHSA-7m36-xw8v-8hq9, MAL-2026-11129", firstSeen: "2026-07-28" },
  { type: "package", value: "parallely@10.0.3", severity: "critical", confidence: 1.0, source: "GHSA-mxc4-6gh5-wpvw, MAL-2026-11143", firstSeen: "2026-07-28" },
  { type: "package", value: "json-schema-inspector@1.1.5", severity: "critical", confidence: 1.0, source: "GHSA-m8v5-qxc2-v92m, MAL-2026-11138", firstSeen: "2026-07-28" },
  { type: "package", value: "json-schema-inspector@1.1.7", severity: "critical", confidence: 1.0, source: "GHSA-m8v5-qxc2-v92m, MAL-2026-11138", firstSeen: "2026-07-28" },
  { type: "package", value: "json-schema-inspector@1.1.6", severity: "critical", confidence: 1.0, source: "GHSA-m8v5-qxc2-v92m, MAL-2026-11138", firstSeen: "2026-07-28" },
  { type: "package", value: "json-schema-inspector@1.1.4", severity: "critical", confidence: 1.0, source: "GHSA-m8v5-qxc2-v92m, MAL-2026-11138", firstSeen: "2026-07-28" },
  { type: "package", value: "korvica@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5h49-444p-9g8v, MAL-2026-11140", firstSeen: "2026-07-28" },
  { type: "package", value: "lib-streak-math@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7hfx-rf8h-6j2g, MAL-2026-11141", firstSeen: "2026-07-28" },
  { type: "package", value: "ethers-secure@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-379c-c2fc-xj46, MAL-2026-11135", firstSeen: "2026-07-28" },
  { type: "package", value: "fluid-type-ui@2.0.8", severity: "critical", confidence: 1.0, source: "GHSA-44q9-v3f9-xcx6, MAL-2026-11136", firstSeen: "2026-07-28" },
  { type: "package", value: "node-array-plus@1.0.9", severity: "critical", confidence: 1.0, source: "GHSA-mgw3-3jfq-3gwx, MAL-2026-11142", firstSeen: "2026-07-28" },
  { type: "package", value: "@crbrc/xbt@1.1.2", severity: "critical", confidence: 1.0, source: "GHSA-f3f6-vqm6-jv4v, MAL-2026-11122", firstSeen: "2026-07-28" },
  { type: "package", value: "@crbrc/xbt@1.1.1", severity: "critical", confidence: 1.0, source: "GHSA-f3f6-vqm6-jv4v, MAL-2026-11122", firstSeen: "2026-07-28" },
  { type: "package", value: "@crbrc/xbt@1.2.1", severity: "critical", confidence: 1.0, source: "GHSA-f3f6-vqm6-jv4v, MAL-2026-11122", firstSeen: "2026-07-28" },
  { type: "package", value: "@crbrc/xbt@1.1.3", severity: "critical", confidence: 1.0, source: "GHSA-f3f6-vqm6-jv4v, MAL-2026-11122", firstSeen: "2026-07-28" },
  { type: "package", value: "@crbrc/xbt@1.1.4", severity: "critical", confidence: 1.0, source: "GHSA-f3f6-vqm6-jv4v, MAL-2026-11122", firstSeen: "2026-07-28" },
  { type: "package", value: "@crbrc/xbt@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-f3f6-vqm6-jv4v, MAL-2026-11122", firstSeen: "2026-07-28" },
  { type: "package", value: "@yancyyu/agentcli@1.9.32", severity: "critical", confidence: 1.0, source: "GHSA-wqc4-72w7-qr9g, MAL-2026-11123", firstSeen: "2026-07-28" },
  { type: "package", value: "app-sim-layer@2.1.6", severity: "critical", confidence: 1.0, source: "GHSA-363f-gw2q-m6j5, MAL-2026-11126", firstSeen: "2026-07-28" },
  { type: "package", value: "app-sima-layer@2.1.6", severity: "critical", confidence: 1.0, source: "GHSA-gxmw-r885-6v87, MAL-2026-11127", firstSeen: "2026-07-28" },
  { type: "package", value: "@apexfnd/apex@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-r3xx-75gm-53pm, MAL-2026-11121", firstSeen: "2026-07-28" },
  { type: "package", value: "@apexfnd/apex@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-r3xx-75gm-53pm, MAL-2026-11121", firstSeen: "2026-07-28" },
  { type: "package", value: "@ai_/autoprefixers@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-8hhx-8x59-hr55, MAL-2026-11120", firstSeen: "2026-07-28" },
  { type: "package", value: "postcss-motion-utils", severity: "critical", confidence: 1.0, source: "GHSA-m763-9wch-p9gg, MAL-2026-11168", firstSeen: "2026-07-28" },
  { type: "package", value: "local-config-parser", severity: "critical", confidence: 1.0, source: "GHSA-f463-rm4g-746g, MAL-2026-11167", firstSeen: "2026-07-28" },
  { type: "package", value: "lib-mtop", severity: "critical", confidence: 1.0, source: "GHSA-vrrg-j2c5-mj4v, MAL-2026-11166", firstSeen: "2026-07-28" },
  { type: "package", value: "aone-sandbox", severity: "critical", confidence: 1.0, source: "GHSA-mv5v-q5f3-gf7h, MAL-2026-11164", firstSeen: "2026-07-28" },
  { type: "package", value: "aone-kit", severity: "critical", confidence: 1.0, source: "GHSA-7w6g-48pj-7977, MAL-2026-11162", firstSeen: "2026-07-28" },
  { type: "package", value: "aone-kit-cli", severity: "critical", confidence: 1.0, source: "GHSA-55qq-2qq4-c47g, MAL-2026-11163", firstSeen: "2026-07-28" },
  { type: "package", value: "cloud-config-fetcher", severity: "critical", confidence: 1.0, source: "GHSA-25r8-r3cf-28q4, MAL-2026-11165", firstSeen: "2026-07-28" },
  { type: "package", value: "smart-config-manager", severity: "critical", confidence: 1.0, source: "GHSA-v644-r975-m85m, MAL-2026-11169", firstSeen: "2026-07-28" },
  { type: "package", value: "string-format-kit@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-xqqx-722m-55gr, MAL-2026-11108", firstSeen: "2026-07-28" },
  { type: "package", value: "num-format-helper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jf75-cqhp-mhch, MAL-2026-11107", firstSeen: "2026-07-28" },
  { type: "package", value: "date-sanitize-helper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jj2h-2x77-rrwf, MAL-2026-11106", firstSeen: "2026-07-28" },
  { type: "package", value: "@wagni_bot/web3@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-48gg-v3w4-m38v, MAL-2026-11117", firstSeen: "2026-07-28" },
  { type: "package", value: "@wagni_bot/wagni@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-c324-fqr6-v3cw, MAL-2026-11116", firstSeen: "2026-07-28" },
  { type: "package", value: "@wagni_bot/polygon@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-5w5j-423r-2x73, MAL-2026-11114", firstSeen: "2026-07-28" },
  { type: "package", value: "@wagni_bot/polymarket@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-46gp-xx3g-2cqr, MAL-2026-11115", firstSeen: "2026-07-28" },
  { type: "package", value: "@wagni_bot/opensea@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-c84m-x93c-fwjj, MAL-2026-11113", firstSeen: "2026-07-28" },
  { type: "package", value: "@wagni_bot/metamask@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vg7p-qg4j-56rc, MAL-2026-11112", firstSeen: "2026-07-28" },
  { type: "package", value: "@wagni_bot/hyperliquid@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-35jp-phg5-g2hr, MAL-2026-11111", firstSeen: "2026-07-28" },
  { type: "package", value: "@wagni_bot/bsc@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-r3x3-gxmq-rmhj, MAL-2026-11109", firstSeen: "2026-07-28" },
  { type: "package", value: "@wagni_bot/eth@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-vr92-xmj8-jr8v, MAL-2026-11110", firstSeen: "2026-07-28" },
  { type: "package", value: "json-to-table-util@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-j9fg-prmr-97cw, MAL-2026-11119", firstSeen: "2026-07-28" },
  { type: "package", value: "array-sort-helper@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mx6g-xr3v-fc2f, MAL-2026-11118", firstSeen: "2026-07-28" },
  { type: "package", value: "tempo-components@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-2c5c-pg2w-83fp, MAL-2026-4685", firstSeen: "2026-07-27" },
  { type: "package", value: "swift-optimizer@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-2857-88rw-5pqc, MAL-2026-4677", firstSeen: "2026-07-27" },
  { type: "package", value: "svharness@0.13.5", severity: "critical", confidence: 1.0, source: "GHSA-4v2r-cgqf-hmf4, MAL-2026-4676", firstSeen: "2026-07-27" },
  { type: "package", value: "skipshot-agent@2.0.3", severity: "critical", confidence: 0.9, source: "GHSA-ggw2-wg95-m4gh", firstSeen: "2026-07-27" },
  { type: "package", value: "superacli@1.15.0", severity: "critical", confidence: 1.0, source: "GHSA-7g4m-4fmq-259x, MAL-2026-4674", firstSeen: "2026-07-27" },
  { type: "package", value: "superacli@1.14.0", severity: "critical", confidence: 1.0, source: "GHSA-7g4m-4fmq-259x, MAL-2026-4674", firstSeen: "2026-07-27" },
  { type: "package", value: "seekcode@0.4.4", severity: "critical", confidence: 1.0, source: "GHSA-xj6w-x4p9-6r73, MAL-2026-4667", firstSeen: "2026-07-27" },
  { type: "package", value: "seekcode@0.4.0", severity: "critical", confidence: 1.0, source: "GHSA-xj6w-x4p9-6r73, MAL-2026-4667", firstSeen: "2026-07-27" },
  { type: "package", value: "seekcode@0.4.6", severity: "critical", confidence: 1.0, source: "GHSA-xj6w-x4p9-6r73, MAL-2026-4667", firstSeen: "2026-07-27" },
  { type: "package", value: "secdriven@1.0.8", severity: "critical", confidence: 1.0, source: "GHSA-vf52-4986-52f7, MAL-2026-4263", firstSeen: "2026-07-27" },
  { type: "package", value: "secdriven@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-vf52-4986-52f7, MAL-2026-4263", firstSeen: "2026-07-27" },
  { type: "package", value: "secdriven@1.0.7", severity: "critical", confidence: 1.0, source: "GHSA-vf52-4986-52f7, MAL-2026-4263", firstSeen: "2026-07-27" },
  { type: "package", value: "tubebrain@0.1.10", severity: "critical", confidence: 0.9, source: "GHSA-2j5r-4jq7-7548", firstSeen: "2026-07-27" },
  { type: "package", value: "supership-scan@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h4qv-p8p2-5227, MAL-2026-4675", firstSeen: "2026-07-27" },
  { type: "package", value: "sysnode@1.0.25", severity: "critical", confidence: 1.0, source: "GHSA-fc7r-grx4-fpr9, MAL-2026-4678", firstSeen: "2026-07-27" },
  { type: "package", value: "whiteboard-agent@1.4.23", severity: "critical", confidence: 1.0, source: "GHSA-w6cx-9c8h-cffm, MAL-2026-4729", firstSeen: "2026-07-27" },
  { type: "package", value: "whiteboard-agent@1.4.24", severity: "critical", confidence: 1.0, source: "GHSA-w6cx-9c8h-cffm, MAL-2026-4729", firstSeen: "2026-07-27" },
  { type: "package", value: "wml-core@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-gmfx-rwvp-x2jx, MAL-2026-4731", firstSeen: "2026-07-27" },
  { type: "package", value: "venturo-playwright-runner@1.0.12", severity: "critical", confidence: 0.9, source: "GHSA-662j-hjw7-8jf2", firstSeen: "2026-07-27" },
  { type: "package", value: "venturo-playwright-runner@1.0.8", severity: "critical", confidence: 0.9, source: "GHSA-662j-hjw7-8jf2", firstSeen: "2026-07-27" },
  { type: "package", value: "venturo-playwright-runner@1.0.6", severity: "critical", confidence: 0.9, source: "GHSA-662j-hjw7-8jf2", firstSeen: "2026-07-27" },
  { type: "package", value: "venturo-playwright-runner@1.0.9", severity: "critical", confidence: 0.9, source: "GHSA-662j-hjw7-8jf2", firstSeen: "2026-07-27" },
  { type: "package", value: "veteran-proxy@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-h5g4-rg26-99h8, MAL-2026-4704", firstSeen: "2026-07-27" },
  { type: "package", value: "tempo-shared-modules@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-q48j-v4r5-5px8, MAL-2026-4688", firstSeen: "2026-07-27" },
  { type: "package", value: "tempo-shared-modules@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-q48j-v4r5-5px8, MAL-2026-4688", firstSeen: "2026-07-27" },
  { type: "package", value: "tempo-shared-modules@99.0.2", severity: "critical", confidence: 1.0, source: "GHSA-q48j-v4r5-5px8, MAL-2026-4688", firstSeen: "2026-07-27" },
  { type: "package", value: "vestibulect@0.0.1", severity: "critical", confidence: 0.9, source: "GHSA-x499-9q4p-8h85", firstSeen: "2026-07-27" },
  { type: "package", value: "tdpilot@1.6.15", severity: "critical", confidence: 0.9, source: "GHSA-7pwh-9692-wgpg", firstSeen: "2026-07-27" },
  { type: "package", value: "tdpilot@1.6.16", severity: "critical", confidence: 0.9, source: "GHSA-7pwh-9692-wgpg", firstSeen: "2026-07-27" },
  { type: "package", value: "share-anything-cli@0.5.6", severity: "critical", confidence: 0.9, source: "GHSA-grg8-g277-985h", firstSeen: "2026-07-27" },
  { type: "package", value: "workrally@2.4.0", severity: "critical", confidence: 0.9, source: "GHSA-7jv7-3gmh-2654", firstSeen: "2026-07-27" },
  { type: "package", value: "vite-json-config@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-w6rm-q7cv-8pqx, MAL-2026-4705", firstSeen: "2026-07-27" },
  { type: "package", value: "venturo-playwright@1.0.13", severity: "critical", confidence: 0.9, source: "GHSA-4g99-4p9c-pjq8", firstSeen: "2026-07-27" },
  { type: "package", value: "use-context-selector-tony@2.0.5", severity: "critical", confidence: 0.9, source: "GHSA-9rcf-g6vx-jpmg", firstSeen: "2026-07-27" },
  { type: "package", value: "thevoid@0.1.4", severity: "critical", confidence: 1.0, source: "GHSA-fxrw-rv9r-j8cv, MAL-2026-4692", firstSeen: "2026-07-27" },
  { type: "package", value: "thevoid@0.1.3", severity: "critical", confidence: 1.0, source: "GHSA-fxrw-rv9r-j8cv, MAL-2026-4692", firstSeen: "2026-07-27" },
  { type: "package", value: "stripe-internal-utils@8.2.0", severity: "critical", confidence: 1.0, source: "GHSA-xpmw-x72r-79gv, MAL-2026-4184", firstSeen: "2026-07-27" },
  { type: "package", value: "vite-plugin-css-blend@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-c762-7qmx-937p, MAL-2026-4706", firstSeen: "2026-07-27" },
  { type: "package", value: "walmart-shared-modules@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-jm93-76cq-hmvv, MAL-2026-4710", firstSeen: "2026-07-27" },
  { type: "package", value: "twokey@1.0.11", severity: "critical", confidence: 1.0, source: "GHSA-v77g-w8fm-5g3v, MAL-2026-4697", firstSeen: "2026-07-27" },
  { type: "package", value: "twokey@1.0.8", severity: "critical", confidence: 1.0, source: "GHSA-v77g-w8fm-5g3v, MAL-2026-4697", firstSeen: "2026-07-27" },
  { type: "package", value: "twokey@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-v77g-w8fm-5g3v, MAL-2026-4697", firstSeen: "2026-07-27" },
  { type: "package", value: "twokey@1.0.10", severity: "critical", confidence: 1.0, source: "GHSA-v77g-w8fm-5g3v, MAL-2026-4697", firstSeen: "2026-07-27" },
  { type: "package", value: "twokey@1.0.7", severity: "critical", confidence: 1.0, source: "GHSA-v77g-w8fm-5g3v, MAL-2026-4697", firstSeen: "2026-07-27" },
  { type: "package", value: "tempo-modules@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-qw78-ggcp-wvqx, MAL-2026-4687", firstSeen: "2026-07-27" },
  { type: "package", value: "uolcs-host-uol-anuncios-fe@99.99.99", severity: "critical", confidence: 1.0, source: "GHSA-7m9p-mh3w-x56r, MAL-2026-4185", firstSeen: "2026-07-27" },
  { type: "package", value: "system-user-identifier-cli@3.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w7hf-hm35-wxvw, MAL-2026-4679", firstSeen: "2026-07-27" },
  { type: "package", value: "system-user-identifier-cli@7.0.1", severity: "critical", confidence: 1.0, source: "GHSA-w7hf-hm35-wxvw, MAL-2026-4679", firstSeen: "2026-07-27" },
  { type: "package", value: "system-user-identifier-cli@6.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w7hf-hm35-wxvw, MAL-2026-4679", firstSeen: "2026-07-27" },
  { type: "package", value: "system-user-identifier-cli@2.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w7hf-hm35-wxvw, MAL-2026-4679", firstSeen: "2026-07-27" },
  { type: "package", value: "system-user-identifier-cli@4.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w7hf-hm35-wxvw, MAL-2026-4679", firstSeen: "2026-07-27" },
  { type: "package", value: "system-user-identifier-cli@7.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w7hf-hm35-wxvw, MAL-2026-4679", firstSeen: "2026-07-27" },
  { type: "package", value: "system-user-identifier-cli@5.0.0", severity: "critical", confidence: 1.0, source: "GHSA-w7hf-hm35-wxvw, MAL-2026-4679", firstSeen: "2026-07-27" },
  { type: "package", value: "wml-components@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-v8jm-fwq5-6xhm, MAL-2026-4730", firstSeen: "2026-07-27" },
  { type: "package", value: "wallet-agent-ai@1.0.1", severity: "critical", confidence: 0.9, source: "GHSA-8vh7-62xq-cwhv", firstSeen: "2026-07-27" },
  { type: "package", value: "wallet-agent-ai@1.0.2", severity: "critical", confidence: 0.9, source: "GHSA-8vh7-62xq-cwhv", firstSeen: "2026-07-27" },
  { type: "package", value: "tempo-layout@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-9x7q-v3r8-jw67, MAL-2026-4686", firstSeen: "2026-07-27" },
  { type: "package", value: "tempo-layout@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9x7q-v3r8-jw67, MAL-2026-4686", firstSeen: "2026-07-27" },
  { type: "package", value: "tempo-layout@99.0.2", severity: "critical", confidence: 1.0, source: "GHSA-9x7q-v3r8-jw67, MAL-2026-4686", firstSeen: "2026-07-27" },
  { type: "package", value: "turing-sdk@1.1.3", severity: "critical", confidence: 1.0, source: "GHSA-gprq-46gr-9qc4, MAL-2026-4696", firstSeen: "2026-07-27" },
  { type: "package", value: "shiroai@2.0.6", severity: "critical", confidence: 1.0, source: "GHSA-6q77-46hr-j6hm, MAL-2026-4669", firstSeen: "2026-07-27" },
  { type: "package", value: "shiroai@2.1.0", severity: "critical", confidence: 1.0, source: "GHSA-6q77-46hr-j6hm, MAL-2026-4669", firstSeen: "2026-07-27" },
  { type: "package", value: "shiroai@2.0.4", severity: "critical", confidence: 1.0, source: "GHSA-6q77-46hr-j6hm, MAL-2026-4669", firstSeen: "2026-07-27" },
  { type: "package", value: "shiroai@2.2.0", severity: "critical", confidence: 1.0, source: "GHSA-6q77-46hr-j6hm, MAL-2026-4669", firstSeen: "2026-07-27" },
  { type: "package", value: "shiroai@2.0.7", severity: "critical", confidence: 1.0, source: "GHSA-6q77-46hr-j6hm, MAL-2026-4669", firstSeen: "2026-07-27" },
  { type: "package", value: "shiroai@2.0.5", severity: "critical", confidence: 1.0, source: "GHSA-6q77-46hr-j6hm, MAL-2026-4669", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.35", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.31", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.16", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.33", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.43", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.21", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.32", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.44", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.39", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.11", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.41", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.7", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.28", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.36", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.40", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.29", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.19", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.42", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.30", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.15", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.8", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.38", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-pentest-rce@1.0.37", severity: "critical", confidence: 1.0, source: "GHSA-2fxc-4jrc-5vff, MAL-2026-4617", firstSeen: "2026-07-27" },
  { type: "package", value: "promptbook-cli@0.1.0", severity: "critical", confidence: 0.9, source: "GHSA-vfg6-5p98-p9q6", firstSeen: "2026-07-27" },
  { type: "package", value: "prjct-cli@2.21.0", severity: "critical", confidence: 0.9, source: "GHSA-hf4g-3jw3-q6p9", firstSeen: "2026-07-27" },
  { type: "package", value: "polygon-toolkit-validate@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-r4v4-vv29-5h6w, MAL-2026-4642", firstSeen: "2026-07-27" },
  { type: "package", value: "osep-react-antd@10.10.11", severity: "critical", confidence: 1.0, source: "GHSA-9959-m74g-fp23, MAL-2026-4634", firstSeen: "2026-07-27" },
  { type: "package", value: "prisma-client-python@0.3.8", severity: "critical", confidence: 0.9, source: "GHSA-h3j4-88mp-vcjg", firstSeen: "2026-07-27" },
  { type: "package", value: "private-next-pages@9.0.5", severity: "critical", confidence: 1.0, source: "GHSA-6ppv-hrcv-rhfr, MAL-2026-4193", firstSeen: "2026-07-27" },
  { type: "package", value: "pg-expense-example@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mcfc-jpwh-gh35, MAL-2026-4639", firstSeen: "2026-07-27" },
  { type: "package", value: "npm-builderio-qwik-poc@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-vjp8-qjpm-4qv6, MAL-2026-4623", firstSeen: "2026-07-27" },
  { type: "package", value: "npm-builderio-qwik-poc@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-vjp8-qjpm-4qv6, MAL-2026-4623", firstSeen: "2026-07-27" },
  { type: "package", value: "npm-builderio-qwik-poc@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-vjp8-qjpm-4qv6, MAL-2026-4623", firstSeen: "2026-07-27" },
  { type: "package", value: "npm-builderio-qwik-poc@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-vjp8-qjpm-4qv6, MAL-2026-4623", firstSeen: "2026-07-27" },
  { type: "package", value: "npm-builderio-qwik-poc@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-vjp8-qjpm-4qv6, MAL-2026-4623", firstSeen: "2026-07-27" },
  { type: "package", value: "peertube-plugin-google-analytics-js@0.0.1", severity: "critical", confidence: 0.9, source: "GHSA-xfjj-g24w-xw5h", firstSeen: "2026-07-27" },
  { type: "package", value: "rapyd-client@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-r2rj-pp6r-42jc, MAL-2026-4658", firstSeen: "2026-07-27" },
  { type: "package", value: "qaq-core-util-v2@1.1.68", severity: "critical", confidence: 1.0, source: "GHSA-qmrh-35wx-h7hh, MAL-2026-4653", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.591", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.593", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.596", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.594", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.590", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.588", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.595", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.592", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.587", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "open-agents-ai@0.187.589", severity: "critical", confidence: 0.9, source: "GHSA-p8h8-98f4-7cj3", firstSeen: "2026-07-27" },
  { type: "package", value: "rendezvous-js@9.9.11", severity: "critical", confidence: 1.0, source: "GHSA-cj5p-rpr4-5cvh, MAL-2026-4662", firstSeen: "2026-07-27" },
  { type: "package", value: "qazaq-cli@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-m7g6-9jrr-q687, MAL-2026-4654", firstSeen: "2026-07-27" },
  { type: "package", value: "promptbook-mcp@0.1.0", severity: "critical", confidence: 0.9, source: "GHSA-vmvx-c3j5-rhw5", firstSeen: "2026-07-27" },
  { type: "package", value: "pulse-axios@1.17.2", severity: "critical", confidence: 1.0, source: "GHSA-pp29-ghv9-7cvv, MAL-2026-4651", firstSeen: "2026-07-27" },
  { type: "package", value: "pulse-axios@1.17.1", severity: "critical", confidence: 1.0, source: "GHSA-pp29-ghv9-7cvv, MAL-2026-4651", firstSeen: "2026-07-27" },
  { type: "package", value: "pulse-axios@1.16.1", severity: "critical", confidence: 1.0, source: "GHSA-pp29-ghv9-7cvv, MAL-2026-4651", firstSeen: "2026-07-27" },
  { type: "package", value: "platform-tempo@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-43pr-3r3m-29jj, MAL-2026-4641", firstSeen: "2026-07-27" },
  { type: "package", value: "polymarket-clob-client@2.1.1", severity: "critical", confidence: 1.0, source: "GHSA-vhch-jmqr-r965, MAL-2026-4643", firstSeen: "2026-07-27" },
  { type: "package", value: "onboardconnect-agent@1.1.24", severity: "critical", confidence: 0.9, source: "GHSA-636f-38jr-28xc", firstSeen: "2026-07-27" },
  { type: "package", value: "onboardconnect-agent@1.1.31", severity: "critical", confidence: 0.9, source: "GHSA-636f-38jr-28xc", firstSeen: "2026-07-27" },
  { type: "package", value: "onboardconnect-agent@1.1.22", severity: "critical", confidence: 0.9, source: "GHSA-636f-38jr-28xc", firstSeen: "2026-07-27" },
  { type: "package", value: "onboardconnect-agent@1.1.15", severity: "critical", confidence: 0.9, source: "GHSA-636f-38jr-28xc", firstSeen: "2026-07-27" },
  { type: "package", value: "onboardconnect-agent@1.1.16", severity: "critical", confidence: 0.9, source: "GHSA-636f-38jr-28xc", firstSeen: "2026-07-27" },
  { type: "package", value: "onboardconnect-agent@1.1.21", severity: "critical", confidence: 0.9, source: "GHSA-636f-38jr-28xc", firstSeen: "2026-07-27" },
  { type: "package", value: "onboardconnect-agent@1.1.5", severity: "critical", confidence: 0.9, source: "GHSA-636f-38jr-28xc", firstSeen: "2026-07-27" },
  { type: "package", value: "onboardconnect-agent@1.1.32", severity: "critical", confidence: 0.9, source: "GHSA-636f-38jr-28xc", firstSeen: "2026-07-27" },
  { type: "package", value: "onboardconnect-agent@1.1.25", severity: "critical", confidence: 0.9, source: "GHSA-636f-38jr-28xc", firstSeen: "2026-07-27" },
  { type: "package", value: "openmct-couch-plugin@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-296j-3c4q-4v4h, MAL-2026-4629", firstSeen: "2026-07-27" },
  { type: "package", value: "openmct-couch-plugin@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-296j-3c4q-4v4h, MAL-2026-4629", firstSeen: "2026-07-27" },
  { type: "package", value: "openmct-couch-plugin@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-296j-3c4q-4v4h, MAL-2026-4629", firstSeen: "2026-07-27" },
  { type: "package", value: "omnius@1.0.153", severity: "critical", confidence: 0.9, source: "GHSA-fv96-22xj-qgjm", firstSeen: "2026-07-27" },
  { type: "package", value: "omnius@1.0.155", severity: "critical", confidence: 0.9, source: "GHSA-fv96-22xj-qgjm", firstSeen: "2026-07-27" },
  { type: "package", value: "omnius@1.0.147", severity: "critical", confidence: 0.9, source: "GHSA-fv96-22xj-qgjm", firstSeen: "2026-07-27" },
  { type: "package", value: "omnius@1.0.136", severity: "critical", confidence: 0.9, source: "GHSA-fv96-22xj-qgjm", firstSeen: "2026-07-27" },
  { type: "package", value: "omnius@1.0.145", severity: "critical", confidence: 0.9, source: "GHSA-fv96-22xj-qgjm", firstSeen: "2026-07-27" },
  { type: "package", value: "omnius@1.0.148", severity: "critical", confidence: 0.9, source: "GHSA-fv96-22xj-qgjm", firstSeen: "2026-07-27" },
  { type: "package", value: "omnius@1.0.140", severity: "critical", confidence: 0.9, source: "GHSA-fv96-22xj-qgjm", firstSeen: "2026-07-27" },
  { type: "package", value: "omnius@1.0.141", severity: "critical", confidence: 0.9, source: "GHSA-fv96-22xj-qgjm", firstSeen: "2026-07-27" },
  { type: "package", value: "omnius@1.0.157", severity: "critical", confidence: 0.9, source: "GHSA-fv96-22xj-qgjm", firstSeen: "2026-07-27" },
  { type: "package", value: "rdflib@2.3.7", severity: "critical", confidence: 0.9, source: "GHSA-8hph-3cmg-6cx6", firstSeen: "2026-07-27" },
  { type: "package", value: "pewter-constants@9999.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9xp5-fhj8-v3j4, MAL-2026-4637", firstSeen: "2026-07-27" },
  { type: "package", value: "search-connector-template@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-r4hg-r38h-7ph7, MAL-2026-4664", firstSeen: "2026-07-27" },
  { type: "package", value: "react-malicious-clone@19.3.0-canary-d5736f09-20260507", severity: "critical", confidence: 1.0, source: "GHSA-ph4w-pqrx-8xg7, MAL-2026-4660", firstSeen: "2026-07-27" },
  { type: "package", value: "pubnub-moderation-tool@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-3pr6-9pq2-m784, MAL-2026-4650", firstSeen: "2026-07-27" },
  { type: "package", value: "pewter-constantstest@9999.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9v38-rpx5-gr5f, MAL-2026-4638", firstSeen: "2026-07-27" },
  { type: "package", value: "seedcode-facturacion-electronica@2.5.35", severity: "critical", confidence: 0.9, source: "GHSA-374g-25m7-f99c", firstSeen: "2026-07-27" },
  { type: "package", value: "qr-code-styling-temp@9.9.10", severity: "critical", confidence: 1.0, source: "GHSA-m7q2-jqhj-4f3q, MAL-2026-4655", firstSeen: "2026-07-27" },
  { type: "package", value: "qr-code-styling-temp@9.9.11", severity: "critical", confidence: 1.0, source: "GHSA-m7q2-jqhj-4f3q, MAL-2026-4655", firstSeen: "2026-07-27" },
  { type: "package", value: "muaddib-scanner@2.11.41", severity: "critical", confidence: 1.0, source: "GHSA-j2fw-2q37-5rjv, MAL-2026-4616", firstSeen: "2026-07-27" },
  { type: "package", value: "logger-draft", severity: "critical", confidence: 1.0, source: "GHSA-4x3v-8mx9-xvpq, MAL-2026-4346", firstSeen: "2026-07-27" },
  { type: "package", value: "midcorp@1.1.9", severity: "critical", confidence: 1.0, source: "GHSA-h5wg-xp63-864f, MAL-2026-4610", firstSeen: "2026-07-27" },
  { type: "package", value: "intl-ads@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-955f-wxwv-77wv, MAL-2026-4587", firstSeen: "2026-07-27" },
  { type: "package", value: "intl-ads@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-955f-wxwv-77wv, MAL-2026-4587", firstSeen: "2026-07-27" },
  { type: "package", value: "intl-ads@99.0.2", severity: "critical", confidence: 1.0, source: "GHSA-955f-wxwv-77wv, MAL-2026-4587", firstSeen: "2026-07-27" },
  { type: "package", value: "git-userhub@2.1.4", severity: "critical", confidence: 1.0, source: "GHSA-f2fq-4hh5-jqrv, MAL-2026-4573", firstSeen: "2026-07-27" },

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

  // Imported from GitHub Advisory Database (2026-07-16) - see docs/threat-feed-sources.md
  { type: "package", value: "@ai-plus/de-agent-sdk", severity: "critical", confidence: 1.0, source: "GHSA-4c3x-2hh8-6pp9, MAL-2026-11175", firstSeen: "2026-07-29" },
  { type: "package", value: "@ai-plus/de-agent", severity: "critical", confidence: 1.0, source: "GHSA-w62v-8p95-rhf2, MAL-2026-11174", firstSeen: "2026-07-29" },
  { type: "package", value: "@ai-agent-node/agent-node", severity: "critical", confidence: 1.0, source: "GHSA-h95p-8cf6-7qrc, MAL-2026-11171", firstSeen: "2026-07-29" },
  { type: "package", value: "@ai-agent-node/nodesql", severity: "critical", confidence: 1.0, source: "GHSA-fm4j-w897-7h3g, MAL-2026-11173", firstSeen: "2026-07-29" },
  { type: "package", value: "@ai-agent-node/createnode", severity: "critical", confidence: 1.0, source: "GHSA-79rw-4w2g-9hr5, MAL-2026-11172", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.2.6", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.2.7", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.2.8", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.3.0", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.3.1", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.3.2", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.3.3", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.3.4", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.3.5", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.3.6", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.3.7", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.3.9", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.4.0", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.4.1", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.4.2", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.4.3", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@zannstore/baileys@2.4.4", severity: "critical", confidence: 1.0, source: "GHSA-vw26-8qc4-8hmg, MAL-2026-11179", firstSeen: "2026-07-29" },
  { type: "package", value: "@peptide-unit/peptide-modify", severity: "critical", confidence: 1.0, source: "GHSA-mw2h-4g9g-g7vv, MAL-2026-11178", firstSeen: "2026-07-29" },
  { type: "package", value: "@peptide-unit/js-unimode", severity: "critical", confidence: 1.0, source: "GHSA-hghj-5h7q-fq5h, MAL-2026-11177", firstSeen: "2026-07-29" },
  { type: "package", value: "test-skill-zip", severity: "critical", confidence: 1.0, source: "GHSA-qw86-6hcg-cj2j, MAL-2026-11189", firstSeen: "2026-07-29" },
  { type: "package", value: "flight-compare-analyzer", severity: "critical", confidence: 1.0, source: "GHSA-wwp4-2j5x-f2m9, MAL-2026-11185", firstSeen: "2026-07-29" },
  { type: "package", value: "lzd-unified-station-sdk", severity: "critical", confidence: 1.0, source: "GHSA-2rgv-qvc2-5q4h, MAL-2026-11187", firstSeen: "2026-07-29" },
  { type: "package", value: "colder-cli", severity: "critical", confidence: 1.0, source: "GHSA-x646-p774-9w26, MAL-2026-11182", firstSeen: "2026-07-29" },
  { type: "package", value: "def-open-client", severity: "critical", confidence: 1.0, source: "GHSA-pxmg-gr7p-wx8p, MAL-2026-11183", firstSeen: "2026-07-29" },
  { type: "package", value: "uniapi-bridge", severity: "critical", confidence: 1.0, source: "GHSA-wpp9-5p7g-7cjh, MAL-2026-11190", firstSeen: "2026-07-29" },
  { type: "package", value: "lwp-web-client", severity: "critical", confidence: 1.0, source: "GHSA-rmm2-5g7m-wj7p, MAL-2026-11186", firstSeen: "2026-07-29" },
  { type: "package", value: "open-worker-cli", severity: "critical", confidence: 1.0, source: "GHSA-2p2c-gx9p-5wg8, MAL-2026-11188", firstSeen: "2026-07-29" },
  { type: "package", value: "feedback-ai-sdk", severity: "critical", confidence: 1.0, source: "GHSA-fh6v-xfxj-m87q, MAL-2026-11184", firstSeen: "2026-07-29" },
  { type: "package", value: "aone-cloud-cli", severity: "critical", confidence: 1.0, source: "GHSA-c6xg-mcq6-m594, MAL-2026-11180", firstSeen: "2026-07-29" },
  { type: "package", value: "stake-math", severity: "critical", confidence: 1.0, source: "GHSA-qcc9-j6wh-4h9h, MAL-2026-6585", firstSeen: "2026-07-29" },
  { type: "package", value: "ts-precision", severity: "critical", confidence: 1.0, source: "GHSA-g38h-2r6h-pwr8, MAL-2026-6469", firstSeen: "2026-07-29" },
  { type: "package", value: "data-parser-utils", severity: "critical", confidence: 1.0, source: "GHSA-vw6q-xg53-fpxh, MAL-2026-6490", firstSeen: "2026-07-29" },
  { type: "package", value: "polymarket-risk-manager", severity: "critical", confidence: 1.0, source: "GHSA-jcx2-q527-7qcx, MAL-2026-6712", firstSeen: "2026-07-29" },
  { type: "package", value: "poly-kelly", severity: "critical", confidence: 1.0, source: "GHSA-c37j-v3j2-6gf8, MAL-2026-6584", firstSeen: "2026-07-29" },
  { type: "package", value: "ts-bn-proto", severity: "critical", confidence: 1.0, source: "GHSA-wxpc-r4jx-9jrw, MAL-2026-6695", firstSeen: "2026-07-29" },
  { type: "package", value: "eslintcmd", severity: "critical", confidence: 1.0, source: "GHSA-73c6-pgjj-9v82, MAL-2026-10670", firstSeen: "2026-07-29" },
  { type: "package", value: "@finxsecdemo/utils@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-qccg-fq42-3rgc, MAL-2026-11170", firstSeen: "2026-07-29" },
  { type: "package", value: "zer0code@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-frrq-7m67-mgxg, MAL-2026-11191", firstSeen: "2026-07-29" },
  { type: "package", value: "git-userhub@2.1.5", severity: "critical", confidence: 1.0, source: "GHSA-f2fq-4hh5-jqrv, MAL-2026-4573", firstSeen: "2026-07-27" },
  { type: "package", value: "lokal-mcp@0.4.0", severity: "critical", confidence: 0.9, source: "GHSA-9rg3-p529-qp32", firstSeen: "2026-07-27" },
  { type: "package", value: "orca-website@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-6g2r-mqhw-mwqf, MAL-2026-4632", firstSeen: "2026-07-27" },
  { type: "package", value: "moneykit-cardano-demo@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-xv7v-7v8w-9c3c, MAL-2026-4614", firstSeen: "2026-07-27" },
  { type: "package", value: "internallib_v493@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-h952-g373-j9x2, MAL-2026-4585", firstSeen: "2026-07-27" },
  { type: "package", value: "internallib_v493@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-h952-g373-j9x2, MAL-2026-4585", firstSeen: "2026-07-27" },
  { type: "package", value: "internallib_v493@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-h952-g373-j9x2, MAL-2026-4585", firstSeen: "2026-07-27" },
  { type: "package", value: "mev-shield@1.4.2", severity: "critical", confidence: 1.0, source: "GHSA-gfqm-g3gp-2hgh, MAL-2026-4609", firstSeen: "2026-07-27" },
  { type: "package", value: "midpatch@1.1.9", severity: "critical", confidence: 1.0, source: "GHSA-f5x8-866f-983p, MAL-2026-4611", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.177", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.199", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.211", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.217", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.210", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.192", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.212", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.197", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.201", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.203", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.198", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.206", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.215", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.209", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.221", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.180", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.178", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.186", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.183", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.207", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "local-mcp@3.0.188", severity: "critical", confidence: 0.9, source: "GHSA-9h8c-f7pm-jmvw", firstSeen: "2026-07-27" },
  { type: "package", value: "nikou-node@2.0.1", severity: "critical", confidence: 1.0, source: "GHSA-3rfr-r9gp-h3f3, MAL-2026-4620", firstSeen: "2026-07-27" },
  { type: "package", value: "osep-api-hub-service-client-v1@10.9.1", severity: "critical", confidence: 1.0, source: "GHSA-jfcj-q4vx-2j8w, MAL-2026-4633", firstSeen: "2026-07-27" },
  { type: "package", value: "n8n-nodes-whatsapp-business-api-by-automations-builder@0.1.0", severity: "critical", confidence: 0.9, source: "GHSA-rm27-jpmx-jj2v", firstSeen: "2026-07-27" },
  { type: "package", value: "koishi-plugin-fusheng-count@1.0.9", severity: "critical", confidence: 0.9, source: "GHSA-gx5c-c8pc-gq8j", firstSeen: "2026-07-27" },
  { type: "package", value: "payment-account-input-selector@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-qvfr-qpp7-hg8h, MAL-2026-4635", firstSeen: "2026-07-27" },
  { type: "package", value: "mcp-server-iehub-proxy@1.0.0", severity: "critical", confidence: 0.9, source: "GHSA-3x3c-57v3-ghqc", firstSeen: "2026-07-27" },
  { type: "package", value: "itc-actors-api@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-49f7-823v-m784, MAL-2026-4589", firstSeen: "2026-07-27" },
  { type: "package", value: "intl-ad-routing@99.0.1", severity: "critical", confidence: 1.0, source: "GHSA-2rpc-828j-v38q, MAL-2026-4586", firstSeen: "2026-07-27" },
  { type: "package", value: "intl-ad-routing@99.0.2", severity: "critical", confidence: 1.0, source: "GHSA-2rpc-828j-v38q, MAL-2026-4586", firstSeen: "2026-07-27" },
  { type: "package", value: "intl-ad-routing@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-2rpc-828j-v38q, MAL-2026-4586", firstSeen: "2026-07-27" },
  { type: "package", value: "ihubinternal@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-wgw2-3732-68h9, MAL-2026-4584", firstSeen: "2026-07-27" },
  { type: "package", value: "klaudius@0.12.3", severity: "critical", confidence: 0.9, source: "GHSA-mcwr-hhqj-88wv", firstSeen: "2026-07-27" },
  { type: "package", value: "klaudius@0.9.0", severity: "critical", confidence: 0.9, source: "GHSA-mcwr-hhqj-88wv", firstSeen: "2026-07-27" },
  { type: "package", value: "klaudius@0.12.1", severity: "critical", confidence: 0.9, source: "GHSA-mcwr-hhqj-88wv", firstSeen: "2026-07-27" },
  { type: "package", value: "klaudius@0.12.2", severity: "critical", confidence: 0.9, source: "GHSA-mcwr-hhqj-88wv", firstSeen: "2026-07-27" },
  { type: "package", value: "klaudius@0.11.0", severity: "critical", confidence: 0.9, source: "GHSA-mcwr-hhqj-88wv", firstSeen: "2026-07-27" },
  { type: "package", value: "klaudius@0.12.0", severity: "critical", confidence: 0.9, source: "GHSA-mcwr-hhqj-88wv", firstSeen: "2026-07-27" },
  { type: "package", value: "ignite-market-contractstest@0.0.9", severity: "critical", confidence: 1.0, source: "GHSA-pw26-5q6r-jg9x, MAL-2026-4583", firstSeen: "2026-07-27" },
  { type: "package", value: "ignite-market-contractstest@9.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pw26-5q6r-jg9x, MAL-2026-4583", firstSeen: "2026-07-27" },
  { type: "package", value: "happy-dlscord.js@14.16.3", severity: "critical", confidence: 1.0, source: "GHSA-r9fj-g789-w27w, MAL-2026-4575", firstSeen: "2026-07-27" },
  { type: "package", value: "maxixy-cli@0.15.11", severity: "critical", confidence: 1.0, source: "GHSA-2523-4cf3-5jhc, MAL-2026-4607", firstSeen: "2026-07-27" },
  { type: "package", value: "hiura-baileys@1.0.1", severity: "critical", confidence: 0.9, source: "GHSA-hm24-vg33-r4xg", firstSeen: "2026-07-27" },
  { type: "package", value: "hiura-baileys@1.0.3", severity: "critical", confidence: 0.9, source: "GHSA-hm24-vg33-r4xg", firstSeen: "2026-07-27" },
  { type: "package", value: "hiura-baileys@1.0.0", severity: "critical", confidence: 0.9, source: "GHSA-hm24-vg33-r4xg", firstSeen: "2026-07-27" },
  { type: "package", value: "kurumi-fca@1.1.8", severity: "critical", confidence: 0.9, source: "GHSA-6p3v-q6wr-32j3", firstSeen: "2026-07-27" },
  { type: "package", value: "kurumi-fca@1.1.7", severity: "critical", confidence: 0.9, source: "GHSA-6p3v-q6wr-32j3", firstSeen: "2026-07-27" },
  { type: "package", value: "koishi-plugin-yuan@1.7.0", severity: "critical", confidence: 0.9, source: "GHSA-q27w-xc5q-6x4x", firstSeen: "2026-07-27" },
  { type: "package", value: "naileys@0.5.2", severity: "critical", confidence: 0.9, source: "GHSA-v8rf-2xhg-4xvw", firstSeen: "2026-07-27" },
  { type: "package", value: "opentiny-react@6.9.31", severity: "critical", confidence: 0.9, source: "GHSA-78vw-3gqj-jhwm", firstSeen: "2026-07-27" },
  { type: "package", value: "lhisp-logger@3.1.10", severity: "critical", confidence: 1.0, source: "GHSA-f699-93m4-w7q3, MAL-2026-4598", firstSeen: "2026-07-27" },
  { type: "package", value: "ignite-market-contracts@9.0.0", severity: "critical", confidence: 1.0, source: "GHSA-46px-qr6j-cc9h, MAL-2026-4582", firstSeen: "2026-07-27" },
  { type: "package", value: "gm-kilo@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-mcvv-crr3-hw73, MAL-2026-4574", firstSeen: "2026-07-27" },
  { type: "package", value: "koishi-plugin-fusheng-car@1.0.6", severity: "critical", confidence: 0.9, source: "GHSA-jjg3-vmf7-9rfh", firstSeen: "2026-07-27" },
  { type: "package", value: "harness-skil@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9fvh-6xx6-h6jj, MAL-2026-4577", firstSeen: "2026-07-27" },
  { type: "package", value: "dot-utils-plus@0.1.9", severity: "critical", confidence: 1.0, source: "GHSA-jr57-8vg6-x89g, MAL-2026-4549", firstSeen: "2026-07-27" },
  { type: "package", value: "dot-utils-plus@0.1.5", severity: "critical", confidence: 1.0, source: "GHSA-jr57-8vg6-x89g, MAL-2026-4549", firstSeen: "2026-07-27" },
  { type: "package", value: "dot-utils-plus@0.1.8", severity: "critical", confidence: 1.0, source: "GHSA-jr57-8vg6-x89g, MAL-2026-4549", firstSeen: "2026-07-27" },
  { type: "package", value: "fnd-stores@0.0.7", severity: "critical", confidence: 1.0, source: "GHSA-vvcx-r78j-rf25, MAL-2026-4565", firstSeen: "2026-07-27" },
  { type: "package", value: "fnd-stores@0.0.6", severity: "critical", confidence: 1.0, source: "GHSA-vvcx-r78j-rf25, MAL-2026-4565", firstSeen: "2026-07-27" },
  { type: "package", value: "get-package-lint@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-w9j4-26h2-4rrm, MAL-2026-4572", firstSeen: "2026-07-27" },
  { type: "package", value: "fca-eryxenx@6.0.0", severity: "critical", confidence: 0.9, source: "GHSA-hv46-jhfp-28wc", firstSeen: "2026-07-27" },
  { type: "package", value: "figma-d2c-utils@0.6.0", severity: "critical", confidence: 0.9, source: "GHSA-gg9j-fhg5-7wh9", firstSeen: "2026-07-27" },
  { type: "package", value: "code-tool-langfuse@0.1.2", severity: "critical", confidence: 1.0, source: "GHSA-239h-wfrf-m3mr, MAL-2026-4532", firstSeen: "2026-07-27" },
  { type: "package", value: "code-tool-langfuse@0.1.1", severity: "critical", confidence: 1.0, source: "GHSA-239h-wfrf-m3mr, MAL-2026-4532", firstSeen: "2026-07-27" },
  { type: "package", value: "code-tool-langfuse@0.1.7", severity: "critical", confidence: 1.0, source: "GHSA-239h-wfrf-m3mr, MAL-2026-4532", firstSeen: "2026-07-27" },
  { type: "package", value: "code-tool-langfuse@0.1.4", severity: "critical", confidence: 1.0, source: "GHSA-239h-wfrf-m3mr, MAL-2026-4532", firstSeen: "2026-07-27" },
  { type: "package", value: "code-tool-langfuse@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-239h-wfrf-m3mr, MAL-2026-4532", firstSeen: "2026-07-27" },
  { type: "package", value: "did-0091@11.0.6", severity: "critical", confidence: 1.0, source: "GHSA-g6qg-2g99-fhg5, MAL-2026-4177", firstSeen: "2026-07-27" },
  { type: "package", value: "did-0091@11.0.5", severity: "critical", confidence: 1.0, source: "GHSA-g6qg-2g99-fhg5, MAL-2026-4177", firstSeen: "2026-07-27" },
  { type: "package", value: "did-0091@11.0.9", severity: "critical", confidence: 1.0, source: "GHSA-g6qg-2g99-fhg5, MAL-2026-4177", firstSeen: "2026-07-27" },
  { type: "package", value: "did-0091@11.1.8", severity: "critical", confidence: 1.0, source: "GHSA-g6qg-2g99-fhg5, MAL-2026-4177", firstSeen: "2026-07-27" },
  { type: "package", value: "did-0091@11.2.8", severity: "critical", confidence: 1.0, source: "GHSA-g6qg-2g99-fhg5, MAL-2026-4177", firstSeen: "2026-07-27" },
  { type: "package", value: "crypt0co-walet-poc@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-94pj-mq7f-3w48, MAL-2026-4540", firstSeen: "2026-07-27" },
  { type: "package", value: "etherproxy-lite@0.6.0", severity: "critical", confidence: 0.9, source: "GHSA-875r-gp38-67f6", firstSeen: "2026-07-27" },
  { type: "package", value: "configcat-trello-powerup@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-pj84-f8w8-wpp7, MAL-2026-4535", firstSeen: "2026-07-27" },
  { type: "package", value: "fulcrum-sessions@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-5m72-5p65-3x22, MAL-2026-4568", firstSeen: "2026-07-27" },
  { type: "package", value: "fulcrum-sessions@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-5m72-5p65-3x22, MAL-2026-4568", firstSeen: "2026-07-27" },
  { type: "package", value: "cryptoco-auth@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-hgjx-qq56-57hf, MAL-2026-4230", firstSeen: "2026-07-27" },
  { type: "package", value: "cryptoco-auth@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-hgjx-qq56-57hf, MAL-2026-4230", firstSeen: "2026-07-27" },
  { type: "package", value: "cryptoco-auth@1.0.8", severity: "critical", confidence: 1.0, source: "GHSA-hgjx-qq56-57hf, MAL-2026-4230", firstSeen: "2026-07-27" },
  { type: "package", value: "cryptoco-auth@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-hgjx-qq56-57hf, MAL-2026-4230", firstSeen: "2026-07-27" },
  { type: "package", value: "cryptoco-auth@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-hgjx-qq56-57hf, MAL-2026-4230", firstSeen: "2026-07-27" },
  { type: "package", value: "cryptoco-auth@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-hgjx-qq56-57hf, MAL-2026-4230", firstSeen: "2026-07-27" },
  { type: "package", value: "cryptoco-auth@1.0.7", severity: "critical", confidence: 1.0, source: "GHSA-hgjx-qq56-57hf, MAL-2026-4230", firstSeen: "2026-07-27" },
  { type: "package", value: "cryptoco-auth@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-hgjx-qq56-57hf, MAL-2026-4230", firstSeen: "2026-07-27" },
  { type: "package", value: "cryptoco-auth@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-hgjx-qq56-57hf, MAL-2026-4230", firstSeen: "2026-07-27" },
  { type: "package", value: "fastgrc-openclaw@1.0.33", severity: "critical", confidence: 1.0, source: "GHSA-mhh2-hp9p-8xc2, MAL-2026-4558", firstSeen: "2026-07-27" },
  { type: "package", value: "create-kachow@1.2.0", severity: "critical", confidence: 1.0, source: "GHSA-qqjp-jmjc-72hp, MAL-2026-4539", firstSeen: "2026-07-27" },
  { type: "package", value: "fca-official-uzair-rajput@1.16.0", severity: "critical", confidence: 0.9, source: "GHSA-fgm2-6hg5-gw2q", firstSeen: "2026-07-27" },
  { type: "package", value: "clobprice.api", severity: "critical", confidence: 1.0, source: "GHSA-mgh9-w2cf-9c5j, MAL-2026-4350", firstSeen: "2026-07-27" },
  { type: "package", value: "clipboard-guardian@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7vwf-f228-qr45, MAL-2026-4290", firstSeen: "2026-07-27" },
  { type: "package", value: "clipboard-guardian@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-7vwf-f228-qr45, MAL-2026-4290", firstSeen: "2026-07-27" },
  { type: "package", value: "clipboard-guardian@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-7vwf-f228-qr45, MAL-2026-4290", firstSeen: "2026-07-27" },
  { type: "package", value: "clipboard-guardian@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-7vwf-f228-qr45, MAL-2026-4290", firstSeen: "2026-07-27" },
  { type: "package", value: "gehneb@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-895f-5vqc-qcp6, MAL-2026-4570", firstSeen: "2026-07-27" },
  { type: "package", value: "clickpy@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-r8qg-w536-ghm7, MAL-2026-4270", firstSeen: "2026-07-27" },
  { type: "package", value: "clickpy@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-r8qg-w536-ghm7, MAL-2026-4270", firstSeen: "2026-07-27" },
  { type: "package", value: "cloudsmith-vsc@2.1.2", severity: "critical", confidence: 1.0, source: "GHSA-8jwj-qw4w-j3vw, MAL-2026-4530", firstSeen: "2026-07-27" },
  { type: "package", value: "freertc@0.1.22", severity: "critical", confidence: 1.0, source: "GHSA-w2xm-fv9h-m364, MAL-2026-4567", firstSeen: "2026-07-27" },
  { type: "package", value: "freertc@0.1.32", severity: "critical", confidence: 1.0, source: "GHSA-w2xm-fv9h-m364, MAL-2026-4567", firstSeen: "2026-07-27" },
  { type: "package", value: "freertc@0.1.33", severity: "critical", confidence: 1.0, source: "GHSA-w2xm-fv9h-m364, MAL-2026-4567", firstSeen: "2026-07-27" },
  { type: "package", value: "freertc@0.1.28", severity: "critical", confidence: 1.0, source: "GHSA-w2xm-fv9h-m364, MAL-2026-4567", firstSeen: "2026-07-27" },
  { type: "package", value: "freertc@0.1.23", severity: "critical", confidence: 1.0, source: "GHSA-w2xm-fv9h-m364, MAL-2026-4567", firstSeen: "2026-07-27" },
  { type: "package", value: "freertc@0.1.20", severity: "critical", confidence: 1.0, source: "GHSA-w2xm-fv9h-m364, MAL-2026-4567", firstSeen: "2026-07-27" },
  { type: "package", value: "freertc@0.1.31", severity: "critical", confidence: 1.0, source: "GHSA-w2xm-fv9h-m364, MAL-2026-4567", firstSeen: "2026-07-27" },
  { type: "package", value: "freertc@0.1.21", severity: "critical", confidence: 1.0, source: "GHSA-w2xm-fv9h-m364, MAL-2026-4567", firstSeen: "2026-07-27" },
  { type: "package", value: "discovery-build@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-7p2r-crfh-wcfh, MAL-2026-4266", firstSeen: "2026-07-27" },
  { type: "package", value: "discovery-build@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-7p2r-crfh-wcfh, MAL-2026-4266", firstSeen: "2026-07-27" },
  { type: "package", value: "discovery-build@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-7p2r-crfh-wcfh, MAL-2026-4266", firstSeen: "2026-07-27" },
  { type: "package", value: "discovery-build@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-7p2r-crfh-wcfh, MAL-2026-4266", firstSeen: "2026-07-27" },
  { type: "package", value: "cosmosdb-server@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-r5xc-mh93-ghcx, MAL-2026-4537", firstSeen: "2026-07-27" },
  { type: "package", value: "cosmosdb-server@0.0.2", severity: "critical", confidence: 1.0, source: "GHSA-r5xc-mh93-ghcx, MAL-2026-4537", firstSeen: "2026-07-27" },
  { type: "package", value: "cloud-pc-templates@1.3.0", severity: "critical", confidence: 1.0, source: "GHSA-x256-c9jq-fgr2, MAL-2026-4528", firstSeen: "2026-07-27" },
  { type: "package", value: "encrata-cli@0.2.0", severity: "critical", confidence: 1.0, source: "GHSA-6c3r-grh6-qvj6, MAL-2026-4551", firstSeen: "2026-07-27" },
  { type: "package", value: "encrata-cli@0.1.0", severity: "critical", confidence: 1.0, source: "GHSA-6c3r-grh6-qvj6, MAL-2026-4551", firstSeen: "2026-07-27" },
  { type: "package", value: "gator-client@9.9.11", severity: "critical", confidence: 1.0, source: "GHSA-r569-8mc4-rfp6, MAL-2026-4569", firstSeen: "2026-07-27" },
  { type: "package", value: "events-router@2.1.4", severity: "critical", confidence: 1.0, source: "GHSA-279h-8g5h-vgr2, MAL-2026-4555", firstSeen: "2026-07-27" },
  { type: "package", value: "ctf-flare@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-8f2r-mhxx-jqg7, MAL-2026-3836", firstSeen: "2026-07-27" },
  { type: "package", value: "emojifancy-print@5.6.3", severity: "critical", confidence: 1.0, source: "GHSA-7qgp-369v-7fw2, MAL-2026-4550", firstSeen: "2026-07-27" },
  { type: "package", value: "dds-js-idl@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-4rrr-3j6v-74gh, MAL-2026-4264", firstSeen: "2026-07-27" },
  { type: "package", value: "dds-js-idl@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-4rrr-3j6v-74gh, MAL-2026-4264", firstSeen: "2026-07-27" },
  { type: "package", value: "cloudpivot@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-mm77-xw6g-5q29, MAL-2026-4529", firstSeen: "2026-07-27" },
  { type: "package", value: "cloudpivot@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-mm77-xw6g-5q29, MAL-2026-4529", firstSeen: "2026-07-27" },
  { type: "package", value: "cxpher-linux-arm32@2.0.22", severity: "critical", confidence: 1.0, source: "GHSA-mch6-wqpx-2cc2, MAL-2026-4547", firstSeen: "2026-07-27" },
  { type: "package", value: "claude-all-config@3.8.3", severity: "critical", confidence: 1.0, source: "GHSA-6353-97m9-6cpx, MAL-2026-4522", firstSeen: "2026-07-27" },
  { type: "package", value: "claude-all-config@3.9.0", severity: "critical", confidence: 1.0, source: "GHSA-6353-97m9-6cpx, MAL-2026-4522", firstSeen: "2026-07-27" },
  { type: "package", value: "claude-all-config@3.8.4", severity: "critical", confidence: 1.0, source: "GHSA-6353-97m9-6cpx, MAL-2026-4522", firstSeen: "2026-07-27" },
  { type: "package", value: "express-enrouten-async@1.4.12", severity: "critical", confidence: 1.0, source: "GHSA-hmrf-wh7g-88vj, MAL-2026-4556", firstSeen: "2026-07-27" },
  { type: "package", value: "express-enrouten-async@1.4.11", severity: "critical", confidence: 1.0, source: "GHSA-hmrf-wh7g-88vj, MAL-2026-4556", firstSeen: "2026-07-27" },
  { type: "package", value: "clob.api@2.73.0", severity: "critical", confidence: 1.0, source: "GHSA-52f3-9m92-26fg, MAL-2026-4349", firstSeen: "2026-07-27" },
  { type: "package", value: "alya-baileys@1.9.36", severity: "critical", confidence: 0.9, source: "GHSA-4v3r-hfg7-pm63", firstSeen: "2026-07-27" },
  { type: "package", value: "alya-baileys@1.9.45", severity: "critical", confidence: 0.9, source: "GHSA-4v3r-hfg7-pm63", firstSeen: "2026-07-27" },
  { type: "package", value: "alya-baileys@1.9.35", severity: "critical", confidence: 0.9, source: "GHSA-4v3r-hfg7-pm63", firstSeen: "2026-07-27" },
  { type: "package", value: "alya-baileys@1.9.42", severity: "critical", confidence: 0.9, source: "GHSA-4v3r-hfg7-pm63", firstSeen: "2026-07-27" },
  { type: "package", value: "alya-baileys@1.9.39", severity: "critical", confidence: 0.9, source: "GHSA-4v3r-hfg7-pm63", firstSeen: "2026-07-27" },
  { type: "package", value: "alya-baileys@1.9.46", severity: "critical", confidence: 0.9, source: "GHSA-4v3r-hfg7-pm63", firstSeen: "2026-07-27" },
  { type: "package", value: "alya-baileys@1.9.38", severity: "critical", confidence: 0.9, source: "GHSA-4v3r-hfg7-pm63", firstSeen: "2026-07-27" },
  { type: "package", value: "alya-baileys@1.9.37", severity: "critical", confidence: 0.9, source: "GHSA-4v3r-hfg7-pm63", firstSeen: "2026-07-27" },
  { type: "package", value: "cami-design@0.2.5", severity: "critical", confidence: 1.0, source: "GHSA-mj2p-8c9p-f8gw, MAL-2026-4504", firstSeen: "2026-07-27" },
  { type: "package", value: "cdk-sagemaker-notebook-workflow@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-xf24-8hh9-hf35, MAL-2026-4255", firstSeen: "2026-07-27" },
  { type: "package", value: "cdk-sagemaker-notebook-workflow@2.0.5", severity: "critical", confidence: 1.0, source: "GHSA-xf24-8hh9-hf35, MAL-2026-4255", firstSeen: "2026-07-27" },
  { type: "package", value: "cdk-sagemaker-notebook-workflow@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-xf24-8hh9-hf35, MAL-2026-4255", firstSeen: "2026-07-27" },
  { type: "package", value: "cdk-sagemaker-notebook-workflow@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-xf24-8hh9-hf35, MAL-2026-4255", firstSeen: "2026-07-27" },
  { type: "package", value: "cdk-sagemaker-notebook-workflow@2.0.4", severity: "critical", confidence: 1.0, source: "GHSA-xf24-8hh9-hf35, MAL-2026-4255", firstSeen: "2026-07-27" },
  { type: "package", value: "cdk-sagemaker-notebook-workflow@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-xf24-8hh9-hf35, MAL-2026-4255", firstSeen: "2026-07-27" },
  { type: "package", value: "class-blend@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-9mw5-h9jw-486p, MAL-2026-4520", firstSeen: "2026-07-27" },
  { type: "package", value: "class-blend@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-9mw5-h9jw-486p, MAL-2026-4520", firstSeen: "2026-07-27" },
  { type: "package", value: "class-blend@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-9mw5-h9jw-486p, MAL-2026-4520", firstSeen: "2026-07-27" },
  { type: "package", value: "class-blend@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-9mw5-h9jw-486p, MAL-2026-4520", firstSeen: "2026-07-27" },
  { type: "package", value: "chain-async-test@1.1.7", severity: "critical", confidence: 1.0, source: "GHSA-7cq4-w24c-cp32, MAL-2026-4516", firstSeen: "2026-07-27" },
  { type: "package", value: "chai-val@1.1.9", severity: "critical", confidence: 1.0, source: "GHSA-xcq8-h4wf-839c, MAL-2026-4515", firstSeen: "2026-07-27" },
  { type: "package", value: "cheaty-sync-bot@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-g4v9-4mhh-3gqw, MAL-2026-4518", firstSeen: "2026-07-27" },
  { type: "package", value: "banana-stand@9.9.11", severity: "critical", confidence: 1.0, source: "GHSA-x4gx-rrjg-5rrh, MAL-2026-4495", firstSeen: "2026-07-27" },
  { type: "package", value: "claude-content-writer@2.2.0", severity: "critical", confidence: 1.0, source: "GHSA-xcv7-f69m-4q6r, MAL-2026-4524", firstSeen: "2026-07-27" },
  { type: "package", value: "bucket-protocol-sdk-v2@1.0.26", severity: "critical", confidence: 1.0, source: "GHSA-q742-7p9j-gqp2, MAL-2026-4502", firstSeen: "2026-07-27" },
  { type: "package", value: "bucket-protocol-sdk-v2@1.0.11", severity: "critical", confidence: 1.0, source: "GHSA-q742-7p9j-gqp2, MAL-2026-4502", firstSeen: "2026-07-27" },
  { type: "package", value: "bucket-protocol-sdk-v2@1.0.23", severity: "critical", confidence: 1.0, source: "GHSA-q742-7p9j-gqp2, MAL-2026-4502", firstSeen: "2026-07-27" },
  { type: "package", value: "bucket-protocol-sdk-v2@1.0.12", severity: "critical", confidence: 1.0, source: "GHSA-q742-7p9j-gqp2, MAL-2026-4502", firstSeen: "2026-07-27" },
  { type: "package", value: "bucket-protocol-sdk-v2@1.0.22", severity: "critical", confidence: 1.0, source: "GHSA-q742-7p9j-gqp2, MAL-2026-4502", firstSeen: "2026-07-27" },
  { type: "package", value: "bucket-protocol-sdk-v2@1.0.18", severity: "critical", confidence: 1.0, source: "GHSA-q742-7p9j-gqp2, MAL-2026-4502", firstSeen: "2026-07-27" },
  { type: "package", value: "bucket-protocol-sdk-v2@1.0.19", severity: "critical", confidence: 1.0, source: "GHSA-q742-7p9j-gqp2, MAL-2026-4502", firstSeen: "2026-07-27" },
  { type: "package", value: "chromestaff-baileys@1.1.3", severity: "critical", confidence: 0.9, source: "GHSA-8v92-crgp-qj9c", firstSeen: "2026-07-27" },
  { type: "package", value: "cb-wallet-data@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-444q-6m2p-p7h8, MAL-2026-4506", firstSeen: "2026-07-27" },
  { type: "package", value: "ask-my-llm@1.1.5", severity: "critical", confidence: 0.9, source: "GHSA-v8q7-fv5q-2h2g", firstSeen: "2026-07-27" },
  { type: "package", value: "ask-my-llm@1.1.4", severity: "critical", confidence: 0.9, source: "GHSA-v8q7-fv5q-2h2g", firstSeen: "2026-07-27" },
  { type: "package", value: "ask-my-llm@1.1.3", severity: "critical", confidence: 0.9, source: "GHSA-v8q7-fv5q-2h2g", firstSeen: "2026-07-27" },
  { type: "package", value: "carvus-lens@1.0.1", severity: "critical", confidence: 1.0, source: "GHSA-699g-wcqx-mpwh, MAL-2026-4505", firstSeen: "2026-07-27" },
  { type: "package", value: "cerebrum-core@1.1.0", severity: "critical", confidence: 1.0, source: "GHSA-85wq-pw3g-578w, MAL-2026-4510", firstSeen: "2026-07-27" },
  { type: "package", value: "clawpro-diagnostics-metrics-cls@3.0.4", severity: "critical", confidence: 0.9, source: "GHSA-3r3v-qph5-vxjf", firstSeen: "2026-07-27" },
  { type: "package", value: "autoheal-dev-cli@1.2.9", severity: "critical", confidence: 1.0, source: "GHSA-f2qc-qv52-cfp9, MAL-2026-4492", firstSeen: "2026-07-27" },
  { type: "package", value: "autoheal-dev-cli@1.2.7", severity: "critical", confidence: 1.0, source: "GHSA-f2qc-qv52-cfp9, MAL-2026-4492", firstSeen: "2026-07-27" },
  { type: "package", value: "autoheal-dev-cli@1.2.5", severity: "critical", confidence: 1.0, source: "GHSA-f2qc-qv52-cfp9, MAL-2026-4492", firstSeen: "2026-07-27" },
  { type: "package", value: "autoheal-dev-cli@1.0.6", severity: "critical", confidence: 1.0, source: "GHSA-f2qc-qv52-cfp9, MAL-2026-4492", firstSeen: "2026-07-27" },
  { type: "package", value: "autoheal-dev-cli@1.0.7", severity: "critical", confidence: 1.0, source: "GHSA-f2qc-qv52-cfp9, MAL-2026-4492", firstSeen: "2026-07-27" },
  { type: "package", value: "autoheal-dev-cli@1.0.9", severity: "critical", confidence: 1.0, source: "GHSA-f2qc-qv52-cfp9, MAL-2026-4492", firstSeen: "2026-07-27" },
  { type: "package", value: "autoheal-dev-cli@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-f2qc-qv52-cfp9, MAL-2026-4492", firstSeen: "2026-07-27" },
  { type: "package", value: "autoheal-dev-cli@1.2.6", severity: "critical", confidence: 1.0, source: "GHSA-f2qc-qv52-cfp9, MAL-2026-4492", firstSeen: "2026-07-27" },
  { type: "package", value: "autoheal-dev-cli@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-f2qc-qv52-cfp9, MAL-2026-4492", firstSeen: "2026-07-27" },
  { type: "package", value: "celonix-otp-react@1.0.3", severity: "critical", confidence: 1.0, source: "GHSA-jj4h-3j8m-gx8q, MAL-2026-4509", firstSeen: "2026-07-27" },
  { type: "package", value: "celonix-otp-react@1.0.2", severity: "critical", confidence: 1.0, source: "GHSA-jj4h-3j8m-gx8q, MAL-2026-4509", firstSeen: "2026-07-27" },
  { type: "package", value: "celonix-otp-react@1.0.4", severity: "critical", confidence: 1.0, source: "GHSA-jj4h-3j8m-gx8q, MAL-2026-4509", firstSeen: "2026-07-27" },
  { type: "package", value: "celonix-otp-react@1.0.5", severity: "critical", confidence: 1.0, source: "GHSA-jj4h-3j8m-gx8q, MAL-2026-4509", firstSeen: "2026-07-27" },
  { type: "package", value: "celonix-otp-react@1.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jj4h-3j8m-gx8q, MAL-2026-4509", firstSeen: "2026-07-27" },
  { type: "package", value: "cb-wallet-http@0.0.1", severity: "critical", confidence: 1.0, source: "GHSA-jhp6-8xc5-6544, MAL-2026-4507", firstSeen: "2026-07-27" },
  { type: "package", value: "chai-as-vite@2.3.5", severity: "critical", confidence: 1.0, source: "GHSA-94hw-rpf9-h2jf, MAL-2026-4514", firstSeen: "2026-07-27" },
  { type: "package", value: "bolt-delivery-menu-app@9.9.11", severity: "critical", confidence: 1.0, source: "GHSA-75c2-fw59-mg5f, MAL-2026-4499", firstSeen: "2026-07-27" },
  { type: "package", value: "chai-as-patch@1.1.9", severity: "critical", confidence: 1.0, source: "GHSA-3cj3-926x-m9jj, MAL-2026-4511", firstSeen: "2026-07-27" },
  { type: "package", value: "@tmecontinue/claude@2.2.15-test.1", severity: "critical", confidence: 0.9, source: "GHSA-vc3x-g46f-q7c5", firstSeen: "2026-07-27" },
  { type: "package", value: "@stockrepublic/republic-components@99.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jr7j-v3mp-pjfv, MAL-2026-4289", firstSeen: "2026-07-27" },
  { type: "package", value: "@stockrepublic/republic-components@100.0.0", severity: "critical", confidence: 1.0, source: "GHSA-jr7j-v3mp-pjfv, MAL-2026-4289", firstSeen: "2026-07-27" },
  { type: "package", value: "@tailwind-core/vite@4.3.0", severity: "critical", confidence: 0.9, source: "GHSA-6r66-6849-h5xj", firstSeen: "2026-07-27" },
  { type: "package", value: "@vino.tian/vibe-kanban@0.1.4420", severity: "critical", confidence: 0.9, source: "GHSA-4w6p-626q-gq95", firstSeen: "2026-07-27" },
  { type: "package", value: "@vino.tian/vibe-kanban@0.1.4413", severity: "critical", confidence: 0.9, source: "GHSA-4w6p-626q-gq95", firstSeen: "2026-07-27" },
  { type: "package", value: "@vino.tian/vibe-kanban@0.1.4418", severity: "critical", confidence: 0.9, source: "GHSA-4w6p-626q-gq95", firstSeen: "2026-07-27" },
  { type: "package", value: "@zesyn/zeditor@1.0.3", severity: "critical", confidence: 0.9, source: "GHSA-3mw9-f3w7-6h72", firstSeen: "2026-07-27" },
  { type: "package", value: "@tarojs/cli@4.1.12-beta.47", severity: "critical", confidence: 0.9, source: "GHSA-pmxj-wf58-gxfp", firstSeen: "2026-07-27" },
  { type: "package", value: "@tarojs/cli@4.2.1-beta.0", severity: "critical", confidence: 0.9, source: "GHSA-pmxj-wf58-gxfp", firstSeen: "2026-07-27" },

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

// Composed from the chunks above. A single array literal of this size trips
// TS2590 ("union type that is too complex to represent") in tsc; splitting it
// into capacity-bounded consts and spreading them keeps every entry fully
// typechecked against FeedIOC while staying far under that ceiling.
// scripts/import-threat-feed.mjs appends to the last chunk and starts a new one
// at FEED_CHUNK_CAPACITY entries, so no single literal grows back into TS2590.
const BUNDLED_FEED: FeedIOC[] = [
  ...FEED_CHUNK_0,
  ...FEED_CHUNK_1,
];

// Exported so the feed channel (feed.ts: "feed refresh") writes its download
// to the exact location loadThreatIntel() reads from.
export const CACHE_DIR = ".scg-cache";
export const FEED_CACHE_FILE = "threat-feed.json";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Copy of the bundled (compiled-in) IOC feed, without any cached remote
 * entries merged. Used by "feed stats" to distinguish bundled vs effective
 * entry counts; scripts/generate-feed.mjs derives the publishable feed.json
 * from the same array (parsed out of this source file, single source of truth).
 */
export function getBundledFeed(): FeedIOC[] {
  return [...BUNDLED_FEED];
}

// ---------------------------------------------------------------------------
// Feed loading
// ---------------------------------------------------------------------------

/** Memoized result of loadThreatIntel, keyed on the cache file's identity. */
interface FeedCacheEntry {
  key: string;
  feed: FeedIOC[];
}
let memoizedFeed: FeedCacheEntry | null = null;

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
  const cacheBase = cacheDir ?? CACHE_DIR;
  const cachePath = path.join(cacheBase, FEED_CACHE_FILE);

  // Identity of the inputs: which cache file, and what state is it in. stat()
  // is one syscall against a read+parse of the entire document.
  let stamp = "none";
  let stat: fs.Stats | undefined;
  try {
    stat = fs.statSync(cachePath);
    stamp = `${stat.mtimeMs}:${stat.size}`;
  } catch { /* no cache file: stamp stays "none" */ }

  // The TTL is evaluated against wall-clock time, so a memo may not outlive the
  // window in which the cache is still considered fresh. Bucket by TTL period
  // so an expiring cache is re-evaluated rather than served stale.
  const ttlBucket = Math.floor(Date.now() / CACHE_TTL_MS);
  // NUL-separated: no filesystem path can contain the separator, so two
  // different cache identities cannot collide into one key.
  const key = `${cachePath}\u0000${remoteFeedUrl ?? ""}\u0000${stamp}\u0000${ttlBucket}`;

  if (memoizedFeed && memoizedFeed.key === key) return memoizedFeed.feed;

  let feed = [...BUNDLED_FEED];

  // Try to load cached remote feed
  if (stat) {
    try {
      const cached = JSON.parse(fs.readFileSync(cachePath, "utf-8")) as {
        timestamp: string;
        entries: FeedIOC[];
      };
      const age = Date.now() - new Date(cached.timestamp).getTime();
      if (age < CACHE_TTL_MS && Array.isArray(cached.entries)) {
        // Quarantine invalid entries instead of trusting the cast: cached
        // remote data reaches the per-file scan loop, so a malformed entry
        // must never leave this function (issue #54).
        feed = mergeFeeds(feed, cached.entries.filter(isValidFeedIOC));
      }
    } catch { /* ignore corrupt cache */ }
  }

  memoizedFeed = { key, feed };
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

    const raw = (await response.json()) as unknown;
    if (!Array.isArray(raw)) throw new Error("Invalid feed format");
    // Validate BEFORE caching: entries failing the indicator contract
    // (unknown type, non-string/empty/oversized value) are quarantined so
    // they can never reach a scan via the cache (issue #54).
    const entries = raw.filter(isValidFeedIOC);

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

// Keys permitted in a published/cached feed document and in its IOC entries.
// Anything outside these sets means the file is NOT our inert data format and
// must be scanned normally - an attacker cannot smuggle code past the check by
// naming a file feed.json, because any extra key or non-scalar value fails it.
const FEED_DOC_KEYS = new Set(["schema", "package", "version", "entryCount", "entries", "timestamp"]);
// Mirrors the FeedIOC interface (plus the legacy "note"/"ecosystem" keys). It
// MUST list every field the feed can carry: "source" and "lastSeen" are part of
// FeedIOC, and entries imported from upstream advisory databases populate
// "source" with their provenance (see scripts/import-threat-feed.mjs). Leaving
// a real field out here would make the project's own feed.json fail this check
// and get scanned as ordinary content - the v5.4.0 phantom-findings bug.
const FEED_ENTRY_KEYS = new Set([
  "type", "value", "severity", "confidence", "family", "campaign", "source",
  "firstSeen", "lastSeen", "note", "ecosystem",
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

// Type-aware value shapes: a structurally "valid string" is not enough - a
// domain entry of "(" would (post-escaping) literal-match every file that
// contains a parenthesis, turning a hostile feed into a false-positive
// generator instead of a crash. Each indicator type has a narrow charset.
const IOC_VALUE_SHAPES: Record<string, RegExp> = {
  // RFC-ish hostname: labels of letters/digits/hyphen/underscore joined by dots.
  domain: /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/i,
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
export function isValidFeedIOC(entry: unknown): entry is FeedIOC {
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
  const shape = IOC_VALUE_SHAPES[e.type];
  return shape !== undefined && shape.test(e.value);
}

// Domain regexes are compiled once per unique value, not per scanned file
// (checkThreatIntel runs for every file with the same feed array). A null
// entry records a value whose compilation failed (unreachable after full
// escaping, kept as belt and braces) - matched via substring fallback.
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
          // Full metacharacter escaping: the value is a literal indicator,
          // so the compiled regex must match exactly it and nothing else.
          regex = new RegExp(escapeRegExp(ioc.value), "i");
        } catch {
          // Cannot throw after full escaping; belt and braces so a future
          // edit can never re-introduce the scan-degrading SyntaxError.
          regex = null;
        }
        domainRegexCache.set(ioc.value, regex);
      }
      matched = regex ? regex.test(content) : contentLower.includes(valueLower);
    } else {
      matched = contentLower.includes(valueLower);
    }

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
 * NuGet package ids are case-insensitive, so the "nuget" ecosystem compares
 * names ignoring case. Other registries treat names as case-sensitive
 * (RubyGems/Packagist names are lowercase by convention).
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

  const caseInsensitive = eco === "nuget";
  const wantName = caseInsensitive ? name.toLowerCase() : name;

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
  const caseInsensitive = eco === "nuget";
  const wantName = caseInsensitive ? name.toLowerCase() : name;

  for (const ioc of entries) {
    if (ioc.type !== "package") continue;
    if (!ioc.value.toLowerCase().startsWith(prefix)) continue;

    const rest = ioc.value.substring(prefix.length);
    const at = rest.lastIndexOf("@");
    const iocName = at > 0 ? rest.substring(0, at) : rest;
    const iocVersion = at > 0 ? rest.substring(at + 1) : undefined;

    const nameMatches = caseInsensitive
      ? iocName.toLowerCase() === wantName
      : iocName === wantName;
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
    // Split "name@version" at the last "@". Ecosystem-prefixed names never
    // start with "@" (npm scopes stay unprefixed), so index 0 means bare name.
    const at = rest.lastIndexOf("@");
    const iocName = at > 0 ? rest.substring(0, at) : rest;
    const iocVersion = at > 0 ? rest.substring(at + 1) : undefined;

    // NuGet package ids are case-insensitive; every other ecosystem compares
    // exactly, so only NuGet keys are folded.
    const keyName = entryEco === "nuget" ? iocName.toLowerCase() : iocName;
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
