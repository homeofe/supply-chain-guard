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
// v5.2.21: documentation files (.md/.markdown/.txt/.rst) legitimately discuss
// threat-intel IOCs - changelog entries, blog posts, security research.
// Matching threat-intel hashes/domains in docs creates noise without security
// value. Same rationale as patterns.ts BENIGN_DOC_FILES and ioc-blocklist.ts.
const BENIGN_DOC_FILES = /\.(md|markdown|txt|rst)$/i;

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
