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
      if (age < CACHE_TTL_MS && Array.isArray(cached.entries)) {
        // Quarantine invalid entries instead of trusting the cast: cached
        // remote data reaches the per-file scan loop, so a malformed entry
        // must never leave this function (issue #54).
        feed = mergeFeeds(feed, cached.entries.filter(isValidFeedIOC));
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
const FEED_ENTRY_KEYS = new Set([
  "type", "value", "severity", "confidence", "family", "campaign", "firstSeen", "note", "ecosystem",
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
  // URL-ish indicator: printable ASCII, no whitespace, and a structure floor
  // of 8+ chars (bundled entries include host/path URLs and 42-char 0x wallet
  // addresses; a 1-char printable like "(" must not pass - same flood risk).
  url: /^[\x21-\x7e]{8,}$/,
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
  const prefix = `${eco}:`;
  const caseInsensitive = eco === "nuget";
  const wantName = caseInsensitive ? name.toLowerCase() : name;

  for (const ioc of entries) {
    if (ioc.type !== "package") continue;
    if (!ioc.value.toLowerCase().startsWith(prefix)) continue;

    const rest = ioc.value.substring(prefix.length);
    // Split "name@version" at the last "@". Ecosystem-prefixed names never
    // start with "@" (npm scopes stay unprefixed), so index 0 means bare name.
    const at = rest.lastIndexOf("@");
    const iocName = at > 0 ? rest.substring(0, at) : rest;
    const iocVersion = at > 0 ? rest.substring(at + 1) : undefined;

    const nameMatches = caseInsensitive
      ? iocName.toLowerCase() === wantName
      : iocName === wantName;
    if (!nameMatches) continue;

    if (iocVersion === undefined) return ioc; // bare-name IOC: any version
    if (version !== undefined && iocVersion === version) return ioc;
  }

  return null;
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
