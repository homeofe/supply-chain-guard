/**
 * Known Indicators of Compromise (IOC) blocklist.
 *
 * Contains known malicious domains, IPs, hashes, GitHub accounts,
 * and compromised package versions. Updated as new threats emerge.
 */

// ---------------------------------------------------------------------------
// Known malicious C2 domains
// ---------------------------------------------------------------------------

export const KNOWN_C2_DOMAINS: string[] = [
  // Vidar stealer C2 (Claude Code leak campaign, April 2026)
  "rti.cargomanbd.com",

  // GlassWorm C2 domains
  "connect.*.workers.dev",

  // Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)
  "audit.checkmarx.cx",
  "checkmarx.cx",

  // CanisterSprawl npm worm / TeamPCP Update 008 (April 2026)
  "whereisitat.lucyatemysuperbox.space",

  // MacSync Stealer / malicious Homebrew ad (May 2026)
  "glowmedaesthetics.com",

  // DAEMON Tools QUIC RAT supply-chain attack (May 2026)
  "env-check.daemontools.cc",

  // Beagle backdoor / fake Claude AI website (May 2026)
  "claude-pro.com",
  "license.claude-pro.com",

  // TCLBANKER Brazilian banking trojan via trojanized Logitech AI Prompt Builder (May 2026)
  "campagna1-api.ef971a42.workers.dev",
  "documents.ef971a42.workers.dev",
  "mxtestacionamentos.com",

  // JDownloader site compromise / Python RAT installers (May 2026)
  "parkspringshotel.com",
  "auraguest.lk",
  "checkinnhotels.com",

  // Fake OpenAI Privacy Filter on Hugging Face / sefirah infostealer (May 2026)
  "recargapopular.com",

  // MacSync Stealer Claude.ai/Google ads variant (May 2026)
  "customroofingcontractors.com",
  "bernasibutuwqu2.com",
  "briskinternet.com",

  // Mini Shai-Hulud Worm / TeamPCP - TanStack/UiPath/Mistral/OpenSearch/Guardrails compromise (May 2026)
  "filev2.getsession.org",
  "seed1.getsession.org",
  "api.masscan.cloud",
  "git-tanstack.com",

  // node-ipc credential stealer via maintainer email hijack (May 2026)
  "sh.azurestaticprovider.net",

  // Phantom Bot DDoS + Shai-Hulud clone npm infostealer (deadcode09284814, May 2026)
  // Leaked Shai-Hulud source code re-weaponized for Golang DDoS + credential theft
  "87e0bbc636999b.lhr.life",
  "edcf8b03c84634.lhr.life",

  // Mini Shai-Hulud @antv wave + actions-cool tag hijack + Nx Console (May 2026)
  // Shared C2 domain across all three concurrent TeamPCP supply-chain attacks
  // (637 @antv versions, actions-cool/issues-helper + maintain-one-comment, nrwl.angular-console 18.95.0)
  "t.m-kosche.com",

  // Laravel-Lang DebugElevator PHP credential stealer (May 23, 2026)
  // 4 Composer packages hijacked via abused GitHub version tags, ~700 historical
  // versions republished with src/helpers.php containing ~5,900-line PHP stealer.
  // Exfiltrates to /exfil endpoint; PDB references developer "Mero" and "claude".
  "flipboxstudio.info",

  // TrapDoor cross-ecosystem credential stealer (npm/PyPI/Crates.io, May 25, 2026)
  // 34+ malicious packages across three registries by single actor ddjidd564
  // targeting AI / DeFi / Web3 developers. GitHub Pages dead-drop C2.
  "ddjidd564.github.io",

  // Polymarket impersonation npm publisher polymarketdev (May 22, 2026)
  // 9 npm packages typosquatting Polymarket SDK; wallet-key exfiltration via
  // Cloudflare Worker. Surfaced alongside Megalodon GitHub Actions campaign.
  "polymarketbot.polymarketdev.workers.dev",

  // ACR Stealer fake Claude page / Google Search malvertising (SANS ISC diary 33018, May 26, 2026)
  // Claude-impersonation pages pushed via Google Search ads serve a corrupted zip that
  // fetches a PowerShell script leading to ACR Stealer. Base domains stored (attacker-
  // controlled; subdomains rotate). i.ibb.co (legit ImgBB image host abused to stage
  // init-block.jpg) is intentionally NOT listed to avoid mass false positives.
  "fairpoint29.com",
  "primemetricsa.com",
  "creativecommunityinfo.art",
  "enhanceblabber.cc",

  // codexui-android npm token stealer (Aikido, disclosed May 27, 2026; THN June 1, 2026)
  // Legitimate-looking Codex remote-UI npm package (~27K-29K weekly downloads since
  // 0.1.82). Reads the user's OpenAI Codex auth file, XOR-encrypts with key
  // "anyclaw2026", base64-encodes and POSTs to /startlog on the C2. Same endpoint is
  // hit by the bundled Android apps "OpenClaw Codex Claude AI Agent" and "Codex"
  // running the package in a PRoot sandbox. Package still live at publish time.
  "sentry.anyclaw.store",

  // LiteLLM PyPI supply-chain compromise (March 24, 2026; re-disclosed Trail of Bits May 22, 2026)
  // TeamPCP-claimed compromise of litellm 1.82.7 / 1.82.8 dropped a litellm_init.pth
  // that auto-runs on every Python startup. Three-stage payload: 50+ category cred
  // harvester (RSA-4096 + AES-256 hybrid encryption) exfil to models.litellm.cloud,
  // Kubernetes lateral-movement toolkit, persistent backdoor polling checkmarx.zone
  // (Checkmarx-brand abuse to bypass DNS allowlists) every 50 minutes for second
  // stages. Origin: poisoned Trivy in LiteLLM's own CI/CD.
  "models.litellm.cloud",
  "checkmarx.zone",
];

// ---------------------------------------------------------------------------
// Known malicious C2 IPs
// ---------------------------------------------------------------------------

export const KNOWN_C2_IPS: string[] = [
  // GhostSocks C2 (Claude Code leak campaign, April 2026)
  "147.45.197.92",
  "94.228.161.88",

  // Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)
  "94.154.172.43",
  "91.195.240.123",

  // EtherRAT fallback C2 (April 2026)
  "135.125.255.55",

  // Beagle backdoor / fake Claude AI website (May 2026)
  "8.217.190.58",

  // TCLBANKER Brazilian banking trojan (May 2026)
  "191.96.224.96",

  // Mini Shai-Hulud Worm / TeamPCP - TanStack/UiPath/Mistral/OpenSearch/Guardrails (May 2026)
  "83.142.209.194",

  // node-ipc credential stealer DNS exfiltration endpoint (May 2026)
  "37.16.75.69",

  // Phantom Bot DDoS C2 (deadcode09284814 npm infostealer, May 2026)
  "80.200.28.28",

  // Megalodon GitHub Actions workflow injection campaign (May 22, 2026)
  // C2 receives base64-encoded CI secrets / cloud creds / SSH keys / OIDC tokens on port 8443
  "216.126.225.129",

  // DPRK OtterCookie Node.js stealer (SANS ISC diary 33006, May 22, 2026)
  // Ports 8085 (browser creds), 8086 (file uploads), 8087/api/notify (WebSocket reverse shell)
  // Same /24 subnet as Megalodon C2 (216.126.225.0/24) - likely shared DPRK infrastructure
  "216.126.225.243",

  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // easy-day-js@1.11.22 postinstall dropper -> cross-platform Node.js crypto-stealer RAT.
  // Dropper C2 on :8000 (/update/49890878); RAT C2 on :443 (/49890878). Both Hostwinds-hosted.
  "23.254.164.92",
  "23.254.164.123",
];

// ---------------------------------------------------------------------------
// Known dead-drop resolver URLs
// ---------------------------------------------------------------------------

export const KNOWN_DEAD_DROPS: string[] = [
  // Vidar dead-drop resolvers (Claude Code leak campaign)
  "steamcommunity.com/profiles/76561198721263282",
  "telegram.me/g1n3sss",
  "t.me/g1n3sss",
];

// ---------------------------------------------------------------------------
// Known malicious file hashes (MD5)
// ---------------------------------------------------------------------------

export const KNOWN_MALICIOUS_HASHES: Record<string, string> = {
  // Claude Code leak campaign (April 2026)
  "d8256fbc62e85dae85eb8d4b49613774": "Claude Code malware archive",
  "8660646bbc6bb7dc8f59a764e25fe1fd": "Claude Code malware archive (variant)",
  "77c73bd5e7625b7f691bc00a1b561a0f": "ClaudeCode_x64.exe Rust dropper",
  "81fb210ba148fd39e999ee9cdc085dfc": "ClaudeCode_x64.exe Rust dropper (variant)",
  "9a6ea91491ccb1068b0592402029527f": "Vidar v18.7 stealer",
  "3388b415610f4ae018d124ea4dc99189": "GhostSocks proxy malware",

  // MacSync Stealer / malicious Homebrew ad (May 2026)
  "a4fcfecc5ac8fa57614b23928a0e9b7aa4f4a3b2b3a8c1772487b46277125571": "MacSync Stealer payload (SHA256)",
  "0d58616c750fc8530a7e90eee18398ddedd08cc0f4908c863ab650673b9819dd": "MacSync Stealer variant (SHA256)",
  "86d0c50cab4f394c58976c44d6d7b67a7dfbbb813fbcf622236e183d94fd944f": "MacSync Stealer variant (SHA256)",

  // TCLBANKER Brazilian banking trojan (May 2026) — REF3076 / trojanized Logitech AI Prompt Builder
  "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626": "TCLBANKER component (SHA256)",
  "8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059": "TCLBANKER component (SHA256)",
  "668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40": "TCLBANKER component (SHA256)",
  "63beb7372098c03baab77e0dfc8e5dca5e0a7420f382708a4df79bed2d900394": "TCLBANKER component (SHA256)",

  // MacSync Stealer Claude.ai/Google ads variant (May 2026) - loader.sh + payload
  "ed5ed79a674972d1506dd8d68e8e13658125267ade86bfcb1ab794e2b49e50ac": "MacSync Stealer Claude.ai variant payload (SHA256)",
  "a833ad989b68dad582a1b591b8cf63466e79c850ff72916cf5d4c4a7f6bc650e": "MacSync Stealer Claude.ai variant loader (SHA256)",

  // node-ipc credential stealer via maintainer email hijack (May 2026) - obfuscated CJS bundle
  "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144": "node-ipc.cjs credential stealer payload (SHA256)",

  // Mini Shai-Hulud TanStack wave router_init.js payload (May 2026)
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c": "Mini Shai-Hulud router_init.js TanStack payload (SHA256)",

  // Mini Shai-Hulud @antv wave - 498KB obfuscated Bun index.js payload (May 19, 2026)
  "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c": "Mini Shai-Hulud @antv index.js Bun payload (SHA256)",

  // Nx Console nrwl.angular-console 18.95.0 compromise (May 18, 2026)
  "1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8": "Nx Console 18.95.0 malicious VSIX (SHA256)",
  "b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74": "Nx Console 18.95.0 main.js (SHA256)",
  "e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1": "Nx Console 18.95.0 obfuscated index.js payload (SHA256)",
  "43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd8": "Nx Console 18.95.0 dropper package.json (SHA256)",

  // Nx Console malicious orphan commit SHA - referenced in VS Code globalState key (May 2026)
  "558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2": "Nx Console malicious orphan commit (Git SHA)",

  // DPRK OtterCookie Node.js stealer (SANS ISC diary 33006, May 22, 2026)
  // Obfuscator.io-style obfuscation; 41 crypto-wallet extension IDs; 200+ file patterns; uses
  // hardcoded HMAC-SHA256 key "SuperStr0ngSecret@)@^"; WSL/macOS/Linux scanning
  "049300aa5dd774d6c984779a0570f59610399c71864b5d5c2605906db46ddeb9": "DPRK OtterCookie Node.js stealer payload (SHA256)",

  // Laravel-Lang DebugElevator PHP credential stealer (May 23, 2026)
  // Hijacked Composer packages laravel-lang/{lang,http-statuses,attributes,actions}; ~700 versions
  // republished with malicious src/helpers.php exfiltrating to flipboxstudio.info/exfil
  "f0d912c1a72e533417d5e158bb9755f848ec678b6448ae7c8fb6e87da78a3053": "DebugElevator src/helpers.php PHP stealer (SHA256)",
  "23e779555c21beaed6ae8f1f298daf9b00d603f1a6716ce329332aadcb80fbe2": "DebugElevator src/helpers.php PHP stealer variant (SHA256)",

  // ACR Stealer fake Claude page / Google Search malvertising (SANS ISC diary 33018, May 26, 2026)
  // Corrupted zip -> PowerShell loader -> ACR Stealer infection chain.
  "70b5ecc110e074dbca92932c0e840ea3492ea0a43c3f215b71392c12b02213b2": "ACR Stealer fake-Claude page component (SHA256)",
  "a14c3ecf5eb3d2543358482e43dc765dbf9ee7a4bec7571f5ecb8829ca719692": "ACR Stealer fake-Claude page component (SHA256)",
  "47fa746422f1bf6b7712dc6803378e6a995488007193a7441d790f70d204728f": "ACR Stealer fake-Claude page component (SHA256)",

  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // Only the malicious easy-day-js@1.11.22 tarball + stage-2 RAT are recorded; the clean
  // precursor easy-day-js@1.11.21 is intentionally NOT listed to avoid false positives.
  "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf": "Mastra attack easy-day-js stage-2 Node.js crypto-stealer RAT (SHA256)",
  "4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417": "easy-day-js@1.11.22 malicious npm tarball (SHA256)",
};

// ---------------------------------------------------------------------------
// Known malicious GitHub accounts
// ---------------------------------------------------------------------------

export const KNOWN_MALICIOUS_GITHUB_ACCOUNTS: string[] = [
  "idbzoomh",
  "idbzoomh1",
  "my3jie",

  // BufferZoneCorp sleeper Go modules / poisoned Ruby gems (May 2026)
  "BufferZoneCorp",

  // TeamPCP / Mr_Rot13 - Checkmarx Jenkins AST plugin compromise + cPanel CVE-2026-41940 (May 2026)
  "Mr_Rot13",
  "TeamPCP",

  // Mini Shai-Hulud TanStack wave staging forks (May 2026)
  "voicproducoes",
  "zblgg",

  // Phantom Bot DDoS + Shai-Hulud clone npm infostealer publisher (May 2026)
  "deadcode09284814",

  // Packagist 8-package Linux binary supply-chain attack (May 23, 2026)
  // Attacker pushed dev-branch commits to 8 Composer packages whose package.json
  // postinstall scripts pull a Linux ELF binary (gvfsd-network) from this account's
  // GitHub Releases to /tmp/.sshd. Account removed but still referenced in package
  // manifests of compromised dev branches.
  "parikhpreyash4",

  // TrapDoor cross-ecosystem credential stealer (May 25, 2026)
  // Single actor maintaining 34+ malicious packages across npm/PyPI/Crates.io
  // and a GitHub Pages dead-drop at ddjidd564.github.io.
  "ddjidd564",

  // Polymarket impersonation npm publisher (May 22, 2026)
  // 9 typosquats of Polymarket SDK with wallet-key exfiltration.
  "polymarketdev",

  // Megalodon GitHub Actions workflow injection throwaways (May 22, 2026)
  // Throwaway accounts pushed 5,718 workflow-injection commits to 5,561 repos in
  // ~6 hours, forging author identities like build-bot / auto-ci / ci-bot / pipeline-bot.
  "rkb8el9r",
  "bhlru9nr",
  "lo6wt4t6",

  // Malware-Slop npm infostealer mouse5212-super-formatter (OX Security via THN, May 27, 2026)
  // Throwaway account created May 26, 2026 (hours before first malicious publish); the npm
  // package authenticates to GitHub and recursively uploads /mnt/user-data (Claude AI user
  // directory) files into attacker-created repos under this account. Account now removed.
  "unplowed3584",

  // codexui-android npm token stealer publisher (Aikido, May 27, 2026)
  // GitHub identity behind the malicious codex-mobile / codexui-android project. Also
  // operates under the "BrutalStrike" handle (5M+ install Android FPS game uses shared
  // infrastructure). Listed for source-code references to the project repo.
  "friuns2",
  "BrutalStrike",

  // Sicoob.Sdk NuGet impersonation + vpmdhaj npm cloud-secret stealers (Socket via THN, May 28-29, 2026)
  // Sicoob-Cooperativa is a GitHub org spun up to lend legitimacy to the fake Sicoob
  // banking SDK NuGet package; joaobcdev is the listed contributor; the 14 sibling
  // npm packages were published under the npm account "vpmdhaj" (a39155771@gmail.com)
  // and used the X-Secret HTTP header "l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1" for C2 auth.
  "Sicoob-Cooperativa",
  "joaobcdev",

  // SStar Agent fake "smart contract engineer" job lure (THN ThreatsDay Bulletin, June 11, 2026)
  // Social-engineering / contagious-interview style lure: a GitHub repo
  // star45674/smart-contract-engineer-role poses as a coding assignment whose
  // npm dependency tw-style-utils deploys the cross-platform SStar Agent RAT
  // (Windows + macOS). Account tracked for repo references in lure assignments.
  "star45674",

  // Malicious Android APK host (THN ThreatsDay Bulletin, June 11, 2026)
  // GitHub account antoniocastaldo1998 hosts a malicious Android APK in its
  // app-scuola repository, pulled down by a separate dropper chain.
  "antoniocastaldo1998",

  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // Compromised npm maintainer account "ehindero" (forgotten contributor with publish
  // rights across the @mastra scope) republished 141 packages with the malicious
  // easy-day-js dependency; "sergey2016" is the linked attacker-controlled account.
  // npm publisher handles, tracked here for source-reference matching.
  "ehindero",
  "sergey2016",

  // Miasma LeoPlatform / GitHub Actions wave (The Hacker News, June 26, 2026)
  // "czirker" is the compromised LeoPlatform npm maintainer account used to republish the
  // leo-* / rstreams-* / serverless-leo / hexo-* packages with a preinstall stealer. npm
  // publisher handle tracked here for source-reference matching (github.com/czirker).
  "czirker",
];

// ---------------------------------------------------------------------------
// Known compromised npm package versions
// ---------------------------------------------------------------------------

export const KNOWN_BAD_NPM_VERSIONS: Record<string, { versions: string[]; description: string }> = {
  "ua-parser-js": {
    versions: ["0.7.29", "0.8.0", "1.0.0"],
    description: "ua-parser-js hijack: crypto miner + credential stealer (Oct 2021)",
  },
  "coa": {
    versions: ["2.0.3", "2.0.4"],
    description: "coa npm hijack: sdd.dll trojan payload (Nov 2021)",
  },
  "rc": {
    versions: ["1.2.9", "1.3.9", "2.3.9"],
    description: "rc npm hijack: sdd.dll trojan payload (Nov 2021)",
  },
  "event-stream": {
    versions: ["3.3.6"],
    description: "event-stream: flatmap-stream backdoor targeting copay wallet (Nov 2018)",
  },
  "axios": {
    versions: ["1.14.1", "0.30.4"],
    description: "axios hijack: embedded RAT (plain-crypto-js) (March 2026)",
  },
  "colors": {
    versions: ["1.4.1", "1.4.2"],
    description: "colors.js protestware: infinite loop (Jan 2022)",
  },
  "faker": {
    versions: ["6.6.6"],
    description: "faker.js protestware: infinite loop + data wipe (Jan 2022)",
  },
  "node-ipc": {
    versions: ["9.1.6", "9.2.3", "10.1.1", "10.1.2", "10.1.3", "12.0.1"],
    description: "node-ipc supply chain attacks: 9.1.6/9.2.3/12.0.1 credential stealer via maintainer email hijack with DNS exfiltration (May 2026); 10.1.x protestware (Mar 2022)",
  },
  "@bitwarden/cli": {
    versions: ["2026.4.0"],
    description: "Bitwarden CLI hijack: bw_setup.js/bw1.js credential stealer linked to Checkmarx KICS breach (April 2026)",
  },
  "@cap-js/sqlite": {
    versions: ["2.2.2"],
    description: "Mini Shai-Hulud / TeamPCP: SAP CAP npm hijack with preinstall hook + Bun-based credential stealer (April 2026)",
  },
  "@cap-js/postgres": {
    versions: ["2.2.2"],
    description: "Mini Shai-Hulud / TeamPCP: SAP CAP npm hijack with preinstall hook + Bun-based credential stealer (April 2026)",
  },
  "@cap-js/db-service": {
    versions: ["2.10.1"],
    description: "Mini Shai-Hulud / TeamPCP: SAP CAP npm hijack with preinstall hook + Bun-based credential stealer (April 2026)",
  },
  "mbt": {
    versions: ["1.2.48"],
    description: "Mini Shai-Hulud / TeamPCP: SAP MTA build tool hijack with preinstall hook + Bun-based credential stealer (April 2026)",
  },
  "intercom-client": {
    versions: ["7.0.4"],
    description: "Mini Shai-Hulud / TeamPCP: intercom-client npm hijack with preinstall hook + credential stealer (April 2026)",
  },
  "@opensearch-project/opensearch": {
    versions: ["3.5.3", "3.6.2", "3.7.0", "3.8.0"],
    description: "Mini Shai-Hulud / TeamPCP: OpenSearch npm client hijack with worm payload (May 2026)",
  },
  "@squawk/mcp": {
    versions: ["0.9.5"],
    description: "Mini Shai-Hulud / TeamPCP: Squawk MCP server hijack with worm payload (May 2026)",
  },
  "@squawk/weather": {
    versions: ["0.5.10"],
    description: "Mini Shai-Hulud / TeamPCP: Squawk weather hijack with worm payload (May 2026)",
  },
  "@squawk/flightplan": {
    versions: ["0.5.6"],
    description: "Mini Shai-Hulud / TeamPCP: Squawk flightplan hijack with worm payload (May 2026)",
  },
  "@tallyui/connector-medusa": {
    versions: ["1.0.1", "1.0.2", "1.0.3"],
    description: "Mini Shai-Hulud / TeamPCP: TallyUI Medusa connector hijack (May 2026)",
  },
  "@tallyui/connector-vendure": {
    versions: ["1.0.1", "1.0.2", "1.0.3"],
    description: "Mini Shai-Hulud / TeamPCP: TallyUI Vendure connector hijack (May 2026)",
  },
  "postmark-mcp": {
    versions: ["1.0.16"],
    description: "postmark-mcp hostile MCP server: developer-introduced hidden BCC of every outbound email to attacker-controlled address; 1.0.15 and earlier are clean (Sep 2025)",
  },
  // --- Mini Shai-Hulud @antv wave (May 19, 2026) -------------------------------
  // Compromised npm maintainer account "atool"; 637 versions across 317 packages
  // published 01:39-02:18 UTC on 2026-05-19. Payload: 498KB obfuscated Bun index.js
  // exfiltrating to t.m-kosche.com. Versions below per Aikido + Snyk analysis.
  "@antv/g2": {
    versions: ["5.5.8", "5.6.8"],
    description: "Mini Shai-Hulud / TeamPCP: @antv ecosystem npm hijack via atool maintainer account (May 2026)",
  },
  "@antv/g6": {
    versions: ["5.2.1", "5.3.1"],
    description: "Mini Shai-Hulud / TeamPCP: @antv ecosystem npm hijack via atool maintainer account (May 2026)",
  },
  "echarts-for-react": {
    versions: ["3.1.7", "3.2.7"],
    description: "Mini Shai-Hulud / TeamPCP: echarts-for-react hijack via atool maintainer account (May 2026)",
  },
  "timeago.js": {
    versions: ["4.1.2", "4.2.2"],
    description: "Mini Shai-Hulud / TeamPCP: timeago.js hijack via atool maintainer account (May 2026)",
  },
  "codexui-android": {
    versions: ["0.1.82", "0.1.83", "0.1.84", "0.1.85", "0.1.86", "0.1.87", "0.1.88", "0.1.89", "0.1.90"],
    description: "codexui-android: OpenAI Codex auth-token stealer; XOR (key 'anyclaw2026') + base64 POST to sentry.anyclaw.store/startlog (Aikido, disclosed May 2026)",
  },
  // --- Miasma / @redhat-cloud-services Mini Shai-Hulud variant (June 1, 2026) -----
  // 32 packages, 96 versions trojanized via compromised Red Hat employee GitHub
  // account abusing a GitHub Actions workflow. Payload "Miasma: The Spreading
  // Blight" - preinstall runs ~4.2 MB index.js, exfils CI/cloud creds to ~309
  // attacker-controlled GitHub repos. Only the package@version pair confirmed by
  // Socket is recorded here; the @redhat-cloud-services namespace itself is NOT
  // blocked, the clean upstream versions remain legitimate.
  "@redhat-cloud-services/chrome": {
    versions: ["2.3.1"],
    description: "Mini Shai-Hulud variant 'Miasma: The Spreading Blight': trojanized @redhat-cloud-services/chrome with preinstall credential stealer; Red Hat employee GitHub account compromise + GitHub Actions abuse (BleepingComputer + Socket.dev, June 2026)",
  },
  // --- Arch Linux AUR mass hijack npm dropper (June 12, 2026) ---------------------
  // 400+ Arch User Repository packages had their build scripts rewritten to pull and run
  // the malicious npm package atomic-lockfile, which installs a credential stealer + eBPF
  // rootkit on any machine that builds them. Version 1.4.2 was published 2026-06-10 and
  // removed by npm security 2026-06-12 (superseded by the 0.0.1-security holding
  // placeholder). Confirmed by The Hacker News + BleepingComputer and the npm registry.
  "atomic-lockfile": {
    versions: ["1.4.2"],
    description: "Arch Linux AUR mass-hijack npm dropper: atomic-lockfile@1.4.2 installs a credential stealer + eBPF rootkit via AUR build-script preinstall hooks; pulled by npm security 2026-06-12 (The Hacker News + BleepingComputer, June 2026)",
  },
  // --- Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026) ----
  // Forgotten-contributor npm account "ehindero" was compromised and used to republish
  // 141 packages across the @mastra scope (01:12-02:36 UTC, 2026-06-17), each gaining a
  // single new dependency: easy-day-js, a dayjs clone whose postinstall hook disables TLS
  // verification, contacts attacker C2 (23.254.164.92:8000), downloads and detaches a
  // cross-platform Node.js crypto-stealer RAT (166 wallet-extension inventory + browser
  // history harvest). Microsoft attributes to Sapphire Sleet/BlueNoroff (also behind the
  // April 2026 axios hijack). easy-day-js@1.11.21 is the clean precursor; only 1.11.22 is
  // malicious. Representative subset of the 143 compromised package@version pairs recorded.
  "easy-day-js": {
    versions: ["1.11.22"],
    description: "Mastra npm scope takeover (Sapphire Sleet/BlueNoroff, DPRK): dayjs clone whose postinstall hook drops a cross-platform Node.js crypto-stealer RAT (disables TLS verify, C2 23.254.164.92); injected as a dependency into 143 republished @mastra packages via compromised maintainer 'ehindero' (June 2026)",
  },
  "@mastra/core": {
    versions: ["1.42.1"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/agent-builder": {
    versions: ["1.0.42"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/auth": {
    versions: ["1.0.3"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/claude": {
    versions: ["1.0.3"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/express": {
    versions: ["1.3.31"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/openai": {
    versions: ["1.0.2"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "mastra": {
    versions: ["1.13.1"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "create-mastra": {
    versions: ["1.13.1"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  // --- NastyC2 npm framework (THN ThreatsDay Bulletin, June 18, 2026) ------------------
  // Three fully malicious npm packages bundling NastyC2, a Rust post-exploitation implant
  // implementing 80+ commands (credential harvesting, Active Directory attacks, container
  // escape, cloud-metadata theft, fileless execution).
  "node-ci-utils": {
    versions: ["2.1.4"],
    description: "NastyC2 npm framework: Rust post-exploitation implant (80+ commands: credential harvesting, AD attacks, container escape, cloud-metadata theft, fileless execution) (THN ThreatsDay, June 2026)",
  },
  "win-env-setup": {
    versions: ["3.0.6"],
    description: "NastyC2 npm framework: Rust post-exploitation implant (80+ commands: credential harvesting, AD attacks, container escape, cloud-metadata theft, fileless execution) (THN ThreatsDay, June 2026)",
  },
  "macos-ci-utils": {
    versions: ["1.0.0"],
    description: "NastyC2 npm framework: Rust post-exploitation implant (80+ commands: credential harvesting, AD attacks, container escape, cloud-metadata theft, fileless execution) (THN ThreatsDay, June 2026)",
  },
  // --- crypto-javascript cross-ecosystem worm (THN ThreatsDay Bulletin, June 18, 2026) -
  // Self-propagating supply-chain worm spreading across Rust/Cargo, Python, CMake, and npm
  // ecosystems; drops a Monero cryptominer and the "Dirty Frag" Linux kernel LPE exploit.
  // GCC build timestamp 2026-04-30. Version-pinned (common-sounding name).
  "crypto-javascript": {
    versions: ["4.2.5"],
    description: "Cross-ecosystem supply-chain worm (Rust/Cargo/Python/CMake/npm): bundles a Monero cryptominer + 'Dirty Frag' Linux kernel LPE exploit (THN ThreatsDay, June 2026)",
  },
  // --- Miasma LeoPlatform / GitHub Actions wave (The Hacker News, June 26, 2026) ---
  // Latest evolution of the Mini Shai-Hulud / Miasma / Hades worm family. The compromised
  // npm maintainer account "czirker" (LeoPlatform) republished the LeoPlatform / RStreams
  // SDK packages plus hexo-* plugins with a preinstall stealer; the worm also propagated to
  // the Go ecosystem (github.com/verana-labs/verana-blockchain@v0.10.1-dev.20, recorded in
  // BUNDLED_FEED) and abused the codfish/semantic-release-action GitHub Action. Exfil into
  // ~559 dead-drop repos with description "Alright Lets See If This Works"; token-relay
  // marker "RevokeAndItGoesKaboom". Only the confirmed package@version pairs are pinned;
  // the clean upstream versions of these packages remain legitimate.
  "leo-sdk": {
    versions: ["6.0.19"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-sdk republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-streams": {
    versions: ["2.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-streams republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-auth": {
    versions: ["4.0.6"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-auth republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-aws": {
    versions: ["2.0.4"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-aws republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-cache": {
    versions: ["1.0.2"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-cache republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-cdk-lib": {
    versions: ["0.0.2"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-cdk-lib republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-cli": {
    versions: ["3.0.3"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-cli republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-config": {
    versions: ["1.1.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-config republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-elasticsearch": {
    versions: ["2.0.6"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-elasticsearch republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-mongo": {
    versions: ["3.0.8"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-mongo republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-mysql": {
    versions: ["3.0.3"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-mysql republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-oracle": {
    versions: ["2.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-oracle republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-redshift": {
    versions: ["3.0.6"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-redshift republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-cron": {
    versions: ["2.0.2"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-cron republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-logger": {
    versions: ["1.0.8"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-logger republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "rstreams-metrics": {
    versions: ["2.0.2"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): rstreams-metrics republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "rstreams-shard-util": {
    versions: ["1.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): rstreams-shard-util republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "serverless-leo": {
    versions: ["3.0.14"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): serverless-leo republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "serverless-convention": {
    versions: ["2.0.4"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): serverless-convention republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "prism-silq": {
    versions: ["1.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): prism-silq republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "solo-nav": {
    versions: ["1.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): solo-nav republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "hexo-deployer-wrangler": {
    versions: ["1.0.4"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): hexo-deployer-wrangler republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "hexo-shoka-swiper": {
    versions: ["0.1.10"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): hexo-shoka-swiper republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
};

// ---------------------------------------------------------------------------
// Known compromised PyPI package versions
// ---------------------------------------------------------------------------

export const KNOWN_BAD_PYPI_VERSIONS: Record<string, { versions: string[]; description: string }> = {
  "ctx": {
    versions: ["0.1.2", "0.2.6"],
    description: "ctx PyPI hijack: steals environment variables (May 2022)",
  },
  "lightning": {
    versions: ["2.6.2", "2.6.3"],
    description: "Mini Shai-Hulud / TeamPCP: PyTorch Lightning PyPI hijack with credential stealer payload (April 2026)",
  },
  "xinference": {
    versions: ["2.6.0", "2.6.1", "2.6.2"],
    description: "TeamPCP Update 008: xinference PyPI hijack with '# hacked by teampcp' marker + credential stealer (April 2026)",
  },
  "guardrails-ai": {
    versions: ["0.10.1"],
    description: "Mini Shai-Hulud / TeamPCP: Guardrails AI PyPI hijack with worm payload (May 2026)",
  },
  "mistralai": {
    versions: ["2.4.6"],
    description: "Mini Shai-Hulud / TeamPCP: Mistral AI PyPI client hijack with worm payload (May 2026)",
  },
  "durabletask": {
    versions: ["1.4.1", "1.4.2", "1.4.3"],
    description: "Mini Shai-Hulud / TeamPCP: officially Microsoft-published durabletask Python SDK trojanized (SANS ISC diary 33016, May 24, 2026)",
  },
  "litellm": {
    versions: ["1.82.7", "1.82.8"],
    description: "LiteLLM PyPI compromise (TeamPCP): litellm_init.pth auto-runs on Python startup; RSA-4096+AES-256 credential exfil to models.litellm.cloud; persistent backdoor polling checkmarx.zone every 50min (March 24, 2026; Trail of Bits write-up May 22, 2026)",
  },
};

// ---------------------------------------------------------------------------
// Utility: check if a string contains any known IOC
// ---------------------------------------------------------------------------

import type { Finding } from "./types.js";

/**
 * Check content against known IOC blocklists.
 */
// v5.2.21: documentation files (.md/.markdown/.txt/.rst) legitimately discuss
// malware IOCs in threat-intel write-ups, changelog entries, and blog posts.
// The IOC blocklist exists to flag actual references in source code, not to
// hit research discussion. Same rationale as patterns.ts BENIGN_DOC_FILES.
const BENIGN_DOC_FILES = /\.(md|markdown|txt|rst)$/i;

export function checkIOCBlocklist(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  // Skip documentation files - IOCs there are discussion, not exploitation.
  if (BENIGN_DOC_FILES.test(relativePath)) return findings;
  const contentLower = content.toLowerCase();

  // Check known C2 domains
  for (const domain of KNOWN_C2_DOMAINS) {
    const domainPattern = domain.replace(/\./g, "\\.").replace(/\*/g, "\\w+");
    const regex = new RegExp(domainPattern, "i");
    if (regex.test(content)) {
      findings.push({
        rule: "IOC_KNOWN_C2_DOMAIN",
        description: `Known malicious C2 domain detected: ${domain}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This domain is a known command-and-control server. Quarantine this code immediately.",
      });
    }
  }

  // Check known C2 IPs
  for (const ip of KNOWN_C2_IPS) {
    if (content.includes(ip)) {
      findings.push({
        rule: "IOC_KNOWN_C2_IP",
        description: `Known malicious C2 IP address detected: ${ip}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This IP is a known command-and-control server. Quarantine this code immediately.",
      });
    }
  }

  // Check known dead-drop resolvers
  for (const url of KNOWN_DEAD_DROPS) {
    if (contentLower.includes(url.toLowerCase())) {
      findings.push({
        rule: "IOC_KNOWN_DEAD_DROP",
        description: `Known dead-drop resolver URL detected: ${url}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This URL is used as a dead-drop resolver to retrieve C2 addresses. This is a strong malware indicator.",
      });
    }
  }

  // Check known malicious hashes
  for (const [hash, desc] of Object.entries(KNOWN_MALICIOUS_HASHES)) {
    if (contentLower.includes(hash.toLowerCase())) {
      findings.push({
        rule: "IOC_KNOWN_MALWARE_HASH",
        description: `Known malware hash detected: ${hash} (${desc})`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This hash matches known malware. Do not execute any associated files.",
      });
    }
  }

  // Check known malicious GitHub accounts
  for (const account of KNOWN_MALICIOUS_GITHUB_ACCOUNTS) {
    const pattern = new RegExp(`github\\.com/${account}\\b`, "i");
    if (pattern.test(content)) {
      findings.push({
        rule: "IOC_KNOWN_MALICIOUS_ACCOUNT",
        description: `Reference to known malicious GitHub account: ${account}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This GitHub account is known to distribute malware. Do not clone or use code from this source.",
      });
    }
  }

  return findings;
}

/**
 * Check a package name + version against the known-bad blocklist.
 */
export function checkBadVersion(
  name: string,
  version: string,
  ecosystem: "npm" | "pypi" | "ruby" | "composer" | "nuget",
): Finding | null {
  // ruby/composer/nuget have no pinned entries yet (their curated IOCs live in
  // threat-intel.ts as ecosystem-prefixed package entries); the union is open
  // so future BAD_VERSIONS entries can target them without an API change.
  const blocklist: Record<string, { versions: string[]; description: string }> =
    ecosystem === "npm"
      ? KNOWN_BAD_NPM_VERSIONS
      : ecosystem === "pypi"
        ? KNOWN_BAD_PYPI_VERSIONS
        : {};

  const entry = blocklist[name];
  if (!entry) return null;

  if (entry.versions.includes(version)) {
    return {
      rule: "IOC_KNOWN_BAD_VERSION",
      description: `Known compromised package version: ${name}@${version} — ${entry.description}`,
      severity: "critical",
      recommendation: `Remove ${name}@${version} immediately. This version contains known malware. Upgrade to a clean version.`,
    };
  }

  return null;
}
