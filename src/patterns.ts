/**
 * Known malicious patterns database
 *
 * This file is designed to be regularly updated as new threats emerge.
 * Add new patterns, wallet addresses, or domain patterns as they are discovered.
 */

import type { Finding, PatternEntry, Severity } from "./types.js";

/** Matches the scanner's own source files — used to prevent self-scan false positives. */
const SCANNER_SRC = /(?:patterns|scanner|playbooks|correlation-engine|ioc-blocklist|threat-intel|remediation-engine|secret-simulator|workflow-modeler|config-scanner|install-hook-scanner|github-trust-scanner|dependency-confusion|attack-graph|reporter|active-validation|solana-monitor|solana-watchlist|slsa-verifier|sbom-generator)\.(ts|js)$/;

// v5.2.21: documentation files (.md/.markdown/.txt/.rst) legitimately discuss
// malware markers as part of threat-intel write-ups, changelog entries, blog
// posts, and academic research. Patterns that match source-code-embedded
// markers (campaign signatures, IOC strings, infostealer paths, C2 references)
// must skip these to avoid flagging discussion as malware.
//
// Used together with SCANNER_SRC via SCANNER_SRC_OR_DOCS. Patterns whose
// design is to fire on documentation (LURE_PATTERNS, PROMPT_INJECTION_PATTERNS)
// keep plain SCANNER_SRC and stay on their onlyFilePattern scope.
const BENIGN_DOC_FILES = /\.(md|markdown|txt|rst)$/i;
const SCANNER_SRC_OR_DOCS = new RegExp(
  `(?:${SCANNER_SRC.source})|(?:${BENIGN_DOC_FILES.source})`,
  "i",
);

// ---------------------------------------------------------------------------
// GlassWorm-specific IOCs
// ---------------------------------------------------------------------------

/** Known GlassWorm marker variables */
export const GLASSWORM_MARKERS = ["lzcdrtfxyqiplpd"];

/** Known GlassWorm Solana wallet addresses used for C2 */
export const KNOWN_C2_WALLETS: string[] = [
  // Add confirmed wallet addresses here as they are discovered
  // Example: "2fTGKciRBTwLpcMVMPGwWEqGkRrG7MkR1FoKGhCPNw2S"
];

/** Known C2 domain patterns (regex strings) */
export const C2_DOMAIN_PATTERNS: string[] = [
  // Domains seen in GlassWorm payloads
  "connect\\.\\w+\\.workers\\.dev",
  "\\w+-api\\.\\w+\\.workers\\.dev",
];

// ---------------------------------------------------------------------------
// File-based detection patterns
// ---------------------------------------------------------------------------

export const FILE_PATTERNS: PatternEntry[] = [
  // GlassWorm marker
  {
    name: "glassworm-marker",
    pattern: "lzcdrtfxyqiplpd",
    description: "GlassWorm campaign marker variable detected",
    severity: "critical",
    rule: "GLASSWORM_MARKER",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },

  // Invisible Unicode characters (zero-width spaces, joiners, etc.)
  // v5.10: the surrogate-pair alternative \uDB40[\uDC00-\uDC7F] covers the
  // Unicode Tags block (U+E0000..U+E007F) used for ASCII smuggling - invisible
  // instructions encoded for an LLM agent that a human reviewer cannot see.
  {
    name: "invisible-unicode",
    pattern:
      "(?:[\\u200B\\u200C\\u200D\\u2060\\uFEFF\\u00AD\\u034F\\u061C\\u180E\\u2028\\u2029\\u202A-\\u202E\\u2066-\\u2069]|\\uDB40[\\uDC00-\\uDC7F]){3,}",
    description:
      "Suspicious invisible Unicode characters detected (potential code obfuscation or ASCII smuggling)",
    severity: "high",
    rule: "INVISIBLE_UNICODE",
    notTestFile: true,
  },

  // Encoded eval/exec patterns
  {
    name: "eval-atob",
    pattern: "eval\\s*\\(\\s*atob\\s*\\(",
    description: "Base64-encoded eval detected (common malware obfuscation)",
    severity: "critical",
    rule: "EVAL_ATOB",
    notTestFile: true,
  },
  {
    name: "eval-buffer-from",
    pattern: "eval\\s*\\(\\s*Buffer\\.from\\s*\\(",
    description:
      "Buffer-encoded eval detected (common malware obfuscation in Node.js)",
    severity: "critical",
    rule: "EVAL_BUFFER",
    notTestFile: true,
  },
  {
    name: "new-function-atob",
    pattern: "new\\s+Function\\s*\\(\\s*atob\\s*\\(",
    description:
      "Base64-encoded Function constructor detected (malware obfuscation)",
    severity: "critical",
    rule: "FUNCTION_ATOB",
    notTestFile: true,
  },
  {
    name: "eval-buffer-hex",
    pattern: "eval\\s*\\(\\s*Buffer\\.from\\s*\\([^)]+,\\s*['\"]hex['\"]\\s*\\)",
    description: "Hex-encoded eval detected",
    severity: "critical",
    rule: "EVAL_HEX",
    notTestFile: true,
  },
  {
    name: "exec-encoded",
    pattern:
      "exec\\s*\\(\\s*(?:atob|Buffer\\.from|decodeURIComponent)\\s*\\(",
    description: "Encoded exec call detected",
    severity: "high",
    rule: "EXEC_ENCODED",
    notTestFile: true,
  },

  // Solana C2 references
  {
    name: "solana-mainnet",
    pattern: "mainnet-beta\\.solana\\.com",
    description: "Solana mainnet RPC reference detected (potential C2 channel)",
    severity: "medium",
    rule: "SOLANA_MAINNET",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "helius-rpc",
    pattern: "helius(?:-rpc)?\\.(?:com|dev)",
    description:
      "Helius Solana RPC reference detected (used in GlassWorm C2)",
    severity: "medium",
    rule: "HELIUS_RPC",
    notTestFile: true,
  },

  // Obfuscation patterns
  {
    name: "hex-string-array",
    pattern:
      "\\[\\s*(?:0x[0-9a-fA-F]+\\s*,\\s*){10,}",
    description: "Large hex array detected (potential obfuscated payload)",
    severity: "medium",
    rule: "HEX_ARRAY",
    notTestFile: true,
  },
  {
    name: "string-char-concat",
    pattern:
      "(?:String\\.fromCharCode|\\\\x[0-9a-fA-F]{2}){5,}",
    description:
      "Character code string construction detected (obfuscation technique)",
    severity: "medium",
    rule: "CHARCODE_OBFUSCATION",
    notTestFile: true,
  },

  // Network exfiltration
  {
    name: "env-exfil",
    pattern:
      "process\\.env\\b[^;]*(?:fetch|https?\\.(?:get|request)|axios|got|node-fetch)",
    description:
      "Environment variable access combined with network request (data exfiltration pattern)",
    severity: "high",
    rule: "ENV_EXFILTRATION",
    notTestFile: true,
  },
  {
    name: "dns-exfil",
    pattern: "dns\\.resolve.*process\\.env",
    description: "DNS-based data exfiltration pattern detected",
    severity: "high",
    rule: "DNS_EXFILTRATION",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Suspicious file names
// ---------------------------------------------------------------------------

/** Files that are suspicious by name alone */
export const SUSPICIOUS_FILES: Array<{
  pattern: string;
  description: string;
  severity: Severity;
  rule: string;
}> = [
  {
    pattern: "^i\\.js$",
    description:
      "Suspicious i.js file (commonly used as GlassWorm payload dropper)",
    severity: "high",
    rule: "SUSPICIOUS_I_JS",
  },
  {
    pattern: "^init\\.json$",
    description:
      "init.json persistence file (used by GlassWorm for configuration persistence)",
    severity: "high",
    rule: "SUSPICIOUS_INIT_JSON",
  },
];

// ---------------------------------------------------------------------------
// Suspicious npm scripts
// ---------------------------------------------------------------------------

/** Package.json script patterns that are suspicious */
export const SUSPICIOUS_SCRIPTS: PatternEntry[] = [
  {
    name: "postinstall-curl",
    pattern: "curl\\s+.*\\|\\s*(?:bash|sh|node)",
    description: "postinstall script downloads and executes remote code",
    severity: "critical",
    rule: "SCRIPT_CURL_EXEC",
    notTestFile: true,
  },
  {
    name: "postinstall-wget",
    pattern: "wget\\s+.*\\|\\s*(?:bash|sh|node)",
    description: "postinstall script downloads and executes remote code",
    severity: "critical",
    rule: "SCRIPT_WGET_EXEC",
    notTestFile: true,
  },
  {
    name: "postinstall-node-e",
    pattern: "node\\s+-e\\s+[\"'].*(?:http|https|fetch|require)",
    description:
      "postinstall script executes inline Node.js with network access",
    severity: "high",
    rule: "SCRIPT_NODE_INLINE",
    notTestFile: true,
  },
  {
    name: "postinstall-encoded",
    pattern: "(?:atob|Buffer\\.from|base64)",
    description: "postinstall script contains encoding/decoding operations",
    severity: "high",
    rule: "SCRIPT_ENCODED",
    notTestFile: true,
  },
  {
    name: "preinstall-exec",
    pattern: "(?:exec|spawn|execSync)\\s*\\(",
    description: "preinstall script executes system commands",
    severity: "medium",
    rule: "SCRIPT_PREINSTALL_EXEC",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Known malicious npm package name patterns
// ---------------------------------------------------------------------------

/** Patterns matching known malicious or typosquatting package names */
export const MALICIOUS_PACKAGE_PATTERNS: string[] = [
  // Fake Paysafe / Skrill / Neteller payment SDKs (Socket, July 8, 2026) - 13
  // npm packages (v1.0.0-1.0.3) impersonating non-existent official payment
  // SDKs; anchored so only these exact names match, never legitimate wrappers.
  "^(paysafe-checkout|paysafe-vault|paysafe-js|paysafe-api|paysafe-node|paysafe-cards|paysafe-fraud|paysafe-kyc|paysafe-payments|skrill|skrill-sdk|skrill-payments|neteller)$",
  // Typosquatting common packages
  "^(lodas|1odash|l0dash|lodash-es-utils)$",
  "^(cros-env|cross-env-shell|crossenv)$",
  "^(bable-cli|babelcli)$",
  "^(event-streem|event_stream)$",

  // GlassWorm campaign packages (pattern: random-looking names)
  "^[a-z]{15,}$", // Very long single-word lowercase names

  // DPRK AI-inserted npm malware (April 2026)
  "^@validate-sdk\\/v2$",

  // BufferZoneCorp poisoned Ruby gems (May 2026)
  "^knot-(activesupport-logger|devise-jwt-helper|rack-session-store|rails-assets-pipeline|rspec-formatter-json|date-utils-rb|simple-formatter)$",

  // BufferZoneCorp sleeper Go modules (May 2026)
  "^github\\.com/BufferZoneCorp/(go-metrics-sdk|go-weather-sdk|go-retryablehttp|go-stdlib-ext|grpc-client|net-helper|config-loader|log-core|go-envconfig)$",

  // ZiChatBot PyPI campaign (May 2026)
  // Drops terminate.dll/terminate.so + uses Zulip REST APIs as C2; potential APT32/OceanLotus link
  "^(uuid32-utils|colorinal|termncolor)$",

  // Phantom Bot DDoS + Shai-Hulud clone npm infostealer (deadcode09284814, May 2026)
  // Four packages from publisher deadcode09284814 carrying leaked Shai-Hulud worm source +
  // Golang Phantom Bot DDoS module (HTTP/TCP/UDP flood + TCP reset). 2,678 combined downloads.
  "^(chalk-tempalte|axois-utils|color-style-utils)$",
  "^@deadcode09284814\\/axios-util$",

  // Nx Console nrwl.angular-console v18.95.0 - compromised VS Code extension (May 18, 2026)
  // Listed for direct name match in extensions.json / dependency manifests.
  "^nrwl\\.angular-console$",

  // TrapDoor cross-ecosystem credential stealer - npm packages (May 25, 2026)
  // 21 malicious npm packages from actor ddjidd564 targeting AI/DeFi/Web3 devs.
  // Reported by The Hacker News May 25, 2026; sibling PyPI/Crates.io waves.
  "^(async-pipeline-builder|build-scripts-utils|chain-key-validator|crypto-credential-scanner|defi-env-auditor|defi-threat-scanner|deployment-key-auditor|dev-env-bootstrapper|eth-wallet-sentinel|llm-context-compressor|mnemonic-safety-check|model-switch-router|node-setup-helpers|project-init-tools|prompt-engineering-toolkit|solidity-deploy-guard|token-usage-tracker|wallet-backup-verifier|wallet-security-checker|web3-secrets-detector|workspace-config-loader)$",

  // Polymarket impersonation - typosquats of Polymarket SDK (May 22, 2026)
  // Publisher polymarketdev; wallet-key exfiltration via Cloudflare Worker.
  "^polymarket-(trading-cli|terminal|trade|auto-trade|copy-trading|bot|claude-code|ai-agent|trader)$",

  // Malware-Slop npm infostealer (OX Security via The Hacker News, May 27, 2026)
  // Fully malicious package by actor unplowed3584; uploads Claude AI user-directory files to GitHub.
  "^mouse5212-super-formatter$",

  // codexui-android npm Codex token stealer (Aikido, disclosed May 27, 2026)
  // Legitimate-looking Codex remote-UI package; since 0.1.82 every invocation XOR-encrypts
  // the OpenAI Codex auth file (key "anyclaw2026") + base64 + POST to sentry.anyclaw.store.
  "^codexui-android$",

  // vpmdhaj cloud-secret npm cluster (Socket via The Hacker News, May 28-29, 2026)
  // 14 npm typosquats of OpenSearch / ElasticSearch / DevOps / env-config libraries
  // by actor "vpmdhaj" (a39155771@gmail.com); preinstall hooks harvest AWS creds,
  // HashiCorp Vault tokens, npm tokens, CI/CD secrets. Published alongside the
  // Sicoob.Sdk NuGet impersonation. Scoped @vpmdhaj/* names + unscoped typosquats.
  "^@vpmdhaj\\/(devops-tools|elastic-helper|opensearch-setup|search-setup)$",
  "^(app-config-utility|elastic-opensearch-helper|env-config-manager|opensearch-config-utility|opensearch-security-scanner|opensearch-setup|opensearch-setup-tool|search-cluster-setup|search-engine-setup|vpmdhaj-opensearch-setup)$",

  // June 2026 npm infostealer cluster (The Hacker News Weekly Recap, June 8, 2026)
  // turbo-axios / faster-axios: trojanized axios copies whose postinstall hooks deploy
  // Epsilon Stealer. cms-store-ren: exfiltrates harvested data to Telegram via an exposed
  // bot API token. parsimonius: typosquat of "parsimonious" deploying a Telegram-based
  // backdoor (published to both npm and PyPI; ~2,474 downloads before removal).
  "^(turbo-axios|faster-axios|cms-store-ren|parsimonius)$",

  // ThreatsDay Bulletin npm cluster (The Hacker News, June 11, 2026)
  // tw-style-utils: poisoned npm package delivering the cross-platform SStar Agent
  // RAT (Windows + macOS), distributed via the star45674/smart-contract-engineer-role
  // fake job-assignment lure. ambar-src: fully malicious npm package (Tenable) whose
  // download count was artificially "pumped" to 50,000+ in three days.
  "^(tw-style-utils|ambar-src)$",

  // Arch Linux AUR mass hijack npm dropper (The Hacker News + BleepingComputer, June 12, 2026)
  // 400+ Arch User Repository packages had their build scripts rewritten with preinstall
  // hooks that download and run the fully malicious npm package atomic-lockfile, which
  // installs a credential stealer + eBPF rootkit. atomic-lockfile@1.4.2 was published
  // 2026-06-10 and pulled by npm security 2026-06-12 (replaced by the 0.0.1-security
  // holding placeholder). Bare-name indicator: the package has no legitimate history.
  "^atomic-lockfile$",

  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // easy-day-js is an attacker-created dayjs clone (no legitimate history) injected as a
  // dependency into 141 republished @mastra packages via compromised maintainer "ehindero".
  // Its postinstall hook drops a cross-platform Node.js crypto-stealer RAT. Microsoft
  // attributes to Sapphire Sleet/BlueNoroff (also behind the April 2026 axios hijack).
  "^easy-day-js$",

  // NastyC2 npm framework (THN ThreatsDay Bulletin, June 18, 2026)
  // Three fully malicious npm packages bundling NastyC2, a Rust post-exploitation implant
  // (80+ commands: credential harvesting, AD attacks, container escape, cloud-metadata
  // theft, fileless execution). Bare names; each package has no legitimate purpose.
  "^(node-ci-utils|win-env-setup|macos-ci-utils)$",

  // PostCSS-impersonation npm packages deliver Windows RAT (The Hacker News, June 23, 2026)
  // Malicious npm packages posing as PostCSS tooling deliver a Windows-based remote access
  // trojan. aes-decode-runner-pro (145 downloads) + postcss-min are fully malicious; bare names.
  "^(postcss-min|aes-decode-runner-pro)$",

  // Contagious Interview "Fake Font" npm + Go wave / InvisibleFerret (The Hacker News, June 29, 2026)
  // DPRK Contagious Interview operation. Two attacker-uploaded npm packages and a cluster of
  // 16 Go modules conceal a hidden VS Code task ("eslint-check") plus a JavaScript payload
  // disguised as a web font (public/fonts/fa-solid-400.woff2) that deploys the InvisibleFerret
  // Python backdoor, using TronGrid/Aptos blockchain transactions as a dead-drop resolver.
  // The npm packages were uploaded 2026-05-25 and removed - bare-name indicators with no
  // legitimate history. The font filename and task name are deliberately NOT used as
  // signatures: both collide with legitimate FontAwesome assets / lint tasks (false positives).
  "^(html-to-gutenberg|fetch-page-assets)$",
  "^github\\.com/(lambda-platform/(lambda|ebarimt-rest-api|dan)|reauheau/goaubio|glacialspring/(go-winsparkle|static)|bm-197/chill|naol7/dist-task-scheduler|anatoli-derese/a2sv-excercise|amantsehay/a2sv-go-course|dexbotsdev/uniswap-v2-v3-arbitrage|zainirfan13/graphql-client|hngi/team-fierce-backend-golang|rickt/slack-weather-bot|Barsu5489/commerce|Setsu548/Logistic)$",

  // Contagious Interview Rollup polyfill npm packages (Lazarus, DPRK) (The Hacker News / JFrog, July 3, 2026)
  // Six attacker-uploaded npm packages masquerading as Rollup polyfill tooling to facilitate
  // remote access + developer-secret theft. Fresh DPRK Contagious Interview wave; C2 216.126.236.244
  // (in ioc-blocklist). Each package is fully malicious with no legitimate history - bare names.
  "^(rollup-packages-polyfill-core|rollup-runtime-polyfill-core|rollup-plugin-polyfill-connect|quirky-token|react-icon-svgs|swift-parse-stream)$",

  // ViteVenom - malicious Vite npm packages w/ blockchain C2 (Checkmarx via The Hacker News, July 18, 2026)
  // Threat actor "SuccessKey"; expansion of ChainVeil. Seven scoped packages impersonating the
  // "@vitejs/*" namespace (published June 29-July 3, 2026) whose payload runs at IMPORT time and
  // delivers a RAT via a Tron/Aptos/BNB Smart Chain blockchain C2. Fully malicious, no legitimate
  // history - anchored to these exact names (the broad scoped catch-all below would also match, but
  // the directory-scan MALICIOUS_DEPENDENCY path uses the exact feed names, so pin them explicitly).
  "^(@uw010010\\/vite-tree|@vite-tab\\/tab|@vite-ln\\/build-ts|@vite-mcp\\/vite-type|@vite-pro\\/vite-ui|@vitets\\/vite-ts|@vite-ts\\/vite-ui)$",

  // Suspicious scoped packages mimicking official ones
  "^@(?!types|babel|eslint|jest|rollup|vitejs|vue|angular|react|next|nuxt|svelte|reduxjs|tanstack|trpc).*\\/.*$",
];

// ---------------------------------------------------------------------------
// Campaign-specific patterns (real-world supply-chain attacks)
// ---------------------------------------------------------------------------

export const CAMPAIGN_PATTERNS: PatternEntry[] = [
  // --- XZ Utils Backdoor (CVE-2024-3094) ---
  {
    name: "xz-get-cpuid",
    pattern: "_get_cpuid",
    description:
      "XZ Utils backdoor indicator: _get_cpuid function (CVE-2024-3094 payload hook)",
    severity: "critical",
    rule: "XZ_GET_CPUID",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "xz-lzma-crc64",
    pattern: "lzma_crc64",
    description:
      "XZ Utils backdoor indicator: lzma_crc64 function reference (CVE-2024-3094 hijacked symbol)",
    severity: "high",
    rule: "XZ_LZMA_CRC64",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "xz-build-inject",
    pattern:
      "gl_cv_host_cpu_c_abi.*=.*configure\\.ac|AM_CONDITIONAL.*\\bgl_INIT\\b|m4/.*\\.m4.*ifnot",
    description:
      "XZ Utils backdoor indicator: build system injection pattern in configure.ac/m4 macros",
    severity: "high",
    rule: "XZ_BUILD_INJECT",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "xz-obfuscated-test",
    pattern:
      "tests/files/.*\\.xz.*\\bhead\\b.*\\btr\\b|\\bxz\\b.*-d.*\\|.*\\bhead\\b.*-c",
    description:
      "XZ Utils backdoor indicator: obfuscated test file extraction pattern (hidden payload in test fixtures)",
    severity: "high",
    rule: "XZ_OBFUSCATED_TEST",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Codecov Bash Uploader ---
  {
    name: "codecov-curl-bash",
    pattern:
      "curl\\s+[^|]*codecov\\.io[^|]*\\|\\s*(?:bash|sh)",
    description:
      "Codecov bash uploader pattern: curl from codecov.io piped to shell (supply-chain risk vector)",
    severity: "high",
    rule: "CODECOV_CURL_BASH",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "codecov-exfil",
    pattern:
      "codecov[^;]*(?:ENV|TOKEN|SECRET|CREDENTIAL|PASSWORD|API_KEY)|(?:ENV|TOKEN|SECRET|CREDENTIAL|PASSWORD|API_KEY)[^;]*codecov",
    description:
      "Codecov exfiltration indicator: environment secrets referenced alongside codecov operations",
    severity: "high",
    rule: "CODECOV_EXFIL",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- SolarWinds SUNBURST ---
  {
    name: "sunburst-dga",
    pattern: "avsvmcloud\\.com",
    description:
      "SolarWinds SUNBURST indicator: DGA C2 domain avsvmcloud.com detected",
    severity: "critical",
    rule: "SUNBURST_DGA",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "sunburst-orion-class",
    pattern: "OrionImprovementBusinessLayer",
    description:
      "SolarWinds SUNBURST indicator: OrionImprovementBusinessLayer class name (backdoor namespace)",
    severity: "critical",
    rule: "SUNBURST_ORION_CLASS",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "sunburst-delayed-exec",
    pattern:
      "(?:Thread\\.Sleep|setTimeout|sleep)\\s*\\([^)]*?(?:[0-9]{7,}|\\d+\\s*\\*\\s*(?:3600|86400|60\\s*\\*\\s*60))",
    description:
      "SUNBURST-style delayed execution: sleep/timeout exceeding 1 hour (evasion technique to avoid sandbox analysis)",
    severity: "high",
    rule: "SUNBURST_DELAYED_EXEC",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- ua-parser-js hijack ---
  {
    name: "uaparser-miner",
    pattern:
      "(?:jsextension|jsextension\\.exe|__package\\.json).*(?:curl|wget|https?://)|(?:curl|wget|https?://).*(?:jsextension|jsextension\\.exe|__package\\.json)",
    description:
      "ua-parser-js hijack indicator: crypto miner download pattern (jsextension binary)",
    severity: "critical",
    rule: "UAPARSER_MINER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "uaparser-preinstall-download",
    pattern:
      "preinstall[\"']?\\s*:\\s*[\"'][^\"']*(?:curl|wget)\\s+https?://[^\"']*(?:\\.exe|\\.sh|\\.bat)",
    description:
      "ua-parser-js hijack indicator: preinstall script downloading executables from external domains",
    severity: "critical",
    rule: "UAPARSER_PREINSTALL_DL",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026) ---
  {
    name: "checkmarx-shai-hulud-third-coming",
    pattern: "Shai-Hulud:?\\s*The\\s+Third\\s+Coming",
    description:
      "Shai-Hulud Third Coming marker detected. Signature string used by the April 2026 Bitwarden CLI / Checkmarx KICS supply-chain breach to label exfiltration repositories.",
    severity: "critical",
    rule: "CHECKMARX_SHAI_HULUD_V3",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "checkmarx-mcp-addon",
    pattern: "mcpAddon\\.js",
    description:
      "Reference to mcpAddon.js. This is the hidden 'MCP addon' loader downloaded by the compromised Checkmarx KICS extensions in April 2026.",
    severity: "critical",
    rule: "CHECKMARX_MCP_ADDON",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "bitwarden-cli-loader",
    pattern: "\\b(?:bw_setup|bw1)\\.js\\b",
    description:
      "Reference to bw_setup.js or bw1.js. Loader and credential-stealing payload from the @bitwarden/cli@2026.4.0 hijack (April 2026).",
    severity: "critical",
    rule: "BITWARDEN_CLI_LOADER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- LofyGang / LofyStealer (April 2026) ---
  {
    name: "lofystealer-marker",
    pattern: "\\b(?:LofyStealer|GrabBot)\\b",
    description:
      "LofyStealer / GrabBot marker detected. Brazilian LofyGang campaign (April 2026) targeting Minecraft players with infostealer disguised as Minecraft hacks.",
    severity: "critical",
    rule: "LOFYSTEALER_MARKER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "lofygang-minecraft-lure",
    pattern: "(?:minecraft|mc)[\\s\\-_]*(?:hack|cheat|client|loader)\\b[^\\n]{0,100}\\b(?:steal|grab|exfil|token|password|wallet)",
    description:
      "Minecraft hack lure combined with credential/wallet theft language. LofyGang campaign distribution pattern.",
    severity: "high",
    rule: "LOFYGANG_MINECRAFT_LURE",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- DPRK AI-inserted npm malware (April 2026) ---
  {
    name: "dprk-validate-sdk",
    pattern: "@validate-sdk\\/v2",
    description:
      "Reference to @validate-sdk/v2 detected. DPRK-linked malicious npm package (April 2026) inserted as a dependency by Claude Opus LLM in social engineering attacks.",
    severity: "critical",
    rule: "DPRK_VALIDATE_SDK",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- ZiChatBot PyPI campaign (May 2026) ---
  {
    name: "zichatbot-package-name",
    pattern: "\\b(?:uuid32-utils|colorinal|termncolor)\\b",
    description:
      "Reference to ZiChatBot PyPI campaign package (uuid32-utils, colorinal, termncolor). May 2026 campaign suspected linked to APT32/OceanLotus, dropping terminate.dll/terminate.so via PyPI install.",
    severity: "critical",
    rule: "ZICHATBOT_PACKAGE",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Mini Shai-Hulud / TeamPCP supply chain worm (April 2026) ---
  {
    name: "mini-shai-hulud-marker",
    pattern: "A\\s+Mini\\s+Shai-Hulud\\s+has\\s+Appeared",
    description:
      "Mini Shai-Hulud campaign marker detected. Signature description string used by the April 2026 SAP CAP / PyTorch Lightning / Intercom worm to label dead-drop GitHub repositories.",
    severity: "critical",
    rule: "MINI_SHAI_HULUD_MARKER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "mini-shai-hulud-bun-loader",
    pattern: "[\"'`/\\\\\\s\\[]\\s*(?:setup\\.mjs|execution\\.js)\\b",
    description:
      "Reference to setup.mjs or execution.js detected. Loader filenames used by the Mini Shai-Hulud preinstall worm to download Bun runtime and execute the credential stealer payload.",
    severity: "high",
    rule: "MINI_SHAI_HULUD_LOADER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "mini-shai-hulud-preinstall-bun",
    pattern: "preinstall[\"']?\\s*:\\s*[\"'][^\"']*\\bbun\\b[^\"']*(?:setup\\.mjs|execution\\.js)",
    description:
      "preinstall script invoking Bun on setup.mjs or execution.js. Direct fingerprint of the Mini Shai-Hulud worm's npm hijack chain.",
    severity: "critical",
    rule: "MINI_SHAI_HULUD_PREINSTALL",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Mini Shai-Hulud @antv / Nx Console / actions-cool wave (May 2026) ---
  // Triple-wave TeamPCP attack: @antv ecosystem (637 versions), Nx Console
  // nrwl.angular-console 18.95.0 VS Code extension, and actions-cool/issues-helper +
  // actions-cool/maintain-one-comment GitHub Action tag redirection. Persistence backdoor
  // installs `cat.py` Python daemon under kitty/kitty-monitor naming, polling GitHub Search
  // for dead-drop commands with marker query "firedalazer".
  {
    name: "antv-wave-kitty-cat-py",
    pattern: "(?:kitty/cat\\.py|com\\.user\\.kitty-monitor|kitty-monitor\\.service)",
    description:
      "Reference to kitty/cat.py Python backdoor or kitty-monitor persistence service. Persistence chain dropped by the May 2026 Mini Shai-Hulud @antv / Nx Console wave (TeamPCP).",
    severity: "critical",
    rule: "ANTV_WAVE_KITTY_PERSISTENCE",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "antv-wave-firedalazer-deaddrop",
    pattern: "firedalazer",
    description:
      "Reference to 'firedalazer' marker. GitHub Search API dead-drop query string used by the Nx Console 18.95.0 backdoor (May 2026 Mini Shai-Hulud wave).",
    severity: "critical",
    rule: "ANTV_WAVE_FIREDALAZER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "antv-wave-otel-c2-masquerade",
    pattern: "m-kosche\\.com[^\"']*api/public/otel/v1/traces",
    description:
      "Mini Shai-Hulud @antv wave C2 exfiltration endpoint masquerading as an OpenTelemetry traces collector at t.m-kosche.com (May 2026).",
    severity: "critical",
    rule: "ANTV_WAVE_OTEL_C2",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- DPRK OtterCookie Node.js stealer (May 22, 2026) ---
  // SANS ISC diary 33006. Sample uploaded to VT as "extracted-decoded.js"; obfuscator.io-style;
  // targets 41 crypto-wallet Chrome extensions and 200+ sensitive file patterns. Exfil to
  // 216.126.225.243 ports 8085 (browser creds) / 8086 (file uploads) / 8087 (WebSocket reverse shell).
  {
    name: "ottercookie-hmac-key",
    pattern: "SuperStr0ngSecret@\\)@\\^",
    description:
      "Reference to 'SuperStr0ngSecret@)@^' detected. Hardcoded HMAC-SHA256 key embedded in the DPRK OtterCookie Node.js stealer (SANS ISC 33006, May 2026). Highly specific fingerprint.",
    severity: "critical",
    rule: "OTTERCOOKIE_HMAC_KEY",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "ottercookie-notify-endpoint",
    pattern: "216\\.126\\.225\\.243:808[567](?:/api/notify)?",
    description:
      "Reference to 216.126.225.243:8085/8086/8087 detected. DPRK OtterCookie stealer C2 endpoints (browser creds / file uploads / WebSocket reverse shell at /api/notify).",
    severity: "critical",
    rule: "OTTERCOOKIE_C2_ENDPOINT",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Megalodon GitHub Actions workflow injection (May 22, 2026) ---
  // 5,718 malicious commits to 5,561 GitHub repositories in 6 hours via throwaway accounts
  // forged as "build-bot", "auto-ci", "ci-bot", "pipeline-bot". Injected workflows ran
  // base64-encoded bash that exfiltrated CI env vars, AWS / GCP credentials, SSH private keys,
  // OIDC tokens, Docker / Kubernetes / Terraform configs to 216.126.225.129:8443.
  {
    name: "megalodon-c2-endpoint",
    pattern: "216\\.126\\.225\\.129(?::8443)?",
    description:
      "Reference to 216.126.225.129:8443 detected. Megalodon GitHub Actions workflow-injection C2 (May 2026); collects base64-encoded CI secrets, AWS/GCP credentials, SSH keys, OIDC tokens, and source-code secrets.",
    severity: "critical",
    rule: "MEGALODON_C2_ENDPOINT",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- coa/rc npm hijack ---
  {
    name: "coa-rc-sdd-dll",
    pattern: "sdd\\.dll",
    description:
      "coa/rc npm hijack indicator: reference to sdd.dll payload (trojanized npm package artifact)",
    severity: "critical",
    rule: "COA_RC_SDD_DLL",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "coa-rc-postinstall-encoded",
    pattern:
      "postinstall[\"']?\\s*:\\s*[\"'][^\"']*(?:compile\\.js|(?:Buffer|atob).*(?:exec|spawn|child_process))",
    description:
      "coa/rc npm hijack indicator: postinstall script with encoded payload execution",
    severity: "critical",
    rule: "COA_RC_POSTINSTALL",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Miasma / @redhat-cloud-services Mini Shai-Hulud variant (June 2026) ---
  // BleepingComputer + Socket.dev disclosed (June 1, 2026) that 32 packages under
  // Red Hat's @redhat-cloud-services namespace were trojanized (96 versions) via a
  // compromised Red Hat employee GitHub account + abused GitHub Actions workflow.
  // Payload is a Shai-Hulud descendant labelled "Miasma: The Spreading Blight",
  // preinstall runs a ~4.2 MB node index.js stealing GitHub Actions secrets, AWS
  // and GCP and Azure credentials, HashiCorp Vault tokens, Kubernetes SA tokens,
  // npm and PyPI publishing tokens, SSH keys, Docker creds, GPG keys, and .env
  // files. Exfiltration into ~309 attacker-controlled GitHub repos.
  {
    name: "miasma-spreading-blight-marker",
    pattern: "Miasma:?\\s*The\\s+Spreading\\s+Blight",
    description:
      "Miasma campaign marker detected. Signature string used by the June 2026 @redhat-cloud-services Mini Shai-Hulud variant to label dead-drop GitHub repositories.",
    severity: "critical",
    rule: "MIASMA_SPREADING_BLIGHT_MARKER",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // --- Miasma LeoPlatform / GitHub Actions wave (The Hacker News, June 26, 2026) ---
  // Latest evolution of the Mini Shai-Hulud / Miasma / Hades worm family. Compromised
  // npm maintainer "czirker" republished the LeoPlatform / RStreams SDK + hexo-* packages
  // (version-pinned in ioc-blocklist), propagated to Go, and abused the
  // codfish/semantic-release-action GitHub Action. "RevokeAndItGoesKaboom" is the unique
  // token-relay marker for the current iteration (firedalazer remains the GitHub commit-
  // polling string, already covered by ANTV_WAVE_FIREDALAZER).
  {
    name: "miasma-leo-revoke-kaboom-marker",
    pattern: "RevokeAndItGoesKaboom",
    description:
      "Reference to 'RevokeAndItGoesKaboom' detected. Token-relay marker used by the June 2026 Miasma LeoPlatform Mini Shai-Hulud wave (czirker-compromised leo-* / rstreams-* npm packages).",
    severity: "critical",
    rule: "MIASMA_LEO_REVOKE_KABOOM",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
];

// ---------------------------------------------------------------------------
// PyPI-specific patterns (Python supply-chain attacks)
// ---------------------------------------------------------------------------

/** Patterns for detecting malicious code in Python packages */
export const PYPI_FILE_PATTERNS: PatternEntry[] = [
  // System command execution in setup files
  {
    name: "setup-os-system",
    pattern: "os\\.system\\s*\\(",
    description: "os.system() call detected in package file (potential code execution during install)",
    severity: "high",
    rule: "PYPI_OS_SYSTEM",
    notTestFile: true,
  },
  {
    name: "setup-subprocess",
    pattern: "subprocess\\.(?:call|run|Popen|check_output|check_call)\\s*\\(",
    description: "subprocess execution detected in package file (potential code execution during install)",
    severity: "high",
    rule: "PYPI_SUBPROCESS",
    notTestFile: true,
  },

  // Encoded execution
  {
    name: "python-exec-encoded",
    pattern: "exec\\s*\\(\\s*(?:base64\\.b64decode|codecs\\.decode|bytes\\.fromhex)\\s*\\(",
    description: "exec() with encoded/decoded content detected (obfuscated code execution)",
    severity: "critical",
    rule: "PYPI_EXEC_ENCODED",
    notTestFile: true,
  },
  {
    name: "python-eval-encoded",
    pattern: "eval\\s*\\(\\s*(?:base64\\.b64decode|codecs\\.decode|bytes\\.fromhex)\\s*\\(",
    description: "eval() with encoded/decoded content detected (obfuscated code execution)",
    severity: "critical",
    rule: "PYPI_EVAL_ENCODED",
    notTestFile: true,
  },
  {
    name: "python-exec-compile",
    pattern: "exec\\s*\\(\\s*compile\\s*\\(",
    description: "exec(compile()) detected (dynamic code compilation and execution)",
    severity: "high",
    rule: "PYPI_EXEC_COMPILE",
    notTestFile: true,
  },

  // Base64 import smuggling
  {
    name: "python-import-base64",
    pattern: "__import__\\s*\\(\\s*['\"]base64['\"]\\s*\\)",
    description: "__import__('base64') detected (hidden import often used for payload decoding)",
    severity: "high",
    rule: "PYPI_IMPORT_BASE64",
    notTestFile: true,
  },
  {
    name: "python-import-codecs",
    pattern: "__import__\\s*\\(\\s*['\"]codecs['\"]\\s*\\)",
    description: "__import__('codecs') detected (hidden import for obfuscation)",
    severity: "medium",
    rule: "PYPI_IMPORT_CODECS",
    notTestFile: true,
  },
  {
    name: "python-import-marshal",
    pattern: "__import__\\s*\\(\\s*['\"]marshal['\"]\\s*\\)",
    description: "__import__('marshal') detected (bytecode-level obfuscation)",
    severity: "high",
    rule: "PYPI_IMPORT_MARSHAL",
    notTestFile: true,
  },

  // Network activity in setup files
  {
    name: "python-urllib-setup",
    pattern: "urllib\\.request\\.urlopen\\s*\\(",
    description: "urllib.request.urlopen() detected (network access, potential payload download)",
    severity: "high",
    rule: "PYPI_URLLIB_FETCH",
    notTestFile: true,
  },
  {
    name: "python-requests-setup",
    pattern: "requests\\.(?:get|post)\\s*\\(",
    description: "requests.get/post() detected (network access during install)",
    severity: "medium",
    rule: "PYPI_REQUESTS_FETCH",
    notTestFile: true,
  },

  // Suspicious pip install in setup.py
  {
    name: "python-pip-install-url",
    pattern: "pip\\s+install\\s+(?:--index-url|--extra-index-url|-i)\\s+https?://(?!pypi\\.org)",
    description: "pip install from non-PyPI URL detected (potential malicious package index)",
    severity: "critical",
    rule: "PYPI_SUSPICIOUS_INDEX",
    notTestFile: true,
  },
  {
    name: "python-pip-install-git",
    pattern: "pip\\s+install\\s+git\\+https?://",
    description: "pip install from git URL in setup file (unverified dependency source)",
    severity: "medium",
    rule: "PYPI_GIT_DEPENDENCY",
    notTestFile: true,
  },

  // Data exfiltration patterns in Python
  {
    name: "python-env-exfil",
    pattern: "os\\.environ\\b[^;\\n]*(?:urllib|requests|http\\.client|socket)",
    description: "Environment variable access combined with network activity (data exfiltration pattern)",
    severity: "high",
    rule: "PYPI_ENV_EXFILTRATION",
    notTestFile: true,
  },
  {
    name: "python-hostname-exfil",
    pattern: "socket\\.gethostname\\s*\\(\\)[^;\\n]*(?:urllib|requests|http)",
    description: "Hostname collection combined with network activity (reconnaissance/exfiltration)",
    severity: "high",
    rule: "PYPI_HOSTNAME_EXFIL",
    notTestFile: true,
  },

  // Install command class override
  {
    name: "python-install-class-override",
    pattern: "class\\s+\\w+\\s*\\(\\s*(?:install|develop|bdist_egg|egg_info|sdist)\\s*\\)",
    description: "Custom command class inheriting from setuptools install/develop command",
    severity: "medium",
    rule: "PYPI_INSTALL_CLASS_OVERRIDE",
    notTestFile: true,
  },

  // marshal.loads (bytecode deserialization)
  {
    name: "python-marshal-loads",
    pattern: "marshal\\.loads\\s*\\(",
    description: "marshal.loads() detected (bytecode deserialization, common obfuscation)",
    severity: "high",
    rule: "PYPI_MARSHAL_LOADS",
    notTestFile: true,
  },

  // exec with marshal.loads
  {
    name: "python-exec-marshal",
    pattern: "exec\\s*\\(\\s*marshal\\.loads\\s*\\(",
    description: "exec(marshal.loads()) detected (executing deserialized bytecode payload)",
    severity: "critical",
    rule: "PYPI_EXEC_MARSHAL",
    notTestFile: true,
  },

  // base64.b64decode combined with exec (various arrangements on same line)
  {
    name: "python-b64decode-exec-combined",
    pattern: "base64\\.b64decode\\s*\\([^)]*\\).*\\bexec\\b|\\bexec\\b.*base64\\.b64decode",
    description: "base64.b64decode combined with exec on the same line (obfuscated execution)",
    severity: "critical",
    rule: "PYPI_B64_EXEC_COMBINED",
    notTestFile: true,
  },
];

/** Setup file names to check for install hooks */
export const PYPI_SETUP_FILES = new Set([
  "setup.py",
  "setup.cfg",
  "pyproject.toml",
]);

/** Suspicious install hook patterns in setup.py */
export const PYPI_INSTALL_HOOK_PATTERNS: PatternEntry[] = [
  {
    name: "setup-cmdclass-install",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]install['\"]",
    description: "Custom install command class detected (code runs during pip install)",
    severity: "medium",
    rule: "PYPI_CUSTOM_INSTALL",
    notTestFile: true,
  },
  {
    name: "setup-cmdclass-develop",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]develop['\"]",
    description: "Custom develop command class detected (code runs during pip install -e)",
    severity: "medium",
    rule: "PYPI_CUSTOM_DEVELOP",
    notTestFile: true,
  },
  {
    name: "setup-cmdclass-egg-info",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]egg_info['\"]",
    description: "Custom egg_info command class detected (code runs during package metadata generation)",
    severity: "medium",
    rule: "PYPI_CUSTOM_EGG_INFO",
    notTestFile: true,
  },
  {
    name: "setup-cmdclass-sdist",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]sdist['\"]",
    description: "Custom sdist command class detected (code runs during source distribution build)",
    severity: "low",
    rule: "PYPI_CUSTOM_SDIST",
    notTestFile: true,
  },
  {
    name: "setup-cmdclass-build-ext",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]build_ext['\"]",
    description: "Custom build_ext command class detected (code runs during native extension build)",
    severity: "low",
    rule: "PYPI_CUSTOM_BUILD_EXT",
    notTestFile: true,
  },
];

/** Python file extensions to scan */
export const PYTHON_EXTENSIONS = new Set([
  ".py",
  ".pyw",
  ".pyi",
]);

/** Known typosquatted PyPI package name patterns */
export const PYPI_TYPOSQUAT_PATTERNS: string[] = [
  // Fake Paysafe payment SDKs on PyPI (Socket, July 8, 2026) - 4 packages
  // (v1.0.0). PyPI normalizes "-" and "_", so both separators are matched.
  "^(paysafe[-_](kyc|payments|sdk|api))$",
  // Typosquats of popular PyPI packages
  "^(reqeusts|requsets|r3quests|reequests|requets)$",
  "^(crypt0graphy|crytography|cryptograhpy)$",
  "^(python-dateutill|python3-dateutil|py-dateutil)$",
  "^(numppy|numpi|numpie)$",
  "^(pandsa|pands)$",
  "^(djang0|dajngo|djnago)$",
  "^(urlib3|urllib33)$",
  "^(colourama|colrama|coloram)$",
  "^(setuptool|setuptoolss)$",
  "^(flaskk|flaask|fl4sk)$",

  // TrapDoor cross-ecosystem credential stealer - PyPI packages (May 25, 2026)
  // 7 malicious PyPI packages from the same actor (ddjidd564) operating the npm /
  // Crates.io waves; targets DeFi / Web3 / Solidity / Ethereum developer tooling.
  "^(cryptowallet-safety|data-pipeline-check|defi-risk-scanner|env-loader-cli|eth-security-auditor|git-config-sync|solidity-build-guard)$",

  // parsimonius: PyPI typosquat of "parsimonious" deploying a Telegram-based backdoor
  // (also published to npm; The Hacker News Weekly Recap, June 8, 2026).
  "^parsimonius$",

  // ChocoPoC RAT / fake PoC exploit repos (The Hacker News, July 2, 2026)
  // Malicious PyPI packages carrying the ChocoPoC data-stealing trojan, distributed
  // via fake Python PoC exploit repos targeting vulnerability researchers. skytext / frint
  // are the current wave; slogsec / logcrypt.cryptography are the same actor's late-2025
  // packages. Compiled payloads gradient.so (Linux) / gradient.pyd (Windows); upload server
  // 91.132.163.78 (in ioc-blocklist). Bare names - fully malicious with no legitimate history.
  "^(frint|skytext|slogsec|logcrypt\\.cryptography)$",

  // Very long single-word lowercase names
  "^[a-z]{20,}$",
];

// ---------------------------------------------------------------------------
// Binary / native addon detection (T-007)
// ---------------------------------------------------------------------------

/** File extensions that indicate binary/native addons */
export const BINARY_EXTENSIONS = new Set([
  ".node",
  ".so",
  ".dll",
  ".dylib",
  ".exe",
  ".bin",
]);

/** Patterns in install scripts that indicate prebuilt binary downloads */
export const BINARY_DOWNLOAD_PATTERNS: PatternEntry[] = [
  {
    name: "node-pre-gyp",
    pattern: "node-pre-gyp\\s+install",
    description: "node-pre-gyp prebuilt binary download detected in install script",
    severity: "medium",
    rule: "BINARY_PREGYP_DOWNLOAD",
    notTestFile: true,
  },
  {
    name: "prebuild-install",
    pattern: "prebuild-install|prebuildify",
    description: "Prebuilt binary installer detected in install script",
    severity: "medium",
    rule: "BINARY_PREBUILD_INSTALL",
    notTestFile: true,
  },
  {
    name: "binary-download-curl",
    pattern:
      "(?:curl|wget)\\s+.*\\.(?:node|so|dll|dylib|exe)(?:\\s|$|[\"'])",
    description: "Install script downloads a binary/native file directly",
    severity: "high",
    rule: "BINARY_DIRECT_DOWNLOAD",
    notTestFile: true,
  },
  {
    name: "node-gyp-rebuild",
    pattern: "node-gyp\\s+rebuild",
    description: "Native addon compilation via node-gyp detected",
    severity: "low",
    rule: "BINARY_NATIVE_COMPILE",
    notTestFile: true,
  },
];

/** Known legitimate packages that use native addons */
export const KNOWN_NATIVE_PACKAGES = new Set([
  "better-sqlite3",
  "sharp",
  "canvas",
  "bcrypt",
  "argon2",
  "sqlite3",
  "node-sass",
  "fsevents",
  "esbuild",
  "lightningcss",
  "swc",
  "@swc/core",
  "turbo",
  "@parcel/watcher",
  "keytar",
  "node-pty",
  "bufferutil",
  "utf-8-validate",
  "cpu-features",
  "microtime",
  "farmhash",
  "xxhash-addon",
  "deasync",
  "sodium-native",
  "leveldown",
  "lmdb",
  "libsql",
  "re2",
  "node-datachannel",
  "unix-dgram",
]);

// ---------------------------------------------------------------------------
// Network beacon and crypto miner detection (T-008)
// ---------------------------------------------------------------------------

export const BEACON_MINER_PATTERNS: PatternEntry[] = [
  // Beacon patterns: periodic network calls
  {
    name: "beacon-setinterval-fetch",
    pattern:
      "setInterval\\s*\\(.*(?:fetch|https?\\.(?:get|request)|axios|got|node-fetch|XMLHttpRequest)",
    description:
      "Periodic network request detected (setInterval + fetch). This is a common beacon pattern for C2 communication.",
    severity: "medium",
    rule: "BEACON_INTERVAL_FETCH",
    notFilePattern: /\.min\.(js|css)$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },
  {
    name: "beacon-settimeout-fetch",
    pattern:
      "setTimeout\\s*\\(.*(?:fetch|https?\\.(?:get|request)|axios|got|node-fetch)",
    description:
      "Delayed network request detected (setTimeout + fetch). May be a beacon with jitter.",
    severity: "medium",
    rule: "BEACON_TIMEOUT_FETCH",
    notTestFile: true,
  },

  // Crypto miner patterns
  {
    name: "stratum-protocol",
    pattern:
      "stratum\\+(?:tcp|ssl|tls)://",
    description:
      "Stratum mining pool protocol reference detected. This is used exclusively for cryptocurrency mining.",
    severity: "critical",
    rule: "MINER_STRATUM_PROTOCOL",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "mining-pool-domain",
    pattern:
      "(?:pool\\.|mining\\.|mine\\.|hashrate\\.).*\\.(?:com|org|net|io)|(?:nanopool|ethermine|f2pool|viabtc|antpool|poolin|slushpool|nicehash|minergate|hashflare|2miners|flexpool|ezil|hiveon)\\.(?:com|org|net|io)",
    description:
      "Known mining pool domain detected. This package may contain a cryptocurrency miner.",
    severity: "critical",
    rule: "MINER_POOL_DOMAIN",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "mining-config-keys",
    pattern:
      "(?:\"|\\'|`)(?:wallet|worker|pool_address|pool_password|mining_address|hashrate|coin|algo)(?:\"|\\'|`)\\s*:",
    description:
      "Mining configuration keys detected. This may be a cryptocurrency miner configuration.",
    severity: "high",
    rule: "MINER_CONFIG_KEYS",
    notFilePattern: /\.json$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },
  {
    name: "coinhive-reference",
    pattern:
      "coinhive|cryptonight|monero\\.(?:crypto|mine)|xmrig|xmr-stak",
    description:
      "Cryptocurrency miner library reference detected (CoinHive, XMRig, etc.).",
    severity: "critical",
    rule: "MINER_LIBRARY_REF",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // Suspicious WebSocket connections
  {
    name: "websocket-external",
    pattern:
      "new\\s+WebSocket\\s*\\(\\s*[\"'`]wss?://(?!localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)",
    description:
      "WebSocket connection to external host detected. Verify this is expected for the package's functionality.",
    severity: "medium",
    rule: "BEACON_WEBSOCKET_EXTERNAL",
    notTestFile: true,
  },

  // Protestware patterns: locale/timezone checks + destructive actions
  {
    name: "protestware-locale-destructive",
    pattern:
      "(?:locale|timezone|timeZone|country|getTimezone|Intl\\.DateTimeFormat).*(?:fs\\.(?:rm|rmdir|unlink|writeFile)|process\\.exit|child_process|execSync|rimraf)",
    description:
      "Locale/timezone check followed by destructive code. This is a protestware pattern that targets users by geography.",
    severity: "critical",
    rule: "PROTESTWARE_LOCALE_DESTRUCT",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "protestware-geo-ip",
    pattern:
      "(?:geoip|ip-api|ipinfo|freegeoip|ipgeolocation).*(?:fs\\.(?:rm|rmdir|unlink)|process\\.exit|execSync)",
    description:
      "GeoIP lookup combined with destructive operations detected. This is a protestware/geo-targeted attack pattern.",
    severity: "critical",
    rule: "PROTESTWARE_GEOIP_DESTRUCT",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// File extensions to scan
// ---------------------------------------------------------------------------

export const SCANNABLE_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
  ".mjs",
  ".cjs",
  ".py",
  ".sh",
  ".bash",
  ".json",
  ".yml",
  ".yaml",
  ".toml",
  ".rs",
  ".go",
  ".tf",
  ".hcl",
  ".svg",
  ".md",
]);

/** Maximum file size to scan (in bytes). Files larger than this are skipped. */
export const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

/**
 * Structured finding for an oversized scannable file (issue #54). Before
 * v5.12.0 the core, VSIX, npm, and PyPI scanners silently `continue`d past
 * files above MAX_FILE_SIZE - a coverage gap an attacker can create on
 * purpose by padding a payload past the limit. severity "info" is a
 * transparency signal: it never affects exit codes (only high/critical do)
 * and can be filtered with --min-severity or --exclude FILE_TOO_LARGE_SKIPPED.
 * The oversized body is never read; only fs.stat metadata is reported.
 */
export function makeOversizedSkipFinding(
  relativePath: string,
  sizeBytes: number,
): Finding {
  const sizeMb = (sizeBytes / (1024 * 1024)).toFixed(1);
  const limitMb = (MAX_FILE_SIZE / (1024 * 1024)).toFixed(0);
  return {
    rule: "FILE_TOO_LARGE_SKIPPED",
    description: `File exceeds the ${limitMb} MB scan limit (${sizeMb} MB) - content was NOT scanned`,
    severity: "info",
    confidence: 1.0,
    category: "info",
    file: relativePath,
    recommendation:
      "This file was skipped by content scanning because of its size. Inspect it manually or verify it is a legitimate large asset - oversized files can be used to smuggle payloads past size-limited scanners.",
  };
}

// ---------------------------------------------------------------------------
// Build tool config patterns (v4.0)
// ---------------------------------------------------------------------------

export const BUILD_TOOL_PATTERNS: PatternEntry[] = [
  {
    name: "build-plugin-download",
    pattern:
      "(?:require|import)\\s*\\(?[\"'][^\"']+[\"']\\)?[^;]*(?:fetch|https?\\.get|axios|got|download)",
    description:
      "Build config plugin downloads code from an external URL during build.",
    severity: "high",
    rule: "BUILD_PLUGIN_DOWNLOAD",
    notTestFile: true,
  },
  {
    name: "build-plugin-exec",
    pattern:
      "(?:child_process|execSync|spawnSync|exec)\\b",
    description:
      "Build config executes system commands. Verify this is expected build behavior.",
    severity: "high",
    rule: "BUILD_PLUGIN_EXEC",
    notTestFile: true,
  },
  {
    name: "build-env-exfil",
    pattern:
      "process\\.env\\b.*(?:fetch|https?\\.(?:get|request)|axios|got)|(?:fetch|https?\\.(?:get|request)|axios|got).*process\\.env",
    description:
      "Build config reads environment variables near network requests (potential secret exfiltration).",
    severity: "critical",
    rule: "BUILD_ENV_EXFIL",
    notTestFile: true,
  },
  {
    name: "build-dynamic-require",
    pattern:
      "require\\s*\\(\\s*(?:process\\.env|`|\\+)",
    description:
      "Dynamic require with variable input in build config. Can load unexpected modules.",
    severity: "medium",
    rule: "BUILD_DYNAMIC_REQUIRE",
    notTestFile: true,
  },
];

/** Build config file names */
export const BUILD_CONFIG_FILES = new Set([
  "webpack.config.js",
  "webpack.config.ts",
  "webpack.config.mjs",
  "rollup.config.js",
  "rollup.config.ts",
  "rollup.config.mjs",
  "vite.config.js",
  "vite.config.ts",
  "vite.config.mjs",
  "next.config.js",
  "next.config.ts",
  "next.config.mjs",
  "esbuild.config.js",
  "esbuild.config.mjs",
  "turbo.json",
  "babel.config.js",
  "babel.config.json",
  ".babelrc",
]);

// ---------------------------------------------------------------------------
// Monorepo / workspace patterns (v4.0)
// ---------------------------------------------------------------------------

export const MONOREPO_PATTERNS: PatternEntry[] = [
  {
    name: "workspace-root-postinstall",
    pattern:
      '"postinstall"\\s*:\\s*"[^"]*(?:curl|wget|node\\s+-e|bash|sh\\s+-c)',
    description:
      "Root-level postinstall in monorepo workspace. Affects all workspace packages.",
    severity: "high",
    rule: "WORKSPACE_ROOT_POSTINSTALL",
    notTestFile: true,
  },
  {
    name: "workspace-private-publish",
    pattern:
      '"private"\\s*:\\s*false[^}]*"publishConfig"',
    description:
      "Workspace package marked as non-private with publishConfig. Verify it should be public.",
    severity: "high",
    rule: "WORKSPACE_PRIVATE_PUBLISH",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// New campaign signatures (v4.0 - 2025/2026)
// ---------------------------------------------------------------------------

export const CAMPAIGN_PATTERNS_V2: PatternEntry[] = [
  // Shai-Hulud npm Worm
  {
    name: "shai-hulud-self-replicate",
    pattern:
      "npm\\s+publish|\\bnpm\\b.*\\bpublish\\b|child_process.*npm.*publish",
    description:
      "Self-publishing pattern detected. The Shai-Hulud worm replicates by publishing infected packages via npm.",
    severity: "critical",
    rule: "SHAI_HULUD_WORM",
    onlyExtensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash"],
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "shai-hulud-npmrc-steal",
    pattern:
      "\\.npmrc|npm_config_userconfig|NPM_TOKEN|npm-cli-login",
    description:
      "npm credentials access pattern. The Shai-Hulud worm steals .npmrc tokens to publish malicious packages.",
    severity: "high",
    rule: "SHAI_HULUD_CRED_STEAL",
    onlyExtensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash"],
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // Expanded protestware
  {
    name: "protestware-ip-geo-destruct",
    pattern:
      "(?:ip-api|ipinfo|geoip-lite|maxmind|geoip2).*(?:unlink|rmdir|rm\\s+-rf|del\\s+/|format\\s+c:)",
    description:
      "IP geolocation combined with destructive file operations. Advanced protestware pattern.",
    severity: "critical",
    rule: "PROTESTWARE_IP_GEO_V2",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
];

// ---------------------------------------------------------------------------
// Extended obfuscation patterns (v4.0)
// ---------------------------------------------------------------------------

export const OBFUSCATION_PATTERNS_V2: PatternEntry[] = [
  {
    name: "template-literal-exec",
    pattern:
      "eval\\s*\\(\\s*`",
    description:
      "eval() with template literal. Template literals can hide complex expressions.",
    severity: "high",
    rule: "TEMPLATE_LITERAL_EXEC",
    notTestFile: true,
  },
  {
    name: "proxy-handler-trap",
    pattern:
      "new\\s+Proxy\\s*\\([^)]*\\{[^}]*(?:get|set|apply|construct)\\s*:",
    description:
      "Proxy handler trap detected. Proxy objects can intercept and modify all object operations.",
    severity: "high",
    rule: "PROXY_HANDLER_TRAP",
    notFilePattern: /\.min\.(js|css)$|(?:\/static\/js\/|\/vendor\/|\/public\/js\/|\/assets\/js\/).*\.js$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },
  {
    name: "dynamic-import-expression",
    pattern:
      "import\\s*\\(\\s*(?:`[^`]*\\$\\{|\\+|process\\.env|String\\.fromCharCode)",
    description:
      "Dynamic import() with computed URL (template literal with expression, env variable, or string construction). Can load modules from attacker-controlled sources.",
    severity: "medium",
    rule: "IMPORT_EXPRESSION",
    notTestFile: true,
  },
  {
    name: "wasm-instantiate-external",
    pattern:
      "WebAssembly\\.instantiate(?:Streaming)?\\s*\\(\\s*(?:fetch|https?|new\\s+URL)",
    description:
      "WebAssembly loaded from external source. WASM modules can execute arbitrary code.",
    severity: "medium",
    rule: "WASM_SUSPICIOUS",
    notTestFile: true,
  },
  {
    name: "steganography-decode",
    pattern:
      "(?:atob|Buffer\\.from)\\s*\\([^)]*(?:\\.png|\\.jpg|\\.gif|\\.bmp|\\.ico|\\.svg|\\.woff|\\.ttf)",
    description:
      "Base64 decoding applied to image/font file content. Potential steganographic payload extraction.",
    severity: "high",
    rule: "STEGANOGRAPHY_DECODE",
    notTestFile: true,
  },
  {
    name: "svg-script-injection",
    pattern:
      "<script[^>]*>[\\s\\S]*?</script>|\\bon\\w+\\s*=\\s*[\"']",
    description:
      "SVG file contains <script> tag or event handler. SVG files can execute JavaScript.",
    severity: "high",
    rule: "SVG_SCRIPT_INJECTION",
    onlyExtensions: [".svg"],
    notTestFile: true,
  },
  {
    name: "rtl-override",
    pattern:
      "\\u202E|\\u2066|\\u2067|\\u2068|\\u2069",
    description:
      "Right-to-left override character detected. Can be used to disguise file extensions or code meaning.",
    severity: "high",
    rule: "RTL_OVERRIDE",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// IaC / Terraform patterns (v4.0)
// ---------------------------------------------------------------------------

export const IAC_PATTERNS: PatternEntry[] = [
  {
    name: "iac-inline-script-curl",
    pattern:
      "(?:provisioner|user_data|inline).*(?:curl|wget)\\s+.*\\|\\s*(?:bash|sh)",
    description:
      "Terraform/IaC provisioner downloads and executes remote code.",
    severity: "high",
    rule: "IAC_INLINE_SCRIPT",
    notTestFile: true,
  },
  {
    name: "iac-external-module",
    pattern:
      'source\\s*=\\s*"(?:https?://|git::|s3::|gcs::)(?!(?:github\\.com/hashicorp|registry\\.terraform\\.io))',
    description:
      "Terraform module from a non-standard source. Modules from untrusted sources can contain backdoors.",
    severity: "medium",
    rule: "IAC_EXTERNAL_MODULE",
    notTestFile: true,
  },
  {
    name: "iac-hardcoded-secret",
    pattern:
      '(?:password|secret_key|access_key|api_key|private_key|token)\\s*=\\s*"(?!(?:test|example|dummy|placeholder|your_|TODO|REPLACE|<|changeme|secret_here|xxx|none|null|false|true)[^"]*")[^"]{8,}"',
    description:
      "Hardcoded secret in IaC configuration file. Secrets should use variables or secret managers.",
    severity: "critical",
    rule: "IAC_HARDCODED_SECRET",
    notTestFile: true,
  },
  {
    name: "iac-remote-exec",
    pattern:
      'provisioner\\s+"remote-exec"',
    description:
      "Terraform remote-exec provisioner. Executes commands on remote resources.",
    severity: "medium",
    rule: "IAC_REMOTE_EXEC",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Infostealer / dropper / proxy malware patterns (v4.1)
// ---------------------------------------------------------------------------

export const INFOSTEALER_PATTERNS: PatternEntry[] = [
  // Dead-drop resolver patterns
  {
    name: "dead-drop-steam",
    pattern:
      "steamcommunity\\.com/profiles/\\d+",
    description:
      "Steam Community profile URL in code. Infostealers (Vidar, Lumma) use Steam profiles as dead-drop resolvers to retrieve C2 addresses.",
    severity: "critical",
    rule: "DEAD_DROP_STEAM",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "dead-drop-telegram",
    pattern:
      "(?:telegram\\.me|t\\.me)/[a-zA-Z0-9_]+",
    description:
      "Telegram channel/user URL in code. Used as dead-drop resolver for C2 address retrieval by Vidar and similar stealers.",
    severity: "critical",
    rule: "DEAD_DROP_TELEGRAM",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "dead-drop-pastebin",
    pattern:
      "(?:pastebin\\.com|hastebin\\.com|ghostbin\\.com|paste\\.ee|rentry\\.co)/(?:raw/)?[a-zA-Z0-9]+",
    description:
      "Pastebin-like service URL in code. Often used as dead-drop resolver for malware C2 configuration.",
    severity: "high",
    rule: "DEAD_DROP_PASTEBIN",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "dead-drop-dns-txt",
    pattern:
      "(?:nslookup|dig)\\s+.*\\bTXT\\b|dns\\.resolveTxt|resolver\\.query.*TXT",
    description:
      "DNS TXT record lookup detected. Malware uses DNS TXT records as covert C2 channels.",
    severity: "medium",
    rule: "DEAD_DROP_DNS_TXT",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // Browser credential theft patterns
  {
    name: "vidar-browser-theft",
    pattern:
      "(?:AppData[/\\\\](?:Local|Roaming)[/\\\\](?:Google|Mozilla|BraveSoftware|Microsoft[/\\\\]Edge)|Library[/\\\\]Application Support[/\\\\](?:Firefox|Google[/\\\\]Chrome|BraveSoftware)|\\.mozilla[/\\\\]firefox|\\.config[/\\\\](?:google-chrome|chromium)).*(?:Login Data|Cookies|Web Data|Local State|key4\\.db|logins\\.json)",
    description:
      "Browser credential/cookie file access pattern. Infostealers (Vidar, Lumma, RedLine) steal browser data from these paths.",
    severity: "high",
    rule: "VIDAR_BROWSER_THEFT",
    notFilePattern: /\.min\.(js|css)$|(?:patterns|scanner|playbooks|correlation-engine|ioc-blocklist|threat-intel|remediation-engine|secret-simulator|workflow-modeler|config-scanner|install-hook-scanner|github-trust-scanner|dependency-confusion|attack-graph|reporter|active-validation|solana-monitor|solana-watchlist|slsa-verifier|sbom-generator)\.(ts|js)$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },

  // Crypto wallet theft patterns
  {
    name: "vidar-wallet-theft",
    pattern:
      "(?:Exodus|exodus|MetaMask|metamask|Phantom|phantom|Atomic|Electrum|electrum|Coinomi|Trust.*Wallet).*(?:wallet|keystore|vault|seed|mnemonic)|wallet\\.dat",
    description:
      "Cryptocurrency wallet file/directory access. Infostealers target wallet files for fund theft.",
    severity: "high",
    rule: "VIDAR_WALLET_THEFT",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },

  // SOCKS5 proxy / backconnect patterns
  {
    name: "ghostsocks-socks5",
    pattern:
      "\\x05[\\x00-\\x03]|SOCKS5|socks5://|socks_version.*5|connect_socks",
    description:
      "SOCKS5 proxy protocol pattern. GhostSocks and similar malware turn infected machines into residential proxies.",
    severity: "critical",
    rule: "GHOSTSOCKS_SOCKS5",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "proxy-backconnect",
    pattern:
      "(?:socks[45]?://|\\bsocks[45]\\b.*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|backconnect.*:\\d{4,5}|residential.*proxy.*\\d{1,3}\\.\\d{1,3}|back_connect|proxy.*checkin)",
    description:
      "Reverse proxy/backconnect pattern. Infected machines are registered as proxy nodes for criminal infrastructure.",
    severity: "high",
    rule: "PROXY_BACKCONNECT",
    notFilePattern: /\.min\.(js|css)$|(?:patterns|scanner|playbooks|correlation-engine|ioc-blocklist|threat-intel|remediation-engine|secret-simulator|workflow-modeler|config-scanner|install-hook-scanner|github-trust-scanner|dependency-confusion|attack-graph|reporter|active-validation|solana-monitor|solana-watchlist|slsa-verifier|sbom-generator)\.(ts|js)$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },

  // Dropper / loader patterns
  {
    name: "dropper-temp-exec",
    pattern:
      "(?:TEMP|TMP|AppData|tmp).*(?:exec|spawn|ShellExecute|CreateProcess|system\\()|(?:writeFile|write_bytes|writeFileSync|saveFile\\().*(?:TEMP|TMP|\\.exe|\\.bat|\\.cmd|\\.ps1)",
    description:
      "Dropper pattern: writing and executing files in temporary directories.",
    severity: "critical",
    rule: "DROPPER_TEMP_EXEC",
    notFilePattern: /\.json$|(?:patterns|scanner|playbooks|correlation-engine|ioc-blocklist|threat-intel|remediation-engine|secret-simulator|workflow-modeler|config-scanner|install-hook-scanner|github-trust-scanner|dependency-confusion|attack-graph|reporter|active-validation|solana-monitor|solana-watchlist|slsa-verifier|sbom-generator)\.(ts|js)$|\.(md|markdown|txt|rst)$/i,
    notTestFile: true,
  },
  {
    name: "dropper-antivm",
    pattern:
      "(?:VMware|VirtualBox|VBOX|QEMU|Hyper-V|Xen|Parallels).*(?:detect|check|exit)|(?:GetTickCount|IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebuggerPresent)",
    description:
      "Anti-VM/anti-debug evasion technique. Malware checks for sandbox environments before executing payloads.",
    severity: "high",
    rule: "DROPPER_ANTIVM",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "dropper-sleep-evasion",
    pattern:
      "(?:sleep|Sleep|usleep|nanosleep|time\\.sleep|Thread\\.sleep|Start-Sleep)\\s*\\(\\s*(?:[0-9]{5,}|\\d+\\s*\\*\\s*(?:60|1000|60000))",
    description:
      "Long sleep before execution. Droppers delay to evade sandbox time limits (SUNBURST/Vidar technique).",
    severity: "high",
    rule: "DROPPER_SLEEP_EVASION",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
];

// ---------------------------------------------------------------------------
// Fake AI-tool / SEO lure patterns (v4.1 - Claude Code campaign)
// ---------------------------------------------------------------------------

export const LURE_PATTERNS: PatternEntry[] = [
  {
    name: "readme-lure-leaked",
    pattern:
      "(?:leaked|exposed|dumped)\\s+(?:source|code|src|binary|build)",
    description:
      "README contains 'leaked source/code' language. This is a common social engineering lure for malware distribution.",
    severity: "high",
    rule: "README_LURE_LEAKED",
    onlyFilePattern: /(?:^|[/\\])(?:README|CHANGELOG|DESCRIPTION|CONTRIBUTING|release[-_]notes)[^/\\]*$/i,
    notTestFile: true,
  },
  {
    name: "readme-lure-crack",
    pattern:
      "\\b(?:crack(?:ed)?|keygen|license\\s*bypass|no\\s*(?:message\\s*)?limits?|unlock(?:ed)?\\s*(?:features?|enterprise|pro|premium))\\b",
    description:
      "README contains crack/keygen/unlock language. Malware repos promise premium features to lure downloads.",
    severity: "critical",
    rule: "README_LURE_CRACK",
    onlyFilePattern: /(?:^|[/\\])(?:README|CHANGELOG|DESCRIPTION|CONTRIBUTING|release[-_]notes)[^/\\]*$/i,
    notTestFile: true,
  },
  {
    name: "readme-lure-urgency",
    pattern:
      "(?:download|get|grab)\\s+(?:before|quickly|fast|now|while).*(?:removed|taken down|deleted|gone|available)",
    description:
      "README uses urgency language to pressure downloads. Classic social engineering tactic.",
    severity: "medium",
    rule: "README_LURE_URGENCY",
    onlyFilePattern: /(?:^|[/\\])(?:README|CHANGELOG|DESCRIPTION|CONTRIBUTING|release[-_]notes)[^/\\]*$/i,
    notTestFile: true,
  },
  {
    name: "campaign-claude-lure",
    pattern:
      "(?:claude\\s*code|anthropic).*(?:leaked|cracked|unlocked|free|exposed|rebuilt)",
    description:
      "Claude Code lure detected. The April 2026 campaign distributed Vidar/GhostSocks via fake 'leaked Claude Code' repos.",
    severity: "critical",
    rule: "CAMPAIGN_CLAUDE_LURE",
    notTestFile: true,
    // Stay on .md - lure patterns target malicious READMEs by design.
    notFilePattern: SCANNER_SRC,
  },
  {
    name: "campaign-ai-tool-lure",
    pattern:
      "(?:copilot|cursor|devin|openai|chatgpt|gemini|claude|windsurf|openclaw).*(?:leaked|cracked|free\\s*download|source\\s*dump)",
    description:
      "Fake AI tool lure detected. The 2026 campaign impersonated 25+ software brands to distribute malware.",
    severity: "critical",
    rule: "CAMPAIGN_AI_TOOL_LURE",
    notTestFile: true,
    notFilePattern: SCANNER_SRC,
  },
  {
    name: "fake-exe-in-release",
    pattern:
      "(?:_x64|_x86|_amd64|_arm64|Setup|Install)\\.(?:exe|msi|bat|cmd|ps1|7z|rar)",
    description:
      "Suspicious executable/archive filename pattern matching malware campaign naming conventions.",
    severity: "high",
    rule: "FAKE_AI_TOOL_LURE",
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Prompt-injection patterns targeting downstream LLM coding agents (v5.2.19)
//
// When attackers compromise an npm/PyPI package, they used to target the human
// developer who reads the README. Increasingly they target the *AI coding
// agent* that reads the README on the developer's behalf (Claude Code, Cursor,
// Copilot, etc.). These patterns flag known LLM-control tokens and role
// markers embedded in package documentation where they have no business being.
//
// Scope: README / CHANGELOG / DESCRIPTION / CONTRIBUTING / release notes only.
// The same tokens are legitimate in actual LLM toolkit source code, so we do
// not scan general .ts/.js/.py source for them.
// ---------------------------------------------------------------------------

// v5.10: also cover issue/PR templates. They are prefilled into the very
// issue/PR bodies that AI agents ingest, so an LLM control token planted in a
// template is a pre-positioned injection against downstream agents. The
// ISSUE_TEMPLATE alternative matches files INSIDE that directory (bug_report.md).
const DOC_FILE_PATTERN = /(?:^|[/\\])(?:README|CHANGELOG|DESCRIPTION|CONTRIBUTING|release[-_]notes|PULL_REQUEST_TEMPLATE|SUPPORT)[^/\\]*$|[/\\]ISSUE_TEMPLATE[/\\][^/\\]+$/i;

export const PROMPT_INJECTION_PATTERNS: PatternEntry[] = [
  {
    name: "prompt-injection-system-reminder",
    // Matches Anthropic / Claude Code harness style: <system-reminder>...</system-reminder>
    // Also catches the opening tag alone since closing tags can be malformed.
    pattern: "<\\s*/?\\s*system[-_](?:reminder|prompt|message|instruction)\\s*>",
    description:
      "Anthropic-style <system-reminder> / <system-prompt> tag in package documentation. These tokens are processed as authoritative instructions by Claude-family LLMs reading the README - a prompt-injection attack on downstream AI coding agents.",
    severity: "high",
    rule: "PROMPT_INJECTION_SYSTEM_REMINDER",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
  {
    name: "prompt-injection-chatml",
    // Matches OpenAI / Llama 2+ / Mistral ChatML: <|im_start|>system ... <|im_end|>
    pattern: "<\\|\\s*im_(?:start|end|sep)\\s*\\|>",
    description:
      "ChatML role-control token (<|im_start|> / <|im_end|>) in package documentation. Used by OpenAI GPT, Llama, Mistral, and Qwen models as role-boundary markers - a prompt-injection attack on downstream AI agents.",
    severity: "high",
    rule: "PROMPT_INJECTION_CHATML",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
  {
    name: "prompt-injection-inst-tag",
    // Matches Mistral / Llama instruction-tuning tags: [INST] ... [/INST]
    // Word-boundary on both sides to avoid matching prose like "configure [INST]ance".
    pattern: "\\[\\s*/?\\s*INST\\s*\\]",
    description:
      "Mistral/Llama instruction tag ([INST] or [/INST]) in package documentation. These tokens delimit user instructions in Mistral and Llama instruction-tuned models - a prompt-injection attack on downstream AI agents.",
    severity: "high",
    rule: "PROMPT_INJECTION_INST_TAG",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
  {
    name: "prompt-injection-role-token",
    // Matches generic role tokens: <|system|>, <|user|>, <|assistant|>, <|developer|>
    pattern: "<\\|\\s*(?:system|user|assistant|developer|function|tool)\\s*\\|>",
    description:
      "Generic role-control token (<|system|>, <|user|>, <|assistant|>) in package documentation. Used by Phi, Gemma, Granite, and other local LLMs to switch conversational role - a prompt-injection attack on downstream AI agents.",
    severity: "high",
    rule: "PROMPT_INJECTION_ROLE_TOKEN",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
  {
    name: "prompt-injection-override-prose",
    // Natural-language jailbreak phrases. Case-insensitive. Require the
    // imperative form to avoid matching documentation ABOUT prompt injection
    // (e.g. "we discuss how attackers ignore previous instructions").
    pattern:
      "(?:^|[.!?\\n]\\s*)(?:please\\s+)?(?:ignore|disregard|forget|override)\\s+(?:all\\s+)?(?:previous|prior|above|earlier|the\\s+system)\\s+(?:instructions?|prompts?|messages?|rules?|directives?|context)",
    description:
      "Natural-language prompt-injection override ('ignore previous instructions', 'disregard the system prompt', etc.) in package documentation. Classic jailbreak phrasing aimed at downstream AI agents reading the README.",
    severity: "high",
    rule: "PROMPT_INJECTION_OVERRIDE_PROSE",
    onlyFilePattern: DOC_FILE_PATTERN,
    // Prompt-injection patterns target docs - stay on .md, only exclude scanner source.
    notFilePattern: SCANNER_SRC,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Extended C2 + Secrets patterns (v4.2)
// ---------------------------------------------------------------------------

export const C2_EXTENDED_PATTERNS: PatternEntry[] = [
  {
    name: "c2-doh-resolver",
    pattern:
      "(?:cloudflare-dns\\.com|dns\\.google|dns\\.quad9\\.net)/dns-query|application/dns-json|application/dns-message",
    description:
      "DNS-over-HTTPS (DoH) resolver in code. Malware uses DoH to resolve C2 domains while bypassing network monitoring.",
    severity: "medium",
    rule: "C2_DOH_RESOLVER",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "dead-drop-gist",
    pattern:
      "gist\\.github(?:usercontent)?\\.com/[a-zA-Z0-9]+/[a-f0-9]+",
    description:
      "GitHub Gist used as dead-drop resolver. Gists store C2 configuration that changes without updating malware code.",
    severity: "high",
    rule: "DEAD_DROP_GIST",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "c2-dynamic-config",
    pattern:
      "(?:fetch|https?\\.get|axios\\.get|got)\\s*\\([^)]*(?:config|settings|update|check|beacon|ping|heartbeat)[^)]*\\).*(?:eval|exec|Function|spawn)",
    description:
      "Dynamic config fetch followed by code execution. Runtime C2 command pattern.",
    severity: "high",
    rule: "C2_DYNAMIC_CONFIG",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
  {
    name: "c2-websocket-dynamic",
    pattern:
      "new\\s+WebSocket\\s*\\(\\s*(?:`|\\+|atob|Buffer\\.from|decodeURI|String\\.fromCharCode)",
    description:
      "WebSocket connection with dynamically constructed URL. Hides C2 server address.",
    severity: "high",
    rule: "C2_WEBSOCKET_DYNAMIC",
    notFilePattern: SCANNER_SRC_OR_DOCS,
    notTestFile: true,
  },
];

export const SECRETS_PATTERNS: PatternEntry[] = [
  {
    name: "secrets-aws-key",
    pattern:
      "(?:AKIA|ASIA)[A-Z0-9]{16}",
    description:
      "AWS Access Key ID detected. Hardcoded AWS credentials can be used for unauthorized access.",
    severity: "critical",
    rule: "SECRETS_AWS_KEY",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-github-token",
    pattern:
      "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}",
    description:
      "GitHub personal access token detected. Exposed tokens grant repository access.",
    severity: "critical",
    rule: "SECRETS_GITHUB_TOKEN",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-private-key",
    pattern:
      "-----BEGIN\\s+(?:RSA|EC|OPENSSH|DSA|PGP)\\s+PRIVATE\\s+KEY-----",
    description:
      "Private key embedded in code. Exposed private keys compromise authentication and encryption.",
    severity: "critical",
    rule: "SECRETS_PRIVATE_KEY",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-ssh-key-read",
    pattern:
      "(?:readFile|readFileSync|open|cat|type).*\\.ssh[/\\\\](?:id_rsa|id_ed25519|id_ecdsa|id_dsa|identity)(?:[^a-z]|$)",
    description:
      "Code reads SSH private key files. Infostealers exfiltrate SSH keys for lateral movement.",
    severity: "critical",
    rule: "SECRETS_SSH_KEY_READ",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-npm-token",
    pattern:
      "npm_[A-Za-z0-9]{36}",
    description:
      "npm automation token detected. Exposed tokens allow publishing malicious package versions.",
    severity: "critical",
    rule: "SECRETS_NPM_TOKEN",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
  {
    name: "secrets-generic-api-key",
    pattern:
      "(?:api_key|apikey|api_secret|secret_key|auth_token)\\s*[=:]\\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]",
    description:
      "Generic API key or secret detected in code.",
    severity: "high",
    rule: "SECRETS_GENERIC_API_KEY",
    notTestFile: true,
    notFilePattern: SCANNER_SRC_OR_DOCS,
  },
];

// ---------------------------------------------------------------------------
// Advanced obfuscation v2 patterns (v4.5)
// ---------------------------------------------------------------------------

export const OBFUSCATION_V3_PATTERNS: PatternEntry[] = [
  {
    name: "code-split-string-obfuscation",
    pattern:
      "(?:['\"][a-zA-Z]{1,3}['\"]\\s*\\+\\s*){5,}",
    description:
      "String built by concatenating many small fragments. This technique hides suspicious strings from static analysis.",
    severity: "high",
    rule: "CODE_SPLIT_STRING_OBFUSCATION",
    notTestFile: true,
  },
  {
    name: "code-multi-layer-encoding",
    pattern:
      "(?:atob|Buffer\\.from|decodeURIComponent|unescape)\\s*\\(\\s*(?:atob|Buffer\\.from|decodeURIComponent|unescape)",
    description:
      "Multi-layer encoding detected (decode inside decode). Malware uses nested encoding to evade detection.",
    severity: "critical",
    rule: "CODE_MULTI_LAYER_ENCODING",
    notTestFile: true,
  },
  {
    name: "code-runtime-deobfuscation",
    pattern:
      "(?:setInterval|setTimeout|requestAnimationFrame)\\s*\\([^)]*(?:eval|Function|exec)",
    description:
      "Delayed runtime deobfuscation. Code deobfuscates and executes payload after a delay to evade analysis.",
    severity: "high",
    rule: "CODE_RUNTIME_DEOBFUSCATION",
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Provenance & integrity signals (v4.5)
// ---------------------------------------------------------------------------

export const PROVENANCE_PATTERNS: PatternEntry[] = [
  {
    name: "provenance-missing-sig",
    pattern:
      '"integrity"\\s*:\\s*""',
    description:
      "Empty integrity hash in lockfile. Package integrity cannot be verified.",
    severity: "medium",
    rule: "PROVENANCE_MISSING",
    notTestFile: true,
  },
];
