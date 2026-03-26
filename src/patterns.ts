/**
 * Known malicious patterns database
 *
 * This file is designed to be regularly updated as new threats emerge.
 * Add new patterns, wallet addresses, or domain patterns as they are discovered.
 */

import type { PatternEntry, Severity } from "./types.js";

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
  },

  // Invisible Unicode characters (zero-width spaces, joiners, etc.)
  {
    name: "invisible-unicode",
    pattern:
      "[\\u200B\\u200C\\u200D\\u2060\\uFEFF\\u00AD\\u034F\\u061C\\u180E\\u2028\\u2029\\u202A-\\u202E\\u2066-\\u2069]{3,}",
    description:
      "Suspicious invisible Unicode characters detected (potential code obfuscation)",
    severity: "high",
    rule: "INVISIBLE_UNICODE",
  },

  // Encoded eval/exec patterns
  {
    name: "eval-atob",
    pattern: "eval\\s*\\(\\s*atob\\s*\\(",
    description: "Base64-encoded eval detected (common malware obfuscation)",
    severity: "critical",
    rule: "EVAL_ATOB",
  },
  {
    name: "eval-buffer-from",
    pattern: "eval\\s*\\(\\s*Buffer\\.from\\s*\\(",
    description:
      "Buffer-encoded eval detected (common malware obfuscation in Node.js)",
    severity: "critical",
    rule: "EVAL_BUFFER",
  },
  {
    name: "new-function-atob",
    pattern: "new\\s+Function\\s*\\(\\s*atob\\s*\\(",
    description:
      "Base64-encoded Function constructor detected (malware obfuscation)",
    severity: "critical",
    rule: "FUNCTION_ATOB",
  },
  {
    name: "eval-buffer-hex",
    pattern: "eval\\s*\\(\\s*Buffer\\.from\\s*\\([^)]+,\\s*['\"]hex['\"]\\s*\\)",
    description: "Hex-encoded eval detected",
    severity: "critical",
    rule: "EVAL_HEX",
  },
  {
    name: "exec-encoded",
    pattern:
      "exec\\s*\\(\\s*(?:atob|Buffer\\.from|decodeURIComponent)\\s*\\(",
    description: "Encoded exec call detected",
    severity: "high",
    rule: "EXEC_ENCODED",
  },

  // Solana C2 references
  {
    name: "solana-mainnet",
    pattern: "mainnet-beta\\.solana\\.com",
    description: "Solana mainnet RPC reference detected (potential C2 channel)",
    severity: "medium",
    rule: "SOLANA_MAINNET",
  },
  {
    name: "helius-rpc",
    pattern: "helius(?:-rpc)?\\.(?:com|dev)",
    description:
      "Helius Solana RPC reference detected (used in GlassWorm C2)",
    severity: "medium",
    rule: "HELIUS_RPC",
  },

  // Obfuscation patterns
  {
    name: "hex-string-array",
    pattern:
      "\\[\\s*(?:0x[0-9a-fA-F]+\\s*,\\s*){10,}",
    description: "Large hex array detected (potential obfuscated payload)",
    severity: "medium",
    rule: "HEX_ARRAY",
  },
  {
    name: "string-char-concat",
    pattern:
      "(?:String\\.fromCharCode|\\\\x[0-9a-fA-F]{2}){5,}",
    description:
      "Character code string construction detected (obfuscation technique)",
    severity: "medium",
    rule: "CHARCODE_OBFUSCATION",
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
  },
  {
    name: "dns-exfil",
    pattern: "dns\\.resolve.*process\\.env",
    description: "DNS-based data exfiltration pattern detected",
    severity: "high",
    rule: "DNS_EXFILTRATION",
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
  },
  {
    name: "postinstall-wget",
    pattern: "wget\\s+.*\\|\\s*(?:bash|sh|node)",
    description: "postinstall script downloads and executes remote code",
    severity: "critical",
    rule: "SCRIPT_WGET_EXEC",
  },
  {
    name: "postinstall-node-e",
    pattern: "node\\s+-e\\s+[\"'].*(?:http|https|fetch|require)",
    description:
      "postinstall script executes inline Node.js with network access",
    severity: "high",
    rule: "SCRIPT_NODE_INLINE",
  },
  {
    name: "postinstall-encoded",
    pattern: "(?:atob|Buffer\\.from|base64)",
    description: "postinstall script contains encoding/decoding operations",
    severity: "high",
    rule: "SCRIPT_ENCODED",
  },
  {
    name: "preinstall-exec",
    pattern: "(?:exec|spawn|execSync)\\s*\\(",
    description: "preinstall script executes system commands",
    severity: "medium",
    rule: "SCRIPT_PREINSTALL_EXEC",
  },
];

// ---------------------------------------------------------------------------
// Known malicious npm package name patterns
// ---------------------------------------------------------------------------

/** Patterns matching known malicious or typosquatting package names */
export const MALICIOUS_PACKAGE_PATTERNS: string[] = [
  // Typosquatting common packages
  "^(lodas|1odash|l0dash|lodash-es-utils)$",
  "^(cros-env|cross-env-shell|crossenv)$",
  "^(bable-cli|babelcli)$",
  "^(event-streem|event_stream)$",

  // GlassWorm campaign packages (pattern: random-looking names)
  "^[a-z]{15,}$", // Very long single-word lowercase names

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
  },
  {
    name: "xz-lzma-crc64",
    pattern: "lzma_crc64",
    description:
      "XZ Utils backdoor indicator: lzma_crc64 function reference (CVE-2024-3094 hijacked symbol)",
    severity: "high",
    rule: "XZ_LZMA_CRC64",
  },
  {
    name: "xz-build-inject",
    pattern:
      "gl_cv_host_cpu_c_abi.*=.*configure\\.ac|AM_CONDITIONAL.*\\bgl_INIT\\b|m4/.*\\.m4.*ifnot",
    description:
      "XZ Utils backdoor indicator: build system injection pattern in configure.ac/m4 macros",
    severity: "high",
    rule: "XZ_BUILD_INJECT",
  },
  {
    name: "xz-obfuscated-test",
    pattern:
      "tests/files/.*\\.xz.*\\bhead\\b.*\\btr\\b|\\bxz\\b.*-d.*\\|.*\\bhead\\b.*-c",
    description:
      "XZ Utils backdoor indicator: obfuscated test file extraction pattern (hidden payload in test fixtures)",
    severity: "high",
    rule: "XZ_OBFUSCATED_TEST",
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
  },
  {
    name: "codecov-exfil",
    pattern:
      "codecov[^;]*(?:ENV|TOKEN|SECRET|CREDENTIAL|PASSWORD|API_KEY)|(?:ENV|TOKEN|SECRET|CREDENTIAL|PASSWORD|API_KEY)[^;]*codecov",
    description:
      "Codecov exfiltration indicator: environment secrets referenced alongside codecov operations",
    severity: "high",
    rule: "CODECOV_EXFIL",
  },

  // --- SolarWinds SUNBURST ---
  {
    name: "sunburst-dga",
    pattern: "avsvmcloud\\.com",
    description:
      "SolarWinds SUNBURST indicator: DGA C2 domain avsvmcloud.com detected",
    severity: "critical",
    rule: "SUNBURST_DGA",
  },
  {
    name: "sunburst-orion-class",
    pattern: "OrionImprovementBusinessLayer",
    description:
      "SolarWinds SUNBURST indicator: OrionImprovementBusinessLayer class name (backdoor namespace)",
    severity: "critical",
    rule: "SUNBURST_ORION_CLASS",
  },
  {
    name: "sunburst-delayed-exec",
    pattern:
      "(?:Thread\\.Sleep|setTimeout|sleep)\\s*\\([^)]*?(?:[0-9]{7,}|\\d+\\s*\\*\\s*(?:3600|86400|60\\s*\\*\\s*60))",
    description:
      "SUNBURST-style delayed execution: sleep/timeout exceeding 1 hour (evasion technique to avoid sandbox analysis)",
    severity: "high",
    rule: "SUNBURST_DELAYED_EXEC",
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
  },
  {
    name: "uaparser-preinstall-download",
    pattern:
      "preinstall[\"']?\\s*:\\s*[\"'][^\"']*(?:curl|wget)\\s+https?://[^\"']*(?:\\.exe|\\.sh|\\.bat)",
    description:
      "ua-parser-js hijack indicator: preinstall script downloading executables from external domains",
    severity: "critical",
    rule: "UAPARSER_PREINSTALL_DL",
  },

  // --- coa/rc npm hijack ---
  {
    name: "coa-rc-sdd-dll",
    pattern: "sdd\\.dll",
    description:
      "coa/rc npm hijack indicator: reference to sdd.dll payload (trojanized npm package artifact)",
    severity: "critical",
    rule: "COA_RC_SDD_DLL",
  },
  {
    name: "coa-rc-postinstall-encoded",
    pattern:
      "postinstall[\"']?\\s*:\\s*[\"'][^\"']*(?:compile\\.js|(?:Buffer|atob).*(?:exec|spawn|child_process))",
    description:
      "coa/rc npm hijack indicator: postinstall script with encoded payload execution",
    severity: "critical",
    rule: "COA_RC_POSTINSTALL",
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
  },
  {
    name: "setup-subprocess",
    pattern: "subprocess\\.(?:call|run|Popen|check_output|check_call)\\s*\\(",
    description: "subprocess execution detected in package file (potential code execution during install)",
    severity: "high",
    rule: "PYPI_SUBPROCESS",
  },

  // Encoded execution
  {
    name: "python-exec-encoded",
    pattern: "exec\\s*\\(\\s*(?:base64\\.b64decode|codecs\\.decode|bytes\\.fromhex)\\s*\\(",
    description: "exec() with encoded/decoded content detected (obfuscated code execution)",
    severity: "critical",
    rule: "PYPI_EXEC_ENCODED",
  },
  {
    name: "python-eval-encoded",
    pattern: "eval\\s*\\(\\s*(?:base64\\.b64decode|codecs\\.decode|bytes\\.fromhex)\\s*\\(",
    description: "eval() with encoded/decoded content detected (obfuscated code execution)",
    severity: "critical",
    rule: "PYPI_EVAL_ENCODED",
  },
  {
    name: "python-exec-compile",
    pattern: "exec\\s*\\(\\s*compile\\s*\\(",
    description: "exec(compile()) detected (dynamic code compilation and execution)",
    severity: "high",
    rule: "PYPI_EXEC_COMPILE",
  },

  // Base64 import smuggling
  {
    name: "python-import-base64",
    pattern: "__import__\\s*\\(\\s*['\"]base64['\"]\\s*\\)",
    description: "__import__('base64') detected (hidden import often used for payload decoding)",
    severity: "high",
    rule: "PYPI_IMPORT_BASE64",
  },
  {
    name: "python-import-codecs",
    pattern: "__import__\\s*\\(\\s*['\"]codecs['\"]\\s*\\)",
    description: "__import__('codecs') detected (hidden import for obfuscation)",
    severity: "medium",
    rule: "PYPI_IMPORT_CODECS",
  },
  {
    name: "python-import-marshal",
    pattern: "__import__\\s*\\(\\s*['\"]marshal['\"]\\s*\\)",
    description: "__import__('marshal') detected (bytecode-level obfuscation)",
    severity: "high",
    rule: "PYPI_IMPORT_MARSHAL",
  },

  // Network activity in setup files
  {
    name: "python-urllib-setup",
    pattern: "urllib\\.request\\.urlopen\\s*\\(",
    description: "urllib.request.urlopen() detected (network access, potential payload download)",
    severity: "high",
    rule: "PYPI_URLLIB_FETCH",
  },
  {
    name: "python-requests-setup",
    pattern: "requests\\.(?:get|post)\\s*\\(",
    description: "requests.get/post() detected (network access during install)",
    severity: "medium",
    rule: "PYPI_REQUESTS_FETCH",
  },

  // Suspicious pip install in setup.py
  {
    name: "python-pip-install-url",
    pattern: "pip\\s+install\\s+(?:--index-url|--extra-index-url|-i)\\s+https?://(?!pypi\\.org)",
    description: "pip install from non-PyPI URL detected (potential malicious package index)",
    severity: "critical",
    rule: "PYPI_SUSPICIOUS_INDEX",
  },
  {
    name: "python-pip-install-git",
    pattern: "pip\\s+install\\s+git\\+https?://",
    description: "pip install from git URL in setup file (unverified dependency source)",
    severity: "medium",
    rule: "PYPI_GIT_DEPENDENCY",
  },

  // Data exfiltration patterns in Python
  {
    name: "python-env-exfil",
    pattern: "os\\.environ\\b[^;\\n]*(?:urllib|requests|http\\.client|socket)",
    description: "Environment variable access combined with network activity (data exfiltration pattern)",
    severity: "high",
    rule: "PYPI_ENV_EXFILTRATION",
  },
  {
    name: "python-hostname-exfil",
    pattern: "socket\\.gethostname\\s*\\(\\)[^;\\n]*(?:urllib|requests|http)",
    description: "Hostname collection combined with network activity (reconnaissance/exfiltration)",
    severity: "high",
    rule: "PYPI_HOSTNAME_EXFIL",
  },

  // Install command class override
  {
    name: "python-install-class-override",
    pattern: "class\\s+\\w+\\s*\\(\\s*(?:install|develop|bdist_egg|egg_info|sdist)\\s*\\)",
    description: "Custom command class inheriting from setuptools install/develop command",
    severity: "medium",
    rule: "PYPI_INSTALL_CLASS_OVERRIDE",
  },

  // marshal.loads (bytecode deserialization)
  {
    name: "python-marshal-loads",
    pattern: "marshal\\.loads\\s*\\(",
    description: "marshal.loads() detected (bytecode deserialization, common obfuscation)",
    severity: "high",
    rule: "PYPI_MARSHAL_LOADS",
  },

  // exec with marshal.loads
  {
    name: "python-exec-marshal",
    pattern: "exec\\s*\\(\\s*marshal\\.loads\\s*\\(",
    description: "exec(marshal.loads()) detected (executing deserialized bytecode payload)",
    severity: "critical",
    rule: "PYPI_EXEC_MARSHAL",
  },

  // base64.b64decode combined with exec (various arrangements on same line)
  {
    name: "python-b64decode-exec-combined",
    pattern: "base64\\.b64decode\\s*\\([^)]*\\).*\\bexec\\b|\\bexec\\b.*base64\\.b64decode",
    description: "base64.b64decode combined with exec on the same line (obfuscated execution)",
    severity: "critical",
    rule: "PYPI_B64_EXEC_COMBINED",
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
  },
  {
    name: "setup-cmdclass-develop",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]develop['\"]",
    description: "Custom develop command class detected (code runs during pip install -e)",
    severity: "medium",
    rule: "PYPI_CUSTOM_DEVELOP",
  },
  {
    name: "setup-cmdclass-egg-info",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]egg_info['\"]",
    description: "Custom egg_info command class detected (code runs during package metadata generation)",
    severity: "medium",
    rule: "PYPI_CUSTOM_EGG_INFO",
  },
  {
    name: "setup-cmdclass-sdist",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]sdist['\"]",
    description: "Custom sdist command class detected (code runs during source distribution build)",
    severity: "low",
    rule: "PYPI_CUSTOM_SDIST",
  },
  {
    name: "setup-cmdclass-build-ext",
    pattern: "cmdclass\\s*=\\s*\\{[^}]*['\"]build_ext['\"]",
    description: "Custom build_ext command class detected (code runs during native extension build)",
    severity: "low",
    rule: "PYPI_CUSTOM_BUILD_EXT",
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
  },
  {
    name: "prebuild-install",
    pattern: "prebuild-install|prebuildify",
    description: "Prebuilt binary installer detected in install script",
    severity: "medium",
    rule: "BINARY_PREBUILD_INSTALL",
  },
  {
    name: "binary-download-curl",
    pattern:
      "(?:curl|wget)\\s+.*\\.(?:node|so|dll|dylib|exe)(?:\\s|$|[\"'])",
    description: "Install script downloads a binary/native file directly",
    severity: "high",
    rule: "BINARY_DIRECT_DOWNLOAD",
  },
  {
    name: "node-gyp-rebuild",
    pattern: "node-gyp\\s+rebuild",
    description: "Native addon compilation via node-gyp detected",
    severity: "low",
    rule: "BINARY_NATIVE_COMPILE",
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
    severity: "high",
    rule: "BEACON_INTERVAL_FETCH",
  },
  {
    name: "beacon-settimeout-fetch",
    pattern:
      "setTimeout\\s*\\(.*(?:fetch|https?\\.(?:get|request)|axios|got|node-fetch)",
    description:
      "Delayed network request detected (setTimeout + fetch). May be a beacon with jitter.",
    severity: "medium",
    rule: "BEACON_TIMEOUT_FETCH",
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
  },
  {
    name: "mining-pool-domain",
    pattern:
      "(?:pool\\.|mining\\.|mine\\.|hashrate\\.).*\\.(?:com|org|net|io)|(?:nanopool|ethermine|f2pool|viabtc|antpool|poolin|slushpool|nicehash|minergate|hashflare|2miners|flexpool|ezil|hiveon)\\.(?:com|org|net|io)",
    description:
      "Known mining pool domain detected. This package may contain a cryptocurrency miner.",
    severity: "critical",
    rule: "MINER_POOL_DOMAIN",
  },
  {
    name: "mining-config-keys",
    pattern:
      "(?:\"|\\'|`)(?:wallet|worker|pool_address|pool_password|mining_address|hashrate|coin|algo)(?:\"|\\'|`)\\s*:",
    description:
      "Mining configuration keys detected. This may be a cryptocurrency miner configuration.",
    severity: "high",
    rule: "MINER_CONFIG_KEYS",
  },
  {
    name: "coinhive-reference",
    pattern:
      "coinhive|cryptonight|monero\\.(?:crypto|mine)|xmrig|xmr-stak",
    description:
      "Cryptocurrency miner library reference detected (CoinHive, XMRig, etc.).",
    severity: "critical",
    rule: "MINER_LIBRARY_REF",
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
  },
  {
    name: "protestware-geo-ip",
    pattern:
      "(?:geoip|ip-api|ipinfo|freegeoip|ipgeolocation).*(?:fs\\.(?:rm|rmdir|unlink)|process\\.exit|execSync)",
    description:
      "GeoIP lookup combined with destructive operations detected. This is a protestware/geo-targeted attack pattern.",
    severity: "critical",
    rule: "PROTESTWARE_GEOIP_DESTRUCT",
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
]);

/** Maximum file size to scan (in bytes). Files larger than this are skipped. */
export const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
