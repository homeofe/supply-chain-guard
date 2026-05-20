# supply-chain-guard

Open-source supply-chain security scanner for npm, PyPI, Cargo, Go, Docker, Terraform, VS Code extensions, GitHub Actions and GitHub repositories. Detects malware campaigns (GlassWorm, Vidar, Shai-Hulud), fake AI tool repos, account takeovers, and 170+ threat indicators. Generates CycloneDX 1.6 SBOMs with real dependency inventories, verifies SLSA provenance, and correlates findings into attack-chain incidents.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-green)](https://nodejs.org)
[![npm](https://img.shields.io/npm/v/supply-chain-guard)](https://www.npmjs.com/package/supply-chain-guard)

## Background

For a deep dive into how GlassWorm infiltrates the software supply chain and the detection techniques behind this tool, read the blog post: [How GlassWorm Gets In and How We Locked It Out](https://blog.elvatis.com/how-glassworm-gets-in-and-how-we-locked-it-out/).

## What It Detects

### Malware Campaigns
- GlassWorm campaign markers and Solana blockchain C2
- Vidar/GhostSocks infostealers (April 2026 Claude Code leak campaign)
- Shai-Hulud self-replicating npm worm
- XZ Utils backdoor (CVE-2024-3094), SolarWinds SUNBURST, Codecov, ua-parser-js, coa/rc
- Fake AI tool repos (Claude Code, Copilot, Cursor, ChatGPT, OpenClaw lures)

### Code-Level Threats
- Obfuscated execution: eval+atob, eval+Buffer.from, template literal eval, dynamic `import()`
- Invisible Unicode, RTL override, SVG script injection, steganography
- Shannon entropy analysis for encoded payloads
- Proxy handler traps, WebAssembly from external sources

### Supply Chain Attacks
- Install hook deep analysis (secret harvesting, download-exec chains, binary blobs)
- Levenshtein-based typosquatting detection against top 100 npm packages with known-safe whitelist
- Dependency confusion and namespace squatting
- Known-bad version blocklist (axios, ua-parser-js, coa, rc, event-stream, node-ipc, colors, faker)
- Publishing anomaly detection (maintainer changes, version gaps, script additions)

### Infrastructure & CI/CD
- GitHub Actions: unpinned actions, secrets exfiltration, encoded payloads, curl piping
- Dockerfile: curl pipe, unpinned base images, hardcoded secrets, SUID bits
- Terraform/IaC: inline scripts, external modules, hardcoded secrets
- Package manager configs (.npmrc, .yarnrc, pip.conf): HTTP registries, exposed tokens
- Git hooks and submodule security

### Repository Trust Signals
- GitHub repo metadata analysis (account age, star-farming, single-commit repos)
- Release artifact scanning (.exe, .7z, double extensions, LNK shortcuts, PE magic)
- README lure detection (leaked/pirated/urgency language)

### Credential Detection
- AWS access keys (AKIA/ASIA), GitHub tokens (ghp_/gho_), npm tokens
- SSH private keys, generic API keys, PEM private keys

### Dead-Drop Resolver / C2 Detection
- Steam Community profiles, Telegram channels, Pastebin, GitHub Gists
- DNS TXT records, DNS-over-HTTPS, dynamic WebSocket URLs
- Known C2 domains and IPs (from IOC blocklist)

### Correlation Engine (v4.2)
Links individual findings into incident-level attack chains:
- "GlassWorm Campaign" (marker + eval + exfiltration)
- "Vidar Stealer Infection" (dead-drop + browser theft + dropper)
- "npm Account Takeover" (maintainer change + install hooks + C2)
- "Fake Repository Malware" (lure + exe release + new account)
- 15+ correlation rules with confidence scoring

### Trust Breakdown (v4.2)
4-dimension trust scoring for every scan:
- Publisher Trust (40%) / Code Quality (30%) / Dependency Trust (20%) / Release Process (10%)

## Installation

```bash
npm install -g supply-chain-guard
```

Or use directly with npx:

```bash
npx supply-chain-guard scan ./my-project
```

## Quickstart

```bash
# Scan a local directory
supply-chain-guard scan ./my-project

# Scan a GitHub repo (includes trust signal analysis)
supply-chain-guard scan https://github.com/user/repo

# Analyze a GitHub repo for trust signals + malware
supply-chain-guard repo https://github.com/user/repo

# Scan an npm package (downloads without installing)
supply-chain-guard npm suspicious-package-name

# Scan a PyPI package
supply-chain-guard pypi suspicious-package

# Scan a VS Code extension
supply-chain-guard vscode publisher.extension-name

# Detect dependency confusion
supply-chain-guard confusion ./my-project

# Scan an entire GitHub organization
supply-chain-guard org my-github-org

# Scan only files changed since a commit (diff mode)
supply-chain-guard scan ./project --since HEAD~5

# Monitor a Solana C2 wallet
supply-chain-guard monitor <wallet-address> --once
```

## Output Formats

```bash
supply-chain-guard scan ./project                # Human-readable text (default)
supply-chain-guard scan ./project --format json   # JSON (for CI/CD pipelines)
supply-chain-guard scan ./project --format html   # Standalone HTML report
supply-chain-guard scan ./project --format markdown # Markdown (for PR comments)
supply-chain-guard scan ./project --format sarif  # SARIF 2.1.0 (GitHub Code Scanning)
supply-chain-guard scan ./project --format sbom   # CycloneDX 1.6 SBOM with real dependency inventory
supply-chain-guard scan ./project --sbom-output sbom.json  # Write SBOM to file separately
```

## CI Exit Code Control

```bash
supply-chain-guard scan ./project --fail-on critical  # Fail only on critical
supply-chain-guard scan ./project --fail-on high       # Fail on high or above
supply-chain-guard scan ./project --fail-on info       # Fail on any finding
```

## Filtering

```bash
supply-chain-guard scan ./project --min-severity high
supply-chain-guard scan ./project --exclude SOLANA_MAINNET,HEX_ARRAY
```

## Policy Configuration (v4.4)

Create `.supply-chain-guard.yml` in your project root to customize behavior:

```yaml
rules:
  disable:
    - HEX_ARRAY
    - CHARCODE_OBFUSCATION
  severityOverrides:
    GHA_UNPINNED_ACTION: medium

allowlist:
  packages:
    - internal-utils
  domains:
    - company.internal
  githubOrgs:
    - my-org

suppress:
  - rule: RELEASE_EXE_ARTIFACT
    reason: Legitimate Windows installer

baseline:
  file: .scg-baseline.json
```

## Baseline Diffing (v4.4)

Only report NEW findings (ignore known baseline):

```bash
# Save current findings as baseline
supply-chain-guard scan ./project --save-baseline .scg-baseline.json

# On subsequent scans, only show new findings
supply-chain-guard scan ./project --baseline .scg-baseline.json
```

## Example Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  supply-chain-guard                                                  v5.1.0 ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Target      ./suspicious-package
  Type        directory  ·  18 / 18 files scanned
  Duration    142ms
  Time        2026-04-07T12:00:00.000Z

┌─────────────────────────────── RISK SCORE ─────────────────────────────────┐
│                                                                              │
│   83 / 100   █████████████████████████████████░░░░░   CRITICAL             │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────── FINDINGS SUMMARY ───────────────────────────────┐
│  CRITICAL      3  ████████████████████████████████                          │
│  HIGH          1  ██████████                                                 │
│  MEDIUM        0  ────────────────────────────────                           │
│  LOW           0  ────────────────────────────────                           │
│  INFO          0  ────────────────────────────────                           │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────── FINDINGS ───────────────────────────────────┐
│                                                                              │
│  [CRITICAL]  DEAD_DROP_STEAM                                                │
│              Steam Community profile URL used as dead-drop C2 resolver      │
│              src/config.js:12                                                │
│              match  https://steamcommunity[.]com/profiles/76561198...       │
│              fix    Remove external URL resolution; use static configuration │
│                                                                              │
│ ············································································· │
│                                                                              │
│  [CRITICAL]  VIDAR_BROWSER_THEFT                                            │
│              Browser credential file access (infostealer pattern)           │
│              src/steal.js:45                                                 │
│              match  AppData[...]Google[...]Chrome[...]Login Data             │
│              fix    Never access browser credential stores                   │
│                                                                              │
│ ············································································· │
│                                                                              │
│  [CRITICAL]  DROPPER_TEMP_EXEC                                              │
│              Dropper: file written and executed from temp directory          │
│              src/loader.js:23                                                │
│              match  saveFile(tmpdir, payload); exe‹c›(tmpPath)              │
│              fix    Remove dropper logic; audit all exec() call sites        │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────── TRUST BREAKDOWN ─────────────────────────────────┐
│  Publisher       ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░  20/100               │
│  Code            █████████░░░░░░░░░░░░░░░░░░░░░░░░░  30/100               │
│  Dependencies    ████████████████████████████████████ 100/100              │
│  Release         ██████████████████████████░░░░░░░░░  80/100               │
│────────────────────────────────────────────────────────────────────────────│
│  Overall         █████████████░░░░░░░░░░░░░░░░░░░░░░  48/100               │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────── CORRELATED INCIDENTS ───────────────────────────┐
│                                                                              │
│  [CRITICAL]  Vidar Stealer Infection  95% confidence                        │
│  Multiple infostealer indicators: dead-drop resolvers for C2,               │
│  browser credential theft, and crypto wallet targeting.                     │
│  Indicators: DEAD_DROP_STEAM, VIDAR_BROWSER_THEFT, DROPPER_TEMP_EXEC       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Supported Ecosystems

| Ecosystem | Command | What It Scans |
|-----------|---------|---------------|
| npm | `scan`, `npm` | package.json, install scripts, lockfile, tarball |
| PyPI | `pypi` | setup.py, setup.cfg, pyproject.toml, install hooks |
| Cargo/Rust | `scan` | Cargo.toml, build.rs, proc macros |
| Go | `scan` | go.mod, init() functions, CGo, plugin loading |
| Docker | `scan` | Dockerfile, docker-compose.yml, Containerfile |
| Terraform | `scan` | .tf, .hcl files (provisioners, modules, secrets) |
| VS Code | `vscode` | .vsix files, activation events, dangerous APIs |
| GitHub Actions | `scan` | .github/workflows/*.yml |
| GitHub Repos | `repo` | Trust signals, releases, README lures |
| Solana | `monitor` | C2 wallet memo transactions |

## GitHub Action

```yaml
name: Supply Chain Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: homeofe/supply-chain-guard@v5
        with:
          fail-on: critical
          comment-on-pr: true
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `format` | Output format (text/json/markdown/html/sarif/sbom) | `markdown` |
| `min-severity` | Minimum severity to report | `low` |
| `exclude-rules` | Comma-separated rule IDs to exclude | |
| `fail-on` | Fail check at this severity or above | `critical` |
| `comment-on-pr` | Post findings as PR comment | `true` |

## Adding Custom Patterns

Edit `src/patterns.ts` to add new detection rules:

```typescript
{
  name: "my-custom-pattern",
  pattern: "regex-pattern-here",
  description: "What this detects",
  severity: "high",
  rule: "MY_CUSTOM_RULE",
}
```

## Architecture

```
scan() -> collectFiles() -> per-file analysis
  -> Pattern matching (170+ rules across 12 categories)
  -> Entropy analysis (Shannon entropy for encoded payloads)
  -> IOC blocklist check (known C2 domains, IPs, hashes)
  -> Install hook deep analysis (secret harvesting, download-exec)
  -> Dependency risk analysis (Levenshtein typosquatting)
  -> Sub-scanners (lockfile, GitHub Actions, Docker, Cargo, Go, IaC)
  -> SLSA verifier (provenance level 0-3, sigstore/cosign, attestations)
  -> SBOM generator (reads package-lock.json → real CycloneDX 1.6 components)
  -> GitHub trust signal analysis (account age, stars, releases)
  -> Correlation engine (links findings into incidents)
  -> Trust breakdown (4-dimension scoring)
  -> Report generation (text/json/html/markdown/sarif/sbom)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. The most impactful contribution is adding new detection patterns for emerging threats.

## Changelog

### v5.2.15 (2026-05-20)
**Threat intel: Mini Shai-Hulud @antv + Nx Console + actions-cool triple wave (May 18-19, 2026)**

TeamPCP launched a coordinated triple supply-chain wave over 18-19 May 2026, all converging on the same exfiltration endpoint `t[.]m-kosche[.]com` (masquerading as an OpenTelemetry traces collector).

- **@antv ecosystem (npm)**: compromised maintainer account `atool` pushed 637 malicious versions across 317 packages in a 22-minute burst (01:39-02:18 UTC on 2026-05-19). Specific versions added: `@antv/g2@5.5.8`/`5.6.8`, `@antv/g6@5.2.1`/`5.3.1`, `echarts-for-react@3.1.7`/`3.2.7`, `timeago.js@4.1.2`/`4.2.2`. Payload: 498KB obfuscated Bun `index.js` (SHA-256 `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`).
- **Nx Console (VS Code)**: `nrwl.angular-console@18.95.0` published 2026-05-18 (exposure window 12:36-12:47 UTC) dropped a multi-stage credential stealer from an orphan commit `558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2` in the official `nrwl/nx` repo. Persistence: `~/.local/share/kitty/cat.py` Python daemon + `com.user.kitty-monitor` LaunchAgent / `kitty-monitor.service`. Dead-drop polls GitHub Search with marker query `firedalazer`. Hashes: VSIX `1a4afce3...`, `main.js` `b0cefb66...`, `index.js` `e7347d90...`, dropper `package.json` `43f2b001...`.
- **actions-cool GitHub Actions**: all tags of `actions-cool/issues-helper` (53 imposter commits) and `actions-cool/maintain-one-comment` (15 imposter commits) redirected to malicious payloads that read `Runner.Worker` process memory to harvest in-flight CI/CD secrets, then exfil over HTTPS to the same `t[.]m-kosche[.]com` C2.
- New `ANTV_WAVE_KITTY_PERSISTENCE`, `ANTV_WAVE_FIREDALAZER`, `ANTV_WAVE_OTEL_C2` rules in `src/patterns.ts`; new campaign tests in `src/__tests__/campaigns.test.ts`.

### v5.2.14 (2026-05-19)
**Threat intel: Phantom Bot DDoS npm infostealer + Mini Shai-Hulud TanStack follow-up (May 2026)**

Leaked Shai-Hulud worm source code was re-weaponized over the weekend of 2026-05-17 by npm publisher `deadcode09284814`. Four packages (`chalk-tempalte`, `@deadcode09284814/axios-util`, `axois-utils`, `color-style-utils`) shipped an infostealer plus a Golang Phantom Bot DDoS module (HTTP / TCP / UDP flood and TCP reset). Combined 2,678 downloads before takedown.

- C2 over localhost.run tunnels `87e0bbc636999b[.]lhr[.]life` and `edcf8b03c84634[.]lhr[.]life`, plus direct TCP to `80[.]200[.]28[.]28:2222`
- `deadcode09284814` added to known malicious GitHub / npm accounts; four packages added to `MALICIOUS_PACKAGE_PATTERNS`
- Follow-up IOCs from SANS ISC diary 32994 for the TanStack wave: `seed1[.]getsession[.]org` (second Session messenger exfil node), `router_init.js` payload SHA-256 `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, staging forks `github[.]com/voicproducoes` and `github[.]com/zblgg`
- New campaign tests for both clusters in `src/__tests__/campaigns.test.ts`

### v5.2.13 (2026-05-16)
**Threat intel: node-ipc credential stealer (May 2026)**

Maintainer email hijack of `atlantis-software[.]net` (re-registered 2026-05-07) led to malicious `node-ipc` releases `9.1.6`, `9.2.3`, and `12.0.1`.

- DNS exfiltration domain `sh[.]azurestaticprovider[.]net` (IP `37[.]16[.]75[.]69`); payload `node-ipc.cjs` SHA-256 `96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144`
- `12.0.1` uses hash-targeted activation and harvests 90+ credential categories
- Domains, IP, hash, and npm package IOCs added to bundled threat-intel feed

### v5.2.12 (2026-05-14)
**Threat intel: Mini Shai-Hulud TanStack / UiPath / Mistral compromise (May 2026)**

Continuation of the Mini Shai-Hulud worm via the TanStack ecosystem (CVE-2026-45321, CVSS 9.6).

- 3 C2 domains (`filev2[.]getsession[.]org`, `api[.]masscan[.]cloud`, `git-tanstack[.]com`) and 1 C2 IP (`83[.]142[.]209[.]194`)
- 9 compromised npm package families: OpenSearch (4 versions), Squawk (3), TallyUI (2)
- 2 compromised PyPI packages: `guardrails-ai@0.10.1`, `mistralai@2.4.6`

### v5.2.11 (2026-05-12)
**Threat intel: Checkmarx Jenkins AST plugin + MacSync Claude variant (May 2026)**

- Checkmarx Jenkins AST Plugin compromise by TeamPCP / Mr_Rot13 (malicious version `2.0.13-829.vc72453fa_1c16`). `Mr_Rot13` and `TeamPCP` added to known malicious GitHub accounts.
- MacSync Stealer Claude.ai / Google Ads variant: 3 new C2 domains (`customroofingcontractors[.]com`, `bernasibutuwqu2[.]com`, `briskinternet[.]com`) plus loader SHA-256 `ed5ed79a...` and payload SHA-256 `a833ad98...`
- New campaign tests for both clusters in `src/__tests__/campaigns.test.ts`

### v5.2.10 (2026-05-10)
**Threat intel: JDownloader compromise + fake OpenAI HF repo (May 2026)**

- JDownloader site compromise (2026-05-06 to 2026-05-07): Python RAT installers via `parkspringshotel[.]com`, `auraguest[.]lk`, `checkinnhotels[.]com`; bogus "Zipline LLC" and "The Water Team" signers; Linux ELF package plus systemd-exec
- Fake OpenAI Privacy Filter on Hugging Face: `Open-OSS/privacy-filter` trended; `loader.py` plus `start.bat` fetch sefirah infostealer (C2 `recargapopular[.]com`)

### v5.2.9 (2026-05-09)
**Threat intel: TCLBANKER Brazilian banking trojan (May 2026)**

REF3076 actor distributes trojanized `LogiAiPromptBuilder.exe` MSI; sideloads `screen_retriever_plugin.dll`; self-spreads via WhatsApp / Outlook worm modules; targets 59 banks, fintech platforms, and crypto exchanges.

- C2 domains: `campagna1-api[.]ef971a42[.]workers[.]dev`, `documents[.]ef971a42[.]workers[.]dev`, `mxtestacionamentos[.]com`
- C2 IP: `191[.]96[.]224[.]96`
- 4 new SHA-256 hashes added to bundled threat-intel feed
- 4 new campaign tests in `src/__tests__/campaigns.test.ts`

### v5.2.8 (2026-05-08)
**Threat intel: ZiChatBot PyPI + Beagle backdoor (May 2026)**

Two fresh May 2026 supply-chain campaigns are now signatured.

- **ZiChatBot PyPI campaign** - Three malicious PyPI packages (`uuid32-utils`, `colorinal`, `termncolor`) drop `terminate.dll` (Windows) / `terminate.so` (Linux) and abuse Zulip REST APIs as C2. Suspected APT32/OceanLotus link. New rule `ZICHATBOT_PACKAGE` in `src/patterns.ts`, `MALICIOUS_PACKAGE_PATTERNS` entries, and bundled threat-intel `package` IOCs.
- **Beagle backdoor / fake Claude AI site** - Drive-by from `claude-pro[.]com` delivers a 505MB ZIP with DonutLoader plus DLL sideloading via `NOVupdate.exe` + `avk.dll`, calling out to `license[.]claude-pro[.]com` (`8[.]217[.]190[.]58`). Domains and IP added to `KNOWN_C2_DOMAINS` / `KNOWN_C2_IPS` plus bundled threat-intel feed.
- 6 new tests in `src/__tests__/campaigns.test.ts`.

### v5.2.7 (2026-05-08)
**Threat intel: DAEMON Tools QUIC RAT supply-chain attack (May 2026)**

- Trojanized DAEMON Tools installers (versions 12.5.0.2421-12.5.0.2434) distributed via official website since 2026-04-08
- Selective second-stage QUIC RAT deployed to gov/scientific/manufacturing hosts in Russia, Belarus, Thailand
- C2 domain `env-check[.]daemontools[.]cc` added to `KNOWN_C2_DOMAINS` + threat-intel feed
- Suspected Chinese-speaking adversary; patched in version 12.6.0.2445

### v5.2.6 (2026-05-08)
**Threat intel: CanisterSprawl, BufferZoneCorp, MacSync, EtherRAT (May 2026)**

- **CanisterSprawl** - TeamPCP Update 008 with ICP canister-based C2 (`whereisitat[.]lucyatemysuperbox[.]space`)
- **xinference PyPI hijack** - Versions 2.6.0-2.6.2 (TeamPCP credential stealer)
- **BufferZoneCorp** - 7 poisoned Ruby `knot-*` sleeper gems + 9 Go modules
- **MacSync Stealer** - Homebrew malvertising via `glowmedaesthetics[.]com`
- **EtherRAT** - GitHub facade repos with Ethereum smart contract C2, fallback IP `135[.]125[.]255[.]55`

### v5.2.5 (2026-05-01)
**Threat intel: Mini Shai-Hulud / TeamPCP supply chain worm (April 2026)**

- SAP CAP npm hijacks: `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`, `mbt@1.2.48`
- Intercom npm hijack: `intercom-client@7.0.4`
- PyTorch Lightning PyPI hijack: `lightning@2.6.2/2.6.3`
- Worm marker "A Mini Shai-Hulud has Appeared", Bun-based preinstall hook fingerprint

### v5.2.4 (2026-04-30)
**Threat intel: DPRK @validate-sdk/v2 + LofyGang / LofyStealer (April 2026)**

Two fresh April 2026 supply-chain campaigns are now signatured.

- **DPRK AI-inserted npm malware** — `@validate-sdk/v2` was inserted into a victim project as a dependency by the Claude Opus LLM during a social-engineering operation attributed to North Korean actors. New rule `DPRK_VALIDATE_SDK` in `src/patterns.ts` plus a `MALICIOUS_PACKAGE_PATTERNS` entry, a bundled threat-intel `package` IOC, and a recommendation to audit AI-suggested dependencies.
- **LofyGang / LofyStealer (aka GrabBot)** — Brazilian crew resurfaces after three years targeting Minecraft players with a new infostealer disguised as Minecraft hacks. New rules `LOFYSTEALER_MARKER` and `LOFYGANG_MINECRAFT_LURE` in `src/patterns.ts`, plus threat-intel `package` IOCs for the family aliases.
- 5 new tests in `src/__tests__/campaigns.test.ts`.

### v5.2.3 (2026-04-26)
**Documentation catch-up** — bumps version strings in `src/cli.ts`, `src/reporter.ts` (text header, SARIF, SBOM, HTML footer) that were stuck at `5.2.0` / `5.1.0` since the v5.2.1 and v5.2.2 releases. No behavior change.

### v5.2.2 (2026-04-26)
**Solana monitor: rate-limit-aware RPC client** — closes [#21](https://github.com/homeofe/supply-chain-guard/issues/21).

The public Solana RPC (`api.mainnet-beta.solana.com`) returns HTTP 429 and JSON-RPC error `-32005` when its per-IP quota is exceeded. Previously the monitor surfaced these as fatal poll errors and skipped the interval. Now `solanaRpc()` retries with exponential backoff and recovers automatically.

- **Detection**: HTTP 429, JSON-RPC code `-32005`, or message heuristics (`rate.?limit`, `too many requests`, `429`, `-32005`)
- **Backoff**: exponential 1s -> 32s with +/- 25% jitter, capped at 5 retries
- **Retry-After**: header (seconds or HTTP-date) is honored when present and overrides backoff
- **Test seam**: `__setSleepForTesting()` lets tests run instantly without real timers
- 6 new tests in `src/__tests__/solana-monitor.test.ts` cover 429 retry, `-32005` retry, Retry-After honoring, max-retry exhaustion, non-rate-limit pass-through, and message-based detection

### v5.2.1 (2026-04-26)
**Threat intel: Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)**

A single threat actor (claiming "TeamPCP") compromised both the Checkmarx KICS Docker images / VSCode-OpenVSX extensions and the `@bitwarden/cli` npm package on April 22, 2026, using a shared `audit[.]checkmarx[.]cx/v1/telemetry` exfiltration endpoint. Targets GitHub tokens, AWS/Azure/GCP credentials, npm tokens, SSH keys, and Claude configs. Marked as a successor to the Shai-Hulud npm worm.

- **C2 domains**: `audit[.]checkmarx[.]cx`, `checkmarx[.]cx` (`src/ioc-blocklist.ts`)
- **C2 IPs**: `94[.]154[.]172[.]43`, `91[.]195[.]240[.]123`
- **Compromised package**: `@bitwarden/cli@2026.4.0`
- **New campaign rules** in `src/patterns.ts`:
  - `CHECKMARX_SHAI_HULUD_V3` — matches the `Shai-Hulud: The Third Coming` exfil marker string
  - `CHECKMARX_MCP_ADDON` — matches the `mcpAddon.js` loader filename
  - `BITWARDEN_CLI_LOADER` — matches `bw_setup.js` / `bw1.js` loader/payload pair
- 4 new tests in `src/__tests__/campaigns.test.ts`

### v5.2.0 (2026-04-08)
**Self-Scan Clean + Text Wrapping** — the scanner no longer flags its own source code. Scanning `supply-chain-guard` itself drops from 100/critical (243 critical + 137 high) to clean.

**Scanner source exclusion** (`src/scanner.ts`):
- New shared `SCANNER_SOURCE_FILE` and `TEST_FILE_REGEX` constants replace duplicated inline regexes
- `checkIOCBlocklist()` and `checkThreatIntel()` now skip scanner definition files and test files — eliminates ~50 IOC/threat-intel self-matches
- `checkMultiLineProtestware()` skips scanner source and test files — eliminates proximity false positives

**Pattern-level guards** (`src/patterns.ts`):
- `notTestFile: true` added to all ~120 pattern rules (was only on 1). Test files with malware samples are no longer flagged
- New `SCANNER_SRC` regex excludes scanner definition files from 35 rules across CAMPAIGN_PATTERNS, INFOSTEALER_PATTERNS, SECRETS_PATTERNS, LURE_PATTERNS, BEACON_MINER_PATTERNS, and CAMPAIGN_PATTERNS_V2
- Existing `notFilePattern` regexes merged for rules that already had one (VIDAR_BROWSER_THEFT, PROXY_BACKCONNECT, DROPPER_TEMP_EXEC)

**Text wrapping** (`src/reporter.ts`):
- New `wrapText()` helper replaces `trunc()` for description, match, and fix fields in findings output
- Long text now word-wraps across multiple lines within box borders instead of being cut off with `…`

### v5.1.1 (2026-04-07)
**CI and test fixes**
- CI workflow: add GitHub Release creation step — after npm publish, automatically creates a GitHub Release with changelog notes extracted from README.md
- `reporter.test.ts`: fix 3 text-format assertions that checked old output patterns (`"scan report"`, `"52/100"`, `"None"`) broken by the v5.1.0 ASCII output redesign

### v5.1.0 (2026-04-07)
**Comprehensive ASCII CLI output** — complete redesign of the default text reporter.
- Double-line banner header (`╔╗`) with tool name and version
- Risk score with 36-char visual gauge bar, color-coded by severity level
- Findings summary as a severity histogram with proportional `█░` bars scaled to highest count
- Finding cards with structured `match` / `fix` label indenting and `···` dot-line separators
- Trust breakdown and risk dimensions with 32-char bar gauges and divider before Overall
- All sections framed in `┌─┐ / └─┘` box-drawing borders at 80-char terminal width
- Fixed stale hardcoded `4.8.0`/`4.9.0` version strings in SARIF, SBOM metadata, and HTML footer

### v5.0.1 (2026-04-07)
**False positive fixes — second pass** after live workspace testing revealed additional FPs.
- `PROXY_HANDLER_TRAP`: `notFilePattern` extended to cover non-minified vendor files in `/static/js/`, `/vendor/`, `/public/js/`, `/assets/js/` directories (e.g. `tailwindcss.js`)
- `SHAI_HULUD_WORM` / `SHAI_HULUD_CRED_STEAL`: switched from `notFilePattern(yml)` to `onlyExtensions` for source code only — eliminates FPs on `.md`, `.json`, and other doc/config files
- `README_LURE` rules: `onlyFilePattern` tightened to filename-based match (README/CHANGELOG/DESCRIPTION/CONTRIBUTING) instead of any `*.md` file — eliminates FPs on `docs/*.md`
- `DROPPER_TEMP_EXEC`: pattern tightened from `save.*\.exe` to `saveFile\(` to avoid matching variable names
- `PROTESTWARE_PROXIMITY`: destructive token detection now requires actual function calls (`fs.rm*\s*\(`) rather than any line containing `child_process`

### v5.0.0 (2026-04-07)
**Context-Aware False Positive Elimination** — workspace-wide scan of 100k+ LOC across 15 projects identified 14 systematic FP categories. v5.0.0 eliminates all of them without weakening real detection.

**New PatternEntry context fields** (`src/types.ts`):
- `onlyFilePattern?: RegExp` — only apply pattern to files whose path matches (e.g. README/docs only)
- `notFilePattern?: RegExp` — skip files whose path matches (e.g. `.min.js`, `.yml`)
- `notTestFile?: boolean` — skip test/spec/fixture/conftest files

**Rule-level fixes** (`src/patterns.ts`):
- `README_LURE_CRACK` / `README_LURE_LEAKED` / `README_LURE_URGENCY`: `onlyFilePattern` → README/CHANGELOG/`.md` files only. Source files like `.ts` no longer trigger these
- `SHAI_HULUD_WORM` / `SHAI_HULUD_CRED_STEAL`: `notFilePattern: /\.ya?ml$/` → `npm publish` in CI workflow YAML is standard; worm runs it from JS/TS code
- `PROXY_HANDLER_TRAP` / `BEACON_INTERVAL_FETCH` / `VIDAR_BROWSER_THEFT` / `PROXY_BACKCONNECT`: `notFilePattern: /\.min\.(js|css)$/` → minified files put everything on one line, making unrelated patterns appear co-located
- `DROPPER_TEMP_EXEC` / `MINER_CONFIG_KEYS`: `notFilePattern: /\.json$/` → Bootstrap icon JSON files won't trigger mining config detection
- `IAC_HARDCODED_SECRET`: `notTestFile: true` + pattern excludes dummy values (`test-key`, `your_*`, `example`, `placeholder`, `changeme`)
- `VIDAR_BROWSER_THEFT`: pattern tightened to require OS-specific browser data paths (Windows AppData, macOS Library, Linux .mozilla)
- `PROXY_BACKCONNECT`: pattern tightened to require SOCKS proxy protocol indicators or IP:port format

**Scanner fixes** (`src/scanner.ts`):
- `.claude/` directory excluded from scanning (eliminates 7× duplicate findings from Claude Code worktrees)
- `CRITICAL_FINDING_NO_OWNER` and `RISK_STAGNATION_HIGH` excluded from risk score calculation (meta-governance findings caused circular score inflation)
- `relativePath` normalized to forward slashes — cross-platform consistency in all finding `file` fields
- `checkBeaconMinerPatterns` now respects `notFilePattern`/`onlyFilePattern`/`notTestFile` like `checkFilePatterns`
- Binary detection path splitting fixed for cross-platform compatibility

**Continuous monitor fix** (`src/continuous-monitor.ts`):
- `RISK_STAGNATION_HIGH` requires ≥5 history entries before firing (avoids false alarms on new projects)

**SCANNABLE_EXTENSIONS**: `.md` added — README/CHANGELOG files now scanned for lure patterns via `checkFilePatterns`

- 22 new context-aware tests (629 total)
- Expected score reduction: projects scoring 100/critical due to FPs → ≤20/low with no actual malware

### v4.9.0 (2026-04-07)
- **New: SBOM Generator** — reads `package-lock.json` (v2+) to generate CycloneDX 1.6 SBOMs with real `components[]` (name, version, PURL, hashes, licenses). Falls back to `package.json` direct deps. VEX statements for suppressed findings. Use `--sbom-output <file>` to write separately.
- **New: SLSA Verifier** — detects SLSA provenance level (0–3) per project. Checks for sigstore/cosign signing, `slsa-github-generator` usage, hermetic build evidence, provenance attestation files. New rules: `SLSA_LEVEL_0`, `SLSA_NO_PROVENANCE`, `SLSA_UNSIGNED_ARTIFACTS`.
- **New: GitHub Actions PPE Patterns** — `GHA_PPE_PULL_TARGET` (critical), `GHA_SCRIPT_INJECTION` (critical), `GHA_OIDC_WRITE_PERM`, `GHA_CACHE_POISONING`, `GHA_ARTIFACT_DOWNLOAD`, `GHA_SELF_MODIFY`. Known malicious SHA blocklist (tj-actions Sep 2025, reviewdog).
- **New: Dependency Confusion Enhancements** — `DEP_HALLUCINATED_PACKAGE` (AI-hallucinated npm/PyPI names), `DEP_FRESH_PUBLISH` (version < 24h old), `DEP_SCOPED_PUBLIC` (internal-looking scoped package on public registry), `scanPypiDependencyConfusion()` for `requirements.txt`/`pyproject.toml`.
- **False Positive Reduction** — scanning a 100k+ LOC production codebase went from 819 findings/critical to 17 findings/high:
  - `LOCKFILE_ORPHANED_DEPENDENCY`: 794 individual findings → 1 aggregated summary (npm v7 flat lockfile fix)
  - `TYPOSQUAT_LEVENSHTEIN`: pre-check against popular-packages set; min name length ≥4; short popular packages (ws/pg/nx) excluded from comparison; bcryptjs/swr/tsx/zod added to whitelist
  - `SVG_SCRIPT_INJECTION`: restricted to `.svg` files only (new `onlyExtensions` field on PatternEntry)
  - `IMPORT_EXPRESSION`: backtick without `${...}` expression no longer triggers; severity high→medium
  - `BEACON_INTERVAL_FETCH`: severity high→medium (React polling false positive)
  - `DEAD_DROP_DNS_TXT` / `C2_DOH_RESOLVER`: severity high→medium (false positives in security tooling)
  - `GHA_ENV_EXFIL`: pattern tightened — only fires when secrets/env passed as curl data/header
  - `WORKFLOW_SECRET_TO_UPLOAD_PATH`: severity high→medium, confidence 0.7→0.6
  - `SECRETS_SSH_KEY_READ`: pattern requires specific key filenames (`id_rsa`, `id_ed25519` etc.) — no longer fires on `cat >> ~/.ssh/known_hosts` CI setup
- **Score Calculation**: per-rule deduplication (each unique rule contributes once to score) + weights medium 8→5, low 3→2
- 45 new tests (607 total)

### v4.8.0 (2026-04-04)
- **New: Continuous Risk Monitor** -- persistent risk history, trend detection (spikes, stagnation, increasing)
- **New: Triage Engine** -- finding ownership, status tracking, governance checks (unowned critical, expired acceptances)
- **New: SLA Engine** -- remediation deadline tracking with breach and at-risk detection
- **New: Risk Forecasting** -- linear regression-based trajectory prediction
- **New: Security Metrics** -- open critical/high, SLA compliance rate, risk trend, top contributors
- 18 new tests (562 total)

### v4.7.0 (2026-04-04)
- **New: Attack Graph Engine** -- models relationships between repos, packages, workflows, secrets, IOCs as directed graphs with exploitable attack paths
- **New: Active Validation Framework** -- confidence tiers (heuristic/correlated/validated/confirmed), rationale and evidence per finding
- **New: Workflow Modeler** -- models GitHub Actions as executable chains, detects secret-to-egress and untrusted-action-in-release paths
- **New: Secret Simulator** -- honeytoken system for sandboxed analysis (fake .npmrc, .env, SSH keys, AWS creds)
- **New: Org Posture Engine** -- portfolio-wide risk posture with systemic drift detection, recurring risky packages/actions
- **New:** `--export-graph json|mermaid` for attack graph visualization
- **New:** Mermaid diagram export for attack paths
- 19 new tests (544 total)

### v4.6.0 (2026-04-04)
- **New: Remediation Engine** -- concrete, prioritized fix steps for every finding
- **New: Fix Suggestions** -- machine-readable patches (pin actions, fix registries)
- **New: Incident Playbooks** -- full response playbooks for GlassWorm, Vidar, npm takeover, fake repos, CI/CD poisoning
- **New: SOC Exporter** -- JSON incident bundles, markdown incident reports, CSV summaries
- **New: Dependency Governance** -- untrusted source detection in lockfiles
- **New:** `--export-incident-md` for ticket-ready incident reports
- **New:** `--export-fixes` for automatable fix suggestions
- **New:** Remediation plan section in text/HTML reports
- 24 new tests (525 total)

### v4.5.0 (2026-04-04)
- **New: Threat Intelligence** -- real-time IOC feed integration with confidence scoring and decay
- **New: Adaptive Risk Engine** -- multi-dimensional scoring (code/deps/repo/CI + confidence)
- **New: Diff-Based Scanning** -- `--since <commit>` scans only changed files
- **New: Org Scanning** -- `supply-chain-guard org <github-org>` scans entire organizations
- **New:** Advanced obfuscation v2 (split strings, multi-layer encoding, runtime deobfuscation)
- **New:** Risk dimensions in text/JSON output (code risk, dep risk, CI/CD risk, threat intel)
- 19 new tests (501 total)

### v4.4.0 (2026-04-04)
- **New: Policy Engine** -- `.supply-chain-guard.yml` config for rule disable, severity overrides, allowlists, suppressions
- **New: Baseline System** -- `--save-baseline` / `--baseline` for diff-only CI scanning (only new findings)
- **New: Trust Signals** -- positive indicators (SECURITY.md, CODEOWNERS, LICENSE, lockfile, repository link)
- **New:** Secret exfiltration chain correlations (install hook + network + obfuscation)
- **New:** Suppression count in reports
- 18 new tests (482 total)

### v4.3.0 (2026-04-04)
- Documentation overhaul: complete README rewrite covering all features through v4.2
- Updated all version references, examples, and detection rule tables

### v4.2.0 (2026-04-04)
- **New: Correlation Engine** -- links findings into incident-level attack chains (15+ rules)
- **New: Trust Breakdown** -- 4-dimension scoring (publisher/code/dependency/release)
- **New: Install Hook Scanner** -- deep analysis (secret harvesting, download-exec, binary blobs)
- **New: Dependency Risk Analyzer** -- Levenshtein typosquat detection
- **New: Publishing Anomaly Detector** -- maintainer changes, version gaps
- **New: Release Scanner** -- double extensions, LNK, PE magic, password hints
- **New:** C2 patterns (DoH, Gist dead-drops, dynamic WebSocket)
- **New:** Secrets detection (AWS, GitHub, SSH, npm tokens, private keys)
- 59 new tests (464 total), ~174 detection rules

### v4.1.0 (2026-04-04)
- **New: GitHub Trust Scanner** -- repo metadata, star-farming, release artifacts, README lures
- **New: IOC Blocklist** -- known C2 domains/IPs, malware hashes, bad npm versions, malicious accounts
- **New:** Vidar/GhostSocks/dropper patterns, dead-drop resolver detection
- **New:** Claude Code leak campaign signatures, fake AI tool lure detection
- 42 new tests (405 total), ~143 detection rules

### v4.0.0 (2026-04-04)
- **New:** Dockerfile, package config, git security, Cargo/Rust, Go module, entropy scanners
- **New:** Build-tool, monorepo, IaC/Terraform patterns
- **New:** HTML report format with severity filtering
- **New:** Shai-Hulud worm, advanced obfuscation, campaign signatures
- 94 new tests (363 total), 110+ detection rules

### v3.1.0 (2026-03-26)
- SBOM export (CycloneDX 1.5), `--fail-on` flag, full test coverage (269 tests)

### v3.0.0 (2026-03-26)
- PyPI scanner, GitHub Actions scanner, SARIF output, Solana watchlist

### v2.0.0
- Multi-platform scanner (npm, PyPI, VS Code), dependency confusion, lockfile checks

### v1.0.0
- Initial release: GlassWorm detection, npm scanning, Solana C2 monitoring

## License

[Apache-2.0](LICENSE) - Copyright 2026 Elvatis - Emre Kohler
