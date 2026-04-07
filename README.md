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
- Obfuscated execution: `eval(atob())`, `eval(Buffer.from())`, template literal eval, dynamic `import()`
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
- README lure detection (leaked/cracked/urgency language)

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
│              match  https://steamcommunity.com/profiles/76561198...         │
│              fix    Remove external URL resolution; use static configuration │
│                                                                              │
│ ············································································· │
│                                                                              │
│  [CRITICAL]  VIDAR_BROWSER_THEFT                                            │
│              Browser credential file access (infostealer pattern)           │
│              src/steal.js:45                                                 │
│              match  AppData/Local/Google/Chrome/User Data/Login Data        │
│              fix    Never access browser credential stores                   │
│                                                                              │
│ ············································································· │
│                                                                              │
│  [CRITICAL]  DROPPER_TEMP_EXEC                                              │
│              Dropper: file written and executed from temp directory          │
│              src/loader.js:23                                                │
│              match  saveFile(tmpdir, payload); exec(tmpPath)                │
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
- `VIDAR_BROWSER_THEFT`: pattern tightened to require OS-specific browser data paths (`AppData/Local/Google/Chrome/...`, `~/.mozilla/firefox/...`)
- `PROXY_BACKCONNECT`: pattern tightened to require SOCKS5 protocol indicators or IP:port format

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
