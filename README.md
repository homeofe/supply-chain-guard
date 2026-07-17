# supply-chain-guard

Open-source supply-chain security scanner for npm, PyPI, Cargo, Go, RubyGems, Composer, NuGet, Docker, Terraform, VS Code extensions, GitHub Actions and GitHub repositories. Detects malware campaigns (GlassWorm, Vidar, Shai-Hulud), fake AI tool repos, account takeovers, and 180+ threat indicators across all major lockfile formats (npm, pnpm, yarn, bun). Generates CycloneDX 1.6 SBOMs with real dependency inventories, verifies SLSA provenance, and correlates findings into attack-chain incidents.

[![npm version](https://img.shields.io/npm/v/supply-chain-guard?logo=npm)](https://www.npmjs.com/package/supply-chain-guard)
[![npm downloads](https://img.shields.io/npm/dw/supply-chain-guard?logo=npm&label=weekly%20downloads)](https://www.npmjs.com/package/supply-chain-guard)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-green?logo=node.js)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue?logo=typescript)](https://www.typescriptlang.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/homeofe/supply-chain-guard/ci.yml?branch=main&label=CI&logo=github)](https://github.com/homeofe/supply-chain-guard/actions/workflows/ci.yml)
[![AAHP Verify](https://github.com/homeofe/supply-chain-guard/actions/workflows/aahp-verify.yml/badge.svg)](https://github.com/homeofe/supply-chain-guard/actions/workflows/aahp-verify.yml)
[![Last commit](https://img.shields.io/github/last-commit/homeofe/supply-chain-guard?logo=github)](https://github.com/homeofe/supply-chain-guard/commits/main)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

![supply-chain-guard scanning a malicious npm package: risk gauges, GlassWorm incident correlation, and a remediation plan](assets/demo.gif)

## Contents

- [Background](#background)
- [What It Detects](#what-it-detects)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Output Formats](#output-formats)
- [CI Exit Code Control](#ci-exit-code-control)
- [Filtering](#filtering)
- [Policy Configuration](#policy-configuration-v44)
- [Baseline Diffing](#baseline-diffing-v44)
- [Example Output](#example-output)
- [Supported Ecosystems](#supported-ecosystems)
- [How It Compares](#how-it-compares)
- [GitHub Action](#github-action)
- [For AI Coding Agents (MCP)](#for-ai-coding-agents-mcp)
- [Live Threat Feed](#live-threat-feed)
- [Install Guard](#install-guard)
- [Adding Custom Patterns](#adding-custom-patterns)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [Changelog](#changelog)

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
- Scan-coverage transparency: files above the 5 MB content-scan limit are surfaced as `FILE_TOO_LARGE_SKIPPED` (info severity, never affects exit codes) instead of being silently skipped - padding a payload past the limit no longer hides it from the report

### Supply Chain Attacks
- Install hook deep analysis (secret harvesting, download-exec chains, binary blobs)
- Levenshtein-based typosquatting detection against top 100 npm packages with known-safe whitelist
- Dependency confusion and namespace squatting
- Known-bad version blocklist (axios, ua-parser-js, coa, rc, event-stream, node-ipc, colors, faker)
- Publishing anomaly detection (maintainer changes, version gaps, script additions)

### Infrastructure & CI/CD
- GitHub Actions: unpinned actions, secrets exfiltration, encoded payloads, curl piping
- Agentic workflows (GitLost class): AI-agent steps and gh-aw `.github/workflows/*.md` that ingest untrusted issue/PR text, hold a cross-repo token, and can post publicly - the prompt-injection data-leak posture
- Dockerfile: curl pipe, unpinned base images, hardcoded secrets, SUID bits
- Terraform/IaC: inline scripts, external modules, hardcoded secrets
- Package manager configs (.npmrc, .yarnrc, pip.conf): HTTP registries, exposed tokens
- Git hooks and submodule security

### Repository Trust Signals
- GitHub repo metadata analysis (account age, star-farming, single-commit repos)
- Release artifact scanning (.exe, .7z, double extensions, LNK shortcuts, PE magic)
- README lure detection (leaked/pirated/urgency language)

### Prompt Injection Against AI Coding Agents (v5.2.19)
Detects LLM-control tokens embedded in package READMEs that target downstream AI coding agents (Claude Code, Cursor, Copilot) reading the docs on behalf of a human developer. The example tokens below are HTML-escaped in the raw README so the patterns do not flag this documentation itself - they render normally in any markdown viewer:
- `&lt;system-reminder&gt;` / `&lt;system-prompt&gt;` (Anthropic family)
- `&lt;|im_start|&gt;` / `&lt;|im_end|&gt;` ChatML (OpenAI, Llama, Mistral, Qwen)
- `&#91;INST&#93;` / `&#91;/INST&#93;` (Mistral, Llama instruction-tuned)
- `&lt;|system|&gt;` / `&lt;|user|&gt;` / `&lt;|assistant|&gt;` (Phi, Gemma, Granite, generic role tokens)
- Natural-language jailbreak phrasing ("ignore previous instructions")

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

### pre-commit

Run the scanner as a [pre-commit](https://pre-commit.com) hook (Python-ecosystem teams get the same gate without touching npm). Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/homeofe/supply-chain-guard
    rev: v5.13.0
    hooks:
      - id: supply-chain-guard
```

The scanner writes its risk history to `.scg-history/` in the scanned repo;
it is not written when `--no-history` is set, which the hook now uses. For
plain scans without that flag, add the folder to your `.gitignore`.

The hook scans the repository root on every commit and fails on high or critical findings.

### Docker

Run the scanner without a Node toolchain via the official multi-arch image (linux/amd64, linux/arm64), published to GHCR on every release tag:

```bash
docker run --rm -v ${PWD}:/scan ghcr.io/homeofe/supply-chain-guard scan /scan
```

`${PWD}` works in bash, zsh, and PowerShell; in cmd.exe use `%cd%` instead.

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

# Scan a VS Code extension from the Open VSX registry (VSCodium etc.)
supply-chain-guard vscode publisher.extension --registry openvsx

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
supply-chain-guard scan ./project --format badge   # Shields.io endpoint JSON
supply-chain-guard scan ./project --format gitlab  # GitLab Dependency Scanning report (security-report-schemas 15.2.4, see examples/gitlab-ci.yml)
```

### Badge

Publish the badge JSON from CI (gist or gh-pages), then point Shields at it:

The scan exits non-zero when it finds high/critical issues - exactly when the
badge MUST update to red. Neutralize the exit code on the generate step (or use
`if: always()` on the publish step) so a bad scan never freezes the badge green:

```yaml
- name: Generate badge JSON
  run: supply-chain-guard scan . --format badge > badge.json || true
- name: Publish to gist
  if: always()
  run: gh api gists/YOUR_GIST_ID -X PATCH -F "files[badge.json][content]=@badge.json"
  env:
    GH_TOKEN: ${{ secrets.BADGE_GIST_TOKEN }}
```

```markdown
![supply-chain-guard](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/YOUR_USER/YOUR_GIST_ID/raw/badge.json)
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
| npm | `scan`, `npm` | package.json, install scripts, tarball; lockfiles: package-lock.json, pnpm-lock.yaml, yarn.lock (v1 + Berry), bun.lock |
| PyPI | `pypi` | setup.py, setup.cfg, pyproject.toml, install hooks |
| Cargo/Rust | `scan` | Cargo.toml, build.rs, proc macros |
| Go | `scan` | go.mod, init() functions, CGo, plugin loading |
| RubyGems | `scan` | Gemfile, Gemfile.lock (malicious-gem IOCs, http/git sources) |
| Composer/PHP | `scan` | composer.json, composer.lock (malicious-package IOCs, http repos) |
| NuGet/.NET | `scan` | packages.lock.json, *.csproj, nuget.config (malicious-package IOCs, http feeds) |
| Docker | `scan` | Dockerfile, docker-compose.yml, Containerfile |
| Terraform | `scan` | .tf, .hcl files (provisioners, modules, secrets) |
| VS Code | `vscode` | .vsix files, activation events, dangerous APIs |
| GitHub Actions | `scan` | .github/workflows/*.yml |
| GitHub Repos | `repo` | Trust signals, releases, README lures |
| Solana | `monitor` | C2 wallet memo transactions |

## How It Compares

supply-chain-guard is the malware / behavior / campaign-IOC layer: it statically scans what you actually install (node_modules, packages, Docker images, VS Code extensions, Actions workflows, IaC) for malicious behavior and known campaign indicators, entirely locally. It does NOT do CVE lookups: pair it with osv-scanner or npm audit for known vulnerabilities. Most tools below measure a different axis and are complementary, not competitors.

| Tool | Focus | Malware / behavior detection | Known-CVE lookup | Ecosystems | Open source | Account needed |
|---|---|---|---|---|---|---|
| **supply-chain-guard** | Malware campaigns, IOCs, behavior heuristics in installed artifacts; SBOM + SLSA verification | Yes: 180+ static heuristics plus campaign-IOC matching, fully local/offline | No | npm (incl. pnpm/yarn/bun lockfiles), PyPI, Cargo, Go, RubyGems, Composer, NuGet, Docker, Terraform/IaC, VS Code extensions, GitHub Actions, GitHub repos | Yes (Apache-2.0) | No |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Known vulnerabilities in dependency inventories (OSV.dev database lookup) | Known-malicious versions via OSV MAL- entries only; no behavior or IOC analysis | Yes (offline mode available) | 11+ ecosystems, 19+ lockfile formats, container images, SBOM input | Yes (Apache-2.0) | No |
| [Socket](https://socket.dev) | Proactive behavioral analysis of entire registries (SaaS) | Yes: 70+ risk types registry-wide, before advisories exist; engine is closed source and cloud-side | Yes | npm, PyPI, Maven, Go, Cargo, RubyGems, NuGet, more; Actions workflows | CLI only (MIT); detection engine proprietary | Yes (except Firewall Free) |
| [GuardDog](https://github.com/DataDog/guarddog) | Heuristic 0-10 risk scoring of individual packages (YARA + registry metadata) | Yes: heuristics only, no known-malware or campaign-IOC database; sandboxed scanning | No | npm, PyPI, Go, RubyGems, GitHub Actions, VS Code extensions | Yes (Apache-2.0) | No |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | Security-practice score of upstream repos (branch protection, pinning, review) | No: rates project hygiene, never analyzes published package contents | Only for the rated repo itself (OSV check) | GitHub repos, partial GitLab | Yes (Apache-2.0) | No (GitHub token for self-run CLI) |
| npm audit | Advisory lookup for your npm dependency tree, built into npm | Known-malicious versions after an advisory is published; no behavior or IOC analysis; `audit signatures` verifies provenance | Yes (GitHub Advisory Database) | npm only | Yes (CLI; lookup is a registry-side service) | No |

Honest caveats: Socket's registry-wide behavioral detection is deeper than anything a local scanner can do, at the cost of a closed engine and cloud analysis. Scorecard is the industry standard on its axis (upstream hygiene prediction) and supply-chain-guard does not replace it. OSV-Scanner and npm audit do flag known-malicious packages: the gap is advisory lag, not a missing capability.

### Pairs well with

- **CI one-two punch**: run `osv-scanner --lockfile=package-lock.json` for known CVEs and MAL- entries, then `supply-chain-guard scan .` for behavioral and campaign-IOC threats in the installed tree. Two axes, one job, both exit-code gated.
- **Zero-install npm baseline**: `npm audit --audit-level=high` plus `npx supply-chain-guard scan .` covers advisory-known vulnerabilities and unreported malware without adding a single dependency.
- **Pre-install vetting of a suspicious package**: `guarddog npm scan <pkg>` for an independent heuristic score, plus `supply-chain-guard npm <pkg>` for campaign-IOC and install-hook analysis, before it ever touches your machine.
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

## For AI Coding Agents (MCP)

supply-chain-guard is both a scanner OF the agentic ecosystem and a tool FOR it.

**Scanning agentic attack surfaces** (automatic in every `scan`):

- MCP server configs: `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`,
  `claude_desktop_config.json` - malicious server packages, C2 endpoints,
  plain-http servers, secrets forwarded to remote servers, prompt injection in
  tool descriptions (MCP_ rules)
- Agent skills and rules files: `.claude/skills/**/SKILL.md`, `.claude/settings.json`
  hooks, `.cursorrules`, `.github/copilot-instructions.md`, `AGENTS.md`, `CLAUDE.md` -
  injected control tokens, invisible Unicode instruction channels, download-and-execute
  and credential-harvesting instructions, dangerous hook commands (SKILL_/AGENT_ rules)

**Built-in MCP server** - let your AI agent vet packages BEFORE installing them:

```bash
npm install -g supply-chain-guard
claude mcp add supply-chain-guard supply-chain-guard mcp
```

This form works in every shell (bash, zsh, PowerShell, cmd) and avoids npx
cold-start timeouts on first connect. On bash/zsh you can use the one-liner
`claude mcp add supply-chain-guard -- npx -y supply-chain-guard mcp` instead;
note that PowerShell swallows the bare `--` itself, so on Windows prefer the
global-install form above.

Exposes three tools over stdio: `ioc_lookup` (offline IOC + known-bad-version check
for npm/PyPI/RubyGems/Composer/NuGet), `scan_directory`, and `scan_npm_package`.
Client config snippets for Claude Code, Claude Desktop, and Cursor: [docs/mcp.md](docs/mcp.md).

## Live Threat Feed

The bundled IOC feed ships with every release, and the same data is published as
[feed.json](feed.json) on every push to main - so protection lands the day a campaign
is ingested, not at the next release:

```bash
supply-chain-guard feed stats     # entry counts by type and severity
supply-chain-guard feed refresh   # pull the latest published feed into the local cache
```

A refreshed feed is merged into every scan for the next 24 hours automatically.

**Indicator contract:** every feed value is a LITERAL indicator (a domain, IP,
URL, hash, or package name), never a regular expression. All ingestion paths
(`feed refresh`, the legacy update API, and the cached-feed load at scan time)
validate each entry against its type's shape and quarantine anything invalid -
a malformed or hostile feed entry can neither crash a scan nor flood it with
garbage matches, and a rejected refresh never overwrites the previous cache.

## Install Guard

Block known-bad packages BEFORE the package manager runs their lifecycle scripts -
the only install blocker whose entire blocklist is auditable in git history,
offline, no account:

```bash
supply-chain-guard guard npm install lodash        # clean: npm runs normally
supply-chain-guard guard pnpm add axios@1.14.1     # known-bad: blocked, exit 2
```

Supports npm, pnpm, yarn, and bun. Guard flags go BEFORE the manager name:
`--dry-run` checks the command without ever invoking the manager, `--force`
proceeds despite findings (with a loud warning). Everything after the manager
name is passed through to it unchanged.

All checks are offline against the bundled IOC feed (plus a `feed refresh`
cache when present), the known-bad-version blocklist, and the typosquat
heuristics - no network call, no telemetry.

Limitation: version ranges and tags (`^1.2.3`, `latest`) are not resolved
offline, so a version-pinned IOC only fires on an exact pin. Bare-name IOCs
(a whole malicious package) fire on any version. Use `scan` after install for
full-tree, behavior-level coverage.

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

Full release history lives in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache-2.0](LICENSE) - Copyright 2026 Elvatis - Emre Kohler
