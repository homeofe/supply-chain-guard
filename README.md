# supply-chain-guard

Open-source supply-chain security scanner for npm, PyPI, Cargo, Go, RubyGems, Composer, NuGet, Docker, Terraform, VS Code extensions, GitHub Actions and GitHub repositories. Detects malware campaigns (GlassWorm, Vidar, Shai-Hulud), fake AI tool repos, account takeovers, and 350+ threat indicators across all major lockfile formats (npm, pnpm, yarn, bun). Generates CycloneDX 1.6 SBOMs with real dependency inventories, grades SLSA provenance (parses and structurally validates in-toto/DSSE attestations), and correlates findings into attack-chain incidents. Supports EU Cyber Resilience Act SBOM and component-documentation work, and NIS2 supply chain risk-management measures.

[![npm version](https://img.shields.io/npm/v/supply-chain-guard?logo=npm)](https://www.npmjs.com/package/supply-chain-guard)
[![npm downloads](https://img.shields.io/npm/dw/supply-chain-guard?logo=npm&label=weekly%20downloads)](https://www.npmjs.com/package/supply-chain-guard)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22-green?logo=node.js)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue?logo=typescript)](https://www.typescriptlang.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/homeofe/supply-chain-guard/ci.yml?branch=main&label=CI&logo=github)](https://github.com/homeofe/supply-chain-guard/actions/workflows/ci.yml)
[![AAHP Verify](https://github.com/homeofe/supply-chain-guard/actions/workflows/aahp-verify.yml/badge.svg)](https://github.com/homeofe/supply-chain-guard/actions/workflows/aahp-verify.yml)
[![AAHP conformant](https://img.shields.io/badge/AAHP-conformant-5b47d6)](https://github.com/homeofe/AAHP)
[![Last commit](https://img.shields.io/github/last-commit/homeofe/supply-chain-guard?logo=github)](https://github.com/homeofe/supply-chain-guard/commits/main)
[![scanned by supply-chain-guard](https://img.shields.io/badge/scanned%20by-supply--chain--guard-2ea44f?logo=npm&logoColor=white)](https://github.com/homeofe/supply-chain-guard)
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
- [Internal Disclosure](#internal-disclosure)
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
- [EU Compliance (CRA / NIS2)](#eu-compliance-cra--nis2)
- [Show that you scan](#show-that-you-scan)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [License](#license)

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
- Starjacking: in `npm <pkg>` mode, corroborates a package's claimed `repository` against the repo's own `package.json` and flags a repo borrowed from an unrelated popular project to inherit its stars/trust (conservative: monorepos, forks, related names, and unfetchable repos are not flagged)
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

### Internal Topology Disclosure
Not credentials: the map of your network that a public repository hands out for free. Private and non-routable addresses (RFC1918, CGNAT, link-local, IPv6 ULA), internal-only hostnames (`.internal`, `.local`, `.lan`, `.corp`, `.home`, `.intranet`), clone URLs pointing at a forge that is not a known public one, developer home-directory paths, and internal service endpoints. Reported at `medium` (reconnaissance value, not compromise), with an optional deny-list for the names only your project knows. See [Internal Disclosure](#internal-disclosure).

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

**Requires Node.js 22 or newer.** Node 20 reached end of life on
2026-04-30; it still installs and is still covered by CI as a transition lane, but it
is out of support and that lane is removed in 5.29.0. Full policy, including what the
package is published from and what the Action and container image run on:
[`docs/node-support.md`](docs/node-support.md).

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
    rev: v5.28.1
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
docker run --rm -v ${PWD}:/scan ghcr.io/homeofe/supply-chain-guard:5.28.1 scan /scan
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
supply-chain-guard scan ./project --format markdown --json-output canonical.json  # Same scan, human report plus canonical JSON
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

`--min-severity` may reduce report noise, but it cannot be stricter than the
active `--fail-on` gate because that would hide findings required for the exit
verdict. Invalid combinations fail before scanning. Incomplete coverage also
exits nonzero regardless of the severity threshold and is reported as
`partialScan: true` in JSON.

## Filtering

```bash
supply-chain-guard scan ./project --min-severity high
supply-chain-guard scan ./project --exclude SOLANA_MAINNET,HEX_ARRAY
```

## Internal Disclosure

Secret scanners answer one question: *did a credential get committed?* This family answers a different one: **did our internal topology get committed?**

Internal hostnames, private LAN addresses, self-hosted forge URLs, developer home directories and private repository names are not credentials, so no secret scanner reports them. Together they are the reconnaissance map an attacker draws before touching anything: what exists, what it is called, where it listens, and who works on it. It leaks through the same boring channels every time. A copied clone command in a README. A `.env.example` that kept the real staging host. A comment with the path the author built from. A lockfile pointing at an internal registry. None of it is a secret, all of it is intelligence, and it stays in git history long after the file is fixed.

The rules are **shape-based**, so they work on a repository whose owner has configured nothing at all. You never have to write down what your infrastructure is called in order to be protected from publishing it.

### What it catches

| Rule | Severity | Shape |
|---|---|---|
| `INTERNAL_PRIVATE_IP` | medium | RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`), link-local (`169.254.0.0/16`) |
| `INTERNAL_PRIVATE_IPV6` | medium | IPv6 Unique Local Addresses (`fc00::/7`) |
| `INTERNAL_HOSTNAME` | medium | Hostnames in an internal-only TLD: `.internal`, `.local`, `.lan`, `.corp`, `.home`, `.intranet` |
| `INTERNAL_SERVICE_ENDPOINT` | medium | `http(s)://HOST:PORT` where HOST is private or internal |
| `INTERNAL_GIT_REMOTE` | medium | `ssh://git@<host>:<port>/<path>` and scp-style `git@<host>:<path>` where the host is not a known public forge |
| `INTERNAL_DEV_PATH` | medium | `C:\Users\<name>\`, `/home/<name>/`, `/Users/<name>/` in committed code or docs. `/Users/` is matched case-sensitively, because `/users/` is a REST route |
| `INTERNAL_SINGLE_LABEL_URL` | low | A URL whose host has no domain at all, so it only resolves through internal DNS or a hosts file |
| `INTERNAL_DENYLIST_MATCH` | medium | A term your project configured (see below). Off unless configured |
| `INTERNAL_DISCLOSURE_TRUNCATED` | info | A limit stopped this family short on one file (see [Bounded cost](#bounded-cost)). Never silent about a gap |

**Severity follows the host, not the rule.** A host with no domain part is the weakest signal in the family whichever rule reports it, so a dotless `payments` host with a port is `low`, exactly like the same host without one. Only a dotted internal name or a private address makes an endpoint `medium`.

`INTERNAL_GIT_REMOTE` is the one worth pointing at: it finds a self-hosted forge **without anyone having to name it**. Any clone URL that is not github.com, gitlab.com, bitbucket.org, codeberg.org, git.sr.ht and the other well-known public hosts is, by shape alone, a forge somebody runs privately.

### Severity is deliberately not inflated

Topology is reconnaissance value, not compromise, so the family reports `medium` and `low`. `high` and `critical` stay reserved for credential-shaped findings, which the existing rules already own.

Practically: the default gate exits non-zero on `critical` and `high` only, so **upgrading cannot turn a passing build red**. `--fail-on high` and `--fail-on critical` are equally unaffected. Two things do change: the risk **score** rises (each medium adds points), and a pipeline that runs `--fail-on medium` or lower will see the new findings. If you would rather not see them at all, they respect every existing control:

```yaml
rules:
  disable: [INTERNAL_PRIVATE_IP, INTERNAL_HOSTNAME, INTERNAL_SERVICE_ENDPOINT,
            INTERNAL_GIT_REMOTE, INTERNAL_DEV_PATH, INTERNAL_SINGLE_LABEL_URL]
```

### False-positive controls

A rule that screams on every README gets switched off, and a switched-off rule protects nothing. Three independent layers keep this quiet.

**1. The reserved documentation space never fires.** Anything written the way the RFCs intend is invisible to these rules:

- addresses from RFC5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
- names from RFC2606: `example.com`, `example.org`, `example.net`, the `.example` TLD, `.invalid`, `.test`
- loopback and the unspecified address, `localhost` URLs
- placeholder and CI account names in paths: `runner`, `vscode`, `ubuntu`, `jenkins`, `you`, `dev`, `user`, `Public` and more
- container and compose service aliases in single-label URLs: `db`, `redis`, `api`, `minio`, `nginx`, and the `unix` / `npipe` pseudo-hosts that mean "a UNIX domain socket, not a machine"
- a CIDR range such as `10.0.0.0/16` is a subnet layout, not a host, so it is not reported (a `/32` host route is)
- **universal infrastructure constants**, which are the same address in every installation on earth and therefore describe nobody's topology: the cloud metadata endpoint `169.254.169.254` (and the ECS `169.254.170.2`, Amazon Time Sync `169.254.169.123`, Alibaba `100.100.100.200`), the Kubernetes defaults `10.96.0.1` and `10.96.0.10` and the k3s `10.43.0.1` / `10.43.0.10`, the default service and pod CIDRs (`10.96.0.0/12`, `10.244.0.0/16`, `10.42.0.0/16`), the Docker bridge gateway `172.17.0.1`, and the Docker Desktop names `host.docker.internal` and friends. A real address inside the same ranges is still reported.

**2. A match has to sit where its rule can mean what it claims.**

- An internal-only TLD has to be the **last** label of the name, so `config.internal.timeout`, `com.acme.internal.util` and `settings.local.json` are never hosts.
- A name preceded by a path separator is a **file**, not a host: `./config.local`, `src/config.local` and `../lib/settings.local` are module specifiers. `https://db.example.corp/`, `//registry.svc.example.corp/` and `git@forge.internal.example:...` still are hosts.
- A name followed by `(` is a **method call**: `res.local(name, val)` in a changelog is not a machine.
- In programming-language sources a bare dotted name is only reported inside a string literal, a comment or a URL, because `config.internal.timeout` and `state.local.value` are property accesses. Data and config files (`.yml`, `.json`, `.toml`, `.env`, Dockerfile, lockfiles) carry unquoted values, so no quotes are required there.
- `/Users/` is matched **case-sensitively** and `:id`, `{id}`, `<id>` and `${user}` are rejected after the account segment, so `app.get("/users/:id")`, `"/users/{id}"` and `app.get("/users/profile/edit")` are routes, not macOS home directories. A Windows path keeps both spellings, because `C:\users\` is unambiguous.

**3. The surface decides which rules stay armed.**

| Surface | Rules that still fire |
|---|---|
| Source files (`.ts`, `.py`, `.tf`, `.yml`, Dockerfile, `.npmrc`, lockfiles) | all of them |
| Documentation prose and fenced code blocks: `.md` / `.rst` / `.txt`, anything under `docs/` | everything except the single-label URL |
| Markdown inline code spans, and fenced blocks tagged ```` ```text ```` / ```` ```plaintext ```` | hostname, endpoint, clone URL |
| Files that exist to BE an example: `examples/`, `samples/`, `fixtures/`, `testdata/`, `*.example.*` / `*.sample.*` / `*.template.*` | hostname, endpoint, clone URL |
| Test, spec, mock and fixture files and directories (`test/`, `tests/`, `spec/`, `e2e/`, `__tests__/`, `__mocks__/`, `*.test.*`), minified and bundled output | none |

The reasoning changed here, deliberately. Documentation used to be excluded wholesale, which silenced precisely the case this family exists for: **a private address or a developer path inside a README is one of the most common ways internal topology reaches a public repository**, and a `/home/<name>/` in a pasted stack trace is a real leak, not a teaching aid. The reserved namespace above is what protects a writer who follows the RFCs, and it works on every surface. What stays excluded is what measurement showed to be noise rather than signal: inline code spans (on the sample used to tune this, eight findings, all of them API signatures or documented examples), placeholder fences, and files whose whole purpose is to show a shape.

Two things are reported on purpose even though they can be examples. Kubernetes in-cluster names (`<service>.<namespace>.svc.cluster.local`) name your service inventory. And an address or path inside a **code comment** (a JSDoc `@example` block, say) is reported, because a comment is the single most common place a real host gets written down and nothing distinguishes an illustrative address from a real one there. Use RFC5737 addresses in code examples, or suppress by path.

<a id="bounded-cost"></a>
### Bounded cost

A generated bundle is one 800 KB line, and a rule family that takes minutes on it is a rule family that gets switched off. Four limits keep the cost flat, and none of them is silent:

- line offsets are computed **once per file** and binary-searched, and each line's quoting and comment structure is computed **once per line** rather than once per match
- a line longer than **2000 characters** is skipped, the way an oversized file is skipped by `FILE_TOO_LARGE_SKIPPED`
- at most **25 findings per pattern** and **100 per file**. Two rules
  (`INTERNAL_DEV_PATH` and `INTERNAL_GIT_REMOTE`) are each written as two
  patterns, so those can reach 50 from a single file. When the per-file cap
  drops findings it keeps the most severe ones.
- at most **20000 candidate matches per rule per file**, which bounds the case where nearly everything is filtered out and so produces no findings to count

Whenever a limit is reached, the file gets one `INTERNAL_DISCLOSURE_TRUNCATED` finding at `info` severity naming the limit. A scanner that quietly stopped looking is indistinguishable from a repository with nothing to find, and that is not a trade this tool makes.

On top of that, everything else already in this tool applies: `suppress` with a `path:` glob, `ignore:` globs, `--exclude`, `--min-severity`, and inline `// scg-ignore-next-line INTERNAL_HOSTNAME reason`.

### The deny-list, and its paradox

Shape rules cannot know that `sample-service` is one of your private repositories. A deny-list can. But **a list of your internal hostnames committed to a public repository is exactly the leak you were trying to prevent**, so there are three ways to configure one and only one of them puts plaintext in the repo.

```yaml
# yaml-language-server: $schema=./node_modules/supply-chain-guard/policy-schema.json

internalDisclosure:
  # (a) HASHED. Publishable: the digest hides the term from a reader and from
  #     grep. It is not a vault - see "What hashing is worth" below.
  #     Generate with: supply-chain-guard internal-hash forge.internal.example
  hashedTerms:
    # sha256("forge.internal.example") and sha256("acme/sample-service"),
    # so you can verify the recipe below against these two lines.
    - 113fbef8cb1afd8d755cfa3c5b954244973c1b4182824c64755235de60a3d106
    - 479ec322598b9047aaac200d2c1c2d5ab9658ce50ef7e60dc1081741f037d7d3

  # (b) EXTERNAL. Full regex/plaintext patterns that must never be published.
  #     Gitignore this file, or provision it on the runner. Matches are
  #     reported REDACTED, so the report cannot leak it either.
  externalFile: .scg-internal-terms.local

  # (c) PLAINTEXT. For a private repository scanning itself, or terms that
  #     are not sensitive. Literals, or /regex/flags.
  patterns:
    - sample-service
    - /build-\d{2}\.corp/
```

**Hashing recipe.** Normalisation is `trim`, then `lowercase`. Then sha256, lowercase hex. That is the whole rule, so any tool can reproduce it:

```bash
# Bundled helper (prints only the digest, so nothing sensitive rides along)
supply-chain-guard internal-hash forge.internal.example

# The same digest, without this tool
printf '%s' "forge.internal.example" | tr 'A-Z' 'a-z' | sha256sum
```

**What hashing is worth, honestly.**

*As a matcher* it is exact-token matching, nothing more. A token is a maximal run of letters, digits, `.`, `_` and `-` (so `https://forge.internal.example/x` yields `forge.internal.example`), plus an `org/repo` pair and a `.git` suffix stripped, all lowercased. A hashed entry for `forge.internal.example` therefore matches that host but not `sub.forge.internal.example`, and there is no way around it: a scanner that could match substrings of a hash would be a scanner that could recover the term. When you need substring or regex power, use `externalFile` (b).

*As a secret* it buys less than "hashed" suggests, and it is worth saying plainly. An unsalted, single-round sha256 of a low-entropy value is **dictionary-attackable**: hostnames come from a small, guessable space (a short site or service word, a two-digit index, one of a handful of internal TLDs), so anyone with your repository can hash candidate names until one matches. What a digest genuinely buys is that the term is not sitting in the file to be read, copied or grepped, and that it does not travel into a report, a log or a screenshot. That is real, and it is not the same as being unrecoverable.

*If you need the stronger claim,* salt it with a value that lives outside the repository:

```bash
export SCG_INTERNAL_HASH_SALT="$(openssl rand -hex 16)"    # store it wherever your CI secrets live
supply-chain-guard internal-hash forge.internal.example    # generates a salted digest
```

```yaml
internalDisclosure:
  hashSalted: true          # says the digests below are salted
  hashedTerms:
    - <salted digest>
```

The salt has to be held outside the repository to be worth anything: a salt committed next to the digests is hashed by the same reader who reads them, which is why there is no config key for the salt itself. `hashSalted: true` is what keeps this fail-visible - a scan that runs without the salt matches nothing, which looks exactly like a clean repository, so the declaration turns that silence into an `INTERNAL_DENYLIST_UNAVAILABLE` finding instead.

**An environment variable** does the same thing as `externalFile` without touching the committed config at all:

```bash
SCG_INTERNAL_DISCLOSURE_FILE=~/.config/scg/internal-terms supply-chain-guard scan .
```

The external file is one entry per line, `#` for comments, `sha256:<digest>` for a hashed entry, `/pattern/flags` for a regex, anything else is a case-insensitive literal. If the file is configured but absent (a shared CI runner that never received it), you get an `INTERNAL_DENYLIST_UNAVAILABLE` finding at `info` severity rather than silence: a deny-list that quietly stopped running looks exactly like a repository that is clean. An entry that cannot be compiled is reported the same way (`INTERNAL_DENYLIST_INVALID_ENTRY`, medium). Neither finding ever prints the entry, and the environment variable is named but its value is not, because a path can itself contain an account name.

**One more note on the paradox.** `allowlist.domains` also answers `INTERNAL_HOSTNAME`, `INTERNAL_SERVICE_ENDPOINT` and `INTERNAL_GIT_REMOTE` for a given host, which is convenient and publishes the host name. If that is not acceptable, suppress by path instead, which names nothing:

```yaml
suppress:
  - rule: INTERNAL_HOSTNAME
    reason: vendored upstream config, reviewed
    path: vendor/**
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
    # Suppresses THREAT_INTEL_MATCH / IOC_KNOWN_C2_DOMAIN findings whose matched
    # host is this domain or a subdomain of it.
    - company.example.internal
  githubOrgs:
    # Trusted action publishers. Suppresses the ownership-trust findings
    # (GHA_THIRD_PARTY_ACTION, GHA_TAG_NOT_SHA) for actions owned by these
    # orgs. Pinning and known-malicious-SHA rules stay armed: trusting an org
    # says who publishes the code, not that every version of it is safe.
    - my-org

# Skip files matched by these path globs (** / * / ?) during the scan.
ignore:
  - vendor/**
  - "**/*.min.js"

suppress:
  - rule: RELEASE_EXE_ARTIFACT
    reason: Legitimate Windows installer
  # Optional path glob: suppress a rule only under a matching path.
  - rule: EVAL_ATOB
    reason: Vendored third-party bundle, reviewed
    path: vendor/**

baseline:
  file: .scg-baseline.json
```

Findings can also be suppressed inline with a comment on the line directly
above them: `// scg-ignore-next-line RULE reason` (JS/TS) or
`# scg-ignore-next-line RULE` (Python/YAML/shell).

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

There is one axis where it goes somewhere the others do not go at all. Credential scanners such as gitleaks and trufflehog hunt secrets, and they are good at it; nothing in that category hunts what a repository gives away *about the network it came from*. That is what [Internal Disclosure](#internal-disclosure) covers: internal hostnames, private addresses, self-hosted forge URLs and developer paths, reported as reconnaissance risk rather than as a leaked credential.

| Tool | Focus | Malware / behavior detection | Known-CVE lookup | Ecosystems | Open source | Account needed |
|---|---|---|---|---|---|---|
| **supply-chain-guard** | Malware campaigns, IOCs, behavior heuristics in installed artifacts; SBOM + SLSA provenance grading (in-toto/DSSE structural validation) | Yes: 350+ static heuristics plus campaign-IOC matching, fully local/offline | No | npm (incl. pnpm/yarn/bun lockfiles), PyPI, Cargo, Go, RubyGems, Composer, NuGet, Docker, Terraform/IaC, VS Code extensions, GitHub Actions, GitHub repos | Yes (Apache-2.0) | No |
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
## EU Compliance (CRA / NIS2)

supply-chain-guard produces artefacts and findings that **support** compliance
work under two EU regulations that apply to software manufacturers. It does not
make an organisation compliant: compliance remains the responsibility of the
organisation deploying the software, and the mapping below describes what the
tool produces, not a legal assessment.

### Cyber Resilience Act (CRA)

The CRA requires manufacturers of products with digital elements to identify and
document the components they ship, to address vulnerabilities in those
components, and to be able to reason about the integrity of what they build on.
supply-chain-guard contributes to each of those activities:

- **Component inventory:** generates a [CycloneDX 1.6](https://cyclonedx.org/)
  SBOM from the real resolved dependency tree, as a machine-readable component
  list you can attach to technical documentation.
- **Dependency risk:** detects known-malicious packages and versions,
  typosquatting, dependency confusion, and compromised publisher activity, at
  scan time and at install time.
- **Supply chain integrity:** grades SLSA provenance from levels 0 to 3 by
  parsing and structurally validating in-toto/DSSE attestations, giving a
  recorded integrity signal per project.

```bash
# Write a CycloneDX 1.6 SBOM alongside the scan report
supply-chain-guard scan ./project --sbom-output sbom.json
```

Article and paragraph citations are deliberately omitted here. Map these outputs
to specific provisions against the final published regulation text, with your own
legal review, rather than against this README.

### NIS2 Directive

NIS2 requires essential and important entities to take measures covering supply
chain security. The relevant capabilities are:

- **Supply chain risk:** typosquatting, dependency confusion, compromised
  packages, and malicious GitHub Actions in CI/CD workflows.
- **Incident evidence:** the correlation engine links individual findings into
  named attack chains with confidence scores, and reports are exportable as
  SARIF, JSON, and CycloneDX for retention alongside an incident record.
- **Configuration exposure:** IaC, Dockerfile, and `.npmrc` / `.yarnrc` scanning
  surfaces misconfiguration before deployment.

### Operating model

Apache-2.0, no account required, and no telemetry: the scanner reports only to
its own output. `scan` runs fully offline against the bundled threat feed, so it
is suitable for air-gapped use. The commands that deliberately reach the network
are the ones that exist to do so: `supply-chain-guard npm <pkg>` and
`supply-chain-guard pypi <pkg>` fetch the package under inspection, and the feed
refresh fetches updated indicators. Offline runs use the feed bundled with the
installed version, so pin the version you intend to audit against.

## GitHub Action

**Pin an exact version.** That is the recommended form, and it is the same advice
this tool gives about your own dependencies: a security scanner should be a
deterministic input, so you know which detection logic and which IOC feed ran, and
an upgrade is a reviewable change rather than something that happens to you.

```yaml
name: Supply Chain Security
on: [push, pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: homeofe/supply-chain-guard@v5.28.1
        with:
          fail-on: critical
          comment-on-pr: true
```

Let Dependabot keep the pin current:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: daily
```

**`daily`, not `weekly`, and this project's release rate is why.** Measured over
the 155 days to 2026-08-21: 134 releases, about 1.4 a day over the last two
months, with a median of 20 hours between releases and two thirds of the gaps
under a day. A weekly schedule cannot track that. Each weekly run opens a correct
bump pull request, and the next weekly run closes it as superseded and opens
another, so an unattended pin never moves at all. Measured in one consumer of
this Action: eight consecutive weekly bump pull requests, each alive for exactly
seven days, each proposing a newer target than the last, while the pin itself sat
unchanged for 49 days and fell 82 releases behind. Every scan check was green
throughout, because a stale pin is not a failing scan.

The interval is the cheap half. The half that actually decides the outcome is
whether somebody merges the pull request, and no setting in this file supplies
that.

### `@v5`, and what it does and does not guarantee

`@v5` also works and stays supported. It is a floating **branch**, fast-forwarded
to each release by CI, and the composite action on it pins an exact npm version
that is bumped and build-gated on every release. So `@v5` is not `latest`: every
resolution still installs one exact, release-gated version.

The caveat is what happens after a major. If the v5 line stops being released once
v6 ships, `@v5` keeps resolving a frozen action that pins an old npm version, and
the IOC feed it installs stops updating. For a scanner that is a silent
false-negative generator, and nothing in your workflow would report it. An exact
pin is what turns that into a reviewable out-of-date dependency instead.

**Be precise about what an exact pin does and does not buy you, because a frozen
exact pin is the same silent false negative.** It ages exactly as quietly. This
scanner runs offline against the IOC feed bundled with the pinned version, so a
pin that stops moving freezes the detection rules at that date, and neither the
exit code, the risk score nor the check name changes to say so. The scan output
carries no age for the feed it just used. What an exact pin buys is a *place*
where the staleness becomes reviewable: the bump pull request. That is a
different claim from the staleness being visible on its own, and the measurement
above is what the difference costs. If those pull requests are opened and
superseded without ever being merged, the pin is frozen, the rule set is ageing,
and nothing in this tool will tell you.

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `format` | Output format (text/json/markdown/sarif/sbom/html/badge/gitlab/junit) | `markdown` |
| `min-severity` | Minimum severity to report | `low` |
| `exclude-rules` | Comma-separated rule IDs to exclude | |
| `fail-on` | Fail check at this severity or above, including `info` | `critical` |
| `comment-on-pr` | Post or update a PR comment | `true` |

Coverage failures are fail-closed regardless of `fail-on`: the Action exits
nonzero, sets `partial-scan` to `true` and `risk-level` to `partial`, and posts
a warning even when severity filters hide the informational coverage finding.
A critical threshold failure retains exit code 2; other partial results exit 1.

PR comments require `pull-requests: write` (shown above). GitHub restricts write
access for pull requests from forks, so the check verdict, job log, and outputs
remain authoritative when the platform refuses a comment.

### Action Outputs

| Output | Description |
|--------|-------------|
| `score` | Risk score from 0 to 100 |
| `risk-level` | `partial`, `clean`, `low`, `medium`, `high`, or `critical` |
| `findings-count` | Number of reportable findings after filters |
| `partial-scan` | `true` when coverage was incomplete |
| `report` | Requested report, or a size notice when it exceeds the safe output budget |
| `report-path` | Runner-local path to the complete report for later steps in the same job |
| `report-truncated` | `true` when `report` was replaced by the size notice |

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
supply-chain-guard feed osv       # export malicious-package IOCs as OSV records
```

A refreshed feed is merged into every scan for the next 24 hours automatically.

**OSV export:** `feed osv` emits the feed's malicious-package indicators (npm,
PyPI-adjacent, Go, RubyGems, Packagist, crates.io, NuGet) as [OSV-schema](https://ossf.github.io/osv-schema/)
records, so the feed is consumable by `osv-scanner` and other OSV-native tooling:

```bash
supply-chain-guard feed osv --out malicious.osv.json
```

**Indicator contract:** every feed value is a LITERAL indicator (a domain, IP,
URL, hash, or package name), never a regular expression. All ingestion paths
(`feed refresh`, the legacy update API, and the cached-feed load at scan time)
validate each entry against its type's shape and quarantine anything invalid -
a malformed or hostile feed entry can neither crash a scan nor flood it with
garbage matches, and a rejected refresh never overwrites the previous cache.

### Where the feed comes from

Curated entries are hand-added from vendor write-ups. Malicious-package entries
are additionally imported from two public upstream databases, with no account
and no API key:

- **[GitHub Advisory Database](https://github.com/advisories?query=type%3Amalware)** - malware
  advisories (CWE-506), the primary source. Licensed
  [CC BY 4.0](https://github.com/github/advisory-database); every imported entry
  carries its `GHSA-...` id in its `source` field.
- **[OSV.dev](https://osv.dev/)** - corroboration only, never discovery. A package
  that OSV also lists as malicious (a `MAL-` record from
  [ossf/malicious-packages](https://github.com/ossf/malicious-packages),
  Apache-2.0) is imported at confidence 1.0 instead of 0.9.

```bash
npm run feed:import -- --dry-run   # what the next refresh would add
npm run feed:import                # import, then regenerate feed.json
```

Every imported entry is auditable: the `source` field names the public advisory
it came from. A failed import writes nothing at all - the previous feed stays in
effect and the process exits non-zero. The full mapping (ecosystem prefixes,
version-range rules, which upstream fields deliberately stay unset) is in
[docs/threat-feed-sources.md](docs/threat-feed-sources.md).

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
  -> Pattern matching (350+ rules across 12 categories)
  -> Entropy analysis (Shannon entropy for encoded payloads)
  -> IOC blocklist check (known C2 domains, IPs, hashes)
  -> Internal-disclosure family (private addresses, internal hostnames,
     non-public forge URLs, developer paths, configured deny-list)
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

## Show that you scan

If supply-chain-guard runs in your CI, add the badge to your README:

[![scanned by supply-chain-guard](https://img.shields.io/badge/scanned%20by-supply--chain--guard-2ea44f?logo=npm&logoColor=white)](https://github.com/homeofe/supply-chain-guard)

```markdown
[![scanned by supply-chain-guard](https://img.shields.io/badge/scanned%20by-supply--chain--guard-2ea44f?logo=npm&logoColor=white)](https://github.com/homeofe/supply-chain-guard)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. The most impactful contribution is adding new detection patterns for emerging threats.

## Changelog

Full release history lives in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache-2.0](LICENSE) - Copyright 2026 Elvatis - Emre Kohler
