# 🛡️ supply-chain-guard

Open-source supply-chain security scanner for npm, PyPI, and VS Code extensions. Detects [GlassWorm](https://www.reversinglabs.com/blog/glassworm-backdoor-campaign-npm-vscode) and similar malware campaigns.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-green)](https://nodejs.org)

## Background

For a deep dive into how GlassWorm infiltrates the software supply chain and the detection techniques behind this tool, read the blog post: [How GlassWorm Gets In and How We Locked It Out](https://blog.elvatis.com/how-glassworm-gets-in-and-how-we-locked-it-out/).

## What It Does

supply-chain-guard scans code repositories and npm packages for known indicators of compromise (IOCs) associated with supply-chain attacks. It catches threats that traditional security scanners miss because it specifically targets software supply-chain attack patterns.

**Detected threats include:**

- 🔴 **GlassWorm campaign markers** (the `lzcdrtfxyqiplpd` variable and associated IOCs)
- 🔴 **Obfuscated code execution** (`eval(atob(...))`, `eval(Buffer.from(...))`, `new Function(atob(...))`)
- 🟠 **Invisible Unicode characters** used to hide malicious code in plain sight
- 🟠 **Suspicious install scripts** (`postinstall`/`preinstall` that download and execute remote code)
- 🟠 **Data exfiltration patterns** (environment variables sent over the network)
- 🟡 **Solana blockchain C2** (mainnet-beta, Helius RPC references used as command-and-control channels)
- 🟡 **Git history manipulation** (committer dates far newer than author dates)
- 🔵 **Typosquatting package names** (known malicious npm package patterns)

## Installation

```bash
npm install -g supply-chain-guard
```

Or use directly with npx:

```bash
npx supply-chain-guard scan ./my-project
```

## Quickstart

**Scan a local directory:**

```bash
supply-chain-guard scan ./my-project
```

**Scan a GitHub repository:**

```bash
supply-chain-guard scan https://github.com/user/repo
```

**Scan an npm package (without installing it):**

```bash
supply-chain-guard npm suspicious-package-name
```

Example output:

```
  Risk Score: 68/100 (CRITICAL)
  Findings:  2 critical, 1 high, 1 medium

  🔴 [CRITICAL] GlassWorm campaign marker variable detected
     Rule: GLASSWORM_MARKER  |  File: src/index.js:42

  🔴 [CRITICAL] Base64-encoded eval detected
     Rule: EVAL_ATOB  |  File: src/loader.js:15
```

See the full [Example Output](#example-output) section below for a complete scan report.

## Usage

### Scan a Local Directory

```bash
supply-chain-guard scan ./my-project
```

### Scan a GitHub Repository

```bash
supply-chain-guard scan https://github.com/user/repo
```

### Scan an npm Package

Downloads and analyzes the published tarball without installing it:

```bash
supply-chain-guard npm express
supply-chain-guard npm suspicious-package-name
```

### Monitor a Solana C2 Wallet

Watch a Solana wallet address for memo transactions (used by GlassWorm for C2 communication):

```bash
# Continuous monitoring
supply-chain-guard monitor <wallet-address>

# One-shot check
supply-chain-guard monitor <wallet-address> --once

# Custom polling interval
supply-chain-guard monitor <wallet-address> --interval 60
```

### Output Formats

```bash
# Human-readable text (default)
supply-chain-guard scan ./project

# JSON (for CI/CD pipelines)
supply-chain-guard scan ./project --format json

# Markdown (for PR comments)
supply-chain-guard scan ./project --format markdown
```

### Filtering

```bash
# Only show critical and high findings
supply-chain-guard scan ./project --min-severity high

# Exclude specific rules
supply-chain-guard scan ./project --exclude SOLANA_MAINNET,HEX_ARRAY
```

## Example Output

```
  supply-chain-guard scan report
  ──────────────────────────────────────────────────────
  Target:    ./suspicious-package
  Type:      directory
  Time:      2026-03-19T02:30:00.000Z
  Duration:  142ms

  Risk Score: 68/100 (CRITICAL)

  Summary
  ──────────────────────────────────────────────────────
  Files:     23/47 scanned
  Findings:  2 critical, 1 high, 1 medium

  Findings
  ──────────────────────────────────────────────────────

  🔴 [CRITICAL] GlassWorm campaign marker variable detected
     Rule: GLASSWORM_MARKER
     File: src/index.js:42
     Match: lzcdrtfxyqiplpd
     Fix: Quarantine this code immediately.

  🔴 [CRITICAL] Base64-encoded eval detected (common malware obfuscation)
     Rule: EVAL_ATOB
     File: src/loader.js:15
     Match: eval(atob("aHR0cHM6Ly..."))
     Fix: Do not execute this code. Decode the base64 to inspect the payload.

  🟠 [HIGH] Suspicious invisible Unicode characters detected
     Rule: INVISIBLE_UNICODE
     File: src/utils.js:3
     Fix: Inspect this file in a hex editor.

  🟡 [MEDIUM] Solana mainnet RPC reference detected
     Rule: SOLANA_MAINNET
     File: src/c2.js:8
     Fix: If this project has no blockchain functionality, investigate.

  Recommendations
  ──────────────────────────────────────────────────────
  • CRITICAL: GlassWorm malware marker detected. Quarantine immediately.
  • CRITICAL: Encoded code execution detected. Do not run this code.
  • Review files with invisible Unicode characters.
  • Solana blockchain references may indicate C2 communication.
```

## GitHub Action

Add supply-chain-guard to your CI/CD pipeline:

```yaml
name: Supply Chain Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: homeofe/supply-chain-guard@v1
        with:
          fail-on: critical    # Fail CI on critical findings
          comment-on-pr: true  # Post findings as PR comment
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `format` | Output format (text/json/markdown) | `markdown` |
| `min-severity` | Minimum severity to report | `low` |
| `exclude-rules` | Comma-separated rule IDs to exclude | |
| `fail-on` | Fail check at this severity or above | `critical` |
| `comment-on-pr` | Post findings as PR comment | `true` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `score` | Risk score (0-100) |
| `risk-level` | clean/low/medium/high/critical |
| `findings-count` | Total number of findings |
| `report` | Full scan report |

## Detection Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `GLASSWORM_MARKER` | Critical | GlassWorm campaign marker variable |
| `EVAL_ATOB` | Critical | Base64-encoded eval |
| `EVAL_BUFFER` | Critical | Buffer-encoded eval |
| `FUNCTION_ATOB` | Critical | Function constructor with base64 |
| `EVAL_HEX` | Critical | Hex-encoded eval |
| `SCRIPT_CURL_EXEC` | Critical | Install script with curl pipe to shell |
| `SCRIPT_WGET_EXEC` | Critical | Install script with wget pipe to shell |
| `INVISIBLE_UNICODE` | High | Invisible Unicode characters (obfuscation) |
| `SUSPICIOUS_I_JS` | High | Suspicious i.js file |
| `SUSPICIOUS_INIT_JSON` | High | GlassWorm persistence file |
| `EXEC_ENCODED` | High | Encoded exec call |
| `SCRIPT_NODE_INLINE` | High | Inline Node.js in install script |
| `SCRIPT_ENCODED` | High | Encoding in install script |
| `ENV_EXFILTRATION` | High | Environment variable exfiltration |
| `DNS_EXFILTRATION` | High | DNS-based data exfiltration |
| `MALICIOUS_PACKAGE_NAME` | High | Known malicious package name pattern |
| `MALICIOUS_DEPENDENCY` | High | Dependency matches malicious pattern |
| `SOLANA_MAINNET` | Medium | Solana mainnet RPC reference |
| `HELIUS_RPC` | Medium | Helius RPC reference |
| `HEX_ARRAY` | Medium | Large hex array (obfuscated payload) |
| `CHARCODE_OBFUSCATION` | Medium | Character code string construction |
| `SCRIPT_PREINSTALL_EXEC` | Medium | Exec in preinstall script |
| `GIT_DATE_ANOMALY` | Medium | Git commit date manipulation |
| `COMPLEX_INSTALL_SCRIPT` | Low | Complex install script |

## Adding Custom Patterns

Edit `src/patterns.ts` to add new detection rules. Each pattern needs:

```typescript
{
  name: "my-custom-pattern",
  pattern: "regex-pattern-here",
  description: "What this detects",
  severity: "high",
  rule: "MY_CUSTOM_RULE",
}
```

## How It Works

1. **File Scanner**: Recursively scans directories, skipping `node_modules`, `.git`, and build artifacts. Checks file content against known malicious patterns using regex.

2. **npm Scanner**: Downloads package tarballs from the npm registry without installing them. Analyzes package.json scripts, dependencies, and published file contents.

3. **Solana Monitor**: Polls the Solana blockchain for transactions on known C2 wallet addresses. Decodes memo instructions that GlassWorm uses to encode payload URLs.

4. **Scoring**: Each finding contributes to a risk score based on severity. The score determines the overall risk level (clean/low/medium/high/critical).

## Background: The GlassWorm Campaign

In early 2026, researchers discovered the GlassWorm campaign: a coordinated supply-chain attack targeting npm packages and VS Code extensions. The campaign used several novel techniques:

- **Solana blockchain as C2**: Payload URLs encoded as transaction memos on the Solana blockchain, making the C2 channel uncensorable
- **Invisible Unicode**: Zero-width characters used to hide malicious code in legitimate-looking files
- **Git history manipulation**: Fake commit dates to make packages appear established
- **Typosquatting**: Hundreds of packages with names similar to popular libraries

supply-chain-guard was built to detect these specific attack patterns and make the detection rules available to everyone.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. The most impactful contribution is adding new detection patterns for emerging threats.

## License

[Apache-2.0](LICENSE) - Copyright 2026 Elvatis - Emre Kohler
