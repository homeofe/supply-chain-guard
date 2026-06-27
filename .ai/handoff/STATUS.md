# supply-chain-guard - Project Status

> Note (2026-06-27, claude-opus-4-8): Full AAHP gate onboarded. Added the
> canonical toolchain (scripts/_aahp-lib.sh, scripts/aahp-manifest.sh,
> scripts/lint-handoff.sh, scripts/verify-handoff.sh,
> scripts/validate-pii-allowlist.py), the .github/workflows/aahp-verify.yml
> required-check workflow, the missing canonical handoff files
> (pii-allowlist.json, LOG-ARCHIVE.md, LOG-ARCHIVE.index.json), and an AAHP
> Verify badge in README.md. The handoff state was previously dormant since the
> 2026-03-26 v3.1.0 session; this refresh brings the manifest commit-pointer and
> file index current. No application code changed in this onboarding.

## Current Version: 3.1.0

### Published
- npm: supply-chain-guard@3.1.0 (unscoped, public)
- GitHub: homeofe/supply-chain-guard (Apache-2.0)
- GitHub Marketplace: supply-chain-guard (GitHub Action)
- ClawHub: not published (CLI tool, not an OpenClaw skill)

### Features (v3.0.0)
- 65+ detection rules across 8 categories
- npm package scanning (install scripts, obfuscation, typosquatting)
- PyPI package scanning with install hook detection (subprocess, base64 exec, cmdclass downloads)
- VS Code extension scanning (.vsix analysis)
- GitHub Actions workflow scanner (CI/CD pipeline attacks, unpinned actions, secrets exfiltration, encoded payloads)
- SARIF 2.1.0 output format for GitHub Code Scanning (`--format sarif`)
- Solana C2 wallet watchlist with persistent monitoring and webhook alerts (`watchlist` commands)
- Dependency confusion detection
- Lockfile integrity verification
- Binary/native addon detection (30-entry whitelist)
- Network beacon + crypto miner + protestware detection
- 13 campaign signatures (XZ Utils, Codecov, SolarWinds, ua-parser-js, coa/rc)
- GitHub Action with branding (shield/red)
- CI workflow (build + test on push/PR, auto-publish to npm on v* tags)
- Blog post reference and quickstart guide in docs/

### Architecture
- CLI entry: src/cli.ts (commander-based)
- Core scanner: src/scanner.ts
- Detection modules: src/detectors/*.ts
- GitHub Action: action.yml + src/action.ts

### Open Issues
- dependabot: picomatch 4.0.3 -> 4.0.4 (low priority)

### Known Limitations
- PyPI scanning requires local package download (no remote API)
- VS Code extension scanning needs .vsix file on disk
- No real-time monitoring (scan-based only)
