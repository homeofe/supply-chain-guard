# supply-chain-guard: Agent Journal

> **Append-only.** Never delete or edit past entries.
> Every agent session adds a new entry at the top.
> This file is the immutable history of decisions and work done.

---

## [2026-03-26] Akido: AAHP handoff docs + post-v3.0.0 cleanup

**Agent:** Akido (OpenClaw / claude-sonnet-4-6)
**Phase:** maintenance
**Branch:** main
**Tasks:** handoff setup, branch cleanup, dependabot merge

### What was done

- Verified v3.0.0 release state: all 5 feature branches already squash-merged to main (PRs #13-17), GitHub Release v3.0.0 exists, npm supply-chain-guard@3.0.0 published
- Updated `.ai/handoff/STATUS.md` and `MANIFEST.json` from v2.0.0 to v3.0.0
- Deleted 5 stale feature branches: feat/issue-8-pypi-scanner, feat/issue-9-github-actions-scanner, feat/issue-10-sarif-output, feat/issue-11-solana-watchlist, fix/issue-12-docs
- Dependabot PR #18 (picomatch 4.0.3 -> 4.0.4) was already merged
- Created complete AAHP handoff docs: CONVENTIONS.md, DASHBOARD.md, NEXT_ACTIONS.md, TRUST.md, WORKFLOW.md, LOG.md (this file)
- Identified 3 test coverage gaps: solana-monitor.ts (no tests), reporter.ts (no tests), cli.ts (no tests)
- Identified 4 feature opportunities: SBOM export, --fail-on flag, Cargo/Go scanner, Solana rate-limit handling
- Confirmed ClawHub is not applicable (CLI tool, not an OpenClaw skill)

### Decisions made

- ClawHub: confirmed not a publishing target -- supply-chain-guard is a CLI + GitHub Action, not an OpenClaw plugin
- npm scope: package published as `supply-chain-guard` (unscoped), not `@elvatis_com/supply-chain-guard`
- Task IDs: started from T-001 (no prior AAHP task history for this project)
- Prioritized test coverage (T-001, T-002, T-003) before new features (T-004+) -- current coverage gaps are on critical paths (Solana monitor, SARIF reporter, CLI)

---

## [2026-03-26] Claude Code agents (via Akido): v3.0.0 feature implementation

**Agent:** Claude Code (multiple sessions via Akido orchestration)
**Phase:** implementation
**Branch:** feat/issue-8 through feat/issue-12, then squash-merged
**Tasks:** #8 PyPI install hooks, #9 GitHub Actions scanner, #10 SARIF output, #11 Solana watchlist, #12 docs

### What was done

- Extended PyPI scanner with `setup.py` install hook detection (subprocess, base64 exec, cmdclass downloads)
- Added GitHub Actions workflow scanner (CI/CD pipeline attack patterns: curl|bash, secrets exfiltration, unpinned actions, encoded payloads)
- Implemented SARIF 2.1.0 output format in reporter.ts for GitHub Code Scanning integration
- Added Solana C2 wallet watchlist with persistent monitoring and webhook alerts
- Added CI workflow (.github/workflows/ci.yml) with npm auto-publish on v* tags
- Bumped version to 3.0.0, updated README changelog
- Total: 185 tests, all passing

---

## [2026-03-19] Initial releases: v1.0.0 and v2.0.0

**Agent:** unknown
**Phase:** initial implementation

### What was done

- v1.0.0: Initial npm scanner (install scripts, obfuscation, typosquatting, campaign signatures)
- v2.0.0: Multi-platform scanner (PyPI, VS Code extensions, dependency confusion, lockfile integrity, binary detection, network beacons, crypto miners)
- 142 tests on initial release, 185 tests by end of v2.0.0
- Published to npm as `supply-chain-guard` (unscoped)
- GitHub Action added with branding (shield/red)
- AAHP handoff directory created (MANIFEST.json, STATUS.md, ARCHITECTURE.md)
