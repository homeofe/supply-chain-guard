# supply-chain-guard: Build Dashboard

> Single source of truth for build health, test coverage, and pipeline state.
> Updated by agents at the end of every completed task.

---

## Components

| Name | Path | Build | Tests | Status | Notes |
|------|------|-------|-------|--------|-------|
| CLI entry | `src/cli.ts` | ✅ | manual | ✅ | commander-based, all subcommands |
| Central scanner | `src/scanner.ts` | ✅ | ✅ 18 | ✅ | delegates to all sub-scanners |
| npm scanner | `src/npm-scanner.ts` | ✅ | ✅ 10 | ✅ | install scripts, obfuscation, typosquatting |
| PyPI scanner | `src/pypi-scanner.ts` | ✅ | ✅ 44 | ✅ | incl. install hook detection |
| VS Code scanner | `src/vscode-scanner.ts` | ✅ | ✅ 14 | ✅ | .vsix analysis |
| GitHub Actions scanner | `src/github-actions-scanner.ts` | ✅ | ✅ 20 | ✅ | CI/CD pipeline attacks |
| Dependency confusion | `src/dependency-confusion.ts` | ✅ | ✅ 12 | ✅ | namespace confusion detection |
| Lockfile checker | `src/lockfile-checker.ts` | ✅ | ✅ 14 | ✅ | integrity verification |
| Binary detection | `src/patterns.ts` + scanner | ✅ | ✅ 11 | ✅ | 30-entry whitelist |
| Beacon/miner detection | `src/patterns.ts` | ✅ | ✅ 21 | ✅ | network beacons, crypto miners |
| Campaign signatures | `src/patterns.ts` | ✅ | ✅ 21 | ✅ | 13 campaigns (XZ, SolarWinds...) |
| Solana C2 monitor | `src/solana-monitor.ts` | ✅ | ❌ none | ⚠️ | no unit tests yet |
| Reporter | `src/reporter.ts` | ✅ | ❌ none | ⚠️ | SARIF/JSON/MD output untested |
| GitHub Action | `action.yml` + `src/action.ts` | ✅ | manual | ✅ | branding: shield/red |
| CI workflow | `.github/workflows/ci.yml` | ✅ | n/a | ✅ | build+test on push/PR, npm publish on v* |

**Legend:** ✅ passing / complete · ❌ failing/missing · ⚠️ needs attention · manual = tested manually only

---

## Test Coverage

| Suite | Tests | Status | Last Run |
|-------|-------|--------|----------|
| scanner.test.ts | 18 | ✅ All pass | 2026-03-26 |
| pypi-scanner.test.ts | 44 | ✅ All pass | 2026-03-26 |
| beacon-miner.test.ts | 21 | ✅ All pass | 2026-03-26 |
| campaigns.test.ts | 21 | ✅ All pass | 2026-03-26 |
| github-actions-scanner.test.ts | 20 | ✅ All pass | 2026-03-26 |
| vscode-scanner.test.ts | 14 | ✅ All pass | 2026-03-26 |
| lockfile-checker.test.ts | 14 | ✅ All pass | 2026-03-26 |
| dependency-confusion.test.ts | 12 | ✅ All pass | 2026-03-26 |
| binary-detection.test.ts | 11 | ✅ All pass | 2026-03-26 |
| npm-scanner.test.ts | 10 | ✅ All pass | 2026-03-26 |
| solana-monitor.test.ts | 0 | ❌ Missing | - |
| reporter.test.ts | 0 | ❌ Missing | - |
| cli.test.ts | 0 | ❌ Missing | - |

**Total: 185 tests, 185 passing**

---

## Infrastructure

| Component | Status | Notes |
|-----------|--------|-------|
| GitHub repo | ✅ | homeofe/supply-chain-guard (Apache-2.0) |
| GitHub Actions CI | ✅ | build + test on push/PR |
| npm auto-publish | ✅ | triggers on `v*` tags via CI |
| npm package | ✅ | supply-chain-guard@3.0.0 (unscoped, public) |
| GitHub Marketplace | ✅ | supply-chain-guard GitHub Action |
| ClawHub | n/a | CLI tool, not an OpenClaw skill |

---

## Pipeline State

| Field | Value |
|-------|-------|
| Current version | 3.0.0 |
| Current phase | feature development |
| Last completed | v3.0.0 release (2026-03-26) |
| Blocking issues | None |

---

## Open Tasks

| ID | Task | Priority | Status |
|----|------|----------|--------|
| T-001 | Add solana-monitor unit tests | high | ready |
| T-002 | Add reporter unit tests (SARIF, JSON, markdown) | high | ready |
| T-003 | Add CLI integration tests | medium | ready |
| T-004 | SBOM export (CycloneDX/SPDX) | medium | ready |
| T-005 | --fail-on severity threshold flag for CI | medium | ready |
| T-006 | Cargo/Go module scanner | low | ready |
| T-007 | Rate-limit handling in Solana monitor | low | ready |

## Completed Tasks

| ID | Task | Completed |
|----|------|-----------|
| - | v1.0.0: Initial npm scanner | 2026-03-19 |
| - | v2.0.0: Multi-platform (PyPI, VS Code, dep confusion, lockfile, binary, beacon) | 2026-03-19 |
| - | v3.0.0: GitHub Actions scanner, SARIF output, Solana watchlist, PyPI install hooks | 2026-03-26 |
| - | CI workflow (auto-publish on tag) | 2026-03-26 |
| - | AAHP handoff docs completed | 2026-03-26 |

---

## Update Instructions (for agents)

After completing any task:

1. Update component status table and test counts
2. Move task from Open to Completed
3. Update Pipeline State (version, phase, last completed)
4. Add entry to LOG.md
5. Notify project owner on task completion
