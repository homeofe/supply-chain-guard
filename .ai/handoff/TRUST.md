# supply-chain-guard: Trust Register

> Tracks verification status of critical system properties.
> In multi-agent pipelines, hallucinations and drift are real risks.
> Every claim here has a confidence level tied to how it was verified.

---

## Confidence Levels

| Level | Meaning |
|-------|---------|
| **verified** | An agent executed code, ran tests, or observed output to confirm this |
| **assumed** | Derived from docs, config files, or chat, not directly tested |
| **untested** | Status unknown; needs verification |

---

## Core Scanner

| Property | Status | Last Verified | Agent | Notes |
|----------|--------|---------------|-------|-------|
| `npm test` passes (185 tests) | verified | 2026-03-26 | Akido | Observed output directly |
| `npm run build` succeeds | verified | 2026-03-26 | Akido | No TypeScript errors |
| All 10 test files pass | verified | 2026-03-26 | Akido | Vitest output confirmed |
| npm package supply-chain-guard@3.0.0 published | verified | 2026-03-26 | Akido | `npm view supply-chain-guard version` = 3.0.0 |
| GitHub Release v3.0.0 exists | verified | 2026-03-26 | Akido | `gh release list` output |
| CI workflow triggers on push | verified | 2026-03-26 | Akido | Run 23571175681 completed success |
| npm auto-publish on v* tag works | assumed | 2026-03-26 | Akido | Workflow exists but not triggered since CI was added |

---

## Detection Rules

| Property | Status | Last Verified | Agent | Notes |
|----------|--------|---------------|-------|-------|
| npm install script detection | verified | 2026-03-26 | Akido | 10 tests pass |
| PyPI install hook detection (setup.py) | verified | 2026-03-26 | Akido | 44 tests pass |
| GitHub Actions CI/CD attack patterns | verified | 2026-03-26 | Akido | 20 tests pass |
| SARIF 2.1.0 output format | assumed | 2026-03-26 | Akido | Code reviewed, no automated test yet |
| Solana C2 memo detection | assumed | 2026-03-26 | Akido | Code reviewed, no unit tests yet |
| Campaign signatures (13 total) | verified | 2026-03-26 | Akido | 21 tests pass |
| Dependency confusion detection | verified | 2026-03-26 | Akido | 12 tests pass |
| Binary/native addon detection | verified | 2026-03-26 | Akido | 11 tests pass |
| Lockfile integrity checks | verified | 2026-03-26 | Akido | 14 tests pass |

---

## Infrastructure

| Property | Status | Last Verified | Agent | Notes |
|----------|--------|---------------|-------|-------|
| GitHub Actions CI running | verified | 2026-03-26 | Akido | Run history confirmed |
| All stale feature branches deleted | verified | 2026-03-26 | Akido | `git branch -a` shows only main + dependabot |
| No open PRs | verified | 2026-03-26 | Akido | `gh pr list` returns empty |
| ClawHub: not applicable | verified | 2026-03-26 | Akido | CLI tool, no SKILL.md, confirmed not on ClawHub |
