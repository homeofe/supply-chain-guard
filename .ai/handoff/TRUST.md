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

## Core Build + Release

| Property | Status | Last Verified | Agent | Notes |
|----------|--------|---------------|-------|-------|
| `npm run build` succeeds | verified | 2026-07-01 | claude-opus-4-8 | `tsc` clean under TypeScript 6 |
| `npm test` passes | verified | 2026-07-01 | claude-opus-4-8 | 823/836; the 13 failures are vscode-scanner tests needing a local `zip` binary (env-only, green on Linux CI) |
| `npm audit` clean | verified | 2026-07-01 | claude-opus-4-8 | 0 vulnerabilities |
| prebuild gates enforce version/changelog | verified | 2026-07-01 | claude-opus-4-8 | `check:changelog` + `check:version-sync` block on drift |
| npm supply-chain-guard@5.2.44 published | verified | 2026-07-01 | claude-opus-4-8 | `npm view` = 5.2.44; ships commander ^14.0.3 |
| npm OIDC trusted publish works | verified | 2026-07-01 | claude-opus-4-8 | v5.2.44 tag run published with no NPM_TOKEN |
| GitHub Release v5.2.44 exists | verified | 2026-07-01 | claude-opus-4-8 | `gh release view v5.2.44` |
| `v5` floating branch tracks latest release | verified | 2026-07-01 | claude-opus-4-8 | refs/heads/v5 == v5.2.44 commit (37cf622) |
| AAHP handoff gate enforced in CI | verified | 2026-07-01 | claude-opus-4-8 | AAHP Verify green; blocks code commits lacking STATUS+MANIFEST |

---

## Dependencies

| Property | Status | Last Verified | Agent | Notes |
|----------|--------|---------------|-------|-------|
| All deps at latest compatible | verified | 2026-07-01 | claude-opus-4-8 | only commander held at 14.x (15 is ESM-only + Node >=22.12) |
| GHA SHA pins are genuine | verified | 2026-07-01 | claude-opus-4-8 | checkout v7.0.0 (9c091bb) + setup-node v6.4.0 (48b55a0) match upstream tags via `git ls-remote` |
| Dependabot configured | verified | 2026-07-01 | claude-opus-4-8 | weekly npm + github-actions; commander >=15 ignored |

---

## Detection (regression-tested)

| Property | Status | Last Verified | Agent | Notes |
|----------|--------|---------------|-------|-------|
| Full detection suite passes | verified | 2026-07-01 | claude-opus-4-8 | ~810 non-env tests across 49 modules green |
| npm / PyPI / Cargo / Go / VS Code scanners | verified | 2026-07-01 | claude-opus-4-8 | dedicated test files per scanner |
| GitHub Actions + workflow modeling | verified | 2026-07-01 | claude-opus-4-8 | injection, unpinned actions, secret paths |
| SBOM (CycloneDX) + SLSA verifier | verified | 2026-07-01 | claude-opus-4-8 | sbom-generator + slsa-verifier test suites |
| Solana C2 monitor + rate-limit handling | verified | 2026-07-01 | claude-opus-4-8 | backoff/Retry-After/429/-32005 tests pass |
| Prompt-injection + IOC/threat-intel feeds | verified | 2026-07-01 | claude-opus-4-8 | dedicated suites; benign-doc scoping enforced |

---

## Notes

- History before 2026-07-01: the register had been frozen at the v3.0.0 (2026-03-26)
  verification snapshot despite ~40 releases since. Refreshed against the live repo on
  2026-07-01. See LOG.md for the gap explanation.
