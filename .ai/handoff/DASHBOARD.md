# supply-chain-guard: Build Dashboard

> Single source of truth for build health, test coverage, and pipeline state.
> Exact per-file test counts live in `npm test` output; this file summarizes.
> Last refreshed: 2026-07-01 (claude-opus-4-8).

---

## Pipeline State

| Field | Value |
|-------|-------|
| Current version | 5.2.44 |
| npm | supply-chain-guard@5.2.44 (unscoped, public, OIDC trusted publish) |
| Build | green (`tsc`, TypeScript 6) |
| Tests | 823 passing / 836 (13 vscode-scanner tests need a local `zip` binary; green on Linux CI) |
| Vulnerabilities | 0 (`npm audit`) |
| Current phase | maintenance |
| Blocking issues | none |
| Open GitHub issues | none |

---

## Toolchain

| Item | Version | Notes |
|------|---------|-------|
| Runtime dep | commander ^14.0.3 | CommonJS line; 15+ is ESM-only + Node >=22.12, ignored by dependabot |
| TypeScript | ^6.0.3 | tsconfig needs `"types": ["node"]` (TS6 dropped auto @types include) |
| vitest | ^4.1.9 | transitive vite 8.1.2 |
| @types/node | ^26.0.1 | dev only |
| Node engines | >=20 | CI runs Node 20 |

---

## Components

49 source modules under `src/` (~53 Vitest test files). Grouped:

| Group | Modules | Status |
|-------|---------|--------|
| Core | scanner, cli, reporter, patterns, types, index | ✅ |
| Package scanners | npm, pypi, cargo, go, vscode | ✅ |
| CI/CD + repo | github-actions-scanner, github-trust-scanner, workflow-modeler, release-scanner, org-scanner, dockerfile-scanner, config-scanner, git-scanner | ✅ |
| Dependency analysis | dependency-confusion, dependency-risk-analyzer, dependency-governance, lockfile-checker, publishing-anomaly-detector | ✅ |
| Detection + intel | ioc-blocklist, threat-intel, entropy, install-hook-scanner, active-validation | ✅ |
| Scoring + risk | risk-engine, risk-forecast, trust-breakdown, trust-signals, correlation-engine, attack-graph, posture-engine, metrics | ✅ |
| Supply-chain provenance | sbom-generator, slsa-verifier, soc-exporter | ✅ |
| Ops + response | remediation-engine, playbooks, triage-engine, sla-engine, continuous-monitor, secret-simulator, diff-scanner, policy-engine | ✅ |
| Solana C2 | solana-monitor (backoff + Retry-After + 429/-32005 handling) | ✅ |

**Legend:** ✅ passing / complete · ❌ failing/missing · ⚠️ needs attention

---

## Infrastructure

| Component | Status | Notes |
|-----------|--------|-------|
| GitHub repo | ✅ | homeofe/supply-chain-guard (Apache-2.0) |
| CI (`ci.yml`) | ✅ | build+test on push/PR; on semver tags: OIDC npm publish, GitHub Release, `v5` branch fast-forward |
| AAHP Verify (`aahp-verify.yml`) | ✅ | handoff gate; dependabot exempt |
| Prebuild gates | ✅ | `check:changelog` + `check:version-sync` (block release drift) |
| npm publish | ✅ | OIDC trusted publishing (no NPM_TOKEN); needs npm >=11.5.1 in CI |
| GitHub Action | ✅ | composite; `uses: homeofe/supply-chain-guard@v5` (floating branch), runs `npm install -g supply-chain-guard` |
| GitHub Marketplace | ✅ | listing updated manually (not automatable) |
| Dependabot | ✅ | weekly npm + github-actions; commander >=15 ignored |

---

## Open Tasks

None. All tracked AAHP tasks (T-001..T-007) are done; see NEXT_ACTIONS.md.

---

## Update Instructions (for agents)

The authoritative release process is in the repo-root `CLAUDE.md`. After any change:

1. Update `STATUS.md` (a top-of-file note) and regenerate `MANIFEST.json`
   (`bash scripts/aahp-manifest.sh . --agent <id> --phase <phase>`) - the AAHP
   gate (`scripts/verify-handoff.sh --level ci`) blocks the commit otherwise.
2. Refresh this DASHBOARD if version/tests/components changed.
3. Append an entry to `LOG.md`; re-prioritize `NEXT_ACTIONS.md`.
4. Mark newly verified facts in `TRUST.md`.
