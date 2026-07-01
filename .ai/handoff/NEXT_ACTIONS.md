# supply-chain-guard: Next Actions for Incoming Agent

> Priority order. Work top-down.
> Each item should be self-contained so the agent can start without asking questions.
> Blocked tasks go to the bottom. Completed tasks move to "Recently Completed".

---

## Status Summary

| Status | Count |
|--------|-------|
| Ready | 0 |
| Blocked | 0 |
| Done | 7 |

---

## Ready - Work These Next

_Nothing queued._ All tracked AAHP tasks (T-001 through T-007) are complete and there are
no open GitHub issues. The package is current at **v5.2.44**, with all dependencies at
their latest compatible versions and 0 known vulnerabilities.

New work normally enters through:

- **Threat-intel routine** - the recurring session that adds IOCs and cuts patch releases
  (see the most recent entries under `## Changelog` in README.md).
- **New GitHub issues / AAHP tasks** - added to `MANIFEST.json` `tasks` and surfaced here.
- **Dependabot PRs** - weekly npm + github-actions updates. Note: commander is pinned to
  the 14.x CommonJS line and 15+ is ignored (ESM-only + Node >=22.12); see
  `.github/dependabot.yml`.

When you pick up a new task, add it above with a self-contained goal, context, steps,
files, and definition-of-done (see this file's git history for the format).

---

## Recently Completed

| ID | Task | Completed |
|----|------|-----------|
| T-007 | Rate-limit handling in Solana monitor (backoff + Retry-After + 429/-32005) | 2026-04 (v4) |
| T-006 | Cargo/Go module scanner (cargo-scanner.ts + go-scanner.ts, wired in scanner.ts) | 2026-04 (v4) |
| T-005 | --fail-on severity threshold flag | 2026-03-26 |
| T-004 | SBOM export (CycloneDX JSON) | 2026-03-26 |
| T-003 | Add CLI integration tests (22 tests) | 2026-03-26 |
| T-002 | Add reporter unit tests (39 tests: JSON, SARIF, markdown, text, SBOM) | 2026-03-26 |
| T-001 | Add solana-monitor unit tests (23 tests) | 2026-03-26 |

### Milestones

| Item | Date |
|------|------|
| v5.2.44 released (dependency maintenance: commander 14 + toolchain refresh) | 2026-07-01 |
| Stale auto-created issues #30/#31 closed; T-006/T-007 marked done | 2026-07-01 |
| Dependabot batch (8 PRs) consolidated + full dependency update to latest | 2026-07-01 |
| v3.1.0 released (269 tests) | 2026-03-26 |
| AAHP handoff docs created | 2026-03-26 |
