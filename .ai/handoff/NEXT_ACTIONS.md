# supply-chain-guard: Next Actions for Incoming Agent

> Priority order. Work top-down.
> Each item should be self-contained so the agent can start without asking questions.
> Blocked tasks go to the bottom. Completed tasks move to "Recently Completed".

---

## Status Summary

| Status | Count |
|--------|-------|
| Ready (community-seeded issues) | 8 |
| Blocked | 0 |
| Roadmap bets remaining | 2 |

Current version: **v5.4.0**. The 2026-07 ideation roadmap quick wins are complete
(README adoption package, contributor funnel, lockfile + ecosystem expansion,
fail-closed policy, live feed) and strategic Bet 1 (agentic security suite) shipped.

---

## Ready - Community-Seeded Issues (good first issues, let contributors take them)

| # | Issue | Size |
|---|-------|------|
| [#40](https://github.com/homeofe/supply-chain-guard/issues/40) | Open VSX registry support for the VS Code scanner | S |
| [#41](https://github.com/homeofe/supply-chain-guard/issues/41) | pre-commit framework hook | S |
| [#42](https://github.com/homeofe/supply-chain-guard/issues/42) | Shields.io endpoint badge output (--format badge) | S |
| [#43](https://github.com/homeofe/supply-chain-guard/issues/43) | Coverage reporting + threshold gate in CI | S |
| [#44](https://github.com/homeofe/supply-chain-guard/issues/44) | examples/: CircleCI recipe | S |
| [#45](https://github.com/homeofe/supply-chain-guard/issues/45) | examples/: Jenkins pipeline recipe | S |
| [#46](https://github.com/homeofe/supply-chain-guard/issues/46) | examples/: Azure Pipelines recipe | S |
| [#47](https://github.com/homeofe/supply-chain-guard/issues/47) | Official Docker image on GHCR (multi-arch) | M, help wanted |

Maintainer policy: leave these open for contributors for a while before self-assigning.

---

## Remaining Strategic Bets (2026-07 roadmap)

### Bet 2: Install-time guard [L]
The only install blocker whose entire blocklist is auditable in git history, offline,
no vendor account. Preconditions now MET: multi-lockfile support (v5.3.0) and the live
feed (v5.4.0) are shipped. Best started after the feed has produced at least one
documented "blocked campaign X the day it broke" story to anchor the launch.

### Bet 3: Docker image + GitLab native format beachhead [M+M]
GHCR image (issue #47) is the prerequisite; gl-dependency-scanning-report.json output
buys the GitLab security UI. Start on the first inbound GitLab demand signal.

### Post-launch follow-ups for the agentic suite (v5.4.0)
- Announce: blog writeup + MCP directory/registry listings (manual, maintainer).
- MCP rug-pull detection (baseline tool-description hashes in .scg-cache) - documented
  as future work in src/mcp-scanner.ts.
- OSV-format export of the feed (same pipeline as feed.json; slow diplomatic track
  toward ossf/malicious-packages).

---

## Recently Completed

| Item | Date |
|------|------|
| v5.4.0: agentic suite (mcp-scanner, skills-scanner, MCP server) + live feed | 2026-07-02 |
| v5.3.0: pnpm/yarn/bun lockfiles, RubyGems/Composer/NuGet scanners, fail-closed policy, devcontainer + examples | 2026-07-02 |
| Contributor funnel: new-pattern label, 8 seeded good-first-issues (#40-#47) | 2026-07-02 |
| v5.2.45: README adoption package (demo GIF, comparison table, changelog split) | 2026-07-02 |
| Release-notes extraction fixed (was broken since day one) | 2026-07-02 |
| T-001..T-007 (v3-v4 era backlog) | done, see MANIFEST.json |
