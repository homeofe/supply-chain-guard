# supply-chain-guard: Next Actions for Incoming Agent

> Priority order. Work top-down.
> Each item should be self-contained so the agent can start without asking questions.
> Blocked tasks go to the bottom. Completed tasks move to "Recently Completed".

---

## Status Summary

| Status | Count |
|--------|-------|
| Ready (gate should-fixes) | 5 |
| Blocked | 0 |
| Roadmap bets remaining | 2 |

Current version: **v5.5.0**. The 2026-07 ideation roadmap quick wins are complete
(README adoption package, contributor funnel, lockfile + ecosystem expansion,
fail-closed policy, live feed) and strategic Bet 1 (agentic security suite) shipped.

---

## Ready - Verification-Gate Should-Fixes (small, next patch)

From the v5.5.0 adversarial release gate (all evidence in the gate report):

| Item | Where |
|------|-------|
| Jenkinsfile: replace global npm install with npx --yes pattern (PATH/EACCES in docker agents) | examples/Jenkinsfile |
| Pin Docker base image by digest (node:20-alpine floats; inconsistent with SHA-pinned Actions) | Dockerfile |
| OpenVSX: allowlist download/redirect hosts (open-vsx.org + CDN) | src/vscode-scanner.ts |
| Finish /tmp -> os.tmpdir() migration | src/npm-scanner.ts, src/pypi-scanner.ts |
| Consider gating .scg-history writes behind a flag for hook/CI use | src/scanner.ts, continuous-monitor.ts |

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
| v5.5.0: all 8 seeded issues (#40-#47) + adversarial release gate (6 must-fixes caught pre-tag) | 2026-07-02 |
| v5.4.0: agentic suite (mcp-scanner, skills-scanner, MCP server) + live feed | 2026-07-02 |
| v5.3.0: pnpm/yarn/bun lockfiles, RubyGems/Composer/NuGet scanners, fail-closed policy, devcontainer + examples | 2026-07-02 |
| Contributor funnel: new-pattern label, 8 seeded good-first-issues (#40-#47) | 2026-07-02 |
| v5.2.45: README adoption package (demo GIF, comparison table, changelog split) | 2026-07-02 |
| Release-notes extraction fixed (was broken since day one) | 2026-07-02 |
| T-001..T-007 (v3-v4 era backlog) | done, see MANIFEST.json |
