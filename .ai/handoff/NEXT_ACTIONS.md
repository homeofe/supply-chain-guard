# supply-chain-guard: Next Actions for Incoming Agent

> Priority order. Work top-down.
> Each item should be self-contained so the agent can start without asking questions.
> Blocked tasks go to the bottom. Completed tasks move to "Recently Completed".

---

## Status Summary

| Status | Count |
|--------|-------|
| Ready (small next-patch items) | 3 |
| Blocked | 0 |
| Roadmap bets remaining | 0 |

Current version: **v5.6.0**. The entire 2026-07 ideation roadmap is shipped:
quick wins, both strategic bets (agentic suite / live feed in v5.4.0; install-time
guard / GitLab format in v5.6.0), and the full seeded-issue backlog (#40-#47).

---

## Ready - Small next-patch items (from the v5.6.0 gate should-fixes)

| Item | Where | Note |
|------|-------|------|
| GitLab `location.dependency.package.name` uses the scan target path (can leak an absolute runner path); use a stable per-finding coordinate | src/reporter.ts formatGitlab | low, cosmetic |
| Jenkinsfile pins `@latest` (non-reproducible); add a one-line "pin a version for reproducible CI" comment | examples/Jenkinsfile | doc only |
| Install Guard: version ranges/tags (^1.2.3, latest) are not resolved offline, so pinned-version IOCs only fire on exact pins; document this limitation in the README Install Guard section | README.md | doc / known-limitation |
| skills-scanner's `readSmallFile()` still returns null silently for oversized agent-rules files (bonus site outside issue #54's scope of core/VSIX/npm/PyPI); consider a SKILL_FILE_TOO_LARGE_SKIPPED for parity | src/skills-scanner.ts readSmallFile | small, parity follow-up |

---

## Ideas / not-yet-scheduled (no owner)

- Install Guard v2: resolve version ranges against the offline metadata cache so
  pinned IOCs fire on ranges too; add a `guard` shell shim/alias so it can wrap npm
  transparently.
- MCP rug-pull detection (baseline tool-description hashes in .scg-cache) - noted as
  future work in src/mcp-scanner.ts.
- OSV-format export of the bundled feed (same pipeline as feed.json); slow diplomatic
  track toward ossf/malicious-packages.
- Post-launch marketing: submit the MCP server to MCP directories/registries (manual).

---

## Recently Completed

| Item | Date |
|------|------|
| Issue #54: FILE_TOO_LARGE_SKIPPED across all 4 scan families + threat-intel literal-indicator contract with type-aware quarantine (v5.12.0) | 2026-07-11 |
| Self-scan INVISIBLE_UNICODE in the gitlost plan doc: literal invisibles replaced with \u escape notation (fencing would NOT have worked - raw byte scan) | 2026-07-09 |
| v5.6.0: install guard (Bet 2) + GitLab format (Bet 3) + registry hardening; gate caught a Windows RCE + 4 more pre-tag | 2026-07-03 |
| v5.5.0: all 8 seeded issues (#40-#47) + adversarial release gate (6 must-fixes) | 2026-07-02 |
| v5.4.x: agentic suite + live feed + MCP-install/PowerShell/leak fixes | 2026-07-02 |
| v5.3.0: pnpm/yarn/bun lockfiles + RubyGems/Composer/NuGet + fail-closed policy | 2026-07-02 |
| v5.2.45: README adoption package (demo GIF, comparison table, changelog split) | 2026-07-02 |
| All 5 v5.5.0 gate should-fixes (OpenVSX allowlist, /tmp migration, Docker digest, Jenkins npx, --no-history) | 2026-07-03 |
| T-001..T-007 (v3-v4 era backlog) | done, see MANIFEST.json |
