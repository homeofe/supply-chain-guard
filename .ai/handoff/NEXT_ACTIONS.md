# supply-chain-guard: Next Actions for Incoming Agent

> Priority order. Work top-down.
> Each item should be self-contained so the agent can start without asking questions.
> Blocked tasks go to the bottom. Completed tasks move to "Recently Completed".

---

## Status Summary

| Status | Count |
|--------|-------|
| Ready (open follow-ups) | 4 |
| Blocked | 0 |
| Roadmap bets remaining | 0 |

Current version: **v5.23.5**. The 2026-07 ideation roadmap plus the follow-on
gap-analysis push (v5.12.4-v5.17.x: fresh threat-intel, Rust/Go/Python lockfile
coverage, product/DX, honest SLSA grading, starjacking, OSV export, MCP-registry
metadata) are shipped. v5.23.4 adds the 2026-07-31 threat-intelligence refresh and
makes GitHub Actions artifact-download findings conditional on a proven workflow trust
boundary while retaining fail-closed cross-run and untrusted-trigger coverage. See
CHANGELOG.md for the full per-release history.

---

## Ready - open follow-ups

| Item | Where | Note |
|------|-------|------|
| **Drain the 2026-07-31 importer backlog without losing reviewability.** The 14-day CWE-506/OSV window had 28,662 corroborated entries remaining after the deliberate 250-entry cap. Decide between bounded catch-up batches, a temporarily higher schedule frequency, or an age-out policy with explicit coverage accounting; never commit an unreviewable 29k-entry machine-generated batch silently | scripts/import-threat-feed.mjs, feed.json | medium; operational follow-up |
| **v5.23.5: reduce structural-matcher cost under V8 coverage instrumentation.** The real 5 MiB wall-clock gates pass with 10-15 second full-suite budgets, while V8 instrumentation adds roughly 2-4x overhead. v5.23.3 keeps explicit 5x instrumented budgets so CI measures bounded work without pretending coverage is a benchmark; profile credential-flow, protestware, V8 ownership, and broad-gap matchers and remove that multiplier when practical | correlated-pattern-matchers.ts, patterns.ts, internal-disclosure.ts | medium; next patch |
| Full offline sigstore signature verification (DSSE signature vs Fulcio cert chain + Rekor inclusion proof) on top of v5.15.0's structural validation | src/slsa-verifier.ts | large; documented follow-up |
| Digest-78 threat cluster (wagni_bot ~30 npm crypto-SDK impersonations, FauxUV PyPI RCE, mcp-server-pg) - needs the same primary-source verification as v5.12.4 before ingest | threat-intel | small-medium; own refresh |

---

## Ideas / not-yet-scheduled (no owner)

- Install Guard v2: resolve version ranges against the offline metadata cache so
  pinned IOCs fire on ranges too; add a `guard` shell shim/alias so it can wrap npm
  transparently.
- MCP rug-pull detection (baseline tool-description hashes in .scg-cache) - noted as
  future work in src/mcp-scanner.ts.
- Publish the MCP server to the official MCP registry: metadata prep shipped in v5.17.1
  (server.json + package.json mcpName); only the manual `mcp-publisher publish` and the
  awesome-list / directory submissions remain.

---

## Recently Completed

| Item | Date |
|------|------|
| v5.23.4: trusted same-run artifact handoffs, fail-closed cross-run controls, and the 2026-07-31 threat-intelligence refresh | 2026-07-31 |
| v5.23.3: exact self-recognition, compiled-counterpart suppression, bundle-safe structural correlation, Python manifest completeness, and build-backed self-scan regression | 2026-07-30 |
| v5.23.1: exact multi-line structural matching, false-positive repairs, complete PatternEntry guard wiring, and transparent partial scans | 2026-07-29 |
| v5.17.3: ViteVenom malicious @vite* npm IOCs (import-time RAT, blockchain C2) | 2026-07-18 |
| v5.17.2: self-scan false-positive fix (recognize own repo checkout by package.json identity, not just install path) | 2026-07-17 |
| v5.17.1: MCP registry metadata (mcpName + server.json) + honest npm description | 2026-07-17 |
| v5.17.0: OSV-format feed export (`feed osv`) + "scanned by" adopter badge | 2026-07-17 |
| v5.16.0: starjacking detection (repository-claim corroboration, FP-conservative) | 2026-07-17 |
| v5.15.0: honest SLSA provenance validation (in-toto/DSSE parsing; fixed the overclaim) | 2026-07-17 |
| v5.14.0: path-scoped policy + inline scg-ignore, JUnit output, MCP v2, dead allowlist.domains fix | 2026-07-17 |
| v5.13.0: Rust/Go/Python lockfile matching + agent-memory scanning | 2026-07-17 |
| v5.12.4: PhantomSync + Pepesoft IOCs (primary-source verified) | 2026-07-17 |
| v5.6.0-gate should-fixes now all shipped: GitLab per-finding coordinate (v5.6.1), Jenkinsfile pin comment (v5.6.1), Install Guard version-range README note (v5.6.1), skills-scanner FILE_TOO_LARGE_SKIPPED (v5.12.0) | 2026-07-11 |
| Issue #54: FILE_TOO_LARGE_SKIPPED across scan families + threat-intel literal-indicator contract (v5.12.0) | 2026-07-11 |
| v5.6.0 / v5.5.0 / v5.4.x / v5.3.0 / v5.2.45 and earlier | see CHANGELOG.md |
| T-001..T-007 (v3-v4 era backlog) | done, see MANIFEST.json |
