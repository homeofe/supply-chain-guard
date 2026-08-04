# supply-chain-guard: Next Actions for Incoming Agent

> MANIFEST.json tasks is authoritative. Work top-down among ready tasks whose
> dependencies are done. Every implementation task has one canonical
> **Acceptance criteria** section of task boxes. Check a box only on evidence.
> Before a task becomes done, each box must be checked, explicitly waived with
> rationale, or moved to a linked open follow-up.

Five tasks are ready, one owner decision is blocked, and T-008 is complete.

Current version: **v5.25.2**

---

## Status Summary

AAHP 3.9.1 adoption and the verified security hardening are complete. Five
follow-ups are ready, and the Node/Babel support-matrix decision is owner-blocked.

| Status | Count |
|--------|-------|
| Ready | 5 |
| Blocked | 1 |

The published package remains v5.25.1. Release metadata for v5.25.2 is
unreleased on `codex/release-v5.25.2`.

---

## T-009: Implement full offline sigstore verification

**Goal:** Verify DSSE signatures, the Fulcio certificate chain, and Rekor inclusion
proofs locally without a network dependency.

**Files:** `src/slsa-verifier.ts` and its focused fixtures/tests.

**Acceptance criteria:**
- [ ] A valid trusted fixture passes DSSE, certificate-chain, identity, and Rekor inclusion verification offline.
- [ ] Invalid signatures, identities, chains, timestamps, and inclusion proofs each fail closed in focused adversarial tests.
- [ ] User-facing partial/verified states and trust-root update behavior are documented.

---

## T-010: Add a first-class known-bad VS Code extension-ID IOC type

**Goal:** Represent malicious extension IDs as threat intelligence without
conflating identity matches with behavioral rules.

**Files:** `src/vscode-scanner.ts`, the threat-feed schema, feed generation, and
focused registry tests.

**Acceptance criteria:**
- [ ] The schema represents normalized `publisher.name` IOCs separately from behavioral findings.
- [ ] Marketplace and Open VSX scans exact-match the normalized ID with positive, case, boundary, and malformed-ID tests.
- [ ] Feed compatibility and version-skew behavior are documented and generated feed checks pass.

---

## T-011: Verify the remaining Digest-78 indicator cluster

**Goal:** Verify FauxUV and `mcp-server-pg` indicators against primary sources
before ingestion, without duplicating the wagni entries already present.

**Files:** `src/threat-intel.ts`, `feed.json`, importer evidence, and feed tests.

**Acceptance criteria:**
- [ ] Every proposed indicator has a recorded primary-source anchor and scoped confidence.
- [ ] Unverified or ambiguous values are excluded with the reason recorded.
- [ ] Confirmed values are deduplicated, generated into the feed, and pass validator and matcher regressions.

---

## T-012: Profile structural matcher cost under V8 coverage

**Goal:** Narrow the instrumented performance multiplier without weakening the
real 5 MiB wall-clock gate.

**Files:** `src/correlated-pattern-matchers.ts`, `src/patterns.ts`,
`src/internal-disclosure.ts`, and performance tests.

**Acceptance criteria:**
- [ ] Reproducible baseline and coverage-mode profiles identify the dominant matcher costs.
- [ ] Any multiplier change is justified by measured data and keeps the real 5 MiB wall-clock gate unchanged.
- [ ] Focused performance and correctness regressions pass on supported Node lines.

---

## T-014: Remove the external zip dependency from VS Code test fixtures

**Goal:** Make the 14 archive-fixture tests runnable on Windows without changing
the production extraction backend or weakening Linux coverage.

**Files:** VS Code test fixture helpers under `src/__tests__/` and Windows CI.

**Acceptance criteria:**
- [ ] An in-process deterministic fixture builder replaces external `zip` only in tests.
- [ ] All 14 currently skipped/failing fixture tests pass on Windows without a PATH-installed zip executable.
- [ ] The same fixtures and the full suite pass in required Linux CI.

---

## T-013: Move to Babel 8 and a supported Node line (blocked)

**Goal:** Upgrade Babel and the supported Node/CI matrix as one compatible change.

**Blocked by:** Owner decision on raising package engines and both CI jobs together;
do not merge Babel 8 alone.

**Acceptance criteria:**
- [ ] The owner selects and records the new minimum Node line.
- [ ] Engines, both CI jobs, Babel, lockfile, and user-facing support documentation move together.
- [ ] Build, full Linux suite, package smoke test, and release gates pass on the new matrix.

---

## Ideas / Not Yet Scheduled

- Resolve Install Guard version ranges against the offline metadata cache and add
  a transparent guard shell shim.
- Baseline MCP tool-description hashes for rug-pull detection.
- Publish the prepared MCP server metadata to the official registry and relevant
  directories.

---

## Recently Completed

> Resolution records the closure evidence: commit, PR, test run, live
> verification, waiver rationale, or linked follow-up that satisfied the criteria.

| Item | Resolution |
|------|------------|
| T-008: AAHP 3.9.1 adoption and verified hardening | 247 focused tests, build, audit, AAHP lint/doctor/prepush, independent review, and PR #114 Linux CI passed |
| v5.25.1: campaign and package IOC update | Released 2026-08-04; feed generation and release gates passed |
| v5.25.0: ecosystem-scoped importer recovery | Released 2026-08-03; importer and feed regressions passed |
| v5.24.0: drain-aware backlog accounting | Released 2026-08-02; recovery-slice tests passed |
| v5.23.5: PointBlank routing and intelligence | Released 2026-08-01; ecosystem routing regressions passed |

### T-008: Adopt AAHP 3.9.1 and close verified scanner and CI defects

**Acceptance criteria:**
- [x] AAHP is exact-pinned at 3.9.1, installs without lifecycle scripts, and its npm audit has no high-severity finding.
- [x] Registry downloads, artifact integrity, self-scan identity, domain IOCs, VS Code identifiers, Solana webhooks, and archive extraction have positive and adversarial focused regressions.
- [x] TypeScript build and the final focused Windows-safe regression set pass.
- [x] AAHP lint, doctor, and pre-push verification pass after regeneration; the advisory criteria report runs with no actionable findings.
- [x] STATUS.md records the exact local and required Linux CI evidence.

**Resolution:** Completed 2026-08-04 with 13 focused files / 247 tests,
`npm run build`, zero high-severity audit findings, AAHP 3.9.1 lint/doctor/prepush,
a bounded independent review, and the required PR #114 Linux full suite and AAHP gates.
