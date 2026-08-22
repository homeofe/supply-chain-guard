# supply-chain-guard: Next Actions for Incoming Agent

> MANIFEST.json tasks is authoritative. Work top-down among ready tasks whose
> dependencies are done. Every implementation task has one canonical
> **Acceptance criteria** section of task boxes. Check a box only on evidence.
> Before a task becomes done, each box must be checked, explicitly waived with
> rationale, or moved to a linked open follow-up.

Six tasks are ready, one owner decision is blocked, and T-008/T-015/T-016/T-017/T-018/T-019/T-020 are complete.

Current version: **v5.28.1**

---

## Status Summary

AAHP 3.9.1 adoption and the verified security hardening are complete. Six
follow-ups are ready. One decision is owner-blocked: the Node/Babel support
matrix.

| Status | Count |
|--------|-------|
| Ready | 6 |
| Blocked | 1 |


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

## T-013: Node baseline migration (DONE in v5.28.0)

Closed. The owner decided the direction and it shipped: Node 22 is the canonical
baseline, `engines.node` is `>=22.0.0`, the npm artifact is published from Node 22, and
the Action, the container image and the dev container all declare the same major. The
state where documentation said one thing, CI tested another, publishing used a third and
distribution executed a fourth no longer exists.

Node 20 survives only as an explicit transition lane: still running the complete suite,
below the floor, out of support, and **removed in 5.29.0**. That is not a reminder. The
policy gate compares `transitionRemovedIn` in `docs/node-support.md` against the version
in `package.json` and fails the build once the project reaches it while the lane still
exists, so the release that would carry the transition past its own deadline cannot be
built.

**What that leaves for 5.29.0**, and it is mechanical rather than a decision:

1. Set `transitionMajors` to `[]` and drop `transitionRemovedIn` in `docs/node-support.md`.
2. Run the build. The gate names every file that still refers to Node 20.
3. Remove the `20` entry from the `compat` matrix in `ci.yml`.

Babel 8 was bundled into this task on the assumption that it was blocked on the same
Node decision. It is not blocked any more: with the floor at 22, dependency majors that
declare `engines >= 22` are mergeable. Whether to take Babel 8 is now an ordinary
dependency call rather than a migration.

**Evidence for the closure:** `src/__tests__/node-version-contract.test.ts`, 28
assertions, mutation-proved; the complete suite and a clean-room install of the packed
tarball on both majors in CI; the container image built and scanned on every PR.

---

## Ideas / Not Yet Scheduled

- Resolve Install Guard version ranges against the offline metadata cache and add
  a transparent guard shell shim.
- Baseline MCP tool-description hashes for rug-pull detection.
- Publish the prepared MCP server metadata to the official registry and relevant
  directories.

---

## T-021: Decide whether checkSlaCompliance is wired into runScan or removed

**Goal:** `checkSlaCompliance` is exported from the package entry point and has
no caller in `src/`, so `SLA_BREACH_CRITICAL` and `SLA_AT_RISK` cannot reach a
scan report through any format. Confirmed end to end: `SLA_` findings number 0
in every CLI case, including one whose only decision is 30 days past a 24 hour
SLA and which the engine flags when called directly. It is also the structural
reason the T-020 contradiction stayed invisible from the CLI, because only one
of the two SLA definitions ever ran.

**Issue:** https://github.com/homeofe/supply-chain-guard/issues/194

**Files:** `src/scanner.ts` (the triage governance block), `src/sla-engine.ts`,
`src/index.ts`.

**Acceptance criteria:**
- [ ] A decision aged past its SLA produces a finding in a real `scan` run, or `checkSlaCompliance` is removed from the public API. One of the two, decided and recorded.
- [ ] The chosen path is exercised end to end by a test, not by calling the engine directly, so "not wired in" cannot return silently.
- [ ] If wired in, the effect on risk score and exit code is stated in the CHANGELOG, because it can newly fail a build for an adopter of triage.
- [ ] If removed, the CHANGELOG records the removal of a published export.

---

## Recently Completed

> Resolution records the closure evidence: commit, PR, test run, live
> verification, waiver rationale, or linked follow-up that satisfied the criteria.

| Item | Resolution |
|------|------------|
| T-020: `slaComplianceRate` measured a resolution rate, not SLA compliance | Done: one definition, `slaVerdict` in `src/sla-engine.ts`, consumed by both `checkSlaCompliance` and `src/metrics.ts`. Rate is nullable, floored not rounded, and WHEN NON-NULL is 100 if and only if the engine reports zero breaches on the same decisions; unrestricted that biconditional is false, since an empty or wholly unparseable decision set gives zero breaches and a rate of `null`. `mttrCritical` removed. A cross-check suite runs both functions on one input, which no test did before. Evidence and the two deliberately open gaps are in STATUS.md; issue https://github.com/homeofe/supply-chain-guard/issues/172. Follow-up: T-021 / https://github.com/homeofe/supply-chain-guard/issues/194. |
| T-016: pinned npm IOCs were unreachable from `scan` | Done: matched in the lockfile path, the only place a RESOLVED version exists. False-positive surface measured at zero across 43 repos / 10,615 resolved deps before shipping. Bare-name entries excluded there to avoid double-reporting across the transitive tree. |
| T-017: matchBareNpmIOC was a linear scan per call | Done: indexed on a WeakMap keyed by feed identity, with the linear implementation kept as `matchBareNpmIOCLinear` and a parity suite asserting the two agree across the whole bundled feed. collection-reachability went from 3,317ms to 21ms and its 30s stopgap is removed. |
| T-019: dropped-persistence detection | Done in two tranches: `.vscode/tasks.json` recall, `CHAINDROP_GH_TOKEN_MONITOR_PERSISTENCE` (also wired into the hook scanner, since the core walk excludes `.claude/`), and `INSTALL_HOOK_PERSISTENCE_WRITE`. Coverage of the five published artefacts went from one of five to five of five. |
| T-018: known-malware hashes never matched a file | Done: `IOC_KNOWN_MALWARE_FILE_DIGEST` computes SHA-256/MD5 per scanned file, before the scannable-extension gate, over raw bytes. The digest-text substring match is kept as a separate signal. |
| v5.25.5: AAHP shared-primitive convergence | PR #120 merged: AAHP bumped 3.9.1->3.9.2, `aahp-dashboard.mjs` renamed to `scg-handoff-docs.mjs`, two vendored bash files deleted, shared primitives imported instead; PR #119 Action comment fix also included |
| T-015: packaged self-scan own-definition false positive | Package-shaped trusted/untrusted regressions pass; v5.25.3 is the recovery release |
| v5.25.2: AAHP 3.9.1 and security hardening | Released 2026-08-04; live install smoke exposed the T-015 packaged self-scan gap |
| T-008: AAHP 3.9.1 adoption and verified hardening | 247 focused tests, build, audit, independent review, and PR #114 Linux CI passed |
| v5.25.1: campaign and package IOC update | Released 2026-08-04; feed generation and release gates passed |
| v5.25.0: ecosystem-scoped importer recovery | Released 2026-08-03; importer and feed regressions passed |

### T-015: Fix packaged self-scan own-definition false positive

**Acceptance criteria:**
- [x] The fixture mirrors npm package contents: compiled `dist/` included, source
  and `.gitignore` absent.
- [x] A trusted own-package scan suppresses only the exact matcher definition;
  an untrusted copy and injected executable payloads still trigger.
- [x] Sixteen focused self-scan tests, build, audit, and AAHP gates pass; required
  Linux PR CI remains the release gate.

**Resolution:** Completed 2026-08-04 from the published v5.25.2 reproduction,
an exact path/rule exemption, package-shaped trusted/untrusted regressions, and
an installed candidate tarball self-scan with zero critical/high findings.

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
