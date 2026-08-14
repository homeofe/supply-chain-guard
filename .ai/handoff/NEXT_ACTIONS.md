# supply-chain-guard: Next Actions for Incoming Agent

> MANIFEST.json tasks is authoritative. Work top-down among ready tasks whose
> dependencies are done. Every implementation task has one canonical
> **Acceptance criteria** section of task boxes. Check a box only on evidence.
> Before a task becomes done, each box must be checked, explicitly waived with
> rationale, or moved to a linked open follow-up.

Six tasks are ready, two owner decisions are blocked, and T-008/T-015/T-018/T-019 are complete.

Current version: **v5.26.2**

---

## Status Summary

AAHP 3.9.1 adoption and the verified security hardening are complete. Six
follow-ups are ready. Two decisions are owner-blocked: the Node/Babel support
matrix and whether version-pinned npm IOCs should match on a directory scan.

| Status | Count |
|--------|-------|
| Ready | 6 |
| Blocked | 2 |

The published package is v5.26.2.

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

## T-017: Index matchBareNpmIOC so npm IOC lookup is O(1)

**Goal:** Give `matchBareNpmIOC` the same indexed lookup `matchPackageIOC`
already has, so npm IOC matching stops being a linear scan of the whole feed.

**Why now:** `matchPackageIOC` is an indexed O(1) lookup (see the comment at
`src/install-guard.ts:270`); `matchBareNpmIOC` (`:242`) still walks the entire
feed per call. Two consequences:

- Production: every dependency checked by `src/scanner.ts` and
  `src/npm-scanner.ts` costs one full pass over 9,374 package entries.
- Tests: `collection-reachability.test.ts` calls the real matcher once per
  entry, which is ~85M comparisons and about 3.3s. It went red on CI during the
  v5.25.6 release at the default 5s timeout, and the cost grows with the SQUARE
  of the feed, which is now growing by thousands of entries per import.

The 30s timeout added there is a stopgap, not the fix. If it goes red again,
index the matcher instead of raising the number.

**Acceptance criteria:**
- [ ] `matchBareNpmIOC` resolves through an index, with identical semantics:
      a bare-name IOC still matches any version, a pinned IOC still matches only
      an exact version, and ecosystem-prefixed entries are still skipped.
- [ ] The index is built once per feed rather than per call, matching how
      `matchPackageIOC` does it.
- [ ] `collection-reachability.test.ts` passes comfortably inside the default
      timeout, and the explicit 30s override plus its comment are removed.
- [ ] A mutation proof: break the pinned-version branch and watch a test go red.

---

## T-016: Decide whether version-pinned npm IOCs should match on a directory scan (blocked)

**Goal:** Close the gap between what the feed knows and what `scan` reports, or
record a deliberate decision not to.

**The finding (verified by execution during the 2026-08-06 backlog import, not
by reading):** `matchBareNpmIOC` (`src/install-guard.ts:242`) matches a
version-pinned IOC only when a real version is supplied. Line 257 returns on a
bare-name IOC for any version; line 258 requires
`version !== undefined && iocVersion === version`. Only one caller passes a real
version, `install-guard.ts:273` (`spec.version`). All three scanning callers pass
`undefined`:

- `src/scanner.ts:1653` - the dependency spec from package.json is discarded at
  line 1647, which sets `version: undefined` for every non-alias dependency
- `src/npm-scanner.ts:237` and `:319` - literal `undefined`

Consequence: a project depending on a version-pinned malicious package is caught
by `guard` but **not** by `scan`. That is 7,749 of the 9,374 package IOCs in the
feed, including every `@hubsync` and `@ornikar` entry.

Reproduction: a fixture depending on `@hubsync/web-sdk-react@6.3.10` scans clean,
while `guard --dry-run npm install @hubsync/web-sdk-react@6.3.10` exits 2 with a
critical `THREAT_INTEL_PACKAGE_IOC`. A bare-name IOC in the same fixture fires
critical `MALICIOUS_DEPENDENCY` on the directory scan.

**Blocked by:** Owner decision. This is a behaviour change with real
false-positive surface, not a bug fix. Making pinned IOCs match a resolved
version would start firing on lockfile-resolved and transitive versions that
scan almost 8,000 pinned entries against, and a false positive gets the tool
switched off, which is worse than a miss. Do not implement it on an agent's own
initiative.

**Acceptance criteria:**
- [ ] The owner decides: match pinned IOCs on scan, leave scan as an install-time
      guard only, or gate the behaviour behind a flag.
- [ ] If matching is adopted, the version source is defined explicitly (declared
      range in package.json vs resolved version in the lockfile) - these are not
      the same and a declared range is not a version.
- [ ] False-positive surface is measured against a real dependency tree before
      the change ships, not asserted.
- [ ] Documentation states which scan paths enforce pinned IOCs, so the feed
      count is not read as scan coverage.

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
