# supply-chain-guard: Next Actions for Incoming Agent

> MANIFEST.json tasks is authoritative. Work top-down among ready tasks whose
> dependencies are done. Every implementation task has one canonical
> **Acceptance criteria** section of task boxes. Check a box only on evidence.
> Before a task becomes done, each box must be checked, explicitly waived with
> rationale, or moved to a linked open follow-up.

Five tasks are ready, one owner decision is blocked, and T-008/T-015/T-016/T-017/T-018/T-019 are complete.

Current version: **v5.27.0**

---

## Status Summary

AAHP 3.9.1 adoption and the verified security hardening are complete. Five
follow-ups are ready. One decision is owner-blocked: the Node/Babel support
matrix.

| Status | Count |
|--------|-------|
| Ready | 5 |
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

## T-013: Move to Babel 8 and a supported Node line (owner decision outstanding)

**Goal:** Upgrade Babel and the supported Node/CI matrix as one compatible change.

**What is now in place.** The compatibility contract, the evidence to act on it and
the machinery to execute it all exist, so the remaining step is a decision rather
than an investigation. `docs/node-support.md` holds the policy as a
machine-readable block, and `src/__tests__/node-version-contract.test.ts` holds
every declaration site to it. The complete suite plus a clean-room install of the
packed tarball now run on Node 20 and Node 22 on every commit.

**What the survey found, and it was not what the task assumed.** The repository
already disagreed with itself. `package.json` promised `>=20.0.0`, CI built,
tested and published on 20, while `action.yml` and the `Dockerfile` both executed
on 22. The two most-used distribution channels were running on a major CI never
exercised. Node 20 also reached end of life on 2026-04-30, verified against the
upstream nodejs/Release schedule, so the artifact was being published from an
unpatched runtime.

**Blocked by:** Owner decision on raising `engines.node`, which is a promise
broken for every consumer still on Node 20 and therefore not an agent's call.
Everything else is mechanical once it is made: set `enginesFloor` and
`testedMajors` in `docs/node-support.md` and the gate names every file that has to
follow.

**Acceptance criteria:**
- [x] Every Node declaration site identified and reconciled to one authoritative policy.
- [x] CI runs the COMPLETE build and suite on both majors, with no reduced smoke lane.
- [x] The publishing path is validated on both majors without a public release: pack, tarball contents against the manifest, clean-room install, entry point, bin mapping, type declarations, metadata and an end-to-end scan from the installed artifact.
- [x] A deterministic drift gate exists, mutation-proved 9/9, and the artifact validation is mutation-proved 3/3.
- [ ] The owner selects and records the new minimum Node line.
- [ ] Engines, Babel, lockfile and user-facing support documentation move together with it.

**Tracked exception: the npm publish job still runs on Node 20.** It is the one
lane that cannot be rehearsed, because it runs only on a tag push and
authenticates by OIDC, which no dry run exercises; a failed publish burns a
version number, and that bill has been paid before when npm 12 dropped Node 20.
Owner: the maintainer. Exit condition, mechanically checkable: set `publishMajor`
to 22 in `docs/node-support.md`, which makes the gate require the publish job to
declare 22. The condition for doing so is a green `compat (Node 22)` leg on `main`
across at least one release cycle. Tracked here rather than in a GitHub issue
because this repository holds zero open issues by rule.

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
