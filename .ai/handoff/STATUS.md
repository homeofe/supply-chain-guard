# supply-chain-guard: Current State

> Updated 2026-08-05. This is one current snapshot, not a session log.
> Historical detail belongs in CHANGELOG.md, generated LOG.md,
> LOG-ARCHIVE.md, and git history.

---

## At a Glance

v5.25.4 was published (2026-08-05 threat-intel run: 251 imported IOCs, 22
hand-added ChainDrop indicators, three Windows-only handoff-gate fixes).
v5.25.5 is being cut from it: the Action PR-comment fallback fix (#119) and
the AAHP shared-primitive convergence (#120, merged 9f5e01a) - see "AAHP
convergence" below for the latter's detail.

| Field | Current state |
|-------|---------------|
| Released package | v5.25.4 on npm |
| Release target | v5.25.5, this branch (chore/release-v5.25.5) |
| Merged since v5.25.4 | #119 (Action comment fix), #120 (AAHP convergence) |
| Working branch base | 9f5e01a (main, post-#120) |
| Threat feed | 6,588 entries, feed.json regenerated at v5.25.5 |
| AAHP dependency | 3.9.2, exact pin (bumped from 3.9.1 in #120) |
| AAHP manifest schema | aahp_version 3.0, intentionally unchanged |
| Task authority | MANIFEST.json |

AAHP 3.9.2 is the installed consumer artifact. `scripts/scg-handoff-docs.mjs`
(renamed from `aahp-dashboard.mjs`) is this repo's own project-specific
handoff-doc generator - it is not, and never was, an AAHP tool, despite the
former name suggesting otherwise. It now imports AAHP's shared bash-resolution,
Windows-path-conversion, and changelog-grammar primitives instead of vendoring
private copies of them.

---

## AAHP convergence (2026-08-05, unreleased, branch chore/aahp-converge-shared-primitives)

Emre's instruction: no divergence between this repo and AAHP. Prior state
(audited this session, by execution not by reading): this repo vendored local
copies of `_aahp-lib.sh` and `aahp-manifest.sh` purely because its own fork
dashboard (`aahp-dashboard.mjs`) called them locally rather than importing
AAHP's package. `_aahp-lib.sh` was purely stale (missing `aahp_manifest_index`
and a since-fixed table-separator regex); `aahp-manifest.sh` was actually AHEAD
of AAHP on one point (it preserved MANIFEST `project` on regeneration; AAHP
clobbered it) - that fix was upstreamed into AAHP 3.9.2 first (AAHP PR #64),
removing the only reason this repo's copy was ever ahead.

What changed on this branch:

- Bumped `@elvatis_com/aahp` 3.9.1 -> 3.9.2 (exact pin, `pinnedDep.allowRange: false`).
- `aahp-dashboard.mjs` renamed to `scripts/scg-handoff-docs.mjs` (`git mv`, history preserved).
  Its own header comment now explicitly disclaims being an AAHP tool.
- Deleted the two locally-vendored `scripts/_aahp-lib.sh` and `scripts/aahp-manifest.sh`.
  The renamed generator now imports `resolveBash`/`toBashPath` from
  `@elvatis_com/aahp/scripts/aahp-config.mjs` and `RELEASE_RE` from
  `@elvatis_com/aahp/scripts/changelog-grammar.mjs` (deep import; the package
  ships `scripts/` with no `exports` map restricting it), and resolves the
  packaged `aahp-manifest.sh` via `createRequire(...).resolve(...)` instead of
  a local sibling file.
- This closes a real bug for free: the local heading regex
  (`/^## \[(\d+\.\d+\.\d+)\] - .../`) silently dropped SemVer pre-release
  headings from the generated LOG.md table with no error. `RELEASE_RE` is a
  strict superset (adds an optional `-[0-9A-Za-z.-]+` group), so every
  currently-committed CHANGELOG heading produces byte-identical output; only
  a future pre-release heading behaves differently (correctly, now).
- `src/__tests__/handoff-gate.test.ts` (13 tests, unchanged behavioral
  coverage) updated: its isolated tmp fixture can no longer copy the two bash
  files from this repo's own `scripts/` (they are gone), so it now stubs
  `node_modules/@elvatis_com/aahp/` inside the fixture, copied from whatever
  is actually installed - the fixture can never silently drift from the real
  pin. One test's expected value changed to match AAHP's own (correct, already
  released) `_aahp-lib.sh` summary-filter behavior: a table header row is real
  content, not header chrome, so it is the correct one-line summary, not a
  later prose line the old, narrower SCG-local filter used to expose instead.
  Two tests that call `refresh()` twice needed a longer timeout (subprocess
  spawn on Windows measured ~6s/call; confirmed this is pre-existing behavior
  identical on the pre-rename script, not a regression from this change).
- Regenerated DASHBOARD.md/TRUST.md/LOG.md/MANIFEST.json. Diff is minimal and
  expected: the AUTO-GENERATED banner's filename, and the truthfully-written
  (but ungated) `@elvatis_com/aahp` row in the Toolchain table.

Verified: `npm run build` (governance + feed + handoff gates + tsc) green;
`npx aahp check .` 7/7 gates pass (handoff sub-check correctly skipped per
`config.check.skip`, NOT the full protocol - see below); `npx aahp verify .
--level ci` all 4 layers green; `src/__tests__/handoff-gate.test.ts` 13/13
green locally, twice. Full Vitest suite not run locally (Windows subprocess
spawning is disproportionately slow for the one handoff-gate file alone) but
confirmed via PR #120's own required Linux CI: `Build and Test` ran all 108
files / 2,655 tests, all passed, 64s.

Merged 2026-08-05 as PR #120 (9f5e01a), with explicit go-ahead - a second
public repo with a floating `v5` Action branch. Release v5.25.5 (this branch,
chore/release-v5.25.5) bundles this convergence with the already-merged #119
Action comment fix.

Correction to a claim from AAHP's own audit of this repo: `.supply-chain-guard.yml`'s
SHAI_HULUD_WORM/SHAI_HULUD_CRED_STEAL suppressions are NOT path-scoped to the
generator file (no `path:` key is set in the actual YAML, despite the
schema supporting one) - they suppress repo-wide. The `reason:` text merely
explains why the trigger comes from that file. Filename references in the
`reason:` text updated for the rename; suppression scope unchanged (tightening
it to a real `path:` scope would be a separate, deliberate improvement, not
folded into this rename).

---

## Threat-Intel Run 2026-08-05 (COMPLETE - merged, shipping in v5.25.4)

Model: claude-opus-5. The run is finished. It was committed as 43ef363, pushed,
opened as PR #117 and squash-merged to main as 74830f2 with both required checks
green. An earlier session had been unable to execute Node at all partway through,
which is why the steps below were recorded as blocked; they have since all run.

### What landed in the working tree

- `src/threat-intel.ts`: +251 imported package IOCs, +22 hand-added ChainDrop
  entries. Feed now holds 6,588 entries, up from 6,315.
- `src/ioc-blocklist.ts`: ChainDrop exfil host, Ethereum dead-drop C2 resolver
  contract, three payload hashes, 18 version-pinned hijacked packages.
- `src/__tests__/campaigns.test.ts`: ChainDrop describe block, 8 cases, with
  clean-version and cloud-metadata negatives.
- `CHANGELOG.md`: entry under `## [Unreleased]`. No version bump, by design.

### Import accounting

The default run reported 2,338 entries still behind `--limit 250`, and flagged
exactly one as undrainable: it would have aged out of the 14-day window before
any future run could reach it. That entry, `n8n-nodes-probe@1.0.4`
(GHSA-v527-x59j-frgj), was recovered first with an explicit exempt slice
`--since 2026-07-22 --until 2026-07-28`, after which the default run exited
clean with no backlog warning. No override flag was used. The remaining 2,337
are all recent and stay reachable by the next scheduled run.

### Windows handoff-gate fixes, found while running STEP 4e

`npm run handoff:refresh` could not regenerate MANIFEST.json from a Windows
checkout. Two independent defects, both pre-existing and neither caused by the
threat-intel change; CI on Linux was unaffected, which is why they went unseen.

- `scripts/aahp-dashboard.mjs` passed a native `C:\...` path to bash. MSYS
  re-parses the Windows command line and treats backslashes as escapes, so bash
  received `C:reposcriptsaahp-manifest.sh` and reported it missing - even though
  execFileSync uses an argv array and no shell. Path arguments are now
  forward-slashed on win32 only.
- The same call trusted whatever `bash` resolved to on PATH. On Windows that is
  normally `C:\Windows\System32\bash.exe`, the WSL launcher, and WSL mounts the
  host at `/mnt/c` with no `C:` drive - so once the path was well-formed it still
  failed, now with "No such file or directory" for a file that demonstrably
  exists. That symptom reads as a missing script rather than a wrong interpreter,
  which is what made this worth writing down. Git-Bash is now preferred
  explicitly on win32; `AAHP_BASH` still overrides.
- `.gitattributes` pinned `*.mjs` to LF but not `*.sh`. With `core.autocrlf=true`
  both `scripts/aahp-manifest.sh` and `scripts/_aahp-lib.sh` were checked out
  CRLF, and bash failed with `$'\r': command not found` and
  `set: pipefail: invalid option name`. Now pinned to LF.

The `.gitattributes` rule only governs future checkouts. The two working-tree
copies are still CRLF and must be renormalized once:
`git checkout-index -f -- scripts/aahp-manifest.sh scripts/_aahp-lib.sh`

### Steps that were blocked, now all green

1. Shell scripts renormalized; `.gitattributes` now pins `*.sh` to LF alongside
   `*.mjs`, so a `core.autocrlf=true` checkout no longer hands bash a stray CR.
2. `npm run feed:generate` - 6,588 entries, feed.json current.
3. `npm run handoff:refresh` - works from a Windows checkout again; the three
   defects behind that are described above and shipped in this release.
4. `npm run build` green (check:aahp + check:feed + check:handoff + tsc), the five
   targeted suites green on Windows, and the full suite green on Linux via openclaw
   (108 files, 2,653 tests, vscode-scanner included because zip is present there).

Nothing is outstanding from this run.

---
## Current Hardening Outcome

### AAHP consumer state

- STATUS.md is a bounded snapshot and LOG.md is generated from CHANGELOG.md.
- MANIFEST.json is authoritative for task status and dependencies;
  NEXT_ACTIONS.md binds every implementation task to canonical task-box criteria.
- Acceptance closure requires evidence, waiver rationale, or a linked follow-up.
- Checksums fail closed when a digest tool returns no output.
- Manifest summaries skip Markdown heading, quote, and table chrome.
- TRUST.md separates generated inventory from complete time-bound trust records.
- Generated release-journal headlines select release content, not subsection labels.
- Workflow routing is harness-owned and optional Phase 4.5 grounding has an
  explicit SHIP / NEEDS_CHANGES / BLOCK verdict.

### Product and transport boundaries

- Shared HTTPS downloads reject credentials, bound redirects, bytes, and total
  time, validate final status, restrict every hop to official registry hosts,
  and clean partial files.
- npm artifacts verify SRI and shasum when present; digestless artifacts remain
  scannable but make the report explicitly partial. PyPI verifies SHA-256.
- VS Code targets require one strict `publisher.name`, encode URL components,
  pin download hosts, use a fixed temporary filename, and clean acquisition failures.
- Self-scan suppression recognizes only the running package's physical root or
  a scanner-created clone of the exact canonical HTTPS repository.
- Package-shaped regressions include compiled `dist/` output without source or
  `.gitignore`, while an untrusted copy still receives the same rule finding.
- Domain IOCs use hostname boundaries. Remote feed metadata, dates, confidence,
  and unknown fields are validated and normalized before scan-time scoring.
- Solana webhooks select HTTP versus HTTPS correctly, reject other schemes,
  settle once at response headers, discard bodies, and enforce one absolute deadline.
- Archive preflight now aligns with Windows, macOS, libarchive, and Info-ZIP
  filename/type semantics, including case and HFS aliases, legacy encodings,
  symlink targets, PAX/GNU precedence, and type-overriding ZIP metadata.

### CI and release safety

- Workflows default to read-only repository permissions and pin external actions
  to immutable revisions.
- Installs disable lifecycle scripts and CI enforces
  `npm audit --audit-level=high`.
- Manual dispatch is build-only. Publishing requires an immutable semver tag
  exactly matching package.json and uses exact-pinned npm 11.18.0 with OIDC.

---

## Verification State

| Check | Current evidence |
|-------|------------------|
| Installed AAHP | 3.9.1 |
| `npm ci --ignore-scripts` | passed |
| `npm audit --audit-level=high` | passed, zero vulnerabilities |
| Focused Windows-safe regressions | 13 files, 247 tests passed |
| Archive hardening subset | 46 tests passed; independent backend re-audit found no remaining actionable mismatch |
| TypeScript `tsc --noEmit` | passed |
| `npm run build` | passed, including governance, feed, handoff, and TypeScript gates |
| AAHP acceptance report | 8 task-bound sections, no actionable findings |
| AAHP lint / doctor / prepush | passed after regeneration |
| Packaged self-scan regression | 16 tests plus installed candidate tarball: zero critical/high; untrusted copy detected |
| Full Vitest suite | 2,644 tests passed in PR #115 and v5.25.2 release CI |
| Linux AAHP Verify | passed for PR #115 and the v5.25.2 release |

The Windows workstation lacks the external `zip` executable used only to build
fixtures for 14 VS Code tests. Do not describe that prerequisite as a product
failure. T-014 tracks replacing the test-only dependency; required Ubuntu CI has
the tool and owns the full-suite result.

---

## Live Decisions and Remaining Work

### Action PR-comment fallback (fixed, unreleased)

`action.yml` guarded `reportForComment` on its own indented value. Indenting an empty
report produces four spaces, which is truthy, so the clean-scan fallback at the end of
the detail chain was unreachable and the three `if (reportForComment)` guards always
fired. Verified by execution, not by reading: an empty report is reachable through a
failed report read or an empty file, and the visible effect is a blank indented line
where the clean explanation belongs. The verdict line is separate, so no comment ever
claimed clean when it was not - degraded, never falsely reassuring.

Reachability is narrower than it first looked: a first clean scan posts no comment at
all, so this only appeared when a stale findings or partial comment was replaced on the
return to clean. Two scanner-level tests now drive the real comment script through the
update path; both fail against the previous guard.

- T-009: implement cryptographic offline DSSE, Fulcio-chain, and Rekor inclusion
  verification.
- T-010: add a first-class known-bad VS Code extension-ID IOC type.
- T-011: verify the remaining Digest-78 indicators against primary sources.
- T-012: profile structural matcher cost under V8 coverage.
- T-014: replace the external zip test-fixture dependency and add Windows coverage.
- T-013 remains blocked on an owner decision to raise package engines and both
  CI Node jobs together for Babel 8. Do not merge Babel 8 alone.
- AAHP (3.9.2, still true) detects a canonical file present on disk but missing
  from the manifest; deleting both the file and its entry remains an upstream
  required-set gap.

Threat-feed imports remain review-sliced. Never use backlog/truncation overrides
merely to make an import exit clean; retain explicit ecosystem/date coverage and
primary-source evidence.

---

## Handoff Rule

Incoming agents start with MANIFEST.json quick_context and tasks, then read this
snapshot and NEXT_ACTIONS.md. A task is eligible only when it is ready and every
`depends_on` task is done. DASHBOARD.md, TRUST.md, LOG.md, and manifest file
metadata are generated with `npm run handoff:refresh`; never hand-edit them.
