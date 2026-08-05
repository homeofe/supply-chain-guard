# supply-chain-guard: Current State

> Updated 2026-08-04. This is one current snapshot, not a session log.
> Historical detail belongs in CHANGELOG.md, generated LOG.md,
> LOG-ARCHIVE.md, and git history.

---

## At a Glance

v5.25.2 was published from 0e68fef after all release workflows passed.
A live install smoke then exposed one critical own-definition false positive.
Branch `codex/release-v5.25.3` carries the narrow packaged self-scan fix.

| Field | Current state |
|-------|---------------|
| Released package | v5.25.2 on npm |
| Release commit | 0e68fef |
| Release target | v5.25.3 |
| Merged implementation | 7481d63, PR #114 |
| Working branch base | 0e68fef |
| Threat feed | 6,588 entries, feed.json regeneration pending |
| AAHP dependency | 3.9.1, exact pin |
| AAHP manifest schema | aahp_version 3.0, intentionally unchanged |
| Task authority | MANIFEST.json |

AAHP 3.9.1 is the installed consumer artifact. The repository keeps its own
handoff state and a narrow local script customization; upgrading the package
does not overwrite or silently discard that consumer state.

---

## Threat-Intel Run 2026-08-05 (INCOMPLETE - gates not run)

Model: claude-opus-5. Working tree carries an unfinished threat-intel change.
It is NOT committed, NOT pushed, and NO pull request was opened, because the
environment blocked all Node execution partway through the run.

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

### Blocked steps, in order

`npm run feed:generate` has since been run and succeeded (6,588 entries), so
feed.json is current. Still outstanding:

1. Renormalize the two shell scripts, per the command above.
2. `npm run handoff:refresh` - DASHBOARD/TRUST/LOG and MANIFEST checksums are
   stale, including from this very edit. `check:handoff` stays red until it runs,
   and it cannot succeed before step 1.
3. `npm run build` and the targeted vitest suites (`feed`, `threat-intel`,
   `campaigns`, `ioc-blocklist`, `feed-import`). No pattern table was modified,
   so the regex-shape validator is not implicated, but nothing here has been
   executed and the new tests have never run.

Do not open the pull request until 1-3 are green. Nothing was committed, so
discarding the working tree is a clean reset if the change is not wanted.

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

- T-009: implement cryptographic offline DSSE, Fulcio-chain, and Rekor inclusion
  verification.
- T-010: add a first-class known-bad VS Code extension-ID IOC type.
- T-011: verify the remaining Digest-78 indicators against primary sources.
- T-012: profile structural matcher cost under V8 coverage.
- T-014: replace the external zip test-fixture dependency and add Windows coverage.
- T-013 remains blocked on an owner decision to raise package engines and both
  CI Node jobs together for Babel 8. Do not merge Babel 8 alone.
- AAHP 3.9.1 detects a canonical file present on disk but missing from the
  manifest; deleting both the file and its entry remains an upstream required-set gap.

Threat-feed imports remain review-sliced. Never use backlog/truncation overrides
merely to make an import exit clean; retain explicit ecosystem/date coverage and
primary-source evidence.

---

## Handoff Rule

Incoming agents start with MANIFEST.json quick_context and tasks, then read this
snapshot and NEXT_ACTIONS.md. A task is eligible only when it is ready and every
`depends_on` task is done. DASHBOARD.md, TRUST.md, LOG.md, and manifest file
metadata are generated with `npm run handoff:refresh`; never hand-edit them.
