# supply-chain-guard: Current State

> Updated 2026-08-04. This is one current snapshot, not a session log.
> Historical detail belongs in CHANGELOG.md, generated LOG.md,
> LOG-ARCHIVE.md, and git history.

---

## At a Glance

PR #114 merged the AAHP 3.9.1 adoption and reviewed hardening into `main`.
Branch `codex/release-v5.25.2` contains only the metadata for the next patch
release; v5.25.1 remains published until the immutable v5.25.2 tag completes CI.

| Field | Current state |
|-------|---------------|
| Released package | v5.25.1 on npm |
| Release commit | 28bbd9f |
| Release target | v5.25.2 |
| Merged implementation | 7481d63, PR #114 |
| Working branch base | 7481d63 |
| Threat feed | 6,315 entries |
| AAHP dependency | 3.9.1, exact pin |
| AAHP manifest schema | aahp_version 3.0, intentionally unchanged |
| Task authority | MANIFEST.json |

AAHP 3.9.1 is the installed consumer artifact. The repository keeps its own
handoff state and a narrow local script customization; upgrading the package
does not overwrite or silently discard that consumer state.

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
| AAHP acceptance report | 7 task-bound sections, no actionable findings |
| AAHP lint / doctor / prepush | passed after regeneration |
| Full Vitest suite | passed in required Ubuntu CI for PR #114 and merged `main` |
| Linux AAHP Verify | passed for PR #114 and merged `main` |

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
