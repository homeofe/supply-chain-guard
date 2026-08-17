# supply-chain-guard: Agent Conventions

> Every agent working on this project must read and follow these conventions.
> Update this file whenever a new standard is established.

---

## Language

- All code, comments, commits, and documentation in **English only**
- Use clear, direct language in handoff files (agents are the primary readers)
- **Do not name the maintainer in repository content.** Write "the owner" or "the
  maintainer", never a personal first name. This repo is public, so a name written
  into a handoff note, commit message, PR body, release body or CHANGELOG entry is
  published and indexed for no benefit. Applies to everything an agent writes.
  It does NOT apply to the deliberate identity and contact fields, which are there
  on purpose and must keep working: the `LICENSE` and README copyright lines, the
  `author` field in `package.json` and `action.yml`, and the reporting addresses in
  `SECURITY.md`, `CODE_OF_CONDUCT.md` and `CONTRIBUTING.md`. Changing any of those
  is an owner decision, and the contact addresses additionally need a working
  mailbox to move to.
- Same rule, same reason as the existing no-AI-attribution rule: both keep
  incidental personal or tooling identity out of a public artefact.

## Code Style

- **TypeScript:** strict mode, explicit types, no `any` except where unavoidable
- **Imports:** Node.js built-ins use `node:` prefix (e.g. `import * as fs from "node:fs"`)
- **JSON:** 2-space indentation, no trailing commas
- **Markdown:** ATX headers, tables with alignment, code blocks with language tags
- Source uses ES module syntax (`import`/`export`) but compiles to **CommonJS** output
  (`module`/`moduleResolution: Node16`). The published package is CommonJS, so runtime
  deps must be CJS-importable (this is why commander is pinned to the 14.x line, not 15)

## Module Structure

Each scanner/detector lives in its own file under `src/`:

- `src/scanner.ts` - central entry point, delegates to sub-scanners
- `src/patterns.ts` - shared regex patterns and campaign signatures
- `src/types.ts` - shared TypeScript types/interfaces
- `src/reporter.ts` - output formatting (text, JSON, markdown, SARIF)
- `src/cli.ts` - CLI entry point (commander-based)
- `src/<platform>-scanner.ts` - platform-specific scanner modules
- `src/__tests__/*.test.ts` - Vitest unit tests

## Branching & Commits

```
feat/issue-<N>-<short-name>  → new feature (tied to GitHub issue)
fix/issue-<N>-<short-name>   → bug fix
docs/<short-name>            → documentation only
refactor/<short-name>        → no behaviour change
chore/<short-name>           → build, deps, tooling
```

- Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`)
- PR title must reference the GitHub issue: `feat: description (#N)`
- Squash-merge into main

## Tests

- Framework: **Vitest** (`npm test`)
- One test file per source module: `src/__tests__/<module>.test.ts`
- Every new scanner must have a corresponding test file
- Tests use in-memory fixtures (no disk I/O where avoidable)
- Tests must not make real network calls (mock external APIs)
- Target: 100% branch coverage for detection rules

## Versioning

- **Semantic versioning:** MAJOR.MINOR.PATCH
- MAJOR: breaking CLI changes or removed detection rules
- MINOR: new scanner module or new detection rules
- PATCH: bug fixes, rule tuning, dependency updates
- All version bumps move together (enforced by `check:version-sync`) across every
  version site in `aahp.config.json`. CHANGELOG.md, STATUS.md and the generated
  handoff set move with the release. See CLAUDE.md for the authoritative sequence.

## Release Checklist

The repo-root **CLAUDE.md** is the authoritative, gated release process. Summary:

1. CHANGELOG.md entry: a new `## [X.Y.Z] - date` block below `## [Unreleased]` in Keep a Changelog format (no `v` in brackets, `### Added/Changed/Fixed` sections, reference-link footer), gated by `check:aahp` (the pinned AAHP CLI's changelog-format gate)
2. Version bumped everywhere (see Versioning above)
3. `npm run build` green (prebuild: `check:aahp` = `npx --no-install aahp check .` [changelog + format + version-sync + claims + forbidden-patterns + schema-doc-sync + doc-links] + `check:feed` + `check:handoff`; CI also runs `aahp doctor` for conformance)
4. `npm test` green
5. One commit (code + docs + handoff) on a release branch
6. Open a PR, wait for protected `Build and Test` and `aahp-verify`, then squash-merge
7. Pull the merged `main`, tag that exact commit as `vX.Y.Z`, and push the tag
8. CI publishes to npm via OIDC, creates the GitHub Release, and fast-forwards the `v5` branch

## Detection Rule Conventions

- Each rule has a unique `rule` ID: `CATEGORY_DESCRIPTION` (SCREAMING_SNAKE_CASE)
- Categories: `NPM_`, `PYPI_`, `GHA_`, `VSCODE_`, `LOCKFILE_`, `BINARY_`, `BEACON_`, `SOLANA_`, `CAMPAIGN_`
- Severity levels: `critical`, `high`, `medium`, `low`, `info`
- Every rule must have a corresponding test case (positive + negative)

## Acceptance Criteria Lifecycle

Every implementation task, and every issue an adapter links to one, carries one
canonical **Acceptance criteria** section written as task boxes.

1. Use exactly `Acceptance criteria` as a Markdown heading or bold label.
   `Completion criteria` and `Definition of done` are legacy aliases only.
2. Use `- [ ]` while a criterion is unresolved. Plain bullets are not criteria.
3. Change a box to `- [x]` only when a commit, PR, test run, or live
   verification supplies evidence.
4. Before a task becomes `done`, every criterion is checked, explicitly waived
   as `(waived: rationale)`, or moved to an open linked follow-up such as
   `(follow-up: T-042)` or `(follow-up: #123)`.
5. Record closure evidence in NEXT_ACTIONS.md's Recently Completed Resolution
   field, including any waiver or follow-up.
6. When tasks are mirrored to GitHub issues, reconcile the same boxes before
   closing the issue and record the closing evidence.
7. `aahp criteria` is an advisory report that always exits zero for findings.
   Review upholds the lifecycle; a clean report is not proof of completion.

## Handoff Protocol

Doc roles: **STATUS.md** is one hand-maintained snapshot of current state. Rewrite
stale facts in place; do not append session notes or use it as a history log.
**MANIFEST.json tasks** is the authoritative machine-readable task graph.
**NEXT_ACTIONS.md** is its concise hand-curated backlog view and its "Current
version" header must equal package.json. **DASHBOARD.md, TRUST.md and LOG.md are
GENERATED** and must never be hand-edited. DASHBOARD/TRUST come from committed
repository inputs plus explicit time-bound verification records in the generator;
LOG.md is the release journal from CHANGELOG.md.

Enforcement (nothing here relies on remembering): the AAHP content-drift gate forces
STATUS.md + MANIFEST.json on every code change, and `check:handoff` (prebuild) regenerates
and diffs DASHBOARD/TRUST/LOG **and** fails if NEXT_ACTIONS.md's version header is behind.

After completing any task:

1. Rewrite STATUS.md so it contains only the current snapshot and live decisions.
2. Update MANIFEST.json tasks and NEXT_ACTIONS.md when task state or backlog changed.
3. Run `npm run handoff:refresh` to regenerate DASHBOARD.md, TRUST.md, LOG.md and
   MANIFEST.json metadata.

LOG.md is NO LONGER hand-appended. It is a generated release journal derived from
CHANGELOG.md, so it cannot silently drift - the old "append every session" convention
lapsed unnoticed across v5.3.0-v5.17.3; the pre-generation hand-authored entries are
preserved in LOG-ARCHIVE.md. Detailed rationale remains recoverable from CHANGELOG.md,
LOG-ARCHIVE.md and git history.
