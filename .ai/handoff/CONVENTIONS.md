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

### Branch hygiene: the invariant is three-sided

A finished deploy leaves exactly `main` and `v5`. That is a statement about the
REMOTE **and** the local checkout **and** the worktree list. Checking only
`git ls-remote` has twice reported clean while stale local branches survived.

```
git ls-remote --heads origin   # only main and v5
git branch --list              # only main
git worktree list              # only the shared checkout, on main
```

Two mechanics make the local side fail silently:

- `git worktree add -b <branch>` creates a local branch that outlives BOTH the
  worktree and the merge. It has survived `--delete-branch` on every PR cut this
  way.
- A local branch still held by a worktree makes the merge command's local delete
  fail, and the REMOTE branch then survives while the error names only the local
  one. Remove the worktree BEFORE merging.

### Verifying a branch is safe to delete

Every PR here is squash-merged, so `git branch --merged`, `git cherry` and
`git rev-list main..branch` all report merged work as UNMERGED. Never delete on
those. Ask GitHub first:

```
gh pr list --state all --search "head:<branch>" --json number,state,mergedAt
git log <branch> -1 --format=%cI     # keep it if the tip is NEWER than mergedAt
```

**Normalise the timezones before comparing.** `--format=%cI` prints a local
offset while GitHub returns UTC, so a naive string compare reads an older tip as
newer and wrongly keeps the branch.

**A repository-wide tree diff does NOT answer this**, and both obvious forms
mislead:

- `git diff main <branch>` is non-empty whenever the branch is merely BEHIND
  main. A branch missing one daily feed sweep shows well over a thousand changed
  lines and is still perfectly safe to delete.
- `git diff main...<branch>` (three-dot) shows the branch's own pre-squash
  commits, which main holds under a different SHA after the squash. It is
  non-empty for a fully merged branch.

Scope the diff to the files the branch itself changed:

```
git diff --stat main <branch> -- <the branch's changed paths>
```

Only version strings and generated feed data should differ. Anything else is
content main does not have, and the branch stays. Confirmed on 2026-08-20:
`fix/npm-scanner-lifecycle-hooks` showed 25 changed lines repo-wide and, scoped
to its own files, differed by exactly two version-string lines.

The one real loss case is a commit made after the merge, which no PR knows
about. The tip-versus-`mergedAt` check above is what guards it.

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
- All version bumps move together (enforced by the `version-sync` gate inside
  `check:aahp`) across every
  version site in `aahp.config.json`. CHANGELOG.md, STATUS.md and the generated
  handoff set move with the release. See CLAUDE.md for the authoritative sequence.

## Release Checklist

The repo-root **CLAUDE.md** is the authoritative, gated release process. Summary:

1. CHANGELOG.md entry: a new `## [X.Y.Z] - date` block below `## [Unreleased]` in
   Keep a Changelog format (no `v` in brackets, `### Added/Changed/Fixed` sections,
   reference-link footer), gated by `check:aahp`. Also repoint the `[Unreleased]`
   compare link at the file foot to `compare/vX.Y.Z...HEAD`: it is gated by the
   schema-doc-sync group and is NOT a versionSite, so step 2 never reaches it
2. Version bumped everywhere (see Versioning above), including `package.json`
   itself, then `npm install --package-lock-only`: npm rewrites the lockfile's
   version fields only at install time, so an edit-based bump leaves it behind
3. `npm run feed:generate` and `npm run handoff:refresh`. Neither is optional and
   neither is implied by step 2. `feed.json` embeds the version, so `check:feed`
   goes red on EVERY bump and not only when threat intelligence changed, and it is
   deliberately not a versionSite so `check:aahp` says nothing about it. This step
   was rediscovered by hand on four consecutive releases before being written down
4. `npm run build` green. Its prebuild runs three groups: `check:aahp`
   (`scripts/check-aahp-pin.mjs`, then `npx --no-install aahp check .`, covering
   changelog presence and format, version-sync, claims, forbidden-patterns,
   schema-doc-sync and doc-links), `check:feed` and `check:handoff`. CI also runs
   `aahp doctor` for conformance.
   The pin preflight is not decoration: `npx --no-install` suppresses a DOWNLOAD but
   still resolves a globally installed `aahp` on PATH, so a checkout with a missing
   `node_modules` ran a different version of the governance CLI and printed
   `Governance OK`. Observed on 2026-08-20 with a global 3.8.0 against a 3.9.2 pin.
5. `npm test` green
6. One commit (code + docs + handoff) on a release branch
7. Open a PR, wait for the THREE protected contexts, then squash-merge.
   `Build and Test` (from `ci.yml`, an aggregator over the Node lanes and the
   container smoke job), `aahp-verify` (from `aahp-verify.yml`) and
   `PR metadata policy` (from `pr-metadata-policy.yml`). Exactly one workflow
   produces each name; two producers for one context means whichever finishes
   last defines it. `enforce_admins` is true, so none of them can be bypassed
8. Pull the merged `main`, tag that exact commit as `vX.Y.Z`, and push the tag
9. CI publishes to npm via OIDC, creates the GitHub Release, and fast-forwards the `v5` branch

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
