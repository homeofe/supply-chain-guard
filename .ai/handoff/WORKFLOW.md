# supply-chain-guard: Autonomous Multi-Agent Workflow

> Based on the [AAHP Protocol](https://github.com/homeofe/AAHP).
> Agents read `DASHBOARD.md` and `NEXT_ACTIONS.md` and work autonomously.

---

## Agent Roles

| Agent | Model | Role | Responsibility |
|-------|-------|------|---------------|
| Implementer | claude-sonnet-4.6 | Implementer | Code, tests, refactoring, commits |
| Reviewer | claude-sonnet-4.6 | Reviewer | Second opinion, edge cases, security review |
| Researcher | perplexity/sonar-pro | Researcher | CVE research, attack pattern research, SBOM/SARIF specs |

---

## The Pipeline

### Phase 1: Pick a Task

```
Reads:   NEXT_ACTIONS.md (top unblocked task)
         DASHBOARD.md (current build state)
         STATUS.md (current version, open issues)
         CONVENTIONS.md (coding standards)

Does:    Identifies the highest-priority unblocked task
         Checks MANIFEST.json for task dependencies
         Reads the full task description
```

### Phase 2: Implement

```
Reads:   Relevant source files in src/
         Existing test files for patterns and fixtures

Does:    Implements the task (code + tests)
         Runs npm test to verify all tests pass
         Runs npm run build to verify TypeScript compiles
         Commits on a feature branch: feat/issue-N-description
```

### Phase 3: Update Handoff

```
Updates: STATUS.md   (a top-of-file note; the hand-maintained living state doc)
         LOG.md      (append-only: what was done, decisions made)
         NEXT_ACTIONS.md (backlog, only if it changed)

Runs:    npm run handoff:refresh                  (regenerates DASHBOARD.md + TRUST.md
                                                    from live data; do NOT hand-edit them)
         bash scripts/aahp-manifest.sh . \
           --agent <id> --phase <phase>           (regenerates MANIFEST.json)
```

The AAHP gate (aahp-verify.yml) enforces STATUS.md + MANIFEST.json on any code change.

### Phase 4: Release (on version bump tasks only)

```
Does:    (Authoritative, gated process is in the repo-root CLAUDE.md.)
         Adds a README ## Changelog entry for the new version
         Bumps the version in package.json, package-lock.json, src/cli.ts, and
           src/reporter.ts (text header + SARIF + SBOM + HTML footer) -- the
           check:changelog + check:version-sync prebuild gates enforce this
         Updates STATUS.md + regenerates MANIFEST.json (AAHP gate)
         One commit, then git tag vX.Y.Z (after the commit)
         git push origin main && git push origin vX.Y.Z
         CI does the rest on the tag: OIDC npm publish (no NPM_TOKEN),
           GitHub Release, and fast-forward of the floating v5 branch
```

---

## Pipeline Rules

- **Pick the top unblocked task** from NEXT_ACTIONS.md (check `depends_on` in MANIFEST.json)
- **Blocked task** → skip, take next unblocked
- **All tasks blocked** → notify project owner
- **Notify project owner** only on fully completed tasks (not mid-task)
- **Never skip tests** -- `npm test` must pass before committing
- **Main-branch policy:** dependabot uses PRs; day-to-day maintenance (docs, threat-intel
  IOCs, dependency bumps, releases) commits directly to main per CLAUDE.md. Every commit
  must still build and pass the AAHP gate.
- **Each commit must build** -- broken builds block the CI publish pipeline

---

## Working with the Codebase

### Adding a new scanner module

1. Create `src/<platform>-scanner.ts`
2. Export a main function: `export async function scan<Platform>(dir: string): Promise<Finding[]>`
3. Wire into `src/scanner.ts` (add to the orchestration logic)
4. Create `src/__tests__/<platform>-scanner.test.ts` with 10+ tests
5. Add entry to DASHBOARD.md component table
6. Update README with usage example

### Adding detection rules

1. Add pattern to `src/patterns.ts` (existing categories) or to the scanner module
2. Rule ID format: `CATEGORY_DESCRIPTION` (SCREAMING_SNAKE_CASE)
3. Add positive test (should detect) AND negative test (should not false-positive)
4. Document in README if user-facing

### Bumping a version

See CLAUDE.md for the full mandatory sequence. All version strings move together
(the `check:version-sync` gate enforces it):
- `package.json` `"version"` + `package-lock.json`
- `src/cli.ts` (`.version(...)`)
- `src/reporter.ts` (text header, SARIF, SBOM, HTML footer)
- `README.md` `## Changelog` entry (the `check:changelog` gate enforces it)
- `.ai/handoff/STATUS.md` note + regenerated `MANIFEST.json`

---

## Context Budget

| Load | Files | Approx tokens |
|------|-------|---------------|
| Minimal (task pick) | MANIFEST.json | ~200 |
| Normal (implementation) | MANIFEST + STATUS + NEXT_ACTIONS + CONVENTIONS | ~2000 |
| Full context | All handoff files | ~5000 |
| Deep dive | All handoff + relevant src files | ~15000+ |

Start with minimal context, load more only as needed.
