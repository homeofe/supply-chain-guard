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

### Phase 3: Merge & Update Handoff

```
Does:    Opens PR, merges to main (squash)
         Deletes feature branch

Updates: STATUS.md (if version changed)
         DASHBOARD.md (component status, test counts)
         NEXT_ACTIONS.md (move task to completed, re-prioritize)
         LOG.md (what was done, decisions made)
         MANIFEST.json (last_session, task status)
         TRUST.md (mark newly verified properties)
```

### Phase 4: Release (on version bump tasks only)

```
Does:    Bumps version in package.json, README, CHANGELOG, STATUS.md, MANIFEST.json
         Commits: chore: bump version to vX.Y.Z
         Tags: git tag vX.Y.Z && git push origin vX.Y.Z
         GitHub Release: gh release create vX.Y.Z
         npm: npm publish --access public (or triggered via CI tag)
```

---

## Pipeline Rules

- **Pick the top unblocked task** from NEXT_ACTIONS.md (check `depends_on` in MANIFEST.json)
- **Blocked task** → skip, take next unblocked
- **All tasks blocked** → notify project owner
- **Notify project owner** only on fully completed tasks (not mid-task)
- **Never skip tests** -- `npm test` must pass before committing
- **Never push directly to main** -- use feature branches + PR (unless trivial docs)
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

All of these must change in one commit:
- `package.json` → `"version"`
- `README.md` → npm badge + Changelog section
- `.ai/handoff/STATUS.md` → `## Current Version`
- `.ai/handoff/MANIFEST.json` → `"version"`

---

## Context Budget

| Load | Files | Approx tokens |
|------|-------|---------------|
| Minimal (task pick) | MANIFEST.json | ~200 |
| Normal (implementation) | MANIFEST + STATUS + NEXT_ACTIONS + CONVENTIONS | ~2000 |
| Full context | All handoff files | ~5000 |
| Deep dive | All handoff + relevant src files | ~15000+ |

Start with minimal context, load more only as needed.
