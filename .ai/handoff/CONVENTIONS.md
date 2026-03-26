# supply-chain-guard: Agent Conventions

> Every agent working on this project must read and follow these conventions.
> Update this file whenever a new standard is established.

---

## Language

- All code, comments, commits, and documentation in **English only**
- Use clear, direct language in handoff files (agents are the primary readers)

## Code Style

- **TypeScript:** strict mode, explicit types, no `any` except where unavoidable
- **Imports:** Node.js built-ins use `node:` prefix (e.g. `import * as fs from "node:fs"`)
- **JSON:** 2-space indentation, no trailing commas
- **Markdown:** ATX headers, tables with alignment, code blocks with language tags
- All modules use ES module syntax (`import`/`export`), not CommonJS

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
- All version bumps: `package.json` + README badge + CHANGELOG + handoff STATUS.md + MANIFEST.json

## Release Checklist

1. All tests pass (`npm test`)
2. Build succeeds (`npm run build`)
3. Version bumped in `package.json`, README, CHANGELOG, STATUS.md, MANIFEST.json
4. Commit: `chore: bump version to vX.Y.Z`
5. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
6. GitHub Release created via `gh release create`
7. npm published: `npm publish --access public`
8. Stale feature branches deleted

## Detection Rule Conventions

- Each rule has a unique `rule` ID: `CATEGORY_DESCRIPTION` (SCREAMING_SNAKE_CASE)
- Categories: `NPM_`, `PYPI_`, `GHA_`, `VSCODE_`, `LOCKFILE_`, `BINARY_`, `BEACON_`, `SOLANA_`, `CAMPAIGN_`
- Severity levels: `critical`, `high`, `medium`, `low`, `info`
- Every rule must have a corresponding test case (positive + negative)

## Handoff Protocol

After completing any task:

1. Update `STATUS.md` (current version, open issues)
2. Update `DASHBOARD.md` (component status, test counts)
3. Add an entry to `LOG.md` (what was done, decisions made)
4. Update `NEXT_ACTIONS.md` (re-prioritize remaining tasks)
5. Update `MANIFEST.json` (version, last_session, task statuses)
