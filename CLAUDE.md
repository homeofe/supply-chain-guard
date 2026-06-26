# Supply-Chain-Guard - Claude Notes

This file is automatically loaded into every Claude Code session. It is the single reliable source of project-wide rules - memory entries are not active in every session.

## Release Process (mandatory)

Every release MUST follow this order. If `npm run build` fails because `check:changelog` is red, do NOT bypass it - add the missing entry.

1. **Update README.md** - new `### vX.Y.Z (YYYY-MM-DD)` block at the very top of `## Changelog`, with title and bullet list. Style: follow previous entries.
2. **SECURITY.md** - keep the Supported Versions table up to date (only for new Major/Minor).
3. **CONTRIBUTING.md** - only when new modules or files are added.
4. **Bump version** in `package.json`, `src/cli.ts`, internal constants in `src/reporter.ts` (text header, SARIF, SBOM, HTML footer) - all at the same time. The `check:version-sync` gate (see step 6) catches any that are missed.
5. **Update tests** that check old output format. Tests that only check the version should read `pkg.version` from `../../package.json` rather than hardcoding it - see `reporter.test.ts`.
6. **`npm run build`** must be green - runs `check:changelog` AND `check:version-sync` as `prebuild`. The first gates against a missing README entry, the second against forgotten version bumps in `cli.ts` and `reporter.ts`.
7. **`npm test`** must be green.
8. **One commit** for everything (code + docs + tests).
9. **`git tag vX.Y.Z`** AFTER the commit.
10. **`git push origin main && git push origin vX.Y.Z`** - CI creates the GitHub Release.

## GitHub Action Distribution (v5 Branch + Marketplace)

The Action is used via `uses: homeofe/supply-chain-guard@v5` (README). Important:

- **`v5` is a BRANCH, not a tag.** It is a floating major-ref that always points to the latest v5.x.y release. Branches are allowed to move - this does NOT violate the "never move tags" rule. The CI (`update-major-branch` job in `ci.yml`) fast-forward-pushes it on every tag release (no `--force`). Nothing needs to be done manually.
- **The Action is `composite`** (`action.yml`) and runs `npm install -g supply-chain-guard` at runtime. It does NOT need a committed `dist/` (dist is gitignored). The `v5` branch only needs to contain `action.yml`.
- **Marketplace publishing is NOT automatable.** GitHub gates it behind a web UI checkbox ("Publish this Action to the GitHub Marketplace") in the Release edit view. There is no `gh` flag, no REST/GraphQL endpoint, no official Action. `gh release create` (our CI) NEVER publishes to the Marketplace. Do NOT build an unofficial cookie/session hack into CI - that would itself be a supply-chain risk. The Marketplace dropdown is purely a discovery UI; the Action runs on the latest version via `@v5` regardless. To update the listing: manually tick the checkbox once in the Release edit view.

## Hard Rules

- **Always defang IOCs.** Domains, subdomains, URLs, and IPs from threats are NEVER written raw in docs, README, commits, PRs, or chat. Format:
  - Domain: `example[.]com` instead of `example.com`
  - URL scheme: `hxxps://` / `hxxp://` instead of `https://` / `http://`
  - IPv4: `1[.]2[.]3[.]4` instead of `1.2.3.4`
  - Email: `user[@]example[.]com`
  - SHA-256 / MD5 remain raw (not clickable)
  - **Exceptions** (stay functional): own project links (`github.com/homeofe/...`, `blog.elvatis.com`, npmjs.com badges) and code in `src/` (values there are compared, not displayed)
  - **Reason:** otherwise external scanners / crawlers can collect the raw-documented IOCs as legitimate hits or trigger clicks
- **Never move tags.** For fixes always create a new patch version (e.g. 5.2.13 -> 5.2.14). No `git tag -f`, no `git push --force` on tags.
- **No em-dashes** (`—`) in docs or commits. Always use a normal hyphen (`-`) or colon (`:`). Also applies to new changelog entries - older entries in the README still have em-dashes, do not perpetuate them.
- **Never bypass hooks or signatures** (`--no-verify`, `--no-gpg-sign`) without explicit permission. If `prebuild` is red, that is the task, not the obstacle.

## Historical Drift (why this file exists)

The release process has broken down multiple times; each time a gate script closed the gap:

**README changelog lagging behind tags:**
- Commit `6d0e887` - backfill for v5.2.5 through v5.2.7
- Backfill for v5.2.9 through v5.2.13
- Consequence: `scripts/check-changelog.mjs` wired in as `prebuild`.

**Version strings out of sync across files:**
- v5.2.14: `src/reporter.ts` on 5.2.14, `reporter.test.ts` still on "v5.2.8" -> npm publish failed (build job red).
- v5.2.17: `src/reporter.ts` on 5.2.17, `reporter.test.ts` still on "v5.2.16" -> npm publish failed (build job red, publish skipped).
- Consequence: `scripts/check-version-sync.mjs` wired in as a second `prebuild`. Plus: `reporter.test.ts` now reads `pkg.version` instead of hardcoding the string, so it can no longer drift.

Do not rely on memory or a checklist alone - the build must gate against both the docs AND cross-file consistency.
