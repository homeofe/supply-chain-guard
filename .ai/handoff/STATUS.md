# supply-chain-guard - Project Status

> Note (2026-07-01, claude-opus-4-8): AAHP protocol fix (Option A). Root cause of the
> doc drift: the content-drift gate only forces STATUS.md + MANIFEST.json, so every other
> handoff doc rotted (DASHBOARD/TRUST sat at v3.1.0 for ~40 releases). Fix: DASHBOARD.md
> and TRUST.md are now GENERATED from live repo data by scripts/aahp-dashboard.mjs
> (`npm run handoff:refresh`) - version, module/test-file counts, audit, and HEAD are
> derived, so there is nothing to hand-maintain or drift. STATUS.md stays the single
> hand-maintained living state doc; NEXT_ACTIONS.md is the one curated backlog; build/test
> pass-fail is left to CI (authoritative). Updated CONVENTIONS + WORKFLOW handoff protocol
> to match.

> Note (2026-07-01, claude-opus-4-8): Closed stale auto-generated issues #30 (T-006
> Cargo/Go scanner) and #31 (T-007 Solana rate-limit handling). Both features were
> already implemented and tested (src/cargo-scanner.ts + src/go-scanner.ts wired into
> scanner.ts; exponential backoff + Retry-After + 429/-32005 handling in
> src/solana-monitor.ts). The issues had been auto-created on 2026-06-28 from AAHP
> manifest tasks that were never flipped off "ready" after the work shipped (v3/v4
> era). Marked T-006 and T-007 "done" in MANIFEST.json so they are not recreated.

> Note (2026-07-01, claude-opus-4-8): Released v5.2.44 - dependency-maintenance release
> that publishes the commander 13->14 runtime bump (plus the TS6 / vitest 4 / @types/node 26
> / vite 8 dev-tree refresh) to npm. Version bumped across package.json, src/cli.ts, and
> src/reporter.ts (text header, SARIF, SBOM, HTML footer); README changelog entry added.
> Maintenance-only: no detection-logic or output-format changes. Tag v5.2.44 triggers the
> OIDC publish + GitHub Release + floating v5 branch fast-forward.

> Note (2026-07-01, claude-opus-4-8): "Update all packages" pass (follow-up to the
> dependabot batch). Removed the now-obsolete esbuild/vite overrides (they patched
> vitest 3's vulnerable transitive tree; vitest 4's tree is clean) and ran
> `npm update` -> everything now at latest within semver: vite 7->8.1.2, esbuild
> refreshed, 0 vulnerabilities. commander stays 14.0.3 (15 is ESM-only + Node
> >=22.12; dependabot ignores >=15). vite 8's stricter oxc parser surfaced a latent
> bug: dependency-confusion.test.ts imported fs+path twice (top + a duplicate
> mid-file block); consolidated all imports at the top and removed the duplicates.
> Build green; 823 tests pass, only the 13 vscode-scanner zip tests fail locally
> (missing `zip` binary; green in CI). No version bump/publish.

> Note (2026-07-01, claude-opus-4-8): Dependabot batch (8 PRs). Landed the safe
> updates and fixed the two that broke `tsc`: typescript 5.7->6.0.3 (added
> "types": ["node"] to tsconfig.json - TS6 no longer auto-includes @types/node,
> which is why console/process/node:* stopped resolving), vitest 3->4.1.9,
> @types/node 22->26, commander 13->14.0.x. Commander was held on the CommonJS
> 14.x line: commander 15 is ESM-only and needs Node >=22.12, incompatible with
> this CJS CLI+library on engines node >=20; dependabot now ignores commander >=15
> (see .github/dependabot.yml, PR #39). GitHub Actions bumped: checkout v4->v7
> (SHA 9c091bb, verified against upstream tag), setup-node v4->v6 (SHA 48b55a0,
> verified), github-script v7->v9, setup-python v5->v6. Build + all
> non-environmental tests green (the 13 vscode-scanner tests fail locally only for
> lack of a `zip` binary; green in CI). No version bump/publish in this commit -
> commander 14 (the only runtime-dep change) ships with the next tagged release.

> Note (2026-06-28, claude-opus-4-8): v5.2.41 security release. github-trust-scanner.ts
> built five `gh api repos/${owner}/${repo}` calls as shell strings via execSync with
> owner/repo unvalidated; analyzeGitHubTrust + parseGitHubUrl are public API, so a
> crafted value could reach shell RCE (continuous swarm review, elvatis/ideabase#24).
> All gh api calls now use execFileSync (no shell); analyzeGitHubTrust + parseGitHubUrl
> validate owner/repo against GitHub-name allowlists (no leading hyphen, no '..').
> Regression tests added. Tagged v5.2.41 -> OIDC publish + v5.

> Note (2026-06-28, claude-opus-4-8): v5.2.40 security release. Remediated the
> first findings from the now-live continuous AAHP Swarm review (elvatis/ideabase
> #24): org-scanner.ts listOrgRepos command injection (gh repo list ${org} via
> string execSync; now execFileSync + org-name allowlist forbidding a leading
> hyphen) and two suppressed-finding leaks (SARIF results + fallback SBOM now
> filter f.suppressed, matching the primary SBOM path). Regression tests added.
> Tagged v5.2.40 -> OIDC publish + v5.

> Note (2026-06-28, claude-opus-4-8): v5.2.39 security release. Remediated findings
> from an AAHP Swarm review of this tool: action.yml GitHub Actions script injection
> (inputs now via env: + quoted bash array; RUNNER_TEMP + random GITHUB_OUTPUT
> delimiter), markdown/HTML injection in the PR-comment report (reporter.ts now
> escapes every attacker-controlled value via mdInlineCode/mdText/mdCell), and the
> hardcoded /tmp in scanner.ts (now os.tmpdir()). Added a markdown-injection
> regression test. Security-reviewed (APPROVE). Tagged v5.2.39 -> OIDC publish + v5.

> Note (2026-06-28, claude-opus-4-8): Gate-consistency fix. Added `.ai/logs/` to
> .gitignore (keeps ephemeral agent log output out of version control) and
> committed the previously-uncommitted NEXT_ACTIONS.md issue-link annotations
> (issue #30, issue #31). Re-synced MANIFEST.json so the committed checksum for
> NEXT_ACTIONS.md matches the committed file. No application code changed.

> Note (2026-06-28, claude-opus-4-8): Added .ai/swarm/profile.md - the public swarm review profile that tells an aahp-swarm what to scrutinize in this scanner (detector bypasses, logic gaps, shell surface, output integrity, prompt-injection).

> Note (2026-06-28, claude-opus-4-8): Security fix, hardened git command execution
> against command injection (found by an aahp-swarm review). scanner.ts cloned a
> GitHub target via string execSync guarded only by startsWith (bypassable with
> shell metacharacters after the prefix), and diff-scanner.ts interpolated an
> unquoted sinceCommit into git diff. Both now use execFileSync (no shell) plus
> strict input validation: a clean GitHub-URL regex for the clone target and a ref
> allowlist for sinceCommit. The git-log anomaly check also moved to execFileSync.
> Added src/__tests__/diff-scanner.test.ts. Build and the affected tests pass.
> Released as v5.2.38 in this commit (tag v5.2.38 triggers the OIDC publish and
> moves the floating v5 branch).

> Note (2026-06-27, claude-opus-4-8): Full AAHP gate onboarded. Added the
> canonical toolchain (scripts/_aahp-lib.sh, scripts/aahp-manifest.sh,
> scripts/lint-handoff.sh, scripts/verify-handoff.sh,
> scripts/validate-pii-allowlist.py), the .github/workflows/aahp-verify.yml
> required-check workflow, the missing canonical handoff files
> (pii-allowlist.json, LOG-ARCHIVE.md, LOG-ARCHIVE.index.json), and an AAHP
> Verify badge in README.md. The handoff state was previously dormant since the
> 2026-03-26 v3.1.0 session; this refresh brings the manifest commit-pointer and
> file index current. No application code changed in this onboarding.

## Current Version: 5.2.38

### Published
- npm: supply-chain-guard@5.2.38 (unscoped, public)
- GitHub: homeofe/supply-chain-guard (Apache-2.0)
- GitHub Marketplace: supply-chain-guard (GitHub Action)
- ClawHub: not published (CLI tool, not an OpenClaw skill)

### Features (v3.0.0)
- 65+ detection rules across 8 categories
- npm package scanning (install scripts, obfuscation, typosquatting)
- PyPI package scanning with install hook detection (subprocess, base64 exec, cmdclass downloads)
- VS Code extension scanning (.vsix analysis)
- GitHub Actions workflow scanner (CI/CD pipeline attacks, unpinned actions, secrets exfiltration, encoded payloads)
- SARIF 2.1.0 output format for GitHub Code Scanning (`--format sarif`)
- Solana C2 wallet watchlist with persistent monitoring and webhook alerts (`watchlist` commands)
- Dependency confusion detection
- Lockfile integrity verification
- Binary/native addon detection (30-entry whitelist)
- Network beacon + crypto miner + protestware detection
- 13 campaign signatures (XZ Utils, Codecov, SolarWinds, ua-parser-js, coa/rc)
- GitHub Action with branding (shield/red)
- CI workflow (build + test on push/PR, auto-publish to npm on v* tags)
- Blog post reference and quickstart guide in docs/

### Architecture
- CLI entry: src/cli.ts (commander-based)
- Core scanner: src/scanner.ts
- Detection modules: src/detectors/*.ts
- GitHub Action: action.yml + src/action.ts

### Open Issues
- dependabot: picomatch 4.0.3 -> 4.0.4 (low priority)

### Known Limitations
- PyPI scanning requires local package download (no remote API)
- VS Code extension scanning needs .vsix file on disk
- No real-time monitoring (scan-based only)

> 2026-06-30 ci: add Dependabot config (per-repo ecosystems) + exempt Dependabot from the aahp-verify handoff gate.
