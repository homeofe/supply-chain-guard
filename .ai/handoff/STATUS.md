> Note (2026-07-21): fix(scan) - the scan command now tears down Node's global HTTP/HTTPS
> keepAlive agents on the clean-scan return path, so pooled npm/PyPI registry sockets close
> and the CLI self-terminates instead of hanging. On Node <=22 free keepAlive sockets stay
> referenced, which stalled shared CI runners for hours on clean/low scans; the critical,
> high and --fail-on exit paths are unchanged. Added src/__tests__/scan-self-exit.test.ts.
> Version bumped to 5.17.7 across the 6 version-sync sites plus CHANGELOG; tag v5.17.7 to
> publish (npm via OIDC) and move the @v5 branch.

> Note (2026-07-20, claude-opus-4-8): Released v5.17.6 - daily threat-intel refresh
> (scheduled task). Fetched arena.elvatis.com/news (/api/news JSON feed gives excerpts +
> per-item source links; pulled the linked The Hacker News article and cross-checked the
> StepSecurity writeup for indicators) and added SleeperGem (StepSecurity + Aikido,
> 2026-07-20). Three gem releases published to RubyGems.org on 2026-07-18/19 act as
> loaders: each fetches a second stage (deploy.sh + a native binary) from an attacker
> account on a public Forgejo instance, checks ~30 CI env vars (GITHUB_ACTIONS, GITLAB_CI,
> CIRCLECI, ...) and exits if any is set so it only detonates on developer laptops, then
> drops a native daemon, cron + systemd-user persistence and - with passwordless sudo - a
> setuid root shell. Added 7 version-pinned ruby: FeedIOCs: git_credential_manager
> 2.8.0/2.8.1/2.8.2/2.8.3, Dendreo 1.1.3/1.1.4, fastlane-plugin-run_tests_firebase_testlab
> 0.3.2. Dendreo and the fastlane plugin are REAL long-lived gems that lay dormant for
> years before the malicious update, so they are version-pinned on purpose - a bare-name
> IOC would flag every clean install (a negative test asserts this). Only
> git_credential_manager (a pure impersonation of Microsoft's Git Credential Manager, no
> legitimate history) is also anchored by name in MALICIOUS_PACKAGE_PATTERNS. Payload host
> ingested as the URL PATH git[.]disroot[.]org/git-ecosystem only: the bare host is a
> legitimate public Forgejo instance and deliberately stays OUT of KNOWN_C2_DOMAINS. Two
> campaign patterns: SLEEPERGEM_PAYLOAD_HOST + SLEEPERGEM_SETUID_SHELL
> (/usr/local/sbin/ping6 - the real ping6 never lives there). The daemon dir
> ~/.local/share/gcm is deliberately NOT a signature: the real Git Credential Manager uses
> it too. No hashes, IPs or wallet addresses were disclosed by either source, so none were
> invented. Other feed items reviewed: ViteVenom (v5.17.3) and NadMesh (v5.17.5) were
> already covered; the 7-Zip / ServiceNow / wp2shell / NGINX items are CVEs with no
> package-registry IOCs. Known gap surfaced while writing the tests: `.rb` is not in
> SCANNABLE_EXTENSIONS, so Ruby source files are never content-scanned - the two new
> campaign patterns only fire on other extensions (tests use .js/.sh, following the
> existing .php/.c precedent). Logged as a follow-up, not fixed here (changing scan scope
> is out of band for a threat-intel refresh). feed.json regenerated (394 entries). Rebased
> onto PR #63/#64 (aahp 3.8.1 re-pin) before pushing; MANIFEST regenerated after the
> rebase. Build gates + aahp check 7/7 + doctor 6/6 green; tests pass (only the 14
> vscode-scanner zip tests fail locally on Windows for lack of a `zip` binary - green in CI).

> Note (2026-07-19, claude-opus-4-8): Review alignment for PR #63 (chore/aahp-conformance).
> Applied the reviewer's grammar fix in the AAHP-cleanup note below ("the follow-up that the
> previous note flagged"). Corrected a stale claim in the PR description: homeofe GitHub Actions
> is ON. The org-wide Actions cost sweep applied to elvatis private repos, not homeofe public
> repos, so the "Actions is OFF org-wide" line in the maintainer follow-up was wrong and is
> removed. No canonical AAHP v3.8.0 template wording (GROUNDING.md, WORKFLOW.md, TRUST.md
> structure) and no TRUST.md provenance placeholders were changed: those are the source of truth
> and provenance was not established in this mechanical conformance PR. MANIFEST checksums
> refreshed via the pinned CLI. Build tooling only, no version bump.

> Note (2026-07-18, claude-opus-4-8): AAHP conformance cleanup (CLI-based) - completed the
> follow-up that the previous note flagged: switched the CI handoff gate to the pinned CLI and
> de-vendored the redundant gate scripts. .github/workflows/aahp-verify.yml now runs
> `npx --no-install aahp verify . --level ci` + `npx --no-install aahp doctor . --json`
> (npm ci --ignore-scripts; Python kept for the Layer 1 pii-allowlist check) instead of
> `bash scripts/verify-handoff.sh`. The CLI is self-contained (it runs its own bundled
> scripts from the installed package root, not the repo copy), so the local copies were
> redundant: DELETED scripts/verify-handoff.sh, scripts/lint-handoff.sh,
> scripts/install-hooks.sh, scripts/verify-hooks.sh, scripts/hooks/pre-commit,
> scripts/hooks/pre-push. KEPT scripts/aahp-manifest.sh + scripts/_aahp-lib.sh: the
> SCG-local aahp-dashboard.mjs (still the SCG-owned DASHBOARD/TRUST/MANIFEST/LOG generator)
> spawns aahp-manifest.sh, and the repo copy is customized (preserves the MANIFEST
> "project" name on regen, which the stock 3.8.0 copy does not). Verified: aahp verify
> --level full + aahp doctor both green (6/6 gates); check:handoff + check:aahp + check:feed
> still pass. Build tooling only, no version bump.
> Note (2026-07-19, claude-opus-4-8): Released v5.17.5 - daily threat-intel refresh
> (scheduled task). Fetched arena.elvatis.com/news (/api/news JSON feed gives excerpts +
> per-item source links; pulled the linked The Hacker News articles for indicators) and
> added the NadMesh botnet (XLab, 2026-07-17). NadMesh is a Go-based botnet that scans for
> exposed AI services (Ollama/vLLM/etc.) and CI/CD hosts, harvesting AWS keys and Kubernetes
> tokens (operator claimed 3,811 unique AWS keys). Added XLab's three published indicators:
> C2 domain cdnorigin[.]net -> KNOWN_C2_DOMAINS, C2 IP 209[.]99[.]186[.]235 -> KNOWN_C2_IPS,
> and the agent-sample SHA1 31c69b3e12936abca770d430066f379ec1d997ec -> KNOWN_MALICIOUS_HASHES
> (XLab published a SHA1, not MD5/SHA256; stored as a content-reference indicator, matched by
> the same substring check as the existing Nx Console Git-SHA entry). All three also added as
> domain/ip/hash FeedIOC entries in BUNDLED_FEED. No package IOCs - this is a scanning botnet,
> not a poisoned registry package. New "NadMesh botnet (July 2026)" campaign test block (3
> tests: domain, IP, hash each -> critical). Other feed items reviewed: ViteVenom was already
> added in yesterday's v5.17.3; ACR Stealer (ClickFix lures) and the Contagious Interview SVG-
> steganography item carried no concrete blocklist-actionable IOCs in their source articles (a
> Slack username only), so nothing was invented. feed.json regenerated (386 entries). Build
> gates + AAHP green; tests pass (only the 14 vscode-scanner zip tests fail locally on Windows
> for lack of a `zip` binary - green in CI).

> Note (2026-07-18, claude-opus-4-8): Step 2 Stages 2+3 - rewired prebuild to the AAHP package
> gates and retired the redundant local copies. prebuild is now `check:aahp` (`npx --no-install
> aahp check .` = changelog + changelog-format + version-sync + claims + forbidden-patterns +
> schema-doc-sync + doc-links, all config-driven from aahp.config.json) + `check:feed` (SCG
> product) + `check:handoff` (SCG's DASHBOARD/TRUST/MANIFEST/LOG generator - the package generate
> only does LOG+freshness). DELETED the 4 now-redundant local scripts: check-changelog.mjs,
> check-version-sync.mjs, check-claims.mjs, check-changelog-format.mjs. CI build job now runs
> `npx --no-install aahp doctor . --json` (conformance: handoff set, MANIFEST schema, grounding,
> exact-version pin). README got an "AAHP conformant" badge (versionless on purpose - a static
> version badge would be the ungated-version drift this session fought; the CI doctor check keeps
> the claim true). Verified: new prebuild green (aahp check 7/7 + feed + handoff); adversarially
> confirmed the package version-sync still guards src/scanner.ts (break it -> aahp check fails ->
> release pipeline still protected); doctor 6/6; tests green. Build tooling only, no version bump.
> STILL SCG-local: aahp-dashboard.mjs (DASHBOARD/TRUST/MANIFEST/LOG generation) + check:feed + the
> vendored handoff gate (verify-handoff.sh/_aahp-lib.sh/aahp-manifest.sh/lint-handoff.sh). A later
> cleanup could switch the handoff gate to `npx aahp verify` and de-vendor those too.

> Note (2026-07-18, claude-opus-4-8): Step 2 Stage 1 - supply-chain-guard now CONSUMES AAHP
> as a pinned dependency (@elvatis_com/aahp@3.8.0, exact devDependency, zero transitive deps).
> Added aahp.config.json mapping SCG onto the v3.8 config schema: 6 versionSites (incl.
> src/scanner.ts), 3 claims (rules 350+/correlation 15+/categories 12) with new floorCmd
> helpers scripts/count-rules.mjs + scripts/count-correlation.mjs (ground-truth counts, run
> by the package's check-claims with no shell), a doc-scoped em-dash forbiddenPattern, a
> severity-enum docSync, docLinks, check.skip:["handoff"] (SCG keeps its own handoff
> generation), and a pinnedDep assertion. Verified: `npx aahp check .` = 7/7 governance gates
> PASS (full parity with SCG's local gates); `npx aahp doctor` = all 6 conformance gates PASS.
> Closed the two doctor gaps found: moved ARCHITECTURE.md out of .ai/handoff/ -> docs/ (it was
> a stray not in AAHP's canonical file set -> handoff-set gate), and added a Provenance COLUMN
> to the generated TRUST.md (the grounding gate needs a table column, not the prose section
> SCG had). Stage 1 is ADDITIVE: prebuild STILL runs SCG's local gates unchanged - the package
> gates run in parallel as proven parity. Stage 2 rewires prebuild/CI to `aahp check` (one
> command replaces the four local gate scripts); Stage 3 retires the redundant locals. DASHBOARD/
> TRUST/MANIFEST generation + check:feed stay SCG-local (the package generate only does LOG+freshness).

> Note (2026-07-18, claude-opus-4-8): Release v5.17.4 - fix a stale tool-version drift a
> user reported. src/scanner.ts hardcoded TOOL_VERSION="5.2.0" (many releases stale), which
> the JSON reporter emits verbatim as ScanReport.tool and persists into .scg-history/, so
> `scan --format json` reported v5.2.0 while text/SARIF/SBOM/HTML/GitLab were correct. Root
> cause: check:version-sync did not include scanner.ts. Fix (option b, matching the repo's
> gate-against-drift pattern): bumped TOOL_VERSION to the release version AND added
> src/scanner.ts to check-version-sync.mjs's required list so it can never drift undetected
> again. Chose (b) over "import from package.json" because tsconfig rootDir:"src" makes a
> ../package.json import break the build, and reporter.ts already establishes hardcoded+gated
> as the repo pattern. This is also the first REAL release on the new Keep a Changelog pipeline
> (validated end-to-end in simulation last session). Full ceremony: all version sites -> 5.17.4,
> KaC CHANGELOG entry + reference link, feed + handoff regenerated.

> Note (2026-07-18, claude-opus-4-8): Migrated CHANGELOG.md to Keep a Changelog + SemVer
> (the fleet standard) and added a `check:changelog-format` prebuild gate (reference-consumer
> step 2). All 92 release headings converted `### vX.Y.Z (date)` -> `## [X.Y.Z] - date`
> (no `v` in brackets), added `## [Unreleased]` + a 93-line reference-link footer; historical
> prose bodies preserved verbatim (not force-fit into sections - that would rewrite shipped
> notes). The gate enforces R1-R9 (heading grammar shared with the LOG generator, ISO dates
> not-in-future, strict SemVer descent, top==package.json, reference links, no BOM, section
> vocab where used). Retargeted the three CHANGELOG consumers to the new heading: ci.yml
> release-notes awk (now index()-based - gawk mangled the `\[` string-regex), check-changelog.mjs,
> and the LOG generator. Also fixed a live bug the migration exposed: the LOG generator stripped
> one `*` off `**headline**` prefixes (headlines rendered as `*Threat intel...`); strip bold
> before the bullet-strip. Verified: awk extracts the full v5.17.3 block, LOG shows all 92 clean,
> gate catches a future-dated entry. Release process docs (CONVENTIONS.md + local CLAUDE.md)
> updated to the new format.

> Note (2026-07-18, claude-opus-4-8): Adopted AAHP's Grounded Reflection Layer (v3.3.0),
> which this repo had been missing entirely - making supply-chain-guard the reference
> consumer for it. Added .ai/handoff/GROUNDING.md (the two-axis status x provenance model +
> task-type anchor matrix, canonical AAHP doctrine) and .ai/handoff/.aiignore (firewall
> config). Added GROUNDING.md to AAHP_HANDOFF_FILES in _aahp-lib.sh so it is checksummed in
> MANIFEST like the other handoff files. Added a Provenance section to the generated TRUST.md
> (via aahp-dashboard.mjs) recording that every structural fact is tool_verified/test_verified
> by the deterministic gates. Context: this is part of the fleet-consistency plan - the org's
> drift comes from repos running frozen copies of AAHP; the fix (decided this session) is to
> consume AAHP as a pinned dependency, standardize on Keep a Changelog, and prove conformance
> here first. Grounding layer is step 1; changelog migration + schema validation follow.

> Note (2026-07-18, claude-opus-4-8): AAHP handoff hardening - closed the drift class in
> the handoff docs themselves. LOG.md had silently lapsed across v5.3.0-v5.17.3 (the
> "append every session" convention was never gated, only STATUS + MANIFEST were). Fixes:
> (1) LOG.md is now GENERATED from CHANGELOG.md by scripts/aahp-dashboard.mjs (a release
> journal, all 92 releases), gated by check:handoff exactly like DASHBOARD/TRUST, so it
> cannot drift; the pre-generation hand entries were moved to LOG-ARCHIVE.md (+ index).
> (2) Added a FRESHNESS gate to check:handoff: NEXT_ACTIONS.md's "Current version" header
> must equal package.json (the drift that let it sit on v5.6.0). (3) ARCHITECTURE.md was
> not just stale but WRONG (described a src/detectors/ layout that was refactored to flat
> src/*-scanner.ts long ago); rewritten to stable prose + a pointer to the generated
> DASHBOARD for the live module list, so it can't re-rot. (4) CONVENTIONS.md + WORKFLOW.md
> updated so they no longer document the retired hand-append duty. Net: every handoff doc
> is now either generated-and-gated or (STATUS/NEXT_ACTIONS) gated for freshness - nothing
> hand-maintained-but-unchecked remains.

> Note (2026-07-18, claude-opus-4-8): The GitHub repo About/description field (was stale
> "180+" + "SLSA verification") is GitHub metadata, not a repo file, so no check:* can
> reach it. Canonical About text now lives in `.github/repo-about.txt`, an in-repo file
> whose "350+" IS pinned by check:claims; the field itself was corrected out-of-band to
> "350+ / SLSA provenance grading". CI AUTO-SYNC IS NOT POSSIBLE with the default
> GITHUB_TOKEN: there is no `administration` permission key for it (repo settings/admin is
> not a grantable GITHUB_TOKEN scope), so `gh repo edit --description` cannot authorize.
> My first attempt added `administration: write` to the ci.yml release job, which made the
> WHOLE workflow file invalid and briefly red-lined main CI (commit ed92584); reverted in
> the next commit (ci.yml restored byte-identical to 15314b9). To automate this, a PAT
> secret with repo-admin / fine-grained "Administration: write" is required - left as a
> maintainer decision. Until then: manual one-liner `gh repo edit homeofe/supply-chain-guard
> --description "$(cat .github/repo-about.txt)"` (source is gated, so the number is safe).
> npm/Marketplace descriptions self-heal on the next publish - no action needed.

> Note (2026-07-18, claude-opus-4-8): Added a `check:claims` prebuild gate
> (scripts/check-claims.mjs) that pins the hand-authored capability numbers to ONE
> canonical value across every LIVE surface, the way check:version-sync pins the version.
> Canonicals: rules/indicators "350+", correlation rules "15+", categories "12"; the
> first two are honesty-checked against ground truth computed from src (373 distinct
> rule-IDs, 19 CORRELATION_RULES) so an advertised floor can never overstate the code.
> This closes the drift class behind the "180+ vs 350+" report: the same fact was copy-
> pasted across README/package.json/docs/mcp.md/src/mcp-server.ts with nothing comparing
> them, so the earlier "350+" rollout silently left src/mcp-server.ts on "200+" (now
> fixed to "350+"). Historical files (CHANGELOG.md, this STATUS footer's v3.0.0 snapshot)
> are excluded by design - they are checksummed history, not accuracy-gated. External
> surfaces (GitHub About, npm/Marketplace) cannot be gated by any check:* (not repo
> files); About sync-on-release + publish-lag self-heal are the plan, pending maintainer OK.

> Note (2026-07-18, claude-fable-5): Untracked CLAUDE.md from the repo and added it
> to .gitignore. It is local Claude Code / agent instructions (release-process
> reminders + hard rules), NOT public project content, and should never be committed
> again; the working-tree file is kept locally (untracked) so local sessions still read
> it. The commit-attribution rule (no Co-Authored-By trailer) now lives ONLY in the
> global ~/.claude/CLAUDE.md, not in this repo. History was deliberately NOT rewritten:
> purging CLAUDE.md from all history would rewrite every commit SHA, orphan every
> release tag, and break the npm/SLSA build provenance that attests to specific commit
> SHAs (a force-push of public main), while not un-publishing an already-public file -
> left as the maintainer's informed decision.

> Note (2026-07-18, claude-fable-5): Trust/authorship housekeeping (no release).
> Added a "Development and review" disclosure to CONTRIBUTING.md (AI-assisted under
> maintainer review; every change reviewed + tested, detection changes adversarially
> reviewed, every release commit SSH-signed/Verified, maintainer accountable). Set the
> repo commit-attribution policy in CLAUDE.md Hard Rules: do NOT append a Co-Authored-By
> trailer to commits - AI assistance is disclosed once in CONTRIBUTING rather than
> per-commit (the per-commit "and claude committed" read as noise). Signing stays
> mandatory. Note for scope: the trailer is commit-message text, not a git config -
> the daily OpenClaw routine already omits it; this CLAUDE.md rule stops Claude Code
> sessions from re-adding it in THIS repo. Enforcement ruleset (require signed commits
> on main) remains offered-but-not-enabled pending the maintainer's go.

> Note (2026-07-18, claude-fable-5): Trust hardening (no release). (1) Added the
> "scanned by supply-chain-guard" self-badge to the README badge row (dogfood trust
> signal). (2) Set up SSH commit signing on the dev machine so every commit gets the
> GitHub "Verified" badge going forward: reused the existing passphrase-free
> ~/.ssh/id_ed25519 key (automation-safe - the daily OpenClaw routine's unattended
> commits sign too), configured globally (gpg.format ssh, user.signingkey,
> commit.gpgsign, tag.gpgsign) + a gpg.ssh.allowedSignersFile for local verification.
> Verified locally: "Good git signature". THIS commit is the first signed one. It (and
> all future commits) show Verified on GitHub only AFTER the pubkey is registered as a
> SIGNING key on the homeofe account - the gh token lacks write:ssh_signing_key scope so
> that one-time step is the maintainer's (web UI or `gh auth refresh -s
> write:ssh_signing_key` then POST /user/ssh_signing_keys). Enforcement (branch
> protection requiring signed commits) is deliberately NOT enabled yet - it would reject
> the automation's pushes until the key is registered. Prior commits stay unsigned (SSH
> signatures verify retroactively once the key is added; unsigned ones cannot be
> back-signed without history rewrite, which we do not do).

> Note (2026-07-17, claude-fable-5): Released v5.17.2 - FALSE-POSITIVE fix
> (user-reported). A user ran `npm install -g supply-chain-guard` then
> `scan .` on a checkout of THIS repo and got ~597 THREAT_INTEL/IOC matches.
> Not a compromise: the scan was matching the tool's OWN threat database
> (threat-intel.ts/ioc-blocklist.ts/test fixtures carry malicious IOCs by
> design). Root cause: self-scan suppression keyed ONLY on isOwnPackageRoot
> (scanned path == the RUNNING binary's package root) - true for node dist/cli.js
> from the repo (self-scan 0/0) but false for a global install scanning a
> separate checkout, so the guard no-opped and flagged its own signatures. Fix:
> added isOwnSourceCheckout(scanDir) - recognizes the checkout by package.json
> identity (name "supply-chain-guard" AND repository homeofe/supply-chain-guard),
> OR'd into scanningOwnPackage. Spoof-gated: the recognition unlocks only the
> narrow IOC-string suppression for the exact SELF_SCAN_INERT_FILES paths;
> checkFilePatterns (malware/obfuscation) still runs on every file, so no payload
> hides by forging the name. Empirically: a full repo copy (incl.
> .supply-chain-guard.yml) now scans 0/0 like the real self-scan; a third-party
> project embedding the same IOC still flags; a name-only spoof still flags. 3
> regression tests (self-scan-recognition.test.ts, added to SELF_SCAN_INERT_FILES).
> Full suite green.

> Note (2026-07-17, claude-fable-5): Released v5.17.1 - MCP registry metadata +
> honest npm description (growth: highest-leverage listing prep). Added mcpName
> ("io.github.homeofe/supply-chain-guard") to package.json and a repo-root server.json
> (schema 2025-12-11, verified live) so the MCP server can be published to the official
> registry (registry.modelcontextprotocol.io) - PulseMCP/Glama/mcp.so auto-ingest from
> it. The npm package must carry mcpName for the registry's npm-ownership check, hence
> a release rather than an uncommitted file. server.json pins the version twice and is
> now covered by check:version-sync so it cannot drift from the published package on
> future releases. Also fixed the package.json description overclaim ("verifies SLSA
> provenance" -> "grades SLSA provenance (in-toto/DSSE structural validation)") - the
> README was corrected in v5.15.0 but the npm description still carried the stale
> wording. To publish: `mcp-publisher login github` + `mcp-publisher publish` (needs a
> homeofe org member; server.json + published mcpName are now in place). Full suite
> green; self-scan 0/0.

> Note (2026-07-17, claude-fable-5): Released v5.17.0 - reachability/ecosystem
> interop (code-side growth items). (1) `feed osv` CLI + new module src/osv-export.ts
> (toOsvRecords/parsePackageValue, exported from the library API): exports the feed's
> malicious-package IOCs as OSV-schema records (npm/Go/RubyGems/Packagist/crates.io/
> NuGet; domain/ip/url/hash + non-OSV ecosystems like jenkins skipped), so the feed is
> consumable by osv-scanner and shaped toward ossf/malicious-packages. Deterministic
> (ids + timestamps derive only from the entry, SHA-256-suffixed ids, sorted). Bare
> name -> all-versions ECOSYSTEM range; name@version -> pinned version. 282 records
> from the current bundled feed, all OSV-required fields present (empirically verified
> via the CLI). 6 tests. (2) "scanned by supply-chain-guard" adopter badge in the
> README (viral loop). Small additive output code (not the scan pipeline), so shipped
> on the full battery + empirical CLI proof rather than a multi-agent gate; self-scan
> 0/0. A background research agent is producing the external LISTING PLAYBOOK
> (awesome-lists, MCP directories, ossf contribution format) for the awesome-list PRs +
> web-form submissions - those are handled separately from this code release.

> Note (2026-07-17, claude-fable-5): Released v5.16.0 - starjacking detection,
> completing the differentiators track (R4-B) and all four tracks of the gap-analysis
> push. In `npm <pkg>` mode, checkRepositoryClaim corroborates a package's claimed
> `repository`: fetches the repo's root package.json (raw.githubusercontent HEAD,
> 10s timeout + 5MB bound, never throws) and emits STARJACKING_SUSPECTED (medium)
> ONLY for the borrowed-trust case - the repo publishes a different, unrelated
> package and is not a monorepo containing this one. Deliberately FP-conservative:
> skips non-GitHub hosts, repository.directory, scope==owner, workspaces/private
> roots, pnpm-workspace.yaml/lerna.json manifests, unfetchable/related/generic-name
> cases. A 3-lens adversarial gate (dominant lens: false positives) confirmed 1
> should-fix, fixed pre-tag: monorepo detection originally read ONLY package.json
> `workspaces`, so pnpm/lerna/nx monorepos (and all-generic names like @x/core) were
> mis-flagged - hardened with scope-owner + private-root + generic-name + workspace-
> manifest guards (the gate's exact @acme/core -> acme/platform FP now skipped;
> evil-wallet -> expressjs/express true positive still fires). My proactive socket-
> timeout fix was implicitly validated (not flagged). 15 tests; full suite green,
> self-scan 0/0. All 4 tracks now shipped: v5.12.4 (threat-intel), v5.13.0 (detection
> gaps), v5.14.0 (product/DX), v5.15.0 + v5.16.0 (differentiators).

> Note (2026-07-17, claude-fable-5): Released v5.15.0 - honest SLSA provenance
> validation (R4 provenance half of the 4-track gap-analysis push; built directly,
> the crypto being too subtle to hand off). The verifier previously treated a file
> merely NAMED provenance.json as proof (empty {} scored L3; README claimed "verifies
> SLSA provenance"). New parseAttestation reads + structurally validates the
> attestation (in-toto Statement / DSSE base64 payload / Sigstore bundle -> requires a
> SLSA predicateType + >=1 digested subject); getSLSALevel now uses .valid not mere
> existence; cosign.pub (a public key) no longer counts. New rule SLSA_PROVENANCE_INVALID
> (medium) for a present-but-malformed provenance file; a valid NON-SLSA in-toto
> attestation (SBOM/SPDX predicate) is legit and NOT flagged. README overclaim fixed
> to "grades SLSA provenance (in-toto/DSSE structural validation)"; full crypto
> signature/Rekor/Fulcio verification documented as follow-up. A focused adversarial
> review confirmed 3 (2 should-fix + 1 nit), all fixed pre-tag: no MAX_FILE_SIZE bound
> on the attestation read (now statSync-guarded like every other scanner; oversized
> skipped, E2E), false positive flagging legit non-SLSA attestations as malformed
> (now kind-aware: slsa/non-slsa-attestation/malformed), doubled phrase in the message.
> extractInTotoStatement recursion depth-bounded against crafted nesting. 27 slsa
> tests; self-scan 0/0, our repo still L3 (npm-native path). REMAINING from the 4-track
> push: R4-B tarball-vs-repo starjacking diff (its own focused release next).

> Note (2026-07-17, claude-fable-5): Released v5.14.0 - product/DX (R3 of the
> 4-track gap-analysis push; worktree agent, integrated + gated + fixed here).
> Path-scoped policy: ignore: globs prune the walk, per-path suppress (rule +
> optional path: glob), inline // scg-ignore-next-line RULE (+ # form) suppress the
> next source line; minimal built-in glob matcher (commander stays only runtime
> dep). Fixed the DEAD allowlist.domains key (parsed + documented but applyPolicy
> only used allowlist.packages) - now suppresses THREAT_INTEL_MATCH/IOC_KNOWN_C2
> for an allowlisted domain/subdomain; githubOrgs honestly documented as
> parsed-but-not-enforced (stderr note) rather than left silently dead. JUnit XML
> (--format junit) + -o/--output. MCP v2: compact report carries line+recommendation
> (maxFindings param), scan_directory takes since, ioc_lookup gained indicator mode
> (domain/url/ip/hash). action.yml no longer double-scans. Adversarial gate confirmed
> 1 should-fix, fixed pre-tag: matchGlob compiled "**/" to bare ".*", so
> ignore:["**/vendor.js"] silently dropped notvendor.js from scanning and per-path
> suppress over-suppressed lookalikes - now "**/" requires the segment boundary
> ((?:.*/)?), 12 boundary cases proven. Also fixed on integration: two R3 test files
> use the real Vidar C2 domain as fixtures -> added to SELF_SCAN_INERT_FILES.
> testFiles 77; self-scan 0/0. R4 (sigstore provenance + starjacking) still to ship.

> Note (2026-07-17, claude-fable-5): Released v5.13.0 - detection-coverage gaps
> (R2 of the 4-track gap-analysis push; built by a worktree agent, integrated +
> gated + fixed here). (1) Cargo.lock + go.sum are now parsed and matched against
> the feed (CARGO_MALICIOUS_CRATE / GO_MALICIOUS_MODULE + checkBadVersion, which
> gained a "cargo" ecosystem) - both files were recognized but never opened, so
> the bundled crates.io/Go IOCs could NEVER match; proven E2E (move-analyzer-build
> crate + BufferZoneCorp go module both fire via the real CLI). (2) New module
> python-lockfile-scanner.ts: poetry.lock/uv.lock/Pipfile.lock -> KNOWN_BAD_PYPI +
> feed. (3) skills-scanner now covers MEMORY.md/AGENTS_MEMORY.md/memory/*.md/
> .claude/memory/*.md/.specstory/**. Adversarial gate confirmed 1 should-fix, fixed
> pre-tag: scanPipfileLockContent only scanned default/develop, missing pipenv
> custom category groups (docs/tests/ci) - a bad pkg pinned there escaped; now
> iterates all top-level package maps except _meta (E2E re-proven). go-scanner.test
> added to SELF_SCAN_INERT_FILES (its go.sum fixture uses the real BufferZoneCorp
> IOC). 63 src modules (was 62), testFiles 77. feed.json 376; self-scan 0/0.

> Note (2026-07-17, claude-fable-5): Released v5.12.4 - threat-intel (part of a
> larger gap-analysis-driven push). Two primary-source-verified campaigns.
> PhantomSync (npm crypto stealer, Xygeni, 2026-07-15): SINGLE-SOURCE so confidence
> 0.85; 8 generic blockchain-util names version-pinned (base58-utils malicious at
> 1.0.0/1.0.1/1.0.3 but NOT 1.0.2) in KNOWN_BAD_NPM_VERSIONS + feed; gist config
> dead-drop + 3 IPFS CIDs in KNOWN_DEAD_DROPS (gateway hosts NOT blocked).
> Pepesoft (NuGet game-cheat surveillance, Socket, 2026-07-14): the 11 package IDs
> are a source-side "-x-x" REDACTION placeholder (absent from a full mirror), NOT
> installable IDs - so NO package blocklist entries (a redacted ID blocks nothing;
> a guessed one false-positives). Detection rides on 31 primary-source SHA-256
> payload hashes (KNOWN_MALICIOUS_HASHES) + network infra (3 C2 sub-hosts, proxy IP,
> Telegram/GitHub/HuggingFace/Discord-webhook paths) - specific sub-hosts/paths only,
> never the workers.dev/selcloud.ru/discord.com/huggingface.co apex. A dedicated IOC
> verification agent caught both the redaction placeholder and the base58-utils-1.0.2
> exception before ingest. 7 campaign tests incl. FP guards; feed.json 376 entries;
> self-scan 0/0. Digest-78 cluster (wagni_bot/FauxUV/mcp-server-pg) deferred to a
> follow-up refresh (needs the same primary-source verification). This is R1 of a
> 4-track build (R2 detection gaps, R3 product/DX, R4 differentiators still to ship).

> Note (2026-07-17, claude-fable-5): Dependency maintenance - resolved all 3 open
> dependabot PRs. #62 (actions/setup-node 6 -> 7) squash-merged after verifying
> the pinned SHA 820762786026740c76f36085b0efc47a31fe5020 matches the upstream
> v7.0.0 tag. #59 (typescript 6.0.3 -> 7.0.2, MAJOR) + #58 (@types/node 26.1.1)
> superseded by one combined local bump: TS7 compiles this codebase with ZERO
> changes, full suite 1249 pass (14 zip-only Windows fails), self-scan 0/0.
> Systemic finding: EVERY dependabot npm PR now fails the check:handoff CI gate
> (dependabot bumps package.json but cannot run handoff:refresh, and DASHBOARD.md
> derives from package.json) - npm-dep PRs need the local combined-bump route
> until the gate is made dependabot-tolerant.

> Note (2026-07-14, claude-opus-4-8): Synced the canonical AAHP gate scripts from homeofe/improvements (v3.5.0 fixes: aahp-manifest.sh --phase documentation + cross_repo_ref preservation, lint-handoff.sh SC2034), AAHP_HANDOFF_FILES preserved, and refreshed the local hook tooling (scripts/hooks/, install-hooks.sh, verify-hooks.sh). Fleet re-sync.

> Note (2026-07-14, claude-opus-4-8): Synced the canonical Layer 3 tolerance fix from homeofe/improvements. verify-handoff.sh now downgrades a non-ancestor MANIFEST.last_session.commit from FAIL to WARN so a squash-merge or rebase-merge no longer trips AAHP Verify Layer 3 on main; Layers 1-2 still gate real staleness.

# supply-chain-guard - Project Status

> Note (2026-07-16, claude-opus-4-8): Released v5.12.3 - daily threat-intel refresh
> (scheduled task). Fetched arena.elvatis.com/news (/api/news JSON feed gives
> excerpts + per-item source links) and added the AsyncAPI npm supply-chain
> compromise (2026-07-14). Five malicious versions across four @asyncapi packages
> were published to npm during a ~4h window (07:10-11:18 UTC on 2026-07-14),
> delivering a credential-stealing multi-stage botnet loader that pulls a second
> stage from IPFS and speaks C2 over HTTP / Nostr / IPFS / BitTorrent DHT / libp2p
> GossipSub / an Ethereum smart contract; all five have since been unpublished.
> The exact package versions were confirmed against two independent primary reports
> (The Hacker News and BleepingComputer, both citing OX Security / SafeDep / Socket /
> StepSecurity). Added @asyncapi/generator@3.3.1, @asyncapi/generator-helpers@1.1.1,
> @asyncapi/generator-components@0.7.1, and @asyncapi/specs@6.11.2 / 6.11.2-alpha.1 as
> version-pinned KNOWN_BAD_NPM_VERSIONS + BUNDLED_FEED entries (legitimate packages, so
> bare names are NOT blocked). Added the specific IPFS second-stage CID
> (ipfs[.]io/ipfs/QmQobZSp1w...) as a KNOWN_DEAD_DROPS entry - the exact CID path only,
> never the ipfs[.]io gateway, so legitimate IPFS usage is not flagged. No file hashes,
> C2 domains, or IPs were disclosed in the reports, so none were invented. New "AsyncAPI
> npm compromise (July 2026)" campaign test block (4 tests, incl. a clean-version FP
> guard). Other feed items reviewed (Starland RAT / LabubaRAT / OkoBot / "300 fake
> GitHub repos" carried no concrete version-pinned package IOCs or disclosed
> domains/IPs/hashes in the feed). feed.json regenerated (355 entries). Build gates +
> AAHP green; tests pass (only the 14 vscode-scanner zip tests fail locally for lack of
> a `zip` binary - green in CI).

> Note (2026-07-13, claude-opus-4-8): Released v5.12.2 - daily threat-intel refresh
> (scheduled task). Fetched arena.elvatis.com/news (/api/news JSON feed gives
> excerpts + per-item source links; pulled the linked The Hacker News article and
> cross-checked BleepingComputer / Socket / Aikido / crypto.news for the exact
> indicators) and added the Injective Labs SDK npm compromise (2026-07-08 to 07-10).
> The Injective Labs SDK GitHub repo was compromised and its OIDC trusted-publisher
> pipeline abused to publish @injectivelabs/sdk-ts@1.20.21 with "fake telemetry"
> that captures wallet private keys + mnemonic seed phrases when SDK key
> generation/import functions run, base64-encodes them, and HTTPS-POSTs to
> testnet.archival.chain.grpc-web.injective[.]network. 1.20.21 was also pinned
> across 17 dependent @injectivelabs packages (18 total; ~310 downloads before
> deprecation); clean version is 1.20.23. Added all 18 as version-pinned
> KNOWN_BAD_NPM_VERSIONS + BUNDLED_FEED entries (legitimate packages, so bare names
> are NOT blocked), the full-specific exfil hostname to KNOWN_C2_DOMAINS (NOT a broad
> injective[.]network block, so legit SDK endpoints like sentry.chain.grpc-web...
> are not flagged), and the two SHA-256 infostealer-file hashes to
> KNOWN_MALICIOUS_HASHES + BUNDLED_FEED. New "Injective SDK npm compromise" campaign
> test block (5 tests, incl. a 1.20.23-clean FP guard). The compromised GitHub
> account was a legitimate contributor (a victim), so it is deliberately NOT added to
> the malicious-account list. Other feed items reviewed (jscrambler@8.14.0 already
> covered in v5.12.1; Ghostcommit/HalluSquatting/Ghost-accounts are research/technique
> writeups with no version-pinned package IOCs). feed.json regenerated (349 entries).
> Build gates + AAHP green; 1245 tests pass (only the 14 vscode-scanner zip tests fail
> locally for lack of a `zip` binary - green in CI).

> Note (2026-07-12, claude-opus-4-8): synced canonical AAHP gate scripts from homeofe/improvements (adds the realpath-relative PII validator invocation that fixes the Windows/MSYS artifact; AAHP_HANDOFF_FILES preserved).

> Note (2026-07-12, claude-opus-4-8): Fixed the recurring "AAHP Verify" Layer 1 failure on deploy. handoff:refresh (aahp-dashboard.mjs) now regenerates MANIFEST.json in lockstep with DASHBOARD.md + TRUST.md via aahp-manifest.sh, and check:handoff (prebuild) now also verifies the manifest checksums (CR-stripped, matching aahp_checksum), so a version bump can no longer leave the manifest stale and surface only in CI.

> Note (2026-07-11, claude-fable-5): Released v5.12.0 - issue #54 hardening, the
> follow-up GPT-5.6-Sol/codex filed after PR #55. (1) FILE_TOO_LARGE_SKIPPED
> (info): core/VSIX/npm/PyPI scanners surface every oversized scannable file
> instead of silently continue-ing past it (attacker can pad a payload over the
> 5 MB limit to dodge content scanning); helper makeOversizedSkipFinding in
> patterns.ts next to MAX_FILE_SIZE; never affects exit codes; oversized body is
> never read. (2) Threat-intel indicator contract: values are LITERALS. The old
> compile at threat-intel.ts (only dots escaped) meant a hostile feed value "("
> threw SyntaxError per file, swallowed by scanner.ts's per-file catch =
> detection silently degraded while the scan exited GREEN (worse than a crash);
> a valid "(a+)+b" would ReDoS. Now: full metachar escaping + per-value compile
> cache + never-throw fallback. (3) Type-aware quarantine (isValidFeedIOC,
> IOC_VALUE_SHAPES) at ALL 3 ingestion points (parseFeedPayload hard-reject,
> updateThreatFeed filter-before-write, loadThreatIntel filter-on-load) - found
> via the E2E proof: a structurally-valid literal "(" would otherwise
> literal-match every file containing a paren (FP flood). npm/pypi walkers
> exported (scanExtractedNpmFiles/scanExtractedFiles) for network-free
> regression tests. 16 new tests (issue-54-hardening.test.ts + 1 vsix test,
> which raises the Windows zip-failure count 13 -> 14, CONTRIBUTING updated).
> E2E-proven via real CLI: hostile cache entry fully quarantined, legit domain
> still matches, big.js surfaced, eval detection intact, self-scan 0/0. A
> 3-lens adversarial gate then BLOCKED the candidate with 6 confirmed findings,
> all fixed pre-tag: charset-only ip/url shapes let degenerate flood values
> (ip ".", url "(") critical-match every file (now IPv4/IPv6 structure + 8-char
> url floor, E2E re-proven); unbounded domainRegexCache (MCP server memory
> growth - now cleared at 10k); severity/confidence unchecked (NaN scores -
> now enum+range gated); skills-scanner readSmallFile silent-skip (now emits
> FILE_TOO_LARGE_SKIPPED, 5th family); unbounded attacker string in the feed
> reject error (now sliced). New test file uses REAL bundled IOC values, so it
> joined scanner.ts's exact-path test allowlist (the PR #55 mechanism). Also in
> this release: PR #55 codex hardening reaches npm (landed after v5.11.1
> published), docker/login-action 4.4.0 (#52, SHA-verified), vitest pair 4.1.10
> (supersedes #50/#51). 1240 tests pass locally (14 zip-only fails).

> Note (2026-07-11, claude-fable-5): Dependency maintenance - resolved all 3 open
> dependabot PRs. #52 (docker/login-action 4.3.0 -> 4.4.0) squash-merged after
> verifying the pinned SHA af1e73f918a031802d376d3c8bbc3fe56130a9b0 matches the
> upstream v4.4.0 tag. #50 + #51 (vitest / @vitest/coverage-v8 4.1.9 -> 4.1.10)
> are peer-coupled and their PR checks were 5 days stale (ran against a v5.6.2-era
> base), so instead of two sequential rebase cycles they were superseded by ONE
> combined local bump keeping the pair consistent; both PRs closed with a comment.
> Full suite on the new state (incl. the just-merged codex PR #55 hardening):
> 1226 tests pass, only the 13 known Windows-only vscode-scanner zip failures.

> Note (2026-07-11, codex): Issue #53 security hardening is ready for review.
> All VSIX, npm, and PyPI archive extraction now goes through one argv-only
> helper that resolves paths before invoking unzip/tar, preventing both shell
> metacharacter execution and leading-dash option injection. IOC and protestware
> self-scan suppression is now gated by the package's physical real path and an
> explicit exact relative-path allowlist; arbitrary reporter/test-style target
> paths are scanned. Added focused regressions; build, lint, self-scan (0/100,
> 0 findings), 43 focused tests, and all 1,225 non-zip-dependent tests pass.
> The 13 legacy VSIX integration tests remain Windows-environment-only failures
> because this host has no zip binary; CI on Ubuntu provides zip.


> Note (2026-07-09, claude-opus-4-8): Post-v5.11.1 repo hygiene (no release, no
> shipped-artifact change - docs/ and Dockerfile are not in the npm tarball).
> (1) The self-scan had flagged 2 INVISIBLE_UNICODE runs in docs/superpowers/plans/
> 2026-07-08-gitlost-agentic-workflow-defense.md: a Unicode-Tags smuggling demo and
> a copy of INVISIBLE_RUN_REGEX that both embedded LITERAL invisible chars. Since
> the detector is a raw byte scan with no code-fence awareness, literal ``` fencing
> would NOT have suppressed it; replaced the literal invisibles with their `\u`
> escape notation (codepoint-identical, now readable and copy-pasteable, matches
> patterns.ts:71 style). Self-scan is back to a true 0/100, 0 findings. (2) Fixed a
> stale Dockerfile comment that still said `node:20-alpine` while both FROM stages
> have pinned `node:22-alpine` since v5.6.1 (a maintainer following the comment's
> `imagetools inspect node:20-alpine` would have inspected the wrong image).
> Audit closed: the npm-12/Node-20 breakage was confined to the CI publish step
> (fixed in v5.11.1); demo.yml, aahp-verify.yml, action.yml, the Dockerfile and the
> devcontainer are all either on Node 22 or on Node 20 without `npm@latest`, and the
> v5.11.1 pipeline ran green end-to-end, so nothing else was broken.

> Note (2026-07-09, claude-opus-4-8): Released v5.11.1 - CI publish-job infra fix.
> The v5.11.0 tag built + tested green but its publish job died at "Upgrade npm for
> OIDC trusted publishing": `npm install -g npm@latest` now resolves to npm 12.0.0,
> which requires Node >=22 and hard-fails EBADENGINE on the Node 20 publish runner
> (npm 12 shipped after yesterday's v5.10.0 release and dropped Node 20). So v5.11.0
> never reached npm and the GitHub Release + `v5` fast-forward were skipped with it.
> Fix: pinned the OIDC npm upgrade to `npm@11` (OIDC-capable since 11.5.1 AND
> Node-20-compatible) instead of floating `npm@latest`, with a comment to bump it
> together with node-version if the runner ever moves to Node 22+. No application
> code changed - v5.11.1 carries the full v5.11.0 payload (Paysafe/Skrill/Neteller
> IOCs + the MALICIOUS_DEPENDENCY dir-scan rule) to npm. Build gates + AAHP green;
> 1222 tests pass (13 vscode-scanner zip tests fail locally for lack of `zip`).

> Note (2026-07-09, claude-opus-4-8): Released v5.11.0 - fake Paysafe / Skrill /
> Neteller payment-SDK campaign (Socket, 2026-07-08). 17 typosquat packages
> published ~2026-07-07 impersonate non-existent official payment SDKs: they
> expose the expected APIs but return fake success responses and exfiltrate every
> env var matching KEY/SECRET/TOKEN/PASS/AUTH/API (Paysafe + AWS keys, GitHub + npm
> tokens) via HTTPS POST to an ngrok tunnel. Added 13 npm names (paysafe-checkout/
> -vault/-js/-api/-node/-cards/-fraud/-kyc/-payments, skrill, skrill-sdk,
> skrill-payments, neteller) + 4 PyPI names (incl. the PyPI-only paysafe-sdk, which
> is pattern-covered, NOT in the npm-scoped feed) to MALICIOUS_PACKAGE_PATTERNS /
> PYPI_TYPOSQUAT_PATTERNS (anchored, exact-name) and to the bundled feed; the exact
> exfil C2 caliber-spinner-finishing[.]ngrok-free[.]dev to KNOWN_C2_DOMAINS (a
> specific subdomain, not a broad ngrok-free[.]dev block, so no FP on legit
> tunnels). NEW detection surface: a directory scan now flags dependency NAMES in
> package.json that are exact known-malicious feed IOCs (rule MALICIOUS_DEPENDENCY),
> so scanning your own repo catches a bad dependency - previously only the
> `npm <pkg>` and install-guard paths did (matchBareNpmIOC exported from
> install-guard, reused in scanner.ts). A self-scan during verification CAUGHT a
> false positive from the first cut: reusing the broad MALICIOUS_PACKAGE_PATTERNS
> heuristics (which flag "any unknown-scope scoped package") mis-flagged our own
> @vitest/coverage-v8; switched to exact feed-IOC matching, self-scan confirms zero
> FP. Empirically proven end-to-end: dir-scan flags the fake deps, install-guard
> blocks (exit 2), MCP ioc_lookup returns malicious. feed.json regenerated (327
> entries). Build green; 1222 tests pass (only the 13 vscode-scanner zip tests fail
> locally for lack of a `zip` binary - green in CI). Pre-existing, unrelated: the
> self-scan surfaces 2 INVISIBLE_UNICODE findings in docs/superpowers/plans/
> 2026-07-08-gitlost-agentic-workflow-defense.md (a committed v5.10.0 planning doc,
> not touched here); logged in NEXT_ACTIONS. No new module, so 61 src modules
> unchanged; testFiles 73.

> Note (2026-07-07, claude-opus-4-8): Released v5.9.0 - opt-in registry version-drift
> detection (--check-registry), implementing the future-work item deferred in v5.8.0.
> Compares the local package.json version against the npm registry 'latest' dist-tag and
> flags REGISTRY_VERSION_DRIFT_MAJOR (medium) when the audited source is a major behind
> what npm installs (e.g. TencentDB source 0.3.6 vs npm latest 1.0.0 - the code you review
> is not what you install). Opt-in + offline-safe: no network call without the flag; the
> fetch resolves null on any error/timeout/non-200 (never throws); same-major minor lag and
> source-ahead dev builds are intentionally not flagged (benign). Lives in
> publishing-anomaly-detector.ts: evaluateVersionDrift (pure) + injectable fetchNpmLatest +
> checkRegistryVersionDrift, wired through ScanOptions.checkRegistry / cli --check-registry /
> scanner.ts (next to the pypi-confusion network block). 10 new tests, none touching the
> wire; verified live against the real registry (source 1.0.0 vs npm 5.8.0 -> medium). No new
> module (functions added to an existing one), so 60 src modules unchanged; testFiles 71.
> Build green; 1190 tests pass (only the 13 vscode-scanner zip tests fail locally for lack of
> a `zip` binary - green in CI).

> Note (2026-07-07, claude-opus-4-8): Released v5.8.0 - agent host-runtime patch
> detection, prompted by a maintainer review of TencentDB-Agent-Memory
> (@tencentdb-agent-memory/memory-tencentdb), an OpenClaw agent-memory plugin whose
> postinstall (`bash scripts/openclaw-after-tool-call-messages.patch.sh 2>/dev/null
> || true`) locates the installed OpenClaw runtime and rewrites its dispatch/hook
> files to inject session.messages into after_tool_call - mutating another installed
> package's code at install time, failures silenced. The old install-hook scanner
> emitted nothing for it (no network/exec/env tokens in the hook string). Added:
> (1) INSTALL_HOOK_HOST_RUNTIME_PATCH (high) in install-hook-scanner.ts - fires only
> on a host-runtime target (openclaw/hermes/claude-code/after-tool-call/hookEvent/
> dispatch-*.js or a write into node_modules/<runtime>) COMBINED with a code-mutation
> action (patch/inject/rewrite/sed -i/*.patch.sh); verified NOT to fire on node
> scripts/build.js, npm run build, tsc, patch-package, husky, node-gyp rebuild.
> (2) openclaw-plugin-scanner.ts (new module) - reads openclaw.plugin.json (rare, so
> zero noise on ordinary packages) and surfaces the memory plugin's data posture as
> info/medium: OPENCLAW_PLUGIN_STARTUP_ACTIVATION, OPENCLAW_PLUGIN_AUTOCAPTURE (med),
> OPENCLAW_PLUGIN_EXTERNAL_LLM (med), OPENCLAW_PLUGIN_CLOUD_BACKEND, _TELEMETRY.
> Confirmed end-to-end against a read-only clone (never executed the package):
> INSTALL_HOOK_HOST_RUNTIME_PATCH high + all 5 plugin findings fire. Future work:
> registry version-drift (source 0.3.6 vs npm latest 1.0.0) needs registry metadata
> that local scans avoid - documented, not implemented. 15 new tests; build green;
> 1180 tests pass (only the 13 vscode-scanner zip tests fail locally for lack of a
> `zip` binary - green in CI). 60 src modules.

> Note (2026-07-07, claude-opus-4-8): Released v5.7.0 - GitHub Actions "Cordyceps"
> cross-workflow composition detection, prompted by novee.security's Cordyceps research
> (BleepingComputer, July 2026). A multi-agent gap analysis confirmed the tool covered
> single-file symptoms but MISSED the article's core thesis: our GHA scanner was single-file
> line-by-line regex with no on:-trigger parsing and no producer->consumer dataflow. Added:
> (1) workflow-ast.ts - a zero-dependency structural parser (triggers, top-level + per-job
> permissions, jobs->steps with uses/run/with.ref/with.script/with.name, on.workflow_run.workflows);
> no YAML dep, since a supply-chain tool should not grow its own supply-chain surface.
> (2) workflow-graph.ts + GHA_CROSS_WORKFLOW_ARTIFACT_TRUST - the core cross-file pass:
> a privileged workflow_run consumer that downloads (critical if it executes) an artifact
> from an untrusted PR producer. (3) Trigger-aware single-file rules in github-actions-scanner.ts:
> GHA_PRIVILEGED_TRIGGER, GHA_PWN_REQUEST_CHECKOUT (critical), GHA_GITHUB_SCRIPT_INJECTION,
> GHA_PERMS_WRITE_ALL, GHA_PERMS_DEFAULT_BROAD; broadened GHA_SCRIPT_INJECTION to comment/review/
> discussion. (4) A "Cordyceps CI/CD Composition Attack" correlation incident that compounds
> the symptoms. An adversarial review gate BLOCKED the first candidate with 14 confirmed
> findings, all fixed pre-tag: a correlation false-CRITICAL on ordinary pull_request_target
> bots (now requires a strong signal), plus valid-YAML evasions (bare-dash steps, refs/pull/N
> and matrix/step-output checkout refs, gh run download consumers, quoted "on": keys,
> misindented comments). No IOCs (composition pattern, not malware), so nothing added to the
> feed. 46 new tests; build green; 1165 tests pass (only the 13 vscode-scanner zip tests fail
> locally for lack of a `zip` binary - green in CI); self-scan 0 GHA findings on our own repo.
> 59 src modules.

> Note (2026-07-04, claude-opus-4-8): Released v5.6.2 - daily threat-intel refresh
> (scheduled task). Fetched arena.elvatis.com/news (JS-rendered; pulled the /api/news
> JSON feed + the two source THN articles for indicators) and added two new July 2026
> developer-targeted campaigns, cross-checked against the existing blocklist first:
> (1) Contagious Interview Rollup Polyfill (Lazarus/DPRK, JFrog via THN 2026-07-03) -
> 6 attacker-uploaded npm packages masquerading as Rollup polyfill tooling
> (rollup-packages-polyfill-core, rollup-runtime-polyfill-core,
> rollup-plugin-polyfill-connect, quirky-token, react-icon-svgs, swift-parse-stream)
> + C2 IP 216.126.236.244 (same 216.126.x range as the OtterCookie/Megalodon DPRK
> infra). (2) ChocoPoC Fake PoC Repos (THN 2026-07-02) - data-stealer in fake Python
> PoC repos targeting researchers; PyPI packages skytext/frint (+ same actor's late-2025
> slogsec/logcrypt.cryptography) + upload IP 91.132.163.78. Abused legit services
> (JSONKeeper, Mapbox) deliberately NOT blocked to avoid mass false positives. 12 new
> indicators across ioc-blocklist.ts (IPs), threat-intel.ts (BUNDLED_FEED), patterns.ts
> (MALICIOUS_PACKAGE_PATTERNS + PYPI_TYPOSQUAT_PATTERNS); 4 new campaign tests. feed.json
> regenerated (312 entries). Build green; 1119 tests pass (only the 13 vscode-scanner
> zip tests fail locally for lack of a `zip` binary - green in CI).

> Note (2026-07-03, claude-fable-5): Released v5.6.1 - polish patch. (1) Declined
> dependabot PR #49 (node 20->26-alpine: premature LTS for a security tool's own
> image); bumped the Docker base to node:22-alpine (digest-pinned) and set dependabot
> to ignore node major bumps so it only brings digest/minor refreshes. (2) --format
> gitlab no longer leaks an absolute runner path: location.dependency.package.name
> now mirrors the per-finding file instead of report.target; proven with an
> absolute-path scan (package.names = evil.js/package.json, no path). Updated the
> gitlab reporter test to the corrected semantics. (3) Docs: Jenkins version-pin note,
> Install Guard version-range limitation. Patch-sized surface, so no separate
> multi-agent gate - full battery + the empirical leak proof instead. 1115 tests green,
> self-scan 0/0/0. Roadmap remains 100% shipped.

> Note (2026-07-03, claude-fable-5): Released v5.6.0 - the last two roadmap bets
> (install-time guard + GitLab-native format) plus the 5 v5.5.0 gate should-fixes, all
> built by 4 worktree agents. Gate round 2 BLOCKED the first candidate with 5 confirmed
> findings, all fixed pre-tag: (1) CRITICAL Windows command injection in the install
> guard - the cmd.exe .cmd-shim escaping was single-pass but %* re-parses, so
> `guard npm install 'x"&echo ...&"'` executed arbitrary commands; fixed to cross-spawn
> double-escape and PROVEN closed by re-running the gate's own PoC (old=vulnerable,
> new=safe); (2)+(3) install-verb bypasses: npm typo-aliases (isntall/i/in/...),
> `yarn global add`, and value-taking global flags before the verb all skipped scanning
> - verb detection rewritten; (4) GitLab report name >255 chars fails the v15.2.4 schema
> so GitLab drops the whole report - now capped; (5) stale rev pins - the v5.5.0
> check:version-sync addition caught them automatically this time. 8 new guard
> regression tests incl. the injection escaper. 40 new tests (1115 green), self-scan
> 0/0/0, GitLab output schema-valid. Roadmap is now 100% shipped; NEXT_ACTIONS holds
> only 3 small doc/cosmetic items. 57 src modules.

> Note (2026-07-02, claude-fable-5): Released v5.5.0 - all 8 seeded issues (#40-#47)
> implemented by 5 worktree agents, then gated by a NEW 4-lens adversarial verification
> workflow (security/interaction/cross-env/functionality) that BLOCKED the first
> candidate with 6 confirmed must-fixes, all fixed pre-tag: (1) Docker build died at
> npm ci (prepare script vs. layer order - now --ignore-scripts), (2) badge severity
> inversion (1 critical = yellow "medium" badge while exit code 2 - badge now derives
> from findings summary, MF-2 regression test added), (3) "prepare": "npx tsc" could
> fetch the NAMESQUATTED tsc registry package - now plain tsc, (4) stale rev: v5.4.2
> pre-commit pin - now gate-enforced via check:version-sync, (5) invalid CircleCI
> when: key, (6) README badge recipe froze green on findings (|| true + if: always()).
> Also: DOCKER_NPM_GLOBAL suppression documented (own image installs the locally built
> tarball), dependabot PR #48 merged (upload-artifact 7.0.1, SHA verified). 35 new
> tests (1056 green), self-scan 0/0/0. Gate should-fixes -> NEXT_ACTIONS. The docker.yml
> workflow fires its FIRST real GHCR build on this tag.

> Note (2026-07-02, claude-fable-5): Released v5.4.2 - suppressed-finding leak fix,
> found by the maintainer's own scan of this repo (report said "clean" AND showed a
> 100%-confidence Shai-Hulud incident; second scan raised a phantom RISK_TREND_SPIKE
> 8->51). Root cause: correlateFindings/trust/trend/forecast/governance consumed RAW
> findings before applyPolicy ran (scanner.ts). Fix: policy pass moved BEFORE the
> analytics + a second pass over late-generated findings keeps RISK_TREND_* rules
> suppressible. Bonus: the constant self-scan score of 8 was itself leak residue
> (correlation riskBoost from the two doc-generator suppressions) - the repo now scans
> an honest 0/100 CLEAN. 5 regression tests in bugfix-v5_4_2.test.ts. Same bug class
> as the v5.2.40 SARIF/SBOM leaks; correlation/trend consumers were missed back then.

> Note (2026-07-02, claude-fable-5): Released v5.4.1 - docs patch release so the npm
> package page (the live landing funnel for launch-day traffic) carries the
> PowerShell-safe MCP install instructions. Also untracked + gitignored the .scg-cache/
> runtime feed cache that a live feed-refresh test had briefly committed in 95e9e7a.

> Note (2026-07-02, claude-fable-5): Docs fix - the documented MCP install one-liner
> (claude mcp add supply-chain-guard -- npx -y supply-chain-guard mcp) fails in
> PowerShell: PowerShell consumes the bare -- itself, so the claude CLI sees -y as its
> own option (error: unknown option '-y'). Verified empirically (works in Git Bash,
> fails in PS). Also found the npx form risks first-connect timeouts (cold npx exceeded
> the MCP probe once). README + docs/mcp.md now lead with the shell-agnostic robust
> form: npm install -g supply-chain-guard && claude mcp add supply-chain-guard
> supply-chain-guard mcp (dash-free, no npx cold start), with the npx one-liner kept
> as a bash/zsh alternative + PowerShell note. Blog post patched via OpenClaw to match.
> npm README carries the old command until the next release; fold into v5.4.1.

> Note (2026-07-02, claude-fable-5): Released v5.4.0 - the agentic security suite +
> live threat feed (roadmap Bet 1). Built by 4 worktree-isolated agents, merged with
> only trivial append-point conflicts: (1) mcp-scanner (6 MCP_ rules: malicious server
> packages via IOC feed, C2/http endpoints, secret-to-remote env, tool-description
> injection, unpinned servers), (2) skills-scanner (5 SKILL_/AGENT_ rules over
> .claude/skills, hooks, .cursorrules, copilot-instructions, AGENTS.md, CLAUDE.md;
> FP-tuned: our own repo scans clean), (3) zero-dep MCP server (JSON-RPC/stdio,
> ioc_lookup + scan_directory + scan_npm_package; smoke-tested live: event-stream@3.3.6
> -> malicious), (4) live feed channel (feed.json published + check:feed prebuild gate
> + feed stats/refresh CLI wiring the previously-dormant .scg-cache/threat-feed.json
> consumption). Two merge-time fixes: a conflict-resolution brace slip in cli.ts, and
> the vitest-vs-shebang CRLF import failure (shebang removed, .gitattributes eol=lf for
> .mjs). Dogfooding catch: feed.json's raw IOC values produced 169 phantom criticals -
> fixed PROPERLY for all feed adopters via isInertThreatFeedFile() (strict structural
> schema check, smuggling-resistant, 8 regression tests) + .scg-cache/.scg-history walk
> exclusion. 106 new tests (1030 green), self-scan 8/100 zero findings, NEXT_ACTIONS
> refreshed (bets 2+3 remain). 56 src modules. Post-launch: blog writeup + MCP directory
> listings are manual maintainer steps.

> Note (2026-07-02, claude-fable-5): Released v5.3.0 - ecosystem expansion, the largest
> coverage release since v5.0. Built by 4 parallel worktree-isolated agents, merged with
> zero conflicts: (1) pnpm/yarn-v1/yarn-Berry/bun lockfile support in lockfile-checker
> (reuses existing LOCKFILE_* rule ids; bun.lockb flagged as unauditable binary),
> (2) rubygems/composer/nuget scanners activating the previously-dead ruby:/composer:/
> nuget: package IOCs via a new matchPackageIOC helper in threat-intel.ts (10 new rules),
> (3) fail-closed policy validation (POLICY_UNKNOWN_KEY high on typos like "supress:",
> POLICY_SUPPRESSION_NO_REASON, POLICY_MALFORMED_RULE_ID) + policy-schema.json shipped in
> the npm tarball, (4) .devcontainer (zip preinstalled: all 930 tests green in-container)
> + examples/ (bot-PR gate for Renovate/Dependabot, GitLab CI, GH Action basic) +
> CONTRIBUTING refresh. Also: new-pattern + ecosystem labels created, 8 good-first-issues
> seeded (#40-#47). 94 new tests (917 total green), tsc clean, self-scan 8/100 with zero
> findings. Version 5.3.0 (MINOR per conventions: new scanner modules). 52 src modules.

> Note (2026-07-02, claude-fable-5): Fixed a from-day-one release-notes bug found while
> verifying v5.2.45: the ci.yml awk range /^### vX/,/^### v[0-9]/ starts AND ends on the
> heading line (it matches both patterns), so extraction always yielded one line, head -n -1
> emptied it, and EVERY release ever shipped the fallback "See README/CHANGELOG" text
> instead of real notes. Replaced with a flag-based awk scan (verified: 24-line extraction
> for v5.2.45); retroactively updated the v5.2.45 GitHub Release body via gh release edit
> (notes edit only - the tag was not touched).

> Note (2026-07-02, claude-fable-5): Released v5.2.45 - README adoption package, part 2.
> The CI-rendered demo GIF (240 frames, 165KB, VHS scanning the malicious fixture: risk
> gauges + GlassWorm incident correlation + remediation plan) now sits at the top of the
> README; CHANGELOG.md carries the v5.2.45 entry; versions bumped across package.json,
> lockfile, cli.ts, reporter.ts x4. Self-scan at release: score 8, zero findings (the
> vhs-action info finding disappeared with the Charm-apt switch). Tag v5.2.45 -> OIDC
> publish + GitHub Release + v5 fast-forward. The npm package page now gets the slim
> README with working GIF (npm rewrites relative image paths to raw.githubusercontent).

> Note (2026-07-02, claude-fable-5): README adoption package, part 1 (restructure).
> Executing the ideation roadmap top item: the changelog (63 entries, ~70KB, two thirds
> of the README) moved to CHANGELOG.md; README slimmed 90KB -> ~19KB with a table of
> contents and a fact-checked "How It Compares" section (osv-scanner / Socket / GuardDog /
> Scorecard / npm audit - positioning: we are the malware/behavior/campaign layer, pair
> with a CVE scanner). Gates moved with the changelog in the same commit:
> scripts/check-changelog.mjs and the ci.yml release-notes awk now read CHANGELOG.md;
> CLAUDE.md release process updated (also now documents check:handoff). Added
> assets/demo.tape + .github/workflows/demo.yml (manual VHS render, artifact-only upload -
> a bot push would fail the AAHP gate). Discoverability: GitHub description updated (was
> claiming 3 ecosystems), topics 9 -> 19, npm keywords +4, package.json description synced
> to the 170+ indicator claim. Part 2 = release v5.2.45 with the rendered GIF.
> Dogfooding catch: the pre-commit self-scan surfaced 4 criticals - scripts/
> aahp-dashboard.mjs's doc templates contain "npm publish"/"NPM_TOKEN" strings that
> legitimately trip the Shai-Hulud patterns in a .mjs file (benign-doc exclusion only
> covers .md). Fixed via two documented suppressions in .supply-chain-guard.yml
> (detection stays strict for scanned user projects). Self-scan now 9/100 with one
> honest info finding, later eliminated: vhs-action ffmpeg install proved flaky, replaced
> with vhs from the Charm apt repo - zero third-party actions remain.

> Note (2026-07-01, claude-opus-4-8): Made the generated handoff docs un-drift-able.
> The earlier Option A made DASHBOARD/TRUST generated but still snapshot-on-demand, so
> they could lag if nobody ran the generator. Now the generator emits a PURE function of
> committed files (package.json + tsconfig + src/ list - no timestamps/HEAD/audit), and a
> new `check:handoff` gate (added to `prebuild`, alongside check:changelog +
> check:version-sync) regenerates in-memory and fails the build if the committed docs
> differ. So a stale DASHBOARD/TRUST now turns the build red in CI - it cannot silently
> drift. Verified the gate fails on a corrupted doc and passes when fresh.

> Note (2026-07-01, claude-opus-4-8): Test-hygiene fix. cli.test.ts scanned the
> version-controlled fixture dirs in-place, and the scanner writes a .scg-history/ into
> whatever directory it scans - so every `npm test` run dirtied two tracked fixture files
> (worked around by reverting them all session). Fixed at the root: cli.test.ts now copies
> the fixtures to a temp dir and scans the copy; removed the two tracked fixture
> risk-history.json files; added .scg-history/ to .gitignore. Verified `npm test` now
> leaves the working tree clean.

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

## Current Version: 5.17.3

### Published
- npm: supply-chain-guard@5.17.3 (unscoped, public)
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
- None currently (track via GitHub issues)

### Known Limitations
- PyPI scanning requires local package download (no remote API)
- VS Code extension scanning needs .vsix file on disk
- No real-time monitoring (scan-based only)

> 2026-06-30 ci: add Dependabot config (per-repo ecosystems) + exempt Dependabot from the aahp-verify handoff gate.

> Note (2026-07-19): Re-pinned @elvatis_com/aahp from 3.8.0 to 3.8.1 (picks up the v3.8.1 Windows/MSYS manifest-regen fix so tasks, next_task_id and cross_repo_ref survive regeneration). No runtime behavior change on Linux or CI. Handoff refreshed and MANIFEST regenerated.
