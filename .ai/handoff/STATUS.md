> Note (2026-08-03, claude-opus-5): Released v5.25.0. Minor, not a patch: `--ecosystem` is
> a new user-facing CLI flag on the importer. Ships that flag plus the 133 package IOCs from
> PR #105; feed at 6,294 entries. PR #106 was merged first so the release met the zero-open-PR
> invariant.
>
> RELEASE-BODY ACCURACY, verified rather than repeated. The incoming handoff warned that 82 of
> the 133 new IOCs are vendor scanner-testbed corpora published as malware on purpose
> (`@gocortexio/npmgremlinbox-*`, `vybscan-testbed-*`), so a "133 new threats" headline would
> overstate it. Counted against the actual diff: 133 new `type: "package"` entries, of which 82
> match those two testbed prefixes, leaving 51 real-world. The handoff's numbers are exact, and
> the CHANGELOG already said so in its own words, so nothing needed rewording - but the count
> was checked before publishing rather than taken on trust.
>
> Version bump read from `aahp.config.json` versionSites (14 sites), not from any checklist,
> then `npm install --package-lock-only` for the two lockfile fields a sed bump misses. Both
> habits exist because each failed a release before.
>
> DECISIONS CARRIED FORWARD, not re-litigated: the PyPI and NuGet halves of the 2026-07-20/21
> spike (~20,800 rows) stay out, re-confirmed 2026-08-03 on a fresh 25-package sample (PyPI
> 0/25 and NuGet 2/25 installable, npm 25/25). Liveness stays un-automated behind `--ecosystem`:
> a package removed from its registry can still sit in a lockfile, a vendored directory or a
> mirror, so "dead on the registry" is not "safe to skip". Reasoning lives in
> docs/threat-feed-sources.md.
>
> STILL OPEN, both need Emre's judgement and neither is a release task:
> - Whether known scanner-testbed corpora should be ingested at all. Current answer is yes,
>   because filtering them means maintaining a list of "malware we choose not to flag". Worth
>   deciding deliberately rather than letting it drift.
> - The vscode-scanner is purely behavioural, so a known-bad extension ID has nowhere to live
>   in the IOC model. The reported IoliteLabs `solidity-*` set has no home today. That is a
>   data-model change, not a release task.

> Note (2026-08-03, claude-opus-5, unreleased): Added `--ecosystem` to the feed importer,
> which is the follow-up the note below flagged for a decision. Emre approved building it
> as its own PR after #105 merged.
>
> Scope was deliberately narrow. The flag filters by ecosystem and nothing else; it does
> NOT automate the liveness check that motivated it. A package removed from its registry
> can still sit in a lockfile, a vendored directory or a mirror, so "dead on the registry"
> is not "safe to skip" - it trades a little coverage for feed size, which is a judgement
> call about a specific spike and should stay with the operator. Automating it would bury
> that trade behind a flag. Recorded because the tempting next step is a `--skip-dead`
> flag, and it should not be built without arguing past this.
>
> Nine tests written failing first (mapAdvisory filtering, the ecosystem-filtered skip
> reason, multi-select, the no-filter regression guard, end-to-end import, comma-separated
> and repeated parsing, and two on rejecting an unknown name). Verified against the real
> spike, not just fixtures: `--since 2026-07-20 --until 2026-07-21 --ecosystem npm` maps
> exactly 153 rows, the same number the hand-rolled fetch proxy produced, and reports
> 21,014 as ecosystem-filtered. Suite 373 -> 382.
>
> Note (2026-08-03, claude-opus-5, unreleased): Daily threat-intel run. 133 package IOCs
> imported (131 npm, 2 PyPI), feed 6,161 -> 6,294. 132 of 133 are corroborated by both
> GHSA and OSV. No version bump; Emre cuts the release.
>
> The substance of this run was NOT the 16 entries from the current quiet days, it was
> the 117 npm entries from the 2026-07-20/21 spike that had never been imported. The
> v5.24.0 note below recorded importing "the npm slices" of the spike, but that covered
> 2026-07-26/27 only - the npm half of 2026-07-20/21 (104 advisories, 100 distinct
> packages) was still missing while the PyPI and NuGet halves of those same days were
> correctly skipped. So the standing decision was right in substance and incomplete in
> execution; this run closes that gap.
>
> The skip decision itself was re-verified rather than assumed, on a fresh 25-package
> liveness sample per ecosystem: PyPI 2026-07-21 is 0/25 still installable, NuGet
> 2026-07-20 is 2/25, npm on the same days is 25/25. That reproduces the v5.24.0 sample
> exactly, so the ~20,800 PyPI/NuGet rows stay out - they are historical record, and
> importing them would quadruple the bundled feed (6,161 -> 27,088, feed.json 1.4 MB ->
> 5.9 MB) to cover packages no one can install. This was measured, not estimated: the
> full flood was imported, sized, typechecked green, and then reverted.
>
> Trap worth recording for the next run: the importer has no ecosystem filter, so there
> is no supported way to take the npm half of a mixed spike day. This run drove the
> shipped `importUpstreamFeed()` through a `fetchImpl` proxy that strips non-npm
> vulnerabilities out of each advisory before mapping, which keeps dedupe, OSV
> corroboration, `applyEntries`, the re-parse proof and feed.json regeneration on the
> shipped code path. If mixed-ecosystem spikes keep recurring, an `--ecosystem` flag is
> the real fix - flagged in the PR, not decided here.
>
> 82 of the 133 new entries are deliberate scanner-testbed corpora
> (`@gocortexio/npmgremlinbox-*`, `vybscan-testbed-*`) - packages published AS malware to
> test scanners. They are genuinely GHSA-listed malware and live on npm, so they are
> ingested rather than filtered, but they are not an active campaign and should not be
> read as one in the release body.
>
> STEP 1b (non-package enrichment) yielded nothing addable. The one campaign with a fresh
> full IOC set in reach was the Fake Payment SDK typosquat (Socket, 2026-07-07), and it is
> already fully enriched here - C2 subdomain and all 56 hashes present from an earlier run.
> Nothing new with atomic indicators was published in the 2026-08-01..03 window.
>
> Note (2026-08-02, claude-opus-5): v5.24.0 - fixed the importer backlog defect that the
> note below flagged for a decision. Root cause was NOT the --limit value. `--limit` is
> correctly sized for the steady-state flow, which is a median of ~35 advisories/day; the
> defect was that the report called an over-limit remainder harmless ("stays available to
> the next run"), which is only true while the remainder can drain before --days slides
> past it.
>
> Evidence, because the headline number is misleading. The 14-day window held 15,122
> advisories, but per-day it is 4-480 on twelve of fourteen days and two bulk-publication
> spikes carry the rest: 2026-07-21 landed 11,520 advisories (11,512 PyPI) and 2026-07-27
> landed 2,262 (all npm). Version-row explosion is a real but secondary effect - one NuGet
> advisory (GHSA-v22p-9fwv-76r7, stripeapi.net) alone carries 506 version rows - yet the
> 73 packages with >=20 versions hold only 18% of rows. There are 15,070 DISTINCT packages,
> so the volume is genuine.
>
> A hypothesis I had to discard, recorded because it is tempting and wrong: collapsing
> "no safe version exists" advisories to a bare-name block. `first_patched_version` is null
> for essentially every malware advisory, including `@ctrl/plex` (GHSA-qj23-4w47-prcr),
> which is a LEGITIMATE package with one hijacked release. Collapsing on that signal would
> bare-name-block real packages and flag every legitimate user. Checked before implementing.
>
> Triage used registry liveness, sampled 25 packages per spike: npm 2026-07-27 is 19/25
> still installable (live threats), PyPI 2026-07-21 is 0/25, NuGet 2026-07-20 is 2/25.
> So the npm slices were imported (3,569 entries, feed 2,592 -> 6,161) and the PyPI and
> NuGet floods were deliberately NOT - roughly 21k rows for a handful of live packages.
> That is now a VISIBLE decision rather than a silent loss, which is the point of the fix.
>
> The fix itself: `countUndrainable()` computes, per entry, whether its queue position
> (floor(index/limit) runs away) outlives its remaining window (days - age). Deliberately
> optimistic - it assumes zero future inflow, so it is a lower bound. Non-zero prints the
> recovering slice command and exits 2, distinct from exit 1 ("failed, nothing written");
> the selected entries are still written. Explicit --since/--until is exempt because
> slicing IS the recovery. `--allow-backlog` suppresses it. Four unit tests, written
> failing first.
>
> Note (2026-08-02, claude-opus-5, unreleased): Daily threat-intel run. Importer took 250
> package IOCs (GitHub Advisory Database CWE-506, 164 OSV-corroborated) out of a 14-day
> window that held 24,484 more behind the --limit; no page cap, no unmappable entries, so
> the window did not need slicing. That backlog is unusually large and will not drain at
> 250/day before entries age out - flagged for Emre in the PR, not decided here.
>
> Hand-added one campaign: the fake Corepack install site (Socket + Gurucul + iTnews),
> nine domains and one dead-drop URL. Discipline calls worth recording: only the specific
> subdomains of `go2cloud[.]org` and `canatrace[.]com` are listed (shared affiliate/tracking
> infrastructure), and the fake VPN landing page is path-scoped instead of blocking
> `freevpn[.]win` as a host. A negative test asserts legitimate Corepack usage
> (`github.com/nodejs/corepack`, `corepack enable`) stays clean, since the tool name is real.
>
> Two other campaigns were investigated and deliberately produced NO change. The Alibaba
> developer toolchain RAT was already fully covered, all eight hashes included. The GitHub
> Actions cPanel/WHM campaign was already covered too - I added its IP, dnshook subdomain
> and payload hash before noticing, and reverted them; the working tree is back at parity
> with main for that campaign. Its victim identifiers stay excluded on purpose: the
> maintainer `dinushchathurya` is a victim, not the actor, and the ten Composer packages
> contain benign PHP - only the `.github/workflows/` files were malicious, and installing
> the packages never executed them.

> Note (2026-08-01, claude-opus-5): Released v5.23.5 - the 2026-08-01 threat-intel import
> plus the PointBlank ecosystem-routing fix (details in the note below, which this release
> ships). 250 imported package IOCs, 79 hand-added non-package indicators, feed at 2,332
> entries.
>
> A MISTAKE OF MINE, AND HOW IT WAS CAUGHT. The session started with the working tree already
> checked out on `threat-intel/2026-08-01`, and I branched the docs/reviews gitignore change
> off that instead of off main. So PR #101 squash-merged the ENTIRE threat-intel changeset to
> main along with the one-line .gitignore edit - including the UNFIXED bare `gcli-control`.
> For roughly ten minutes main carried the inverted detection. It surfaced when PR #100 then
> reported a merge conflict it had no business having; resolving that (taking the corrected
> side for threat-intel.ts and campaigns.test.ts, regenerating feed.json and MANIFEST) put
> the fix on main. Verified after merge: main has `pypi:gcli-control` only, zero bare
> occurrences, feed.json agrees. Lesson worth keeping: check `git rev-parse --abbrev-ref HEAD`
> before `git checkout -b`; a scheduled job can leave the tree on a topic branch, and a
> squash-merge of a branch cut from the wrong base silently ships everything under it.
>
> The docs/reviews gitignore is live on main (PR #101) and it proved necessary within the
> hour: while staging this fix, `git add -A` on the PR branch swept all five review files
> toward a public commit, because the ignore rule was not yet on that branch. Unstaged before
> commit. That is exactly the failure the ignore exists to prevent, and the daily job runs the
> same `git add -A` unattended at 07:02.

> Note (2026-08-01, claude-opus-5, unreleased): Fixed an ecosystem-routing defect in this
> PR before merge, found while reviewing it and confirmed by an independent three-model
> cross-review (gpt-5, grok-4.5, gemini-3.6-flash; prompt and verbatim replies in the local
> docs/reviews/, which is gitignored - see PR #101).
>
> THE DEFECT. The PointBlank RAT is a PyPI package, but the hand-added feed entry was the
> bare value `gcli-control`. A bare value is the NPM namespace, so the detection was
> inverted: a poetry.lock/requirements.txt pinning gcli-control produced ZERO findings while
> an npm dependency of that name was flagged CRITICAL. It matters more than a typo because
> gcli-control is the only new PyPI IOC in this PR still live on the registry (~20 published
> versions). Fixed to `pypi:gcli-control`, feed.json regenerated. After: poetry.lock ->
> CRITICAL PYTHON_MALICIOUS_PACKAGE, npm package.json -> clean.
>
> WHY CI DID NOT CATCH IT. Both PointBlank tests asserted against the PYPI_TYPOSQUAT_PATTERNS
> constant and never called scan(), so they passed while the feed routed the entry to the
> wrong ecosystem. Added two scanner-level tests (poetry.lock positive, npm negative).
> Mutation-proved: reverting to the bare value fails both and passes everything else.
>
> WHAT THE CROSS-REVIEW ADDED beyond the fix, all three independently agreeing:
> - The misrouting is a CLASS, not one entry. gpt-5 counted 26 misrouted PyPI coordinates
>   across 20 names already on main; gemini named 10 including `frint`, which is registered
>   bare (npm) but is a PyPI name, while `frint` is a real npm package with ~89 versions
>   since 2016 - i.e. a live false positive shipping today. NOT fixed here: a data PR is the
>   wrong blast radius for it. Own task, own verification.
> - "Just pass the declared version" for the Finding B wiring gap is NOT safe, unanimously.
>   A package.json version is usually a RANGE; an IOC names one exact malicious version. All
>   three say the safe activation surface is the RESOLVED LOCKFILE tree, not manifest ranges,
>   and that lockfile matching should come first.
> - `pypi:` is necessary but not sufficient: it reaches poetry/uv/Pipfile lockfiles but not
>   requirements-only or pyproject-only projects, and PEP 503 normalization (gcli_control,
>   GCLI-Control) is unhandled.
> - Backlog policy: all three chose option (d) - fix routing and wiring first, then
>   re-evaluate the cap. Nobody argued for raising --limit now.
>
> A CORRECTION TO MY OWN EARLIER NOTE. I wrote that the 2026-07-28 BACKLOG DECISION "rests on
> a false premise". Two reviewers pushed back: the premise IS false (bare-name npm entries do
> fire via matchBareNpmIOC, wired v5.11.0, 19 days before the decision), but the decision did
> not rest on it alone - it also cited data quality and reviewability, and its own sequence
> already put "wire the npm dependency check to the feed" ahead of any backfill. So: correct
> the stated reason, keep the conclusion. Do not backfill yet.
> Note (2026-08-01, claude-opus-5): Gitignored `docs/reviews/`, a local-only folder for
> external model cross-reviews (mirrors elvatis/ideabase `docs/reviews/`). Two reasons it
> must be ignored rather than merely untracked: this repo is PUBLIC and its hard rules
> forbid AI/tool attribution in published artefacts, and the daily job commits with
> `git add -A`, so anything left there would be swept into a public commit by the next
> 07:02 run. Same reasoning as `docs/superpowers/`. Review outputs are working material,
> not the record: decisions still go to STATUS.md, cross-repo items to elvatis/ideabase.
>
> Context - three findings are out for cross-review (prompt in docs/reviews/, not committed):
> (1) PR #100 registers the PointBlank PyPI RAT as bare `gcli-control`, which is the npm
> namespace, so a poetry.lock/requirements.txt pinning it yields ZERO findings while a
> package.json dependency of that name is flagged critical - the detection is inverted, and
> `gcli-control` is the only new PyPI IOC still live on the registry. Fix is `pypi:` +
> regenerate feed.json + a scanner-level test; the PR's tests assert against the
> PYPI_TYPOSQUAT_PATTERNS constant and never call scan(), which is how it passed CI. The same
> class is already live on main: `frint` is registered bare but is a PyPI name, and `frint`
> is a real npm package (~89 versions since 2016).
> (2) scanner.ts builds dependency candidates with `version: undefined`, and matchBareNpmIOC
> needs exact version equality, so of 2,095 bundled package IOCs only 620 bare npm names fire
> on the primary path; 1,039 version-pinned npm entries cannot fire from an ordinary
> package.json dependency. The npm ALIAS form is matched while the ordinary declaration is
> not, and the package-lock.json path never consults the feed at all.
> (3) THE 2026-07-28 "BACKLOG DECISION, MADE - do not re-litigate" RESTS ON A FALSE PREMISE.
> Its load-bearing claim that the main scan path never consults feed package entries for npm
> is wrong, and was wrong when written: the wiring landed in v5.11.0 on 2026-07-09, 19 days
> earlier, via checkMaliciousDependencyNames -> matchBareNpmIOC (the analysis searched for
> matchPackageIOC, the wrong function for the npm namespace). Verified by fixture. Separately,
> PR #100's claim that the backlog "refills faster than a 250/run cap drains it" is
> contradicted by the record: 29,246 -> 29,024 -> 28,763 -> 28,662 -> 28,235, shrinking ~253
> per run. Both that note and the 07-28 note called a trend from two points and reached
> opposite conclusions. A free falsifiable test lands on the 2026-08-05 run, when the 21 July
> burst (11,520 advisories) leaves the 14-day window. Do not act on either backlog claim until
> the wiring in (2) is fixed - importing more version-pinned entries into a path that cannot
> fire them buys nothing.

> Note (2026-08-01, threat-intel, unreleased): Daily threat-intel update. No version
> bump - the version belongs to the release Emre cuts.
>
> IMPORT: `npm run feed:import` added 250 package IOCs (GitHub Advisory Database CWE-506,
> corroborated against OSV.dev) for the window from 2026-07-18. 18,649 advisories over
> 187 pages, under the 200-page cap, so no window slicing and no truncation. Skipped 30:
> 7 unmappable-version-range (bounded ranges the scanner cannot express), 22
> unsafe-package-name, 1 withdrawn. None were forced in by hand.
>
> ENRICHMENT: two campaigns the advisory databases cannot supply atomic indicators for.
> Joyfill npm compromise / DEV#POPPER (Socket + StepSecurity, 2026-07-28) was only
> PARTIALLY covered - the databases published 2 of 6 malicious releases. Added the
> remaining four @joyfill/components and @joyfill/layouts 2773 betas as version pins
> (both packages are legitimate and still maintained), 4 stage-3/4 C2 IPs, 15 payload
> SHA-256 hashes and 7 blockchain C2 resolver addresses. Socket's PolinRider attribution
> is corroborated independently: the wave re-uses two Tron tier-2 wallets already pinned
> for ViteVenom/ChainVeil. Every hash was shape-checked and the extraction was verified
> against an exact-string search before ingest. PointBlank PyPI RAT (Xygeni,
> 2026-07-21..31): gcli-control blocked by name at feed confidence 0.85, single-source.
>
> DELIBERATE NON-INGESTS: api.trongrid[.]io, fullnode.mainnet.aptoslabs[.]com,
> bsc-dataseed.binance[.]org, bsc-rpc.publicnode[.]com, ip-api[.]com and npoint[.]io are
> shared public infrastructure that the two loaders abuse rather than own. Blocking any
> of them would flag legitimate web3 and developer projects, so they are excluded and
> regression tests assert they stay clean. The generic "gcli" import package name is
> excluded for the same reason. Xygeni published no npoint[.]io bin id, so there is no
> campaign-specific dead-drop path to ingest.
>
> OPEN FOR EMRE: the importer backlog is structural, not transient. It was 28,662 on
> 2026-07-31 and is 28,235 after this run - a 250/run cap against a 14-day window that
> refills faster than it drains, so the oldest slice ages out unimported and is
> unreachable by any later run. That is a silent false negative by design, and raising
> --limit is explicitly not the fix (it would push a machine-generated thousand-entry
> diff into a public repo). This needs a policy decision, not another daily run.
>
> Note (2026-07-31, v5.23.4): Issue #97 replaces the unconditional
> GHA_ARTIFACT_DOWNLOAD action-name match with a fail-closed structural trust proof.
> A download is clean only when trusted triggers, stable upload/download refs, matching
> exact or glob artifact selectors and every matching producer in the consumer's
> transitive needs closure are all established. Explicit repository/run/token inputs,
> untrusted or unknown triggers, mutable refs, unlinked producers and parse failures
> remain low findings; cross-workflow artifact escalation remains independent.
>
> PARSER/REGRESSIONS: workflow-ast now captures scalar, flow-list and block-list needs
> plus artifact pattern/repository/run-id/github-token inputs. Exact Docker multi-arch,
> transitive-needs, cross-run, pull_request_target, missing/unrelated/unlinked producer
> and mutable-ref cases are covered. The build-backed self-scan asserts that Issue #97
> stays absent. Focused local verification is green: 66 workflow AST/scanner/graph tests,
> 23 build-backed self-scan tests and TypeScript no-emit lint. The governed production
> build passes all AAHP/feed/handoff gates, and the built v5.23.4 CLI scans the real
> checkout at score 0 / clean with zero findings at every severity.
>
> RELEASE SCOPE: PR #98 was corrected to the real 1,807 -> 2,058 feed transition and
> merged separately, so v5.23.4 contains 250 package IOCs plus one verified manifest
> hash without mixing generated data into the scanner patch. Coverage-instrumentation
> profiling is explicitly moved to v5.23.5; the 28,662-entry importer backlog replaces
> the stale feed-chunking action in NEXT_ACTIONS.
> Note (2026-07-31, threat-intel, unreleased): Daily threat-intel update. No version
> bump - the version belongs to the release Emre cuts.
>
> IMPORT: `npm run feed:import` added 250 package IOCs (GitHub Advisory Database CWE-506,
> corroborated against OSV.dev) for the window from 2026-07-17. Mostly typosquats of
> socket.io, passport and mongoose plus machine-generated throwaway names. The importer
> hit its `--limit 250` with 28,662 more entries still ready in the window; that is the
> benign cap, and the remainder stays available for subsequent runs. No page-cap error,
> so the window did not need slicing. Skipped: 7 unmappable version ranges, 22 unsafe
> package names, 1 withdrawn advisory.
>
> ENRICHMENT: one hand-added indicator, the SHA-256 of the malicious jscrambler@8.20.0
> manifest. Single-source (Socket), fed at confidence 0.85. Every other atomic indicator
> checked this run was already covered: the AsyncAPI compromise (C2 host, C2 IP, both
> IPFS payload CIDs, the Ethereum dead-drop and all seven artifact hashes), the fake
> Paysafe/Skrill/Neteller SDK campaign (C2 subdomain plus all 56 published hashes) and
> the jscrambler payload hashes.
>
> DATA-QUALITY NOTE: the fetch-and-summarize path garbled two hashes from Socket's
> Paysafe IOC list - one came back at 65 characters, the other differed from the shipped
> value by a single character. Both were already in the blocklist in their correct
> 64-character form, so nothing was written. Long hex strings from that path are
> verified against the repo (and by exact-string search) before ingestion rather than
> trusted; that check is what kept two corrupt hashes out of a public release.
>
> Model: claude-opus-5.

> Note (2026-07-30, v5.23.3): The compiled self-scan regression is fixed without
> excluding `dist/` from protection. Exact package and canonical repository identity
> are required before suppressing reviewed inert source/generated counterparts or
> exact path-and-rule pairs. Arbitrary generated payloads and unrelated rules remain
> detectable.
>
> PRECISION: credential theft now requires source-to-network-sink flow with lexical,
> receiver and shell scope ownership; Vite/Vitest metadata and ordinary Proxy handlers
> remain clean. Mining, pool-host, protestware, backconnect, character-code execution,
> V8 ownership and broad-gap rules use bounded structural correlation. Python manifest
> coverage includes modern requirements and pyproject dependency surfaces while
> retaining explicit partial verdicts for unresolved intent.
>
> RELEASE SURFACE: v5.23.3 is synchronized across governed metadata, the feed and Action
> pin. The reviewed workflow dependency updates from PRs #94 and #95 are included.
> CHANGELOG.md records the self-scan policy choice, detector behavior, regressions and
> trade-offs in detail.
>
> VALIDATION: the focused Windows set passed 713 tests in 10 files. The built CLI scanned
> this checkout at score 3 / low risk with zero high and zero critical findings; its only
> partial item was the deliberate deep-path fixture. The complete Linux correctness run
> passed all 2,541 tests in all 106 files. Coverage-sensitive regression groups also pass
> with an explicit instrumentation multiplier, preserving the real full-suite wall-clock
> budgets instead of treating V8 coverage as a benchmark.
>
> DEFERRED: profile the structural matcher hot paths and remove the coverage multiplier
> in v5.23.4. That work is recorded in NEXT_ACTIONS.md and is not a correctness or
> self-scan release blocker.
>> Note (2026-07-30, v5.23.2): The threat-intel change below shipped as v5.23.2 (patch,
> matching the threat-intel-only release precedent of v5.18.2 and v5.20.1). It was
> reviewed and merged as #92 before the release was cut, so the release commit carries
> only the version bump and the regenerated artifacts.
>
> Note (2026-07-30, scheduled threat-intel run): Daily IOC refresh.
> The advisory importer added 250 package IOCs (GitHub Advisory Database CWE-506,
> corroborated against OSV.dev); 28,763 more remain inside the 14-day window behind
> the default --limit 250 and will be taken by subsequent runs. The fetch needed 184
> of the 200 allowed pages, so the page cap was not hit and no window slicing was
> required - but the margin is thin and the backlog is the open question below.
>
> Manual enrichment (STEP 1b) added 79 non-package indicators the advisory databases
> never publish, across three campaigns: the Alibaba developer toolchain RAT (2 C2
> subdomains, 8 OSS staging dead drops, 8 payload hashes, GitHub account smi1e2u -
> the only campaign with no prior atomic coverage), 56 entry-point hashes for the
> fake Paysafe/Skrill/Neteller payment SDKs, and 2 further AsyncAPI artifacts.
> Sources: Socket (via cybersecuritynews), Socket + gbhackers, Unit 42.
>
> False-positive discipline: hijacked packages are version-pinned, never name-blocked,
> and no shared host was ingested - aliyuncs[.]com, fcapp[.]run, ai-app[.]pub,
> ngrok-free[.]dev and github[.]com apexes are excluded, matching the decision in
> ioc-blocklist.ts not to block the AsyncAPI campaign's Nostr relays and BitTorrent
> DHT bootstrap nodes. Two negative tests assert the OSS and Function Compute apexes
> stay clean.
>
> Open question for Emre: at 250/run the 28,763-entry backlog cannot drain before the
> --days 14 window ages entries out, which is a silent false negative by design. Worth
> deciding whether to raise --limit for a catch-up run, widen --days, or accept the
> loss. Recorded here rather than as an issue, per the zero-open-issues invariant.

> Note (2026-07-29, independent review - v5.23.1): The complete v5.23.0 review
> set is fixed in one patch release. The two release blockers were reproduced before
> implementation: the engine silently stopped after 500 lines, and `DROPPER_TEMP_EXEC`
> treated `.execSync` as an executable-file suffix in ordinary installer code. The
> multi-line engine also lost matches beyond character 4,096 on a minified line.
>
> MATCHING: the scanner no longer raises the regex window over attacker-controlled input.
> Registered broad-gap patterns instead require bounded structural matchers at load time.
> This covers the core tables plus Docker, Cargo, Go, Git, npm, VS Code, and GitHub Actions
> workflow tables. Differential tests preserve legacy start, greedy-end, overlap, line
> separator, and evidence semantics where no precision correction was intended. Safety
> budgets and conservative fallbacks emit `PATTERN_SCAN_INCOMPLETE`; they never return a
> clean verdict. The false-positive corrections require real same-value/data-flow or
> in-body correlation for dropper, Proxy, GeoIP protestware, and PyPI base64 rules.
>
> WIRING: one shared runner now applies the full `PatternEntry` contract, including file
> extension, path, test-file, corroboration, value, line-span, and structural-matcher
> guards. AST-based wiring checks reject new direct regex consumers, and load validation
> rejects malformed patterns, invalid spans, duplicate core rule IDs, unsafe broad gaps,
> and missing structural matchers. Late-file, long-line, repeated-token, and non-vacuous
> boundary fixtures cover the review's nine findings.
>
> COVERAGE: partial status survives severity and policy filtering and is explicit in every
> report/gate surface. Unreadable, unenumerable, depth-limited, oversized, broken-link,
> escaping-link, special-node, cycle, and traversal-budget paths fail closed with normalized,
> deduplicated public paths. Specialized scanners receive an explicit trusted root.
> Contained internal symlinks retain their public artifact path; external targets are not
> read. Walk depth and alias expansion are bounded, including skill trees and VSIX manifests.
>
> ARTIFACTS: PyPI scans every unique latest-release sdist and wheel, preserves distinct
> valid digests, verifies downloaded SHA-256 identities, retries equivalent metadata URLs,
> and attributes findings to the alias whose bytes passed verification. Missing or malformed
> digest metadata leaves the content scan explicitly partial. npm and VSIX scans include
> shipped `node_modules`. Archive members are fully preflighted before extraction for unsafe
> paths, links, types, structures, and bounded resource use.
>
> VERDICT INTEGRITY: the CLI rejects incompatible report/gate thresholds and colliding
> output writers before scanning, produces a canonical JSON sidecar from the same report,
> and lets large nonzero reports drain before exit. Direct state and organization APIs also
> preserve partial status and exclude incomplete scores from complete-repository averages.
> The Marketplace Action uses one scan, one explicit severity gate, isolated temp files,
> schema and formatter reconciliation, immutable Action pins, an exact CLI pin, bounded
> logs/outputs/comments, inert report rendering, and fail-closed partial behavior. PR comment
> updates are paginated and limited to the canonical GitHub Actions bot marker.
>
> RELEASE HYGIENE: v5.23.1 is synchronized across every governed version site, including
> specialized ScanReport versions and the Action CLI pin. Public release notes contain no
> private environment details. Verification is green: the Windows-compatible focused set
> passed 907 tests in 38 files with 17 platform skips; the complete Linux set passed all
> 2,169 tests in all 104 files with no skips or failures. Linux TypeScript lint, the governed
> production build, Action Bash/jq gates, npm pack/install and packaged-CLI smoke checks,
> feed integrity, handoff integrity, and all 14 governed version sites pass. The first Linux
> pass exposed four platform-only gaps; each was fixed before the complete green rerun. No
> release tag or publish action has been performed.

> Note (2026-07-29, grok-4.5 - v5.23.0): Multi-line pattern matching. The engine matched line by
> line, so PROXY_HANDLER_TRAP (and any rule bridging two ideas) only fired on one-line payloads.
> Reproduced: one-line Proxy+fetch was HIGH; the identical construct pretty-printed across three
> lines was silent.
>
> DESIGN: opt-in PatternEntry.spansLines (default 1). Sliding window of N lines, match with the s
> flag inside the window only. Hard caps: MAX_SPANS_LINES=20, MAX_SPAN_WINDOW_CHARS=4096,
> MAX_MATCH_ATTEMPTS_PER_PATTERN=500. Shared matchPatternInContent used by directory/npm/PyPI/
> VS Code/Dockerfile/config scanners so entry points cannot drift. Whole-file dotAll rejected:
> would pair tmpdir on line 3 with exec on line 900 (the v5.22 FP class, scaled by file size).
> Character-bounded `.{0,400}` under s was considered and rejected: one global char budget is a
> worse fit than a per-rule line window, and line numbers are harder to justify to operators.
>
> ENABLED spansLines on: PROXY_HANDLER_TRAP(5), DROPPER_TEMP_EXEC(6), PYPI_B64_EXEC_COMBINED(4),
> PYPI_CUSTOM_*(6), PROTESTWARE_IP_GEO_V2(8). All other rules stay single-line.
>
> MEASURED on this box's node_modules (~1,166 files / 903 scanned):
> - FP high+critical by rule: BEFORE and AFTER identical (BINARY_UNEXPECTED 3, HIGH_ENTROPY 3,
>   MINER_CONFIG_KEYS 1, MINER_POOL_DOMAIN 1). No new high/critical rule started firing.
> - Wall time: 3056 ms -> 3231 ms (~+6%). Acceptable for a precision fix.
> - FN: precision-corpus green; new multi-line proxytrap + dropper samples fire; one-line forms
>   still fire. Window-boundary and ReDoS-budget unit tests green.
>
> ALSO NOTED (not fixed here): `scg scan .` vs `scg npm supply-chain-guard` produce different
> results by design - local scan walks the full working tree (tests, docs, src, handoff); npm
> path downloads the published tarball (packaged files only, different path filters / self-scan
> suppression surface). Not a multi-line defect.
>
> NEEDS A DECISION from Emre: opt-in (this PR) vs opt-out multi-line for all `.*` / `[^}]` rules.
> Recommendation remains opt-in: safer, slower to roll out, matches the v5.22 precision posture.
>
> STILL OPEN after this: more rules that could benefit from spansLines (inventory of ~41 bridge
> patterns); only the high-value ones above were enabled with justification. Roll out further
> only with per-rule node_modules measurement.

> Note (2026-07-29, claude-opus-5, fourth pass - v5.22.0): Emre asked for the whole remaining
> precision backlog fixed at once, with real testing, because the daily routine kept surfacing a
> new defect every run. Root cause of THAT complaint: every FP so far was found by ad-hoc
> measurement, so a new one appeared whenever anyone looked. Two permanent harnesses now make
> that class fail the build instead.
>
> MEASURED BEFORE: 7 files of completely ordinary code (a release script, a proxy config, a CI
> helper, a gist link in a comment, an ES6 Proxy, a template-literal WebSocket URL, a napi-rs
> version check) produced 8 findings, 2 critical, 5 high. Zero true positives. AFTER: zero high,
> zero critical, and all 9 matching malicious samples still detected.
>
> NEW ENGINE CAPABILITY: PatternEntry.requiresInFile. The worst FPs were rules whose regex
> asserted something true of innocent code, which no path- or value-level filter can fix. A rule
> can now demand corroboration elsewhere in the file: "npm publish" counts only next to
> credential access AND process execution, ".npmrc" only next to an exfil call, a gist URL only
> next to a fetch.
>
> THREE DEFECTS FOUND THAT NOBODY ASKED FOR, all worse than the ones on the list:
> 1. A MALFORMED REGEX SILENTLY DISABLED CONTENT SCANNING ENTIRELY. scanner.ts compiles patterns
> inside a per-file try/catch, so one bad entry threw on the first file, was swallowed, and
> suppressed every rule ordered after it, for every file, exiting 0. Reproduced: an invalid entry
> placed first took a scan from 2 findings to 1 (EVAL_ATOB lost) and reported success. All 145
> patterns are now compiled at module load and a bad one is a loud crash.
> 2. requiresInFile WAS HONOURED BY ONE SCANNER OUT OF EIGHT. The pattern arrays are iterated by
> the directory, npm, PyPI, VS Code, Dockerfile and config scanners. A guard applied in one loop
> means the same file gets different verdicts depending on entry point. Both guards are now
> applied everywhere, via isPatternApplicableToFile, enforced by a wiring test that DISCOVERED
> two consumers I had missed (agentic-workflow-scanner, mcp-scanner) and now fails if a new loop
> appears without them.
> 3. ENTROPY NEVER FIRED ON BASE64. base64 cannot exceed log2(64) = 6.0 and the threshold was a
> strict "> 6.0", so the payload shape the rule exists for was systematically missed. The metric
> also iterated code points, not bytes, so it was unbounded while its thresholds assumed 0..8.
> Now byte-based, threshold re-derived by measurement: over 1,151 real third-party files max was
> 5.70 and none exceeded 5.8.
>
> ALSO FIXED: dependabot PRs were red FOREVER. The generated dashboard embeds a dependency
> version table and the staleness gate demanded a byte-exact match, so every bump failed prebuild
> and dependabot cannot regenerate it (read-only token). The version column is still written
> truthfully but is out of the comparison; add/remove of a dependency still gates.
>
> A CORRECTION I had to make against my own sources: the review told me to add a bare-name feed
> entry for @convera/ui-shared. The npm registry says it has a 0.0.1 that upstream never flagged,
> so a bare entry would block a release no source called malicious. Only @tc-core/campus-service
> got one (absent from npm, every published version malicious).
>
> VERIFIED: full suite 1,672 pass / 14 fail, all 14 the documented vscode-scanner `zip` gap
> (binary genuinely absent on this box; green on Linux CI). npm run build green. Self-scan 0
> critical - note my first draft of the tests embedded the REAL PhantomSync dead-drop literal and
> made the repo flag itself with 5 criticals; the fixtures now use a synthetic id of the same
> shape.
>
> STILL OPEN: the line-based pattern engine cannot match a construct split across lines
> (documented in precision-corpus.test.ts). Fixing that is a real engine change, not a regex edit.

> Note (2026-07-29, claude-opus-5, third pass - v5.21.0): Emre asked for the two deferred items
> plus a general quality lift, then the release. A second measurement workflow (4 agents) and a
> 3-lens adversarial judge panel ran first. The judges refuted three of the dossier's own
> recommendations AND caught two errors in the code I had landed an hour earlier.
>
> BIGGEST FIND, and it was nobody's brief: npm ALIAS SPECS BYPASSED THE SCANNER ENTIRELY.
> `"utils": "npm:chalk-tempalte@1.0.0"` installs the target while every check read the manifest
> KEY. Reproduced before/after: a fixture with two known-malicious feed packages behind aliases
> scanned {critical: 0}; it now reports 3 critical. On the guard path `npm install
> x@npm:<malware>` returned specs=[] because parseSpecToken split at the LAST "@", landed on the
> alias target's own version, failed the registry-name regex and dropped the spec silently. Both
> paths fixed by resolving the alias to its target. This was a live, trivially attacker-
> controllable false negative in a public security tool, readable in the published source.
>
> TWO ERRORS IN MY OWN PREVIOUS COMMIT, both caught by the judges, both now fixed:
> 1. The osaDistance doc comment claimed "veim" -> viem was a true positive of
> TYPOSQUAT_LEVENSHTEIN. Measured: veim is QUIET, because viem is not in POPULAR_PACKAGES. That
> comment was the public justification for lowering the ceiling, and it was false.
> 2. The TYPOSQUAT_ALLOWLIST comment argued against adding viem to POPULAR_PACKAGES because it
> would flag vuex and timm "at distance 2" - reasoning from the 2-edit rule that the same commit
> had just replaced. Both rewritten to claims that measurement supports.
>
> SHIPPED: alias resolution (both paths); typosquat target floor 4 -> 5 (57 -> 29 measured FPs on
> 29,687 real names, curated true positives unchanged); TYPOSQUAT_SIMILAR_TO_DEP hardened (length
> floor, osaDistance, one-sided known-good guard, one finding per pair) taking it from 5.0% of
> 939 real manifests to under 1% while ADDING transposition recall; policy allowlist extended to
> that rule (it previously had no per-package escape at all); install-guard blocking demoted to a
> deny-list with only DEP_INTERNAL_NAME_PUBLIC warn-only.
>
> REJECTED AFTER MEASUREMENT, do not retry without new data:
> - Demoting TYPOSQUAT_LEVENSHTEIN to warn-only in the guard. Measured to lose 10 real blocks
> (lodahs, expresss, crossenv, cros-env, 1odash, l0dash, nodemai1er, reqeust, axois, raect),
> because checkSpec never consults patterns.ts - the heuristic is the guard's ONLY view of those
> curated names. Wiring patterns.ts into checkSpec is the prerequisite for revisiting this.
> - Two-sided known-good suppression on the pair rule. Drops 11 of 14 true positives; the
> mutation proof for this is in the suite.
> - Digit-edit suppression on the pair rule. Publishes the recipe "append a digit to a
> non-popular dependency name"; 62 of 770 npm feed names end in a digit.
> - Severity high -> medium on the pair rule. Left at high: it is the rule's only unique
> territory (babelcli+babel-cli produces no other finding). Needs Emre.
> - Entropy metric fix. src/entropy.ts iterates code points, so the metric is unbounded and the
> 6.0/5.7 thresholds are calibrated against a byte range the code never computes. Fixing the
> metric without re-deriving both thresholds is a blind severity change on the rule that exists
> to catch obfuscated payloads. Needs its own corpus pass.
>
> MUTATION-PROVED (the part CI cannot do): revert osaDistance in the pair rule -> 2 tests red;
> make the pair guard two-sided -> 4 tests red; revert alias resolution -> 1 test red. All
> restored green. Self-scan of this repo: 0 critical, 0 typosquat findings.
>
> STILL OPEN FOR EMRE (documented, deliberately not shipped):
> 1. A 13-item precision sweep of src/patterns.ts, measured with reproductions. The worst:
> SHAI_HULUD_WORM makes the literal string "npm publish" a CRITICAL verdict in any file, so every
> repo with a release script is critical on sight; GHOSTSOCKS_SOCKS5 fires on the bare word
> SOCKS5; the MALICIOUS_PACKAGE_PATTERNS scoped catch-all matches 94.3% of ALL scoped packages on
> the `scg npm` path. That last one must NOT be deleted outright - 85 curated malicious scoped
> names are matched ONLY by it, so npm-scanner.ts needs a bundled-feed lookup wired in first.
> 2. Removing the six DEP_INTERNAL_NAME_PUBLIC suffix patterns requires adding BARE feed entries
> for @convera/ui-shared and @tc-core/campus-service first; they exist only as version pins, so
> removing the suffixes silences them completely on every path.
> 3. A pinned-corpus regression harness. Every defect found across both rounds was a rule whose
> coverage was asserted on one code path and refuted on another.

> Note (2026-07-29, claude-opus-5, second pass): Emre reviewed the threat-intel PR and asked for
> BOTH open decisions to be fixed on the same branch before merge. Done. A four-agent
> investigation plus a three-lens adversarial judge panel ran first; the headline finding is that
> the "viem false positive" was not a one-off.
>
> MEASURED SCOPE OF THE FP: a 27,140-name corpus of real npm packages was run through the actual
> heuristic. 321 legitimate packages were flagged, and the rate RISES with popularity (2.37% above
> 10M weekly downloads). acorn (237M/wk), preact, cypress, redux, enquirer, gaxios, globby, jose,
> mime, util, knex and viem were all reported as typosquats, which in `guard` is a hard install
> block. Against the repo's own 653 unscoped known-malicious names the rule caught 2 (rimarf,
> yarsg) - roughly 1:160 signal to noise. Both of those are ALSO already caught by exact name in
> patterns.ts and the feed, so the rule's unique recall against known malware was ZERO. That is
> what made tightening safe: there was no measured detection to lose.
>
> FIX: ceiling is now one Optimal-String-Alignment edit. OSA counts an adjacent transposition as
> 1, and every real squat in this project's threat data is a transposition (rimarf, yarsg, lodahs,
> veim) which plain Levenshtein scores 2 - so the ceiling could drop from 2 to 1 without losing
> one of them. viem/vite is OSA 2, so viem clears structurally with no allowlist entry.
>
> THREE PROPOSALS WERE REJECTED after the judge panel, worth recording so they are not retried:
> 1. Same-first-character predicate. Cuts ~24 more FPs but makes the rule structurally unable to
> catch 1odash / l0dash, which patterns.ts curates by hand, and on a public repo it is a
> documented one-character bypass. Two of three lenses rejected it independently.
> 2. Adding viem to POPULAR_PACKAGES. That array doubles as the target list, so exempting viem
> would newly flag the legitimate vuex (1.7M/wk) and timm (2.0M/wk). The allowlist is a SEPARATE
> additive set for this reason; the POPULAR_PACKAGES membership term stays in the guard because 17
> entries in that array collide with each other at distance 2.
> 3. Applying the allowlist to TYPOSQUAT_SIMILAR_TO_DEP. Left alone deliberately - see the open
> item below.
>
> ALSO FIXED, found during the investigation and not in the original ask: `--limit abc` parsed to
> NaN, which disabled the cap and limit guards, imported ZERO IOCs and exited 0 reporting success.
> A silent false negative in a threat-feed importer. All four numeric CLI options now reject
> non-positive-integers.
>
> VERIFIED: mutation-proved by reverting the ceiling to <= 2 and watching three new tests go red,
> then restoring. Self-scan of this repo went from 2 typosquat findings (pathe conf 0.85, obug
> conf 0.65 - both registry-verified legitimate) to 0. npm run build green. Ran only the affected
> suites (dependency-risk-analyzer, install-guard, campaigns, policy-engine, feed-import): 351
> pass. Full suite left to CI.
>
> STILL OPEN, needs Emre - deliberately NOT fixed here:
> 1. TYPOSQUAT_SIMILAR_TO_DEP is a second, parallel FP generator. It fires on legitimate pairs in
> one manifest (vue+vuex, path+pathe, color+colors, mysql+mysql2, uuid+ulid), has no length floor,
> never consults any allowlist, and has NO suppression path even via a policy file
> (policy-engine.ts gates allowlist.packages on TYPOSQUAT_LEVENSHTEIN and DEP_INTERNAL_NAME_PUBLIC
> only). It was left untouched because the obvious two-sided fix breaks the rule's highest-value
> case - a squat sitting in the manifest next to the package it imitates - and the existing
> expres+express test encodes exactly that. It needs its own corpus measurement.
> 2. install-guard blocks on ANY finding (`findings.length > 0`) with no policy allowlist plumbed
> in, so a 0.65-confidence heuristic carries the same blocking authority as a 1.0-confidence feed
> match, escapable only with --force. That is the mechanism by which a false positive gets the
> tool switched off.

> Note (2026-07-29, claude-opus-5): Scheduled daily threat-intel run. No version bump; this is
> a PR for Emre to review and release.
>
> IMPORTER: 250 package IOCs added from the GitHub Advisory Database (CWE-506, 120 OSV-corroborated).
> 18,368 advisories fetched over 184 pages - the page cap is 200, so the window is close to the
> FATAL "page cap reached" ceiling and the next run may need --since/--until slicing. 29,024 more
> entries stayed behind --limit 250 (fine: they remain in the --days 14 window for later runs).
> Skipped 30: 7 unmappable-version-range, 22 unsafe-package-name, 1 withdrawn.
>
> MANUAL ENRICHMENT (the part the advisory databases never publish): two campaigns, 35 non-package
> indicators plus 23 package names.
> - NeoShadow (Aikido, Jan 2026; packages corroborated by o3.security MAL-2026-334). Atomic IOCs
>   are Aikido-only, so they carry confidence 0.85 and are commented single-source.
> - SANDWORM_MODE (Socket + OX Security, Feb 2026). Both vendors publish the same 19 packages and
>   the workers.dev C2; the two secondary apexes are Socket-only at 0.85.
>
> DISCIPLINE NOTES, three judgement calls worth recording:
> 1. All 23 package names were verified against the npm registry before being blocked by bare name.
> Every one returns a "security holding package" placeholder, i.e. npm removed the malware and no
> legitimate release history exists under those names. The unscoped `supabase-js` is the squat; the
> real package is the scoped `@supabase/supabase-js` and is not matched.
> 2. The NeoShadow Ethereum address went into the FEED as type:"url" (0x-prefixed), NOT into
> KNOWN_C2_WALLETS. That collection holds only Tron and Aptos addresses by design - the feed's
> structural url floor is what covers EVM. I had it in the wrong collection first; the convention
> is documented in the url-floor comment in threat-intel.ts.
> 3. Socket's stage-2 AES key, IV and auth tag were deliberately NOT ingested into
> KNOWN_MALICIOUS_HASHES. They are decryption material, not file digests, and a key in the hash map
> would misreport as "this file is malware".
>
> NOT ADDED: a SHA-256 (46faab8a...) that a search snippet attributed to the OX Security worm
> write-up. Fetching the article directly returned no hashes at all, so the snippet is unconfirmed
> and inventing it would violate the never-invent-indicators rule. Left out on purpose.
>
> ONE PRE-EXISTING FALSE POSITIVE FOUND, not caused by this change and not fixed here: the install
> guard blocks the legitimate `viem`, because the generic Levenshtein heuristic puts it 2 edits from
> `vite` and `viem` is absent from POPULAR_PACKAGES in dependency-risk-analyzer.ts. My first test
> asserted `viem` was unblocked and failed; the assertion was wrong, not the code. The test now
> asserts the meaningful invariant (viem never earns a MALICIOUS_DEPENDENCY/THREAT_INTEL_MATCH
> verdict) and documents why it is flagged. Adding `viem` to POPULAR_PACKAGES is a real candidate
> fix but is out of scope for a threat-intel run - it needs Emre's call.
>
> Verified: npm run build green (check:aahp + check:feed + check:handoff + tsc). Ran only the
> suites covering the change - campaigns, ioc-blocklist, feed, threat-intel, feed-import,
> install-guard, dependency-risk-analyzer, npm-scanner, new-patterns, scanner: 438 pass. Full
> suite deliberately not run locally; CI on the PR is the authoritative verdict.

> Note (2026-07-28, claude-opus-4-8): Post-release review of v5.20.2 (external, GPT-5.6-Sol)
> found two real defects. Both confirmed by measurement, both fixed here. No republish: the
> published package is correct.
>
> 1. LOCKFILE NEVER BUMPED, TWO RELEASES RUNNING. package-lock.json carries the project
> version twice (root `.version` and `.packages[""].version`) and npm only rewrites them at
> install time, so an in-place (sed) release bump leaves them behind. Measured at the tags:
> v5.20.0 lock=5.20.0 (correct), v5.20.1 lock=5.20.0 (stale), v5.20.2 lock=5.20.1 (stale) -
> it trails by exactly one release. Nothing caught it because package-lock.json was not in
> aahp.config.json versionSites. It never affected the published package (the lockfile is not
> in `files`). Fixed: lockfile resynced, ADDED to versionSites (minOccurrences 2, now 7 sites),
> and CLAUDE.md release step 4 now says to run `npm install --package-lock-only` after the
> bump. Mutation-proved: reverting the lock to 5.20.1 turns version-sync red.
>
> 2. "feed.json is byte-identical" WAS FALSE AS SHIPPED - my error, in the CHANGELOG and the
> release notes. Byte-identity was verified at the chunking step, before the version bump; the
> bump then changed feed.json's embedded version string (the ONLY line that differs between
> v5.20.1 and v5.20.2). The accurate claim, now in the CHANGELOG: all 1,197 entries are
> identical, only the embedded version differs. Worth naming the pattern - a claim verified at
> one point in the work was carried forward after a later step invalidated it, which is exactly
> the staleness class the gates in this repo exist to prevent. Re-verify claims at the point
> you publish them, not at the point you first prove them.
>
> The full local suite is 1,589 pass / 14 fail, all vscode-scanner, all from the missing Windows
> `zip` binary - the documented environment gap, green on CI. Not a regression.

> Note (2026-07-28, claude-opus-4-8): Released v5.20.2 - removed the TS2590 build ceiling
> and bumped the AAHP gate toolchain to 3.9.0 (supersedes PR #83).
>
> THE CEILING - AND A CORRECTION. The incoming handoff stated the boundary as exactly 2,243
> entries (clean at 2,242), giving "about 4 days". That number is UNREPRODUCIBLE and is
> retracted. Re-measured on this file with TypeScript 7.0.2 across four padding shapes: the
> TS2590 limit is CONTENT-dependent, not an entry count. Uniformly-shaped entries - exactly
> what the daily advisory import appends ({type:"package", severity, confidence, source,
> firstSeen}) - fail at 1,256 total, i.e. only 58 entries of headroom above the 1,197 on main.
> Shape-diverse entries reach 4,245. 2,243 sits between the two, consistent with a third
> unrecorded shape. Operationally this was FAR more urgent than "4 days": the next 250-entry
> import could have broken the build. Do not record any single number as "the ceiling" again
> without stating the entry shape it was measured with - that ambiguity is what caused this.
>
> Fixed by storing the feed as capacity-bounded FEED_CHUNK_n consts spread into BUNDLED_FEED.
> Measured: 100,000 entries across 100 chunks typecheck clean in ~9.1s; 4,547 real entries
> produced by the actual importer in 2.35s. feed.json is byte-identical - no IOC data changed.
>
> CHUNKS HAVE THEIR OWN CEILING - capacity is not arbitrary. A single chunk fails at 3,053
> real-shape entries (clean at 3,052), and the per-chunk limit is independent of chunk count
> (9 x 3,000 = 28,197 total is clean). FEED_CHUNK_CAPACITY is therefore 1,000: a 3.05x margin.
> Do not raise it toward 3,000 "because chunks are fine" - that is a 1.02x margin and walks
> straight back into TS2590. Every threshold here is tied to the current FeedIOC interface and
> to tsc 7.0.2; re-measure if either changes.
>
> HOW LONG THIS HOLDS, HONESTLY. The CLIFF is gone: with rollover no single literal can grow
> into TS2590 again, and the three guards make a silent short feed impossible. What remains is
> GRADUAL, not a cliff. At 250/day the feed reaches ~100k entries in about a year, where tsc
> measured ~9.1s (today: 0.34s), and src/threat-intel.ts plus its compiled dist/ output would
> be roughly 15 MB - and package.json `files` ships dist/**, so the npm tarball grows with it.
> Neither breaks anything; both degrade. The structural answer WHEN that matters is to move the
> feed data out of TypeScript into a JSON data file loaded at runtime, which fixes build time
> and tarball size together. That is deliberately NOT done here: it would trade the compile-time
> FeedIOC validation this release just proved intact for a runtime check, and it is a far bigger
> change than a build that was days from breaking could wait for. Revisit when tsc time or
> tarball size actually hurts, not before.
>
> VALIDATION IS NOT WEAKENED by chunking - verified, not assumed. Five defect classes were
> injected into a 30,000-entry chunked build at first/middle/last chunk positions and all five
> were caught: bad severity literal (TS2322), missing required field (TS2741), wrong primitive
> type (TS2322), unknown property (TS2353), bad type literal (TS2322). tsc still typechecks
> every entry against FeedIOC, so the data-integrity gate the array shape provides is intact.
>
> THE HANDOFF UNDERSTATED THE SCOPE. It called this a two-file change (threat-intel.ts +
> generate-feed.mjs). It is THREE: scripts/import-threat-feed.mjs (the daily importer) uses
> the SAME marker/terminator pair, so after chunking it would have appended into the spread
> array and check:feed would have gone red the next morning. More importantly, chunking
> ALONE only defers the ceiling: the importer appends to one place, so that array grows back
> to 2,243 in about eight days. The real fix is ROLLOVER - applyEntries now fills the last
> chunk to FEED_CHUNK_CAPACITY (1000) then opens a new chunk and registers it in the spread,
> splitting oversized batches across as many chunks as needed. Simulated three consecutive
> imports (+250, +600, +2500) against the real file: counts exact, max chunk 1000, no drops.
>
> THE NEW FAILURE MODE IS GATED. Chunking introduces exactly one way to ship a silently short
> feed: a chunk that exists but never makes it into the spread. That is now caught three ways -
> generate-feed.mjs throws at generate/--check time (chunk totals vs composed total), and four
> feed-integrity tests assert the bundled total equals feed.json entryCount, stays above a
> floor, equals the sum of declared chunks, and that no chunk exceeds capacity. Mutation-proved:
> dropping ...FEED_CHUNK_1, turns check:feed red and fails 3 guard tests; restore returns green.
>
> PR #83 (dependabot aahp 3.8.1 -> 3.9.0) was red on Build and Test, but NOT because of AAHP.
> Its check:aahp step passed all 7 gates on 3.9.0; the failure was check:handoff, because the
> generated DASHBOARD.md embeds the dependency table, so any dep bump makes it stale and
> dependabot cannot regenerate it. Integrated the bump here with a handoff refresh instead;
> #83 is superseded and should be closed rather than merged.
>
> STILL OPEN (deliberate, unchanged): the sourcemap packaging win (tsconfig sourceMap +
> declarationMap ship ~862 KB of dead maps pointing at src/, which is not in the tarball) was
> NOT bundled into this release - it is a packaging change, independent of the build ceiling,
> and mixing it in would widen the blast radius of a fix that had a deadline. Next-highest-value
> work remains item 2 in the 2026-07-28 note below: making shipped indicators reachable
> (npm dependency check wired to the feed, requirements.txt/pyproject matching, and the
> cross-namespace over-match where bare unscoped npm entries are compared against PyPI names).

> Note (2026-07-28, claude-opus-5): Released v5.20.1. Data-only release: the 258 indicators from PR #84 (250 imported package IOCs plus the 8 hand-added AsyncAPI infrastructure indicators) and the 5 campaign tests covering them. No behaviour change, hence a patch.
>
> URGENT, DISCOVERED THIS SESSION AND NOT FIXED BY THIS RELEASE: `npm run build` will begin failing on its own within about four days. `tsc` throws TS2590 ("union type too complex to represent") on the BUNDLED_FEED array literal at exactly 2,243 entries; 2,242 is clean. Boundary reproduced directly on this box with the repo's pinned compiler (TypeScript 7.0.2), both sides confirmed. main is now at 1,197 entries and the daily importer adds 250/day, so the wall lands about 2026-08-01. Nothing needs to change for this to happen - the scheduled import walks into it. THE FIX IS CHEAP AND MEASURED: split BUNDLED_FEED into chunked const arrays of about 1,500 and spread them back together (`const BUNDLED_FEED: FeedIOC[] = [...FEED_CHUNK_0, ...]`). Verified clean at 30,197 entries in 2.76 s, with no build-plumbing change, `tsc` still typechecking every entry, and feed.json byte-identical. This is the next action and it should not wait for the next daily run.
>
> BACKLOG DECISION, MADE - do not re-litigate: DO NOT BACKFILL the importer backlog, and leave `--limit 250` alone. A 15-agent analysis (4 understand, 3 design, 6 adversarial judges, 1 synthesis; the fourth design agent died on a connection error, so the "query the API instead of vendoring" option got less scrutiny than the other three and is the one gap in this decision) reframed the problem three times over. (a) There is no capacity problem: the normal advisory rate is ~500-900/month and the 29,246 backlog came from four burst days of mass-spray spam, 21 July alone contributing 11,520. `--limit 250` is newest-first, so it keeps the freshest advisories and drops the stalest - it has been an accidental quality filter, not a bottleneck, and every high-value catch in the feed came in under it (jest-canvas-mock@2.5.3 at 11.3M downloads/month, still installable; the @antv wave). (b) The backlog is mostly dead data: sampled against the live registries, ~98% of the PyPI names and ~88% of the npm version-pins are already removed. (c) THE ONE THAT MATTERS, verified in code by the orchestrator: the main `scan` path never calls matchPackageIOC for npm dependencies at all. scanner.ts calls checkThreatIntel (which skips type:"package" entries by design) and checkBadVersion (which reads the hand-maintained KNOWN_BAD_NPM_VERSIONS constant, NOT the feed). Feed package entries reach only the specialised scanners (cargo/composer/go/nuget/python-lockfile/rubygems/mcp/install-guard). So the imported package IOCs are largely decorative in the primary path that the GitHub Action exercises. Ingesting 29,000 more into a path that does not consult them buys nothing.
>
> THEREFORE the agreed sequence, in priority order, none of it done yet: (1) chunk BUNDLED_FEED to unblock the build, plus drop dist/**/*.map from the published files (862 KB of maps pointing at src/, which is not in the tarball). (2) Make what is already shipped reachable - wire the npm dependency check to the feed, add requirements.txt / pyproject.toml feed matching, and fix the cross-namespace over-match where bare unscoped npm entries are compared against PyPI names (2 of 190 sampled collide with live PyPI packages today, so this is a live false-positive risk and it gets 25x worse under any backfill). This step buys more real detection than the backfill would. (3) Build a withdrawal reconciler - there is currently NO removal path anywhere in the repo; package IOCs are append-only, exempt from confidence decay, and produce hardcoded critical findings forever, while GitHub does withdraw malware advisories and sometimes weeks after publication, which the import-time withdrawn_at check structurally cannot catch. Use the advisory API's `updated=` filter, NOT one GET per advisory (that design needs ~20,000 requests against a 1,000/hour cap). (4) A daily dry-run watchdog that alarms on the DERIVATIVE (backlog accelerating) rather than on `remaining > 0`, which is permanently non-zero and would be ignored within a week; it must pass --allow-truncated and a raised page cap or it goes blind on exactly the burst days it exists to watch.
>
> TWO PROPOSALS REJECTED AS FATAL, recorded so they are not re-proposed: collapsing feed entries into a `versions[]` array (an already-installed client does not reject the unknown shape, it reads it as a BARE-NAME catch-all matching every version of that package - a fleet-wide false-positive event through the unversioned feed URL, for 0% wire saving after compression), and downgrading bulk entries to severity `high` (the Action's `fail-on` default is `critical`, so this silently stops failing builds on real malware hits). Also rejected: auto-merge for the importer PR (its OSV "trusted class" gate queries by package name only, with no version and no advisory id, making it most permissive on exactly the hijacked-legitimate-package case that most needs a human), shrinking published feed.json to a curated core (the package value-shape regex has never changed since v5.12.0, so package entries carry near-zero version-skew risk; the split would silently stop delivering 816 package IOCs to installed clients for a miscounted safety gain), and defaulting the Action to fetch the feed at scan time (breaks CI reproducibility and falsifies the README's "no network call, no telemetry" claim on a public artefact).
>
> OPEN QUESTION FOR EMRE, not a defect: is this product an intelligence feed or a blocklist mirror? The 447 curated entries all carry campaign attribution, so a hit tells an operator which campaign they are in and what to rotate; the ~750 imported entries carry none and duplicate what npm audit and Dependabot already deliver live and free. If the answer is "intelligence feed" then ~12% coverage of published advisories is the CORRECT answer rather than an embarrassment, and it belongs in the README as a stated design choice.

> Note (2026-07-28, claude-opus-5): Daily threat-intel run. `npm run feed:import` added 250 malicious-package IOCs from the GitHub Advisory Database (advisories published 2026-07-14+), 125 corroborated against OSV.dev. No page-cap failure, but the run used 184 of the 200-page budget against 165 the day before, so the window did NOT need slicing this time and probably will next time: when it goes fatal, slice with `--since`/`--until` rather than reaching for `--allow-truncated`. The importer skipped 31 (22 unsafe-package-name, 8 unmappable-version-range, 1 withdrawn) and reported 29,246 further entries waiting behind `--limit 250`, up from 25,583 yesterday. That gap is now GROWING faster than a 250/run cadence can drain it, which means the oldest slice of every window ages out permanently; it is the same backlog cohort recorded in the v5.19.0/v5.20.0 notes below and is a package-size decision for Emre, not a defect to fix here.
>
> Manual enrichment (STEP 1b) closed a real gap rather than adding a new campaign. The 2026-07-26 note below recorded AsyncAPI as "already in the blocklist"; that was true only of the package pins and one IPFS CID. The atomic infrastructure was never ingested, so the campaign was detectable by version but invisible by behaviour. Added, corroborated by Socket and StepSecurity independently: the C2 host 85[.]137[.]53[.]71 (:8080 commands, :8081 credential upload, :8091 proxy management) and the Ethereum fallback contract 0x12c37a86...eac710 (stored lowercase; feed matching is case-insensitive via contentLower, so the EIP-55 checksummed form in the write-ups still matches). Added single-source at confidence 0.85 and labelled as such in-code: the second IPFS CID Qmet4fhs... serving the @asyncapi/specs branch (StepSecurity only; Socket lists just the generator CID), and SHA-256 for all five malicious registry tarballs (Socket only, though StepSecurity corroborates the same five artifacts by version). The hashes are the part the version pins cannot do: they catch a vendored or mirrored copy where the version metadata is gone.
>
> THREE INDICATORS DELIBERATELY NOT INGESTED, so a future run does not "fix" this by adding them: (a) the campaign's Nostr relays (relay.damus[.]io), BitTorrent DHT bootstrap nodes (router.bittorrent[.]com, dht.transmissionbt[.]com) and the ipfs[.]io gateway apex are shared public infrastructure - blocking any of them flags every legitimate consumer, which is the false positive that gets the tool switched off; only the campaign-specific CID paths are matched. (b) StepSecurity lists the malicious commits' git identity as "Your Name" <you@example[.]com> with GitHub login `invalid-email-address`; that is git's unset-identity placeholder, not an attacker handle, and adding it to KNOWN_MALICIOUS_GITHUB_ACCOUNTS would match unrelated repositories with misconfigured authorship. (c) Xygeni digest 80 (July 17-24 wave: bingo-ai's 85 PyPI versions in 23 minutes, the Twilio and crypto/DeFi impersonation clusters) published exactly one atomic indicator, npoint[.]io, the free JSON-hosting service used as a C2 relay by the gcli-control RAT. Same shared-host rule: the specific bin URL would have been ingestable, but it was not published. Those packages are the importer's job and are in the backlog, not hand-added.
>
> Structural note worth keeping: the EVM contract went into BUNDLED_FEED as type:"url" and NOT into KNOWN_C2_WALLETS, following the EtherRAT/FakeAgent precedent and the shape contract in src/threat-intel.ts, whose branch 1 exists for exactly this (0x + 40..64 hex). KNOWN_C2_WALLETS holds the non-EVM addresses (Tron, Aptos) that have no structure to floor. A bare IPFS CID cannot go in the feed at all - it is opaque base58 with no host, port or path, so it fails the url shape floor; it must be the ipfs[.]io/ipfs/<CID> form there, which is why the dead-drop entry differs from the bare-CID PhantomSync entries in ioc-blocklist.ts. Five tests added to campaigns.test.ts covering the new dead drop, C2 IP and tarball hash, plus a NEGATIVE test asserting the bare gateway host and an adjacent IP (85[.]137[.]53[.]70) produce zero findings.

> Note (2026-07-27, claude-opus-5): Released v5.20.0. Closes the "Needs a decision" items from PR #80/#81 and adds a guard for the whole defect class rather than just the instances. SHIPPED: (1) the `url` indicator shape is now structural. It was /^[!-~]{8,}$/, which accepted `process.env`, `require(`, `module.exports` and every other 8-char code token; since every non-package feed entry is substring-matched against whole file contents at its own severity, one typo or one hostile remote entry would have flagged an entire repository as critical. The new shape has three branches (0x EVM address; scheme:// or // + host; bare host that carries a port or a path). Measured before shipping: accepts 9/9 shipping url values in BOTH the bundled feed and feed.json, 14/14 plausible-future shapes, leaks 0/39 hostile code tokens, 9.5 ms for 200 iterations over 2 KB adversarial inputs. A bare dotted host is deliberately REJECTED because it is indistinguishable from a dotted identifier - those belong in type:"domain". VERSION-SKEW INVARIANT now in the code comment: this shape may only be LOOSENED in a release that does not itself add an entry needing the looser shape, because parseFeedPayload rejects the ENTIRE document on one invalid entry and DEFAULT_FEED_URL is unversioned - shipping both at once makes every older client discard the whole feed on refresh. (2) `jenkins:checkmarx-ast-plugin@2026.5.09` was UNREACHABLE: no code path passed a `jenkins:` prefix to matchPackageIOC, so a critical indicator shipped as detection that could never fire. Fixed by adding `go` and `jenkins` to the MCP ioc_lookup enum (widening checkBadVersion's union accordingly) rather than by deleting the indicator - deleting a verified critical IOC to make a guard green trades real detection for a green test. (3) Deleted two dead collections from src/patterns.ts, GLASSWORM_MARKERS and C2_DOMAIN_PATTERNS: exported, read by nothing. Zero detection loss - the GlassWorm marker is a live FILE_PATTERNS rule and the first C2 pattern duplicates a live blocklist entry; the second was NOT recreated because it matches ordinary Cloudflare Workers hostnames. (4) NEW src/__tests__/collection-reachability.test.ts, the recurrence guard. Four guards, all data-driven so a new entry is covered without a test edit: A dead-symbol scan over every exported collection; B every package feed entry reachable by a matcher some caller actually invokes; C every blocklist entry fires its rule through the real scan-path function, plus targeted normalization probes for GitHub login case-insensitivity and PEP 503; D a benign-code corpus produces ZERO findings. D exists because A/B/C are all monotonic in matches and therefore structurally blind to OVER-matching, which is the failure that gets the tool switched off. HONEST SCOPE, written into the file header: A would have caught the dead KNOWN_C2_WALLETS but NOT the case-sensitivity or PEP 503 bugs; C would have caught those two but NOT the dead collection, because it was EMPTY and a per-entry loop passes vacuously over zero entries. No single guard covers the class; that is why there are four. All five mutation proofs run and recorded. CLOSED DECISION, do not re-litigate: KNOWN_C2_WALLETS must NEVER seed the src/solana-monitor.ts watchlist. That watchlist speaks Solana JSON-RPC only, against a hardcoded endpoint, and filters the SPL Memo program; all three shipped wallet IOCs are Tron/Aptos and none is a Solana pubkey. Seeding buys zero coverage (detection already ships via IOC_KNOWN_C2_WALLET in the scan path) and would abort `watchlist monitor` at the un-guarded baseline loop. OPEN, tracked here, NOT shipped: (i) cross-namespace over-match - bare npm-namespace feed entries are matched against PyPI specs (src/mcp-scanner.ts, src/mcp-server.ts); 563 bare entries, 285 unversioned. The fix ORDER matters: classify the bare entries by registry, re-namespace, THEN gate the matcher. Gating first would lose `uvx lightning@2.6.2`, a genuine PyPI hijack currently filed bare - a false negative, the worse failure. (ii) type:"domain" has the same shape hole the url type just lost, and is worse (no length floor at all: value "e.g" is accepted today). The only real discriminator is a TLD allowlist, which is a data blob with its own maintenance burden. (iii) monitorWatchlist's baseline loop has no per-entry try/catch, so one bad address kills baselining for every other watched wallet; confirmed real, but its mutation proof needs a way out of the infinite poll loop. (iv) PREFIXED_ECOSYSTEMS in src/mcp-server.ts lacks pypi:/cargo:; confirmed UNEXPLOITABLE (it can only compare a literal "pypi:foo" as a bare name, which cannot produce a miss). (v) A Solana address validator on addToWatchlist would change a PUBLIC library export and needs its own minor. (vi) The ~25,583-entry importer backlog is now unblocked by the v5.19.0-era Map index but NOT drained; that is a package-size call (packed ~0.49 -> ~0.86 MB, unpacked ~2.21 -> ~8.98 MB; the older 5.39 MB estimate omits dist/threat-intel.js.map, which does ship). Deliberately kept out of this release so a 25k-entry machine-generated diff does not land on top of four code changes. Never open a GitHub issue for any of these: a release leaves zero open issues and zero open PRs.

> Note (2026-07-27, claude-opus-5): Fixed the three items parked under "Needs a decision" in PR #80. CORRECTION FIRST, because it was wrong in the note below: the claim that wallet addresses had no detection path is FALSE. They already ride the feed as `FeedIOC` type `url` - four EtherRAT/FakeAgent operator wallets have shipped that way since April, and the value-shape contract in src/threat-intel.ts documents "42-char 0x wallet addresses" explicitly. The three ViteVenom addresses could have been ingested on 2026-07-27 with no code change. Declining to ship into a dead constant was still right; the stated reason was not. (1) KNOWN_C2_WALLETS re-homed from src/patterns.ts, where it was empty and imported by nothing, into src/ioc-blocklist.ts as a Record, seeded with the 3 published ViteVenom/ChainVeil Tron+Aptos addresses, matched by a new IOC_KNOWN_C2_WALLET rule and wired into the scanner's infrastructure recommendation + getRecommendation map. Matching is exact-literal by design and a load-time floor rejects anything under 32 chars or under 12 distinct chars, because the realistic ingest mistake is a short-form Aptos address (0x1) that would substring-match every file; a fixture-based unit test cannot catch a value nobody added to the fixture. Aptos addresses are stored WITHOUT the 0x so a concatenated literal still matches. A REJECTED design is worth recording as a repo invariant: adding a "wallet" variant to FeedIOC would be FLEET-BREAKING, because parseFeedPayload (src/feed.ts) throws on the first entry failing isValidFeedIOC and rejects the ENTIRE document, and DEFAULT_FEED_URL is an unversioned raw.githubusercontent main URL. One wallet-typed entry in the published feed.json would permanently kill the whole same-day-protection channel for every already-installed older client. INVARIANT: no new FeedIOC.type value may ever appear in the published feed.json without a new versioned feed URL. (2) The malicious-GitHub-account blocklist had SIX unreachable mixed-case entries, not the three claimed (BufferZoneCorp, Mr_Rot13, TeamPCP, BrutalStrike, Sicoob-Cooperativa, Xpos587 - 23% of the list): the check lowercased the owner and compared it against the raw array. Now normalized through one isKnownMaliciousAccount helper. Two adjacent defects found and fixed in the same pass, both arguably worse: the hasGhCli() gate sat ABOVE the blocklist check, so on any runner without the GitHub CLI the entire 26-entry list was dead (it is a local array lookup needing no network, and now runs first); and checkBadVersion did a raw key lookup for PyPI, so LiteLLM==1.82.7 passed while litellm was flagged - now PEP 503 normalized. npm is deliberately NOT normalized: npm names are case-sensitive at the registry, so lowercasing there is the one variant that could create a false positive. Mr_Rot13 stays unreachable via the repo-owner path because GH_OWNER rejects underscores as injection hardening and "_" is not a legal GitHub login; a test asserts that the unreachable set is exactly [Mr_Rot13] so a future addition is noticed. (3) matchPackageIOC is now a Map index built once per feed array (WeakMap-keyed), preserving semantics exactly - NuGet case-insensitivity, and first-match-wins between a bare-name and a version-pinned entry for the same package. The reference linear implementation is KEPT in the file and a differential parity test asserts the index agrees with it across every entry in the real feed plus wrong-version, case-flipped and absent probes; that test, not a timing assertion, is the guard. loadThreatIntel is memoized on cache path + mtime/size + TTL bucket and now returns the array BY REFERENCE (verified: none of the 29 call sites mutate it), which is also what keeps the index valid across calls. Measured on this box, 200 deps: 12.1 ms -> 0.08 ms at the current feed, 573.6 ms -> 0.10 ms at 26,000 entries; memoization saves a further 142 ms per scan against a 2.3 MB cache. DEVIATION from the plan: the dead matchPackageIOC("npm", ...) call at src/install-guard.ts was NOT deleted. The only argument for removing it was cost, and the index reduced that to an O(1) miss; meanwhile a remote or third-party feed may legitimately publish npm:-prefixed entries, so deleting it would have created a silent false negative to save nothing. Kept with a comment. Mutation proofs run for all three items (reverted case normalization -> 2 red; removed wallet loop -> 3 red; dropped the NuGet fold -> 3 red; broke bucket ordering -> 1 red). Still open and NOT done here: the backfill decision (packed tarball ~0.49 -> ~0.86 MB, unpacked ~2.21 -> ~8.98 MB; the earlier 5.39 MB estimate appears to omit dist/threat-intel.js.map, which does ship), whether KNOWN_C2_WALLETS should seed the src/solana-monitor.ts watchlist (that CLI is the product's other wallet home and remains a separate seam), and the isValidFeedIOC url shape floor, which today accepts values like "require(" or "process.env" that would substring-match every scanned file.
> Note (2026-07-27, claude-opus-5): Daily threat-intel run. `npm run feed:import` added 250 malicious-package IOCs from the GitHub Advisory Database (advisories published 2026-07-13+), 173 corroborated against OSV.dev; the bundled feed goes 680 -> 939 entries. No page-cap failure this run (165 of the 200-page budget), so the window did not need slicing. The importer skipped 31 (22 unsafe-package-name, 6 unmappable-version-range, 2 unsupported-ecosystem, 1 withdrawn) and reported 25,583 further entries still waiting behind `--limit 250` - that is the known backlog described in the v5.19.0 notes below, not a new regression, and it is NOT recoverable by repeated runs at the current limit: the window holds far more than 14 days of runs can drain, so the oldest slice will age out. This is the same cohort as DEFERRED item (2) below and still needs the `matchPackageIOC` Map indexing in item (1) before any bulk backfill is safe. Manual enrichment (STEP 1b) added the ChainVeil wave: nine npm typosquats of Tailwind/Sass/TypeORM/rate-limiter libraries (Checkmarx Zero, June 16 2026), the predecessor of the already-covered ViteVenom cluster, tied to it and to DPRK PolinRider by shared Tron/Aptos addresses and XOR keys. Corroborated by two independent sources and verified against the live npm registry: all nine now return `0.0.1-security` "security holding package" placeholders, i.e. npm removed them as malware, which is why bare names are safe. Two indicators were deliberately NOT ingested, both worth knowing about: (a) the ViteVenom Tron wallets and Aptos address are now published (the July 26 note said they were unextractable), but `KNOWN_C2_WALLETS` in src/patterns.ts is declared and never imported anywhere in src/, so it is dead code - ingesting them would look like coverage while detecting nothing, and `FeedIOC.type` has no wallet variant either; (b) a C2 IP attributed to ViteVenom by one aggregator could not be corroborated, and this campaign's whole design is blockchain C2 rather than IP infrastructure, so a single-sourced IP was treated as too weak to block. Separately, `KNOWN_MALICIOUS_GITHUB_ACCOUNTS` is matched case-sensitively in src/github-trust-scanner.ts (`includes(owner.toLowerCase())`) while the ioc-blocklist matcher is case-insensitive, so the mixed-case entries BufferZoneCorp, Mr_Rot13 and TeamPCP can never match via the repo-owner path; not touched here because it is a code defect, not threat intel. The npm publisher handle `successkeyteck` was likewise not added, because both account matchers are GitHub-specific and it is an npm account.

> Note (2026-07-26, claude-opus-5): Docker image build moved off QEMU onto native runners. Symptom was a hung "Build and push" step whose log could not even be expanded in the Actions UI, because GitHub had no log blob for it at all (`BlobNotFound`) - the step produced zero output. Cause: `linux/arm64` was built under QEMU emulation and Node under `qemu-user` has a deadlock class that stalls `npm ci`/`tsc` silently. Baseline for this workflow is about 90 seconds, so a hang is unmistakable once you look at run history: v5.18.0 ran 18:21:45 -> 00:22:05 and was killed by GitHub's default 360-minute job timeout, and v5.19.0 hung the same way, which is why ghcr `:latest` sat on 5.18.2 after v5.19.0 shipped to npm. Fix: per-architecture native runners (`ubuntu-latest`, `ubuntu-24.04-arm`) each pushing a digest-only image, plus a merge job that builds the manifest, refuses fewer than 2 digests, and verifies both architectures are present before going green. Tagging moved into that merge job so a half-finished matrix cannot move `:latest` onto a single-arch image. Added explicit `timeout-minutes`, per-arch gha cache, and a `version` dispatch input as the recovery path for a release whose image failed after npm had already published. Two process notes for future sessions: (1) the `actions/download-artifact` SHA I pinned in the first draft did not exist upstream - every action pin in a new workflow must be checked against the API before pushing, which is doubly true in this repo; (2) this commit initially failed `aahp-verify` Layer 2 because `npm run handoff:refresh` regenerates DASHBOARD/TRUST/LOG/MANIFEST but does NOT write STATUS.md, so any code change needs a STATUS note added by hand first, then a refresh.

> Note (2026-07-26, claude-opus-5): CORRECTION to the two notes below, and process hardening. The claim that the importer's 250-entry cap left "a backlog remains for the next run to pick up" was WRONG, and the importer's own output is what made it plausible ("New entries: 250 (limit reached)"). Measured against the live API: the binding cap was `maxPages=10`, i.e. 1000 advisories, while the 7-day window held 11,952 advisories mapping to 20,915 new IOCs. Only 1,108 were reachable, so 94.7% of the window was never fetched. Worse, the query is `published/desc` and there is no cursor, so the unfetched remainder is the OLDEST slice and every subsequent run re-fetches the same newest pages: that remainder was unreachable by any number of runs and aged out permanently. 8 of 54 rolling 7-day windows over the previous 60 days exceeded the cap, so this was recurring, not an edge case. A silent false negative is the failure this scanner exists to prevent, so truncation is now FATAL (`--allow-truncated` to override), `maxPages` is 200, `days` is 14, and the capped message states how many entries are waiting and that they expire. `--limit` stays 250 deliberately: it is a review bound, entries over it are genuinely recoverable, and a 2500-entry machine-generated diff in a public repo is not reviewable.
>
> Adversarial review of the v5.19.0 gates (5 agents) found 8 defects in the first draft, all fixed before merge, and 6 smaller ones deliberately deferred and recorded here rather than as open issues. Fixed: the attribution pattern was brand-anchored and enumerated two literal URLs, so plain text with no link, a trailing space inside the link text, a percent-encoded hyphen, the docs.claude.com URL, and three trailer variants all evaded it (now attribution-PHRASE anchored plus the vendor no-reply address, proven against all 8 payloads); the include list covered 12 files and missed package.json, server.json, socket.yml, policy-schema.json and src/ (all published); the CI step would have hard-blocked dependabot (which cannot edit its own body) and any revert or cherry-pick, since main carries 137 commits with an inherited trailer; it also failed OPEN on an empty base sha; commit author/committer identity was unchecked; the changelog gates rejected any SemVer pre-release and were coupled to package.json's exact indentation; and my own token fail-fast broke 8 offline tests until it was scoped to the real network path. DEFERRED: (a) the zero-coverage pathspec CLASS is still unguarded - a one-character edit can silently return any rule to scanning nothing while the gate reports green, which needs the file count in the gate output (upstream AAHP change); (b) post-merge PR body edits cannot be blocked by a merge gate, only detected; (c) numeric CLI options are unvalidated, so a fractional --limit yields a fractional `remaining`; (d) `.ai/handoff/LOG.md` renders "### Fixed" as the headline for Keep-a-Changelog releases; (e) docSync failure messages read backwards for same-file groups; (f) whether 5.19.0 should have been a patch, since scripts/ is not in the npm payload and dist/ is functionally identical - the two Added bullets are prefixed "Repo process:" so a stranger is not misled either way.
>
> DEFERRED, needs Emre: (1) `matchPackageIOC` (src/threat-intel.ts) lowercases every feed value on every call and is O(feed) per package, measured 5.6 ms at 680 entries but 59.6 ms at 3,000 and 510 ms at 21,595 for 200 deps. Indexing it into a Map is the prerequisite for any large feed growth; it was left out of this release rather than bundle a core-matching-path refactor with process gates. `--limit 250` keeps growth at about 250/run so no regression is introduced meanwhile. (2) A one-time backfill of the ~20,915 IOCs already missed would take the npm tarball from 2.13 MB to about 5.39 MB (+152%) and needs (1) first; it is a judgement call about package size, not a defect fix, and part of that cohort has already aged out. (3) The daily import still runs from a local scheduled task on this machine rather than from a workflow in the repo, so its flags are invisible to review and uncovered by CI.

> Note (2026-07-26, claude-opus-5): Released v5.18.2 - the 250 imported IOCs from #75, no code change. Two process defects were fixed in CLAUDE.md in the same commit, both of which had caused rework this session: (1) the release process said `git push origin main`, but `main` is protected with required checks AND `enforce_admins: true`, so a direct push is rejected and every release must go through a squash-merged PR with the tag applied to the merged commit afterwards; (2) a new hard rule bans AI attribution footers in commits, PR bodies and release bodies, because the Claude Code harness's own default instructions tell the agent to append `🤖 Generated with Claude Code` to every PR body, so it silently returns each session unless this file countermands it. Anything that depends on suppressing a harness default belongs in CLAUDE.md, not in memory, since memory is not loaded in every session.

> Note (2026-07-26, claude-opus-5): Daily threat-intel run. `npm run feed:import` added 250 malicious-package IOCs from the GitHub Advisory Database (advisories published 2026-07-19+), 194 corroborated against OSV.dev; the bundled feed goes 430 -> 680 entries. The run hit the importer's default 250-entry cap, so a backlog remains for the next run to pick up. Importer skipped 21 (20 unsafe-package-name, 1 withdrawn); nothing was reported as unmappable (no bounded version ranges, no unsupported ecosystems this batch). Manual enrichment for atomic indicators found nothing addable: all current vendor write-ups (AsyncAPI, jscrambler, node-ipc, Shai-Hulud family) are already in the blocklist, and the sole uncovered campaign (payment-SDK typosquats, July 2026) exfiltrates only via shared ngrok-free[.]dev tunnels and AWS infra, which discipline forbids blocking. Note for future runs: this branch was cut from 01525d8 while main advanced to v5.18.1, so it was rebased onto main before merge - `src/threat-intel.ts` was untouched upstream, so the 250 entries re-applied cleanly and only CHANGELOG/STATUS plus the two generated files needed redoing.

> Note (2026-07-25, claude-opus-4-8): v5.18.1. The scanner state directory `.scg-history/` now writes a `.gitignore` containing `*` when it is created, so scanner state can no longer be swept into a consumer commit by `git add -A`. Found because a risk-history file written in April was committed to a public repository in June inside an unrelated commit. New `src/state-dir.ts` is the single creation point for both the history and triage stores; 5 tests cover it, including one that runs real git and asserts nothing stages.

> Note (2026-07-25, claude-opus-4-8): Released v5.18.0 with the internal-disclosure rule family. Post-review follow-ups in this commit: `spec/` is scanned again (it is the OpenAPI and AsyncAPI convention as often as an RSpec one, and a server URL in an API spec is the shape the family most wants to catch), the deny-list pass now reports its own 400-token per-line budget as INTERNAL_DISCLOSURE_TRUNCATED instead of going quiet, and the per-file cap emits exactly 100 findings while keeping the most severe ones. 75 tests in the family, 1522 in the suite; the 14 vscode-scanner failures are `zip` missing on the Windows dev box and reproduce identically on main.

> Note (2026-07-25, claude-opus-5): Adversarial review of the
> internal-disclosure family came back FAIL with measured numbers; this is the
> remediation, measured the same way (axios, express, got, awesome-compose =
> 992 files, plus an 810 KB single-line bundle).
> BLOCKER, quadratic scan cost. The 810 KB bundle took 49 s and produced a
> 26 MB report. Three causes, all fixed: the per-match lexical context
> (quotedRanges + three indexOf calls) rescanned the whole line for EVERY match
> on it, the overlap dedupe was quadratic across the whole file (on a bundle
> every finding shares line 1), and nothing bounded the match count. Now: one
> line index per file built once and binary-searched (buildLineIndex /
> lineAtOffset), per-line context computed once and cached, a 2000-character
> line limit that skips the rest of an over-long line in a single lastIndex
> jump, dedupe grouped by line, and caps of 25 findings per rule, 100 per file,
> 20000 candidate matches per rule. Same file now scans in 0.01 s with a
> sub-1 KB report. Every limit that fires emits INTERNAL_DISCLOSURE_TRUNCATED
> (info) - the FILE_TOO_LARGE_SKIPPED principle: a scanner that silently
> stopped looking is indistinguishable from a clean repository.
> BLOCKER, test directories were not excluded. TEST_FILE used /\/tests?\//,
> which requires a LEADING slash, so a top-level test/ or tests/ directory (the
> dominant JS layout) never matched: 28 of the 35 findings on the sample came
> from directories that were meant to be excluded. The pattern now matches a
> leading segment and covers spec/, e2e/, __tests__/, __fixtures__/, __mocks__/,
> __snapshots__/, fixtures/, testdata/ and test-data/.
> Universal constants are no longer topology: cloud metadata (169.254.169.254,
> ECS 169.254.170.2, Amazon Time Sync, Alibaba), Kubernetes and k3s service and
> DNS defaults, the default pod/service CIDRs, the Docker bridge gateway and
> host.docker.internal. Each entry names what it is in the source; a real
> address in the same range still reports.
> Severity now follows the HOST, not the rule that matched first:
> INTERNAL_SERVICE_ENDPOINT was promoting every compose and Kubernetes service
> name to medium by winning the overlap dedupe against the deliberately-low
> single-label rule. severityForHost() is the single decision point.
> /Users/ is matched case-SENSITIVELY, which removes the worst false positive
> in the set: REST routes (/users/:id, /users/{id}, app.get("/users/profile/edit"))
> were being read as macOS home directories. A route or template parameter after
> the account segment is rejected as well. Windows keeps both spellings because
> the drive letter makes it unambiguous.
> A .local name preceded by a path separator is a module specifier, not a host
> ("./config.local"), and a name followed by "(" is a method call
> ("res.local(name, val)" in a changelog).
> Documentation rebalanced, and this is the one that mattered most: markdown
> prose AND fenced blocks now report private addresses, ULAs, developer paths
> and hostnames. Excluding documentation wholesale silenced exactly the case
> this family exists for - the sample turned up a real /home/<name>/ inside a
> pasted stack trace in a ```js block that the old behaviour never saw. What
> stays excluded is what MEASURED as noise: inline code spans (8 findings on
> the sample, every one an API signature or documented example), ```text
> fences, and files that exist to BE an example (examples/, fixtures/,
> *.example.*). The reserved namespace (RFC5737/RFC2606/loopback) is the
> backstop and works on every surface.
> Honesty fix: the README said a digest "reveals nothing". An unsalted
> single-round sha256 of a hostname is dictionary-attackable. The wording now
> says what it actually buys (out of the file, out of grep, out of reports) and
> an optional salt was added - SCG_INTERNAL_HASH_SALT, deliberately env-only
> because a salt committed beside the digests is hashed by the same reader,
> plus internalDisclosure.hashSalted so a scan without the salt is reported
> instead of matching nothing and looking clean.
> Two more real defects found while measuring: line.indexOf("//") treated the
> "//" of "https://" as a comment start, so every dotted name to the right of a
> URL was accepted as a hostname (and "#" is now only a comment outside the C
> family); and "http://unix" - the UNIX-domain-socket pseudo-host used by got,
> axios and dockerode - was 14 of the 35 sample findings.
> Result: 3.5 findings per 100 files -> 1.1, with the one genuine leak in the
> sample (a developer home directory in got's documentation) now REPORTED
> rather than silently missed. Self-scan stays clean at 0 findings; the new
> README and doc-comment examples were written into the reserved namespace,
> same discipline as before. NOT DONE HERE: no version bump, the release is cut
> separately.

> Note (2026-07-25, claude-opus-5): Added the internal-disclosure rule family
> (src/internal-disclosure.ts, 8 rules, INTERNAL_*). New detection axis: existing
> scanners including this one hunt CREDENTIALS, nothing hunts internal TOPOLOGY
> leaking into a public repo (internal hostnames, private LAN addresses,
> non-public forge URLs, developer paths, private repo inventories). All rules
> are shape-based so they work with zero configuration, and INTERNAL_GIT_REMOTE
> in particular finds a self-hosted forge WITHOUT anyone naming it: any ssh://
> or scp-style clone URL whose host is not one of the known public forges.
> Severity is deliberately medium (low for the single-label URL rule):
> topology is reconnaissance value, not compromise, and the default gate plus
> --fail-on high/critical stay unaffected, so nobody upgrades into a red build.
> Scores DO move (documented in the CHANGELOG Changed section).
> Deny-list solves its own paradox three ways: hashedTerms (sha256 of a term
> normalised trim+lowercase, publishable, exact-token matching only, generated
> with the new internal-hash CLI command), externalFile plus
> SCG_INTERNAL_DISCLOSURE_FILE (never committed, matches reported REDACTED so
> the report cannot leak what the config kept out), and plaintext patterns for
> repos that are private anyway. A configured externalFile that is absent is
> reported at info (INTERNAL_DENYLIST_UNAVAILABLE) instead of silently doing
> nothing - same fail-closed reasoning as the v5.3 policy validation, and info
> keeps a CI runner that legitimately has no copy of the file quiet.
> False positives were treated as the adoption question they are: two layers,
> a VALUE layer (RFC5737 addresses, RFC2606 names and the .example TLD,
> loopback, CI/placeholder account names like runner and vscode, container
> service aliases, CIDR ranges vs host addresses) and a CONTEXT layer (doc
> files, docs/ and examples/ trees, *.example.* artifacts keep only the
> hostname/endpoint/clone-URL rules; markdown fenced blocks and inline code
> spans keep only the clone-URL rule, because the copy-paste clone command is
> exactly where a self-hosted forge URL really leaks; test fixtures and
> minified bundles keep none). Extended existing plumbing rather than a
> parallel system: PatternEntry + valueFilter/valueGroup, allowlist.domains now
> also answers the host-shaped INTERNAL rules, new POLICY_INVALID_INTERNAL_TERM
> warning, Finding.category gained "disclosure", INTERNAL_ counts in the
> repoTrust risk dimension. 43 tests (src/__tests__/internal-disclosure.test.ts)
> cover a true positive per rule, the false-positive classes, all three
> deny-list modes and a test that the hashed path never stores or reports
> plaintext. Self-scan stays clean: the first draft flagged its OWN doc
> comments, where the endpoint and clone-URL examples were written as plausible
> internal names, and those were rewritten into the reserved documentation
> namespace, which is the feature working. Same discipline applies to this
> file. NOT DONE
> HERE: no version bump and no dated CHANGELOG heading, the release is cut
> separately.

> Note (2026-07-25, claude-opus-5): Cut the feed's dependency on the internal
> security-news aggregator and wired real upstream sources instead. That
> aggregator was 17 general security RSS feeds, none of them package-malware or
> supply-chain specific, so every run needed a human to chase primary vendor
> write-ups for atomic indicators; the app is also unmaintained (its repo was
> deleted during the Forgejo migration). Replacement: scripts/import-threat-feed.mjs
> imports malicious-package IOCs from the GitHub Advisory Database malware
> advisories (public REST API, no key; GITHUB_TOKEN optional, rate limit only) and
> corroborates each hit against OSV.dev querybatch (MAL- records from
> ossf/malicious-packages). OSV is corroboration ONLY - it can lift confidence
> 0.9 -> 1.0 but never discovers a package, so a MAL- record covering one version
> of a legitimate package can never become a whole-package block. Discipline
> carried over from the manual process: only an exact pin (= 1.2.3 -> name@1.2.3)
> or an all-versions range (>= 0 -> bare name) is mapped, bounded ranges are
> reported as unmappable instead of collapsed, ecosystems with no matcher are
> skipped, family/campaign stay unset because upstream publishes neither, and
> package names are re-validated against a charset with no quotes or backslashes
> before being written into TypeScript. Provenance is the FeedIOC.source field
> (0 of 430 existing entries used it); that also required adding "source" and
> "lastSeen" to FEED_ENTRY_KEYS, otherwise our own feed.json stops passing
> isInertThreatFeedFile() and gets scanned as ordinary content (the v5.4.0
> phantom-findings bug). Failure mode is inert: the fetch is the only fatal step,
> nothing is written until the batch re-parses in memory, and a rewrite that does
> not re-parse is rolled back - a network error leaves src/threat-intel.ts and
> feed.json byte-identical and exits non-zero. 42 offline tests
> (src/__tests__/feed-import.test.ts) cover the mapping, dedup and that failure
> mode with fixtures; no test touches the network. Docs in
> docs/threat-feed-sources.md carry the required attribution (GitHub Advisory
> Database CC BY 4.0, ossf/malicious-packages Apache-2.0). Historical arena
> references to that host in CHANGELOG.md and this file were reworded to "news-aggregator
> feed" so nothing points at a dead host. No IOCs were imported in this change -
> it ships the mechanism only. NOT DONE HERE: the daily refresh still runs from a
> local scheduled task on Emre's machine that fetches the retired aggregator URL; it
> needs to be repointed at `npm run feed:import` (or replaced by a scheduled
> workflow) or the dead source stays in the loop.

> Note (2026-07-25): Released v5.17.10 - rule precision. Five rules that matched a
> SHAPE without inspecting context or value are now context-aware, and one silently
> dead config key is implemented. GHA_SECRET_EXFIL_MULTILINE is per-step instead of a
> sticky file-level flag; GHA_PPE_PULL_TARGET and GHA_SCRIPT_INJECTION consider exec
> lines only and PPE requires an elevated trigger; IAC_HARDCODED_SECRET inspects the
> matched value; DOCKER_NPM_GLOBAL reports only unpinned specs; allowlist.githubOrgs is
> applied to ownership-trust findings (never to known-malicious SHAs). Two pre-existing
> false negatives were closed as well (the env-hop script-injection evasion, and
> `npm i -g` / `npm add --global`). Measured across 7 Elvatis repos: 128 -> 92 findings,
> 10 -> 1 criticals, with nothing lost outside the confirmed false-positive classes.

> Note (2026-07-25, claude-opus-5): Rule-precision pass after a fleet audit showed that
> most of the reported risk across 13 scanned repositories came from rules matching a
> SHAPE without context or value. Fixed five, each with a true-positive AND a
> false-positive test (src/__tests__/rule-precision.test.ts, 35 tests):
> (1) GHA_SECRET_EXFIL_MULTILINE had a file-level sticky `envSecretsExported` flag and a
> run-block exit test that only a column-0 line could satisfy, so one step's env secret
> made every later curl look like exfiltration and the finding named the wrong block. Now
> per step via the AST (step env + job env + workflow env + the step's own run), reporting
> the line of the network command; `git fetch` no longer counts as egress. Files the
> parser cannot split into steps keep the old file-level check (fail closed).
> (2)+(3) GHA_PPE_PULL_TARGET and GHA_SCRIPT_INJECTION were bare file regexes that fired
> on `env: PR_TITLE: ${{ github.event.pull_request.title }}`, the mitigation GitHub
> documents and our own recommendation text prescribes. New classifyWorkflowLines() in
> workflow-ast.ts labels each line exec / env / structural; both rules consider exec lines
> only, and PPE additionally requires an elevated trigger (pull_request_target,
> workflow_run, issue_comment, pull_request_review_comment), a workflow_call whose caller
> may be privileged, or an unreadable trigger block. The env hop is not a bypass: a value
> read back with ${{ env.NAME }} inside run: is still reported.
> (4) IAC_HARDCODED_SECRET never looked at the value, so `password = "${REDIS_PASSWORD}"`,
> `password = "$(openssl rand -base64 32)"` and `const token = "trust_pat_"` were all
> CRITICAL. PatternEntry gained an optional `valueFilter` (honoured by every pattern loop);
> isLikelyRealSecretValue() rejects references, substitutions, prefix templates, paths and
> placeholders, all structural checks, so a real credential is untouched.
> (5) DOCKER_NPM_GLOBAL contradicted its own recommendation by firing on `npm install -g
> pnpm@9` / `npm@11.18.0`; it now parses the specs and reports only unversioned, dist-tag
> or range installs (and covers `npm i` / `npm add` / `--location=global`). Our own
> DOCKER_NPM_GLOBAL suppression is therefore deleted from .supply-chain-guard.yml.
> (6) allowlist.githubOrgs was parsed, documented and schema-validated but never read by
> applyPolicy(); it now suppresses GHA_THIRD_PARTY_ACTION / GHA_TAG_NOT_SHA for an
> allowlisted owner, while pinning and known-malicious-SHA rules stay armed.
> Measured on 7 real Elvatis repos (baseline v5.17.9 binary vs this branch): 128 -> 92
> findings, 10 -> 1 criticals, with NO finding lost that was not one of the confirmed
> false-positive classes (the 4 deploy-workflow exfil findings stayed, only moved to the
> correct line). Self-scan 0 findings / risk 0 with the suppression removed. Full suite
> 1403 pass; the 14 vscode-scanner "zip" tests still fail locally on Windows (known env
> gap, green in CI). NOT fixed, reported for a decision: WORKFLOW_SECRET_TO_UPLOAD_PATH
> (three bare .test(content) regexes, `https?://` anywhere counts as egress),
> VIDAR_WALLET_THEFT (unbounded `.*` matched "phantom" to "seed" across a 20KB JSON line
> in a handoff MANIFEST), TYPOSQUAT_LEVENSHTEIN ("pino" vs "sinon", 14x in one repo) and
> SECRETS_PRIVATE_KEY (PEM header only, fired on a MOCK-KEY-REPLACE-IN-PRODUCTION literal).
>
> Note (2026-07-25, claude-opus-4-8): Released v5.17.9 - daily threat-intel refresh
> (scheduled task). The news-aggregator feed again carried mostly named campaigns with
> no atomic IOCs, so - per the task's STEP 1b - enriched from primary vendor write-ups.
> Added ONE new campaign: FakeAgent / SectopRAT fake Claude Desktop malvertising (Huntress
> + BleepingComputer + Help Net Security + cyberpress, 2026-07-21 to 07-22). Bing "Claude
> Desktop app" ads -> malicious public Claude Artifact on the legitimate claude[.]ai domain
> -> attacker redirect domains (download-app[.]us, claude.ai.download-app[.]us,
> downloading-api.it[.]com, plus 5ca8758c-...[.]com and polse[.]us) -> trojanized
> ClaudeDesktop.exe sideloading libcef.dll = SectopRAT/ArechClient2 infostealer w/ HVNC;
> EtherHiding via BNB Smart Chain for live C2. Added 5 domains, a 6-IP representative
> subset of the ~21 published rotating BuyVM/FranTech C2 pool (Akamai CDN edge + remainder
> omitted to limit false positives), 5 payload SHA-256 hashes, and the 2 EtherHiding C2
> addresses (as feed type "url", per the EtherRAT precedent). DISCIPLINE: the legitimate
> claude[.]ai apex is NOT blocked (only the abused artifact path was malicious) and the
> it[.]com registry apex is NOT blocked (only the attacker subdomain). Reviewed but NOT
> added: BlueNoroff Zoom phishing kit (80+ typosquat domains reported but none enumerated
> in sources - no addable atomic indicator), Golden Chickens TinyEgg/ChonkyChicken (no
> hashes/C2 in available write-ups), Slopsquatting/HalluSquatting (conceptual AI-attack
> pattern, no packages named), Talos Python-packaging research (no IOCs), and the Straiker
> Claude Code impersonation / Amatera set (single-source, March-May, largely shared-host
> subdomains + overlaps the existing ACR-Stealer entry - FP-heavy, skipped). Added to
> ioc-blocklist.ts + threat-intel.ts with 4 new FakeAgent tests (incl. a claude.ai
> negative). feed.json regenerated. Build gates + tests expected green (only the 14
> vscode-scanner "zip" tests fail locally on Windows - known env gap, green in CI).
>
> Note (2026-07-24, claude-opus-4-8): Released v5.17.8 - daily threat-intel refresh
> (scheduled task, run interactively). The news-aggregator feed carried only named
> campaigns with no atomic IOCs this cycle, so - at the user's direction - widened the
> net to the linked primary vendor write-ups (Socket, The Hacker News, OX, StepSecurity,
> safedep, Rescana) and extracted concrete indicators for three developer-targeted
> supply-chain campaigns. (1) jscrambler npm compromise (2026-07-11): extended the prior
> partial 8.14.0-only entry to the full malicious set - jscrambler 8.14.0/8.16.0/8.17.0/
> 8.18.0/8.20.0 (preinstall hook -> dist dropper), plus jscrambler-webpack-plugin 8.6.2,
> gulp-jscrambler 8.6.2, grunt-jscrambler 8.5.2, jscrambler-metro-plugin 9.0.2, and 5
> SHA-256 payload hashes; clean 8.13.0, fixed 8.22.0. (2) cPanel/WHM GitHub Actions abuse
> (Socket, 2026-07-23): C2 IP 43[.]228[.]157[.]68, the UUID DNS-callback subdomain on
> dnshook[.]site, and the Linux exploit payload SHA-256. The compromised Packagist
> maintainer (dinushchathurya) is a VICTIM, so neither the account nor the bare package
> names are ingested; only network + file IOCs. (3) Apex macOS infostealer (safedep/THN,
> 2026-07-22): @apexfdn/apex + its re-publish @copilot-mcp/apex, blocked by name (20+
> versions in 8h, no legitimate history). NOTE: this work was first cut as 5.17.7 but that
> version released out-of-band (#65, scan self-exit fix) mid-task, so it was rebased onto
> that release and re-cut as 5.17.8. Added to ioc-blocklist.ts + threat-intel.ts +
> patterns.ts with 10 new campaign tests (incl. a clean-8.13.0 negative). feed.json
> regenerated. Build gates + aahp check 7/7 green; tests pass (only the 14 vscode-scanner
> zip tests fail locally on Windows for lack of a `zip` binary - green in CI). Also widened
> the daily routine SKILL.md to make primary-source enrichment a standing step.

> Note (2026-07-21): fix(scan) - the scan command now tears down Node's global HTTP/HTTPS
> keepAlive agents on the clean-scan return path, so pooled npm/PyPI registry sockets close
> and the CLI self-terminates instead of hanging. On Node <=22 free keepAlive sockets stay
> referenced, which stalled shared CI runners for hours on clean/low scans; the critical,
> high and --fail-on exit paths are unchanged. Added src/__tests__/scan-self-exit.test.ts.
> Version bumped to 5.17.7 across the 6 version-sync sites plus CHANGELOG; tag v5.17.7 to
> publish (npm via OIDC) and move the @v5 branch.

> Note (2026-07-20, claude-opus-4-8): Released v5.17.6 - daily threat-intel refresh
> (scheduled task). Fetched the news-aggregator feed (JSON gives excerpts +
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
> (scheduled task). Fetched the news-aggregator feed (JSON gives excerpts +
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
> (scheduled task). Fetched the news-aggregator feed (JSON gives
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
> (scheduled task). Fetched the news-aggregator feed (JSON gives
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
> (scheduled task). Fetched the news-aggregator feed (JS-rendered; pulled the
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

## Historical Snapshot: 5.17.3 (superseded)

> This section is retained as historical provenance. It is not the current
> product state; see the v5.23.1 review note at the top and `package.json`.

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
