# supply-chain-guard: Current State

> Updated 2026-08-19 (release v5.26.7). This is one current snapshot, not a session
> log. Historical detail belongs in CHANGELOG.md, generated LOG.md, LOG-ARCHIVE.md,
> and git history.

---

## Carried open items (process and design, not tied to one sweep)

Deliberately a top-level section rather than another dated "Open for the owner". Both
items outlive any single sweep, and an entry filed under a sweep heading is
effectively gone once the next sweep adds its own list. Neither is urgent.

### Branch hygiene: check LOCAL branches, not only the remote

The invariant is that this repo carries exactly `main` and `v5`. That has always
been read as a statement about the remote, with `git ls-remote --heads origin`
treated as the confirmation. **It is not sufficient.** On 2026-08-17, immediately
after a clean release, the remote was correct while the shared checkout still
held six stale local branches, the oldest from 2026-08-12:
`threat-intel/2026-08-12`, `chore/release-v5.25.12`, `chore/release-v5.26.0`,
`feat/file-digest-matching`, `feat/install-hook-persistence`,
`feat/persistence-recall`. All six belonged to merged PRs (#134 to #139). They
were verified and deleted in that session; the checkout is clean as of this note,
verified again on all three checks below.

The release routine should check both sides. CLAUDE.md step 12 currently
prescribes only the remote check; its local copy on the Dev-PC was corrected
alongside this note, but **CLAUDE.md is gitignored in this repo**, so that copy
is per-machine and does not survive a fresh clone or reach the second
subscription's checkout. This section is the durable record of the rule, and any
machine picking the routine up from CLAUDE.md alone will still have the weaker
check until it is corrected there too:

    git ls-remote --heads origin     # only main and v5
    git branch --list                # only main
    git worktree list                # only the shared checkout, on main

Local leftovers are not merely untidy. A local branch held by a worktree makes
the merge command's local delete fail, and the remote branch then survives while
the error names only the local one. That is how `release/v5.25.10` was left on
the remote after a finished deploy on 2026-08-10. Removing the worktree BEFORE
merging is what prevents it, and that ordering worked correctly for v5.26.5.

Verifying a branch before deleting: every PR here is squash-merged, so
`git branch --merged`, `git cherry` and `git rev-list main..branch` all report
merged work as UNMERGED. Never delete on those. Ask GitHub, then guard the one
real loss case:

    gh pr list --state all --search "head:<branch>" --json number,state,mergedAt
    git log <branch> -1 --format=%cI     # keep it if the tip is NEWER than mergedAt

A tip newer than `mergedAt` means a commit exists that no PR knows about. That is
the only scenario in which deleting loses work.

### A duplicate CI run can block the merge while `gh pr checks` reports green

Hit while cutting v5.26.7 on 2026-08-19. Pushing the release commit onto the open
sweep PR left the head commit with **two** `CI` runs from the same `pull_request`
event, created in the same second. The workflow's concurrency group cancelled one,
and both stayed attached as check runs named `Build and Test`. Branch protection
takes the latest run per check name, saw a cancelled required check, and refused:

    X Pull request #150 is not mergeable: the base branch policy prohibits the merge.

`gh pr checks 150 --watch` said green throughout, because it reports the run it
followed rather than every run on the commit. The twin is only visible per commit:

    gh api repos/homeofe/supply-chain-guard/commits/<sha>/check-runs \
      --jq '.check_runs[] | "\(.name): \(.status)/\(.conclusion)"'
    gh run list --commit <sha> --json databaseId,name,event,status,conclusion

This is the same failure mode as the existing "do not merge back to back" rule, where
a cancelled CI conclusion blocks the deploy gate. It is worth writing down separately
because it fires from a **single** PR with no second merge involved, so that rule does
not cover it and the protection error reads as a mystery.

The fix is to re-run the cancelled twin, not to work around the gate:

    gh run rerun <cancelled-run-id>
    gh run watch <cancelled-run-id> --exit-status
    gh pr view <n> --json mergeStateStatus,mergeable    # BLOCKED -> CLEAN

Do NOT reach for `gh pr merge --admin`: protection here has `enforce_admins: true`
deliberately, and an empty commit to re-trigger CI only moves the head and can
reproduce the same duplicate. The merge went through normally once the re-run
concluded success.

### Design decision due before v6: the floating major branch, and Marketplace

Decide before v6 is cut, not during. Also captured as a memory entry outside the
repo, since it spans releases.

**How it works today,** verified against `action.yml` and `ci.yml` on main: `v5`
is a floating BRANCH, not a tag. The `update-major-branch` job fast-forward-pushes
it to each release commit (no `--force`; branches are allowed to move, so this
does not violate the never-move-tags rule). The Action is composite, and
`action.yml` on that branch pins an EXACT npm version. The number is deliberately
not repeated here: `action.yml` is one of the 14 `versionSites`, so the pin is
bumped and gated on every release, and a copy in prose only drifts.

That combination is better than it looks and should not be lost by accident:
`@v5` gives consumers a floating convenience ref, while every resolution still
installs an exact, release-gated version rather than a mutable `latest`.

**The problem at v6.** If v5.x stops being released once v6 ships, everyone still
on `@v5` keeps resolving a frozen `action.yml` pinning an old npm version, so
their IOC feed silently stops updating. For a scanner that is a false-negative
generator, and a false negative here lowers the bar across every repo using it.

**The counter-argument, which is why this needs a decision and not just an
implementation.** A major version is a breaking change by definition. `@v5` exists
precisely so a v6 that changes inputs, outputs or exit codes does not silently
break every consumer's workflow on their next run. Collapsing to a single
always-current ref makes breaking changes auto-propagate, which is the opposite of
what a major ref is for. The Action already uses exit code 2 for a critical gate
hit and publishes seven outputs, so there is real surface to break.

Options worth weighing:

- Keep major branches with an explicit v5 maintenance policy, e.g. feed-only
  patches to the v5 line for a stated window, so `@v5` does not go stale silently.
  Solves staleness without breaking anyone; costs an ongoing dual release.
- A single floating ref (`latest`, or point consumers at `main`). Simplest to
  operate and best for detection freshness, but gives up the breaking-change
  firewall.
- Make exact-version pinning (`@v5.26.5`) the documented default in the README
  with a Dependabot note, keeping a major ref only as a convenience. Arguably the
  most defensible posture for a security tool, since it is the advice this project
  gives its own users.
- Hybrid: keep `@v5` working but emit a deprecation warning once v6 ships, so the
  ref stops being silently stale even if nobody upgrades.

Whichever is chosen, the README `uses:` examples, `docs/mcp.md`, `action.yml` and
the `update-major-branch` job's `if:` condition all move together, and the
branch-hygiene invariant above changes shape (a `v6` branch appearing, or major
branches disappearing). Update CLAUDE.md's "GitHub Action Distribution" section in
the same change, since it currently documents the v5-branch scheme as settled.

**Marketplace, re-check at the same time.** Marketplace publishing is NOT
automatable: GitHub gates it behind a web-UI checkbox in the Release edit view.
There is no `gh` flag and no REST/GraphQL endpoint, and `gh release create`, which
is what CI uses, never publishes there. Do NOT build a cookie or session hack into
CI; that would itself be a supply-chain risk in a supply-chain security tool. The
listing is discovery UI only and the Action runs via `@v5` regardless. At v6,
verify by hand that the listing still resolves, that the `uses:` line it advertises
matches the chosen scheme, and that the checkbox is ticked on the release that
should be the public entry point. Confirm the current listing state before changing
anything, since nothing in CI reports it.

---

## Threat-intel sweep 2026-08-20 (unreleased, branch threat-intel/2026-08-20)

Model: claude-opus-5. Prepared by the scheduled daily job, which never releases.
No version bump; the release PR is separate as usual.

**141 package IOCs imported, as two explicit slices.** Same approach as the previous
three sweeps: the 2026-08-14 backfill still sits in the default rolling window, so the
window was cut into day slices that exclude it by construction rather than importing
the block or accepting the age-out warning. The slices were
`--since 2026-08-15 --until 2026-08-20` (140 entries) and
`--since 2026-08-06 --until 2026-08-13` (1 entry, `golaaa@1.0.3`). Explicit slices are
exempt from the undrainable check, so no `--allow-backlog` was needed and nothing was
silently dropped.

The split was re-derived rather than inherited, by dumping the full window with
`--dry-run --limit 100000 --json` and grouping by `firstSeen` and scope:

- 4,504 non-duplicate entries in the window. 4,363 are `@zalastax/nolb-*`, all dated
  2026-08-14; the remaining 141 are dated 2026-08-06, 08-19 and 08-20. The two sets
  still do not overlap on any day, which is what keeps the date slice a clean
  substitute for the scope filter the importer does not have.
- **A re-run of the default window after both slices reports 4,363 remaining, all of
  them `@zalastax/nolb-*` and none of them anything else.** That is the check worth
  repeating each sweep: it proves the slices took everything that was not the block,
  rather than assuming it from the date grouping.
- A fresh sample of the zalastax scope is dead again (`0.0.1-security` holding
  versions, description "security holding package"). That is the sixth independent
  sample across six sweeps returning the same answer.

**All 121 distinct names were probed against their registries, not sampled:** 27 live,
38 npm security-holding stubs, 53 with no published versions, 3 hard 404 (all three
PyPI). Every one of the 27 live names is version-pinned by the importer. The stronger
result, and the one that matters for false positives: **all 34 bare-name blocks in this
batch landed on packages npm has already replaced with a holding stub**, so not one
all-versions block in this batch can reach installable code. `o0o9@1.8.0` pins a
version the registry no longer serves, which is harmless.

One entry is worth naming because it is a real vendor SDK rather than a squat:
`composer:intercom/intercom-php@5.0.2`, 56 releases on Packagist, flagged as part of
the Mini Shai-Hulud / TeamPCP wave. The advisory range was re-read directly from the
GitHub API before trusting the import: it is exactly `= 5.0.2`, so the version pin is
correct and no bare-name block was created.

**No non-package indicator was added by hand.** The enrichment step found nothing
addable, which is the second sweep in a row with that result. Checked and found already
covered: the ChainDrop / keyv worm set (domains, `setup.mjs` dropper hashes, the
Ethereum resolver contract, the Bun-loader chain), NullReceiver / Contagious Interview
(`bianira-ui@1.27.0`, `fluid-type-ui@2.0.8`, C2 `166[.]88[.]134[.]62`, the attacker
wallet and the dead-drop recipient address), Flooding Dropper / WEL1DROPPER, the
Sonatype six-package Ethereum-transaction set (`@kolbo/mcp`, `agentgui`, `godot-kit`,
`envpack-conf`, `postcss-initial-provider`, `tailwindcss-motion-advanced`), the Mastra
scope takeover, mrmustard, LiteLLM/telnyx, GlassWASM, TrapDoor, the Nx Console VS Code
extension breach and the `durabletask` PyPI hijack. Sources swept: Socket, Aikido,
StepSecurity, OX Security, Sonatype, Unit 42, Wiz, Datadog, safedep, Snyk, Arctic Wolf,
Phoenix Security and The Hacker News.

Incidental corroboration worth recording: today's import added
`postcss-initialize-provider@3.0.4`, a third spelling in the family that already carries
`postcss-initial-provider` and `postcss-initialize-plugin@3.0.4`.

### One indicator deliberately NOT ingested

`shai_hulululud@1.0.48596`, the npm package Socket describes as probing AI malware
scanners with prompt-injection comments and context flooding. Left out for two reasons,
recorded so a later sweep does not re-add it as an oversight: Socket classifies it as
protestware or potentially unwanted behaviour rather than functional malware, and no
advisory database carries it. It is also out of window (published 2026-06-16). If a
vendor later reclassifies it as malware, it becomes a normal import rather than a hand
addition.

### Still true from the previous sweep

The default rolling window keeps reporting the zalastax block until it ages out around
2026-08-28. The day-slice workaround handles it without an importer change, so the
`--exclude-scope` idea remains unbuilt and unneeded. Note that after 2026-08-28 the
block disappears on its own and the plain `npm run feed:import` call in the task file
starts working again without slicing; a sweep after that date should not keep slicing
out of habit.

---

## Lifecycle-hook coverage gap (2026-08-19, unreleased, branch fix/npm-scanner-lifecycle-hooks)

No version bump; the release PR is separate as usual.

**The gap was real and slightly larger than reported.** The finding named one
four-name `dangerousHooks` list in `npm-scanner.ts`. There were two identical
copies: `npm-scanner.ts` `checkPackageScripts` (the `scg npm <pkg>` registry
path) and `scanner.ts` `checkPackageJson` (the directory path), both listing
`preinstall`, `postinstall`, `preuninstall`, `postuninstall`. A third list in
`install-hook-scanner.ts` carried six names and was already correct about
`install` and `prepare`, which is why the miss was easy to overlook: an
`"install": "curl ... | bash"` in a directory scan still produced
`INSTALL_HOOK_DOWNLOAD_EXEC`, just never a `SCRIPT_CURL_EXEC`. On the registry
path it produced nothing at all.

All three now read one exported constant, `AUTO_RUN_LIFECYCLE_HOOKS`, in
`patterns.ts`. Fixing only the reported copy would have left the second one
behind, which is worse than not fixing it, because the rule then looks covered.

**The precision decision, which is the part worth re-reading.** The full set of
hooks npm can run on its own is larger than the set worth scanning.
`prepublishOnly` is deliberately excluded: it runs only on `npm publish`, never
on any install, so it cannot reach a consumer, and npm documents it as the home
for build steps (this repo keeps `npm run build` there). Scanning it would report
release tooling as install-time risk, which is how a scanner gets switched off.
`prepack`/`postpack` are out for the same reason. `prepublish` is IN despite
being deprecated, because it still fires on a bare `npm install` in the package's
own directory, which is exactly what a directory scan describes.

The added hooks were NOT given a reduced severity. Severity here comes from the
SUSPICIOUS_SCRIPTS entry that matched, `prepare` genuinely executes for a
consumer whenever the dependency resolves from a git URL rather than a registry
tarball, and the `prepare` wrappers were included so that moving a payload from
`prepare` to `postprepare` is not a one-word evasion.

**Verification.** 44 new tests in `lifecycle-hook-coverage.test.ts`: 13
new-hook detections across all three paths, 4 regressions on the hooks that
already worked, 26 pinning the benign and deliberately-excluded cases, 1 pinning
that the install-hook extractor and analyzer read the same list. Mutation proof:
deleting the single line `"install",` from `AUTO_RUN_LIFECYCLE_HOOKS` turns
exactly the two `install` tests red; reverting the whole constant to its previous
four names turns exactly the 13 new-hook detections red and leaves the other 31
green. `precision-corpus`, `rule-precision`, `precision-pattern-regressions`,
`persistence-recall` and `self-scan-recognition` (147 tests) are unchanged, so
the wider hook set adds no false positive on the corpus. Per repo practice the
full suite was not run on Windows; Linux CI carries that verdict.

**One honest limit.** The test that asserts the extractor and the analyzer agree
derives its expectation from `AUTO_RUN_LIFECYCLE_HOOKS`, so it stays green under
both mutations. It pins parity between the two functions, not the contents of the
list. The 13 behavioural tests are what pin the contents.

## Release v5.26.7 (2026-08-19)

Model: claude-opus-5. Contents: the 2026-08-19 threat-intel sweep, detailed below.
Nothing else - no dependency bumps were open at cut time.

PATCH. The release adds feed and blocklist data plus one test block: no new rule, no
pattern-table change, no change to what the scanner does. Same call as v5.26.2
through v5.26.6, and the reasoning recorded there still applies.

The sweep was prepared by the scheduled daily job, which never releases. The release
was cut in the same session on an explicit instruction to ship, so the version bump
and the data landed in one PR rather than the usual two: PR #150 was opened as the
sweep, then retitled once the release commit went on top of it. One merge, one CI
settle, then the tag.

---

## Threat-intel sweep 2026-08-19

Model: claude-opus-5. Prepared by the scheduled daily job, which never releases.
Shipped as v5.26.7 (PR #150), together with the release commit.

**205 package IOCs imported, as two explicit slices.** The default rolling window
still reports the 2026-08-14 spike, so the same approach as the 2026-08-18 sweep was
used: run explicit day slices that exclude 2026-08-14 by construction, rather than
importing the block or accepting the age-out warning. The two slices were
`--since 2026-08-15 --until 2026-08-19` (204 entries) and
`--since 2026-08-05 --until 2026-08-13` (1 entry, `big-tss@5.0.4`). Explicit slices
are exempt from the undrainable check, so no `--allow-backlog` was needed and
nothing was silently dropped.

The split was re-derived rather than inherited, by dumping the full window with
`--dry-run --limit 100000 --json` and grouping by `firstSeen` and scope:

- 4,568 non-duplicate entries in the window. 4,363 are `@zalastax/nolb-*`, all dated
  2026-08-14; the remaining 205 are dated 2026-08-07, 08-15, 08-18 and 08-19. The
  two sets do not overlap on any day, which is what makes the date slice a clean
  substitute for the scope filter the importer does not have.
- A fresh 30-name sample of the zalastax scope is 30/30 dead: maintainer `npm`,
  description "security holding package". That is the fifth independent sample
  across five sweeps returning the same answer.
- All 140 distinct names in the imported 205 were probed against the registry, not
  just sampled: 14 live, 42 holding stubs, 69 with no published versions, 15 hard
  404. The live set is `chaikit`, `twapfetch`, `sw-pluginer`, `txs-lib-sdk`,
  `timed-assess`, `streak-key-lib`, `streak-cal-core`, `ai-texts`,
  `agora402-payment-utils`, `bqq1`, `ts-rand-sdk`, `big-tss`,
  `@mohamed_nowisar/depconf-canary-test` and PyPI `infogram-bot`. Every one of them
  is version-pinned by the importer rather than blocked by bare name.

**One non-package indicator added by hand.** Unit 42's ChainDrop analysis catalogues
a third preinstall-dropper artefact, `setup.mjs.malicious`, whose SHA-256 was not in
`KNOWN_MALICIOUS_HASHES` alongside the two dropper waves already pinned. Added there
and to the bundled feed at confidence 0.85, since Unit 42 is the only vendor to
publish it; the digest was re-confirmed by exact-string search before ingest rather
than trusted from the fetched page, which is the standing rule for a fetched hash. A
positive test was added to `campaigns.test.ts`.

**Everything else in this week's write-ups was already covered.** Checked and found
present: the ChainDrop domain set (`npm-cache[.]com`, `pypi-get[.]com`,
`js-mirror[.]com`, `awqhnjewqjkl[.]icu`), the Ethereum resolver contract, the
`thebeautifulmarchoftime` / `thebeautifulsnadsoftime` dead-drop markers, the
`gh-token-monitor` persistence chain, the Flooding Dropper / WEL1DROPPER hosts and
payload hashes, the Alibaba dev-toolchain RAT cluster, the LiteLLM and telnyx PyPI
compromises, and TrapDoor. The enrichment step found nothing new beyond the one hash.

**Four indicators were deliberately NOT ingested,** and the reasoning is recorded
here so a later sweep does not re-add them as an oversight:

- `104[.]21[.]91[.]101` and `172[.]67[.]215[.]154`, listed by Unit 42 as ChainDrop
  IPs, are Cloudflare edge addresses. `ioc-blocklist.ts` already excludes the
  ChainDrop router IP for exactly this reason, and blocking a Cloudflare edge IP
  would flag arbitrary legitimate infrastructure.
- `tcsbank[.]ru` and `cloudpayments[.]ru`, which appear in the Flooding Dropper
  write-ups, are a real bank and a real payment processor. They are named as
  targets, not as attacker infrastructure.
- The ChainDrop contract-owner wallet and the Binance deposit address it pivots
  through were left out too. `KNOWN_C2_WALLETS` is matched against scanned source,
  and neither address is carried by the payload: the resolver contract is what the
  stage-2 code actually reads, and it is already listed. The Binance address belongs
  to the exchange in any case.

### Observation for the owner, not a blocker

Two of the imported names are self-described security-research probes:
`@mohamed_nowisar/depconf-canary-test` (still live, description "token diagnostics -
will be deleted") and `mtslink-depconf-probe-profileusername`. GitHub classified both
as malware (CWE-506) and the importer took them on that basis, which is the correct
default: this job does not overrule advisory classification by hand. Worth knowing
that the feed now carries a small number of entries whose author would describe them
as benign. No action taken.

### Still true from the previous sweep

The default rolling window will keep reporting the zalastax block until it ages out
around 2026-08-28. The day-slice workaround handles it without an importer change,
so the `--exclude-scope` idea remains unbuilt and unneeded for now.

---

## Release v5.26.6 (2026-08-18)

Model: claude-opus-5. Contents: the 2026-08-18 threat-intel sweep, detailed below,
plus the `@types/node` 26.1.2 to 26.2.0 dev-dependency bump.

PATCH. The release adds feed and blocklist data plus one test block: no new rule, no
pattern-table change, no change to what the scanner does. Same call as v5.26.2
through v5.26.5, and the reasoning recorded there still applies.

The sweep was prepared by the scheduled daily job, which never releases. The release
was cut in the same session on an explicit instruction to ship, so the version bump
and the data landed in one PR rather than the usual two. One merge, one CI settle,
then the tag.

The dependabot bump was pulled into this commit rather than merged as its own PR, and
PR #147 was closed explicitly. Two reasons, both already recorded: merging back to
back cancels the previous commit's CI run, after which the deploy gate correctly
refuses a commit whose CI concluded `cancelled`; and the repo invariant is that a
released version leaves zero open pull requests. The bump is dev-only
(`@types/node`), so it cannot affect the published artefact.

---

## Threat-intel sweep 2026-08-18

Model: claude-opus-5. Prepared by the scheduled daily job, which never releases.
Shipped as v5.26.6 (PR #148, merged c5be80d); the `threat-intel/2026-08-18`
branch is deleted. The sweep and the version bump landed as one squash-merge,
which is the documented way to avoid back-to-back merges cancelling CI.

**The 2026-08-14 backfill question is answered, and it did not need the importer
change.** It was carried as "NEEDS A DECISION" from the v5.26.3 sweep and repeated
in the two after it, framed as a choice between importing all 5,249 entries or
losing the tail behind them, because the importer cannot exclude a scope. There is
a third option and it is the one taken here: run the explicit day slice, take the
importer's own selection, and drop the one dead scope from it before writing. The
scope split was re-derived rather than inherited:

- The day slice maps to 4,550 non-duplicate entries. 4,363 are `@zalastax/nolb-*`
  and 187 are everything else.
- A fresh 25-name sample of the zalastax scope is 25/25 dead: sole published version
  `0.0.1-security`, npm's security-holding placeholder, published 2023-02-01. Four of
  the 25 carry a second version, and `latest` still resolves to the placeholder on
  all four. That is the fourth independent sample across four sweeps to return the
  same answer.
- All 187 outside that scope are now in the feed. Of a 25-name sample, 5 are live and
  installable, and the interesting ones are the `@zapier/*` set: three of those are
  live packages still publishing, correctly version-pinned by the importer. No bare
  name IOC in the 187 lands on a live legitimate package - the 43 bare names are the
  `@zittertea/*` gibberish-latin farm plus `@zyro-inc/eslint-config-zyro`.

So the backlog warning will keep firing on the default rolling window until the
spike ages out around 2026-08-28, but **the queue behind the zalastax block is now
empty**, and that is measured rather than argued: a dry run of the default window
after these three slices reports 4,363 entries still queued, 250 selected plus 4,113
remaining, and every name in the selected head is `@zalastax/nolb-*`. 4,363 is
exactly the size of that scope, so nothing else is left in the window. A future run
can read the warning as noise until the spike ages out. The importer improvement
noted below is still worth having; it is now a cost problem rather than a coverage
risk.

The other two slices were routine: 6 entries for 2026-08-04 to 2026-08-13 (the
window was already almost fully drained by prior sweeps) and 46 for 2026-08-15 to
2026-08-18. 239 package IOCs total, no page cap hit, nothing unmappable, nothing
left behind `--limit` outside the dead scope.

Hand-added, since advisory databases publish package coordinates and nothing else -
all NullReceiver / DPRK "Contagious Interview" (OpenSourceMalware 2026-08-05,
corroborated by Sonatype Research Labs 2026-08-10 and The Hacker News):

- Two blockchain addresses in `KNOWN_C2_WALLETS`. The campaign was already partly
  covered: its C2 IP `166[.]88[.]134[.]62` is pinned from the Joyfill/PolinRider
  wave, and 8 of its 13 packages were already in the feed. The dead-drop pair was
  the gap. The recipient address needs no external corroboration to trust: its
  first four bytes decode to the C2 IP already in the blocklist and its trailing
  bytes are ASCII `helloipbot!!`, so it validates against data this repo already
  holds. The attacker wallet was matched character-for-character across three
  independent write-ups, which is the guard against a WebFetch-mangled hex string.
- Three packages no advisory database carries. `agentgui@1.0.1127` in both the feed
  and `KNOWN_BAD_NPM_VERSIONS`: 1,110 published releases, and the trojanized one is
  the current `latest` tag, so a name block would flag 1,109 clean releases.
  `scrollbar-hide-plugin` and `tailwind-animation-founder` are unpublished with zero
  surviving versions and no legitimate history, so those are name blocks.

Deliberately NOT added, each for a reason worth keeping:

- The RPC pool `1rpc[.]io` and `eth[.]drpc[.]org`. Shared public Ethereum
  infrastructure; listing them flags every legitimate web3 repository. A negative
  test asserts they stay unflagged.
- The npm publisher handles `npmuser1101` and `npmuser3002`.
  `KNOWN_MALICIOUS_GITHUB_ACCOUNTS` matches on `github.com/<account>`, so an npm-only
  handle put there would never fire and would only mislead the next reader. There is
  no npm-publisher collection to put them in.
- The hardcoded loader tag `A10-npm3!`. It would be a valid anchored literal, but
  adding to a pattern table is a scanner-behaviour change and the two wallets already
  cover the campaign. Left for a considered change.

### Open for the owner

- **The Sui/Move cluster has no vendor write-up yet.** `sui-move-rpc`,
  `sui-gql-core`, `sui-move-graphql`, `bcs-core`, `leb128x`, `sui-gql-lite`,
  `bcs-mini`, `bucket-protocol-sdk-v2` and friends were published across 2026-08-06,
  2026-08-17 and 2026-08-18 and are in the feed on advisory data alone. They are
  Sui blockchain developer-tooling lures and the shape suggests one operator. If a
  vendor publishes atomic indicators for it in the next few days, that is the
  enrichment this window is missing, and it is worth a targeted look on the next run
  rather than waiting for the generic sweep to surface it.
- **The importer still cannot exclude a scope**, so the manual step used here would
  be needed again for the next bulk backfill. A `--exclude-scope` flag, or a
  registry-liveness filter dropping names that resolve to a holding stub before they
  are queued, would remove the manual step entirely. Still a considered change to the
  importer and still outside what the daily job should decide.
- **No decision is needed to merge this branch.** Both points above are about future
  runs.

---

## Release v5.26.5 (2026-08-17)

Model: claude-opus-5. Contents: the 2026-08-17 threat-intel sweep, detailed below.

PATCH. Feed and blocklist data plus two hand-added version pins and one new campaign
test block: no new rule, no pattern-table change, no change to what the scanner does.
Same call as v5.26.3 and v5.26.4.

The sweep was prepared by the scheduled daily job, which never releases. The release
was cut in the same session on an explicit instruction to ship, so the version bump
was added to the already-green sweep PR (#145) and the whole thing landed as one
squash-merge rather than the usual two. Same deliberate choice as v5.26.4: CLAUDE.md
warns against back-to-back merges, because each one cancels the previous commit's CI
run and the deploy gate then refuses a commit whose CI concluded `cancelled`. One
merge, one CI settle, then the tag.

## Threat-intel sweep 2026-08-17

Importer: 6,819 advisories over 69 pages, 9,966 mapped, 5,089 already present, 65
covered by an existing bare-name IOC, 250 written, 234 OSV-corroborated. Run with
`--allow-backlog`, justified below rather than used to silence the warning.

**The finding that changes the read on this backfill.** The 2026-08-14 bulk backfill
still dominates the window, and the last two sweeps concluded it was a historical
archive of dead names. That conclusion does not hold for today's selected head. Every
one of the 235 distinct names in the 250-entry head was probed against the live npm
registry and **124 came back still installable** - not holding stubs, not 404s. They
are a handful of active name farms, concentrated in four publisher accounts:
`ryliefrey` (the `*-putri-tea`, `*-salwa-tea`, `*-lia-tea`, `*-fri-zidan-tea`
families), `doelsumbing87` and `abbeey` (all carrying the description "Jual Beli All
Variant Kopling"), and `mipta19`. So the importer's newest-first ordering is doing
real work here, and the head is worth taking on its own merits rather than as a
formality.

The remainder was probed too, not accepted blind. Of 4,691 distinct names in the full
window, 4,363 are the single `@zalastax/nolb-*` scope; a fresh 25-name sample was
again 25/25 security-holding stubs, matching both prior sweeps. Of the 328 names
outside that scope, 129 are live and 124 of those are already inside the selected
head. Exactly one live, still-installable package sits outside what `--limit 250` can
reach before it ages out: `@zinley/orion`, hand-added and version-pinned. So the 1,812
undrainable entries are a loss of uninstallable names, not of detection coverage - the
same conclusion as 2026-08-16, but re-derived rather than assumed.

Hand-added, since advisory databases publish package coordinates and nothing else:

- `@zinley/orion`, six versions (GHSA-jf8m-fw34-6mg8). 41 published versions and a
  real purpose, so version-pinned; 1.2.35, 1.2.37 and 1.2.40 are deliberately clean
  and a negative test asserts the pin has not widened into a name block.
- The `mgc` npm account takeover (UNC1069 / "Sapphire Sleet" / WAVESHAPER.V2,
  safedep, April 2026): four version pins, the tarball digest, the C2 `/gate`
  endpoint and three gist paths. This extends a campaign the feed previously covered
  only through the axios wave. Single-source, so confidence 0.85 - but the implant
  paths safedep reports match the axios/UNC1069 hash descriptions already in
  `ioc-blocklist.ts` character-for-character, which is what carried the attribution.
  The compromised maintainer is NOT blocked: the gist sits under his own GitHub
  account and the C2 on his own personal domain, both taken over rather than
  attacker-registered, so only the specific paths are listed and a negative test
  asserts the account stays out of `KNOWN_MALICIOUS_GITHUB_ACCOUNTS`.

### Open for the owner

- **The importer still cannot filter by scope, and this is the third consecutive
  sweep to re-derive that `@zalastax/nolb-*` is dead.** 4,363 of 4,691 distinct names
  in the window are that one scope. Every daily run re-fetches and re-ranks it, and
  every run spends its judgement budget proving the same negative. An
  `--exclude-scope` flag, or a pre-queue registry-liveness filter, would end it. This
  was flagged on 2026-08-16 and not acted on; repeating it because the cost is now
  three sweeps deep. It is a considered importer change, so the daily job does not
  make it.
- **Today weakens the "backfill is all dead" heuristic.** 124 live names in the head
  is not what the last two sweeps found. If a future run is tempted to skip the
  import because the window "is just the backfill", that would now be wrong. The
  registry probe is the thing that answers it, not the shape of the names.
- The four publisher accounts above are still publishing. Blocking per-package
  chases them one name at a time; a maintainer-level indicator would not, but the
  scanner has no such concept today. Worth a decision on whether it should.

---

## Release v5.26.4 (2026-08-16)

Model: claude-opus-5. Contents: the 2026-08-16 threat-intel sweep, detailed below.

PATCH. Feed and blocklist data plus one hand-added version pin: no new rule, no
pattern-table change, no change to what the scanner does. Same call as v5.26.3.

The sweep was prepared by the scheduled daily job, which never releases. The release
was cut in the same session on an explicit instruction to ship, so the version bump
was added to the already-green sweep PR (#144) and the whole thing landed as one
squash-merge rather than the usual two. That is deliberate: CLAUDE.md warns against
back-to-back merges, because each one cancels the previous commit's CI run. One
merge, one CI settle, then the tag. Nothing about the tag or publish path changed.

## Threat-intel sweep 2026-08-16

Importer: 6,827 advisories over 69 pages, 9,972 mapped, 4,847 already present,
65 covered by an existing bare-name IOC, 250 written, 223 OSV-corroborated. Run with
`--allow-backlog`, which is justified below rather than used to silence the warning.

The 2026-08-14 backfill from the v5.26.3 sweep has not drained and still dominates the
window. 4,810 entries sat behind `--limit 250` and 1,810 of those cannot be reached
before they age out. Rather than accept that blind, the tail was enumerated and probed
against the live npm registry:

- 1,680 of the 1,810 are one scope, `@zalastax/nolb-*`, all `MAL-2025-*`. A 25-name
  sample came back 25/25 npm security-holding stubs (maintainer `npm`, sole version
  `0.0.1-security`). Not installable, so not a detection loss.
- The other 130 span 40 package names and look far more interesting at first glance:
  sentinel-version dependency-confusion lures aimed at real organisation namespaces.
  Probing them individually deflated that: 37 of the 40 are also holding stubs, one is
  a hard 404, and one of the two survivors has zero published versions. Only
  `dakumangalsingh` is genuinely installable, and it is now pinned by hand in both the
  feed and `KNOWN_BAD_NPM_VERSIONS`.

Worth recording because it cuts against the obvious reading: a tail full of
`99.9.9`-style names against recognisable companies looks like the highest-value
material in the queue, and it was almost entirely dead. The liveness probe, not the
name shape, is what settled it.

No atomic indicators were added. Everything reported in the window is already covered
(keyv / ChainDrop, Flooding Dropper / WEL1DROPPER, PolinRider / DEV#POPPER,
spellcheckpy). The WEL1DROPPER entry in particular already documents why the four
platform download subdomains are covered through their shared parent label and why the
possible victim hosts are deliberately unlisted, so there was nothing to extend.

### Open for the owner

- **The importer cannot exclude a scope, so this repeats daily until ~2026-08-28.**
  Every run re-fetches and re-ranks the same ~4,300 dead `@zalastax` names, the
  backlog warning fires every time, and each run has to re-derive that it is safe to
  ignore. `--ecosystem` does not help: the spike is entirely npm. A `--exclude-scope`
  flag, or a registry-liveness filter that drops names resolving to a holding stub
  before they are queued, would fix it. That is a considered change to the importer
  and outside what the daily job should decide, so it is left here rather than done.
- **No decision is needed to merge this branch.** The point above is about future
  runs, not about this change.

## Release v5.26.3 (2026-08-15)

Model: claude-opus-5. Contents: the 2026-08-15 threat-intel sweep, detailed below.

PATCH. The release adds feed and blocklist data plus one test block: no new rule, no
pattern-table change, no change to what the scanner does. Same call as v5.26.2 and
v5.26.1, and the reasoning recorded there still applies.

The sweep was prepared by the scheduled daily job, which never releases. The release
was cut in the same session on an explicit instruction to ship, so the version bump
and the data landed in one PR (#143) rather than the usual two. One merge, one CI
settle, then the tag. Nothing about the tag or publish path changed.

## Threat-intel sweep 2026-08-15

Importer: 6,824 advisories fetched over 69 pages, 9,948 mapped to IOCs, 250 new
entries written (the `--limit` default), 173 of them OSV-corroborated. 4,620 were
already in the feed and 65 already covered by a bare-name IOC. Zero skipped, zero
unmappable, no page cap hit.

Manual enrichment: six atomic indicators plus two GitHub accounts for the Vellia /
Guangnao / lodash-js cluster, all single-source (amazon-inspector via OpenSSF
`malicious-packages`) and therefore confidence 0.85. Detail in CHANGELOG.md under
`[Unreleased]`. Everything the vendor sweep surfaced for the ChainDrop / keyv wave
was already covered, including `npm-cache[.]com`, `t[.]m-kosche[.]com` and the
`StringListStore` contract address, so nothing was added there.

### NEEDS A DECISION: the 2026-08-14 advisory backfill

This window is not a normal one and the `--limit` guidance does not cleanly apply.
GitHub bulk-loaded 5,249 OpenSSF `malicious-packages` records into the advisory
database on 2026-08-14, and the importer now reports 5,013 entries still queued with
1,763 of them undrainable: at 250 per run the tail is more runs away than it has days
left in the `--days 14` window, which is the same silent-false-negative failure the
page cap treats as fatal. The run was completed with `--allow-backlog`. Three things
about that queue matter, and the third is the actual decision:

1. **4,363 of the 5,249 are `@zalastax/nolb-*`**, a single scope mass-published in
   2023. Sampled 25 of them against the live registry: 25/25 are npm security-holding
   stubs, zero installable. The advisories are boilerplate ("was found to contain
   malicious code") with no analysis. Importing them would grow the feed by roughly
   38 percent and `feed.json` from 2.7 MB to about 3.7 MB, to catch names that cannot
   be installed. Flagging an npm-owned holding stub as critical with a "rotate all
   secrets" recommendation is also arguably a false positive.
2. **129 entries sit in the tail behind that block and are genuinely worth having**:
   `dinotech-auth-utils@99.9.9`, `@veertly/web-app@99.9.9` and `@100.0.0`,
   `@vyzensockets/baileys`, `tecken`, the `hrp*` set. The sentinel version numbers are
   the classic dependency-confusion marker. At `--limit 250` no future run reaches
   them before they age out, because the zalastax block sits in front of them.
3. **The importer has no way to express "take everything except this scope."** It
   filters by ecosystem, and the whole spike is npm, so `--ecosystem` does not help.
   The options are to take all 5,249 or to lose the 129.

Recommended: run the explicit slice for that day and accept the zalastax bulk,
`npm run feed:import -- --since 2026-08-14 --until 2026-08-15 --limit 100000`, or add
a scope-exclusion flag to the importer so the dead namespace can be skipped without
losing the tail. Not done here because a 5,000-entry machine-generated diff into a
public repo is the owner's call, not the scheduled job's.

The Zapier packages (`@zapier/mcp-integration`, `@zapier/ai-actions-react`,
`@zapier/spectral-api-ruleset`, `@zapier/stubtree`) are in that queue at positions
719 to 763, so they arrive on the next run or two either way. They are the Shai-Hulud
2.0 compromise of November 2025 and are correctly version-pinned by the importer.

### Detection gap found while checking that: Shai-Hulud 2.0 loader filenames

`MINI_SHAI_HULUD_LOADER` in `src/patterns.ts` matches only `setup.mjs` and
`execution.js`, the April 2026 Mini variant. The November 2025 Shai-Hulud 2.0 wave
that hit Zapier staged through `setup_bun.js` and `bun_environment.js`, and neither
string appears anywhere in `src/`. Closing it looks like a literal alternation in the
existing rule's proven shape, so it is low risk, but it changes a pattern table and
pattern tables throw at module load, so it belongs in a considered change rather than
in an unattended threat-intel run.

---

## Release v5.26.2 (2026-08-14)

Model: claude-opus-5. Contents: the 2026-08-14 threat-intel sweep, detailed below.

PATCH. The release adds feed data only: no new rule, no pattern-table change, no
change to what the scanner does. That is the same call as v5.26.1 and the reasoning
recorded there still applies, `5.x.0` carries anything that changes scanner
behaviour and threat-intel data ships as a patch.

The sweep was prepared by the scheduled daily job, which never releases. The release
was cut in the same session on an explicit instruction to decide the open question
and ship, so the version bump and the data landed in one PR (#142) rather than the
usual two. One merge, one CI settle, then the tag. Nothing about the tag or publish
path changed.

## Threat-intel sweep 2026-08-14

Importer: 1,842 advisories fetched over 19 pages, 4,782 mapped to IOCs, 169 new
entries written, 122 of them OSV-corroborated. 4,549 were already in the feed and 64
were already covered by a bare-name IOC. Zero skipped, zero unmappable, no page cap
hit, and nothing left waiting behind `--limit` (169 is under the 250 default), so the
next run starts from a clean window.

Manual enrichment: none, and that is the notable part of this run. Every campaign the
vendor sweep surfaced was already fully covered. Checked and confirmed present:
ChainDrop / keyv (including the `npm-cache[.]com` domain and the `StringListStore`
contract address), Miasma "Hades" (yesterday's work), Team PCP (the StepSecurity
2026-08-13 post is a CloudSEK victimology disclosure, 78,330 secrets from 2,186
organisations, and carries no indicator we lack, `scan[.]aquasecurtiy[.]org`, telnyx
and the KICS action are all already ingested), and WEL1DROPPER / Flooding Dropper.
The one WEL1DROPPER detail worth recording: the four DNS-fallback subdomains
`sdk[.]`, `ext[.]`, `pkg[.]` and `net[.]dl[.]wel1[.]ru` are NOT separate blocklist
entries, they are covered by the single `dl.wel1.ru` entry, and
`campaigns.test.ts:4029` exists specifically to prove that. Do not "fix" their
apparent absence by adding four redundant entries.

### False-positive review of the bare-name blocks

59 of the 169 entries are bare names rather than version pins, which is the shape that
would hurt if one of them were a real package. Twelve of the riskiest-looking were
checked against the npm registry (`react-shield`, `source-analyzer`, `root-locator`,
`path-match-js`, `ts-enum-helper`, `mutex-forge`, `sourceflow-tracker`,
`finvu-hdfc-sdk`, `blocks-angular`, `index-design-system`, `lab-helper`,
`nolimit-agent`): every one was created 2026-08-13 and has exactly one published
version, so none is an established package that a name-level block would break.
`nolimit-agent` is the one to watch, 12,272 downloads in 30 days off a one-day-old
single-version package.

### Bare-name blocks: resolved, all 59 stay as names

The open question was whether the bare names under scopes belonging to real
organisations (`@rocketreach/rr-components`, `@sapappgyver/appgyver-descriptors`,
`@open-banking/cabinet-providers`, `@stockrepublic/republic-components`,
`@sourceflow-uk/sourceflow-tracker`, `@hanssoft/baileys`, `@hanssoft/libsignal-node`)
were hijacked legitimate packages that should have been version-pinned instead.

They were not, and there is a clean registry signal that settles it. All 60 bare names
in this window were queried against the npm registry: 59 now carry exactly one version,
`0.0.1-security`, published by the `npm-support` account. That is npm's takedown stub,
which npm publishes only when it removes a package name in its entirety. The one
exception, `@dsp-next-gen-ui/needs-review`, carries the stub plus the malicious
dependency-confusion sentinel `999.99.1` and no legitimate release either.

The marker discriminates, which is the part that makes it usable rather than merely
suggestive. Run against genuinely hijacked packages as controls, `keyv` (85 versions,
maintainers `lukechilds`/`jaredwray`), `flat-cache` (52, `jaredwray`) and `axios` (143,
`jasonsaayman`) are all intact with full version history: npm removed the bad versions
and left the name with its real owner. A whole-name takedown therefore means the name
was attacker-owned end to end, and a version pin would be wrong because there is no
legitimate version left to preserve.

Worth reusing: `0.0.1-security` + `npm-support` as sole maintainer is a positive
confirmation that a bare-name block is safe, and is cheaper than reasoning about
whether a scope looks corporate.

## Release v5.26.1 (2026-08-13)

Model: claude-opus-5. Contents: #140, the 2026-08-13 threat-intel sweep, detailed
below.

PATCH, not a minor, and the distinction is worth recording because 5.26.0 went the
other way one day earlier. The repo's rule is that `5.x.0` carries anything that
changes what the scanner *does*, while threat-intel data ships as a patch. This
release adds data plus one rule, `HADES_WAVE_DEADDROP_MARKER`, which is a literal
three-string alternation with no behavioural component: it is an IOC that happens
to live in `patterns.ts` because the campaign's markers are payload text rather
than locators. The precedent is `ANTV_WAVE_FIREDALAZER`, a marker rule of exactly
this shape, which shipped in 5.2.15 as a patch; `DPRK_VALIDATE_SDK` and
`LOFYSTEALER_MARKER` likewise in 5.2.4. 5.26.0 was a minor because it changed
detection behaviour (a dangerous-command battery applied to a new file type, a
persistence chain wired into the hook scanner), which this does not.

## Threat-intel sweep 2026-08-13

Scheduled daily sweep, released as v5.26.1.

Importer: 1,918 advisories fetched over 20 pages, 179 new entries written, 160 of
them OSV-corroborated. Zero skipped, zero unmappable, no page cap hit and nothing
left waiting behind `--limit` (179 is under the 250 default), so the next run
starts from a clean window.

Manual enrichment: the Miasma "Hades" PyPI wave's second cluster. The June 8
bioinformatics cluster was already covered; Socket, StepSecurity and Orca have
since documented a larger developer-tooling cluster of the same campaign. Twenty
package names had no coverage at all and `rlask` was under-pinned. 41 feed
entries and 21 blocklist pins added, plus two dead-drop repository prefixes and
one new pattern rule for the campaign's markers.

Confidence basis, since this is the part a database cannot do: three independent
write-ups list identical version sets, and the PyPI registry independently
confirms them, with the malicious versions removed and the highest surviving
release sitting exactly one below the first malicious one for every package.
`nhmpy` is the one entry carrying reduced confidence (0.85): the whole project is
gone from PyPI and only two of the three sources name it.

### Open for the owner

1. **Persistence artefacts from this wave were deliberately NOT added.** The
   write-ups list `~/.config/systemd/user/update-monitor.service`,
   `~/.local/share/updater/update.py`, `/tmp/.bun_ran` and a fixed lock file
   `/tmp/tmp.0144018410.lock`. `CHAINDROP_PERSISTENCE_ARTEFACT_REGEX` currently
   covers only the `gh-token-monitor` chain. Extending it would raise recall on
   this campaign, but `update.py` and `update-monitor.service` are generic enough
   that the false-positive cost looked worse than the miss, and the daily sweep is
   the wrong place for a considered detection change. Worth a deliberate decision:
   the lock-file paths are specific enough to be safe on their own, the two
   `update*` names are not.
2. **`api.anthropic.com` is named as an exfiltration endpoint by Socket.** Not
   listed, on the shared-legitimate-host rule. Flagging it here only to record
   that it was seen and consciously excluded, not overlooked.

## Release v5.26.0 (2026-08-12)

Model: claude-opus-5. First MINOR since 5.25.0, and deliberately so. The repo's
own precedent is that `5.25.x` carries threat-intel data while `5.x.0` carries
anything that changes what the scanner does: 5.25.0 was an importer flag, 5.24.0
and 5.22.0 were fixes to importer and detection behaviour. All three PRs in this
release add rules that make previously-clean scans report findings, which can
turn a consumer's `--fail-on` gate red. That is a minor here, not a patch.

Contents: #136 (file-digest matching), #137 (ChainDrop persistence chain and
dangerous editor tasks), #138 (install hooks that register OS-level
persistence). Their individual entries are below and are unchanged by this
release.

| | Before | After |
|---|--------|-------|
| ChainDrop persistence artefacts detected | 1 of 5 | 5 of 5 |
| Known-malware hashes able to match a file | 0 of 194 | 187 of 189 eligible |
| `.vscode/tasks.json` dangerous commands | not inspected | inspected |

Version bumped across all 14 `aahp.config.json` versionSites plus package.json,
with per-file occurrence counts asserted before rewriting, and package-lock.json
rewritten by `npm install --package-lock-only`. CHANGELOG `[Unreleased]` promoted
to `## [5.26.0] - 2026-08-12`, reference link added and the compare link
re-based. NEXT_ACTIONS.md version headers updated. feed.json and the generated
handoff set regenerated.

SECURITY.md untouched, and that is a considered call rather than an omission:
its Supported Versions table tracks major lines (`5.x`), so a minor inside 5.x
does not change it. CONTRIBUTING.md untouched: the three PRs extended existing
modules and added no new `src/` module.

Two follow-ups deliberately left open, both recorded rather than acted on:

- **T-016** stays blocked. Version-pinned npm IOCs match through the install
  guard but not through a directory scan, covering most of the package IOCs in
  the feed. Unchanged by this release and still an owner decision.
- **`precision-corpus.test.ts` has no legitimate `.claude/settings.json` or
  `.vscode/tasks.json` samples.** That gap is what blocks the tranche-3
  structural heuristics (a `runOn: folderOpen` signal in its own right). Build
  the corpus before attempting them, not after.

## Install-hook persistence, T-019 tranche 2 (2026-08-12, unreleased, branch feat/install-hook-persistence)

Model: claude-opus-5. PR 3 of 3 for the v5.26.0 line. No version bump. With this
merged, T-019 is complete and the version bump is the only remaining step.

Adds `INSTALL_HOOK_PERSISTENCE_WRITE`: launchd, systemd, cron, Windows scheduled
tasks, the `CurrentVersion\Run` key, the Startup folder, and an auto-imported
`site-packages` `.pth`. Reported at **high, not critical**, so a consumer running
`--fail-on critical` is unaffected by a new rule; a package that legitimately
registers a service is rare but not impossible, and high is the honest level for
it.

Scope is the whole reason the false-positive surface is small. The rule reads
only the six package.json install-script strings `install-hook-scanner.ts`
already reads. The identical commands in ordinary source belong to any service
manager or devops tool, where they would false-positive constantly. Ten benign
hooks are pinned as clean, including `systemctl restart nginx`, which is not
persistence registration and must not fire.

**The limit that follows from that scope, demonstrated rather than asserted.**
The hook string is all the rule sees. Fixture A (persistence inline in the
postinstall) now fires; fixture C (`"install": "node index.js"`, with the
`systemctl` call inside `index.js`) still does not, and that is correct
behaviour for a string-level check rather than a miss. A test pins it, so if it
ever starts passing the limit has been lifted and the CHANGELOG claim needs
updating with it. Said plainly in the CHANGELOG: this raises the cost of the
attack, it does not close it.

Verification: 24 new tests, 12 detection and 12 benign/boundary. Mutation proof:
neutering the mechanism regex turns exactly the 12 detection tests red and leaves
all 12 benign and boundary tests green. `install-hook-scanner`,
`install-hook-host-runtime-patch`, `precision-corpus`, `rule-precision`,
`persistence-recall`, `file-digest` and `self-scan-recognition` all re-run green.

## Persistence recall, T-019 tranche 1 (2026-08-12, unreleased, branch feat/persistence-recall)

Model: claude-opus-5. PR 2 of 3 for the v5.26.0 line. No version bump.

Two changes, both measured against the ten fixtures built when the gap was first
investigated (preserved under the session scratchpad at `persist-fix/`).

**`.vscode/tasks.json` recall.** The identical `curl | bash` produced two
criticals inside `.claude/settings.json` and nothing inside `.vscode/tasks.json`,
with the file confirmed read. That is a recall gap in a file already opened, not
a scope question, so it reuses the existing dangerous-command vocabulary rather
than inventing a heuristic. A task's invocation is split across `command` and
`args`, so the payload usually sits in an argument; they are rejoined into the
line that actually executes. `runOn: folderOpen` only escalates high to critical
and never fires on its own, since it is an ordinary VS Code feature. That limit
is pinned by a test so the tranche-3 heuristic cannot arrive early by accident.

**`CHAINDROP_GH_TOKEN_MONITOR_PERSISTENCE`.** Campaign literal for the dropped
script, LaunchAgent and systemd unit, cloning the `ANTV_WAVE_KITTY_PERSISTENCE`
entry's shape and guards.

One thing the fixture re-run caught that reading would not have: adding the
pattern alone left the headline case still undetected. A `.claude/settings.json`
hook whose command merely launches the already-dropped script carries no
independently dangerous token, so the command battery cannot see it, and the core
walk lists `.claude` in `excludedDirectories`, so that content never reaches the
pattern table either. The literal is therefore defined once in `patterns.ts` and
tested directly in the hook scanner as well, which closes it. Without re-running
the fixtures this PR would have shipped claiming a fix it did not have.

Measured coverage of the five published artefacts: **one of five before, five of
five after.** The benign control stays clean, the positive control and the
package-identity reference are unchanged, and the self-scan gate is green.

| Fixture | Before | After |
|---------|--------|-------|
| LaunchAgent plist | `COMPLEX_INSTALL_SCRIPT` (low) only | critical |
| dropped script + chmod | payload cred-steal only | + critical |
| systemd unit | nothing | critical |
| agent hook, curl-pipe-bash | 2 criticals | 3 criticals |
| agent hook, launches dropped script | nothing | critical |
| tasks.json, curl-pipe-bash | nothing | critical |
| tasks.json, launches dropped script | nothing | critical |
| benign control | clean | clean |

Verification: 12 new tests in `src/__tests__/persistence-recall.test.ts`, plus
`skills-scanner`, `precision-corpus`, `file-digest` and `self-scan-recognition`
re-run. Mutation proof in two parts, because the PR has two independent halves:
ignoring `args` turns exactly the four args-dependent tests red, and neutering
the campaign literal turns exactly the two chain tests red.

## File-digest matching, T-018 (2026-08-12, unreleased, branch feat/file-digest-matching)

Model: claude-opus-5. First of three PRs agreed for the v5.26.0 line; no version
bump here, and the version stays 5.25.12 until all three are on `main`.

Ships `IOC_KNOWN_MALWARE_FILE_DIGEST`. The known-malware hash collection had
exactly one matcher, the substring loop at `src/ioc-blocklist.ts:2245`, which
tests whether the digest TEXT appears inside file content. That is a real signal
for a digest quoted in a manifest or advisory and is kept unchanged, but it
cannot identify the malware itself, because a payload never contains its own
digest. Every entry describing a dropped artefact was unreachable by the thing it
names.

Three design decisions, each pinned by a test that fails if it is reversed:

1. **Runs before the `SCANNABLE_EXTENSIONS` gate.** Hashing needs no parser, and
   most of the collection describes compiled payloads with no scannable
   extension, which never reach the content scanners at all. Gating on the
   extension list would have left exactly the artefacts the digests were
   collected for unreachable.
2. **Hashes raw bytes, not decoded text.** Hashing a UTF-8 decoding does not
   reproduce a binary's published digest. The buffer is reused for the UTF-8
   decode below it, so a scannable file is still read exactly once.
3. **Excludes 40-character keys.** The collection holds a Git object id (an
   orphan commit) and a genuine file SHA-1 at the same length, and nothing in the
   data distinguishes them. Matching either could label a file as malware on the
   strength of a commit id. This is a data-modelling gap to fix by typing the
   collection, not something to guess at in the matcher.

Verification. 10 new tests in `src/__tests__/file-digest.test.ts`, plus
`ioc-blocklist`, `collection-reachability`, `binary-detection` and
`precision-corpus` re-run: 70 passing. Mutation proof: moving the check behind
the extension gate and hashing the decoded string turns exactly the two
corresponding tests red and leaves the other eight green.

A real digest has no computable preimage, so no test can construct a file
matching a shipped entry. Unit tests pass their own index; the end-to-end scan
tests inject one entry into `KNOWN_MALICIOUS_HASHES` in `beforeAll`, before
anything builds the lazily-cached index, and remove it afterwards.

Cost, measured rather than asserted, on this repo (574 files enumerated, 404
content-scanned): median scan wall-clock 6.71s without the check and 6.88s with
it, about 3 percent. 278 files totalling 8.8 MB are hashed, of which only 24
files and 0.68 MB were newly read; the rest were already in memory. The
self-scan produces zero digest findings, so no false positive on this repo.

## Release v5.25.12 (2026-08-12)

Model: claude-opus-5. Cuts the 2026-08-12 sweep (#134, merged as 6f66eb0) as a
patch release at the owner's direction. Version bumped across all 14
`aahp.config.json` versionSites plus package.json, with per-file occurrence
counts asserted before rewriting so a drifted file aborts rather than being
blind-replaced, and package-lock.json rewritten by `npm install
--package-lock-only`. CHANGELOG `[Unreleased]` promoted to `## [5.25.12] -
2026-08-12`, reference link added, `[Unreleased]` compare link re-based.
NEXT_ACTIONS.md current-version header updated, and its "published package"
line corrected: it had drifted to v5.25.6 because releases v5.25.7 through
v5.25.11 only updated the header above it. feed.json and the generated handoff
set regenerated. SECURITY.md untouched (patch); CONTRIBUTING.md untouched (no
new modules). This STATUS entry is part of the version-bump commit itself so
`aahp-verify` Layer 2 content-drift has a doc change paired with the source
change.

Pre-merge verification of #134 beyond what the sweep reported: all 26 new
bare-name entries were checked individually against the npm registry, since a
bare name blocks a package outright and several of them squat real DeFi brands
(Aerodrome, Camelot, Euler's EVC, BoringVault). Result: 20 are npm security
holding packages, 4 were created 2026-08-11 and are already unpublished with
zero versions remaining, and 2 return 404. None has legitimate publishing
history. The real projects do not publish under those npm names, which is
precisely why blocking them is safe.

One latent risk recorded rather than acted on: npm permanently holds the 20
security-holding names, but the 4 unpublished ones are not held the same way. If
a legitimate project later claims `ethereum-vault-connector` or
`camelot-ammv2-core` - plausible, since those are real product names - the
bare-name IOC would begin firing on a legitimate package. Version-pinning is not
available as an alternative because the malicious versions were unpublished.

## Threat-intel sweep 2026-08-12 (no version bump)

Model: claude-opus-5. Scheduled daily run. Branch `threat-intel/2026-08-12`, cut
from `main` at e64f72a in a scratchpad worktree, so the shared checkout stayed on
`main`. The version is deliberately untouched: the owner cuts the release separately.

Importer (rolling 14-day window, 1,791 advisories over 18 pages): 93 new package
IOCs across 50 names. Nothing was reported unmappable, nothing was skipped, the
`--limit 250` cap was not reached and the page cap was not hit, so the window did
not need slicing and no later run inherits a backlog. OSV corroborated 49.

This run added NO hand-written non-package indicators, and that is the finding
rather than a gap in the search. Every atomic indicator published in the current
reporting window was already in the blocklist:

- Flooding Dropper / WEL1DROPPER: the three `oob-worker.*.workers[.]dev` hosts,
  `dl[.]wel1[.]ru` (which covers the `sdk[.]`/`ext[.]`/`pkg[.]`/`net[.]` platform
  subdomains by substring), `c[.]wel1[.]ru` and both stage-2 hashes are all
  present from the 2026-08-11 sweep.
- ChainDrop / Shai-Hulud `keyv` wave (Socket, 2026-08-04): all three published
  SHA-256 digests (`54dc7ea5...`, `fd3ca400...`, `9fc2570b...`) verified as
  well-formed 64-char digests and already present in both
  `ioc-blocklist.ts` and the bundled feed.
- Mini Shai-Hulud `filev2[.]getsession[.]org` exfil host: already present.

Three deliberate exclusions, all of them the "legitimate shared host" trap:

- `tcsbank[.]ru` and `cloudpayments[.]ru` appear in the Flooding Dropper reporting
  as institutions the malware TARGETS, not as attacker infrastructure. Blocking
  them would flag victims.
- `169[.]254[.]169[.]254` and `169[.]254[.]170[.]2` are the AWS/ECS metadata
  link-local endpoints the ChainDrop payload queries. They are legitimate cloud
  infrastructure and would false-positive on any AWS SDK.
- The Bun release URL under `github[.]com/oven-sh/bun` and the
  `registry[.]npmjs[.]org` token endpoints are likewise legitimate services the
  payload abuses rather than attacker-controlled hosts.

### Open points for the owner

1. **Dropped-persistence paths have no home in the blocklist.** The Socket keyv
   write-up publishes concrete persistence artefacts:
   `~/.local/bin/gh-token-monitor.sh`, `~/.config/gh-token-monitor/{token,handler}`,
   `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`, and
   `~/.config/systemd/user/gh-token-monitor.service`, plus the `.claude/settings.json`
   and `.vscode/tasks.json` autostart hooks. None of the seven `ioc-blocklist.ts`
   collections models a dropped file path, so none of these were ingested. Adding a
   path/persistence collection, or a pattern rule, is a considered design change
   rather than something a daily sweep should improvise. Worth a decision.
2. **The newest clusters have no vendor write-up yet.** The DeFi SDK impersonation
   set (`camelot-ammv2-*`, `boring-vault`, `ethereum-vault-connector`, `sui-*`,
   `pypi:euler-sdk`, `pypi:morpho-sdk`, `pypi:dlmm-sdk`) and the hijack-shaped
   `@telekom-ods/react-ui-kit@2.6.9` pin are 1 to 2 days old and are currently
   covered by package name and version only. If a vendor publishes C2 or hash
   indicators for them in the next few days, a follow-up sweep should pick those up.

---

## Release v5.25.11 (2026-08-11)

Model: claude-opus-5. Cuts the 2026-08-11 sweep (#132, merged as 547ffbb) as a
patch release at the owner's direction, in the same session. Version bumped across all
14 `aahp.config.json` versionSites plus package.json, with package-lock.json
rewritten by `npm install --package-lock-only` rather than by text substitution.
CHANGELOG `[Unreleased]` promoted to `## [5.25.11] - 2026-08-11`, reference link
added and the `[Unreleased]` compare link re-based on the new tag. NEXT_ACTIONS.md
current-version header updated. feed.json and the generated handoff set
regenerated. SECURITY.md untouched: its table tracks `5.x` and this is a patch.
CONTRIBUTING.md untouched: no new modules.

The gate note recorded against v5.25.10 was applied preemptively this time: this
STATUS entry is part of the version-bump commit itself, not a follow-up, so
`aahp-verify` Layer 2 content-drift has a doc change to pair with the source
change. That layer lives only in CI, not in the local `check:handoff` script.

Content of the release is the 2026-08-11 threat-intel sweep: 104 imported package
IOCs across 54 names, plus the hand-added Mini Shai-Hulud / Miasma `Hades` PyPI
wave (23 version pins across 18 packages, 2 artifact hashes) and the Flooding
Dropper `c[.]wel1[.]ru` TXT control channel. The three judgement calls behind that
sweep are recorded in the entry below and are unchanged by this release.

---

## Threat-intel sweep 2026-08-11 (no version bump)

Model: claude-opus-5. Scheduled daily run. Branch `threat-intel/2026-08-11`, cut
from `main` at 00c9fcf. The version is deliberately untouched: the owner cuts the
release separately.

Importer (rolling 14-day window, 1,806 advisories over 19 pages): 104 new package
IOCs across 54 names. No skips, no unmappable entries, page cap not hit, `--limit
250` not reached, so no backlog carries into tomorrow.

Manual enrichment, Mini Shai-Hulud / Miasma `Hades` PyPI wave (June 8, 2026): 23
version pins across 18 PyPI packages plus 2 SHA-256 artifact digests. The family
was already covered on its npm side (the `@redhat-cloud-services` and LeoPlatform
waves) but the PyPI branch was entirely absent: all 18 names returned zero hits
across `threat-intel.ts`, `ioc-blocklist.ts` and `patterns.ts`. Sourced from
Socket, corroborated by Endor Labs, O3 Security and Snyk.

Also added `c[.]wel1[.]ru`, the Flooding Dropper TXT-record control channel. The
existing `dl[.]wel1[.]ru` entry covers the four platform download subdomains by
substring but not this sibling label.

### Decisions taken, for review

1. **The eight fully-removed `Hades` names are version-pinned, not name-blocked.**
   `instructor-mcp`, `langchain-core-mcp`, `openai-mcp`, `orchestr8-platform`,
   `rlask`, `rsquests`, `tiktoken-mcp` and `tlask` are gone from PyPI as whole
   projects, so the registry cannot show whether they ever had legitimate
   history. `rlask` / `tlask` / `rsquests` are transparent Flask and requests
   typosquats and would justify a bare-name rule in
   `PYPI_TYPOSQUAT_PATTERNS`; the four MCP names impersonate real brands but
   might plausibly be reclaimed by a legitimate project later. Pinning versions
   is the conservative read and matches what the sources actually published.
   Worth revisiting if a later write-up confirms the names were never legitimate.

2. **The two `Hades` hashes are labelled by campaign, not per file.** Socket
   publishes a digest for `langchain_core_mcp-1.4.2-py3-none-any.whl` and one for
   `langchain_core-setup.pth`, but two independent extractions of that page
   disagreed on which digest belongs to which file. Both hashes verify as exact
   strings against the source, so both are ingested; the file-level attribution
   is the part that is not solid, and inventing it would put a wrong filename in
   a user-facing finding. Same treatment the Alibaba digests already get.

3. **`ch4ce` was not added.** It is the npm publisher alias behind the Alibaba
   `@ali`-scope dependency-confusion wave (Socket, August 3). All 18 of that
   wave's packages are already pinned. `KNOWN_MALICIOUS_GITHUB_ACCOUNTS` matches
   on `github.com/<handle>`, so adding an npm-only alias there would flag any
   reference to an unrelated GitHub user of the same name.

4. **`tcsbank[.]ru` and `cloudpayments[.]ru` remain unlisted**, per the reasoning
   already recorded against the Flooding Dropper block. Re-checked this run and
   left as is.

---

## Release v5.25.10 (2026-08-10)

Model: claude-opus-5. Cuts the 2026-08-10 sweep (#130, merged as bd33bc8) as a
patch release at the owner's direction, in the same session. Version bumped across all
14 `aahp.config.json` versionSites plus package.json (19 source occurrences),
with package-lock.json rewritten by `npm install --package-lock-only`. CHANGELOG
`[Unreleased]` promoted to `## [5.25.10] - 2026-08-10`, reference link added and
the `[Unreleased]` compare link re-based on the new tag. NEXT_ACTIONS.md
current-version header updated. feed.json and the generated handoff set
regenerated. SECURITY.md untouched: its table tracks `5.x` and this is a patch.

`npm run build` green on all 7 aahp gates plus check:feed, check:handoff and
tsc; the version-sensitive suites (reporter, cli, feed, threat-intel,
sbom-generator) pass locally at 180/181 with 1 skip. CI is the full-suite
verdict.

**Gate note for the next release.** The first push of this release branch went
red on `aahp-verify` Layer 2 (content-drift: source changed but STATUS.md did
not) even though local `npm run build` was fully green. That layer lives only in
CI `aahp verify`, not in the local `check:handoff` script, so a release commit
that touches only version strings will always trip it unless STATUS.md is edited
in the SAME commit. Treat "STATUS.md gets a note" as part of the version-bump
step, not as an afterthought.

## Threat-intel run (2026-08-10, merged as #130, shipping in v5.25.10)

Model: claude-opus-5. Scheduled daily advisory sweep. Base: 186ff84 (main,
post-v5.25.9). Repo was clean with zero open PRs and zero open issues, so no
concurrent-writer conflict; work was done in a `git worktree` under the session
scratchpad and the shared checkout was left on `main`. No version bump on this
branch by design: the owner cuts the release.

**Importer.** 2 new package IOCs, both PyPI (`kotanku@0.1.0`,
`cubesat-upstream-driver@1.0.1`), in one standard pass over the rolling 14-day
window. 4,014 advisories fetched over 41 pages, both new entries corroborated by
OSV. The page cap was NOT hit, so no window slicing and no `--allow-truncated`.
The `--limit 250` cap was NOT reached (`remaining: 0`, `undrainable: 0`), so
nothing is left waiting. 151 advisories skipped by design (149 withdrawn, 2
unmappable version range); the JSON report carries only counts for those, not
per-advisory detail.

**Manual enrichment (STEP 1b).** The cross-reference turned up that TeamPCP was
only half ingested: the litellm side was covered, the telnyx sibling three days
later was not, and the campaign's whole March 2026 npm wave was missing. Added
the non-package indicators (C2 hosts, WAV dead drops, four wheel/`_client.py`
hashes, the `Argon-DevOps-Mgt` attacker account) plus 58 hijacked npm packages.

**Method note worth keeping: GHSA version ranges are too NARROW.** The first cut
of this change assumed the opposite. The vendor write-up listed more versions
than the advisories (`customer-sdk` 1.54.1-1.54.5 vs the advisory's
1.54.1-1.54.2, `@teale.io/eslint-config` 1.8.9-1.8.16 vs 1.8.9-1.8.10), and that
was initially read as the fetch padding the list with invented sequential
numbers. The npm registry settled it the other way: a fabricated version cannot
carry a real publish timestamp, and every disputed version is present in the
registry `time` map, published 2026-03-20, since unpublished, while the last
legitimate release of each package is still live. `@teale.io/eslint-config` has
70 live versions of 78 ever published, and the 8 unpublished ones are exactly the
vendor's range.

The pins are therefore generated from three signals: an advisory covers the
version, OR it was published inside the campaign window and has since been
unpublished from a package the campaign is known to have hit. That added 27
versions across 12 packages that GHSA alone would have missed (90 -> 117 pins).
Registry-derived PRERELEASES are excluded on purpose: the `@emilgroup` packages
retract beta channels constantly, so "unpublished" carries no signal there and
one such candidate (`changelog-sdk-node@1.0.1-beta.13`) was dropped.

A 404 on the whole package is NOT evidence against an indicator: seven packages
here 404, and one of them (`@opengov/form-utils`) has a GHSA advisory. Only 3
pins now rest on the vendor list alone, and they carry confidence 0.85.

**Open question for the owner (no PR issue opened, per the repo invariant).** The
ecosystem-prefix defect below survived many green releases even though the trap
is already written down in CLAUDE.md, so prose is demonstrably not holding it.
A cheap build gate would: assert in `check:feed` that no key of
`KNOWN_BAD_PYPI_VERSIONS` appears as a BARE feed value, plus the mirror for
`KNOWN_BAD_NPM_VERSIONS` and a `pypi:` prefix. Deliberately not added here so
this change stays reviewable, and because a gate deserves its own mutation
proof. Worth noting `isValidFeedIOC` is still not wired into any prebuild gate
either. Not gateable offline: version SETS, which need the registry.

**Defect found and fixed.** Six PyPI compromises had their package IOCs in the
feed as BARE values, which means the npm namespace. `matchPackageIOC("pypi",
...)` returned null for them while the npm resolver answered instead. The
lockfile scan still flagged them through `KNOWN_BAD_PYPI_VERSIONS`, which is
exactly why this survived: the blocklist masked the feed miss. Mutation-proved
both directions before and after. See the "Needs a decision" section of the PR
for the one open question this leaves.

## Threat-intel run (2026-08-09, merged as #128, shipping in v5.25.9)

Model: claude-opus-5. Scheduled daily advisory sweep, merged as #128. The sweep
branch itself carried no version bump; v5.25.9 is cut from it in a separate
release commit at the owner's direction in the same session. Base: 7afaedc (main,
post-v5.25.8). Repo was clean with zero open PRs, so no concurrent-writer
conflict. No version bump on this branch by design: the owner cuts the release.

**Importer.** 64 new package IOCs (62 npm, 2 PyPI) in one standard pass over the
rolling 14-day window. 4,492 advisories fetched over 45 pages, 16 corroborated by
OSV. The page cap was NOT hit, so no window slicing and no `--allow-truncated`.
The `--limit 250` cap was NOT reached either (`remaining: 0`, `undrainable: 0`),
so unlike the last two runs nothing is left waiting. 158 advisories were skipped
by design (149 withdrawn, 7 unmappable version range, 2 unsafe package name); the
JSON report carries only counts for those, not per-advisory detail.

**Manual enrichment (STEP 1b).** The headline campaign of the week, the
keyv/cacheable ChainDrop worm, needed nothing: the 2026-08-07 and 2026-08-08 runs
had already ingested its hashes, C2, wallet and package pins, including the
judgement calls (cloud metadata IPs excluded, the `file-entry-cache@11.1.7`
vendor discrepancy resolved against the registry). Three genuine gaps were filled
instead:

- **Flooding Dropper / WEL1DROPPER** (2026-08-07, ~850 packages). The feed already
  held 78 `bigops` and 134 `dolyame` package entries from the advisory databases,
  but none of the delivery infrastructure. Added 8 Cloudflare Worker sub-hosts, the
  DNS-fallback host `dl[.]wel1[.]ru`, and 2 payload hashes.
- **axios / UNC1069** (2026-03-31). Versions were already pinned; the C2, its
  resolver IP and the 3 implant hashes were not.
- **spellcheckpy / spellcheckerpy** (2026-01-20). Never ingested at all. Backfilled
  as bare-name PyPI blocks plus host and IP. Single-source, confidence 0.85.

**Deliberate non-additions.** The `workers[.]dev` apex; `nexus[.]tcsbank[.]ru`,
`repo-linux[.]tcsbank[.]ru` and `alertmanager[.]cloudpayments[.]ru` (real Russian
financial-services hosts that OpenSourceMalware embeds with an explicitly UNCLEAR
role - health check, decoy, or compromised third party); the Cloudflare anycast
address `104[.]21[.]35[.]216` published for the ChainDrop router; and the hijacked
axios maintainer account, who is a victim. `dl[.]wel1[.]ru` is listed once rather
than as five rows because domain matching is an unanchored substring test, so one
entry covers the published platform subdomains without each double-reporting.

**`nrwise` resolved - do NOT add it, and do not re-open this next run.** Aikido
lists a second attacker-controlled account, `nrwise` (`nrwise[@]proton[.]me`),
alongside the hijacked axios maintainer. It was initially left out as an open
question; it is now settled as a deliberate non-addition, on three independent
grounds:

- *The matcher makes it worthless.* `KNOWN_MALICIOUS_GITHUB_ACCOUNTS` is matched
  as `github\.com/<account>\b`, so it only ever fires on a github.com URL in
  scanned content. `github[.]com/nrwise` has ZERO public repositories, so no such
  URL exists to be referenced. Detection value is exactly zero, not merely small.
- *The account points away from the attacker.* It has been dormant since 2013
  with no public repos and 2 followers. npm and GitHub are separate namespaces, so
  an identical handle implies no connection; an abandoned 13-year-old account fits
  an unrelated person who grabbed a short name far better than infrastructure
  stood up for a March 2026 npm publish. Aikido's context (a proton[.]me address,
  an npm-publishing attack) indicates their `nrwise` is the npm publisher account.
  The aged-account-takeover reading cannot be excluded, but it changes nothing:
  with no public repos there is still nothing to detect.
- *There is nowhere correct to file an npm handle anyway.* No npm-account
  collection exists in this codebase - `KNOWN_MALICIOUS_GITHUB_ACCOUNTS` is the
  only account list. And the three packages involved (`axios@1.14.1`,
  `axios@0.30.4`, `plain-crypto-js@4.2.1`) are already version-pinned, so the
  handle would add no coverage. Same reasoning as `ch4ce` in the 2026-08-08 run.

The asymmetry is one-sided: no detection gained, against a real risk of flagging a
live account belonging to an actual person.

---

## Threat-intel run (2026-08-08, merged as #126, shipping in v5.25.8)

Model: claude-opus-5. Scheduled daily advisory sweep, merged as #126. The sweep
branch itself carried no version bump; v5.25.8 is cut from it in a separate
release commit. Base: 5f37e55 (main, post-v5.25.7). Repo was clean, no open PRs,
so no concurrent-writer conflict.

**Importer.** 250 new package IOCs (230 npm, 20 PyPI) in one standard pass over
the rolling 14-day window. 4,498 advisories fetched over 45 pages, 182
corroborated by OSV. The page cap was NOT hit, so no window slicing and no
`--allow-truncated`. 49 mappable entries remain behind `--limit 250` with
`undrainable: 0`, meaning the next scheduled run reaches all of them before they
age out - unlike 2026-08-07, this did not need a second slice pass. 178
advisories were skipped by design (149 withdrawn, 22 unsafe package name, 7
unmappable version range); the JSON report carries only counts for those, not
per-advisory detail, so the reasons cannot be enumerated from a completed run.

**End-of-run drain check.** Skipped deliberately this run: the remainder is 49
with `undrainable: 0`, which is the condition the check exists to detect. Re-run
the check when a run reports a non-zero `undrainable`.

**Hand-added enrichment.** Two campaigns, 13 non-package indicators:

- *ChainDrop npm worm, second wave.* Microsoft and Datadog published the resolver
  internals after the initial 2026-08-04 write-ups the previous run ingested. Two
  sibling C2 routers (`pypi-get[.]com`, `js-mirror[.]com`), one earlier rotation
  target (`awqhnjewqjkl[.]icu`, single-source), four later-wave SHA-256 hashes,
  and two GitHub exfiltration-repo marker names.
- *Alibaba developer toolchain RAT, Corgea follow-up.* The live
  `raw.githubusercontent[.]com` config dead-drop path, and `node-data-utils@1.0.1`
  as a nineteenth staging package. Both single-source, confidence 0.85.

**Hash verification.** Datadog listed five hashes. Four round-tripped and were
independently re-confirmed by exact-string search (op-c.net's ChainDrop IOC list,
Socket's Miasma write-up, SlowMist, Aikido/Snyk). The fifth,
`619c56acf572df75b6004a6fc013c80900316a76099b241d64312da3a44f10b4`, appears in no
other source and is absent from op-c.net's otherwise-identical list, which is the
signature of a WebFetch transcription error rather than a real indicator. It was
NOT ingested. Anyone revisiting this should read Datadog's IOC table directly
rather than trusting a fetched rendering.

**Deliberately not ingested.**

- The public Ethereum RPC providers the ChainDrop resolver calls
  (`eth-mainnet.nodereal[.]io`, `go.getblock[.]io`, `eth.llamarpc[.]com`). Shared
  legitimate infrastructure: blocking them flags every Ethereum repository. A
  negative test pins this.
- The npm publisher handle `ch4ce` behind five of the Alibaba RAT packages.
  Socket states the origin is unconfirmed - account takeover or insider - so it
  may be a victim account. All five of its packages are already covered by name,
  so blocking the handle adds no detection and only adds victim-blocking risk.
- The two ChainDrop taunt strings (`Shai-Hulud: Here We Go Again` and the long
  `IfYouBlockThisAPIKey...` marker). They are payload description text, not
  locators; if they are wanted, they belong in `patterns.ts` as campaign rules,
  which is a considered change rather than a sweep addition.

**Unrelated fix carried in the same PR.** GHSA-2v37-7h3g-55p8 against `nanoid`
was published after v5.25.7 and turns `npm audit --audit-level=high` red on
EVERY branch, so the first CI run on this PR failed on it rather than on
anything in the sweep. Fixed with a lockfile-only bump to 3.3.18 (dev-only
transitive: vitest -> vite -> postcss; the published package still ships
`commander` as its only runtime dependency). If a dependabot PR appears for the
same advisory, close it explicitly - it is already resolved here.

**A SECOND Windows-only test gap exists, alongside the known `zip` one.** Two
`IOC_KNOWN_C2_DOMAIN` tests fail on this box on unmodified `main` - the Phantom
Bot `87e0bbc636999b.lhr.life` test and the GlassWASM `dodod[.]lat` stage-2
delivery host test. **CI settled it: both pass on Linux** (PR #126 run, 2,666
passing), so this is the environment, not a defect in v5.25.7. Recorded here so
the next run does not re-investigate it: calling `checkIOCBlocklist()` directly
on the same content returns the finding correctly, the loss is somewhere in the
`scan()` pipeline under Windows, and repeated runs over one fixture do not
always produce identical findings. Treat these two the way the `zip` failures
are already treated.

**CI caught something a green local build could not.** The two ChainDrop
exfiltration-repo markers were first added as `type: "url"` feed entries as well
as blocklist entries. `isValidFeedIOC` rejects them, correctly - a bare
repository name is not URL-shaped, and `IOC_VALUE_SHAPES.url` is what stops a
remote feed injecting arbitrary strings. `npm run build` is green on this
because no prebuild gate executes the validator; it surfaced only in
`issue-54-hardening.test.ts`. They are now blocklist-only, which costs no
detection since `KNOWN_DEAD_DROPS` is substring-matched. **Add
`src/__tests__/issue-54-hardening.test.ts` to the targeted suite list whenever a
run hand-adds a bundled-feed entry** - the existing list in the job file does
not include it, and `feed.test.ts` does not cover the value-shape contract.

---

## At a Glance (historical, as of the v5.25.9 cut - superseded)

v5.25.8 was published (#127). v5.25.9 is being cut from it and is a threat-intel
release: the 2026-08-09 advisory sweep, merged as #128, which added 64 package
IOCs plus the Flooding Dropper / WEL1DROPPER delivery infrastructure, the axios /
UNC1069 C2 and implant hashes, and a backfill of the spellcheckpy PyPI RAT. The
feed goes from 10,680 to 10,764 entries (+84: 64 imported, 20 hand-added).

| Field | Current state |
|-------|---------------|
| Released package | v5.25.8 on npm |
| Release target | v5.25.9, this branch (chore/release-v5.25.9) |
| Merged since v5.25.8 | #128 (2026-08-09 advisory sweep + Flooding Dropper + axios/UNC1069 + spellcheckpy backfill) |
| Working branch base | 8df6b32 (main, post-#128) |
| Open owner decisions | T-013 (Node/Babel matrix), T-016 (pinned IOCs on scan) |
| Threat feed | 10,764 entries, feed.json regenerated (window fully drained, remaining 0, undrainable 0) |
| AAHP dependency | 3.9.2, exact pin (bumped from 3.9.1 in #120) |
| AAHP manifest schema | aahp_version 3.0, intentionally unchanged |
| Task authority | MANIFEST.json |

AAHP 3.9.2 is the installed consumer artifact. `scripts/scg-handoff-docs.mjs`
(renamed from `aahp-dashboard.mjs`) is this repo's own project-specific
handoff-doc generator - it is not, and never was, an AAHP tool, despite the
former name suggesting otherwise. It now imports AAHP's shared bash-resolution,
Windows-path-conversion, and changelog-grammar primitives instead of vendoring
private copies of them.

---

## Threat-intel run (2026-08-07, merged as #124, shipping in v5.25.7)

Model: claude-opus-5. Scheduled daily advisory sweep. No version bump - the
version belongs to the owner's release. Base: c40d603 (main, post-v5.25.6).

**Importer.** 783 new package IOCs, in two passes over the same 14-day window.
4,318 advisories fetched over 44 pages. The first dry run flagged a
bulk-publication spike: 533 waiting behind the `--limit 250` cap, of which 33
were undrainable (they would age out of the window before a future capped run
could reach them). The standard batch took 250, then the remainder was drained
with an explicit `--since 2026-07-24 --limit 100000` slice, which is exempt from
the age-out check. `--allow-backlog` and `--allow-truncated` were NOT used and
the page cap was not hit. 178 advisories were skipped by the importer (149
withdrawn, 22 unsafe package name, 7 unmappable version range); those stay
excluded by design.

**End-of-run drain check.** After the slice, `npm run feed:import -- --dry-run`
reports `New entries: 0` with no waiting count and no undrainable warning. That
is the check that proves nothing was stranded, because the importer evaluates
the whole `--days` window independently of what any single run took. Make it the
standing last step of this job: a non-zero remainder there is the only reliable
signal that indicators are aging out unreached.

**Hand-added enrichment: GlassWASM.** The advisory databases only publish
`package@version`, so the atomic indicators come from vendor write-ups. This run
found that GlassWASM (Socket, 2026-06-15; corroborated by Corgea) had zero
coverage in this repo despite being a live Open VSX extension campaign. Added to
`src/ioc-blocklist.ts` and mirrored into `FEED_CHUNK_9`:

- `dodod[.]lat` (C2 apex) plus its three per-platform stage-2 paths
  (`/darwin/i/_`, `/linux/i/_`, `/win32/i/_`)
- Solana dead-drop wallet `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz`, which
  the WASM stager polls and reads commands from via the SPL Memo field
- Open VSX / GitHub publisher account `zaitoona43`
- three SHA-256 hashes: the TinyGo WASM stager (shipped under two byte-identical
  random names) and one per published VSIX

Deliberate exclusions, recorded so a later run does not "fix" them: the
impersonated upstream publishers `ExarGD` and `noellee-doc` are victims;
`api.mainnet.solana.com` and the two SPL Memo system program ids are shared
infrastructure every legitimate Solana project touches. The extension
identifiers are NOT feed package IOCs - a bare feed value means the npm
namespace, and these are Open VSX names, so ingesting them would route to the
wrong ecosystem; the two VSIX hashes carry that identity instead.

The three hashes are single-source (only Socket published them), so they carry
confidence 0.85 in the feed while every other indicator is 1.0. Per the standing
caution that WebFetch can corrupt long hex strings, each was checked for a
well-formed 64-char digest and the stager hash was re-confirmed by exact-string
search returning the Socket write-up.

ChainDrop was re-checked against two fresh write-ups (Aikido, The Hacker News)
and needed nothing: every hash they publish already round-trips byte-identical
against what is in the blocklist. The 546 "Shai-Hulud: Here We Go Again" staging
repositories were NOT ingested - they sit under compromised victim accounts.

**Retention rule settled this run (owner decision, 2026-08-07).** The advisory window and
detection retention are two separate concerns and must not be conflated:

- The `--days 14` window scopes what the IMPORTER ingests. Keep it strict.
- It says nothing about what the ENGINE keeps detecting. Every validated
  indicator stays in the feed indefinitely. A campaign is not over because its
  write-up is weeks or months old, and there is no basis for assuming an actor
  stopped operating just because someone published about them.

So a hand-added indicator is never dropped for being older than the window, and
feed size is never reduced by expiring old campaigns. Controlling import cost and
scan runtime is a technical problem to solve in the importer and the scan path,
tracked as a separate refactor - not something to pay for with lost coverage.

Note for future review: GlassWASM had NO prior coverage here, which is easy to
misread as an oversight. It is not reachable by the importer at all. The advisory
databases publish `package@version`, and this campaign's indicators are a C2
host, a wallet, hashes and a publisher account, which only ever appear in vendor
write-ups; its carriers are Open VSX extensions, an ecosystem the advisory
databases do not cover. Only the manual STEP 1b enrichment can find campaigns of
this shape, which is why that step is mandatory on every run.

**Verification.** Routing was proved by scanning fixtures, not by asserting on
the arrays: `src/__tests__/campaigns.test.ts` gains a GlassWASM block with four
positive cases (domain, hash, wallet, account) and one negative case asserting
the public Solana infrastructure is never flagged.

---

## Backlog-completion import (2026-08-06, merged as #122, shipped in v5.25.6)

Model: claude-opus-5. Second commit on the same branch, so the curated first
commit stays reviewable and this machine-generated drain is an isolated diff.
No version bump - the version belongs to the owner's release.

The owner authorised the full import. Window used: `--since 2026-08-04 --until
2026-08-06 --limit 100000`. That narrow window was verified to be sufficient
before running it: a dry run over it reported exactly 2,683 new entries, the
same number the full `--days 14` window reported as waiting, so no entry sat
outside it. **2,683 entries imported**, feed 6,948 -> **9,631**. The follow-up
dry run reports 0 new and 0 undrainable, and duplicates rose by exactly 2,683.

The 179 unmappable advisories (150 withdrawn, 22 unsafe package names, 7 bounded
version ranges) remain excluded by design. They all sit in the older
`2026-07-23..2026-08-03` part of the window, which is why the narrow window
reported 0 skipped.

**Bare-name audit (the only real false-positive risk).** 129 of the new entries
are bare names, which block a package name outright. Every one was checked
against the npm registry, not sampled: all 129 were created 2026-08-05 or
2026-08-06, all have exactly one version, and **all 129 are npm "security
holding packages"** - npm's own security team has already seized every name.
No package in the set has any legitimate history, so nothing needed escalating.
The remaining 2,554 new entries are version-pinned.

**Gaps closed:** `@hubsync` 27 entries, `@ornikar` 441 (from zero). Both are
entirely version-pinned, so neither scope is blocked wholesale. 7 new PyPI
entries, all correctly `pypi:`-prefixed; no other ecosystem appeared. Prefix
inversion is structurally impossible here: `ECOSYSTEM_PREFIX` lookups that miss
are routed to `skipped: unsupported-ecosystem` rather than defaulting to a bare
npm value, and this window skipped none.

**Fixture scan (routing, not feed-array assertions).** A throwaway fixture
depending on `@hubsync/web-sdk-react@6.3.10`, `@ornikar/apollo-link-timeout@1.4.2`,
the new bare name `async-mutex-lock`, and a clean control `lodash@4.17.21`:

| Path | Result |
|------|--------|
| Directory scan, bare name | FIRES, critical `MALICIOUS_DEPENDENCY` |
| Directory scan, version-pinned | does NOT fire |
| `guard --dry-run npm install <pkg>@<ver>`, pinned | FIRES, critical `THREAT_INTEL_PACKAGE_IOC`, exit 2 |
| Clean control, both paths | stays clean |

That third row is where the `@hubsync` / `@ornikar` coverage actually lives.
See "Needs a decision" below: this is a pre-existing scanner limitation that
this import did not cause and did not change.

**Windows Defender exclusion is in place** for the repo, so the churn that
previously showed up as `testFiles=107` in the generated dashboard did not
recur; `handoff:refresh` reports `testFiles=108`.

### Needs a decision: version-pinned npm IOCs are unreachable from a repo scan

> Tracked as **T-016** (blocked, owner decision) in MANIFEST.json and
> NEXT_ACTIONS.md, which is where it survives the next rewrite of this file.
> The analysis below is the evidence behind that task.

`matchBareNpmIOC` (`src/install-guard.ts:242`) matches a version-pinned IOC only
when a real version is supplied: line 257 returns on a bare-name IOC for any
version, line 258 requires `version !== undefined && iocVersion === version`.
Only one caller passes a real version, `install-guard.ts:273` (`spec.version`).
All three scanning callers hardcode `undefined`:

- `src/scanner.ts:1653` - the dependency spec from package.json is discarded at
  line 1647, which sets `version: undefined` for every non-alias dependency
- `src/npm-scanner.ts:237` and `:319` - literal `undefined`

So a project that depends on a version-pinned malicious package is NOT flagged
by `scan`, only by `guard`. That covers 7,749 of the 9,374 package IOCs now in
the feed, including every `@hubsync` and `@ornikar` entry this run added. It is
pre-existing and out of scope for a threat-feed import, but it means "closes the
`@hubsync`/`@ornikar` gaps" is true of the feed and only partly true of `scan`.
Fixing it is a behaviour change with real false-positive surface (a pinned IOC
would begin firing on lockfile-resolved versions), so it needs the owner, not an
agent acting alone.

---

## Threat-intel run (2026-08-06, merged as #122, shipped in v5.25.6)

Model: claude-opus-5. No version bump - the version belongs to the owner's release.

Imported 358 package IOCs (250 standard batch + a 108-entry explicit slice) and
hand-added 2 non-package indicators. Detail is in the CHANGELOG `[Unreleased]`
block; what follows was the part that needed a human decision.

> **RESOLVED 2026-08-06.** The owner decided to import the remainder. All 2,683
> entries were drained in the backlog-completion commit on this branch (see the
> section above); the feed is at 9,631 and the importer reports 0 waiting and 0
> undrainable. The `@hubsync` and `@ornikar` feed gaps described below are
> closed. The 179 unmappable entries stay excluded, as decided. The analysis
> below is kept as the record of why the import was justified.

**The `--days 14` window held a backlog of 2,683 unimported entries, and it was
not ordinary backlog.** The importer's undrainable check fired on the first run
of this session: 108 entries in `2026-07-26..2026-07-28` were already more runs
away than they had days left in the window, so no future capped run could ever
have reached them. They were recovered here with an explicit
`--since 2026-07-26 --until 2026-07-28 --limit 100000` slice, which is the
remedy the importer itself prescribes, and the warning is gone on re-run.

What remains is a bulk-publication spike concentrated on two days:

| Day | New entries |
|-----|-------------|
| 2026-08-04 | 2,320 |
| 2026-08-05 | 552 |
| 2026-08-06 | 61 |

The arithmetic currently says these are drainable at `--limit 250` (the
importer reports 0 undrainable after the slice), but only just: 2,683 entries
is roughly eleven more daily runs, and the 08-04 slice ages out of the window in
twelve days. That margin assumes exactly one run per day and no new arrivals,
and the fetch is newest-first, so every new advisory pushes the 08-04 tail
further back. It is likely to go undrainable on its own.

The content raises the stakes. Cross-referencing the 2026-08-04 spike against
the safedep write-up of the ChainDrop / Shai-Hulud wave (2,234 poisoned versions
across 444 package names, twelve organisations) shows the repo currently has
**zero** feed coverage for two of the named scopes, `@hubsync` and `@ornikar`,
while the other twelve scopes are partially covered. Those advisories are in
the undrained remainder.

Deliberately NOT done here, both recorded so they are not re-derived:

- Not force-importing the remainder. The scheduled task is explicit that a
  thousand-entry machine-generated diff must not be pushed into a public repo on
  the agent's own initiative. Scope is the owner's call - see the PR body.
- Not hand-adding the `@hubsync` / `@ornikar` versions. No source publishes the
  per-scope version lists, and inventing version pins is the one thing the
  enrichment step forbids.

Two indicators were also deliberately rejected rather than ingested:

- `ch4ce`, the attacker npm maintainer alias for the Alibaba RAT campaign.
  `KNOWN_MALICIOUS_GITHUB_ACCOUNTS` matches only the literal `github.com/<account>`,
  so an npm-only alias can never fire there, and it would risk a false positive
  against an unrelated GitHub user of the same name.
- `jaredwray`, which safedep's IOC table lists under "attacker-controlled
  accounts". That is a mis-framing: jaredwray is the compromised maintainer, the
  victim. The repo already treats it correctly (named in a comment, absent from
  the accounts blocklist) and that must stay the case.

---

## AAHP convergence (2026-08-05, unreleased, branch chore/aahp-converge-shared-primitives)

The owner's instruction: no divergence between this repo and AAHP. Prior state
(audited this session, by execution not by reading): this repo vendored local
copies of `_aahp-lib.sh` and `aahp-manifest.sh` purely because its own fork
dashboard (`aahp-dashboard.mjs`) called them locally rather than importing
AAHP's package. `_aahp-lib.sh` was purely stale (missing `aahp_manifest_index`
and a since-fixed table-separator regex); `aahp-manifest.sh` was actually AHEAD
of AAHP on one point (it preserved MANIFEST `project` on regeneration; AAHP
clobbered it) - that fix was upstreamed into AAHP 3.9.2 first (AAHP PR #64),
removing the only reason this repo's copy was ever ahead.

What changed on this branch:

- Bumped `@elvatis_com/aahp` 3.9.1 -> 3.9.2 (exact pin, `pinnedDep.allowRange: false`).
- `aahp-dashboard.mjs` renamed to `scripts/scg-handoff-docs.mjs` (`git mv`, history preserved).
  Its own header comment now explicitly disclaims being an AAHP tool.
- Deleted the two locally-vendored `scripts/_aahp-lib.sh` and `scripts/aahp-manifest.sh`.
  The renamed generator now imports `resolveBash`/`toBashPath` from
  `@elvatis_com/aahp/scripts/aahp-config.mjs` and `RELEASE_RE` from
  `@elvatis_com/aahp/scripts/changelog-grammar.mjs` (deep import; the package
  ships `scripts/` with no `exports` map restricting it), and resolves the
  packaged `aahp-manifest.sh` via `createRequire(...).resolve(...)` instead of
  a local sibling file.
- This closes a real bug for free: the local heading regex
  (`/^## \[(\d+\.\d+\.\d+)\] - .../`) silently dropped SemVer pre-release
  headings from the generated LOG.md table with no error. `RELEASE_RE` is a
  strict superset (adds an optional `-[0-9A-Za-z.-]+` group), so every
  currently-committed CHANGELOG heading produces byte-identical output; only
  a future pre-release heading behaves differently (correctly, now).
- `src/__tests__/handoff-gate.test.ts` (13 tests, unchanged behavioral
  coverage) updated: its isolated tmp fixture can no longer copy the two bash
  files from this repo's own `scripts/` (they are gone), so it now stubs
  `node_modules/@elvatis_com/aahp/` inside the fixture, copied from whatever
  is actually installed - the fixture can never silently drift from the real
  pin. One test's expected value changed to match AAHP's own (correct, already
  released) `_aahp-lib.sh` summary-filter behavior: a table header row is real
  content, not header chrome, so it is the correct one-line summary, not a
  later prose line the old, narrower SCG-local filter used to expose instead.
  Two tests that call `refresh()` twice needed a longer timeout (subprocess
  spawn on Windows measured ~6s/call; confirmed this is pre-existing behavior
  identical on the pre-rename script, not a regression from this change).
- Regenerated DASHBOARD.md/TRUST.md/LOG.md/MANIFEST.json. Diff is minimal and
  expected: the AUTO-GENERATED banner's filename, and the truthfully-written
  (but ungated) `@elvatis_com/aahp` row in the Toolchain table.

Verified: `npm run build` (governance + feed + handoff gates + tsc) green;
`npx aahp check .` 7/7 gates pass (handoff sub-check correctly skipped per
`config.check.skip`, NOT the full protocol - see below); `npx aahp verify .
--level ci` all 4 layers green; `src/__tests__/handoff-gate.test.ts` 13/13
green locally, twice. Full Vitest suite not run locally (Windows subprocess
spawning is disproportionately slow for the one handoff-gate file alone) but
confirmed via PR #120's own required Linux CI: `Build and Test` ran all 108
files / 2,655 tests, all passed, 64s.

Merged 2026-08-05 as PR #120 (9f5e01a), with explicit go-ahead - a second
public repo with a floating `v5` Action branch. Release v5.25.5 (this branch,
chore/release-v5.25.5) bundles this convergence with the already-merged #119
Action comment fix.

Correction to a claim from AAHP's own audit of this repo: `.supply-chain-guard.yml`'s
SHAI_HULUD_WORM/SHAI_HULUD_CRED_STEAL suppressions are NOT path-scoped to the
generator file (no `path:` key is set in the actual YAML, despite the
schema supporting one) - they suppress repo-wide. The `reason:` text merely
explains why the trigger comes from that file. Filename references in the
`reason:` text updated for the rename; suppression scope unchanged (tightening
it to a real `path:` scope would be a separate, deliberate improvement, not
folded into this rename).

---

## Threat-Intel Run 2026-08-05 (COMPLETE - merged, shipping in v5.25.4)

Model: claude-opus-5. The run is finished. It was committed as 43ef363, pushed,
opened as PR #117 and squash-merged to main as 74830f2 with both required checks
green. An earlier session had been unable to execute Node at all partway through,
which is why the steps below were recorded as blocked; they have since all run.

### What landed in the working tree

- `src/threat-intel.ts`: +251 imported package IOCs, +22 hand-added ChainDrop
  entries. Feed now holds 6,588 entries, up from 6,315.
- `src/ioc-blocklist.ts`: ChainDrop exfil host, Ethereum dead-drop C2 resolver
  contract, three payload hashes, 18 version-pinned hijacked packages.
- `src/__tests__/campaigns.test.ts`: ChainDrop describe block, 8 cases, with
  clean-version and cloud-metadata negatives.
- `CHANGELOG.md`: entry under `## [Unreleased]`. No version bump, by design.

### Import accounting

The default run reported 2,338 entries still behind `--limit 250`, and flagged
exactly one as undrainable: it would have aged out of the 14-day window before
any future run could reach it. That entry, `n8n-nodes-probe@1.0.4`
(GHSA-v527-x59j-frgj), was recovered first with an explicit exempt slice
`--since 2026-07-22 --until 2026-07-28`, after which the default run exited
clean with no backlog warning. No override flag was used. The remaining 2,337
are all recent and stay reachable by the next scheduled run.

### Windows handoff-gate fixes, found while running STEP 4e

`npm run handoff:refresh` could not regenerate MANIFEST.json from a Windows
checkout. Two independent defects, both pre-existing and neither caused by the
threat-intel change; CI on Linux was unaffected, which is why they went unseen.

- `scripts/aahp-dashboard.mjs` passed a native `C:\...` path to bash. MSYS
  re-parses the Windows command line and treats backslashes as escapes, so bash
  received `C:reposcriptsaahp-manifest.sh` and reported it missing - even though
  execFileSync uses an argv array and no shell. Path arguments are now
  forward-slashed on win32 only.
- The same call trusted whatever `bash` resolved to on PATH. On Windows that is
  normally `C:\Windows\System32\bash.exe`, the WSL launcher, and WSL mounts the
  host at `/mnt/c` with no `C:` drive - so once the path was well-formed it still
  failed, now with "No such file or directory" for a file that demonstrably
  exists. That symptom reads as a missing script rather than a wrong interpreter,
  which is what made this worth writing down. Git-Bash is now preferred
  explicitly on win32; `AAHP_BASH` still overrides.
- `.gitattributes` pinned `*.mjs` to LF but not `*.sh`. With `core.autocrlf=true`
  both `scripts/aahp-manifest.sh` and `scripts/_aahp-lib.sh` were checked out
  CRLF, and bash failed with `$'\r': command not found` and
  `set: pipefail: invalid option name`. Now pinned to LF.

The `.gitattributes` rule only governs future checkouts. The two working-tree
copies are still CRLF and must be renormalized once:
`git checkout-index -f -- scripts/aahp-manifest.sh scripts/_aahp-lib.sh`

### Steps that were blocked, now all green

1. Shell scripts renormalized; `.gitattributes` now pins `*.sh` to LF alongside
   `*.mjs`, so a `core.autocrlf=true` checkout no longer hands bash a stray CR.
2. `npm run feed:generate` - 6,588 entries, feed.json current.
3. `npm run handoff:refresh` - works from a Windows checkout again; the three
   defects behind that are described above and shipped in this release.
4. `npm run build` green (check:aahp + check:feed + check:handoff + tsc), the five
   targeted suites green on Windows, and the full suite green on Linux via openclaw
   (108 files, 2,653 tests, vscode-scanner included because zip is present there).

Nothing is outstanding from this run.

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
- Package-shaped regressions include compiled `dist/` output without source or
  `.gitignore`, while an untrusted copy still receives the same rule finding.
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
| AAHP acceptance report | 8 task-bound sections, no actionable findings |
| AAHP lint / doctor / prepush | passed after regeneration |
| Packaged self-scan regression | 16 tests plus installed candidate tarball: zero critical/high; untrusted copy detected |
| Full Vitest suite | 2,644 tests passed in PR #115 and v5.25.2 release CI |
| Linux AAHP Verify | passed for PR #115 and the v5.25.2 release |

The Windows workstation lacks the external `zip` executable used only to build
fixtures for 14 VS Code tests. Do not describe that prerequisite as a product
failure. T-014 tracks replacing the test-only dependency; required Ubuntu CI has
the tool and owns the full-suite result.

---

## Live Decisions and Remaining Work

### Action PR-comment fallback (fixed, unreleased)

`action.yml` guarded `reportForComment` on its own indented value. Indenting an empty
report produces four spaces, which is truthy, so the clean-scan fallback at the end of
the detail chain was unreachable and the three `if (reportForComment)` guards always
fired. Verified by execution, not by reading: an empty report is reachable through a
failed report read or an empty file, and the visible effect is a blank indented line
where the clean explanation belongs. The verdict line is separate, so no comment ever
claimed clean when it was not - degraded, never falsely reassuring.

Reachability is narrower than it first looked: a first clean scan posts no comment at
all, so this only appeared when a stale findings or partial comment was replaced on the
return to clean. Two scanner-level tests now drive the real comment script through the
update path; both fail against the previous guard.

- T-009: implement cryptographic offline DSSE, Fulcio-chain, and Rekor inclusion
  verification.
- T-010: add a first-class known-bad VS Code extension-ID IOC type.
- T-011: verify the remaining Digest-78 indicators against primary sources.
- T-012: profile structural matcher cost under V8 coverage.
- T-014: replace the external zip test-fixture dependency and add Windows coverage.
- T-013 remains blocked on an owner decision to raise package engines and both
  CI Node jobs together for Babel 8. Do not merge Babel 8 alone.
- AAHP (3.9.2, still true) detects a canonical file present on disk but missing
  from the manifest; deleting both the file and its entry remains an upstream
  required-set gap.

Threat-feed imports remain review-sliced. Never use backlog/truncation overrides
merely to make an import exit clean; retain explicit ecosystem/date coverage and
primary-source evidence.

---

## Handoff Rule

Incoming agents start with MANIFEST.json quick_context and tasks, then read this
snapshot and NEXT_ACTIONS.md. A task is eligible only when it is ready and every
`depends_on` task is done. DASHBOARD.md, TRUST.md, LOG.md, and manifest file
metadata are generated with `npm run handoff:refresh`; never hand-edit them.
