# supply-chain-guard: Current State

> Updated 2026-08-10 (threat-intel sweep). This is one current snapshot, not a session log.
> Historical detail belongs in CHANGELOG.md, generated LOG.md,
> LOG-ARCHIVE.md, and git history.

---

## Threat-intel run (2026-08-10, PR open, no release)

Model: claude-opus-5. Scheduled daily advisory sweep. Base: 186ff84 (main,
post-v5.25.9). Repo was clean with zero open PRs and zero open issues, so no
concurrent-writer conflict; work was done in a `git worktree` under the session
scratchpad and the shared checkout was left on `main`. No version bump on this
branch by design: Emre cuts the release.

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

**Method note worth keeping.** The vendor write-up's version enumeration proved
unreliable: asked to enumerate the `@emilgroup` family it returned longer runs
of versions than the GitHub Advisory Database records (for example
`customer-sdk` 1.54.1-1.54.5 against the advisory's 1.54.1-1.54.2, and
`@teale.io/eslint-config` 1.8.9-1.8.16 against 1.8.9-1.8.10). Every
package@version pair in this change is therefore read from GHSA at generation
time, not transcribed. Treat fetched enumerations as a lead, not as data.

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
release commit at Emre's direction in the same session. Base: 7afaedc (main,
post-v5.25.8). Repo was clean with zero open PRs, so no concurrent-writer
conflict. No version bump on this branch by design: Emre cuts the release.

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

## At a Glance

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
version belongs to Emre's release. Base: c40d603 (main, post-v5.25.6).

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

**Retention rule settled this run (Emre, 2026-08-07).** The advisory window and
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
No version bump - the version belongs to Emre's release.

Emre authorised the full import. Window used: `--since 2026-08-04 --until
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
would begin firing on lockfile-resolved versions), so it needs Emre, not an
agent acting alone.

---

## Threat-intel run (2026-08-06, merged as #122, shipped in v5.25.6)

Model: claude-opus-5. No version bump - the version belongs to Emre's release.

Imported 358 package IOCs (250 standard batch + a 108-entry explicit slice) and
hand-added 2 non-package indicators. Detail is in the CHANGELOG `[Unreleased]`
block; what follows was the part that needed a human decision.

> **RESOLVED 2026-08-06.** Emre decided to import the remainder. All 2,683
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
  the agent's own initiative. Scope is Emre's call - see the PR body.
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

Emre's instruction: no divergence between this repo and AAHP. Prior state
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
