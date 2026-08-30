## v6.0.7 release preparation (2026-08-30)

Model: OpenAI Codex. Branch `codex/release-v6.0.7`.

Patch release for the false-positive remediation merged in #247, the measured
typosquat guard merged in #248, and the 2026-08-30 threat-intelligence batch
merged in #246. The version moves together across package metadata, every
CLI/scanner/reporter surface, the Action and examples, container documentation,
MCP metadata, the generated feed, the lockfile, and the handoff set.
`CHANGELOG.md` carries the dated 6.0.7 block and release reference, and the
Unreleased comparison starts at v6.0.7.

This release branch contains version, changelog, and generated-metadata changes
only. The immutable `v6.0.7` tag and publication remain deliberately after the
release PR's squash merge, so the tag can point at the exact commit on `main`.

Evidence before the release PR:

- `npm run build` passes all seven AAHP governance gates, feed consistency,
  handoff consistency, and TypeScript compilation; all 16 governed version sites
  report 6.0.7.
- `aahp doctor`: all six conformance gates pass.
- The full Windows run reaches 133/138 passing test files, 3,275 passing tests,
  and 21 skips. Its 19 failures are environmental: 14 VS Code tests require the
  absent `zip` executable, the two documented campaign fixtures do not resolve
  their temporary paths on Windows, two Git/filesystem integration tests exceed
  the five-second Windows limit, and one temporary-directory cleanup receives
  Windows `EPERM`. The protected Linux PR matrix is the release gate.

## Typosquat heuristic: homoglyph-aware leading-character guard (2026-08-30)

Model: Claude Opus 5. Branch `perf/typosquat-first-char-predicate`, stacked on
`fix/typosquat-false-positives`. No version bump. Raised for independent review.

### The calibration was unreproducible, and now is not

Every threshold in `dependency-risk-analyzer.ts` carries a false-positive count over
real npm names in its comment. None of those numbers could be recomputed: the corpus was
never committed and no script existed. A calibration you cannot re-run is the same kind
of unverifiable claim as a `coveredBy` string, so `scripts/measure-typosquat-fp.mjs` now
draws a corpus across 156 points of the npm replication index, caches it, and runs all
three policies through the complete SHIPPED classifier rather than a reimplementation
or a post-filtered result that could drift.

To make that possible, the decision was extracted from the middle of
`analyzeDependencyRisks` into an exported `classifyTyposquat`. Behaviour-preserving; the
existing suite passed unchanged before any guard was added.

### What the measurement actually said, including where it corrected me

Over 31,200 names:

| Variant | Flagged | Curated squats lost |
| --- | --- | --- |
| no guard (previous behaviour) | 27 | - |
| blanket first-character guard | 8 | 1 (`1odash`) |
| homoglyph-aware guard (shipped) | 8 | 0 of 9 |

Two corrections came out of this rather than out of reasoning:

1. My first corpus sampled one-letter prefixes and returned only 8 hits. That is an
   artifact: the replication index is alphabetical, so a one-letter startkey returns
   `a0`, `a1`, `a-b-c` style junk instead of names anyone depends on. Two-letter
   prefixes fixed it. The absolute count is corpus-dependent and the script says so.
2. Reading the 19 suppressed names, I first called them a react-squatting campaign.
   Probing them showed the opposite: `focha` is a Mocha wrapper by bahmutov, `meact` a
   Markdown React renderer, and `xeact`, `zeact`, `riact`, `xedis`, `xebug`, `zrequest`
   are live packages with real maintainers. They were the false positives.

The recall number is deliberately scoped: zero of the nine evidence-backed squats are
lost, but unrelated leading substitutions, insertions and deletions are intentionally
outside the shipped high-severity heuristic. Same-leading edits and the declared
homoglyph groups remain covered; exact feed and pattern verdicts are independent. Tests
pin this boundary so it cannot be mistaken for a claim about every synthetic mutation.

### The comment this supersedes was factually wrong

`dependency-risk-analyzer.ts` argued against ANY first-character predicate because
patterns.ts curates `1odash` and `l0dash` and "both change character zero". Only
`1odash` does. `l0dash` is l-0-d-a-s-h against l-o-d-a-s-h: identical at position zero,
differing at position one. So the objection covered exactly one curated name, and a
homoglyph group covers that case without the original one-value Map's duplicate-key
overwrite. Both the old note and the arithmetic behind it are replaced.

### Deliberately NOT in this change

`1odash` and `l0dash` stay in `patterns.ts`. The measurement removes the argument that
they must stay for the heuristic to generalise leading homoglyphs, but removing curated
names is a separate decision with its own evidence bar, and bundling it here would make
this pull request two changes wearing one title.

## Typosquat false positives removed (2026-08-30)

Model: Claude Opus 5. Branch `fix/typosquat-false-positives`. No version bump.

### How they were found

The name tables were audited by expansion rather than by reading. Every rule in
`MALICIOUS_PACKAGE_PATTERNS` and `PYPI_TYPOSQUAT_PATTERNS` was expanded into its literal
match set: **216 names, and no rule that could not be expanded**. Each name was then
probed against its registry. That turns "does this rule over-match?" from a judgement
call into a finite check.

Fifteen names came back live. Seven are legitimate projects, listed in the CHANGELOG with
their evidence. The decisive ones were settled by package CONTENT, not metadata:
`lodas` ships an `index.js` that installs lodash for the user and removes itself, and
`lodash-es-utils` ships only a minified bundle with no hook and no network access.
`cross-env-shell` has no scripts at all and 21,156 downloads/month, which are `npx`
resolving the bin name rather than victims.

The worst of the seven is `github.com/amantsehay/a2sv-go-course`: a real person's public
Go coursework repository, 89 files, no campaign artifact anywhere in the tree, listed as
DPRK infrastructure by both a regex and a versionless `go:` feed IOC. Both detection
paths are removed, and the `go.sum` scanner test retains a real campaign module beside
the negative control.

### Why this happened, and what actually prevents a recurrence

The regexes were never wrong. `^(numppy|numpi|numpie)$` matches exactly what it says. The
defect is that a **resemblance was recorded as a verdict**: names were added to a table
that asserts malware at critical because they looked like misspellings, with no registry
check and, for the lodash rule, no cited source or date at all.

The project already has the right mechanism for resemblance. `TYPOSQUAT_LEVENSHTEIN` in
`dependency-risk-analyzer.ts` uses transposition-aware distance with a ceiling of one
edit, is calibrated against 29,687 real npm names, reports at high, and carries its own
dated allowlist that is scoped to exactly one rule. A hand-written alternation asserting
critical is a second, worse implementation of that same idea.

So the durable rule is: **`patterns.ts` and `threat-intel.ts` carry evidence-backed
names; misspelling shape belongs to the distance rule.** The new tests assert the
corrected behaviour through both the tables and the public `go.sum` scanner path, so a
future re-add fails CI rather than shipping.

### Follow-up opened separately

`1odash` and `l0dash` are deliberately KEPT here. `dependency-risk-analyzer.ts` documents
them as the reason it uses no first-character predicate, since a leading-homoglyph rule
would make the heuristic structurally unable to generalise them. Removing them is
therefore coupled to a calibration change worth about 24 further false positives, and it
needs its own measurement against the 29,687-name corpus rather than an assumption. That
is raised as a separate reviewable pull request and is not bundled here.
## Threat-intel import, 2026-08-30

Model: Claude Opus 5. Branch `threat-intel/2026-08-30`. Scheduled daily run. No
version bump: the version belongs to the release, which the owner cuts.

Imported 250 package IOCs (249 npm, one PyPI) and hand-added three atomic indicators
for the npm bin entry harvesting campaign. Details in the CHANGELOG Unreleased block.

### Every bare name was probed, and none had a legitimate release

246 of the 250 imported entries are bare name-blocks, which block every version, so
each was probed against `registry.npmjs.org` before being accepted. The result was
unanimous: 93 npm security holding packages, 81 hard 404s, 72 published-then-
unpublished. **Zero live packages with a real maintainer and a version history.**

That matters more than usual this run, because 51 of the bare names read as live
vendor packages: `amplitude-session-replay`, `confluence-rest`, `firestore-lite`,
`calcite-web`, `intuit-authz`, `ring-device-settings-library`, `jira-projects-backbone`.
Name shape predicted nothing; the probe settled all 51 the same way. `calcite-web`
and `firestore-lite` were re-checked against the raw registry response by hand: both
are holding packages created 2026-08-29 with an empty maintainer list and a single
`0.0.1-security` placeholder.

### Eight names moved from version pin to name block

v6.0.6 pinned `calcite-web`, `amplitude-experiment`, `intuit-authz`, `qbo-ui-services`,
`confluence-editor`, `katal-logger`, `alimama-minisite` and `nx-app` at a single
implausibly high version. This run adds a bare block for each. That is a real widening,
not bookkeeping: a bare block reaches every version, including any future one. It is
justified here because npm has since seized all eight names, and npm does not release a
seized name back to a publisher. Flagged because it is the one judgment call in the run
rather than a mechanical import.

### The bin entry harvesting campaign was only ever half-importable

safedep published 21 packages on 2026-08-14 whose names are the BINARY names Google's
scoped packages expose, so an internal build calling a bare `ngsw-config` rather than
consuming `@angular/service-worker` resolves the public malicious one. Twenty of the 21
arrived through the advisory importer on 2026-08-19 and were already version-pinned. The
advisory database carries no C2, so the apex `jchunt[.]top`, the IP `152[.]53[.]138[.]110`
and the missed 21st package are added by hand.

Two deliberate exclusions, both asserted in `campaigns.test.ts` rather than merely
intended:

- `104[.]21[.]61[.]226` and `172[.]67[.]216[.]7`, which the write-up lists for the apex,
  are shared Cloudflare edge addresses fronting millions of ordinary sites.
- The npm publisher account `rootdaddy-msrc` is NOT added to
  `KNOWN_MALICIOUS_GITHUB_ACCOUNTS`. That matcher tests literally for
  `github.com/<account>`, so an npm publisher handle there would be a category error
  that never matches the thing it names, while risking a false positive on an unrelated
  GitHub user of the same name.

The 21 squatted names stay version-pinned rather than name-blocked, unlike the 246
above, because they collide with real Google and Angular CLI binary names that those
projects could legitimately publish. All 21 currently probe as unpublished.

### The 3layerdipstack rule is added; the decline is deliberately NOT

The owner asked for the anchored rule during this session, so
`^3layerdipstack[a-z0-9]+$` now ships in `MALICIOUS_PACKAGE_PATTERNS`. It is added
ALONGSIDE the 337 existing feed entries, never in place of them.

Measured before writing it, across the union of the bundled feed and the live import
queue: **407 distinct names, 407 match the rule, 0 carry a version pin.** The suffix is
5 or 6 characters (179 and 228) drawn only from `[a-z0-9]`. The rule does not hard-code
that length, because the family is still being published and a 7-character variant would
otherwise slip past. All 407 probe as non-installable: 42 holding packages, 81 hard 404s
and 72 published-then-unpublished among the 337 already carried, and all 70 still queued
are holding packages.

**The matching `threat-feed-declined.json` entry was NOT added.** The rule alone changes
nothing about the import queue, because the importer's `dedupe` compares against the
bundled feed and cannot see `patterns.ts`, so the family will keep being re-proposed
until it is declined. Declining is the step that actually frees the roughly 200 slots per
run, and it is also the step that removes coverage if the `coveredBy` claim is wrong. The
claim is now measured rather than assumed, so the remaining question is not whether the
rule matches but whether the owner accepts the reach tradeoff:

The cost is measured rather than estimated. `MALICIOUS_PACKAGE_PATTERNS` is read by the
npm-scanner name check and its package.json fallback, NOT by the generic directory scan,
which matches exact feed names only. Running both paths against the built CLI:

| Name | Covered by | `scg npm` name check | `scg scan <dir>` |
| --- | --- | --- | --- |
| `3layerdipstackm1j2h` | feed entry | `MALICIOUS_PACKAGE_NAME`, **critical** | flagged |
| `3layerdipstackzq7v4` | rule only | `MALICIOUS_PACKAGE_NAME`, **high** | not flagged |

So a declined name is still caught, but one severity level lower and on one path instead
of two. The 337 names already in the feed keep the fuller coverage either way, because
the rule was added alongside them. A decline would apply that downgrade to the 70 queued
names and to every future member of the family. It is the same tradeoff the
`@zalastax/nolb-` entry already accepts, and it is a narrowing rather than a loss, but it
is a deliberate one and belongs to the owner. Both rows above are asserted in
`campaigns.test.ts` so the tradeoff cannot silently change.

To act on it, add to `threat-feed-declined.json`:

```json
{
  "namePrefix": "3layerdipstack",
  "reason": "Generated-identifier sweep backfilled into the GitHub Advisory Database in batches from 2026-08-26. 407 names catalogued so far, all published at 0.1.4 on 2026-08-26 and taken down within two days. Draining them through the importer consumed 195 of 250 slots on 2026-08-30 and would keep doing so.",
  "coveredBy": "src/patterns.ts MALICIOUS_PACKAGE_PATTERNS, anchored rule ^3layerdipstack[a-z0-9]+$ (added 2026-08-30). Verified 407 of 407 candidates matched it, none version-pinned, and all 407 non-installable on the registry.",
  "declinedOn": "2026-08-30"
}
```

Then re-run `npm run feed:import -- --dry-run` and confirm it reports the decline and
exits 0.

### Needs a decision from the owner

**The `3layerdipstack` decline is the one open item.** 195 of today's 250 slots went to
that one family, leaving 55 for everything else, and 70 of the family are still queued.
The 2026-08-29 note recorded that declining it would remove coverage, because 0 of 407
candidates matched any rule in `MALICIOUS_PACKAGE_PATTERNS` and there was nothing to name
in `coveredBy`. **That blocker is now gone**: the anchored rule exists and is verified
against all 407, as recorded in the section above.

What is left is the decline entry itself, with the exact JSON to paste written out above.
It frees roughly 200 slots per run, and its only cost is that future members of the
family are covered by the pattern rule rather than by a feed entry, which is a narrower
reach. That is the owner's call, not a scheduled job's.

**Advisory volume has a named cause.** The 2026-08-28 ThreatsDay recap reports that the
GitHub Advisory Database now ingests OpenSSF `malicious-packages` across all eight
ecosystems. The backlog growth the 2026-08-29 note flagged is therefore structural and
will not subside, which sharpens the open question about `--limit 250` already recorded
there.

## v6.0.6 release preparation (2026-08-29)

Model: OpenAI Codex, GPT-5. Branch `codex/release-v6.0.6`.

Patch release for the security and false-assurance remediations merged in #244,
plus the current Unreleased threat-intelligence and feed-correctness work. The
version moved together across package metadata, every CLI/scanner/reporter surface,
the Action and examples, container documentation, MCP metadata, the generated feed,
the lockfile, and the handoff set. `CHANGELOG.md` now carries the dated 6.0.6 block
and its release reference; the Unreleased comparison starts at v6.0.6.

The release dry run found that runtime detection-set provenance still reported
6.0.5 even though all 15 configured version sites passed. `src/threat-intel.ts` now
reports 6.0.6, and that value is the 16th `aahp.config.json` version site so the
same omission blocks future release builds.

Evidence before the release PR:

- `npm run build`: seven AAHP gates, feed consistency, handoff consistency and
  TypeScript compilation all pass.
- `aahp doctor`: all six conformance gates pass.
- The focused provenance integration suite passes 8/8 after the version-site fix.
- Full Linux suite on openclaw: 138/138 test files and 3,294/3,294 tests pass.
- Release PR: #245. Tagging and publication remain deliberately after its squash
  merge, so the immutable tag will point at the commit that is actually on `main`.

## Silent detection failures: unread file types and an unread package (2026-08-29)

Model: claude-opus-5. Branch fix/silent-detection-failures. No version bump.

**Two measured defects, both in the class the tool exists to prevent: a clean
verdict for something that was never read.**

**1. The scannable set was 19 extensions.** A byte-identical payload scoring three
critical findings in a `.js` file produced ZERO findings in `.mts .cts .ps1 .psm1
.bat .cmd .rb .php .cs .vue .svelte .ipynb .zsh .fish`. Two of those are not a
judgement call at all: `.mjs` and `.cjs` were read while their TypeScript siblings
`.mts` and `.cts` were not, and three more are the source languages of ecosystems
this scanner already ships dedicated scanners and feed IOCs for (RubyGems,
Composer, NuGet). The Windows pair is a measured attack shape rather than a
hypothetical: a `postinstall` of `cmd /c .\install.bat` produced no finding at all.

Fifteen extensions added. Measured before and after on one payload: 14 file types
went from 0 to 2 critical/high findings each, `.png` and `.lock` correctly still
unread.

**What this does NOT buy, stated plainly.** The rule tables are JS-shaped. A `.rb`
file gains coverage for language-agnostic rules and for JavaScript smuggled inside
it, which is the realistic dropper shape, but idiomatic Ruby exfiltration
(`Net::HTTP.post(..., ENV["NPM_TOKEN"])`) still produces nothing. This was measured,
and the malicious corpus entry was written to match what actually fires rather than
asserting a Ruby capability that does not exist.

**2. The three remote package scanners never got the issue-205 coverage contract.**
`supply-chain-guard npm <pkg>` whose payload is a `.ps1` reported "0 / 1 files
scanned", RISK 2/100 LOW, zero findings, exit 0. The directory path has emitted
`SCAN_ZERO_COVERAGE` / `SCAN_NO_SCANNABLE_FILES` for that state since issue 205;
`npm-scanner.ts`, `pypi-scanner.ts` and `vscode-scanner.ts` emitted neither. The
skip at `src/npm-scanner.ts:742` was a bare `continue`, three lines above an
oversized-file branch whose own comment says "surface the skip instead of silently
dropping coverage (issue #54)".

`makePackageCoverageFindings` now supplies that contract, wired into the npm path.

**A severity decision was deliberately NOT re-litigated.** `src/scanner.ts:782-786`
records a measured finding that treating "this tool does not read that language" as
a partial scan turned exit 0 into exit 1 for every ordinary Java, C#, Ruby, PHP or
Kotlin project. The new finding therefore stays `info` and stays out of
`PARTIAL_SCAN_RULES`, matching the directory contract, and a test pins that so a
later severity bump has to argue with the measurement rather than quietly win.

**Evidence.**

- Recall: 14 previously-blind file types now detect an identical payload.
- Precision: 8 adversarially-written ordinary files in the new languages, using the
  constructs that look malicious (`Invoke-WebRequest`, `powershell
  -ExecutionPolicy Bypass`, `base64_encode`, `curl_exec`, `HttpClient`, env-var
  secrets), produce ZERO non-info findings. Coverage went 1/9 to 9/9 files with the
  verdict unchanged at low / score 1.
- The precision corpus materialised only `.js` and `.json`, so it would have
  reported green whether or not the new languages misfired. It now carries seven
  benign and two malicious samples in the new types, both sides of the gate.
- Performance: the scanner's own `src/` tree, 4908 ms to 4923 ms median of three
  (+0.3%), identical 221/221 files and identical 1719 findings.
- Mutation proof, five mutations, all caught, clean baseline and clean post-restore:
  removing PowerShell, TypeScript-ESM or Ruby from the set, unwiring the coverage
  helper from npm-scanner, and renaming the coverage rule id.
- Full suite on the Linux box: 137/137 files, 3265 tests.

**Not addressed here**, and tracked rather than implied: the PyPI and VS Code
scanners have the same missing coverage contract as npm and are the obvious next
call sites; `scg guard` still prints an affirmative "no known-bad packages" for
`npm exec <critical IOC>`; and `SUSPICIOUS_SCRIPTS` has no Windows-shell coverage,
so the `.bat` dropper is now READ but still not flagged on the script value itself.

## 2026-08-29: Feed correctness and delivery, after a project-health review

Branch `fix/feed-correctness-and-delivery`. Triggered by a request to review project
health against a belief that adoption was declining. Model: claude-opus-5.

### The premise did not hold, and that matters for what follows

npm download data contradicts a decline. Monthly totals: 2026-03 420, 04 2,357,
05 3,536, 06 4,215, 07 9,621, 08 8,735 through the 28th. Normalised per day, July is
310/day and August 312/day, so the last two months are FLAT after strong growth, not
falling. Weekly variance is 2-3x routinely (800, then 3,397, then 1,741), so no single
week is a trend. The most recent week is the weakest in six, which is worth watching
and is not evidence of decline.

What the review did find is a genuine correctness problem and a genuine delivery
problem. Neither is visible in the download curve.

### Six false positives were shipping, and the mechanism is systemic

An audit of all 2,746 bare-name npm blocks in the shipped feed against the live
registry classified them: 1,739 npm takedown holdings, 839 live, 89 gone, 79
unpublished stubs. Of the 839 live, 816 have a publish span under 14 days, which is
campaign-shaped and correctly blocked. Twenty-three did not, and six of those had no
advisory id at all: they were hand-added campaign enrichment.

Three were wrong (see CHANGELOG for the full detail): the four ChocoPoC names lost
their `pypi:` prefix and inverted into the npm namespace, blocking the ten-year-old
`frint` framework plugin; and `html-to-gutenberg` / `fetch-page-assets` were
name-blocked as "attacker-uploaded, since removed" when JFrog had in fact reported
them as hijack victims with one poisoned release each. Both packages are still live
with 32 clean releases between them.

The mechanism is what should be recorded: **a bare-name block is a claim about the
registry at one moment, and nothing ever re-checked it.** It decays in both
directions - an attacker name can be released back to a legitimate owner, and a
write-up can be misread at ingestion time. No offline gate can catch either, because
the evidence lives in the registry rather than in the repo. `npm run audit:blocklist`
is the answer to that and now exits 0 across all 2,734 remaining blocks.

### The 24h cache expiry was the reason for the daily-release treadmill

`loadThreatIntel()` dropped a refreshed feed cache whole once it passed 24h and said
nothing. So `feed refresh` was only useful to someone running it daily, and the npm
release was in practice the only reliable way to receive new IOCs. That explains the
release cadence: 145 releases in about six months, 51 in July and 32 in August, and
six consecutive days of 6.0.0 through 6.0.5. Every consumer with this package in
devDependencies gets a dependency-update PR essentially every day, which is real
adoption friction that no download graph would show as a cause.

Stale entries are now merged and reported rather than discarded, which makes
`feed refresh` useful at any cadence and removes the functional reason to release
daily. The release cadence itself is a process decision and is NOT changed here.

### Measurements, including one that contradicted the reviewer

Taken on the Linux runner against this branch:

- Full suite 136/137 under parallel load, 137/137 with the one failure re-run alone.
  That failure is `beacon-miner.test.ts` "keeps nested and sequential geo-gate analysis
  linear on 5 MiB", a timing test: 8.29s in isolation, failing only under contention.
  Same known class as the v5.28.0 tag-run failure.
- Mutation proofs, both with a clean baseline and a green post-restore:
  reintroducing the stale-drop gate turns exactly the three new cache tests red;
  removing the `pypi:` prefix turns the two ChocoPoC regression tests red, including
  "does NOT flag the legitimate npm package frint".
- Bundled feed cost: 13,650 entries, feed.json 2.92 MB, `dist/threat-intel.js` 2.35 MB
  of a 7.46 MB unpacked package. Importing that module costs **101 ms** on every CLI
  invocation and retains 3.93 MB of heap.
- **Feed size is not a scan-throughput problem, contrary to the reviewer's own earlier
  claim.** `checkThreatIntel` on a 104 KB file costs 4.72 ms at 500 entries and 9.44 ms
  at 13,650: 27x the entries for 2x the cost, because the matcher is properly indexed
  and a fixed per-call cost dominates. The cost of feed growth is startup time and
  package size, not per-file matching. Any future argument for trimming the bundle
  should rest on those two, not on scan speed.

### Needs a decision from the owner

- **Release cadence.** With the cache fix, same-day IOCs no longer require a release.
  Moving threat-intel data to a slower release train (weekly, or only with code
  changes) would cut dependency-update noise for every consumer. Not done here: it is
  a process and distribution decision, not a code one.
- **`ecinc-cloud-moaxmpp` is the least comfortable allowlist entry.** 65 versions over
  731 days with a release as recent as 2026-06-07, blocked on the strength of
  GHSA-65hf-ffjr-7wpg / MAL-2025-6214, which classifies the whole package as malware.
  Upstream advisory was preferred over the local heuristic, but it deserves a second
  look.
- The five other allowlisted names are advisory-backed and dormant, so they are low
  risk, but the file is the place to revisit them if an advisory is withdrawn.
## 2026-08-29: Threat-intel sweep

Scheduled daily run. Imported 250 malicious-package IOCs from the GitHub Advisory
Database, corroborated against OSV.dev (221 confirmed). No non-package indicator was
added: STEP 1b found no vendor write-up published since the last run that carries an
atomic indicator this engine does not already hold. No version bump, no release.
Model: claude-opus-5.

Changed files: `src/threat-intel.ts`, `feed.json`, `CHANGELOG.md` (under
`[Unreleased]`), this file, plus the generated handoff set.

### The bare-name share flipped, and the probe is what made it safe

148 of the 250 entries are bare npm names, against 21 in the v6.0.5 batch. A bare name
blocks every version, so each one was probed against `registry.npmjs.org` before being
accepted. The result is unambiguous: five answer with npm's takedown marker (a lone
`0.0.1-security` placeholder, no maintainer), 48 return 404, and 95 return a metadata
stub carrying only `_id`, `name`, `time` and `_rev`, where the `time` map records the
single published version alongside an `unpublished` block and the `versions` map is
absent entirely.

That third shape is the one worth recording, because a naive probe misreads it. A
`GET` returns **200**, so a liveness check keyed on the status code calls it live; only
reading `versions` (empty) and `time.unpublished` (present) shows the package is gone.
142 of those 95-plus-48 are the `3layerdipstack<6 random chars>` family, every one
published at `0.1.4` on 2026-08-26 and unpublished again on 2026-08-28. Nothing
installable is reachable by any of the 148 name-blocks.

### The advisory backlog tripled and is worth a decision

The importer reports **1115 entries still queued behind `--limit 250`**, against 355
after the 2026-08-28 run. The undrainable-backlog check did NOT fire, so nothing is
aging out yet, and a `--limit 100000` dry run drains the whole window cleanly (1365
candidates, `remaining 0`, `undrainable 0`). But at 250 per day and roughly 400 new
advisories per day, the queue is growing faster than it drains.

The queue splits cleanly in two, and the two halves need different answers.

**902 bare names**, almost all of them generated-identifier sweeps: `3layerdipstack*`
(407), `secure-test-browser*` (215), `classlink-*` (188) and `desmos-graphing-*` (69),
879 between them. They share a signature: created 2026-08-26, a single version, and
unpublished again on 2026-08-28.

**463 version pins** across only 79 distinct packages, and `isite` alone is **354 of
them** from one advisory, GHSA-hmvc-prpq-wwcr. `isite` is one package, not a name
family: an earlier note in this file grouped it with the name sweeps by prefix, which
was wrong.

### Coverage for the generated-name families was checked, and there is none

The 2026-08-29 note first recorded this as unverified. It has since been measured, so
the open item can be stated as fact rather than as a suspicion.

Every one of the 407 `3layerdipstack` candidates was tested against all 37 compiled
rules in `MALICIOUS_PACKAGE_PATTERNS`: **0 of 407 match**. Same for the other three
families, 0 of 215, 0 of 188 and 0 of 69. `src/patterns.ts` contains no literal
mention of any of the four prefixes, and the only entropy check in the codebase
(`analyzeEntropy`, called from `src/scanner.ts`) runs over file CONTENT, not over
package names, so no generic name-shape heuristic reaches them either.

**Therefore a `threat-feed-declined.json` entry for these families would remove
coverage, not restate it.** There is no rule to name in `coveredBy`. The decision not
to decline is now verified, not merely cautious, and it should not be revisited
without first adding a rule that actually matches the family.

### Needs a decision from the owner

`isite` is the cheaper lever, and it is separate from the decline question. npm
converted it into a `0.0.1-security` holding package on 2026-08-27 (registry-verified:
one version, no maintainer, `description: "security holding package"`), so no
installable release exists to protect. A single bare name-block would replace all 354
pins and free 353 slots in one `--limit 250` batch, which is more than a day of drain.
That is a hand-added enrichment, not something the importer will do, and it is the
kind of change that wants a deliberate decision rather than a scheduled run.

The generated-name families have no such shortcut. Draining them at 250/day is
currently the only safe option; the alternative is writing an anchored rule per family
(for example `^3layerdipstack[a-z0-9]{6}$`) and only then declining them against it.

### `--limit 250` is the wrong instrument, and the owner flagged it

Raised by the owner on 2026-08-29: advisory volume is climbing and will keep climbing,
so a fixed daily cap cannot hold. That is right, and the measurements below say the cap
is not actually protecting what its rationale claims.

The documented reason for `--limit 250` is diff review-ability: not forcing a
thousand-entry machine-generated diff into a public repo. But nobody reads either a
250-line or a 1365-line generated diff line by line; what carries the review is the
aggregate verification (registry probes on bare names, ecosystem-prefix correctness).
Meanwhile the cap IS the only thing currently bounding growth of a bundled artifact,
which is a different job that it does badly.

Measured on this branch:

- `feed.json` is **13,900 entries / 3.1 MB**, and `src/threat-intel.ts` is 15,525
  lines, already split into `FEED_CHUNK_n` consts to dodge TS2590. The chunking is
  itself a symptom.
- **10,584 of 13,570 package entries are version pins.** 8,038 of those belong to
  1,630 packages carrying more than one pin.
- Drain is 250/day. The queue went 355 -> 1,115 in a single day.

**Collapsing pin floods into name-blocks does not rescue this.** Of the 60 largest
npm pin floods with no existing bare-name entry, only 22 packages (580 pins) are
safely collapsible - npm-holding, unpublished stub, or 404. The other 38 (1,416 pins)
are LIVE with large legitimate version histories (`@servicetitan/suppress-warnings`
342 pins against 335 live versions, `@yeaft/webchat-agent` 147 against 1,672), so a
bare name-block there would be a false positive. `isite` remains a valid one-off (it
is npm-held), but there is no general compression lever here.

**The plumbing for the real fix already exists.** `loadThreatIntel(cacheDir,
remoteFeedUrl)` starts from `BUNDLED_FEED` and layers the remote feed on top, purely
additively, with a size-bounded fetch and a TTL cache. So the bundle does not have to
be the complete set: it can carry a recent or high-value slice while the full history
lives in the hosted feed.

The trade-off is real and is the owner's call, not a scheduled run's: trimming the
bundle reduces coverage for anyone scanning offline or never fetching the remote feed,
which is the default. That is a detection decision, not a packaging one.

**Options, in the order they should be considered:**

1. Raise `--limit` to match the arrival rate now (500-750) and accept linear bundle
   growth. Buys time, solves nothing.
2. Give the bundle a retention policy (for example: keep all name-blocks and all
   non-package IOCs, keep version pins for N months, drop older pins whose package
   npm has since taken down) and make the remote feed the complete record. Bounds the
   shipped artifact. Needs a decision on default-offline coverage first.
3. Add anchored rules for the generated-name families, then decline them against
   those rules. Removes roughly 879 of the current 1,365 queued candidates at the
   source. Cheapest win on queue pressure, but every rule is a real detection-surface
   change and must clear the regex-shape validator.

No change was made in this run: all three are considered changes and this is an
ingestion run.

### Carried forward

- `bundledVersion` in `src/threat-intel.ts` is still ungated and hand-bumped at each
  release, and `src/threat-intel.ts` / `feed.json` must stay off any version-replace
  target list. Unchanged by this run, which bumps nothing.

## 2026-08-28: Release v6.0.5

Cuts the 2026-08-28 threat-intel sweep as v6.0.5 at the owner's go-ahead. Ships the
250 imported package IOCs, the two Douqiu publisher-namespace rules and the Douqiu
config-server domain from #240. Patch release: no API change, no new modules.
Model: claude-opus-5.

SECURITY.md was deliberately not touched. Its Supported Versions table is keyed by
major (`6.x`), so a patch adds no row. CONTRIBUTING.md likewise, since no module or
file was added.

### The version-bump collision recurred exactly as predicted, and widened

The v6.0.4 note warned that this collision "recurs at 6.0.5 and at every release whose
number any IOC happens to use". It did. `src/threat-intel.ts` carries FIVE IOC values
containing the outgoing release number:

- `pypi:yt-yson-bindings@66.0.4`
- `chai-as-staged@6.0.4`
- `chai-as-modified@6.0.4`
- `eslint-plus@6.0.4`
- `@ornikar/babel-preset-base@6.0.4`

`yt-yson-bindings@66.0.4` is the one worth naming, because it defeats the bounded
regex the v6.0.4 bump relied on. That regex refused to replace where the version is
preceded by a digit or a dot, which protects `@66.0.4`. But the other four are all
preceded by `@`, which is neither, so a bounded-regex bump over this file would still
have rewritten four live IOCs to a version the attacker never published. The v6.0.4
note reached the same conclusion and it held again here.

So the control that actually works is the FILE LIST, not the pattern: `src/threat-intel.ts`
and `feed.json` are never replace targets. This bump enumerated the 15 versionSites
explicitly, asserted the expected occurrence count per file before touching it, changed
`bundledVersion` by exact string, regenerated `feed.json` from the module, and then
re-asserted all five IOC values survived as canaries. The canary check is cheap and it
is the only step that would catch a silent corruption, since version-sync does not
cover `src/threat-intel.ts`.

`bundledVersion` remains ungated and hand-bumped, as before.

### Carried open items

- **355 advisory entries are still queued behind `--limit 250`.** They remain inside
  the `--days 14` window, so the next scheduled run takes the next batch. Nothing is
  lost; this is only worth acting on if the backlog should be drained in one release.
- **`@hd-team` has no publisher-namespace rule, by design.** Its eight names are exact
  feed entries, so a scope rule would only double-report. If a later batch shows the
  Douqiu ring publishing `@hd-team` names the advisory database has not catalogued,
  that decision needs revisiting, because the feed covers exact names only.

## 2026-08-28: Threat-intel sweep (advisory import + Douqiu ring)

Scheduled daily run. No version bump: the content sits under `## [Unreleased]` and the
owner cuts the release. Model: claude-opus-5.

### What landed

250 package IOCs from the advisory importer (237 npm, 13 PyPI) plus two hand-added
pattern rules and one C2 domain. The importer reported no page-cap truncation and no
undrainable backlog; the `@zalastax/nolb-` decline entry suppressed 4,363 candidates
as designed, and no new decline entry was needed.

### The bare-name probe caught one case the importer could not

All 21 proposed bare names were probed against the npm registry, because a bare name
blocks every version. 20 came back as `0.0.1-security` holding packages. The 21st,
`tailwindcss-3d-animate`, was LIVE with a real maintainer account and three current
versions, which is normally the signal to version-pin instead of name-block.

It was name-blocked anyway, and the reason is worth keeping: the package was created
2026-08-26 and its entire history is four versions inside twelve hours, the maintainer
address is on a disposable domain, and the `repository` field points at an unrelated
legitimate project it is impersonating. The advisory range is `>= 0`. So the
"live package with a real maintainer" test was not measuring what it usually measures.
The test that actually decided it was whether any clean release exists to protect, and
none does.

### The advisory database only saw a third of the Douqiu ring

The eight `@hd-team/*` packages the importer added are config carriers for a gambling
and pirate-streaming operation. The primary source documents 51 packages across THREE
publisher scopes. GHSA catalogued only `@hd-team`, and npm took only `@hd-team` down.

`@yuming2022` (43 packages, one with 3,274 published versions, newest 2025-12-08) and
`@elton.bfw` are still live and still installable. They are now covered by two
anchored publisher-namespace rules. The safety argument is npm's ownership model
rather than takedown status: a scope belongs to exactly one account, so an anchored
`^@scope/` rule cannot reach a package any unrelated party controls. This is the same
shape as the `@zalastax/nolb-` rule and expressly not the scoped catch-all that
`patterns.ts` rejects.

`@hd-team` was deliberately NOT given a scope rule, so the feed's exact names stay the
single source of truth for it and nothing double-reports. `campaigns.test.ts` asserts
that split directly.

### Only one of about 70 published domains was ingested

The write-up carries a large domain list, but re-reading the primary source for the
precise question - which hosts appear in the npm payload as opposed to the APK, the
websites or the streaming tier - returned exactly one: `apiyf[.]dq87771[.]com`, quoted
inside the base64 config blob. That is the only one a package scan can encounter, so
it is the only one added. The rest would have been coverage the scanner cannot use,
and several sit on shared cloud hosts where an entry flags unrelated projects.

### Verification

`campaigns.test.ts`, `regex-complexity.test.ts` and `pattern-applicability.test.ts`
pass locally (451 passed). Two `IOC_KNOWN_C2_DOMAIN` tests fail on this Windows box
(Phantom Bot `lhr[.]life`, GlassWASM `dodod[.]lat`); both were re-run on unmodified
`main` and fail identically there, so they are the known local gap and not a
regression. The full-suite verdict comes from CI on the PR.

### Open for the owner

Nothing blocking. Two items worth a decision when the release is cut:

1. **355 advisory entries stayed behind `--limit 250`.** They remain inside the
   `--days 14` window, so the next scheduled run takes the next batch. No action
   needed unless the backlog should be drained in one release instead.
2. **`@hd-team` has no scope rule by design.** If a later batch shows the ring
   publishing `@hd-team` names the advisory database has not catalogued, that
   decision should be revisited, since the feed covers exact names only.

## 2026-08-27: Release v6.0.4

Cuts the sweep-11 content as v6.0.4 at the owner's go-ahead. Ships the 34
malicious-package IOCs from #237 and the RedShell detection-scope decision record
from #238. Patch release: no API change, no new modules. Model: claude-opus-5.

SECURITY.md was deliberately not touched. Its Supported Versions table is keyed by
major (`6.x`), so a patch adds no row. CONTRIBUTING.md likewise, since no module or
file was added.

### The version bump needed a precise replace, not a blanket one

`src/threat-intel.ts` carries the IOC `@item-shop-data/client@56.0.3`, which contains
the outgoing version as a substring. A blanket `6.0.3` to `6.0.4` replace would have
silently rewritten that entry to `@56.0.4` and corrupted a live threat indicator,
and version-sync would not have caught it because threat-intel.ts is not a version
site. This is the same trap class as the README CIDRs, but with a detection
consequence rather than a documentation one.

The bump therefore ran a bounded regex, replacing the version only where it is not
preceded or followed by a digit or dot, and asserted that IOC survived as an explicit
canary afterwards.

**The regex is NOT what makes this safe, and it must not be relied on as if it were.**
The feed also carries seven IOCs whose own package version is the outgoing release
number: `chai-as-operated@6.0.3`, `chai-as-predicted@6.0.3`, `chai-as-built@6.0.3`,
`chai-as-synced@6.0.3`, `@tabrex/bs58@6.0.3`, `@ornikar/babel-preset-base@6.0.3` and
`pypi:ml-nps-shared@6.0.3`. Every one of them is preceded by `@`, which is neither a
digit nor a dot, so the bounded regex would have rewritten all seven and silently
retargeted them at a version the attacker never published.

They survived only because `src/threat-intel.ts` is not a version site and was never
a replace target: the single line touched there is `bundledVersion`, by exact-string
replace, and `feed.json` is regenerated from the module rather than edited. That
exclusion is the actual control.

So the rule for every future bump is the file list, not the pattern: never run a
wholesale replace over `src/threat-intel.ts` or `feed.json`, bump `bundledVersion` by
exact string, and regenerate the feed. The collision recurs at 6.0.5 and at every
release whose number any IOC happens to use, which is common for a `6.0.x` line.

`bundledVersion` in `src/threat-intel.ts` was bumped by hand as usual. It is not in
`aahp.config.json` versionSites and no gate covers it.

## 2026-08-27: RedShell detection-scope decision (both sweep-11 open items closed)

Follow-up to #237. Both items the sweep left for the owner are resolved, one of them
by finding it was already done. No behaviour change: this is a decision record.
Model: claude-opus-5.

### The persistence marker earns no rule, and the primary source settles it

`~/.config/.rsvc` is NOT added as a signature. The deciding fact is where it is
written: TrendAI's own analysis puts the marker in the compiled ELF at runtime on the
victim host, and describes `dist/index.mjs` as only re-exporting the date helpers,
resolving the bundled binary and spawning it with `cp.spawn({detached: true})`. The
loader never carries the string, so a rule for it could only ever match a machine
that is already compromised, never the package a scan is looking at. It would add a
maintenance surface and zero detection.

The six rotating payload paths (`dist/*.bin`, `dist/internal/*.bin`, `calc-math.dat`)
are rejected on the separate ground that they are generic enough to hit clean builds,
and the implant digest already covers all six names. That half was in fact already
argued in the hash comment ("the digest catches the payload the filename cannot").

Confirmed rather than assumed: the five RedShell tests in `campaigns.test.ts` pass,
including the hash test, so `IOC_KNOWN_MALWARE_HASH` demonstrably fires on the
payload the path rules would have targeted. The reasoning is now written into the
hash block in `src/ioc-blocklist.ts` so a later sweep does not re-raise it.

Precedent followed: `src/patterns.ts:2623`, where the SleeperGem daemon dir
(`~/.local/share/gcm`) is deliberately not a signature because the real Git
Credential Manager uses it too.

### Correction: the second item was already closed in v6.0.3

The sweep-11 note below lists `litterbox[.]catbox[.]moe` and `api[.]ipify[.]org` as
needing a decision recorded. They already had one. `src/ioc-blocklist.ts` has carried
it since the RedShell block landed in v6.0.3: the comment above `217.60.77.63` names
both hosts, defanged, and states that blocking them would flag legitimate projects,
alongside the same call on the `127[.]0[.]0[.]1:8792` loopback fallback. The sweep
raised it as open without grepping for it first. No change was needed and none was
made; the item is struck, not implemented.

## 2026-08-27: Threat-intel sweep 11 (34 IOCs, first clean importer run in ten sweeps)

Daily scheduled sweep. 34 malicious-package IOCs imported from the GitHub Advisory
Database and corroborated against OSV.dev. No release cut; the version is untouched
and stays at 6.0.3. Model: claude-opus-5.

### The decline list worked, exactly as sweep 10 predicted

This is the first sweep in ten that needed no window slicing and no manual
diagnosis. The importer reported `Declined: 4363 (@zalastax/nolb- x4363)` and exited
0 on the plain `--days 14` default. Sweep 10 predicted this run would be the last
one needing the slice; instead the decline entry shipped in v6.0.3 removed the need
outright, one sweep earlier than expected. No page cap, no backlog error, and
nothing left waiting behind `--limit` (34 new against a limit of 250).

Sweep 10's guidance still stands for the future: a large backlog reported from
2026-08-29 onward is NOT zalastax, and the JSON dump grouped by `firstSeen` and
scope is the first thing to run.

### What the 34 entries are

19 npm name-blocks, 10 npm version pins, 5 PyPI version pins. All 19 bare names were
probed against the registry before being accepted, because a bare name blocks every
version: all 19 answer with a single `0.0.1-security` placeholder, no maintainer and
no release history. That is npm's own takedown marker, so the name-block cannot hit
anything legitimate. Seventeen probes did the same job in sweep 9 and it is now the
routine gate on importer output, not only on hand-added names.

Two clusters are worth recording. Five entries hit the Baileys WhatsApp library
ecosystem inside one 20-second publish window, and five more carry Dune-themed names
referencing the Shai-Hulud family this feed already tracks. The Dune set has no
vendor write-up behind it, so it is carried on advisory provenance alone with no
family or campaign annotation and no claim of shared payload.

The one entry that required judgement is `zenntechinc-cli`. Unlike everything else
in the batch it is a live product with 20 legitimate releases and an active
maintainer, so it is version-pinned at 1.6.4 and 1.6.6 rather than name-blocked. A
name-block there would have flagged every clean release of a real package.
`spotify-url-resolvers@3.4.2` is pinned on the same reasoning.

### Enrichment found nothing addable

STEP 1b turned up four August campaigns and every one is already fully covered:
ChainDrop / keyv (domain, four dropper hashes, correlated matchers), Flooding
Dropper / WEL1DROPPER, the Alibaba dev-toolchain RAT, and RedShell / RedC2. For
RedShell the fuller write-up that appeared after sweep 10 now lists all 14 package
names; a per-name check confirmed all 14 are already in the feed, eight of them
having arrived through the advisory databases without the campaign annotation. No
hand-added indicator this run.

### Needs a decision from the owner

1. **RedShell file-path indicators are still uncovered.** The TrendAI write-up lists
   on-disk markers the feed has no rule for: the side-loaded ELF paths under
   `dist/internal/` (`calc-cache.bin`, `calc-mapping.bin`, `calc-math.dat`,
   `math-calc.bin`, `math-core.bin`, `calc.bin`) and the persistence marker
   `~/.config/.rsvc`. These were left alone deliberately. Several of the paths are
   generic enough to hit clean builds, and a pattern-table change is a considered
   change rather than sweep work. `.rsvc` is the specific one and is probably safe
   on its own. Worth a decision on whether the persistence marker earns a rule.
2. **Two hosts in the RedShell IOC list were deliberately not ingested.**
   `litterbox[.]catbox[.]moe` and `api[.]ipify[.]org` are legitimate shared services
   the implant merely uses, not attacker infrastructure. Blocking either would be a
   false positive against ordinary software. Recording the decision so a later sweep
   does not treat the gap as an oversight and add them.

## 2026-08-26: Release v6.0.3 (threat-intel sweep 10 + importer decline list)

Started as the daily scheduled sweep: 164 malicious-package IOCs imported from the
GitHub Advisory Database and corroborated against OSV.dev. The owner then asked for
the two carried open items to be fixed and the release cut in the same pass, so this
also closes the importer's daily red exit and the stale branch invariant, and ships
as v6.0.3. Model: claude-opus-5.

### The zalastax backfill still dominates the window, and date-purity still held

Tenth consecutive sweep blocked by the same `@zalastax/nolb-*` block. Unsliced, the
14-day window offered 4,527 new entries and exited red with the undrainable-backlog
error (4,277 behind `--limit 250`, 3,777 of them projected to age out). The
diagnosis ran exactly as the previous nine:

- JSON dump grouped by `firstSeen` and scope: 4,363 `@zalastax/nolb-*` entries, all
  on 2026-08-14, and that day carried **0 non-zalastax new entries**. Date-purity
  holds, so no timestamp slice was needed.
- Pattern-coverage re-check against the shipped rule
  `^@zalastax\/nolb-[a-z0-9._-]+$` in `src/patterns.ts`: **4,363 of 4,363 matched,
  0 unmatched, 0 carrying a version pin**. That is what makes the slice lossless,
  and it is the check that replaced the older "are these names dead" probe.
- Two slices took the whole real remainder: `--since 2026-08-12 --until 2026-08-13`
  returned 0 and `--since 2026-08-15 --until 2026-08-26` returned 164.
  0 + 164 = 4,527 - 4,363 exactly, which is the arithmetic that proves nothing real
  was dropped.

This block leaves the 14-day window on 2026-08-28, so sweep 11 (2026-08-27) should
be the last one that needs the slice. If a sweep from 2026-08-29 onward still
reports a large backlog, it is NOT zalastax: re-run the JSON dump and group by
`firstSeen` and scope before touching anything else.

### What the 164 entries are

Dominant cluster is a 59-entry dependency-confusion wave against the T-Bank /
Tinkoff internal npm namespace (31 `tinkoff-*`, 16 `twork-data-services-*`, five
`statist-browser-typed-client-*`, plus `tms-x-headers`, `time-webkit-tag`,
`taiga-ui-proprietary-navigation` and three more), about half published at sentinel
`20.x.y` versions. Worth recording because this feed already carries
`nexus[.]tcsbank[.]ru` and `repo-linux[.]tcsbank[.]ru` from the Flooding Dropper /
WEL1DROPPER reporting: the same organisation is being probed from two directions.
No shared payload or operator is claimed, only the overlap in target.

Then 24 more `streak-*` / `svelte-*-streak*` name-farm entries extending the family
that carried the RedShell / RedC2 4.0 loader in v6.0.2, six more `cls`/`dim` UI
variants, an 11-entry `vite-plugin-*` lure set, the smaller `devplatform-*`,
`bigops-*`, `wm-*` and `mc-*` internal-namespace sets, and eight PyPI entries.

Two live packages were hijacked rather than squatted and are version-pinned only, so
their clean releases stay installable: `react-remove-properties@6.14.1` and
`spotify-url-infos@3.4.2`. Seventeen bare names were probed against
`registry.npmjs.org` before accepting them; every one came back as an npm security
holding package, so the registry had already taken the name down and blocking by
name carries no false-positive risk.

### STEP 1b (non-package enrichment) produced nothing addable today

Searched Socket, safedep, StepSecurity, Aikido, JFrog, Elastic, Wiz, TrendAI and The
Hacker News. Every campaign still on the front page is already fully ingested,
including the deliberate exclusions: keyv / ChainDrop, RedShell / RedC2 4.0
(including `217[.]60[.]77[.]63` and the fourteen package names, with tests),
Flooding Dropper / WEL1DROPPER (including the documented decision to cover the four
`dl[.]wel1[.]ru` platform subdomains by substring and to leave `tcsbank[.]ru` and
`cloudpayments[.]ru` unblocked as victim infrastructure), mini Shai-Hulud
TanStack / Mistral (including `git-tanstack[.]com`, with `filev2[.]getsession[.]org`
and the Session seed nodes handled as documented), and TeamPCP. Nothing new was
published in the 2026-08-24 to 2026-08-26 window that carries an atomic indicator
this feed lacks. No hand-added IOCs in this PR.

### Both carried open items are now closed

**1. The importer no longer re-proposes a family it will never take.** The root cause
was that `dedupe` compares candidates against the committed feed and against nothing
else, so a family deliberately covered by one anchored rule in `src/patterns.ts`
instead of N feed entries is re-proposed forever. `threat-feed-declined.json` at the
repository root now lists such families, each with a mandatory `reason` and a
mandatory `coveredBy` naming the coverage that replaces them. Declines are applied
after dedupe and before `--limit`, so a declined family neither eats the per-run
budget nor counts as backlog. Seeded with `@zalastax/nolb-`. Verified end to end: an
unsliced default `--dry-run`, which had failed for ten consecutive days, now reports
`Declined: 4363 (@zalastax/nolb- x4363)` and exits 0.

The other candidate fix, "skip anything the pattern tables match", was considered and
REJECTED, and the reasoning is written into the code so it is not re-litigated:
`MALICIOUS_PACKAGE_PATTERNS` is read by the npm-scanner name check and its
package.json fallback, NOT by the generic directory scan, which matches exact feed
names only. A pattern match is therefore not equivalent to feed coverage, and
auto-skipping on one would quietly narrow detection. The tables also carry heuristics
such as `^[a-z]{20,}$`, which would have swallowed genuinely new malware whose name
happens to be long. Declining stays a per-family human decision, reviewable in a diff.

Mutation proof: baseline 83/83 green, `applyDeclineList` stubbed to a no-op turns 3
tests red, restored file byte-identical to the pre-mutation copy and green again.

**2. The branch invariant is corrected where it is committed.** `docs/ci-and-release.md`
and `.ai/handoff/CONVENTIONS.md` both said a finished deploy leaves exactly `main` and
`v5`. CI derives the floating major ref from the tag
(`git push origin HEAD:refs/heads/v${MAJOR}`), so v6.0.0 created `v6` by itself and
`v5` stays frozen at the last v5 release because consumers still pin it. Both now read
"`main` plus one major-ref branch per released major, and no topic branches", which is
what the post-release check is actually for. The per-machine `CLAUDE.md` copy was
updated too, but it is gitignored, so this paragraph is the durable record.

### Carried forward

Nothing from this session. The `@zalastax/nolb-*` block leaves the 14-day window on
2026-08-28 on its own; with the decline list in place that no longer matters either
way. If a future sweep reports a large backlog, do NOT assume zalastax: dump
`--dry-run --json --limit 100000` and group by `firstSeen` and scope first.

## 2026-08-25: Release v6.0.2 (threat-intel patch)

Patch release carrying the 115 IOCs merged in #234 (107 imported package IOCs plus
8 hand-added RedShell / RedC2 indicators). No behaviour change beyond the detection
set. Model: claude-opus-5.

Release steps per CLAUDE.md: CHANGELOG block + reference link + updated
`[Unreleased]` compare base, version bumped at all 15 `versionSites` plus
`package.json`, the lockfile, the ungated `bundledVersion`, and the
`NEXT_ACTIONS.md` "Current version" header; `feed:generate`, `handoff:refresh`,
green `npm run build`.

### The README CIDR trap fired again, and the guard worked

Bumping 6.0.1 -> 6.0.2 is the second bump in a row where the OLD version string is
a substring of documentation that must not change. README line 334 documents the
Kubernetes service defaults `10.96.0.1` and `10.96.0.10`, and both contain the
literal `6.0.1`. A blanket `sed s/6.0.1/6.0.2/` would have rewritten them to
`10.96.0.2` / `10.96.0.20` and `check:version-sync` would still have reported PASS,
because it only counts occurrences of the NEW version and never inspects what else
moved. Every README site was replaced under an individual anchor instead
(`rev: v`, the docker tag, and the two `homeofe/supply-chain-guard@v` refs), and
the five affected constants were re-counted afterwards in both README.md and
`src/internal-disclosure.ts`.

The general shape, since it will recur on 6.0.3: enumerate every occurrence of the
OLD version across the tree FIRST, classify each as tool-version or data, and only
then write anchored replacements. `src/threat-intel.ts`, `src/ioc-blocklist.ts`,
`feed.json` and the historical CHANGELOG entries all carry IOC version strings that
match the tool version by coincidence - this release, `awaitly-visualizer@6.0.1`,
`awaitly-postgres@6.0.1`, `bs58-33@6.0.1`, `pypi:mem8@6.0.1` and
`@servicetitan/suppress-warnings@6.0.1` among them. The one-line diff on
`src/threat-intel.ts` is the check that the anchor held.

### Dependabot PRs folded in rather than merged separately

#232 (`@vitest/coverage-v8` 4.1.10 -> 4.1.11) and #233 (`vitest` 4.1.10 -> 4.1.11)
were pulled into this release commit and closed explicitly, the documented handling
for this repo: every dependabot PR fails `check:handoff` on its own, because
DASHBOARD.md embeds the dependency table and the bot never regenerates it. Closing
them here keeps the "a release leaves zero open PRs" invariant.

### Still carried, unchanged

`bundledVersion` in `src/threat-intel.ts` remains a version site that cannot be
gated - the full reasoning is in the 2026-08-24 entry below. It was bumped by hand
again here. The importer/pattern-table blind spot behind the recurring
`@zalastax/nolb-*` slice is also still open; see the sweep note below.

## 2026-08-25: Threat-intel sweep (daily job, PR only - no release)

Scheduled detection-set update. 107 package IOCs imported from the advisory
databases plus 8 hand-added RedShell / RedC2 indicators, and a campaign test block
for the latter. No version bump: the version belongs to the release, which the
owner cuts. Model: claude-opus-5.

### The zalastax backlog is now on its ninth sweep, unchanged

Same diagnosis as 2026-08-21/23/24, re-derived rather than assumed. The `--days 14`
window offered 4,470 new entries; 4,363 were `@zalastax/nolb-*` all carrying
`firstSeen: 2026-08-14`, and that day contributes nothing else, so it is date-pure
by new-entry count. All 4,363 were tested against the shipped anchored rule
`^@zalastax\/nolb-[a-z0-9._-]+$`: 4,363 matched, 0 unmatched, 0 carrying a version
pin. Two slices then took the whole real remainder - `--since 2026-08-11 --until
2026-08-13` returned 0 and `--since 2026-08-15 --until 2026-08-25` returned 107,
and 0 + 107 = 4,470 - 4,363 exactly, which is the arithmetic that proves nothing
real was dropped.

The root cause is still open and is NOT something the daily job should fix on its
own: the importer dedupes candidates against the feed and against bare-name feed
IOCs, but never against the pattern tables. Any family deliberately covered by one
anchored rule instead of N feed entries is therefore re-proposed on every run, and
once it is large enough it trips the undrainable-backlog error and halts the import
until a human slices the window. Written up on 2026-08-24 with two candidate fixes
(test candidates against the pattern tables before proposing them; or keep a
declined-list of advisory ids / name prefixes). The zalastax block ages out of the
14-day window around 2026-08-28, which makes the symptom disappear without fixing
the cause - the next family covered by a pattern rule will reproduce it.

### Needs a decision from the owner

1. **Fix the importer/pattern-table blind spot, or accept the manual slice as
   permanent?** The slice costs one diagnosis per run and is easy to get wrong in
   the direction of silent loss. This is the third consecutive week it has been
   raised.
2. **`@medisend/*` at `-security-research` versions.** Five packages
   (`@medisend/auth`, `@medisend/core`, `@medisend/shared`,
   `@medisend/webview-bridge` at two versions) were imported from GHSA/OSV at
   confidence 1.0, but the version string reads like a researcher's disclosure PoC
   rather than live malware. They were left in because advisory-sourced package
   IOCs are not second-guessed by this job, and the entries are version-pinned so
   the legitimate namespace is unaffected. Worth a look before the next release if
   the owner would rather this class were dropped.

## 2026-08-24: Release v6.0.1 (threat-intel patch)

Patch release carrying the 40 malicious-package IOCs merged in #230. No behaviour
change beyond the detection set. Model: claude-opus-5.

Release steps followed per CLAUDE.md: CHANGELOG block + reference link + updated
`[Unreleased]` compare base, version bumped at all 15 `versionSites` plus
`package.json` and the lockfile via `npm install --package-lock-only`,
`feed:generate`, `handoff:refresh`, green `npm run build`.

### Two things worth knowing about the bump

**The README contains CIDR ranges that look like the version.** `172.16.0.0/12`
and `10.96.0.0/12` both contain the literal substring `6.0.0`, so a blanket
`sed s/6.0.0/6.0.1/` over README.md silently corrupts the `INTERNAL_PRIVATE_IP`
rule documentation and the universal-infrastructure-constants list. The bump was
done with four targeted replacements instead (`rev: v`, the docker tag, and two
`homeofe/supply-chain-guard@v` refs), and the two CIDR matches were verified
untouched afterwards. `check:version-sync` would NOT have caught the corruption:
it counts occurrences of the NEW version and never looks at what else changed.
The same trap applies to any future 6.0.x bump.

**`src/__tests__/provenance.test.ts` hardcoded the tool version 12 times** and was
rewritten to read `pkg.version`, the pattern `reporter.test.ts` already uses. This
is the exact failure that broke the v5.2.14 and v5.2.17 publishes.

### Carried open item: bundledVersion is a version site that CANNOT be gated

`getDetectionSetProvenance()` in `src/threat-intel.ts` returns a hardcoded
`bundledVersion`, and that string is surfaced as the detection-set identity in all
nine report formats. It is NOT in `aahp.config.json` versionSites, so
`check:version-sync` has never covered it. It was correct for v6.0.0 only because
someone bumped it by hand in the release commit (d4639fc), and it was bumped by
hand again here.

Adding it to `versionSites` was tried and REVERTED, because it does not work and
would have been worse than the gap. `check-version-sync.mjs` asserts that the
current version appears at least `minOccurrences` times as a substring, and
`src/threat-intel.ts` holds 13,086 IOC entries whose values are arbitrary package
versions - 19 of them already contain `6.0.1` (`awaitly-visualizer@6.0.1`,
`pypi:ml-data-shared@16.0.1`, ...). Proof it is vacuous: with the entry added and
`bundledVersion` deliberately mutated back to `"6.0.0"`, version-sync still
reported `PASS ... matches all 16 configured version site(s)`. The schema's
`boundary` option does not help either - the IOC values are exact version strings,
not `6.0.19`-style substrings, so they match on word boundaries too.

So this file cannot be gated by presence-counting, and a gate that always passes
gives false assurance about a value that ships in every report.

The real fix is a considered change, not a patch-release side quest, which is why
it is written here rather than done:

- Have `threat-intel.ts` read the version instead of restating it - either from a
  small dedicated `src/version.ts` that IS gateable, or from `package.json`. This
  removes the drift entirely rather than detecting it. Needs a decision about
  importing `package.json` from shipped library code and the bundling implications.
- Or teach `check-version-sync.mjs` to accept an anchored pattern per site
  (`bundledVersion: "<version>"`) rather than a bare substring count. That fixes
  the whole class, and would let other data-heavy files be gated too. It is an
  upstream AAHP change, so it lands in `@elvatis_com/aahp` first.

Until one of those happens, **`bundledVersion` must be bumped by hand in every
release** and no gate will tell you if it is missed. The symptom would be silent:
scans keep working and every report advertises a stale detection-set version.
## 2026-08-24: Threat-intel import (40 package IOCs), zalastax backlog re-confirmed as covered

Scheduled daily threat-intel run. Model: claude-opus-5. No version bump - the
version belongs to the release, which the owner cuts.

### What changed

`npm run feed:import -- --since 2026-08-15 --limit 1000` added 40 package IOCs to
`FEED_CHUNK_13` in `src/threat-intel.ts`, and `feed.json` was regenerated. Every
one of the 40 carries both a GHSA and a MAL- id, so all import at confidence 1.0.
Nothing was unmappable, and no ecosystem was skipped.

Clusters, for whoever reads the diff:

- Dependency-confusion probes at sentinel versions. `sm-*` (admin, apikey-model,
  billing-form, cart, checkout, oauth, payment, session) at `99.0.0`/`99.0.1`, and
  `amundi-compare` / `fund-calculator` / `fund-list-filter` / `fund-portfolio` at
  `999.9.12`. The `99.x` / `999.9.x` shape is the standard "win the version
  comparison against the internal registry" marker.
- `conversa-sdk`, eight pinned versions from one advisory.
- `message-compiler@9.2.0`, `@opap/player-kyc-widget@3.999.999`.
- PyPI: `envprovision` 1.2.0/1.3.0/1.4.0, `cryptgraphy@1.0.0` (typosquat of
  `cryptography`), `mlflow-otel-instrumentor@1.1.0`.
- Six all-versions names, blocked bare: `identitysecuretokenserv`,
  `svelte-dim-kit`, `hydration-dim-kit`, `totp-utils`,
  `@sdgdfgdfhhhfd/multiviewr`, `@sdgdfgdfhhhfd/chainvista`.

Each of those six was checked against the npm registry before accepting a
bare-name block: all six now hold a single `0.0.1-security` version and nothing
else, so there is no legitimate release history a name-level rule could catch.
`message-compiler` was fully unpublished, and is version-pinned regardless.

### Why the window was sliced

The default `--days 14` run proposes 4,403 entries and dies on the undrainable
backlog check: 4,363 of them are the `@zalastax/nolb-*` advisory backfill of
2026-08-14, already handled on 2026-08-22 by the single anchored rule
`^@zalastax\/nolb-[a-z0-9._-]+$` in `MALICIOUS_PACKAGE_PATTERNS`.

Re-verified today rather than assumed: all 4,363 match that rule, 0 do not, and
0 carry a version pin. So the slice loses nothing.

### Carried open item: the importer cannot see the pattern tables

The importer dedupes new entries against the feed and against bare-name feed
IOCs, but not against `MALICIOUS_PACKAGE_PATTERNS`. So a family that was
deliberately covered by one anchored rule instead of N feed entries is proposed
again on every single run, and - once the family is big enough - trips the
undrainable-backlog error and stops the whole import until a human slices the
window by hand.

This one ages out on 2026-08-28, so it stops being noise on its own. The general
case does not: the next flood handled by a pattern rule will do exactly the same
thing, and the failure mode is a scheduled run that halts rather than one that
imports something wrong.

Worth a decision by the owner, not by this job, because both directions have a
real cost:

- Teach the importer to test candidates against the pattern tables before
  proposing them. Closes it properly, but couples the importer to `patterns.ts`
  and its module-load validation.
- Keep a small declined-list of advisory ids or name prefixes the importer skips
  with a reason. Cheaper, but it is a second place that has to stay true.

Doing nothing is also defensible: the slice is two flags and the run is
supervised. It just means every future flood costs a manual diagnosis first.

### Non-package enrichment: nothing addable today

Searched Socket, Aikido, StepSecurity, JFrog, Checkmarx and the Hacker News recaps
for write-ups on today's clusters. None has published on them yet - these are
fresh advisories on names npm has already taken down, and the atomic indicators
(C2 domain, C2 IP, hash, dead-drop, actor handle) are not in any source. Nothing
was invented to fill the gap.

Cross-checked the large recent campaigns for partial coverage while looking:
keyv/cacheable, Shai-Hulud, node-ipc (`sh.azurestaticprovider[.]net`), TanStack
(Session network) are all already present in `src/ioc-blocklist.ts` and the feed.
No gap to extend.

### Verification

`npm run build` green (check:aahp + check:feed + check:handoff, then tsc).
Targeted suites run locally; the full suite is CI's verdict per the repo rule.
No pattern table was touched, so no module-load regex validation risk this run.
## 2026-08-23: Release v6.0.0 (Zero Open Issues, Node 22+ Baseline, Complete Provenance, SBOM & SLSA Hardening)

Major release v6.0.0. Zero-open-issues requirement achieved across all issues (#169-#208) and PR acceptance criteria (#185-#227).

### Major Release Invariants & Highlights
- **Zero open issues:** 100% of open issues resolved, merged, and reconciled on GitHub.
- **Node support baseline:** Node 22 canonical baseline and Node 24 Active LTS enforced; Node 20 transition lane retired.
- **Full provenance metadata across 9 formats (#208):** Tool version, scan timestamp, git revision SHA/branch/origin URL, and threat feed generation vintage and cache merge status emitted across text, JSON, markdown, SARIF, SBOM, HTML, badge, GitLab, and JUnit.
- **CycloneDX 1.6 SBOM correctness cluster (#221, #191-#200):** Hexadecimal hashes, canonical RFC purls, lockfile component names, specifier annotation properties, and incident cluster survival across SARIF/SBOM/markdown.
- **SLSA attestation & evidence-backed posture (#220, #188-#190):** Envelope structural validation (`structurallyValid`), AST-level workflow comment stripping, and explicit posture score disclosure.
- **Offline boundary & network disclosure (#201, #224):** Fully documented offline architecture and explicit network boundaries.
- **Calibrated correlation confidence (#203, #225):** Incident confidence mapped accurately to indicator match ratios.
- **Directory scan trust renormalisation (#202, #226):** Mode-aware trust scoring for offline directory targets.
- **Single SLA compliance definition (#172, #209, #194, #223):** Unified time-to-breach SLA calculation and triage pair-scoped evaluation.

## 2026-08-23: Issue 208 (Provenance Metadata and Detection Set Version Across All Report Formats)

Zero-open-issues met and PR #227 merged!

### Already on GitHub / Closed Issues
All closed-issue acceptance boxes were reconciled against origin/main on GitHub
by editing issue bodies. Done for: 205, 204, 203 (merged via PR #225), 202 (merged via PR #226), 201 (merged via PR #224),
200, 199, 198, 197, 196, 195, 194, 193, 192, 191, 190, 189, 188, 180, 179, 178, 177, 176,
175, 174, 173, 172, 171, 170, 169, 167, 168.

### Open issues remaining: 208 (addressed by this branch)

This change addresses Issue #208:
- Git revision provenance: `src/scanner.ts` extracts HEAD commit, branch, and remote URL when target is a git repository.
- Detection set provenance: `src/threat-intel.ts` exports `FEED_GENERATED_AT` and `getDetectionSetProvenance()`, reporting bundled version, entry count, generation timestamp, and cache merge status.
- `feed.json` & `scripts/generate-feed.mjs`: `feed.json` carries a distinct `generatedAt` timestamp, and `FEED_DOC_KEYS` validates it.
- All 9 report formats in `src/reporter.ts` surface tool version, timestamp, git commit provenance, and detection set identity. SARIF emits `run.invocations[].startTimeUtc` and `run.versionControlProvenance[]`.
- Added test suite `src/__tests__/provenance.test.ts` asserting provenance across all 9 formats.




## Closeout after #220 and #221: SLA findings reach the report, and riskTrend includes now

#220 and #221 are on main. Remaining open issues after that merge and the
closes they implied: 167, 168, 194, 201, 202, 203, 206, 208. #179 was already
done on main (persist-credentials: false on every checkout that does not
push, delete_branch_on_merge true, AAHP pin 3.10.0) and was closed with that
evidence.

This change:

- Issue 194: `scan()` calls `checkSlaCompliance` on the triage decisions.
  A tree whose store is 30 days past SLA now raises `SLA_BREACH_CRITICAL`.
- Issue 206: `calculateMetrics` takes the current score. Two history rows at
  40 plus a current score of 0 report `decreasing`; the same history without
  the current score still reports `stable`.

Not in this change: 167 (ancestry gate already on main; aahp-verify on tags
would fail because a tag of HEAD is a HEAD-equal base and 3.10.0 blocks
that), 168 (policy-diff against the base ref), 201, 202, 203, 208.

## Remaining review findings on the SBOM cluster: they reproduced, and they are closed

Independent re-read of the four leftovers on #221:

1. The `!refsArePaths` guard is load-bearing and was untested. A package.json
   fallback uses the declared key as the bom-ref, so prefix-matching `src`
   against a finding in `src/app.js` would attribute that finding to an
   unrelated dependency. A test now asserts the affects ref stays `target`;
   deleting the guard turns it red.
2. `expect(ids).toContain(steam?.correlationId)` could not fail under the
   pre-change overwrite: the last-written incident is still one of `ids`. The
   legacy field is now asserted to be `correlationIds[0]`, and not the last
   entry, which is the overwrite the field used to do.
3. `describeInventoryCoverage()` has three branches. Only `NOTHING WAS
   INVENTORIED` was asserted. All three states are now named by a test that
   calls the function.
4. The CHANGELOG said a bare component count is never all a reader sees. That
   sentence reached only the `--sbom-output` stderr line. The default text
   report now prints the coverage sentence under the SBOM bar.

## Two review findings on the SBOM cluster: an unenforced checksum and a root-only walk

Adversarial review found the conformance proof anchored to three vendored
CycloneDX schema files whose integrity nothing checked. `.gitattributes`
justified pinning them to LF by saying that otherwise "every recorded checksum
would stop matching, so the one check that says 'this is still the official
schema' could no longer be run" - asserting a check that did not exist. The
checksums sat in the fixtures README and were never compared to anything.
`src/__tests__/vendored-schema-integrity.test.ts` is that check. It parses the
expected values out of the README rather than carrying a second copy, because
two copies of a checksum is how one of them quietly stops matching. Mutation
proof: append one byte to a schema, exit 1; restore, exit 0.
Second finding: `detectUninventoriedManifests()` looked only at the project
root. A monorepo keeps `pyproject.toml` and `Cargo.toml` under `packages/*` or
`services/*`, so issue 195 survived intact in the layout most likely to hold
more than one ecosystem - while the README stated every such file is named. It
now walks, skipping `node_modules` and friends, bounded at depth 4 and 25
reported entries.
WHAT THIS DOES NOT COVER: the walk is bounded, so a manifest deeper than four
levels is still not named, and that is deliberate rather than an oversight - an
unbounded traversal inside a scanner becomes the slowest part of a scan and then
gets switched off. The bound is pinned by a test, so raising it is a decision
someone makes rather than a change someone discovers.

## SBOM cluster follow-up: the incident evidence document that was already there

Model: claude-opus-5. Branch fix/sbom-correctness-cluster. No version bump.
Follow-up to the entry below, addressing the second comment on issue 200.

`scan --export-incident-md` has shipped for several releases and writes exactly
the artefact the NIS2 bullet describes: risk score, each detected incident with
its confidence, narrative and indicator list, the critical findings, and the
response playbooks. The README named it nowhere, so the bullet promised less
than the tool does while pointing at formats that carried nothing. Verified by
running it against the issue's own fixture before writing the sentence. It is now
named in the NIS2 bullet. No behaviour changed; this is documentation of an
existing flag.

WHAT THIS DOES NOT COVER: the flag is still absent from the CLI options table and
from the GitHub Action inputs. It is mentioned where a reader looking for
incident evidence will be, not everywhere it could be listed.

## SBOM: the document was well formed and wrong, in seven places at once

Model: claude-opus-5. Branch fix/sbom-correctness-cluster. No version bump.
Closes issues 191, 192, 193, 195, 197, 198 and 200; all seven were reproduced on
this branch's base commit before anything was changed.

The seven had one shape. The emitted CycloneDX document parsed, said
`bomFormat: CycloneDX` and `specVersion: 1.6`, and the process exited 0, while
the values a consumer actually reads were unmatchable, truncated, unresolvable or
absent with no statement that they were absent. That shape is why they are fixed
together and share one regression suite.

Measured on this repository, before and after:

- **Schema.** 119 of 119 components carried a hash, 0 of 119 in the encoding the
  spec requires, 119 errors from the official CycloneDX 1.6 schema. `integrity`
  is base64; `hashes[].content` must be hex. Now 0 errors.
- **purls.** 55 of 119 matched the canonical purl from `packageurl-js`, the purl
  specification's reference implementation; the other 64 were scoped names with
  `%2F` where the separator belongs. Now 119 of 119.
- **Identity.** A nested duplicate entered the inventory as
  `middle/node_modules/@acme/dep`, so the older installed version was present in
  the document and unfindable under its own name. A workspace member was named
  after its directory while its lockfile entry declared the real name.
- **Versions without a lockfile.** The fallback produced a version by deleting
  one leading non-digit character: `latest` became `atest`, and `^1.2.3` became
  the factual claim that 1.2.3 ships. A component now carries `version` and
  `purl` only for an exact version, and says why when it does not.
- **Unread ecosystems.** A Python, Cargo or Go project got `components: []` and
  exit 0. The document now carries `inventory-coverage` and `not-inventoried`,
  and the CLI prints the same sentence next to the component count.
- **Two commands, one artefact.** `--sbom-output` wrote a file with no
  `vulnerabilities` key while `--format sbom` merged the findings in; every
  `affects[].ref` in the latter pointed at a path, not at a bom-ref, so 0 of the
  references in a scan of this repository resolved.
- **Incidents.** SARIF and CycloneDX carried no incident name, confidence or
  indicator list, and a finding belonging to two incidents reported one.

WHAT THIS DOES NOT COVER, so the next reader does not overestimate it:

- **No new ecosystem is inventoried.** A Python, Cargo, Go, RubyGems, Composer or
  NuGet project still produces an SBOM with no components from that ecosystem,
  and a pnpm, yarn or bun project still falls back to the direct dependencies in
  `package.json`. What changed is that the document and the CLI now SAY so. The
  issue asked for exactly this, and the stronger option - refusing to write an
  SBOM at all for an ecosystem that cannot be inventoried - is a behaviour change
  for existing adopters and is left as an owner decision, named in the pull
  request.
- **`--sbom-output` writes a different file than it did.** It now contains the
  scan's findings as `vulnerabilities`, and `annotations` when the scan
  correlated an incident. That is the point of issue 198, but a consumer that
  diffs SBOMs across versions will see it.
- **`affects` attribution is prefix matching on lockfile paths.** It is attempted
  only when the inventory came from `package-lock.json`, because only then are
  bom-refs relative paths. On the `package.json` fallback every finding is
  attributed to the subject with its path in a property. Nothing is guessed, but
  nothing is attributed either.
- **The vendored CycloneDX schemas can go stale.** They are unmodified upstream
  copies with their SHA-256 recorded in
  `src/__tests__/fixtures/cyclonedx/README.md`, pinned to LF in `.gitattributes`
  so a Windows checkout cannot silently invalidate the checksums. Nothing
  automatically notices a new 1.6 patch release; refreshing them is a manual
  step, documented there.
- **Markdown, HTML, badge, GitLab and JUnit still carry no incident record.** The
  README's NIS2 bullet now names only the three formats that do, rather than
  being widened to formats that would then need the same work.
- **The conformance suite validates structure, not truth.** A document that
  passes the CycloneDX schema and carries canonical purls can still describe the
  wrong tree if the lockfile is wrong. The schema check closes "well formed and
  wrong", not "wrong".

Three test-only devDependencies were added: `ajv` and `ajv-formats` to evaluate
the real schema, `packageurl-js` to compare against the reference purl
implementation. All three carry `dev: true` in `package-lock.json`, verified by
reading the lockfile, so `npm ci --omit=dev` and the Docker build drop them and
the published tarball's dependency set is unchanged.
`@cyclonedx/cyclonedx-library` was deliberately NOT added: it declares `ajv`,
`ajv-formats` and `packageurl-js` as OPTIONAL PEER dependencies, which is the
shape that gets a dev-only package recorded without the `dev` flag and shipped
into a production image.
## Independent review of the remaining #220 findings: they reproduced, and they are closed

The handover asked a second reader to contradict the two vacuous-test findings
that kept #220 unmerged. They held.

1. The mechanism carrying "not assessed" into a published artefact was
   untested. Deleting the SARIF `slsa` invocation property, the JUnit
   `slsa-level` / `slsa-not-assessed` properties, the text `NOT ASSESSED:` /
   `from:` blocks, the zero-coverage caveat sentence, or the GitLab `warn`
   level left reporter.test.ts, issue-205-zero-coverage.test.ts and
   slsa-verifier.test.ts green. Those tests now exist, and the JUnit renderer
   now also emits `slsa-basis` (the acceptance box claimed every renderer
   showed it; JUnit showed the level and omitted the checks that produced it).
2. `rejects an array digest rather than an algorithm-to-value map` called
   `writeSubjectDigest([])`. An empty array is already rejected by the
   `entries.length === 0` check. `Object.entries(["deadbeef"])` is
   `[["0","deadbeef"]]`, which would pass that check and the string-value
   check; the test now uses that input, so deleting `Array.isArray` turns it
   red.
3. The slsa-github-generator Level 3 path still combined a generator mention
   in one file with `workflow_call` in another. Same bound as the npm-native
   path, on files rather than jobs: both signals must now live in one
   workflow file. Split-file stays at 2 via the Level 2 generator pattern.

`delete_branch_on_merge` is now `true` on this repository (the handover
recorded `false`). The worktree at `_scg-wt-sbomfix` still holds
`fix/sbom-correctness-cluster` and still has to be removed before merging
#221.

## Provenance published through a reusable workflow was rejected

Issue 190's fix required the `npm publish --provenance` step and the
`id-token: write` permission to resolve to the same job. Correct for a job that
publishes from its own steps; wrong for a common real layout.
A caller job holds the permission and does nothing but `uses:` a reusable
workflow; the callee runs the publish. GitHub passes the CALLER permissions to
the callee, so the token really is in effect at the publish step and that
configuration really does mint Sigstore provenance. It was graded 2.
A false negative is the safe direction of error, but silently under-grading is
the same defect class as silently over-grading, so it is fixed: a caller job
holding `id-token: write` whose `uses:` resolves to a LOCAL workflow with a
publishing job now counts.
THE BOUND THAT KEEPS THIS FROM BECOMING OVER-GRADING: only local callees are
resolved. A remote `owner/repo/...@ref` cannot be read from the checkout, and a
lookup that collapsed it to a bare file name would match a local file of the
same name and credit a workflow nobody here has read. Remote refs keep their
full form, fail the lookup, and are reported rather than credited. A test pins
that refusal with a same-named local decoy present.
FOUND WHILE VERIFYING, worth recording: the first implementation compiled,
read correctly and did nothing, because the map was keyed on a parsed
workflow's bare file name while `uses:` gives a repository path. Only running it
on a real layout showed it - the diff looked right.

## Zero coverage and an unread language are not the same state

The first version of the issue-205 fix fired on `filesScanned === 0`. That is a
different predicate from the one the issue describes. Issue 205 is a scan of an
EMPTY TREE - a checkout that did not run, a wrong working directory, a sparse
checkout, an empty mounted volume.
An ordinary Java, C#, Ruby, PHP, Kotlin, Swift or plain-HTML repository has
files that simply carry no scannable extension, so it also landed on
`filesScanned === 0`. Measured on a two-file Maven project: exit 0 became exit 1
and a brightgreen badge became orange, with remediation text naming only causes
that did not apply to it.
That is a false positive reaching every adopter whose language is not in the
scanned set, and a control that fails ordinary use gets switched off - taking
the real issue-205 protection down with it.
Split into the two states:
  allFiles.length === 0                     -> SCAN_ZERO_COVERAGE, partial, fails.
  allFiles.length > 0 and filesScanned == 0 -> SCAN_NO_SCANNABLE_FILES, informational.
The second is deliberately NOT in PARTIAL_SCAN_RULES: "this tool does not read
that language" is a statement about the tool, not a coverage gap in the run. It
still says so out loud, so it cannot be read as a clean verdict either.
WHAT THIS DOES NOT COVER: a scan whose coverage is merely LOW rather than zero -
one file of a thousand because ignore globs pruned the rest - is still reported
as a complete verdict. A proportional coverage floor needs a threshold nobody
has chosen, and guessing one here would repeat the mistake this entry records.

## No green without evidence: four controls that reported success without doing the work

Branch fix/no-green-without-evidence. Model claude-opus-5. No version bump; the
comments say "unreleased" rather than naming a release nobody has chosen yet.

Issues 205, 188, 189 and 190 are one defect with four faces: an output that
cannot say "I did not check this", so ignorance renders as a pass. All four were
reproduced at HEAD fa81f70 before anything was edited, and the reproduction
output is in the pull request body.

### What changed

- **A scan of zero files is no longer a clean verdict** (issue 205).
  `src/scanner.ts` raises `SCAN_ZERO_COVERAGE` when `filesScanned === 0`, and
  that rule joins `PARTIAL_SCAN_RULES` in `src/pattern-scanner.ts`, so the
  existing partial-coverage path fires in every renderer that already honours
  it. Measured before: the badge for an empty directory was byte-identical to
  the badge for a clean two-file tree, and `--fail-on critical` exited 0. After:
  `partial`/orange, and exit 1. `action.yml` carries the same rule list and a
  test enforces that the two stay identical, so the Action's coverage schema was
  updated with it.
- **SARIF, GitLab and JUnit now state their own denominator** (issue 205). The
  SARIF invocation is now always emitted and carries a `coverage` property bag;
  GitLab always carries a coverage message, warn-level when the count is zero;
  JUnit always emits a `<properties>` block with the file counts. Those three
  formats read neither `filesScanned` nor `totalFiles` before, which is why they
  could not tell nothing from nothing-found.
- **An unsigned DSSE envelope is no longer valid provenance** (issue 188). The
  `signatures` member was never read. `signatures: []`, a missing key, and
  entries with no `sig` value are now `kind: "malformed"` and raise a new
  `SLSA_ATTESTATION_UNSIGNED` finding. `AttestationResult` gained
  `structurallyValid`, `signatureStatus` and `checksNotPerformed`; the boolean
  named `valid` is kept as a deprecated alias so no consumer breaks.
- **An empty or non-string digest set is malformed** (issue 189). The old test
  was `digest && typeof digest === "object"`, satisfied by both `{}` and `[]`.
  `isUsableDigestSet` now requires a non-empty map of non-empty strings, and
  `subjectCount` counts only subjects that pass it.
- **A commented-out publish step no longer grades a repository 3/3** (issue 190).
  Level 2 and the generator reference are matched over comment-stripped workflow
  text; the npm-native Level 3 path resolves `npm publish --provenance` and
  `id-token: write` inside ONE parsed job, using the repository's own
  `src/workflow-ast.ts` and GitHub's real permission semantics (a job-level
  block REPLACES the workflow-level one). `HERMETIC_BUILD_PATTERNS` is gone: it
  matched `workflow_call`, which is a trigger and not an isolation property, and
  hermeticity is not a SLSA v1.0 Build L3 requirement at all.
- **A malformed attestation can no longer coexist with a 3/3 headline** in the
  same report; it caps the level at 2.
- **`SLSAAssessment`** (`level`, `basis`, `notAssessed`, `attestation`) is on the
  report and rendered by the text, JSON, SARIF and JUnit formats, so the number
  never appears without the checks that produced it and the three this tool
  never performs.

### Two existing assertions were CHANGED, not added

Both locked in a defect, and both are called out in place with the reason:

- `src/__tests__/slsa-verifier.test.ts`: "should treat --provenance +
  id-token:write split across two workflow files as L3" asserted 3 for a
  configuration that cannot mint provenance at runtime. It now asserts 2.
- `src/__tests__/scanner.test.ts`: "should return a clean report for an empty
  directory" asserted precisely the behaviour issue 205 reports. It now asserts
  the coverage signal. The security half of it is unchanged.

### WHAT THIS DOES NOT COVER

- **No signature is verified.** Nothing here fetches key material, walks a
  Fulcio chain, or checks a Rekor inclusion proof. A syntactically valid but
  untrusted signature is still indistinguishable from a trusted one, and issue
  188's acceptance criterion asking for those three states to be distinguishable
  is only two-thirds met: absent is now distinguishable, forged is not. Real
  verification means choosing trust roots and adding a network or bundled-root
  dependency to a supply-chain tool, which is an owner decision.
- **The field named `valid` still exists** and still reads as a verification
  verdict. Renaming it outright breaks every published consumer of the exported
  API, so it is deprecated in place rather than removed. Owner decision.
- **The output is still labelled "SLSA Level"** and still renders as `n/3`.
  Issue 190 argues the number should not be published under a specification's
  name when it cannot mean the specification's level. That is a public-facing
  rename touching README, badge and JSON consumers. Owner decision; only the
  qualifying text was added.
- **Low coverage is not partial coverage.** One file scanned out of a thousand,
  because ignore globs pruned the rest, is still reported as a complete verdict.
  Only zero is treated as a gap. A proportional floor needs a threshold nobody
  has chosen.
- **`subjectCount` is a count of digested subjects, not of verified ones.** No
  digest is compared against any artefact, in the tree or published.
- **The full suite was not run locally.** Only the files touched plus their
  neighbours were, and `src/__tests__/vscode-scanner.test.ts` fails 14 tests here
  for a missing `zip` binary, identically on unmodified `main`. CI on Linux is
  the authoritative verdict.

### Noticed in passing, fixed, and NOT covered by a test

`slsaLevel` was computed inside the returned object literal, which is evaluated
AFTER `fs.rmSync(tempDir)`. For a `github` scan target the SLSA level was
therefore graded against a directory that had just been deleted, while
`verifySLSA` had run much earlier against the real checkout, so the level and the
findings in one report could disagree. The assessment is now taken before the
cleanup. This is not covered by a new test: exercising it needs a real clone, and
this branch adds no networked test.
## Threat-intel sweep 2026-08-23: 38 package IOCs, no atomic indicators

Model: claude-opus-5. Branch threat-intel/2026-08-23. No version bump.

38 package IOCs imported from the GitHub Advisory Database, corroborated against
OSV.dev (22 confirmed). 37 npm, 1 PyPI. No non-package indicator was added by
hand this run, and that is a finding rather than a gap: see below.

### The import had to be sliced again, and the reason is unchanged

The plain rolling-window call still exits 2. Measured today: 5,955 advisories in
the 14-day window, 4,401 of them "new", of which 4,363 are the `@zalastax/nolb-*`
backfill that the 2026-08-22 sweep already resolved with one anchored pattern in
`MALICIOUS_PACKAGE_PATTERNS`. The importer has no way to know those names are
covered by a pattern rather than by feed entries, so it will keep counting them
as new until they age out.

Independently re-derived today rather than taken on trust, since the earlier
finding is what the whole slicing decision rests on: the bulk is 4,363 of the
5,083 advisories published on 2026-08-14, all npm, all all-versions ranges, and a
20-name spread sample resolves 20/20 to npm security holding packages carrying
only `0.0.1-security`. The underlying releases date from Jan 2023 and were
unpublished in Feb 2023. Registry ownership now reads as npm's own holding
account. So the conclusion of the previous sweep holds.

**New, and what made this run cheaper:** the bulk was published inside a
two-minute window, `2026-08-14T11:13:55Z` to `2026-08-14T11:16:08Z`, and the
advisories API accepts a full ISO timestamp in the `published` range, not only a
date. So the slice can cut around the flood instead of dropping the whole day:

    npm run feed:import -- --since 2026-08-14T11:16:09Z --until 2026-08-23T23:59:59Z --limit 100000

Only 6 non-zalastax advisories fall inside that two-minute window, and all 6 were
verified already present in the feed, so nothing is lost by excluding it. The
slice below it (2026-08-09 to 2026-08-14T11:13:54Z) was also run and returned 0
new entries, so the whole genuine yield of the window is the 38 taken here.

This still needs no importer change. **After roughly 2026-08-28 the block ages
out and the plain `npm run feed:import` starts working again**; a later sweep
should stop slicing rather than keep doing it out of habit.

### What was imported

The largest clusters: `totp-utils` (8 versions), a ten-entry dependency-confusion
set of the form `<digit>-<verb>sight-web`, and nine `stillm4ddpocs-*`
proof-of-concept publications on 999.9.x lure versions. Also the
`@syncraft-labs/*` trio at 0.4.1, four `*-testkit` / `*-testing-utils` names,
`create-coin@20.1.1`, the bare name `internallib_v902`, and
`@usaa-grp-personal-profile/personal-profile-common@999.0.0`, a dependency
confusion lure aimed at an internal scope of a real financial institution and so
version-pinned rather than blocked by name.

Incidental corroboration: the PyPI entry is `scrambleeeer@0.1.0`, a fourth
spelling in a family the feed already carries as `scrambleeer`.

Nothing was reported unmappable, nothing was skipped for an unresolvable
ecosystem, and the page cap was not reached on either slice.

### Why no atomic indicators were added

The vendor sweep found no write-up published since the 2026-08-22 sweep that
carries an indicator this feed does not already hold. Sources checked: Socket,
Aikido, StepSecurity, The Hacker News, GitGuardian, JFrog, Elastic, Unit 42 and
Zscaler. Every campaign currently on their front pages was cross-referenced and
is already covered: Mastra scope takeover, Miasma LeoPlatform, ChainDrop /
keyv-cacheable including the smart-contract C2 resolver, the Open VSX evil-twin
set and its collection host, WEL1DROPPER, RedC2 4.0 and the Alibaba-tooling RAT
set. The newest vendor post found anywhere in the sweep is dated 2026-08-21,
which is inside the window the previous sweep already covered.

`shai_hulululud@1.0.48596` remains deliberately out, on the reasoning recorded by
the previous sweep. Re-confirmed today that no advisory database carries it.

### NEEDS A DECISION: this repository is 24 branches over its own invariant

Not caused by this sweep and not acted on by it, but it is the largest thing
visibly wrong with the repo right now, and the release checklist says a finished
deploy leaves exactly `main` and `v5`.

`git ls-remote --heads origin` currently lists 24 branches besides those two:

- **21 belong to MERGED pull requests** and should have been deleted with the
  merge (#164, #165, #166, #181, #182, #183, #184, #185, #186, #187, #207, #209,
  #210, #211, #212, #213, #214, #215, #216, #217, #218). `threat-intel/2026-08-22`
  is among them, so the previous run of this task left its branch behind too.
- **2 are the open pull requests** #220 and #221, which are legitimate.
- **1 has no pull request at all**: `fix/issue-193-purl-namespace-separator`.
  That one is not bookkeeping. It is either abandoned work or work that was never
  proposed, and it should be looked at before it is deleted with the rest.

This is the failure mode the checklist already warns about: `gh pr merge
--delete-branch` leaves the remote branch behind when a worktree holds the local
one, and it names only the local branch in the error, so it reads as harmless.
Twenty-one at once suggests it is systematic rather than a one-off.

Deliberately not fixed here: deleting branches is destructive, two pull requests
are in flight from another session, and one branch has no pull request to prove
its content is preserved. The safe check per branch is a tree diff against the
release that shipped it, not `git branch --merged`, which lies under squash-merge.

## SBOM: the licences, dependency relationships and bom-refs the lockfile already carried

The generated CycloneDX document was omitting three things the npm lockfile already
holds: per-component licence expressions, the dependency graph, and stable
bom-refs. A consumer feeding it to a licence-compliance tool got a well-formed
document that answered "unknown" for every component, which is worse than
refusing, because it reads as a measurement.
`src/sbom-generator.ts` now emits all three, `src/types.ts` carries the shapes,
and `src/policy-engine.ts` takes the shared `SUPPRESS_PLACEHOLDER_REASON`
constant rather than a second literal copy of the same placeholder text - two
spellings of one placeholder is how one of them quietly stops matching.
WHAT THIS DOES NOT COVER, so the next reader does not overestimate it: the
licence data is only as good as the lockfile's. A package that declares no
licence still produces a component with no licence expression; the document now
distinguishes "the lockfile did not say" from "we did not look", but it cannot
invent the answer. Ecosystems other than npm are unaffected by this change.

## 2026-08-23 - declare merge=union for the handoff append-log

`.ai/handoff/STATUS.md` is prepend-only, so two branches almost always differ by
one block and nothing else. Eight sibling repositories in this estate already
declare `merge=union` for it; this one did not, and the two that lacked it are
exactly the two where twenty-two rebases on 2026-08-23 each resolved this file by
hand.

It does not stop a pull request going CONFLICTING - GitHub does not honour merge
drivers server-side, measured 2026-07-31 - so this removes the hand resolution,
not the merge. `MANIFEST.json` is deliberately left without a driver: it is
generated state, and the correct resolution is to take main's copy and recompute
the changed entries, which no driver can do.

# supply-chain-guard: Current State

> Updated 2026-08-20 (release v5.27.0). This is one current snapshot, not a session
> log. Historical detail belongs in CHANGELOG.md, generated LOG.md, LOG-ARCHIVE.md,
> and git history.

---

## The rule set now reports its own age (2026-08-22, unreleased)

Model: claude-opus-5. Branch feat/feed-staleness-self-report. No version bump.

This closes the gap the previous section left open under "Known limitation of
this change": documentation told consumers that a frozen pin freezes the rules,
but nothing at scan time said so.

### What the feed's age actually is, measured

At v5.28.1 the bundled feed is **1 day old**: 12,962 entries, 12,951 of them
carrying a `firstSeen`, newest indicator 2026-08-21, oldest 2025-09-29. Two
thirds of the corpus was added in the last two months (6,360 in 2026-07, 6,073 in
2026-08). So the feed shipped with the current release is not the problem. The
whole exposure sits on the consumer side, in a pin that stops moving while this
corpus keeps growing at roughly a hundred entries a day.

The previous session concluded the scanner "cannot currently report the age of
the rules it just ran" because the feed carries no feed-level generation date.
It does not need one. The per-indicator `firstSeen` dates are enough: the maximum
over the feed is the date past which this rule set knows nothing.

### What was built

`feedFreshness()` in `src/feed.ts` derives `{ newestIndicator, ageDays,
datedEntries, stale }` from that maximum. Pure, offline, deterministic, no
network and no configuration. Past 30 days `scan()` emits `THREAT_FEED_STALE`
(medium) carrying the measured age and the newest indicator's date.

Two decisions worth knowing:

- **It measures the EFFECTIVE feed, not the pin.** `scanner.ts` passes the
  merged bundled-plus-refreshed-cache list that `checkThreatIntel` and
  `matchPackageIOC` already consumed. A consumer running `feed refresh` before
  each scan is genuinely current on an old pin and is reported as such. That
  makes it an assertion about the consequence, not about the configuration.
- **medium, not high.** It moves the score off zero and the risk level off
  `clean`, so it is named in eight of the nine report formats and in the Action's
  pull request comment, but it cannot flip the Action's default `fail-on:
  critical` gate or the CLI's default `high` gate. Verified against a real scan:
  exit 0, unchanged. Escalating it is a product decision, not a side effect. See
  NEXT_ACTIONS.

**Corrected 2026-08-22: this said "every report format", and that was one format
too many.** Rendering a single `THREAT_FEED_STALE` finding through
`formatReport` for all nine formats, the rule id appears in `text`, `json`,
`markdown`, `sarif`, `sbom`, `html`, `gitlab` and `junit`, and NOT in `badge`.
`formatBadge` builds a Shields.io endpoint payload (`schemaVersion`, `label`,
`message`, `color`) out of `report.summary` counts alone, so no rule id or
description can reach it by construction; what is observable there is an
otherwise clean repository's badge turning from `clean`/`brightgreen` into
`1 medium`/`yellow`. `junit` carries the id but as a passing `<testcase>`, since
`formatJunit` only renders `critical`/`high` as `<failure>`. The same wrong
sentence stood in CHANGELOG.md, README.md, NEXT_ACTIONS.md and the doc comment
on `feedStalenessFindings` in `src/feed.ts`, and is corrected in all four;
CHANGELOG.md is the one that becomes the GitHub Release body verbatim, which is
why it was fixed before the pull request text. The `src/feed.ts` comment matters
because it is the copy a maintainer meets at the moment they consider raising
the severity, so it now carries the measurement and an instruction not to
restore the old wording without re-rendering all nine formats. That edit is a
comment: no behaviour changed.

Three ways this check could have stopped firing are closed and each has its own
test: a future-dated `firstSeen` is ignored (one mistyped year would otherwise
make every feed look permanently current), a date that parses but does not
round-trip (`2026-02-31`, which `Date.UTC` rolls into March) is rejected rather
than normalized past every real entry, and a feed with no usable date at all
reports stale rather than silent.

`feed stats` now prints both ages, bundled and effective, and returns them under
`bundledFreshness` / `freshness` in `--format json`.

### Proof

`src/__tests__/feed-staleness.test.ts`, 12 tests. The integration case scans the
SAME directory twice, once with a 1-day feed and once with a 400-day feed, so the
only variable is the feed's age: the stale run gains exactly the one rule and a
higher score, and no other rule appears or disappears. Mutation proof after
committing the fix, five substitutions, each guarded by an assertion that it
changed the file: trusting a future date, accepting a non-round-tripping date,
treating an undatable feed as fresh, never emitting the finding, and dropping the
scanner wiring. All five go red; restoring returns 12 of 12 green on a clean tree.

Local full suite: 4 files / 18 tests failing on this branch, versus 8 files / 52
tests failing on unmodified `origin/main` in the same environment. Every file
failing here also fails there (the missing `zip` binary and load-dependent
flakes). Linux CI is the verdict.

### Independent re-audit of the published release bodies

All 134 release bodies re-fetched and re-scanned for private repository names,
internal issue numbers, LAN addresses, host names and local paths. Same result as
the previous session, reached independently: **zero real disclosures**. The 16
raw matches are all deliberate publications (Kubernetes/k3s/Docker default
service CIDRs from this scanner's own detection corpus, a public agent-runtime
product name it ships a scanner for, and the English words trust/intelligence/
awareness in feature prose). v5.2.40 and v5.2.41 both carry the era's stub body,
"See README.md for full changelog"; the anchor resolves to the corrected file.
## A triage decision is a (rule, file) pair, and only one consumer knew it (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/triage-decision-scope-key. No version bump.
Fixes https://github.com/homeofe/supply-chain-guard/issues/171

### What was wrong

`calculateMetrics` built its resolved set from `d.findingRule` alone, so one
resolved decision removed every finding of that rule from `openCritical`,
`openHigh` and `topRiskContributors`, including findings in files nobody had
triaged. `TriageDecision.findingFile` exists to scope a decision to a file and
was never read there.

The root cause is not a missing file check. `git log -- src/metrics.ts` returns a
single commit, the one that created the file, and the correct (rule, file) key
was written the same day in the same feature over the same array, in
`checkTriageGovernance`. One feature shipped two key widths and only one
survived. Both read the identical decisions array on the same scan, so one JSON
report could carry `"openCritical": 0` beside "2 critical finding(s) have no
assigned owner or triage decision".

It survived four months because every case in `metrics.test.ts` used at most one
finding per rule and never set `file` on either side. With one instance per rule
a rule-keyed set and a pair-keyed set give identical answers, so the suite could
not tell the two implementations apart and stayed green under either. The green
suite was part of the finding.

### What changed

The scope rule now has exactly one implementation, `src/triage-scope.ts`, and
both consumers ask it. Sharing a key STRING between the two call sites would
have fixed the counts and left the divergence one edit away, so no consumer
builds a key at all; they ask "does any of these decisions cover this finding?".
`buildTriageScope` is exported for library consumers, who are the only way to
use the store since it has no CLI subcommand.

One behaviour change came with it: `CRITICAL_FINDING_NO_OWNER` joined
`file ?? ""` into its key, so a decision carrying no `findingFile` matched only
findings that carry no file and every instance in a real file stayed "unowned".
It now covers them, which is what an absent `findingFile` has always meant on
the metrics side. Absent and empty stay different, and each branch has a test.

`docs/triage-decisions.md` is new: the store, its format and its scope rule were
documented nowhere.

### Evidence

Paired end to end through the built CLI on one fixture, three critical
`EVAL_ATOB` findings in three files, one resolved decision naming `src/a.js`,
same command both times:

| | before | after |
| --- | --- | --- |
| `summary.critical` | 3 | 3 |
| `metrics.openCritical` | 0 | 2 |
| `topRiskContributors` | `CRITICAL_FINDING_NO_OWNER` | `EVAL_ATOB`, `CRITICAL_FINDING_NO_OWNER` |
| process exit code | 2 | 2 |

Variant with the decision naming `vendor/not-scanned.js`, a path no finding
carries: `openCritical` 0 before, 3 after. Variant with no `findingFile` at all:
0 before, 0 after, which is the behaviour that had to be preserved.

No gate moved. `getReportExitCode` reads `report.summary`, `report.findings` and
`report.partialScan`, never `metrics`, and the fixture exits 2 in both columns.
The wrong number reached `--format json`, `--json-output` and library consumers.

Mutation proof, both branches of the new module, run on the three affected test
files: replacing the file-scoped lookup with a rule-level one reddens 11 of 34;
replacing `d.findingFile === undefined` with `!d.findingFile` reddens the 2 cases
that pin absent against empty. Restored, 34 pass.

### Open for the maintainer

1. **The severity label on the issue.** It carries `priority: high`. The measured
   blast radius is narrower than that: no gate, no exit code, no finding and no
   human-facing report format was affected, and reaching the defect at all
   requires opting into a store with no CLI surface. Against calling it low: a
   security KPI reading 0 next to three live critical findings in the same
   payload is exactly the number a dashboard or a compliance report trusts, and
   the failure is silent and permanent once a stale decision exists. The call is
   the maintainer's; the fix does not depend on it.
2. **Whether the triage store gets a CLI surface.** Options and the argument for
   each are written down at the end of `docs/triage-decisions.md`, next to the
   format they concern, rather than here.
## The scanner now scans this repository (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/issue-173-self-scan-gate. No version bump.
Issue: https://github.com/homeofe/supply-chain-guard/issues/173

CI built the scanner, started it, and confirmed it emitted parseable JSON against
a four-line fixture `package.json`. It never pointed the scanner at this
repository, so every rule this tool enforces on its consumers was unenforced on
its own tree, and none of the three status checks branch protection requires on
`main` read a line of it. The omission dates from the first commit: no commit in
the history of `.github/workflows/` ever removed such a step, because none ever
added one.

The class matters more than the instance: a smoke test that proves the tool RUNS
reads exactly like a check that the tool PASSES. Both are green, and only one of
them looked at your code.

### What the first real self-scan found

Four critical findings, all four self-referential false positives. Nothing was
hiding behind the missing gate, which is a measured result and not an assumption.
The cost was elsewhere. `.supply-chain-guard.yml` had been maintained for a
self-scan that never ran, and it had already drifted: one of its five
suppressions matched nothing. Two product-level false positives had also shipped
undetected, one of which fires on any adopter whose changelog names a package
like the real malicious `nolimit-agent`.

All four are fixed rather than suppressed. A gate introduced on a red tree is a
gate somebody turns off. The tree now reports zero findings at every severity,
plus seven suppressions each carrying a written reason.

### The wiring constraint, which is the part that is easy to get wrong

The step must run the locally built CLI from the checkout root.
`isOwnPackageRoot` compares the resolved target against the scanner's own install
root, and only a match applies `SELF_SCAN_INERT_FILES` and loads the policy file
from this directory. Reaching the same tree through a container mount, which
looks like the cheap option because the docker job already mounts one, switches
both off and reports roughly 1700 self-referential findings. That is measured.
Anyone rewiring this should read the comment above the step first.

The step also carries a positive control, and that is the load-bearing half: a
scan of the wrong directory finds nothing and exits 0, so a green step that
inspected nothing looks exactly like a green step that inspected a clean tree.
It compares `filesScanned` against the count of TypeScript sources the checkout
tracks under `src/`. Verified by execution: repointed at the old fixture, the
scan is green at `critical` and the control fails the step anyway.

### Open for the owner

The threshold is `--fail-on critical`, and that is a choice rather than a
ceiling. With these fixes the tree is clean at every severity, so `--fail-on
info` would also pass today. `critical` was chosen because it is the severity at
which a finding is a regression rather than a backlog item, and because it
already covers the only recurring finding source here, the threat-intelligence
releases that add real indicators to `CHANGELOG.md` and `feed.json`. Tightening
to `high` or lower is a live option once the step has enough history to show what
appears at those severities. The decision and its tradeoff are recorded next to
the step in `ci.yml`, not only here.

### Not addressed

The docker job still scans only the fixture; making it scan the checkout is the
wiring that produces the 1700 findings, so it needs the self-scan trust model to
work through a mount first. Suppression visibility is also untouched: a report
exposes only a `suppressedCount` and not the entries behind it, which is exactly
why the inert suppression stayed invisible.
## PR bodies are now gated too, and the published surfaces were re-checked (2026-08-21, unreleased)

Model: claude-opus-5. Branch fix/pr-body-disclosure-gate. No version bump.

Follow-up to the section below. Two things: the earlier finding was re-verified
against the surfaces that are actually published, and the two coverage holes that
verification exposed were closed.

### The published surfaces, re-checked

The previous session recorded that the two `CHANGELOG.md` entries were "on their
way to an indexed surface" because `CHANGELOG.md` becomes the GitHub Release body
verbatim. That mechanism is real, but it did **not** apply to those two releases.
The published bodies of v5.2.40 and v5.2.41 (both 2026-06-28) contain one line
pointing at the README and nothing else - the CHANGELOG-as-release-body pipeline
came later. **Nothing needs to be retracted from either release body.**

The exposure those two entries did produce was somewhere else. Until 2026-07-02
the changelog lived in `README.md`, and `README.md` is in `package.json`'s `files`
array, so it ships inside every npm tarball. Four published versions carry the
reference in their README: **5.2.40, 5.2.41, 5.2.42 and 5.2.44**. npm tarballs are
immutable, so this is the one copy that cannot be edited - only deprecated. That
is an owner decision and nothing was done about it here.

### Two holes the re-check exposed, both now closed

- **The gate could not see a pull request title or body.** It reads tracked files;
  PR metadata is not a file. That is the surface that cannot be retracted at all,
  and it is where the largest known disclosure in this repository still sits. A
  POSIX-ERE twin of the same pattern now runs in the `PR metadata policy` required
  check - the only workflow triggered by `edited`, so the only one that can see a
  body rewrite. It sits under a **different** required check name than the file
  copy on purpose, so neither can stand in for the other.
- **The gate did not cover `.github/workflows/*.yml`.** Measured by mutation before
  the change: a cross-repository reference injected into a workflow file left
  `check:aahp` green. That glob is now in the rule's include list, and the same
  mutation now fails the build.

### Proven, in both directions

Replayed against real data rather than fixtures: the new predicate fires on all
three merged PR bodies that carry a disclosure and stays silent on the five most
recent clean ones. The pattern was also run through the same `grep -Eiq` the
runner executes, over 11 cases - five reference shapes that must fire, and six
things this project publishes on purpose that must not (the maintainer contact
address, the npm scope, the LICENSE holder line, prose describing the rule
itself). Each file-scope mutation asserts the substitution actually changed the
file first, because a mutation that fails to apply looks exactly like a gate that
passed.

One trap worth recording: the include-list anchor used for the config edit is
**not unique** - the `ai-attribution` rule ends its list on the same string and
appears first in the file. A plain replace would have widened the wrong rule and
left this one untouched, with the gate still reporting three rules and still
passing. The uniqueness assertion caught it; the edit is scoped to the slice that
starts at the rule's own id.

### Needs a decision (owner)

- The four immutable npm tarballs above (5.2.40, 5.2.41, 5.2.42, 5.2.44).
- The three merged PR bodies that name consumer repositories. Still not edited -
  editing a merged body is the owner's call. The new gate prevents the next one;
  it cannot retract these.
## SLA compliance had two definitions and shipped the wrong one (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/issue-172-sla-single-definition. No version bump.
Fixes https://github.com/homeofe/supply-chain-guard/issues/172.

### What was wrong

`slaComplianceRate` in `src/metrics.ts` computed `resolved / not-new`, a
resolution rate, under an SLA name. The real deadline logic lived in
`src/sla-engine.ts`. The two had never been executed against the same input in
the same process, in code or in a test, so they disagreed in both directions for
every release from v4.8.0 (2026-04-04) to v5.28.1:

| Decisions | Old rate | `checkSlaCompliance` |
|-----------|----------|----------------------|
| two accepted-risk | 0 | 0 breaches |
| all in-remediation, inside deadline | 0 | 0 breaches |
| one `new`, 30 days past a 24h SLA | 100 | 1 breach |
| none at all | 100 | 0 breaches |

The third row was not in the issue and is the dangerous direction: the metric
excluded `new` from its denominator while the engine evaluated it, so a report
could show 100 percent compliance next to real breaches.

### What changed

One definition, `slaVerdict` in `src/sla-engine.ts`, returning
`compliant | at-risk | breached | unmeasurable`. `checkSlaCompliance` builds its
findings from it and `src/metrics.ts` counts its verdicts. `slaComplianceRate`
became `number | null`, floored rather than rounded, so the published invariant
is exact: when the rate is non-null, it is 100 if and only if the engine reports
zero breaches over the same decisions. `mttrCritical` was removed from
`SecurityMetrics`; it was assigned `undefined` unconditionally and was always
absent from JSON output.

The "when non-null" qualifier is a correction. An earlier revision of this entry,
the CHANGELOG entry, the `SecurityMetrics` doc comment and the pull request body
all stated the biconditional unrestricted, and unrestricted it is false in one
direction. Executed on this branch, 2026-08-22: an empty decision set gives
`checkSlaCompliance` 0 breaches and `slaComplianceRate` `null`, not 100; two
decisions whose `decidedAt` cannot be parsed give the same pair; and the control,
one `resolved` decision, gives 0 breaches and 100. So zero breaches does not
imply 100. The other direction needs no qualifier: 100 does imply zero breaches.
The code and the tests were already right about this. The cross-check in
`src/__tests__/sla-engine.test.ts` asserts the weaker, correct form,
`if (breaches === 0) expect(rate === null || rate === 100).toBe(true)`; only the
prose overreached, and only the prose changed.

Both are breaking for TypeScript consumers of the library API and nothing else:
no gate, exit code, workflow, Action input or output, non-JSON report format or
MCP field reads either one. The CHANGELOG entry says so plainly.

### Assumptions now written next to the code, not left implicit

- `resolved`, `false-positive` and `accepted-risk` are compliant by status with
  no date read. An accepted risk is a recorded decision not to remediate, so it
  has no deadline to miss. The alternative, that acceptance should expire and be
  re-approved, needs an expiry field on `TriageDecision` that does not exist and
  is an owner decision.
- An unparseable `decidedAt` is `unmeasurable`, excluded from both sides of the
  rate rather than counted as compliant, so a corrupt triage store reports "not
  measured" instead of "perfect".
- A `decidedAt` in the future is compliant. Clock skew between machines writing a
  committed triage file is ordinary and any future-dating cut-off would be an
  invented number.
- `at-risk` is inside the SLA. The 0.8 warning fraction is named
  `AT_RISK_FRACTION` and documented as the pre-existing value it is.
- `Math.floor` rather than `Math.round`, because rounding lets one breach in 200
  decisions report as 100.

### Two gaps found and deliberately not closed here

1. **`checkSlaCompliance` has no caller**, so `SLA_BREACH_CRITICAL` and
   `SLA_AT_RISK` cannot reach a scan report at all. Filed as
   https://github.com/homeofe/supply-chain-guard/issues/194 (T-021). It is the
   structural reason the contradiction above stayed invisible from the CLI: only
   one of the two definitions ever ran. Wiring it in changes risk score and exit
   code for adopters of triage, which is a decision, not a patch.
2. **`TriageDecision.dueDate` is never consulted** by either the engine or the
   metric; the deadline is derived from the rule id. The field is declared and
   accepted from the triage store, so it looks like it works. This is now stated
   in a comment at the line that would have to change. Honouring it would move
   the deadline for every project that already sets it, so it is an owner call.

### Owner decision recorded, not deferred

The issue's acceptance criteria required that the empty decision set stop
returning 100. The two ways to do that are a nullable type (chosen) or a rename
to `resolutionRate` keeping the old arithmetic (rejected: it preserves a number
nothing consumed, under a second name, and leaves the SLA field missing). The
nullable type is breaking for TypeScript consumers, so the release carrying it
should be at least a minor bump with the CHANGELOG note that is already written.
## Every checkout now states whether it keeps the token (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/checkout-credential-contract. No version bump.

Addresses the first of the three items in
https://github.com/homeofe/supply-chain-guard/issues/179. The other two are settled
below rather than changed, and the reasons are the point.

### What was true

`actions/checkout` writes the job's `GITHUB_TOKEN` into `.git/config` as an
`http.<origin>/.extraheader` basic-auth header unless the step sets
`persist-credentials: false`. At the pinned v7.0.1 that input defaults to `true`.
Measured at `1a141fe8322345dbd8ec3c449a402eedc3c6d83f`: 8 checkout steps across 4
workflows, and `git grep -i 'persist-credentials'` over the whole repository exited
1 with zero matches. Every one of them took the default.

### Why it was not exploitable, which is the actual finding

Five independent controls each closed a leg, and none of them is about checkout:
every real `npm` invocation passes `--ignore-scripts`; there is no
`pull_request_target`, `workflow_run` or `issue_comment` trigger anywhere, so a fork
pull request can never hold a write token; `.dockerignore` excludes `.git` and the
`Dockerfile` uses named `COPY`s, so the token cannot reach a published layer even
though the build context is `.`; the three `upload-artifact` paths are narrow; and
every `uses:` reference is pinned to a commit SHA.

So this is defence in depth, and it is worth taking for exactly that reason: the
token's absence was a property of five other decisions, any one of which could move
without anyone connecting the move to a credential sitting in a workspace.

### What changed

All 8 steps now state their choice. Seven set `false`. One sets `true`:
`ci.yml`'s `update-major-branch` job, whose only purpose is
`git push origin "HEAD:refs/heads/${MAJOR}"`, the only push in this repository. git
reads that credential from `.git/config`, so `false` there would not harden anything;
it would freeze the floating `v5` branch that every Action consumer resolves. The
reason is written on the step itself, not only in the test.

`src/__tests__/workflow-checkout-credentials.test.ts` is the mechanism, 6 assertions.
It treats an omitted key as a failure rather than as a default, because from outside
a missing key and a considered `true` are indistinguishable and only one of them is a
decision. An exception is valid only if the job it names actually runs a remote git
command, so the allowlist cannot become a place to park inconvenient steps. The
converse is asserted too: a job that DOES run one must be an exception, so this
contract cannot break a release push by "hardening" it. And the number of steps the
block walker classified must equal the number of `actions/checkout` lines in the same
files, so a walker that silently stopped resolving steps fails instead of passing
vacuously.

### The two items that were not changed, and why

**`delete_branch_on_merge` is `false` and no pull request can change it.** It is a
repository setting on GitHub, not a file. Recorded as T-020 in `NEXT_ACTIONS.md` with
both options written out, and in `docs/ci-and-release.md` under "Settings that live
on GitHub, not in this repository", because this project keeps zero open issues and
the issue tracker is therefore the one place it would not survive. Measured cost
today: across 114 merged pull requests, 112 branches were removed anyway and 2
survived.

**The AAHP CLI pin was left at 3.9.2 here on purpose, because bumping it is already
in flight in https://github.com/homeofe/supply-chain-guard/pull/186 and the bump
does not work alone.** Verified by
execution rather than by reading the release notes: with 3.10.0 installed in a
checkout of this repository, `aahp verify . --level ci` with no base reports
`FAIL: Level ci requires an explicit base commit via --base SHA or AAHP_BASE_SHA`
and one blocking issue, where 3.9.2 on the same tree printed
`OK: No source files changed outside .ai/handoff/` and passed. So bumping the pin
without also passing `AAHP_BASE_SHA` in `aahp-verify.yml` turns a REQUIRED status
check red on every run. Two changes to one workflow from two branches at once is how
one of them gets lost, so this branch touches only the `with:` block of that
workflow's checkout step and leaves the `env:` and the pin to the branch that owns
them.

Worth recording separately: the pin sitting one release behind is not a broken
mechanism. `.github/dependabot.yml` scans npm weekly on Monday and has opened bump
pull requests for this exact package before. 3.10.0 published on a Friday, the
measurement was taken on the Saturday, and the next scheduled scan was the Monday.
The bound that follows is now written down in `docs/ci-and-release.md` rather than
left to be rediscovered: up to seven days plus merge latency, against a CLI whose
median gap between its 17 published versions is 4 days.

### Verification

Found on the way past, and recorded rather than fixed: `compat (Node 22)` is FLAKY on
`multi-line-pattern-engine.test.ts > keeps exact greedy/lazy endpoints on 5 MiB
repeated completions`. It failed on unmodified `main` at `1a141fe`, failed again on a
branch changing only CI metadata, and passed on that same branch one amend later, while
`compat (Node 20)` passed every time. It is a wall-clock assertion with a 15 s timeout
around a 10 s budget, and the losing run took 16573 ms. That belongs to T-012 in
`NEXT_ACTIONS.md`, where the three runs are now tabulated.

`npx vitest run src/__tests__/workflow-checkout-credentials.test.ts` and
`src/__tests__/workflow-trigger-contract.test.ts`, both green, plus a mutation proof:
deleting the single line `persist-credentials: false` from `demo.yml` turns the
contract red and vitest exits 1. The full suite is not run on Windows; required Linux
CI is the verdict.
## The npm scanner took its feed from the reporting accessor (2026-08-22, unreleased)

Model: claude-opus-5. Branch perf/issue-177-npm-scanner-feed-reuse. No version bump.
Issue: https://github.com/homeofe/supply-chain-guard/issues/177

### What was actually wrong

Not the cache. `bareNpmIndexCache` in `src/install-guard.ts` is correct, and the
hoist that pulls the feed out of the dependency loop works. The defect was one
level up: `src/npm-scanner.ts` sourced its feed from `getBundledFeed()`, whose
documented job is reporting and export and which therefore returns a defensive
copy per call. The index is memoized on the array's IDENTITY, so a new array per
call meant the index was rebuilt from all 12,962 entries every time. Every other
scanner takes its feed from `loadThreatIntel()`, which returns the shared array
and says so. This scanner was the only one that did not, and nothing in the types
or the tests distinguished the two accessors.

The second cost was the same shape: `MALICIOUS_PACKAGE_PATTERNS` is exported as
`string[]`, so the loop compiled all 34 patterns per dependency, while
`validateRegexStringSet` had already compiled them at module load and thrown the
results away.

### Measured, before and after

Both trees built and driven through the same harness, three process runs each.

| | before | after |
|---|---|---|
| index builds, three package scans in one process | 6 | 1 |
| index builds per `scanNpmPackage()` | 2 | 0 or 1 |
| 112 dependencies, ms in the two feed-consuming functions, warm | 8.41 / 8.37 / 8.15 | 0.19 / 0.21 / 0.24 |
| 200 dependencies, same | 9.72 / 7.99 / 10.01 | 0.26 / 0.32 / 0.25 |
| first scan shape in a fresh process, 112 dependencies | 15.9 to 17.7 | 9.3 to 10.5 |
| short-lived heap over 20 such scans | 4.75 MB each | 0.16 MB each |

112 is the largest dependency count observed on the registry across express,
eslint, webpack, typescript, `@angular/cli` and react-scripts.

**No end-to-end speed-up is claimed.** The same three real registry scans took
1,063 / 4,593 / 9,187 ms before and 1,447 / 10,066 / 15,645 ms after, which is
download variance, not a regression: an npm scan is network bound and the saving
is well under one percent of it. The value is in the MCP server, where the
process is long lived and the waste repeated per request, and in removing the
divergence itself.

### What is now enforced rather than documented

`getBundledFeedRef()` returns `Object.freeze(BUNDLED_FEED)`, so a structural
mutation throws instead of silently invalidating every derived index. The freeze
is shallow by a recorded decision written next to the accessor: deep-freezing
12,962 entries costs 1.32 ms against 0.0014 ms, and those entry objects are
shared by reference into what `getBundledFeed()` and `loadThreatIntel()` return,
so freezing them would be a breaking change for embedders.

### Open decision for the owner

`scg npm <package>` reads the bundled feed only and therefore never sees IOCs
added by `feed refresh`, while `scg scan` does. Verified here: bundled 12,962
entries against 12,963 merged with a synthetic refreshed entry, a MISS on the
npm path and a HIT on the scan path, with a control name from the bundled feed
hitting on both. That is a coverage question, not a performance one, and it was
deliberately left unchanged. Tracked as T-020, with both options written next to
the code that would change.

Also for the owner: the issue carries `bug` and `priority: medium`. Nothing here
produced a wrong verdict, so `enhancement` and `priority: low` fit the measured
impact better. The labels were left alone.

### Environment note

`src/__tests__/campaigns.test.ts` fails two tests on this Windows machine,
"Phantom Bot C2 domain" and "the GlassWASM delivery host". Identical failures,
same two names and the same 2 failed / 337 passed count, on the unmodified tree
at the same commit. Pre-existing and unrelated; Linux CI gives the real verdict.
## The scanned tree's own policy file is input, not configuration (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/internal-disclosure-config-containment. No
version bump. Remediates
https://github.com/homeofe/supply-chain-guard/issues/169; the pull request is
https://github.com/homeofe/supply-chain-guard/pull/183 and the issue is left open
for the owner to close.

### What was actually wrong

Not a missing check. The containment predicate this needed was already written in
this repository, twice, and the deny-list loader used neither. The reasoning that
allowed that is visible in the old comment beside the code: it asked whether the
configured path STRING was safe to print, correctly concluded that a committed
path is already public, and never asked the separate question of whether the
CONTENTS at that path are inside the trust boundary.

The same gap explains the regular-expression half. `MAX_MATCH_ATTEMPTS_PER_RULE`
and the `performanceBudget` test helper bound the patterns this project wrote.
Neither reached the patterns a scanned repository writes.

`hashedTerms` and `suppress` were designed with the scanned tree's trust level in
mind. `externalFile` and `patterns` were not, and `.supply-chain-guard.yml`
travels inside a tree whose owner is routinely not the operator.

### What changed

`externalFile` from the committed config must resolve inside the scanned
directory: absolute paths, `..` traversal and symlink escapes are refused BEFORE
the file is opened, so the existence, permission and per-line reporting that
follow a read cannot describe anything outside the tree. A committed regular
expression is capped at 200 characters and refused when it quantifies a group
that already contains a variable quantifier. What survives runs under a scan-wide
wall-clock budget. Refusals are reported as `INTERNAL_DENYLIST_REFUSED` (medium),
registered both in `PARTIAL_SCAN_RULES` and in the `coverage_rule` list in
`action.yml`, so the Action fails closed on them.

Containment reuses `isContainedPath` and `hasContainedExistingAncestor` from
`src/pattern-scanner.ts`, now exported instead of copied. The shape classifier
`hasNestedUnboundedQuantifier` was added beside the existing
`hasBroadUnboundedConsumingGap` in `src/regex-complexity.ts` and reuses its
parsing primitives.

### Numbers worth keeping

- The pathological committed pattern `/(a+)+$/` against a non-matching line built
  from a run of 34 characters did NOT complete within a 60,000 ms budget before
  the change.
  After it, the same scan completes in under 300 ms and reports the refusal. At
  the worst input the deny-list pass still inspects, a line of 1,998 characters,
  it also completes in under 350 ms.
- A legitimate deny-list of six ordinary entries over this project's own `src/`
  tree (196 files, 96,133 lines, 5.23 MB) consumes 108 ms of the matcher budget.
  That measurement is why the budget is 30 seconds and not two: overrunning is
  reported and makes the scan partial, so a budget set too low fails loudly on a
  clean repository.
- 85 existing tests in `src/__tests__/internal-disclosure.test.ts` surrounded this
  defect without covering it. Every one of them wrote its external file inside the
  scan root with a bare relative name.

### What this does NOT close, stated where the next reader meets it

An independent review before merge measured three limits that the first draft of
this entry, the CHANGELOG and two code comments all described as tighter than
they are. All three are now stated in `README.md`, in `CHANGELOG.md`, in the doc
comments on `hasNestedUnboundedQuantifier` and `SCANNED_TREE_MATCHER_BUDGET_MS`,
and pinned by tests, and all three stay open on
https://github.com/homeofe/supply-chain-guard/issues/169.

- **The shape check is not exhaustive, so the third acceptance criterion is
  partially met, not met.** `hasNestedUnboundedQuantifier` reads the source text,
  which cannot see ambiguity arising from overlapping alternation. `/(a|a)+$/`,
  `/(a|ab)+$/` and `/(a+){2,30}$/` are all accepted, all clear the
  200-character cap, and all remain catastrophic. Measured here: `/(a|a)+$/`
  against a non-matching line of 27 characters spends about 16 seconds inside a
  single `exec`, and the budget is checked between matcher invocations, so it
  cannot interrupt one. Closing this needs a matcher that can be stopped
  mid-match, which is a different change.
- **The check also over-refuses, and it over-refuses the common case.** The
  chained-label hostname shape `/(?:[a-z0-9-]+\.)+corp\.example/` is refused
  even though it is linear in practice, in `patterns` and in a gitignored
  in-tree `externalFile` alike. Because the refusal is a coverage rule, a
  consumer who has that pattern today meets this as a red build and a term that
  silently stops being matched. `/[a-z0-9.-]+\.corp\.example/` is the accepted
  rewrite, and both documents now say so before the upgrade rather than after.
- **Containment is to the scanned directory and nothing narrower.** A committed
  `externalFile: .git/config` stays inside the tree and is still read: verified
  here, the load reports `INTERNAL_DENYLIST_INVALID_ENTRY` naming `.git/config
  line 3` and the scan reports a redacted match naming `.git/config line 2`. So
  the per-line compile-failure oracle and the whole-line guess-confirmation
  oracle survive against whatever the runner wrote into the workspace, retargeted
  from outside the tree to inside it. Redaction still holds.

One policy consequence was taken without being flagged as one, and is the
owner's to confirm: the issue asked for `INTERNAL_DENYLIST_REFUSED` to be a
coverage rule so an attacker-supplied refusal fails the gate closed. The same
rule now fails an operator's own build closed when their own pattern is refused.
Whether that should stay build-breaking or become advisory is recorded on the
issue.

### Open, and deliberately not done here

- The operator-supplied `SCG_INTERNAL_DISCLOSURE_FILE` source is untouched,
  including its line-number reporting for a file outside the tree. That source is
  chosen by whoever runs the scan, and per-line reporting is what makes a silently
  broken deny-list visible. Recorded as a decision in the code, open for the owner
  to revisit.
- No size cap on the read that containment still allows. With containment the file
  is inside the tree the runner already downloaded, so a cap bounds a memory copy
  rather than a new capability. Separate change.
- The published composite Action still declares no `timeout-minutes`. It is a
  property of the Action rather than of this defect and changes behaviour for
  every consumer, so it belongs in its own pull request.
## The em-dash rule was enforced on a set of files that held none of them (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/em-dash-rule-scope. No version bump.

An audit reported 77 em dashes across 17 files "with no check enforcing the
rule". Half of that was wrong in a way worth keeping: a check did exist, it ran
on every pull request, and it sat inside a required status check. It was green,
truthfully, because the `em-dash` rule's `include` list named six pathspecs and
those six matched none of the 17 files. The gate answered the question it was
asked. Nobody had noticed the question had drifted away from the rule.

### What was actually wrong

Three things, in the order they matter.

1. **Opt-in scope fails open.** Every file created after the rule was written
   was outside it by default, silently. The `include` list is now the single
   pathspec `*`, so a file is covered the moment git tracks it and the only way
   out is a reviewed entry.
2. **A config line read like a mechanism and was not one.** `exclude` held
   `CHANGELOG.md`, which every reader took for the reason the changelog went
   unchecked. It was inert: a non-empty `include` REPLACES the gate's default
   file set, so `CHANGELOG.md` was never in scope for `exclude` to remove.
   Deleting that line alone changed nothing, which was verified before it was
   removed.
3. **The only written statement of the rule was the gate's own `message`
   field**, and it said "banned in docs". Under that wording the 49 source
   occurrences were not violations at all. `CONTRIBUTING.md` now carries the
   scope, and the two narrower scopes that were rejected, with the reason for
   each.

### The scope decision, and why the other two were rejected

Documentation only was rejected because the one occurrence with measurable reach
outside this project was not in documentation: it is in `src/slsa-verifier.ts`,
in the sentence a scan prints for a project with no build script, and it lands
in the SARIF report adopters upload to GitHub code scanning. Documentation plus
emitted strings was rejected because no gate can express it, so the rule would
have gone back to being a review convention, which is the state that let the 77
accumulate. Every tracked file was chosen because it is the only one of the
three a gate can decide.

### The second gate, and what it deliberately is not

`scripts/check-em-dash-scope.mjs` runs inside `check:aahp`, before the AAHP
gates. It never reads file content and never searches for U+2014. There is still
exactly one em-dash rule and it lives in `aahp.config.json`. The script answers
the question that rule cannot ask about itself: does its scope still cover the
repository? It exits 1 when a tracked file is uncovered and unexplained, and 2
when it cannot determine the answer at all, which includes a pathspec that
matches nothing and an `exclude` entry that subtracts nothing.

Two files are exempt, each with its reason in `SCOPE_EXCEPTIONS`: the binary
demo GIF, because a chance byte sequence in compressed image data is not prose,
and the handoff archive, because its own header declares its entries preserved
verbatim. Both hold zero occurrences today, so both preserve rather than
suppress.

### Assumption recorded, so it is not re-derived

The handoff-archive exemption rests on an inference, not on a written policy:
the file states it is append-only with older entries "preserved below verbatim",
and that is read as a reason not to rewrite them. The inference is written next
to the exemption. Anyone who disagrees deletes the `SCOPE_EXCEPTIONS` entry and
the matching `exclude` line together, and the file is simply covered.

### Open for the owner

Nothing blocks this change. One item is deliberately left out of it: the AAHP
CLI gate reads each file inside `try { readFileSync } catch { continue }`, so a
file it cannot read is skipped in silence rather than failing. That is the same
fail-open class, it ships to every consumer of the governance CLI, and it is not
this repository's file to fix. It belongs upstream as its own piece of work.
## A policy-narrowed scan can no longer pass for a clean one (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/issue-168-policy-visibility. No version bump.
Issue: https://github.com/homeofe/supply-chain-guard/issues/168

### What was actually wrong

The issue's title is about the trust boundary: policy is read from the tree being
scanned, so a proposed change can disable the rule that would flag it. That much
is deliberate and unchanged here, because moving it is an owner decision.

The defect that was fixed is the second one underneath it, and it is the reason
the first one is dangerous rather than merely awkward: the narrowing was
**silent**. Measured on a directory containing `eval(atob(...))`:

- `rules.disable: [EVAL_ATOB]` took the scan from exit 2 with one critical to
  exit 0 with none. `suppressedCount` reached 1, but nothing named the rule, and
  the markdown report, which is the Action's default format and the body of the
  pull request comment it posts by default, contained the word "suppress" zero
  times.
- `ignore: ["app.js"]` was quieter still. `ignore` prunes files before any rule
  opens them, so `suppressedCount` stayed 0 and **all nine** output formats were
  silent. Nothing distinguished that report from a genuinely clean one.

The second variant is the severe one, and the issue mentions it only in passing.
A fix that covered `rules.disable` alone would have passed its own tests while
leaving the quieter path exactly as it was.

### What changed

- `ScanReport.policyEffect` carries the loaded config's effect as structured
  metadata: config file, disabled rules, ignored globs, suppressed rules, each
  with its written reason when one exists. Built by `describePolicyEffect()` in
  `src/policy-engine.ts`, attached in `src/scanner.ts` next to the policy load.
  It is `undefined` when the config narrows nothing, so its presence always means
  something was switched off.
- All nine formats render it: text, JSON, markdown, SARIF, SBOM, HTML, badge,
  GitLab and JUnit. Markdown places it **above** the summary, because that is the
  rendering a reviewer reads before deciding a green check means the change is
  clean. SARIF carries it as a run-level notification plus
  `invocations[0].properties`. The badge appends `(policy-narrowed)`, since
  "clean" on a scan whose config removed a rule is the most misleading string
  this tool can publish.
- The v5.2.40 rule is intact and is asserted by a test: policy METADATA is
  surfaced, suppressed FINDINGS still never enter SARIF, SBOM or GitLab.
- `POLICY_DISABLE_NO_REASON` and `POLICY_IGNORE_NO_REASON` (medium) bring
  `rules.disable` and `ignore` up to the audit bar `suppress` has met since v5.3.
  Both sections now accept a reason-carrying mapping form alongside the list
  form. Nothing is vetoed: the bare form still disables and still excludes, it is
  simply reported as undocumented.
- `README.md` and `action.yml` state where policy is read from and what that
  means on a `pull_request` event. That was documented nowhere. The README also
  corrects a `rules.disable` example written as a one-line flow sequence, a form
  the parser reports as `POLICY_UNKNOWN_KEY` and which disables nothing.

### Evidence

`src/__tests__/issue-168-policy-visibility.test.ts`, 14 tests. The reproduction
was re-run against a pristine build of the cited commit and against the fixed
build, same fixtures, same commands: before, `ignore:` produced zero mentions in
all nine formats; after, all nine name `app.js`, and the `rules.disable` fixture
names `EVAL_ATOB` in all nine.

Mutation proof: deleting only the `ignoredGlobs` half of `describePolicyEffect`
leaves the `rules.disable` test green and reddens the `ignore` test, which is the
mutation that would have caught a decorative fix.

### Still open, and deliberately so

The gate still exits 0 on both fixtures. Making the bypass **loud** is what this
change does; making it **impossible** means giving the scanner a trusted policy
source outside the scanned tree, which changes the tool's trust boundary and is
recorded in the issue as needing the owner. `ScanOptions.policyFile` exists in
the type and is read by nothing, which is where that work would start.
## A corrupt state file was a clean baseline, in both stores (2026-08-22, unreleased)

A corrupt state store no longer reads as a clean baseline in either of the two stores.
Branch `fix/issue-175-risk-history-unreadable`, no version bump.
Fixes https://github.com/homeofe/supply-chain-guard/issues/175.

Both readers under `.scg-history/` ended in `catch { return []; }`, the same
value the absent case returns, so "no history yet" and "the store could not be
read" were one outcome. Reproduced end to end, then re-run against the branch.

### What was measured

Fixture: a project whose recorded risk climbs over ten scans. Removing the last
120 bytes of `risk-history.json` took the scan from exit 1, level `high`, three
trend findings, to exit 0, level `low`, none. The suppressed findings are all
`high` and the default gate with no `--fail-on` is `summary.high > 0`, so the
gate stopped detecting a regression it detected the day before, in silence.

The triage store was measured too rather than assumed to be the weaker twin, and
it is not weaker. A truncated `triage-decisions.json` took the same scan from
exit 1 with two `high` governance findings to exit 0 with none, and reported
`metrics.slaComplianceRate` 100 where the intact store gave 0. That number is
the sharper harm: the corrupt file did not only hide a verdict, it manufactured
a compliant one. That measurement is why both stores are fixed in one change.

Two on-disk states, `null` and `{}`, never reached either `catch`, because both
readers ended in an `as` cast. They threw an unhandled `TypeError` and produced
no report at all. Four cases across the two stores, all closed by validating the
declared entry shape.

Evidence destruction was real and is closed: the truncated file still held nine
recoverable entries and the next plain scan replaced it with one.

### Decisions a later reader should not have to re-derive

All of these are written next to the code they constrain, not only here.

- Severity `high` on both new findings is derived, not chosen: the findings each
  one replaces are `high` and the default gate is `summary.high > 0`, so
  `medium` would reproduce the defect one layer down. Recorded at
  `riskHistoryUnreadableFinding` in `src/continuous-monitor.ts`.
- `saveRiskHistory` throws rather than overwriting an unreadable store;
  `saveTriageDecisions` deliberately does not. The first does a read, append and
  write, so refusing preserves recoverable entries; the second replaces the file
  wholesale from its caller's list, so refusing would remove the only supported
  repair path while preventing no measured loss. Recorded at both call sites.
- `loadRiskHistory` and `loadTriageDecisions` are deprecated in place rather
  than re-typed, because both are published API in `src/index.ts`.
- The three-way reader lives in `src/state-dir.ts`, next to the directory both
  stores write into, so a third store does not rediscover the rule.

### Open, and it is an owner decision

`SecurityMetrics.riskTrend` and `SecurityMetrics.slaComplianceRate` still read
`stable` and 100 when a store is unreadable, because neither type has a member
meaning "unknown". The report is marked `partialScan` and the finding text says
in words that the metrics came from an empty store, which is what keeps this
from being a silent wrong answer. Widening either type is a breaking change for
library and JSON consumers, so it belongs in a major rather than a defect fix.
The choice and its cost are recorded on `calculateMetrics` in `src/metrics.ts`.

Separately, `saveRiskHistory` still writes with a plain `writeFileSync` onto the
live path, with no temp file and rename anywhere in `src/`, so an interrupted
scan can still manufacture the corruption this change now reports. Reporting it
is in scope here; making it unmanufacturable is a separate change.
## The engines floor had no ceiling, so the matrix never ran the Active LTS (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/176-compat-matrix-reaches-active-lts. No version bump.
Reported as https://github.com/homeofe/supply-chain-guard/issues/176

### What the report said, and what was actually wrong

The report compared `.github/workflows/ci.yml` against `package.json` and found a
Node 20 leg below an `engines.node` floor of `>=22.0.0`. Every count in it
re-derives exactly. Its conclusion does not follow: `docs/node-support.md` declares
`supportedMajors` and `transitionMajors` as disjoint lists, the gate already asserted
a transition major is strictly below the floor, and `README.md` tells consumers the
package requires Node 22 or newer. The Node 20 leg is a dated, gate-enforced
transition lane, deleted in 5.29.0 by an assertion that fails the build. It stays.

The report's own measurement contained the real defect, one line below its headline:
**legs above the floor, 0 of 2.** `engines.node` is a floor with no ceiling, so
`>=22.0.0` claims Node 22 and every major after it, and the matrix stopped at 22. Read
against the upstream `nodejs/Release` schedule on 2026-08-22, Node 22 had been in
Maintenance LTS since 2025-10-21 and Node 24 had been Active LTS since 2025-10-28. The
only major the project supported was the one already in maintenance, and the major
consumers are migrating onto was claimed and never executed. `@types/node` is on the
Node 26 API surface, so an API available only above Node 22 would have type-checked
clean, passed both legs, and failed in a consumer's hands.

### What changed

`docs/node-support.md` gains `activeLtsMajor` (24) and `activeLtsReviewedIn` (5.29.0),
`supportedMajors` becomes `[22, 24]`, and the `compat` matrix becomes 20, 22 and 24.
`src/__tests__/node-version-contract.test.ts` gains ten cases: five that assert the
claim reaches the top of its own range and carries a re-read deadline, and five that
assert the workflow comment keeps naming the policy vocabulary. That comment called the
matrix "every Node major this package supports" four lines above a pointer to the policy
whose subject is that supported and tested are different lists, which is the most
plausible reason this report exists at all.

Restoring the exact pre-change configuration turns exactly the two new upward cases red
and leaves the other 36 green, which is the demonstration that nothing in the repository
could see this before.

### Decisions recorded in the repository, not here

Both live in `docs/node-support.md` so the next reader meets them at the code:

- **Why the bound is the Active LTS**, with the two rejected alternatives and their
  costs. `engines.node` deliberately keeps no upper bound, so majors above the Active
  LTS (Node 26 today) are claimed and not executed. That residual is stated, and the
  alternative that would close it is written out with exactly what to change.
- **Why `activeLtsMajor` is hand-copied rather than fetched**, what the gate can and
  cannot catch about a hand-copied fact, and why the deadline is `5.29.0`.

### What adding the third leg exposed, and why it had to be fixed here

The Node 24 leg went red on its first run, and the cause was not Node 24. The perf case
`keeps exact greedy/lazy endpoints on 5 MiB repeated completions` in
`src/__tests__/multi-line-pattern-engine.test.ts` timed out at 15,070ms against a bare
`timeout: 15_000`. Measured across the three legs of that single run: Node 20 8,734ms,
Node 22 13,622ms, Node 24 15,070ms. The same case had already failed the **Node 22** leg
on `main` at `1a141fe`, at 15,137ms, with no Node 24 anywhere. The budget sits inside the
runner's own noise band, so it reports noise, not an algorithmic regression.

Underneath that is a real inconsistency. `npm run test:coverage`, the only command the
compat legs run, sets `SCG_VITEST_COVERAGE=1` in `vitest.config.ts`, which makes
`performanceBudget` multiply by five. So the assertion inside that test allowed 50,000ms
while the harness killed it at 15,000ms: **the guard could never be reached under the
command CI actually runs.** Both `it` options in that file now use
`performanceBudget(15_000)`, which is what every sibling perf test already did. Outside a
coverage run `performanceBudget` is the identity, so `npm test` is bit for bit unchanged,
and the algorithmic guard, `performanceBudget(10_000)`, is untouched.

### Open for the owner

The same bare-literal pattern is still elsewhere, deliberately left because it is outside
this change and touching a dozen test files in a Node matrix pull request would be worse
than naming it. Counted, not estimated:

- **2 files import `performanceBudget` and still use a bare `timeout:` literal**, which is
  exactly the inconsistency fixed above: `src/__tests__/core-broad-gap-matchers.test.ts`
  and `src/__tests__/internal-disclosure.test.ts`.
- **10 further files use a bare `timeout:` literal** without importing it. Some of those
  have no scaled assertion to disagree with, so they need reading rather than rewriting.

A gate could assert that no file importing `performanceBudget` also carries a bare
`timeout:` literal. It is not added here, because it would be red on the two files above
on the day it landed, and a gate that ships red teaches people to ignore it.
## Docker base image pinning: one parser, three verdicts (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/issue-174-docker-base-image-pinning. Issue
https://github.com/homeofe/supply-chain-guard/issues/174. No version bump.

`DOCKER_UNPINNED_BASE` was one regex and it was narrower than its own five tag
words. Measured on the released rule over 19 representative `FROM` lines: 5
flagged, and those 5 were exactly the five bare literal words. Three shapes
inside the rule's own stated scope scanned clean:

- `FROM --platform=$BUILDPLATFORM node:latest`, because `\S+` bound to the flag
  token. End to end through the CLI: risk score 2, zero high findings,
  `--fail-on high` exit 0, on a line carrying a literal `:latest`.
- `node:lts-alpine`, `nginx:stable-alpine`, `nginx:mainline-alpine`,
  `node:current-slim`, because the alternation ended at `(?:\s|$)`. The suffixed
  forms are the upstream rolling tags and the ones people write.
- `FROM scratch-base:latest` and `FROM scratchpad:latest`, because `(?!scratch)`
  had no token boundary.

Widening the regex was not available: two of the three misses are structural,
and `validatePatternSet` rejects the obvious widened forms at module load as a
broad unbounded consuming gap. All three `FROM` rules now share one
`correlatedMatcher`. It strips instruction flags, joins backslash continuations,
drops comment lines, tracks `AS <stage>` names in file order, and exempts
`scratch` only as a whole token. Because the three rules read the same parse,
they can no longer disagree about what a build-stage reference is.

### The two decisions, both recorded in the repository

Both are written into `docs/ARCHITECTURE.md`, "Base Image Pinning (decision
record)", and summarised next to the code in `src/dockerfile-scanner.ts`. Neither
lives only in a pull request.

1. **Tiering.** The issue asked for one rule at `high` for every `FROM` line
   without a digest. Not taken. `high` is what the default gate fails on
   (`getReportExitCode` returns 1 when `summary.high > 0`), so one high tier
   flips every ordinary version-tagged Dockerfile in every consumer from pass to
   fail in one release, for a risk that has not changed. Instead
   `DOCKER_UNPINNED_BASE` stays `high` for a moving channel tag and the new
   `DOCKER_TAG_NOT_DIGEST` reports a tag without a digest at `low`, mirroring
   `GHA_UNPINNED_ACTION` / `GHA_TAG_NOT_SHA`. Default gate, `--fail-on high` and
   `--fail-on medium` unchanged; `--fail-on low`, `--fail-on info` and the risk
   score do change.
2. **Compose.** `image:` values stay out of scope, said out loud in each rule's
   `description`, in README.md and in `docs/ARCHITECTURE.md`. Nine of nine
   Docker rules are anchored on a Dockerfile instruction keyword, so a Compose
   file returns nothing from the Docker rule set while the README used to list
   it as a scanned Docker target. The blocker for implementing it is recorded:
   a service that also declares `build:` uses `image:` to name what it BUILDS,
   and telling the two apart needs service-block structure, which this project
   has no YAML parser for.

### Deliberate behaviour changes a consumer will see

- Newly reported at `high`: `--platform` lines carrying a channel tag, suffixed
  channel tags, `scratch`-prefixed names, and `FROM ubuntu AS base` (no tag).
- Newly reported at `low`: every `FROM` line with a tag and no digest.
- No longer reported: a build-stage reference (`FROM builder`), a commented-out
  `FROM`, and `FROM` appearing inside another instruction.
- A `FROM` line carrying an embedded carriage return still classifies. Writing
  the instruction regex the obvious way, anchored with `$`, would have made
  `FROM node:latest\rEXTRA` scan clean, because JavaScript's `.` stops at a line
  terminator. The released regex did report it, so this would have been a
  regression introduced by the fix rather than a gap left in place. Caught while
  reading the finished parser, not by the test suite, which is the argument for
  reading a structural rewrite line by line before shipping it.
- The report-level "pin base images by digest" recommendation in `src/scanner.ts`
  now also fires for `DOCKER_TAG_NOT_DIGEST`, so a report whose only base-image
  finding is the new tier is not left without a recommendation.
- This repository's own `Dockerfile` stays clean: both `FROM` lines are digest
  pinned, and a self-scan reports zero `DOCKER_*` findings.

### Open for the owner

Nothing blocks the merge. One judgement is worth a second opinion: whether
`DOCKER_TAG_NOT_DIGEST` should ship at `low` or at `medium`. `low` was chosen
because it matches the in-repo Actions precedent and leaves every existing gate
where it was. `medium` would make it visible to `--fail-on medium` consumers and
is a one-word change in `src/dockerfile-scanner.ts`; the trade-off is written out
in `docs/ARCHITECTURE.md`.
## Feed acquisition is bounded, on both paths (2026-08-22, unreleased)

Branch fix/issue-170-feed-timeout-and-size-cap. No version bump.
Closes https://github.com/homeofe/supply-chain-guard/issues/170 once reviewed.

### What was wrong, and where the issue was incomplete

The issue named one function, `updateThreatFeed`, which is exported library API
that no CLI command calls. The command the README documents,
`supply-chain-guard feed refresh`, went through a SECOND downloader in
`src/feed.ts` with the same two defects and no backstop of any kind. Fixing only
the function the acceptance criteria name would have closed the issue green with
the shipped command unchanged.

Measured on the base commit against a loopback peer that sends headers and then
stalls: `feed refresh` ran 150 seconds with empty stdout, empty stderr and no
exit, and was killed at the cap. The identical command against a healthy peer
finished in 0.28 seconds. A 64 MiB chunked body was accepted in full.

### Root cause

Not a forgotten timeout. `src/remote-download.ts` already existed and already
implemented every bound this issue asks for, and `src/npm-scanner.ts`,
`src/pypi-scanner.ts` and `src/vscode-scanner.ts` already used it. Registry
acquisition was hardened behind that shared module; feed acquisition was the one
caller that never adopted it, and nothing in the build requires a new outbound
request to go through it.

A contributing cause sits in the tests. `src/__tests__/feed.test.ts` mocks
`node:https` wholesale and delivers the whole body in one tick, so none of its
six `refreshFeed` tests could observe a stall. The suite passed around the
defect rather than over it.

### What changed

- `FEED_REMOTE_LIMITS` in `src/threat-intel.ts`, beside the cache constants:
  32 MiB, 30 s, 5 redirects. The byte figure is roughly ten times the published
  feed; the other two are the values the registry scanners already use.
- `refreshFeed` delegates to `fetchHttpsBuffer`. The hand-rolled request is gone,
  and with it a second defect in the same function: it decoded each chunk
  separately, so a multi-byte UTF-8 sequence split across a chunk boundary became
  replacement characters.
- `updateThreatFeed` keeps the global `fetch` and its quarantine-and-continue
  validation, and gains an `AbortSignal` deadline, a `Content-Length` refusal
  before the body is touched, and a running byte count while streaming.
- Both take an optional per-call limit override; both default to the constant.
- New suite `src/__tests__/issue-170-feed-bounds.test.ts` drives a real loopback
  server rather than a mock, because a mock that answers in one tick cannot
  represent a peer that stalls.

### The one decision left for the owner

`updateThreatFeed` was hardened in place rather than turned into a wrapper over
`refreshFeed`. The wrapper would remove the second implementation, which is the
better end state, but it is a behavioural change to exported, documented API:
`parseFeedPayload` hard-rejects a bad entry where `updateThreatFeed` quarantines
it and continues, and the error strings differ. That belongs in its own change
with its own changelog entry, not smuggled in behind a timeout fix.

Also for the owner: the acceptance criteria on the issue are satisfied by the
`updateThreatFeed` half alone and need rewriting to name `src/feed.ts` as well,
or the next reader will conclude the CLI path was out of scope.
## Threat-intel sweep 2026-08-22: a 4,363-entry backfill answered with one rule (unreleased)

Model: claude-opus-5. Branch threat-intel/2026-08-22. No version bump.

The scheduled import proposed 4,409 new IOCs and refused to exit clean: at the
default `--limit 250`, 2,659 of the remainder would age out of the `--days 14`
window before any later run could reach them.

### What the backlog actually was

4,363 of the 4,409 were a single publisher's namespace, `@zalastax/nolb-*`,
backfilled into the GitHub Advisory Database on 2026-08-14 from
ossf/malicious-packages. All are all-versions ranges on names published in
Jan/Feb 2023. The real signal in the window was the other 46.

Two registry checks decided the response, and the first one was misleading on its
own. A liveness check said the packages exist, are not unpublished, and predate
the advisory by three years, which reads as a live gap. Reading the version
contents corrected it: they are npm SECURITY HOLDING PACKAGES. Of a 14-name
spread sample, 12 carry only a `0.0.1-security` placeholder and 2 still have
their original 2023 version alongside it. So the payload is largely gone and the
names have no legitimate release history, which is what makes a bare-name rule
safe here, the same reasoning the SANDWORM_MODE set already uses.

Taken as feed entries, they would have grown the bundled feed 34% (12,962 to
17,325) and added roughly 1 MB to `feed.json`, shipped to every consumer, for one
publisher's taken-down 2023 squats. They are covered by one anchored pattern in
`MALICIOUS_PACKAGE_PATTERNS` instead, and the 46 real entries were imported
normally through the project's own writer.

### Needs a decision

**`MALICIOUS_PACKAGE_PATTERNS` does not reach the generic directory scan.** It is
read by the npm-scanner name check and its `package.json` fallback. The directory
scan in `scanner.ts` matches exact feed names only, deliberately, because the
pattern table holds broad rules such as `^[a-z]{20,}$` that would produce false
positives there. That is the surface the GitHub Action runs, so a
pattern-only campaign is invisible to it.

Taken-down names make the residual gap small in this case, but the general
question is open and it is not this job's call to settle: should the directory
scan consult a NARROW subset of the pattern table, or should any campaign that
matters on that surface always be paid for in feed entries? Today's answer was
the pattern, on the grounds that the names are dead. A live campaign of this
shape would need the other answer, and there is currently nothing that forces
that choice to be made deliberately.

Second, smaller: the importer has no way to exclude a namespace, so every future
run will re-propose these 4,363 and refuse to exit clean until they age out
around 2026-08-28. Runs in that window need `--allow-backlog` or a namespace
filter in `scripts/import-threat-feed.mjs`.

### Enrichment (STEP 1b) found nothing addable

Socket, Aikido, StepSecurity, safedep, OX Security and The Hacker News were all
checked for write-ups newer than the v5.28.1 sweep. Every atomic indicator they
publish is already in the blocklist: the keyv/cacheable Shai-Hulud domains and
both payload hashes, the arrayref build-time dropper, WEL1DROPPER, the Alibaba
RAT cluster, Joyfill and the fake Corepack site. The one genuinely new cluster,
`@postman-cse`, had its advisory published 2026-08-22 00:44 UTC and has no vendor
write-up yet, so there were no atomic indicators to add beyond the version pins.
## The release trigger lived in a ref namespace the gates never reach (2026-08-22)

Branch fix/release-ancestry-gate. No version bump. Closes the ancestry half of the
release-authority finding; two named items stay open for the owner.

### What was true before

Branch protection on `main` requires three contexts. Only one of them, `Build and
Test`, can exist on a `refs/tags/*` push: required status checks, branch protection
and `enforce_admins` are all properties of `refs/heads/main`, and `aahp-verify` and
`PR metadata policy` have no tag-ref run in their histories. `needs: build` did already
hold the `publish` job until the compat matrix and the container build and scan passed,
but none of that says where the commit lives, and the one pre-publish check that looked
at the tag, `Validate immutable release tag`, compares the tag string against
`package.json`. That check is satisfied by any commit at all whose version field
matches, so it too carries no information about where the commit lives.

`docs/ci-and-release.md` says to tag the merged commit on `main` and never the
pre-merge commit. That sentence was written down on 2026-08-20, in the 5.28.0 release;
135 of the 138 tags to date predate it, so as a written rule in the release runbook it
governed at most the last three releases. This repository squash-merges, so those two commits always have
different shas while the content looks identical. Nothing went wrong: measured
2026-08-22, all 138 semver tags to date are ancestors of `main` and none is not, which
is what a convention looks like right up until the release where it is not. This closes
a latent defect, not an incident.

### What changed

`scripts/check-release-ancestry.mjs` fetches `main` and refuses the release unless the
commit being published is an ancestor of it. It runs in `ci.yml`'s `publish` job before
every other step, and in `docker.yml`'s `merge` job before the image tags move, because
that workflow carries its own tag trigger and moves `:latest` on its own. Both jobs now
check out with `fetch-depth: 0`; the gate refuses to answer in a shallow checkout rather
than answering from the few commits a depth-1 fetch happens to hold, which is the most
plausible way it could have decayed into a silent pass.

Each outcome has its own exit code, and "cannot answer" (2, 3, 4, 5) is deliberately a
different code from "answered no" (6). `src/__tests__/release-ancestry.test.ts` asserts
the exact codes against real git repositories, and asserts the wiring on comment-stripped
YAML: with the step deleted, the raw file still contains the script path in a comment, so
a text search would have reported a gate that no longer runs.

### Still open, and both are owner decisions

1. Whether `aahp-verify.yml` should gain a `tags:` trigger so the handoff gate evaluates
   the released commit. That changes what a release must satisfy.
2. Whether a repository ruleset should restrict creation of `refs/tags/v*`. That is an
   access-control change and needs an explicit bypass list.

Neither is required for the ancestry gate to close the hole. Both are recorded on
https://github.com/homeofe/supply-chain-guard/issues/167, which this pull request does
not close.

### What the gate does not reach

Actions runs a workflow from the file present at the pushed ref, so the gate binds only
tags whose commit already contains it. Two consequences, both stated in the gate script
header and above the `publish` job rather than only here: a tag cut from a commit that
predates this change still publishes ungated, and an actor who controls the commit
controls its `ci.yml` and can omit the step. The gate closes the accident. Only the tag
ruleset closes the deliberate case.

---

## The required handoff gate compared main to itself on every push (2026-08-22, unreleased)

Model: claude-opus-5. Branch fix/aahp-verify-explicit-base. No version bump.

`aahp-verify` is one of three required status checks on `main`. Its Layer 2
content-drift gate enforces "code changed implies handoff state changed", and to
answer that it needs a base commit. Up to CLI 3.9.2 it inferred one: the upstream
tracking branch first, then `origin/main`. On a push to `main`, `actions/checkout`
sets the local branch to track the remote branch at the pushed commit, so the
inferred base was HEAD. The gate diffed HEAD against itself, the change set came
back empty, and an empty change set was printed as a pass.

The consequence is not one bad run. It is every push run the workflow has ever
produced, and every `workflow_dispatch` run, reporting a Layer 2 verdict that
compared nothing. Run 32517774317 is the recorded instance: a push whose commit
touched eight files, five of them outside `.ai/handoff/`, and Layer 2 printed
"No source files changed outside .ai/handoff/. Drift gate not triggered."

### What was NOT open

No merge path. The `pull_request` run of the same required check is not vacuous:
on a pull request `actions/checkout` lands on the merge ref in detached HEAD, the
upstream lookup fails, and the CLI falls through to `origin/main`, which is a
different commit. Run 32525214132 is a real `pull_request` run of the unfixed
workflow that correctly named three drifted files and blocked. `main` is
protected with `enforce_admins` on and force pushes off, and the recent history
on `main` arrives through squash-merged pull requests, each gated by that
non-vacuous pull request run.

So what was lost is the per-commit attestation on `main` and the independent
second evaluation, not a way into `main`. The pull request path worked by
accident rather than by design, which is precisely why the push run that is
supposed to catch a regression there could not.

### What changed

Two halves, and neither works alone:

1. `@elvatis_com/aahp` 3.9.2 -> 3.10.0 (exact pin, package.json and
   package-lock.json). 3.9.2 has no way to be told a base at all, so passing one
   to it is a no-op. 3.10.0 reads `--base` / `AAHP_BASE_SHA`, requires it at
   `--level ci`, and turns a missing, all-zero, malformed, unreadable or
   HEAD-equal base into a blocking failure rather than an empty change set. It
   also compares the two endpoint trees instead of `base...HEAD`, so a rollback
   cannot collapse to an empty merge-base diff.
2. `.github/workflows/aahp-verify.yml` passes the base the event knows:
   `AAHP_BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.before || inputs.base }}`,
   bound as step env rather than spliced into the run line. `workflow_dispatch`
   gained a required `base` input, because a manual run has no event base and at
   `--level ci` a missing base now blocks instead of guessing.

### Correction: the pull request operand DOES change that leg's change set

An earlier revision of this entry said "the pull request operand is not a change
of verdict for that leg; it is what keeps that leg running once the CLI stops
guessing." The second half holds. The first half is wrong, and the measurement
is below rather than the reasoning that produced it.

3.9.2 resolved its own base on that leg. The checkout is a detached merge ref,
the upstream lookup fails, and it fell through to `origin/main`, read live from
the same clone, then diffed `origin/main...HEAD` (three-dot). The merge ref is
rebuilt on the live tip, so that change set was exactly the pull request's own
files. 3.10.0 diffs two endpoint trees from
`github.event.pull_request.base.sha`, which is the base tip recorded on the pull
request when the event fired, not the live one. `branches/main/protection`
returns `strict: false`, read live on 2026-08-22, so a pull request is never
forced up to date and nothing keeps the two operands in step. Pull request 165
is the live instance: its `base.sha` is still `a5048bd`, one merged commit
behind `main` at `1a141fe`.

Measured on this repository, 2026-08-22, against `refs/pull/183/merge` (parents
`1a141fe` and `ee0235d`):

```
git diff --name-only origin/main...refs/pull/183/merge   -> 12 files
git diff --name-only a5048bd refs/pull/183/merge         -> 15 files
```

The extra three, `.ai/handoff/DASHBOARD.md`, `.ai/handoff/TRUST.md` and
`src/__tests__/consumer-update-path-contract.test.ts`, are the whole of
`1a141fe`, another author's commit, not that pull request's.

Widening is not simply stricter, which is the part worth writing down. Layer 2
sets `STATUS_TOUCHED` and `MANIFEST_TOUCHED` over the WHOLE change set and
passes when both are set, so a commit dragged in from `main` carries the very
two files that satisfy the gate. Constructed on top of `1a141fe`: one commit
touching only `src/scanner.ts` and no handoff file, merged into a simulated
merge ref. The live-tip selector returns `M src/scanner.ts` alone, which is the
failing case. The same merge ref against the stale `a5048bd` returns that plus
`M .ai/handoff/STATUS.md` and `M .ai/handoff/MANIFEST.json`, which is the
passing case. On a stale base the widened change set can therefore mask a real
drift failure, not merely report extra files.

What remains true: passing an operand at all is what keeps that leg running,
because 3.10.0 blocks a `--level ci` run given no base. The operand that would
not widen is the base tip the merge ref was actually built on, which is
`HEAD^1` of the merge ref rather than the event's recorded `base.sha`. That is
a behaviour change to a required gate, so it is written here as an open item
for the owner rather than made silently in this pull request.

`src/__tests__/aahp-verify-base-contract.test.ts` evaluates the `||` chain the
way GitHub would, per event, and asserts the resolved base is never the commit
under test. A string comparison would not have caught the original defect, since
the defect was two different expressions resolving to the same commit.

### What was deliberately left

The Dependabot actor skip. Six steps in this workflow, including the checkout,
carry `github.actor != 'dependabot[bot]'`, so on a Dependabot change the required
check concludes success having executed one `echo` and evaluated zero layers.
That is real and confirmed at runtime, and it is a separate defect from base
selection. Removing it is not drop-in safe: a dependency bump modifies
package.json and package-lock.json, both outside `.ai/handoff/`, so Layer 2 would
hard-block every dependency update including security updates. 3.10.0 ships the
mechanism that resolves it, `handoffImpact.nonImpactingModifiedFiles`, but
writing that list is a reviewed policy statement about which files do not
describe product state, not a mechanical fix. It needs an owner decision.

## The published update path was the one that froze a pin (2026-08-21, unreleased)

Model: claude-opus-5. Branch fix/consumer-update-cadence. No version bump.

Two questions were asked of this repository: whether the consumer-name fix
actually reached the PUBLISHED surface, and what this project's release cadence
and consumer-update path really are when measured rather than assumed.

### The disclosure fix did reach the published surface, because it never left it

`CHANGELOG.md` becomes the GitHub Release body verbatim, so the v5.2.40 and
v5.2.41 entries looked like they were already published. They were not. Both
release bodies were created before the changelog moved out of `README.md`, so
`ci.yml` found no matching section and fell back to its stub, "See README.md for
full changelog". All 44 releases of that era carry the same stub. The anchor they
point at still resolves, and the file behind it is the corrected one.

All 134 published release bodies were fetched and scanned for the reference
shape. Zero hits. The 16 raw matches were all deliberate publications: Kubernetes
and k3s default service CIDRs that are the scanner's own detection corpus in
`src/internal-disclosure.ts`, and a public agent-runtime product name this
project ships a scanner for. `CHANGELOG.md` is also not in the npm `files` list,
so the tarball never carried it either.

**The remaining exposure is the pull request body surface, and it is larger than
the changelog was.** It was not touched: editing a merged body is the owner's
call. Details are in the section below and in the session report.

### The cadence, measured

134 releases in the 155 days to 2026-08-21. 1.40 per day over the last 60 days.
Median gap 19.8 hours, two thirds of gaps under a day, 51 percent of calendar
days ship, 93 patch / 36 minor / 4 major.

The README told consumers to pin an exact version and let Dependabot follow it on
a `weekly` schedule. At 1.4 releases a day that recipe cannot converge: each
weekly run opens a correct bump pull request and the next weekly run closes it as
superseded. Measured in one consumer of this Action, counts only: eight
consecutive weekly bump pull requests, each alive exactly seven days, each
proposing a newer target, while the pin sat unchanged for 49 days and fell 82
releases behind, with a green scan check every day.

So the answer to "can consumers practically follow releases" is no, not with the
configuration this project published, and that is a finding about this package
rather than about the consumer.

### What changed

`README.md` now recommends `daily` with the measured rate stated as the reason,
and says plainly that the interval is the cheap half while merging the pull
request is the half that decides the outcome.

It also drops a claim it should not have made. It said an exact pin "turns that
into a visible out-of-date dependency". It does not. `scan` runs offline against
the IOC feed bundled with the pinned version, so a pin that stops moving freezes
the detection rules at that date, and no exit code, risk score or check name
reports it. A frozen rule set is a silent false-negative generator, which is the
same failure the surrounding paragraph warns about for the floating major ref.
An exact pin buys a PLACE where staleness is reviewable, the bump pull request,
which is a weaker and different claim.

`src/__tests__/consumer-update-path-contract.test.ts` holds both halves, asserts
the positive and negative directions separately, guards them with a
snippet-exists check so a deleted snippet cannot pass vacuously, and re-asserts
the counts-not-names rule over its own text. Mutation proof after committing the
fix: reverting the interval fails 2 of 5, reverting the claim fails 1 of 5,
restoring passes 5 of 5 with a clean tree.

### Known limitation of this change

Nothing here makes a stale pin visible to the consumer at scan time. The IOC feed
is compiled into `src/threat-intel.ts` with per-indicator `firstSeen` dates but
no feed-level generation date, so the scanner cannot currently report the age of
the rules it just ran. Documenting the gap is not closing it. See the session
report for the proposal.

---

## Consumer-name disclosure: removed from files, gated, written down (2026-08-21, unreleased)

Model: claude-opus-5. Branch fix/consumer-name-disclosure. No version bump.

An audit of this public repository for internal disclosure found three
cross-repository references in tracked files, and one much larger disclosure in a
merged pull request body.

### What was fixed in files

- `CHANGELOG.md` (entries v5.2.40 and v5.2.41) named a private repository and an
  internal issue number as the provenance of a security fix. The provenance now
  reads "the continuous AAHP Swarm review" with no cross-repository reference.
  `CHANGELOG.md` becomes the GitHub Release body verbatim, so this was on its way
  to an indexed surface.
- `src/__tests__/rule-precision.test.ts:168` named a private consumer repository
  as the source of the PPE attack shape the test asserts. It now describes the
  shape instead of the codebase it was observed in.

### What now prevents a repeat

A third `forbiddenPatterns` rule, `consumer-repo-disclosure`, in
`aahp.config.json`. It runs inside `check:aahp`, which `prebuild` runs, which the
required `Build and Test` check runs, so it fails a pull request rather than
merely reporting. Coverage was widened past the `ai-attribution` include list to
`src/__tests__/*.ts`, `examples/*` and `.ai/handoff/*.md`, because a private name
in a tracked handoff note in a public repository is exactly as exposed as one in
the CHANGELOG.

The rule deliberately does **not** enumerate private repository names. That list,
committed to a public config file, would itself be the disclosure it exists to
prevent. It matches the reference SHAPE only, which is why `CONTRIBUTING.md` now
carries the actual rule ("benchmark evidence carries counts, never consumer
names") and the gate is documented as the backstop, not the control.

Proven in both directions: with the fix committed, `check:aahp` reports
`forbidden-patterns: 3 rule(s), no matches`. Re-injecting the exact removed
string into `CHANGELOG.md` turns that gate RED and fails the build; restoring it
returns to green.

### Needs a decision (owner)

**A merged public pull request body names seven private consumer repositories
next to their security-finding counts.** Editing a merged pull request body is
the owner's call, not an agent's, so nothing was changed there. The exact
location and the proposed remediation are in the session report. The standing
rule that prevents the next one is now in `CONTRIBUTING.md` and in the pull
request template checklist.

---

## Threat-intel sweep: 84 advisory IOCs + arrayref dropper (2026-08-21, unreleased)

Model: claude-opus-5. Branch threat-intel/2026-08-21. No version bump.

84 package IOCs imported from the GitHub Advisory Database (71 npm, 4 PyPI, 9
crates.io) plus 8 atomic indicators added by hand for the arrayref build-time
dropper: the attacker VPS host, four C2 addresses and three poisoned `.crate`
digests, with eight scanner tests in `campaigns.test.ts`.

### The window had to be sliced, and why

The default rolling window proposed **4,447** entries and warned that 2,447 of
them would age out before any future run could reach them. That number is not a
detection backlog. **4,363 of the 4,447 were `@zalastax/nolb-*`**, a single scope
bulk-published to GHSA on 2026-08-14 with MAL-**2025** ids. Checked against the
registry, those packages now carry npm's own `security holding package`
placeholder, owned by npm's own registry account, with the 2023 malicious version removed:
the malware is not obtainable, and every entry would have been a bare-name block.

The day is cleanly separable, which is what made the call safe: 2026-08-07 to
08-13 yields 0 entries, 08-14 yields 4,363 and **all** of them are that scope, and
08-15 to 08-21 yields the 84 genuine 2026 entries with zero zalastax. So the
import ran as `--since 2026-08-15 --until 2026-08-21` and **nothing real was
dropped** - the arithmetic closes exactly.

**Needs a decision (owner).** The daily job will hit this same wall until the
backfill ages out of the 14-day window around 2026-08-28: every run re-proposes
those 4,363, trips the `undrainable` guard and exits non-zero. Three options:
ignore the red exit for a week; ingest the backfill once to silence it (costs a
4,363-entry machine-generated diff in a public repo for near-zero detection
value); or teach the importer to recognise an npm security-holding placeholder and
skip it, which is the durable fix and would also cover the next bulk backfill.

### Deliberately not ingested

- The crates.io handle that published the dropper. It typosquats a well-known
  maintainer name, but `KNOWN_MALICIOUS_GITHUB_ACCOUNTS` is GitHub-specific and
  consumed by the repo-owner check. **There is no GitHub account of that name**,
  and the crates.io numeric id is a crates.io id, not a GitHub id: resolving it as
  one lands on an unrelated real GitHub user created in 2010. A crates.io-account
  collection would be the right home if this recurs.
- The compromised maintainer account, which is a victim, and the
  `hostwindsdns[.]com` apex, which is a shared hosting provider. Only the
  attacker's specific host is listed, and a negative test pins that.
- The campaign's SHA-1 digests: the one source listing them gives them unlabelled
  and with duplicates, so there is no reliable file mapping to record.

One hash needed three sources. Two independent write-ups agreed on the
`proc-macro1` 1.0.106 digest; a third returned a rendering with a non-hex `o` in
it, i.e. corrupted in transport rather than a genuine disagreement. Shape-checked
all three digests as 64 hex characters before ingesting.

Local suites: campaigns, feed, threat-intel, ioc-blocklist, feed-import,
issue-54-hardening, cargo-scanner. All new tests green. Two pre-existing
`IOC_KNOWN_C2_DOMAIN` failures (Phantom Bot, GlassWASM) reproduce identically on
unmodified `main` on this Windows box and are green in CI. Full-suite verdict is
CI's.

## Exact version pinning documented as the default (2026-08-20, unreleased)

Model: claude-opus-5. Branch docs/recommend-exact-pinning. No version bump.

README and `examples/github-action-basic.yml` now pin an exact release, with a
Dependabot snippet, and `@v5` is documented as a supported transition path rather
than the headline form. The README states what `@v5` does and does not guarantee,
because it is better than it looks: the composite action on that branch pins an
exact, build-gated npm version, so it is not `latest`. The failure mode is only
after a major, when a frozen action keeps installing an old feed.

One coupling worth knowing before editing these docs again: pinning an exact
version in an example turns that file into a version site. Left unregistered it
would silently go stale and ship stale copy-paste, so `examples/github-action-basic.yml`
was added to `aahp.config.json` and README's `minOccurrences` raised to 2.
**There are now 15 version sites, not 14** - read the count from the config rather
than from any prose, including this note. CONVENTIONS.md already says "every version
site in aahp.config.json" and needed no change; the historical "all 14" lines in
older STATUS entries are records of what was true at the time and stay as written.

The remaining half of the v6 decision (a deprecation warning on `@v5` once v6 ships,
and the manual Marketplace re-check) is still open and unchanged.
## T-016 done: pinned npm IOCs now match on a directory scan (2026-08-20, unreleased)

Model: claude-opus-5. Branch feat/lockfile-pinned-ioc. No version bump. Lands on
top of the indexed matcher from #154, which is what makes it affordable.

Re-derived before deciding: the feed is 12,870 entries / 12,551 package IOCs, of
which 9,597 are version-pinned npm (76.5%) and 2,433 bare. The note carried since
2026-08-06 said 7,749 of 9,374, so absolute exposure grew by 1,848 while the SHARE
fell from 82.7%, because bare names grew faster.

Two findings changed the decision rather than confirming it:

1. The false-positive fear was mis-specified. It is exact name@version equality, so
   it can only fire wrongly on a wrong pin in the FEED, which is a data-quality
   question already governed by the bare-name audit discipline. Measured: zero hits
   across 43 repos and 10,615 resolved dependencies, and zero again with the built
   scanner on the ten largest trees.
2. `scan` already did exact name@version matching, in checkLockfileBadVersions,
   against KNOWN_BAD_NPM_VERSIONS. It simply never consulted the feed. The PyPI
   scanner already consumed feed data this way. The inconsistency was architectural,
   not conceptual.

The three callers passing no version are NOT defects: checkPackageName receives only
a name, and the other iterates Object.keys(dependencies), whose values are ranges.
There is genuinely nothing to pass, so nothing there was changed.

Mutation proof, three properties separately: reverting to the original bug (no
version passed) turns 2 tests red; dropping the bare-name exclusion turns 1 red;
dropping the dedup turns 1 red. An earlier mutant survived and that was a gap in
the tests, not a pass - it is recorded here because the first attempt looked like a
proof and was not.

## EU compliance positioning in the README (2026-08-20, unreleased)

Model: claude-opus-5. Branch docs/eu-compliance-positioning. README only, plus
this note. No version bump.

Adds an `EU Compliance (CRA / NIS2)` section between `How It Compares` and
`GitHub Action`, and one sentence to the intro paragraph. Four things were
deliberately left OUT of the drafted text, and they are recorded here so a
later pass does not reinstate them as helpful additions:

1. **No company or location line.** The draft claimed a legal entity and a city.
   Neither appears anywhere in the repository, the entity is still in formation,
   and a public README is not the place to assert it. Removed at the owner's
   direction.
2. **No article or paragraph citations.** The draft cited specific CRA article
   paragraphs. Those were not verifiable from an authoritative source here, and
   the SBOM obligation is commonly attributed to a different provision than the
   one drafted. Wrong statutory citations in a section aimed at compliance
   readers are worse than no citations, so the section describes what the tool
   PRODUCES and tells the reader to map it against the final regulation text
   with their own legal review.
3. **"Supports", never "satisfies" or "CRA-ready".** A scanner can contribute
   artefacts to compliance work; it cannot make an organisation compliant. The
   section says so in its opening paragraph.
4. **Air-gap claim qualified.** `scan` is genuinely offline against the bundled
   feed, but `npm <pkg>` / `pypi <pkg>` fetch the package under inspection and
   the feed refresh fetches indicators. The unqualified "fully air-gappable"
   would have been false for those commands.

Formatting: the drafted text carried four em-dashes and two en-dashes. The
`em-dash` forbidden-patterns rule covers README.md, so it would have failed the
build rather than merged. Written with hyphens and colons instead, and verified
at zero of both before the gate ran.

The documented example was executed rather than assumed:
`scan <dir> --sbom-output sbom.json` exits 0 and writes a CycloneDX 1.6
document. The flag exists at `src/cli.ts:225`, and SLSA levels 0 to 3 match
`src/slsa-verifier.ts:326`.

**Repository topics, still open.** The related request was to replace all topics
with a 20-item list. Replacement would have dropped 8 existing topics including
`pypi`, `golang` and `rust`, which are supported ecosystems, and `glassworm`, a
campaign the scanner detects by name. Additive was chosen instead, but the repo
already holds 19 of GitHub's 20-topic maximum, so exactly ONE slot is free
against 9 proposed additions. Which one, and whether any existing topic is worth
trading, is deferred to a separate prioritisation review.

## v5.28.0: Node 22 becomes the baseline, and the gates stop failing open (2026-08-20)

Model: claude-opus-5. Branch release/v5.28.0. MINOR: #156 added a rule, and
`engines.node` moves.

**The owner's decision, and what it settled.** Node 20 reached end of life on
2026-04-30. Continuing to treat it as the strategic baseline was ruled out, and the
end state asked for was explicit: documentation, CI, publishing and the distribution
channels must agree on ONE policy, with a single time-boxed transition exception and
nothing more.

**What that meant in practice.** `engines.node` is now `>=22.0.0`. The npm artifact is
published from Node 22, which removes the third runtime: until this release the package
was tested on one major, published from another, and executed by the Action and image on
a third. Node 20 remains as an explicit TRANSITION lane, still running the complete
suite but below the floor and out of support.

**The milestone is enforced, not remembered.** `docs/node-support.md` gained
`transitionRemovedIn: "5.29.0"`, and the gate compares it against the version in
package.json. The build FAILS once the project reaches that version while a transition
lane still exists, so the transition cannot outlive its own deadline: the release that
would carry it past cannot be built. Extending it means editing a date in a diff someone
reviews, which is the difference between a decision and a drift.

**The publish-lane exception is withdrawn, and the withdrawal is recorded rather than
quiet.** v5.27.0's `docs/node-support.md` gated moving `publishMajor` on the Node 22 leg
being green on `main` "across at least one release cycle", and zero cycles have elapsed
since #160. That condition is waived by the owner's direction to unify the runtimes,
against a stronger evidence base than it anticipated: the complete suite plus a
clean-room install of the packed tarball on both majors, and a container image now built
and scanned on every PR. Deleting a condition and then doing the thing it gated, without
saying so, is the move this note exists to prevent.

**One variable moved on the lane that cannot be rehearsed.** The publish job's npm pin
stays at 11.18.0. Its engine range is `^20.17.0 || >=22.9.0`, checked against the
registry rather than assumed, so it runs on Node 22 unchanged. npm 12.0.2 would also run
there, but the publish lane executes only on a tag push and authenticates by OIDC that no
dry run exercises, so the Node major and the npm major do not move in the same release.
Node 22.23.2 still bundles npm 10.9.8, so the explicit upgrade step remains load bearing.

**The gate was failing open, and that is the finding of this release.** `check:aahp` ran
`npx --no-install aahp check .` on the belief that `--no-install` forces the pinned copy.
It suppresses a DOWNLOAD; it does not stop npx resolving a globally installed `aahp` on
PATH. Measured 2026-08-20: this repository pins 3.9.2 exactly, a global 3.8.0 was on
PATH, and in a checkout with an empty `node_modules` the gates reported
`Governance OK: 7 gate(s) ran, no failures` from 3.8.0, with nothing anywhere saying
which version had spoken. That was then reproduced by accident in the shared checkout
during this very session. `scripts/check-aahp-pin.mjs` now runs first and fails closed;
mutation-proved by hiding `node_modules/@elvatis_com` and confirming exit 1 where the old
script printed green. It is the exact failure class this project exists to detect in
other people's builds.

**The container path is validated before a release rather than during one.** `docker.yml`
already publishes multi-arch to ghcr, but only on a semver tag, so the first build of any
Dockerfile or base-image change happened during the release itself, after the decision to
publish. A non-publishing `Docker build and smoke` job now runs on every PR and gates the
`Build and Test` aggregator: it builds both stages, asserts the image runs the Node major
the policy declares, checks the packaged CLI version, and completes a real scan from
inside the image. Proven locally before being wired in. `Dockerfile` also gained
`--ignore-scripts` on its global install, which was the only npm invocation in the repo
without it and ran as root.

**Trigger hygiene finished rather than left half-done.** `ready_for_review` is gone from
ci.yml: it creates no new head sha and no job is draft-gated, so it started a duplicate
full matrix on an identical tree and could cancel an in-flight run. `aahp-verify.yml`,
a required-check producer that predated the whole design, gained explicit
`types: [opened, synchronize, reopened]`, an explicit `name: aahp-verify` (the context was
previously the job key by coincidence) and its own concurrency group. `docker.yml` gained
a serialising group, because both its triggers end in an unconditional `:latest` push from
different refs.

**Evidence.** Node policy gate: 28 assertions, 5 of 5 new-pattern mutations caught
(Azure `versionSpec`, the URL-encoded README badge, a reverted supporting workflow, the
CircleCI image, and `Node >= NN` prose). Workflow contract: 15 assertions, 5 of 5
mutations caught (re-adding `ready_for_review`, an unnamed `aahp-verify` job, a shared
concurrency group, dropping `synchronize`, and a second workflow claiming the
`Build and Test` context). Both harnesses printed a green baseline and a green
post-restore, without which the numbers would mean nothing.

**Dependabot PR #161 pulled in rather than merged separately.** It bumps
docker/setup-buildx-action 4.2.0 to 4.3.0 in the two places docker.yml uses it, and
docker.yml is a file this release already changes. The pinned digest was verified
against the upstream tag before being taken (the v4.3.0 ref resolves to
37fe631027851001ddb9b187196cc803df7f5f0e, which is what the bot proposed) rather than
trusted because a bot proposed it. The PR is closed explicitly, since a release
leaves zero open pull requests.

**Found by the audit, not by reading the config.** The blind spots above were invisible
to the first version of the gate: `versionSpec: '20.x'` installed Node 20 in
azure-pipelines.yml while its own prose next to it said 22, the README badge encoded
`>=20` as `%3E%3D20`, and `cimg/node:lts` floats to Node 24 with no digits for any check
to see.

## CI trigger split: metadata policy separated from code validation (2026-08-20)

Model: claude-opus-5. Branch ci/split-metadata-policy. No version bump.

**The defect.** `edited` sat in ci.yml's `pull_request` types so the AI-attribution
gate would re-run when a PR title or body changed. Every metadata edit therefore
started the full build, test, package and security pipeline against a head commit
whose content had not changed. Whether the duplicate blocked a merge depended on
which run finished last: on the v5.26.7 cut the cancelled twin was last and blocked
it, on v5.27.0 the successful one was last and it did not. That is timing, not
design, and it was reproduced again on 2026-08-20 when two PR-body edits on #158
produced a third run on one SHA.

**Why the trigger could not simply be deleted.** The gate covers four surfaces, and
they do not share an input. PR title and PR body are metadata. Commit messages and
the author/committer identity fields are read from the BASE..HEAD range and change
only when the code changes. Removing `edited` without moving the first two would
have left a PR able to go green and then have an attribution footer pasted into the
body with nothing re-checking it, on a public repo where that rule is CI-enforced.

**The split.** `pr-metadata-policy.yml` owns the title and body checks and the new
`PR metadata policy` check name, on `[opened, edited, reopened]`, with no checkout,
so it reads only the event payload and cannot execute PR code. ci.yml keeps the
commit-message and identity checks inside `Build and Test` on
`[opened, synchronize, reopened, ready_for_review]`. Each required check now has
exactly one producing workflow, and the two use separate concurrency groups, so a
metadata edit can no longer cancel an in-flight code-validation run.

**No PAT is required, and the earlier claim that one was is withdrawn.** It
conflated the Actions `GITHUB_TOKEN`, which genuinely lacks `administration`, with
the maintainer token used from the workstation, which reports `admin=true` and
already read the protection settings. Branch protection is updated from the
workstation, not from a workflow, so no write-capable credential is introduced and
nothing new is reachable from untrusted pull-request code.

**Ordering, and the window it leaves.** The new check name cannot be required
before the workflow exists on `main`, or every PR blocks on a check that never
runs. So: merge first, then add `PR metadata policy` to
`required_status_checks.contexts`. Between those two steps the metadata check still
RUNS and reports, it is simply not yet blocking. That window is seconds long and is
recorded here rather than glossed.

**Trigger sets, after the scenario run.** Code validation takes
`[opened, synchronize, reopened, ready_for_review]`; metadata policy takes
`[opened, edited, reopened, synchronize]`. The asymmetry is the point: ci.yml must
not see `edited` because its job costs two minutes and metadata cannot change
code, and the metadata workflow must see `synchronize` because a required check is
evaluated against the head commit's check-runs and therefore has to exist on every
sha, which six seconds with no checkout makes affordable.

**Scenario record.** Every scenario below was executed against PR #159 and the
result read back from the API, not inferred. `CI` produces the `Build and Test`
required check, `PR Metadata Policy` produces `PR metadata policy`, `AAHP Verify`
produces `aahp-verify`.

| # | event | head sha | runs created on that sha | conclusions | cancellation | branch-protection state |
| --- | --- | --- | --- | --- | --- | --- |
| A | opened | 6c74849 | CI, AAHP Verify, PR Metadata Policy | all success | none | BLOCKED then CLEAN once the build finished |
| B | edited (title only) | 6c74849 | PR Metadata Policy only, CI count unchanged at 1 | success | none, the in-flight build kept running | unchanged |
| C | edited (body only) | 3b92109 | PR Metadata Policy only, CI count unchanged at 1 | success | none | unchanged |
| D | synchronize | 03e75fd | CI, AAHP Verify, and NO metadata run | success | none | see the defect this exposed, below |
| E | two commits ~30s apart | 03beef5 then a43f8a7 | CI on both | superseded CI cancelled, newest sha conclusive | correct, obsolete run cancelled | decided by the newest sha only |
| F | edited while a build was in progress | 6c74849 | PR Metadata Policy | success | the running CI run was NOT cancelled | unchanged |
| G | violating title or body | n/a, harness | gate script from the workflow yaml | 11/11 expectations met | n/a | n/a |
| H | violation fixed | 3b92109 | AAHP Verify | failure to success | none | BLOCKED to CLEAN |
| I | required check failing | a43f8a7 | aahp-verify failed on a real drift | failure | none | BLOCKED |
| J | re-run | 3b92109 | none, `gh run rerun` re-runs IN PLACE | success | n/a | CLEAN |

**Scenario D found a defect in the first version of this split, and it would have
deadlocked the repo.** The metadata workflow originally omitted `synchronize` on
the reasoning that a new head commit cannot change a title or body. True, and
irrelevant: a required status check is evaluated against the check-runs attached
to the HEAD COMMIT, so head sha 03e75fd carried a CI run, an AAHP Verify run and
zero metadata runs. Adding `PR metadata policy` to the required contexts would
then have blocked every PR that received a push after being opened, forever, on a
check that never arrives. Found by running the scenario, not by reading the
config, which is the reason for running them.

**Scenarios G and H were run as a harness rather than by editing the PR, on
purpose.** The violating input IS an AI-attribution footer, this repo is public,
and GitHub keeps PR title and body edit history visible permanently. Publishing
one to test the gate that forbids publishing them is self-defeating. The harness
executes the PATTERN extracted from the workflow yaml, so it cannot drift from
what CI runs, and covers seven violating forms plus four that must NOT trip,
including this project's own threat intelligence naming the brand and prose
describing the rule. The platform link the harness cannot prove, that a failing
step becomes a failing required check and blocks the merge, was proven live
instead by scenario I.

**On the cancelled-twin question, which is what started this.** Scenario F's
follow-up put a cancelled and a successful run of the SAME required check name on
ONE head sha (runs 32358446823 cancelled and 32358449384 success on 6c74849) and
the PR still read CLEAN, so GitHub evaluates the newest run for a context. That is
structural rather than lucky: cancel-in-progress only cancels a run that a newer
run in the same group has just superseded, and the newer run then runs to
completion. The v5.26.7 block therefore remains UNEXPLAINED by cancellation alone
and was not reproduced in this session. What is claimed here is narrower and
measured: the generator of same-sha duplicate CI runs, the `edited` trigger, is
gone, and a title or body edit now provably creates no CI run at all. The recorded
remedy in CONVENTIONS.md stays, and scenario J confirms `gh run rerun` re-runs in
place and leaves the check conclusive.

**Regression mechanism.** `src/__tests__/workflow-trigger-contract.test.ts` encodes
the event-to-workflow matrix and fails if `edited` returns to ci.yml, if the
title/body checks move back into the build job, if the commit-range checks leave it,
if a check name gains a second producer, if the concurrency groups collide, if the
metadata job gains a checkout, if the two attribution patterns drift apart, or if
the dependabot exemption moves from step level to job level.

Mutation proof, four mutations, each caught: re-adding `edited`, moving `PR_TITLE`
back into ci.yml, sharing one concurrency group, and giving the metadata job a
checkout. The concurrency mutation initially SURVIVED, because the test compared
raw strings and `ci-${{ ...number }}` differs textually from
`ci-${{ ...number || github.ref }}` while resolving to the same group on a
pull_request event. The assertion now resolves the `||` fallback for that event
before comparing. Recorded because the first version looked like a proof and was
not.

## T-013: Node compatibility contract, evidence lanes and drift gate (2026-08-20)

Model: claude-opus-5. Branch node/22-compat-contract. No version bump.

**The survey came back different from the task's premise.** T-013 was written as
"move to a supported Node line". The inventory found the repository already
disagreeing with itself: `package.json` promised `>=20.0.0`, CI built, tested and
PUBLISHED on 20, and `action.yml` and the `Dockerfile` both ran on 22. So the
composite Action and the container image, the two things people actually run,
executed on a major CI never exercised, and had for months with everything green,
because nothing compared the files to each other.

Node 20 reached end of life on 2026-04-30. That was read from the upstream
nodejs/Release schedule rather than recalled. For a supply-chain security tool,
building and publishing the artifact from an unpatched runtime is a defect in the
product, not housekeeping.

**What shipped.** One authoritative policy in `docs/node-support.md`, as a
machine-readable block inside its own documentation so the doc cannot drift from
the config. `src/__tests__/node-version-contract.test.ts` parses it and holds
every declaration site to it, including two invariants that were being violated:
the runtime major must be tested, and the publish major must be tested.

CI now runs the complete build, every governance gate and the full suite on Node
20 and Node 22, with no reduced smoke lane. `scripts/validate-package.sh` runs
inside each matrix leg: it packs, checks the tarball against the manifest,
installs it into a directory sharing nothing with the checkout, and drives the CLI
and the programmatic entry point from that install, ending in a real scan.

**The check name stayed put, deliberately.** Making `build` a matrix would have
renamed its check to `Build and Test (20)` and `Build and Test (22)` and deleted
the context branch protection waits for, which is the deadlock PR #159 measured
two days' work earlier in this same session. Instead the matrix runs under
`compat (Node N)` and a one-step aggregator keeps `Build and Test` as a single
required context with a single producer. It carries `if: always()` because a
SKIPPED job is not a failing one, so without it a red matrix could report as a
non-failure.

**Evidence.** Drift gate: 20 assertions, 9 of 9 mutations caught, including
action.yml reverting to 20, the Dockerfile reverting to 20, dropping 22 from the
matrix, lowering the engines floor, moving the publish job to an untested major,
the devcontainer staying on the EOL major, a user-facing example advertising an
untested major, and the policy document itself claiming an untested runtime major.

Artifact validation: 34 checks, 3 of 3 artifact defects caught. The first run of
that mutation harness was INVALID and is recorded as such: it reported 3 of 3
caught while the clean tree also exited 127, because Python spawned a bash whose
PATH had no `node`, so every run failed for the same unrelated reason. Re-run from
bash, one mutation then SURVIVED: dropping `policy-schema.json` from `files[]` was
invisible, because every assertion read `files[]` and confirmed the tarball
matched it, so deleting an entry removed the file and the check together. A
manifest-independent floor of required runtime assets was added, and the mutation
is caught.

**CI evidence, read off the run rather than off the tick.** PR #160, head sha
75fb45e, CI run 32362440688. `compat (Node 20)` ran on node v20.20.2 and
`compat (Node 22)` on node v22.23.2; both reported 116 of 116 test files
passing, which is the whole suite and not a subset, and both finished with
"Packaged artifact OK" covering tarball contents, clean-room install, metadata,
bin mapping, entry point, declarations and an end-to-end scan. This is the first
time this project has ever run its suite on Node 22.

That run was also the first PR under the three required contexts, so it doubles
as the branch-protection verification the CI split needed: `Build and Test`,
`aahp-verify` and `PR metadata policy` were all present and green on the head
sha, the aggregator reported once, and the PR read CLEAN. The contract is
satisfiable on a normal PR, which is the property scenario D showed could not be
taken for granted.

**What is deliberately NOT done.** `engines.node` still says `>=20.0.0`. Raising
it is a promise broken for every consumer still on Node 20, in a package installed
inside other people's pipelines where the Node version is often not theirs to
choose. That is an owner decision, it is recorded as the outstanding half of T-013,
and the gate makes executing it mechanical. The publish job also still runs on
Node 20, tracked as a named exception with an owner and a mechanically checkable
exit condition in `docs/node-support.md`.

## Carried open items (process and design, not tied to one sweep)

### Duplicate CI runs: RESOLVED in v5.28.0 (was: do NOT simply drop `edited`)

This entry argued that removing `edited` from `ci.yml` was unsafe as stated, because
the attribution gate needed it to re-check a PR title or body. That reasoning was
right, and the fix it proposed has now shipped, so the item is retired rather than
carried: PR #159 split the title and body halves into `pr-metadata-policy.yml` and
narrowed `ci.yml`, and v5.28.0 removed `ready_for_review` for the same reason.

Two things this entry said are now known to be wrong and are corrected here so they
are not re-derived from the old text:

- **It claimed branch protection needs a PAT** because `GITHUB_TOKEN` has no
  `administration` permission. That conflates the Actions token with the maintainer
  token used from the workstation, which reports `admin=true`. Protection is edited
  from the workstation, never from a workflow, so no write-capable credential is
  introduced.
- **It called the surviving behaviour luck.** Measured since: a cancelled and a
  successful run of the same required check on one head sha left the PR CLEAN,
  because GitHub evaluates the newest run and `cancel-in-progress` only ever cancels
  a run that a newer one has just superseded. The v5.26.7 block therefore remains
  unexplained by cancellation alone and was never reproduced. `gh run rerun` is
  still the recovery, and it re-runs in place, leaving the check conclusive.

The full event-to-workflow contract now lives in `docs/ci-and-release.md`, and
`src/__tests__/workflow-trigger-contract.test.ts` fails if the workflows drift from
it.

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

## T-017 done: matchBareNpmIOC indexed (2026-08-20, unreleased, branch perf/index-bare-npm-ioc)

Model: claude-opus-5. No version bump.

`matchBareNpmIOC` walked the entire feed on every call, and it is the matcher
every npm dependency check goes through. Now indexed on a `WeakMap` keyed by feed
array identity, mirroring `matchPackageIOC`. The linear version is kept as
`matchBareNpmIOCLinear` and a parity suite asserts the two agree across every npm
entry in the bundled feed, in both the pinned-exact and bare-name branches.

Measured, not asserted: `collection-reachability.test.ts` went from 3,317ms to
**21ms**, and the 30s stopgap it was carrying is removed. Worth noting the feed
grew from 9,374 to 12,551 package IOCs between those two measurements, so the
improvement is understated by the comparison.

Mutation proof: making the index drop the pinned version - so a pinned IOC would
match any version - turns exactly 3 of the 6 parity tests red, and restoring it
returns 6/6.

One deliberate asymmetry: the parity suite itself carries a 120s budget. That is
NOT the same kind of number as the stopgap removed here. Proving parity means
running the linear reference once per case, so it is O(cases x feed) by
construction. If it ever needs raising, sample the cases rather than weaken the
assertion.

## Release v5.27.0 (2026-08-20)

Model: claude-opus-5. Contents: the 2026-08-20 threat-intel sweep and the
lifecycle-hook coverage fix, both detailed below.

**MINOR, not PATCH, and this is the first release since v5.26.1 that is not a
patch.** The rule this repo has been applying is recorded under v5.26.6: a release is
a PATCH when it adds "feed and blocklist data plus one test block: no new rule, no
pattern-table change, no change to what the scanner does". The threat-intel half of
this release meets that description exactly. The lifecycle-hook half does not. It
changes `patterns.ts`, and it changes what the scanner reports on all three code
paths that read `package.json` scripts: `install`, `prepare`, `preprepare`,
`postprepare` and `prepublish` now produce `SCRIPT_*` findings where they produced
none. No new rule id was added, so the change is invisible to a rule inventory, but a
consumer whose gate was green can go red on the next run without changing a single
dependency. That is a behaviour change and it gets a minor.

Worth being precise about what does NOT drive the decision, so the precedent stays
usable: `AUTO_RUN_LIFECYCLE_HOOKS` is a new exported symbol, but `src/index.ts` does
not re-export `patterns.ts`, so it is not reachable through the package entry point
and is not public API. The minor rests on the scanner's observable output, not on the
export.

SECURITY.md needed no edit: its Supported Versions table is major-granularity (`5.x`),
so a minor does not move it.

The sweep was prepared by the scheduled daily job, which never releases. The release
was cut in the same session on an explicit instruction to ship, so the version bump
and the data landed in one PR rather than the usual two. One merge, one CI settle,
then the tag.

---

## Threat-intel sweep 2026-08-20

Model: claude-opus-5. Prepared by the scheduled daily job, which never releases.
Shipped as v5.27.0 (PR #153), together with the release commit.

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

## Lifecycle-hook coverage gap (2026-08-19)

Merged as PR #152 and shipped in v5.27.0; it is the half of that release that makes it
a minor rather than a patch.

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
