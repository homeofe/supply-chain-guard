# supply-chain-guard: Current State

> Updated 2026-08-13 (release v5.26.1). This is one current snapshot, not a session log.
> Historical detail belongs in CHANGELOG.md, generated LOG.md,
> LOG-ARCHIVE.md, and git history.

---

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

### Open for Emre

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
patch release at Emre's direction. Version bumped across all 14
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
`main`. The version is deliberately untouched: Emre cuts the release separately.

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

### Open points for Emre

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
patch release at Emre's direction, in the same session. Version bumped across all
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
from `main` at 00c9fcf. The version is deliberately untouched: Emre cuts the
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
patch release at Emre's direction, in the same session. Version bumped across all
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

**Open question for Emre (no PR issue opened, per the repo invariant).** The
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
