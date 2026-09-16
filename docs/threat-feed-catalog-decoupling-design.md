# Threat-feed catalog decoupling

Design for resolving the bulk-migration deferral backlog by splitting the threat
feed into a compiled-in bundle and a downloadable historical catalog, with an
explicit finding whenever the catalog is absent, stale or unverifiable.

Status: design approved, revised after review, not yet implemented.
Date: 2026-09-16.
Supersedes Tier 3 of `docs/threat-feed-bulk-backfill-strategy.md`.

Revision note: the first draft carried seven defects found in review, an eighth
was found while writing the implementation plan against it, and four more were
found by re-auditing the design against the code before merging. All twelve are
corrected below and recorded in section 11, because most of them are the same
class of mistake this project keeps producing and the record is worth more than
a clean-looking document.

## 1. Problem

`threat-feed-deferred.json` holds five ranges covering 56,294 npm package IOCs
that the importer has deliberately not ingested:

| range | entries |
| --- | --- |
| 2026-09-02 | 9,758 |
| 2026-09-04 | 9,937 |
| 2026-09-06 | 8,550 |
| 2026-09-10 | 8,891 |
| 2026-09-13 | 19,158 |

A deferral makes no claim that anything else detects these names. Unlike a
decline, it is a recorded, deliberate gap. The gap is live rather than
historical: the liveness audit in the backfill strategy document sampled 50 of
these packages and found 28 still installable on npm today.

Three properties make this hard to resolve by importing the block:

1. **It is not a fixed quantity.** The waves are an alphabet walk currently at
   `j`, with the remainder of `f` skipped. More is arriving. Any fix that treats
   56,294 as the total will be re-litigated within weeks.
2. **The bundle pays the cost on every invocation.** The feed is compiled into
   `dist/threat-intel.js` and imported by the CLI on every run.
3. **Declining is not available.** The block spans roughly 1,189 distinct name
   tokens across unrelated malware families, so no anchored rule in
   `src/patterns.ts` covers it and `coveredBy` cannot be satisfied honestly.

## 2. Measurements

Measured on 2026-09-16 against the v6.1.3 tree. Import cost was measured by
generating synthetic feed modules shaped like the real chunked array literal and
timing `require()`.

### Import cost is linear at about 3.5 microseconds per entry

| feed entries | module import | generated source |
| --- | --- | --- |
| 20,969 (today) | 75 ms | 3.3 MB |
| 40,000 | 143 ms | 6.4 MB |
| 77,263 (today plus the backlog) | 266 ms | 12.3 MB |
| 150,000 (alphabet walk completed) | 527 ms | 24.1 MB |

Paid on every CLI invocation, because the feed is a module-level array literal
the runtime must parse before anything else happens.

### Package size

1.30 MB packed, 9.91 MB unpacked, of which `dist/threat-intel.js` is 3.56 MB and
its source map a further 2.76 MB. `action.yml` is a composite action running
`npm install -g supply-chain-guard` at runtime, so size is paid per Action run.

Absorbing the backlog takes the package to roughly 19 MB unpacked; completing
the alphabet walk takes it to roughly 31 MB.

### Compression

`feed.json` is 4.63 MB raw, 0.34 MB gzip -9 (7.3 percent), 0.27 MB brotli.

| catalog size | raw | gzip |
| --- | --- | --- |
| 56,294 entries | 12.44 MB | 0.91 MB |
| 150,000 entries | 33.14 MB | 2.42 MB |

Compression is not optional at scale. A 150,000-entry catalog is 33.14 MB raw,
which exceeds `FEED_REMOTE_LIMITS.maxBytes` of 32 MiB. Gzipped it is 2.42 MB.

### The transport exists and is wired to itself

`refreshFeed()`, `parseFeedPayload()`, the cache merge in `loadThreatIntel()`,
`FEED_REMOTE_LIMITS` and `THREAT_FEED_STALE` are built and tested. But
`DEFAULT_FEED_URL` resolves to `feed.json` on `main`, the same document compiled
into the bundle, so a refresh re-fetches what the caller already has.

## 3. Decision

Ship a two-tier feed in which the historical corpus is downloaded rather than
compiled in, and make its absence, staleness or unverifiability an explicit
finding on every scan.

Keeping absolute offline parity was rejected: at 150,000 entries it costs half a
second of startup per invocation and a 31 MB global install on every Action run,
and liveness filtering cannot rescue a corpus where more than half is live.

A silently optional catalog was also rejected. A scanner that quietly answers a
narrower question than the caller believes it is asking is the failure mode this
project treats as unacceptable.

## 4. Architecture

```text
src/threat-intel.ts FEED_CHUNK_n     <- authored bundle, comments preserved, compiled
        +--> dist/threat-intel.js         (compiled into the package)
        +--> feed.json                    (published bundle document)

data/threat-catalog.jsonl            <- authored catalog, never compiled
        +--> catalog.json.gz              (published release asset)
        +--> src/catalog-digest.ts        (generated constant: version + SHA-256)

scripts/check-feed-partition.mjs     <- gate: validates placement across both
```

### 4.1 Two authored stores, not one generated store

An earlier revision of this design made `data/threat-corpus.jsonl` the single
source of truth and regenerated `src/threat-intel.ts` from it. **That is not
implementable and the plan for it was abandoned before any code was written.**

The feed chunks in `src/threat-intel.ts` carry 792 comment lines interleaved
with the 20,969 entries. They are the curated rationale this project depends
on: why `jsonkeeper[.]com`'s apex is deliberately not listed, why a compromised
maintainer is a victim rather than an indicator, why a given entry is pinned
instead of name-blocked. `FeedIOC` has no field for any of it. A round trip
through a JSONL corpus would delete all 792 lines, and the byte-identical
Phase 1 check the migration depends on could never pass.

So the bundle stays exactly where it is, authored as it is today, with its
comments and its existing importer workflow untouched. Only the catalog is new:

- **`src/threat-intel.ts`** remains the authored bundle. No change to how it is
  written, reviewed or generated into `feed.json`.
- **`data/threat-catalog.jsonl`** is the catalog store, one `FeedIOC` per line,
  machine-written only. JSONL because this project reviews feed diffs line by
  line and a 33 MB array literal reformats unreadably. Nothing in it is
  compiled, so it costs neither TypeScript nor startup time.

The partition therefore becomes a **routing rule applied at write time** and a
**placement gate applied at build time**, rather than a projection of one store
into two.

**Invariants, asserted by `check:feed-partition`:**

- No `value` appears in both stores.
- The catalog contains no entry whose `type` is not `package`, and none
  carrying `campaign` or `family`. Those belong in the bundle by rules 1 and 2
  of section 4.2, so their presence in the catalog is a routing bug.
- Every catalog line parses as a `FeedIOC` and passes `isValidFeedIOC`.

The gate is what makes placement checkable without a single generated source,
and it fails the build rather than warning.

### 4.2 Partition policy, and why the cutoff is a committed date

An entry stays in the bundle when any of the following holds:

1. Its `type` is not `package`. Atomic indicators (ip, domain, url, hash) are
   few, high value and cheap. All stay bundled.
2. It carries a `campaign` or `family` field. These are curated, hand-reviewed
   campaign entries, the intelligence a database cannot supply.
3. **It sits beneath a curated comment block in `src/threat-intel.ts`**, meaning
   a comment run that is not an importer batch header. Migration-time only; see
   below.
4. Its `firstSeen` is on or after `BUNDLE_CUTOFF_DATE`.

**Rule 3 exists because rule 2 does not actually capture what "curated" means
here.** Curation in this repository is expressed in COMMENTS, not in fields.
Measured on the v6.1.3 feed: 1,094 entries sit beneath a curated comment block,
and 60 of them carry no `campaign` or `family` field at all. `lotusbail` has a
fourteen-line rationale about a credential-theft campaign and no `campaign:`
field; the two `dakumangalsingh` pins have a seven-line comment explaining why
they had to be added by hand. Under rules 1, 2 and 4 alone, those entries move to
the catalog and their rationale is orphaned in a file that no longer contains
what it describes.

Rule 3 is evaluated only by the Phase 2 migration, because only the migration
moves entries that a human already authored. The importer never needs it: its
own output is written beneath an importer batch header, which rule 3 explicitly
does not match. So `partitionTarget()` stays a pure function of the entry, and
the migration applies rule 3 on top from its own parse of the file.

The cost is negligible and was measured: with rule 3 in force, 11,998 entries
move instead of 12,002. Four entries stay bundled so that three curated comment
blocks keep the entries they describe.

Everything else is routed to the catalog. The rule is evaluated by the
importer when an entry is first written, by the Phase 2 migration when an
existing bundled entry is moved, and by `check:feed-partition` when validating
placement. One exported function, three callers.

`BUNDLE_CUTOFF_DATE` is an explicit ISO date committed in
`feed-partition.config.json`, **not** a rolling window measured from the current
date or the release date. A rolling window is not a pure function of committed
inputs: the generator and `check:feed` run during ordinary prebuilds, so the
same corpus would cross the cutoff on a later day, committed generated files
would drift without anyone editing them, and the byte-identical check that
Phase 1 depends on could not hold. The release date is also unavailable to a PR
gate, which runs before any tag exists.

Moving the cutoff is a deliberate, reviewable commit. `BUNDLE_CUTOFF_DATE`
starts earlier than every entry in the bundle, so rule 4 admits everything
already there and Phase 1 moves nothing. That is what lets Phase 1 prove itself
by leaving `src/threat-intel.ts` and `feed.json` untouched.

### 4.3 Catalog document, compression and bounded decompression

Same envelope as `feed.json` plus a discriminator:

```json
{
  "schema": 1,
  "kind": "catalog",
  "package": "supply-chain-guard",
  "version": "6.2.0",
  "entryCount": 56294,
  "generatedAt": "2026-09-16T00:00:00.000Z",
  "entries": [ ... ]
}
```

Published gzipped as `catalog.json.gz`.

**The current transport cannot consume this and must be extended.**
`refreshFeed()` calls `httpsGetBody()`, which calls `fetchHttpsBuffer()` and
immediately does `body.toString("utf-8")` before `JSON.parse`. There is no
decompression anywhere in `src/feed.ts` or `src/remote-download.ts`. A gzipped
asset fed to the existing path fails to parse every time, so the refresh would
never install a single historical indicator.

The design adds an explicit, bounded decompression step:

- Decompress with `gunzipSync(buf, { maxOutputLength: CATALOG_MAX_DECOMPRESSED_BYTES + 1 })`,
  reusing the exact pattern already used in `src/archive-extractor.ts`, which
  bounds expansion rather than trusting the header.
- `CATALOG_MAX_DECOMPRESSED_BYTES` starts at 64 MiB, roughly twice the projected
  150,000-entry raw size.
- Two independent bounds apply: `FEED_REMOTE_LIMITS.maxBytes` caps the
  downloaded bytes, and `maxOutputLength` caps the expansion. A decompression
  bomb fails the second even when it passes the first.
- Both failures are fail-closed: the previous cache and the bundled feed stay in
  effect and the missing-catalog finding fires.

`parseFeedPayload()` gains a `kind` check so a bundle cannot be accepted as a
catalog or the reverse.

**An empty catalog is valid, but only for `kind: "catalog"`.**
`parseFeedPayload()` currently throws on `entries.length === 0`. That is correct
for a bundle feed, where empty means something broke, and wrong for a catalog,
where empty is the legitimate Phase 1 state. Without this the Phase 1 catalog is
rejected by the very parser that is supposed to accept it, leaving
`THREAT_FEED_CATALOG_MISSING` firing after a successful refresh and making
`catalog: "required"` unsatisfiable. The relaxation is scoped to the catalog kind
and tested in both directions.

### 4.4 Hosting, version pinning and integrity

The catalog is published as a GitHub Release asset on the release tag by the
existing `Create GitHub Release` job, which already holds `contents: write` and
reaches GitHub through `gh`. One extra argument on the existing
`gh release create` call: no new workflow, no new credential.

**The catalog is pinned to the installed package version, not to `latest`.**
A client requests the asset for its own version and refuses anything else.

**Integrity does not rest on release-asset immutability.** The first draft
claimed assets are immutable per tag. That is false for this repository as
configured: `immutable_releases` is `null` and no ruleset enables it, and
`gh release upload --clobber` can delete and replace an asset on an existing
tag. Enabling the setting would help but is external state this design cannot
assert.

Instead, `scripts/generate-catalog.mjs` computes the catalog's SHA-256 and writes
it into `src/catalog-digest.ts`, a generated and committed TypeScript constant
that compiles into the published package. The client verifies the downloaded
catalog against it before parsing. The anchor is therefore the immutable npm
artifact and the tagged git tree, not a mutable release asset. A replaced asset
fails verification, is discarded, and the finding fires.

**A constant rather than a JSON file read at runtime.** Three reasons, none of
them portability:

1. `loadThreatIntel()` is on the hot path of every scan and already performs a
   `stat` and a read for each cache file. A constant costs nothing at runtime.
2. It is typechecked and cannot drift into a shape the caller does not expect.
3. It gives `refreshFeed()` the version to request. That function has no version
   parameter and no access to `package.json`, so without the constant the
   version-pinned catalog URL could not be built at all.

An earlier revision justified this differently and wrongly, claiming
`__dirname` is undefined under vitest and citing the defensive comment at
`src/mcp-server.ts:59`. That was asserted from a comment rather than measured.
Measured: this package has no `"type": "module"`, vitest transforms the sources
to CommonJS, and `__dirname` is a defined string there. A JSON file located
relative to `__dirname` would have worked. The constant is still the better
design for the three reasons above, but it was not rescuing a broken one.

Staleness is gated: `check:catalog` regenerates the constant and fails the build
if the committed copy differs, so a digest can never drift from the catalog it
describes.

**Repository release immutability is enabled as well**, as defence in depth
rather than as a dependency.

Immutable releases are a dedicated GitHub feature with their own endpoints, not
a field on the repository object:

```bash
gh api repos/homeofe/supply-chain-guard/immutable-releases            # read
gh api -X PUT repos/homeofe/supply-chain-guard/immutable-releases     # enable
gh api -X DELETE repos/homeofe/supply-chain-guard/immutable-releases  # disable
```

The read returns `{"enabled": bool, "enforced_by_owner": bool}`. Enabled on
2026-09-16; it now reads `{"enabled": true, "enforced_by_owner": false}`.

An earlier revision of this document instructed
`gh api -X PATCH repos/{owner}/{repo} -f immutable_releases=true` and verified it
with `--jq .immutable_releases` on the repository object. Both were wrong in the
same direction, which is why they agreed with each other. No such field exists
on that object, so `PATCH` silently ignored it and the check returned `null` for
a key that is simply absent. The setting was never enabled, and the verification
could not have told anyone: a bad command and a bad check that confirm each
other look exactly like a working system. This is the third absence-read-as-a-
value error in this document, recorded as entries 9, 14 and 15 in section 11.

**It does not retrofit.** Immutability is stamped per release at creation time:
`GET /repos/{owner}/{repo}/releases/tags/{tag}` carries an `immutable` boolean,
measured `false` for v6.1.1, v6.1.2 and v6.1.3. Those stay mutable forever, so
on any release published before 2026-09-16 the shipped digest is the catalog's
only protection.

Two consequences this design takes seriously:

1. The shipped digest is not belt-and-braces on the current release, it is the
   only protection the catalog has there.
2. Phase 2 asserts `immutable == true` on the first release published after the
   setting change, because a setting nobody verified is a setting nobody has.

### 4.5 Cache, merge, and what counts as unavailable

A second cache file, `threat-catalog.json`, beside the existing
`threat-feed.json`. It records the catalog `version`, its `sha256` and the fetch
timestamp alongside the entries.

`loadThreatIntel()` merges bundle, then feed cache, then catalog cache, through
the same `isValidFeedIOC` and `normalizeFeedIOC` quarantine the feed cache
already passes, because cached remote data reaches the per-file scan loop.

**A readable cache is not a usable cache.** The catalog counts as unavailable,
and the finding fires, when any of these holds:

- the cache file is absent, unreadable or unparsable;
- its recorded `version` does not equal the installed package version;
- its recorded `sha256` does not equal `CATALOG_DIGEST.sha256`.

The version check is what closes the hole the first draft left open. After an
upgrade, or after a refresh where the bundle succeeded and the catalog fetch
failed, a previous release's catalog stays readable on disk. A finding that
fired only on an absent file would let `catalog: "required"` pass while the
cached catalog silently omits every historical indicator added since. Nor can
`THREAT_FEED_STALE` catch it: that rule reads the newest `firstSeen` across the
merged feed, and the recent bundled entries keep that date current no matter how
old the catalog is.

`scg feed refresh` fetches both documents. One verb, no new subcommand.

The memo key in `loadThreatIntel()` extends to cover the catalog cache identity,
so a refreshed catalog is observed rather than served from a stale memo.

### 4.6 The corpus must be exempt from the repository self-scan

`data/threat-catalog.jsonl` will contain tens of thousands of raw malicious
package names, and in future possibly other raw indicator values. The scanner runs against its own repository
in CI, and the corpus is ordinary repository content to it:

- `collectFiles()` does not exclude `data/`.
- `isInertThreatFeedFile()` accepts only the basenames `feed.json` and
  `threat-feed.json`, and requires a JSON object with an `entries` array. A
  JSONL file is neither.
- `src/self-scan-files.json` is a source-file allowlist and lists no data path.

Left alone, Phase 1 would drown the self-scan in criticals from the project's
own detection data and block the gate. This is not hypothetical: the comment on
`isInertThreatFeedFile()` records the v5.4.0 dogfooding find of 169 findings on
this repository's own `feed.json`, which is why the function exists.

The design adds `isInertThreatCatalogFile(filename, content)` with strictness
equal to the existing check, sharing its constants so the two cannot drift:

- basename must be `threat-catalog.jsonl`;
- every non-empty line must parse as a JSON object;
- every key on every line must be in `FEED_ENTRY_KEYS`;
- every value must be an inert scalar (string or number).

Any deviation means the file is scanned like everything else. An exact-hash
allowlist entry was rejected as the alternative: the catalog changes on every
import, so the hash would be updated reflexively and would stop being a check.


### 4.7 The catalog is a public artifact and is gated as one

The catalog is a new file published to the open internet under the project's
name. Everything in it is derived from public advisory databases, but "derived
from public sources" is an intention, not a guarantee, and the release step is
the last point where it can be checked.

`check:catalog` therefore refuses to build a catalog carrying anything that is
not public advisory data. The check is entirely STRUCTURAL:

- no entry may carry a key outside `FEED_ENTRY_KEYS`;
- no entry may carry the free-text `note` field at all. The catalog is
  machine-written and never needs prose, and prose is the only place an internal
  detail could realistically travel. Banning the field is closed and checkable;
  validating its contents would not be;
- no `value` or `source` may match a private-infrastructure shape: an RFC1918,
  loopback or link-local address, a `.local`, `.internal`, `.lan`, `.corp` or
  `.home` host, or a local filesystem path such as `C:\Users\...` or `/home/...`.

**An earlier revision of this section also required every entry to carry a
`source` naming a public vendor from a list. That was measured against the
shipped feed and rejected**: 514 of 20,969 entries would have failed it, 465 of
them because they carry no `source` at all, and the rest because the list did not
happen to name Datadog, Unit 42, Sonatype, Corgea and others. It is the failure
this project already has written down: the moment a check judges a value it has
to enumerate spellings, and the next spelling walks past. Worse, it would have
failed the build on legitimate data, which is how a gate gets switched off.

The structural form was measured the same way: 14 of 14 genuinely private
control values are caught, there are zero false positives against real public
IOCs (including `172.15.0.1` and `172.32.0.1` either side of the RFC1918 range),
and across all 20,969 shipped entries and all 12,002 that a 30-day cutoff would
route to the catalog it reports zero violations. It gates without breaking
anything that exists.

**The check matches shapes, and deliberately contains no list of the
organization's own hostnames or repository names.** Embedding such a list in a
public repository would publish exactly the information the check exists to keep
unpublished, and the check would then leak more than it caught. Shape matching
needs no secrets to work: a `10.x` address or a `.internal` host is recognizable
without knowing whose it is.

A violation fails the build and names the offending line number, not the value,
for the same reason.

This is cheap, it runs on every build rather than only at release, and it makes
"no internal data in the public artifact" a property the repository enforces
rather than a habit the maintainer has to remember.

The same rule already governs the bundled feed by convention. The difference is
that the bundle is reviewed line by line in pull requests, while the catalog is
machine-written in bulk and nobody will read 56,294 lines.

### 4.8 The catalog has a ceiling, and the build refuses to cross it

`CATALOG_MAX_DECOMPRESSED_BYTES` is 64 MiB. Measured against the real feed at
165 serialized bytes per entry, that is a hard ceiling of about **406,000
entries**, and it binds long before the 32 MiB download cap does, which at the
measured 10.1 percent gzip ratio would allow about 2 million.

| state | entries | raw | gzip | share of the cap |
| --- | --- | --- | --- | --- |
| after Phase 3 | 68,292 | 10.7 MB | 1.08 MB | 17 percent |
| alphabet walk complete | ~150,000 | 23.6 MB | 2.37 MB | 37 percent |
| double that | 300,000 | 47.2 MB | 4.75 MB | 74 percent |

**The cap is a compatibility floor, not a tunable.** It is compiled into every
released client. Raising it in a future version does nothing for the clients
already installed, so a catalog that outgrows 64 MiB is not fixable by editing a
constant: it would simply fail to install for everyone on an older release, and
those users cannot be reached.

So the generator gates on it. `check:catalog` fails the build when the
serialized catalog exceeds `CATALOG_SIZE_BUDGET`, set at 48 MiB, roughly 305,000
entries and 75 percent of the floor. Crossing that budget is the signal to shard
the catalog into per-prefix documents, which is a real design change, and the
budget exists so that change is made deliberately with 25 percent of headroom
left rather than discovered by a user whose refresh stopped working.

A maintainer can never ship a catalog this project's own clients cannot read,
because the build will not produce one.

## 5. Failure semantics: the loud part

`THREAT_FEED_CATALOG_MISSING` is emitted on every scan where the catalog is
unavailable by any of the four conditions in section 4.5. It follows the
`THREAT_FEED_STALE` shape exactly: `category: "trust"`, `confidence: 1.0`, a
description naming the number of indicators not consulted and the reason
(absent, version mismatch, digest mismatch), and a recommendation naming the
command that fixes it.

### 5.1 Severity follows the state, never the clock

The measured defaults this has to live with: the CLI fails at `high`
(`src/cli.ts:73`), and the Action fails at `critical` (`action.yml:43`). So
`medium` breaks nobody, `high` stops a developer's CLI run, and `critical` stops
a CI pipeline.

| state | severity | why |
| --- | --- | --- |
| absent | `medium` | A fresh install that has not run `feed refresh` yet. Legitimate, extremely common, and self-correcting. Breaking it would punish first use. |
| version mismatch | `medium` | The user upgraded and has not refreshed. Normal, expected after every release, self-correcting. |
| unreadable | `medium` | Corrupt or truncated cache. The remedy is the same one command. |
| digest mismatch | `high` | Never a normal state. The catalog's bytes do not match what this release expects, which is either corruption or tampering with the scanner's own detection data. |

Under `catalog: "required"` every unavailable state becomes `critical` and fails
the gate, for consumers who want the guarantee rather than the signal.

**There is no time-based escalation, and this is a decision rather than an
omission.** A severity that rises because thirty days passed answers "how long
has this been true" when the question is "what is wrong". That is exactly the
guard-answers-a-different-question failure this project produces most often, and
it would make a build's outcome depend on the calendar rather than on its own
configuration, which is the opposite of working properly every time. A tool used
by strangers must be predictable: the same repository, the same package version
and the same policy produce the same verdict today and in six months.

The digest-mismatch case is the one place the severity does rise, because the
STATE is different rather than because time passed. For a security scanner,
detection data that fails verification is a finding in its own right.

**The same principle settles the companion question about stale rule sets.**
`THREAT_FEED_STALE` keeps its severity too. Enforcement belongs in policy, where
the consumer declares what they need, not in a timer that decides for them.

## 6. The durable fix: a size budget with a gate

This problem exists because no step in any workflow owned the feed's size, so it
grew until one upstream event made it a crisis.

A prebuild gate, `check:feed-budget`, fails the build when either bound is
exceeded:

- bundled entries greater than `MAX_BUNDLED_ENTRIES`
- generated `src/threat-intel.ts` larger than `MAX_BUNDLE_BYTES`

A release that would breach the budget cannot be built; the fix is to move
`BUNDLE_CUTOFF_DATE` forward and regenerate. Without this gate the split merely
resets the clock.

### 6.1 The values, chosen from the measured distribution

The 90-day cutoff proposed in the first draft was checked against the actual
feed before being adopted, and it does almost nothing. Measured on the v6.1.3
feed, 20,969 entries, with the release date as the reference point:

| cutoff | bundle | catalog | import |
| --- | --- | --- | --- |
| 30 days | 8,967 | 12,002 | ~32 ms |
| 60 days | 20,625 | 344 | ~74 ms |
| 90 days | 20,846 | 123 | ~75 ms |
| 180 days | 20,947 | 22 | ~75 ms |

These figures are the DATE rule alone, which is what the cutoff has to be
chosen against. The comment anchor in section 4.2 then holds four of them
back, so the actual Phase 2 result at 30 days is 8,971 bundled and 11,998
moved, not 8,967 and 12,002. The two are consistent; the table is the input to
the decision and section 4.2 is the outcome.

At 90 days the split moves 123 entries and changes nothing. The feed is
recent-skewed because the daily importer has been running, and there is a cliff
between 30 and 60 days.

Of the 20,969 entries, 1,048 are non-package or curated and stay bundled under
rules 1 and 2 regardless of any date. Zero plain package entries are undated, so
the fail-safe branch is currently empty.

**Decided values:**

- `BUNDLE_CUTOFF_DATE`: **30 days before the release**. It is the only cutoff on
  the curve that does real work: the bundle drops to 8,967 entries, startup
  falls from 75 ms to about 32 ms on every invocation, and the package roughly
  halves, which every Action run pays for since `action.yml` installs the
  package at runtime. The offline default still carries every atomic indicator,
  every curated campaign, and a month of fresh package intelligence, which is
  the part most likely to be in a lockfile someone is scanning today.
- `MAX_BUNDLED_ENTRIES`: **15,000**. Roughly 65 percent headroom above the 8,967
  the cutoff produces, which at the observed daily volume of 26 to 450 new
  entries is several months of slack. Set well below today's 20,969 on purpose:
  the budget must be able to catch a cutoff that was not moved, and a limit
  above the unsplit size could never do that.
- `MAX_BUNDLE_BYTES`: **2 MiB**. The 8,967-entry bundle is about 1.6 MB, so this
  is the byte-side equivalent of the same headroom.

Both limits are deliberately reachable. A budget that can never be hit is not a
gate, and the point of this one is to force the cutoff conversation before the
feed becomes a problem rather than after.

Phase 1 sets the limits above the current unsplit size so the phase can land
without moving an indicator, and Phase 2 tightens them to the values above in
the same commit that moves the cutoff.

## 7. Migration

Ordered so coverage never silently drops, and so that no phase depends on a
state a later phase creates.

**Phase 1: build the catalog path, change nothing that is detected.**
`src/threat-intel.ts` and `feed.json` are not touched at all, which is how this
phase proves it changed nothing. Add `isInertThreatCatalogFile()` FIRST, before
an empty `data/threat-catalog.jsonl` is committed, or the self-scan gate blocks
the phase. Add the partition policy function, `check:feed-partition` and
`check:feed-budget` with limits above current size. Add bounded gzip
decompression, the `kind` check, the empty-catalog allowance, the digest file,
the second cache, the merge and the availability conditions. Add
`THREAT_FEED_CATALOG_MISSING` and the `catalog` policy knob. Publish an empty
catalog asset from CI. Detection is unchanged.

**Phase 2: make the partition finite and migrate.**
Move `BUNDLE_CUTOFF_DATE` forward to 30 days before the release, tighten the
budget to 15,000 entries and 2 MiB, and run a
migration script that moves every now-unqualifying bundle entry into the
catalog. The script must preserve the bundle's comments: a batch header comment
is removed only when every entry beneath it moved, and left intact otherwise, so
no rationale is orphaned or silently deleted. This is the only step that reduces
what a bare install detects, and it lands after the finding that reports it.
Measure and record the resulting bundle size and import time, then tighten the
budget to the new size.

**Phase 3: drain the deferrals.**
Import all five ranges with explicit `--since`/`--until` slices. Because the
cutoff is now finite and these entries are `package` type with no campaign and a
`firstSeen` far older than the cutoff, the importer's routing rule sends every
one of them to `data/threat-catalog.jsonl`. The bundle does not grow.
`threat-feed-deferred.json` empties and the 56,294 indicator gap closes for any
consumer who has refreshed.

The first draft had this phase before the cutoff was made finite, where every
deferred entry would have satisfied rule 4, landed in the bundle, and breached
the budget immediately.

**Phase 4: retire the deferral mechanism for bulk waves.**
With a catalog that absorbs volume, a future alphabet wave is an ordinary
import. The deferral machinery stays for genuinely undecidable blocks but should
no longer be reached for size alone.

## 8. Testing

A guard is proved by cutting it, never by reading it, with a clean baseline
before and after.

- **Partition placement gate.** Assert no value appears in both stores, and that
  no catalog line is a non-package type or carries `campaign`/`family`. Cut:
  plant a duplicate value in both stores, then a campaign entry in the catalog,
  and watch each go red for its own reason.
- **Partition determinism.** Generate twice with the system clock moved a year
  forward between runs; assert byte-identical output. Cut: reintroduce a
  now-relative cutoff and watch it go red.
- **Budget gate.** Cut in both directions: a corpus one entry over each limit
  fails for that specific reason, and one entry under passes.
- **Self-scan inertness.** A well-formed catalog produces no findings. Cut: a
  catalog line with a key outside `FEED_ENTRY_KEYS`, one with a non-scalar
  value, and one under a different basename each fall back to being scanned.
- **Comment preservation.** After the Phase 2 migration, assert every comment
  line still in `src/threat-intel.ts` sits above at least one surviving entry,
  and that the count of curated comment lines did not drop except for batch
  headers whose entries all moved.
- **Missing-catalog finding.** Fires with no cache; fires with a cache whose
  version does not match; fires with a cache whose digest does not match; does
  not fire with a valid cache. Under `required` the severity is `critical` and
  the gate fails.
- **Bounded decompression.** A valid gzip catalog parses. A gzip bomb exceeding
  `CATALOG_MAX_DECOMPRESSED_BYTES` is refused, leaves the previous cache in
  effect and fires the finding.
- **Empty catalog.** Accepted for `kind: "catalog"`, still rejected for a bundle
  feed.
- **Envelope confusion.** A bundle offered as a catalog, and the reverse, are
  both rejected by the `kind` check.
- **Catalog detection parity.** Sample names from the drained deferral ranges;
  assert they are NOT detected without the catalog and ARE detected with it.
  This is the test that proves the split preserved coverage.

Per the project's Windows constraint, only the suites covering the change run
locally; CI produces the full-suite verdict.

## 9. Non-goals

- Changing what counts as malicious, or any severity beyond the two named.
- Reworking the importer's discovery adapters or its decline policy.
- Liveness filtering of holding packages. Still available as a corpus-shrinking
  tactic, but unnecessary once volume no longer lands in the bundle, and it
  would discard indicators a future republish could make live again.
- The 2.76 MB `dist/threat-intel.js.map` shipped in the package. It is 28
  percent of unpacked size and is a source map for a data array, so probably
  removable, but that is an adjacent packaging question.

## 10. Decisions

Every question this design opened is now closed. They are recorded here with
their reasons, because a stranger reading the repository should be able to see
why a security tool behaves the way it does without reconstructing it.

1. **Severity follows the state, not the clock.** `medium` for absent, version
   mismatch and unreadable; `high` for digest mismatch; `critical` for any of
   them under `catalog: "required"`. No time-based escalation, here or for
   `THREAT_FEED_STALE`. Full reasoning in section 5.1. The short version: the
   same repository, package version and policy must produce the same verdict in
   six months as today, and a clock-driven severity breaks that for everyone at
   once.
2. **Repository release immutability is enabled**, as defence in depth rather
   than as a dependency. It has its own endpoints
   (`/repos/{owner}/{repo}/immutable-releases`), not a field on the repository
   object, and it now reads `{"enabled": true}`. It does not retrofit: v6.1.1
   through v6.1.3 are `immutable: false` permanently, so on those the shipped
   digest is the catalog's only protection. Section 4.4.
3. **`BUNDLE_CUTOFF_DATE` is 30 days, `MAX_BUNDLED_ENTRIES` is 15,000 and
   `MAX_BUNDLE_BYTES` is 2 MiB.** Chosen from the measured distribution in
   section 6.1, not from round numbers: at the originally proposed 90 days the
   split would have moved 123 of 20,969 entries and accomplished nothing.
4. **The catalog resolves to the installed version, never to `latest`**, which
   is what makes the digest check and the version-mismatch state possible at
   all. Section 4.4.
5. **The published catalog is gated as a public artifact** (section 4.7): every
   entry must carry public advisory provenance, and no value may match
   private-infrastructure shapes. The build fails otherwise.

What remains genuinely open is not a decision but a measurement: Phase 2's real
bundle size and import time. Those are recorded when Phase 2 lands, and the
Phase 3 and 4 plans are written against the measured numbers rather than the
projections in section 6.1.

## 11. Review corrections

The first draft was reviewed and seven defects were found. All were verified
against the source before being accepted, and all are fixed above. They are
recorded because six of the seven are a guard or a claim that reads correct and
answers a different question, which is this project's most common defect class.

| # | Defect | Fix |
| --- | --- | --- |
| 1 | Phase ordering: the backlog drain ran while the cutoff was still infinite, so every deferred entry would have landed in the bundle and breached the budget | Phases 2 and 3 swapped; the cutoff is finite before the drain |
| 2 | No decompression exists anywhere in the refresh path, so a `.gz` asset could never parse | Bounded `gunzipSync` with `maxOutputLength`, section 4.3 |
| 3 | `parseFeedPayload()` rejects an empty `entries` array, so the Phase 1 empty catalog was unusable | Empty allowed for `kind: "catalog"` only |
| 4 | Release assets were claimed immutable; `immutable_releases` is `null` on this repository and `--clobber` can replace them | Integrity anchored to a SHA-256 shipped in the npm package |
| 5 | The finding fired only on an absent file, so a previous release's catalog silently satisfied `catalog: "required"` | Version and digest mismatch also count as unavailable |
| 6 | The cutoff was relative to the release date, which is not a committed input and is unavailable to a PR gate, so generated files would drift | `BUNDLE_CUTOFF_DATE` is a committed ISO date |
| 7 | The committed catalog would be scanned as ordinary content and flood the self-scan, blocking Phase 1 | `isInertThreatCatalogFile()`, sharing the existing allowlist constants |
| 8 | Regenerating `src/threat-intel.ts` from a JSONL corpus would delete the 792 curated comment lines inside the feed chunks, and the byte-identical Phase 1 check could never pass. Found while writing the implementation plan, not in review | Two authored stores instead of one generated store, section 4.1; placement enforced by a gate rather than by regeneration |
| 9 | NOT A DEFECT, and recorded because the claim was published before it was measured. The digest was moved from a JSON file to a generated constant on the stated grounds that `__dirname` is undefined under vitest. Measured afterwards: it is a defined string, because this package is CommonJS. The change stands on its real merits (no read on the hot path, typechecked, supplies the version for fix 11) but the original reason was false | Rationale corrected in section 4.4; the design is unchanged |
| 10 | `policy.catalog` was added to `policy-schema.json` only; `tsc` would have failed because `PolicyConfig` in `src/types.ts` has no such field | The field is added to both |
| 11 | `refreshFeed()` has no version in scope, so the version-pinned catalog URL could not be built | `CATALOG_DIGEST.version` supplies it, from the same generated constant as fix 9 |
| 12 | `src/threat-intel.ts` and `src/scanner.ts` are listed in `src/self-scan-files.json`, so `check:self-scan` turns red on nearly every task and would block each commit | Every affected task regenerates and commits `self-scan-manifest.json` |
| 13 | The partition treated `campaign`/`family` as the definition of "curated", but curation here lives in COMMENTS. 60 of 1,094 comment-anchored entries carry no such field, so their rationale would have been orphaned as they aged past the cutoff | Rule 3 in section 4.2: an entry beneath a curated comment block is immovable. Found while planning Phase 2 |
| 14 | The claim that release immutability was off rested on `immutable_releases` reading `null`, which actually means the repo API does not expose the field at all. Absence was read as a value, which is the same mistake as entry 9 | Verified per release instead: `immutable` is a real field on the release object, and it is `false` on v6.1.1 through v6.1.3. Phase 2 asserts it on the next release |
| 15 | The command given for enabling immutability, `PATCH /repos/{owner}/{repo} -f immutable_releases=true`, addressed a field that does not exist. GitHub ignored it silently, the setting was never enabled, and the verification in entry 14 could not detect that because it read the same non-existent field. A wrong command and a wrong check agreed with each other and looked like a working system | The feature has dedicated endpoints: `GET`, `PUT` and `DELETE` on `/repos/{owner}/{repo}/immutable-releases`, returning `{"enabled", "enforced_by_owner"}`. Enabled and verified `true` on 2026-09-16 |

Defects 10 to 12 were found by re-auditing the design against the code before
merging, after the review had already been addressed. All three are the same
failure: a design that named a mechanism without checking how this repository
actually implements it.

Entry 9 is the same failure pointing the other way, and is the most useful line
in this table. The re-audit produced a confident claim about `__dirname`, sourced
from a code comment, and it went into this document before anyone ran it. It
survived one revision. It was caught only because the claim was measured before
merge, which is the rule this project already writes down: a surprising
measurement gets re-measured before it is published. A design document is not
exempt from that just because it contains no code.

## 12. Durability: what is settled, and what could still change

This design is meant to hold for every future release without revisiting. What
follows is an honest account of what that does and does not mean.

### Settled, and not expected to change again

- **Two authored stores, partition by routing, placement by gate.** The bundle
  is authored as it always was; only the catalog is new. Nothing about this has
  to change as either store grows.
- **Integrity anchored to a digest compiled into the package.** Independent of
  release-asset immutability, which is enabled as defence in depth but is not
  load-bearing and does not retrofit.
- **Version-pinned catalogs.** What makes the digest check and the
  version-mismatch state possible at all.
- **Severity by state, never by clock.** The verdict a consumer gets is a
  function of their repository, their installed version and their policy, and
  nothing else. This is what makes the tool predictable for strangers.
- **Structural public-artifact hygiene.** Checks shape, never a list of values,
  so it cannot be walked past by a new spelling and needs no maintenance.
- **A budget gate on the bundle and a size gate on the catalog.** Both fail the
  build rather than warning, and both name the remedy.

### The one recurring manual step

`BUNDLE_CUTOFF_DATE` is a committed date and a release moves it forward. That is
deliberate: a clock-derived cutoff is not a pure function of committed inputs,
and a cutoff derived from the newest entry in the feed would make every daily
import silently evict older entries, turning the daily threat-intel pull into a
migration whose diff nobody could review. Review of those pull requests is a
security control here, so it is worth one committed value per release.

The step is bounded and self-announcing rather than remembered:
`check:feed-budget` fails the build when the bundle outgrows its limit, and it
prints the exact date to set. Forgetting it costs one failed build, roughly a
month after the fact at the observed arrival rate of 26 to 450 entries a day,
and the fix is a one-line commit.

### What would genuinely require a design change

1. **The catalog passing 305,000 entries** (section 4.8), which is about 4.5
   times the post-Phase-3 size. The answer then is sharding the catalog by name
   prefix, and `check:catalog` fails the build well before any user is affected.
2. **An upstream source that publishes something other than package identifiers
   in bulk.** The partition routes by `type`, and a flood of non-package IOCs
   would sit in the bundle by rule 1. That rule is correct today because atomic
   indicators are few and high value; if that stops being true the rule needs
   revisiting, and the bundle budget is what would surface it.
3. **A need to update a catalog between releases.** Catalogs are version-pinned,
   so today the answer is that anything urgent is recent, and recent entries are
   bundled anyway. If that stops being true, the catalog would need its own
   version line independent of the package.

None of these are reachable from the current trajectory without the build
failing first, which is the property that matters.

### A consequence worth stating plainly

A user who never upgrades keeps getting recent intelligence, because
`feed refresh` also refreshes the bundle feed, which is published from `main`
and is not version-pinned. What they stop getting is newly added HISTORICAL
indicators, because the catalog is pinned to their installed version. That split
is deliberate: recent intelligence is what protects a lockfile being installed
today, and it keeps flowing to old installs. Complete historical coverage is a
reason to upgrade, and `THREAT_FEED_STALE` already tells them when their rule set
has aged.
