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
3. Its `firstSeen` is on or after `BUNDLE_CUTOFF_DATE`.

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
starts earlier than every entry in the bundle, so rule 3 admits everything
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

## 5. Failure semantics: the loud part

`THREAT_FEED_CATALOG_MISSING` is emitted on every scan where the catalog is
unavailable by any of the four conditions in section 4.5. It follows the
`THREAT_FEED_STALE` shape exactly: `category: "trust"`, `confidence: 1.0`, a
description naming the number of indicators not consulted and the reason
(absent, version mismatch, digest mismatch), and a recommendation naming the
command that fixes it.

**Severity is `medium` by default, deliberately.** Shipping at `high` would turn
every existing consumer's default gate red on upgrade day for a condition they
did not cause. That is the reasoning already recorded for `THREAT_FEED_STALE`,
which chose `medium` so the condition is visible in the score, the risk level
and eight of nine report formats without failing a `fail-on: critical` or
`fail-on: high` build.

For consumers who want the guarantee rather than the signal, policy gains
`catalog: "optional" | "required"`. Under `required` a missing, mismatched or
unverifiable catalog is a `critical` finding and fails the gate.

Escalating the default is left as an owner decision, recorded with the existing
open question about whether a badly stale rule set should fail the build.

## 6. The durable fix: a size budget with a gate

This problem exists because no step in any workflow owned the feed's size, so it
grew until one upstream event made it a crisis.

A fifth prebuild gate, `check:feed-budget`, fails the build when either bound is
exceeded:

- bundled entries greater than `MAX_BUNDLED_ENTRIES` (initially 25,000)
- generated `src/threat-intel.ts` larger than `MAX_BUNDLE_BYTES` (initially 4 MB)

A release that would breach the budget cannot be built; the fix is to move
`BUNDLE_CUTOFF_DATE` forward and regenerate. Without this gate the split merely
resets the clock.

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
Move `BUNDLE_CUTOFF_DATE` forward to 90 days before the release and run a
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
deferred entry would have satisfied rule 3, landed in the bundle, and breached
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

## 10. Open questions for the owner

1. **Should `THREAT_FEED_CATALOG_MISSING` escalate to `high` after a grace
   period, and should a badly stale rule set fail the build?** The same question
   twice; they should be decided together.
2. **Should repository release immutability be enabled anyway?** The digest
   check in section 4.4 makes the design not depend on it, but enabling it is
   cheap defence in depth for every other asset.
3. **Initial values for `MAX_BUNDLED_ENTRIES`, `MAX_BUNDLE_BYTES` and the Phase
   2 `BUNDLE_CUTOFF_DATE`.** The proposed 25,000 / 4 MB / 90 days keeps the
   bundle near its current size and its import near 75 ms.

The first draft's question about resolving the catalog to `latest` is closed:
section 4.4 pins it to the installed version, which is what makes the digest
check and the version-mismatch condition possible.

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
