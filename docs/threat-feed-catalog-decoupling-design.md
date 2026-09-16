# Threat-feed catalog decoupling

Design for resolving the bulk-migration deferral backlog by splitting the threat
feed into a compiled-in bundle and a downloadable historical catalog, with an
explicit finding whenever the catalog is absent.

Status: design approved, not yet implemented.
Date: 2026-09-16.
Supersedes the Tier 3 sketch in `docs/threat-feed-bulk-backfill-strategy.md`.

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
these packages and found 28 of them still installable on npm today.

Three properties make this hard to resolve by importing the block:

1. **It is not a fixed quantity.** The waves are an alphabet walk currently at
   `j`, and the remainder of `f` was skipped rather than completed. More is
   arriving. Any fix that treats 56,294 as the total will be re-litigated.
2. **The bundle pays the cost on every invocation.** The feed is compiled into
   `dist/threat-intel.js` and imported by the CLI on every run.
3. **Declining is not available.** The block spans roughly 1,189 distinct name
   tokens across unrelated malware families, so no anchored rule in
   `src/patterns.ts` covers it, and `coveredBy` cannot be satisfied honestly.

## 2. Measurements

Every number below was measured on 2026-09-16 against the v6.1.3 tree, not
estimated. Import cost was measured by generating synthetic feed modules shaped
like the real chunked array literal and timing `require()`.

### Import cost scales linearly at about 3.5 microseconds per entry

| feed entries | module import | generated source |
| --- | --- | --- |
| 20,969 (today) | 75 ms | 3.3 MB |
| 40,000 | 143 ms | 6.4 MB |
| 77,263 (today plus the backlog) | 266 ms | 12.3 MB |
| 150,000 (alphabet walk completed) | 527 ms | 24.1 MB |

This cost is paid on every CLI invocation, because the feed is a module-level
array literal that the runtime must parse before anything else happens.

### Package size

The published package is 1.30 MB packed and 9.91 MB unpacked, of which
`dist/threat-intel.js` is 3.56 MB and its source map a further 2.76 MB.
`action.yml` is a composite action that runs `npm install -g supply-chain-guard`
at runtime, so package size is paid by every Action run rather than once per
developer machine.

Absorbing the backlog into the bundle takes the package to roughly 19 MB
unpacked; completing the alphabet walk takes it to roughly 31 MB.

### Compression

`feed.json` is 4.63 MB raw, 0.34 MB gzip -9 (7.3 percent), 0.27 MB brotli.
Projecting the same ratio:

| catalog size | raw | gzip |
| --- | --- | --- |
| 56,294 entries | 12.44 MB | 0.91 MB |
| 150,000 entries | 33.14 MB | 2.42 MB |

A 150,000-entry catalog transfers in about 2.4 MB, comfortably inside the
existing `FEED_REMOTE_LIMITS.maxBytes` of 32 MiB.

### The decoupling machinery already exists and is wired to itself

`refreshFeed()`, `parseFeedPayload()`, the cache merge in `loadThreatIntel()`,
`FEED_REMOTE_LIMITS` and the `THREAT_FEED_STALE` finding are all built and
tested. But `DEFAULT_FEED_URL` resolves to `feed.json` on `main`, which is the
same document that is compiled into the bundle. A refresh today re-fetches what
the caller already has. Splitting the two documents is a generation and
publishing change, not new transport infrastructure.

## 3. Decision

Ship a two-tier feed in which the historical corpus is downloaded rather than
compiled in, and make its absence an explicit finding on every scan.

The alternative of keeping absolute offline parity was rejected: at 150,000
entries it costs half a second of startup per invocation and a 31 MB global
install on every Action run, and no amount of liveness filtering brings a
corpus of that shape back under a sane budget when more than half of it is
live.

The variant where the catalog is simply optional and silent was also rejected.
A scanner that quietly answers a narrower question than the caller believes it
is asking is the failure mode this project treats as unacceptable, and it is
precisely the class of defect that `THREAT_FEED_STALE` already exists to
prevent for a different cause.

## 4. Architecture

Two published documents, one partition, one source of truth.

```text
data/threat-corpus.jsonl            <- source of truth, all entries, not compiled
        |
        | scripts/generate-feed.mjs applies the partition policy
        |
        +--> src/threat-intel.ts FEED_CHUNK_n   (generated, committed, typechecked)
        |         |
        |         +--> dist/threat-intel.js     (compiled into the package)
        |         +--> feed.json                (published bundle document)
        |
        +--> catalog.json.gz                     (published release asset)
```

### 4.1 Source of truth moves out of TypeScript

Today `src/threat-intel.ts` is the source of truth and `feed.json` is derived
from it. That cannot hold once the corpus exceeds what should be compiled,
because the source of truth would itself be the thing we are trying not to
compile.

The corpus moves to `data/threat-corpus.jsonl`, one `FeedIOC` per line. The
bundle chunks in `src/threat-intel.ts` become generated output, committed and
typechecked exactly as now, so nothing about review, diffing or the existing
gates changes for the entries that remain bundled.

This makes the partition invariant structural rather than a matter of
discipline. Both documents come from one array and one policy function, so an
entry cannot be in both, and cannot be in neither.

**Invariants, asserted by gate:**

- `bundle` union `catalog` equals the corpus, with no entry lost.
- `bundle` intersect `catalog` is empty.
- Both are generated from `data/threat-corpus.jsonl` by a single pure function.

### 4.2 Partition policy

An entry stays in the bundle when any of the following holds:

1. Its `type` is not `package`. Atomic indicators (ip, domain, url, hash) are
   few, high value, and cheap. All of them stay bundled.
2. It carries a `campaign` or `family` field. These are curated, hand-reviewed
   campaign entries, which is the intelligence a database cannot supply.
3. Its `firstSeen` is within `BUNDLE_RECENT_DAYS` of the release date.

Everything else goes to the catalog.

The policy is a single exported function so the gate, the generator and the
tests all consult the same rule. `BUNDLE_RECENT_DAYS` is the tuning knob when
the budget in section 6 is threatened.

`BUNDLE_RECENT_DAYS` starts at `Infinity`, which makes rule 3 admit every
existing entry and the partition a no-op. That is what lets Phase 1 prove
itself by producing byte-identical output. Phase 3 is the moment it takes a
finite value, and that is the only change in this design that reduces what a
bare install detects.

### 4.3 Catalog document

Same envelope as `feed.json`, with a discriminator:

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

Published gzipped as `catalog.json.gz`. `parseFeedPayload()` already accepts the
published envelope and a raw array; it gains a `kind` check so a catalog cannot
be mistaken for a bundle or the reverse.

### 4.4 Hosting

A GitHub Release asset on the release tag, uploaded by the existing
`Create GitHub Release` job, which already holds `contents: write` and reaches
GitHub through `gh`. One extra argument on the existing `gh release create`
call, no new workflow and no new credential.

Release assets are immutable per tag, which matches the project's rule against
moving a published artifact. Clients resolve the asset for the `latest` release
by default and record the resolved version and timestamp in the cache, so a
scan can always say which catalog it matched against. `--catalog-url` overrides
for air-gapped mirrors.

Not `raw.githubusercontent.com`: a 2.4 MB document on a branch path is served
without the release's immutability guarantee, and the existing feed URL already
occupies that path.

### 4.5 Cache and merge

A second cache file, `threat-catalog.json`, beside the existing
`threat-feed.json`. `loadThreatIntel()` merges bundle, then feed cache, then
catalog cache, through the same `isValidFeedIOC` and `normalizeFeedIOC`
quarantine that the feed cache already passes through. Cached catalog data
reaches the per-file scan loop, so it gets the same treatment as any other
remote input.

`scg feed refresh` fetches both documents. One verb, no new subcommand, and an
existing consumer's muscle memory keeps working.

The memo key in `loadThreatIntel()` extends to cover the catalog cache's
identity, so a refreshed catalog is observed rather than served from a stale
memo.

## 5. Failure semantics: the loud part

A new finding, `THREAT_FEED_CATALOG_MISSING`, is emitted on every scan where
the catalog cache is absent or unreadable.

It follows the `THREAT_FEED_STALE` shape exactly: `category: "trust"`,
`confidence: 1.0`, a description that names the number of indicators that were
not consulted, and a recommendation naming the command that fixes it. Reusing
the shape matters, because consumers already know how to read and how to
exclude a trust finding by rule id.

**Severity is `medium` by default, and this is deliberate.** Shipping it at
`high` would turn every existing consumer's default gate red on upgrade day for
a condition they did not cause and had no chance to prepare for. That is the
same reasoning recorded for `THREAT_FEED_STALE`, which chose `medium` so the
condition is visible in the score, the risk level and eight of the nine report
formats without failing a `fail-on: critical` or `fail-on: high` build.

For consumers who want the guarantee rather than the signal, policy gains
`catalog: "optional" | "required"`. Under `required`, a missing catalog is a
`critical` finding and fails the gate. This is the knob that makes "loud"
enforceable without breaking anyone on the day it lands.

Escalating the default is left as an owner decision, recorded alongside the
existing open question about whether a badly stale rule set should fail the
build. The two questions have the same shape and should be answered together.

## 6. The durable fix: a size budget with a gate

The reason this problem exists is not that anyone chose a large feed. It is
that no step in any workflow owned the feed's size, so it grew until a single
upstream event made it a crisis.

A fifth prebuild gate, `check:feed-budget`, fails the build when either bound is
exceeded:

- bundled entries greater than `MAX_BUNDLED_ENTRIES` (initially 25,000)
- generated `src/threat-intel.ts` larger than `MAX_BUNDLE_BYTES` (initially 4 MB)

A release that would breach the budget cannot be built. The fix is to retune
`BUNDLE_RECENT_DAYS` and regenerate, which moves older entries to the catalog.
The budget is the mechanism that stops this recurring; without it the split
merely resets the clock.

Both limits live beside the partition policy and are asserted by the same
tests.

## 7. Migration

Ordered so that coverage never silently decreases. The loud finding ships
before anything leaves the bundle.

**Phase 1: split the pipeline, change nothing that is detected.**
Introduce `data/threat-corpus.jsonl` seeded from the current feed, generate the
bundle from it, and confirm byte-identical output for `src/threat-intel.ts` and
`feed.json`. Publish an empty catalog asset. Add `THREAT_FEED_CATALOG_MISSING`,
the `catalog` policy knob, the second cache and the merge. Add
`check:feed-budget` with limits set above current size so it passes.
Detection is unchanged; this phase is pure plumbing and is verifiable by the
generated files not moving.

**Phase 2: drain the deferrals into the catalog.**
Import all five ranges with explicit `--since`/`--until` slices, routing them to
the corpus. The partition policy sends them to the catalog, because they are
`package` entries with no campaign and a `firstSeen` older than the window.
The bundle does not grow. `threat-feed-deferred.json` empties, and the 56,294
indicator gap closes for any consumer who has refreshed.

**Phase 3: apply the policy to existing bundled entries.**
Set `BUNDLE_RECENT_DAYS` from `Infinity` to 90 and regenerate. Historical package entries
move out of the bundle into the catalog. This is the only step that reduces
what a bare install detects, and it lands after the finding that reports it.
Measure and record the resulting bundle size and import time.

**Phase 4: retire the deferral mechanism for bulk waves.**
With a catalog that absorbs volume, a future alphabet wave is an ordinary
import. The deferral machinery stays for genuinely undecidable blocks, but
should no longer be reached for size alone.

## 8. Testing

The project's rule is that a guard is proved by cutting it, never by reading
it, with a clean baseline before and after.

- **Partition round trip.** Generate from a fixture corpus; assert union equals
  the corpus and intersection is empty. Mutation: drop one entry from the
  bundle branch of the policy and watch the union assertion go red.
- **Budget gate.** Mutation: generate a corpus that breaches each limit and
  assert the gate fails for that specific reason, and that a corpus one entry
  under the limit passes. Both directions, per the project's control rule.
- **Missing-catalog finding.** A scan with no catalog cache emits
  `THREAT_FEED_CATALOG_MISSING` naming the correct count; a scan with the
  catalog cached does not. Under `catalog: "required"` the severity is
  `critical` and the gate fails.
- **Catalog detection parity.** Take a sample of names from the drained
  deferral ranges, assert they are NOT detected with no catalog, and ARE
  detected with the catalog cached. This is the test that proves the split
  preserved coverage rather than losing it.
- **Envelope confusion.** A bundle document offered as a catalog, and the
  reverse, are both rejected by the `kind` check.
- **Malformed catalog.** A corrupt or oversized catalog leaves the previous
  cache and the bundled feed in effect, matching the existing feed behaviour.

Per the project's Windows constraint, only the suites covering the change are
run locally; CI produces the full-suite verdict.

## 9. Non-goals

- Changing what counts as malicious, or any severity other than the two named.
- Reworking the importer's discovery adapters or its decline policy.
- Liveness filtering of holding packages. It was Tier 2 of the earlier
  strategy, and it remains available as a corpus-shrinking tactic, but it is
  not needed once volume no longer lands in the bundle and it would discard
  indicators that a future republish could make live again.
- The 2.76 MB `dist/threat-intel.js.map` shipped in the package. It is 28
  percent of the unpacked size and is a source map for a data array, so it is
  probably removable, but that is an adjacent packaging question and not part
  of this design.

## 10. Open questions for the owner

1. **Should `THREAT_FEED_CATALOG_MISSING` escalate to `high` after some grace
   period, and should a badly stale rule set fail the build?** These are the
   same question and should be decided together.
2. **Should the catalog resolve to `latest` or to the installed version?**
   This design chooses `latest` with the resolved version recorded in the
   cache, trading strict reproducibility for coverage. A consumer who needs
   byte-reproducible scans pins with `--catalog-url`.
3. **Initial values for `MAX_BUNDLED_ENTRIES`, `MAX_BUNDLE_BYTES` and
   `BUNDLE_RECENT_DAYS`.** The proposed 25,000 / 4 MB / 90 days keeps the
   bundle near its current size and its import near 75 ms. Tighter values buy
   startup time at the cost of default-install coverage.
