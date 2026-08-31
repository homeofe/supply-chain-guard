# Threat-feed architecture

This document records the architecture of the multi-source threat-feed rebuild.
It separates package discovery from corroboration and IOC enrichment so that
adding a URL never silently becomes permission to block everything behind it.

## Goals

- Discover malicious packages from more than one upstream database.
- Preserve the original provider and advisory id on every imported entry.
- Import every eligible candidate by default, without a hidden daily cap.
- Refuse partial source snapshots before changing committed files.
- Keep bounded version reports version-bounded.
- Retain offline scanning and deterministic feed generation.

## Data flow and trust boundaries

```text
GitHub malware advisories ---------\
                                    > discovery adapters -> normalized candidates
OpenSSF MAL records via OSV export-/                              |
                                                                   v
                                          validation -> dedupe -> decline policy
                                                                   |
GHSA candidates only -> OSV querybatch corroboration --------------+
                                                                   |
                                                                   v
                                             bundled feed -> feed.json
```

The public network is untrusted. Package names, versions, ids, timestamps and
provider labels are validated before they can be serialized. Each enabled
discovery adapter is completeness-critical: an index error, record error,
timeout or malformed payload aborts the complete run before either
`src/threat-intel.ts` or `feed.json` is written.
Index bodies are capped at 32 MiB and individual records at 4 MiB, including
streaming responses without a declared content length.

OSV querybatch is different. It does not discover packages and is not needed to
make the snapshot complete, so an outage only prevents confidence enrichment.
It is queried for GitHub-discovered candidates only. Querying an
OpenSSF-discovered candidate against the OSV database that exported it would
let one source corroborate itself.

## Discovery-source contract

`createDiscoverySources()` is the adapter registry. Every adapter has:

- a stable source id used in machine-readable reports;
- an attribution string;
- `discover()`, which returns a complete source-specific snapshot for the
  requested window;
- `map()`, which normalizes that snapshot into feed candidates plus explicit
  skip reasons.

The importer orchestrates those methods without branching on upstream payload
shapes. A future source must implement the same boundary and receive offline
mapping tests, malformed-input tests and an end-to-end failure test.

## Current source policy

### GitHub Advisory Database

GitHub malware advisories are selected by their publication time. Exact pins
and explicit all-version ranges are accepted. Bounded ranges are not broadened.
A GitHub-only candidate has confidence 0.9; an OSV `MAL-` match raises it to 1.0.

### OpenSSF malicious-packages

OpenSSF is an independent discovery path. The importer reads each enabled
ecosystem's official OSV `modified_id.csv`, selects recently changed `MAL-`
records, and fetches only those records. This avoids cloning or downloading the
complete database on every run.

The OpenSSF record id and its `malicious-packages-origins` provider labels are
kept in `source`. A single-origin record has confidence 0.9; several distinct
origins have confidence 1.0. OpenSSF defines these records as malicious
packages whose use can require incident response, so accepted entries use the
scanner's critical severity policy.

An open-ended range introduced at version zero becomes a bare package name.
For any bounded range, only versions explicitly enumerated by the OSV record
are imported. A bounded range without an expanded version list is reported as
unmappable and never becomes a whole-package finding.

The queue age for OpenSSF is its modified-index date, not its original
publication date. This prevents a newly changed historical report from being
incorrectly treated as already expired when an operator uses `--limit`.

Exact candidates reported by both discovery adapters are coalesced before feed
deduplication, preserving the GHSA id, MAL id and provider labels. An OpenSSF
record whose only origin is `ghsa-malware` is treated as a mirror, not as
independent confirmation.

## Sources that do not directly block packages

ThreatFox, URLhaus, MalwareBazaar and phishing feeds describe broad malware
infrastructure, payloads or phishing sites. Importing their full dumps as
package-supply-chain verdicts would create unrelated matches, shared-hosting
false positives and unclear commercial-use obligations.

They belong in an enrichment adapter that requires a link to an already known
package or campaign. The enrichment output may add an exact URL, payload hash,
domain or family label after shared infrastructure and expiry checks. It must
not invent a package verdict.

## Next storage step

The current canonical feed remains chunked TypeScript arrays so this first
rebuild stage changes discovery without changing runtime loading. The adapter
pipeline can now outgrow that representation. The next stage will move
canonical records into a data file and generate two artifacts:

1. a compact runtime index for the npm package and offline scans;
2. a full provenance feed for audit, refresh and research use.

That migration must preserve `npm run check:feed`, deterministic builds,
self-scan suppression, cache merging and the current public `FeedIOC` schema.
