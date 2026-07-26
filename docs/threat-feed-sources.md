# Threat feed sources

Where the bundled IOC feed comes from, how upstream records are mapped onto the
feed's own entry schema, and what the import deliberately refuses to do.

The feed has two kinds of entries:

| Kind | How it gets in | Provenance |
| --- | --- | --- |
| Curated | A maintainer reads a vendor write-up and hand-adds the atomic indicators (package, domain, IP, hash, URL) | Recorded in the `CHANGELOG.md` entry for the release that shipped it |
| Imported | `npm run feed:import` pulls malicious-package records from upstream advisory databases | Recorded per entry in the `source` field |

Both land in the same place: the `BUNDLED_FEED` array in `src/threat-intel.ts`,
which is the single source of truth. `npm run feed:generate` republishes it as
`feed.json`, and `npm run check:feed` fails the build if the two ever drift.

## Upstream sources

### 1. GitHub Advisory Database (primary)

`GET https://api.github.com/advisories?type=malware`

Malware advisories only (CWE-506, "Embedded Malicious Code"), reviewed by
GitHub's security team. These are the records that say "this published package
is malware", which is exactly the indicator class this scanner blocks.

- **No account required, and the token needs no scopes.** `GITHUB_TOKEN` /
  `GH_TOKEN` is read from the environment and raises the REST rate limit from 60
  to 5000 requests/hour. It is optional only for a window small enough to fit the
  60-request anonymous budget. The default `--max-pages 200` does not fit it, so a
  default run needs a token and fails fast with an actionable message rather than
  dying mid-pagination on a 403.
- **Licence: CC BY 4.0** (`github/advisory-database`). Attribution is required
  and travels with the data: every imported entry carries its `GHSA-...` id in
  the `source` field, and this page names the database.

### 2. OSV.dev (corroboration only)

`POST https://api.osv.dev/v1/querybatch`

One batched query per import run asks whether OSV also lists a package as
malicious, i.e. whether it has a `MAL-` record (those originate from
`ossf/malicious-packages`, Apache-2.0). This is **never** used for discovery:
OSV can only raise the confidence of a package GitHub already flagged, so a
`MAL-` record that applies to one version of an otherwise legitimate package
can never turn into a whole-package block here.

- A package listed by both databases gets `confidence: 1.0` and a `source` of
  `GHSA-..., MAL-...`.
- A package listed only by GitHub gets `confidence: 0.9`.
- If OSV is unreachable the import continues at 0.9 and says so in the report.
  Corroboration is an enrichment, not a gate.

The relationship is symmetric with the export side: `supply-chain-guard feed osv`
already emits the feed's package IOCs as OSV-schema records.

## Mapping

Upstream advisory to `FeedIOC`:

| FeedIOC field | Source | Notes |
| --- | --- | --- |
| `type` | always `"package"` | Advisory databases describe packages; domain/IP/hash/URL indicators stay a curated-only concern |
| `value` | `vulnerabilities[].package` + `vulnerable_version_range` | See the version rules below |
| `severity` | advisory `severity` | `critical` -> `critical`, `high` -> `high`, `moderate`/`medium`/`low`/`unknown` -> `medium`. The feed schema has only three levels, so nothing is ever promoted above what upstream claimed |
| `confidence` | **not published upstream** | Project constant: 0.9 single-source, 1.0 corroborated by OSV. Documented here rather than invented per entry |
| `source` | `ghsa_id` (plus the OSV `MAL-` id when corroborated) | The provenance record; makes every imported entry traceable back to a public advisory page |
| `firstSeen` | advisory `published_at`, date part only | |
| `family` | **not published upstream** | Left unset. GitHub malware advisories name no malware family, and guessing one would put fiction in the feed |
| `campaign` | **not published upstream** | Left unset, same reason |
| `lastSeen` | **not populated** | Upstream `updated_at` is a record-edit timestamp, not a sighting |

### Ecosystem prefixes

Only ecosystems the scanner can actually resolve are imported. An entry for an
ecosystem with no matcher would be data no scan could ever use.

| Upstream ecosystem | Feed value prefix | Resolved by |
| --- | --- | --- |
| `npm` | *(none, bare name)* | `matchBareNpmIOC`, `checkMaliciousDependencyNames` |
| `pip` | `pypi:` | `python-lockfile-scanner` (poetry.lock, uv.lock, Pipfile.lock) |
| `composer` | `composer:` | `composer-scanner` |
| `go` | `go:` | `go-scanner` |
| `rubygems` | `ruby:` | `rubygems-scanner` |
| `rust` | `cargo:` | `cargo-scanner` |
| `nuget` | `nuget:` | `nuget-scanner` |

Everything else (Maven, GitHub Actions, Pub, Swift, Hex, `other`) is counted in
the run report under `unsupported-ecosystem` and skipped.

### Version ranges

Only two upstream shapes are mapped, and the reason is false positives:

| Upstream range | Feed value | Meaning |
| --- | --- | --- |
| `= 1.2.3` | `name@1.2.3` | Exactly that version is malicious |
| `>= 0`, `> 0`, `>= 0.0.0` | `name` | The whole package is malicious at every version |
| anything else (`>= 1.0.0, <= 1.2.0`, `< 2.0.0`, empty) | *skipped* | Reported as `unmappable-version-range` |

A bounded range is **not** collapsed into a bare name. Doing so would block
versions upstream never called malicious, which is the exact over-blocking the
curated feed avoids by hand for hijacked-but-legitimate packages.

### Safety of the mapping itself

Package names come from a public database that anyone can file into, and the
importer writes them into a TypeScript source file. Names are therefore
re-validated against a charset narrower than the feed's own package shape (no
quotes, no backslashes, no whitespace, no control characters) before they are
serialized, and anything that fails is reported as `unsafe-package-name` rather
than written. Values are additionally serialized with `JSON.stringify`, and the
rewritten file is re-parsed and entry-counted before `feed.json` is regenerated.

## Running an import

```bash
npm run feed:import -- --dry-run          # report only, writes nothing
npm run feed:import                       # last 14 days, max 250 new entries
npm run feed:import -- --days 30 --limit 500
npm run feed:import -- --json             # machine-readable report
```

| Option | Default | Purpose |
| --- | --- | --- |
| `--days <n>` | 14 | Look-back window |
| `--since <YYYY-MM-DD>` | - | Explicit start date, overrides `--days` |
| `--until <YYYY-MM-DD>` | - | Explicit end date |
| `--limit <n>` | 250 | Maximum new entries added in one run |
| `--max-pages <n>` | 200 | Hard cap on upstream pages fetched; hitting it is fatal |
| `--allow-truncated` | off | Import anyway when the page cap was hit |
| `--timeout <ms>` | 15000 | Per-request timeout |
| `--no-osv` | off | Skip the OSV corroboration query |
| `--dry-run` | off | Report only |
| `--json` | off | Machine-readable report |

Network calls are bounded three ways: an explicit per-request timeout on every
request, a page cap, and the fixed 100-item page size. Pagination stops as soon
as a response carries no `rel="next"`, so a quiet window costs about 3 requests
regardless of how high `--max-pages` is; the cap only binds on an unusually busy
window.

### Why the page cap is fatal, and the limit is not

The two caps fail in completely different ways, and only one of them is
recoverable.

`--limit` is a **review** bound. Entries over the limit are still in the window, so
the next run picks them up and the report prints how many are waiting. That makes
them recoverable, but only conditionally: a run drains at most `--limit` per run, so
the leftovers survive only while `remaining <= limit * runs_left_before_they_expire`.
On a burst window the arithmetic does not close and the excess ages out just as
page-cap loss does. The difference is that the number is reported, so the operator
can widen `--days`, raise `--limit`, or slice the window deliberately.

`--max-pages` is a **correctness** bound. The upstream query sorts
`published/desc`, so a page cap keeps the newest advisories and never fetches the
oldest ones - precisely those closest to ageing out. There is no cursor: the next
run starts again at page 1 and re-fetches the same newest pages, so it can never
reach the remainder. Those advisories are therefore lost permanently, which in a
scanner means a silent false negative. Truncation consequently **aborts the import
and exits non-zero** rather than writing a knowingly partial window. Recover by
raising `--max-pages`, or by slicing the window with `--since`/`--until`. Only
pass `--allow-truncated` when a partial import is genuinely what you want.

Because a busy window can need hundreds of requests, `GITHUB_TOKEN` is optional
for a small window but effectively required for a large one: the anonymous REST
budget is 60 requests/hour against 5000 authenticated, and a rate-limit rejection
is fatal and loud.

### Failure mode

The upstream fetch is the only fatal step, and nothing is written until the
whole batch has been fetched, mapped, deduplicated and validated in memory:

- Network error, timeout, non-200, or a body that is not an advisory array:
  the process prints one line to stderr and exits **non-zero**.
  `src/threat-intel.ts` and `feed.json` are left **byte-identical**.
- If the rewritten source does not re-parse to the expected entry count, the
  source file is rolled back and `feed.json` is never regenerated.
- Nothing new to add is not a failure: the run exits 0 having written nothing.

A failed import therefore never empties, truncates or corrupts the published
feed - the previous feed stays in effect, exactly like a failed
`supply-chain-guard feed refresh` leaves the previous cache in place.

## Deduplication

Imported entries are checked against the feed that is already committed:

1. **Exact duplicate** - same `type:value` (the same key `mergeFeeds` uses at
   scan time).
2. **Already covered** - a bare-name IOC for the same ecosystem and package
   already fires on every version, so a version-pinned import adds nothing.

Deduplication is ecosystem-aware: `pypi:foo` and the bare npm `foo` are
different packages and are never conflated. Duplicates inside a single incoming
batch are collapsed too.

## Reviewing an import

An import is a proposal, not a release. Read the diff before committing: the
entries are appended to `BUNDLED_FEED` under a dated comment, and every one of
them names the advisory it came from, so each line can be checked against
`https://github.com/advisories/<GHSA-id>`.
