# Threat feed sources

Where the bundled IOC feed comes from, how upstream records are mapped onto the
feed's own entry schema, and what the import deliberately refuses to do.

The feed has two kinds of entries:

| Kind | How it gets in | Provenance |
| --- | --- | --- |
| Curated | A maintainer reads a vendor write-up and hand-adds the atomic indicators (package, domain, IP, hash, URL) | Recorded in the `CHANGELOG.md` entry for the release that shipped it |
| Imported | `npm run feed:import` pulls malicious-package records from upstream advisory databases | Recorded per entry in the `source` field |

Both land in the same place: the bundled feed in `src/threat-intel.ts`, which is
the single source of truth. `npm run feed:generate` republishes it as `feed.json`,
and `npm run check:feed` fails the build if the two ever drift.

The feed is stored as capacity-bounded `FEED_CHUNK_n` consts spread back together
into `BUNDLED_FEED`. That is not cosmetic: one array literal of this size trips
`TS2590` in `tsc`, and the limit is content-dependent (uniformly-shaped imported
entries hit it far sooner than hand-curated ones). Entries are appended to the last
chunk; when it reaches `FEED_CHUNK_CAPACITY` the importer opens a new chunk and
registers it in the spread, so no single literal can grow into that ceiling. Nothing
about this changes how you run an import - the rollover is automatic.

## Upstream sources

### 1. GitHub Advisory Database (primary)

`GET https://api.github.com/advisories?type=malware`

Malware advisories only (CWE-506, "Embedded Malicious Code"), reviewed by
GitHub's security team. These are the records that say "this published package
is malware", which is exactly the indicator class this scanner blocks.

- **No account required, and the token needs no scopes.** `GITHUB_TOKEN` /
  `GH_TOKEN` is read from the environment and raises the REST rate limit from 60
  to 5000 requests/hour. It is optional only for a window small enough to fit the
  60-request anonymous budget. The default `--max-pages 750` does not fit it, so a
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
npm run feed:import                       # last 14 days, import every new entry
npm run feed:import -- --days 30 --limit 500
npm run feed:import -- --json             # machine-readable report
npm run feed:import -- --since 2026-07-20 --until 2026-07-21 --ecosystem npm --limit 100000
```

| Option | Default | Purpose |
| --- | --- | --- |
| `--days <n>` | 14 | Look-back window |
| `--since <YYYY-MM-DD>` | - | Explicit start date, overrides `--days` |
| `--until <YYYY-MM-DD>` | - | Explicit end date |
| `--ecosystem <list>` | all | Import only these ecosystems (comma-separated, repeatable) |
| `--limit <n>` | unlimited | Optional maximum new entries added in one run |
| `--max-pages <n>` | 750 | Hard cap on upstream pages fetched; hitting it is fatal |
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

### Why the page cap is fatal, and the optional limit is not

The two caps fail in completely different ways, and only one of them is
recoverable.

By default there is no `--limit`: every mappable, non-duplicate, non-declined entry
in the fetched window is imported. This is the correctness-oriented operating mode
for the daily feed because a fixed batch size can be overtaken by sustained advisory
volume and delay detection indefinitely.

An explicitly supplied `--limit` is a **review** bound. Entries over that limit are
still in the window, so the next run can pick them up and the report prints how many
are waiting. That recovery is conditional: a limited run drains at most `--limit`
per run, so leftovers survive only while
`remaining <= limit * runs_left_before_they_expire`. On a burst window the arithmetic
may not close and the excess ages out just as page-cap loss does. The importer reports
that condition so the operator can widen `--days`, raise or remove `--limit`, or slice
the window deliberately.

`--max-pages` is a **correctness** bound. The upstream query sorts
`published/desc`, so a page cap keeps the newest advisories and never fetches the
oldest ones - precisely those closest to ageing out. There is no cursor: the next
run starts again at page 1 and re-fetches the same newest pages, so it can never
reach the remainder. Those advisories are therefore lost permanently, which in a
scanner means a silent false negative. Truncation consequently **aborts the import
and exits non-zero** rather than writing a knowingly partial window. Recover by
raising `--max-pages`, or by slicing the window with `--since`/`--until`. Only
pass `--allow-truncated` when a partial import is genuinely what you want.

### Why a spike may be worth taking only in part

A bulk-publication spike is routinely mixed, and the halves are not equally
useful. On 2026-07-20/21 the window carried 104 npm advisories alongside roughly
11,800 PyPI and NuGet ones. Sampling 25 distinct packages per ecosystem against
the registries: npm was 25/25 still installable, PyPI 0/25, NuGet 2/25. The npm
half was live threat data; the rest was historical record that would have taken
the bundled feed from 6,294 to about 27,000 entries to cover packages nobody can
install.

`--ecosystem` is how that split is taken. Everything outside the selection is
counted under `ecosystem-filtered` in the skip report rather than quietly
omitted, so the decision stays visible in the run output:

```
Ecosystem filter:     npm only
Mapped to IOCs:       153
Skipped:              21014 {"ecosystem-filtered":21014}
```

An unknown ecosystem name is rejected instead of ignored. A silently ignored
typo would filter every advisory out and import zero IOCs while exiting 0, which
is the same silent false negative the page cap is fatal about.

Liveness itself is deliberately **not** automated. A package removed from its
registry can still sit in a lockfile, a vendored directory or a mirror, so
skipping dead packages trades a small amount of coverage for feed size. That is
a judgement call about a specific spike, and it belongs with the operator rather
than buried behind a flag.

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

## The decline list

Deduplication compares candidates against the committed feed and against nothing
else. It does not know that `src/patterns.ts` may already cover a whole family with
one anchored rule instead of N feed entries. Such a family is therefore re-proposed
on every run, and once it is large enough it trips the undrainable-backlog check and
halts the import until a human slices the window by hand.

`threat-feed-declined.json` at the repository root is the answer: a list of families
a human has ruled out, with the reason and the coverage that replaces them. Entries
are removed **after** deduplication and **before** `--limit`, so a declined family
neither consumes the per-run budget nor counts as backlog the run is losing.

```json
{
  "declined": [
    {
      "namePrefix": "@zalastax/nolb-",
      "reason": "why these are not worth N feed entries",
      "coveredBy": "where the coverage that replaces them lives"
    }
  ]
}
```

An entry carries exactly one matcher, either `namePrefix` (matched against the
ecosystem-qualified package name with the version stripped, so a non-npm family
needs its `pypi:` / `ruby:` / `go:` prefix written in) or `ghsa` (one exact
advisory id). `reason` and `coveredBy` are both mandatory and both non-trivial, a
`namePrefix` shorter than six characters is rejected, and a malformed file is a
hard error rather than a silent fall-back in either direction. Only `package`
indicators are declinable.

**What this deliberately is NOT: an automatic "skip anything the pattern tables
match".** `MALICIOUS_PACKAGE_PATTERNS` is read by the npm-scanner name check and its
package.json fallback, not by the generic directory scan, which matches exact feed
names only. A pattern match is therefore not equivalent to feed coverage, and
auto-skipping on one would quietly narrow detection. The tables also hold
heuristics such as `^[a-z]{20,}$`, which would swallow genuinely new malware whose
name happens to be long. Declining stays a per-family decision, written down with
its justification and reviewable in the diff.

## Reviewing an import

An import is a proposal, not a release. Read the diff before committing: the
entries are appended to the last feed chunk under a dated comment (or to a new
chunk, if that one was full), and every one of them names the advisory it came
from, so each line can be checked against
`https://github.com/advisories/<GHSA-id>`.
