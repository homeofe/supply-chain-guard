# Daily signed feed channel and offline import

Status: design, approved direction (2026-10-21). Not yet built.

## Why

Malicious packages are published every day, and the advisory databases this
project imports from record new ones every day. Today that intelligence reaches
users only through a release:

- `supply-chain-guard feed refresh` downloads `feed.json` and `feed.json.sig` from
  the **latest GitHub Release** (`DEFAULT_FEED_URL` in `src/feed.ts`), with a
  fallback to the newest release that carries a signed feed.
- The GitHub Action runs `feed refresh` on every run, so Action users get the
  same release-bound feed, whatever version they pin.
- An offline scan uses only the feed compiled into the installed version.

So fresh intelligence needs a release, and a release needs the maintainer to
review, merge, bump and tag. That made the project depend on a daily release
cadence that one maintainer cannot sustain: review work piled up, and several
daily pull requests overlapped and had to be reconciled by hand.

The maintainer decided to separate the two speeds:

| What | Cadence | Who |
| --- | --- | --- |
| Threat data (`feed.json`) | daily | automated, no daily maintainer step |
| Code release (npm, Action, Docker image) | weekly; security fixes immediately | maintainer |
| Review of everything that can cause a false positive | weekly | maintainer |

Prior art for the same split: Trivy publishes its vulnerability database
separately from the binary and refreshes it several times a day; Grype has
`grype db import` for offline networks.

## Goals

1. A signed `feed.json` that is at most about 26 hours old is available every day,
   without a release and without a maintainer step.
2. `feed refresh` (and therefore the Action) uses that daily feed by default, and
   falls back to the release feed when the daily channel is unavailable.
3. The daily channel can only ADD indicators of the low-risk kinds below, on top
   of what the maintainer reviewed on `main`. This is enforced by the publishing
   job, not by convention.
4. Networks without internet access can install the same signed feed from a file,
   with the same checks as `feed refresh`.
5. The channel is served from GitHub Pages, which will also host a project website.

## Non-goals

- The project website itself. It shares the Pages deployment (see "Pages"), but
  its content and design are a separate project.
- Changing how the historical catalog is distributed. It stays a per-release set
  of assets pinned by `src/catalog-digest.ts`.
- Merging anything into `main` automatically. The daily job publishes; it never
  commits, merges, tags or releases.
- npm, Docker or Marketplace releases on a daily schedule.

## Anti-goals (a build that does any of these has failed, even if it works)

- The daily job can REMOVE an indicator, or add a bare package name, a version
  range, a pin derived from a range or a whole-package claim, a domain, an IP or
  a URL, without maintainer review.
- A client accepts a daily feed with a weaker check than a release feed gets today
  (signature, rollback guard, minimum size), or `--allow-unsigned-feed` becomes
  necessary for the default path.
- A failure in the website build stops the feed from being published.
- The fallback to the release feed is silent in a way that makes a stale feed look
  current. Staleness must stay visible (`THREAT_FEED_STALE`, `feed stats`).

## Decided

### Which indicators the daily channel may add on its own

Maintainer decision, 2026-10-21: **exact-version package pins whose version a
source names, and file hashes** may be published daily without review. Everything else waits for the weekly
review on `main`: bare package names, version ranges, domains, IPs, URLs, and any
removal or change of an existing entry.

The reason: a pin fires only on one exact release, and a hash only on one exact
file. But not every pin the importer emits was named by a source. Some are
DERIVED: a version range resolved against today's registry or read out of a
range expression, or the sampled versions of a whole-package claim (the
`range-resolved`, `pin-only` and `whole-claim-sample` labels of the importer's
`DERIVATION`). Pins from an OpenSSF record's own `versions` list are NOT derived,
also when the record's range covers the whole package (`_pinnedFromWholeRange`):
the record names those versions. The two worst false-positive traps found so far
came from exactly that: resolving a range would have pinned 45 legitimate releases
of `flipper-frontend-core`, and a whole-package claim on a hijacked live package
would have pinned all 1,927 releases of `@toptal/picasso`. The importer now guards
both (range pins only up to the record's first publication, whole claims on live
packages only for versions with a malware sample). The daily channel adds a
second line of defence on top: it publishes only what a source named as an exact
version (see "Decision on derived pins" below).

In practice the automated source is the existing importer
(`scripts/import-threat-feed.mjs`: GitHub Advisory Database, OpenSSF/OSV, DataDog
dataset). It produces package entries; hashes today come only from hand-written
enrichment, which goes through `main`. The rule still names hashes so that a
future automated source of hashes needs no new decision.

### What the daily feed is

The daily feed = the `feed.json` that `main` currently generates (`npm run
feed:generate`), plus the importer's new exact-version pins since `main`'s last
import, with a fresh `generatedAt`. The publishing job:

1. checks out `main`, installs with `--ignore-scripts`, runs the importer as a dry
   run with JSON output (no write to the repository),
2. keeps only proposed entries that are exact-version pins (`name@version`, with
   the ecosystem prefix the importer assigns) AND whose version the source record
   itself lists. The dry-run JSON does not carry that distinction today
   (`publicEntry` strips the `_` bookkeeping fields), so the importer's report
   gains a per-entry derivation field (listed, range-resolved, whole-claim
   sample, pin-only list). Everything else is dropped and the dropped count per
   derivation is reported,
3. builds the daily feed as `main`'s feed plus those pins, regardless of whether
   the importer would route them to the bundle or the catalog (the daily feed is an
   overlay, so routing does not apply to it), plus the catalog entries `main`
   gained since the latest release. A client on the latest release therefore
   misses nothing the catalog of its own version lacks; clients on older releases
   keep today's behaviour. `generatedAt` is the current time (full timestamp, not
   midnight),
4. **enforces the invariant** against `main`'s `feed.json` and catalog: every
   entry of `main`'s feed is present unchanged, every catalog entry added in step 3
   is present unchanged on `main`, and every other additional entry is an
   exact-version package pin or a hash. Any other difference fails the job before
   signing. A daily batch above a fixed cap (start at 2,000 added pins; a bulk
   backfill wave is that size or larger and needs a human) also fails the job,
5. on any failure (importer error or tripwire, an unreachable source, the
   invariant, the cap, validation, signing) publishes NOTHING: the run is red, the
   channel keeps the previous day's feed, and its age stays visible to clients.
   It never republishes `main`'s feed with a fresh timestamp, because that would
   claim a freshness the run did not deliver,
6. validates the result with the same parser and validators the client uses
   (`parseFeedDocument`, `isValidFeedIOC`) and the same minimum-size rule,
7. signs it with the existing Ed25519 key (`scripts/sign-feed.mjs`, which already
   verifies its own output against the public key in the package),
8. publishes `feed.json` and `feed.json.sig` to the channel (see "Pages").

Because the job starts from `main` every day and does not keep its own state, a
pin that turns out to be wrong disappears from the channel on the next run once
`main` declines it (decline list or pin-only list). It also disappears when the
importer stops proposing it.

### What a daily feed can and cannot change on a client

The client merges the cached feed INTO the feed compiled into the installed
version (`mergeFeeds` in `src/threat-intel.ts`: union by type and value). So:

- a daily feed can add indicators to any installed version,
- a daily feed can withdraw an indicator only if that indicator came from an
  earlier daily feed (the cache is replaced on each refresh),
- an indicator compiled into an installed version can only be removed by a new
  release. That is today's behaviour and stays so.

### Client changes

- `DEFAULT_FEED_URL` becomes the daily channel URL. If the daily feed cannot be
  installed for any reason (fetch, signature, parse, size or rollback check),
  `feed refresh` tries today's release path (latest release, then the newest
  signed release) with the same checks. It says which source it installed, or
  why it installed none.
- A client whose cache is already at least as new as what both sources offer
  keeps its cache. That is the expected case when the release feed (midnight
  `generatedAt`) is older than a cached daily feed. `feed refresh` reports the
  cache as current with its date and exits 0; it exits non-zero only when the
  cache is missing or stale (older than the 24-hour refresh window) and no source
  could replace it.
- A custom `--url` keeps today's behaviour exactly: no fallback, catalog follows
  the feed, `--allow-unsigned-feed` applies only there.
- The catalog does NOT follow the daily channel. Today `catalogTemplateForFeedUrl`
  derives the catalog location from the feed URL, which is right for a custom
  `--url` mirror and wrong for the new default: the daily default must keep
  `DEFAULT_CATALOG_URL_TEMPLATE` (release assets of the installed version).
- Signature check, rollback guard (`assertFeedMayReplace`) and minimum size stay
  exactly as they are for every source.
- `feed stats` and the scan report keep showing the feed's own `generatedAt`, so
  a client that silently fell back to an older release feed shows its real age.

### Offline import

- New command `supply-chain-guard feed import <dir>`. `<dir>` holds files with the
  same names as the published assets: `feed.json`, `feed.json.sig`, and optionally
  `catalog-index.json` plus the catalog shards for the installed version.
- It runs the same verification as `feed refresh` (signature against the bundled
  key, rollback guard, minimum size, catalog digest chain) and writes the same
  cache files. It makes no network request.
- The daily channel also publishes one archive with the day's `feed.json` and
  `feed.json.sig` and a checksum file. The catalog files are per release and stay
  on the release page; the README explains that an offline network fetches them
  once per upgrade.
- README section "Air-gapped networks": download on a connected machine, verify
  the checksum, carry the files across, run `feed import`. Also: installing the
  npm package from an internal registry, and pinning the Docker image by digest.
  The section ends with an invitation to describe offline setups in GitHub
  Discussions, because nobody knows yet who runs this offline.

### Pages

- GitHub Pages, deployed from a workflow (source "GitHub Actions"), at the
  default `homeofe.github.io/supply-chain-guard` address until the maintainer
  decides on a custom domain.
- One deployment carries the whole site, so the daily job deploys the feed files
  and the current website together. The feed lives under `/feed/`
  (`/feed/feed.json`, `/feed/feed.json.sig`, the offline archive).
- The website source lives in `main` (a directory such as `site/`); there is no
  `gh-pages` branch, because the repository carries no branches besides `main`
  and the `vN` refs. The website build is isolated from the feed: if it fails, the
  job deploys the feed next to a minimal static index page that is committed in
  the repository, and reports the site failure as its own red step. Until the
  website project exists, that minimal page (linking to the repository) is the
  site.
- The signing key moves into a GitHub Environment (for example `feed-publish`)
  whose deployment policy allows the branch `main` and tags matching `v*.*.*`, so
  the daily job (scheduled on `main`) and the release job (on the tag) can both
  use it and nothing else can. Creating it is a maintainer setting.

### Schedule and monitoring

- The daily job runs once a day on a schedule and can be started by hand.
- It fails loudly: any invariant breach, validation error or signing error is a
  red run, which GitHub reports to the maintainer.
- A freshness check runs in a DIFFERENT workflow than the publisher (the existing
  daily `feed-reconcile` workflow), so it also catches the publisher not running
  at all. It reads the live `/feed/feed.json` and fails when its `generatedAt` is
  older than 30 hours. The target stays about 26 hours; the margin absorbs GitHub's
  delayed scheduled runs and the Pages deploy.

## Decision on derived pins

The maintainer first approved "exact pins and hashes" on 2026-10-21, on the
premise that no recent false positive was an exact pin. That premise was wrong for
derived pins (see above). Asked again with that correction, the maintainer decided
the same day: the daily channel publishes only versions a source lists
explicitly. Range-resolved pins, whole-claim sample pins and pin-only-list pins
wait for the weekly review on `main`.

## Calls made while writing this (check these)

- Failure publishes nothing (no fresh-timestamp republish of `main`).
- A cap of 2,000 added pins per day.
- The daily feed carries `main`'s catalog additions since the latest release.
- Fallback on any install failure of the daily feed; exit 0 when the cache is
  already current.
- Website source in `main`, minimal committed index page as the fallback site.
- Environment policy: branch `main` plus tags `v*.*.*`.
- Freshness alert at 30 hours, checked from `feed-reconcile`.

## Left to the builder

- Workflow file layout and job names; whether site and feed are separate jobs.
- How the dry-run JSON is filtered (the importer's report fields), as long as the
  invariant check in step 4 is an independent comparison of the two feed files
  and not a re-use of the filter.
- The offline archive format and name.
- Exact client messages and the shape of the fallback code.
- Tests. At minimum: the invariant check is proven by cutting it (a removed entry,
  a changed entry, an added bare name, an added range and an added domain must
  each fail the job); the client falls back when the channel is down and keeps
  the release catalog template; `feed import` refuses a bad signature, an older
  feed and a short feed, with no network access.

## Rollout

1. Maintainer settings: enable Pages with source "GitHub Actions"; create the
   signing environment and move `FEED_SIGNING_KEY` into it.
2. Ship the daily job first. It publishes to Pages while clients still read
   releases, so a few days of real output can be checked before anyone depends on it.
3. Release the client change (new default plus fallback) and `feed import`.
   Installed older versions keep using release feeds; users get the daily
   channel when they upgrade, Action users when they bump their pin.
4. Update the README sections on `feed refresh`, the Action and offline use.
