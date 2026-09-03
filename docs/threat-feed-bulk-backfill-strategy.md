# Threat-Feed Bulk Backfill Ingestion Strategy

This document outlines the strategy for handling large upstream threat-intelligence
backfills, specifically addressing the GitHub Advisory Database / OpenSSF bulk backfill
observed on 2026-09-02 (and subsequent alphabetical waves).

## 1. Problem Statement

On 2026-09-02, the GitHub Advisory Database bulk-published roughly 9,776 historic
OpenSSF malicious-package records (MAL IDs spanning 2023 to 2026). The distribution
is 99.8% alphabetical: 6,965 names beginning with "a" and 2,793 names beginning with
"b". This directly followed the 2026-08-31 batch that imported 4,398 "a" entries.

The backfill poses three interrelated challenges:

1. **Window Expiration (2026-09-16):** The importer runs with a rolling 14-day window.
   If no ingestion or retention decision is made by 2026-09-16, the backfill ages out
   and becomes unreachable by future routine runs, resulting in a permanent silent drop.
2. **Bundle & Compilation Bloat:** Ingesting 9,776 entries wholesale would expand the
   bundled feed from 20,183 to ~30,000 entries (+49%) in a single diff. If waves
   continue through c-z, the bundled feed could exceed 100,000 entries. In Node/TypeScript:
   - `src/threat-intel.ts` is already divided into 21 chunks of 1,000 items to avoid
     `TS2590` ("Expression produces a union type that is too complex to represent").
   - `feed.json` (4.44 MB) and `dist/threat-intel.js` (3.40 MB) already total 7.84 MB.
     The GitHub Action installs this package globally on every run, so unbounded bundle
     growth penalizes global CI runtimes.
   - Parity tests in `src/__tests__/threat-intel.test.ts` compare indexed lookups
     against linear scans, suffering quadratic cost increases as feed entries multiply.
3. **Decline Policy Violation:** Declining this block in `threat-feed-declined.json`
   requires a valid `coveredBy` property pointing to existing pattern coverage. Because
   the backfill spans 1,189 distinct prefix tokens across diverse malware types, no
   anchored regex in `src/patterns.ts` covers it. Declining it without coverage would
   falsely suppress real threat intelligence.

---

## 2. Empirical Findings: Registry Liveness Audit

A common assumption during backfill triage is that historic advisories represent dead
holding packages that npm has already quarantined, offering little practical protection.

To verify this, 50 packages were sampled at random from the 2026-09-02 batch and probed
against `https://registry.npmjs.org`:

| Registry Status | Count (out of 50) | Description |
| :--- | :--- | :--- |
| **Security Holding Stub** | 9 | Returns single `0.0.1-security` version, description "security holding package", no maintainer. |
| **Unpublished / No versions** | 13 | Metadata exists but versions array is empty. |
| **Live Installable Packages** | **28** (>50%) | Active package releases (e.g. version `1.2.3`), active maintainers (e.g. `rajhsinggg`), dependencies, and downloadable tarballs hosted on npm. |

**Key Takeaway:** Over half the surveyed sample consists of packages still live and
downloadable on npm today (e.g. `bellatrix-nextjs-jupiter-dagda`,
`bellatrix-polaris-resolvers-xenos`, `bellatrix-spawn-iota-convict`). Failing to import
these packages creates a genuine, active detection gap.

---

## 3. Concrete Strategic Recommendations

We recommend a three-tiered approach:

### Tier 1: Immediate Staged Slicing (Before 2026-09-16)
Rather than deferring until the window expires, ingest the 2026-09-02 backfill in
controlled, reviewable slices using the existing importer controls:
```bash
# Example 2,000-entry sliced batches
node scripts/import-threat-feed.mjs --since 2026-09-02 --until 2026-09-03 --limit 2000
```
This distributes the 9,776 entries across 4-5 discrete PRs, giving Vitest test budgets
and TypeScript chunking headroom to adapt without a single massive diff or window loss.

### Tier 2: Import-Time Registry Liveness Verification
Introduce an optional `--filter-holding-packages` flag into `scripts/import-threat-feed.mjs`:
- During candidate normalization, probe `registry.npmjs.org/<name>`.
- If npm returns a `0.0.1-security` holding package with empty maintainers and no payload,
  the entry is categorized as a quiescent holding package and optionally bypassed for
  the bundled feed.
- If the package has live version history, tarballs, or active maintainers, it is
  immediately prioritized for bundled inclusion.
- This immediately eliminates 20-30% of inactive stub volume while preserving 100% of
  protection against active, installable packages.

### Tier 3: Long-Term Architectural Feed Decoupling
The project already contains remote feed infrastructure (`src/feed.ts`, `updateThreatFeed()`,
and `FEED_REMOTE_LIMITS`).
- Maintain a lean `BUNDLED_FEED` containing rules, active campaigns, and the last 90 days
  of high-severity indicators.
- Distribute the complete historical catalog (30,000+ entries) as an external, compressed
  JSON artifact (e.g. via GitHub Releases assets or CDN).
  - Gzip/brotli compression reduces a 7 MB `feed.json` to ~500 KB.
  - Consumers update this catalog via `supply-chain-guard feed refresh`.
- This removes historical malware bloat from TypeScript compilation (`src/threat-intel.ts`)
  and keeps the npm distribution package lightweight.
