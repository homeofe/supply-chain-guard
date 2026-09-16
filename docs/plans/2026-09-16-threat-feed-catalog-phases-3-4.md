# Threat-Feed Catalog Decoupling, Phases 3 and 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 56,294-indicator detection gap by draining the five deferred
bulk-migration ranges into the catalog, then retire the bulk-deferral mechanism
so a future alphabet wave is an ordinary import.

**Architecture:** No new machinery. Phase 3 is a data operation that runs the
existing importer over five explicit date ranges and lets the Phase 2 routing
put every entry in the catalog. Phase 4 removes the reason the deferral list
existed and keeps it only for genuinely undecidable blocks.

**Tech Stack:** The importer (`scripts/import-threat-feed.mjs`), the partition
routing from Phase 2, vitest.

**Spec:** `docs/threat-feed-catalog-decoupling-design.md`

**Depends on:** Phase 2 fully landed. Phase 3 relies on the importer routing
built in Phase 2 Task 4; without it all 56,294 entries land in the compiled
bundle and breach the budget on the first range.

## Global Constraints

- **No em-dashes or en-dashes** anywhere in code, comments, docs or commit
  messages.
- **No AI attribution** in any commit message, PR title or body.
- **Never name the maintainer** in repository content.
- **Defang IOCs** in comments, docs and PR bodies. Raw values in `src/` and in
  the catalog stay raw. Hashes stay raw.
- **Never run the full suite on Windows.** For a real verdict use a Linux host
  and remove the temp directory afterwards. The host alias is local to the
  maintainer and is deliberately not named in this public repository.
- **`main` is protected.** One PR per range, squash-merged.
- **A release leaves zero open issues and zero open PRs.** Do not park notes in
  issues; durable notes go in `.ai/handoff/STATUS.md`.

## The five ranges

From `threat-feed-deferred.json`, measured 2026-09-16:

| range | entries | recovery command |
| --- | --- | --- |
| 2026-09-02 | 9,758 | `npm run feed:import -- --since 2026-09-02 --until 2026-09-02` |
| 2026-09-04 | 9,937 | `npm run feed:import -- --since 2026-09-04 --until 2026-09-04` |
| 2026-09-06 | 8,550 | `npm run feed:import -- --since 2026-09-06 --until 2026-09-06` |
| 2026-09-10 | 8,891 | `npm run feed:import -- --since 2026-09-10 --until 2026-09-10` |
| 2026-09-13 | 19,158 | `npm run feed:import -- --since 2026-09-13 --until 2026-09-13` |

**No `--limit` is passed, deliberately.** The importer is exhaustive by default:
`appliedLimit` is `null` unless the operator supplies the flag, and the code
comment at the selection site says so explicitly ("Exhaustive by default. A
limit is only applied when the operator explicitly supplies `--limit`"). Adding
one here would silently drain part of a range and leave a remainder that no
later run proposes, because an explicit range is not re-offered by the daily
job.

**An explicit `--since`/`--until` slice ignores the deferral list**, which is
what makes these commands work at all.

Projected catalog after the drain: 11,998 from Phase 2 plus 56,294 equals 68,292
entries, roughly 15.8 MB raw and about 1.2 MB gzipped at the measured 7.3
percent ratio. That is well inside `FEED_REMOTE_LIMITS.maxBytes` of 32 MiB and
inside `CATALOG_MAX_DECOMPRESSED_BYTES` of 64 MiB.

---

### Task 1: Drain one range, and prove the routing holds

Do the smallest range that still exercises everything. Treat this task as the
pilot: if anything here is wrong, four more PRs would repeat it.

**Files:**
- Modify: `data/threat-catalog.jsonl` (generated)
- Modify: `threat-feed-deferred.json`
- Modify: `src/catalog-digest.ts` (generated)

- [ ] **Step 1: Record the before state**

```bash
node -e "
const fs=require('node:fs');
const cat = fs.readFileSync('data/threat-catalog.jsonl','utf8').split('\n').filter(l=>l.trim()).length;
console.log('catalog entries BEFORE:', cat);
console.log('bundle entries BEFORE :', require('./feed.json').entryCount);
console.log('deferred ranges       :', require('./threat-feed-deferred.json').deferred.length);
"
```

Expected after Phase 2: `catalog 11998`, `bundle 8971`, `deferred ranges 5`.
Anything else means Phase 2 did not land as planned; stop and reconcile before
importing.

- [ ] **Step 2: Dry-run the range**

```bash
export GITHUB_TOKEN=$(gh auth token)
npm run feed:import -- --since 2026-09-06 --until 2026-09-06 --dry-run
```

Expected: exit 0, roughly 8,550 new entries, and the summary reporting nearly
all of them routed to the catalog rather than the bundle. These are historical
`MAL-` records whose `firstSeen` predates the cutoff by months, so bundle-bound
entries should be a handful at most.

**If the summary says most entries are bundle-bound, stop.** It means either the
cutoff was not moved in Phase 2 or the routing is not wired, and importing would
breach the budget.

- [ ] **Step 3: Apply it**

```bash
npm run feed:import -- --since 2026-09-06 --until 2026-09-06
npm run feed:generate
npm run catalog:generate
npm run handoff:refresh
```

- [ ] **Step 4: Verify nothing landed in the wrong store**

```bash
node -e "
const fs=require('node:fs');
const cat = fs.readFileSync('data/threat-catalog.jsonl','utf8').split('\n').filter(l=>l.trim()).length;
const bundle = require('./feed.json').entryCount;
console.log('catalog', cat, '(was 11998, expect about 20548)');
console.log('bundle ', bundle, '(was 8971, expect unchanged or nearly so)');
"
npm run check:feed-partition
npm run check:feed-budget
npm run check:catalog
```

Expected: the catalog grew by about 8,550, the bundle barely moved, and all
three gates are green. `check:feed-budget` is the one that matters: it is the
gate that would have caught this going wrong, so seeing it green here is
evidence, not decoration.

- [ ] **Step 5: Verify the entries are actually detectable**

Pick five package names from the imported range and assert the scanner now flags
them with the catalog cached, and does not without it:

```bash
node -e "
const { getBundledFeed } = require('./dist/threat-intel.js');
const { matchBareNpmIOC } = require('./dist/install-guard.js');
const feed = getBundledFeed();
for (const n of ['<name1>','<name2>','<name3>','<name4>','<name5>']) {
  console.log(n, matchBareNpmIOC(n, '1.0.0', feed) ? 'IN BUNDLE (unexpected)' : 'not in bundle (expected)');
}
"
```

Then refresh the catalog and repeat against `loadThreatIntel()`. Use
`matchBareNpmIOC` for bare npm entries and `matchPackageIOC` for PyPI ones:
`matchPackageIOC` returns `null` for a bare npm entry and the test then reads
like a missing IOC.

This is the step that proves the drain closed the gap rather than merely moving
bytes.

- [ ] **Step 6: Remove the drained range from the deferral list**

Delete the `2026-09-06` object from `threat-feed-deferred.json`. Then:

```bash
npm run feed:import -- --dry-run 2>&1 | grep -A2 "Deferred:"
```

Expected: the summary now names four ranges, not five, and the drained day is
gone. A range left in the file after its entries are imported is a lie the next
operator will act on.

- [ ] **Step 7: Full gate chain and Linux verdict**

```bash
npm run build
npx --no-install aahp lint
```

Then the real suite on Linux, per the Global Constraints. Expected: zero
failures.

- [ ] **Step 8: Commit and open the PR**

```bash
git add -A
git commit -m "feat(threat-intel): drain the 2026-09-06 bulk-migration range

Imports 8550 historical OpenSSF malicious-package records that have been a
recorded, uncovered detection gap since 2026-09-06. Every one routes to the
catalog through the Phase 2 partition, so the compiled bundle does not grow
and startup is unchanged.

The range is removed from threat-feed-deferred.json in the same commit,
because a drained range left in that file is a lie the next operator acts on.

Pilot for the remaining four ranges."
```

The PR body must state the before and after catalog counts, that the bundle is
unchanged, and that `check:feed-budget` passed.

---

### Task 2: Drain the remaining four ranges

One PR per range, in this order: 2026-09-02, 2026-09-04, 2026-09-10, 2026-09-13.
Smallest blast radius first is not the goal here; chronological order keeps the
catalog's provenance readable.

For each range, repeat Task 1 Steps 2, 3, 4, 6, 7 and 8 with that range's dates
and expected count from the table above.

- [ ] **Step 1: 2026-09-02, 9,758 entries**
- [ ] **Step 2: 2026-09-04, 9,937 entries**
- [ ] **Step 3: 2026-09-10, 8,891 entries**
- [ ] **Step 4: 2026-09-13, 19,158 entries**

Two notes that apply to the later ranges specifically:

**The 2026-09-13 range is two publication bursts, not one.** It was recorded as
10,010 candidates on the day and had grown to 19,158 by the time the range was
written, because a second burst landed at 20:12Z. Expect the larger number. If
the run reports about 10,000, the window is being resolved differently than the
deferral record assumed and the remainder would be silently left behind.

**Do not merge these back to back.** Each merge to `main` cancels the previous
commit's CI run, and the deploy gate then refuses a commit whose CI concluded
`cancelled`. Let CI settle between merges.

- [ ] **Step 5: Confirm the deferral list is empty of bulk ranges**

```bash
node -e "console.log(require('./threat-feed-deferred.json').deferred.length, 'range(s) remain')"
npm run feed:import -- --dry-run 2>&1 | grep -c "DEFERRED, NOT COVERED"
```

Expected: `0 range(s) remain` and no deferral banner at all.

- [ ] **Step 6: Measure the end state**

```bash
node -e "
const fs=require('node:fs');
const cat = fs.readFileSync('data/threat-catalog.jsonl','utf8').split('\n').filter(l=>l.trim()).length;
console.log('catalog entries:', cat, '(expect about 68292)');
console.log('bundle entries :', require('./feed.json').entryCount, '(expect about 8971)');
console.log('threat-intel.ts:', (fs.statSync('src/threat-intel.ts').size/1048576).toFixed(2), 'MB (expect about 1.58)');
"
node -e "const t=process.hrtime.bigint();require('./dist/threat-intel.js');console.log('import', Number(process.hrtime.bigint()-t)/1e6,'ms (expect about 32)')"
ls -la catalog-index.json catalog-*.json.gz
```

Record all of it in `.ai/handoff/STATUS.md`. The headline for the release notes
is that 56,294 previously undetected indicators are now covered while startup
got faster, which is the point of the whole exercise.

---

### Task 3: Retire the bulk-deferral path (Phase 4)

The deferral mechanism exists because volume had nowhere to go. It now does. The
mechanism stays for genuinely undecidable blocks, but it must stop being the
reflex for size.

**Files:**
- Modify: `scripts/import-threat-feed.mjs` (the undrainable-backlog guidance
  text)
- Modify: `docs/threat-feed-bulk-backfill-strategy.md`
- Modify: the daily threat-intel scheduled-task instructions (operator-local,
  outside this repository, not committed)

- [ ] **Step 1: Update the importer's own guidance**

The undrainable-backlog error currently tells the operator to defer or slice. It
should now tell them the catalog absorbs volume, and that deferral is for blocks
whose CORRECTNESS is undecided, not blocks that are merely large. Change the
message to name the catalog first and deferral last.

- [ ] **Step 2: Mark the strategy document superseded in full**

`docs/threat-feed-bulk-backfill-strategy.md` already carries a
partial-supersession banner from the design phase. Tier 1 (staged slicing) and
Tier 2 (liveness filtering) are now also moot for volume reasons. Update the
banner to say the whole of section 3 is superseded, and keep sections 1 and 2,
which remain the evidence that the block could not be declined.

- [ ] **Step 3: Correct a stale claim in the operator instructions**

The scheduled-task file states the importer defaults are `--days 14 --limit 250
--max-pages 750`. Measured: there is no implicit limit. `appliedLimit` is `null`
unless `--limit` is passed, and the code comment at the selection site says
exhaustive by default. The `--limit 250` guidance would have caused a partial
drain in Phase 3. Correct it, and note that an explicit range imports in full.

This file is local to the machine and is not committed, so record the correction
in `.ai/handoff/STATUS.md` as well, or the next machine keeps the stale copy.

- [ ] **Step 4: Add the regression that keeps this honest**

A test asserting the importer is exhaustive without `--limit`, so a future
change cannot quietly reintroduce an implicit cap:

```typescript
it("is exhaustive when no limit is supplied", async () => {
  const result = await runImporterAgainstFixture(makeCandidates(1200), { limit: undefined });
  expect(result.added).toHaveLength(1200);
  expect(result.capped).toBe(false);
});

it("caps only when a limit is explicitly supplied", async () => {
  const result = await runImporterAgainstFixture(makeCandidates(1200), { limit: 250 });
  expect(result.added).toHaveLength(250);
  expect(result.capped).toBe(true);
});
```

Prove it by cutting: give `appliedLimit` a default of 250 and watch the first
test go red and the second stay green. Restore.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs(feed): retire bulk deferral as the answer to volume

The deferral mechanism existed because a large upstream wave had nowhere to
go. The catalog is now that somewhere, so deferral is reserved for blocks
whose correctness is undecided rather than blocks that are merely large.

Also corrects a stale claim that the importer defaults to --limit 250. It is
exhaustive by default; a limit applies only when explicitly supplied. Acting
on the stale text during the Phase 3 drain would have imported 250 of 19158
entries and left a remainder no later run proposes. Adds a regression in both
directions so an implicit cap cannot be reintroduced quietly."
```

---

### Task 4: Release

- [ ] **Step 1: Cut the release**

Follow `CLAUDE.md` exactly: CHANGELOG, `SECURITY.md` only for a new major or
minor, version at every `versionSites` entry plus `package.json` and the ungated
`bundledVersion`, `npm install --package-lock-only`, then `npm run build` and
the targeted suites, one commit, PR, squash-merge, annotated tag on the merged
commit, push the tag.

Measure the version string's occurrences per file before editing.
`src/threat-intel.ts` in particular contains feed entries that merely CONTAIN
the version as a substring, and a blanket replace corrupts them with no gate to
catch it.

- [ ] **Step 2: Verify the release is immutable**

```bash
gh api repos/homeofe/supply-chain-guard/immutable-releases
gh api repos/homeofe/supply-chain-guard/releases/tags/<new tag> --jq .immutable
```

Expected: `{"enabled": true, ...}` and `true`. If the release reads `false`
while the setting reads `true`, the release was stamped before the setting
applied and the shipped digest is its only protection. Record the answer either
way.

Never verify this through `immutable_releases` on the repository object: that
field does not exist and returns `null` regardless, which is how this was got
wrong once already.

- [ ] **Step 3: Verify the catalog asset actually published and verifies**

```bash
gh release view <new tag> --json assets --jq '.assets[] | "\(.name) \(.size)"'
BASE="https://github.com/homeofe/supply-chain-guard/releases/download/<new tag>"
curl -sL "$BASE/catalog-index.json" -o index.json
node -e "
const z=require('node:zlib'), c=require('node:crypto'), fs=require('node:fs'), cp=require('node:child_process');
const idx = fs.readFileSync('index.json','utf8');
const { CATALOG_DIGEST } = require('./dist/catalog-digest.js');
const isha = c.createHash('sha256').update(idx,'utf8').digest('hex');
console.log('index', isha === CATALOG_DIGEST.sha256 ? 'MATCH' : 'MISMATCH');
const parsed = JSON.parse(idx);
let total = 0, bad = 0;
for (const s of parsed.shards) {
  cp.execSync('curl -sL \'' + process.env.BASE + '/' + s.path + '\' -o ' + s.path);
  const json = z.gunzipSync(fs.readFileSync(s.path)).toString('utf8');
  const sha = c.createHash('sha256').update(json,'utf8').digest('hex');
  if (sha !== s.sha256) { bad++; console.log(s.path, 'MISMATCH'); }
  total += JSON.parse(json).entries.length;
}
console.log('shards', parsed.shards.length, '| mismatched', bad, '| entries', total);
"
```

Expected: `index MATCH`, `mismatched 0`, and about 68,292 entries across 2
shards. This is the end-to-end proof that the whole chain of trust, package to
index to shard, works against the real published artifacts rather than against
fixtures.

- [ ] **Step 4: Verify a clean install detects a drained indicator after
      refresh**

```bash
ssh <your linux host>
WD=$(mktemp -d) && cd "$WD"
npm install -g supply-chain-guard@<new version>
mkdir proj && cd proj
echo '{"name":"t","dependencies":{"<a drained package name>":"<its version>"}}' > package.json
supply-chain-guard scan .            # expect: not flagged, plus THREAT_FEED_CATALOG_MISSING
supply-chain-guard feed refresh
supply-chain-guard scan .            # expect: flagged, and the finding gone
```

Both halves matter. The first proves the finding fires and the gap is real
without the catalog; the second proves the catalog closes it. Remove the temp
directory afterwards.

- [ ] **Step 5: Confirm the release invariant**

```bash
gh issue list -R homeofe/supply-chain-guard --state open --json number --jq 'length'
gh pr list -R homeofe/supply-chain-guard --state open --json number --jq 'length'
git ls-remote --heads origin
git branch --list
git worktree list
```

Expected: zero issues, zero PRs, and only `main` plus the `vN` major refs on the
remote, `main` locally.

---

## Self-review

- **Spec coverage.** Section 7 Phase 3 (drain): Tasks 1 and 2. Section 7 Phase 4
  (retire deferral): Task 3. Section 8 catalog detection parity: Task 1 Step 5
  and Task 4 Step 4. Section 4.4 immutability verification: Task 4 Step 2.
  Section 4.3 bounded decompression against a real artifact: Task 4 Step 3.
- **Placeholders.** Five `<name>` placeholders remain in Task 1 Step 5 and Task
  4 Step 4. They are deliberate: the specific package names cannot be chosen
  until the range is imported, and inventing them now would put unverified
  indicator names into a public plan. Each is accompanied by the command that
  produces the real value.
- **Type consistency.** No new interfaces. Every function named
  (`matchBareNpmIOC`, `matchPackageIOC`, `getBundledFeed`, `loadThreatIntel`,
  `CATALOG_DIGEST`) exists after Phases 1 and 2.
- **One ordering risk made explicit.** Task 2 Step 4 drains 19,158 entries in
  one PR. That is a large machine-generated diff, but JSONL makes it a pure
  append with line-level review, and splitting it would create a remainder that
  the daily job never re-proposes because an explicit range is not re-offered.

