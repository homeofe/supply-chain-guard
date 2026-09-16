# Threat-Feed Catalog Decoupling, Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the partition real. Move 11,998 historical package indicators out of the compiled bundle into the catalog, without orphaning a single line of curated rationale, and teach the importer to route new entries so the bundle stops growing.

**Architecture:** Three changes land together because the invariant breaks if they do not: `BUNDLE_CUTOFF_DATE` becomes finite, a migration script moves the now-unqualifying entries out of `src/threat-intel.ts` into `data/threat-catalog.jsonl`, and the importer routes new entries through `partitionTarget()` instead of always appending to the bundle. The budget then tightens to the new size.

**Tech Stack:** TypeScript (ESM syntax, CommonJS output, Node 22 floor), vitest, `.mjs` build scripts wired into `prebuild`, GitHub Actions.

**Spec:** `docs/threat-feed-catalog-decoupling-design.md`

**Depends on:** `docs/plans/2026-09-16-threat-feed-catalog-phase-1.md`, fully landed. Phase 1 changes nothing detectable, so every measurement below, taken against v6.1.3, is still the correct input.

## Global Constraints

- **No em-dashes or en-dashes** anywhere in code, comments, docs or commit messages. Use a plain hyphen or a colon.
- **No AI attribution** in any commit message, PR title or body: no model co-authorship trailer, no tool-generated footer, no model name. The repo is public and CI fails on it.
- **Never name the maintainer** in repository content. Write "the owner" or "the maintainer".
- **Defang IOCs** in comments and docs (`example[.]com`, `hxxps://`, `1[.]2[.]3[.]4`). Raw values in `src/` are compared, not displayed, and stay raw. Hashes stay raw.
- **The green baseline is 146 files / 3565 tests, all passing**, measured on Linux against `main` at v6.1.3 (`05c0729`), 54.7 seconds. Phase 1 adds test files, so both numbers must be higher and failures must still be zero.
- **Never run the full suite on Windows.** Run only the suite covering the change. For a real verdict, use a Linux host: clone into a fresh `mktemp -d` directory, `npm ci`, `npx vitest run`, then remove it. (The maintainer has an `ssh` alias for such a host; it is deliberately not named here, because this file is public.)
- **`src/threat-intel.ts` and `src/scanner.ts` are in `src/self-scan-files.json`.** Any task touching them must run `npm run self-scan:generate` and commit `self-scan-manifest.json`, or `check:self-scan` fails on an unrelated gate.
- **`main` is protected.** All work lands through a squash-merged PR.
- **Every gate is proved by cutting it**: green baseline, make the cut, watch the specific assertion go red, restore, green again.

## The measurements this plan is built on

Taken against the v6.1.3 feed on 2026-09-16. An implementer who gets materially different numbers should stop, because the input changed.

| quantity | value |
| --- | --- |
| bundled entries today | 20,969 |
| entries staying at a 30-day cutoff | 8,971 |
| entries moving to the catalog | 11,998 |
| `src/threat-intel.ts` today | 3.54 MB |
| projected after migration | 1.58 MB |
| module import today | 75 ms |
| projected after migration | ~32 ms |

Comment structure inside the `FEED_CHUNK_n` literals, which is what the migration must not damage:

| quantity | value |
| --- | --- |
| comment groups | 217 |
| importer batch headers | 86 (86 comment lines, 19,678 entries) |
| curated comment blocks | 131 (706 comment lines, 1,094 entries) |
| entries with no comment above them | 0 |
| groups where every entry moves | 45 (header removable) |
| groups where no entry moves | 158 |
| groups that SPLIT | 14 (header must stay) |

---

### Task 1: The migration's comment-aware parser

The migration cannot use `extractBundledEntries()`, which evaluates the array in a VM sandbox and discards comments. It needs a line-level parse that knows which comment block each entry sits beneath.

**Files:**
- Create: `scripts/feed-migrate.mjs`
- Test: `src/__tests__/feed-migrate.test.ts`

**Interfaces:**
- Produces: `export function parseChunks(source: string): Array<{ header: string[]; isCurated: boolean; entries: Array<{ line: string; value: string; firstSeen: string | null; hasCampaignField: boolean; isPackage: boolean }> }>`

- [ ] **Step 1: Write the failing test**

```typescript
import { parseChunks } from "../../scripts/feed-migrate.mjs";

const SRC = [
  'const FEED_CHUNK_0: FeedIOC[] = [',
  '  // Imported from GitHub Advisory Database (2026-01-01) - see docs/threat-feed-sources.md',
  '  { type: "package", value: "a@1.0.0", severity: "critical", firstSeen: "2026-01-01" },',
  '  { type: "package", value: "b@1.0.0", severity: "critical", firstSeen: "2026-01-02" },',
  '',
  '  // Some campaign (January 2026). Two lines of rationale that must survive',
  '  // whatever the migration does to the entries underneath it.',
  '  { type: "package", value: "c@1.0.0", severity: "critical", campaign: "x", firstSeen: "2026-01-03" },',
  '  { type: "ip", value: "1.2.3.4", severity: "critical", firstSeen: "2026-01-03" },',
  '];',
].join("\n");

describe("parseChunks", () => {
  it("separates importer headers from curated blocks", () => {
    const groups = parseChunks(SRC);
    expect(groups).toHaveLength(2);
    expect(groups[0].isCurated).toBe(false);
    expect(groups[0].header).toHaveLength(1);
    expect(groups[0].entries.map((e) => e.value)).toEqual(["a@1.0.0", "b@1.0.0"]);
    expect(groups[1].isCurated).toBe(true);
    expect(groups[1].header).toHaveLength(2);
    expect(groups[1].entries.map((e) => e.value)).toEqual(["c@1.0.0", "1.2.3.4"]);
  });

  it("extracts the fields the partition rules need", () => {
    const [imported, curated] = parseChunks(SRC);
    expect(imported.entries[0]).toMatchObject({
      value: "a@1.0.0", firstSeen: "2026-01-01", hasCampaignField: false, isPackage: true,
    });
    expect(curated.entries[0].hasCampaignField).toBe(true);
    expect(curated.entries[1].isPackage).toBe(false);
  });

  it("preserves each entry's exact source line", () => {
    const groups = parseChunks(SRC);
    expect(groups[0].entries[0].line).toBe(
      '  { type: "package", value: "a@1.0.0", severity: "critical", firstSeen: "2026-01-01" },',
    );
  });

  it("ignores anything outside a FEED_CHUNK literal", () => {
    const noise = 'const OTHER = [\n  { type: "package", value: "z@1", severity: "critical" },\n];\n' + SRC;
    const groups = parseChunks(noise);
    expect(groups.flatMap((g) => g.entries).some((e) => e.value === "z@1")).toBe(false);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed-migrate.test.ts -t "parseChunks"`
Expected: FAIL, cannot resolve `../../scripts/feed-migrate.mjs`.

- [ ] **Step 3: Implement**

```javascript
// feed-migrate.mjs - move entries out of the compiled bundle into the catalog.
//
// This parses src/threat-intel.ts at the LINE level rather than through
// extractBundledEntries(), which evaluates the array in a VM sandbox and
// therefore discards every comment. The comments are the point: 706 of them
// carry the curated rationale this project depends on, and a migration that
// cannot see them cannot avoid orphaning them.

const CHUNK_START = /^const FEED_CHUNK_\d+: FeedIOC\[\] = \[/;
const CHUNK_END = /^\];/;
const COMMENT = /^\s*\/\//;
const ENTRY = /^\s*\{ type:/;
const IMPORTER_HEADER = /Imported from/i;

/**
 * Group the chunk literals into {header comments, entries beneath them}.
 * A group starts at a run of comment lines and runs until the next such run.
 */
export function parseChunks(source) {
  const groups = [];
  const lines = source.split(/\r?\n/);
  let inChunk = false;
  let pending = [];
  let current = null;

  const flush = () => { if (current) { groups.push(current); current = null; } };

  for (const line of lines) {
    if (CHUNK_START.test(line)) { inChunk = true; flush(); pending = []; continue; }
    if (inChunk && CHUNK_END.test(line)) { inChunk = false; flush(); pending = []; continue; }
    if (!inChunk) continue;

    if (COMMENT.test(line)) {
      if (current) flush();
      pending.push(line);
      continue;
    }
    if (ENTRY.test(line)) {
      if (!current) {
        current = {
          header: pending,
          isCurated: pending.length > 0 && !IMPORTER_HEADER.test(pending[0]),
          entries: [],
        };
        pending = [];
      }
      const value = /value: "([^"]+)"/.exec(line);
      const firstSeen = /firstSeen: "([^"]+)"/.exec(line);
      current.entries.push({
        line,
        value: value ? value[1] : "",
        firstSeen: firstSeen ? firstSeen[1] : null,
        hasCampaignField: /campaign:|family:/.test(line),
        isPackage: /type: "package"/.test(line),
      });
    }
    // Blank lines keep the current group open.
  }
  flush();
  return groups;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed-migrate.test.ts -t "parseChunks"`
Expected: PASS, 4 tests.

- [ ] **Step 5: Verify the parser against the real file, with a control**

```bash
node -e "
const { parseChunks } = require('./scripts/feed-migrate.mjs');
const fs = require('node:fs');
const g = parseChunks(fs.readFileSync('src/threat-intel.ts','utf8'));
const imported = g.filter(x => !x.isCurated);
const curated = g.filter(x => x.isCurated);
console.log('groups', g.length, '| importer', imported.length, '| curated', curated.length);
console.log('entries', g.reduce((s,x)=>s+x.entries.length,0));
"
```

Expected exactly: `groups 217 | importer 86 | curated 131` and `entries 20969`. The entry count is the control: it must equal `feed.json`'s `entryCount`, or the parser is dropping lines and every later step is built on a short read.

- [ ] **Step 6: Commit**

```bash
git add scripts/feed-migrate.mjs src/__tests__/feed-migrate.test.ts
git commit -m "feat(feed): comment-aware parser for the bundle migration

extractBundledEntries() evaluates the chunk literals in a VM sandbox and
discards comments, so it cannot be used to move entries: 706 comment lines
carry the curated rationale and a migration that cannot see them cannot
avoid orphaning them. Verified against the real file, where it finds 217
groups (86 importer headers, 131 curated blocks) and all 20969 entries."
```

---

### Task 2: The migration rule, including the comment anchor

**Files:**
- Modify: `scripts/feed-migrate.mjs`
- Test: `src/__tests__/feed-migrate.test.ts`

**Interfaces:**
- Consumes: `parseChunks` (Task 1), `partitionTarget` and `loadPartitionConfig` from `scripts/feed-partition.mjs` (Phase 1 Task 2)
- Produces: `export function planMigration(source, config): { move: Array<{value, line}>; keep: number; groups: Array<{header, removeHeader, movedCount, keptCount}> }`

- [ ] **Step 1: Write the failing test**

```typescript
import { planMigration } from "../../scripts/feed-migrate.mjs";

const CONFIG = { bundleCutoffDate: "2026-06-01", maxBundledEntries: 15000, maxBundleBytes: 2097152 };

function chunk(...lines: string[]) {
  return ["const FEED_CHUNK_0: FeedIOC[] = [", ...lines, "];"].join("\n");
}
const old = (v: string, extra = "") =>
  `  { type: "package", value: "${v}", severity: "critical"${extra}, firstSeen: "2026-01-01" },`;
const recent = (v: string) =>
  `  { type: "package", value: "${v}", severity: "critical", firstSeen: "2026-09-01" },`;

describe("planMigration", () => {
  it("moves an old plain package under an importer header", () => {
    const plan = planMigration(chunk("  // Imported from GitHub Advisory Database (2026-01-01)", old("a@1")), CONFIG);
    expect(plan.move.map((m) => m.value)).toEqual(["a@1"]);
  });

  it("keeps a recent package", () => {
    const plan = planMigration(chunk("  // Imported from GitHub Advisory Database (2026-09-01)", recent("b@1")), CONFIG);
    expect(plan.move).toEqual([]);
  });

  it("keeps an old entry that carries a campaign field", () => {
    const plan = planMigration(chunk("  // Imported from GitHub Advisory Database (2026-01-01)", old("c@1", ', campaign: "x"')), CONFIG);
    expect(plan.move).toEqual([]);
  });

  it("keeps an old plain package beneath a CURATED comment block", () => {
    const plan = planMigration(chunk("  // Hand-added because the importer could not reach it.", old("d@1")), CONFIG);
    expect(plan.move).toEqual([]);
  });

  it("removes an importer header only when every entry beneath it moved", () => {
    const all = planMigration(chunk("  // Imported from GitHub Advisory Database (2026-01-01)", old("e@1"), old("f@1")), CONFIG);
    expect(all.groups[0].removeHeader).toBe(true);

    const split = planMigration(chunk("  // Imported from GitHub Advisory Database (2026-01-01)", old("g@1"), recent("h@1")), CONFIG);
    expect(split.groups[0].removeHeader).toBe(false);
    expect(split.move.map((m) => m.value)).toEqual(["g@1"]);
  });

  it("never removes a curated header, even when every entry beneath it moved", () => {
    const plan = planMigration(chunk("  // Curated rationale.", old("i@1", ', campaign: "x"')), CONFIG);
    expect(plan.groups[0].removeHeader).toBe(false);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed-migrate.test.ts -t "planMigration"`
Expected: FAIL, `planMigration is not a function`.

- [ ] **Step 3: Implement**

```javascript
import { partitionTarget } from "./feed-partition.mjs";

/**
 * Decide what moves. Rules 1, 2 and 4 come from partitionTarget(), which the
 * importer also uses. Rule 3, the comment anchor, is applied here and only
 * here: it protects entries a human authored beneath a curated comment, and
 * the importer never needs it because its own output sits under an importer
 * batch header.
 *
 * Measured cost of rule 3 on the v6.1.3 feed: 4 entries out of 12,002 stay
 * bundled so that three curated comment blocks keep the entries they describe.
 */
export function planMigration(source, config) {
  const groups = parseChunks(source);
  const move = [];
  let keep = 0;
  const report = [];

  for (const group of groups) {
    let moved = 0;
    for (const entry of group.entries) {
      const immovable =
        group.isCurated ||
        partitionTarget(
          {
            type: entry.isPackage ? "package" : "other",
            value: entry.value,
            firstSeen: entry.firstSeen ?? undefined,
            ...(entry.hasCampaignField ? { campaign: "present" } : {}),
          },
          config,
        ) === "bundle";

      if (immovable) { keep++; continue; }
      move.push({ value: entry.value, line: entry.line });
      moved++;
    }
    report.push({
      header: group.header,
      // A curated header is never removed: its rationale outlives its entries.
      removeHeader: !group.isCurated && group.entries.length > 0 && moved === group.entries.length,
      movedCount: moved,
      keptCount: group.entries.length - moved,
    });
  }

  return { move, keep, groups: report };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed-migrate.test.ts -t "planMigration"`
Expected: PASS, 6 tests.

- [ ] **Step 5: Prove the comment anchor by cutting it**

Remove `group.isCurated ||` from the `immovable` expression. Re-run. Expected: "keeps an old plain package beneath a CURATED comment block" goes RED and the other five stay green. Restore and confirm green. This is the rule that exists solely to protect rationale, so it must be shown to be load-bearing rather than decorative.

- [ ] **Step 6: Dry-run against the real file**

```bash
node -e "
const { planMigration } = require('./scripts/feed-migrate.mjs');
const { loadPartitionConfig } = require('./scripts/feed-partition.mjs');
const fs = require('node:fs');
const cfg = { ...loadPartitionConfig(), bundleCutoffDate: '2026-08-17' };
const p = planMigration(fs.readFileSync('src/threat-intel.ts','utf8'), cfg);
console.log('move', p.move.length, '| keep', p.keep, '| total', p.move.length + p.keep);
console.log('headers removable', p.groups.filter(g => g.removeHeader).length);
console.log('groups split', p.groups.filter(g => g.movedCount > 0 && g.keptCount > 0).length);
"
```

Expected, with a cutoff 30 days before 2026-09-16: `move 11998 | keep 8971 | total 20969`, `headers removable 45`, `groups split 14`. If `total` is not 20969 the parser lost entries and nothing below is trustworthy.

- [ ] **Step 7: Commit**

```bash
git add scripts/feed-migrate.mjs src/__tests__/feed-migrate.test.ts
git commit -m "feat(feed): migration rule with the curated-comment anchor

Rules 1, 2 and 4 come from partitionTarget, shared with the importer. Rule 3,
the comment anchor, lives here: an entry beneath a curated comment block never
moves, because curation in this repo is expressed in comments rather than in
fields. Measured: 1094 entries sit under a curated block and 60 carry no
campaign or family field, so without this rule their rationale is orphaned as
they age past the cutoff. Cost is 4 entries of 12002.

An importer batch header is removed only when every entry beneath it moved. A
curated header is never removed."
```

---

### Task 3: Apply the migration

**Files:**
- Modify: `scripts/feed-migrate.mjs` (writer + CLI)
- Modify: `src/threat-intel.ts` (generated result)
- Modify: `data/threat-catalog.jsonl` (generated result)
- Modify: `feed-partition.config.json`
- Test: `src/__tests__/feed-migrate.test.ts`

**Interfaces:**
- Produces: `export function applyMigration(source, plan): { source: string; catalogLines: string[] }`

- [ ] **Step 1: Write the failing test**

```typescript
import { applyMigration, planMigration, parseChunks } from "../../scripts/feed-migrate.mjs";

describe("applyMigration", () => {
  const SRC = [
    "const FEED_CHUNK_0: FeedIOC[] = [",
    "  // Imported from GitHub Advisory Database (2026-01-01)",
    '  { type: "package", value: "a@1", severity: "critical", firstSeen: "2026-01-01" },',
    "",
    "  // Curated rationale that must survive.",
    '  { type: "package", value: "b@1", severity: "critical", firstSeen: "2026-01-01" },',
    "",
    "  // Imported from GitHub Advisory Database (2026-09-01)",
    '  { type: "package", value: "c@1", severity: "critical", firstSeen: "2026-09-01" },',
    "];",
  ].join("\n");
  const CONFIG = { bundleCutoffDate: "2026-06-01", maxBundledEntries: 15000, maxBundleBytes: 2097152 };

  it("removes only the moved entry lines", () => {
    const { source } = applyMigration(SRC, planMigration(SRC, CONFIG));
    expect(source).not.toContain('value: "a@1"');
    expect(source).toContain('value: "b@1"');
    expect(source).toContain('value: "c@1"');
  });

  it("keeps every curated comment line", () => {
    const { source } = applyMigration(SRC, planMigration(SRC, CONFIG));
    expect(source).toContain("// Curated rationale that must survive.");
  });

  it("removes an importer header whose entries all left", () => {
    const { source } = applyMigration(SRC, planMigration(SRC, CONFIG));
    expect(source).not.toContain("(2026-01-01)");
    expect(source).toContain("(2026-09-01)");
  });

  it("emits one JSONL line per moved entry", () => {
    const { catalogLines } = applyMigration(SRC, planMigration(SRC, CONFIG));
    expect(catalogLines).toHaveLength(1);
    expect(JSON.parse(catalogLines[0])).toMatchObject({ value: "a@1", type: "package" });
  });

  it("leaves no comment line without an entry beneath it", () => {
    const { source } = applyMigration(SRC, planMigration(SRC, CONFIG));
    for (const g of parseChunks(source)) {
      expect(g.entries.length).toBeGreaterThan(0);
    }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed-migrate.test.ts -t "applyMigration"`
Expected: FAIL, `applyMigration is not a function`.

- [ ] **Step 3: Implement**

```javascript
import { readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Rewrite the source with the moved entry lines removed, and render the moved
 * entries as JSONL. Line-exact: an entry line is deleted by identity, never
 * reformatted, so the diff shows only removals and nothing else shifts.
 */
export function applyMigration(source, plan) {
  const movedLines = new Set(plan.move.map((m) => m.line));
  const removableHeaders = new Set(
    plan.groups.filter((g) => g.removeHeader).flatMap((g) => g.header),
  );

  const kept = [];
  for (const line of source.split(/\r?\n/)) {
    if (movedLines.has(line)) continue;
    if (removableHeaders.has(line)) continue;
    kept.push(line);
  }

  // Parse each moved line into a FeedIOC. The line is a JS object literal, not
  // JSON, so read the fields rather than trying to JSON.parse it.
  const catalogLines = plan.move.map((m) => {
    const entry = {};
    for (const [, k, v] of m.line.matchAll(/(\w+): "([^"]*)"/g)) entry[k] = v;
    const num = /confidence: ([\d.]+)/.exec(m.line);
    if (num) entry.confidence = Number(num[1]);
    return JSON.stringify(entry);
  });

  return { source: kept.join("\n"), catalogLines };
}
```

Add the CLI entry point:

```javascript
const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const { loadPartitionConfig } = await import("./feed-partition.mjs");
  const config = loadPartitionConfig(repoRoot);
  const target = join(repoRoot, "src", "threat-intel.ts");
  const original = readFileSync(target, "utf8");
  const plan = planMigration(original, config);

  console.log(`migration plan: move ${plan.move.length}, keep ${plan.keep}, total ${plan.move.length + plan.keep}`);
  console.log(`  headers removable: ${plan.groups.filter((g) => g.removeHeader).length}`);
  console.log(`  groups split     : ${plan.groups.filter((g) => g.movedCount > 0 && g.keptCount > 0).length}`);

  if (process.argv.includes("--dry-run")) { console.log("Nothing written (--dry-run)."); process.exit(0); }

  const { source, catalogLines } = applyMigration(original, plan);
  writeFileSync(target, source);
  appendFileSync(join(repoRoot, "data", "threat-catalog.jsonl"), catalogLines.map((l) => l + "\n").join(""));
  console.log(`migrated ${catalogLines.length} entries into data/threat-catalog.jsonl`);
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed-migrate.test.ts -t "applyMigration"`
Expected: PASS, 5 tests.

- [ ] **Step 5: Dry run against the real file**

```bash
node scripts/feed-migrate.mjs --dry-run
```

The cutoff is still the Phase 1 placeholder, so this must report `move 0`. That is the control: it proves the migration is inert until the cutoff is deliberately moved, rather than firing on whatever the config happens to say.

- [ ] **Step 6: Automate the cutoff, then migrate**

The cutoff is the one value a release moves, and it must not become a thing
someone remembers. Add `scripts/release-prepare.mjs`:

```javascript
// release-prepare.mjs - move the bundle cutoff and migrate, as part of a release.
//
// The cutoff is NOT derived from the clock at build time: that would make the
// generated files a function of the day they were generated, so the same commit
// would produce different output tomorrow and check:feed would fail on an
// untouched tree. It is NOT derived from the newest feed entry either: that
// would slide the window on every daily import, putting a migration inside
// every threat-intel pull request and burying the day's additions in hundreds
// of unrelated removals. Reviewing those diffs is a security control here.
//
// Binding it to the release gets the automation without either cost: a release
// is already a deliberate, reviewed, gated event that regenerates many files.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const WINDOW_DAYS = 30;

export function cutoffFor(now, windowDays = WINDOW_DAYS) {
  return new Date(now.getTime() - windowDays * 86_400_000).toISOString().slice(0, 10);
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const p = join(repoRoot, "feed-partition.config.json");
  const config = JSON.parse(readFileSync(p, "utf8"));
  const previous = config.bundleCutoffDate;
  config.bundleCutoffDate = cutoffFor(new Date());
  writeFileSync(p, `${JSON.stringify(config, null, 2)}\n`);
  console.log(`bundleCutoffDate ${previous} -> ${config.bundleCutoffDate}`);
  console.log("Now run: node scripts/feed-migrate.mjs && npm run feed:generate && npm run catalog:generate");
}
```

Add its test, pinning `now` so the test does not read the real clock. This file
has been broken once already by tests that did:

```typescript
import { cutoffFor } from "../../scripts/release-prepare.mjs";

describe("cutoffFor", () => {
  it("is 30 days before the given date", () => {
    expect(cutoffFor(new Date("2026-09-16T00:00:00Z"))).toBe("2026-08-17");
  });
  it("does not read the clock", () => {
    const a = cutoffFor(new Date("2026-09-16T00:00:00Z"));
    const realNow = Date.now;
    Date.now = () => realNow() + 400 * 86400000;
    try { expect(cutoffFor(new Date("2026-09-16T00:00:00Z"))).toBe(a); }
    finally { Date.now = realNow; }
  });
});
```

Add the script and tighten the limits to the decided values in
`feed-partition.config.json`:

```json
    "release:prepare": "node scripts/release-prepare.mjs",
```

```json
{
  "bundleCutoffDate": "2026-08-17",
  "maxBundledEntries": 15000,
  "maxBundleBytes": 2097152
}
```

Then run the sequence a release will run from now on:

```bash
npm run release:prepare
node scripts/feed-migrate.mjs
npm run feed:generate
npm run catalog:generate
npm run self-scan:generate
npm run handoff:refresh
```

Expected: `move 11998, keep 8971, total 20969`, then `feed.json` regenerated at 8971 entries and the catalog at 11998 across 1 shard (it crosses into 2 shards in Phase 3).

- [ ] **Step 7: Verify the migration preserved everything**

```bash
node -e "
const { parseChunks } = require('./scripts/feed-migrate.mjs');
const fs = require('node:fs');
const src = fs.readFileSync('src/threat-intel.ts','utf8');
const groups = parseChunks(src);
const orphan = groups.filter(g => g.entries.length === 0);
console.log('orphaned comment groups:', orphan.length);
const curatedLines = groups.filter(g => g.isCurated).reduce((s,g) => s + g.header.length, 0);
console.log('curated comment lines remaining:', curatedLines, '(was 706)');
const bundle = groups.reduce((s,g) => s + g.entries.length, 0);
const cat = fs.readFileSync('data/threat-catalog.jsonl','utf8').split('\n').filter(l => l.trim()).length;
console.log('bundle', bundle, '+ catalog', cat, '=', bundle + cat, '(must be 20969)');
console.log('threat-intel.ts', (fs.statSync('src/threat-intel.ts').size/1048576).toFixed(2), 'MB (was 3.54)');
"
```

Expected: `orphaned comment groups: 0`, `curated comment lines remaining: 706`, `bundle 8971 + catalog 11998 = 20969`, and about 1.58 MB. All four are load-bearing: zero orphans and 706 preserved lines are the whole point of Tasks 1 and 2, and the sum proves nothing was lost rather than merely moved.

- [ ] **Step 8: Confirm the gates agree**

```bash
npm run check:feed-partition
npm run check:feed-budget
npm run build
```

Expected: partition clean, budget green at 8,971 of 15,000 and 1.58 MB of 2 MiB, and the full prebuild chain plus `tsc` green.

- [ ] **Step 9: Measure the improvement**

```bash
node -e "const t=process.hrtime.bigint();require('./dist/threat-intel.js');console.log('import', Number(process.hrtime.bigint()-t)/1e6, 'ms (was 75)')"
npm pack --dry-run --json | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const j=JSON.parse(s)[0];console.log('packed',(j.size/1048576).toFixed(2),'MB | unpacked',(j.unpackedSize/1048576).toFixed(2),'MB (were 1.30 / 9.91)')})"
```

Record both numbers in the PR body and in `.ai/handoff/STATUS.md`. They are the evidence that this phase did what it claimed, and Phase 3 and 4 plans are written against them.

- [ ] **Step 9b: Record the recurring cutoff step in the release documentation**

`BUNDLE_CUTOFF_DATE` is the one value a release has to move by hand, so it belongs in the committed release documentation rather than only in a gate message. Add to `docs/ci-and-release.md`, in the release checklist:

```markdown
- **Run `npm run release:prepare`**, then `node scripts/feed-migrate.mjs` and
  regenerate. This moves `bundleCutoffDate` to 30 days before today and
  migrates the entries that fall outside it. It is the one value a release
  moves, and the script moves it, so nobody has to remember a date. If a
  release is ever skipped long enough to matter, `check:feed-budget` fails the
  build and prints the exact date to set.
```

Do not put it only in a gitignored file. The gate names the value and the
committed documentation names the step, so neither a new maintainer nor a fresh
machine has to rediscover it.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "feat(feed): migrate historical indicators into the catalog

Moves 11998 of 20969 entries out of the compiled bundle. src/threat-intel.ts
drops from 3.54 MB to about 1.58 MB and module import from 75 ms to about
32 ms, paid on every CLI invocation and every Action run.

Nothing is lost: bundle plus catalog is still 20969, all 706 curated comment
lines survive, and no comment group is left without an entry beneath it. An
importer batch header is removed only when every entry under it moved; 45
qualified and 14 groups split, keeping their header.

Sets bundleCutoffDate to 30 days before the release and tightens the budget
to 15000 entries and 2 MiB, which the result fits with room to spare."
```

---

### Task 4: Route new entries at import time

Without this the bundle starts growing again on the next daily import and the migration is undone within weeks.

**Files:**
- Modify: `scripts/import-threat-feed.mjs`
- Test: `src/__tests__/feed-import.test.ts`

**Interfaces:**
- Consumes: `partitionTarget`, `loadPartitionConfig`

- [ ] **Step 1: Write the failing test**

```typescript
describe("importer routing", () => {
  it("routes a recent entry to the bundle and an old one to the catalog", async () => {
    const result = await runImporterAgainstFixture([
      { value: "fresh@1.0.0", firstSeen: todayIso() },
      { value: "stale@1.0.0", firstSeen: "2026-01-01" },
    ]);
    expect(result.bundleAdded.map((e) => e.value)).toEqual(["fresh@1.0.0"]);
    expect(result.catalogAdded.map((e) => e.value)).toEqual(["stale@1.0.0"]);
  });

  it("never routes a non-package IOC to the catalog", async () => {
    const result = await runImporterAgainstFixture([
      { type: "ip", value: "203.0.113.9", firstSeen: "2020-01-01" },
    ]);
    expect(result.catalogAdded).toEqual([]);
    expect(result.bundleAdded).toHaveLength(1);
  });

  it("reports both destinations in its summary", async () => {
    const result = await runImporterAgainstFixture([
      { value: "fresh@1.0.0", firstSeen: todayIso() },
      { value: "stale@1.0.0", firstSeen: "2026-01-01" },
    ]);
    expect(result.summary).toMatch(/1 to the bundle/);
    expect(result.summary).toMatch(/1 to the catalog/);
  });
});
```

Follow the fixture helpers already used in `src/__tests__/feed-import.test.ts` rather than inventing new ones, and pin `now` explicitly: that file has already been broken once by tests that read the real clock.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed-import.test.ts -t "importer routing"`
Expected: FAIL, everything lands in the bundle.

- [ ] **Step 3: Implement**

In `scripts/import-threat-feed.mjs`, at the point where accepted candidates are appended to the last `FEED_CHUNK_n`, split them first:

```javascript
import { partitionTarget, loadPartitionConfig } from "./feed-partition.mjs";

const partitionConfig = loadPartitionConfig(repoRoot);
const toBundle = [];
const toCatalog = [];
for (const entry of accepted) {
  (partitionTarget(entry, partitionConfig) === "catalog" ? toCatalog : toBundle).push(entry);
}
```

Append `toBundle` to the chunk literal exactly as today, and `toCatalog` to `data/threat-catalog.jsonl` as one JSON object per line. Report both counts in the summary, so a run that silently sends everything one way is visible:

```javascript
console.log(`  New entries:          ${accepted.length} (${toBundle.length} to the bundle, ${toCatalog.length} to the catalog)`);
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed-import.test.ts -t "importer routing"`
Expected: PASS, 3 tests.

- [ ] **Step 5: Prove the routing by cutting it**

Replace the ternary with `toBundle.push(entry)` unconditionally. Re-run and expect the first and third tests to go red while the second stays green, because a non-package IOC belongs in the bundle either way. Restore and confirm green.

- [ ] **Step 6: Dry-run the real importer**

```bash
export GITHUB_TOKEN=$(gh auth token)
npm run feed:import -- --dry-run
```

Expected: exit 0, and the summary now names both destinations. Almost every candidate should route to the bundle, because the importer fetches a 14-day window and the cutoff is 30 days, so routing to the catalog is the exception for a normal daily run. That asymmetry is the expected shape; a run that sends most entries to the catalog means the cutoff was moved too far forward.

- [ ] **Step 7: Commit**

```bash
git add scripts/import-threat-feed.mjs src/__tests__/feed-import.test.ts
git commit -m "feat(importer): route new entries by the partition policy

Without this the bundle grows again on the next daily run and the migration
is undone within weeks. Uses the same partitionTarget() the migration and the
placement gate use, so an entry cannot mean different things in different
places. The summary names both destinations, so a run that silently sends
everything one way is visible rather than discovered later."
```

---

### Task 5: Phase 2 acceptance

- [ ] **Step 1: Verify the release immutability setting actually took effect**

The repository API does not expose `immutable_releases`, so the only honest check is on a release published after the setting changed:

```bash
gh api repos/homeofe/supply-chain-guard/immutable-releases
gh api repos/homeofe/supply-chain-guard/releases/tags/<the first tag after the change> --jq .immutable
```

Expected: `{"enabled": true, ...}` from the first, and `true` from the second.

Check BOTH. The repository setting says immutability is on from now on; the release flag says this particular release actually got it. The setting was enabled on 2026-09-16, and it does not retrofit, so v6.1.1 through v6.1.3 remain `false` permanently. If the setting reads `true` but the release reads `false`, something stamped the release before the setting applied and the shipped digest is that release's only protection.

Do not verify this by reading `immutable_releases` on the repository object. No such field exists there, so it returns `null` whether the feature is on or off, and an earlier revision of this design was misled by exactly that for a full day.

- [ ] **Step 2: Confirm the catalog is now real and verifiable**

```bash
npm run check:catalog
node -e "
const d = require('./src/catalog-digest.ts'.replace('.ts','.js'));
console.log('digest entries', d.CATALOG_DIGEST.entryCount, 'version', d.CATALOG_DIGEST.version);
"
```

Expected: `catalog digest up to date`, `entryCount 11998`, `shardCount 1`.

One shard here, two after Phase 3 crosses 50,000 entries. Check `shardCount`
explicitly rather than only `entryCount`: the sharding path is what removes the
catalog's ceiling, and a generator that silently stopped sharding would look
identical on entry count alone.

- [ ] **Step 3: Confirm the finding clears after a refresh**

```bash
node dist/cli.js scan . --format json | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const r=JSON.parse(s);const f=r.findings.find(x=>x.rule==='THREAT_FEED_CATALOG_MISSING');console.log(f?f.severity+': '+f.description.slice(0,70):'not emitted')})"
```

Expected before a refresh: `medium: The historical indicator catalog was not consulted...`. After `node dist/cli.js feed refresh` against a published catalog, expected: `not emitted`. Both directions matter: a finding that never clears is as useless as one that never fires.

- [ ] **Step 4: Get the real full-suite verdict on Linux**

```bash
ssh <your linux host>
WD=$(mktemp -d) && cd "$WD"
git clone --quiet --branch feat/threat-feed-catalog-phase-2 https://github.com/homeofe/supply-chain-guard.git repo
cd repo && npm ci --silent && npx vitest run --reporter=dot
```

Expected: zero failures, with file and test counts at or above the Phase 1 numbers. Remove the temp directory afterwards.

- [ ] **Step 5: Record the measurements and open the PR**

Prepend a dated note to `.ai/handoff/STATUS.md` with the measured post-migration bundle size, import time and package size, and the answer to Step 1. Run `npm run handoff:refresh`, then open the PR. The body must state the before and after numbers and that bundle plus catalog still equals 20,969, because that is the claim a reviewer needs to check.

---

## Phases 3 and 4

See `docs/plans/2026-09-16-threat-feed-catalog-phases-3-4.md`. Phase 3 drains the five deferral ranges through the routing built in Task 4; Phase 4 retires the bulk-deferral mechanism. Neither can start before this phase lands, because both depend on the importer routing to a catalog that exists.

## Self-review

- **Spec coverage.** Section 4.2 rule 3 (comment anchor): Task 2. Section 7 Phase 2 migration and comment preservation: Tasks 1 to 3. Importer routing, which Phase 3 depends on: Task 4. Section 6.1 budget tightening: Task 3 Step 6. Section 4.4 immutability verification: Task 5 Step 1. Section 8 catalog detection parity: Task 5 Step 3.
- **Type consistency.** `parseChunks` is defined in Task 1 and consumed in Tasks 2 and 3. `planMigration` is defined in Task 2 and consumed in Task 3. `partitionTarget` and `loadPartitionConfig` come from Phase 1 Task 2 and are consumed in Tasks 2 and 4.
- **One risk left explicit rather than hidden.** `applyMigration` deletes entry lines by exact string identity. If two entries in different chunks share a byte-identical line, both are removed when one moves. Measured on the v6.1.3 feed: entry lines are unique, because each carries a distinct `value`. Task 3 Step 7's `bundle + catalog = 20969` assertion catches it if that ever stops being true.
