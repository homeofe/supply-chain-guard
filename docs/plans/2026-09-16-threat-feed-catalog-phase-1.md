# Threat-Feed Catalog Decoupling, Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete catalog path (routing policy, gates, transport, cache, finding) without moving a single indicator out of the bundle, so that detection is provably unchanged when the phase lands.

**Architecture:** `src/threat-intel.ts` stays the authored bundle, untouched. A new `data/threat-catalog.jsonl` becomes the catalog store, committed empty in this phase. Placement across the two stores is enforced by a build gate rather than by regeneration. The existing feed transport gains bounded gzip decompression, a `kind` discriminator, a second cache keyed by version and SHA-256, and a finding that fires whenever the catalog is absent, version-mismatched or digest-mismatched.

**Tech Stack:** TypeScript (ESM, Node 22 floor), vitest, `.mjs` build scripts run by `npm run` and wired into `prebuild`, GitHub Actions.

**Spec:** `docs/threat-feed-catalog-decoupling-design.md`

## Global Constraints

Copied verbatim from the project's rules. Every task's requirements implicitly include this section.

- **No em-dashes or en-dashes** anywhere in code, comments, docs or commit messages. Use a plain hyphen or a colon. See the Language section of `.ai/handoff/CONVENTIONS.md`.
- **No AI attribution** in any commit message, PR title or body: no model co-authorship trailer, no tool-generated footer, no model name. The repo is public and CI fails on it. Agent notes belong in `.ai/handoff/STATUS.md`.
- **Never name the maintainer** in repository content. Write "the owner" or "the maintainer".
- **Defang IOCs** in comments and docs: `example[.]com`, `hxxps://`, `1[.]2[.]3[.]4`. Raw values in `src/` code are compared, not displayed, and stay raw. Hashes stay raw.
- **Never run the full test suite locally.** Run only the suite file covering the change: `npx vitest run src/__tests__/<file>.test.ts`. CI produces the full-suite verdict.
- **Never bypass hooks** (`--no-verify`, `--no-gpg-sign`).
- **`main` is protected.** All work lands through a squash-merged PR.
- **The green baseline is 146 files / 3565 tests, all passing.** Measured on 2026-09-16 on Linux against `main` at v6.1.3 (`05c0729`), 54.7 seconds wall clock. Any other number means something broke.
- On Windows that baseline is unreachable and the difference is environmental, not a regression. Two campaign tests (`Phantom Bot C2 domain`, `GlassWASM stage-2 delivery host`) fail there on unmodified `main`, and the vscode-scanner archive tests fail for a missing `zip` binary. Both pass on Linux. Never call the suite broken from a Windows run without first running the same suite on unmodified `main`.
- For a real full-suite verdict without waiting for CI, use the Linux runner: `ssh openclaw`, clone into a fresh `mktemp -d /tmp/...` directory, `npm ci`, `npx vitest run`. That is under a minute against hours on Windows. Remove the temp directory afterwards.
- **Every gate is proved by cutting it**, never by reading it: show a green baseline, make the cut, watch the specific assertion go red, restore, show green again.

---

### Task 1: Recognize the catalog file as inert detection data

Must land before any catalog file is committed. `collectFiles()` does not exclude `data/`, and `isInertThreatFeedFile()` accepts only the basenames `feed.json` and `threat-feed.json` with a JSON-object shape, so a committed `.jsonl` catalog would be scanned as ordinary content and flood the self-scan with criticals from the project's own detection data.

**Files:**
- Modify: `src/threat-intel.ts` (beside `isInertThreatFeedFile`, around line 22436)
- Modify: `src/scanner.ts:449`
- Test: `src/__tests__/self-scan-recognition.test.ts`

**Interfaces:**
- Consumes: `FEED_ENTRY_KEYS` (existing module-private `Set<string>` in `src/threat-intel.ts`)
- Produces: `export function isInertThreatCatalogFile(filename: string, content: string): boolean`

- [ ] **Step 1: Write the failing test**

```typescript
import { isInertThreatCatalogFile } from "../threat-intel.js";

const LINE = JSON.stringify({
  type: "package", value: "evil-pkg@1.0.0", severity: "critical",
  confidence: 1, source: "GHSA-x", firstSeen: "2026-09-16",
});

describe("isInertThreatCatalogFile", () => {
  it("accepts a well-formed catalog", () => {
    expect(isInertThreatCatalogFile("data/threat-catalog.jsonl", `${LINE}\n${LINE}\n`)).toBe(true);
  });
  it("accepts an empty catalog", () => {
    expect(isInertThreatCatalogFile("data/threat-catalog.jsonl", "")).toBe(true);
  });
  it("rejects a key outside the entry allowlist", () => {
    const bad = JSON.stringify({ type: "package", value: "x@1", severity: "critical", exploit: "rm -rf /" });
    expect(isInertThreatCatalogFile("data/threat-catalog.jsonl", bad)).toBe(false);
  });
  it("rejects a non-scalar value", () => {
    const bad = JSON.stringify({ type: "package", value: { nested: "payload" }, severity: "critical" });
    expect(isInertThreatCatalogFile("data/threat-catalog.jsonl", bad)).toBe(false);
  });
  it("rejects any other basename", () => {
    expect(isInertThreatCatalogFile("data/other.jsonl", LINE)).toBe(false);
  });
  it("rejects a line that is not JSON", () => {
    expect(isInertThreatCatalogFile("data/threat-catalog.jsonl", "not json")).toBe(false);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/self-scan-recognition.test.ts -t "isInertThreatCatalogFile"`
Expected: FAIL, `isInertThreatCatalogFile is not a function`.

- [ ] **Step 3: Implement**

Add to `src/threat-intel.ts`, immediately after `isInertThreatFeedFile`:

```typescript
/** Basename of the committed catalog store. */
export const CATALOG_FILE = "threat-catalog.jsonl";

/**
 * Structural check: is this file supply-chain-guard's own catalog store?
 *
 * Same reasoning as isInertThreatFeedFile above, for the JSONL catalog: it
 * holds RAW IOC values as machine-readable detection data, and without this
 * check the project's own self-scan drowns in phantom criticals from its own
 * protection data. Shares FEED_ENTRY_KEYS with the feed check so the two
 * cannot drift apart.
 *
 * Strictness is the security property: every non-empty line must be a JSON
 * object whose every key is allowlisted and whose every value is an inert
 * scalar. Any deviation means the file is scanned like everything else.
 */
export function isInertThreatCatalogFile(filename: string, content: string): boolean {
  const base = filename.replace(/\\/g, "/").split("/").pop() ?? "";
  if (base !== CATALOG_FILE) return false;
  for (const line of content.split("\n")) {
    if (line.trim() === "") continue;
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      return false;
    }
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return false;
    for (const [k, v] of Object.entries(entry as Record<string, unknown>)) {
      if (!FEED_ENTRY_KEYS.has(k)) return false;
      if (typeof v !== "string" && typeof v !== "number") return false;
    }
  }
  return true;
}
```

In `src/scanner.ts`, extend the import on line 88 to include `isInertThreatCatalogFile`, and change line 449 from:

```typescript
    if (isInertThreatFeedFile(relativePath, content)) continue;
```

to:

```typescript
    if (isInertThreatFeedFile(relativePath, content)) continue;
    if (isInertThreatCatalogFile(relativePath, content)) continue;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/self-scan-recognition.test.ts -t "isInertThreatCatalogFile"`
Expected: PASS, 6 tests.

- [ ] **Step 5: Prove the guard by cutting it**

Temporarily change `if (!FEED_ENTRY_KEYS.has(k)) return false;` to `if (false) return false;`. Re-run. Expected: the "rejects a key outside the entry allowlist" case goes RED and the others stay green. Restore the line and re-run to confirm green again. Record both observations in the commit body.

- [ ] **Step 6: Commit**


**`src/threat-intel.ts` and `src/scanner.ts` are both listed in `src/self-scan-files.json`, so `check:self-scan` goes red the moment either is edited.** Run `npm run self-scan:generate` and include `self-scan-manifest.json` in this task's commit, or the next `npm run build` fails on a gate that has nothing to do with the change. `src/feed.ts` is NOT listed, so tasks touching only it are unaffected.

```bash
npm run self-scan:generate
git add src/threat-intel.ts src/scanner.ts self-scan-manifest.json src/__tests__/self-scan-recognition.test.ts
git commit -m "feat(scanner): recognize the catalog store as inert detection data

Same mechanism as isInertThreatFeedFile, extended to the JSONL catalog, and
sharing FEED_ENTRY_KEYS so the two cannot drift. Lands before any catalog
file is committed: collectFiles() does not exclude data/ and the existing
check is basename-locked to feed.json, so a committed catalog would
otherwise be scanned as ordinary content."
```

---

### Task 2: Partition policy as one shared function

**Files:**
- Create: `feed-partition.config.json`
- Create: `scripts/feed-partition.mjs`
- Test: `src/__tests__/feed-partition.test.ts`

**Interfaces:**
- Produces:
  - `export function partitionTarget(entry, config): "bundle" | "catalog"`
  - `export function loadPartitionConfig(root?): { bundleCutoffDate: string; maxBundledEntries: number; maxBundleBytes: number }`

- [ ] **Step 1: Write the failing test**

```typescript
import { partitionTarget } from "../../scripts/feed-partition.mjs";

const CONFIG = { bundleCutoffDate: "2026-06-01", maxBundledEntries: 25000, maxBundleBytes: 4194304 };

describe("partitionTarget", () => {
  it("keeps every non-package type in the bundle", () => {
    for (const type of ["ip", "domain", "url", "hash"]) {
      expect(partitionTarget({ type, value: "x", firstSeen: "2020-01-01" }, CONFIG)).toBe("bundle");
    }
  });
  it("keeps curated campaign and family entries in the bundle", () => {
    expect(partitionTarget({ type: "package", value: "a@1", campaign: "c", firstSeen: "2020-01-01" }, CONFIG)).toBe("bundle");
    expect(partitionTarget({ type: "package", value: "b@1", family: "f", firstSeen: "2020-01-01" }, CONFIG)).toBe("bundle");
  });
  it("keeps packages on or after the cutoff", () => {
    expect(partitionTarget({ type: "package", value: "c@1", firstSeen: "2026-06-01" }, CONFIG)).toBe("bundle");
  });
  it("routes older plain packages to the catalog", () => {
    expect(partitionTarget({ type: "package", value: "d@1", firstSeen: "2026-05-31" }, CONFIG)).toBe("catalog");
  });
  it("keeps an undatable package in the bundle rather than guessing", () => {
    expect(partitionTarget({ type: "package", value: "e@1" }, CONFIG)).toBe("bundle");
    expect(partitionTarget({ type: "package", value: "f@1", firstSeen: "not-a-date" }, CONFIG)).toBe("bundle");
  });
  it("is independent of the current clock", () => {
    const entry = { type: "package", value: "g@1", firstSeen: "2026-05-31" };
    const first = partitionTarget(entry, CONFIG);
    const realNow = Date.now;
    Date.now = () => realNow() + 365 * 86400000;
    try {
      expect(partitionTarget(entry, CONFIG)).toBe(first);
    } finally {
      Date.now = realNow;
    }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed-partition.test.ts`
Expected: FAIL, cannot resolve `../../scripts/feed-partition.mjs`.

- [ ] **Step 3: Implement**

`feed-partition.config.json`:

```json
{
  "$comment": "Partition policy for the threat feed. bundleCutoffDate is an explicit committed date, never a rolling window: the generator and the gates run during ordinary prebuilds, so a clock-relative cutoff would make the same corpus cross it on a later day and drift the committed files. Moving it is a deliberate commit. Phase 1 sets it earlier than every existing entry so nothing moves.",
  "bundleCutoffDate": "2000-01-01",
  "maxBundledEntries": 25000,
  "maxBundleBytes": 4194304
}
```

`scripts/feed-partition.mjs`:

```javascript
// feed-partition.mjs - the single routing rule deciding whether an IOC belongs
// in the compiled bundle (src/threat-intel.ts) or the downloadable catalog
// (data/threat-catalog.jsonl).
//
// Three callers: the importer when an entry is first written, the Phase 2
// migration when an existing bundled entry is moved, and
// check-feed-partition.mjs when validating placement. One rule, so placement
// cannot mean different things in different places.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Parse an ISO date into a UTC epoch, or null when it is not a real calendar date. */
function isoToEpoch(value) {
  if (typeof value !== "string") return null;
  const m = ISO_DATE.exec(value.slice(0, 10));
  if (!m) return null;
  const [, y, mo, d] = m;
  const epoch = Date.UTC(Number(y), Number(mo) - 1, Number(d));
  const back = new Date(epoch);
  // Reject values that parse but do not round-trip (2026-02-31 rolls over).
  if (back.getUTCMonth() !== Number(mo) - 1 || back.getUTCDate() !== Number(d)) return null;
  return epoch;
}

export function loadPartitionConfig(root = repoRoot) {
  const raw = JSON.parse(readFileSync(join(root, "feed-partition.config.json"), "utf8"));
  return {
    bundleCutoffDate: raw.bundleCutoffDate,
    maxBundledEntries: raw.maxBundledEntries,
    maxBundleBytes: raw.maxBundleBytes,
  };
}

/**
 * Where does this entry belong? Pure: depends only on the entry and the
 * committed config, never on the current date.
 *
 * An entry with a missing or unparsable firstSeen stays in the bundle. Failing
 * closed toward MORE detection is the safe direction: the cost is a few bytes,
 * where guessing it out of the bundle would silently drop coverage.
 */
export function partitionTarget(entry, config) {
  if (entry.type !== "package") return "bundle";
  if (entry.campaign !== undefined || entry.family !== undefined) return "bundle";
  const seen = isoToEpoch(entry.firstSeen);
  if (seen === null) return "bundle";
  const cutoff = isoToEpoch(config.bundleCutoffDate);
  if (cutoff === null) {
    throw new Error(`feed-partition.config.json: bundleCutoffDate "${config.bundleCutoffDate}" is not a valid ISO date`);
  }
  return seen >= cutoff ? "bundle" : "catalog";
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed-partition.test.ts`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add feed-partition.config.json scripts/feed-partition.mjs src/__tests__/feed-partition.test.ts
git commit -m "feat(feed): add the bundle/catalog partition policy

One exported rule with three future callers, so placement cannot mean
different things in different places. The cutoff is a committed ISO date
rather than a rolling window: the gates run during ordinary prebuilds, so a
clock-relative cutoff would drift the committed files on a later day with
nobody editing them. A test moves the clock a year forward and asserts the
answer does not change."
```

---

### Task 3: Commit the empty catalog and gate placement

**Files:**
- Create: `data/threat-catalog.jsonl` (empty)
- Create: `scripts/check-feed-partition.mjs`
- Modify: `package.json` (scripts)
- Test: `src/__tests__/feed-partition.test.ts` (extend)

**Interfaces:**
- Consumes: `partitionTarget`, `loadPartitionConfig` from Task 2; `extractBundledEntries` from `scripts/generate-feed.mjs`
- Produces: `export function checkPartition(root?): string[]` returning a list of violation messages, empty when clean

- [ ] **Step 1: Write the failing test**

```typescript
import { checkPartition } from "../../scripts/check-feed-partition.mjs";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

function fixture(bundleEntries: unknown[], catalogLines: string[]): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-part-"));
  fs.mkdirSync(path.join(root, "src"));
  fs.mkdirSync(path.join(root, "data"));
  const body = bundleEntries.map((e) => `  ${JSON.stringify(e)},`).join("\n");
  fs.writeFileSync(path.join(root, "src", "threat-intel.ts"), `const FEED_CHUNK_0: FeedIOC[] = [\n${body}\n];\n`);
  fs.writeFileSync(path.join(root, "data", "threat-catalog.jsonl"), catalogLines.join("\n"));
  fs.writeFileSync(path.join(root, "feed-partition.config.json"), JSON.stringify({ bundleCutoffDate: "2026-06-01", maxBundledEntries: 25000, maxBundleBytes: 4194304 }));
  return root;
}

describe("checkPartition", () => {
  it("passes on a clean split", () => {
    const root = fixture([{ type: "package", value: "new@1", severity: "critical", firstSeen: "2026-07-01" }],
      [JSON.stringify({ type: "package", value: "old@1", severity: "critical", firstSeen: "2026-01-01" })]);
    expect(checkPartition(root)).toEqual([]);
  });
  it("rejects a value present in both stores", () => {
    const dup = { type: "package", value: "dup@1", severity: "critical", firstSeen: "2026-07-01" };
    const root = fixture([dup], [JSON.stringify({ ...dup, firstSeen: "2026-01-01" })]);
    expect(checkPartition(root).join(" ")).toMatch(/dup@1.*both/i);
  });
  it("rejects a non-package entry in the catalog", () => {
    const root = fixture([], [JSON.stringify({ type: "ip", value: "1.2.3.4", severity: "critical", firstSeen: "2026-01-01" })]);
    expect(checkPartition(root).join(" ")).toMatch(/1\.2\.3\.4.*belongs in the bundle/i);
  });
  it("rejects a campaign entry in the catalog", () => {
    const root = fixture([], [JSON.stringify({ type: "package", value: "c@1", severity: "critical", campaign: "x", firstSeen: "2026-01-01" })]);
    expect(checkPartition(root).join(" ")).toMatch(/c@1.*belongs in the bundle/i);
  });
  it("rejects a malformed catalog line", () => {
    const root = fixture([], ["{ not json"]);
    expect(checkPartition(root).join(" ")).toMatch(/line 1/i);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed-partition.test.ts -t "checkPartition"`
Expected: FAIL, cannot resolve `../../scripts/check-feed-partition.mjs`.

- [ ] **Step 3: Implement**

Create `data/threat-catalog.jsonl` as a zero-byte file:

```bash
: > data/threat-catalog.jsonl
```

`scripts/check-feed-partition.mjs`:

```javascript
// check-feed-partition.mjs - gate: is every IOC in the right store?
//
// With two authored stores instead of one generated store, nothing structurally
// prevents an entry from landing in both or in the wrong one. This gate is what
// replaces that structural guarantee, so it fails the build rather than warning.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { extractBundledEntries } from "./generate-feed.mjs";
import { partitionTarget, loadPartitionConfig } from "./feed-partition.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

export function checkPartition(root = repoRoot) {
  const config = loadPartitionConfig(root);
  const violations = [];

  const bundle = extractBundledEntries(root);
  const bundleValues = new Set(bundle.map((e) => e.value));

  const raw = readFileSync(join(root, "data", "threat-catalog.jsonl"), "utf8");
  const catalogValues = new Set();

  raw.split("\n").forEach((line, i) => {
    if (line.trim() === "") return;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      violations.push(`data/threat-catalog.jsonl line ${i + 1}: not valid JSON`);
      return;
    }
    if (typeof entry !== "object" || entry === null || Array.isArray(entry) || typeof entry.value !== "string") {
      violations.push(`data/threat-catalog.jsonl line ${i + 1}: not a FeedIOC object`);
      return;
    }
    if (catalogValues.has(entry.value)) {
      violations.push(`data/threat-catalog.jsonl line ${i + 1}: duplicate value ${entry.value}`);
    }
    catalogValues.add(entry.value);
    if (bundleValues.has(entry.value)) {
      violations.push(`${entry.value} is in both stores; it must be in exactly one`);
    }
    if (partitionTarget(entry, config) === "bundle") {
      violations.push(`${entry.value} is in the catalog but belongs in the bundle by the partition policy`);
    }
  });

  return violations;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const violations = checkPartition();
  if (violations.length > 0) {
    console.error(`\n  feed partition: ${violations.length} violation(s)\n`);
    for (const v of violations.slice(0, 25)) console.error(`    ${v}`);
    if (violations.length > 25) console.error(`    ... and ${violations.length - 25} more`);
    console.error("");
    process.exit(1);
  }
  console.log("feed partition OK: every IOC is in exactly one store, correctly placed.");
}
```

In `package.json`, add the script and extend `prebuild`:

```json
    "check:feed-partition": "node scripts/check-feed-partition.mjs",
    "prebuild": "npm run check:aahp && npm run check:feed && npm run check:feed-partition && npm run check:handoff && npm run check:self-scan",
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed-partition.test.ts -t "checkPartition"`
Expected: PASS, 5 tests.

- [ ] **Step 5: Verify the gate runs green against the real tree**

Run: `npm run check:feed-partition`
Expected: `feed partition OK: every IOC is in exactly one store, correctly placed.` The catalog is empty and the cutoff is 2000-01-01, so nothing can violate it yet.

- [ ] **Step 6: Prove the gate by cutting it**

Append a line to `data/threat-catalog.jsonl` duplicating a value that exists in the bundle, for example `{"type":"package","value":"plogme@1.0.0","severity":"critical","firstSeen":"2026-01-01"}`. Run `npm run check:feed-partition` and expect exit 1 naming that value as being in both stores. Then replace it with a `campaign`-carrying entry and expect the "belongs in the bundle" violation instead. Truncate the file back to empty, re-run, and confirm it is green again.

- [ ] **Step 7: Commit**

```bash
git add data/threat-catalog.jsonl scripts/check-feed-partition.mjs package.json src/__tests__/feed-partition.test.ts
git commit -m "feat(feed): commit the empty catalog store and gate placement

Two authored stores mean nothing structurally prevents an entry from landing
in both or in the wrong one, so this gate replaces that guarantee and fails
the build rather than warning. Wired into prebuild beside check:feed.
Proved by cutting: a value planted in both stores and a campaign entry
planted in the catalog each fail for their own reason."
```

---

### Task 4: Budget gate on the bundle

**Files:**
- Create: `scripts/check-feed-budget.mjs`
- Modify: `package.json` (scripts)
- Test: `src/__tests__/feed-partition.test.ts` (extend)

**Interfaces:**
- Consumes: `extractBundledEntries`, `loadPartitionConfig`
- Produces: `export function checkBudget(root?): string[]`

- [ ] **Step 1: Write the failing test**

```typescript
import { checkBudget } from "../../scripts/check-feed-budget.mjs";

describe("checkBudget", () => {
  it("passes one entry under the entry limit", () => {
    const root = fixtureWithLimits(24999, 4194304);
    expect(checkBudget(root)).toEqual([]);
  });
  it("fails one entry over the entry limit", () => {
    const root = fixtureWithLimits(25001, 4194304);
    expect(checkBudget(root).join(" ")).toMatch(/25001 bundled entries exceeds 25000/);
  });
  it("fails when the generated source exceeds the byte limit", () => {
    const root = fixtureWithLimits(10, 100);
    expect(checkBudget(root).join(" ")).toMatch(/exceeds the 100 byte budget/);
  });
});
```

Add this helper beside `fixture` in the same file:

```typescript
function fixtureWithLimits(entryCount: number, maxBundleBytes: number): string {
  const entries = Array.from({ length: entryCount }, (_, i) => ({
    type: "package", value: `p${i}@1.0.0`, severity: "critical", firstSeen: "2026-07-01",
  }));
  const root = fixture(entries, []);
  fs.writeFileSync(path.join(root, "feed-partition.config.json"),
    JSON.stringify({ bundleCutoffDate: "2026-06-01", maxBundledEntries: 25000, maxBundleBytes }));
  return root;
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed-partition.test.ts -t "checkBudget"`
Expected: FAIL, cannot resolve `../../scripts/check-feed-budget.mjs`.

- [ ] **Step 3: Implement**

```javascript
// check-feed-budget.mjs - gate: the compiled bundle must stay inside its budget.
//
// The root cause of the deferral backlog was that no step in any workflow owned
// the feed's size, so it grew until one upstream event made it a crisis. This
// gate is the durable half of the fix: a release that would breach the budget
// cannot be built, and the remedy is to move bundleCutoffDate forward and
// migrate, not to raise the limit reflexively.

import { statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { extractBundledEntries } from "./generate-feed.mjs";
import { loadPartitionConfig } from "./feed-partition.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

export function checkBudget(root = repoRoot) {
  const config = loadPartitionConfig(root);
  const violations = [];

  const entries = extractBundledEntries(root);
  if (entries.length > config.maxBundledEntries) {
    violations.push(
      `${entries.length} bundled entries exceeds ${config.maxBundledEntries}. ` +
      `Move bundleCutoffDate forward in feed-partition.config.json and migrate.`,
    );
  }

  const bytes = statSync(join(root, "src", "threat-intel.ts")).size;
  if (bytes > config.maxBundleBytes) {
    violations.push(
      `src/threat-intel.ts is ${bytes} bytes, which exceeds the ${config.maxBundleBytes} byte budget. ` +
      `Move bundleCutoffDate forward in feed-partition.config.json and migrate.`,
    );
  }

  return violations;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const violations = checkBudget();
  if (violations.length > 0) {
    console.error("");
    for (const v of violations) console.error(`  ${v}`);
    console.error("");
    process.exit(1);
  }
  console.log("feed budget OK.");
}
```

In `package.json`:

```json
    "check:feed-budget": "node scripts/check-feed-budget.mjs",
    "prebuild": "npm run check:aahp && npm run check:feed && npm run check:feed-partition && npm run check:feed-budget && npm run check:handoff && npm run check:self-scan",
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed-partition.test.ts -t "checkBudget"`
Expected: PASS, 3 tests.

- [ ] **Step 5: Set the real byte limit from a measurement, not a guess**

Run: `node -e "console.log(require('node:fs').statSync('src/threat-intel.ts').size)"`. The current file is about 3.71 MB. Confirm `maxBundleBytes` of 4194304 (4 MiB) leaves headroom, then run `npm run check:feed-budget` against the real tree and expect `feed budget OK.`

- [ ] **Step 6: Commit**

```bash
git add scripts/check-feed-budget.mjs package.json src/__tests__/feed-partition.test.ts
git commit -m "feat(feed): gate the compiled bundle against a size budget

The durable half of the catalog split. The backlog existed because no step
owned the feed's size; this fails the build when the bundle exceeds its
entry or byte limit, and names moving the cutoff as the remedy rather than
raising the limit. Proved in both directions: one entry over each limit
fails for that specific reason, one entry under passes."
```

---

### Task 5: Teach the payload parser about catalogs

**Files:**
- Modify: `src/feed.ts` (`parseFeedPayload`, around line 247)
- Test: `src/__tests__/feed.test.ts`

**Interfaces:**
- Produces: `parseFeedPayload(raw: string, expectedKind?: "feed" | "catalog"): FeedIOC[]` (the second parameter is new and defaults to `"feed"`, so every existing caller is unchanged)

- [ ] **Step 1: Write the failing test**

```typescript
import { parseFeedPayload } from "../feed.js";

const ENTRY = { type: "package", value: "e@1", severity: "critical" };
const doc = (kind: string | undefined, entries: unknown[]) =>
  JSON.stringify({ schema: 1, ...(kind ? { kind } : {}), package: "supply-chain-guard", entries });

describe("parseFeedPayload kind handling", () => {
  it("accepts an empty catalog", () => {
    expect(parseFeedPayload(doc("catalog", []), "catalog")).toEqual([]);
  });
  it("still rejects an empty feed", () => {
    expect(() => parseFeedPayload(doc(undefined, []), "feed")).toThrow(/non-empty entries/);
  });
  it("rejects a feed offered as a catalog", () => {
    expect(() => parseFeedPayload(doc("feed", [ENTRY]), "catalog")).toThrow(/expected kind "catalog"/);
  });
  it("rejects a catalog offered as a feed", () => {
    expect(() => parseFeedPayload(doc("catalog", [ENTRY]), "feed")).toThrow(/expected kind "feed"/);
  });
  it("treats a missing kind as a feed, for the published feed.json", () => {
    expect(parseFeedPayload(doc(undefined, [ENTRY]), "feed")).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed.test.ts -t "kind handling"`
Expected: FAIL, the empty catalog throws `invalid feed format: missing non-empty entries array`.

- [ ] **Step 3: Implement**

In `src/feed.ts`, change the signature and the two checks inside `parseFeedPayload`:

```typescript
export function parseFeedPayload(
  raw: string,
  expectedKind: "feed" | "catalog" = "feed",
): FeedIOC[] {
```

After the JSON parse and before the entries check, add the discriminator test. A document with no `kind` is a feed, because the published `feed.json` predates this field:

```typescript
  const kind = typeof (doc as { kind?: unknown }).kind === "string"
    ? (doc as { kind: string }).kind
    : "feed";
  if (kind !== expectedKind) {
    throw new Error(`invalid feed format: expected kind "${expectedKind}", got "${kind}"`);
  }
```

Then relax the emptiness check so it applies only to a feed. An empty bundle feed means something broke; an empty catalog is the legitimate Phase 1 state:

```typescript
  if (!Array.isArray(entries) || (entries.length === 0 && expectedKind === "feed")) {
    throw new Error("invalid feed format: missing non-empty entries array");
  }
```

Add `"kind"` to `FEED_DOC_KEYS` in `src/threat-intel.ts` (line 22409), or the published catalog fails `isInertThreatFeedFile` and any repo committing it drowns in phantom findings:

```typescript
const FEED_DOC_KEYS = new Set(["schema", "kind", "package", "version", "entryCount", "entries", "timestamp", "generatedAt"]);
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed.test.ts -t "kind handling"`
Expected: PASS, 5 tests.

- [ ] **Step 5: Confirm no existing caller regressed**

Run: `npx vitest run src/__tests__/feed.test.ts`
Expected: PASS for the whole file. `expectedKind` defaults to `"feed"`, so every existing call site keeps its behaviour.

- [ ] **Step 6: Commit**

```bash
npm run self-scan:generate
git add src/feed.ts src/threat-intel.ts self-scan-manifest.json src/__tests__/feed.test.ts
git commit -m "feat(feed): discriminate catalog payloads and allow an empty one

parseFeedPayload rejected every empty entries array, which is right for a
bundle feed and wrong for a catalog, where empty is the legitimate initial
state. Without this the first published catalog is rejected by the parser
meant to accept it. Adds a kind check in both directions; a document with no
kind is a feed, so the published feed.json is unaffected. kind is added to
FEED_DOC_KEYS so a committed catalog stays inert to the scanner."
```

---

### Task 6: Bounded gzip decompression in the transport

The catalog must be compressed: 150,000 entries is 33.14 MB raw, which exceeds `FEED_REMOTE_LIMITS.maxBytes` of 32 MiB, and 2.42 MB gzipped. But nothing in `src/feed.ts` or `src/remote-download.ts` decompresses anything, so a `.gz` asset fed to the current path can never parse.

**Files:**
- Modify: `src/feed.ts`
- Test: `src/__tests__/feed.test.ts`

**Interfaces:**
- Produces:
  - `export const CATALOG_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;`
  - `export function decodeCatalogBody(body: Buffer): string`

- [ ] **Step 1: Write the failing test**

```typescript
import { gzipSync } from "node:zlib";
import { decodeCatalogBody, CATALOG_MAX_DECOMPRESSED_BYTES } from "../feed.js";

describe("decodeCatalogBody", () => {
  it("decompresses a gzip body", () => {
    expect(decodeCatalogBody(gzipSync(Buffer.from('{"ok":true}')))).toBe('{"ok":true}');
  });
  it("passes through an uncompressed body", () => {
    expect(decodeCatalogBody(Buffer.from('{"ok":true}'))).toBe('{"ok":true}');
  });
  it("refuses a decompression bomb", () => {
    const bomb = gzipSync(Buffer.alloc(CATALOG_MAX_DECOMPRESSED_BYTES + 1024, 0x61));
    expect(() => decodeCatalogBody(bomb)).toThrow(/decompressed catalog exceeds/);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed.test.ts -t "decodeCatalogBody"`
Expected: FAIL, `decodeCatalogBody is not a function`.

- [ ] **Step 3: Implement**

Add the import at the top of `src/feed.ts`:

```typescript
import { gunzipSync } from "node:zlib";
```

Then:

```typescript
/**
 * Expansion cap for the downloaded catalog, about twice the projected size of
 * a 150,000-entry corpus. Two independent bounds apply: FEED_REMOTE_LIMITS
 * .maxBytes caps the bytes that arrive, and this caps what they expand into, so
 * a decompression bomb that passes the first still fails the second.
 */
export const CATALOG_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;

/** gzip magic: 0x1f 0x8b. */
function isGzip(body: Buffer): boolean {
  return body.length >= 2 && body[0] === 0x1f && body[1] === 0x8b;
}

/**
 * Decode a catalog body, decompressing when it is gzipped. Bounded by
 * maxOutputLength rather than by trusting the gzip header's stated size, the
 * same pattern src/archive-extractor.ts already uses.
 */
export function decodeCatalogBody(body: Buffer): string {
  if (!isGzip(body)) return body.toString("utf-8");
  try {
    return gunzipSync(body, { maxOutputLength: CATALOG_MAX_DECOMPRESSED_BYTES }).toString("utf-8");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/maxOutputLength|buffer|size/i.test(message)) {
      throw new Error(
        `decompressed catalog exceeds ${CATALOG_MAX_DECOMPRESSED_BYTES} bytes`,
      );
    }
    throw new Error(`catalog is not valid gzip: ${message}`);
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed.test.ts -t "decodeCatalogBody"`
Expected: PASS, 3 tests.

- [ ] **Step 5: Prove the bound by cutting it**

Temporarily raise `CATALOG_MAX_DECOMPRESSED_BYTES` to `1024 * 1024 * 1024`. Re-run and expect the bomb test to go RED (it no longer throws). Restore the constant, re-run, confirm green. This proves the test measures the bound rather than the try/catch.

- [ ] **Step 6: Commit**

```bash
git add src/feed.ts src/__tests__/feed.test.ts
git commit -m "feat(feed): add bounded gzip decompression for the catalog

Nothing in the refresh path decompressed anything, so a gzipped catalog
asset could never have parsed and the refresh would have installed no
historical indicators at all. Compression is not optional: a 150,000-entry
catalog is 33.14 MB raw, over the 32 MiB download cap, and 2.42 MB gzipped.
Bounded with maxOutputLength like archive-extractor.ts, so a bomb that fits
under the download cap still fails on expansion."
```

---

### Task 7: Generate and ship the catalog digest

Integrity cannot rest on release-asset immutability: `immutable_releases` is `null` on this repository and `gh release upload --clobber` can replace an asset on an existing tag. The anchor is instead a digest shipped inside the npm package.

**Files:**
- Create: `scripts/generate-catalog.mjs`
- Modify: `package.json` (scripts, `files`)
- Test: `src/__tests__/feed.test.ts`

**Interfaces:**
- Produces:
  - `catalog.json.gz` at the repo root (gitignored build artifact)
  - `src/catalog-digest.ts`, a GENERATED and COMMITTED TypeScript constant:
    `export const CATALOG_DIGEST = { version: string; sha256: string; entryCount: number }`

**Why a TypeScript constant and not a JSON file read at runtime.** Three
reasons:

1. `loadThreatIntel()` runs on every scan and already does a `stat` plus a read
   per cache file. A compiled-in constant costs nothing.
2. It is typechecked, so it cannot drift into a shape the caller does not expect.
3. It supplies the version `refreshFeed()` needs to build the version-pinned
   catalog URL. That function has no version parameter and no access to
   `package.json`, so without it Task 10 cannot be implemented at all.

A note on what this is NOT. An earlier revision of this plan justified the
constant by claiming `__dirname` is undefined when vitest runs the TypeScript
sources, citing the defensive comment at `src/mcp-server.ts:59`. That was taken
from a comment and never run. Measured on 2026-09-16: this package has no
`"type": "module"`, vitest transforms to CommonJS, and `__dirname` is a defined
string with `require` available. A `__dirname`-relative JSON read would have
worked. Do not reintroduce that reasoning; the three reasons above are the real
ones.

- [ ] **Step 1: Write the failing test**

```typescript
import { buildCatalog } from "../../scripts/generate-catalog.mjs";
import { gunzipSync } from "node:zlib";
import { createHash } from "node:crypto";

describe("buildCatalog", () => {
  it("produces a gzipped catalog whose digest matches the manifest", () => {
    const { json, digest } = buildCatalog([], "9.9.9");
    expect(digest.sha256).toBe(createHash("sha256").update(json, "utf8").digest("hex"));
    expect(digest.version).toBe("9.9.9");
    expect(digest.entryCount).toBe(0);
    const doc = JSON.parse(json);
    expect(doc.kind).toBe("catalog");
    expect(doc.entries).toEqual([]);
  });
  it("is deterministic: the same input yields the same digest", () => {
    const a = buildCatalog([{ type: "package", value: "x@1", severity: "critical" }], "1.0.0");
    const b = buildCatalog([{ type: "package", value: "x@1", severity: "critical" }], "1.0.0");
    expect(a.digest.sha256).toBe(b.digest.sha256);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed.test.ts -t "buildCatalog"`
Expected: FAIL, cannot resolve `../../scripts/generate-catalog.mjs`.

- [ ] **Step 3: Implement**

```javascript
// generate-catalog.mjs - build the publishable catalog asset and its digest.
//
// The digest is what makes integrity independent of release-asset mutability:
// it ships inside the npm package, so the anchor is the immutable npm artifact
// and the tagged git tree rather than an asset that --clobber can replace.

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Read data/threat-catalog.jsonl into an array of entries. */
export function readCatalogEntries(root = repoRoot) {
  const raw = readFileSync(join(root, "data", "threat-catalog.jsonl"), "utf8");
  return raw.split("\n").filter((l) => l.trim() !== "").map((l) => JSON.parse(l));
}

/**
 * Build the gzipped catalog document and its digest manifest. Deterministic:
 * no timestamps derived from the clock, so the same corpus and version always
 * produce the same bytes and the same digest.
 */
export function buildCatalog(entries, version) {
  const doc = {
    schema: 1,
    kind: "catalog",
    package: "supply-chain-guard",
    version,
    entryCount: entries.length,
    entries,
  };
  // Hash the DECOMPRESSED JSON, not the gzip bytes: an air-gapped mirror may
  // serve the asset uncompressed and the digest must still verify. gzip output
  // is also not guaranteed byte-stable across zlib versions, which would make a
  // digest over the compressed form spuriously mismatch.
  const json = JSON.stringify(doc);
  const gz = gzipSync(Buffer.from(json, "utf-8"), { level: 9 });
  const digest = {
    version,
    sha256: createHash("sha256").update(json, "utf8").digest("hex"),
    entryCount: entries.length,
  };
  return { json, gz, digest };
}

/** Render the committed TypeScript constant. Generated, never hand-edited. */
export function renderDigestModule(digest) {
  return [
    "// GENERATED by scripts/generate-catalog.mjs. Do not edit by hand.",
    "//",
    "// Shipped inside the npm package so the integrity anchor is the immutable",
    "// npm artifact and the tagged git tree, not a release asset that --clobber",
    "// can replace. A constant rather than a JSON file read at runtime because",
    "// __dirname is unavailable in some ESM runners (see src/mcp-server.ts).",
    "export const CATALOG_DIGEST = {",
    `  version: ${JSON.stringify(digest.version)},`,
    `  sha256: ${JSON.stringify(digest.sha256)},`,
    `  entryCount: ${digest.entryCount},`,
    "} as const;",
    "",
  ].join("\n");
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const version = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")).version;
  const { gz, digest } = buildCatalog(readCatalogEntries(), version);
  const modulePath = join(repoRoot, "src", "catalog-digest.ts");
  const rendered = renderDigestModule(digest);

  if (process.argv.includes("--check")) {
    if (readFileSync(modulePath, "utf8") !== rendered) {
      console.error("src/catalog-digest.ts is stale; run `npm run catalog:generate` and commit it.");
      process.exit(1);
    }
    console.log(`catalog digest up to date (${digest.entryCount} entries, v${digest.version}).`);
  } else {
    writeFileSync(join(repoRoot, "catalog.json.gz"), gz);
    writeFileSync(modulePath, rendered);
    console.log(`catalog:generate OK - ${digest.entryCount} entries, ${gz.length} bytes, sha256 ${digest.sha256.slice(0, 12)}...`);
  }
}
```

In `package.json`, add the script, ship the digest, and ignore the asset from git:

```json
    "catalog:generate": "node scripts/generate-catalog.mjs",
    "check:catalog": "node scripts/generate-catalog.mjs --check",
```

and extend `prebuild` again so a stale digest cannot be committed:

```json
    "prebuild": "npm run check:aahp && npm run check:feed && npm run check:feed-partition && npm run check:feed-budget && npm run check:catalog && npm run check:handoff && npm run check:self-scan",
```

`src/catalog-digest.ts` is compiled into the package like any other source file, so nothing needs adding to `files`. Add `catalog.json.gz` to `.gitignore`: it is a build artifact rebuilt from the committed catalog, and committing a binary blob that changes on every import would bloat history.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed.test.ts -t "buildCatalog"`
Expected: PASS, 2 tests.

- [ ] **Step 5: Generate against the real tree and commit the digest module**

Run `npm run catalog:generate`, then `npm run check:catalog`.
Expected: the first writes `src/catalog-digest.ts` and `catalog.json.gz`; the second reports `catalog digest up to date (0 entries, v6.1.3).` Commit `src/catalog-digest.ts`.

- [ ] **Step 6: Commit**

```bash
git add scripts/generate-catalog.mjs src/catalog-digest.ts package.json .gitignore src/__tests__/feed.test.ts
git commit -m "feat(feed): build the catalog asset and its shipped digest

Integrity is anchored to a SHA-256 that travels inside the npm package
rather than to release-asset immutability, which this repository does not
have enabled and which --clobber can defeat on an existing tag. Generation
is deterministic, so the same catalog and version always produce the same
bytes and the same digest."
```

---

### Task 8: Catalog cache, merge, and what counts as unavailable

**Files:**
- Modify: `src/threat-intel.ts` (`loadThreatIntel`, around line 22237)
- Test: `src/__tests__/threat-intel.test.ts`

**Interfaces:**
- Consumes: `isValidFeedIOC`, `normalizeFeedIOC`, `mergeFeeds` (all existing)
- Produces:
  - `export const CATALOG_CACHE_FILE = "threat-catalog.json";`
  - `export type CatalogUnavailableReason = "absent" | "unreadable" | "version-mismatch" | "digest-mismatch";`
  - `export interface CatalogState { available: boolean; reason?: CatalogUnavailableReason; entryCount: number; cachedVersion?: string; }`
  - `export function lastCatalogState(): CatalogState`

- [ ] **Step 1: Write the failing test**

```typescript
import { loadThreatIntel, lastCatalogState, CATALOG_CACHE_FILE } from "../threat-intel.js";

function writeCatalogCache(dir: string, body: unknown) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, CATALOG_CACHE_FILE), JSON.stringify(body));
}

describe("catalog cache availability", () => {
  it("reports absent when there is no cache", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cat-"));
    loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "absent" });
  });
  it("reports version-mismatch for a previous release's catalog", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cat-"));
    writeCatalogCache(dir, { version: "0.0.1", sha256: "deadbeef", entries: [] });
    loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "version-mismatch" });
  });
  it("reports digest-mismatch when the digest does not match the shipped manifest", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cat-"));
    writeCatalogCache(dir, { version: pkg.version, sha256: "0".repeat(64), entries: [] });
    loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: false, reason: "digest-mismatch" });
  });
  it("merges a valid catalog and reports it available", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cat-"));
    const entry = { type: "package", value: "catalog-only@1.0.0", severity: "critical" };
    writeCatalogCache(dir, { version: pkg.version, sha256: expectedDigest.sha256, entries: [entry] });
    const feed = loadThreatIntel(dir);
    expect(lastCatalogState()).toMatchObject({ available: true, entryCount: 1 });
    expect(feed.some((e) => e.value === "catalog-only@1.0.0")).toBe(true);
  });
});
```

Import `pkg` from `../../package.json` and `CATALOG_DIGEST` from `../catalog-digest.js` at the top of the file, and use `CATALOG_DIGEST.sha256` where the test writes `expectedDigest.sha256`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/threat-intel.test.ts -t "catalog cache availability"`
Expected: FAIL, `lastCatalogState is not a function`.

- [ ] **Step 3: Implement**

Add beside `FEED_CACHE_FILE` (line 22076):

```typescript
/** Cache file for the downloaded historical catalog, beside the feed cache. */
export const CATALOG_CACHE_FILE = "threat-catalog.json";

export type CatalogUnavailableReason =
  | "absent" | "unreadable" | "version-mismatch" | "digest-mismatch";

export interface CatalogState {
  available: boolean;
  reason?: CatalogUnavailableReason;
  entryCount: number;
  cachedVersion?: string;
}

let lastCatalog: CatalogState = { available: false, reason: "absent", entryCount: 0 };

/** State of the catalog cache as of the last loadThreatIntel() call. */
export function lastCatalogState(): CatalogState {
  return { ...lastCatalog };
}
```

Import the generated digest constant from Task 7. No filesystem access and no
`__dirname`, so it resolves identically under vitest and in `dist/`:

```typescript
import { CATALOG_DIGEST } from "./catalog-digest.js";
```

Inside `loadThreatIntel`, after the existing feed-cache merge and before `lastCacheState = state;`, add the catalog merge. Note that a cache that fails any check is NOT merged: a version-mismatched catalog is not partial coverage to be used opportunistically, it is coverage the caller must be told is missing.

```typescript
  const catalogPath = path.join(cacheBase, CATALOG_CACHE_FILE);
  let catalog: CatalogState = { available: false, reason: "absent", entryCount: 0 };
  if (fs.existsSync(catalogPath)) {
    try {
      const cached = JSON.parse(fs.readFileSync(catalogPath, "utf-8")) as {
        version?: string; sha256?: string; entries?: FeedIOC[];
      };
      if (!Array.isArray(cached.entries)) {
        catalog = { available: false, reason: "unreadable", entryCount: 0 };
      } else if (cached.version !== CATALOG_DIGEST.version) {
        catalog = {
          available: false, reason: "version-mismatch",
          entryCount: 0, cachedVersion: cached.version,
        };
      } else if (cached.sha256 !== CATALOG_DIGEST.sha256) {
        catalog = {
          available: false, reason: "digest-mismatch",
          entryCount: 0, cachedVersion: cached.version,
        };
      } else {
        const entries = cached.entries.filter(isValidFeedIOC).map(normalizeFeedIOC);
        feed = mergeFeeds(feed, entries);
        catalog = {
          available: true, entryCount: entries.length, cachedVersion: cached.version,
        };
      }
    } catch {
      catalog = { available: false, reason: "unreadable", entryCount: 0 };
    }
  }
  lastCatalog = catalog;
```

Extend the memo key so a refreshed catalog is observed rather than served from a stale memo. Replace the `stamp` computation with one that covers both files, and include it in `key`:

```typescript
  let catalogStamp = "none";
  try {
    const cstat = fs.statSync(path.join(cacheBase, CATALOG_CACHE_FILE));
    catalogStamp = `${cstat.mtimeMs}:${cstat.size}`;
  } catch { /* no catalog cache */ }
```

and change the key line to:

```typescript
  const key = `${cachePath} ${remoteFeedUrl ?? ""} ${stamp} ${catalogStamp} ${ttlBucket}`;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/threat-intel.test.ts -t "catalog cache availability"`
Expected: PASS, 4 tests.

- [ ] **Step 5: Prove the version check by cutting it**

Temporarily change `cached.version !== expected.version` to `false`. Re-run and expect the version-mismatch test to go RED while the others stay green. This is the check that closes the hole where a previous release's catalog silently satisfies `catalog: "required"`, so it must be shown to bite. Restore and confirm green.

- [ ] **Step 6: Commit**

```bash
npm run self-scan:generate
git add src/threat-intel.ts self-scan-manifest.json src/__tests__/threat-intel.test.ts
git commit -m "feat(feed): merge the catalog cache and define what unavailable means

A readable cache is not a usable cache. After an upgrade, or a refresh where
the feed succeeded and the catalog failed, a previous release's catalog stays
readable on disk, and a check that fired only on an absent file would let it
pass silently while omitting every historical indicator added since.
THREAT_FEED_STALE cannot catch that either, because recent bundled entries
keep the merged feed's newest firstSeen current. Version and digest mismatch
therefore count as unavailable, and a failing cache is not merged at all."
```

---

### Task 9: The finding and the policy knob

**Files:**
- Modify: `src/feed.ts`
- Modify: `src/scanner.ts` (where `feedStalenessFindings` is called)
- Modify: `policy-schema.json`
- Test: `src/__tests__/feed.test.ts`

**Interfaces:**
- Consumes: `lastCatalogState`, `CatalogState` from Task 8
- Produces:
  - `export const CATALOG_MISSING_RULE = "THREAT_FEED_CATALOG_MISSING";`
  - `export function catalogFindings(state: CatalogState, mode: "optional" | "required"): Finding[]`

- [ ] **Step 1: Write the failing test**

```typescript
import { catalogFindings, CATALOG_MISSING_RULE } from "../feed.js";

describe("catalogFindings", () => {
  it("returns nothing when the catalog is available", () => {
    expect(catalogFindings({ available: true, entryCount: 10 }, "optional")).toEqual([]);
  });
  it("is medium by default so an existing fail-on gate does not turn red", () => {
    const [f] = catalogFindings({ available: false, reason: "absent", entryCount: 0 }, "optional");
    expect(f.rule).toBe(CATALOG_MISSING_RULE);
    expect(f.severity).toBe("medium");
    expect(f.category).toBe("trust");
  });
  it("is critical under the required policy", () => {
    const [f] = catalogFindings({ available: false, reason: "absent", entryCount: 0 }, "required");
    expect(f.severity).toBe("critical");
  });
  it("names the reason so the operator knows which failure this is", () => {
    const [f] = catalogFindings({ available: false, reason: "version-mismatch", entryCount: 0, cachedVersion: "6.1.2" }, "optional");
    expect(f.description).toMatch(/6\.1\.2/);
    expect(f.description).toMatch(/version/i);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed.test.ts -t "catalogFindings"`
Expected: FAIL, `catalogFindings is not a function`.

- [ ] **Step 3: Implement**

In `src/feed.ts`, mirroring `feedStalenessFindings`:

```typescript
/** Rule id of the missing-catalog finding. Stable: consumers exclude it by name. */
export const CATALOG_MISSING_RULE = "THREAT_FEED_CATALOG_MISSING";

const CATALOG_REASON_TEXT: Record<string, string> = {
  absent: "no catalog has been downloaded",
  unreadable: "the cached catalog could not be read",
  "version-mismatch": "the cached catalog was built for a different release",
  "digest-mismatch": "the cached catalog did not match its expected digest",
};

/**
 * Report a catalog that is absent, stale or unverifiable.
 *
 * Severity is medium by default, for the same reason THREAT_FEED_STALE is:
 * shipping at high would turn every existing consumer's default gate red on
 * upgrade day for a condition they did not cause. Consumers who want the
 * guarantee rather than the signal set policy.catalog to "required".
 */
export function catalogFindings(
  state: CatalogState,
  mode: "optional" | "required",
): Finding[] {
  if (state.available) return [];

  const reason = CATALOG_REASON_TEXT[state.reason ?? "absent"] ?? "the catalog is unavailable";
  const which = state.cachedVersion ? ` (cached catalog version ${state.cachedVersion})` : "";

  return [
    {
      rule: CATALOG_MISSING_RULE,
      description:
        `The historical indicator catalog was not consulted by this scan: ${reason}${which}. ` +
        `Those indicators are not compiled into the package, so every one of them was ` +
        `invisible to this run, and no other part of the result says so.`,
      severity: mode === "required" ? "critical" : "medium",
      confidence: 1.0,
      category: "trust",
      rationale:
        "The bundled rule set carries recent and curated indicators only. The historical " +
        "catalog is downloaded, so a scan without it answers a narrower question than the " +
        "caller is likely to assume.",
      recommendation:
        "Run `supply-chain-guard feed refresh` before the scan to download the catalog for " +
        `this release. Exclude the ${CATALOG_MISSING_RULE} rule only if scanning without ` +
        "the historical catalog is the deliberate intent.",
    },
  ];
}
```

In `src/scanner.ts`, line 661 currently reads `findings.push(...feedStalenessFindings(feedFreshness(threatFeed)));`. `policy` is already in scope there, declared at line 234 as `const policy = loadPolicyConfig(scanDir)`. Add immediately after it:

```typescript
  findings.push(...catalogFindings(lastCatalogState(), policy?.catalog ?? "optional"));
```

The policy value needs BOTH a schema entry and a TypeScript field, or `tsc` fails on `policy.catalog`. In `src/types.ts`, inside `interface PolicyConfig` (line 554), add:

```typescript
  /**
   * Whether the downloadable historical indicator catalog must be present.
   * "optional" (the default) reports a missing catalog as a medium trust
   * finding; "required" reports it as critical and fails the gate.
   */
  catalog?: "optional" | "required";
```

Then in `policy-schema.json`, add to `properties`:

```json
    "catalog": {
      "type": "string",
      "enum": ["optional", "required"],
      "default": "optional",
      "description": "Whether the downloadable historical indicator catalog must be present. 'optional' reports a missing catalog as a medium trust finding; 'required' reports it as critical and fails the gate."
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed.test.ts -t "catalogFindings"`
Expected: PASS, 4 tests.

- [ ] **Step 5: Verify end to end through a real scan**

```bash
node dist/cli.js scan . --format json > /tmp/scan.json
node -e "const r=require('/tmp/scan.json'); const f=r.findings.find(x=>x.rule==='THREAT_FEED_CATALOG_MISSING'); console.log(f ? f.severity+': '+f.description.slice(0,80) : 'NOT EMITTED')"
```

Expected: `medium: The historical indicator catalog was not consulted by this scan: no catalog has been downloaded...`. There is no catalog cache yet, so the finding must appear.

- [ ] **Step 6: Commit**

```bash
npm run self-scan:generate
git add src/feed.ts src/scanner.ts src/types.ts policy-schema.json self-scan-manifest.json src/__tests__/feed.test.ts
git commit -m "feat(scanner): report a missing or unverifiable catalog

Fires on every scan where the catalog is absent, unreadable,
version-mismatched or digest-mismatched, naming which. Medium by default,
matching the reasoning already recorded for THREAT_FEED_STALE: shipping at
high would turn existing consumers' gates red on upgrade day for a condition
they did not cause. policy.catalog = required makes it critical for
consumers who want the guarantee rather than the signal."
```

---

### Task 10: `feed refresh` fetches both documents

**Files:**
- Modify: `src/feed.ts` (`refreshFeed`)
- Modify: `src/cli.ts` (the `feed refresh` handler output)
- Test: `src/__tests__/feed.test.ts`

**Interfaces:**
- Consumes: `decodeCatalogBody` (Task 6), `parseFeedPayload` (Task 5), `CATALOG_CACHE_FILE` (Task 8)
- Produces:
  - `export const DEFAULT_CATALOG_URL_TEMPLATE = "https://github.com/homeofe/supply-chain-guard/releases/download/v{version}/catalog.json.gz";`
  - `export function catalogUrlFor(version: string, template?: string): string`
  - `refreshFeed` return type gains `catalog?: { entryCount: number; cachePath: string }`

- [ ] **Step 1: Write the failing test**

```typescript
import { catalogUrlFor, DEFAULT_CATALOG_URL_TEMPLATE } from "../feed.js";

describe("catalogUrlFor", () => {
  it("pins the asset to the installed version, not latest", () => {
    expect(catalogUrlFor("6.2.0")).toBe(
      "https://github.com/homeofe/supply-chain-guard/releases/download/v6.2.0/catalog.json.gz",
    );
    expect(DEFAULT_CATALOG_URL_TEMPLATE).toContain("{version}");
    expect(catalogUrlFor("6.2.0")).not.toContain("latest");
  });
  it("honours an override for an air-gapped mirror", () => {
    expect(catalogUrlFor("6.2.0", "https://mirror.internal/scg/{version}/catalog.json.gz"))
      .toBe("https://mirror.internal/scg/6.2.0/catalog.json.gz");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/__tests__/feed.test.ts -t "catalogUrlFor"`
Expected: FAIL, `catalogUrlFor is not a function`.

- [ ] **Step 3: Implement**

```typescript
/**
 * Release-asset location of the historical catalog, pinned to the installed
 * version. Not "latest": the client verifies the download against the digest
 * shipped in its own package, which only exists for its own version, and
 * version pinning is also what makes a stale cache detectable.
 */
export const DEFAULT_CATALOG_URL_TEMPLATE =
  "https://github.com/homeofe/supply-chain-guard/releases/download/v{version}/catalog.json.gz";

export function catalogUrlFor(version: string, template = DEFAULT_CATALOG_URL_TEMPLATE): string {
  return template.replace("{version}", version);
}
```

Extend `refreshFeed` to fetch the catalog after the feed. A catalog failure must not fail the whole refresh: the feed is the more important document, and the missing-catalog finding already reports the gap.

```typescript
    // CATALOG_DIGEST.version is the installed package's version, generated at
    // build time. refreshFeed() has no version parameter and reading
    // package.json at runtime would reintroduce the __dirname problem.
    const version = CATALOG_DIGEST.version;
    let catalog: RefreshResult | undefined;
    try {
      const catalogBody = decodeCatalogBody(
        (await fetchHttpsBuffer(catalogUrlFor(version), limits)).body,
      );
      const catalogEntries = parseFeedPayload(catalogBody, "catalog");
      const catalogPath = path.join(cacheDir, CATALOG_CACHE_FILE);
      fs.writeFileSync(catalogPath, JSON.stringify({
        version,
        sha256: createHash("sha256").update(catalogBody, "utf8").digest("hex"),
        timestamp: new Date().toISOString(),
        entries: catalogEntries,
      }, null, 2));
      catalog = { entryCount: catalogEntries.length, cachePath: catalogPath };
    } catch { /* the missing-catalog finding reports this; the feed refresh stands */ }
```

The digest is taken over the DECODED body, matching how `generate-catalog.mjs`
computes it in Task 7. Both sides hash the decompressed JSON, so an air-gapped
mirror serving the asset uncompressed still verifies.

Add the imports `createHash` from `node:crypto` and `CATALOG_DIGEST` from
`./catalog-digest.js` at the top of `src/feed.ts`.

In `src/cli.ts`, extend the `feed refresh` output so the operator sees both results:

```typescript
  console.log(`Feed refreshed: ${result.entryCount} entries -> ${result.cachePath}`);
  if (result.catalog) {
    console.log(`Catalog refreshed: ${result.catalog.entryCount} entries -> ${result.catalog.cachePath}`);
  } else {
    console.log("Catalog not available for this release; historical indicators were not downloaded.");
  }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/__tests__/feed.test.ts -t "catalogUrlFor"`
Expected: PASS, 2 tests.

- [ ] **Step 5: Confirm the digest agrees across both sides**

Run `npx vitest run src/__tests__/feed.test.ts -t "buildCatalog"` and confirm the Task 7 tests still pass. Then run `npm run check:catalog` and expect `catalog digest up to date`. The client and the generator must hash the same bytes, so if this disagrees every download would be rejected as a digest mismatch.

- [ ] **Step 6: Commit**

```bash
git add src/feed.ts src/cli.ts src/__tests__/feed.test.ts
git commit -m "feat(cli): feed refresh downloads the catalog alongside the feed

One verb, both documents. The asset is pinned to the installed version
rather than latest: the client verifies against the digest shipped in its
own package, and version pinning is what makes a stale cache detectable at
all. A catalog failure leaves the feed refresh standing, because the
missing-catalog finding already reports the gap. The digest is taken over
the decompressed JSON on both sides so an uncompressed mirror still
verifies."
```

---

### Task 11: Publish the catalog asset from CI

**Files:**
- Modify: `.github/workflows/ci.yml` (the `release` job, around line 641)

**Interfaces:**
- Consumes: `npm run catalog:generate` from Task 7

- [ ] **Step 1: Add the generation and upload steps**

In the `release` job, between "Extract changelog for this version" and "Create GitHub Release", add:

```yaml
      - name: Set up Node
        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: 22

      - name: Build the catalog asset
        run: |
          npm run catalog:generate
          # The digest committed in the repo must match what we are about to
          # publish. If it does not, the tagged tree and the asset disagree and
          # every client would reject the download as a digest mismatch.
          node -e "
            const fs = require('node:fs');
            const src = fs.readFileSync('src/catalog-digest.ts', 'utf8');
            const built = {
              version: /version: "([^"]+)"/.exec(src)[1],
              sha256: /sha256: "([^"]+)"/.exec(src)[1],
              entryCount: Number(/entryCount: (\d+)/.exec(src)[1]),
            };
            const tagged = process.env.GITHUB_REF_NAME.replace(/^v/, '');
            if (built.version !== tagged) {
              console.error('catalog digest version ' + built.version + ' does not match tag ' + tagged);
              process.exit(1);
            }
            console.log('catalog asset: ' + built.entryCount + ' entries, sha256 ' + built.sha256);
          "
```

Then change the release creation step to attach the asset:

```yaml
      - name: Create GitHub Release
        run: |
          gh release create "$GITHUB_REF_NAME" \
            --title "supply-chain-guard $GITHUB_REF_NAME" \
            --notes-file release_notes.md \
            catalog.json.gz
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 2: Verify the workflow file is valid before pushing**

Run:

```bash
node -e "const y=require('js-yaml');const fs=require('node:fs');y.load(fs.readFileSync('.github/workflows/ci.yml','utf8'));console.log('ci.yml parses')"
```

Expected: `ci.yml parses`. An invalid `ci.yml` makes the ENTIRE workflow file invalid and no job runs at all, which reads as "CI did not trigger" rather than as a syntax error.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: publish the catalog asset with the GitHub Release

One extra argument on the existing gh release create call, which already
holds contents: write. Asserts before publishing that the committed digest's
version matches the tag, because a tagged tree and an asset that disagree
would make every client reject the download as a digest mismatch."
```

---

### Task 12: Phase 1 acceptance

Detection must be provably unchanged. This is the task that demonstrates it.

**Files:** none modified; this is verification.

- [ ] **Step 1: Confirm the bundle was not touched**

```bash
git diff --stat origin/main -- src/threat-intel.ts feed.json
```

Expected: `src/threat-intel.ts` shows only the additions from Tasks 1, 5 and 8 (the inert-catalog check, the `kind` key, the catalog cache), and `feed.json` shows NO diff at all. A changed `feed.json` means an indicator moved, which is Phase 2 work and must not happen here.

- [ ] **Step 2: Confirm the entry count is unchanged**

```bash
node -e "console.log(require('./feed.json').entryCount)"
```

Expected: 20969, the same count as v6.1.3.

- [ ] **Step 3: Confirm the whole gate chain is green**

```bash
npm run build
npx --no-install aahp lint
```

Expected: `check:aahp`, `check:feed`, `check:feed-partition`, `check:feed-budget`, `check:catalog`, `check:handoff`, `check:self-scan`, then `tsc`, all green; lint green.

- [ ] **Step 4: Confirm the self-scan does not flag the catalog**

```bash
node dist/cli.js scan . --format json > /tmp/self.json
node -e "const r=require('/tmp/self.json'); const c=r.findings.filter(f=>(f.file||'').includes('threat-catalog')); console.log('catalog findings:', c.length)"
```

Expected: `catalog findings: 0`. The catalog is empty in Phase 1, so run this again at the start of Phase 2 with a populated catalog, which is the case that actually exercises `isInertThreatCatalogFile`.

- [ ] **Step 5: Run every suite touched by this phase**

```bash
npx vitest run src/__tests__/feed.test.ts src/__tests__/threat-intel.test.ts \
  src/__tests__/feed-partition.test.ts src/__tests__/self-scan-recognition.test.ts \
  src/__tests__/campaigns.test.ts
```

Expected on Windows: all pass except the two known environment failures (`Phantom Bot C2 domain`, `GlassWASM stage-2 delivery host`) plus the vscode-scanner archive tests if that file is run. Confirm any failure also fails on unmodified `main` before attributing it to this work.

Then get the real verdict, because a Windows run cannot produce one:

```bash
ssh openclaw
WD=$(mktemp -d /tmp/scg-phase1-XXXXXX) && cd "$WD"
git clone --quiet --branch feat/threat-feed-catalog-phase-1 https://github.com/homeofe/supply-chain-guard.git repo
cd repo && npm ci --silent && npx vitest run --reporter=dot
```

Expected: 146 files and at least 3565 tests passing, zero failures. The baseline at v6.1.3 is exactly 146 / 3565; this phase adds test files, so both numbers must be HIGHER and the failure count must still be zero. Remove the temp directory when done.

- [ ] **Step 6: Update the handoff and open the PR**

Prepend a dated note to `.ai/handoff/STATUS.md` recording what Phase 1 changed, the measured bundle size and import time (unchanged), and that Phase 2 is the next step. Run `npm run handoff:refresh`, then:

```bash
git add -A
git commit -m "docs(handoff): record Phase 1 of the catalog decoupling"
git push -u origin feat/threat-feed-catalog-phase-1
gh pr create --base main --title "feat(feed): catalog decoupling, Phase 1" --body-file <path>
```

The PR body must state that `feed.json` is unchanged and the entry count is still 20969, because that is the claim a reviewer needs to check.

---

## Phases 2 to 4

Not in this plan. Each is a separate deliverable with its own plan, written after the preceding phase has landed and its measurements are known:

- **Phase 2** moves `BUNDLE_CUTOFF_DATE` forward and migrates the now-unqualifying bundle entries into the catalog, preserving the bundle's 792 curated comment lines by removing a batch header only when every entry beneath it moved. This is the only phase that reduces what a bare install detects.
- **Phase 3** drains the five deferral ranges into the catalog through the importer's routing rule.
- **Phase 4** retires the deferral mechanism for bulk waves.

Phase 2's plan depends on the bundle size and import time Phase 1 measures, so writing it now would be guessing.

## Self-review

Checked against the spec on 2026-09-16:

- **Spec coverage.** Section 4.1 two stores: Tasks 2, 3. Section 4.2 partition policy and committed cutoff: Task 2. Section 4.3 catalog envelope, gzip, empty allowance: Tasks 5, 6, 7. Section 4.4 hosting and digest: Tasks 7, 10, 11. Section 4.5 cache and availability: Task 8. Section 4.6 self-scan inertness: Task 1. Section 5 finding and policy knob: Task 9. Section 6 budget gate: Task 4. Section 7 Phase 1: Task 12 verifies it. Section 8 tests: every listed Phase 1 case has a task, except catalog detection parity and comment preservation, which are Phase 2 cases because they need a populated catalog.
- **Type consistency.** `CatalogState` is defined in Task 8 and consumed in Task 9. `decodeCatalogBody` is defined in Task 6 and consumed in Task 10. `partitionTarget`/`loadPartitionConfig` are defined in Task 2 and consumed in Tasks 3 and 4. `CATALOG_CACHE_FILE` is defined in Task 8 and consumed in Task 10.
- **One cross-task conflict found and resolved inline.** Task 7 originally hashed the gzip bytes while Task 10 hashed the decoded body, which would have made every download fail verification. Task 10 Step 3 now changes both sides to hash the decompressed JSON, and Task 10 Step 5 regenerates the digest.
