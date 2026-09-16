import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";

import {
  readCatalogEntries,
  buildCatalog,
  renderDigestModule,
  checkCatalogHygiene,
  checkCatalogSize,
  FEED_ENTRY_KEYS,
  CATALOG_SHARD_MAX_ENTRIES,
  CATALOG_SHARD_MAX_BYTES,
  CATALOG_MAX_DECOMPRESSED_BYTES as SCRIPT_FLOOR,
} from "../../scripts/generate-catalog.mjs";
import { CATALOG_KEY_ORDER } from "../../scripts/feed-migrate.mjs";
import { CATALOG_MAX_DECOMPRESSED_BYTES as CLIENT_FLOOR } from "../feed.js";

const entry = (value: string, extra: Record<string, unknown> = {}) => ({
  type: "package",
  value,
  severity: "critical",
  confidence: 1,
  ...extra,
});

const many = (n: number) => Array.from({ length: n }, (_, i) => entry(`p${i}@1`));

describe("buildCatalog", () => {
  it("puts a small corpus in a single shard", () => {
    const { shards, digest } = buildCatalog(many(3), "1.2.3");
    expect(shards).toHaveLength(1);
    expect(shards[0].path).toBe("catalog-000.json.gz");
    expect(digest).toMatchObject({ version: "1.2.3", entryCount: 3, shardCount: 1 });
  });

  // Always at least one shard. An empty catalog is the legitimate Phase 1
  // state, and a zero-shard index would give the client nothing to verify
  // against, making "no catalog" and "an empty catalog" indistinguishable.
  it("emits one shard even when the catalog is empty", () => {
    const { shards, digest } = buildCatalog([], "1.2.3");
    expect(shards).toHaveLength(1);
    expect(shards[0].entryCount).toBe(0);
    expect(digest.entryCount).toBe(0);
  });

  it("splits at exactly CATALOG_SHARD_MAX_ENTRIES, not one either side", () => {
    expect(buildCatalog(many(CATALOG_SHARD_MAX_ENTRIES), "1.2.3").shards).toHaveLength(1);
    expect(buildCatalog(many(CATALOG_SHARD_MAX_ENTRIES + 1), "1.2.3").shards).toHaveLength(2);
  });

  it("loses no entry across a split", () => {
    const entries = many(CATALOG_SHARD_MAX_ENTRIES + 7);
    const { shards, digest } = buildCatalog(entries, "1.2.3");
    const total = shards.reduce((n: number, s: { entryCount: number }) => n + s.entryCount, 0);
    expect(total).toBe(entries.length);
    expect(digest.entryCount).toBe(entries.length);
  });

  // The chain of trust: the package holds the index digest, the index holds a
  // digest per shard. If either link is computed over the wrong bytes the chain
  // verifies nothing while still looking complete.
  it("digests the index, and the index digests each shard", () => {
    const { indexJson, shards, digest } = buildCatalog(many(2), "1.2.3");
    expect(digest.sha256).toBe(createHash("sha256").update(indexJson, "utf8").digest("hex"));

    const index = JSON.parse(indexJson);
    expect(index.kind).toBe("catalog-index");
    expect(index.shards[0].sha256).toBe(
      createHash("sha256").update(shards[0].json, "utf8").digest("hex"),
    );
  });

  // The digest is over the DECOMPRESSED json, so an air-gapped mirror serving
  // the asset uncompressed still verifies, and a zlib version change cannot
  // make a correct catalog fail.
  it("digests the decompressed json, not the gzip bytes", () => {
    const { shards } = buildCatalog(many(2), "1.2.3");
    const overGz = createHash("sha256").update(shards[0].gz).digest("hex");
    expect(shards[0].sha256).not.toBe(overGz);
  });

  // Determinism is what lets check:catalog be a gate at all. A clock-derived
  // field would make the output a function of the day it ran, so an untouched
  // tree would go red the next morning.
  it("is byte-reproducible and carries no clock-derived field", () => {
    const a = buildCatalog(many(5), "1.2.3");
    const b = buildCatalog(many(5), "1.2.3");
    expect(b.indexJson).toBe(a.indexJson);
    expect(b.digest.sha256).toBe(a.digest.sha256);
    expect(a.indexJson).not.toContain("generatedAt");
    expect(a.shards[0].json).not.toContain("generatedAt");
  });

  it("marks shards as kind catalog and the index as kind catalog-index", () => {
    const { indexJson, shards } = buildCatalog(many(2), "1.2.3");
    expect(JSON.parse(shards[0].json).kind).toBe("catalog");
    expect(JSON.parse(indexJson).kind).toBe("catalog-index");
  });
});

describe("renderDigestModule", () => {
  it("renders a typed constant and ends with a newline", () => {
    const out = renderDigestModule({
      version: "1.2.3",
      sha256: "abc",
      entryCount: 4,
      shardCount: 2,
    });
    expect(out).toContain('version: "1.2.3"');
    expect(out).toContain('sha256: "abc"');
    expect(out).toContain("entryCount: 4");
    expect(out).toContain("shardCount: 2");
    expect(out).toContain("as const");
    expect(out.endsWith("\n")).toBe(true);
  });

  // The control: the byte comparison check:catalog performs must be able to
  // FAIL. Without this, a comparison that always matched would look identical
  // to a gate that works.
  it("changes when the digest changes", () => {
    const base = { version: "1.2.3", sha256: "abc", entryCount: 0, shardCount: 1 };
    expect(renderDigestModule({ ...base, sha256: "def" })).not.toBe(renderDigestModule(base));
    expect(renderDigestModule({ ...base, entryCount: 1 })).not.toBe(renderDigestModule(base));
  });
});

describe("the compatibility floor is shared, not mirrored", () => {
  // Two copies of a floor in two modules is the pair that silently diverges.
  // Released clients carry their own copy, so a generator that drifts above the
  // client's limit produces shards that old installs simply cannot read.
  it("matches the client's CATALOG_MAX_DECOMPRESSED_BYTES", () => {
    expect(SCRIPT_FLOOR).toBe(CLIENT_FLOOR);
  });

  it("keeps the per-shard budget below the client floor", () => {
    expect(CATALOG_SHARD_MAX_BYTES).toBeLessThan(CLIENT_FLOOR);
  });

  // The plan's draft of this generator listed eleven allowed keys, including
  // the legacy note and ecosystem that Phase 1 had already removed. Sharing one
  // definition is what makes that class of drift impossible rather than merely
  // unlikely.
  it("allows exactly the fields the migration writes, both directions", () => {
    expect([...FEED_ENTRY_KEYS].sort()).toEqual([...CATALOG_KEY_ORDER].sort());
    expect(FEED_ENTRY_KEYS.has("note")).toBe(false);
    expect(FEED_ENTRY_KEYS.has("ecosystem")).toBe(false);
  });
});

describe("checkCatalogSize", () => {
  it("passes a shard inside the budget", () => {
    const { shards } = buildCatalog(many(10), "1.2.3");
    expect(checkCatalogSize(shards)).toEqual([]);
  });

  it("reports a shard over the budget", () => {
    const oversized = [{ path: "catalog-000.json.gz", json: "x".repeat(CATALOG_SHARD_MAX_BYTES + 1) }];
    const violations = checkCatalogSize(oversized);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatch(/over the \d+ byte per-shard budget/);
    // The remedy must not be "raise the client limit", which cannot reach
    // installs that already exist.
    expect(violations[0]).toMatch(/do NOT raise the client limit/);
  });

  it("treats a shard at exactly the budget as acceptable", () => {
    const atCap = [{ path: "catalog-000.json.gz", json: "x".repeat(CATALOG_SHARD_MAX_BYTES) }];
    expect(checkCatalogSize(atCap)).toEqual([]);
  });
});

describe("checkCatalogHygiene", () => {
  it("passes ordinary public advisory data", () => {
    expect(
      checkCatalogHygiene([
        entry("left-pad@1.0.0", { source: "GHSA-1234-5678-9abc", firstSeen: "2026-01-01" }),
      ]),
    ).toEqual([]);
  });

  it("rejects a key that is not an allowed FeedIOC field", () => {
    const v = checkCatalogHygiene([entry("a@1", { internalTicket: "OPS-1" })]);
    expect(v).toHaveLength(1);
    expect(v[0]).toMatch(/key "internalTicket" is not an allowed FeedIOC field/);
  });

  // note was dropped from the allowed fields in Phase 1, so the allowlist
  // rejects it without any separate rule needing to remember it.
  it("rejects the legacy free-text note field", () => {
    expect(checkCatalogHygiene([entry("a@1", { note: "anything" })])[0]).toMatch(/"note"/);
  });

  it.each([
    ["RFC1918 ten", "10.1.2.3"],
    ["RFC1918 192.168", "192.168.0.7"],
    ["RFC1918 172.16", "172.16.4.9"],
    ["loopback", "127.0.0.1"],
    ["link-local", "169.254.1.1"],
  ])("rejects a %s address in value", (_label, value) => {
    const v = checkCatalogHygiene([{ ...entry("x@1"), type: "ip", value }]);
    expect(v.some((s: string) => s.includes("private-infrastructure shape"))).toBe(true);
  });

  it.each([
    ["an .internal host", "buildbox.internal"],
    ["a .corp host", "files.corp"],
    ["localhost", "localhost"],
  ])("rejects %s in value", (_label, value) => {
    const v = checkCatalogHygiene([{ ...entry("x@1"), type: "domain", value }]);
    expect(v.some((s: string) => s.includes("private-infrastructure shape"))).toBe(true);
  });

  it("rejects a local filesystem path leaking through source", () => {
    const win = checkCatalogHygiene([entry("a@1", { source: "C:/Users/someone/notes.txt" })]);
    expect(win.some((s: string) => s.includes("source matches"))).toBe(true);
    const nix = checkCatalogHygiene([entry("a@1", { source: "see /home/someone/notes" })]);
    expect(nix.some((s: string) => s.includes("source matches"))).toBe(true);
  });

  // The report is what gets printed by a public CI job, so it must name the
  // LINE and never the value: a message that echoed the offending string would
  // publish exactly what the check exists to keep unpublished.
  it("reports the line number and never the offending value", () => {
    const v = checkCatalogHygiene([
      entry("clean@1"),
      { ...entry("x@1"), type: "ip", value: "10.9.9.9" },
    ]);
    expect(v).toHaveLength(1);
    expect(v[0]).toContain("line 2");
    expect(v[0]).not.toContain("10.9.9.9");
  });

  it("does not flag a public version string that merely looks numeric", () => {
    expect(checkCatalogHygiene([entry("some-pkg@10.1.2")])).toEqual([]);
  });
});

describe("readCatalogEntries", () => {
  it("reads the committed catalog without throwing", () => {
    expect(Array.isArray(readCatalogEntries())).toBe(true);
  });
});
