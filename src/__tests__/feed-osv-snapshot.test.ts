/**
 * Full OpenSSF reconcile (`feed:import -- --osv-snapshot`, `feed:reconcile`).
 *
 * WHY THIS EXISTS. The windowed OpenSSF adapter discovers records through
 * modified_id.csv and keeps only ids whose `modified` date falls inside the
 * window. A record nobody touched after the adapter was introduced
 * (2026-08-31) was therefore never fetched by any run. The first complete
 * reconcile on 2026-10-05 found 164,239 such entries missing from BOTH stores,
 * among them a PyPI reverse shell and an npm credential stealer from June 2026.
 *
 * Every test is offline: archives are built in memory and served through an
 * injected fetchImpl. Package names are synthetic.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { deflateRawSync } from "node:zlib";

const IMPORT_SCRIPT_URL = new URL("../../scripts/import-threat-feed.mjs", import.meta.url).href;
const load = () => import(/* @vite-ignore */ IMPORT_SCRIPT_URL);

// ---------------------------------------------------------------------------
// A minimal zip writer, so the reader is tested against real archive bytes.
// ---------------------------------------------------------------------------

interface ZipFile {
  name: string;
  data: string | Buffer;
  stored?: boolean;
  encrypted?: boolean;
  /** Lie about the uncompressed size in the central directory. */
  declaredSize?: number;
}

function buildZip(files: ZipFile[], { zip64 = false } = {}): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const file of files) {
    const raw = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data, "utf8");
    const body = file.stored ? raw : deflateRawSync(raw);
    const method = file.stored ? 0 : 8;
    const flags = file.encrypted ? 1 : 0;
    const name = Buffer.from(file.name, "utf8");
    const size = file.declaredSize ?? raw.length;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, body);

    // In ZIP64 mode the local offset is saturated and carried in the extra field.
    const extra = zip64 ? Buffer.alloc(12) : Buffer.alloc(0);
    if (zip64) {
      extra.writeUInt16LE(0x0001, 0);
      extra.writeUInt16LE(8, 2);
      extra.writeBigUInt64LE(BigInt(offset), 4);
    }
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(45, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(extra.length, 30);
    central.writeUInt32LE(zip64 ? 0xffffffff : offset, 42);
    centrals.push(central, name, extra);

    offset += local.length + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const cdOffset = offset;
  const tail: Buffer[] = [];
  if (zip64) {
    const record = Buffer.alloc(56);
    record.writeUInt32LE(0x06064b50, 0);
    record.writeBigUInt64LE(44n, 4);
    record.writeBigUInt64LE(BigInt(files.length), 24);
    record.writeBigUInt64LE(BigInt(files.length), 32);
    record.writeBigUInt64LE(BigInt(cd.length), 40);
    record.writeBigUInt64LE(BigInt(cdOffset), 48);
    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(0x07064b50, 0);
    locator.writeBigUInt64LE(BigInt(cdOffset + cd.length), 8);
    locator.writeUInt32LE(1, 16);
    tail.push(record, locator);
  }
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(zip64 ? 0xffff : files.length, 8);
  eocd.writeUInt16LE(zip64 ? 0xffff : files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(zip64 ? 0xffffffff : cdOffset, 16);
  return Buffer.concat([...locals, cd, ...tail, eocd]);
}

function malRecord(id: string, over: Record<string, unknown> = {}) {
  return {
    id,
    published: "2026-06-05T22:09:46Z",
    // Deliberately OLD: no windowed run after 2026-08-31 would ever list it.
    modified: "2026-06-06T00:00:00Z",
    affected: [
      {
        package: { ecosystem: "npm", name: `scg-snapshot-${id.toLowerCase()}` },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
      },
    ],
    database_specific: { "malicious-packages-origins": [{ source: "kam193" }] },
    ...over,
  };
}

const record = (id: string, over: Record<string, unknown> = {}) => ({
  name: `osv/${id}.json`,
  data: JSON.stringify(malRecord(id, over)),
});

/** Serve one archive per OSV directory; fail on anything else. */
function archiveFetch(archives: Record<string, Buffer>, calls: string[] = []) {
  return async (url: string | URL) => {
    const value = String(url);
    calls.push(value);
    const match = value.match(/osv-vulnerabilities\/([^/]+)\/all\.zip$/);
    const body = match ? archives[decodeURIComponent(match[1])] : undefined;
    if (!body) return { ok: false, status: 404, headers: { get: () => null } };
    return {
      ok: true,
      status: 200,
      headers: { get: (h: string) => (h.toLowerCase() === "content-length" ? String(body.length) : null) },
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.length),
    };
  };
}

const emptyZip = () => buildZip([]);

// ---------------------------------------------------------------------------
// readZipEntries
// ---------------------------------------------------------------------------

describe("readZipEntries", () => {
  it("reads stored and deflated entries", async () => {
    const { readZipEntries } = await load();
    const zip = buildZip([
      { name: "a.json", data: '{"a":1}', stored: true },
      { name: "b.json", data: '{"b":2}' },
    ]);
    const entries = readZipEntries(zip);
    expect(entries.map((e: { name: string; data: Buffer }) => [e.name, e.data.toString()])).toEqual([
      ["a.json", '{"a":1}'],
      ["b.json", '{"b":2}'],
    ]);
  });

  // npm's export holds more than 65,535 files, so its end record is saturated
  // and the real counts live in the ZIP64 record. A reader without this path
  // reads 65,535 records and silently drops the rest.
  it("follows the ZIP64 end record when the classic one is saturated", async () => {
    const { readZipEntries } = await load();
    const zip = buildZip(
      [
        { name: "x.json", data: "1" },
        { name: "y.json", data: "2" },
        { name: "z.json", data: "3" },
      ],
      { zip64: true },
    );
    expect(readZipEntries(zip).map((e: { name: string }) => e.name)).toEqual(["x.json", "y.json", "z.json"]);
  });

  it("applies the include filter and skips directories", async () => {
    const { readZipEntries } = await load();
    const zip = buildZip([
      { name: "dir/", data: "", stored: true },
      { name: "dir/MAL-1.json", data: "1" },
      { name: "dir/GHSA-1.json", data: "2" },
    ]);
    const names = readZipEntries(zip, { include: (n: string) => n.includes("MAL-") }).map(
      (e: { name: string }) => e.name,
    );
    expect(names).toEqual(["dir/MAL-1.json"]);
  });

  it("throws on a truncated archive instead of returning what it could read", async () => {
    const { readZipEntries } = await load();
    const zip = buildZip([{ name: "a.json", data: "x".repeat(200) }]);
    expect(() => readZipEntries(zip.subarray(0, zip.length - 10))).toThrow(/zip:/);
    expect(() => readZipEntries(zip.subarray(0, 40))).toThrow(/zip:/);
  });

  it("throws when an entry inflates to a different size than declared", async () => {
    const { readZipEntries } = await load();
    const zip = buildZip([{ name: "a.json", data: "abc", stored: true, declaredSize: 4 }]);
    expect(() => readZipEntries(zip)).toThrow(/expected 4/);
  });

  it("refuses an encrypted entry", async () => {
    const { readZipEntries } = await load();
    const zip = buildZip([{ name: "a.json", data: "abc", encrypted: true }]);
    expect(() => readZipEntries(zip)).toThrow(/encrypted/);
  });

  it("refuses an entry larger than the per-record bound", async () => {
    const { readZipEntries } = await load();
    const zip = buildZip([{ name: "a.json", data: "x".repeat(100) }]);
    expect(() => readZipEntries(zip, { maxEntryBytes: 10 })).toThrow(/over 10/);
  });
});

// ---------------------------------------------------------------------------
// fetchOsvMalwareSnapshot
// ---------------------------------------------------------------------------

describe("fetchOsvMalwareSnapshot", () => {
  it("returns every MAL record of the selected ecosystems and nothing else", async () => {
    const { fetchOsvMalwareSnapshot } = await load();
    const calls: string[] = [];
    const fetchImpl = archiveFetch(
      {
        npm: buildZip([record("MAL-2026-1"), record("MAL-2026-2"), { name: "osv/GHSA-xxxx.json", data: "{}" }]),
        PyPI: buildZip([record("MAL-2026-3")]),
      },
      calls,
    );
    const result = await fetchOsvMalwareSnapshot({ ecosystems: ["npm", "pip"], fetchImpl });
    expect(result.records.map((r: { id: string }) => r.id)).toEqual(["MAL-2026-1", "MAL-2026-2", "MAL-2026-3"]);
    expect(result.archives).toEqual([
      expect.objectContaining({ directory: "npm", malRecords: 2 }),
      expect.objectContaining({ directory: "PyPI", malRecords: 1 }),
    ]);
    expect(calls.every((u) => u.endsWith("/all.zip"))).toBe(true);
  });

  it("fetches a record named by two ecosystem exports once", async () => {
    const { fetchOsvMalwareSnapshot } = await load();
    const fetchImpl = archiveFetch({
      npm: buildZip([record("MAL-2026-7")]),
      PyPI: buildZip([record("MAL-2026-7")]),
    });
    const result = await fetchOsvMalwareSnapshot({ ecosystems: ["npm", "pip"], fetchImpl });
    expect(result.records).toHaveLength(1);
  });

  // Zero is a claim and needs a control: an empty npm export can only be a
  // broken export or a broken reader, never "no malware on npm".
  it("refuses an npm snapshot without a single MAL record", async () => {
    const { fetchOsvMalwareSnapshot } = await load();
    const fetchImpl = archiveFetch({ npm: emptyZip() });
    await expect(fetchOsvMalwareSnapshot({ ecosystems: ["npm"], fetchImpl })).rejects.toThrow(
      /holds no MAL records/,
    );
  });

  it("accepts an empty export for a small ecosystem", async () => {
    const { fetchOsvMalwareSnapshot } = await load();
    const fetchImpl = archiveFetch({ CRAN: emptyZip() });
    const result = await fetchOsvMalwareSnapshot({ ecosystems: ["cran"], fetchImpl });
    expect(result.records).toEqual([]);
  });

  it("rejects the whole snapshot when one archive is unavailable", async () => {
    const { fetchOsvMalwareSnapshot } = await load();
    const fetchImpl = archiveFetch({ npm: buildZip([record("MAL-2026-1")]) });
    await expect(fetchOsvMalwareSnapshot({ ecosystems: ["npm", "pip"], fetchImpl })).rejects.toThrow(
      /HTTP 404/,
    );
  });

  it("rejects a record whose id does not match its file name", async () => {
    const { fetchOsvMalwareSnapshot } = await load();
    const fetchImpl = archiveFetch({
      npm: buildZip([{ name: "osv/MAL-2026-1.json", data: JSON.stringify(malRecord("MAL-2026-9")) }]),
    });
    await expect(fetchOsvMalwareSnapshot({ ecosystems: ["npm"], fetchImpl })).rejects.toThrow(
      /unexpected payload/,
    );
  });

  it("rejects a record that is not JSON", async () => {
    const { fetchOsvMalwareSnapshot } = await load();
    const fetchImpl = archiveFetch({ npm: buildZip([{ name: "osv/MAL-2026-1.json", data: "{" }]) });
    await expect(fetchOsvMalwareSnapshot({ ecosystems: ["npm"], fetchImpl })).rejects.toThrow(/not valid JSON/);
  });
});

// ---------------------------------------------------------------------------
// importUpstreamFeed --osv-snapshot, end to end in a throwaway repository
// ---------------------------------------------------------------------------

describe("importUpstreamFeed with osvSnapshot", () => {
  let root: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-snapshot-"));
    fs.mkdirSync(path.join(root, "src"));
    fs.mkdirSync(path.join(root, "data", "threat-catalog"), { recursive: true });
    fs.writeFileSync(
      path.join(root, "src", "threat-intel.ts"),
      [
        "export interface FeedIOC { type: string }",
        'export const FEED_GENERATED_AT = "2026-08-23T00:00:00.000Z";',
        "const BUNDLED_FEED: FeedIOC[] = [",
        '  { type: "domain", value: "existing.example", severity: "critical", confidence: 1.0 },',
        "];",
        "",
      ].join("\n"),
    );
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ version: "9.9.9" }));
    fs.writeFileSync(path.join(root, "feed.json"), '{"schema":1,"entries":[]}\n');
    // One record is already in the catalog: the reconcile must count it as present.
    fs.writeFileSync(
      path.join(root, "data", "threat-catalog", "part-000.jsonl"),
      '{"type":"package","value":"scg-snapshot-mal-2026-2","severity":"critical","confidence":0.9,"source":"MAL-2026-2 (kam193)","firstSeen":"2026-06-05"}\n',
    );
    fs.writeFileSync(
      path.join(root, "feed-partition.config.json"),
      JSON.stringify({ bundleCutoffDate: "2026-09-04", maxBundledEntries: 15000, maxBundleBytes: 2097152 }),
    );
    fs.writeFileSync(
      path.join(root, "src", "catalog-digest.ts"),
      'export const CATALOG_DIGEST = {\n  version: "9.9.9",\n  sha256: "",\n  entryCount: 1,\n  shardCount: 1,\n} as const;\n',
    );
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  const archives = () => ({
    npm: buildZip([record("MAL-2026-1"), record("MAL-2026-2")]),
    PyPI: buildZip([
      record("MAL-2026-3", {
        affected: [{ package: { ecosystem: "PyPI", name: "scg-snapshot-py" }, versions: ["0.0.1", "0.0.2"] }],
      }),
    ]),
  });

  it("finds an old record the windowed run can never list, and routes it to the catalog", async () => {
    const { importUpstreamFeed } = await load();
    const calls: string[] = [];
    const report = await importUpstreamFeed({
      root,
      osvSnapshot: true,
      ecosystems: ["npm", "pip"],
      fetchImpl: archiveFetch(archives(), calls),
      now: new Date("2026-10-05T08:00:00Z"),
    });
    expect(report.osvSnapshot).toBe(true);
    expect(report.since).toBeNull();
    expect(report.duplicates).toBe(1);
    expect(report.entries.map((e: { value: string }) => e.value).sort()).toEqual([
      "pypi:scg-snapshot-py@0.0.1",
      "pypi:scg-snapshot-py@0.0.2",
      "scg-snapshot-mal-2026-1",
    ]);
    expect(report.addedToCatalog).toBe(3);
    expect(report.addedToBundle).toBe(0);
    expect(report.written).toBe(true);
    const catalog = fs.readFileSync(path.join(root, "data", "threat-catalog", "part-000.jsonl"), "utf8");
    expect(catalog).toContain('"scg-snapshot-mal-2026-1"');
    expect(catalog).toContain('"pypi:scg-snapshot-py@0.0.1"');
    // The snapshot never asks GitHub, so it needs no token and no page budget.
    expect(calls.some((u) => u.includes("api.github.com"))).toBe(false);
  });

  // The control for the test above: the same old record is invisible to the
  // windowed adapter, which is exactly the gap this mode closes.
  it("control: the windowed adapter does not list a record modified before its window", async () => {
    const { parseOsvModifiedIndex } = await load();
    const index = "2026-06-06T00:00:00Z,MAL-2026-1\n2026-10-04T00:00:00Z,MAL-2026-99\n";
    expect(parseOsvModifiedIndex(index, { since: "2026-09-21" }).map((e: { id: string }) => e.id)).toEqual([
      "MAL-2026-99",
    ]);
  });

  it("is complete on a second run: nothing left to add", async () => {
    const { importUpstreamFeed, checkFailed } = await load();
    const opts = {
      root,
      osvSnapshot: true,
      ecosystems: ["npm", "pip"],
      now: new Date("2026-10-05T08:00:00Z"),
    };
    const first = await importUpstreamFeed({ ...opts, fetchImpl: archiveFetch(archives()) });
    expect(checkFailed(first)).toBe(true);
    const second = await importUpstreamFeed({ ...opts, dryRun: true, fetchImpl: archiveFetch(archives()) });
    expect(second.added).toBe(0);
    expect(checkFailed(second)).toBe(false);
  });

  it("cannot be combined with a date window or with --no-ossf", async () => {
    const { importUpstreamFeed } = await load();
    await expect(
      importUpstreamFeed({ root, osvSnapshot: true, since: "2026-01-01", fetchImpl: archiveFetch(archives()) }),
    ).rejects.toThrow(/cannot be combined with --since/);
    await expect(
      importUpstreamFeed({ root, osvSnapshot: true, useOssf: false, fetchImpl: archiveFetch(archives()) }),
    ).rejects.toThrow(/cannot be combined with --no-ossf/);
  });

  // 260,000 candidates used to overflow the call stack in `push(...array)`.
  it("handles a snapshot far larger than the argument limit", async () => {
    const { importUpstreamFeed } = await load();
    const count = 150_000;
    const records = Array.from({ length: count }, (_, i) => ({
      name: `osv/MAL-2025-${i}.json`,
      data: JSON.stringify(malRecord(`MAL-2025-${i}`)),
      stored: true,
    }));
    const report = await importUpstreamFeed({
      root,
      osvSnapshot: true,
      ecosystems: ["npm"],
      dryRun: true,
      // Over 65,535 files: ZIP64, like the real npm export.
      fetchImpl: archiveFetch({ npm: buildZip(records, { zip64: true }) }),
      now: new Date("2026-10-05T08:00:00Z"),
    });
    expect(report.added).toBe(count);
  }, 120_000);
});

describe("checkFailed (the --check verdict)", () => {
  it("is red when an overdue entry is missing or anything is held back, green only at zero", async () => {
    const { checkFailed } = await load();
    expect(checkFailed({ added: 1, overdue: 1, deferred: 0 })).toBe(true);
    expect(checkFailed({ added: 0, overdue: 0, deferred: 3 })).toBe(true);
    expect(checkFailed({ added: 0, overdue: 0, deferred: 0 })).toBe(false);
  });

  // Both directions of the grace period, through the real pipeline. A record
  // upstream changed today is import latency; one changed in June is a gap.
  it("does not fail on a record younger than the grace period, and does on an old one", async () => {
    const { importUpstreamFeed, checkFailed } = await load();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-grace-"));
    try {
      fs.mkdirSync(path.join(root, "src"));
      fs.mkdirSync(path.join(root, "data", "threat-catalog"), { recursive: true });
      fs.writeFileSync(
        path.join(root, "src", "threat-intel.ts"),
        'export interface FeedIOC { type: string }\nconst BUNDLED_FEED: FeedIOC[] = [\n  { type: "domain", value: "existing.example", severity: "critical", confidence: 1.0 },\n];\n',
      );
      fs.writeFileSync(path.join(root, "data", "threat-catalog", "part-000.jsonl"), "");
      fs.writeFileSync(
        path.join(root, "feed-partition.config.json"),
        JSON.stringify({ bundleCutoffDate: "2026-09-04", maxBundledEntries: 15000, maxBundleBytes: 2097152 }),
      );
      const now = new Date("2026-10-05T08:00:00Z");
      const run = (modified: string) =>
        importUpstreamFeed({
          root,
          osvSnapshot: true,
          ecosystems: ["npm"],
          dryRun: true,
          now,
          fetchImpl: archiveFetch({
            npm: buildZip([record("MAL-2026-5", { published: modified, modified })]),
          }),
        });
      const fresh = await run("2026-10-05T01:00:00Z");
      expect(fresh.added).toBe(1);
      expect(fresh.overdue).toBe(0);
      expect(checkFailed(fresh)).toBe(false);
      const old = await run("2026-06-06T00:00:00Z");
      expect(old.overdue).toBe(1);
      expect(checkFailed(old)).toBe(true);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("rejects a non-numeric grace period instead of disabling the gate", async () => {
    const { parseArgs } = await load();
    expect(() => parseArgs(["--grace-days", "abc"])).toThrow(/positive integer/);
  });

  it("--check implies a dry run, so the gate never writes", async () => {
    const { parseArgs } = await load();
    expect(parseArgs(["--osv-snapshot", "--check"])).toEqual(
      expect.objectContaining({ osvSnapshot: true, check: true, dryRun: true }),
    );
  });
});
