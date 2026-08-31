/**
 * Upstream threat-feed import (scripts/import-threat-feed.mjs).
 *
 * Every test here is OFFLINE: the upstream responses are fixtures and the
 * network layer is injected as `fetchImpl`. The three behaviours that matter
 * are the mapping (upstream advisory -> FeedIOC), the deduplication against
 * the feed that is already committed, and the failure mode (a network error
 * must leave src/threat-intel.ts and feed.json byte-identical and surface as
 * a rejected promise, which the CLI turns into a non-zero exit).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { isValidFeedIOC, type FeedIOC } from "../threat-intel.js";

const IMPORT_SCRIPT_URL = new URL("../../scripts/import-threat-feed.mjs", import.meta.url).href;
const load = () => import(/* @vite-ignore */ IMPORT_SCRIPT_URL);

// ---------------------------------------------------------------------------
// Fixtures - shaped exactly like GET /advisories?type=malware responses.
// Package names are synthetic (never real packages) so a fixture can never
// become a live indicator by accident.
// ---------------------------------------------------------------------------

interface AdvisoryFixture {
  ghsa_id: string;
  type?: string;
  severity?: string;
  published_at?: string;
  withdrawn_at?: string | null;
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string };
    vulnerable_version_range: string | null;
  }>;
}

function advisory(over: Partial<AdvisoryFixture> = {}): AdvisoryFixture {
  return {
    ghsa_id: "GHSA-aaaa-bbbb-cccc",
    type: "malware",
    severity: "critical",
    published_at: "2026-07-24T17:20:25Z",
    withdrawn_at: null,
    vulnerabilities: [
      {
        package: { ecosystem: "npm", name: "scg-fixture-pkg" },
        vulnerable_version_range: ">= 0",
      },
    ],
    ...over,
  };
}

/** A fetchImpl that answers one page and then stops. */
function singlePage(body: unknown, status = 200) {
  return async (url?: string | URL) => {
    if (String(url ?? "").includes("modified_id.csv")) {
      return {
        ok: status === 200,
        status,
        headers: { get: () => null },
        text: async () => "",
        json: async () => ({}),
      };
    }
    return {
      ok: status === 200,
      status,
      headers: { get: () => null },
      json: async () => body,
    };
  };
}

function osvMalwareRecord(over: Record<string, unknown> = {}) {
  return {
    id: "MAL-2026-4242",
    published: "2026-08-30T10:00:00Z",
    modified: "2026-08-30T11:00:00Z",
    affected: [
      {
        package: { ecosystem: "npm", name: "scg-fixture-ossf" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
      },
    ],
    database_specific: {
      "malicious-packages-origins": [{ source: "amazon-inspector" }],
    },
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Version-range mapping
// ---------------------------------------------------------------------------

describe("parseVersionRange", () => {
  it("maps an exact pin", async () => {
    const { parseVersionRange } = await load();
    expect(parseVersionRange("= 1.2.3")).toEqual({ kind: "exact", version: "1.2.3" });
    expect(parseVersionRange("=1.2.3")).toEqual({ kind: "exact", version: "1.2.3" });
  });

  it("maps an all-versions range", async () => {
    const { parseVersionRange } = await load();
    expect(parseVersionRange(">= 0")).toEqual({ kind: "all" });
    expect(parseVersionRange("> 0")).toEqual({ kind: "all" });
    expect(parseVersionRange(">= 0.0.0")).toEqual({ kind: "all" });
  });

  it("refuses to collapse a bounded range into a bare-name block", async () => {
    const { parseVersionRange } = await load();
    // Collapsing this to a bare name would block versions upstream never
    // called malicious - the over-blocking the curated feed avoids by hand.
    expect(parseVersionRange(">= 1.0.0, <= 1.2.0")).toEqual({ kind: "unmappable" });
    expect(parseVersionRange("< 2.0.0")).toEqual({ kind: "unmappable" });
    expect(parseVersionRange("")).toEqual({ kind: "unmappable" });
    expect(parseVersionRange(null)).toEqual({ kind: "unmappable" });
  });
});

// ---------------------------------------------------------------------------
// Advisory -> FeedIOC mapping
// ---------------------------------------------------------------------------

describe("mapAdvisory", () => {
  it("maps an all-versions npm advisory to a bare-name IOC", async () => {
    const { mapAdvisory, publicEntry } = await load();
    const { entries, skipped } = mapAdvisory(advisory());
    expect(skipped).toEqual([]);
    expect(publicEntry(entries[0])).toEqual({
      type: "package",
      value: "scg-fixture-pkg",
      severity: "critical",
      confidence: 0.9,
      source: "GHSA-aaaa-bbbb-cccc",
      firstSeen: "2026-07-24",
    });
  });

  it("maps an exact pin to name@version", async () => {
    const { mapAdvisory } = await load();
    const { entries } = mapAdvisory(
      advisory({
        vulnerabilities: [
          {
            package: { ecosystem: "npm", name: "scg-fixture-pkg" },
            vulnerable_version_range: "= 4.5.6",
          },
        ],
      }),
    );
    expect(entries[0].value).toBe("scg-fixture-pkg@4.5.6");
  });

  it("prefixes every non-npm ecosystem the scanner can match", async () => {
    const { mapAdvisory } = await load();
    const cases: Array<[string, string]> = [
      ["pip", "pypi:scg-fixture-pkg"],
      ["composer", "composer:scg-fixture-pkg"],
      ["go", "go:scg-fixture-pkg"],
      ["rubygems", "ruby:scg-fixture-pkg"],
      ["rust", "cargo:scg-fixture-pkg"],
      ["nuget", "nuget:scg-fixture-pkg"],
      ["npm", "scg-fixture-pkg"],
    ];
    for (const [ecosystem, expected] of cases) {
      const { entries } = mapAdvisory(
        advisory({
          vulnerabilities: [
            {
              package: { ecosystem, name: "scg-fixture-pkg" },
              vulnerable_version_range: ">= 0",
            },
          ],
        }),
      );
      expect(entries[0].value).toBe(expected);
    }
  });

  it("keeps a scoped npm name and a Go module path intact", async () => {
    const { mapAdvisory } = await load();
    const { entries } = mapAdvisory(
      advisory({
        vulnerabilities: [
          {
            package: { ecosystem: "npm", name: "@scg-fixture/scoped" },
            vulnerable_version_range: "= 1.0.0",
          },
          {
            package: { ecosystem: "go", name: "github.com/scg-fixture/mod" },
            vulnerable_version_range: ">= 0",
          },
        ],
      }),
    );
    expect(entries.map((e: FeedIOC) => e.value)).toEqual([
      "@scg-fixture/scoped@1.0.0",
      "go:github.com/scg-fixture/mod",
    ]);
  });

  it("maps severity down to the three levels the feed schema has", async () => {
    const { mapAdvisory } = await load();
    const sev = (s: string) => mapAdvisory(advisory({ severity: s })).entries[0].severity;
    expect(sev("critical")).toBe("critical");
    expect(sev("high")).toBe("high");
    expect(sev("moderate")).toBe("medium");
    expect(sev("medium")).toBe("medium");
    // Never promoted above what upstream claimed.
    expect(sev("low")).toBe("medium");
    expect(sev("unknown")).toBe("medium");
  });

  it("records provenance in the source field", async () => {
    const { mapAdvisory } = await load();
    const { entries } = mapAdvisory(advisory({ ghsa_id: "GHSA-1234-5678-9abc" }));
    expect(entries[0].source).toBe("GHSA-1234-5678-9abc");
  });

  it("skips withdrawn advisories", async () => {
    const { mapAdvisory } = await load();
    const result = mapAdvisory(advisory({ withdrawn_at: "2026-07-25T00:00:00Z" }));
    expect(result.entries).toEqual([]);
    expect(result.skipped[0].reason).toBe("withdrawn");
  });

  it("skips ecosystems the scanner has no matcher for", async () => {
    const { mapAdvisory } = await load();
    const result = mapAdvisory(
      advisory({
        vulnerabilities: [
          {
            package: { ecosystem: "maven", name: "org.example:thing" },
            vulnerable_version_range: ">= 0",
          },
        ],
      }),
    );
    expect(result.entries).toEqual([]);
    expect(result.skipped[0].reason).toBe("unsupported-ecosystem");
  });

  it("skips a package name that could break out of the TypeScript literal", async () => {
    const { mapAdvisory } = await load();
    const hostile = advisory({
      vulnerabilities: [
        {
          package: { ecosystem: "npm", name: 'x", severity: "critical" }, { type: "domain", value: "evil' },
          vulnerable_version_range: ">= 0",
        },
      ],
    });
    const result = mapAdvisory(hostile);
    expect(result.entries).toEqual([]);
    expect(result.skipped[0].reason).toBe("unsafe-package-name");
  });

  it("reports an unmappable range instead of guessing", async () => {
    const { mapAdvisory } = await load();
    const result = mapAdvisory(
      advisory({
        vulnerabilities: [
          {
            package: { ecosystem: "npm", name: "scg-fixture-pkg" },
            vulnerable_version_range: ">= 1.0.0, <= 1.2.0",
          },
        ],
      }),
    );
    expect(result.entries).toEqual([]);
    expect(result.skipped[0].reason).toBe("unmappable-version-range");
  });

  it("emits entries that pass the feed's own validity gate", async () => {
    const { mapAdvisory, publicEntry } = await load();
    const { entries } = mapAdvisory(
      advisory({
        vulnerabilities: [
          { package: { ecosystem: "npm", name: "scg-fixture-pkg" }, vulnerable_version_range: "= 1.0.0" },
          { package: { ecosystem: "pip", name: "scg-fixture-py" }, vulnerable_version_range: ">= 0" },
        ],
      }),
    );
    expect(entries).toHaveLength(2);
    for (const entry of entries) {
      expect(isValidFeedIOC(publicEntry(entry))).toBe(true);
    }
  });
});

describe("mapOsvMalwareRecord", () => {
  it("maps a whole-package MAL record and preserves its original provider", async () => {
    const { mapOsvMalwareRecord, publicEntry } = await load();
    const result = mapOsvMalwareRecord(osvMalwareRecord());
    expect(result.skipped).toEqual([]);
    expect(publicEntry(result.entries[0])).toEqual({
      type: "package",
      value: "scg-fixture-ossf",
      severity: "critical",
      confidence: 0.9,
      source: "MAL-2026-4242 (amazon-inspector)",
      firstSeen: "2026-08-30",
    });
  });

  it("uses explicit versions for a bounded range instead of blocking every version", async () => {
    const { mapOsvMalwareRecord } = await load();
    const result = mapOsvMalwareRecord(
      osvMalwareRecord({
        affected: [
          {
            package: { ecosystem: "PyPI", name: "scg-fixture-python" },
            ranges: [
              {
                type: "ECOSYSTEM",
                events: [{ introduced: "1.0.0" }, { fixed: "1.2.0" }],
              },
            ],
            versions: ["1.0.0", "1.1.0"],
          },
        ],
      }),
    );
    expect(result.entries.map((entry: FeedIOC) => entry.value)).toEqual([
      "pypi:scg-fixture-python@1.0.0",
      "pypi:scg-fixture-python@1.1.0",
    ]);
  });

  it("rejects an unexpanded bounded range instead of broadening it", async () => {
    const { mapOsvMalwareRecord } = await load();
    const result = mapOsvMalwareRecord(
      osvMalwareRecord({
        affected: [
          {
            package: { ecosystem: "npm", name: "scg-fixture-bounded" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
          },
        ],
      }),
    );
    expect(result.entries).toEqual([]);
    expect(result.skipped[0].reason).toBe("unmappable-version-range");
  });

  it("raises confidence when a MAL record has several distinct origins", async () => {
    const { mapOsvMalwareRecord, CONFIDENCE_CORROBORATED } = await load();
    const result = mapOsvMalwareRecord(
      osvMalwareRecord({
        database_specific: {
          "malicious-packages-origins": [
            { source: "amazon-inspector" },
            { source: "checkmarx" },
            { source: "amazon-inspector" },
          ],
        },
      }),
    );
    expect(result.entries[0].confidence).toBe(CONFIDENCE_CORROBORATED);
    expect(result.entries[0].source).toBe("MAL-2026-4242 (amazon-inspector+checkmarx)");
  });

  it("skips withdrawn and non-MAL records", async () => {
    const { mapOsvMalwareRecord } = await load();
    expect(
      mapOsvMalwareRecord(osvMalwareRecord({ withdrawn: "2026-08-31T00:00:00Z" })).skipped[0]
        .reason,
    ).toBe("withdrawn");
    expect(mapOsvMalwareRecord(osvMalwareRecord({ id: "GHSA-aaaa-bbbb-cccc" })).skipped[0].reason).toBe(
      "not-malware-record",
    );
  });
});

describe("coalesceCandidates", () => {
  it("retains GHSA, MAL id and provider provenance for cross-source overlap", async () => {
    const { coalesceCandidates, mapAdvisory, mapOsvMalwareRecord } = await load();
    const github = mapAdvisory(advisory()).entries[0];
    const ossf = mapOsvMalwareRecord(
      osvMalwareRecord({
        affected: [
          {
            package: { ecosystem: "npm", name: "scg-fixture-pkg" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
          },
        ],
        database_specific: {
          "malicious-packages-origins": [{ source: "amazon-inspector" }],
        },
      }),
    ).entries[0];
    const result = coalesceCandidates([github, ossf]);
    expect(result.coalesced).toBe(1);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].source).toBe(
      "GHSA-aaaa-bbbb-cccc, MAL-2026-4242 (amazon-inspector)",
    );
    expect(result.entries[0].confidence).toBe(1);
  });

  it("does not treat a GHSA mirror as independent corroboration", async () => {
    const { coalesceCandidates, mapAdvisory, mapOsvMalwareRecord } = await load();
    const github = mapAdvisory(advisory()).entries[0];
    const ossf = mapOsvMalwareRecord(
      osvMalwareRecord({
        affected: [
          {
            package: { ecosystem: "npm", name: "scg-fixture-pkg" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
          },
        ],
        database_specific: {
          "malicious-packages-origins": [{ source: "ghsa-malware" }],
        },
      }),
    ).entries[0];
    expect(coalesceCandidates([github, ossf]).entries[0].confidence).toBe(0.9);
  });
});

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe("countUndrainable", () => {
  // The advisory database bulk-publishes retrospective malware datasets: on
  // 2026-07-21 it landed 11,512 PyPI advisories in one day, and on 2026-07-27
  // it landed 2,262 npm ones. An explicit --limit may be sized for the historical
  // steady-state flow (median ~35 advisories/day), but a spike can leave a remainder
  // far larger than any future run can take before --days slides past it. Those entries are
  // then lost for good, which is a silent false negative - the exact failure
  // the page-cap guard already treats as fatal.
  const now = new Date("2026-08-02T00:00:00Z");
  const entry = (firstSeen: string) => ({
    type: "package",
    value: `pkg-${firstSeen}-${Math.random()}`,
    severity: "critical",
    confidence: 1,
    firstSeen,
  });

  it("reports nothing undrainable when the remainder fits in the window", async () => {
    const { countUndrainable } = await load();
    // 30 entries, all published today, limit 10 -> reached within 3 runs, and
    // they have the full 14 days of window left.
    const added = Array.from({ length: 30 }, () => entry("2026-08-02"));
    expect(countUndrainable(added, { limit: 10, days: 14, now })).toBe(0);
  });

  it("counts entries whose queue position outlives their window", async () => {
    const { countUndrainable } = await load();
    // 500 entries published 13 days ago: they leave the window tomorrow, but at
    // limit 10 the tail is ~50 runs away. Everything past the first two batches
    // ages out.
    const added = Array.from({ length: 500 }, () => entry("2026-07-20"));
    const undrainable = countUndrainable(added, { limit: 10, days: 14, now });
    expect(undrainable).toBeGreaterThan(0);
    expect(undrainable).toBe(480);
  });

  it("ignores entries taken by the current run", async () => {
    const { countUndrainable } = await load();
    const added = Array.from({ length: 5 }, () => entry("2026-07-19"));
    // All 5 are inside limit=10, so this run takes them; nothing is left behind.
    expect(countUndrainable(added, { limit: 10, days: 14, now })).toBe(0);
  });

  it("skips entries with no firstSeen rather than guessing their age", async () => {
    const { countUndrainable } = await load();
    const added = Array.from({ length: 500 }, () => ({
      type: "package",
      value: `no-date-${Math.random()}`,
      severity: "critical",
      confidence: 1,
    }));
    expect(countUndrainable(added, { limit: 10, days: 14, now })).toBe(0);
  });

  it("uses an OpenSSF modified-index date when an old report becomes newly discoverable", async () => {
    const { countUndrainable } = await load();
    const added = Array.from({ length: 30 }, (_, i) => ({
      type: "package",
      value: `newly-indexed-${i}`,
      severity: "critical",
      confidence: 0.9,
      firstSeen: "2022-01-01",
      _queueDate: "2026-08-02",
    }));
    expect(countUndrainable(added, { limit: 10, days: 14, now })).toBe(0);
  });
});

describe("dedupe", () => {
  const existing: FeedIOC[] = [
    { type: "package", value: "already-there@1.0.0", severity: "critical", confidence: 1 },
    { type: "package", value: "whole-package-bad", severity: "critical", confidence: 1 },
    { type: "package", value: "ruby:gem-bad", severity: "critical", confidence: 1 },
    { type: "domain", value: "c2.example", severity: "critical", confidence: 1 },
  ];

  it("drops an exact duplicate", async () => {
    const { dedupe } = await load();
    const result = dedupe(existing, [
      { type: "package", value: "already-there@1.0.0", severity: "critical", confidence: 0.9 },
    ]);
    expect(result.added).toEqual([]);
    expect(result.duplicates).toBe(1);
  });

  it("drops a version pin already covered by a bare-name IOC", async () => {
    const { dedupe } = await load();
    const result = dedupe(existing, [
      { type: "package", value: "whole-package-bad@9.9.9", severity: "critical", confidence: 0.9 },
      { type: "package", value: "ruby:gem-bad@2.0.0", severity: "critical", confidence: 0.9 },
    ]);
    expect(result.added).toEqual([]);
    expect(result.covered).toBe(2);
  });

  it("does not confuse ecosystems that share a package name", async () => {
    const { dedupe } = await load();
    const result = dedupe(existing, [
      { type: "package", value: "pypi:whole-package-bad@1.0.0", severity: "critical", confidence: 0.9 },
    ]);
    expect(result.added).toHaveLength(1);
    expect(result.covered).toBe(0);
  });

  it("deduplicates within the incoming batch too", async () => {
    const { dedupe } = await load();
    const incoming = [
      { type: "package", value: "brand-new@1.0.0", severity: "critical", confidence: 0.9 },
      { type: "package", value: "brand-new@1.0.0", severity: "critical", confidence: 0.9 },
    ];
    const result = dedupe(existing, incoming);
    expect(result.added).toHaveLength(1);
    expect(result.duplicates).toBe(1);
  });

  it("adds genuinely new indicators", async () => {
    const { dedupe } = await load();
    const result = dedupe(existing, [
      { type: "package", value: "brand-new", severity: "critical", confidence: 0.9 },
    ]);
    expect(result.added).toHaveLength(1);
    expect(result.duplicates).toBe(0);
    expect(result.covered).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Decline list - families a human ruled out, so the importer stops re-proposing
// ---------------------------------------------------------------------------

describe("loadDeclineList", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-decline-"));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const write = (obj: unknown) =>
    fs.writeFileSync(path.join(dir, "threat-feed-declined.json"), JSON.stringify(obj));

  const valid = {
    namePrefix: "@evilscope/nolb-",
    reason: "a".repeat(30),
    coveredBy: "b".repeat(30),
  };

  it("returns an empty list when the file is absent", async () => {
    const { loadDeclineList } = await load();
    expect(loadDeclineList(dir)).toEqual([]);
  });

  it("loads a well-formed entry", async () => {
    const { loadDeclineList } = await load();
    write({ declined: [valid] });
    expect(loadDeclineList(dir)).toHaveLength(1);
  });

  it("throws on malformed JSON rather than failing open", async () => {
    const { loadDeclineList } = await load();
    fs.writeFileSync(path.join(dir, "threat-feed-declined.json"), "{ nope");
    expect(() => loadDeclineList(dir)).toThrow(/not valid JSON/);
  });

  it("throws when the declined key is not an array", async () => {
    const { loadDeclineList } = await load();
    write({ declined: "everything" });
    expect(() => loadDeclineList(dir)).toThrow(/"declined" array/);
  });

  it("rejects a prefix short enough to decline an unbounded set", async () => {
    const { loadDeclineList } = await load();
    write({ declined: [{ ...valid, namePrefix: "a" }] });
    expect(() => loadDeclineList(dir)).toThrow(/at least 6 characters/);
  });

  it("requires both a reason and the coverage that replaces the entries", async () => {
    const { loadDeclineList } = await load();
    write({ declined: [{ namePrefix: "@evilscope/nolb-", coveredBy: "b".repeat(30) }] });
    expect(() => loadDeclineList(dir)).toThrow(/"reason"/);
    write({ declined: [{ namePrefix: "@evilscope/nolb-", reason: "a".repeat(30) }] });
    expect(() => loadDeclineList(dir)).toThrow(/"coveredBy"/);
  });

  it("requires exactly one of namePrefix or ghsa", async () => {
    const { loadDeclineList } = await load();
    write({ declined: [{ ...valid, ghsa: "GHSA-aaaa-bbbb-cccc" }] });
    expect(() => loadDeclineList(dir)).toThrow(/exactly one/);
    write({ declined: [{ reason: "a".repeat(30), coveredBy: "b".repeat(30) }] });
    expect(() => loadDeclineList(dir)).toThrow(/exactly one/);
  });

  it("accepts the decline list this repository actually ships", async () => {
    const { loadDeclineList } = await load();
    const shipped = loadDeclineList();
    expect(shipped.length).toBeGreaterThan(0);
    for (const entry of shipped) {
      expect(entry.reason.length).toBeGreaterThanOrEqual(20);
      expect(entry.coveredBy.length).toBeGreaterThanOrEqual(20);
    }
  });
});

describe("applyDeclineList", () => {
  const rule = (over: Record<string, unknown> = {}) => ({
    namePrefix: "@evilscope/nolb-",
    reason: "a".repeat(30),
    coveredBy: "b".repeat(30),
    ...over,
  });

  it("is a no-op when nothing is declined", async () => {
    const { applyDeclineList } = await load();
    const entries = [{ type: "package", value: "brand-new", severity: "critical", confidence: 1 }];
    expect(applyDeclineList(entries, []).kept).toBe(entries);
  });

  it("drops a declined family and tallies it per rule", async () => {
    const { applyDeclineList } = await load();
    const result = applyDeclineList(
      [
        { type: "package", value: "@evilscope/nolb-aaa", severity: "critical", confidence: 1 },
        { type: "package", value: "@evilscope/nolb-bbb@1.0.0", severity: "critical", confidence: 1 },
        { type: "package", value: "genuinely-new", severity: "critical", confidence: 1 },
      ],
      [rule()],
    );
    expect(result.kept.map((e: FeedIOC) => e.value)).toEqual(["genuinely-new"]);
    expect(result.declined).toBe(2);
    expect(result.byRule).toEqual({ "@evilscope/nolb-": 2 });
  });

  it("anchors the prefix at the start of the name, never mid-string", async () => {
    const { applyDeclineList } = await load();
    const result = applyDeclineList(
      [{ type: "package", value: "not-@evilscope/nolb-aaa", severity: "critical", confidence: 1 }],
      [rule()],
    );
    expect(result.declined).toBe(0);
  });

  it("does not let an npm prefix decline the same name on PyPI", async () => {
    const { applyDeclineList } = await load();
    const result = applyDeclineList(
      [{ type: "package", value: "pypi:@evilscope/nolb-aaa", severity: "critical", confidence: 1 }],
      [rule()],
    );
    expect(result.declined).toBe(0);
  });

  it("declines a PyPI family when the prefix carries the ecosystem", async () => {
    const { applyDeclineList } = await load();
    const result = applyDeclineList(
      [{ type: "package", value: "pypi:evilfarm-aaa@1.0.0", severity: "critical", confidence: 1 }],
      [rule({ namePrefix: "pypi:evilfarm-" })],
    );
    expect(result.declined).toBe(1);
  });

  it("declines by exact advisory id, ignoring the appended MAL- id", async () => {
    const { applyDeclineList } = await load();
    const result = applyDeclineList(
      [
        {
          type: "package",
          value: "some-name",
          severity: "critical",
          confidence: 1,
          source: "GHSA-aaaa-bbbb-cccc, MAL-2026-1",
        },
        {
          type: "package",
          value: "other-name",
          severity: "critical",
          confidence: 1,
          source: "GHSA-dddd-eeee-ffff",
        },
      ],
      [rule({ namePrefix: undefined, ghsa: "GHSA-aaaa-bbbb-cccc" })],
    );
    expect(result.kept.map((e: FeedIOC) => e.value)).toEqual(["other-name"]);
  });

  it("never declines a non-package indicator", async () => {
    const { applyDeclineList } = await load();
    const result = applyDeclineList(
      [{ type: "domain", value: "@evilscope/nolb-aaa", severity: "critical", confidence: 1 }],
      [rule()],
    );
    expect(result.declined).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Fetch layer (bounded, optional token) - injected fetchImpl, no network
// ---------------------------------------------------------------------------

describe("fetchMalwareAdvisories", () => {
  it("follows Link rel=next and stops at the page cap", async () => {
    const { fetchMalwareAdvisories } = await load();
    let calls = 0;
    const fetchImpl = async () => {
      calls++;
      return {
        ok: true,
        status: 200,
        headers: { get: (h: string) => (h === "link" ? '<https://next.example/page>; rel="next"' : null) },
        json: async () => [advisory({ ghsa_id: `GHSA-page-${calls}-cccc` })],
      };
    };
    const result = await fetchMalwareAdvisories({ maxPages: 3, fetchImpl });
    expect(calls).toBe(3);
    expect(result.pages).toBe(3);
    expect(result.truncated).toBe(true);
    expect(result.advisories).toHaveLength(3);
  });

  it("sends no Authorization header when no token is configured", async () => {
    const { fetchMalwareAdvisories } = await load();
    let seen: Record<string, string> = {};
    const fetchImpl = async (_url: string, init: { headers: Record<string, string> }) => {
      seen = init.headers;
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => [] };
    };
    await fetchMalwareAdvisories({ fetchImpl });
    expect(seen.Authorization).toBeUndefined();
    expect(seen.Accept).toBe("application/vnd.github+json");
  });

  it("uses the token when one is supplied (rate limit only, never required)", async () => {
    const { fetchMalwareAdvisories } = await load();
    let seen: Record<string, string> = {};
    const fetchImpl = async (_url: string, init: { headers: Record<string, string> }) => {
      seen = init.headers;
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => [] };
    };
    await fetchMalwareAdvisories({ fetchImpl, token: "t0ken" });
    expect(seen.Authorization).toBe("Bearer t0ken");
  });

  it("passes an abort signal so a hung upstream cannot stall the run", async () => {
    const { fetchMalwareAdvisories } = await load();
    let signal: unknown;
    const fetchImpl = async (_url: string, init: { signal: unknown }) => {
      signal = init.signal;
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => [] };
    };
    await fetchMalwareAdvisories({ fetchImpl, timeoutMs: 1234 });
    expect(signal).toBeInstanceOf(AbortSignal);
  });

  it("rejects on a non-200 and names the rate limit when it is the cause", async () => {
    const { fetchMalwareAdvisories } = await load();
    const fetchImpl = async () => ({
      ok: false,
      status: 403,
      headers: { get: (h: string) => (h === "x-ratelimit-remaining" ? "0" : null) },
      json: async () => ({}),
    });
    await expect(fetchMalwareAdvisories({ fetchImpl })).rejects.toThrow(/HTTP 403.*GITHUB_TOKEN/s);
  });

  it("rejects on a transport error", async () => {
    const { fetchMalwareAdvisories } = await load();
    const fetchImpl = async () => {
      throw new Error("getaddrinfo ENOTFOUND");
    };
    await expect(fetchMalwareAdvisories({ fetchImpl })).rejects.toThrow(/request failed/);
  });

  it("rejects a payload that is not an array of advisories", async () => {
    const { fetchMalwareAdvisories } = await load();
    await expect(
      fetchMalwareAdvisories({ fetchImpl: singlePage({ message: "nope" }) }),
    ).rejects.toThrow(/unexpected payload/);
  });
});

describe("OpenSSF OSV discovery", () => {
  it("parses only MAL ids inside the requested modified-time window", async () => {
    const { parseOsvModifiedIndex } = await load();
    const index = [
      "2026-08-31T12:00:00Z,MAL-2026-3",
      "2026-08-30T12:00:00Z,GHSA-aaaa-bbbb-cccc",
      "2026-08-29T12:00:00Z,MAL-2026-2",
      "2026-08-01T12:00:00Z,MAL-2026-1",
      "",
    ].join("\n");
    expect(parseOsvModifiedIndex(index, { since: "2026-08-29", until: "2026-08-30" })).toEqual([
      { id: "MAL-2026-2", modified: "2026-08-29T12:00:00Z" },
    ]);
  });

  it("rejects malformed selected index data", async () => {
    const { parseOsvModifiedIndex } = await load();
    expect(() => parseOsvModifiedIndex("not-a-csv-line", { since: "2026-08-01" })).toThrow(
      /malformed/,
    );
    expect(() =>
      parseOsvModifiedIndex("2026-08-31T12:00:00Z,MAL-2026-1/../../x", {
        since: "2026-08-01",
      }),
    ).toThrow(/unsafe MAL id/);
  });

  it("fetches per-ecosystem indexes and each discovered record exactly once", async () => {
    const { fetchOsvMalwareRecords } = await load();
    const calls: string[] = [];
    const fetchImpl = async (url: string | URL) => {
      const value = String(url);
      calls.push(value);
      if (value.endsWith("npm/modified_id.csv")) {
        return {
          ok: true,
          status: 200,
          text: async () =>
            "2026-08-30T11:00:00Z,MAL-2026-4242\n2026-08-30T10:00:00Z,GHSA-aaaa-bbbb-cccc\n",
        };
      }
      if (value.endsWith("PyPI/modified_id.csv")) {
        return {
          ok: true,
          status: 200,
          text: async () => "2026-08-30T11:00:00Z,MAL-2026-4242\n2026-08-29T10:00:00Z,MAL-2026-4343\n",
        };
      }
      const id = value.includes("MAL-2026-4242") ? "MAL-2026-4242" : "MAL-2026-4343";
      return { ok: true, status: 200, json: async () => osvMalwareRecord({ id }) };
    };
    const result = await fetchOsvMalwareRecords({
      since: "2026-08-29",
      ecosystems: ["npm", "pip"],
      fetchImpl,
      baseUrl: "https://osv-export.example",
    });
    expect(result.indexes).toBe(2);
    expect(result.modifiedIds).toBe(2);
    expect(result.records.map((record: { id: string }) => record.id)).toEqual([
      "MAL-2026-4242",
      "MAL-2026-4343",
    ]);
    expect(calls.filter((url) => url.includes("MAL-2026-4242"))).toHaveLength(1);
  });

  it("fails closed when any selected record cannot be fetched", async () => {
    const { fetchOsvMalwareRecords } = await load();
    const fetchImpl = async (url: string | URL) => {
      if (String(url).endsWith("modified_id.csv")) {
        return {
          ok: true,
          status: 200,
          text: async () => "2026-08-30T11:00:00Z,MAL-2026-4242\n",
        };
      }
      return { ok: false, status: 503, json: async () => ({}) };
    };
    await expect(
      fetchOsvMalwareRecords({
        since: "2026-08-29",
        ecosystems: ["npm"],
        fetchImpl,
        baseUrl: "https://osv-export.example",
      }),
    ).rejects.toThrow(/HTTP 503/);
  });

  it("rejects an oversized modified index before reading it", async () => {
    const { fetchOsvMalwareRecords, MAX_OSV_INDEX_BYTES } = await load();
    let bodyRead = false;
    const fetchImpl = async () => ({
      ok: true,
      status: 200,
      headers: { get: () => String(MAX_OSV_INDEX_BYTES + 1) },
      text: async () => {
        bodyRead = true;
        return "";
      },
    });
    await expect(
      fetchOsvMalwareRecords({
        since: "2026-08-29",
        ecosystems: ["npm"],
        fetchImpl,
        baseUrl: "https://osv-export.example",
      }),
    ).rejects.toThrow(/exceeds/);
    expect(bodyRead).toBe(false);
  });

  it("registers OpenSSF as a discovery adapter by default", async () => {
    const { createDiscoverySources } = await load();
    const sources = createDiscoverySources({ fetchImpl: singlePage([]) });
    expect(sources.map((source: { id: string }) => source.id)).toEqual([
      "github-advisory-database",
      "openssf-malicious-packages",
    ]);
  });
});

// ---------------------------------------------------------------------------
// OSV corroboration - enrichment, never a gate
// ---------------------------------------------------------------------------

describe("crossReferenceOsv", () => {
  it("records a MAL- id per package and lifts nothing else", async () => {
    const { crossReferenceOsv } = await load();
    const fetchImpl = async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({
        results: [
          { vulns: [{ id: "MAL-2026-11054" }] },
          { vulns: [{ id: "GHSA-not-a-mal-id" }] },
          {},
        ],
      }),
    });
    const result = await crossReferenceOsv(
      [
        { prefix: "", name: "a" },
        { prefix: "pypi:", name: "b" },
        { prefix: "go:", name: "c" },
      ],
      { fetchImpl },
    );
    expect(result.ok).toBe(true);
    expect(result.ids.get("a")).toBe("MAL-2026-11054");
    expect(result.ids.has("pypi:b")).toBe(false);
    expect(result.ids.has("go:c")).toBe(false);
  });

  it("degrades gracefully when OSV is unavailable", async () => {
    const { crossReferenceOsv } = await load();
    const fetchImpl = async () => {
      throw new Error("ECONNRESET");
    };
    const result = await crossReferenceOsv([{ prefix: "", name: "a" }], { fetchImpl });
    expect(result.ok).toBe(false);
    expect(result.error).toContain("ECONNRESET");
    expect(result.ids.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Serialization into the BUNDLED_FEED array literal
// ---------------------------------------------------------------------------

describe("applyEntries", () => {
  const SOURCE = [
    "const BUNDLED_FEED: FeedIOC[] = [",
    '  { type: "domain", value: "existing.example", severity: "critical", confidence: 1.0 },',
    "];",
    "",
    "export const CACHE_DIR = \".scg-cache\";",
    "",
  ].join("\n");

  it("appends inside the array, before the terminator", async () => {
    const { applyEntries } = await load();
    const out = applyEntries(
      SOURCE,
      [
        {
          type: "package",
          value: "scg-fixture-pkg@1.0.0",
          severity: "critical",
          confidence: 0.9,
          source: "GHSA-aaaa-bbbb-cccc",
          firstSeen: "2026-07-24",
        },
      ],
      { date: "2026-07-24" },
    );
    const arrayBody = out.slice(0, out.indexOf("\n];"));
    expect(arrayBody).toContain('value: "scg-fixture-pkg@1.0.0"');
    expect(arrayBody).toContain('source: "GHSA-aaaa-bbbb-cccc"');
    expect(arrayBody).toContain("// Imported from GitHub Advisory Database (2026-07-24)");
    expect(out).toContain('export const CACHE_DIR = ".scg-cache";');
  });

  it("produces a literal that evaluates back to the same entry", async () => {
    const { applyEntries } = await load();
    const { runInNewContext } = await import("node:vm");
    const entry = {
      type: "package",
      value: "pypi:scg-fixture-py",
      severity: "high",
      confidence: 1.0,
      source: "GHSA-aaaa-bbbb-cccc, MAL-2026-11054",
    };
    const out = applyEntries(SOURCE, [entry], { date: "2026-07-24" });
    const marker = "const BUNDLED_FEED: FeedIOC[] = [";
    const body = out.slice(out.indexOf(marker) + marker.length, out.indexOf("\n];"));
    const parsed = runInNewContext(`[${body}\n]`, {}) as FeedIOC[];
    expect(parsed[parsed.length - 1]).toEqual(entry);
  });

  it("preserves CRLF working trees without splitting a CRLF pair", async () => {
    const { applyEntries } = await load();
    const crlf = SOURCE.replace(/\n/g, "\r\n");
    const out = applyEntries(crlf, [
      { type: "package", value: "x", severity: "critical", confidence: 0.9, source: "GHSA-aaaa-bbbb-cccc" },
    ], { date: "2026-07-24" });
    expect(out).toContain('value: "x"');
    // A stray "\r" or a lone "\n" makes git treat the whole file as rewritten,
    // turning a 25-line append into a several-thousand-line diff.
    expect(out.match(/\r\r/g)).toBeNull();
    expect(out.match(/[^\r]\n/g)).toBeNull();
    // Every line ends CRLF and the array still terminates correctly.
    expect(out.split("\r\n").length).toBe(crlf.split("\r\n").length + 3);
    expect(out).toContain("\r\n];");
  });

  it("keeps LF working trees on LF", async () => {
    const { applyEntries } = await load();
    const out = applyEntries(SOURCE, [
      { type: "package", value: "x", severity: "critical", confidence: 0.9, source: "GHSA-aaaa-bbbb-cccc" },
    ], { date: "2026-07-24" });
    expect(out.includes("\r")).toBe(false);
    expect(out).toContain("\n];");
  });

  it("writes confidence in the file's existing 1.0 style", async () => {
    const { formatEntry } = await load();
    expect(formatEntry({ type: "package", value: "x", severity: "critical", confidence: 1.0, source: "GHSA-aaaa-bbbb-cccc" })).toContain(
      "confidence: 1.0",
    );
    expect(formatEntry({ type: "package", value: "x", severity: "critical", confidence: 0.9, source: "GHSA-aaaa-bbbb-cccc" })).toContain(
      "confidence: 0.9",
    );
  });

  it("refuses a source file without the expected array", async () => {
    const { applyEntries } = await load();
    expect(() => applyEntries("const OTHER = [];", [], { date: "2026-07-24" })).toThrow(
      /marker not found/,
    );
  });

  it("advances the bundled-feed timestamp deterministically", async () => {
    const { updateFeedGeneratedAt } = await load();
    const source = 'export const FEED_GENERATED_AT = "2026-08-23T00:00:00.000Z";\n';
    expect(updateFeedGeneratedAt(source, "2026-08-31")).toBe(
      'export const FEED_GENERATED_AT = "2026-08-31T00:00:00.000Z";\n',
    );
    expect(() => updateFeedGeneratedAt("", "2026-08-31")).toThrow(/marker not found/);
  });
});

// ---------------------------------------------------------------------------
// Chunk rollover
//
// The feed is stored as capacity-bounded FEED_CHUNK_n consts spread into
// BUNDLED_FEED, because one array literal that large trips TS2590 in tsc.
// Appending forever into a single array would walk straight back into that
// ceiling, so the importer rolls over. These pin that behaviour: the daily
// import is the thing that would otherwise re-create the problem.
// ---------------------------------------------------------------------------

describe("applyEntries chunk rollover", () => {
  const entryLine = (v: string) =>
    `  { type: "package", value: ${JSON.stringify(v)}, severity: "high", confidence: 0.9 },`;

  /** Build a chunked threat-intel.ts source with the given chunk contents. */
  const chunkedSource = (chunks: string[][]) => {
    const parts: string[] = [];
    chunks.forEach((values, i) => {
      parts.push(`const FEED_CHUNK_${i}: FeedIOC[] = [`);
      values.forEach((v) => parts.push(entryLine(v)));
      parts.push("];", "");
    });
    parts.push("const BUNDLED_FEED: FeedIOC[] = [");
    chunks.forEach((_, i) => parts.push(`  ...FEED_CHUNK_${i},`));
    parts.push("];", "");
    return parts.join("\n");
  };

  const mk = (v: string) => ({
    type: "package",
    value: v,
    severity: "high",
    confidence: 0.9,
    source: "GHSA-test",
  });

  const counts = async (source: string) => {
    const { findFeedChunks } = await load();
    return findFeedChunks(source).map((c: { count: number }) => c.count);
  };

  it("appends into the last chunk while it has room", async () => {
    const { applyEntries } = await load();
    const source = chunkedSource([["a", "b"]]);
    const out = applyEntries(source, [mk("c")], { date: "2026-07-28", capacity: 3 });
    expect(await counts(out)).toEqual([3]);
    expect(out).not.toContain("FEED_CHUNK_1");
  });

  it("opens a new chunk when the last one is full and registers it in the spread", async () => {
    const { applyEntries } = await load();
    const source = chunkedSource([["a", "b", "c"]]);
    const out = applyEntries(source, [mk("d"), mk("e")], { date: "2026-07-28", capacity: 3 });
    expect(await counts(out)).toEqual([3, 2]);
    // Declared AND spread - a chunk missing from the spread ships a short feed.
    expect(out).toContain("const FEED_CHUNK_1: FeedIOC[] = [");
    expect(out).toContain("  ...FEED_CHUNK_1,");
    // The new chunk is declared before the array that spreads it.
    expect(out.indexOf("const FEED_CHUNK_1: FeedIOC[] = [")).toBeLessThan(
      out.indexOf("const BUNDLED_FEED: FeedIOC[] = ["),
    );
  });

  it("splits an oversized batch across chunks, none above capacity", async () => {
    const { applyEntries } = await load();
    const source = chunkedSource([["a", "b"]]);
    const batch = ["c", "d", "e", "f", "g"].map(mk);
    const out = applyEntries(source, batch, { date: "2026-07-28", capacity: 2 });
    const sizes = await counts(out);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(2);
    expect(sizes.reduce((a: number, b: number) => a + b, 0)).toBe(7);
    for (let i = 0; i < sizes.length; i++) expect(out).toContain(`  ...FEED_CHUNK_${i},`);
  });

  it("never drops entries when rolling over", async () => {
    const { applyEntries } = await load();
    const source = chunkedSource([["a", "b", "c"]]);
    const batch = ["d", "e", "f", "g"].map(mk);
    const out = applyEntries(source, batch, { date: "2026-07-28", capacity: 3 });
    for (const v of ["a", "b", "c", "d", "e", "f", "g"]) {
      expect(out).toContain(`value: ${JSON.stringify(v)}`);
    }
    const sizes = await counts(out);
    expect(sizes.reduce((a: number, b: number) => a + b, 0)).toBe(7);
  });

  it("still appends into BUNDLED_FEED when the source has no chunks", async () => {
    const { applyEntries } = await load();
    const source = ["const BUNDLED_FEED: FeedIOC[] = [", entryLine("a"), "];", ""].join("\n");
    const out = applyEntries(source, [mk("b")], { date: "2026-07-28", capacity: 3 });
    expect(out).toContain('value: "b"');
    expect(out).not.toContain("FEED_CHUNK_");
  });
});

// ---------------------------------------------------------------------------
// Failure mode - the feed must survive a broken upstream untouched
// ---------------------------------------------------------------------------

describe("importUpstreamFeed failure mode", () => {
  let tmpRoot: string;
  let threatIntelPath: string;
  let feedPath: string;

  const FAKE_THREAT_INTEL = [
    "export interface FeedIOC { type: string }",
    'export const FEED_GENERATED_AT = "2026-08-23T00:00:00.000Z";',
    "const BUNDLED_FEED: FeedIOC[] = [",
    '  { type: "domain", value: "existing.example", severity: "critical", confidence: 1.0 },',
    "];",
    "",
  ].join("\n");

  beforeEach(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "scg-import-"));
    fs.mkdirSync(path.join(tmpRoot, "src"));
    threatIntelPath = path.join(tmpRoot, "src", "threat-intel.ts");
    feedPath = path.join(tmpRoot, "feed.json");
    fs.writeFileSync(threatIntelPath, FAKE_THREAT_INTEL);
    fs.writeFileSync(path.join(tmpRoot, "package.json"), JSON.stringify({ version: "9.9.9" }));
    fs.writeFileSync(feedPath, '{"schema":1,"entries":[{"type":"domain","value":"existing.example"}]}\n');
  });

  afterEach(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("leaves both files byte-identical and rejects when the upstream fetch fails", async () => {
    const { importUpstreamFeed } = await load();
    const before = {
      ts: fs.readFileSync(threatIntelPath),
      feed: fs.readFileSync(feedPath),
    };
    const fetchImpl = async () => {
      throw new Error("getaddrinfo ENOTFOUND api.github.com");
    };

    await expect(importUpstreamFeed({ root: tmpRoot, useOssf: false, fetchImpl })).rejects.toThrow(
      /GitHub Advisory Database request failed/,
    );

    expect(fs.readFileSync(threatIntelPath).equals(before.ts)).toBe(true);
    expect(fs.readFileSync(feedPath).equals(before.feed)).toBe(true);
  });

  it("leaves both files untouched on an HTTP error", async () => {
    const { importUpstreamFeed } = await load();
    const before = fs.readFileSync(threatIntelPath);
    const fetchImpl = async () => ({
      ok: false,
      status: 503,
      headers: { get: () => null },
      json: async () => ({}),
    });
    await expect(importUpstreamFeed({ root: tmpRoot, useOssf: false, fetchImpl })).rejects.toThrow(
      /HTTP 503/,
    );
    expect(fs.readFileSync(threatIntelPath).equals(before)).toBe(true);
  });

  it("writes nothing in --dry-run but still reports what it would add", async () => {
    const { importUpstreamFeed } = await load();
    const before = fs.readFileSync(threatIntelPath);
    const report = await importUpstreamFeed({
      root: tmpRoot,
      dryRun: true,
      useOsv: false,
      fetchImpl: singlePage([advisory()]),
    });
    expect(report.added).toBe(1);
    expect(report.written).toBe(false);
    expect(report.entries[0].value).toBe("scg-fixture-pkg");
    expect(fs.readFileSync(threatIntelPath).equals(before)).toBe(true);
  });

  it("writes nothing when everything upstream is already covered", async () => {
    const { importUpstreamFeed } = await load();
    fs.writeFileSync(
      threatIntelPath,
      FAKE_THREAT_INTEL.replace(
        "];",
        '  { type: "package", value: "scg-fixture-pkg", severity: "critical", confidence: 1.0 },\n];',
      ),
    );
    const before = fs.readFileSync(threatIntelPath);
    const report = await importUpstreamFeed({
      root: tmpRoot,
      useOsv: false,
      fetchImpl: singlePage([advisory()]),
    });
    expect(report.added).toBe(0);
    expect(report.duplicates).toBe(1);
    expect(report.written).toBe(false);
    expect(fs.readFileSync(threatIntelPath).equals(before)).toBe(true);
  });

  it("applies new entries and regenerates feed.json from the updated source", async () => {
    const { importUpstreamFeed } = await load();
    const report = await importUpstreamFeed({
      root: tmpRoot,
      useOsv: false,
      fetchImpl: singlePage([
        advisory({
          ghsa_id: "GHSA-1111-2222-3333",
          vulnerabilities: [
            { package: { ecosystem: "pip", name: "scg-fixture-py" }, vulnerable_version_range: "= 2.0.0" },
          ],
        }),
      ]),
    });
    expect(report.written).toBe(true);
    expect(report.added).toBe(1);

    const source = fs.readFileSync(threatIntelPath, "utf8");
    expect(source).toContain('value: "pypi:scg-fixture-py@2.0.0"');
    expect(source).toContain('source: "GHSA-1111-2222-3333"');

    const feed = JSON.parse(fs.readFileSync(feedPath, "utf8"));
    expect(feed.schema).toBe(1);
    expect(feed.entryCount).toBe(2);
    expect(feed.entries[1].value).toBe("pypi:scg-fixture-py@2.0.0");
    // Provenance survives into the published artifact.
    expect(feed.entries[1].source).toBe("GHSA-1111-2222-3333");
  });

  it("discovers OpenSSF MAL records independently and does not self-corroborate them", async () => {
    const { importUpstreamFeed, CONFIDENCE_SINGLE_SOURCE } = await load();
    let queryBatchCalls = 0;
    const fetchImpl = async (url: string | URL) => {
      const value = String(url);
      if (value.includes("api.github.com")) {
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => [] };
      }
      if (value.endsWith("modified_id.csv")) {
        return {
          ok: true,
          status: 200,
          text: async () => "2026-08-30T11:00:00Z,MAL-2026-4242\n",
        };
      }
      if (value.includes("MAL-2026-4242.json")) {
        return { ok: true, status: 200, json: async () => osvMalwareRecord() };
      }
      if (value.includes("api.osv.dev")) {
        queryBatchCalls++;
        return { ok: true, status: 200, json: async () => ({ results: [] }) };
      }
      throw new Error(`unexpected test URL: ${value}`);
    };

    const report = await importUpstreamFeed({
      root: tmpRoot,
      ecosystems: ["npm"],
      now: new Date("2026-08-31T00:00:00Z"),
      fetchImpl,
    });

    expect(report.written).toBe(true);
    expect(report.added).toBe(1);
    expect(report.ossfRecordsFetched).toBe(1);
    expect(report.discoverySources["openssf-malicious-packages"].mapped).toBe(1);
    expect(report.additionsByDiscovery).toEqual({
      githubOnly: 0,
      openssfOnly: 1,
      githubAndOpenssf: 0,
    });
    expect(report.entries[0].source).toBe("MAL-2026-4242 (amazon-inspector)");
    expect(report.entries[0].confidence).toBe(CONFIDENCE_SINGLE_SOURCE);
    expect(queryBatchCalls).toBe(0);
  });

  it("writes nothing when OpenSSF discovery is incomplete", async () => {
    const { importUpstreamFeed } = await load();
    const before = {
      ts: fs.readFileSync(threatIntelPath),
      feed: fs.readFileSync(feedPath),
    };
    const fetchImpl = async (url: string | URL) => {
      const value = String(url);
      if (value.includes("api.github.com")) {
        return {
          ok: true,
          status: 200,
          headers: { get: () => null },
          json: async () => [advisory()],
        };
      }
      if (value.endsWith("modified_id.csv")) {
        return {
          ok: true,
          status: 200,
          text: async () => "2026-08-30T11:00:00Z,MAL-2026-4242\n",
        };
      }
      return { ok: false, status: 503, json: async () => ({}) };
    };

    await expect(
      importUpstreamFeed({
        root: tmpRoot,
        ecosystems: ["npm"],
        useOsv: false,
        fetchImpl,
      }),
    ).rejects.toThrow(/OpenSSF\/OSV export returned HTTP 503/);
    expect(fs.readFileSync(threatIntelPath).equals(before.ts)).toBe(true);
    expect(fs.readFileSync(feedPath).equals(before.feed)).toBe(true);
  });

  it("still imports (at single-source confidence) when OSV is down", async () => {
    const { importUpstreamFeed, CONFIDENCE_SINGLE_SOURCE } = await load();
    const fetchImpl = async (url: string) => {
      if (String(url).includes("modified_id.csv")) {
        return { ok: true, status: 200, text: async () => "" };
      }
      if (String(url).includes("osv.dev")) throw new Error("ECONNRESET");
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        json: async () => [advisory()],
      };
    };
    const report = await importUpstreamFeed({ root: tmpRoot, fetchImpl });
    expect(report.osvAvailable).toBe(false);
    expect(report.written).toBe(true);
    expect(report.entries[0].confidence).toBe(CONFIDENCE_SINGLE_SOURCE);
  });

  it("raises confidence to 1.0 when OSV corroborates the package", async () => {
    const { importUpstreamFeed, CONFIDENCE_CORROBORATED } = await load();
    const fetchImpl = async (url: string) => {
      if (String(url).includes("modified_id.csv")) {
        return { ok: true, status: 200, text: async () => "" };
      }
      if (String(url).includes("osv.dev")) {
        return {
          ok: true,
          status: 200,
          headers: { get: () => null },
          json: async () => ({ results: [{ vulns: [{ id: "MAL-2026-11054" }] }] }),
        };
      }
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => [advisory()] };
    };
    const report = await importUpstreamFeed({ root: tmpRoot, fetchImpl });
    expect(report.entries[0].confidence).toBe(CONFIDENCE_CORROBORATED);
    expect(report.entries[0].source).toBe("GHSA-aaaa-bbbb-cccc, MAL-2026-11054");
    expect(report.corroboratedByOsv).toBe(1);
  });

  it("imports every entry by default instead of leaving a hidden daily backlog", async () => {
    const { importUpstreamFeed } = await load();
    const many = Array.from({ length: 5 }, (_, i) =>
      advisory({
        ghsa_id: `GHSA-all${i}-bbbb-cccc`,
        vulnerabilities: [
          { package: { ecosystem: "npm", name: `scg-fixture-all-${i}` }, vulnerable_version_range: ">= 0" },
        ],
      }),
    );
    const report = await importUpstreamFeed({
      root: tmpRoot,
      useOsv: false,
      fetchImpl: singlePage(many),
    });
    expect(report.added).toBe(5);
    expect(report.entries).toHaveLength(5);
    expect(report.capped).toBe(false);
    expect(report.limitApplied).toBeNull();
    expect(report.remaining).toBe(0);
    expect(report.undrainable).toBe(0);
  });

  it("caps how many entries a single run may add when --limit is explicit", async () => {
    const { importUpstreamFeed } = await load();
    const many = Array.from({ length: 5 }, (_, i) =>
      advisory({
        ghsa_id: `GHSA-cap${i}-bbbb-cccc`,
        vulnerabilities: [
          { package: { ecosystem: "npm", name: `scg-fixture-cap-${i}` }, vulnerable_version_range: ">= 0" },
        ],
      }),
    );
    const report = await importUpstreamFeed({
      root: tmpRoot,
      limit: 2,
      useOsv: false,
      fetchImpl: singlePage(many),
    });
    expect(report.added).toBe(2);
    expect(report.capped).toBe(true);
    expect(report.limitApplied).toBe(2);
    // The 3 left behind are recoverable by a later run, unlike a page-cap loss.
    expect(report.remaining).toBe(3);
  });

  it("rejects an invalid programmatic limit before fetching or writing", async () => {
    const { importUpstreamFeed } = await load();
    let fetched = false;
    const fetchImpl = async () => {
      fetched = true;
      return singlePage([])();
    };
    await expect(
      importUpstreamFeed({ root: tmpRoot, limit: 0, useOsv: false, fetchImpl }),
    ).rejects.toThrow(/--limit expects a positive integer/);
    expect(fetched).toBe(false);
  });

  // A page cap is NOT a resumable backlog. The query is published/desc, so the
  // unfetched remainder is the OLDEST part of the window and the next run re-fetches
  // the same newest pages - the remainder ages out of --days permanently. Silently
  // importing a partial window is a false negative in a security scanner, so it
  // must be fatal. Regression guard for the 2026-07-26 run, where the cap dropped
  // 94% of the window and the report called it "page cap reached" and exited 0.
  it("refuses to import a truncated window and writes nothing", async () => {
    const { importUpstreamFeed } = await load();
    const before = fs.readFileSync(path.join(tmpRoot, "src", "threat-intel.ts"), "utf8");
    let calls = 0;
    const alwaysMorePages = async () => {
      calls++;
      return {
        ok: true,
        status: 200,
        headers: { get: (h: string) => (h === "link" ? '<https://next.example/page>; rel="next"' : null) },
        json: async () => [
          advisory({
            ghsa_id: `GHSA-trunc${calls}-bbbb-cccc`,
            vulnerabilities: [
              { package: { ecosystem: "npm", name: `scg-fixture-trunc-${calls}` }, vulnerable_version_range: ">= 0" },
            ],
          }),
        ],
      };
    };
    await expect(
      importUpstreamFeed({
        root: tmpRoot,
        maxPages: 2,
        useOsv: false,
        useOssf: false,
        fetchImpl: alwaysMorePages,
      }),
    ).rejects.toThrow(/page cap reached/);
    // Inert failure: the source file is byte-identical.
    expect(fs.readFileSync(path.join(tmpRoot, "src", "threat-intel.ts"), "utf8")).toBe(before);
  });

  it("imports a truncated window only when --allow-truncated is passed", async () => {
    const { importUpstreamFeed } = await load();
    let calls = 0;
    const alwaysMorePages = async () => {
      calls++;
      return {
        ok: true,
        status: 200,
        headers: { get: (h: string) => (h === "link" ? '<https://next.example/page>; rel="next"' : null) },
        json: async () => [
          advisory({
            ghsa_id: `GHSA-allow${calls}-bbbb-cccc`,
            vulnerabilities: [
              { package: { ecosystem: "npm", name: `scg-fixture-allow-${calls}` }, vulnerable_version_range: ">= 0" },
            ],
          }),
        ],
      };
    };
    const report = await importUpstreamFeed({
      root: tmpRoot,
      maxPages: 2,
      allowTruncated: true,
      useOsv: false,
      useOssf: false,
      fetchImpl: alwaysMorePages,
    });
    expect(report.truncated).toBe(true);
    expect(report.added).toBe(2);
  });

  it("derives a 14-day window when days is not passed", async () => {
    const { importUpstreamFeed } = await load();
    const report = await importUpstreamFeed({
      root: tmpRoot,
      useOsv: false,
      dryRun: true,
      now: new Date("2026-07-26T12:00:00Z"),
      fetchImpl: singlePage([]),
    });
    expect(report.since).toBe("2026-07-12");
  });

  // Fails BEFORE spending any of the 60-request anonymous budget, so the operator
  // gets an actionable message instead of an opaque 403 mid-pagination.
  it("refuses a default-sized real-network run with no token", async () => {
    const { importUpstreamFeed } = await load();
    const noToken = { ...process.env };
    delete noToken.GITHUB_TOKEN;
    delete noToken.GH_TOKEN;
    const saved = { GITHUB_TOKEN: process.env.GITHUB_TOKEN, GH_TOKEN: process.env.GH_TOKEN };
    delete process.env.GITHUB_TOKEN;
    delete process.env.GH_TOKEN;
    try {
      await expect(
        // fetchImpl omitted on purpose: the guard is scoped to the real network path.
        // maxPages omitted too: the guard fires for any default above the anonymous
        // budget, so the test tracks the shipped default instead of restating it.
        importUpstreamFeed({ root: tmpRoot, useOsv: false }),
      ).rejects.toThrow(/no GITHUB_TOKEN/);
    } finally {
      if (saved.GITHUB_TOKEN !== undefined) process.env.GITHUB_TOKEN = saved.GITHUB_TOKEN;
      if (saved.GH_TOKEN !== undefined) process.env.GH_TOKEN = saved.GH_TOKEN;
    }
  });
});

// ---------------------------------------------------------------------------
// Ecosystem filter
//
// A bulk-publication spike is routinely mixed: 2026-07-20/21 carried 104 live
// npm advisories alongside ~11,800 PyPI/NuGet ones that no longer resolve on
// their registries. Taking only the live half was a real need twice, and with
// no flag for it the only way through was a hand-rolled fetch proxy that
// stripped vulnerabilities before mapping - an unreviewed script standing in
// for a tool. These tests pin the supported way to do it.
// ---------------------------------------------------------------------------

describe("ecosystem filter", () => {
  const mixed = {
    ghsa_id: "GHSA-eeee-ffff-0000",
    type: "malware",
    severity: "critical",
    published_at: "2026-07-21T09:00:00Z",
    withdrawn_at: null,
    vulnerabilities: [
      { package: { ecosystem: "npm", name: "scg-fixture-live" }, vulnerable_version_range: ">= 0" },
      { package: { ecosystem: "pip", name: "scg-fixture-dead" }, vulnerable_version_range: ">= 0" },
      { package: { ecosystem: "nuget", name: "Scg.Fixture.Dead" }, vulnerable_version_range: ">= 0" },
    ],
  };

  it("maps only the selected ecosystem", async () => {
    const { mapAdvisory } = await load();
    const { entries } = mapAdvisory(mixed, { ecosystems: ["npm"] });
    expect(entries.map((e: FeedIOC) => e.value)).toEqual(["scg-fixture-live"]);
  });

  it("records what the filter excluded rather than dropping it silently", async () => {
    const { mapAdvisory } = await load();
    const { skipped } = mapAdvisory(mixed, { ecosystems: ["npm"] });
    expect(skipped.map((s: { reason: string }) => s.reason)).toEqual([
      "ecosystem-filtered",
      "ecosystem-filtered",
    ]);
  });

  it("selects several ecosystems at once", async () => {
    const { mapAdvisory } = await load();
    const { entries } = mapAdvisory(mixed, { ecosystems: ["npm", "nuget"] });
    expect(entries.map((e: FeedIOC) => e.value)).toEqual([
      "scg-fixture-live",
      "nuget:Scg.Fixture.Dead",
    ]);
  });

  it("maps every supported ecosystem when no filter is given", async () => {
    const { mapAdvisory } = await load();
    const { entries } = mapAdvisory(mixed);
    expect(entries).toHaveLength(3);
  });

  it("imports only the selected ecosystem end to end", async () => {
    const { importUpstreamFeed } = await load();
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "scg-eco-"));
    try {
      fs.mkdirSync(path.join(tmpRoot, "src"));
      fs.writeFileSync(
        path.join(tmpRoot, "src", "threat-intel.ts"),
        [
          "export interface FeedIOC { type: string }",
          'export const FEED_GENERATED_AT = "2026-08-23T00:00:00.000Z";',
          "const BUNDLED_FEED: FeedIOC[] = [",
          '  { type: "domain", value: "existing.example", severity: "critical", confidence: 1.0 },',
          "];",
          "",
        ].join("\n"),
      );
      fs.writeFileSync(path.join(tmpRoot, "package.json"), JSON.stringify({ version: "9.9.9" }));
      fs.writeFileSync(
        path.join(tmpRoot, "feed.json"),
        '{"schema":1,"entries":[{"type":"domain","value":"existing.example"}]}\n',
      );

      const report = await importUpstreamFeed({
        root: tmpRoot,
        useOsv: false,
        ecosystems: ["npm"],
        fetchImpl: singlePage([mixed]),
      });

      expect(report.added).toBe(1);
      expect(report.entries[0].value).toBe("scg-fixture-live");
      expect(report.ecosystems).toEqual(["npm"]);
      const source = fs.readFileSync(path.join(tmpRoot, "src", "threat-intel.ts"), "utf8");
      expect(source).not.toContain("scg-fixture-dead");
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it("parses --ecosystem as a comma-separated list", async () => {
    const { parseArgs } = await load();
    expect(parseArgs(["--ecosystem", "npm,pip"]).ecosystems).toEqual(["npm", "pip"]);
  });

  it("accumulates a repeated --ecosystem flag", async () => {
    const { parseArgs } = await load();
    expect(parseArgs(["--ecosystem", "npm", "--ecosystem", "nuget"]).ecosystems).toEqual([
      "npm",
      "nuget",
    ]);
  });

  // A typo here would silently import nothing, which in a threat-feed importer
  // is the same silent false negative the page-cap guard is fatal about.
  it("rejects an unknown ecosystem instead of importing nothing", async () => {
    const { parseArgs } = await load();
    expect(() => parseArgs(["--ecosystem", "npmm"])).toThrow(/unknown ecosystem/);
  });

  it("names the valid ecosystems in the rejection", async () => {
    const { parseArgs } = await load();
    expect(() => parseArgs(["--ecosystem", "maven"])).toThrow(/nuget/);
  });
});

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

describe("parseArgs", () => {
  it("parses the documented options", async () => {
    const { parseArgs } = await load();
    expect(parseArgs(["--days", "30", "--limit", "10", "--dry-run", "--no-osv", "--json"])).toEqual({
      days: 30,
      limit: 10,
      dryRun: true,
      useOsv: false,
      useOssf: true,
      json: true,
    });
  });

  it("rejects an unknown option instead of ignoring it", async () => {
    const { parseArgs } = await load();
    expect(() => parseArgs(["--wat"])).toThrow(/unknown option/);
  });

  // --allow-truncated is the only documented recovery path from the fatal page-cap
  // error, so a flag that parsed but never reached importUpstreamFeed would be a
  // silent no-op that only surfaced during an incident.
  it("parses --allow-truncated and --max-pages", async () => {
    const { parseArgs } = await load();
    expect(parseArgs(["--allow-truncated", "--max-pages", "7"])).toEqual({
      allowTruncated: true,
      maxPages: 7,
      dryRun: false,
      useOsv: true,
      useOssf: true,
      json: false,
    });
  });

  it("allows OpenSSF discovery to be disabled explicitly for outage diagnosis", async () => {
    const { parseArgs } = await load();
    expect(parseArgs(["--no-ossf"]).useOssf).toBe(false);
  });

  // The default window width is the whole point of the 5.19.0 change: it sets how
  // much of a missed run is still recoverable, so it is asserted, not commented.
  it("looks back 14 days by default", async () => {
    const { sinceDate } = await load();
    expect(sinceDate(14, new Date("2026-07-26T12:00:00Z"))).toBe("2026-07-12");
  });
});
