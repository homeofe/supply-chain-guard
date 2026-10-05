/**
 * The OpenSSF records the importer used to skip (2026-10-05: 1,077 of them).
 *
 *   - names outside the ASCII charset: NuGet homoglyph typosquats, npm names
 *     squatting CLI flags (`--no-audit`) and legacy scopes (`@_x/...`)
 *   - npm records with a bounded range and no `versions` list, settled against
 *     the registry's version history into exact pins
 *   - the residue no mapping can take, which a human records in
 *     threat-feed-unresolvable.json so the completeness check stays red only
 *     for NEW gaps
 *
 * Offline: the registry is an injected fetchImpl. Package names are synthetic
 * except where a test documents a real record's shape.
 */

import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const IMPORT_SCRIPT_URL = new URL("../../scripts/import-threat-feed.mjs", import.meta.url).href;
const load = () => import(/* @vite-ignore */ IMPORT_SCRIPT_URL);

/** A publish time before every fixture record. */
const D = "2026-05-01T00:00:00Z";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

describe("isSafePackageName per ecosystem", () => {
  it("accepts a Unicode NuGet id only for NuGet", async () => {
    const { isSafePackageName } = await load();
    expect(isSafePackageName("Gunа.Forms.Net", "nuget")).toBe(true);
    expect(isSafePackageName("Solnеt.Wаllet឵", "nuget")).toBe(true);
    expect(isSafePackageName("Gunа.Forms.Net", "npm")).toBe(false);
    expect(isSafePackageName("Gunа.Forms.Net")).toBe(false);
  });

  it("accepts an npm name squatting a CLI flag, and a legacy scope, only for npm", async () => {
    const { isSafePackageName } = await load();
    expect(isSafePackageName("--no-audit", "npm")).toBe(true);
    expect(isSafePackageName("@_wnpm/wnpm-cli", "npm")).toBe(true);
    expect(isSafePackageName("@mipta19/-gfs", "npm")).toBe(true);
    expect(isSafePackageName("--no-audit", "pip")).toBe(false);
  });

  it.each([
    ["a quote", 'evil"pkg'],
    ["a backslash", "evil\\pkg"],
    ["whitespace", "evil pkg"],
    ["a bidi override", "evil‮pkg"],
    ["a zero-width joiner", "ev‍il"],
  ])("still refuses %s in a NuGet id", async (_label, name) => {
    const { isSafePackageName } = await load();
    expect(isSafePackageName(name, "nuget")).toBe(false);
  });
});

describe("semver and OSV range evaluation", () => {
  it("orders releases, prereleases and numeric identifiers like semver", async () => {
    const { parseSemver, compareSemver } = await load();
    const order = ["0.0.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0", "1.0.1", "1.10.0"];
    for (let i = 1; i < order.length; i++) {
      expect(compareSemver(parseSemver(order[i - 1]), parseSemver(order[i]))).toBeLessThan(0);
    }
    expect(parseSemver("not-a-version")).toBeNull();
  });

  it("evaluates introduced/fixed, last_affected and open-ended ranges", async () => {
    const { osvRangesAffect } = await load();
    const fixed = [{ type: "SEMVER", events: [{ introduced: "1.95.6" }, { fixed: "1.95.8" }] }];
    expect(osvRangesAffect("1.95.5", fixed)).toBe(false);
    expect(osvRangesAffect("1.95.6", fixed)).toBe(true);
    expect(osvRangesAffect("1.95.7", fixed)).toBe(true);
    expect(osvRangesAffect("1.95.8", fixed)).toBe(false);
    const last = [{ type: "SEMVER", events: [{ introduced: "1.1.5" }, { last_affected: "1.1.7" }] }];
    expect(osvRangesAffect("1.1.7", last)).toBe(true);
    expect(osvRangesAffect("1.1.8", last)).toBe(false);
    const open = [{ type: "SEMVER", events: [{ introduced: "99.0.0" }] }];
    expect(osvRangesAffect("98.9.9", open)).toBe(false);
    expect(osvRangesAffect("1337.0.0", open)).toBe(true);
  });

  it("names only the explicitly affected versions when no registry is left", async () => {
    const { explicitRangeVersions } = await load();
    expect(explicitRangeVersions([{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.0" }] }])).toEqual([]);
    expect(
      explicitRangeVersions([{ type: "SEMVER", events: [{ introduced: "1.1.8" }, { last_affected: "1.1.9" }] }]),
    ).toEqual(["1.1.8", "1.1.9"]);
  });
});

describe("resolveBoundedNpmRanges", () => {
  const pending = (name: string, events: Array<Record<string, string>>) => ({
    id: "MAL-2026-1",
    name,
    ranges: [{ type: "SEMVER", events }],
    firstSeen: "2026-06-01",
    source: "MAL-2026-1 (kam193)",
    confidence: 0.9,
    origins: ["kam193"],
    assessedAt: "2026-06-01T00:00:00Z",
  });

  const registry = (docs: Record<string, unknown>, calls: string[] = []) => async (url: string | URL) => {
    calls.push(String(url));
    const name = decodeURIComponent(String(url).split("/").pop() ?? "");
    if (name === "boom") return { ok: false, status: 503, json: async () => ({}) };
    if (!(name in docs)) return { ok: false, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => docs[name] };
  };

  it("pins every published version in range, including unpublished ones, and never a bare name", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const calls: string[] = [];
    const result = await resolveBoundedNpmRanges([pending("@scg/hijacked", [{ introduced: "2.0.1" }, { fixed: "2.0.3" }])], {
      fetchImpl: registry(
        {
          "@scg/hijacked": {
            time: { created: "x", modified: "x", unpublished: {}, "2.0.0": D, "2.0.1": D, "2.0.2": D, "2.0.3": D },
          },
        },
        calls,
      ),
    });
    expect(result.entries.map((e: { value: string }) => e.value)).toEqual(["@scg/hijacked@2.0.1", "@scg/hijacked@2.0.2"]);
    expect(result.entries.every((e: { value: string }) => e.value.includes("@2.0."))).toBe(true);
    expect(result.unresolved).toEqual([]);
    expect(calls[0]).toMatch(/\/@scg%2Fhijacked$/);
  });

  // A name can never add a path segment to the registry request.
  it("percent-encodes every slash in the name", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const calls: string[] = [];
    await resolveBoundedNpmRanges([pending("a/b/c", [{ introduced: "0" }, { fixed: "1.0.0" }])], {
      fetchImpl: registry({}, calls),
    });
    expect(calls[0]).toBe("https://registry.npmjs.org/a%2Fb%2Fc");
  });

  it("pins only the explicit versions of a package the registry deleted", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const result = await resolveBoundedNpmRanges(
      [pending("scg-deleted", [{ introduced: "1.1.8" }, { last_affected: "1.1.9" }])],
      { fetchImpl: registry({}) },
    );
    expect(result.entries.map((e: { value: string }) => e.value)).toEqual(["scg-deleted@1.1.8", "scg-deleted@1.1.9"]);
  });

  it("leaves a deleted package with no explicit version unresolved, naming why", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const result = await resolveBoundedNpmRanges([pending("scg-gone", [{ introduced: "0" }, { fixed: "1.2.0" }])], {
      fetchImpl: registry({}),
    });
    expect(result.entries).toEqual([]);
    expect(result.unresolved).toEqual([
      { reason: "unmappable-version-range", detail: "MAL-2026-1 npm/scg-gone (not on the registry)" },
    ]);
  });

  // flipper-frontend-core (GHSA-qmrm-wwg3-xhpg): an attacker published 1.0.0
  // and 1.1.0, the advisory said "<= 1.1.0", and the rightful owner then
  // published 0.1.0 and up. Those later versions were never assessed.
  it("pins no version published after the record, even inside the range", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const result = await resolveBoundedNpmRanges(
      [{ ...pending("scg-reclaimed", [{ introduced: "0" }, { last_affected: "1.1.0" }]), assessedAt: "2022-05-31T12:58:09Z" }],
      {
        fetchImpl: registry({
          "scg-reclaimed": {
            time: {
              created: "x",
              "1.0.0": "2022-05-26T10:00:00Z",
              "1.1.0": "2022-05-26T11:00:00Z",
              "0.0.1-security": "2022-05-31T13:00:00Z",
              "0.1.0": "2022-10-15T00:00:00Z",
              "0.212.0": "2023-08-19T00:00:00Z",
            },
          },
        }),
      },
    );
    expect(result.entries.map((e: { value: string }) => e.value).sort()).toEqual(["scg-reclaimed@1.0.0", "scg-reclaimed@1.1.0"]);
  });

  it("pins nothing from the registry when the record has no publication date", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const { assessedAt, ...undated } = pending("scg-undated", [{ introduced: "1.0.0" }]);
    const result = await resolveBoundedNpmRanges([undated], {
      fetchImpl: registry({ "scg-undated": { time: { "1.0.0": D } } }),
    });
    expect(result.entries).toEqual([]);
    expect(result.unresolved[0].detail).toMatch(/published before the record/);
  });

  // An outage must not turn known malware into a skip count.
  it("rejects on any registry failure other than 404", async () => {
    const { resolveBoundedNpmRanges } = await load();
    await expect(
      resolveBoundedNpmRanges([pending("boom", [{ introduced: "1.0.0" }])], { fetchImpl: registry({}) }),
    ).rejects.toThrow(/HTTP 503/);
  });
});

describe("threat-feed-unresolvable.json", () => {
  const root = (content?: unknown) => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "scg-unres-"));
    dirs.push(d);
    if (content !== undefined) {
      fs.writeFileSync(path.join(d, "threat-feed-unresolvable.json"), JSON.stringify(content));
    }
    return d;
  };
  const reason = "Dependency-confusion record on a deleted package, no exact version known.";

  it("is empty when absent and loads a valid list", async () => {
    const { loadUnresolvableList } = await load();
    expect(loadUnresolvableList(root())).toEqual([]);
    expect(loadUnresolvableList(root({ records: [{ id: "MAL-2022-455", reason }] }))).toHaveLength(1);
  });

  it.each([
    ["no records array", {}],
    ["an unknown key", { records: [{ id: "MAL-1", reason, coveredBy: "x" }] }],
    ["a short reason", { records: [{ id: "MAL-1", reason: "deleted" }] }],
    ["a repeated id", { records: [{ id: "MAL-1", reason }, { id: "MAL-1", reason }] }],
    ["an unsafe id", { records: [{ id: "MAL 1", reason }] }],
  ])("throws on %s instead of failing open", async (_label, content) => {
    const { loadUnresolvableList } = await load();
    expect(() => loadUnresolvableList(root(content))).toThrow();
  });

  it("the committed list loads, and every entry names an npm dependency-confusion record", async () => {
    const { loadUnresolvableList } = await load();
    const repo = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..", "..");
    const list = loadUnresolvableList(repo);
    expect(list.length).toBeGreaterThan(0);
    for (const record of list) expect(record.id).toMatch(/^MAL-\d{4}-\d+$/);
  });
});

describe("checkFailed counts unmapped records", () => {
  it("is red for an unmapped record and green once every gap is recorded", async () => {
    const { checkFailed } = await load();
    expect(checkFailed({ overdue: 0, deferred: 0, unmapped: 1 })).toBe(true);
    expect(checkFailed({ overdue: 0, deferred: 0, unmapped: 0, acknowledgedUnresolvable: 21 })).toBe(false);
  });

  it("only gap reasons count: withdrawn or out-of-scope records do not", async () => {
    const { GAP_SKIP_REASONS } = await load();
    expect([...GAP_SKIP_REASONS].sort()).toEqual(
      ["no-affected-package", "unmappable-version-range", "unsafe-package-name", "unsafe-version"].sort(),
    );
    expect(GAP_SKIP_REASONS.has("withdrawn")).toBe(false);
  });
});

describe("GitHub bounded ranges (vulnerable_version_range strings)", () => {
  it("translates exactly the shapes malware advisories use", async () => {
    const { githubRangeToOsvEvents } = await load();
    expect(githubRangeToOsvEvents(">= 3.6.0")).toEqual([{ introduced: "3.6.0" }]);
    expect(githubRangeToOsvEvents(">= 1.0.0, <= 1.1.9")).toEqual([{ introduced: "1.0.0" }, { last_affected: "1.1.9" }]);
    expect(githubRangeToOsvEvents(">= 1.0.0, < 1.2.0")).toEqual([{ introduced: "1.0.0" }, { fixed: "1.2.0" }]);
    expect(githubRangeToOsvEvents("< 2.0.0")).toEqual([{ introduced: "0" }, { fixed: "2.0.0" }]);
    expect(githubRangeToOsvEvents("<= 2.0.0")).toEqual([{ introduced: "0" }, { last_affected: "2.0.0" }]);
  });

  // An exclusive lower bound, a second bound of one kind or an unknown
  // operator has no exact OSV form here, so it is not approximated.
  it.each(["> 1.0.0", ">= 1.0.0, >= 2.0.0", "< 1.0.0, <= 2.0.0", "!= 1.0.0", "", "1.0.0"])(
    "refuses %j",
    async (range) => {
      const { githubRangeToOsvEvents } = await load();
      expect(githubRangeToOsvEvents(range)).toBeNull();
    },
  );

  it("mapAdvisory hands an npm bounded range to the registry resolver, a PyPI one not", async () => {
    const { mapAdvisory } = await load();
    const advisory = (ecosystem: string, range: string) => ({
      ghsa_id: "GHSA-aaaa-bbbb-cccc",
      type: "malware",
      severity: "critical",
      published_at: "2026-07-01T00:00:00Z",
      vulnerabilities: [{ package: { ecosystem, name: "scg-range-pkg" }, vulnerable_version_range: range }],
    });
    const npm = mapAdvisory(advisory("npm", ">= 99.99.2"));
    expect(npm.entries).toEqual([]);
    expect(npm.skipped[0].resolve).toEqual(
      expect.objectContaining({
        name: "scg-range-pkg",
        ranges: [{ type: "SEMVER", events: [{ introduced: "99.99.2" }] }],
        discoverySource: "github-advisory-database",
        source: "GHSA-aaaa-bbbb-cccc",
      }),
    );
    // Outside npm: no registry resolution, only the explicitly named version.
    const pip = mapAdvisory(advisory("pip", ">= 1.0.0"));
    expect(pip.skipped.some((x: { resolve?: unknown }) => x.resolve)).toBe(false);
    expect(pip.entries.map((e: { value: string }) => e.value)).toEqual(["pypi:scg-range-pkg@1.0.0"]);
  });

  // num2words (PyPI): no registry resolution outside npm, but the range names
  // both affected versions in its own words.
  it("pins the versions a non-npm range names explicitly, and nothing else", async () => {
    const { mapAdvisory } = await load();
    const advisory = (range: string) => ({
      ghsa_id: "GHSA-aaaa-bbbb-cccc",
      type: "malware",
      severity: "critical",
      published_at: "2025-07-28T00:00:00Z",
      vulnerabilities: [{ package: { ecosystem: "pip", name: "scg-py" }, vulnerable_version_range: range }],
    });
    expect(mapAdvisory(advisory(">= 0.5.15, <= 0.5.16")).entries.map((e: { value: string }) => e.value)).toEqual([
      "pypi:scg-py@0.5.15",
      "pypi:scg-py@0.5.16",
    ]);
    // `< 1.0.0` names no version: still unmappable, never a guess.
    const open = mapAdvisory(advisory("< 1.0.0"));
    expect(open.entries).toEqual([]);
    expect(open.skipped[0].reason).toBe("unmappable-version-range");
  });

  it("resolves a GitHub range into pins that keep GitHub as their source", async () => {
    const { resolveBoundedNpmRanges, mapAdvisory } = await load();
    const { skipped } = mapAdvisory({
      ghsa_id: "GHSA-aaaa-bbbb-cccc",
      type: "malware",
      severity: "critical",
      published_at: "2026-07-01T00:00:00Z",
      vulnerabilities: [{ package: { ecosystem: "npm", name: "scg-range-pkg" }, vulnerable_version_range: ">= 1.0.0, <= 1.0.1" }],
    });
    const result = await resolveBoundedNpmRanges([skipped[0].resolve], {
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ time: { created: "x", "0.9.0": D, "1.0.0": D, "1.0.1": D, "1.0.2": D } }),
      }),
    });
    expect(result.entries.map((e: { value: string }) => e.value)).toEqual(["scg-range-pkg@1.0.0", "scg-range-pkg@1.0.1"]);
    expect(result.entries[0]._discoverySource).toBe("github-advisory-database");
    expect(result.entries[0].source).toBe("GHSA-aaaa-bbbb-cccc");
    expect(result.entries[0].firstSeen).toBe("2026-07-01");
  });
});
