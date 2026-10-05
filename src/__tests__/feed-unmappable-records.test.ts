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
            time: { created: "x", modified: "x", unpublished: {}, "2.0.0": "x", "2.0.1": "x", "2.0.2": "x", "2.0.3": "x" },
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
