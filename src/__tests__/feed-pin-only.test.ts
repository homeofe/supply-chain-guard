/**
 * Pin-only scopes (threat-feed-pin-only.json): dependency-confusion targets.
 *
 * In such a scope the malicious versions are the attacker's and the NAME is
 * the victim's own internal package, so a whole-package verdict must settle
 * into exact pins and never become a bare name. A bare name would flag every
 * developer at the victim organization who installs the real package from
 * its private registry.
 *
 * Offline: the registry is an injected fetchImpl. Package names are synthetic
 * except in the committed-store invariant at the end.
 */

import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const IMPORT_SCRIPT_URL = new URL("../../scripts/import-threat-feed.mjs", import.meta.url).href;
const CATALOG_STORE_URL = new URL("../../scripts/catalog-store.mjs", import.meta.url).href;
const load = () => import(/* @vite-ignore */ IMPORT_SCRIPT_URL);
const REPO_ROOT = path.resolve(__dirname, "../..");

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function withPinOnlyFile(content: unknown): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pin-only-"));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, "threat-feed-pin-only.json"), typeof content === "string" ? content : JSON.stringify(content));
  return dir;
}

const SCOPE = { scope: "@victim-corp/", reason: "Dependency-confusion squats of an internal scope.", addedOn: "2026-10-09" };

describe("loadPinOnlyList", () => {
  it("returns [] when the file is absent", async () => {
    const { loadPinOnlyList } = await load();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pin-only-"));
    dirs.push(dir);
    expect(loadPinOnlyList(dir)).toEqual([]);
  });

  it("loads a valid list", async () => {
    const { loadPinOnlyList } = await load();
    expect(loadPinOnlyList(withPinOnlyFile({ scopes: [SCOPE] }))).toEqual([SCOPE]);
  });

  it.each([
    ["a scope without its slash", { ...SCOPE, scope: "@victim-corp" }],
    ["an unscoped prefix", { ...SCOPE, scope: "victim-" }],
    ["an uppercase scope", { ...SCOPE, scope: "@Victim/" }],
    ["a scope with a package part", { ...SCOPE, scope: "@victim-corp/core" }],
    ["a short reason", { ...SCOPE, reason: "squat" }],
    ["a rolled-over date", { ...SCOPE, addedOn: "2026-02-31" }],
    ["an unknown key", { ...SCOPE, coveredBy: "x" }],
  ])("throws on %s", async (_label, item) => {
    const { loadPinOnlyList } = await load();
    expect(() => loadPinOnlyList(withPinOnlyFile({ scopes: [item] }))).toThrow(/threat-feed-pin-only\.json/);
  });

  it("accepts an exact package name, and requires exactly one of scope or name", async () => {
    const { loadPinOnlyList } = await load();
    const named = { name: "hijacked-sdk", reason: SCOPE.reason, addedOn: SCOPE.addedOn };
    expect(loadPinOnlyList(withPinOnlyFile({ scopes: [named] }))).toEqual([named]);
    expect(() => loadPinOnlyList(withPinOnlyFile({ scopes: [{ ...named, scope: "@x/" }] }))).toThrow(/exactly one/);
    expect(() => loadPinOnlyList(withPinOnlyFile({ scopes: [{ reason: SCOPE.reason, addedOn: SCOPE.addedOn }] }))).toThrow(
      /exactly one/,
    );
    expect(() => loadPinOnlyList(withPinOnlyFile({ scopes: [{ ...named, name: "Hijacked SDK" }] }))).toThrow(/"name"/);
  });

  it("throws on a repeated scope and on malformed JSON", async () => {
    const { loadPinOnlyList } = await load();
    expect(() => loadPinOnlyList(withPinOnlyFile({ scopes: [SCOPE, SCOPE] }))).toThrow(/repeats/);
    expect(() => loadPinOnlyList(withPinOnlyFile("{"))).toThrow(/not valid JSON/);
  });
});

describe("applyPinOnlyList", () => {
  const osvRecord = {
    id: "MAL-2026-90001",
    published: "2026-10-08T12:00:00Z",
    affected: [
      {
        package: { ecosystem: "npm", name: "@victim-corp/core" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
        versions: ["999.0.3", "999.0.5"],
      },
    ],
  };

  it("takes a whole-package verdict in a listed scope out of the bare-name path", async () => {
    const { mapOsvMalwareRecord, applyPinOnlyList } = await load();
    const { entries } = mapOsvMalwareRecord(osvRecord);
    expect(entries.map((e: { value: string }) => e.value)).toEqual(["@victim-corp/core"]);

    const { kept, pending } = applyPinOnlyList(entries, [SCOPE]);
    expect(kept).toEqual([]);
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({
      id: "MAL-2026-90001",
      name: "@victim-corp/core",
      listedVersions: ["999.0.3", "999.0.5"],
      assessedAt: "2026-10-08T12:00:00Z",
      pinOnly: true,
    });
  });

  it("carries a GitHub advisory's assessment time", async () => {
    const { mapAdvisory, applyPinOnlyList } = await load();
    const { entries } = mapAdvisory({
      ghsa_id: "GHSA-aaaa-bbbb-cccc",
      type: "malware",
      severity: "critical",
      published_at: "2026-10-08T13:00:00Z",
      vulnerabilities: [{ package: { ecosystem: "npm", name: "@victim-corp/core" }, vulnerable_version_range: ">= 0" }],
    });
    const { pending } = applyPinOnlyList(entries, [SCOPE]);
    expect(pending[0]).toMatchObject({ id: "GHSA-aaaa-bbbb-cccc", assessedAt: "2026-10-08T13:00:00Z", listedVersions: [] });
  });

  it("leaves pins, other scopes, other ecosystems and DataDog claims alone", async () => {
    const { applyPinOnlyList } = await load();
    const entries = [
      { type: "package", value: "@victim-corp/core@999.0.3", _ecosystemPrefix: "", _name: "@victim-corp/core" },
      { type: "package", value: "@other/core", _ecosystemPrefix: "", _name: "@other/core" },
      { type: "package", value: "pypi:@victim-corp/core", _ecosystemPrefix: "pypi:", _name: "@victim-corp/core" },
      { type: "package", value: "@victim-corp/x", _ecosystemPrefix: "", _name: "@victim-corp/x", _wholePackageClaim: true },
    ];
    const { kept, pending } = applyPinOnlyList(entries, [SCOPE]);
    expect(kept).toEqual(entries);
    expect(pending).toEqual([]);
  });

  it("is a no-op without a list", async () => {
    const { applyPinOnlyList } = await load();
    const entries = [{ type: "package", value: "@victim-corp/core", _ecosystemPrefix: "", _name: "@victim-corp/core" }];
    expect(applyPinOnlyList(entries, [])).toEqual({ kept: entries, pending: [] });
  });
});

describe("resolveBoundedNpmRanges on a pin-only item", () => {
  const D = "2026-10-08T10:00:00Z";
  const LATER = "2026-10-09T10:00:00Z";
  const item = (over: Record<string, unknown> = {}) => ({
    id: "MAL-2026-90001",
    name: "@victim-corp/core",
    ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
    listedVersions: ["999.0.3"],
    firstSeen: "2026-10-08",
    source: "MAL-2026-90001 (amazon-inspector)",
    confidence: 0.9,
    origins: [],
    assessedAt: "2026-10-08T12:00:00Z",
    pinOnly: true,
    ...over,
  });
  const registry = (docs: Record<string, unknown>) => async (url: string | URL) => {
    const name = decodeURIComponent(String(url).split("/").pop() ?? "");
    if (!(name in docs)) return { ok: false, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => docs[name] };
  };

  it("pins the listed versions when the registry has deleted the package", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const result = await resolveBoundedNpmRanges([item()], { fetchImpl: registry({}) });
    expect(result.entries.map((e: { value: string }) => e.value)).toEqual(["@victim-corp/core@999.0.3"]);
    expect(result.unresolved).toEqual([]);
  });

  it("adds registry versions published before the record, never later ones or npm placeholders", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const result = await resolveBoundedNpmRanges([item()], {
      fetchImpl: registry({
        "@victim-corp/core": {
          time: { created: D, modified: LATER, "0.0.0-stage": D, "999.0.3": D, "999.0.4": D, "1.0.0": LATER, "0.0.1-security": D },
        },
      }),
    });
    expect(result.entries.map((e: { value: string }) => e.value).sort()).toEqual([
      "@victim-corp/core@999.0.3",
      "@victim-corp/core@999.0.4",
    ]);
  });

  it("never yields a bare name, and reports an OpenSSF record without any version as a gap", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const result = await resolveBoundedNpmRanges([item({ listedVersions: [] })], {
      fetchImpl: registry({ "@victim-corp/core": { time: { created: D, "0.0.0-stage": D } } }),
    });
    expect(result.entries).toEqual([]);
    expect(result.unresolved).toEqual([expect.objectContaining({ reason: "unmappable-version-range" })]);
  });

  // A hijacked legitimate package: every older release is the rightful owner's.
  it("pins only the listed versions for an exact-name entry, never registry history", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const result = await resolveBoundedNpmRanges([item({ name: "hijacked-sdk", listedVersions: ["0.5.144"], listedOnly: true })], {
      fetchImpl: registry({ "hijacked-sdk": { time: { created: D, "0.5.142": D, "0.5.143": D, "0.5.144": D } } }),
    });
    expect(result.entries.map((e: { value: string }) => e.value)).toEqual(["hijacked-sdk@0.5.144"]);
  });

  it("routes an exact-name entry as listed-only, and a scope entry as listed plus registry", async () => {
    const { applyPinOnlyList } = await load();
    const list = [SCOPE, { name: "hijacked-sdk", reason: SCOPE.reason, addedOn: SCOPE.addedOn }];
    const bare = (name: string) => ({ type: "package", value: name, _ecosystemPrefix: "", _name: name, source: "MAL-1" });
    const { pending } = applyPinOnlyList([bare("hijacked-sdk"), bare("@victim-corp/core"), bare("hijacked-sdk-extra")], list);
    expect(pending.map((p: { name: string; listedOnly: boolean }) => [p.name, p.listedOnly])).toEqual([
      ["hijacked-sdk", true],
      ["@victim-corp/core", false],
    ]);
  });

  it("reports a GitHub advisory without any version as pin-only-no-version, not as a gap", async () => {
    const { resolveBoundedNpmRanges, DISCOVERY_SOURCE } = await load();
    const result = await resolveBoundedNpmRanges([item({ listedVersions: [], discoverySource: DISCOVERY_SOURCE.GITHUB })], {
      fetchImpl: registry({}),
    });
    expect(result.entries).toEqual([]);
    expect(result.unresolved).toEqual([expect.objectContaining({ reason: "pin-only-no-version" })]);
  });

  it("ignores listedVersions on an ordinary bounded-range item", async () => {
    const { resolveBoundedNpmRanges } = await load();
    const result = await resolveBoundedNpmRanges([item({ pinOnly: undefined, listedVersions: ["999.0.3"] })], {
      fetchImpl: registry({}),
    });
    expect(result.entries).toEqual([]);
  });
});

describe("the committed stores", () => {
  // The contract the list exists for: no bare name in a pin-only scope, in
  // either store. A hand-added entry or an importer regression lands here.
  it("hold no bare name in a pin-only scope", async () => {
    const { loadPinOnlyList, isPinOnlyName } = await load();
    const { readCatalogLines } = await import(/* @vite-ignore */ CATALOG_STORE_URL);
    const pinOnly = loadPinOnlyList(REPO_ROOT);
    expect(pinOnly.length, "threat-feed-pin-only.json must list the known scopes").toBeGreaterThan(0);

    const bundleText = fs.readFileSync(path.join(REPO_ROOT, "src/threat-intel.ts"), "utf8");
    const values = [
      ...[...bundleText.matchAll(/value: "([^"]+)"/g)].map((m) => m[1]),
      ...readCatalogLines(REPO_ROOT).map((line: string) => JSON.parse(line).value as string),
    ];
    const inScope = values.filter((v) => isPinOnlyName(v, pinOnly));
    // Control: the scopes are populated with pins, so the filter is live.
    expect(inScope.length).toBeGreaterThan(0);
    const bare = inScope.filter((v) => !/^@[^/]+\/[^@]+@.+$/.test(v));
    expect(bare).toEqual([]);
  });
});
