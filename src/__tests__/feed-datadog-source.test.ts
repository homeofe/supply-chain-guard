/**
 * The DataDog malicious-software-packages-dataset as a third discovery source.
 *
 * On 2026-10-05 it named 3,667 npm and 462 PyPI packages that were in neither
 * store, after the full OpenSSF and GitHub reconciles. Its manifests carry no
 * dates and claim most packages whole, so the claims are the risky part: a
 * whole-package claim becomes a bare name only when the registry confirms the
 * package is gone, and pins on every published version when it is live.
 *
 * Offline: every network answer is an injected fetchImpl.
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

const json = (body: unknown, status = 200) => ({
  ok: status === 200,
  status,
  headers: { get: () => null },
  json: async () => body,
  text: async () => JSON.stringify(body),
});

/** Route by URL: DataDog manifests and tree, npm and PyPI registries. */
function network(routes: Record<string, unknown>, calls: string[] = []) {
  return async (url: string | URL) => {
    const u = String(url);
    calls.push(u);
    for (const [needle, body] of Object.entries(routes)) {
      if (u.includes(needle)) return body === 404 ? json({}, 404) : body === 503 ? json({}, 503) : json(body);
    }
    return json({}, 404);
  };
}

describe("parseDatadogSampleDates", () => {
  it("takes the earliest sample date per package, scoped names stored with @", async () => {
    const { parseDatadogSampleDates } = await load();
    const dates = parseDatadogSampleDates([
      "samples/npm/malicious_intent/evil-pkg/1.0.1/2025-03-02-evil-pkg-v1.0.1.zip",
      "samples/npm/malicious_intent/evil-pkg/1.0.0/2025-03-01-evil-pkg-v1.0.0.zip",
      "samples/npm/compromised_lib/@scope@lib/2.0.0/2026-01-05-@scope_lib-v2.0.0.zip",
      "samples/pypi/malicious_intent/badpy/0.1/2024-07-07-badpy-v0.1.zip",
      "README.md",
    ]);
    expect(dates.get("npm:evil-pkg")).toBe("2025-03-01");
    expect(dates.get("npm:@scope@lib")).toBe("2026-01-05");
    expect(dates.get("pypi:badpy")).toBe("2024-07-07");
  });
});

describe("mapDatadogDataset", () => {
  const now = new Date("2026-10-05T08:00:00Z");

  it("maps a versions list to pins and a null to a whole-package claim", async () => {
    const { mapDatadogDataset } = await load();
    const { entries } = mapDatadogDataset(
      {
        manifests: { npm: { "scg-dd-whole": null, "scg-dd-hijacked": ["1.2.3"] }, pypi: { "scg-dd-py": null } },
        dates: new Map([["npm:scg-dd-whole", "2025-01-02"]]),
        sampleVersions: new Map([["npm:scg-dd-hijacked", new Set(["1.2.3"])]]),
        manifestDates: { npm: "2026-10-02" },
      },
      { now },
    );
    const byValue = Object.fromEntries(entries.map((e: { value: string }) => [e.value, e]));
    expect(byValue["scg-dd-whole"]._wholePackageClaim).toBe(true);
    expect(byValue["scg-dd-whole"].firstSeen).toBe("2025-01-02");
    expect(byValue["scg-dd-whole"]._queueDate).toBe("2026-10-02");
    expect(byValue["scg-dd-hijacked@1.2.3"]._wholePackageClaim).toBeUndefined();
    // Undated: the day this run first saw it.
    expect(byValue["pypi:scg-dd-py"].firstSeen).toBe("2026-10-05");
    expect(byValue["pypi:scg-dd-py"]._queueDate).toBeUndefined();
    for (const e of entries) expect(e.source).toBe("datadog-malicious-packages");
  });

  // The lightning shape (2026-10-05): the npm manifest listed versions whose
  // only samples were under pypi/. npm's lightning is unrelated and legitimate.
  it("imports a listed version only with a sample in the same ecosystem", async () => {
    const { mapDatadogDataset } = await load();
    const { entries, withoutSample } = mapDatadogDataset(
      {
        manifests: { npm: { "scg-light": ["2.6.2", "2.6.3"] }, pypi: { "scg-light": ["2.6.2", "2.6.3"] } },
        dates: new Map(),
        sampleVersions: new Map([["pypi:scg-light", new Set(["2.6.2", "2.6.3"])]]),
      },
      { now },
    );
    expect(entries.map((e: { value: string }) => e.value).sort()).toEqual(["pypi:scg-light@2.6.2", "pypi:scg-light@2.6.3"]);
    expect(withoutSample).toEqual(["scg-light@2.6.2,2.6.3"]);
  });

  it("skips an unsafe name and an empty versions list instead of guessing", async () => {
    const { mapDatadogDataset } = await load();
    const { entries, skipped } = mapDatadogDataset(
      { manifests: { npm: { 'evil"pkg': null, "scg-empty": [] } }, dates: new Map() },
      { now },
    );
    expect(entries).toEqual([]);
    expect(skipped.map((s: { reason: string }) => s.reason).sort()).toEqual(["unmappable-version-range", "unsafe-package-name"]);
  });
});

describe("settleDatadogWholePackages", () => {
  const claim = (name: string, prefix = "") => ({
    type: "package",
    value: `${prefix}${name}`,
    severity: "critical",
    confidence: 0.9,
    source: "datadog-malicious-packages",
    firstSeen: "2025-01-01",
    _ecosystemPrefix: prefix,
    _name: name,
    _discoverySource: "datadog-malicious-software-packages",
    _wholePackageClaim: true,
  });

  it("blocks the name of a package the registry removed (404, holding package, all unpublished)", async () => {
    const { settleDatadogWholePackages } = await load();
    const fetchImpl = network({
      "/scg-gone": 404,
      "/scg-held": { description: "security holding package", versions: { "0.0.1-security": {} }, time: { "0.0.1-security": "x", "1.0.0": "x" } },
      "/scg-unpub": { time: { created: "x", unpublished: {}, "1.0.0": "x" } },
      "pypi.org/pypi/scg-pygone": 404,
    });
    const result = await settleDatadogWholePackages(
      [claim("scg-gone"), claim("scg-held"), claim("scg-unpub"), claim("scg-pygone", "pypi:")],
      { fetchImpl },
    );
    expect(result.entries.map((e: { value: string }) => e.value).sort()).toEqual(
      ["pypi:scg-pygone", "scg-gone", "scg-held", "scg-unpub"],
    );
    expect(result.bare).toBe(4);
    expect(result.entries.every((e: Record<string, unknown>) => e._wholePackageClaim === undefined)).toBe(true);
  });

  // A live package must never become a name block: a later legitimate owner
  // of the name would be flagged on every release.
  // The @toptal/picasso shape (2026-10-05): a hijacked LEGITIMATE package the
  // dataset marks whole. Pinning every published version flagged all 1,927
  // releases; only the sampled, trojanized ones may be pinned.
  it("pins only the sampled versions of a live package, never every release and never its name", async () => {
    const { settleDatadogWholePackages } = await load();
    const time = { created: "x", modified: "x", "53.0.0": "x", "54.0.3": "x", "54.0.4": "x", "54.0.5": "x", "55.0.0": "x" };
    const fetchImpl = network({
      "/@scg%2Fpicasso": { versions: Object.fromEntries(Object.keys(time).slice(2).map((v) => [v, {}])), time },
      "pypi.org/pypi/scg-pylive": { releases: { "0.1": [], "0.2": [], "1.1.99": [] } },
    });
    const result = await settleDatadogWholePackages(
      [
        { ...claim("@scg/picasso"), _sampledVersions: ["54.0.4", "54.0.5"] },
        { ...claim("scg-pylive", "pypi:"), _sampledVersions: ["1.1.99"] },
      ],
      { fetchImpl },
    );
    expect(result.entries.map((e: { value: string }) => e.value).sort()).toEqual([
      "@scg/picasso@54.0.4",
      "@scg/picasso@54.0.5",
      "pypi:scg-pylive@1.1.99",
    ]);
    expect(result.entries.some((e: { value: string }) => !e.value.includes("@", 1))).toBe(false);
  });

  // No sample, no evidence for any version: not imported, but named.
  it("imports nothing for a live package without a sample and reports it", async () => {
    const { settleDatadogWholePackages } = await load();
    const fetchImpl = network({
      "/@scg%2Fcli": { versions: { "1.0.0": {} }, time: { "1.0.0": "x" } },
    });
    const result = await settleDatadogWholePackages([{ ...claim("@scg/cli"), _sampledVersions: [] }], { fetchImpl });
    expect(result.entries).toEqual([]);
    expect(result.liveWithoutSamples).toEqual(["@scg/cli"]);
  });

  it("leaves entries without a claim untouched and asks no registry for them", async () => {
    const { settleDatadogWholePackages } = await load();
    const calls: string[] = [];
    const pin = { ...claim("scg-pin"), value: "scg-pin@1.0.0" };
    delete (pin as Record<string, unknown>)._wholePackageClaim;
    const result = await settleDatadogWholePackages([pin], { fetchImpl: network({}, calls) });
    expect(result.entries).toEqual([pin]);
    expect(calls).toEqual([]);
  });

  // Each holding signal on its own: a fixture carrying both would let either
  // check be deleted unnoticed.
  it.each([
    ["the holding description alone", { description: "security holding package", versions: { "0.0.1": {} }, time: { "0.0.1": "x" } }],
    ["a -security placeholder version alone", { description: "", versions: { "0.0.1-security": {} }, time: { "0.0.1-security": "x" } }],
  ])("treats %s as removed", async (_label, doc) => {
    const { settleDatadogWholePackages } = await load();
    const result = await settleDatadogWholePackages([claim("scg-held-one")], { fetchImpl: network({ "/scg-held-one": doc }) });
    expect(result.entries.map((e: { value: string }) => e.value)).toEqual(["scg-held-one"]);
  });

  // The @postman-cse shape: another source pins the name by version, which is
  // how a dependency-confusion name is recorded. Never a bare name then.
  it("adds only sampled versions for a removed package another source pins by version", async () => {
    const { settleDatadogWholePackages } = await load();
    const result = await settleDatadogWholePackages(
      [{ ...claim("@scg/okta-aio"), _sampledVersions: ["0.11.6"] }],
      { fetchImpl: network({ "/@scg%2Fokta-aio": 404 }), versionScoped: new Set(["@scg/okta-aio"]) },
    );
    expect(result.entries.map((e: { value: string }) => e.value)).toEqual(["@scg/okta-aio@0.11.6"]);
    expect(result.bare).toBe(0);
  });

  it("rejects the run on a registry outage instead of dropping the claim", async () => {
    const { settleDatadogWholePackages } = await load();
    await expect(
      settleDatadogWholePackages([claim("scg-x")], { fetchImpl: network({ "/scg-x": 503 }) }),
    ).rejects.toThrow(/HTTP 503/);
  });
});

describe("the DataDog source in a full run", () => {
  const repo = () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-dd-"));
    dirs.push(root);
    fs.mkdirSync(path.join(root, "src"));
    fs.mkdirSync(path.join(root, "data", "threat-catalog"), { recursive: true });
    fs.writeFileSync(
      path.join(root, "src", "threat-intel.ts"),
      'export interface FeedIOC { type: string }\nconst BUNDLED_FEED: FeedIOC[] = [\n  { type: "domain", value: "existing.example", severity: "critical", confidence: 1.0 },\n];\n',
    );
    // Already known: a pin of scg-live, which the live-package settlement re-creates.
    fs.writeFileSync(
      path.join(root, "data", "threat-catalog", "part-000.jsonl"),
      '{"type":"package","value":"scg-live@1.0.0","severity":"critical","confidence":0.9,"source":"MAL-2025-1","firstSeen":"2025-01-01"}\n',
    );
    fs.writeFileSync(
      path.join(root, "feed-partition.config.json"),
      JSON.stringify({ bundleCutoffDate: "2026-09-04", maxBundledEntries: 15000, maxBundleBytes: 2097152 }),
    );
    return root;
  };

  it("adds only what is new, after settling and deduplicating again", async () => {
    const { importUpstreamFeed } = await load();
    const fetchImpl = network({
      // First: the commits URL also contains the manifest path.
      "/commits?path=": [{ commit: { committer: { date: "2026-10-02T00:00:00Z" } } }],
      "samples/npm/manifest.json": { "scg-gone": null, "scg-live": null },
      "samples/pypi/manifest.json": {},
      "samples/ide_extensions/manifest.json": {},
      // Walked per category, as the real tree API is truncated on one call.
      "git/trees/main": { tree: [{ path: "samples", type: "tree", sha: "sha-samples" }] },
      "git/trees/sha-samples": { tree: [{ path: "npm", type: "tree", sha: "sha-npm" }] },
      "git/trees/sha-npm": { tree: [{ path: "malicious_intent", type: "tree", sha: "sha-mal" }] },
      "git/trees/sha-mal": {
        tree: [
          { path: "scg-gone/1.0.0/2025-05-05-scg-gone-v1.0.0.zip", type: "blob" },
          { path: "scg-live/1.1.0/2025-06-01-scg-live-v1.1.0.zip", type: "blob" },
        ],
      },
      "/scg-gone": 404,
      "/scg-live": { versions: { "1.0.0": {}, "1.1.0": {} }, time: { "1.0.0": "x", "1.1.0": "x" } },
      "osv-vulnerabilities": 404,
    });
    const report = await importUpstreamFeed({
      root: repo(),
      useDatadog: true,
      useOssf: false,
      dryRun: true,
      since: "2026-10-01",
      maxPages: 1,
      fetchImpl: async (url: string | URL) =>
        String(url).includes("api.github.com/advisories") ? json([]) : fetchImpl(url),
      now: new Date("2026-10-05T08:00:00Z"),
    });
    expect(report.entries.map((e: { value: string }) => e.value).sort()).toEqual(["scg-gone", "scg-live@1.1.0"]);
    expect(report.datadog).toEqual(
      expect.objectContaining({ wholePackageClaimsProbed: 2, settledAsBareName: 1, settledAsPins: 1 }),
    );
    expect(report.additionsByDiscovery.datadogOnly).toBe(2);
    const gone = report.entries.find((e: { value: string }) => e.value === "scg-gone");
    expect(gone.firstSeen).toBe("2025-05-05");
    expect(Object.keys(gone).some((k) => k.startsWith("_"))).toBe(false);
  });

  // Samples are the evidence; without the tree nothing can be verified.
  it("rejects the run when the sample tree cannot be read", async () => {
    const { fetchDatadogDataset } = await load();
    const fetchImpl = network({ "samples/npm/manifest.json": { x: null }, "samples/pypi/manifest.json": {}, "git/trees/main": 503 });
    await expect(fetchDatadogDataset({ fetchImpl })).rejects.toThrow(/sample tree could not be read/);
  });

  it("rejects the run when a sample subtree is truncated", async () => {
    const { fetchDatadogDataset } = await load();
    const fetchImpl = network({
      "samples/npm/manifest.json": { x: null },
      "samples/pypi/manifest.json": {},
      "git/trees/main": { tree: [{ path: "samples", type: "tree", sha: "sha-samples" }] },
      "git/trees/sha-samples": { tree: [{ path: "npm", type: "tree", sha: "sha-npm" }] },
      "git/trees/sha-npm": { tree: [{ path: "malicious_intent", type: "tree", sha: "sha-mal" }] },
      "git/trees/sha-mal": { truncated: true, tree: [] },
    });
    await expect(fetchDatadogDataset({ fetchImpl })).rejects.toThrow("truncated: npm/malicious_intent");
  });

  it("is on by default for the CLI and can be turned off", async () => {
    const { parseArgs } = await load();
    expect(parseArgs([]).useDatadog).toBe(true);
    expect(parseArgs(["--no-datadog"]).useDatadog).toBe(false);
  });
});

describe("DataDog IDE extensions", () => {
  it("parses publisher.name/version.vsix sample paths", async () => {
    const { parseDatadogExtensionSamples } = await load();
    const map = parseDatadogExtensionSamples([
      "samples/ide_extensions/compromised_lib/scgpub.scg-ext/1.84.0.vsix",
      "samples/ide_extensions/malicious_intent/scgpub.other/0.0.1.vsix",
      "samples/ide_extensions/manifest.json",
    ]);
    expect([...map.get("scgpub.scg-ext")]).toEqual(["1.84.0"]);
    expect([...map.get("scgpub.other")]).toEqual(["0.0.1"]);
  });

  // garytyler.darcula-pycharm 1.0.0: the theme's current release since 2019,
  // 367,801 installs, still listed. A version still published anywhere is
  // never pinned on this dataset's word alone.
  it.each([
    [{ inVscode: true, inOpenVsx: false }, []],
    [{ inVscode: false, inOpenVsx: true }, []],
    [{ inVscode: true, inOpenVsx: true }, []],
    // Removed from both, the usual fate of a malicious release (amazon-q-vscode 1.84.0).
    [{ inVscode: false, inOpenVsx: false }, ["vscode:", "openvsx:"]],
  ])("places %j under %j", async (placement, prefixes) => {
    const { extensionPrefixesFor } = await load();
    expect(extensionPrefixesFor(placement)).toEqual(prefixes);
  });

  it("asks both marketplaces about each sampled version", async () => {
    const { probeExtensionVersions } = await load();
    const fetchImpl = async (url: string | URL, init?: { method?: string }) => {
      const u = String(url);
      if (init?.method === "POST") {
        return json({ results: [{ extensions: [{ versions: [{ version: "1.0.0" }, { version: "2.0.0" }] }] }] });
      }
      return u.endsWith("/2.0.0") ? json({}) : json({}, 404);
    };
    expect(await probeExtensionVersions("scgpub.scg-ext", ["1.0.0", "2.0.0", "9.9.9"], { fetchImpl })).toEqual([
      { version: "1.0.0", inVscode: true, inOpenVsx: false },
      { version: "2.0.0", inVscode: true, inOpenVsx: true },
      { version: "9.9.9", inVscode: false, inOpenVsx: false },
    ]);
  });

  // One marketplace failing at a time: a test failing both would let either
  // check be deleted while the other still throws.
  it("rejects the run when the VS Code Marketplace answers with an error", async () => {
    const { probeExtensionVersions } = await load();
    const fetchImpl = async (_url: string | URL, init?: { method?: string }) =>
      init?.method === "POST" ? json({}, 503) : json({}, 404);
    await expect(probeExtensionVersions("scgpub.scg-ext", ["1.0.0"], { fetchImpl })).rejects.toThrow(
      /VS Code Marketplace returned HTTP 503/,
    );
  });

  it("rejects the run when Open VSX answers with an error", async () => {
    const { probeExtensionVersions } = await load();
    const fetchImpl = async (_url: string | URL, init?: { method?: string }) =>
      init?.method === "POST" ? json({ results: [{ extensions: [] }] }) : json({}, 503);
    await expect(probeExtensionVersions("scgpub.scg-ext", ["1.0.0"], { fetchImpl })).rejects.toThrow(
      /Open VSX returned HTTP 503/,
    );
  });

  it("reports a still-published version instead of pinning it", async () => {
    const { mapDatadogDataset } = await load();
    const { entries, stillPublished } = mapDatadogDataset(
      {
        manifests: {},
        dates: new Map(),
        extensions: [{ id: "scgpub.theme", placements: [{ version: "1.0.0", inVscode: true, inOpenVsx: false }] }],
      },
      { now: new Date("2026-10-05T08:00:00Z") },
    );
    expect(entries).toEqual([]);
    expect(stillPublished).toEqual(["scgpub.theme@1.0.0 (vscode)"]);
  });

  it("maps a version removed from both marketplaces to a pin on each, never a whole-extension block", async () => {
    const { mapDatadogDataset } = await load();
    const { entries } = mapDatadogDataset(
      {
        manifests: {},
        dates: new Map(),
        extensions: [{ id: "scgpub.scg-ext", placements: [{ version: "1.84.0", inVscode: false, inOpenVsx: false }] }],
      },
      { now: new Date("2026-10-05T08:00:00Z") },
    );
    expect(entries.map((e: { value: string }) => e.value)).toEqual([
      "vscode:scgpub.scg-ext@1.84.0",
      "openvsx:scgpub.scg-ext@1.84.0",
    ]);
  });
});
