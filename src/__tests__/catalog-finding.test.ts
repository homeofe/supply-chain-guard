import { describe, it, expect, afterEach } from "vitest";

import { catalogFindings, catalogSeverityFor, CATALOG_MISSING_RULE } from "../feed.js";
import { CATALOG_DIGEST } from "../catalog-digest.js";
import type { CatalogState } from "../threat-intel.js";
import { loadPolicyConfig } from "../policy-engine.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const state = (over: Partial<CatalogState> = {}): CatalogState => ({
  available: false,
  reason: "absent",
  entryCount: 0,
  ...over,
});

// The rule only has anything to say when the release actually pins a non-empty
// catalog. While it is empty every unavailable case is a no-op, so these tests
// state which side of that they are exercising rather than silently depending
// on today's value.
const CATALOG_IS_EMPTY = CATALOG_DIGEST.entryCount === 0;

describe("catalogFindings", () => {
  it("says nothing when the catalog was consulted", () => {
    expect(catalogFindings(state({ available: true, entryCount: 12 }), "optional")).toEqual([]);
  });

  // The guard that keeps `catalog: required` satisfiable in the phase where the
  // published catalog is still empty. An empty-but-valid catalog is available,
  // not missing, and must not fire even under the strictest mode.
  it("says nothing for an empty but valid catalog, in either mode", () => {
    expect(catalogFindings(state({ available: true, entryCount: 0 }), "optional")).toEqual([]);
    expect(catalogFindings(state({ available: true, entryCount: 0 }), "required")).toEqual([]);
  });

  // A finding naming zero missing indicators on every scan is noise, and noise
  // is what gets a scanner switched off. Under `required` it still fires,
  // because that setting is about the mechanism being in place.
  it("stays silent while the release pins an empty catalog, unless required", () => {
    if (!CATALOG_IS_EMPTY) {
      expect(catalogFindings(state(), "optional")).toHaveLength(1);
      return;
    }
    expect(catalogFindings(state(), "optional")).toEqual([]);
    expect(catalogFindings(state(), "required")).toHaveLength(1);
  });

  it("uses the rule id and the trust category", () => {
    const [finding] = catalogFindings(state(), "required");
    expect(finding.rule).toBe(CATALOG_MISSING_RULE);
    expect(finding.rule).toBe("THREAT_FEED_CATALOG_MISSING");
    expect(finding.category).toBe("trust");
    expect(finding.confidence).toBe(1.0);
  });

  // No `file`. The scanner pushes this above the path-ignore filter, which
  // drops anything carrying a file path, so a file here would make the finding
  // vanish for any repo with ignore globs set.
  it("carries no file, so the path-ignore filter cannot drop it", () => {
    const [finding] = catalogFindings(state(), "required");
    expect(finding.file).toBeUndefined();
  });

  it("names the reason, and the version when the cache recorded one", () => {
    const [finding] = catalogFindings(
      state({ reason: "version-mismatch", cachedVersion: "1.0.0-old" }),
      "required",
    );
    expect(finding.description).toMatch(/different release/);
    expect(finding.description).toContain("1.0.0-old");
  });

  it("omits the version clause when the cache recorded none", () => {
    const [finding] = catalogFindings(state({ reason: "absent" }), "required");
    expect(finding.description).not.toContain("it was built for");
  });

  it("recommends the refresh command and names the rule to exclude", () => {
    const [finding] = catalogFindings(state(), "required");
    expect(finding.recommendation).toContain("feed refresh");
    expect(finding.recommendation).toContain(CATALOG_MISSING_RULE);
  });
});

describe("catalogFindings severity", () => {
  // Asserted through catalogSeverityFor rather than through catalogFindings.
  // While the release pins an empty catalog the optional path returns nothing,
  // so an assertion made through catalogFindings would sit behind a condition
  // that is never true and prove nothing at all.
  //
  // The design distinguishes these; the plan specified a flat medium. The
  // distinction is the only thing telling an operator whether to run a refresh
  // or to go and look at the machine.
  // `absent` is info on purpose: it is the state of every fresh install, and a
  // medium there turns the badge yellow for every user on every run until they
  // refresh. The rest of the ladder is about how much is actually wrong.
  it.each([
    ["absent", "info"],
    ["version-mismatch", "low"],
    ["unreadable", "medium"],
  ] as const)("reports %s as %s in optional mode", (reason, severity) => {
    expect(catalogSeverityFor(reason, "optional")).toBe(severity);
  });

  // The control that keeps the ladder meaningful: not everything is info.
  it("separates a missing download from replaced detection data", () => {
    expect(catalogSeverityFor("absent", "optional")).toBe("info");
    expect(catalogSeverityFor("digest-mismatch", "optional")).toBe("high");
    expect(catalogSeverityFor("corrupt", "optional")).toBe("high");
  });

  // Neither of these is a normal state: one means the cached catalog was built
  // from a different catalog than this release pins, the other that its entries
  // no longer match their own checksum. Both say the scanner's detection data
  // was corrupted or modified underneath it.
  it.each([["digest-mismatch"], ["corrupt"]] as const)(
    "treats %s as more than a missed download",
    (reason) => {
      expect(catalogSeverityFor(reason, "optional")).toBe("high");
    },
  );

  it("raises every reason to critical under catalog: required", () => {
    for (const reason of [
      "absent",
      "unreadable",
      "version-mismatch",
      "digest-mismatch",
      "corrupt",
    ] as const) {
      expect(catalogSeverityFor(reason, "required")).toBe("critical");
      expect(catalogFindings(state({ reason }), "required")[0].severity).toBe("critical");
    }
  });

  // The wiring control: the severity the finding carries is the one the map
  // gives, not a constant that happens to agree with it today.
  it("puts the mapped severity on the finding itself", () => {
    const [finding] = catalogFindings(state({ reason: "corrupt" }), "required");
    expect(finding.severity).toBe(catalogSeverityFor("corrupt", "required"));
  });

  it("defaults to optional when no mode is given", () => {
    expect(catalogFindings(state({ available: true }))).toEqual([]);
  });
});

describe("the catalog policy knob", () => {
  const dirs: string[] = [];
  const withConfig = (yaml: string) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-policy-"));
    dirs.push(dir);
    fs.writeFileSync(path.join(dir, ".supply-chain-guard.yml"), yaml);
    return loadPolicyConfig(dir);
  };

  it("parses catalog: required", () => {
    const config = withConfig("catalog: required\n");
    expect(config?.catalog).toBe("required");
    expect(config?.warnings ?? []).toEqual([]);
  });

  it("parses catalog: optional", () => {
    const config = withConfig("catalog: optional\n");
    expect(config?.catalog).toBe("optional");
    expect(config?.warnings ?? []).toEqual([]);
  });

  it("accepts a quoted value", () => {
    expect(withConfig('catalog: "required"\n')?.catalog).toBe("required");
  });

  // Reported, never silently dropped. A typo would otherwise leave the default
  // in place while the author believes the catalog is required, which is the
  // exact failure this setting exists to prevent.
  it("warns on an unrecognised value and leaves the setting unset", () => {
    const config = withConfig("catalog: yes\n");
    expect(config?.catalog).toBeUndefined();
    expect(config?.warnings?.some((w) => /catalog must be/.test(w.message))).toBe(true);
  });

  it("does not turn catalog into a section", () => {
    // If `catalog:` opened a section, the block beneath it would be parsed in
    // that stale context and the suppress entries would be lost or warned
    // about. Zero warnings plus a parsed suppress block is the evidence that it
    // stayed a scalar.
    const config = withConfig(
      "catalog: required\nsuppress:\n  - rule: SOME_RULE\n    reason: exercising the parser\n",
    );
    expect(config?.catalog).toBe("required");
    expect(config?.suppress?.some((s) => s.rule === "SOME_RULE")).toBe(true);
    expect(config?.warnings ?? []).toEqual([]);
  });

  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });
});
