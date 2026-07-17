import { describe, it, expect } from "vitest";
import { toOsvRecords, parsePackageValue } from "../osv-export.js";
import type { FeedIOC } from "../threat-intel.js";
import { getBundledFeed } from "../threat-intel.js";

describe("parsePackageValue", () => {
  it("maps bare and prefixed package values to OSV ecosystems", () => {
    expect(parsePackageValue("left-pad")).toEqual({ ecosystem: "npm", name: "left-pad" });
    expect(parsePackageValue("@asyncapi/generator@3.3.1")).toEqual({ ecosystem: "npm", name: "@asyncapi/generator", version: "3.3.1" });
    expect(parsePackageValue("go:github.com/x/y")).toEqual({ ecosystem: "Go", name: "github.com/x/y" });
    expect(parsePackageValue("nuget:Sicoob.Sdk@2.0.0")).toEqual({ ecosystem: "NuGet", name: "Sicoob.Sdk", version: "2.0.0" });
    expect(parsePackageValue("ruby:knot-devise-jwt-helper")).toEqual({ ecosystem: "RubyGems", name: "knot-devise-jwt-helper" });
    expect(parsePackageValue("cargo:move-analyzer-build")).toEqual({ ecosystem: "crates.io", name: "move-analyzer-build" });
    expect(parsePackageValue("composer:foo/bar")).toEqual({ ecosystem: "Packagist", name: "foo/bar" });
  });

  it("returns null for ecosystems with no OSV mapping", () => {
    expect(parsePackageValue("jenkins:some-plugin")).toBeNull();
  });
});

describe("toOsvRecords", () => {
  const feed: FeedIOC[] = [
    { type: "package", value: "@asyncapi/generator@3.3.1", severity: "critical", confidence: 1, family: "BotnetLoader", campaign: "AsyncAPI npm compromise", firstSeen: "2026-07-14" },
    { type: "package", value: "skrill", severity: "critical", confidence: 0.98, campaign: "Fake Payment SDK Typosquat", firstSeen: "2026-07-07" },
    { type: "package", value: "jenkins:x", severity: "high", confidence: 0.9 }, // skipped (no OSV ecosystem)
    { type: "domain", value: "evil.example", severity: "critical", confidence: 0.9 }, // skipped (not a package)
  ];

  it("exports package IOCs as valid OSV records and skips the rest", () => {
    const records = toOsvRecords(feed);
    expect(records).toHaveLength(2);
    for (const r of records) {
      expect(r.schema_version).toBe("1.6.0");
      expect(r.id).toMatch(/^SCG-MAL-[A-Z0-9-]+$/);
      expect(r.modified).toMatch(/^\d{4}-\d{2}-\d{2}T00:00:00Z$/);
      expect(r.affected[0].package.ecosystem).toBeTruthy();
      expect(r.database_specific.malicious).toBe(true);
    }
  });

  it("uses a pinned version for name@version and an all-versions range for a bare name", () => {
    const records = toOsvRecords(feed);
    const pinned = records.find((r) => r.affected[0].package.name === "@asyncapi/generator");
    expect(pinned?.affected[0].versions).toEqual(["3.3.1"]);
    expect(pinned?.affected[0].ranges).toBeUndefined();

    const bare = records.find((r) => r.affected[0].package.name === "skrill");
    expect(bare?.affected[0].versions).toBeUndefined();
    expect(bare?.affected[0].ranges).toEqual([{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }]);
  });

  it("is deterministic: same feed -> byte-identical output", () => {
    expect(JSON.stringify(toOsvRecords(feed))).toBe(JSON.stringify(toOsvRecords(feed)));
  });

  it("produces unique, sorted ids and exports the real bundled feed cleanly", () => {
    const records = toOsvRecords(getBundledFeed());
    expect(records.length).toBeGreaterThan(50);
    const ids = records.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length); // unique
    expect([...ids].sort()).toEqual(ids); // already sorted
    // Every record is a structurally valid OSV malicious-package entry.
    for (const r of records) {
      expect(r.affected[0].package.name.length).toBeGreaterThan(0);
      expect(Boolean(r.affected[0].versions) !== Boolean(r.affected[0].ranges)).toBe(true);
    }
  });
});
