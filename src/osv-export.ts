/**
 * OSV-format export of the bundled threat feed's package IOCs.
 *
 * Emits records in the OSV schema (https://ossf.github.io/osv-schema/) so the
 * feed can be consumed by osv-scanner and is shaped toward the
 * ossf/malicious-packages ecosystem. Only `type: "package"` entries whose
 * ecosystem maps to a real OSV ecosystem are exported; domain/ip/url/hash IOCs
 * and non-OSV ecosystems (e.g. Jenkins plugins) have no OSV representation and
 * are skipped.
 *
 * Deterministic: ids and timestamps derive only from the entry (no clock/
 * randomness), so exporting the same feed twice yields identical output.
 */

import { createHash } from "node:crypto";
import type { FeedIOC } from "./threat-intel.js";

/** Ecosystem-prefix (feed) -> OSV ecosystem name. Unlisted prefixes are skipped. */
const OSV_ECOSYSTEMS: Record<string, string> = {
  npm: "npm", // bare (unprefixed) feed package entries are npm
  go: "Go",
  ruby: "RubyGems",
  composer: "Packagist",
  cargo: "crates.io",
  nuget: "NuGet",
};

export interface OsvRecord {
  schema_version: string;
  id: string;
  modified: string;
  published?: string;
  summary: string;
  details: string;
  affected: Array<{
    package: { ecosystem: string; name: string };
    versions?: string[];
    ranges?: Array<{ type: string; events: Array<{ introduced: string }> }>;
  }>;
  database_specific: Record<string, unknown>;
}

/** Deterministic RFC3339 timestamp from a feed `firstSeen` date, or a sentinel. */
function toRfc3339(firstSeen?: string): string {
  if (firstSeen && /^\d{4}-\d{2}-\d{2}/.test(firstSeen)) {
    return `${firstSeen.slice(0, 10)}T00:00:00Z`;
  }
  // Deterministic sentinel for entries without a firstSeen date.
  return "2020-01-01T00:00:00Z";
}

/**
 * Parse a feed package `value` into an OSV ecosystem + package name + optional
 * pinned version. Returns null for non-OSV ecosystems. Mirrors matchPackageIOC/
 * matchBareNpmIOC: the version separator is the LAST "@" (an npm scope's leading
 * "@" is at index 0 and is not a version separator).
 */
export function parsePackageValue(
  value: string,
): { ecosystem: string; name: string; version?: string } | null {
  let ecoKey = "npm";
  let rest = value;
  const prefix = value.match(/^([a-z]+):/);
  if (prefix) {
    ecoKey = prefix[1];
    rest = value.slice(prefix[0].length);
  }
  const ecosystem = OSV_ECOSYSTEMS[ecoKey];
  if (!ecosystem) return null; // e.g. jenkins: - no OSV ecosystem

  const at = rest.lastIndexOf("@");
  const name = at > 0 ? rest.slice(0, at) : rest;
  const version = at > 0 ? rest.slice(at + 1) : undefined;
  if (!name) return null;
  return { ecosystem, name, version };
}

/** Stable, collision-resistant OSV id for a package IOC. */
function osvId(ecosystem: string, name: string, version?: string): string {
  const canonical = `${ecosystem}:${name}@${version ?? "*"}`;
  const slug = `${ecosystem}-${name}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  const hash = createHash("sha256").update(canonical).digest("hex").slice(0, 8);
  return `SCG-MAL-${slug}-${hash}`.toUpperCase();
}

/** Convert the feed's package IOCs to OSV records. Non-package/non-OSV entries are skipped. */
export function toOsvRecords(feed: FeedIOC[]): OsvRecord[] {
  const records: OsvRecord[] = [];
  const seen = new Set<string>();

  for (const ioc of feed) {
    if (ioc.type !== "package") continue;
    const parsed = parsePackageValue(ioc.value);
    if (!parsed) continue;

    const id = osvId(parsed.ecosystem, parsed.name, parsed.version);
    if (seen.has(id)) continue; // dedupe (e.g. same name pinned + bare)
    seen.add(id);

    const when = toRfc3339(ioc.firstSeen);
    const context = [
      ioc.campaign ? `Campaign: ${ioc.campaign}.` : "",
      ioc.family ? `Malware family: ${ioc.family}.` : "",
      "Flagged by the supply-chain-guard threat feed.",
    ]
      .filter(Boolean)
      .join(" ");

    const affected: OsvRecord["affected"][number] = {
      package: { ecosystem: parsed.ecosystem, name: parsed.name },
    };
    if (parsed.version) {
      affected.versions = [parsed.version];
    } else {
      // Bare name: the whole package is malicious at every version.
      affected.ranges = [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }];
    }

    records.push({
      schema_version: "1.6.0",
      id,
      modified: when,
      published: when,
      summary: `Malicious package: ${parsed.ecosystem}/${parsed.name}`,
      details: context,
      affected: [affected],
      database_specific: {
        malicious: true,
        source: "supply-chain-guard threat feed",
        severity: ioc.severity,
        confidence: ioc.confidence,
        ...(ioc.family ? { malware_family: ioc.family } : {}),
        ...(ioc.campaign ? { campaign: ioc.campaign } : {}),
      },
    });
  }

  // Deterministic ordering by id so the export is stable across runs.
  records.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return records;
}
