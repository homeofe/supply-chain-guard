import { describe, it, expect } from "vitest";
import { loadThreatIntel, checkThreatIntel, matchPackageIOC } from "../threat-intel.js";
import type { FeedIOC } from "../threat-intel.js";
import { performanceBudget } from "./performance-budget.js";

describe("Threat Intelligence", () => {
  it("should load bundled threat feed", () => {
    const feed = loadThreatIntel();
    expect(feed.length).toBeGreaterThan(5);
    expect(feed.some((i) => i.family === "Vidar")).toBe(true);
    expect(feed.some((i) => i.family === "GhostSocks")).toBe(true);
  });

  it("should detect known C2 domain from feed", () => {
    const feed = loadThreatIntel();
    const content = 'const c2 = "https://rti.cargomanbd.com/api/data";';
    const findings = checkThreatIntel(content, "malware.js", feed);
    expect(findings.some((f) => f.rule === "THREAT_INTEL_MATCH")).toBe(true);
    expect(findings[0]?.description).toContain("Vidar");
  });

  it("should detect known C2 IP from feed", () => {
    const feed = loadThreatIntel();
    const content = 'connect("147.45.197.92", 443);';
    const findings = checkThreatIntel(content, "backdoor.js", feed);
    expect(findings.some((f) => f.rule === "THREAT_INTEL_MATCH")).toBe(true);
  });

  it("should detect known hash from feed", () => {
    const feed = loadThreatIntel();
    const content = "sha256: 77c73bd5e7625b7f691bc00a1b561a0f";
    const findings = checkThreatIntel(content, "config.json", feed);
    expect(findings.some((f) => f.rule === "THREAT_INTEL_MATCH")).toBe(true);
  });

  it("should return empty for clean content", () => {
    const feed = loadThreatIntel();
    const content = 'const x = "hello world";';
    const findings = checkThreatIntel(content, "clean.js", feed);
    expect(findings).toHaveLength(0);
  });

  it("should include confidence and category", () => {
    const feed = loadThreatIntel();
    const content = 'fetch("https://rti.cargomanbd.com")';
    const findings = checkThreatIntel(content, "test.js", feed);
    expect(findings[0]?.confidence).toBeGreaterThan(0);
    expect(findings[0]?.category).toBe("malware");
  });

  it("should skip package-type IOCs in content check", () => {
    const feed: FeedIOC[] = [
      { type: "package", value: "axios@1.14.1", severity: "critical", confidence: 1.0 },
    ];
    const content = "axios@1.14.1";
    const findings = checkThreatIntel(content, "test.js", feed);
    expect(findings).toHaveLength(0); // Packages checked separately
  });
});

// ---------------------------------------------------------------------------
// matchPackageIOC index parity
// ---------------------------------------------------------------------------

/**
 * Reference implementation: the exact pre-index semantics of matchPackageIOC.
 * The indexed implementation must agree with this for every probe. An index
 * that changes matching semantics generates both false positives and, far
 * worse, false negatives - so this differential test is the real guard, not
 * any timing assertion.
 */
function referenceMatch(
  entries: FeedIOC[],
  ecosystem: string,
  name: string,
  version?: string,
): FeedIOC | null {
  const eco = ecosystem.toLowerCase();
  const prefix = `${eco}:`;
  const normalizeName = (value: string): string => {
    if (eco === "pypi") return value.toLowerCase().replace(/[-_.]+/g, "-");
    return eco === "nuget" ? value.toLowerCase() : value;
  };
  const wantName = normalizeName(name);

  for (const ioc of entries) {
    if (ioc.type !== "package") continue;
    if (!ioc.value.toLowerCase().startsWith(prefix)) continue;
    const rest = ioc.value.substring(prefix.length);
    const at = rest.lastIndexOf("@");
    const iocName = at > 0 ? rest.substring(0, at) : rest;
    const iocVersion = at > 0 ? rest.substring(at + 1) : undefined;
    const nameMatches = normalizeName(iocName) === wantName;
    if (!nameMatches) continue;
    if (iocVersion === undefined) return ioc;
    if (version !== undefined && iocVersion === version) return ioc;
  }
  return null;
}

describe("matchPackageIOC index parity", () => {
  const feed = loadThreatIntel();

  /** Every ecosystem:name pair actually present in the feed, parsed once. */
  const parsed = feed
    .filter((i) => i.type === "package")
    .map((i) => {
      const colon = i.value.indexOf(":");
      if (colon <= 0) return null;
      const eco = i.value.substring(0, colon);
      const rest = i.value.substring(colon + 1);
      const at = rest.lastIndexOf("@");
      return {
        eco,
        name: at > 0 ? rest.substring(0, at) : rest,
        version: at > 0 ? rest.substring(at + 1) : undefined,
      };
    })
    .filter((x): x is { eco: string; name: string; version: string | undefined } => x !== null);

  it("has a non-trivial set of prefixed package entries to probe", () => {
    // Guards the whole suite: if the feed shape changes so nothing is indexed,
    // every parity assertion below would pass vacuously.
    expect(parsed.length).toBeGreaterThan(20);
  });

  // These two cases run the LINEAR reference implementation once per probe, so their
  // cost is the feed size times the probe count and grows quadratically as the feed
  // does. Vitest's default 5 s cap was never a deliberate budget for that: on
  // 2026-09-02 the four-probe case took 5.243 s on a GitHub-hosted Node 22 runner at
  // 20,140 entries and was killed, while the identical tree passed on Node 24 and on
  // main. An explicit budget with real headroom is what keeps this a correctness test
  // rather than a runner-speed test, and performanceBudget() keeps it meaningful under
  // V8 coverage instrumentation the same way the core broad-gap case does.
  it("agrees with the reference scan for every real feed entry", { timeout: performanceBudget(20_000) }, () => {
    for (const p of parsed) {
      expect(matchPackageIOC(p.eco, p.name, p.version, feed), `${p.eco}:${p.name}`).toBe(
        referenceMatch(feed, p.eco, p.name, p.version),
      );
    }
  });

  it("agrees with the reference scan for wrong-version and case-flipped probes", { timeout: performanceBudget(60_000) }, () => {
    for (const p of parsed) {
      const flipped =
        p.name === p.name.toUpperCase() ? p.name.toLowerCase() : p.name.toUpperCase();
      const probes: Array<[string, string, string | undefined]> = [
        [p.eco, p.name, "0.0.0-does-not-exist"],
        [p.eco, p.name, undefined],
        [p.eco, flipped, p.version],
        [p.eco.toUpperCase(), p.name, p.version],
      ];
      for (const [eco, name, version] of probes) {
        expect(
          matchPackageIOC(eco, name, version, feed),
          `${eco}:${name}@${version ?? "-"}`,
        ).toBe(referenceMatch(feed, eco, name, version));
      }
    }
  });

  it("agrees with the reference scan for names that are not in the feed", () => {
    const absent: Array<[string, string, string | undefined]> = [
      ["npm", "definitely-not-a-real-package-xyz", "1.0.0"],
      ["pypi", "definitely-not-a-real-package-xyz", undefined],
      ["nuget", "Definitely.Not.Real", "2.0.0"],
      ["go", "github.com/nobody/nothing", "v1.0.0"],
      ["cargo", "", undefined],
    ];
    for (const [eco, name, version] of absent) {
      expect(matchPackageIOC(eco, name, version, feed), `${eco}:${name}`).toBe(
        referenceMatch(feed, eco, name, version),
      );
    }
  });

  it("preserves first-match-wins when a bare name and a versioned entry collide", () => {
    // Order matters: the linear scan returned whichever came first.
    const versionedFirst: FeedIOC[] = [
      { type: "package", value: "pypi:dup@1.0.0", severity: "critical", confidence: 1.0 },
      { type: "package", value: "pypi:dup", severity: "high", confidence: 0.9 },
    ];
    const bareFirst: FeedIOC[] = [versionedFirst[1]!, versionedFirst[0]!];

    // Exact version hit: the versioned entry wins only when it comes first.
    expect(matchPackageIOC("pypi", "dup", "1.0.0", versionedFirst)?.severity).toBe("critical");
    expect(matchPackageIOC("pypi", "dup", "1.0.0", bareFirst)?.severity).toBe("high");
    // Non-matching version falls through to the bare entry in both orders.
    expect(matchPackageIOC("pypi", "dup", "9.9.9", versionedFirst)?.severity).toBe("high");
    expect(matchPackageIOC("pypi", "dup", "9.9.9", bareFirst)?.severity).toBe("high");

    for (const f of [versionedFirst, bareFirst]) {
      for (const v of ["1.0.0", "9.9.9", undefined]) {
        expect(matchPackageIOC("pypi", "dup", v, f)).toBe(referenceMatch(f, "pypi", "dup", v));
      }
    }
  });

  it("applies NuGet case folding and PEP 503 normalization only where defined", () => {
    const f: FeedIOC[] = [
      { type: "package", value: "nuget:Newtonsoft.Json", severity: "critical", confidence: 1.0 },
      { type: "package", value: "pypi:guardrails-ai@0.10.1", severity: "critical", confidence: 1.0 },
      { type: "package", value: "ruby:Case-Sensitive", severity: "critical", confidence: 1.0 },
    ];
    expect(matchPackageIOC("nuget", "newtonsoft.json", "1.0.0", f)).not.toBeNull();
    expect(matchPackageIOC("nuget", "NEWTONSOFT.JSON", "1.0.0", f)).not.toBeNull();
    for (const name of ["guardrails-ai", "guardrails_ai", "guardrails.ai", "GUARDRAILS_AI"]) {
      expect(matchPackageIOC("pypi", name, "0.10.1", f), name).not.toBeNull();
    }
    expect(matchPackageIOC("ruby", "case-sensitive", undefined, f)).toBeNull();
    expect(matchPackageIOC("ruby", "Case-Sensitive", undefined, f)).not.toBeNull();
  });

  it("does not match unprefixed npm entries through the prefixed lookup", () => {
    // npm feed entries carry no ecosystem prefix by construction; they are
    // matched by matchBareNpmIOC instead. Documented so a future change that
    // starts emitting "npm:" prefixes is a deliberate one.
    const f: FeedIOC[] = [
      { type: "package", value: "left-pad@1.0.0", severity: "critical", confidence: 1.0 },
    ];
    expect(matchPackageIOC("npm", "left-pad", "1.0.0", f)).toBeNull();
    expect(matchPackageIOC("npm", "left-pad", "1.0.0", f)).toBe(
      referenceMatch(f, "npm", "left-pad", "1.0.0"),
    );
  });

  it("returns a stable result across repeated calls on the same feed array", () => {
    // The index is cached per feed array; a stale or mutated index would show
    // up as a second call disagreeing with the first.
    const p = parsed[0]!;
    const first = matchPackageIOC(p.eco, p.name, p.version, feed);
    for (let i = 0; i < 3; i++) {
      expect(matchPackageIOC(p.eco, p.name, p.version, feed)).toBe(first);
    }
  });
});
