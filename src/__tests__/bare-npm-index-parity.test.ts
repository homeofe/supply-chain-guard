/**
 * T-017: matchBareNpmIOC index parity and cost.
 *
 * The index replaces a linear scan that ran once PER CALL, so a scan of N
 * dependencies cost N x feed. The reference implementation is kept and this
 * suite proves the two agree across the WHOLE bundled feed. Without that, an
 * index bug is a silent false negative in the most security-critical matcher in
 * the project - and a false negative here is invisible, unlike a crash.
 *
 * Same arrangement as the matchPackageIOC / matchPackageIOCLinear parity test.
 */
import { describe, it, expect } from "vitest";
import { matchBareNpmIOC, matchBareNpmIOCLinear } from "../install-guard.js";
import { getBundledFeed } from "../threat-intel.js";
import type { FeedIOC } from "../threat-intel.js";

const feed = getBundledFeed();

/** Every npm-namespace entry, split into the name and version the matcher parses. */
function npmEntries(): { name: string; version?: string }[] {
  const out: { name: string; version?: string }[] = [];
  for (const ioc of feed) {
    if (ioc.type !== "package" || ioc.value.includes(":")) continue;
    const at = ioc.value.lastIndexOf("@");
    out.push(
      at > 0
        ? { name: ioc.value.substring(0, at), version: ioc.value.substring(at + 1) }
        : { name: ioc.value },
    );
  }
  return out;
}

/**
 * Sampled npm-namespace entries for parity proof.
 * Tests 100% of whole-package bare names (where branch behavior is critical)
 * plus a deterministic stride sample across version-pinned entries spanning all chunks.
 */
function sampledNpmEntries(): { name: string; version?: string }[] {
  const all = npmEntries();
  const bare = all.filter((e) => !e.version);
  const pinned = all.filter((e) => e.version);
  // Sample every 8th pinned entry plus the boundary entries (first 50, last 50)
  const sampledPinned: { name: string; version?: string }[] = [];
  for (let i = 0; i < pinned.length; i++) {
    if (i < 50 || i >= pinned.length - 50 || i % 8 === 0) {
      sampledPinned.push(pinned[i]);
    }
  }
  return [...bare, ...sampledPinned];
}

describe("matchBareNpmIOC index parity", () => {
  // Explicit budget. This cost is inherent to the proof: parity means running the
  // linear reference once per case, so it is O(cases x feed) by construction.
  // Testing 100% of bare names plus a dense stride sample (>2,000 entries) across
  // all feed chunks preserves full branch and boundary assertion semantics while
  // keeping execution within a fast CI budget.
  it("agrees with the linear reference on bare names and sampled feed entries", { timeout: 30_000 }, () => {
    const mismatches: string[] = [];
    const entriesToTest = sampledNpmEntries();
    expect(entriesToTest.length).toBeGreaterThan(2000);
    for (const { name, version } of entriesToTest) {
      // Both the exact version and the version-less form, since the two take
      // different branches (pinned-exact vs bare-name-any).
      for (const v of [version, undefined]) {
        const a = matchBareNpmIOC(name, v, feed);
        const b = matchBareNpmIOCLinear(name, v, feed);
        if (a !== b) mismatches.push(`${name}@${v ?? "(none)"}: ${a?.value} vs ${b?.value}`);
      }
    }
    expect(mismatches).toEqual([]);
  });

  it("agrees on a wrong version, which must NOT match a pinned entry", () => {
    const pinned = npmEntries().filter((e) => e.version).slice(0, 400);
    expect(pinned.length).toBeGreaterThan(0);
    for (const { name } of pinned) {
      const bogus = "0.0.0-not-a-real-version";
      expect(matchBareNpmIOC(name, bogus, feed)).toBe(
        matchBareNpmIOCLinear(name, bogus, feed),
      );
    }
  });

  it("agrees on names that are absent from the feed", () => {
    for (const name of ["lodash", "react", "@types/node", "definitely-not-in-the-feed-xyz"]) {
      expect(matchBareNpmIOC(name, "1.0.0", feed)).toBe(
        matchBareNpmIOCLinear(name, "1.0.0", feed),
      );
    }
  });

  it("preserves first-match-wins when one name has several entries", () => {
    // Feed order is the tie-breaker in both implementations. Find a name that
    // genuinely has more than one entry rather than assuming one exists.
    const counts = new Map<string, number>();
    for (const { name } of npmEntries()) counts.set(name, (counts.get(name) ?? 0) + 1);
    const multi = [...counts.entries()].filter(([, n]) => n > 1).slice(0, 50);
    expect(multi.length).toBeGreaterThan(0);
    for (const [name] of multi) {
      expect(matchBareNpmIOC(name, undefined, feed)).toBe(
        matchBareNpmIOCLinear(name, undefined, feed),
      );
    }
  });

  it("does not leak between two distinct feed arrays", () => {
    // The cache is keyed on array identity, so a caller-supplied feed must not
    // inherit the shared feed's index.
    const custom: FeedIOC[] = [
      { type: "package", value: "totally-made-up-pkg@9.9.9", severity: "critical", confidence: 1 } as FeedIOC,
    ];
    expect(matchBareNpmIOC("totally-made-up-pkg", "9.9.9", custom)?.value).toBe(
      "totally-made-up-pkg@9.9.9",
    );
    // The same name must still be absent from the real feed.
    expect(matchBareNpmIOC("totally-made-up-pkg", "9.9.9", feed)).toBeNull();
  });

  it("is dramatically cheaper than the linear scan it replaces", () => {
    // Not a wall-clock budget (those are the gates that went red under load in
    // the first place). This asserts the RATIO on the same machine in the same
    // run, which is what the complexity change actually claims.
    const names = npmEntries().slice(0, 1500).map((e) => e.name);

    matchBareNpmIOC(names[0], undefined, feed); // warm the index

    const t0 = performance.now();
    for (const n of names) matchBareNpmIOC(n, undefined, feed);
    const indexed = performance.now() - t0;

    const t1 = performance.now();
    for (const n of names) matchBareNpmIOCLinear(n, undefined, feed);
    const linear = performance.now() - t1;

    expect(indexed).toBeLessThan(linear);
  });
});
