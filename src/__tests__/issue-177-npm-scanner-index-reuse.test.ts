/**
 * Issue 177 regression: the npm scanner must reuse the bundled feed's lookup
 * index and the compiled name-pattern table, not rebuild them per scan.
 * https://github.com/homeofe/supply-chain-guard/issues/177
 *
 * Why a NEW file rather than an addition to bare-npm-index-parity.test.ts: that
 * suite takes `const feed = getBundledFeed()` once at module scope and reuses
 * it, so it exercises the shared-array shape and can never observe the
 * fresh-copy shape production used. Twenty tests across it and
 * npm-scanner.test.ts passed with the defect present. A test that surrounds a
 * defect does not cover it, so the assertions here are written against the
 * production call sites (checkPackageName, checkDependencies) and against a
 * counter of actual index builds, not against a feed array this file chose.
 *
 * The two mutations these tests exist to catch:
 *   1. src/npm-scanner.ts going back to getBundledFeed() at either call site.
 *      "index is built at most once" and "steady state builds nothing" both go
 *      red (they read 6 across three package scans).
 *   2. src/patterns.ts compiling MALICIOUS_PACKAGE_REGEXES with the "g" flag,
 *      copied from validateRegexStringSet. The flags assertion goes red, and so,
 *      independently, does the four-call determinism assertion - which is the
 *      one that catches the consequence rather than the shape, because a shared
 *      "g" regex carries lastIndex across .test() calls and silently misses
 *      every second match of a known-malicious name.
 */
import { describe, it, expect } from "vitest";
import { checkDependencies, checkPackageName } from "../npm-scanner.js";
import { getBareNpmIndexBuildCount } from "../install-guard.js";
import { getBundledFeed, getBundledFeedRef } from "../threat-intel.js";
import { MALICIOUS_PACKAGE_PATTERNS, MALICIOUS_PACKAGE_REGEXES } from "../patterns.js";
import type { Finding } from "../types.js";

/**
 * Dependency names that match no feed IOC and no MALICIOUS_PACKAGE_PATTERNS
 * entry, so every lookup reaches the index and every pattern loop runs to
 * completion instead of short-circuiting on an early hit.
 */
function syntheticDeps(count: number, tag: string): Record<string, string> {
  const deps: Record<string, string> = {};
  for (let i = 0; i < count; i++) deps[`scg-issue177-${tag}-${i}`] = "^1.0.0";
  return deps;
}

/**
 * The two feed and pattern consumers scanNpmPackage() calls once each per scan,
 * driven directly. Everything else in a scan is registry metadata, a tarball
 * download and per-file content scanning, none of which touches the feed index.
 */
function scanShape(packageName: string, depCount: number, tag: string): Finding[] {
  const findings: Finding[] = [];
  checkPackageName(packageName, findings);
  checkDependencies(
    {
      dependencies: syntheticDeps(Math.ceil(depCount / 2), `${tag}-d`),
      devDependencies: syntheticDeps(Math.floor(depCount / 2), `${tag}-v`),
    },
    findings,
  );
  return findings;
}

describe("issue 177: bundled feed index is built once per process", () => {
  it("builds the bare-npm index at most once across a multi-package scan", () => {
    // 112 is the largest dependency count observed on the registry across
    // express, eslint, webpack, typescript, @angular/cli and react-scripts
    // (webpack: 20 dependencies + 92 devDependencies). Chosen so the input size
    // is a real one rather than a number picked to make an assertion pass; the
    // assertion below does not depend on it.
    const DEPS_PER_PACKAGE = 112;
    const packages = ["scg-issue177-alpha", "scg-issue177-beta", "scg-issue177-gamma"];

    const before = getBareNpmIndexBuildCount();
    for (const name of packages) scanShape(name, DEPS_PER_PACKAGE, "first");
    const firstPass = getBareNpmIndexBuildCount() - before;

    // At most one: another test in this file may already have warmed the index,
    // in which case zero is correct. Before the fix this read 6, two per scan.
    expect(firstPass).toBeLessThanOrEqual(1);

    // The invariant that does not depend on what ran first: once warm, no scan
    // rebuilds anything, ever. Before the fix this read 6 as well.
    const warm = getBareNpmIndexBuildCount();
    for (const name of packages) scanShape(name, DEPS_PER_PACKAGE, "second");
    expect(getBareNpmIndexBuildCount() - warm).toBe(0);
  });

  it("hands out one stable frozen array for the bundled feed", () => {
    const first = getBundledFeedRef();
    const second = getBundledFeedRef();

    // Identity, which is what the WeakMap in install-guard.ts keys on.
    expect(second).toBe(first);
    // Structural mutation throws instead of silently invalidating the index.
    expect(Object.isFrozen(first)).toBe(true);
    expect(() => (first as unknown as unknown[]).push({})).toThrow(TypeError);

    // The copying accessor keeps its contract: "feed stats" and the OSV export
    // still get an independent, mutable array, so this change did not turn a
    // reporting path into a shared-state path.
    const copyA = getBundledFeed();
    const copyB = getBundledFeed();
    expect(copyA).not.toBe(copyB);
    expect(copyA).not.toBe(first);
    expect(Object.isFrozen(copyA)).toBe(false);

    // Same entries either way: the reference is not a filtered or reordered view.
    expect(copyA.length).toBe(first.length);
    expect(copyA).toEqual([...first]);
  });
});

describe("issue 177: malicious package name patterns are compiled once", () => {
  it("compiles every pattern, with no flags", () => {
    expect(MALICIOUS_PACKAGE_REGEXES.length).toBe(MALICIOUS_PACKAGE_PATTERNS.length);
    for (let i = 0; i < MALICIOUS_PACKAGE_PATTERNS.length; i++) {
      const compiled = MALICIOUS_PACKAGE_REGEXES[i]!;
      // Same pattern, same order, so the table stays the single source of truth.
      expect(compiled.source).toBe(new RegExp(MALICIOUS_PACKAGE_PATTERNS[i]!).source);
      // No flags at all. "g" specifically makes .test() stateful via lastIndex;
      // "y" does the same. Asserting the empty string rejects both and anything
      // else a future edit might add without thinking about reuse.
      expect(compiled.flags).toBe("");
    }
  });

  it("returns the same verdict on repeated checks of one malicious name", () => {
    // "crossenv" matches exactly one MALICIOUS_PACKAGE_PATTERNS entry and is not
    // in the bundled feed, so checkPackageName does not early-return on the IOC
    // branch and the compiled-pattern loop is the code under test.
    const MALICIOUS_NAME = "crossenv";
    const REPEATS = 4;

    for (let call = 1; call <= REPEATS; call++) {
      const findings: Finding[] = [];
      checkPackageName(MALICIOUS_NAME, findings);
      expect(
        findings.filter((f) => f.rule === "MALICIOUS_PACKAGE_NAME"),
        `call ${call} of ${REPEATS} on checkPackageName("${MALICIOUS_NAME}")`,
      ).toHaveLength(1);
    }

    for (let call = 1; call <= REPEATS; call++) {
      const findings: Finding[] = [];
      checkDependencies({ dependencies: { [MALICIOUS_NAME]: "^1.0.0" } }, findings);
      expect(
        findings.filter((f) => f.rule === "MALICIOUS_DEPENDENCY"),
        `call ${call} of ${REPEATS} on checkDependencies({ ${MALICIOUS_NAME} })`,
      ).toHaveLength(1);
    }
  });
});
