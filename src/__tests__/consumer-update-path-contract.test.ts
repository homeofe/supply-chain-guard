/**
 * The consumer update path published in the README is a contract, not prose.
 *
 * WHY THIS EXISTS
 * ---------------
 * This project releases roughly 1.4 times a day: 134 releases in the 155 days to
 * 2026-08-21, a median of 20 hours between them, two thirds of the gaps under a
 * day. The README tells consumers to pin an exact version and let Dependabot keep
 * the pin current, so the interval in that published snippet decides whether the
 * advice works at all.
 *
 * It recommended `weekly`, and `weekly` cannot track this cadence. Each weekly run
 * opens a correct bump pull request; the next weekly run closes it as superseded
 * and opens another. Measured in one consumer of this Action: eight consecutive
 * weekly bump pull requests, each alive for exactly seven days, each proposing a
 * newer target than the last, while the pin itself sat unchanged for 49 days and
 * fell 82 releases behind. Every scan check was green throughout, because a stale
 * pin is not a failing scan. The README was publishing the recipe that produced
 * that outcome.
 *
 * WHY A TEST AND NOT JUST THE EDIT
 * --------------------------------
 * A documentation fix has nothing behind it. The next person to touch the snippet
 * has no way to know the interval was chosen against a measurement rather than
 * typed out of habit, and `weekly` is the habitual value. This test is the thing
 * that makes the choice survive.
 *
 * NOTE ON SCOPE: this asserts the PUBLISHED RECOMMENDATION only. It cannot assert
 * that any consumer merges the pull requests, and that, not the interval, is what
 * finally decides whether a pin moves. See the README section for the distinction.
 */
import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const read = (rel: string) => fs.readFileSync(path.join(REPO, rel), "utf-8");

/**
 * Prose in this README is hard-wrapped and the file is checked out with CRLF on
 * Windows, so a sentence-level assertion written as one line matches neither.
 * Collapsing every whitespace run to a single space makes the assertions depend
 * on the words rather than on the wrap column or the checkout's line endings.
 */
const flat = (s: string) => s.replace(/\s+/g, " ");

/**
 * Extract the `.github/dependabot.yml` snippet the README publishes for
 * consumers. Returning null rather than throwing lets the "snippet exists at all"
 * assertion fail with its own message instead of an unrelated parse error.
 * `\r?\n` because the fence terminator differs by checkout line endings.
 */
function consumerDependabotSnippet(readme: string): string | null {
  const fences = readme.match(/```yaml\r?\n[\s\S]*?```/g) ?? [];
  for (const fence of fences) {
    if (fence.includes(".github/dependabot.yml")) return fence;
  }
  return null;
}

describe("README consumer update path", () => {
  const readme = read("README.md");

  it("still publishes a Dependabot snippet for consumers", () => {
    // Guards every assertion below: a deleted snippet must fail loudly rather
    // than let the interval checks pass vacuously on an empty string.
    expect(consumerDependabotSnippet(readme)).not.toBeNull();
  });

  it("recommends a daily interval, because the release cadence is ~1.4/day", () => {
    const snippet = consumerDependabotSnippet(readme)!;
    expect(snippet).toMatch(/interval:\s*["']?daily["']?/);
  });

  it("does NOT recommend weekly, the interval that measurably froze a pin", () => {
    const snippet = consumerDependabotSnippet(readme)!;
    // The negative direction is the one that actually regressed, so it is
    // asserted separately rather than inferred from the positive match.
    expect(snippet).not.toMatch(/interval:\s*["']?weekly["']?/);
  });

  it("does not claim a stale exact pin announces itself", () => {
    // The scanner runs offline against the IOC feed bundled with the pinned
    // version. Nothing in the exit code, risk score or check name reports the
    // pin's age, so the README must not promise that it does.
    expect(flat(readme)).toMatch(
      /exact pin is what turns that into a reviewable out-of-date dependency/,
    );
    expect(flat(readme)).not.toMatch(
      /exact pin turns that into a visible out-of-date dependency/,
    );
  });

  it("names no consumer repository while citing the measurement", () => {
    // Same rule as the consumer-repo-disclosure gate: counts, never names.
    // Asserted here too because this test's own docblock cites the measurement.
    const self = read("src/__tests__/consumer-update-path-contract.test.ts");
    for (const text of [readme, self]) {
      expect(text).not.toMatch(/elvatis[/-][A-Za-z0-9]/);
    }
  });
});
