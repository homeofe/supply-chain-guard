/**
 * The rule set in use reports its own age.
 *
 * `scan` matches offline against the feed bundled with the installed version,
 * so a version pin that stops moving freezes detection at that release's date
 * while every scan keeps returning a green check. These tests assert the
 * CONSEQUENCE in both directions: a stale rule set reaches the report as a
 * finding, and a current one does not - plus the three ways a staleness check
 * can quietly stop firing (a future date, an unparseable date, no date at all).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { FeedIOC } from "../threat-intel.js";

// Lets the integration cases below choose what loadThreatIntel() returns.
// null means "defer to the real bundled feed".
const mockState = vi.hoisted(() => ({ feedOverride: null as FeedIOC[] | null }));

vi.mock("../threat-intel.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../threat-intel.js")>();
  return {
    ...actual,
    loadThreatIntel: (...args: Parameters<typeof actual.loadThreatIntel>) =>
      mockState.feedOverride ?? actual.loadThreatIntel(...args),
  };
});

import {
  feedFreshness,
  feedStalenessFindings,
  FEED_STALE_AFTER_DAYS,
  FEED_STALE_RULE,
} from "../feed.js";

/** Fixed reference instant so every case is deterministic. */
const NOW = Date.UTC(2026, 7, 22); // 2026-08-22

/** Synthetic indicator on the reserved .example TLD - never a real IOC. */
function ioc(firstSeen?: string | number | null): FeedIOC {
  const entry: Record<string, unknown> = {
    type: "domain",
    value: `fixture-${String(firstSeen)}.example`,
    severity: "critical",
    confidence: 1.0,
  };
  if (firstSeen !== undefined) entry.firstSeen = firstSeen;
  return entry as unknown as FeedIOC;
}

/** `days` before NOW, as a YYYY-MM-DD string. */
function daysAgo(days: number): string {
  return new Date(NOW - days * 86_400_000).toISOString().slice(0, 10);
}

describe("feedFreshness", () => {
  it("reports the newest indicator's age, not the oldest or the average", () => {
    const result = feedFreshness(
      [ioc(daysAgo(400)), ioc(daysAgo(7)), ioc(daysAgo(120))],
      NOW,
    );
    expect(result.newestIndicator).toBe(daysAgo(7));
    expect(result.ageDays).toBe(7);
    expect(result.datedEntries).toBe(3);
    expect(result.stale).toBe(false);
  });

  it("is not stale at exactly the threshold and is stale one day past it", () => {
    expect(feedFreshness([ioc(daysAgo(FEED_STALE_AFTER_DAYS))], NOW).stale).toBe(false);
    expect(feedFreshness([ioc(daysAgo(FEED_STALE_AFTER_DAYS + 1))], NOW).stale).toBe(true);
  });

  it("ignores a future-dated indicator instead of letting it fake currency", () => {
    // One mistyped year in one entry would otherwise make every feed look
    // permanently current - the false negative this check exists to prevent.
    const result = feedFreshness([ioc(daysAgo(365)), ioc("2099-01-01")], NOW);
    expect(result.newestIndicator).toBe(daysAgo(365));
    expect(result.ageDays).toBe(365);
    expect(result.datedEntries).toBe(1);
    expect(result.stale).toBe(true);
  });

  it("ignores dates that are malformed or that do not round-trip", () => {
    // 2026-02-31 parses through Date.UTC and silently rolls into March. Taking
    // it at face value would advance the newest-indicator date past every real
    // entry, so it has to be rejected rather than normalized.
    const result = feedFreshness(
      [ioc(daysAgo(200)), ioc("2026-02-31"), ioc("not-a-date"), ioc(20260822), ioc(null)],
      NOW,
    );
    expect(result.newestIndicator).toBe(daysAgo(200));
    expect(result.datedEntries).toBe(1);
    expect(result.stale).toBe(true);
  });

  it("treats a feed with no usable date as stale, never as fresh", () => {
    const result = feedFreshness([ioc(), ioc("garbage")], NOW);
    expect(result.newestIndicator).toBeNull();
    expect(result.ageDays).toBeNull();
    expect(result.datedEntries).toBe(0);
    expect(result.stale).toBe(true);
  });

  it("treats an empty feed as stale", () => {
    expect(feedFreshness([], NOW).stale).toBe(true);
  });

  it("can still date the real bundled feed", async () => {
    // Guards the check against silently losing its input: a refactor that drops
    // firstSeen from the bundled entries would leave feedFreshness with nothing
    // to measure, and a staleness check with no measurable input is a check
    // that never fires for the right reason.
    const { getBundledFeed } = await vi.importActual<typeof import("../threat-intel.js")>(
      "../threat-intel.js",
    );
    const result = feedFreshness(getBundledFeed(), NOW);
    expect(result.datedEntries).toBeGreaterThan(1000);
    expect(result.newestIndicator).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(result.ageDays).not.toBeNull();
  });
});

describe("feedStalenessFindings", () => {
  it("emits nothing while the rule set is current", () => {
    expect(feedStalenessFindings(feedFreshness([ioc(daysAgo(1))], NOW))).toEqual([]);
  });

  it("emits one medium finding carrying the measured age", () => {
    const findings = feedStalenessFindings(feedFreshness([ioc(daysAgo(90))], NOW));
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe(FEED_STALE_RULE);
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].description).toContain("90 days old");
    expect(findings[0].description).toContain(daysAgo(90));
    expect(findings[0].recommendation).toContain("feed refresh");
  });

  it("says the age is unknown rather than inventing one", () => {
    const findings = feedStalenessFindings(feedFreshness([ioc()], NOW));
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain("unknown age");
    expect(findings[0].description).not.toContain("NaN");
    expect(findings[0].description).not.toContain("null");
  });
});

describe("scan() surfaces rule-set staleness", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-staleness-"));
    fs.writeFileSync(path.join(dir, "index.js"), "console.log('hello');\n");
  });

  afterEach(() => {
    mockState.feedOverride = null;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("adds the finding and raises the score for a stale rule set, and nothing else", async () => {
    // The point of the whole change: the stale run is the one that used to come
    // back indistinguishable from the current one. Both directions are scanned
    // here against the SAME repository, so the only variable is the feed's age
    // and the delta cannot be anything the repository contributed.
    const { scan } = await import("../scanner.js");

    mockState.feedOverride = [ioc(daysAgo(1))];
    const current = await scan({ target: dir, format: "json", noHistory: true });

    mockState.feedOverride = [ioc(daysAgo(400))];
    const stale = await scan({ target: dir, format: "json", noHistory: true });

    expect(current.findings.filter((f) => f.rule === FEED_STALE_RULE)).toHaveLength(0);

    const reported = stale.findings.filter((f) => f.rule === FEED_STALE_RULE);
    expect(reported).toHaveLength(1);
    expect(reported[0].severity).toBe("medium");
    expect(reported[0].description).toContain("400 days old");

    // The report visibly changes: score up, risk level off whatever the clean
    // run reported. Without that, the finding would exist and still be invisible
    // to a gate reading only the score.
    expect(stale.score).toBeGreaterThan(current.score);

    // No other rule appears or disappears because of the feed's age.
    const rules = (r: typeof stale): string[] =>
      [...new Set(r.findings.map((f) => f.rule))].sort();
    expect(rules(stale).filter((r) => r !== FEED_STALE_RULE)).toEqual(rules(current));
  });

  it("honours the documented escape hatch for a deliberately frozen rule set", async () => {
    mockState.feedOverride = [ioc(daysAgo(400))];
    const { scan } = await import("../scanner.js");
    const report = await scan({
      target: dir,
      format: "json",
      noHistory: true,
      excludeRules: [FEED_STALE_RULE],
    });

    expect(report.findings.filter((f) => f.rule === FEED_STALE_RULE)).toHaveLength(0);
  });
});
