import { describe, expect, it } from "vitest";
import {
  hasBroadUnboundedConsumingGap,
  hasNestedUnboundedQuantifier,
} from "../regex-complexity.js";

describe("hasBroadUnboundedConsumingGap", () => {
  it.each([
    /prefix.*suffix/.source,
    /prefix.+?suffix/.source,
    /(?:left|right).*?(?:end|stop)/.source,
    /foo|bar.+baz/.source,
    /(?=.*token)anchored/.source,
  ])("recognizes unescaped wildcard gaps in %s", (source) => {
    expect(hasBroadUnboundedConsumingGap(source)).toBe(true);
  });

  it.each([
    /[^/]*\/package/.source,
    /[^\r\n]+?/.source,
    /[^]*/.source,
    /prefix[^"]+suffix/.source,
  ])("recognizes quantified negated classes in %s", (source) => {
    expect(hasBroadUnboundedConsumingGap(source)).toBe(true);
  });

  it.each([
    /[\s\S]*/.source,
    /[\S\s]+?/.source,
    /[\d\D]+/.source,
    /[\w\W]*?/.source,
    /[a\s\S]*/.source,
  ])("recognizes quantified universal classes in %s", (source) => {
    expect(hasBroadUnboundedConsumingGap(source)).toBe(true);
  });

  it.each([
    /prefix.{0,}suffix/.source,
    /prefix.{1,}?suffix/.source,
    /prefix[^/]{2,}suffix/.source,
    /prefix[\s\S]{0,}suffix/.source,
  ])("recognizes open-ended brace quantifiers in %s", (source) => {
    expect(hasBroadUnboundedConsumingGap(source)).toBe(true);
  });

  it.each([
    /(?:.)*suffix/.source,
    /(?:[^/])+suffix/.source,
    /(?:[\s\S]){1,}suffix/.source,
    /(?:\s|\S)*suffix/.source,
    /(?:.|\n)+suffix/.source,
  ])("recognizes equivalent unbounded group wrappers in %s", (source) => {
    expect(hasBroadUnboundedConsumingGap(source)).toBe(true);
  });

  it.each([
    "",
    /plain-text/.source,
    /foo|bar/.source,
    /literal\.\*text/.source,
    /(?=\.\*)literal/.source,
    /[.*+?]+/.source,
    /[a*+?]/.source,
    /[\^]+/.source,
    /[^/]/.source,
    /[\s\S]{0,100}/.source,
    /(?:.){0,100}/.source,
    /(?:\s|\S){3}/.source,
    /(?:foo|bar)*/.source,
    /[\sS]*/.source,
    String.raw`\[\\s\\S\]\*`,
    String.raw`[\\s\\S]*`,
  ])("ignores non-gap and escaped/class-contained syntax in %s", (source) => {
    expect(hasBroadUnboundedConsumingGap(source)).toBe(false);
  });

  it("uses escape parity rather than treating every preceded dot as escaped", () => {
    expect(hasBroadUnboundedConsumingGap(String.raw`\.\*`)).toBe(false);
    expect(hasBroadUnboundedConsumingGap(String.raw`\\.*`)).toBe(true);
  });
});

describe("hasNestedUnboundedQuantifier", () => {
  it.each([
    "(a+)+$",
    "(a*)*b",
    "(a?)+b",
    "(x+x+)+y",
    "([a-z]+)*end",
    "(?:\\d+)+tail",
    "prefix(?:[0-9]{2,4})*suffix",
    "outer((inner+))+",
  ])("refuses the exponential shape in %s", (source) => {
    expect(hasNestedUnboundedQuantifier(source)).toBe(true);
  });

  it.each([
    "build-\\d{2}\\.corp",
    "(alpha|beta)+",
    "(a{2})+",
    "\\w+\\.internal\\.example",
    "(?:alpha|beta)\\d{4}",
    "sample-service-\\d+",
    "\\(a+\\)+",
    "[+*?]+",
    "(?<label>alpha|beta)*",
  ])("accepts the ordinary deny-list shape in %s", (source) => {
    expect(hasNestedUnboundedQuantifier(source)).toBe(false);
  });

  it("does not read the group-prefix question mark as an inner quantifier", () => {
    // "(?:" opens a non-capturing group. Treating its "?" as a quantifier
    // would refuse every grouped alternation anyone writes.
    expect(hasNestedUnboundedQuantifier("(?:alpha)+")).toBe(false);
    expect(hasNestedUnboundedQuantifier("(?:alpha?)+")).toBe(true);
  });

  it("separates a fixed repetition from a variable one", () => {
    // "{2}" matches exactly twice, so an outer quantifier has nothing to
    // explore; "{2,3}" gives it a choice on every repetition.
    expect(hasNestedUnboundedQuantifier("(a{2})*")).toBe(false);
    expect(hasNestedUnboundedQuantifier("(a{2,3})*")).toBe(true);
  });
});

/**
 * The classifier is wrong in two directions, and both are load-bearing for its
 * callers, so both are pinned here rather than left in a doc comment. A
 * refusal is a visible finding an author can act on; an acceptance is NOT a
 * certificate that the source is safe to run.
 *
 * If a change to `hasNestedUnboundedQuantifier` flips one of these, that is
 * good news, not a broken test. Move the case to the block above, and update
 * the doc comment, the README and the CHANGELOG in the same commit, because
 * all three currently state these limits to consumers.
 */
describe("hasNestedUnboundedQuantifier: the limits it is documented to have", () => {
  it.each([
    // Ambiguity from overlapping alternation, which a scan of the source
    // cannot see. Each of these is catastrophic and each is accepted.
    "(a|a)+$",
    "(a|ab)+$",
    String.raw`(\d|\d\d)+$`,
    // A bounded outer repetition: "{2,30}" is not read as unbounded.
    "(a+){2,30}$",
  ])("under-rejects %s, so a false answer is not a time bound", (source) => {
    expect(hasNestedUnboundedQuantifier(source)).toBe(false);
  });

  it.each([
    // The ordinary way to write an internal hostname or path prefix. Linear in
    // practice, because the inner class cannot match the separator that
    // follows it, and refused anyway.
    String.raw`(?:[a-z0-9-]+\.)+corp\.example`,
    String.raw`([a-z0-9-]+\.)+internal`,
    String.raw`(\w+\.)+example\.test`,
    String.raw`(?:[\w-]+/)+deploy\.key`,
  ])("over-rejects the ordinary chain shape %s", (source) => {
    expect(hasNestedUnboundedQuantifier(source)).toBe(true);
  });

  it("accepts the rewrite the refusal steers an author towards", () => {
    // What README.md and the INTERNAL_DENYLIST_REFUSED recommendation offer in
    // place of the refused chain shape. If this ever starts failing, both of
    // those documents are wrong and consumers have no working rewrite.
    expect(hasNestedUnboundedQuantifier(String.raw`[a-z0-9.-]+\.corp\.example`)).toBe(false);
  });
});
