import { describe, expect, it } from "vitest";
import { hasBroadUnboundedConsumingGap } from "../regex-complexity.js";

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
