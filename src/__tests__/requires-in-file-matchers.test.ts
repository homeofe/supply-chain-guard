import { describe, expect, it } from "vitest";
import { hasDropperPayloadPreparation } from "../broad-gap-pattern-matchers.js";

const LEGACY_DROPPER_GUARD =
  /\b(?:fetch\s*\(|axios|https?\.(?:get|request)|XMLHttpRequest|node-fetch|curl\s|wget\s|urllib|requests\.|atob\s*\(|powershell)|Buffer\.from\s*\([^)]*base64|chmod/;

describe("structural whole-file requirements", () => {
  it.each([
    "fetch(url)",
    "prefix axios.get(url)",
    "curl https://example.invalid",
    "Buffer.from(encoded, 'base64')",
    "Buffer.from(\nencoded base64",
    "Buffer.from(foo) later base64",
    "xBuffer.from(encoded base64",
    "buffer.from(encoded base64",
    "mychmod",
    "chmod +x payload",
    "nothing suspicious",
  ])("preserves the dropper guard verdict for %j", (content) => {
    expect(hasDropperPayloadPreparation(content)).toBe(
      LEGACY_DROPPER_GUARD.test(content),
    );
  });

  it("handles a 5 MiB repeated Buffer.from prefix without backtracking", () => {
    const content = "Buffer.from(".repeat(Math.ceil((5 * 1024 * 1024) / 12));
    expect(hasDropperPayloadPreparation(content)).toBe(false);
  });
});