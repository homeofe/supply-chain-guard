import { describe, it, expect } from "vitest";
import { generateRemediations, generateFixSuggestions } from "../remediation-engine.js";
import type { Finding } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" = "high", match?: string, file?: string): Finding {
  return { rule, description: "test", severity, recommendation: "test", match, file };
}

describe("Remediation Engine", () => {
  it("should generate remediation for install hook network", () => {
    const rems = generateRemediations([makeFinding("INSTALL_HOOK_NETWORK", "critical")]);
    expect(rems.length).toBeGreaterThan(0);
    expect(rems[0].priority).toBe("critical");
    expect(rems[0].steps.length).toBeGreaterThan(0);
  });

  it("should generate remediation for unpinned action", () => {
    const rems = generateRemediations([makeFinding("GHA_UNPINNED_ACTION")]);
    expect(rems.some((r) => r.title.includes("Pin"))).toBe(true);
    expect(rems[0].automated).toBe(true);
  });

  it("should generate remediation for exposed secrets", () => {
    const rems = generateRemediations([makeFinding("SECRETS_AWS_KEY", "critical")]);
    expect(rems.some((r) => r.category === "secret")).toBe(true);
    expect(rems[0].steps.some((s) => s.includes("Rotate") || s.includes("Deactivate"))).toBe(true);
  });

  it("should deduplicate remediations by rule", () => {
    const rems = generateRemediations([
      makeFinding("IOC_KNOWN_BAD_VERSION", "critical"),
      makeFinding("IOC_KNOWN_BAD_VERSION", "critical"),
    ]);
    expect(rems).toHaveLength(1);
  });

  it("should sort by priority", () => {
    const rems = generateRemediations([
      makeFinding("GHA_UNPINNED_ACTION"),
      makeFinding("IOC_KNOWN_BAD_VERSION", "critical"),
    ]);
    expect(rems[0].priority).toBe("critical");
  });

  it("should return empty for unknown rules", () => {
    const rems = generateRemediations([makeFinding("UNKNOWN_RULE")]);
    expect(rems).toHaveLength(0);
  });

  it("should include risk reduction scores", () => {
    const rems = generateRemediations([makeFinding("INSTALL_HOOK_DOWNLOAD_EXEC", "critical")]);
    expect(rems[0].riskReduction).toBeGreaterThan(0);
  });
});

describe("Fix Suggestions", () => {
  it("should suggest fix for unpinned action", () => {
    const fixes = generateFixSuggestions([
      makeFinding("GHA_UNPINNED_ACTION", "high", "uses: actions/checkout@main", ".github/workflows/ci.yml"),
    ]);
    expect(fixes.length).toBeGreaterThan(0);
    expect(fixes[0].changeType).toBe("replace");
    expect(fixes[0].after).toContain("@<commit-sha>");
  });

  it("should suggest fix for HTTP registry", () => {
    const fixes = generateFixSuggestions([
      makeFinding("CONFIG_HTTP_REGISTRY", "critical", "registry=http://evil.com", ".npmrc"),
    ]);
    expect(fixes.length).toBeGreaterThan(0);
    expect(fixes[0].after).toContain("https://");
  });

  it("should return empty for non-automatable rules", () => {
    const fixes = generateFixSuggestions([makeFinding("EVAL_ATOB", "critical")]);
    expect(fixes).toHaveLength(0);
  });
});
