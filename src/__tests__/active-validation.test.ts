import { describe, it, expect } from "vitest";
import { validateFindings, promoteConfidence } from "../active-validation.js";
import type { Finding } from "../types.js";

function makeFinding(rule: string, opts?: Partial<Finding>): Finding {
  return { rule, description: "test", severity: "high", recommendation: "fix", ...opts };
}

describe("Active Validation", () => {
  it("should assign rationale to findings", () => {
    const findings = [makeFinding("EVAL_ATOB")];
    validateFindings(findings);
    expect(findings[0].rationale).toBeTruthy();
  });

  it("should assign evidence to findings", () => {
    const findings = [makeFinding("EVAL_ATOB", { file: "src/index.js", line: 42, match: "eval(atob(" })];
    validateFindings(findings);
    expect(findings[0].evidence).toContain("src/index.js");
  });

  it("should identify confirmed tier for IOC matches", () => {
    const findings = [makeFinding("IOC_KNOWN_C2_DOMAIN")];
    validateFindings(findings);
    expect(findings[0].rationale).toContain("confirmed");
  });

  it("should identify correlated tier for clustered findings", () => {
    const findings = [makeFinding("EVAL_ATOB", { correlationId: "incident-1" })];
    validateFindings(findings);
    expect(findings[0].rationale).toContain("Correlated");
  });

  it("should promote confidence on confirmed validation", () => {
    const f = makeFinding("EVAL_ATOB", { confidence: 0.7 });
    promoteConfidence(f, "confirmed");
    expect(f.confidence).toBeGreaterThan(0.7);
    expect(f.rationale).toContain("VALIDATED");
  });

  it("should reduce confidence on negative validation", () => {
    const f = makeFinding("EVAL_ATOB", { confidence: 0.7 });
    promoteConfidence(f, "negative");
    expect(f.confidence).toBeLessThan(0.7);
    expect(f.rationale).toContain("REDUCED");
  });

  it("should not change confidence on inconclusive", () => {
    const f = makeFinding("EVAL_ATOB", { confidence: 0.7 });
    promoteConfidence(f, "inconclusive");
    expect(f.confidence).toBe(0.7);
  });
});
