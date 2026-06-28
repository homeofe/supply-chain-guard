import { describe, it, expect } from "vitest";
import { analyzeOrgFindings, listOrgRepos } from "../org-scanner.js";
import type { Finding } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" = "high"): Finding {
  return { rule, description: "test", severity, recommendation: "test" };
}

describe("Org Scanner", () => {
  it("should detect shared malicious patterns across repos", () => {
    const repoFindings = new Map<string, Finding[]>();
    repoFindings.set("repo1", [makeFinding("EVAL_ATOB", "critical")]);
    repoFindings.set("repo2", [makeFinding("EVAL_ATOB", "critical")]);
    repoFindings.set("repo3", [makeFinding("EVAL_ATOB", "critical")]);

    const findings = analyzeOrgFindings(repoFindings);
    expect(findings.some((f) => f.rule === "ORG_SHARED_MALICIOUS_PATTERN")).toBe(true);
    expect(findings[0]?.description).toContain("EVAL_ATOB");
    expect(findings[0]?.description).toContain("3 repos");
  });

  it("should not flag patterns in fewer than 3 repos", () => {
    const repoFindings = new Map<string, Finding[]>();
    repoFindings.set("repo1", [makeFinding("EVAL_ATOB", "critical")]);
    repoFindings.set("repo2", [makeFinding("EVAL_ATOB", "critical")]);

    const findings = analyzeOrgFindings(repoFindings);
    expect(findings.some((f) => f.rule === "ORG_SHARED_MALICIOUS_PATTERN")).toBe(false);
  });

  it("should detect cluster anomaly when majority has critical findings", () => {
    const repoFindings = new Map<string, Finding[]>();
    for (let i = 0; i < 15; i++) {
      repoFindings.set(`repo${i}`, i < 10
        ? [makeFinding("EVAL_ATOB", "critical")]
        : [makeFinding("HEX_ARRAY")],
      );
    }

    const findings = analyzeOrgFindings(repoFindings);
    expect(findings.some((f) => f.rule === "ORG_REPO_CLUSTER_ANOMALY")).toBe(true);
  });

  it("should return empty for clean org", () => {
    const repoFindings = new Map<string, Finding[]>();
    repoFindings.set("repo1", []);
    repoFindings.set("repo2", []);

    const findings = analyzeOrgFindings(repoFindings);
    expect(findings).toHaveLength(0);
  });
});

describe("listOrgRepos input validation", () => {
  it("rejects an org with shell metacharacters and does not execute gh", () => {
    // A crafted org must never reach a shell or be read as a flag; the guard
    // returns an empty list before any command runs.
    expect(listOrgRepos("foo; echo pwned")).toEqual([]);
    expect(listOrgRepos("$(touch /tmp/scg-pwned)")).toEqual([]);
    expect(listOrgRepos("a && rm -rf ~")).toEqual([]);
    expect(listOrgRepos("`id`")).toEqual([]);
    expect(listOrgRepos("--flag-injection")).toEqual([]);
  });

  it("rejects an out-of-range limit", () => {
    expect(listOrgRepos("validorg", 0)).toEqual([]);
    expect(listOrgRepos("validorg", 99999)).toEqual([]);
  });
});
