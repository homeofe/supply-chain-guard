import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { applyPolicy, applyBaseline, saveBaseline, loadPolicyConfig, applyInlineSuppressions, matchGlob } from "../policy-engine.js";
import type { Finding, PolicyConfig } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" | "medium" = "high", file?: string): Finding {
  return { rule, description: `Finding: ${rule}`, severity, file, recommendation: "Fix it" };
}

describe("Policy Engine", () => {
  describe("applyPolicy", () => {
    it("should disable specified rules", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical"), makeFinding("HEX_ARRAY", "medium")];
      const policy: PolicyConfig = { rules: { disable: ["HEX_ARRAY"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].rule).toBe("EVAL_ATOB");
      expect(result.suppressedCount).toBe(1);
    });

    it("should override severity", () => {
      const findings = [makeFinding("GHA_UNPINNED_ACTION", "high")];
      const policy: PolicyConfig = { rules: { severityOverrides: { GHA_UNPINNED_ACTION: "medium" } } };
      const result = applyPolicy(findings, policy);
      expect(result.findings[0].severity).toBe("medium");
    });

    it("should suppress specified rules", () => {
      const findings = [makeFinding("RELEASE_EXE_ARTIFACT", "critical")];
      const policy: PolicyConfig = { suppress: [{ rule: "RELEASE_EXE_ARTIFACT", reason: "Legit installer" }] };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(0);
      expect(result.suppressedCount).toBe(1);
    });

    it("should allowlist packages for typosquat checks", () => {
      const findings = [{ ...makeFinding("TYPOSQUAT_LEVENSHTEIN"), description: 'Dependency "internal-utils" is...' }];
      const policy: PolicyConfig = { allowlist: { packages: ["internal-utils"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(0);
    });

    // ── allowlist.domains (previously parsed but never read) ──────────────────
    it("should suppress a THREAT_INTEL_MATCH for an allowlisted domain (subdomain-of)", () => {
      const findings = [
        {
          ...makeFinding("THREAT_INTEL_MATCH", "critical"),
          description: 'Threat intelligence match: domain "rti.cargomanbd.com" (Vidar)',
        },
      ];
      const policy: PolicyConfig = { allowlist: { domains: ["cargomanbd.com"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(0);
      expect(result.suppressedCount).toBe(1);
    });

    it("should still fire a THREAT_INTEL_MATCH for a non-allowlisted domain", () => {
      const findings = [
        {
          ...makeFinding("THREAT_INTEL_MATCH", "critical"),
          description: 'Threat intelligence match: domain "totally-other-evil.com"',
        },
      ];
      const policy: PolicyConfig = { allowlist: { domains: ["cargomanbd.com"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(1);
      expect(result.suppressedCount).toBe(0);
    });

    it("should suppress an IOC_KNOWN_C2_DOMAIN for an exact allowlisted host", () => {
      const findings = [
        {
          ...makeFinding("IOC_KNOWN_C2_DOMAIN", "critical"),
          description: "Known malicious C2 domain detected: internal.example.com",
        },
      ];
      const policy: PolicyConfig = { allowlist: { domains: ["internal.example.com"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(0);
    });

    it("should not let a domain allowlist touch unrelated rules", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical")];
      const policy: PolicyConfig = { allowlist: { domains: ["cargomanbd.com"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(1);
    });

    // ── per-path suppress (rule + optional path glob) ─────────────────────────
    it("should suppress a rule only under a matching path glob", () => {
      const policy: PolicyConfig = {
        suppress: [{ rule: "EVAL_ATOB", reason: "vendored code", path: "vendor/**" }],
      };
      const underPath = applyPolicy([makeFinding("EVAL_ATOB", "critical", "vendor/lib/a.js")], policy);
      expect(underPath.findings).toHaveLength(0);
      expect(underPath.suppressedCount).toBe(1);

      const outsidePath = applyPolicy([makeFinding("EVAL_ATOB", "critical", "src/a.js")], policy);
      expect(outsidePath.findings).toHaveLength(1);
      expect(outsidePath.suppressedCount).toBe(0);
    });

    it("should keep a bare suppress entry (no path) global", () => {
      const policy: PolicyConfig = { suppress: [{ rule: "EVAL_ATOB", reason: "accepted" }] };
      const result = applyPolicy([makeFinding("EVAL_ATOB", "critical", "any/where.js")], policy);
      expect(result.findings).toHaveLength(0);
      expect(result.suppressedCount).toBe(1);
    });
  });

  describe("matchGlob", () => {
    it("matches * within a single path segment only", () => {
      expect(matchGlob("*.min.js", "app.min.js")).toBe(true);
      expect(matchGlob("*.min.js", "src/app.min.js")).toBe(false);
    });

    it("matches ** across path separators", () => {
      expect(matchGlob("**/*.min.js", "src/vendor/app.min.js")).toBe(true);
      expect(matchGlob("vendor/**", "vendor/deep/lib.js")).toBe(true);
      expect(matchGlob("vendor/**", "src/lib.js")).toBe(false);
    });

    it("anchors the whole path", () => {
      expect(matchGlob("src/a.js", "src/a.js")).toBe(true);
      expect(matchGlob("src/a.js", "x/src/a.js")).toBe(false);
    });

    it("requires a segment boundary after **/ (no lookalike over-match)", () => {
      // v5.14.0 gate: "**/" must not over-match a basename that merely ends
      // with the literal, or ignore:/suppress-path silently hide real findings.
      expect(matchGlob("**/vendor.js", "vendor.js")).toBe(true);
      expect(matchGlob("**/vendor.js", "a/b/vendor.js")).toBe(true);
      expect(matchGlob("**/vendor.js", "notvendor.js")).toBe(false);
      expect(matchGlob("**/vendor.js", "myvendor.js")).toBe(false);
      expect(matchGlob("**/test.js", "latest.js")).toBe(false);
    });
  });

  describe("applyInlineSuppressions", () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-inline-"));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("suppresses the finding on the line directly below the directive but not others", () => {
      fs.writeFileSync(
        path.join(tmpDir, "app.js"),
        [
          'const a = 1;',                       // line 1
          '// scg-ignore-next-line EVAL_ATOB accepted', // line 2
          'eval(atob("x"));',                   // line 3 (suppressed)
          'eval(atob("y"));',                   // line 4 (not suppressed)
        ].join("\n"),
      );
      const findings = [
        { ...makeFinding("EVAL_ATOB", "critical", "app.js"), line: 3 },
        { ...makeFinding("EVAL_ATOB", "critical", "app.js"), line: 4 },
      ];
      const result = applyInlineSuppressions(findings, tmpDir);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].line).toBe(4);
      expect(result.suppressedCount).toBe(1);
    });

    it("supports the # comment form and only suppresses the named rule", () => {
      fs.writeFileSync(
        path.join(tmpDir, "conf.yml"),
        ["# scg-ignore-next-line HARDCODED_SECRET", "token: abc"].join("\n"),
      );
      const wrongRule = applyInlineSuppressions(
        [{ ...makeFinding("EVAL_ATOB", "high", "conf.yml"), line: 2 }],
        tmpDir,
      );
      expect(wrongRule.findings).toHaveLength(1); // directive names a different rule

      const rightRule = applyInlineSuppressions(
        [{ ...makeFinding("HARDCODED_SECRET", "high", "conf.yml"), line: 2 }],
        tmpDir,
      );
      expect(rightRule.findings).toHaveLength(0);
      expect(rightRule.suppressedCount).toBe(1);
    });

    it("passes findings through when the file cannot be read", () => {
      const result = applyInlineSuppressions(
        [{ ...makeFinding("EVAL_ATOB", "high", "does-not-exist.js"), line: 5 }],
        tmpDir,
      );
      expect(result.findings).toHaveLength(1);
    });

    it("should pass through findings with no matching policy", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical")];
      const policy: PolicyConfig = { rules: { disable: ["UNRELATED_RULE"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(1);
    });

    it("should handle empty policy", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical")];
      const result = applyPolicy(findings, {});
      expect(result.findings).toHaveLength(1);
      expect(result.suppressedCount).toBe(0);
    });
  });

  describe("Baseline system", () => {
    let tmpDir: string;
    let baselinePath: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(process.env.TEMP ?? "/tmp", "scg-bl-"));
      baselinePath = path.join(tmpDir, ".scg-baseline.json");
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("should save baseline", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical", "src/index.js")];
      saveBaseline(findings, baselinePath);
      expect(fs.existsSync(baselinePath)).toBe(true);
      const saved = JSON.parse(fs.readFileSync(baselinePath, "utf-8"));
      expect(saved).toHaveLength(1);
      expect(saved[0].rule).toBe("EVAL_ATOB");
    });

    it("should filter out baseline findings", () => {
      const findings = [
        makeFinding("EVAL_ATOB", "critical", "src/index.js"),
        makeFinding("HEX_ARRAY", "medium", "src/data.js"),
      ];
      saveBaseline(findings, baselinePath);

      const newFindings = [
        makeFinding("EVAL_ATOB", "critical", "src/index.js"), // in baseline
        makeFinding("NEW_RULE", "high", "src/new.js"),        // not in baseline
      ];
      const result = applyBaseline(newFindings, baselinePath);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].rule).toBe("NEW_RULE");
      expect(result.suppressedCount).toBe(1);
    });

    it("should return all findings when no baseline exists", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical")];
      const result = applyBaseline(findings, "/nonexistent/path");
      expect(result.findings).toHaveLength(1);
      expect(result.suppressedCount).toBe(0);
    });
  });

  describe("loadPolicyConfig", () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(process.env.TEMP ?? "/tmp", "scg-cfg-"));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("should load .supply-chain-guard.yml", () => {
      fs.writeFileSync(path.join(tmpDir, ".supply-chain-guard.yml"), [
        "rules:",
        "  disable:",
        "    - HEX_ARRAY",
        "    - CHARCODE_OBFUSCATION",
        "  severityOverrides:",
        "    GHA_UNPINNED_ACTION: medium",
        "allowlist:",
        "  packages:",
        "    - internal-utils",
      ].join("\n"));

      const config = loadPolicyConfig(tmpDir);
      expect(config).not.toBeNull();
      expect(config!.rules?.disable).toContain("HEX_ARRAY");
      expect(config!.rules?.severityOverrides?.GHA_UNPINNED_ACTION).toBe("medium");
      expect(config!.allowlist?.packages).toContain("internal-utils");
    });

    it("should return null when no config exists", () => {
      expect(loadPolicyConfig(tmpDir)).toBeNull();
    });

    it("should parse ignore globs and per-path suppress, stripping quotes", () => {
      fs.writeFileSync(path.join(tmpDir, ".supply-chain-guard.yml"), [
        "ignore:",
        "  - vendor/**",
        '  - "**/*.min.js"',
        "suppress:",
        "  - rule: EVAL_ATOB",
        "    reason: vendored",
        "    path: vendor/**",
      ].join("\n"));

      const config = loadPolicyConfig(tmpDir);
      expect(config).not.toBeNull();
      expect(config!.ignore).toEqual(["vendor/**", "**/*.min.js"]);
      expect(config!.suppress?.[0]).toMatchObject({ rule: "EVAL_ATOB", path: "vendor/**" });
      // Quoted glob must have its quotes stripped so it actually matches.
      expect(matchGlob(config!.ignore![1], "src/app.min.js")).toBe(true);
      expect(config!.warnings).toBeUndefined();
    });
  });

  describe("Fail-closed config validation (v5.3)", () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-val-"));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    function loadConfig(lines: string[]): PolicyConfig {
      fs.writeFileSync(path.join(tmpDir, ".supply-chain-guard.yml"), lines.join("\n"));
      const config = loadPolicyConfig(tmpDir);
      expect(config).not.toBeNull();
      return config!;
    }

    it("should flag a typo'd top-level section (supress:) as POLICY_UNKNOWN_KEY", () => {
      const config = loadConfig([
        "supress:",
        "  - rule: EVAL_ATOB",
        "    reason: reviewed and accepted",
      ]);
      const warnings = config.warnings ?? [];
      expect(warnings.some((w) => w.rule === "POLICY_UNKNOWN_KEY" && w.message.includes('"supress"'))).toBe(true);
      // The fail-open condition the warning is about: nothing was suppressed
      expect(config.suppress).toBeUndefined();
    });

    it("should convert warnings into high-severity findings via applyPolicy", () => {
      const config = loadConfig(["supress:", "  - rule: EVAL_ATOB"]);
      const result = applyPolicy([makeFinding("EVAL_ATOB", "critical")], config);
      // Original finding stays (the typo'd suppression must NOT apply)...
      expect(result.findings.some((f) => f.rule === "EVAL_ATOB")).toBe(true);
      // ...and the broken config is reported as a finding
      const policyFinding = result.findings.find((f) => f.rule === "POLICY_UNKNOWN_KEY");
      expect(policyFinding).toBeDefined();
      expect(policyFinding!.severity).toBe("high");
      expect(policyFinding!.category).toBe("config");
      expect(policyFinding!.confidence).toBeGreaterThan(0);
      expect(policyFinding!.file).toBe(".supply-chain-guard.yml");
      expect(policyFinding!.line).toBe(1);
      expect(result.suppressedCount).toBe(0);
    });

    it("should flag an unknown key inside a suppress entry", () => {
      const config = loadConfig([
        "suppress:",
        "  - rule: EVAL_ATOB",
        "    reason: reviewed and accepted",
        "    owner: someone",
      ]);
      const warnings = config.warnings ?? [];
      expect(warnings.some((w) => w.rule === "POLICY_UNKNOWN_KEY" && w.message.includes('"owner"'))).toBe(true);
      // The entry itself is still parsed
      expect(config.suppress).toHaveLength(1);
      expect(config.suppress![0].rule).toBe("EVAL_ATOB");
      // A documented reason exists, so no POLICY_SUPPRESSION_NO_REASON
      expect(warnings.some((w) => w.rule === "POLICY_SUPPRESSION_NO_REASON")).toBe(false);
    });

    it("should flag an unknown subsection under rules", () => {
      const config = loadConfig(["rules:", "  disble:", "    - HEX_ARRAY"]);
      const warnings = config.warnings ?? [];
      expect(warnings.some((w) => w.rule === "POLICY_UNKNOWN_KEY" && w.message.includes('"disble"'))).toBe(true);
      expect(config.rules?.disable).toBeUndefined();
    });

    it("should flag a suppress entry with a missing reason", () => {
      const config = loadConfig(["suppress:", "  - rule: EVAL_ATOB"]);
      const warnings = config.warnings ?? [];
      expect(warnings.some((w) => w.rule === "POLICY_SUPPRESSION_NO_REASON")).toBe(true);
      const result = applyPolicy([], config);
      const finding = result.findings.find((f) => f.rule === "POLICY_SUPPRESSION_NO_REASON");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("medium");
      expect(finding!.category).toBe("config");
    });

    it("should flag a suppress entry with an empty reason", () => {
      const config = loadConfig(["suppress:", "  - rule: EVAL_ATOB", "    reason:"]);
      const warnings = config.warnings ?? [];
      expect(warnings.some((w) => w.rule === "POLICY_SUPPRESSION_NO_REASON")).toBe(true);
    });

    it("should flag a malformed suppress rule id (not SCREAMING_SNAKE_CASE)", () => {
      const config = loadConfig([
        "suppress:",
        "  - rule: eval-atob",
        "    reason: reviewed and accepted",
      ]);
      const warnings = config.warnings ?? [];
      expect(warnings.some((w) => w.rule === "POLICY_MALFORMED_RULE_ID" && w.message.includes('"eval-atob"'))).toBe(true);
    });

    it("should not flag a well-formed suppress rule id", () => {
      const config = loadConfig([
        "suppress:",
        "  - rule: GHA_UNPINNED_ACTION",
        "    reason: reviewed and accepted",
      ]);
      expect((config.warnings ?? []).some((w) => w.rule === "POLICY_MALFORMED_RULE_ID")).toBe(false);
    });

    it("should produce zero warnings and zero policy findings for a valid config", () => {
      const config = loadConfig([
        "rules:",
        "  disable:",
        "    - HEX_ARRAY",
        "  severityOverrides:",
        "    GHA_UNPINNED_ACTION: medium",
        "allowlist:",
        "  packages:",
        "    - internal-utils",
        "  domains:",
        "    - registry.internal",
        "  githubOrgs:",
        "    - homeofe",
        "suppress:",
        "  - rule: RELEASE_EXE_ARTIFACT",
        "    reason: legit installer artifact",
        "baseline:",
        "  file: .scg-baseline.json",
      ]);
      expect(config.warnings).toBeUndefined();
      const result = applyPolicy([makeFinding("EVAL_ATOB", "critical")], config);
      expect(result.findings.some((f) => f.rule.startsWith("POLICY_"))).toBe(false);
    });

    it("should tolerate a leading yaml-language-server schema comment", () => {
      const config = loadConfig([
        "# yaml-language-server: $schema=./policy-schema.json",
        "suppress:",
        "  - rule: RELEASE_EXE_ARTIFACT",
        "    reason: legit installer artifact",
      ]);
      expect(config.warnings).toBeUndefined();
      expect(config.suppress).toHaveLength(1);
      expect(config.suppress![0].rule).toBe("RELEASE_EXE_ARTIFACT");
      expect(config.suppress![0].reason).toBe("legit installer artifact");
    });

    it("should not allow the config to suppress its own validation findings", () => {
      const config = loadConfig([
        "supress:",
        "  - rule: EVAL_ATOB",
        "suppress:",
        "  - rule: POLICY_UNKNOWN_KEY",
        "    reason: trying to silence the validator",
      ]);
      const result = applyPolicy([], config);
      // Fail-closed: the diagnosis is still reported
      expect(result.findings.some((f) => f.rule === "POLICY_UNKNOWN_KEY")).toBe(true);
    });

    it("repo's own .supply-chain-guard.yml should validate clean against the parser", () => {
      const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
      const config = loadPolicyConfig(repoRoot);
      expect(config).not.toBeNull();
      expect(config!.warnings).toBeUndefined();
      expect(config!.suppress!.length).toBeGreaterThan(0);
      // The schema referenced by the leading comment exists and is strict
      const schemaPath = path.join(repoRoot, "policy-schema.json");
      const schema = JSON.parse(fs.readFileSync(schemaPath, "utf-8"));
      expect(schema.$schema).toContain("draft-07");
      expect(schema.additionalProperties).toBe(false);
    });
  });
});
