/**
 * Issue 168: a policy config in the scanned tree could remove the rule that
 * would have failed the gate, and leave no trace a reader could find.
 * https://github.com/homeofe/supply-chain-guard/issues/168
 *
 * Two independent silences were measured on the commit the issue cites:
 *
 *   rules.disable: [EVAL_ATOB]   critical 1 -> 0, exit 2 -> 0.
 *                                suppressedCount reached 1, but nothing named
 *                                the rule, and the markdown format - the
 *                                Action default and the body of its pull
 *                                request comment - said nothing at all.
 *   ignore: ["app.js"]           critical 1 -> 0, exit 2 -> 0.
 *                                suppressedCount stayed 0, because `ignore`
 *                                prunes files before any rule opens them, so
 *                                all nine output formats were silent.
 *
 * These tests hold the fix for both halves. The `ignore` half is the one that
 * matters most: it is strictly quieter than `rules.disable`, and a fix that
 * covers only `rules.disable` would pass a suite that omitted it while leaving
 * the more severe variant exactly as silent as before.
 *
 * NOT tested here, because it is deliberately unchanged: policy is still read
 * from the scanned tree, so the gate still exits 0 on these fixtures. Making
 * that loud is what this change does; making it impossible is a trust-boundary
 * decision recorded in the issue.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { formatReport } from "../reporter.js";
import { describePolicyEffect, loadPolicyConfig, applyPolicy } from "../policy-engine.js";
import type { Finding, ScanReport } from "../types.js";

/** The payload every fixture trips: a critical EVAL_ATOB finding. */
const PAYLOAD = "function boot(p) { return eval(atob(p)); }\nmodule.exports = { boot };\n";

/** Every format the CLI and the Action can emit. */
const ALL_FORMATS = [
  "text",
  "json",
  "markdown",
  "sarif",
  "sbom",
  "html",
  "badge",
  "gitlab",
  "junit",
] as const;

describe("issue 168: a policy-narrowed scan is never indistinguishable from a clean one", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-issue168-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  /** Write the payload plus a policy config, and scan the result. */
  async function scanWithPolicy(configYaml: string): Promise<ScanReport> {
    fs.writeFileSync(path.join(tempDir, "app.js"), PAYLOAD);
    fs.writeFileSync(path.join(tempDir, ".supply-chain-guard.yml"), configYaml);
    return scan({ target: tempDir, format: "json", noHistory: true });
  }

  // ── The bypass itself is still real, which is what makes the rest matter ──

  it("still removes the critical finding, so the report state is the only warning left", async () => {
    fs.writeFileSync(path.join(tempDir, "app.js"), PAYLOAD);
    const control = await scan({ target: tempDir, format: "json", noHistory: true });
    expect(control.summary.critical).toBe(1);
    expect(control.findings.map((f) => f.rule)).toContain("EVAL_ATOB");
    // No config, so no policy block: its presence always means something was
    // switched off, never "a config file happened to exist".
    expect(control.policyEffect).toBeUndefined();

    const disabled = await scanWithPolicy("rules:\n  disable:\n    - EVAL_ATOB\n");
    expect(disabled.summary.critical).toBe(0);
    expect(disabled.findings.map((f) => f.rule)).not.toContain("EVAL_ATOB");
  });

  // ── Report state: both halves ─────────────────────────────────────────────

  it("names the disabled rule in the report, where only a count used to be", async () => {
    const report = await scanWithPolicy("rules:\n  disable:\n    - EVAL_ATOB\n");

    // Delete `policyEffect,` from the returned object in src/scanner.ts to redden this.
    expect(report.policyEffect).toBeDefined();
    expect(report.policyEffect?.configFile).toBe(".supply-chain-guard.yml");
    expect(report.policyEffect?.disabledRules).toEqual([{ id: "EVAL_ATOB" }]);
    expect(report.policyEffect?.ignoredGlobs).toEqual([]);
  });

  it("names the ignored glob, which never reached suppressedCount at all", async () => {
    const report = await scanWithPolicy('ignore:\n  - "app.js"\n');

    // The measurement that makes this the severe half: the count a reader
    // might have pulled on is still zero, because the file was never opened.
    expect(report.suppressedCount).toBeUndefined();
    expect(report.summary.critical).toBe(0);

    // Delete the `ignoredGlobs` line from describePolicyEffect to redden this.
    expect(report.policyEffect?.ignoredGlobs).toEqual([{ id: "app.js" }]);
    expect(report.policyEffect?.disabledRules).toEqual([]);
  });

  it("carries the written reason when the config supplies one, and no reason when it does not", async () => {
    const withReason = await scanWithPolicy(
      "rules:\n  disable:\n    EVAL_ATOB: vendored bundle, reviewed 2026-08\n",
    );
    expect(withReason.policyEffect?.disabledRules).toEqual([
      { id: "EVAL_ATOB", reason: "vendored bundle, reviewed 2026-08" },
    ]);
    // The mapping form must still DISABLE, not merely document.
    expect(withReason.summary.critical).toBe(0);

    const withoutReason = await scanWithPolicy("rules:\n  disable:\n    - EVAL_ATOB\n");
    expect(withoutReason.policyEffect?.disabledRules[0].reason).toBeUndefined();
  });

  it("does not present the suppress placeholder reason as a written justification", () => {
    // The parser fills every suppress entry with a placeholder before a real
    // `reason:` line can overwrite it. Reporting that placeholder to a reader
    // would make an unaudited suppression read as an audited one.
    fs.writeFileSync(
      path.join(tempDir, ".supply-chain-guard.yml"),
      "suppress:\n  - rule: EVAL_ATOB\n",
    );
    const policy = loadPolicyConfig(tempDir);
    expect(policy?.suppress?.[0].reason).toBe("suppressed by policy");
    expect(describePolicyEffect(policy!)?.suppressedRules).toEqual([{ id: "EVAL_ATOB" }]);
  });

  // ── Every output format, which is the claim the issue actually makes ──────

  it("names the disabled rule in ALL NINE output formats", async () => {
    const report = await scanWithPolicy("rules:\n  disable:\n    - EVAL_ATOB\n");

    for (const format of ALL_FORMATS) {
      const rendered = formatReport(report, format);
      if (format === "badge") {
        // A shield carries one short string; the qualifier is what fits.
        expect(rendered, format).toContain("policy-narrowed");
      } else {
        expect(rendered, format).toContain("EVAL_ATOB");
        expect(rendered.toLowerCase(), format).toContain("policy");
      }
    }
  });

  it("names the ignored path in ALL NINE output formats", async () => {
    // THE MUTATION THAT CATCHES A DECORATIVE FIX. Remove only the `ignore`
    // half of the policy metadata and leave `rules.disable` intact: the test
    // above stays green and this one goes red. If both stay green, the fix has
    // the same blind spot the original code had.
    const report = await scanWithPolicy('ignore:\n  - "app.js"\n');

    for (const format of ALL_FORMATS) {
      const rendered = formatReport(report, format);
      if (format === "badge") {
        expect(rendered, format).toContain("policy-narrowed");
      } else {
        expect(rendered, format).toContain("app.js");
        expect(rendered.toLowerCase(), format).toContain("policy");
      }
    }
  });

  it("puts the disabled rule in the markdown body a pull request reviewer reads", async () => {
    // Asserted on the rendered string rather than on report state, because the
    // markdown report IS the Action's default pull request comment, and it was
    // the format with zero mentions of the word "suppress" before this change.
    const report = await scanWithPolicy("rules:\n  disable:\n    - EVAL_ATOB\n");
    const markdown = formatReport(report, "markdown");

    expect(markdown).toContain("Policy in effect");
    expect(markdown).toContain("EVAL_ATOB");
    // Above the summary, so it cannot be scrolled past.
    expect(markdown.indexOf("Policy in effect")).toBeLessThan(markdown.indexOf("### Summary"));
  });

  it("puts the policy effect in SARIF, where GitHub code scanning reads it", async () => {
    const report = await scanWithPolicy('ignore:\n  - "app.js"\n');
    const sarif = JSON.parse(formatReport(report, "sarif")) as {
      runs: Array<{
        invocations?: Array<{
          executionSuccessful: boolean;
          toolExecutionNotifications: Array<{ message: { text: string } }>;
          properties?: { policyEffect?: { ignoredGlobs: Array<{ id: string }> } };
        }>;
      }>;
    };

    const invocation = sarif.runs[0].invocations?.[0];
    expect(invocation).toBeDefined();
    // A policy-narrowed scan still EXECUTED successfully; only partial coverage
    // sets this false, and that distinction must survive the new notification.
    expect(invocation?.executionSuccessful).toBe(true);
    expect(invocation?.toolExecutionNotifications[0].message.text).toContain("app.js");
    expect(invocation?.properties?.policyEffect?.ignoredGlobs).toEqual([{ id: "app.js" }]);
  });

  // ── Option C: a narrowing without a written reason is a finding ───────────

  it("reports a bare rules.disable entry as POLICY_DISABLE_NO_REASON", async () => {
    const bare = await scanWithPolicy("rules:\n  disable:\n    - EVAL_ATOB\n");
    expect(bare.findings.map((f) => f.rule)).toContain("POLICY_DISABLE_NO_REASON");

    const documented = await scanWithPolicy(
      "rules:\n  disable:\n    EVAL_ATOB: vendored bundle, reviewed 2026-08\n",
    );
    expect(documented.findings.map((f) => f.rule)).not.toContain("POLICY_DISABLE_NO_REASON");
  });

  it("reports a bare ignore entry as POLICY_IGNORE_NO_REASON", async () => {
    const bare = await scanWithPolicy('ignore:\n  - "app.js"\n');
    expect(bare.findings.map((f) => f.rule)).toContain("POLICY_IGNORE_NO_REASON");

    const documented = await scanWithPolicy(
      'ignore:\n  "app.js": generated bundle, scanned at source instead\n',
    );
    expect(documented.findings.map((f) => f.rule)).not.toContain("POLICY_IGNORE_NO_REASON");
    // The documented form must still EXCLUDE the file, or the reason would be
    // buying an exemption the config no longer gets.
    expect(documented.summary.critical).toBe(0);
    expect(documented.policyEffect?.ignoredGlobs).toEqual([
      { id: "app.js", reason: "generated bundle, scanned at source instead" },
    ]);
  });

  it("holds rules.disable to the same bar suppress has met since v5.3", async () => {
    // The contrast the issue leads with: suppress demanded a reason and warned
    // without one; rules.disable demanded nothing while removing findings more
    // completely. Both halves are asserted from the same fixture so neither can
    // pass because of the other.
    const report = await scanWithPolicy(
      "rules:\n  disable:\n    - EVAL_ATOB\nsuppress:\n  - rule: HEX_ARRAY\n",
    );
    const rules = report.findings.map((f) => f.rule);
    expect(rules).toContain("POLICY_DISABLE_NO_REASON");
    expect(rules).toContain("POLICY_SUPPRESSION_NO_REASON");
  });

  // ── The v5.2.40 rule this fix must not break ──────────────────────────────

  it("keeps suppressed FINDINGS out of machine output while surfacing policy METADATA", () => {
    const suppressed: Finding = {
      rule: "SUPPRESSED_RULE",
      description: "policy-suppressed body text",
      severity: "high",
      file: "b.js",
      recommendation: "fix",
      suppressed: true,
    };
    const report: ScanReport = {
      tool: "supply-chain-guard v5.28.1",
      timestamp: "2026-08-22T10:00:00.000Z",
      target: "fixture",
      scanType: "directory",
      durationMs: 1,
      findings: [suppressed],
      summary: { totalFiles: 1, filesScanned: 1, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      score: 0,
      riskLevel: "clean",
      recommendations: [],
      policyEffect: {
        configFile: ".supply-chain-guard.yml",
        disabledRules: [],
        ignoredGlobs: [],
        suppressedRules: [{ id: "SUPPRESSED_RULE", reason: "reviewed tradeoff" }],
      },
    };

    for (const format of ["sarif", "sbom", "gitlab"] as const) {
      const rendered = formatReport(report, format);
      // The policy block names the rule...
      expect(rendered, format).toContain("SUPPRESSED_RULE");
      // ...but the suppressed finding's own body never enters the document.
      expect(rendered, format).not.toContain("policy-suppressed body text");
    }
  });

  // ── The parser change, isolated from the scanner ──────────────────────────

  it("accepts both the list and the mapping form for disable and ignore", () => {
    fs.writeFileSync(
      path.join(tempDir, ".supply-chain-guard.yml"),
      [
        "rules:",
        "  disable:",
        "    - HEX_ARRAY",
        "    EVAL_ATOB: reviewed, vendored",
        "ignore:",
        '  - "dist/**"',
        '  "vendor/**": upstream code',
        "",
      ].join("\n"),
    );
    const policy = loadPolicyConfig(tempDir);

    expect(policy?.rules?.disable).toEqual(["HEX_ARRAY", "EVAL_ATOB"]);
    expect(policy?.rules?.disableReasons).toEqual({ EVAL_ATOB: "reviewed, vendored" });
    expect(policy?.ignore).toEqual(["dist/**", "vendor/**"]);
    expect(policy?.ignoreReasons).toEqual({ "vendor/**": "upstream code" });

    // Both forms must actually disable, not merely parse.
    const findings: Finding[] = [
      { rule: "HEX_ARRAY", description: "a", severity: "medium", recommendation: "fix" },
      { rule: "EVAL_ATOB", description: "b", severity: "critical", recommendation: "fix" },
    ];
    const applied = applyPolicy(findings, policy!);
    expect(applied.findings.filter((f) => !f.rule.startsWith("POLICY_"))).toHaveLength(0);

    // Exactly one no-reason warning: the bare list entry in each section.
    const warned = (policy?.warnings ?? []).map((w) => w.rule);
    expect(warned.filter((r) => r === "POLICY_DISABLE_NO_REASON")).toHaveLength(1);
    expect(warned.filter((r) => r === "POLICY_IGNORE_NO_REASON")).toHaveLength(1);
  });
});
