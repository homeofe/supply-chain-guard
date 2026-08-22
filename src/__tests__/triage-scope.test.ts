import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { calculateMetrics } from "../metrics.js";
import { checkTriageGovernance } from "../triage-engine.js";
import { buildTriageScope } from "../triage-scope.js";
import type { Finding, TriageDecision } from "../types.js";

/**
 * Cross-consumer cover for the triage scope key.
 *
 * The defect this file exists for was not a missing file check. One feature
 * introduced two different key widths over the same decisions array and only
 * one of them survived: the governance check keyed on (rule, file) while the
 * metrics engine keyed on the rule alone. Both read the identical array on the
 * same scan, so a single scan report could state "0 open critical" beside
 * "2 critical finding(s) have no assigned owner or triage decision".
 *
 * A unit test on either consumer alone cannot see that. These cases assert the
 * two consumers reach the SAME verdict about the SAME findings, which is the
 * property that broke, and they are deliberately written against the public
 * behaviour of both rather than against the shared helper, so they keep
 * holding if the helper is ever replaced.
 */
describe("Triage scope: every consumer of a decision reads the same scope", () => {
  const critical = (rule: string, file: string | undefined): Finding => ({
    rule,
    description: "",
    severity: "critical",
    recommendation: "",
    file,
  });

  /** True when the governance check reports at least one uncovered critical. */
  function hasUncoveredCritical(findings: Finding[], decisions: TriageDecision[]): boolean {
    return checkTriageGovernance(findings, decisions).some(
      (f) => f.rule === "CRITICAL_FINDING_NO_OWNER",
    );
  }

  const twoFiles = [critical("IOC_C2_DOMAIN", "src/a.ts"), critical("IOC_C2_DOMAIN", "src/b.ts")];

  it("a file-scoped decision leaves the other file uncovered for BOTH consumers", () => {
    const decisions: TriageDecision[] = [
      {
        findingRule: "IOC_C2_DOMAIN",
        findingFile: "src/a.ts",
        status: "resolved",
        decidedAt: "2026-08-22T10:00:00.000Z",
      },
    ];
    const openCritical = calculateMetrics(twoFiles, [], decisions).openCritical;
    expect([openCritical > 0, hasUncoveredCritical(twoFiles, decisions)]).toEqual([true, true]);
    expect(openCritical).toBe(1);
  });

  it("a rule-wide decision covers every file for BOTH consumers", () => {
    const decisions: TriageDecision[] = [
      {
        findingRule: "IOC_C2_DOMAIN",
        status: "resolved",
        decidedAt: "2026-08-22T10:00:00.000Z",
      },
    ];
    const openCritical = calculateMetrics(twoFiles, [], decisions).openCritical;
    expect([openCritical > 0, hasUncoveredCritical(twoFiles, decisions)]).toEqual([false, false]);
    expect(openCritical).toBe(0);
  });
});

/**
 * The scope rule itself, stated once per branch.
 *
 * These are the cases a reviewer reads to learn what a decision covers. Each
 * one pins a single sentence of the contract documented at the top of
 * src/triage-scope.ts.
 */
describe("buildTriageScope", () => {
  const finding = (rule: string, file: string | undefined): Finding => ({
    rule,
    description: "",
    severity: "critical",
    recommendation: "",
    file,
  });

  const decision = (findingRule: string, findingFile: string | undefined): TriageDecision => ({
    findingRule,
    findingFile,
    status: "resolved",
    decidedAt: "2026-08-22T10:00:00.000Z",
  });

  it("covers nothing when there are no decisions", () => {
    expect(buildTriageScope([]).covers(finding("R", "src/a.ts"))).toBe(false);
  });

  it("a file-scoped decision covers its own file and no other", () => {
    const scope = buildTriageScope([decision("R", "src/a.ts")]);
    expect([scope.covers(finding("R", "src/a.ts")), scope.covers(finding("R", "src/b.ts"))]).toEqual(
      [true, false],
    );
  });

  it("a file-scoped decision does not leak across rules", () => {
    const scope = buildTriageScope([decision("R", "src/a.ts")]);
    expect(scope.covers(finding("OTHER", "src/a.ts"))).toBe(false);
  });

  it("a decision with no findingFile covers every file of its rule", () => {
    const scope = buildTriageScope([decision("R", undefined)]);
    expect([scope.covers(finding("R", "src/a.ts")), scope.covers(finding("R", undefined))]).toEqual([
      true,
      true,
    ]);
  });

  it("an empty findingFile covers the finding that has no file, and only that one", () => {
    // Absent and empty are different. Truthiness on findingFile would collapse
    // this case into the rule-wide one above and take src/a.ts with it.
    const scope = buildTriageScope([decision("R", "")]);
    expect([scope.covers(finding("R", undefined)), scope.covers(finding("R", "src/a.ts"))]).toEqual([
      true,
      false,
    ]);
  });

  it("several decisions on one rule each cover their own file", () => {
    const scope = buildTriageScope([decision("R", "src/a.ts"), decision("R", "src/b.ts")]);
    expect([
      scope.covers(finding("R", "src/a.ts")),
      scope.covers(finding("R", "src/b.ts")),
      scope.covers(finding("R", "src/c.ts")),
    ]).toEqual([true, true, false]);
  });

  it("line and match are not part of the scope", () => {
    // Documented in src/triage-scope.ts: a decision is (rule, file) and nothing
    // finer, because TriageDecision cannot express a line and because line
    // numbers move on every edit.
    const scope = buildTriageScope([decision("R", "src/a.ts")]);
    const moved: Finding = { ...finding("R", "src/a.ts"), line: 42, match: "x" };
    expect(scope.covers(moved)).toBe(true);
  });
});

/**
 * Structural guard against the same class reappearing.
 *
 * The two key widths could diverge because each consumer built its own key out
 * of `findingFile`. After the fix the scope rule lives in exactly one module,
 * `src/triage-scope.ts`, and every consumer asks it rather than rebuilding the
 * key. This test fails the moment a second module starts reading `findingFile`
 * directly, which is how the divergence would come back.
 *
 * If a module legitimately needs the field for DISPLAY rather than for scope
 * (rendering a decision in a report, for example), add it to ALLOWED below with
 * a one-line reason. The point of this guard is that a second SCOPE rule cannot
 * appear unnoticed, not that the field is untouchable.
 */
describe("Triage scope: the scope rule has exactly one home", () => {
  const ALLOWED = new Set([
    // Declares the field.
    "types.ts",
    // Owns the scope rule; the whole point of the guard.
    "triage-scope.ts",
  ]);

  /**
   * Comments are stripped so the guard reads code and not prose: the modules
   * that were fixed explain the scope rule in their comments and name the field
   * while doing so, which is exactly the documentation this defect was missing.
   * The line-comment pattern skips a `//` preceded by a colon so a URL inside a
   * string survives; the approximation is acceptable because the only question
   * asked afterwards is whether one identifier is present.
   */
  function stripComments(source: string): string {
    return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:])\/\/.*$/gm, "$1");
  }

  it("no module outside src/triage-scope.ts reads findingFile", () => {
    const srcDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const offenders = fs
      .readdirSync(srcDir, { withFileTypes: true })
      .filter((e) => e.isFile() && e.name.endsWith(".ts") && !ALLOWED.has(e.name))
      .filter((e) =>
        /\bfindingFile\b/.test(stripComments(fs.readFileSync(path.join(srcDir, e.name), "utf-8"))),
      )
      .map((e) => e.name);
    expect(offenders).toEqual([]);
  });
});
