/**
 * Regression tests for the two state stores under .scg-history/.
 *
 * The defect these lock down: both readers ended in `catch { return []; }`,
 * which is the same value the absent case returns, so a corrupt store was
 * reported as a clean first baseline. Measured consequence, identical for both
 * stores: the default gate flipped from exit 1 to exit 0 with the scanned code
 * unchanged, because the findings that disappear are `high` and the default
 * gate is `summary.high > 0`. On top of that, `null` and `{}` parse as valid
 * JSON, so they never reached either `catch` and instead crashed the scan with
 * an unhandled TypeError and no report at all.
 *
 * These tests drive the real `scan()` over temp fixtures rather than calling
 * the readers directly, because the claim being defended is about what a scan
 * REPORTS, not about what a helper returns. A unit test on `readRiskHistory`
 * alone would stay green if the scanner stopped acting on the status.
 *
 * Why the control cases matter as much as the corruption cases: before this
 * change, six suites mentioned the risk history or the trend rules and 36 of 36
 * tests stayed green with `return [];` inserted as the first statement of
 * `loadRiskHistory`, i.e. with the entire read path removed. A suite that only
 * asserts more findings would surround this code without covering it. The
 * `valid` and `absent` cases below are what make the corruption assertions
 * discriminating rather than merely additive.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { getReportExitCode } from "../reporter.js";
import {
  readRiskHistory,
  saveRiskHistory,
  RiskHistoryUnreadableError,
} from "../continuous-monitor.js";
import { readTriageDecisions } from "../triage-engine.js";
import { STATE_DIR } from "../state-dir.js";
import type { ScanReport } from "../types.js";

let tmpDir: string;

/**
 * Ten scans whose risk climbs and then stays high. This exact shape is what
 * makes the control meaningful: it is enough entries for the trend rules
 * (>= 10) and the forecast rules (>= 5) to fire, so a `NONE` in a corruption
 * case is a real absence rather than a rule that was never eligible.
 */
const CLIMBING_SCORES = [10, 12, 14, 16, 18, 55, 60, 65, 70, 75];

function validHistoryJson(): string {
  const entries = CLIMBING_SCORES.map((score, i) => ({
    timestamp: new Date(Date.UTC(2026, 7, 1 + i)).toISOString(),
    score,
    findingsCount: score,
    criticalCount: 0,
  }));
  return JSON.stringify(entries, null, 2);
}

/**
 * One expired risk acceptance and one stale in-remediation decision. Both
 * produce `high` governance findings, which is what lets the triage assertions
 * below check the gate rather than only the finding list.
 */
function validTriageJson(): string {
  return JSON.stringify(
    [
      {
        findingRule: "SOME_RULE",
        status: "accepted-risk",
        dueDate: "2026-01-01T00:00:00.000Z",
        decidedAt: "2025-12-01T00:00:00.000Z",
      },
      {
        findingRule: "OTHER_RULE",
        status: "in-remediation",
        decidedAt: "2026-01-01T00:00:00.000Z",
      },
    ],
    null,
    2,
  );
}

function stateFile(name: string): string {
  return path.join(tmpDir, STATE_DIR, name);
}

function writeState(name: string, contents: string): void {
  fs.mkdirSync(path.join(tmpDir, STATE_DIR), { recursive: true });
  fs.writeFileSync(stateFile(name), contents);
}

/** Cut the last `bytes` bytes off, the shape an interrupted write leaves. */
function truncated(json: string, bytes: number): string {
  return json.slice(0, json.length - bytes);
}

function rulesOf(report: ScanReport): string[] {
  return report.findings.map((f) => f.rule);
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-store-corrupt-"));
  fs.writeFileSync(
    path.join(tmpDir, "package.json"),
    '{ "name": "demo-app", "version": "1.0.0", "dependencies": {} }\n',
  );
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Risk history
// ---------------------------------------------------------------------------

describe("risk history: the two cases that must never be confused", () => {
  it("control: an intact history still produces the trend findings", async () => {
    writeState("risk-history.json", validHistoryJson());
    const report = await scan({ target: tmpDir, format: "json", noHistory: true });

    // If this control ever goes quiet, every "NONE" assertion below becomes
    // vacuous, so it asserts the findings are present rather than merely that
    // the scan ran.
    expect(rulesOf(report)).toContain("RISK_TREND_INCREASING");
    expect(rulesOf(report)).toContain("RISK_STAGNATION_HIGH");
    expect(rulesOf(report)).not.toContain("RISK_HISTORY_UNREADABLE");
    expect(report.partialScan).toBeUndefined();
    expect(getReportExitCode(report)).toBe(1);
  });

  it("an absent history is a first scan: silent, clean, exit 0", async () => {
    const report = await scan({ target: tmpDir, format: "json", noHistory: true });

    expect(rulesOf(report)).not.toContain("RISK_HISTORY_UNREADABLE");
    expect(report.partialScan).toBeUndefined();
    // This is the case the fix must not regress. A first scan of a clean
    // project has to stay exit 0, or the tool fails every new adopter.
    expect(getReportExitCode(report)).toBe(0);
  });

  const unreadableHistories: Array<[string, string]> = [
    ["zero bytes", ""],
    ["truncated mid-entry", truncated(validHistoryJson(), 120)],
    ["not JSON at all", "not json at all"],
    // The next two parse as valid JSON and so never reached the old `catch`.
    // Before this change each crashed the scan with an unhandled TypeError and
    // produced no report at all.
    ["JSON null", "null"],
    ["JSON object", "{}"],
  ];

  for (const [label, contents] of unreadableHistories) {
    it(`reports an unreadable history (${label}) instead of an empty baseline`, async () => {
      writeState("risk-history.json", contents);
      const report = await scan({ target: tmpDir, format: "json", noHistory: true });

      const unreadable = report.findings.filter(
        (f) => f.rule === "RISK_HISTORY_UNREADABLE",
      );
      expect(unreadable).toHaveLength(1);
      expect(unreadable[0].severity).toBe("high");
      expect(report.partialScan).toBe(true);

      // Exact code, not "nonzero". 1 is the gate failure; 2 would mean a
      // critical finding, which an unreadable baseline is not, and 0 is the
      // defect. Asserting `not.toBe(0)` would pass on all three.
      expect(getReportExitCode(report)).toBe(1);
    });
  }

  it("--fail-on cannot talk the gate back down to 0", async () => {
    writeState("risk-history.json", truncated(validHistoryJson(), 120));
    const report = await scan({ target: tmpDir, format: "json", noHistory: true });

    // partialScan is checked in getReportExitCode before the --fail-on branch,
    // so the strictest available threshold still cannot produce a clean exit.
    expect(getReportExitCode(report, "critical")).toBe(1);
  });

  it("an empty JSON array is a well-formed empty store, not a corrupt one", async () => {
    writeState("risk-history.json", "[]");
    const report = await scan({ target: tmpDir, format: "json", noHistory: true });

    expect(rulesOf(report)).not.toContain("RISK_HISTORY_UNREADABLE");
    expect(report.partialScan).toBeUndefined();
    expect(getReportExitCode(report)).toBe(0);
  });

  it("an entry with a non-numeric score is unreadable, not a NaN baseline", async () => {
    // `as RiskHistoryEntry[]` was a cast, not a check. A string score parses,
    // is an array, and would poison every average and slope with NaN.
    writeState(
      "risk-history.json",
      JSON.stringify([
        { timestamp: "2026-08-01T00:00:00.000Z", score: "high", findingsCount: 1, criticalCount: 0 },
      ]),
    );
    const read = readRiskHistory(tmpDir);
    expect(read.status).toBe("unreadable");
    expect(read.reason).toBe("invalid-entry");
    expect(read.entries).toEqual([]);
  });

  it("distinguishes the four unreadable reasons from each other", () => {
    expect(readRiskHistory(tmpDir).status).toBe("absent");

    writeState("risk-history.json", "not json");
    expect(readRiskHistory(tmpDir).reason).toBe("not-json");

    writeState("risk-history.json", "null");
    expect(readRiskHistory(tmpDir).reason).toBe("not-an-array");

    writeState("risk-history.json", "[{}]");
    expect(readRiskHistory(tmpDir).reason).toBe("invalid-entry");
  });

  it("no reason value leaks a filesystem path or an account name", () => {
    // The reason is published inside a scan report. An exception message from
    // fs or JSON.parse would carry the absolute path, and on a developer
    // machine that carries the account name.
    writeState("risk-history.json", "not json");
    const read = readRiskHistory(tmpDir);
    expect(read.reason).toBe("not-json");
    expect(String(read.reason)).not.toContain(path.sep);
    expect(String(read.reason)).not.toContain(os.homedir());
  });
});

describe("risk history: the corrupt file survives the scan that reports it", () => {
  it("a plain scan does not overwrite a truncated history", async () => {
    const corrupt = truncated(validHistoryJson(), 120);
    writeState("risk-history.json", corrupt);
    const before = fs.readFileSync(stateFile("risk-history.json"), "utf-8");

    // noHistory deliberately NOT set: this is the write-enabled path that used
    // to replace 1072 bytes holding nine recoverable entries with a 119-byte
    // file holding one, turning "corrupt" into "gone" on the very next run.
    await scan({ target: tmpDir, format: "json" });

    const after = fs.readFileSync(stateFile("risk-history.json"), "utf-8");
    expect(after).toBe(before);
    expect((after.match(/"score":/g) ?? []).length).toBe(9);
  });

  it("saveRiskHistory refuses rather than silently overwriting", () => {
    writeState("risk-history.json", truncated(validHistoryJson(), 120));
    const report = {
      timestamp: new Date().toISOString(),
      score: 0,
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, filesScanned: 0, totalFiles: 0 },
      riskLevel: "low",
      recommendations: [],
      target: tmpDir,
      scanType: "directory",
      tool: "test",
      durationMs: 0,
    } as unknown as ScanReport;

    // A silent no-op here would be the same conflation the reader was fixed
    // for: the caller could not tell "saved" from "refused".
    expect(() => saveRiskHistory(tmpDir, report)).toThrow(RiskHistoryUnreadableError);
    expect(String(new RiskHistoryUnreadableError("not-json"))).not.toContain(os.homedir());
  });

  it("control: saveRiskHistory still appends to an intact history", () => {
    writeState("risk-history.json", validHistoryJson());
    const report = {
      timestamp: "2026-08-20T00:00:00.000Z",
      score: 42,
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, filesScanned: 0, totalFiles: 0 },
      riskLevel: "medium",
      recommendations: [],
      target: tmpDir,
      scanType: "directory",
      tool: "test",
      durationMs: 0,
    } as unknown as ScanReport;

    saveRiskHistory(tmpDir, report);
    const read = readRiskHistory(tmpDir);
    expect(read.status).toBe("ok");
    expect(read.entries).toHaveLength(CLIMBING_SCORES.length + 1);
    expect(read.entries[read.entries.length - 1].score).toBe(42);
  });
});

// ---------------------------------------------------------------------------
// Triage decisions: the same construct, measured to have the same consequence
// ---------------------------------------------------------------------------

describe("triage store: the same two cases, equally separated", () => {
  it("control: an intact store still produces the governance findings", async () => {
    writeState("triage-decisions.json", validTriageJson());
    const report = await scan({ target: tmpDir, format: "json", noHistory: true });

    expect(rulesOf(report)).toContain("RISK_ACCEPTANCE_EXPIRED");
    expect(rulesOf(report)).toContain("STALE_CRITICAL_FINDING");
    expect(rulesOf(report)).not.toContain("TRIAGE_STORE_UNREADABLE");
    expect(report.partialScan).toBeUndefined();
    expect(getReportExitCode(report)).toBe(1);
    // The true value for this fixture under the single SLA definition in
    // src/sla-engine.ts: two measurable decisions, one of them compliant.
    //
    // `accepted-risk` is compliant by `slaVerdict` regardless of its dueDate,
    // and `in-remediation` decided 2026-01-01 is past its window, so the rate
    // is 50. It was 0 before because the old formula in metrics.ts counted
    // RESOLVED over NOT-NEW - a resolution rate carrying the name of SLA
    // compliance, which is the defect this change removes. Nothing in this
    // fixture is resolved, which is exactly why the old number was 0.
    //
    // The expired acceptance is still reported: RISK_ACCEPTANCE_EXPIRED is
    // asserted above and the exit code is 1. The SLA rate is not the channel
    // that carries it.
    expect(report.metrics?.slaComplianceRate).toBe(50);
  });

  it("an absent store is silent and clean", async () => {
    const report = await scan({ target: tmpDir, format: "json", noHistory: true });
    expect(rulesOf(report)).not.toContain("TRIAGE_STORE_UNREADABLE");
    expect(getReportExitCode(report)).toBe(0);
  });

  const unreadableStores: Array<[string, string]> = [
    ["truncated mid-entry", truncated(validTriageJson(), 60)],
    ["not JSON at all", "not json at all"],
    ["JSON null", "null"],
    ["JSON object", "{}"],
  ];

  for (const [label, contents] of unreadableStores) {
    it(`reports an unreadable triage store (${label}) instead of no decisions`, async () => {
      writeState("triage-decisions.json", contents);
      const report = await scan({ target: tmpDir, format: "json", noHistory: true });

      const unreadable = report.findings.filter(
        (f) => f.rule === "TRIAGE_STORE_UNREADABLE",
      );
      expect(unreadable).toHaveLength(1);
      expect(unreadable[0].severity).toBe("high");
      expect(report.partialScan).toBe(true);
      expect(getReportExitCode(report)).toBe(1);
    });
  }

  it("an unrecognised status is unreadable, not a decision that matches no rule", () => {
    writeState(
      "triage-decisions.json",
      JSON.stringify([{ findingRule: "R", status: "probably-fine", decidedAt: "2026-01-01T00:00:00.000Z" }]),
    );
    const read = readTriageDecisions(tmpDir);
    expect(read.status).toBe("unreadable");
    expect(read.reason).toBe("invalid-entry");
  });
});
