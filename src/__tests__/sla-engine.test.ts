/**
 * SLA engine tests, and the regression guard for the defect where
 * `slaComplianceRate` carried its own definition of SLA compliance and
 * contradicted this engine on identical input.
 *
 * WHY THIS FILE EXISTS AT ALL: before it, `src/sla-engine.ts` had no test file
 * and no internal caller, and no test anywhere ran both definitions in one
 * process. There was no place a disagreement could surface, which is why the
 * contradiction shipped in every release from v4.8.0 onwards while the suite
 * stayed green.
 *
 * The load-bearing test is "agreement invariant" below. It executes
 * `calculateMetrics` and `checkSlaCompliance` on the SAME decisions and asserts
 * the exact equivalence they now share:
 *
 *     slaComplianceRate === 100  <=>  checkSlaCompliance reports zero breaches
 *
 * Any future second definition of SLA compliance breaks that equivalence on at
 * least one row of the table, so it reddens here rather than shipping.
 */

import { describe, it, expect } from "vitest";
import { calculateMetrics } from "../metrics.js";
import { checkSlaCompliance, slaVerdict } from "../sla-engine.js";
import type { TriageDecision } from "../types.js";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/** ISO timestamp `ms` milliseconds in the past. */
const ago = (ms: number): string => new Date(Date.now() - ms).toISOString();

const decision = (over: Partial<TriageDecision> = {}): TriageDecision => ({
  findingRule: "SOME_MEDIUM_RULE",
  status: "in-remediation",
  decidedAt: ago(1 * HOUR),
  ...over,
});

describe("slaVerdict", () => {
  it("treats resolved, false-positive and accepted-risk as compliant without reading the date", () => {
    for (const status of ["resolved", "false-positive", "accepted-risk"] as const) {
      // 10 years old and still compliant: these statuses have no remaining
      // deadline to miss, so the date is never consulted.
      expect(slaVerdict(decision({ status, decidedAt: ago(3650 * DAY) }))).toBe("compliant");
    }
  });

  it("evaluates `new`, which the old metric excluded entirely", () => {
    expect(
      slaVerdict(decision({ status: "new", findingRule: "X_CRITICAL", decidedAt: ago(30 * DAY) })),
    ).toBe("breached");
  });

  it("reports an unparseable decidedAt as unmeasurable, not compliant", () => {
    expect(slaVerdict(decision({ decidedAt: "" }))).toBe("unmeasurable");
    expect(slaVerdict(decision({ decidedAt: "not-a-date" }))).toBe("unmeasurable");
  });

  it("treats a future decidedAt as compliant, because no deadline can have passed", () => {
    const future = new Date(Date.now() + 1 * DAY).toISOString();
    expect(slaVerdict(decision({ decidedAt: future }))).toBe("compliant");
  });

  it("separates at-risk from breached at the SLA deadline", () => {
    // 24h SLA for a CRITICAL rule. 0.8 of it is 19.2 hours.
    const critical = { findingRule: "X_CRITICAL", status: "in-remediation" } as const;
    expect(slaVerdict(decision({ ...critical, decidedAt: ago(10 * HOUR) }))).toBe("compliant");
    expect(slaVerdict(decision({ ...critical, decidedAt: ago(22 * HOUR) }))).toBe("at-risk");
    expect(slaVerdict(decision({ ...critical, decidedAt: ago(26 * HOUR) }))).toBe("breached");
  });
});

describe("checkSlaCompliance", () => {
  it("emits one SLA_BREACH_CRITICAL per breached decision", () => {
    const findings = checkSlaCompliance([
      decision({ findingRule: "A_CRITICAL", status: "new", decidedAt: ago(30 * DAY) }),
      decision({ findingRule: "B_CRITICAL", status: "new", decidedAt: ago(30 * DAY) }),
    ]);
    expect(findings.filter((f) => f.rule === "SLA_BREACH_CRITICAL")).toHaveLength(2);
  });

  it("emits SLA_AT_RISK inside the deadline and no breach", () => {
    const findings = checkSlaCompliance([
      decision({ findingRule: "A_CRITICAL", status: "in-remediation", decidedAt: ago(22 * HOUR) }),
    ]);
    expect(findings.map((f) => f.rule)).toEqual(["SLA_AT_RISK"]);
  });

  it("emits nothing for a decision whose decidedAt cannot be parsed", () => {
    expect(checkSlaCompliance([decision({ decidedAt: "" })])).toEqual([]);
  });
});

/**
 * The regression guard. One table, both functions, same input, one invariant.
 */
describe("slaComplianceRate agrees with the SLA engine", () => {
  const rows: Array<{
    name: string;
    decisions: TriageDecision[];
    rate: number | null;
    breaches: number;
  }> = [
    {
      // Issue case 1: the full inversion. The old metric said 0 percent here.
      name: "two accepted-risk decisions",
      decisions: [
        decision({ findingRule: "A_CRITICAL", status: "accepted-risk", decidedAt: ago(2 * DAY) }),
        decision({ findingRule: "B_HIGH", status: "accepted-risk", decidedAt: ago(2 * DAY) }),
      ],
      rate: 100,
      breaches: 0,
    },
    {
      name: "accepted-risk aged 365 days",
      decisions: [
        decision({ findingRule: "A_CRITICAL", status: "accepted-risk", decidedAt: ago(365 * DAY) }),
      ],
      rate: 100,
      breaches: 0,
    },
    {
      // Issue case 2: active remediation inside the deadline read as failure.
      name: "all in-remediation, inside the deadline",
      decisions: [
        decision({ findingRule: "A_MEDIUM", status: "in-remediation", decidedAt: ago(1 * DAY) }),
        decision({ findingRule: "B_MEDIUM", status: "in-remediation", decidedAt: ago(1 * DAY) }),
      ],
      rate: 100,
      breaches: 0,
    },
    {
      name: "a fresh triaged decision",
      decisions: [
        decision({ findingRule: "A_MEDIUM", status: "triaged", decidedAt: ago(1 * HOUR) }),
      ],
      rate: 100,
      breaches: 0,
    },
    {
      // The defect the issue did not document, and the dangerous direction:
      // the old metric excluded `new` from its denominator and reported 100
      // while the engine reported a breach on the same decision.
      name: "one stale `new`, 30 days past a 24h SLA",
      decisions: [
        decision({ findingRule: "A_CRITICAL", status: "new", decidedAt: ago(30 * DAY) }),
      ],
      rate: 0,
      breaches: 1,
    },
    {
      name: "one resolved plus two stale `new`",
      decisions: [
        decision({ findingRule: "A_CRITICAL", status: "resolved", decidedAt: ago(30 * DAY) }),
        decision({ findingRule: "B_CRITICAL", status: "new", decidedAt: ago(30 * DAY) }),
        decision({ findingRule: "C_CRITICAL", status: "new", decidedAt: ago(30 * DAY) }),
      ],
      rate: 33,
      breaches: 2,
    },
    {
      // at-risk is inside the SLA, so the rate stays at 100 while the engine
      // still raises its warning. This row is what stops a future change from
      // "fixing" the invariant by counting at-risk as a breach.
      name: "one at-risk decision, deadline not yet passed",
      decisions: [
        decision({ findingRule: "A_CRITICAL", status: "in-remediation", decidedAt: ago(22 * HOUR) }),
      ],
      rate: 100,
      breaches: 0,
    },
    {
      name: "every decision unmeasurable",
      decisions: [decision({ decidedAt: "" }), decision({ decidedAt: "nonsense" })],
      rate: null,
      breaches: 0,
    },
    {
      name: "no decisions at all",
      decisions: [],
      rate: null,
      breaches: 0,
    },
  ];

  for (const row of rows) {
    it(`${row.name}: rate ${JSON.stringify(row.rate)}, ${row.breaches} breach(es)`, () => {
      const rate = calculateMetrics([], [], row.decisions).slaComplianceRate;
      const breaches = checkSlaCompliance(row.decisions).filter(
        (f) => f.rule === "SLA_BREACH_CRITICAL",
      ).length;

      expect(rate).toBe(row.rate);
      expect(breaches).toBe(row.breaches);

      // The invariant itself, asserted on every row rather than once:
      // 100 percent compliant and "the engine found a breach" cannot coexist,
      // and anything short of 100 must be explained by an actual breach.
      if (breaches === 0) {
        expect(rate === null || rate === 100).toBe(true);
      } else {
        expect(rate).not.toBe(100);
      }
    });
  }

  it("does not round a lone breach away: 1 breach in 200 decisions is 99, not 100", () => {
    const decisions: TriageDecision[] = [
      decision({ findingRule: "STALE_CRITICAL", status: "new", decidedAt: ago(30 * DAY) }),
    ];
    for (let i = 0; i < 199; i += 1) {
      decisions.push(decision({ findingRule: `OK_${i}_MEDIUM`, status: "resolved" }));
    }
    expect(calculateMetrics([], [], decisions).slaComplianceRate).toBe(99);
    expect(
      checkSlaCompliance(decisions).filter((f) => f.rule === "SLA_BREACH_CRITICAL"),
    ).toHaveLength(1);
  });
});
