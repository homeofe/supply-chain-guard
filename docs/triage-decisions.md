# Triage decisions

A triage decision records that somebody has looked at a finding: who owns it,
what they decided, and when. Decisions live in the scanner's own state
directory inside the scanned project, at `.scg-history/triage-decisions.json`.
That directory ignores itself, so the file never reaches the scanned project's
commits unless the project adds it deliberately.

This page exists because the format was previously described nowhere, and the
only way to use it is to write the file or to call the library. A feature whose
scope rule is undocumented is a feature whose scope rule can be implemented
twice, differently, which is exactly what happened:
https://github.com/homeofe/supply-chain-guard/issues/171

## File format

An array of objects. `findingRule`, `status` and `decidedAt` are required, the
rest are optional.

```json
[
  {
    "findingRule": "EVAL_ATOB",
    "findingFile": "src/loader.js",
    "status": "resolved",
    "owner": "security-team",
    "team": "platform",
    "reason": "Decoded payload is a build-time locale table, reviewed 2026-08-20.",
    "decidedAt": "2026-08-20T10:00:00.000Z",
    "dueDate": "2026-11-20T00:00:00.000Z"
  }
]
```

`status` is one of `new`, `triaged`, `in-remediation`, `resolved`,
`false-positive`, `accepted-risk`. The exact union is `FindingStatus` in
`src/types.ts`, which is the authority if this page and the type ever disagree.

The file is read on every scan. A file that is missing, or that fails to parse,
is treated as an empty decision list rather than as an error: a corrupt state
file must never be able to stop a security scan from running.

## What a decision applies to

**A decision identifies a rule and a file, not a rule.** This is the single most
important sentence on this page.

| `findingFile` | The decision applies to |
| --- | --- |
| absent | every finding of that rule, in any file |
| a path, for example `src/loader.js` | findings of that rule whose `file` is exactly that path |
| the empty string `""` | findings of that rule that carry no file at all, which is what a project-level finding looks like |

Absent and empty are different on purpose. Absent means "not scoped to a file".
Empty means "scoped to the finding that has no file".

Paths are compared exactly, against the `file` field of a finding, which is
relative to the scan root. There is no prefix, glob or directory matching, and
no normalisation of separators. A decision naming a path that no finding
carries applies to nothing, which is the intended behaviour for a decision left
behind after its file was renamed or deleted: it must not silently resolve
anything else.

Line numbers are deliberately not part of the scope. `TriageDecision` has no
line field, and a line-scoped decision would expire on the next edit that moves
the code, turning every reformatting commit into a wave of reopened findings.

This rule is implemented once, in `src/triage-scope.ts`, and every consumer asks
that module. It is not reimplemented per call site, and a test fails if a second
module starts reading `findingFile` directly.

## Who reads the decisions

Two things inside a scan, and they now agree by construction:

- **`calculateMetrics` (`src/metrics.ts`)** subtracts findings covered by a
  `resolved` decision from `metrics.openCritical`, `metrics.openHigh` and
  `metrics.topRiskContributors`. Only `resolved` counts here. A finding that is
  triaged, in remediation or accepted is still open.
- **`checkTriageGovernance` (`src/triage-engine.ts`)** treats a finding as owned
  when **any** decision covers it, whatever its status, and raises
  `CRITICAL_FINDING_NO_OWNER` for critical findings that none covers. It also
  raises `RISK_ACCEPTED_WITHOUT_EXPIRY`, `RISK_ACCEPTANCE_EXPIRED` and
  `STALE_CRITICAL_FINDING` from the decisions alone.

Note what triage does **not** do. It does not remove findings from
`report.findings` or from `report.summary`, and it does not change the process
exit code. `getReportExitCode` never reads `metrics`. Triage annotates a report;
it does not suppress detections, and it cannot be used to make a failing scan
pass.

## Library use

There is no `triage` subcommand. The store is reached through the library:

```ts
import {
  loadTriageDecisions,
  saveTriageDecisions,
  buildTriageScope,
} from "supply-chain-guard";

const decisions = loadTriageDecisions(projectDir);
const resolved = buildTriageScope(decisions.filter((d) => d.status === "resolved"));
const stillOpen = findings.filter((f) => !resolved.covers(f));
```

`buildTriageScope` is exported so that code outside this package answers "does
this decision cover this finding?" with the same rule the package uses
internally. Deciding *which* decisions to index is the caller's business, as in
the `status` filter above; deciding *what a decision covers* is not.

## Open decision for the maintainer

The store still has no CLI surface. Recording a decision means hand-writing
JSON or calling `saveTriageDecisions` from a script, which is a plausible reason
the scope defect above survived four months without a report. Three options,
none of them taken here because the choice is a product decision rather than a
bug fix:

1. **Documentation only**, which is the state this page leaves it in. Cheapest,
   and honest about the feature being library-first.
2. **Add a `triage` subcommand** to record and list decisions. Makes the feature
   usable without writing JSON by hand, and creates a place to validate a
   decision against the findings of the current scan, which would have surfaced
   a decision that matches nothing.
3. **Drop the persisted store** and let consumers own it, keeping only the
   governance and metrics functions over a decisions array they pass in.
