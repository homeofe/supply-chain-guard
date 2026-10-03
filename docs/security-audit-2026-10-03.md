# Security audit report - 2026-10-03

## Scope and evidence

This review covers the `supply-chain-guard` repository at
`df75b5aeaa3b666ccffd5f6a1b149ad79bde911d` (v6.4.2), plus the separately
identified state of [PR #377](https://github.com/homeofe/supply-chain-guard/pull/377)
at `cbfde9624b2cdadfe76a7396285a1d26090188b3`. Its purpose is to record
confirmed defects and guide fixes. This change contains no runtime fixes.

The review inventoried the repository and searched the complete source, test,
script, and workflow trees for process execution, network access, filesystem
writes, path handling, regular expressions, and security-sensitive output. It
then traced the higher-risk paths manually: state and cache directories, feed
and catalog loading, policy matching, archive extraction, remote acquisition,
scanner orchestration, reporters, the MCP interface, the GitHub Action, and
build/release scripts. This is a code review and targeted reproduction, not a
formal proof that no other defects exist.

Verification on the exact main commit:

- Linux temporary checkout: `npm ci --ignore-scripts`, TypeScript compilation,
  `npm test` (195 files, 4,951 tests passed), and `npm run build` passed. The
  build included the repository's prebuild gates.
- Local type check, dependency audit, self-scan check, and the installed v6.4.2
  CLI self-scan passed. The dependency audit reported zero known findings. The
  self-scan reported no high-severity findings; it does not exercise the logic
  defects below.
- The full Windows test run had 4,908 passes, 21 failures, and 22 skips. The
  failures included line-ending, shell-path, antivirus, and timeout behavior.
  The successful Linux run at the same commit is the reliable full-suite
  result. Windows parity remains unverified.
- The ignored local `dist` directory reported v6.2.4 while the source package
  and globally installed CLI reported v6.4.2. Findings were rechecked against
  v6.4.2 rather than inferred from the stale local build.

All proof-of-concept values below were synthetic. No real access token or
malware payload was needed for the reproductions.

## Confirmed findings

### 1. Project-controlled history path writes outside the scan root - high

[`ensureStateDir`](../src/state-dir.ts#L39) creates and uses `.scg-history`
without rejecting a symlink or junction. A default scan then writes its risk
history through that path
([`scanner.ts`](../src/scanner.ts#L1097),
[`continuous-monitor.ts`](../src/continuous-monitor.ts#L195)). A scanned
project can therefore redirect the scanner's fixed history filenames to a
directory outside the project, with the scanner user's filesystem privileges.

In isolated Windows and Linux test projects, `.scg-history` pointed to a
sibling directory. A normal scan returned exit code 0, replaced the sibling
directory's `.gitignore`, and created `risk-history.json` there. This affects
default CLI scans and callers that do not disable history, including the MCP
directory scan. The reproduced overwrite is of a fixed filename; the review
does not claim arbitrary filename selection.

**Fix direction:** reject symlinks and reparse points in the state path and
validate the final files before writes, or store scanner state outside
untrusted projects. A refusal must be visible rather than silently ignored.
Add a regression that scans a linked state directory and asserts that its
external target remains untouched.

### 2. Git remote credentials can enter JSON and SARIF reports - high when present

[`scanner.ts`](../src/scanner.ts#L1223) reads `remote.origin.url` directly into
`repositoryUri`; [`reporter.ts`](../src/reporter.ts#L1112) carries that value
into SARIF, and the JSON result carries it too. Git remote URLs can contain
HTTP user information or query parameters. If one contains a credential, a
report or CI artifact can disclose it.

An isolated Git repository with a **synthetic** credential in its remote URL
produced JSON and SARIF output containing that exact test value. The current
remote URL of this repository was separately checked: it contains no embedded
HTTP user information, query, or fragment. This review found no evidence that
the maintainer's real token was disclosed by this path. Authentication stored
separately by Git was not read.

**Fix direction:** sanitize repository URLs before adding them to any report.
Cover user information, query, and fragment components; use the same sanitized
value for JSON and SARIF. Add regression tests for both formats. Review any
historical report only if its Git remote actually contained a credential.

### 3. Untrusted policy glob can stall a scan - medium to high

[`matchGlob`](../src/policy-engine.ts#L26) turns every `*` into a regex fragment
and executes the resulting expression against paths. The policy file is read
from the scanned project. Repeated wildcards can cause expensive backtracking
on a long, nearly matching filename.

A control project completed normally; adding a short adversarial ignore glob
to its policy made the same scan exceed a three-second timeout. A direct
matcher test showed the same behavior. This allows a malicious project or pull
request to delay a CI verdict.

**Fix direction:** use a linear-time glob matcher or bounded dynamic
programming, and set input limits. Add a regression with a long filename and
repeated wildcards that completes within a fixed budget.

### 4. Corrupt refreshed threat cache silently removes detections - medium to high

[`loadThreatIntel`](../src/threat-intel.ts#L5144) ignores a cache parse failure
and continues without a cache-corruption or partial-scan signal. A direct
cache write during refresh is one plausible way to leave incomplete JSON
([`feed.ts`](../src/feed.ts#L725)).

With a valid synthetic cache, a matching IOC produced a finding and exit code
2. Replacing that cache with malformed JSON removed the finding: the next scan
returned exit code 0 and did not mark the scan partial. Other informational
findings did not describe the lost cache coverage.

**Fix direction:** distinguish an absent cache from an invalid cache, surface
lost coverage in the result and exit behavior, and write refreshed cache files
atomically. Test valid, absent, and corrupt cache states through the public
scan entry point.

### 5. Cache provenance contradicts the actual detection set - medium

The loader still merges an expired but parseable threat cache, while
[`getDetectionSetProvenance`](../src/threat-intel.ts#L6015) sets `cacheMerged`
only if the cache is newer than the TTL. The resulting metadata can say
`cacheMerged:false` even when cache-only entries influenced the verdict.

An isolated three-day-old synthetic cache produced a critical IOC match and
an effective entry count larger than the bundled count, while the report said
`cacheMerged:false` and omitted the cache path and refresh time.

**Fix direction:** derive provenance from the actual load/merge result. Report
staleness as a separate property. Assert the same provenance in JSON and SARIF.

## Additional functional findings

### Incremental scan with no changes scans the full tree

[`diff-scanner.ts`](../src/diff-scanner.ts#L17) returns an empty list both for
no changes and a diff error. [`scanner.ts`](../src/scanner.ts#L306) only applies
the changed-file filter when that list is nonempty. In a Git test project,
`scan --since HEAD` reported one file scanned despite `git diff HEAD HEAD`
reporting no changes. This can increase CI work and obscures an invalid ref.
Represent an empty successful diff separately from a failed diff and define an
explicit no-change result.

### PR #377 legacy-cache note misses an alternate explicit cache path

At the PR head named above, `legacyRefreshNote` does not emit a note when a
legacy `.scg-cache` exists but refresh uses a different explicitly selected
cache path. The current helper in
[`cache-dir.ts`](../src/cache-dir.ts#L104) treats every explicit cache choice as
excluding the legacy note. The PR's focused test covers the explicit legacy
path but not a different explicit path. Compare the resolved write path with
the legacy path and add that missing case. This observation is about the
separate PR; it is not a defect introduced by this documentation change.

At the time of review, PR #377's `AAHP Verify` job also failed because its
handoff state and manifest had not changed with the code. Other observed
checks passed. That CI snapshot must be rechecked at the PR's next head.

## Priority and acceptance

1. Prevent writes through project-controlled state links and sanitize Git
   remote URLs in every report format.
2. Bound policy matching and make corrupted cache coverage visible.
3. Correct cache provenance and incremental-scan behavior.
4. Resolve the separately tracked PR #377 behavior and handoff gate.

This report records reproducible defects. None is fixed by this PR. Closing a
finding requires a focused regression at the public scanner interface, an
output and exit-code assertion where relevant, the complete test suite, and
the required build and handoff gates at the fixing commit.
