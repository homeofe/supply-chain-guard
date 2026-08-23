/**
 * Triage decision scope.
 *
 * ONE definition of which findings a triage decision applies to, shared by
 * every consumer of the decision store.
 *
 * WHY THIS MODULE EXISTS. The triage feature shipped with two different key
 * widths over the same decisions array: the governance check in
 * ./triage-engine.ts identified a decision by (rule, file), while the metrics
 * engine in ./metrics.ts identified it by rule alone. Both read the identical
 * array on the same scan, so one scan report could state "openCritical: 0"
 * beside "2 critical finding(s) have no assigned owner or triage decision",
 * and resolving one instance of a rule silently removed every instance of that
 * rule from the KPIs, including instances in files nobody had looked at.
 * Details and the measured reproduction:
 * https://github.com/homeofe/supply-chain-guard/issues/171
 *
 * Sharing a key STRING between the two call sites would have been enough to
 * fix the counts, but it leaves the same defect one careless edit away. So no
 * consumer builds a key at all: the scope rule is resolved here, and callers
 * ask a question ("does any of these decisions cover this finding?") instead of
 * constructing an identity they could construct differently. A test in
 * src/__tests__/triage-scope.test.ts fails if a second module starts reading
 * `findingFile` directly, which is how the divergence would come back.
 *
 * THE SCOPE RULE, in full:
 *
 *   findingFile ABSENT (undefined)  ->  the decision applies to every finding
 *                                       of that rule, in any file.
 *   findingFile PRESENT             ->  the decision applies only to findings
 *                                       of that rule whose `file` equals it.
 *
 * Absent and empty are deliberately different. `undefined` means "not scoped
 * to a file"; `""` means "scoped to the finding that carries no file", which is
 * what a project-level finding looks like (Finding.file is optional). Reading
 * findingFile for truthiness rather than for `undefined` would silently promote
 * an empty-string decision to rule-wide. Both branches are pinned by their own
 * test case.
 *
 * ASSUMPTION, and the reason it is safe: a finding's identity for triage
 * purposes is (rule, file) and nothing finer. Finding also carries `line` and
 * `match`, which are NOT part of the scope. That is intentional rather than an
 * oversight: line numbers move on every edit, so a line-scoped decision would
 * expire on the next commit and reintroduce the same silent under-count from
 * the other direction. TriageDecision has no line field, so this assumption is
 * also what the persisted format can express.
 *
 * This module holds no I/O and no state, so it stays cheap to import from
 * anywhere. It deliberately does not live in ./triage-engine.ts, which pulls in
 * node:fs and node:path for the decision store; ./metrics.ts is a pure
 * calculation and should not acquire a filesystem dependency to ask a question
 * about scope.
 */

import type { Finding, TriageDecision } from "./types.js";

/**
 * A resolved scope: the set of findings covered by the decisions it was built
 * from. Build it once per pass and query it per finding.
 */
export interface TriageScope {
  /** True when at least one of the indexed decisions applies to this finding. */
  covers(finding: Finding): boolean;
}

/**
 * Index a set of triage decisions by the findings they apply to.
 *
 * Callers narrow the input to the decisions they care about: the metrics engine
 * passes only `status === "resolved"` decisions, because only a resolution
 * removes a finding from the open counts, while the governance check passes all
 * of them, because any decision at all means the finding has an owner.
 * Narrowing is the caller's business; SCOPE is this module's business, and that
 * split is what keeps the two consumers from disagreeing about scope again.
 */
export function buildTriageScope(decisions: Iterable<TriageDecision>): TriageScope {
  /** Rules whose decisions name no file, and therefore cover every file. */
  const ruleWide = new Set<string>();
  /**
   * Rule -> the exact file paths its file-scoped decisions name.
   *
   * Two levels rather than one joined "rule|file" string on purpose: a joined
   * key needs a separator, and a separator needs the guarantee that neither
   * half can contain it. Rule ids are produced by this scanner and file paths
   * come from the scanned project, so that guarantee would be about the
   * consumer's filesystem. A nested map needs no such guarantee.
   */
  const fileScoped = new Map<string, Set<string>>();

  for (const d of decisions) {
    if (d.findingFile === undefined) {
      ruleWide.add(d.findingRule);
      continue;
    }
    let files = fileScoped.get(d.findingRule);
    if (files === undefined) {
      files = new Set<string>();
      fileScoped.set(d.findingRule, files);
    }
    files.add(d.findingFile);
  }

  return {
    covers(finding: Finding): boolean {
      if (ruleWide.has(finding.rule)) return true;
      return fileScoped.get(finding.rule)?.has(finding.file ?? "") ?? false;
    },
  };
}
