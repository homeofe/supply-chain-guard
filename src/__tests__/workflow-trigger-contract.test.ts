/**
 * Trigger-separation contract between the two pull-request workflows.
 *
 * WHY THIS EXISTS
 * ---------------
 * `edited` used to sit in ci.yml's pull_request types so the AI-attribution gate
 * would re-run when a PR title or body changed. The side effect was that every
 * metadata edit started the full build, test, package and security pipeline
 * against a head commit whose content had not changed, producing two or three
 * runs on one SHA. Whether that blocked a merge depended on which run finished
 * last: on the v5.26.7 cut the cancelled twin was last and blocked it; on
 * v5.27.0 the successful one was last and it did not. That is timing, not design.
 *
 * The split gives each required check exactly one producing workflow. This test
 * is the regression mechanism: a future edit that re-adds `edited` to ci.yml, or
 * moves the title/body checks back into the build job, fails here rather than
 * being discovered by a merge that mysteriously will not go through.
 *
 * EVENT TO WORKFLOW MATRIX (the contract these assertions encode)
 * --------------------------------------------------------------
 *   opened            -> both  (code validation + metadata policy)
 *   reopened          -> both
 *   synchronize       -> ci.yml only        (new head commit = new code)
 *   ready_for_review  -> ci.yml only        (changes merge candidacy)
 *   edited            -> pr-metadata-policy only  (title/body cannot change code)
 *   push (main, tags) -> ci.yml only
 *
 * Deliberately asserted on the RAW file text rather than a parsed object: no YAML
 * parser is a dependency of this package, and adding one to a security scanner to
 * lint its own CI would be a poor trade. The assertions below are anchored on
 * exact strings that appear once each.
 */
import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const CI = fs.readFileSync(path.join(REPO, ".github/workflows/ci.yml"), "utf-8");
const META = fs.readFileSync(
  path.join(REPO, ".github/workflows/pr-metadata-policy.yml"),
  "utf-8",
);

/** The `types: [...]` list under a workflow's pull_request trigger. */
function pullRequestTypes(yaml: string): string[] {
  const m = yaml.match(/pull_request:[\s\S]*?types:\s*\[([^\]]*)\]/);
  if (!m) throw new Error("no pull_request types list found");
  return m[1]!.split(",").map((s) => s.trim()).filter(Boolean);
}

describe("workflow trigger contract", () => {
  it("code validation does NOT run on a metadata-only edit", () => {
    // The single assertion this whole split exists to guarantee.
    expect(pullRequestTypes(CI)).not.toContain("edited");
  });

  it("code validation runs on every event that can change the code", () => {
    const types = pullRequestTypes(CI);
    for (const t of ["opened", "synchronize", "reopened", "ready_for_review"]) {
      expect(types).toContain(t);
    }
  });

  it("metadata policy runs on edit, and not on a new head commit", () => {
    const types = pullRequestTypes(META);
    expect(types).toContain("edited");
    expect(types).toContain("opened");
    expect(types).toContain("reopened");
    // synchronize would re-run the metadata check on every push, which is the
    // duplication this split removes, just pointed the other way.
    expect(types).not.toContain("synchronize");
  });

  it("the title and body checks live in exactly one workflow", () => {
    // If these come back to ci.yml, `edited` follows them and the split is undone.
    expect(CI).not.toContain("PR_TITLE");
    expect(CI).not.toContain("PR_BODY");
    expect(META).toContain("PR_TITLE");
    expect(META).toContain("PR_BODY");
  });

  it("the commit-range checks stay with code validation", () => {
    // Their input is BASE..HEAD, so they must not move to the metadata workflow,
    // which has no checkout and no commit range.
    expect(CI).toContain("BASE_SHA");
    expect(CI).toContain("HEAD_SHA");
    expect(META).not.toContain("BASE_SHA");
    expect(META).not.toContain("HEAD_SHA");
  });

  it("each required check name has exactly one producing workflow", () => {
    const names = (y: string) =>
      [...y.matchAll(/^\s{4}name:\s*(.+)$/gm)].map((m) => m[1]!.trim());
    const ciNames = names(CI);
    const metaNames = names(META);

    expect(ciNames).toContain("Build and Test");
    expect(metaNames).toContain("PR metadata policy");

    // No name may be produced by both files, or branch protection sees two runs
    // competing to define one context.
    expect(ciNames.filter((n) => metaNames.includes(n))).toEqual([]);
  });

  it("the two workflows use separate concurrency groups ON A PULL_REQUEST EVENT", () => {
    // Sharing a group would let a metadata edit cancel an in-flight code run,
    // which is precisely the ambiguous-cancellation state being designed out.
    //
    // Comparing the raw strings is NOT enough. An earlier version of this test
    // passed a mutation that set the metadata group to `ci-${{ ...number }}`
    // while ci.yml carries `ci-${{ ...number || github.ref }}`. Those differ as
    // text and resolve to the SAME group for a pull_request event, because the
    // `||` fallback is only taken when there is no PR. Compare what the
    // expressions actually resolve to for the event both workflows share.
    const group = (y: string) => y.match(/concurrency:\s*\n\s*group:\s*(.+)/)?.[1]?.trim();

    /** Resolve a group expression the way GitHub would for a pull_request event. */
    const forPullRequest = (expr: string) =>
      expr
        // `a || b` yields `a` on a PR, since the PR number is always set there.
        .replace(/\$\{\{\s*([^|}]+?)\s*\|\|[^}]*\}\}/g, "${{ $1 }}")
        .replace(/\s+/g, " ")
        .trim();

    const ciGroup = group(CI);
    const metaGroup = group(META);
    expect(ciGroup).toBeTruthy();
    expect(metaGroup).toBeTruthy();
    expect(forPullRequest(metaGroup!)).not.toBe(forPullRequest(ciGroup!));
  });

  it("the metadata workflow never checks out PR code", () => {
    // It reads only the event payload. A checkout would let it execute
    // attacker-controlled code from a fork on a cheap, frequently-triggered path.
    expect(META).not.toContain("actions/checkout");
  });

  it("the attribution pattern is identical in both workflows", () => {
    // The two copies are twins by design; drift means one surface silently stops
    // matching what the other rejects.
    const pat = (y: string) => y.match(/PATTERN='([^']+)'/)?.[1];
    expect(pat(CI)).toBeTruthy();
    expect(pat(META)).toBe(pat(CI));
  });

  it("dependabot is exempted at step level, not job level", () => {
    // A skipped JOB reports a non-success conclusion for its check context. The
    // job must run and the step must skip, so the required check stays conclusive.
    expect(META).toMatch(/- name: No AI attribution in PR title or body\n\s+if: github\.actor != 'dependabot\[bot\]'/);
  });
});
