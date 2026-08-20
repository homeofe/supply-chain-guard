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
 *   synchronize       -> both  (see below - NOT because metadata changed)
 *   ready_for_review  -> NOTHING             (creates no new sha; see below)
 *   edited            -> pr-metadata-policy only  (title/body cannot change code)
 *   push (main, tags) -> ci.yml only
 *
 * `synchronize` reaching the metadata workflow looks redundant and is not. A
 * required status check is evaluated against the check-runs on the HEAD COMMIT, so
 * a workflow that never runs on `synchronize` leaves every pushed-to PR with a head
 * sha carrying no run of it, and the required context blocks on a check that never
 * arrives. The asymmetry is deliberate: ci.yml must NOT see `edited` because its job
 * costs two minutes and metadata cannot change code, while the metadata workflow
 * must see `synchronize` because its check has to exist on every sha, and six
 * seconds with no checkout is what makes that affordable.
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
const AAHP = fs.readFileSync(
  path.join(REPO, ".github/workflows/aahp-verify.yml"),
  "utf-8",
);

/** The three contexts branch protection requires, and the file that must produce each. */
const REQUIRED: Array<[string, string]> = [
  ["Build and Test", ".github/workflows/ci.yml"],
  ["aahp-verify", ".github/workflows/aahp-verify.yml"],
  ["PR metadata policy", ".github/workflows/pr-metadata-policy.yml"],
];

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
    for (const t of ["opened", "synchronize", "reopened"]) {
      expect(types).toContain(t);
    }
  });

  it("metadata policy runs on edit AND on every event that makes a new head sha", () => {
    const types = pullRequestTypes(META);
    expect(types).toContain("edited");
    expect(types).toContain("opened");
    expect(types).toContain("reopened");
    // The one that is easy to delete as redundant. A required check is evaluated
    // against the head commit's check-runs, so dropping `synchronize` leaves every
    // pushed-to PR blocked on a context that never reports. Measured on PR #159
    // before it was added: head sha 03e75fd carried a CI run, an AAHP Verify run,
    // and no metadata run at all.
    expect(types).toContain("synchronize");
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

    // Pairwise across ALL THREE required-check producers, not just the original
    // pair. Concurrency groups are REPOSITORY-wide, so two workflows that happen to
    // pick the same prefix would serialise and cancel each other's runs, and the
    // symptom would be an unrelated required check mysteriously going cancelled.
    const groups = [["ci.yml", CI], ["pr-metadata-policy.yml", META], ["aahp-verify.yml", AAHP]] as const;
    const resolved = groups.map(([name, yaml]) => {
      const g = group(yaml);
      expect(g, `${name} declares no concurrency group`).toBeTruthy();
      return [name, forPullRequest(g!)] as const;
    });
    for (let i = 0; i < resolved.length; i++) {
      for (let j = i + 1; j < resolved.length; j++) {
        expect(
          resolved[i]![1],
          `${resolved[i]![0]} and ${resolved[j]![0]} resolve to the same concurrency group on a pull_request event`,
        ).not.toBe(resolved[j]![1]);
      }
    }
  });

  it("every required context has exactly one producing workflow", () => {
    // The check-run name is the contract with branch protection. This asserts the
    // name appears in the file that owns it and in NO other workflow.
    const dir = path.join(REPO, ".github/workflows");
    for (const [context, owner] of REQUIRED) {
      const producers = fs
        .readdirSync(dir)
        .filter((f) => /\.ya?ml$/.test(f))
        .filter((f) => new RegExp(`^\\s*name:\\s*${context}\\s*$`, "m").test(
          fs.readFileSync(path.join(dir, f), "utf-8"),
        ))
        .map((f) => `.github/workflows/${f}`);
      expect(producers, `context "${context}" must be produced by exactly one workflow`).toEqual([owner]);
    }
  });

  it("no job in a required-check workflow is left unnamed", () => {
    // A job with no `name:` still produces a check run, using the JOB KEY as the
    // context. aahp-verify relied on that coincidence: the key happened to equal the
    // required context, so renaming the key would have silently deleted the context
    // branch protection waits for.
    for (const [, file] of REQUIRED) {
      const yaml = fs.readFileSync(path.join(REPO, file), "utf-8");
      const jobsAt = yaml.indexOf("\njobs:");
      expect(jobsAt, `${file} has no jobs block`).toBeGreaterThan(-1);
      const jobKeys = [...yaml.slice(jobsAt).matchAll(/^ {2}([a-z][a-z0-9_-]*):$/gm)].map((m) => m[1]!);
      expect(jobKeys.length, `${file} declares no jobs`).toBeGreaterThan(0);
      const named = [...yaml.slice(jobsAt).matchAll(/^ {4}name:/gm)].length;
      expect(named, `${file} has ${jobKeys.length} job(s) but only ${named} explicit name(s)`).toBe(jobKeys.length);
    }
  });

  it("the metadata workflow cancels superseded runs", () => {
    // Load-bearing for a property measured on PR #159: because a superseded run
    // is only ever cancelled BY a newer run in the same group, and that newer run
    // then runs to completion, the newest run for this check name is never the
    // cancelled one - which is what keeps a cancelled twin from becoming the
    // effective result. Turning this off would also let two runs race and let one
    // that inspected the older body finish last.
    expect(META).toMatch(/cancel-in-progress:\s*true/);
  });

  it("the handoff gate runs on every event that creates a head sha", () => {
    // Same rule as the metadata workflow, and it was previously implicit: this file
    // had no `types:` at all, so it inherited GitHub's default and the contract was
    // whatever that default happened to be. Now it is written down and asserted.
    const types = pullRequestTypes(AAHP);
    for (const t of ["opened", "synchronize", "reopened"]) expect(types).toContain(t);
    expect(types).not.toContain("edited");
  });

  it("code validation does not run on ready_for_review either", () => {
    // It creates no new head sha and no job here is draft-gated, so a draft PR's
    // opened/synchronize runs already made the sha conclusive. Re-adding it starts a
    // duplicate full matrix on an identical tree and, with cancel-in-progress on for
    // pull_request, can cancel an in-flight run and replace a green result.
    expect(pullRequestTypes(CI)).not.toContain("ready_for_review");
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
    // `\s+` rather than `\n\s+`: this repository is worked on from Windows as
    // well as Linux and has no .gitattributes forcing LF, so the same file is
    // CRLF in one checkout and LF in another. A hardcoded \n passes on the CI
    // runner and fails on a Windows clone, which is a test that reports on the
    // checkout rather than on the thing it claims to assert.
    expect(META).toMatch(/- name: No AI attribution in PR title or body\s+if: github\.actor != 'dependabot\[bot\]'/);
  });
});
