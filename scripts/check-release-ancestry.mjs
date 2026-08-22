#!/usr/bin/env node
/**
 * Release gate: the commit being released must already be on the default branch.
 *
 * WHY THIS EXISTS
 * ---------------
 * This repository's integrity gates are bound to a BRANCH while its release trigger
 * is bound to a TAG, and the two ref namespaces do not intersect. Branch protection,
 * required status checks and enforce_admins are all properties of `refs/heads/main`
 * and are never evaluated on a `refs/tags/*` push. `ci.yml` opts into the tag
 * namespace with its `tags:` trigger and then treated arrival there as sufficient
 * authority to publish. Nothing asserted the relationship between the two.
 *
 * The publish job did already wait on `needs: build`, so the full compat matrix and
 * the container build and scan had to pass before it ran. None of that says where the
 * commit lives. The one pre-publish gate that looked at the tag itself, "Validate
 * immutable release tag", compares the tag STRING against `package.json`. It is
 * satisfied by ANY commit whose version field matches, wherever that commit lives, so
 * it too carries no information about whether the code was ever on `main`.
 *
 * A tag push moves four public distribution channels at once: the npm package and
 * its `latest` dist-tag, the GitHub Release, the container image including `:latest`,
 * and the floating major-version branch that `uses: ...@v5` resolves to. None of them
 * asked where the commit came from.
 *
 * The everyday risk is not an attacker, it is an accident. `docs/ci-and-release.md`
 * already says: tag the MERGED commit on `main`, never the pre-merge commit. This
 * repository squash-merges, so the local pre-merge commit ALWAYS has a different sha
 * from the commit that lands on `main`. Tagging the local one produces a release
 * whose content looks identical, whose run is green end to end with no failing step,
 * and whose divergence is visible only in the provenance sha. That rule existed only
 * in prose. This script is the same rule as a gate.
 *
 * That has never happened here. Measured on 2026-08-22, all 138 semver tags published
 * to date are ancestors of `main` and none is not, and the runbook sentence quoted
 * above was only written down on 2026-08-20, in the 5.28.0 release, which 135 of those
 * tags predate. This gate closes a latent defect found by inspection. It is not the
 * response to an incident: nothing was ever published off `main`.
 *
 * Provenance does not cover this. An off-main release carries a genuine, verifiable
 * attestation naming a commit that is absent from `main`'s history, and signature
 * verification passes on it. Provenance is forensics, not prevention.
 *
 * USAGE
 * -----
 *   node scripts/check-release-ancestry.mjs [options]
 *
 *   --commit <sha>    commit to check; defaults to $GITHUB_SHA
 *   --branch <name>   branch it must be on; defaults to "main"
 *   --remote <name>   remote to fetch that branch from; defaults to "origin"
 *   --repo <dir>      repository to run in; defaults to the current directory
 *
 * Outside GitHub Actions $GITHUB_SHA is empty, so --commit is REQUIRED there and the
 * script exits 2 rather than passing on nothing. The pre-tag check a maintainer runs
 * from the merged commit is:
 *
 *   npm run check:release-ancestry -- --commit HEAD
 *
 * EXIT CODES (each outcome has its own code, deliberately)
 * -------------------------------------------------------
 *   0  the commit IS an ancestor of the branch, or is the branch tip itself
 *   2  usage error: no commit to check, or a rejected branch/remote name
 *   3  the commit is not present in this repository
 *   4  the repository is SHALLOW, so ancestry cannot be decided here
 *   5  the branch could not be fetched or resolved, or git failed
 *   6  the commit is NOT an ancestor of the branch
 *
 * "Cannot answer" (2, 3, 4, 5) is kept distinct from "answered no" (6) on purpose.
 * A caller that treats every non-zero code as the same thing cannot tell a gate that
 * rejected a commit from a gate that never ran, and a test that asserts merely
 * "non-zero" would pass on a mutation that broke the comparison itself.
 *
 * WHY A SHALLOW REPOSITORY IS A HARD FAILURE
 * ------------------------------------------
 * `actions/checkout` fetches depth 1 unless told otherwise, and the publish job did
 * exactly that. In a shallow checkout `git merge-base --is-ancestor` answers from the
 * commits it happens to hold, so the most likely way this gate decays is that someone
 * removes `fetch-depth: 0` and it keeps reporting green while inspecting almost
 * nothing. Refusing to answer is loud and blocks the release; answering wrongly is
 * silent and ships it.
 *
 * WHAT THIS GATE CANNOT DO
 * ------------------------
 * This gate is a STEP IN A WORKFLOW FILE, and Actions runs a workflow from the file
 * present at the PUSHED ref. So it binds only tags whose commit already contains it.
 *
 *   1. Transitional: a tag cut from a commit that predates this change carries a
 *      ci.yml without this step and still publishes ungated.
 *   2. Permanent: an actor who controls the commit also controls its ci.yml and can
 *      simply omit the step. This closes the ACCIDENT, the wrong sha out of two that
 *      look identical after a squash merge. It cannot close the deliberate case.
 *
 * The control for the deliberate case is a repository ruleset restricting creation of
 * refs/tags/v*, which is an access-control change and an open owner decision on
 * https://github.com/homeofe/supply-chain-guard/issues/167. Nothing in this file
 * should be read as covering it.
 *
 * Two smaller limits, for the same reason:
 *   * Both workflows call this script with no arguments, so --branch is not reachable
 *     from a release. A release cut from a maintenance branch exits 6 until someone
 *     edits the workflow, which is deliberate rather than accidental.
 *   * The check performs a network `git fetch`, so an unreachable remote surfaces as
 *     exit 5, a red release rather than a silent pass. It does not need the checkout's
 *     credentials: this repository is public and an unauthenticated ls-remote of
 *     refs/heads/main was verified to resolve on 2026-08-22, so persist-credentials:
 *     false, proposed on issue 179 of this repository, leaves this gate working. See
 *     https://github.com/homeofe/supply-chain-guard/issues/179
 */
import { spawnSync } from "node:child_process";
import process from "node:process";

const EXIT_OK = 0;
const EXIT_USAGE = 2;
const EXIT_UNKNOWN_COMMIT = 3;
const EXIT_SHALLOW = 4;
const EXIT_BRANCH_UNRESOLVED = 5;
const EXIT_NOT_ANCESTOR = 6;

/** Conservative ref-name shape. Also rejects a leading "-", which git would read as a flag. */
const REF_NAME = /^[A-Za-z0-9][A-Za-z0-9._/-]*$/;

function fail(code, title, message) {
  console.error(`::error title=${title}::${message}`);
  process.exit(code);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const known = ["--commit", "--branch", "--remote", "--repo"];
    if (!known.includes(arg)) {
      fail(EXIT_USAGE, "Bad argument", `unrecognised argument "${arg}". See the header of scripts/check-release-ancestry.mjs.`);
    }
    const value = argv[++i];
    if (value === undefined) fail(EXIT_USAGE, "Bad argument", `${arg} needs a value.`);
    out[arg.slice(2)] = value;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const cwd = args.repo || process.cwd();
const commit = args.commit || process.env.GITHUB_SHA || "";
const branch = args.branch || "main";
const remote = args.remote || "origin";

/** Run git and hand back status plus output. Never uses a shell, so no argument is ever re-parsed. */
const git = (...gitArgs) => {
  const r = spawnSync("git", gitArgs, { cwd, encoding: "utf8" });
  if (r.error) {
    fail(EXIT_BRANCH_UNRESOLVED, "git unavailable", `could not run git: ${r.error.message}`);
  }
  return { status: r.status, stdout: (r.stdout || "").trim(), stderr: (r.stderr || "").trim() };
};

if (!commit) {
  fail(
    EXIT_USAGE,
    "No commit to check",
    "no --commit given and GITHUB_SHA is empty. Refusing to pass without checking anything.",
  );
}
for (const [label, value] of [["branch", branch], ["remote", remote]]) {
  if (!REF_NAME.test(value)) {
    fail(EXIT_USAGE, "Bad name", `${label} name "${value}" is not an accepted ref name.`);
  }
}

const inside = git("rev-parse", "--is-inside-work-tree");
if (inside.status !== 0 || inside.stdout !== "true") {
  fail(EXIT_BRANCH_UNRESOLVED, "Not a git repository", `${cwd} is not a git work tree. ${inside.stderr}`);
}

// Before anything else: a shallow repository cannot answer this question. See the header.
const shallow = git("rev-parse", "--is-shallow-repository");
if (shallow.stdout === "true") {
  fail(
    EXIT_SHALLOW,
    "Shallow checkout",
    `this repository is shallow, so ancestry cannot be decided. Check out with fetch-depth: 0 before running this gate.`,
  );
}

const resolved = git("rev-parse", "--verify", "--quiet", `${commit}^{commit}`);
if (resolved.status !== 0 || !resolved.stdout) {
  fail(
    EXIT_UNKNOWN_COMMIT,
    "Unknown commit",
    `${commit} is not a commit in this repository, so its ancestry cannot be checked.`,
  );
}
const commitSha = resolved.stdout;

// Fetch the branch explicitly rather than trusting whatever refs the checkout left
// behind. --no-tags is deliberate: this runs on a tag ref during a release, and
// walking the tag namespace here fetches a great deal that is not being asked about.
const fetched = git("fetch", "--no-tags", remote, `+refs/heads/${branch}:refs/remotes/${remote}/${branch}`);
if (fetched.status !== 0) {
  fail(
    EXIT_BRANCH_UNRESOLVED,
    "Branch not fetched",
    `could not fetch ${branch} from ${remote}: ${fetched.stderr || fetched.stdout}`,
  );
}

const tip = git("rev-parse", "--verify", "--quiet", `refs/remotes/${remote}/${branch}^{commit}`);
if (tip.status !== 0 || !tip.stdout) {
  fail(EXIT_BRANCH_UNRESOLVED, "Branch not resolved", `${remote}/${branch} does not resolve to a commit.`);
}
const branchSha = tip.stdout;

const ancestry = git("merge-base", "--is-ancestor", commitSha, branchSha);
// git answers 0 for yes and 1 for no. Anything else is git failing, which is NOT an
// answer of "no" and must not be reported as one.
if (ancestry.status !== 0 && ancestry.status !== 1) {
  fail(
    EXIT_BRANCH_UNRESOLVED,
    "Ancestry check failed",
    `git merge-base exited ${ancestry.status}: ${ancestry.stderr || ancestry.stdout}`,
  );
}
if (ancestry.status === 1) {
  console.error(`commit:        ${commitSha}`);
  console.error(`${remote}/${branch}:   ${branchSha}`);
  fail(
    EXIT_NOT_ANCESTOR,
    "Release commit is not on " + branch,
    `${commitSha} is not an ancestor of ${remote}/${branch}. Tag the MERGED commit on ${branch}, never the pre-merge commit. Nothing has been published.`,
  );
}

console.log(
  `check:release-ancestry OK - ${commitSha} is an ancestor of ${remote}/${branch} (${branchSha}).`,
);
process.exit(EXIT_OK);
