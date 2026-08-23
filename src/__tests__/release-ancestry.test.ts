/**
 * The release-authority gate: a tagged commit may only be published if it is already
 * on `main` (scripts/check-release-ancestry.mjs, wired into ci.yml and docker.yml).
 *
 * WHY THIS EXISTS
 * ---------------
 * Required status checks, branch protection and enforce_admins are properties of
 * `refs/heads/main`. The publish trigger is a `refs/tags/*` push. The two namespaces
 * do not intersect, so none of those gates is ever evaluated on the commit that is
 * actually released. `needs: build` did already hold the publish job until the compat
 * matrix and the container build and scan passed, but none of that says where the
 * commit lives, and the one pre-publish gate that looked at the tag compares the tag
 * STRING against `package.json`, so it is satisfied by ANY commit whose version field
 * matches, wherever it lives.
 *
 * The everyday route into that hole is not an attacker. This repository squash-merges,
 * so the local pre-merge commit ALWAYS has a different sha from the commit that lands
 * on `main`, while its content looks identical. `docs/ci-and-release.md` says to tag
 * the merged one. That rule lived only in prose until this gate, and no release ever
 * broke it: measured 2026-08-22, all 138 semver tags to date are ancestors of `main`.
 * These tests pin a latent defect closed, not an incident cleaned up.
 *
 * They also do not, and cannot, cover the deliberate case. Actions runs a workflow
 * from the file at the pushed ref, so the gate binds only tags whose commit already
 * contains it. See the "WHAT THIS GATE CANNOT DO" section of the script header.
 *
 * WHAT THESE TESTS ARE FOR, AND HOW TO REDDEN THEM ON PURPOSE
 * ----------------------------------------------------------
 * Half of them drive the real script against real git repositories, and half assert
 * that the two publish workflows actually call it. Both halves are needed: a correct
 * script no workflow invokes is not a fix, and a wired-up script that answers wrongly
 * is worse than no script.
 *
 * Every outcome is asserted by its EXACT exit code, never by "non-zero". The script
 * gives "cannot answer" (2, 3, 4, 5) and "answered no" (6) different codes precisely
 * so that a test cannot mistake a gate that never ran for a gate that rejected
 * something. A reviewer who wants to watch these go red can:
 *   - swap the two arguments to `git merge-base --is-ancestor` in the script, which is
 *     the realistic version of this bug, and reverses the question being asked; or
 *   - delete the `if (ancestry.status === 1)` block, which is the gate itself; or
 *   - delete the `- name: Require the released commit to be on main` step from either
 *     workflow, which unwires it.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

const REPO = path.resolve(__dirname, "..", "..");
const GATE = path.join(REPO, "scripts", "check-release-ancestry.mjs");
const CI = fs.readFileSync(path.join(REPO, ".github/workflows/ci.yml"), "utf-8");
const DOCKER = fs.readFileSync(path.join(REPO, ".github/workflows/docker.yml"), "utf-8");

/** The exit codes documented in the script header. Kept as names so failures read. */
const EXIT = {
  OK: 0,
  USAGE: 2,
  UNKNOWN_COMMIT: 3,
  SHALLOW: 4,
  BRANCH_UNRESOLVED: 5,
  NOT_ANCESTOR: 6,
} as const;

let tmp: string;
let upstream: string;
let work: string;
let shallow: string;
/** Tip of `main`, an older commit on `main`, an unmerged branch commit, an unpushed one. */
let mainTip: string;
let mainOlder: string;
let sideCommit: string;
let offMain: string;

/**
 * Every git invocation carries its own identity and skips hooks and signing, so the
 * fixture cannot inherit whatever the machine running the suite happens to configure.
 */
const git = (cwd: string, ...args: string[]): string => {
  const r = spawnSync(
    "git",
    ["-c", "user.email=gate@example.invalid", "-c", "user.name=Gate Fixture", "-c", "commit.gpgsign=false", ...args],
    { cwd, encoding: "utf8" },
  );
  if (r.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed in ${cwd}: ${r.stderr || r.stdout}`);
  }
  return (r.stdout || "").trim();
};

const commitAll = (cwd: string, message: string): string => {
  git(cwd, "add", "-A");
  git(cwd, "commit", "--no-verify", "-q", "-m", message);
  return git(cwd, "rev-parse", "HEAD");
};

/**
 * Run the gate. GITHUB_SHA is blanked by default: the suite itself runs inside GitHub
 * Actions, where that variable is always set, and a test that silently read the real
 * one would be asserting against the wrong repository.
 */
const runGate = (args: string[], env: Record<string, string> = {}) =>
  spawnSync(process.execPath, [GATE, ...args], {
    encoding: "utf8",
    env: { ...process.env, GITHUB_SHA: "", ...env },
  });

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scg-ancestry-"));
  upstream = path.join(tmp, "upstream");
  work = path.join(tmp, "work");
  shallow = path.join(tmp, "shallow");

  fs.mkdirSync(upstream, { recursive: true });
  git(upstream, "init", "-q", "-b", "main");
  fs.writeFileSync(path.join(upstream, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0" }, null, 2));
  mainOlder = commitAll(upstream, "first release");
  fs.writeFileSync(path.join(upstream, "README.md"), "second\n");
  mainTip = commitAll(upstream, "second release");

  // A branch that exists on the remote and was never merged. Tagging one of these is
  // the deliberate version of the mistake.
  git(upstream, "checkout", "-q", "-b", "unmerged-work");
  fs.writeFileSync(path.join(upstream, "feature.txt"), "feature\n");
  sideCommit = commitAll(upstream, "unmerged feature");
  git(upstream, "checkout", "-q", "main");

  git(tmp, "clone", "-q", upstream, work);

  // The accidental version, and the one this repository is actually exposed to: a
  // local pre-merge commit that carries the release version bump. After a squash
  // merge the commit that lands on main has a different sha, and this one never
  // reaches main at all.
  git(work, "checkout", "-q", "-b", "release-prep");
  fs.writeFileSync(path.join(work, "package.json"), JSON.stringify({ name: "fixture", version: "9.9.9" }, null, 2));
  offMain = commitAll(work, "release 9.9.9");

  // Depth 1 is what actions/checkout does unless told otherwise, which is what the
  // publish job used to do. --no-local forces a transport that honours --depth.
  git(tmp, "clone", "-q", "--no-local", "--depth", "1", upstream, shallow);
}, 120_000);

afterAll(() => {
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

describe("release ancestry gate: behaviour", () => {
  it("passes the merged commit at the tip of main", () => {
    const r = runGate(["--commit", mainTip, "--repo", work]);
    expect(r.status, r.stderr).toBe(EXIT.OK);
    expect(r.stdout).toContain(mainTip);
  }, 30_000);

  it("passes an older commit on main, not only the tip", () => {
    // A release is often cut from a commit that main has already moved past. If the
    // gate compared for equality instead of ancestry, this is the test that says so.
    const r = runGate(["--commit", mainOlder, "--repo", work]);
    expect(r.status, r.stderr).toBe(EXIT.OK);
  }, 30_000);

  it("rejects the local pre-merge commit with the not-on-main code", () => {
    const r = runGate(["--commit", offMain, "--repo", work]);
    expect(r.status, r.stdout + r.stderr).toBe(EXIT.NOT_ANCESTOR);
    expect(r.stderr).toContain(offMain);
    expect(r.stderr).toContain("is not an ancestor");
  }, 30_000);

  it("rejects a commit on a branch that was pushed but never merged", () => {
    // Reachable from the remote, so a fetch finds it; still not on main.
    const r = runGate(["--commit", sideCommit, "--repo", work]);
    expect(r.status, r.stdout + r.stderr).toBe(EXIT.NOT_ANCESTOR);
  }, 30_000);

  it("catches what the tag validator cannot: the same commit passes that one", () => {
    // The finding, encoded. The publish job's pre-existing gate, "Validate immutable
    // release tag", is READ OUT OF ci.yml rather than restated here, so it cannot
    // drift from the thing actually shipping, and executed against the off-main
    // commit's tree. It passes, because all it compares is the tag string against
    // package.json. That is why an ancestry gate had to be added rather than the
    // existing one tightened.
    // Anchored to the step that owns it, NOT to the first `node -e` in the
    // file. The self-scan step added later also runs a `node -e`, and it sits
    // earlier in ci.yml, so a positional match silently selected that one and
    // executed it in a temp repo without its environment. Reading the real
    // command out of ci.yml is the property worth keeping; selecting it by
    // position was the part that could not survive a second command being added.
    const VALIDATOR_STEP = "- name: Validate immutable release tag";
    const stepAt = CI.indexOf(VALIDATOR_STEP);
    expect(stepAt, `ci.yml no longer has a step named ${VALIDATOR_STEP}`).toBeGreaterThan(-1);
    const oneLiner = CI.slice(stepAt).match(/node -e '([^']*)'/)?.[1];
    expect(oneLiner, "ci.yml no longer contains the tag validator one-liner").toBeTruthy();

    const validator = spawnSync(process.execPath, ["-e", oneLiner!], {
      cwd: work,
      encoding: "utf8",
      env: { ...process.env, GITHUB_REF_NAME: "v9.9.9" },
    });
    expect(git(work, "rev-parse", "HEAD")).toBe(offMain);
    expect(validator.status, "the tag validator no longer accepts an off-main commit").toBe(0);

    const gate = runGate(["--commit", offMain, "--repo", work]);
    expect(gate.status).toBe(EXIT.NOT_ANCESTOR);
  }, 30_000);

  it("refuses to answer in a shallow checkout even when the commit IS on main", () => {
    // The rot guard. Removing `fetch-depth: 0` from a publish checkout is the most
    // plausible way this gate decays, and the failure mode that matters is the silent
    // one. This asserts the loud outcome: its own exit code, and NOT a pass.
    const tip = git(shallow, "rev-parse", "HEAD");
    expect(tip).toBe(mainTip);
    const r = runGate(["--commit", tip, "--repo", shallow]);
    expect(r.status, r.stdout + r.stderr).toBe(EXIT.SHALLOW);
  }, 30_000);

  it("separates cannot-answer from answered-no when the branch does not exist", () => {
    // A gate that reported "not on main" here would be indistinguishable from one
    // that had really looked, and a typo in the branch name would read as a finding.
    const r = runGate(["--commit", mainTip, "--branch", "no-such-branch", "--repo", work]);
    expect(r.status, r.stdout + r.stderr).toBe(EXIT.BRANCH_UNRESOLVED);
  }, 30_000);

  it("reports an unknown commit as unknown rather than as not-on-main", () => {
    const r = runGate(["--commit", "0".repeat(40), "--repo", work]);
    expect(r.status, r.stdout + r.stderr).toBe(EXIT.UNKNOWN_COMMIT);
  }, 30_000);

  it("refuses to pass when it has nothing to check", () => {
    // The workflows pass no --commit and rely on GITHUB_SHA. If that is ever empty,
    // the gate must fail rather than sail through having inspected nothing.
    const r = runGate(["--repo", work]);
    expect(r.status, r.stdout + r.stderr).toBe(EXIT.USAGE);
  }, 30_000);

  it("reads the commit from GITHUB_SHA, which is how the workflows call it", () => {
    const ok = runGate(["--repo", work], { GITHUB_SHA: mainTip });
    expect(ok.status, ok.stderr).toBe(EXIT.OK);
    // Same call shape, off-main commit: the environment path is gated too, not just
    // the argument path.
    const bad = runGate(["--repo", work], { GITHUB_SHA: offMain });
    expect(bad.status, bad.stdout + bad.stderr).toBe(EXIT.NOT_ANCESTOR);
  }, 30_000);
});

/**
 * Drop comment lines before asserting on wiring.
 *
 * Not cosmetic. The comment above the publish job names the gate script, so deleting
 * the STEP that runs it still leaves the string in the file: measured, `grep -c
 * check-release-ancestry .github/workflows/ci.yml` returns 1 with the step gone. A
 * wiring test that searched the raw text would have reported a wired-up gate that no
 * longer runs, which is the exact failure class this whole change exists to close.
 */
const executable = (yaml: string): string =>
  yaml
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");

/** The block of a workflow file belonging to one job key. */
function jobBlock(yaml: string, key: string): string {
  const start = yaml.search(new RegExp(`^ {2}${key}:\\s*?$`, "m"));
  expect(start, `no job "${key}"`).toBeGreaterThan(-1);
  const rest = yaml.slice(start + 1);
  const next = rest.search(/^ {2}[a-z][a-z0-9_-]*:\s*?$/m);
  return next === -1 ? yaml.slice(start) : yaml.slice(start, start + 1 + next);
}

/** The block of one `- name: ...` step, up to the next step at the same indent. */
function stepBlock(jobYaml: string, stepName: string): string {
  const start = jobYaml.indexOf(`- name: ${stepName}`);
  expect(start, `no step "${stepName}"`).toBeGreaterThan(-1);
  const rest = jobYaml.slice(start + 1);
  const next = rest.search(/^ {6}- /m);
  return next === -1 ? jobYaml.slice(start) : jobYaml.slice(start, start + 1 + next);
}

const GATE_STEP = "Require the released commit to be on main";
const GATE_CALL = "node scripts/check-release-ancestry.mjs";

describe("release ancestry gate: wiring", () => {
  it("guards npm publish, before the publish step runs", () => {
    const publish = executable(jobBlock(CI, "publish"));
    const gateAt = publish.indexOf(GATE_CALL);
    const publishAt = publish.indexOf("npm publish");
    expect(gateAt, "the publish job does not call the ancestry gate").toBeGreaterThan(-1);
    expect(publishAt).toBeGreaterThan(-1);
    expect(gateAt).toBeLessThan(publishAt);
  });

  it("guards the container manifest push, before the tags move", () => {
    // ci.yml is not the only publish path: docker.yml has its own tag trigger and
    // moves :latest and :X.Y.Z by itself, so gating only npm would leave the image
    // channel open to exactly the commit npm had just refused.
    const merge = executable(jobBlock(DOCKER, "merge"));
    const gateAt = merge.indexOf(GATE_CALL);
    const pushAt = merge.indexOf("imagetools create");
    expect(gateAt, "the manifest job does not call the ancestry gate").toBeGreaterThan(-1);
    expect(pushAt).toBeGreaterThan(-1);
    expect(gateAt).toBeLessThan(pushAt);
  });

  it("gives both gated jobs the full history the gate needs", () => {
    // Without this the gate cannot answer and refuses, so every release goes red.
    // Asserted per JOB, because a fetch-depth elsewhere in the file would satisfy a
    // whole-file search while the gated job stayed shallow.
    for (const [label, block] of [
      ["ci.yml publish", executable(jobBlock(CI, "publish"))],
      ["docker.yml merge", executable(jobBlock(DOCKER, "merge"))],
    ] as const) {
      expect(block, `${label} checks out without fetch-depth: 0`).toMatch(/fetch-depth:\s*0/);
      expect(block.search(/fetch-depth:\s*0/), `${label} fetches the history after the gate ran`).toBeLessThan(
        block.indexOf(GATE_CALL),
      );
    }
  });

  it("leaves the gate step unconditional in both workflows", () => {
    // An `if:` here is how this becomes decorative: the step reports green by being
    // skipped, and a skipped step is not a passing one. The tag condition belongs on
    // the publish JOB, which already carries it, not on the gate step.
    for (const [label, yaml, job] of [
      ["ci.yml", CI, "publish"],
      ["docker.yml", DOCKER, "merge"],
    ] as const) {
      const step = executable(stepBlock(jobBlock(yaml, job), GATE_STEP));
      expect(step, `${label} conditions the ancestry gate away`).not.toMatch(/^\s+if:/m);
      expect(step).toContain(GATE_CALL);
    }
  });
});
