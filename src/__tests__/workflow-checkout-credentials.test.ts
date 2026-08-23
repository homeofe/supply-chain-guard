/**
 * Checkout-credential contract for every workflow in this repository.
 *
 * WHY THIS EXISTS
 * ---------------
 * `actions/checkout` fails OPEN. At the pinned v7.0.1 its `persist-credentials`
 * input defaults to `true`, and the action then writes the job's `GITHUB_TOKEN`
 * into `.git/config` as an `http.<origin>/.extraheader` basic-auth header. Every
 * later step in that job can read it, including build and test code that arrives
 * from `node_modules`. The secure state is therefore not a state the repository
 * can reach once: it has to be re-asserted on every checkout step that is ever
 * added, forever, or the default quietly comes back.
 *
 * Measured at commit 1a141fe8322345dbd8ec3c449a402eedc3c6d83f: 8 checkout steps,
 * 0 of them set `persist-credentials`. Nothing was exploitable, because five
 * independent controls each closed a leg (`--ignore-scripts` on every real npm
 * invocation, no `pull_request_target` / `workflow_run` / `issue_comment`
 * trigger anywhere, `.git` excluded from the Docker build context with named
 * `COPY`s in the Dockerfile, narrow `upload-artifact` paths, and every `uses:`
 * pinned to a commit SHA). That is exactly why it is worth a check rather than a
 * review note: nothing was going to notice if one of those controls moved.
 *
 * WHAT IS ASSERTED
 * ----------------
 *   1. Every `actions/checkout` step declares `persist-credentials` explicitly.
 *      An omitted key is a FAILURE, not a pass. The point of the contract is that
 *      the value is a decision somebody made, never a default nobody revisited.
 *   2. The value is `false` unless the step's job appears on EXCEPTIONS below.
 *   3. An exception is only valid if the job it names actually runs a remote git
 *      operation. Prose in the allowlist is not enough; the justification has to
 *      be mechanically true of the workflow.
 *   4. The converse: a job that runs a remote git operation MUST be on the
 *      allowlist. Otherwise this contract could break a push by "hardening" it.
 *   5. The step of every exception carries a comment, so the reason is met by
 *      whoever reads the YAML and not only by whoever reads this test.
 *   6. The number of steps this file classified equals the number of
 *      `actions/checkout` references in the same files. A block-walker that
 *      silently skips a step must fail, because "I could not look" must never
 *      report as "I looked and it was fine".
 *
 * Deliberately asserted on the RAW file text, for the same reason recorded at the
 * top of workflow-trigger-contract.test.ts: no YAML parser is a dependency of this
 * package, and adding one to a security scanner so it can lint its own CI would be
 * a poor trade. Line splitting is `\r?\n` throughout, because this repository is
 * worked on from Windows as well as Linux and `.gitattributes` forces LF only for
 * `*.mjs` and `*.sh`, so the same workflow file is CRLF in one checkout and LF in
 * another.
 */
import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const WORKFLOW_DIR = path.join(REPO, ".github/workflows");

/**
 * Checkout steps allowed to keep the credential in `.git/config`.
 *
 * Adding an entry here is a security decision and needs all three of: the job
 * genuinely performing a remote git operation (asserted below), a reason
 * recorded here, and the same reason written as a comment on the step itself.
 */
const EXCEPTIONS: ReadonlyArray<{ workflow: string; job: string; reason: string }> = [
  {
    workflow: "ci.yml",
    job: "update-major-branch",
    reason:
      "The job exists to fast-forward the floating v5 branch with `git push origin`, " +
      "the only push in this repository. git reads that credential from .git/config, " +
      "so persist-credentials: false does not harden this step, it breaks the push and " +
      "freezes the floating v5 branch that every Action consumer resolves.",
  },
];

/** A git subcommand that talks to a remote and therefore needs the credential. */
const REMOTE_GIT = /\bgit\s+(?:push|fetch|pull|clone|ls-remote)\b/;

const workflowFiles = fs
  .readdirSync(WORKFLOW_DIR)
  .filter((f) => /\.ya?ml$/.test(f))
  .sort();

interface CheckoutStep {
  workflow: string;
  job: string;
  /** 1-based line number of the `uses: actions/checkout@` line. */
  line: number;
  /** `true`, `false`, or null when the key is absent. */
  persist: boolean | null;
  /** The step's own lines, comments included. */
  block: string[];
}

/** Strip whole-line comments: the contract is about what executes, not about prose. */
const withoutComments = (lines: string[]) => lines.filter((l) => !/^\s*#/.test(l));

const indentOf = (line: string) => (line.match(/^ */) as RegExpMatchArray)[0].length;

/**
 * Every `actions/checkout` step in one workflow, with the job that owns it and
 * the value it declares. Throws rather than returning a partial answer: a step
 * this function cannot resolve has to surface as a failing test.
 */
function checkoutSteps(workflow: string): CheckoutStep[] {
  const text = fs.readFileSync(path.join(WORKFLOW_DIR, workflow), "utf-8");
  const lines = text.split(/\r?\n/);
  const jobsAt = lines.findIndex((l) => /^jobs:\s*$/.test(l));

  const out: CheckoutStep[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*(?:-\s+)?uses:\s*actions\/checkout@/.test(lines[i]!)) continue;

    // The job key is the nearest preceding two-space top-level key under `jobs:`.
    let jobIdx = i;
    while (jobIdx >= 0 && !/^ {2}[A-Za-z][A-Za-z0-9_-]*:\s*$/.test(lines[jobIdx]!)) jobIdx--;
    if (jobIdx < 0 || jobIdx < jobsAt) {
      throw new Error(`${workflow}:${i + 1}: cannot resolve the job owning this checkout step`);
    }
    const job = (lines[jobIdx]!.match(/^ {2}([A-Za-z][A-Za-z0-9_-]*):/) as RegExpMatchArray)[1]!;

    // The step starts at its own `- ` marker, which is either this line or above it.
    let start = i;
    while (start >= 0 && !/^\s*-\s/.test(lines[start]!)) start--;
    if (start < 0 || start <= jobIdx) {
      throw new Error(`${workflow}:${i + 1}: cannot find the list marker that starts this step`);
    }
    const stepIndent = indentOf(lines[start]!);

    // It ends at the first non-blank line that is not deeper than that marker.
    let end = start + 1;
    while (end < lines.length) {
      const l = lines[end]!;
      if (l.trim() !== "" && indentOf(l) <= stepIndent) break;
      end++;
    }
    const block = lines.slice(start, end);

    const declarations = withoutComments(block).filter((l) => /^\s*persist-credentials:/.test(l));
    if (declarations.length > 1) {
      throw new Error(`${workflow}:${i + 1}: ${declarations.length} persist-credentials keys on one step`);
    }
    let persist: boolean | null = null;
    if (declarations.length === 1) {
      const m = declarations[0]!.match(/^\s*persist-credentials:\s*(\S+)\s*$/);
      if (!m || (m[1] !== "true" && m[1] !== "false")) {
        // Unclassifiable is a failure, never a skip.
        throw new Error(
          `${workflow}:${i + 1}: persist-credentials must be exactly \`true\` or \`false\`, found ${JSON.stringify(
            declarations[0]!.trim(),
          )}`,
        );
      }
      persist = m[1] === "true";
    }

    out.push({ workflow, job, line: i + 1, persist, block });
  }
  return out;
}

/** The lines of one job, comments removed. */
function jobBody(workflow: string, job: string): string {
  const lines = fs.readFileSync(path.join(WORKFLOW_DIR, workflow), "utf-8").split(/\r?\n/);
  const start = lines.findIndex((l) => new RegExp(`^ {2}${job}:\\s*$`).test(l));
  if (start < 0) throw new Error(`${workflow}: no job named ${job}`);
  let end = start + 1;
  while (end < lines.length && !/^ {2}[A-Za-z][A-Za-z0-9_-]*:\s*$/.test(lines[end]!)) end++;
  return withoutComments(lines.slice(start, end)).join("\n");
}

const allSteps = workflowFiles.flatMap((f) => checkoutSteps(f));

const isException = (s: CheckoutStep) =>
  EXCEPTIONS.some((e) => e.workflow === s.workflow && e.job === s.job);

describe("checkout credential contract", () => {
  it("finds every checkout step the raw files contain", () => {
    // Guards the block walker itself. If it silently stopped resolving steps, every
    // assertion below would pass vacuously and the contract would be gone.
    const raw = workflowFiles.reduce(
      (n, f) =>
        n +
        fs
          .readFileSync(path.join(WORKFLOW_DIR, f), "utf-8")
          .split(/\r?\n/)
          .filter((l) => /uses:\s*actions\/checkout@/.test(l)).length,
      0,
    );
    expect(raw, "no checkout step found at all - the scan is broken, not the workflows").toBeGreaterThan(0);
    expect(allSteps.length, "the block walker classified fewer steps than the files declare").toBe(raw);
  });

  it("every checkout step states its credential decision explicitly", () => {
    // An absent key is the v7.0.1 default, which is `true`. Silence is the defect.
    const silent = allSteps
      .filter((s) => s.persist === null)
      .map((s) => `.github/workflows/${s.workflow}:${s.line} (job ${s.job})`);
    expect(
      silent,
      "these checkout steps declare no persist-credentials, so they inherit the action's `true` default",
    ).toEqual([]);
  });

  it("no checkout keeps the credential unless it is a named exception", () => {
    const keeping = allSteps
      .filter((s) => s.persist === true && !isException(s))
      .map((s) => `.github/workflows/${s.workflow}:${s.line} (job ${s.job})`);
    expect(keeping, "add the job to EXCEPTIONS with a reason, or set persist-credentials: false").toEqual([]);
  });

  it("every named exception is a job that actually talks to a remote", () => {
    // Stops the allowlist from becoming a place to park steps that were merely
    // inconvenient to fix. The justification has to be true of the workflow.
    for (const e of EXCEPTIONS) {
      expect(e.reason.trim().length, `EXCEPTIONS entry ${e.workflow}/${e.job} carries no reason`).toBeGreaterThan(40);
      expect(
        jobBody(e.workflow, e.job),
        `job ${e.job} in ${e.workflow} is allowed to persist credentials but runs no remote git command`,
      ).toMatch(REMOTE_GIT);
      const steps = allSteps.filter((s) => s.workflow === e.workflow && s.job === e.job);
      expect(steps.length, `${e.workflow}/${e.job} has no checkout step, so the exception is dead`).toBeGreaterThan(0);
      for (const s of steps) {
        expect(s.persist, `${e.workflow}:${s.line} is an exception but does not set persist-credentials: true`).toBe(
          true,
        );
        expect(
          s.block.some((l) => /^\s*#/.test(l)),
          `${e.workflow}:${s.line} keeps the credential with no comment saying why`,
        ).toBe(true);
      }
    }
  });

  it("a job that talks to a remote is never silently hardened into failing", () => {
    // The converse guard. Setting persist-credentials: false on a pushing job breaks
    // it at release time, which is the worst moment to discover it.
    for (const f of workflowFiles) {
      const lines = fs.readFileSync(path.join(WORKFLOW_DIR, f), "utf-8").split(/\r?\n/);
      const jobsAt = lines.findIndex((l) => /^jobs:\s*$/.test(l));
      expect(jobsAt, `${f} has no jobs block`).toBeGreaterThan(-1);
      // Keyed by LINE INDEX, not by re-finding the reconstructed key text: `on:`,
      // `env:` and `concurrency:` children sit at the same indent, and only keys
      // after `jobs:` are jobs. Matching on the index cannot silently drop a job
      // whose line differs from the string this test would have rebuilt.
      const jobs = lines
        .map((l, i) => [l, i] as const)
        .filter(([l, i]) => i > jobsAt && /^ {2}[A-Za-z][A-Za-z0-9_-]*:\s*$/.test(l))
        .map(([l]) => (l.match(/^ {2}([A-Za-z][A-Za-z0-9_-]*):/) as RegExpMatchArray)[1]!);
      expect(jobs.length, `${f} declares no jobs, so this scan proves nothing about it`).toBeGreaterThan(0);
      for (const j of jobs) {
        if (!REMOTE_GIT.test(jobBody(f, j))) continue;
        expect(
          EXCEPTIONS.some((e) => e.workflow === f && e.job === j),
          `job ${j} in ${f} runs a remote git command but is not in EXCEPTIONS`,
        ).toBe(true);
      }
    }
  });

  it("the exception list is exactly as long as the repository needs", () => {
    // A count, so growing the allowlist is an edit somebody has to make on purpose
    // and a reviewer can see in the diff, rather than a quiet append.
    expect(EXCEPTIONS.length).toBe(1);
    expect(allSteps.filter((s) => s.persist === true).length).toBe(1);
  });
});
