/**
 * Layer 2 base-selection contract for the required `aahp-verify` status check.
 *
 * WHY THIS EXISTS
 * ---------------
 * The content-drift gate answers "did code change without the handoff state
 * changing?", and to answer it at all it needs a base commit to diff HEAD
 * against. Up to CLI 3.9.2 the gate INFERRED that base from repository state:
 * it preferred the upstream tracking branch, then `origin/main`. On a push to
 * `main`, `actions/checkout` sets the local `main` to track `origin/main` at
 * the pushed commit, so the inferred base WAS HEAD. The gate then diffed HEAD
 * against itself, got an empty change set, and printed
 *
 *   OK: No source files changed outside .ai/handoff/. Drift gate not triggered.
 *
 * A required status check reported success having compared nothing. "There was
 * nothing to compare" and "there was nothing wrong" produced identical green
 * output, so the failure was invisible from the outside.
 *
 * The repair has two halves and NEITHER works alone:
 *   1. The CLI must be able to be told a base, and must refuse a degenerate
 *      one. CLI 3.10.0 reads `--base` / `AAHP_BASE_SHA`, requires it at
 *      `--level ci`, and turns a missing, all-zero, malformed, unreadable or
 *      HEAD-equal base into a blocking failure instead of an empty diff.
 *      Passing a base to 3.9.2 is a no-op, because 3.9.2 never reads one.
 *   2. The workflow must actually pass the base the EVENT knows, per event:
 *      the pull request base SHA, the push `before` SHA, a required input on a
 *      manual run.
 *
 * So this file asserts both halves, and asserts the push leg resolves to the
 * PRE-PUSH commit rather than to the pushed commit. That last assertion is the
 * one that encodes the defect: any selector that resolves to the commit under
 * test reproduces "compare a thing to itself" no matter how explicit it looks.
 *
 * Asserted on the RAW workflow text and on a hand-written evaluator for the
 * `||` chain, for the reason the sibling trigger-contract test gives: no YAML
 * parser is a dependency of this package, and adding one to a security scanner
 * so it can lint its own CI would be a poor trade. Comparing the selector as a
 * STRING would not be enough either: two different expressions can resolve to
 * the same commit for a given event, which is exactly how the defect hid.
 */
import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const AAHP_WORKFLOW = ".github/workflows/aahp-verify.yml";
const AAHP = fs.readFileSync(path.join(REPO, AAHP_WORKFLOW), "utf-8");

/** Lowest CLI that reads an explicit base and rejects a HEAD-equal one. */
const MIN_CLI = [3, 10, 0] as const;

/** Distinct sentinels, so "resolved to the right thing" cannot be luck. */
const PR_BASE_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PR_MERGE_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PUSHED_SHA = "cccccccccccccccccccccccccccccccccccccccc";
const PRE_PUSH_SHA = "dddddddddddddddddddddddddddddddddddddddd";
const DISPATCH_INPUT_SHA = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/**
 * The context values GitHub would expose for each event. `undefined` means the
 * expression is falsy there, which is what makes `||` fall through.
 *
 * `github.sha` on a push is the PUSHED commit, and on a pull request it is the
 * merge commit. Both are HEAD at the moment the gate runs, so both are listed
 * as known-but-wrong answers rather than left out of the table.
 */
const CONTEXTS: Record<string, Record<string, string | undefined>> = {
  push: {
    "github.event.pull_request.base.sha": undefined,
    "github.event.before": PRE_PUSH_SHA,
    "inputs.base": undefined,
    "github.event.inputs.base": undefined,
    "github.sha": PUSHED_SHA,
    "github.event.after": PUSHED_SHA,
    "github.event.head_commit.id": PUSHED_SHA,
    "github.ref": "refs/heads/main",
  },
  pull_request: {
    "github.event.pull_request.base.sha": PR_BASE_SHA,
    "github.event.before": undefined,
    "inputs.base": undefined,
    "github.event.inputs.base": undefined,
    "github.sha": PR_MERGE_SHA,
    "github.event.after": undefined,
    "github.event.head_commit.id": undefined,
    "github.ref": "refs/pull/1/merge",
  },
  workflow_dispatch: {
    "github.event.pull_request.base.sha": undefined,
    "github.event.before": undefined,
    "inputs.base": DISPATCH_INPUT_SHA,
    "github.event.inputs.base": DISPATCH_INPUT_SHA,
    "github.sha": PUSHED_SHA,
    "github.event.after": undefined,
    "github.event.head_commit.id": undefined,
    "github.ref": "refs/heads/main",
  },
};

/** HEAD, per event: the commit the gate is being asked to judge. */
const HEAD_OF: Record<string, string> = {
  push: PUSHED_SHA,
  pull_request: PR_MERGE_SHA,
  workflow_dispatch: PUSHED_SHA,
};

const LINES = AAHP.split(/\r?\n/);
const indentOf = (line: string) => line.length - line.trimStart().length;

/**
 * The body of the block introduced by `key:` at `indent`, as raw lines.
 *
 * Slicing between two `indexOf` markers instead would swallow whatever sits
 * between them: everything from `on:` to `jobs:` also contains `permissions:`
 * and `concurrency:`, whose own two-space children would then be read as
 * declared triggers.
 */
function blockOf(key: string, indent: number): string[] {
  const head = " ".repeat(indent) + key + ":";
  const start = LINES.indexOf(head);
  if (start === -1) throw new Error(`${AAHP_WORKFLOW} has no "${key}:" block at indent ${indent}`);
  const body: string[] = [];
  for (let i = start + 1; i < LINES.length; i++) {
    const line = LINES[i]!;
    if (line.trim() === "") continue;
    if (indentOf(line) <= indent) break;
    body.push(line);
  }
  return body;
}

/** The value the verify step binds to AAHP_BASE_SHA, as written in the file. */
function baseSelector(): string {
  const m = AAHP.match(/^[^\S\n]*AAHP_BASE_SHA:[^\S\n]*(\S.*?)[^\S\n]*$/m);
  if (!m) {
    throw new Error(
      `${AAHP_WORKFLOW} binds no AAHP_BASE_SHA, so the CI gate has no base and ` +
        "Layer 2 goes back to inferring one from repository state",
    );
  }
  return m[1]!;
}

/** The `||` operands of a `${{ ... }}` expression, left to right. */
function operands(expr: string): string[] {
  const inner = expr.match(/^\$\{\{([\s\S]+)\}\}$/)?.[1];
  if (inner === undefined) throw new Error(`not a GitHub expression: ${expr}`);
  return inner.split("||").map((s) => s.trim()).filter(Boolean);
}

/**
 * Resolve the selector the way GitHub would for one event: the first operand
 * with a value wins.
 *
 * An operand this table does not know THROWS rather than resolving to
 * undefined. Fail closed: a selector nobody modelled must not be reported as
 * safe, which is the same mistake the gate itself made.
 */
function resolveFor(expr: string, event: string): string {
  const ctx = CONTEXTS[event]!;
  for (const operand of operands(expr)) {
    if (!(operand in ctx)) {
      throw new Error(
        `unmodelled operand "${operand}" in AAHP_BASE_SHA; add it to CONTEXTS with ` +
          `the value GitHub gives it on a ${event} event before trusting this selector`,
      );
    }
    const value = ctx[operand];
    if (value !== undefined) return value;
  }
  return "";
}

/** The exact pin, from package.json devDependencies. */
function pinnedCli(): string {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, "package.json"), "utf-8"));
  return (pkg.devDependencies || {})["@elvatis_com/aahp"];
}

function parseSemver(v: string): [number, number, number] {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v);
  if (!m) throw new Error(`not an exact version: ${v}`);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function atLeast(v: string, min: readonly [number, number, number]): boolean {
  const got = parseSemver(v);
  for (let i = 0; i < 3; i++) {
    if (got[i]! > min[i]!) return true;
    if (got[i]! < min[i]!) return false;
  }
  return true;
}

describe("aahp-verify Layer 2 base contract", () => {
  it("the CI gate is handed an explicit base instead of inferring one", () => {
    // Delete the `AAHP_BASE_SHA:` line from the workflow to redden this.
    expect(() => baseSelector()).not.toThrow();
  });

  it("the base is bound as step env, not spliced into the run command", () => {
    // `run: npx ... --base ${{ ... }}` would splice event-controlled text into a
    // shell command line. Binding it to env keeps it a value, never syntax.
    expect(AAHP).not.toMatch(/run:.*--base/);

    const at = LINES.findIndex((l) => /^\s*AAHP_BASE_SHA:/.test(l));
    expect(at, "no AAHP_BASE_SHA binding in the workflow").toBeGreaterThan(-1);
    // Walk back to the nearest enclosing key, skipping comments and siblings.
    let owner = at - 1;
    while (
      owner >= 0 &&
      (LINES[owner]!.trim() === "" ||
        LINES[owner]!.trim().startsWith("#") ||
        indentOf(LINES[owner]!) >= indentOf(LINES[at]!))
    ) {
      owner--;
    }
    expect(LINES[owner]!.trim(), "AAHP_BASE_SHA is not a key of an env block").toBe("env:");
  });

  it("the push leg compares against the pre-push commit, never the pushed commit", () => {
    // THE assertion this file exists for. Before the fix the gate inferred
    // `origin/main`, which on a push to main IS the pushed commit, so Layer 2
    // diffed HEAD against itself and reported an empty change set as a pass.
    const base = resolveFor(baseSelector(), "push");

    expect(base).toBe(PRE_PUSH_SHA);
    expect(base).not.toBe(HEAD_OF.push);
    expect(base).not.toBe("");
  });

  it("no leg resolves its base to the commit under test", () => {
    // The same vacuity, checked across every event that can start this
    // workflow, so a future selector cannot fix push and reintroduce it on a
    // manual run.
    const selector = baseSelector();
    for (const event of Object.keys(CONTEXTS)) {
      const base = resolveFor(selector, event);
      expect(base, `${event}: base resolves to nothing, so the gate has no diff`).not.toBe("");
      expect(base, `${event}: base resolves to HEAD, which makes Layer 2 vacuous`).not.toBe(
        HEAD_OF[event],
      );
    }
  });

  it("every trigger the workflow declares is modelled here", () => {
    // A trigger added without a base operand would be a new vacuous path, and
    // an unmodelled event would otherwise be silently untested.
    const declared = blockOf("on", 0)
      .filter((l) => indentOf(l) === 2)
      .map((l) => /^ {2}([a-z_]+):/.exec(l)?.[1])
      .filter((n): n is string => Boolean(n));
    expect(declared.length, "no triggers parsed out of the on: block").toBeGreaterThan(0);
    for (const event of declared) {
      expect(Object.keys(CONTEXTS), `trigger "${event}" has no modelled base`).toContain(event);
    }
  });

  it("a manual run must be given a base rather than defaulting to one", () => {
    // With the CLI at 3.10.0 a ci run without a base is a blocking failure, so
    // an optional input would make every manual dispatch red. Required, typed
    // and described is what keeps that path usable.
    const dispatch = blockOf("workflow_dispatch", 2).join("\n");
    expect(dispatch).toMatch(/^ {4}inputs:$/m);
    expect(dispatch).toMatch(/^ {6}base:$/m);
    expect(dispatch).toMatch(/^ {8}required: true$/m);
  });

  it("the pinned CLI is one that reads the base and rejects a HEAD-equal one", () => {
    // Without this the workflow half is decoration: 3.9.2 never reads
    // AAHP_BASE_SHA, so passing it changes nothing and the gate keeps guessing.
    const pin = pinnedCli();
    expect(pin, "@elvatis_com/aahp is not pinned in devDependencies").toBeTruthy();
    expect(
      atLeast(pin, MIN_CLI),
      `@elvatis_com/aahp is pinned to ${pin}; ${MIN_CLI.join(".")} is the first version ` +
        "that reads an explicit base and refuses a HEAD-equal one at --level ci",
    ).toBe(true);
  });

  it("the lockfile installs the same CLI the pin names", () => {
    // The pin decides what the gate CAN do; the lockfile decides what CI
    // actually installs. A lockfile left behind would install 3.9.2 while
    // package.json claimed otherwise, and the gate would resume guessing.
    const lock = JSON.parse(fs.readFileSync(path.join(REPO, "package-lock.json"), "utf-8"));
    const installed = lock.packages?.["node_modules/@elvatis_com/aahp"]?.version;
    expect(installed, "package-lock.json does not install @elvatis_com/aahp").toBeTruthy();
    expect(installed).toBe(pinnedCli());
  });
});
