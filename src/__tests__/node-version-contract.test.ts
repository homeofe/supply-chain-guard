/**
 * Node version policy: one source of truth, mechanically enforced.
 *
 * WHY THIS EXISTS
 * ---------------
 * Before this gate, the repository disagreed with itself about Node and nothing
 * noticed. `package.json` promised `>=20.0.0`, CI built, tested and PUBLISHED on
 * 20, and the two artefacts people actually run - the composite Action in
 * `action.yml` and the container image in the `Dockerfile` - both executed on 22.
 * So the two most-used distribution channels ran on a major that CI never
 * exercised, and had done for months. Nothing was red, because nothing compared
 * the files to each other.
 *
 * Node 20 also reached end of life on 2026-04-30, which makes the disagreement
 * worse than untidy: the artifact consumers install was being built and published
 * by an unpatched runtime, in a package whose entire subject is supply-chain risk.
 *
 * SUPPORTED IS NOT TESTED
 * -----------------------
 * As of v5.28.0 Node 22 is the canonical baseline and Node 20 is a TRANSITION lane:
 * still fully tested, but below the engines floor and out of support, so a consumer
 * who has not migrated is warned rather than broken. The two lists are separate and
 * disjoint on purpose. A transition major is asserted to be strictly BELOW the floor,
 * because a transition major at or above the floor is indistinguishable from a
 * supported one, and that is how "temporary" support becomes permanent.
 *
 * The milestone has teeth: `transitionRemovedIn` is compared against the version in
 * package.json, and this suite FAILS once the project reaches that version while a
 * transition lane still exists. The transition cannot outlive its own deadline,
 * because the release that would carry it past cannot be built.
 *
 * The policy itself lives in docs/node-support.md as a machine-readable block, so
 * the documentation cannot drift from the configuration either: this test parses
 * that block and holds every declaration site to it.
 */
import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const read = (rel: string) => fs.readFileSync(path.join(REPO, rel), "utf-8");

interface NodePolicy {
  baseline: number;
  enginesFloor: string;
  supportedMajors: number[];
  transitionMajors: number[];
  transitionRemovedIn?: string;
  publishMajor: number;
  runtimeMajor: number;
  devBaseline: number;
}

const POLICY_DOC = "docs/node-support.md";

/** The single authoritative policy, parsed out of its own documentation. */
function policy(): NodePolicy {
  const doc = read(POLICY_DOC);
  const block = doc.match(/```json\s*\n([\s\S]*?)\n```/);
  if (!block) throw new Error(`no json policy block in ${POLICY_DOC}`);
  return JSON.parse(block[1]!) as NodePolicy;
}

const P = policy();
const FLOOR = Number(P.enginesFloor.split(".")[0]);

/** Every major CI is expected to run: supported plus whatever is still in transition. */
const ALL_LANES = [...P.supportedMajors, ...P.transitionMajors].sort((a, b) => a - b);

/** Numeric semver compare, enough for the x.y.z strings this repo uses. */
function cmp(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

/** `node-version: '20'` / `node-version: "22"` / `node-version: 20`. */
function nodeVersions(yaml: string): string[] {
  return [...yaml.matchAll(/node-version:\s*['"]?([0-9.]+)['"]?/g)].map((m) => m[1]!);
}

/** Every Node major mentioned as a version in a chunk of text. */
function majorsMentioned(text: string): number[] {
  const found = new Set<number>();
  const patterns = [
    /node-version:\s*['"]?(\d+)/g,
    /node:(\d+)/g,
    /javascript-node:(\d+)/g,
    /\bNode(?:\.js)?\s+(\d\d)\b/g,
    /cimg\/node:(\d+)/g,
    // Azure Pipelines' NodeTool input. Missed on the first pass, which is how
    // azure-pipelines.yml kept installing Node 20 while its own prose said 22.
    /versionSpec:\s*['"]?(\d+)/g,
    // Prose of the form "Node >= 22", used in the CircleCI example.
    /\bNode(?:\.js)?\s*>=\s*(\d+)/g,
  ];
  for (const re of patterns) {
    for (const m of text.matchAll(re)) found.add(Number(m[1]));
  }

  // Shields.io badges URL-encode their comparison operators, so ">=20" is written
  // `Node.js-%3E%3D20-green` and no plain pattern above can see it. Take the whole
  // label segment and pull every number out of it.
  for (const m of text.matchAll(/badge\/Node(?:\.js)?-([^-)]*)/g)) {
    for (const n of (m[1] ?? "").matchAll(/(\d\d)/g)) found.add(Number(n[1]));
  }

  return [...found];
}

describe("node version policy", () => {
  describe("the policy is internally coherent", () => {
    it("the baseline is the engines floor", () => {
      expect(P.baseline).toBe(FLOOR);
      expect(P.supportedMajors).toContain(P.baseline);
    });

    it("every supported major is at or above the engines floor", () => {
      for (const m of P.supportedMajors) expect(m).toBeGreaterThanOrEqual(FLOOR);
    });

    it("every transition major is strictly BELOW the floor", () => {
      // A transition major at or above the floor is indistinguishable from a
      // supported one, which is precisely how a temporary lane becomes permanent.
      for (const m of P.transitionMajors) expect(m).toBeLessThan(FLOOR);
    });

    it("no major is both supported and in transition", () => {
      const overlap = P.supportedMajors.filter((m) => P.transitionMajors.includes(m));
      expect(overlap).toEqual([]);
    });

    it("the runtime major is SUPPORTED, not merely tested", () => {
      // The invariant that was violated: action.yml and the Dockerfile execute on
      // runtimeMajor, so shipping there on a transition lane would mean the published
      // artefacts run on a major the project does not support.
      expect(P.supportedMajors).toContain(P.runtimeMajor);
    });

    it("the publish major is SUPPORTED, not merely tested", () => {
      // An artifact must not be built by a toolchain the project does not support.
      // Until v5.28.0 this was Node 20: a third runtime, distinct from both the
      // tested one and the executed one.
      expect(P.supportedMajors).toContain(P.publishMajor);
    });

    it("the dev baseline is a supported major", () => {
      expect(P.supportedMajors).toContain(P.devBaseline);
    });
  });

  describe("the transition milestone has teeth", () => {
    it("a transition lane must declare the release that removes it", () => {
      if (P.transitionMajors.length > 0) {
        expect(P.transitionRemovedIn, "transitionMajors without transitionRemovedIn is an open-ended exception").toBeTruthy();
        expect(P.transitionRemovedIn).toMatch(/^\d+\.\d+\.\d+$/);
      }
    });

    it("the project has not passed its own removal milestone", () => {
      // The teeth. Once package.json reaches transitionRemovedIn, this fails and the
      // release cannot be built until the lane is deleted. Extending the deadline
      // requires editing the date in a diff someone reviews, which is a decision
      // rather than a drift.
      if (P.transitionMajors.length === 0 || !P.transitionRemovedIn) return;
      const version = JSON.parse(read("package.json")).version as string;
      expect(
        cmp(version, P.transitionRemovedIn),
        `version ${version} has reached the Node ${P.transitionMajors.join("/")} removal milestone ${P.transitionRemovedIn}: delete the transition lane, or move the milestone deliberately`,
      ).toBeLessThan(0);
    });
  });

  describe("normative sites match the policy exactly", () => {
    it("package.json engines.node is the declared floor", () => {
      const pkg = JSON.parse(read("package.json"));
      expect(pkg.engines?.node).toBe(`>=${P.enginesFloor}`);
    });

    it("the CI compat matrix is exactly the supported plus transition majors", () => {
      const ci = read(".github/workflows/ci.yml");
      const m = ci.match(/matrix:\s*\n\s*node:\s*\[([^\]]*)\]/);
      expect(m, "no compat matrix found in ci.yml").toBeTruthy();
      const declared = m![1]!
        .split(",")
        .map((s) => Number(s.trim().replace(/['"]/g, "")))
        .sort((a, b) => a - b);
      expect(declared).toEqual(ALL_LANES);
    });

    it("the CI publish job runs on the publish major", () => {
      const ci = read(".github/workflows/ci.yml");
      // Slice the publish job out so the compat matrix's setup-node cannot satisfy this.
      const job = ci.slice(ci.indexOf("\n  publish:"), ci.indexOf("\n  release:"));
      expect(job.length).toBeGreaterThan(0);
      expect(nodeVersions(job)).toEqual([String(P.publishMajor)]);
    });

    it("action.yml runs the published Action on the runtime major", () => {
      expect(nodeVersions(read("action.yml"))).toEqual([String(P.runtimeMajor)]);
    });

    it("every Dockerfile stage uses the runtime major", () => {
      const froms = [...read("Dockerfile").matchAll(/^FROM\s+node:(\d+)-/gm)].map((m) => m[1]!);
      expect(froms.length, "expected at least one FROM node: stage").toBeGreaterThan(0);
      for (const f of froms) expect(f).toBe(String(P.runtimeMajor));
    });

    it("the devcontainer is the declared dev baseline", () => {
      expect(read(".devcontainer/devcontainer.json")).toContain(`javascript-node:${P.devBaseline}`);
    });

    it("no supporting workflow runs on a major below the baseline", () => {
      // Globbed, not listed. A hardcoded pair could not see a workflow split out of
      // ci.yml later, and that is precisely what happened when pr-metadata-policy.yml
      // was created. ci.yml is excluded because its matrix is asserted exactly above.
      const dir = path.join(REPO, ".github/workflows");
      const workflows = fs.readdirSync(dir).filter((f) => /\.ya?ml$/.test(f) && f !== "ci.yml");
      expect(workflows.length, "expected to find supporting workflows").toBeGreaterThan(0);
      for (const wf of workflows) {
        for (const v of nodeVersions(fs.readFileSync(path.join(dir, wf), "utf-8"))) {
          expect(Number(v.split(".")[0]), `${wf} declares node ${v}`).toBeGreaterThanOrEqual(P.baseline);
        }
      }
    });
  });

  describe("user-facing copy does not point readers at an unsupported runtime", () => {
    // Two lists, because two different things are being asserted and conflating them
    // produced a false positive on the first attempt.
    //
    // COPY-PASTE files are configuration a reader lifts wholesale into their own
    // pipeline. Every version in them is a recommendation, so none may be below the
    // baseline. A floor rather than exact membership: suggesting Node 24 is fine, and
    // pinning the examples to one major would make them wrong the moment the baseline
    // moves.
    const copyPaste = [
      "examples/azure-pipelines.yml",
      "examples/bot-pr-gate.yml",
      "examples/circleci-config.yml",
      "examples/gitlab-ci.yml",
      "examples/README.md",
      "examples/Jenkinsfile",
      "examples/github-action-basic.yml",
      "docs/github-actions-sarif.yml",
    ];

    // PROSE files have to be able to NAME the transition major in order to explain
    // it. README's requirements paragraph says Node 20 is end-of-life and removed in
    // 5.29.0, which is the opposite of advertising it, and a regex cannot tell the
    // difference. So prose may mention a transition major and nothing else below the
    // baseline: it still cannot quietly suggest Node 18.
    const prose = ["README.md", "CONTRIBUTING.md"];

    for (const file of copyPaste) {
      it(`${file} recommends no major below the baseline`, () => {
        for (const m of majorsMentioned(read(file))) {
          expect(m, `${file} recommends Node ${m}, below the ${P.baseline} baseline`).toBeGreaterThanOrEqual(P.baseline);
        }
      });
    }

    for (const file of prose) {
      it(`${file} names only the baseline or a declared transition major`, () => {
        for (const m of majorsMentioned(read(file))) {
          if (m >= P.baseline) continue;
          expect(
            P.transitionMajors,
            `${file} names Node ${m}, which is below the ${P.baseline} baseline and is not a declared transition major`,
          ).toContain(m);
        }
      });
    }

    it("the dependabot comment names the image the Dockerfile actually uses", () => {
      // Found stale while taking the inventory: the comment said node:20-alpine
      // while the Dockerfile had been on node:22-alpine for releases. A comment that
      // describes the wrong file is how the next person reasons from a false premise.
      const mentioned = [...read(".github/dependabot.yml").matchAll(/node:(\d+)-alpine/g)].map((m) => Number(m[1]));
      for (const m of mentioned) expect(m).toBe(P.runtimeMajor);
    });
  });

  describe("the exclusions are deliberate", () => {
    it("scanner fixtures and threat intel are data, not policy", () => {
      // Guard against someone "fixing" the gate by widening it into src/, which would
      // start rewriting fixtures that exist precisely to contain an old version string.
      const excluded = ["src/", "CHANGELOG.md", ".ai/handoff/", "feed.json"];
      expect(excluded.length).toBe(4);
      expect(read("src/__tests__/dockerfile-scanner.test.ts")).toContain("node:20-alpine");
    });
  });
});
