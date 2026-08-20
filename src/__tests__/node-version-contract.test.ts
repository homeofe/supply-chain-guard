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
 * The policy itself lives in docs/node-support.md as a machine-readable block, so
 * the documentation cannot drift from the configuration either: this test parses
 * that block and holds every declaration site to it. Changing the policy is
 * editing one JSON object and then doing what the failures say.
 */
import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const read = (rel: string) => fs.readFileSync(path.join(REPO, rel), "utf-8");

interface NodePolicy {
  enginesFloor: string;
  testedMajors: number[];
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
  ];
  for (const re of patterns) {
    for (const m of text.matchAll(re)) found.add(Number(m[1]));
  }
  return [...found];
}

describe("node version policy", () => {
  describe("the policy is internally coherent", () => {
    it("the runtime major is one the suite actually runs on", () => {
      // The invariant that was violated. action.yml and the Dockerfile execute on
      // runtimeMajor; if CI never runs there, the published artefacts are the
      // least tested thing in the project.
      expect(P.testedMajors).toContain(P.runtimeMajor);
    });

    it("the publish major is one the suite actually runs on", () => {
      // An artifact must not be built by a toolchain the suite has never run under.
      expect(P.testedMajors).toContain(P.publishMajor);
    });

    it("every tested major is at or above the engines floor", () => {
      const floor = Number(P.enginesFloor.split(".")[0]);
      for (const m of P.testedMajors) expect(m).toBeGreaterThanOrEqual(floor);
    });

    it("the engines floor is itself tested", () => {
      // Promising `>=20` while testing only 22 is promising something unverified.
      expect(P.testedMajors).toContain(Number(P.enginesFloor.split(".")[0]));
    });
  });

  describe("normative sites match the policy exactly", () => {
    it("package.json engines.node is the declared floor", () => {
      const pkg = JSON.parse(read("package.json"));
      expect(pkg.engines?.node).toBe(`>=${P.enginesFloor}`);
    });

    it("the CI compat matrix is exactly the tested majors", () => {
      const ci = read(".github/workflows/ci.yml");
      const m = ci.match(/matrix:\s*\n\s*node:\s*\[([^\]]*)\]/);
      expect(m, "no compat matrix found in ci.yml").toBeTruthy();
      const declared = m![1]!
        .split(",")
        .map((s) => Number(s.trim().replace(/['"]/g, "")))
        .sort((a, b) => a - b);
      expect(declared).toEqual([...P.testedMajors].sort((a, b) => a - b));
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
      const dc = read(".devcontainer/devcontainer.json");
      expect(dc).toContain(`javascript-node:${P.devBaseline}`);
    });

    it("the supporting workflows run on a tested major", () => {
      // Not pinned to one value: these gate the repo, not the artifact, so any
      // major the suite covers is a defensible choice. Drifting OUTSIDE the
      // covered set is not.
      for (const wf of [".github/workflows/aahp-verify.yml", ".github/workflows/demo.yml"]) {
        for (const v of nodeVersions(read(wf))) {
          expect(P.testedMajors, `${wf} declares node ${v}`).toContain(Number(v.split(".")[0]));
        }
      }
    });
  });

  describe("user-facing copy does not advertise an untested major", () => {
    // These are non-normative, but they are what a reader copies into their own
    // pipeline, and a security tool recommending an end-of-life runtime is its
    // own kind of finding. Asserting membership rather than a fixed value is what
    // makes the future floor move mechanical: drop 20 from testedMajors and every
    // one of these turns red until it is updated.
    const userFacing = [
      "examples/azure-pipelines.yml",
      "examples/bot-pr-gate.yml",
      "examples/circleci-config.yml",
      "examples/gitlab-ci.yml",
      "examples/README.md",
      "docs/github-actions-sarif.yml",
      "CONTRIBUTING.md",
    ];

    for (const file of userFacing) {
      it(`${file} only mentions tested majors`, () => {
        const majors = majorsMentioned(read(file));
        for (const m of majors) {
          expect(P.testedMajors, `${file} mentions Node ${m}`).toContain(m);
        }
      });
    }

    it("the dependabot comment names the image the Dockerfile actually uses", () => {
      // Found stale while taking the inventory: the comment said node:20-alpine
      // while the Dockerfile had been on node:22-alpine since v5.x. A comment that
      // describes the wrong file is how the next person reasons from a false premise.
      const db = read(".github/dependabot.yml");
      const mentioned = [...db.matchAll(/node:(\d+)-alpine/g)].map((m) => Number(m[1]));
      for (const m of mentioned) expect(m).toBe(P.runtimeMajor);
    });
  });

  describe("the exclusions are deliberate", () => {
    it("scanner fixtures and threat intel are data, not policy", () => {
      // Guard against someone "fixing" the gate by widening it into src/, which
      // would start rewriting fixtures that exist precisely to contain an old
      // version string. Named here so the exclusion is a decision, not an oversight.
      const excluded = ["src/", "CHANGELOG.md", ".ai/handoff/", "feed.json"];
      for (const e of excluded) expect(read(POLICY_DOC)).toBeTruthy();
      expect(excluded.length).toBe(4);
      // The fixtures really do carry an out-of-policy version, which is why the
      // gate must never be pointed at them.
      expect(read("src/__tests__/dockerfile-scanner.test.ts")).toContain("node:20-alpine");
    });
  });
});
