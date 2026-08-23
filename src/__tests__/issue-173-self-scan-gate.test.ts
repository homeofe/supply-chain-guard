/**
 * The scanner scans this repository, and keeps scanning it.
 * https://github.com/homeofe/supply-chain-guard/issues/173
 *
 * WHY THIS EXISTS
 * ---------------
 * CI built the scanner, started it, and confirmed it emitted parseable JSON
 * against a four-line fixture package.json. It never pointed the scanner at
 * this repository. So every rule this tool enforces on its consumers was
 * unenforced on its own tree, and none of the three status checks that branch
 * protection requires on main inspected a single line of it. The omission was
 * there from the first commit: `git log -S` over .github/workflows/ finds no
 * commit that ever removed such a step, because none ever added one.
 *
 * The class of defect is worth naming, because it is easy to reintroduce: a
 * smoke test that proves the tool RUNS reads exactly like a check that the tool
 * PASSES. Both are green. Only one of them looked at your code.
 *
 * WHAT THIS FILE PINS
 * -------------------
 * 1. CI runs the freshly built CLI over the checkout, inside the job that
 *    produces the required "Build and Test" context, with an explicit threshold
 *    and with a control that a mis-pointed target cannot pass.
 * 2. The two product-level false positives that the first real self-scan
 *    surfaced stay fixed, since they are what would otherwise make the new gate
 *    red on an unmodified tree and get it switched off.
 *
 * Point 1 is asserted against the RAW TEXT of ci.yml. No YAML parser is a
 * dependency of this package, and adding one to a security scanner so it can
 * lint its own CI would be a poor trade; src/__tests__/workflow-trigger-contract.test.ts
 * made the same call for the same reason. The assertions below locate the step
 * by the invocation it contains rather than by its display name, so renaming the
 * step does not produce a false red.
 *
 * WHAT THIS FILE DOES NOT PIN
 * ---------------------------
 * That the gate is EFFECTIVE against arbitrary planted content. No unit test can
 * establish that, because the check is the scan itself. It is established by
 * execution instead, and the measurement is recorded on the issue: a file
 * carrying one bundled C2 indicator, planted at a path that is not on the
 * self-scan allowlist, moves the tree from 0 critical findings to 2 and the step
 * from exit 0 to exit 1.
 *
 * A KNOWN, DELIBERATE BLIND SPOT, stated so that nobody discovers it by
 * surprise: an indicator planted inside one of the files named in
 * SELF_SCAN_INERT_FILES (src/scanner.ts) is invisible to this gate. That is
 * correct behaviour for a scanner whose own source spells out the signatures it
 * detects, but it means the gate covers this repository MINUS those named files,
 * and reviewing changes to them stays a human job.
 */
import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { LURE_PATTERNS } from "../patterns.js";
import { KNOWN_MALICIOUS_HASHES } from "../ioc-blocklist.js";
import { scan } from "../scanner.js";

const REPO = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

/**
 * Line endings are normalised on read. A checkout on Windows with
 * core.autocrlf=true delivers ci.yml as CRLF, and the line-anchored helpers
 * below would then find no job at all and fail for a reason that has nothing to
 * do with what they assert. Contributors on Windows should get the same verdict
 * as the Linux runners.
 */
function readText(relativePath: string): string {
  return fs.readFileSync(path.join(REPO, relativePath), "utf-8").replace(/\r\n/g, "\n");
}

const CI = readText(".github/workflows/ci.yml");
const SCANNER_SOURCE = readText("src/scanner.ts");

/** The body of one job under `jobs:`, from its key to the next job key. */
function jobBlock(yaml: string, job: string): string {
  const start = yaml.indexOf(`\n  ${job}:\n`);
  if (start === -1) throw new Error(`job "${job}" not found in ci.yml`);
  const rest = yaml.slice(start + 1);
  const next = rest.search(/\n {2}[A-Za-z0-9_-]+:\n/);
  return next === -1 ? rest : rest.slice(0, next);
}

/**
 * The one step of a job whose body contains `needle`. Located by content rather
 * than by name so that renaming the step does not redden this file.
 */
function stepContaining(jobYaml: string, needle: string): string {
  const steps = jobYaml.split(/\n(?= {6}- name: )/);
  const hits = steps.filter((step) => step.includes(needle));
  if (hits.length !== 1) {
    throw new Error(
      `expected exactly one step containing ${JSON.stringify(needle)}, found ${hits.length}`,
    );
  }
  return hits[0]!;
}

const COMPAT = jobBlock(CI, "compat");

/**
 * The invocation this whole issue is about: the built CLI, pointed at `.`, which
 * is the checkout root because no step in this job changes directory.
 *
 * `.` is load-bearing and not interchangeable with an absolute path to the same
 * place. isOwnPackageRoot in src/scanner.ts compares the RESOLVED scan target
 * against the scanner's own install root, and only a match applies
 * SELF_SCAN_INERT_FILES and loads .supply-chain-guard.yml from this directory.
 * Reaching the same tree through a container mount resolves to a different root,
 * switches both off, and reports roughly 1700 self-referential findings on
 * detector definitions this tool ships on purpose.
 */
const SELF_SCAN_INVOCATION = "node dist/cli.js scan .";

describe("CI scans this repository (issue 173)", () => {
  it("runs the built CLI over the checkout, not over a fixture", () => {
    // Delete the `node dist/cli.js scan .` line from ci.yml and this is the
    // assertion that goes red. It is the whole defect in one line.
    expect(CI).toContain(SELF_SCAN_INVOCATION);
  });

  it("runs it inside the job that feeds the required 'Build and Test' context", () => {
    // A self-scan wired into a job nothing requires is a self-scan that cannot
    // block a merge, which is a report rather than a gate.
    expect(COMPAT).toContain(SELF_SCAN_INVOCATION);

    const build = jobBlock(CI, "build");
    expect(build).toMatch(/name:\s*Build and Test/);
    expect(build).toMatch(/needs:\s*\[[^\]]*\bcompat\b[^\]]*\]/);
  });

  it("declares an explicit failure threshold", () => {
    // Without --fail-on, exit codes follow the default ladder in
    // getReportExitCode and the gate's strictness becomes an accident of
    // whichever severities happen to be present. The threshold is a decision and
    // has to be written down as one.
    const step = stepContaining(COMPAT, SELF_SCAN_INVOCATION);
    expect(step).toMatch(/--fail-on\s+(critical|high|medium|low|info)\b/);
  });

  it("proves it inspected this repository before its verdict counts", () => {
    // The positive control. A scan of the wrong directory finds nothing and
    // exits 0, and a green step that inspected nothing is indistinguishable from
    // a green step that inspected a clean tree. That ambiguity IS issue 173, so a
    // gate without this control reintroduces the defect it was added to close.
    const step = stepContaining(COMPAT, SELF_SCAN_INVOCATION);
    expect(step).toContain("filesScanned");
    expect(step).toMatch(/git ls-files/);
  });

  it("cannot be disabled by a change to the Node matrix", () => {
    // `if: matrix.node == '22'` is the tempting way to pay the cost once. It also
    // means the gate vanishes without a word on the day that value leaves the
    // matrix, which is the same silent-omission failure as the missing step. The
    // scan costs about 9 s in a job that already runs npm ci, npm audit, tsc, the
    // full suite with coverage, and a clean-room tarball install, so it runs on
    // every leg unconditionally.
    const step = stepContaining(COMPAT, SELF_SCAN_INVOCATION);
    expect(step).not.toMatch(/^\s+if:/m);
  });
});

/**
 * The first real self-scan of this tree returned four critical findings, all
 * four self-referential false positives. They are fixed here rather than
 * suppressed, because a gate introduced on a red tree is a gate someone turns
 * off, and because one of the two is not specific to this repository at all.
 */
describe("findings the first self-scan surfaced stay fixed (issue 173)", () => {
  const crack = LURE_PATTERNS.find((p) => p.rule === "README_LURE_CRACK");
  const fires = (text: string): boolean =>
    new RegExp(crack!.pattern, "i").test(text);

  /** The exact prose from CHANGELOG.md that scored a critical finding. */
  const CHANGELOG_LINE =
    "  `xrblocks-mcp`, `mastraqqq`, `nolimit-agent` with its two platform binaries); and";

  it("does not flag a hyphenated package name quoted in prose", () => {
    // `nolimit-agent` is a real malicious npm package. This project's own
    // threat-intelligence release notes name it, which is what a security
    // changelog is for, and that earned a CRITICAL finding on the tool's own
    // CHANGELOG. Any adopter documenting the same advisory hit the same finding,
    // so this was fixed at the rule rather than suppressed for one repository.
    expect(crack).toBeDefined();
    expect(fires(CHANGELOG_LINE)).toBe(false);

    // The measured false-positive shape is a hyphen on either side, meaning the
    // match is one segment of a longer identifier token rather than a word in a
    // sentence. All three orientations must stay quiet.
    expect(fires("the agent-nolimit package")).toBe(false);
    expect(fires("@scope/nolimit-agent")).toBe(false);
    expect(fires("nolimits-agent released")).toBe(false);
  });

  it("still flags every lure phrasing the rule exists for", () => {
    // The other half of the fix, and the half that makes it a fix rather than a
    // hole. Narrowing a critical malware-lure detector to silence one changelog
    // line would trade a false positive for a false negative, which is the worse
    // of the two for a scanner in a trust chain.
    for (const lure of [
      "Download the cracked version with keygen included",
      "unlocked enterprise features",
      "license bypass included",
      "now with no limits",
      "no message limits",
      "no limit on messages",
      "nolimits build", // single token, no hyphen: still a lure
      "no limits - download now", // prose that happens to precede a dash
    ]) {
      expect(fires(lure), `expected README_LURE_CRACK to fire on: ${lure}`).toBe(true);
    }
  });

  it("does not flag the changelog line through a real directory scan", async () => {
    // End to end rather than regex level, because onlyFilePattern, the benign-doc
    // exclusions and the policy engine all sit between the pattern and a finding,
    // and the finding is what turns the new CI gate red.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-issue-173-"));
    try {
      fs.writeFileSync(
        path.join(dir, "CHANGELOG.md"),
        `## v5.28.1\n\n- Threat intel sweep covering AI and agent tooling names (\n${CHANGELOG_LINE}\n`,
      );
      const report = await scan({ target: dir, format: "text" });

      // A scan that inspected nothing reports no findings, which would let this
      // assertion pass without testing anything. That is the same shape as the
      // defect this file exists for, so the control belongs here too.
      expect(report.summary.filesScanned).toBeGreaterThan(0);

      expect(
        report.findings.filter((f) => f.rule === "README_LURE_CRACK"),
      ).toEqual([]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it("treats the file-digest fixtures as this package's own inert definitions", () => {
    // Three of the four findings were IOC_KNOWN_MALWARE_HASH and
    // THREAT_INTEL_MATCH on src/__tests__/file-digest.test.ts, which quotes two
    // SHIPPED entries of KNOWN_MALICIOUS_HASHES verbatim. It has to quote them:
    // its assertions are about how those exact digests are routed, and an
    // invented digest proves nothing about a shipped one. Sixteen sibling test
    // files doing the same thing were already on the allowlist, so this was an
    // oversight rather than a decision.
    expect(SCANNER_SOURCE).toContain('"src/__tests__/file-digest.test.ts"');

    // Keep the entry honest. An allowlist entry naming a file that no longer
    // exists, or that no longer quotes a shipped indicator, is a standing
    // exemption with nothing behind it.
    const fixtureFile = path.join(REPO, "src/__tests__/file-digest.test.ts");
    expect(fs.existsSync(fixtureFile)).toBe(true);

    const fixtureSource = readText("src/__tests__/file-digest.test.ts");
    const shippedDigestsQuoted = Object.keys(KNOWN_MALICIOUS_HASHES).filter(
      (digest) => fixtureSource.includes(digest),
    );
    expect(shippedDigestsQuoted.length).toBeGreaterThan(0);
  });
});
