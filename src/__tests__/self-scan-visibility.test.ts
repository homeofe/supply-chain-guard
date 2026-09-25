import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

// The README's "scanned by supply-chain-guard" badge used to be a static image,
// and the self-scan that backs it ran only inside the compat job's log, so a
// pull request showed no sign of it. .github/workflows/self-scan.yml makes the
// scan visible (code scanning + job summary) and the badge is its live status.
// These tests keep the visible scan honest: same threshold as the blocking
// gate, same positive control, and a badge that cannot drift back to a claim.

const ROOT = path.resolve(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(ROOT, rel), "utf8");
const WORKFLOW = ".github/workflows/self-scan.yml";

const failOn = (text: string) => [...text.matchAll(/node dist\/cli\.js scan \. --fail-on (\w+)/g)].map((m) => m[1]);

describe("the self-scan workflow", () => {
  const wf = read(WORKFLOW);

  it("runs on every pull request and on main", () => {
    expect(wf).toMatch(/\non:\n {2}push:\n {4}branches: \[main\]\n {2}pull_request:/);
  });

  it("uses the same threshold as the blocking gate in ci.yml", () => {
    const gate = failOn(read(".github/workflows/ci.yml"));
    expect(gate).toHaveLength(1);
    expect(failOn(wf)).toEqual(gate);
  });

  it("reports from the Action's default minimum severity", () => {
    const actionDefault = read("action.yml").match(/\n {2}min-severity:\n[\s\S]*?\n {4}default: "(\w+)"/)?.[1];
    expect(actionDefault).toBeDefined();
    // Read from the scan COMMAND: the workflow's header comment names the same
    // flag, and a check that a comment can satisfy guards nothing.
    const onCommand = [...wf.matchAll(/node dist\/cli\.js scan \. [^\n]*--min-severity (\w+)/g)].map((m) => m[1]);
    expect(onCommand).toEqual([actionDefault]);
  });

  it("keeps the gate's positive control before anything is published", () => {
    const control = wf.indexOf("scanned >= floor");
    expect(control).toBeGreaterThan(0);
    expect(control).toBeLessThan(wf.indexOf('formatReport(r, "sarif")'));
    expect(wf).toContain("git ls-files -- src | grep -c '\\.ts$'");
  });

  it("uploads SARIF to code scanning under its own category", () => {
    expect(wf).toContain("github/codeql-action/upload-sarif@");
    expect(wf).toContain("category: supply-chain-guard");
    expect(wf).toMatch(/security-events: write/);
  });

  it("skips the upload for forks by an env comparison, never by interpolating into a script", () => {
    expect(wf).toContain("steps.scan.outputs.upload == 'yes'");
    expect(wf).toContain("HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}");
    // No pull-request field is expanded inside a run: block (script injection).
    for (const block of wf.split(/\n\s+run: \|\n/).slice(1)) {
      const body = block.split(/\n\s+- (?:name|uses):/)[0];
      expect(body).not.toMatch(/\$\{\{\s*github\.event\.pull_request/);
    }
  });

  it("gives its verdict after the upload, so a red run still annotates", () => {
    const upload = wf.indexOf("- name: Upload to code scanning");
    const verdict = wf.indexOf("- name: Verdict at the critical threshold");
    expect(upload).toBeGreaterThan(0);
    expect(verdict).toBeGreaterThan(upload);
  });
});

describe("the README badge", () => {
  const readme = read("README.md");
  const top = readme.split("\n").slice(0, 30).join("\n");

  it("is the self-scan workflow's live status, not a static claim", () => {
    expect(top).toContain(
      "[![scanned by supply-chain-guard](https://github.com/homeofe/supply-chain-guard/actions/workflows/self-scan.yml/badge.svg?branch=main)](https://github.com/homeofe/supply-chain-guard/actions/workflows/self-scan.yml)",
    );
    expect(top).not.toContain("img.shields.io/badge/scanned%20by");
  });

  it("names the workflow the badge reads", () => {
    expect(fs.existsSync(path.join(ROOT, WORKFLOW))).toBe(true);
    expect(read(WORKFLOW)).toMatch(/^name: scanned by supply-chain-guard$/m);
  });
});

describe("the self-scan policy file", () => {
  // Two entries sat two columns too deep for months: invalid YAML that the
  // scanner's own lenient parser accepted, so nothing noticed. This checks the
  // one shape the file uses, without a YAML dependency.
  const problems = (text: string): string[] => {
    const out: string[] = [];
    const body = text.split(/^suppress:\n/m)[1] ?? "";
    let entries = 0;
    let reasons = 0;
    for (const line of body.split("\n")) {
      if (line.trim() === "" || /^\s*#/.test(line)) continue;
      if (/^ {2}- rule: [A-Z0-9_]+$/.test(line)) entries++;
      else if (/^ {4}reason: \S/.test(line)) reasons++;
      else if (!/^ {4}path: \S+$/.test(line)) out.push(line);
    }
    if (entries === 0) out.push("no entries");
    if (reasons !== entries) out.push(`${entries} entries but ${reasons} reasons`);
    return out;
  };

  it("keeps every suppression at one indentation, each with a reason", () => {
    expect(problems(read(".supply-chain-guard.yml"))).toEqual([]);
  });

  it("rejects the nesting it used to have (control)", () => {
    const old = "suppress:\n  - rule: A\n    reason: x\n\n    - rule: EVAL_ATOB\n      path: CHANGELOG.md\n      reason: y\n";
    expect(problems(old).length).toBeGreaterThan(0);
  });
});

describe("the documented SARIF workflow", () => {
  const example = read("docs/github-actions-sarif.yml");
  const pkg = JSON.parse(read("package.json"));

  it("uses the Action pinned to the current release", () => {
    expect(example).toContain(`uses: homeofe/supply-chain-guard@v${pkg.version}`);
    expect(example).toMatch(/format: sarif/);
    expect(example).toContain("sarif_file: ${{ steps.scg.outputs.report-path }}");
  });

  it("neither installs a floating version nor hides a failed scan", () => {
    expect(example).not.toMatch(/npm (?:install|i) /);
    expect(example).not.toContain("continue-on-error");
    expect(example).toMatch(/if: always\(\) && steps\.scg\.outputs\.report-path != ''/);
  });
});
