import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { PARTIAL_SCAN_RULES } from "../pattern-scanner.js";
import pkg from "../../package.json";
import { SCORE_EXCLUDED_RULES, calculateScore } from "../scanner.js";
import { SEVERITY_SCORES } from "../types.js";
import type { Finding } from "../types.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const action = fs.readFileSync(path.join(repoRoot, "action.yml"), "utf8");
const runStart = action.indexOf("    - name: Run scan");
const commentStart = action.indexOf("    - name: Comment on PR");
const runStep = action.slice(runStart, commentStart);
const commentStep = action.slice(commentStart);

function literalBlock(section: string, marker: string, indent: number): string {
  const start = section.indexOf(marker);
  if (start < 0) throw new Error(`Missing block marker: ${marker}`);
  const lines = section.slice(start + marker.length).replace(/^\r?\n/, "").split(/\r?\n/);
  const prefix = " ".repeat(indent);
  const body: string[] = [];
  for (const line of lines) {
    if (line.length > 0 && !line.startsWith(prefix)) break;
    body.push(line.startsWith(prefix) ? line.slice(indent) : "");
  }
  return body.join("\n");
}

const scanScript = literalBlock(runStep, "      run: |", 8);
const commentScript = literalBlock(commentStep, "        script: |", 10);
const jqStart = scanScript.indexOf("if ! jq -e '") + "if ! jq -e '".length;
const jqEnd = scanScript.indexOf("' \"$JSON_FILE\"", jqStart);
const jqProgram = scanScript.slice(jqStart, jqEnd);

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor as new (
  ...args: string[]
) => (...values: unknown[]) => Promise<void>;
const nodeRequire = createRequire(import.meta.url);

interface CommentScenario {
  report?: string;
  reportValid?: boolean;
  passesConsistent?: boolean;
  partial?: boolean;
  findingsCount?: number;
  outcome?: string;
  format?: string;
  existingBody?: string;
  existingAuthor?: string;
}

async function runCommentScenario(scenario: CommentScenario): Promise<{
  created?: { body: string };
  updated?: { body: string };
}> {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "scg-action-comment-"));
  if (scenario.report !== undefined) {
    fs.writeFileSync(path.join(temp, "scg-report.txt"), scenario.report, "utf8");
  }

  const envKeys = [
    "RUNNER_TEMP",
    "SCG_REPORT_VALID",
    "SCG_PASSES_CONSISTENT",
    "SCG_PARTIAL_SCAN",
    "SCG_FINDINGS_COUNT",
    "SCG_SCAN_OUTCOME",
    "SCG_REPORT_PATH",
    "SCG_FORMAT",
  ] as const;
  const previous = new Map(envKeys.map((key) => [key, process.env[key]]));
  process.env.RUNNER_TEMP = temp;
  process.env.SCG_REPORT_VALID = scenario.reportValid ? "true" : "";
  process.env.SCG_PASSES_CONSISTENT = (scenario.passesConsistent ?? scenario.reportValid) ? "true" : "false";
  process.env.SCG_PARTIAL_SCAN = scenario.partial ? "true" : "false";
  process.env.SCG_FINDINGS_COUNT = scenario.findingsCount?.toString() ?? "";
  process.env.SCG_SCAN_OUTCOME = scenario.outcome ?? "failure";
  process.env.SCG_REPORT_PATH = path.join(temp, "scg-report.txt");
  process.env.SCG_FORMAT = scenario.format ?? "markdown";

  const calls: { created?: { body: string }; updated?: { body: string } } = {};
  const comments = scenario.existingBody
    ? [{
      id: 7,
      body: scenario.existingBody,
      user: { login: scenario.existingAuthor ?? "github-actions[bot]" },
    }]
    : [];
  const github = {
    paginate: async () => comments,
    rest: {
      issues: {
        listComments: async () => ({ data: comments }),
        createComment: async (args: { body: string }) => { calls.created = args; },
        updateComment: async (args: { body: string }) => { calls.updated = args; },
      },
    },
  };
  const context = { repo: { owner: "owner", repo: "repo" }, issue: { number: 1 } };
  const core = { info: () => undefined };
  const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);

  try {
    const execute = new AsyncFunction("require", "github", "context", "core", commentScript);
    await execute(nodeRequire, github, context, core);
    if (scenario.report === undefined) {
      expect(errorLog).toHaveBeenCalledTimes(1);
      expect(errorLog).toHaveBeenCalledWith(
        "Failed to read the bounded report excerpt:",
        expect.objectContaining({ code: "ENOENT" }),
      );
    } else {
      expect(errorLog).not.toHaveBeenCalled();
    }
    return calls;
  } finally {
    errorLog.mockRestore();
    for (const key of envKeys) {
      const value = previous.get(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

const validEmptyReport = {
  summary: {
    totalFiles: 1,
    filesScanned: 1,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  },
  findings: [],
  score: 0,
  riskLevel: "clean",
};

const hasBash = process.platform !== "win32"
  && spawnSync("bash", ["--version"], { stdio: "ignore" }).status === 0;
const hasJq = spawnSync("jq", ["--version"], { stdio: "ignore" }).status === 0;

function jqAccepts(value: unknown): boolean {
  return spawnSync("jq", ["-e", jqProgram], {
    input: JSON.stringify(value),
    encoding: "utf8",
  }).status === 0;
}

interface ScanScriptOptions {
  format?: string;
  minSeverity?: string;
  scanStatus?: number;
  formattedReport?: string;
  commentOnPr?: string;
}

function explicitGateStatus(report: unknown, failOn: string): number {
  if (!report || typeof report !== "object") return 0;
  const value = report as {
    partialScan?: unknown;
    findings?: Array<{ severity?: unknown }>;
  };
  if (value.partialScan === true) return 1;
  const rank: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  const threshold = rank[failOn];
  if (threshold === undefined || !Array.isArray(value.findings)) return 0;
  return value.findings.some(
    (finding) => typeof finding?.severity === "string" &&
      (rank[finding.severity] ?? -1) >= threshold,
  ) ? 1 : 0;
}
function runScanScript(
  report: unknown,
  failOn = "critical",
  options: ScanScriptOptions = {},
): ReturnType<typeof spawnSync> {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "scg-action-shell-"));
  const bin = path.join(temp, "bin");
  fs.mkdirSync(bin);
  const scanner = path.join(bin, "supply-chain-guard");
  fs.writeFileSync(scanner, `#!/usr/bin/env bash
format=text
json_output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --format) format="$2"; shift 2 ;;
    --json-output) json_output="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$json_output" ] || exit 97
printf '%s' "$FAKE_JSON" > "$json_output"
echo "$FAKE_REPORT"
exit "$FAKE_SCAN_STATUS"
`, "utf8");
  fs.chmodSync(scanner, 0o755);
  const scriptPath = path.join(temp, "scan.sh");
  fs.writeFileSync(scriptPath, scanScript, "utf8");
  const outputPath = path.join(temp, "github-output.txt");
  const expectedStatus = explicitGateStatus(report, failOn);
  const requestedFormat = options.format ?? "json";
  const formattedReport = options.formattedReport
    ?? (requestedFormat === "json"
      ? JSON.stringify(report)
      : "## supply-chain-guard Scan Report\n\n| Property | Value |");

  const result = spawnSync("bash", [scriptPath], {
    cwd: temp,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNNER_TEMP: temp,
      GITHUB_OUTPUT: outputPath,
      SCG_PATH: ".",
      SCG_FORMAT: requestedFormat,
      SCG_MIN_SEVERITY: options.minSeverity ?? "low",
      SCG_EXCLUDE_RULES: "",
      SCG_FAIL_ON: failOn,
      SCG_COMMENT_ON_PR: options.commentOnPr ?? "true",
      FAKE_JSON: JSON.stringify(report),
      FAKE_REPORT: formattedReport,
      FAKE_SCAN_STATUS: String(options.scanStatus ?? expectedStatus),
    },
  });
  (result as ReturnType<typeof spawnSync> & { githubOutput?: string }).githubOutput =
    fs.existsSync(outputPath) ? fs.readFileSync(outputPath, "utf8") : "";
  fs.rmSync(temp, { recursive: true, force: true });
  return result;
}

describe("Marketplace Action fail-closed contract", () => {
  it("publishes mapped partial and bounded-report outputs from a version-pinned CLI", () => {
    expect(action).toContain("value: ${{ steps.scan.outputs['partial-scan'] }}");
    expect(action).toContain("value: ${{ steps.scan.outputs['report-path'] }}");
    expect(action).toContain("value: ${{ steps.scan.outputs['report-truncated'] }}");
    // Pin must track package.json - hardcoding left this a release behind at v5.23.2.
    expect(action).toContain(`npm install -g supply-chain-guard@${pkg.version}`);
    expect(scanScript).toContain('SCG_RUN_DIR=$(mktemp -d "$RUNNER_TEMP/scg-action.XXXXXX")');
    expect(scanScript).not.toContain('$RUNNER_TEMP/scg-report.json');
    expect(commentScript).toContain("fs.openSync(process.env.SCG_REPORT_PATH, 'r')");
    expect(action).toContain("uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0");
    expect(action).toContain("package-manager-cache: false");
    expect(action).toContain("uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0");
  });

  it("validates every gate field and rejects invalid enum inputs before scanning", () => {
    const validation = runStep.indexOf("did not produce a valid JSON scan report; failing closed");
    const extraction = runStep.indexOf("SCORE=$(jq -r");
    expect(validation).toBeGreaterThan(-1);
    expect(extraction).toBeGreaterThan(validation);
    expect(runStep).toContain("def nonnegint:");
    expect(runStep).toContain("def minimum_visible_score:");
    const minimumScoreBlock = scanScript.slice(
      scanScript.indexOf("def minimum_visible_score:"),
      scanScript.indexOf("def coverage_rule:"),
    );
    const actionScoreExclusions = [
      ...minimumScoreBlock.matchAll(/\.rule != "([A-Z0-9_]+)"/g),
    ].map((match) => match[1]!);
    expect(new Set(actionScoreExclusions)).toEqual(new Set(SCORE_EXCLUDED_RULES));
    expect(scanScript).toContain(`if . == "critical" then ${SEVERITY_SCORES.critical}`);
    expect(scanScript).toContain(`elif . == "high" then ${SEVERITY_SCORES.high}`);
    expect(scanScript).toContain(`elif . == "medium" then ${SEVERITY_SCORES.medium}`);
    expect(scanScript).toContain(`elif . == "low" then ${SEVERITY_SCORES.low}`);
    expect(scanScript).toContain(`else ${SEVERITY_SCORES.info}`);
    expect(runStep).toContain("Invalid comment-on-pr input. Allowed: true, false.");
    expect(scanScript).toContain("SCAN_STATUS=$?\nset -e");
    expect(runStep).toContain(".summary.critical == ([.findings[]");
    expect(runStep).toContain('.partialScan | type == "boolean"');
    expect(runStep).toContain('*) echo "Invalid fail-on input. Allowed: info, low, medium, high, critical." >&2; exit 1 ;;');
    expect(runStep).toContain('*) echo "Invalid format input. Allowed: text, json, markdown, sarif, sbom, html, badge, gitlab, junit." >&2; exit 1 ;;');
    expect(runStep).toContain("would hide findings required by fail-on");
    expect(runStep.indexOf("would hide findings required by fail-on"))
      .toBeLessThan(runStep.indexOf("supply-chain-guard scan"));
  });

  it("keeps the Action coverage schema synchronized with scanner partial rules", () => {
    const start = scanScript.indexOf("def coverage_rule:");
    const end = scanScript.indexOf(";\n  type == \"object\"", start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const actionRules = [
      ...scanScript.slice(start, end).matchAll(/\. == "([A-Z0-9_]+)"/g),
    ].map((match) => match[1]!);

    expect(new Set(actionRules)).toEqual(new Set(PARTIAL_SCAN_RULES));
  });

  it("uses one read-only scan for both formats and preserves critical-before-partial ordering", () => {
    expect(runStep).toContain('FILTER_ARGS=(--no-history --fail-on "$FAIL_SEVERITY")');
    expect(runStep).toContain('--json-output "$JSON_FILE"');
    expect(runStep).toContain(`jq -s -e 'length == 2 and .[0] == .[1]' "$FORMAT_FILE" "$JSON_FILE"`);
    expect(runStep).toContain('echo "::stop-commands::$LOG_COMMAND_TOKEN"');
    expect(runStep).toContain('echo "::$LOG_COMMAND_TOKEN::"');
    expect(runStep.match(/supply-chain-guard scan/g)).toHaveLength(1);
    const severityGate = runStep.lastIndexOf('case "$FAIL_SEVERITY" in');
    const criticalExit = runStep.indexOf("exit 2", severityGate);
    const partialGate = runStep.indexOf('if [ "$PARTIAL_SCAN" = "true" ]', criticalExit);
    const partialExit = runStep.indexOf("exit 1", partialGate);
    const successExit = runStep.indexOf("exit 0", partialExit);
    expect(criticalExit).toBeGreaterThan(severityGate);
    expect(partialExit).toBeGreaterThan(criticalExit);
    expect(successExit).toBeGreaterThan(partialExit);
  });

  it("never posts a clean fallback when setup or scanning produced no validated report", async () => {
    const calls = await runCommentScenario({ outcome: "failure" });
    expect(calls.created?.body).toContain("No clean verdict is available");
    expect(calls.created?.body).not.toContain("no reportable malicious indicators detected");
  });

  // An empty report indents to "    " (four spaces), which is truthy. Guarding on
  // the indented string instead of the source made the clean-scan fallback
  // unreachable and every `if (reportForComment)` guard always true. A first clean
  // scan posts nothing at all, so this only surfaces when a stale finding or
  // partial comment is replaced on the return to clean - which is exactly when the
  // reader most needs to be told the run came back clean.
  it("explains the clean result when replacing a stale comment and the report cannot be read", async () => {
    const calls = await runCommentScenario({
      reportValid: true,
      findingsCount: 0,
      outcome: "success",
      existingBody: "## supply-chain-guard Scan Report\n\n> WARNING: Findings were detected.",
      // report omitted: the file is never written, so the read throws and the
      // script falls back to an empty report string.
    });
    expect(calls.updated?.body).toContain("no reportable malicious indicators detected");
  });

  it("explains the clean result when replacing a stale comment and the report is empty", async () => {
    const calls = await runCommentScenario({
      report: "   \n  ",
      reportValid: true,
      findingsCount: 0,
      outcome: "success",
      existingBody: "## supply-chain-guard Scan Report\n\n> WARNING: Scan incomplete.",
    });
    expect(calls.updated?.body).toContain("no reportable malicious indicators detected");
  });

  it("lets canonical partial metadata override a contradictory formatted report", async () => {
    const calls = await runCommentScenario({
      report: "Formatter claimed clean",
      reportValid: true,
      partial: true,
      findingsCount: 0,
      outcome: "failure",
    });
    expect(calls.created?.body).toContain("Coverage is partial; no clean verdict is available");
    expect(calls.created?.body.indexOf("Coverage is partial")).toBeLessThan(
      calls.created?.body.indexOf("Formatter claimed clean") ?? -1,
    );
    expect(calls.created?.body).toContain("Canonical JSON report: **0 reportable finding(s)**");
  });

  it("puts canonical finding metadata ahead of a contradictory formatted report", async () => {
    const calls = await runCommentScenario({
      report: "Formatter claimed clean",
      reportValid: true,
      passesConsistent: true,
      findingsCount: 2,
      outcome: "failure",
    });
    expect(calls.created?.body).toContain("Canonical JSON report: **2 reportable finding(s)**");
    expect(calls.created?.body.indexOf("Canonical JSON report")).toBeLessThan(
      calls.created?.body.indexOf("Formatter claimed clean") ?? -1,
    );
  });

  it("does not create first-time clean noise but replaces a stale comment", async () => {
    const firstClean = await runCommentScenario({
      report: "Complete report",
      reportValid: true,
      findingsCount: 0,
      outcome: "success",
    });
    expect(firstClean).toEqual({});

    const recovered = await runCommentScenario({
      report: "Complete report",
      reportValid: true,
      findingsCount: 0,
      outcome: "success",
      existingBody: "## supply-chain-guard Scan Report\n\nOld partial warning",
    });
    expect(recovered.updated?.body).toContain("Complete report");
    expect(recovered.updated?.body).not.toContain("Old partial warning");
  });

  it("updates only an exact marker comment authored by github-actions", async () => {
    expect(commentScript).toContain("github.paginate(github.rest.issues.listComments");
    expect(commentScript).toContain("per_page: 100");
    expect(commentScript).toContain("comment.user?.login === 'github-actions[bot]'");
    expect(commentScript).toContain("comment.body.startsWith(`${marker}\\n`)");

    const calls = await runCommentScenario({
      report: "Finding report",
      reportValid: true,
      findingsCount: 1,
      outcome: "failure",
      existingBody: "## supply-chain-guard Scan Report\n\nSpoofed user comment",
      existingAuthor: "attacker",
    });
    expect(calls.updated).toBeUndefined();
    expect(calls.created?.body).toContain("Finding report");
  });

  it("reads only a bounded report excerpt and caps the comment body", async () => {
    expect(commentScript).toContain("fs.readSync");
    expect(commentScript).not.toContain("fs.readFileSync");

    const calls = await runCommentScenario({
      report: "x".repeat(1_000_000),
      reportValid: true,
      findingsCount: 1,
      outcome: "failure",
    });
    expect(calls.created?.body).toContain("Comment truncated");
    expect(calls.created?.body.length).toBeLessThan(56_000);
  });

  it("renders non-Markdown reports as inert, mention-neutralized code", async () => {
    const calls = await runCommentScenario({
      report: "<script>alert(1)</script>\n@security-team",
      reportValid: true,
      findingsCount: 1,
      outcome: "failure",
      format: "html",
    });
    expect(calls.created?.body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(calls.created?.body).toContain("&#64;security-team");
    expect(calls.created?.body).not.toContain("<script>");
    expect(calls.created?.body).not.toContain("@security-team");
  });

  it("renders Markdown formatter content as inert code in PR comments", async () => {
    const calls = await runCommentScenario({
      report: "![scan-tracker](https://example.invalid/pixel.svg)\n# Spoofed heading",
      reportValid: true,
      findingsCount: 1,
      outcome: "failure",
      format: "markdown",
    });
    const body = calls.created?.body ?? "";
    expect(body).toContain("    ![scan-tracker](https://example.invalid/pixel.svg)");
    expect(body).toContain("    # Spoofed heading");
    expect(body).not.toMatch(/(?:^|\n)!\[scan-tracker\]/);
    expect(body).not.toMatch(/(?:^|\n)# Spoofed heading/);
  });

  it("uses bracket access for every hyphenated input and output expression", () => {
    expect(action).not.toMatch(/\binputs\.(?:min-severity|exclude-rules|fail-on|comment-on-pr)\b/);
    expect(action).not.toMatch(/\bsteps\.scan\.outputs\.(?:findings-count|partial-scan|report-path|report-truncated)\b/);
    expect(action).toContain("inputs['min-severity']");
    expect(action).toContain("steps.scan.outputs['findings-count']");
  });

  it.skipIf(!hasBash)("has syntactically valid composite Bash", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "scg-action-syntax-"));
    const script = path.join(temp, "scan.sh");
    fs.writeFileSync(script, scanScript, "utf8");
    const result = spawnSync("bash", ["-n", script], { encoding: "utf8" });
    fs.rmSync(temp, { recursive: true, force: true });
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });

  it.skipIf(!hasJq)("accepts a complete schema and rejects malformed or undercounted reports", () => {
    expect(jqAccepts(validEmptyReport)).toBe(true);
    expect(jqAccepts({ summary: {}, findings: [], score: 0, riskLevel: "clean" })).toBe(false);
    expect(jqAccepts({ ...validEmptyReport, partialScan: "true" })).toBe(false);
    expect(jqAccepts({ ...validEmptyReport, riskLevel: "clean\nreport-valid=true" })).toBe(false);
    expect(jqAccepts({ ...validEmptyReport, score: 25, riskLevel: "clean" })).toBe(false);
    expect(jqAccepts({
      ...validEmptyReport,
      summary: { ...validEmptyReport.summary, critical: 1 },
      findings: [{ rule: "TEST_CRITICAL", severity: "critical" }],
    })).toBe(false);
    expect(jqAccepts({
      ...validEmptyReport,
      findings: [{ severity: "critical" }],
    })).toBe(false);
    const coverageFinding = { rule: "PATH_SCAN_INCOMPLETE", severity: "info" };
    const coverageReport = {
      ...validEmptyReport,
      summary: { ...validEmptyReport.summary, info: 1 },
      findings: [coverageFinding],
      score: 1,
      riskLevel: "low",
    };
    expect(jqAccepts(coverageReport)).toBe(false);
    expect(jqAccepts({ ...coverageReport, partialScan: true })).toBe(true);
    // Zero is the score calculateScore() actually returns when every finding is
    // info, so the floor must accept it. This asserted the opposite until
    // v6.0.10, which is what made the Action reject its own scanner's output.
    expect(jqAccepts({
      ...coverageReport,
      score: 0,
      riskLevel: "clean",
      partialScan: true,
    })).toBe(true);
  });

  // The constants above are necessary but nowhere near sufficient: they pin the
  // severity table and the excluded-rule list, and both were still correct when
  // v6.0.10 shipped a floor that rejected every report the scanner produced for
  // a repository scanned at --min-severity info. What drifted was the control
  // flow, which no constant describes. This runs the shipped jq against reports
  // scored by the real function, so the two cannot disagree unnoticed.
  it.skipIf(!hasJq)("floors the score at what calculateScore actually returns", () => {
    const riskLevelFor = (score: number) =>
      score === 0 ? "clean"
        : score <= 10 ? "low"
        : score <= 30 ? "medium"
        : score <= 60 ? "high"
        : "critical";

    const mixes: { name: string; findings: { rule: string; severity: string }[] }[] = [
      {
        name: "a rule that only ever appears at info",
        findings: [{ rule: "GHA_THIRD_PARTY_ACTION", severity: "info" }],
      },
      {
        // The consumer shape v6.0.10 rejected: two info-only rules lifted the
        // floor to 19 against a score of 17.
        name: "info findings beside scored ones",
        findings: [
          { rule: "GHA_SECRET_EXFIL_MULTILINE", severity: "high" },
          { rule: "INTERNAL_PRIVATE_IP", severity: "medium" },
          { rule: "GHA_THIRD_PARTY_ACTION", severity: "info" },
          { rule: "LOCKFILE_ORPHANED_DEPENDENCY", severity: "info" },
        ],
      },
      {
        name: "one rule seen at info and at a scored severity",
        findings: [
          { rule: "INTERNAL_HOSTNAME", severity: "medium" },
          { rule: "INTERNAL_HOSTNAME", severity: "info" },
        ],
      },
      {
        name: "a meta-governance rule excluded from the score",
        findings: [{ rule: "CRITICAL_FINDING_NO_OWNER", severity: "critical" }],
      },
    ];

    for (const mix of mixes) {
      const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const finding of mix.findings) {
        summary[finding.severity as keyof typeof summary]++;
      }
      const score = calculateScore(mix.findings as unknown as Finding[]);
      const report = {
        summary: { totalFiles: 1, filesScanned: 1, ...summary },
        findings: mix.findings,
        score,
        riskLevel: riskLevelFor(score),
      };
      expect(jqAccepts(report), `${mix.name} (score ${score})`).toBe(true);

      if (score > 0) {
        // A report scoring even one point below calculateScore must fail closed:
        // the floor is an exact minimum, not an approximate bound.
        const underReport = {
          ...report,
          score: score - 1,
          riskLevel: riskLevelFor(score - 1),
        };
        expect(
          jqAccepts(underReport),
          `${mix.name} (under-reported score ${score - 1} vs floor ${score})`,
        ).toBe(false);
      }
    }
  });

  it.skipIf(!hasBash || !hasJq)("executes clean, partial, critical, malformed, and invalid-input gates", () => {
    const clean = runScanScript(validEmptyReport);
    expect(clean.status).toBe(0);
    expect((clean as typeof clean & { githubOutput?: string }).githubOutput).toContain("report-valid=true");

    const partial = runScanScript({ ...validEmptyReport, partialScan: true });
    expect(partial.status).toBe(1);

    const critical = runScanScript({
      ...validEmptyReport,
      summary: { ...validEmptyReport.summary, critical: 1 },
      findings: [{ rule: "TEST_CRITICAL", severity: "critical" }],
      score: 25,
      riskLevel: "medium",
    });
    expect(critical.status).toBe(2);

    expect(runScanScript({ summary: {}, findings: [], score: 0, riskLevel: "clean" }).status).toBe(1);
    expect(runScanScript(validEmptyReport, "criticial").status).toBe(1);
    expect(runScanScript(validEmptyReport, "critical", { commentOnPr: "tru" }).status).toBe(1);

    const injectedEnum = runScanScript(validEmptyReport, "critical", {
      format: "bad\n::warning::spoofed",
    });
    expect(injectedEnum.status).toBe(1);
    expect(`${injectedEnum.stdout}${injectedEnum.stderr}`).not.toContain(
      "::warning::spoofed",
    );
    const hiddenInfo = runScanScript(validEmptyReport, "info");
    expect(hiddenInfo.status).toBe(1);
    expect(hiddenInfo.stderr).toContain("would hide findings required by fail-on 'info'");
    expect((hiddenInfo as typeof hiddenInfo & { githubOutput?: string }).githubOutput).toBe("");

    const hiddenHigh = runScanScript(validEmptyReport, "high", {
      minSeverity: "critical",
    });
    expect(hiddenHigh.status).toBe(1);
    expect(hiddenHigh.stderr).toContain("would hide findings required by fail-on 'high'");

    const exactCriticalThresholds = runScanScript(validEmptyReport, "critical", {
      minSeverity: "critical",
    });
    expect(exactCriticalThresholds.status).toBe(0);
    expect(exactCriticalThresholds.stderr).not.toContain("default high gate");
    const validThresholds = runScanScript(validEmptyReport, "critical", {
      minSeverity: "low",
    });
    expect(validThresholds.status).toBe(0);

    const wrongScanStatus = runScanScript(validEmptyReport, "critical", { scanStatus: 1 });
    expect(wrongScanStatus.status).toBe(1);
    expect((wrongScanStatus as typeof wrongScanStatus & { githubOutput?: string }).githubOutput)
      .toContain("passes-consistent=false");

    const brokenFormatter = runScanScript(validEmptyReport, "critical", {
      format: "markdown",
      formattedReport: "formatter failed",
      scanStatus: 0,
    });
    expect(brokenFormatter.status).toBe(1);
    expect((brokenFormatter as typeof brokenFormatter & { githubOutput?: string }).githubOutput)
      .toContain("passes-consistent=false");

    const brokenJsonFormatter = runScanScript(validEmptyReport, "critical", {
      format: "json",
      formattedReport: "{}",
      scanStatus: 0,
    });
    expect(brokenJsonFormatter.status).toBe(1);

    const workflowCommand = "::warning file=spoof.js::untrusted";
    const commandReport = runScanScript(validEmptyReport, "critical", {
      format: "markdown",
      formattedReport:
        `## supply-chain-guard Scan Report\n\n| Property | Value |\n${workflowCommand}`,
    });
    expect(commandReport.status).toBe(0);
    const stop = commandReport.stdout.match(/::stop-commands::(SCG_LOG_[^\r\n]+)/);
    expect(stop).not.toBeNull();
    expect(commandReport.stdout.indexOf(stop![0])).toBeLessThan(
      commandReport.stdout.indexOf(workflowCommand),
    );
    expect(commandReport.stdout.indexOf(workflowCommand)).toBeLessThan(
      commandReport.stdout.indexOf(`::${stop![1]}::`),
    );
  });
});
