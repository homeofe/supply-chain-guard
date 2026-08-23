/**
 * Issue 205: a scan that examined ZERO files rendered a bright green clean
 * badge, byte-identical to a scan of a real clean tree.
 * https://github.com/homeofe/supply-chain-guard/issues/205
 *
 * Measured on the commit the issue cites, and re-measured at fa81f70 before
 * this fix: for an empty directory versus the repository's own two-file clean
 * fixture, the `badge`, `sarif`, `gitlab` and `junit` artefacts were identical
 * after normalising timestamps and the target path, and
 * `scan <empty> --fail-on critical` exited 0.
 *
 * The class is "a verdict rendered without its denominator": four renderers
 * described only what was FOUND and never how much was LOOKED AT. Every
 * realistic cause of a zero-file scan is an ordinary CI accident - a checkout
 * that did not run, a wrong working directory, a sparse checkout, an empty
 * mounted volume - and in each of those the published badge said `clean`.
 *
 * NOT covered here, deliberately: a scan whose coverage is merely LOW rather
 * than zero (one file of a thousand, because ignore globs pruned the rest) is
 * still reported as a complete verdict. Only the zero case is a coverage gap
 * this change routes into PARTIAL_SCAN_RULES; a proportional coverage floor
 * would be a policy decision with a threshold nobody has chosen.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { formatReport, getReportExitCode } from "../reporter.js";
import type { ScanReport } from "../types.js";

/** Every format the CLI and the Action can emit. */
const ALL_FORMATS = [
  "text",
  "json",
  "markdown",
  "sarif",
  "sbom",
  "html",
  "badge",
  "gitlab",
  "junit",
] as const;

/**
 * Remove everything that legitimately differs between two runs, so a surviving
 * difference is a real coverage signal and not a clock reading. The target path
 * is normalised too: both directories are temp paths, and a difference in the
 * path alone is not the tool stating its coverage.
 */
function normalise(output: string, target: string): string {
  return output
    .split(target.replace(/\\/g, "\\\\")).join("TARGET")
    .split(target.replace(/\\/g, "/")).join("TARGET")
    .split(target).join("TARGET")
    .replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?/g, "TIMESTAMP")
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, "UUID")
    .replace(/"durationMs":\s*\d+/g, '"durationMs":D')
    .replace(/time="[\d.]+"/g, 'time="D"')
    .replace(/\d+\s*ms/g, "Dms")
    .replace(/(start_time|end_time)":\s*"[^"]*"/g, '$1":"T"');
}

describe("issue 205: a scan of zero files is never indistinguishable from a clean scan", () => {
  let emptyDir: string;
  let cleanDir: string;

  beforeEach(() => {
    emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-205-empty-"));
    cleanDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-205-clean-"));
    fs.writeFileSync(
      path.join(cleanDir, "package.json"),
      JSON.stringify({ name: "clean-pkg", version: "1.0.0" }, null, 2),
    );
    fs.writeFileSync(path.join(cleanDir, "index.js"), "module.exports = () => 1;\n");
  });

  afterEach(() => {
    fs.rmSync(emptyDir, { recursive: true, force: true });
    fs.rmSync(cleanDir, { recursive: true, force: true });
  });

  const scanEmpty = () => scan({ target: emptyDir, noHistory: true });
  const scanClean = () => scan({ target: cleanDir, noHistory: true });

  it("raises a coverage finding and marks the report partial", async () => {
    const report = await scanEmpty();
    expect(report.summary.filesScanned).toBe(0);
    expect(report.findings.map((f) => f.rule)).toContain("SCAN_ZERO_COVERAGE");
    // The finding is only useful if it reaches the flag every renderer honours.
    // Deleting SCAN_ZERO_COVERAGE from PARTIAL_SCAN_RULES turns this line red
    // while leaving the finding itself in place.
    expect(report.partialScan).toBe(true);
  });

  it("positive control: a populated clean tree stays a complete clean verdict", async () => {
    const report = await scanClean();
    expect(report.summary.filesScanned).toBeGreaterThan(0);
    expect(report.findings.map((f) => f.rule)).not.toContain("SCAN_ZERO_COVERAGE");
    expect(report.partialScan).toBeUndefined();
  });

  it("differs from a clean scan in EVERY output format", async () => {
    const empty = await scanEmpty();
    const clean = await scanClean();
    for (const format of ALL_FORMATS) {
      const a = normalise(formatReport(empty, format), emptyDir);
      const b = normalise(formatReport(clean, format), cleanDir);
      expect(a, `format ${format} is indistinguishable from a clean scan`).not.toBe(b);
    }
  });

  it("does not publish a green clean badge for a zero-file scan", async () => {
    const badge = JSON.parse(formatReport(await scanEmpty(), "badge")) as {
      message: string;
      color: string;
    };
    expect(badge.message).not.toBe("clean");
    expect(badge.color).not.toBe("brightgreen");
  });

  it("states its own denominator in SARIF, GitLab and JUnit", async () => {
    const empty = await scanEmpty();

    const sarif = JSON.parse(formatReport(empty, "sarif")) as {
      runs: Array<{
        invocations: Array<{
          executionSuccessful: boolean;
          properties: { coverage: { filesScanned: number | null; totalFiles: number | null } };
        }>;
      }>;
    };
    expect(sarif.runs[0].invocations[0].properties.coverage.filesScanned).toBe(0);
    expect(sarif.runs[0].invocations[0].executionSuccessful).toBe(false);

    const gitlab = JSON.parse(formatReport(empty, "gitlab")) as {
      scan: { status: string; messages: Array<{ level: string; value: string }> };
    };
    expect(gitlab.scan.status).toBe("failure");
    expect(gitlab.scan.messages.some((m) => m.value.includes("0 of 0 files"))).toBe(true);

    const junit = formatReport(empty, "junit");
    expect(junit).toContain('name="supply-chain-guard:files-scanned" value="0"');
  });

  it("a clean scan's machine formats also state the denominator", async () => {
    // The denominator is not a partial-scan decoration: a report that examined
    // a real tree has to say so too, or a reader cannot tell the two apart.
    const clean = await scanClean();
    const sarif = JSON.parse(formatReport(clean, "sarif")) as {
      runs: Array<{ invocations: Array<{ properties: { coverage: { filesScanned: number } } }> }>;
    };
    expect(sarif.runs[0].invocations[0].properties.coverage.filesScanned).toBeGreaterThan(0);
    expect(formatReport(clean, "junit")).toContain("supply-chain-guard:files-scanned");
  });

  it("does not exit 0 while claiming a clean verdict", async () => {
    const empty = (await scanEmpty()) as ScanReport;
    expect(getReportExitCode(empty)).toBe(1);
    // --fail-on cannot talk the gate back down: partial coverage is checked
    // before the severity threshold is applied.
    expect(getReportExitCode(empty, "critical")).toBe(1);
    expect(getReportExitCode(await scanClean())).toBe(0);
  });
});
