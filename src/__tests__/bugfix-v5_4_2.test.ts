/**
 * Regression tests for the v5.4.2 suppressed-finding leak fixes.
 *
 * Found by a real user scan of this very repo: the report simultaneously said
 * "No findings - clean" AND showed a "[CRITICAL] Shai-Hulud npm Worm, 100%
 * confidence" incident, because correlateFindings() consumed findings BEFORE
 * applyPolicy() removed the policy-suppressed ones. The trend check had the
 * same flaw: it compared a pre-suppression score against the post-suppression
 * score stored in .scg-history, so the second scan of any repo with
 * suppressions produced a guaranteed phantom RISK_TREND_SPIKE (observed:
 * "spiked from 8 to 51 (538% increase)"). Same bug class as the v5.2.40
 * SARIF/SBOM suppressed-finding leaks.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";

// Content that trips SHAI_HULUD_WORM ("npm publish") and SHAI_HULUD_CRED_STEAL
// (".npmrc" / "NPM_TOKEN") in a plain .js file - the same rule pair whose
// suppressed findings previously leaked into a worm incident.
const WORMY_JS = [
  'const { execSync } = require("child_process");',
  'execSync("npm publish --access public");',
  'const token = process.env.NPM_TOKEN;',
  'require("fs").readFileSync(".npmrc", "utf-8");',
  "",
].join("\n");

const SUPPRESSING_POLICY = [
  "suppress:",
  "  - rule: SHAI_HULUD_WORM",
  "    reason: test fixture documents its own publish pipeline",
  "  - rule: SHAI_HULUD_CRED_STEAL",
  "    reason: test fixture documents token-less publishing",
  "",
].join("\n");

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-v542-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("v5.4.2: policy-suppressed findings do not leak into incidents", () => {
  it("control: without a policy, the worm findings correlate into an incident", async () => {
    fs.writeFileSync(path.join(tmpDir, "payload.js"), WORMY_JS);
    const report = await scan({ target: tmpDir, format: "json" });

    expect(report.findings.some((f) => f.rule === "SHAI_HULUD_WORM")).toBe(true);
    const incidentNames = (report.incidents ?? []).map((i) => i.name);
    expect(incidentNames.join(" ")).toMatch(/shai-hulud/i);
  });

  it("with the rules suppressed by policy, no incident is built from them", async () => {
    fs.writeFileSync(path.join(tmpDir, "payload.js"), WORMY_JS);
    fs.writeFileSync(path.join(tmpDir, ".supply-chain-guard.yml"), SUPPRESSING_POLICY);
    const report = await scan({ target: tmpDir, format: "json" });

    // The findings themselves are suppressed...
    expect(report.findings.some((f) => f.rule.startsWith("SHAI_HULUD"))).toBe(false);
    // ...and (the fix) no incident may be correlated out of the suppressed set.
    const incidentNames = (report.incidents ?? []).map((i) => i.name);
    expect(incidentNames.join(" ")).not.toMatch(/shai-hulud/i);
  });

  it("suppressed findings do not add correlation riskBoost to the score", async () => {
    fs.writeFileSync(path.join(tmpDir, "payload.js"), WORMY_JS);
    fs.writeFileSync(path.join(tmpDir, ".supply-chain-guard.yml"), SUPPRESSING_POLICY);
    const suppressed = await scan({ target: tmpDir, format: "json" });

    fs.writeFileSync(path.join(tmpDir, "payload.js"), 'console.log("clean");\n');
    fs.rmSync(path.join(tmpDir, ".scg-history"), { recursive: true, force: true });
    const clean = await scan({ target: tmpDir, format: "json" });

    // A fully-suppressed scan must score like a clean scan (no hidden boost).
    expect(suppressed.score).toBe(clean.score);
  });
});

describe("v5.4.2: trend check uses the post-suppression score", () => {
  it("second scan of a repo with suppressions produces no phantom RISK_TREND_SPIKE", async () => {
    fs.writeFileSync(path.join(tmpDir, "payload.js"), WORMY_JS);
    fs.writeFileSync(path.join(tmpDir, ".supply-chain-guard.yml"), SUPPRESSING_POLICY);

    // First scan establishes the history baseline (post-suppression score).
    const first = await scan({ target: tmpDir, format: "json" });
    // Second scan of the UNCHANGED repo previously compared the raw
    // pre-suppression score against that baseline -> guaranteed spike.
    const second = await scan({ target: tmpDir, format: "json" });

    expect(second.findings.some((f) => f.rule === "RISK_TREND_SPIKE")).toBe(false);
    expect(second.score).toBe(first.score);
  });

  it("RISK_TREND_SPIKE remains suppressible via policy (late second pass)", async () => {
    // Establish a low-score history, then introduce real (unsuppressed)
    // findings so a genuine spike occurs - but with the trend rule suppressed.
    fs.writeFileSync(path.join(tmpDir, "clean.js"), 'console.log("ok");\n');
    await scan({ target: tmpDir, format: "json" });

    fs.writeFileSync(path.join(tmpDir, "payload.js"), WORMY_JS);
    fs.writeFileSync(
      path.join(tmpDir, ".supply-chain-guard.yml"),
      ["suppress:", "  - rule: RISK_TREND_SPIKE", "    reason: noisy in this environment", ""].join("\n"),
    );
    const report = await scan({ target: tmpDir, format: "json" });

    expect(report.findings.some((f) => f.rule === "RISK_TREND_SPIKE")).toBe(false);
    // The real findings are NOT suppressed - only the trend rule is.
    expect(report.findings.some((f) => f.rule === "SHAI_HULUD_WORM")).toBe(true);
  });
});
