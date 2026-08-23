/**
 * Issue 194: checkSlaCompliance had no caller, so SLA_BREACH_CRITICAL and
 * SLA_AT_RISK could never reach a scan report. The engine itself worked; the
 * defect was that scan() never invoked it.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { STATE_DIR } from "../state-dir.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-194-"));
  fs.writeFileSync(path.join(tmpDir, "package.json"), '{"name":"x","version":"1.0.0"}');
  fs.writeFileSync(path.join(tmpDir, "index.js"), "module.exports = 1;\n");
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

it("a scan of a tree whose triage store is 30 days past SLA raises SLA_BREACH_CRITICAL", async () => {
  fs.mkdirSync(path.join(tmpDir, STATE_DIR), { recursive: true });
  fs.writeFileSync(
    path.join(tmpDir, STATE_DIR, "triage-decisions.json"),
    JSON.stringify(
      [
        {
          findingRule: "EVAL_ATOB",
          status: "new",
          decidedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        },
      ],
      null,
      2,
    ),
  );

  const report = await scan({ target: tmpDir, format: "json", noHistory: true });
  expect(report.findings.map((f) => f.rule)).toContain("SLA_BREACH_CRITICAL");
});
