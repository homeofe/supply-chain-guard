/**
 * The scanner's state directory must never become a commit in the repository
 * it is scanning. A stale history file once reached a public repository this
 * way, months after it was written, inside an unrelated commit.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { STATE_DIR, ensureStateDir } from "../state-dir.js";
import { saveRiskHistory } from "../continuous-monitor.js";
import { saveTriageDecisions } from "../triage-engine.js";
import type { ScanReport } from "../types.js";

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-state-"));
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

const report = {
  timestamp: "2026-07-25T00:00:00.000Z",
  score: 0,
  findings: [],
  summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
} as unknown as ScanReport;

describe("scanner state directory", () => {
  it("writes a self-ignore file when it creates the directory", () => {
    ensureStateDir(tempDir);
    const ignore = path.join(tempDir, STATE_DIR, ".gitignore");
    expect(fs.existsSync(ignore)).toBe(true);
    // `*` is what makes git skip the directory contents AND this file itself.
    expect(fs.readFileSync(ignore, "utf-8").split("\n")).toContain("*");
  });

  it("self-ignores when risk history is saved, not only on a direct call", () => {
    saveRiskHistory(tempDir, report);
    expect(fs.existsSync(path.join(tempDir, STATE_DIR, "risk-history.json"))).toBe(true);
    expect(fs.existsSync(path.join(tempDir, STATE_DIR, ".gitignore"))).toBe(true);
  });

  it("self-ignores when triage decisions are saved", () => {
    saveTriageDecisions(tempDir, []);
    expect(fs.existsSync(path.join(tempDir, STATE_DIR, "triage-decisions.json"))).toBe(true);
    expect(fs.existsSync(path.join(tempDir, STATE_DIR, ".gitignore"))).toBe(true);
  });

  it("restores the self-ignore if someone deletes it", () => {
    ensureStateDir(tempDir);
    fs.rmSync(path.join(tempDir, STATE_DIR, ".gitignore"));
    saveRiskHistory(tempDir, report);
    expect(fs.existsSync(path.join(tempDir, STATE_DIR, ".gitignore"))).toBe(true);
  });

  it("makes git actually ignore the directory, which is the point", () => {
    // The assertion that matters: not that a file exists, but that a real git
    // sees nothing to commit after a scan has written its state.
    const git = (...args: string[]) =>
      execFileSync("git", args, { cwd: tempDir, encoding: "utf-8" });
    git("init", "-q");
    git("config", "user.email", "test@example.com");
    git("config", "user.name", "test");

    saveRiskHistory(tempDir, report);
    saveTriageDecisions(tempDir, []);

    // `git add -A` is exactly how this went wrong in the first place.
    git("add", "-A");
    const staged = git("diff", "--cached", "--name-only");
    expect(staged).not.toContain(STATE_DIR);
    expect(staged.trim()).toBe("");
  });
});
