/**
 * Regression test: the `scan` command must self-terminate after a clean scan.
 *
 * Background: the scanners reach the npm and PyPI registries over Node's global
 * HTTP(S) agents. Since Node 19 those agents pool sockets with keepAlive, and an
 * idle pooled socket can keep the event loop alive on runtimes that do not unref
 * free sockets. A scan that finds critical/high findings calls process.exit() and
 * terminates regardless, but a clean or medium/low-only scan falls through with no
 * exit() call, so a lingering pooled socket left the CLI running forever ("finished
 * the work, never returned the prompt"). The fix tears the global agents down on the
 * clean-return path so the loop drains and the command exits on its own.
 *
 * This test spawns the compiled CLI against a directory whose requirements.txt lists
 * real public PyPI packages (so the dependency-confusion scanner performs live
 * registry lookups that pool sockets) and asserts the process exits on its own,
 * well within a bounded time, instead of being killed by the spawn timeout. On the
 * pre-fix code, in an environment where free keepAlive sockets stay referenced, the
 * process would still be running when the timeout fired (status null, signal set).
 *
 * Requires `npm run build` to have been run first (mirrors cli.test.ts).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../..");
const CLI = path.join(ROOT, "dist", "cli.js");

// Hard cap for the spawned CLI. Real work is sub-second; anything approaching this
// means the process failed to self-terminate.
const SPAWN_TIMEOUT_MS = 20000;

let workdir: string;
let scanTarget: string;

beforeAll(() => {
  workdir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-self-exit-"));
  scanTarget = path.join(workdir, "clean-project");
  fs.mkdirSync(scanTarget, { recursive: true });
  fs.writeFileSync(
    path.join(scanTarget, "package.json"),
    JSON.stringify({ name: "clean-project", version: "1.0.0" }, null, 2),
    "utf-8",
  );
  // Well-established public PyPI packages: each has a description, a homepage and
  // many releases, so the dependency-confusion scanner raises at most one flag per
  // package (below its two-flag reporting threshold). The scan therefore stays clean
  // and lands on the exact clean-return path that used to hang, while still issuing
  // the live PyPI lookups that pool keepAlive sockets.
  fs.writeFileSync(
    path.join(scanTarget, "requirements.txt"),
    ["requests", "flask", "numpy", "click"].join("\n") + "\n",
    "utf-8",
  );
});

afterAll(() => {
  fs.rmSync(workdir, { recursive: true, force: true });
});

describe("CLI scan self-termination (clean scan)", () => {
  it("exits on its own after a clean scan instead of hanging on pooled sockets", () => {
    const start = Date.now();
    const result = spawnSync(process.execPath, [CLI, "scan", scanTarget], {
      encoding: "utf-8",
      timeout: SPAWN_TIMEOUT_MS,
    });
    const elapsed = Date.now() - start;

    // spawnSync populates `error` (ETIMEDOUT) and kills the child with a signal when
    // the timeout fires. A process that self-terminates leaves error undefined,
    // signal null, and a numeric status.
    expect(result.error).toBeUndefined();
    expect(result.signal).toBeNull();
    expect(result.status).toBe(0);
    // Sanity bound: self-exit should happen long before the hard cap.
    expect(elapsed).toBeLessThan(SPAWN_TIMEOUT_MS);
  });
});
