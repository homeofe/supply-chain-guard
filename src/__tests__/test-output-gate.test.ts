import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runner = path.join(repoRoot, "scripts", "run-vitest-clean.mjs");
const fixtureConfig = path.join(
  repoRoot,
  "src",
  "__tests__",
  "fixtures",
  "test-output-gate",
  "vitest.config.mjs",
);

function runFixture(name: string) {
  return spawnSync(process.execPath, [runner, "--config", fixtureConfig, name], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
}

describe("clean test-output gate", () => {
  it("keeps a passing suite with clean stderr green", () => {
    const result = runFixture("clean.fixture.mjs");
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
  });

  it("rejects a passing suite that writes a warning or error to stderr", () => {
    const result = runFixture("stderr.fixture.mjs");
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("intentional stderr fixture");
    expect(result.stderr).toContain("Test suite passed but wrote to stderr");
  });

  it("preserves an ordinary Vitest failure without mislabelling it as stderr noise", () => {
    const result = runFixture("failure.fixture.mjs");
    expect(result.status).toBe(1);
    expect(result.stdout).toContain("failure fixture");
    expect(result.stderr).toContain("AssertionError");
    expect(result.stderr).not.toContain("Test suite passed but wrote to stderr");
  });
});
