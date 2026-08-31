#!/usr/bin/env node

/**
 * Run Vitest and reject a green suite that wrote diagnostics to stderr.
 *
 * Vitest correctly fails on assertion errors, but console warnings and error
 * logs from passing tests otherwise leave the job green. That makes genuine
 * deprecations and unexpected error paths indistinguishable from test noise.
 * Tests that intentionally exercise logging must spy on and assert that output.
 */

import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const vitestRoot = dirname(require.resolve("vitest/package.json"));
const vitestCli = join(vitestRoot, "vitest.mjs");
const child = spawn(
  process.execPath,
  [vitestCli, "run", "--disableConsoleIntercept", ...process.argv.slice(2)],
  {
    env: process.env,
    stdio: ["inherit", "inherit", "pipe"],
  },
);

let stderrBytes = 0;

child.stderr.on("data", (chunk) => {
  stderrBytes += chunk.length;
  process.stderr.write(chunk);
});

child.on("error", (error) => {
  console.error(`Unable to start Vitest: ${error.message}`);
  process.exitCode = 1;
});

child.on("close", (code, signal) => {
  if (signal) {
    console.error(`Vitest terminated by signal ${signal}.`);
    process.exitCode = 1;
    return;
  }
  if (code !== 0) {
    process.exitCode = code ?? 1;
    return;
  }
  if (stderrBytes > 0) {
    console.error(
      "Test suite passed but wrote to stderr. Capture and assert intentional diagnostics; " +
        "fix unexpected warnings or errors instead of allowing a noisy green pipeline.",
    );
    process.exitCode = 1;
  }
});
