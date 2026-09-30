import { defineConfig } from "vitest/config";
import * as os from "node:os";
import * as path from "node:path";

const coverageRun = process.argv.some((arg) => arg === "--coverage" || arg.startsWith("--coverage."));
const testCacheRoot = path.join(os.tmpdir(), `scg-vitest-cache-${process.pid}`);

export default defineConfig({
  test: {
    include: ["src/__tests__/**/*.test.ts"],
    // SCG_CACHE_DIR keeps every test that does not name a cache directory off
    // the developer's real per-user cache (src/cache-dir.ts): an empty,
    // per-run directory, so no test reads a catalog it did not install.
    // LOCALAPPDATA and XDG_CACHE_HOME point there too, so a test still cannot
    // reach the real per-user cache when SCG_CACHE_DIR is not honoured: that
    // happened once, during a mutation run that disabled it on purpose, and a
    // fixture feed landed in the developer's real cache.
    env: {
      SCG_VITEST_COVERAGE: coverageRun ? "1" : "0",
      SCG_CACHE_DIR: path.join(testCacheRoot, "explicit"),
      LOCALAPPDATA: path.join(testCacheRoot, "localappdata"),
      XDG_CACHE_HOME: path.join(testCacheRoot, "xdg"),
    },
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/__tests__/**", "dist/**", "scripts/**"],
      reporter: ["text", "json-summary"],
      reportOnFailure: true,
      // Measured locally on Windows (13 zip-dependent vscode-scanner tests
      // skipped): lines 68.45, statements 68.14, functions 70.30,
      // branches 63.10. CI (ubuntu) runs the full suite, so its numbers are
      // equal or higher. Thresholds sit ~4 points below the local baseline
      // so the gate rejects regressions, not the status quo.
      thresholds: {
        lines: 64,
        statements: 64,
        functions: 66,
        branches: 59,
      },
    },
  },
});
