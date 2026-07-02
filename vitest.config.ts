import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/__tests__/**/*.test.ts"],
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
