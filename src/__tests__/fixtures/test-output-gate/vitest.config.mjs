import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/__tests__/fixtures/test-output-gate/*.fixture.mjs"],
  },
});
