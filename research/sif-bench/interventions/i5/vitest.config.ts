import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./src/global-setup.ts"],
    include: ["src/**/*.test.ts"],
    // One embedded Postgres shared across the run; serial for a deterministic db.
    fileParallelism: false,
    testTimeout: 60000,
    hookTimeout: 120000,
  },
});
