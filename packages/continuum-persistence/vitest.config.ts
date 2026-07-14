import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/global-setup.ts"],
    include: ["src/**/*.test.ts"],
    // One embedded Postgres instance shared across files; run serially so the
    // shared database is deterministic.
    fileParallelism: false,
    testTimeout: 30000,
    hookTimeout: 90000,
  },
});
