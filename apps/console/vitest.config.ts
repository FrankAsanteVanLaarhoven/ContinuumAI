import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["lib/**/*.test.ts", "app/**/*.test.ts"],
    // Workspace packages are symlinked .ts source; inline so vitest transforms them.
    server: { deps: { inline: [/@continuum\//] } },
  },
});
