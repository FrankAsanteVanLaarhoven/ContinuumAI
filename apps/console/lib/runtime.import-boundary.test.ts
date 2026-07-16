/**
 * Gate 7 — the synchronous research engine must not enter the production console.
 *
 * The production path (page + runtime + api/runtime) is scanned at the source
 * level: no `runVerticalSlice`, no `new ContinuumEngine`, no import of the retired
 * synchronous data layer. It must depend only on the async engine + store
 * adapters. Comments are stripped first so a doc-mention of the boundary is not a
 * false positive.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const PRODUCTION_MODULES = [
  "lib/runtime.ts",
  "lib/runtime-dto.ts",
  "app/page.tsx",
  "app/api/runtime/route.ts",
];

function code(rel: string): string {
  return readFileSync(join(root, rel), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");
}

function exists(rel: string): boolean {
  try {
    readFileSync(join(root, rel), "utf8");
    return true;
  } catch {
    return false;
  }
}

describe("console production import boundary (gate 7)", () => {
  it("no production module uses the synchronous research engine or slice", () => {
    for (const rel of PRODUCTION_MODULES) {
      const s = code(rel);
      expect(s, `${rel} must not call runVerticalSlice`).not.toMatch(/runVerticalSlice\s*\(/);
      expect(s, `${rel} must not construct ContinuumEngine`).not.toMatch(/new\s+ContinuumEngine\b/);
      expect(s, `${rel} must not import the retired lib/engine`).not.toMatch(/from\s+["'][^"']*lib\/engine["']/);
      expect(s, `${rel} must not import ContinuumEngine/runVerticalSlice by name`).not.toMatch(
        /import[\s\S]*?\b(ContinuumEngine|runVerticalSlice)\b[\s\S]*?from/,
      );
    }
  });

  it("the runtime depends on the async engine + store adapters", () => {
    const s = readFileSync(join(root, "lib/runtime.ts"), "utf8");
    expect(s).toMatch(/AsyncContinuumEngine/);
    expect(s).toMatch(/resolveStoreMode/);
    expect(s).toMatch(/PostgresStore/);
    expect(s).toMatch(/InMemoryAsyncStore/);
  });

  it("the retired synchronous console data layer is removed", () => {
    for (const rel of ["lib/engine.ts", "app/api/state/route.ts", "app/api/rerun/route.ts"]) {
      expect(exists(rel), `${rel} should have been removed`).toBe(false);
    }
  });
});
