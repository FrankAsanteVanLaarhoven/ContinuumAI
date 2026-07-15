/**
 * Import-boundary: the async production engine must not take a RUNTIME dependency
 * on the synchronous research engine, and the async surface must not re-export it.
 *
 * The InMemoryAsyncStore is the deterministic RESEARCH-ONLY adapter and IS
 * allowed to wrap the synchronous engine; the production console/API path
 * (increment 2, Step D) will import the async engine + PostgresStore only, and a
 * console-scoped boundary test will be added there.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as asyncApi from "./index";

const here = dirname(fileURLToPath(import.meta.url));

function importsOfSyncEngine(file: string): string[] {
  const src = readFileSync(join(here, file), "utf8");
  return src
    .split("\n")
    .filter((l) => /from\s+["']\.\.\/engine["']/.test(l))
    .map((l) => l.trim());
}

describe("async import boundary", () => {
  it("async/engine.ts imports the sync engine module for TYPES ONLY (no runtime dependency)", () => {
    const lines = importsOfSyncEngine("engine.ts");
    expect(lines.length).toBeGreaterThan(0); // it references MetricsSnapshot
    for (const l of lines) expect(l.startsWith("import type")).toBe(true);
  });

  it("the async surface does not re-export the synchronous ContinuumEngine class", () => {
    expect(Object.keys(asyncApi)).not.toContain("ContinuumEngine");
    // It DOES export the async boundary + the research adapter.
    expect(Object.keys(asyncApi)).toContain("AsyncContinuumEngine");
    expect(Object.keys(asyncApi)).toContain("InMemoryAsyncStore");
  });

  it("only the research adapter (memory-store) takes a runtime dependency on the sync engine", () => {
    // memory-store is permitted to wrap the frozen engine; engine.ts is not.
    const memLines = importsOfSyncEngine("memory-store.ts");
    expect(memLines.some((l) => !l.startsWith("import type"))).toBe(true);
  });
});
