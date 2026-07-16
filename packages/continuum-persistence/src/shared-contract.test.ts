/**
 * Gate 4 — one shared ContinuumStore contract, satisfied identically by the async
 * in-memory adapter and the PostgreSQL adapter. Both are seeded from the SAME
 * deterministic vertical slice (the in-memory adapter wraps the slice engine; the
 * PostgreSQL database was persisted from the same slice by the global-setup), so
 * agreement is evidence that swapping the adapter does not change semantics.
 */
import { describe, expect, it } from "vitest";
import {
  AsyncContinuumEngine,
  InMemoryAsyncStore,
  runVerticalSlice,
  type RequestContext,
} from "@continuum/core";
import { dbConfigFromEnv } from "./pg";
import { serviceContext } from "../test/identity";
import { PostgresStore } from "./postgres-store";

// The global-setup persisted runVerticalSlice(SLICE_TIME); the in-memory adapter
// must be seeded from the same instant so the two stores hold identical state.
// serviceContext carries the provisioned trusted identity for the Postgres path;
// the in-memory adapter simply reads the tenant it names.
const SLICE_TIME = Date.parse("2026-07-14T12:00:00.000Z");
const acme = (): RequestContext => serviceContext("t_acme", { nowMs: SLICE_TIME, source: "service_api" });
const globex = (): RequestContext => serviceContext("t_globex", { nowMs: SLICE_TIME, source: "service_api" });

/** Assertions every conformant ContinuumStore adapter must satisfy. */
async function assertContract(engine: AsyncContinuumEngine): Promise<void> {
  const mem = await engine.listAuthorizedMemory(acme());
  expect(mem.length).toBe(10);
  for (const m of mem) expect("content" in m).toBe(false); // content never leaves on this path

  const glx = await engine.listAuthorizedMemory(globex());
  expect(glx.map((m) => m.memory_id)).toEqual(["mem_glx_quote"]); // tenant isolation

  const chain = await engine.verifyEvidenceChain(acme());
  expect(chain.valid).toBe(true);
}

describe("shared ContinuumStore contract (gate 4): in-memory and postgres agree", () => {
  it("InMemoryAsyncStore satisfies the contract", async () => {
    const store = new InMemoryAsyncStore(runVerticalSlice(SLICE_TIME).engine);
    expect(store.mode).toBe("memory");
    await assertContract(new AsyncContinuumEngine(store));
    await store.close();
  });

  it("PostgresStore satisfies the SAME contract", async () => {
    const store = new PostgresStore(dbConfigFromEnv());
    expect(store.mode).toBe("postgres");
    try {
      await assertContract(new AsyncContinuumEngine(store));
    } finally {
      await store.close();
    }
  });
});
