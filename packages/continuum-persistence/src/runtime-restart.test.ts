/**
 * Gate 6 (state · evidence · revocation) — restart persistence through the async
 * runtime. A brand-new PostgresStore (a fresh connection pool) simulates a
 * process restart: durable state, the evidence chain, and revocations all survive
 * and re-verify because they live in PostgreSQL, not in process memory.
 *
 * (Proof-replay and action-idempotency restart persistence are covered by their
 * own suites once those write paths land.)
 */
import { describe, expect, it } from "vitest";
import { AsyncContinuumEngine, type RequestContext } from "@continuum/core";
import { appPool, dbConfigFromEnv } from "./pg";
import { serviceContext, withServiceCtx } from "../test/identity";
import { PostgresStore } from "./postgres-store";

const NOW = Date.parse("2026-07-15T00:00:00.000Z");
const acme = (): RequestContext => serviceContext("t_acme", { nowMs: NOW, source: "console_api" });

async function withStore<T>(fn: (e: AsyncContinuumEngine, s: PostgresStore) => Promise<T>): Promise<T> {
  const s = new PostgresStore(dbConfigFromEnv());
  try {
    return await fn(new AsyncContinuumEngine(s), s);
  } finally {
    await s.close();
  }
}

describe("restart persistence through the async runtime (gate 6)", () => {
  it("durable state survives a restart (fresh pool)", async () => {
    const intentId = await withServiceCtx(appPool(dbConfigFromEnv()), "t_acme", async (c) =>
      (await c.query("SELECT intent_id FROM intents LIMIT 1")).rows[0]?.intent_id as string,
    );
    // Fresh store = new pool = restart.
    await withStore(async (engine, store) => {
      expect((await engine.listAuthorizedMemory(acme())).length).toBe(10);
      expect((await store.getIntent(acme(), intentId))?.intent_id).toBe(intentId);
    });
  });

  it("the evidence chain survives a restart and re-verifies", async () => {
    await withStore(async (engine) => {
      const v = await engine.verifyEvidenceChain(acme());
      expect(v.valid).toBe(true);
      expect(v.length).toBeGreaterThan(0);
    });
  });

  it("a revocation persists across a restart", async () => {
    const handle = await withServiceCtx(appPool(dbConfigFromEnv()), "t_acme", async (c) =>
      (await c.query("SELECT revocation_handle FROM capabilities LIMIT 1")).rows[0]?.revocation_handle as string | undefined,
    );
    expect(handle).toBeTruthy();
    await withStore((engine) => engine.revokeCapability(acme(), { revocationHandle: handle! }));
    // Fresh pool observes the persisted revocation row.
    const rows = await withServiceCtx(appPool(dbConfigFromEnv()), "t_acme", async (c) =>
      (await c.query("SELECT 1 FROM revocations WHERE revocation_handle = $1", [handle])).rows,
    );
    expect(rows.length).toBe(1);
  });
});
