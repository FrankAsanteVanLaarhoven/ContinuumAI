/**
 * PostgresStore contract flows over REAL embedded PostgreSQL (RLS-enforced).
 * Uses the workspace global-setup: one embedded cluster seeded with a durable
 * vertical-slice export (t_acme = 10 memory objects + evidence chain + a
 * capability; t_globex = 1 memory object).
 *
 * Proves through the async ContinuumStore boundary: tenant-scoped reads, foreign
 * tenant invisibility, chain verification, durability across a fresh pool
 * (restart), revocation persistence, fail-closed missing tenant, and that the
 * write/decision path is HELD (documented, not a silent stub).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AsyncContinuumEngine, type RequestContext } from "@continuum/core";
import { appPool, dbConfigFromEnv } from "./pg";
import { serviceContext, withServiceCtx } from "../test/identity";
import { PostgresStore } from "./postgres-store";

const NOW = Date.parse("2026-07-15T00:00:00.000Z");
function ctx(tenantId: string, principalId = "spiffe://acme.ai/agents/procurement-agent"): RequestContext {
  return serviceContext(tenantId, { nowMs: NOW, source: "service_api", subject: principalId });
}

let store: PostgresStore;

beforeAll(() => {
  store = new PostgresStore(dbConfigFromEnv());
});
afterAll(async () => {
  await store.close();
});

describe("PostgresStore · read/verify/revoke/durability over real RLS", () => {
  it("lists memory scoped to the context tenant (t_acme), content withheld", async () => {
    const meta = await store.listAuthorizedMemory(ctx("t_acme"));
    expect(meta).toHaveLength(10);
    for (const m of meta) expect("content" in m).toBe(false);
    expect(meta.map((m) => m.memory_id)).not.toContain("mem_glx_quote");
  });

  it("a different tenant (t_globex) sees only its own object", async () => {
    const meta = await store.listAuthorizedMemory(ctx("t_globex"));
    expect(meta.map((m) => m.memory_id)).toEqual(["mem_glx_quote"]);
  });

  it("a foreign-tenant intent read returns null (RLS invisibility)", async () => {
    // Any intent id, read from the wrong tenant, is invisible.
    const acmeIntent = await withServiceCtx(appPool(dbConfigFromEnv()), "t_acme", async (c) =>
      (await c.query("SELECT intent_id FROM intents LIMIT 1")).rows[0]?.intent_id as string | undefined,
    );
    expect(acmeIntent).toBeTruthy();
    const seenForeign = await store.getIntent(ctx("t_globex"), acmeIntent!);
    expect(seenForeign).toBeNull();
    const seenOwn = await store.getIntent(ctx("t_acme"), acmeIntent!);
    expect(seenOwn?.intent_id).toBe(acmeIntent);
  });

  it("verifies the persisted evidence chain for its tenant", async () => {
    const v = await store.verifyEvidenceChain(ctx("t_acme"));
    expect(v.valid).toBe(true);
    expect(v.length).toBeGreaterThan(0);
  });

  it("evidence durability survives a fresh pool (process-restart simulation)", async () => {
    const restarted = new PostgresStore(dbConfigFromEnv());
    try {
      const v = await restarted.verifyEvidenceChain(ctx("t_acme"));
      expect(v.valid).toBe(true);
    } finally {
      await restarted.close();
    }
  });

  it("revocation persists (append-only) and is visible on a fresh pool", async () => {
    const handle = await withServiceCtx(appPool(dbConfigFromEnv()), "t_acme", async (c) =>
      (await c.query("SELECT revocation_handle FROM capabilities LIMIT 1")).rows[0]?.revocation_handle as string | undefined,
    );
    expect(handle).toBeTruthy();

    const r = await store.transaction(ctx("t_acme"), (tx) => tx.revokeCapability({ revocationHandle: handle! }));
    expect(r.revoked).toBe(true);

    const restarted = new PostgresStore(dbConfigFromEnv());
    try {
      const rows = await withServiceCtx(appPool(dbConfigFromEnv()), "t_acme", async (c) =>
        (await c.query("SELECT revocation_handle FROM revocations WHERE revocation_handle = $1", [handle])).rows,
      );
      expect(rows.length).toBe(1);
    } finally {
      await restarted.close();
    }
  });

  it("revoking an unknown handle reports not revoked", async () => {
    const r = await store.transaction(ctx("t_acme"), (tx) => tx.revokeCapability({ revocationHandle: "rev_does_not_exist" }));
    expect(r.revoked).toBe(false);
  });

  it("the AsyncContinuumEngine runs unchanged over PostgresStore (store-agnostic)", async () => {
    const engine = new AsyncContinuumEngine(store);
    expect(engine.mode).toBe("postgres");
    const meta = await engine.listAuthorizedMemory(ctx("t_acme"));
    expect(meta).toHaveLength(10);
    const v = await engine.verifyEvidenceChain(ctx("t_acme"));
    expect(v.valid).toBe(true);
  });

  it("fails closed when the tenant context is missing", async () => {
    const broken = { ...ctx("t_acme"), tenant: { ...ctx("t_acme").tenant, tenantId: "" } };
    await expect(store.listAuthorizedMemory(broken)).rejects.toThrow(/missing tenant context/i);
  });

  it("HOLDS the write/decision path with a documented pending-review error", async () => {
    await expect(
      store.transaction(ctx("t_acme"), (tx) => tx.authorizeIntent({ intentId: "any" })),
    ).rejects.toThrow(/held pending review/i);
    await expect(
      store.transaction(ctx("t_acme"), (tx) => tx.submitIntent({})),
    ).rejects.toThrow(/held pending review/i);
  });

  it("reports healthy structural status (reachable · migrations · RLS fail-closed · append-only)", async () => {
    const h = await store.health();
    expect(h.mode).toBe("postgres");
    expect(h.databaseReachable).toBe(true);
    expect(h.migrationsCurrent).toBe(true);
    expect(h.rlsVerified).toBe(true);
    expect(h.appendOnlyRoleVerified).toBe(true);
    expect(h.status).toBe("healthy");
  });
});
