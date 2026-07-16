/**
 * Gate 5 — RLS through the actual async runtime path (AsyncContinuumEngine over
 * PostgresStore), including foreign-tenant denial and pooled-connection reuse.
 *
 * Runs against the workspace global-setup database (t_acme = 10 memory objects,
 * t_globex = 1). Tenant authority comes only from the RequestContext; the
 * transaction-local `app.current_tenant` must not leak across the shared pool.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AsyncContinuumEngine, researchContext, type RequestContext } from "@continuum/core";
import { appPool, dbConfigFromEnv, withTenant } from "./pg";
import { PostgresStore } from "./postgres-store";

const NOW = Date.parse("2026-07-15T00:00:00.000Z");
const acme = (): RequestContext =>
  researchContext({ tenantId: "t_acme", principalId: "spiffe://acme.ai/agents/procurement-agent", nowMs: NOW, source: "console_api" });
const globex = (): RequestContext =>
  researchContext({ tenantId: "t_globex", principalId: "spiffe://globex.health/agents/billing-agent", nowMs: NOW, source: "console_api" });

let store: PostgresStore;
let engine: AsyncContinuumEngine;

beforeAll(() => {
  store = new PostgresStore(dbConfigFromEnv());
  engine = new AsyncContinuumEngine(store);
});
afterAll(async () => {
  await store.close();
});

describe("RLS through the async runtime path (gate 5)", () => {
  it("each tenant reads only its own authorized memory", async () => {
    expect((await engine.listAuthorizedMemory(acme())).length).toBe(10);
    expect((await engine.listAuthorizedMemory(globex())).map((m) => m.memory_id)).toEqual(["mem_glx_quote"]);
  });

  it("a foreign-tenant intent read returns null (invisible), own tenant sees it", async () => {
    const acmeIntent = await withTenant(appPool(dbConfigFromEnv()), "t_acme", async (c) =>
      (await c.query("SELECT intent_id FROM intents LIMIT 1")).rows[0]?.intent_id as string | undefined,
    );
    expect(acmeIntent).toBeTruthy();
    expect(await store.getIntent(globex(), acmeIntent!)).toBeNull();
    expect((await store.getIntent(acme(), acmeIntent!))?.intent_id).toBe(acmeIntent);
  });

  it("pooled-connection reuse does not leak tenant across concurrent requests", async () => {
    // 24 interleaved requests share a pool capped at 4; each transaction sets its
    // own transaction-local tenant. A leak would let an Acme request see Globex
    // data (or vice versa).
    const jobs = Array.from({ length: 24 }, (_, i) => {
      const isAcme = i % 2 === 0;
      return engine
        .listAuthorizedMemory(isAcme ? acme() : globex())
        .then((m) => ({ isAcme, ids: m.map((x) => x.memory_id) }));
    });
    const results = await Promise.all(jobs);
    for (const r of results) {
      if (r.isAcme) {
        expect(r.ids).toHaveLength(10);
        expect(r.ids).not.toContain("mem_glx_quote");
      } else {
        expect(r.ids).toEqual(["mem_glx_quote"]);
      }
    }
  });

  it("fails closed when the tenant context is missing", async () => {
    const broken = { ...acme(), tenant: { ...acme().tenant, tenantId: "" } };
    await expect(engine.listAuthorizedMemory(broken)).rejects.toThrow(/missing tenant context/i);
  });
});
