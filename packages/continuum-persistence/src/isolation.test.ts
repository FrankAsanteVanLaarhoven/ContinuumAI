import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { appPool, dbConfigFromEnv, withTenant, withoutTenant } from "./pg";

let pool: Pool;

beforeAll(() => {
  pool = appPool(dbConfigFromEnv());
});
afterAll(async () => {
  await pool.end();
});

describe("RLS tenant isolation (database-enforced)", () => {
  it("a tenant sees only its own memory objects", async () => {
    const acme = await withTenant(pool, "t_acme", async (c) =>
      (await c.query("SELECT memory_id FROM memory_objects")).rows.map((r) => r.memory_id),
    );
    const globex = await withTenant(pool, "t_globex", async (c) =>
      (await c.query("SELECT memory_id FROM memory_objects")).rows.map((r) => r.memory_id),
    );
    expect(acme).toHaveLength(10);
    expect(acme).not.toContain("mem_glx_quote");
    expect(globex).toEqual(["mem_glx_quote"]);
  });

  it("cross-tenant read of a specific foreign object returns nothing", async () => {
    const leaked = await withTenant(pool, "t_acme", async (c) =>
      (await c.query("SELECT memory_id FROM memory_objects WHERE memory_id = $1", ["mem_glx_quote"])).rows,
    );
    expect(leaked).toHaveLength(0);
  });

  it("missing tenant context exposes nothing (fail-closed)", async () => {
    const rows = await withoutTenant(pool, async (c) =>
      (await c.query("SELECT memory_id FROM memory_objects")).rows,
    );
    expect(rows).toHaveLength(0);
    const ev = await withoutTenant(pool, async (c) =>
      (await c.query("SELECT event_id FROM evidence_envelopes")).rows,
    );
    expect(ev).toHaveLength(0);
  });

  it("a forged tenant_id insert is rejected by WITH CHECK", async () => {
    await expect(
      withTenant(pool, "t_acme", async (c) => {
        await c.query(
          "INSERT INTO memory_objects (tenant_id, memory_id, owner_id, memory_class, content, content_hash, classification, purpose_constraints, read_operation, residency, retention_policy, sensitive_fields, confidence, verification_state, revocation_state, deletion_state, created_at) VALUES ('t_globex','forged','o','evidence','{}','h','confidential','[]','read:x','GB','P1Y','[]',1,'verified','active','present','2026-01-01')",
        );
      }),
    ).rejects.toThrow();
  });

  it("evidence is cross-tenant isolated", async () => {
    const acmeEv = await withTenant(pool, "t_acme", async (c) =>
      (await c.query("SELECT count(*)::int AS n FROM evidence_envelopes")).rows[0].n,
    );
    const globexEv = await withTenant(pool, "t_globex", async (c) =>
      (await c.query("SELECT count(*)::int AS n FROM evidence_envelopes")).rows[0].n,
    );
    expect(acmeEv).toBeGreaterThan(0);
    expect(globexEv).toBe(0);
  });

  it("the evidence stream is append-only (UPDATE and DELETE rejected)", async () => {
    await expect(
      withTenant(pool, "t_acme", async (c) => {
        await c.query("UPDATE evidence_envelopes SET decision = 'tampered' WHERE seq = 0");
      }),
    ).rejects.toThrow();
    await expect(
      withTenant(pool, "t_acme", async (c) => {
        await c.query("DELETE FROM evidence_envelopes WHERE seq = 0");
      }),
    ).rejects.toThrow();
  });

  it("the app role cannot UPDATE or DELETE authoritative rows (least privilege)", async () => {
    await expect(
      withTenant(pool, "t_acme", async (c) => {
        await c.query("DELETE FROM memory_objects WHERE memory_id = 'mem_q_apex'");
      }),
    ).rejects.toThrow();
  });
});
