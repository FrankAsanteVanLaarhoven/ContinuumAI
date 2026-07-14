import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { runVerticalSlice } from "@continuum/core";
import { appPool, dbConfigFromEnv, withTenant } from "./pg";
import { countRows, loadEvidence, verifyPersistedChain } from "./repository";

// A brand-new pool: no shared in-process state with the engine that wrote the
// data. This is the "reconnect after restart" path — everything must come from
// the durable store.
let pool: Pool;
const SLICE_TIME = Date.parse("2026-07-14T12:00:00.000Z");

beforeAll(() => {
  pool = appPool(dbConfigFromEnv());
});
afterAll(async () => {
  await pool.end();
});

describe("durability and restart-safe evidence", () => {
  it("re-verifies the persisted hash chain over a fresh connection", async () => {
    const result = await verifyPersistedChain(pool, "t_acme");
    expect(result.valid).toBe(true);
    expect(result.broken_at).toBeNull();
    expect(result.length).toBeGreaterThan(0);
  });

  it("persists an evidence envelope for every material step", async () => {
    // The in-memory slice is deterministic, so its evidence count is the oracle.
    const inMemory = runVerticalSlice(SLICE_TIME).engine.evidence().entries.length;
    const persisted = await countRows(pool, "t_acme", "evidence_envelopes");
    expect(persisted).toBe(inMemory);
  });

  it("keeps evidence ordered and gap-free", async () => {
    const entries = await loadEvidence(pool, "t_acme");
    const seqs = entries.map((e) => e.seq);
    expect(seqs).toEqual(seqs.map((_, i) => i));
    expect(entries[0]?.prev_hash).toBe("GENESIS");
  });

  it("persists the capability and its revocation durably", async () => {
    const caps = await countRows(pool, "t_acme", "capabilities");
    const revs = await countRows(pool, "t_acme", "revocations");
    expect(caps).toBe(1);
    expect(revs).toBe(1);
  });

  it("persists the action state machine outcomes", async () => {
    const states = await withTenant(pool, "t_acme", async (c) =>
      (await c.query("SELECT operation, state FROM action_proposals ORDER BY operation")).rows,
    );
    const byOp = new Map(states.map((r) => [r.operation, r.state]));
    expect(byOp.get("place_order")).toBe("DENIED");
    expect(byOp.get("publish:recommendation")).toBe("SUCCEEDED");

    const approvals = await countRows(pool, "t_acme", "approvals");
    expect(approvals).toBe(1); // the human-approved external action
  });

  it("reproduces migrations from an empty database (idempotent re-run)", async () => {
    // Re-running the migration must not error and must not duplicate policy rows.
    const { migrate } = await import("./migrate");
    await migrate(dbConfigFromEnv());
    const policies = await withTenant(pool, "t_acme", async (c) =>
      (await c.query("SELECT count(*)::int AS n FROM policies")).rows[0].n,
    );
    expect(policies).toBe(1);
  });
});
