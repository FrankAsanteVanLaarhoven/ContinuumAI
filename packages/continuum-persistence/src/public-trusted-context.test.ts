/**
 * Phase 3 S2B — the REAL public.* data plane on trusted context (embedded PostgreSQL).
 *
 * After migration 0004 every tenant-scoped public.* policy keys on
 * continuum.current_tenant(), which returns a tenant ONLY for a live
 * (principal, session, membership, tenant) context established through
 * continuum.begin_authenticated_context. This suite proves, as the least-privilege
 * application role, that:
 *   - a forged app.current_tenant GUC reads and mutates NOTHING (intents,
 *     capabilities, memory, actions/approvals, evidence, proof-replay, idempotency);
 *   - missing context denies; trusted context sees only the DERIVED tenant;
 *   - foreign-membership selection denies; membership/session revocation and
 *     principal suspension take effect on the next transaction;
 *   - tenant switching requires another owned active membership;
 *   - context is transaction-local (no pooled-reuse retention, cleared on rollback);
 *   - the async runtime paths (PostgresStore) establish trusted context and cannot
 *     read without a provisioned identity; restart persistence is intact;
 *   - the app role cannot manufacture authority via a raw authority-setting call.
 */
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Pool, PoolClient } from "pg";
import { runVerticalSlice } from "@continuum/core";
import {
  adminPool,
  appPool,
  withTenant,
  withTrustedContext,
  withoutTenant,
  provisionTrustedIdentity,
  type DbConfig,
} from "./pg";
import { migrate } from "./migrate";
import { persistExport } from "./repository";
import { provisionForExport, serviceRef } from "./provisioning";
import { PostgresStore } from "./postgres-store";
import { serviceContext, withServiceCtx } from "../test/identity";

const DB: DbConfig = { host: "127.0.0.1", port: 55444, database: "continuum_s2b" };
const SLICE_TIME = Date.parse("2026-07-14T12:00:00.000Z");

let admin: Pool;
let app: Pool;

// A multi-tenant principal for the tenant-switching test.
const P_MULTI = randomUUID();
const S_MULTI = randomUUID();
const M_ACME = randomUUID();
const M_GLOBEX = randomUUID();

/** Attacker path: set ONLY the raw app.current_tenant GUC (no trusted context). */
function forged<T>(tenantId: string, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  return withTenant(app, tenantId, fn);
}

beforeAll(async () => {
  const bootstrap = adminPool({ ...DB, database: "continuum" });
  try {
    await bootstrap.query("DROP DATABASE IF EXISTS continuum_s2b");
    await bootstrap.query("CREATE DATABASE continuum_s2b");
  } finally {
    await bootstrap.end();
  }
  await migrate(DB); // full schema through 0004 (trusted-context public RLS)
  admin = adminPool(DB);
  app = appPool(DB);

  // Seed real tenant data (t_acme rich; t_globex = 1 memory) under trusted context.
  const exp = runVerticalSlice(SLICE_TIME).engine.exportState();
  const resolveRef = await provisionForExport(admin, exp);
  await persistExport(app, exp, resolveRef);

  // A single principal that is a member of BOTH tenants (for the switching test).
  await admin.query(`INSERT INTO continuum.principals (principal_id, principal_type, status) VALUES ($1,'service','active')`, [P_MULTI]);
  await admin.query(`INSERT INTO continuum.tenant_memberships (membership_id, principal_id, tenant_id, status) VALUES ($1,$2,'t_acme','active')`, [M_ACME, P_MULTI]);
  await admin.query(`INSERT INTO continuum.tenant_memberships (membership_id, principal_id, tenant_id, status) VALUES ($1,$2,'t_globex','active')`, [M_GLOBEX, P_MULTI]);
  await admin.query(
    `INSERT INTO continuum.authenticated_sessions (session_id, principal_id, credential_digest, idle_expires_at, absolute_expires_at, identity_version)
     VALUES ($1,$2,'d', now() + interval '8 hour', now() + interval '8 hour', 1)`,
    [S_MULTI, P_MULTI],
  );

  // Seed one consumed_proof under trusted context so the proof-replay table is non-empty.
  await withServiceCtx(app, "t_acme", (c) =>
    c.query(`INSERT INTO consumed_proofs (tenant_id, token_id, challenge, consumed_at) VALUES ('t_acme','tok','C0','t')`),
  );
});

afterAll(async () => {
  await admin.end();
  await app.end();
});

const TENANT_TABLES = [
  "intents", "capabilities", "memory_objects", "action_proposals",
  "approvals", "evidence_envelopes", "consumed_proofs", "revocations", "consent",
];

describe("S2B — public data plane on trusted context", () => {
  it("a forged tenant GUC reads NOTHING from any tenant-scoped table", async () => {
    for (const t of TENANT_TABLES) {
      const rows = await forged("t_acme", (c) => c.query(`SELECT 1 FROM ${t} LIMIT 5`).then((r) => r.rows));
      expect(rows, `forged read of ${t}`).toHaveLength(0);
    }
  });

  it("a forged tenant GUC cannot read or mutate intents", async () => {
    expect(await forged("t_acme", (c) => c.query("SELECT intent_id FROM intents").then((r) => r.rows))).toHaveLength(0);
    await expect(
      forged("t_acme", (c) =>
        c.query(`INSERT INTO intents (tenant_id,intent_id,owner_id,actor_id,purpose,requested_operations,prohibited_operations,constraints,required_evidence,human_gate,actor_geo,risk_score)
                 VALUES ('t_acme','forged','o','a','p','[]','[]','{}','[]','{}','GB',0.1)`),
      ),
    ).rejects.toThrow(/row-level security|policy/i);
  });

  it("a forged tenant GUC cannot access capabilities", async () => {
    expect(await forged("t_acme", (c) => c.query("SELECT token_id FROM capabilities").then((r) => r.rows))).toHaveLength(0);
  });

  it("a forged tenant GUC cannot access memory metadata or disclosure", async () => {
    expect(await forged("t_acme", (c) => c.query("SELECT memory_id FROM memory_objects").then((r) => r.rows))).toHaveLength(0);
    await expect(
      forged("t_acme", (c) =>
        c.query(`INSERT INTO memory_objects (tenant_id,memory_id,owner_id,memory_class,content,content_hash,classification,purpose_constraints,read_operation,residency,sensitive_fields,retention_policy,confidence,verification_state,revocation_state,deletion_state,created_at)
                 VALUES ('t_acme','forged','o','evidence','{}','h','confidential','[]','read:x','GB','[]','P1Y',1,'verified','active','present','2026-01-01')`),
      ),
    ).rejects.toThrow(/row-level security|policy/i);
  });

  it("a forged tenant GUC cannot access actions or approvals", async () => {
    expect(await forged("t_acme", (c) => c.query("SELECT action_id FROM action_proposals").then((r) => r.rows))).toHaveLength(0);
    expect(await forged("t_acme", (c) => c.query("SELECT id FROM approvals").then((r) => r.rows))).toHaveLength(0);
  });

  it("a forged tenant GUC cannot access evidence", async () => {
    expect(await forged("t_acme", (c) => c.query("SELECT event_id FROM evidence_envelopes").then((r) => r.rows))).toHaveLength(0);
  });

  it("a forged tenant GUC cannot bypass the proof-replay or idempotency boundaries", async () => {
    // Cannot read the durable proof-replay ledger…
    expect(await forged("t_acme", (c) => c.query("SELECT token_id FROM consumed_proofs").then((r) => r.rows))).toHaveLength(0);
    // …nor pre-plant a consumed proof to deny a victim's disclosure…
    await expect(
      forged("t_acme", (c) => c.query(`INSERT INTO consumed_proofs (tenant_id,token_id,challenge,consumed_at) VALUES ('t_acme','tok','C0','t')`)),
    ).rejects.toThrow(/row-level security|policy/i);
    // …nor read or forge the action idempotency ledger.
    await expect(
      forged("t_acme", (c) =>
        c.query(`INSERT INTO action_proposals (tenant_id,action_id,intent_id,actor,operation,action_class,state,requires_human_approval,expected_effect,reversible,cost_gbp)
                 VALUES ('t_acme','forged','i','a','op','external','PROPOSED',true,'',true,0)`),
      ),
    ).rejects.toThrow(/row-level security|policy/i);
  });

  it("missing trusted context denies (fail-closed)", async () => {
    for (const t of ["intents", "capabilities", "memory_objects", "evidence_envelopes"]) {
      const rows = await withoutTenant(app, (c) => c.query(`SELECT 1 FROM ${t} LIMIT 1`).then((r) => r.rows));
      expect(rows, `no-context read of ${t}`).toHaveLength(0);
    }
  });

  it("a valid session + membership permit ONLY the derived tenant", async () => {
    const acme = await withServiceCtx(app, "t_acme", (c) => c.query("SELECT memory_id FROM memory_objects").then((r) => r.rows.map((x) => x.memory_id)));
    expect(acme).toHaveLength(10);
    expect(acme).not.toContain("mem_glx_quote");
    const globex = await withServiceCtx(app, "t_globex", (c) => c.query("SELECT memory_id FROM memory_objects").then((r) => r.rows.map((x) => x.memory_id)));
    expect(globex).toEqual(["mem_glx_quote"]);
  });

  it("foreign-membership selection denies", async () => {
    // t_acme's principal presenting t_globex's membership id → not owned → denied.
    const foreignRef = { ...serviceRef("t_acme"), membershipId: serviceRef("t_globex").membershipId };
    await expect(withTrustedContext(app, foreignRef, async () => undefined)).rejects.toThrow(/not owned by principal/i);
  });

  it("membership revocation applies on the next transaction", async () => {
    const id = await provisionTrustedIdentity(admin, { tenantId: "t_acme" });
    expect((await withTrustedContext(app, id.ref(), async (_c, est) => est.tenantId))).toBe("t_acme");
    await admin.query("UPDATE continuum.tenant_memberships SET status='revoked', revoked_at=now() WHERE membership_id=$1", [id.membershipId]);
    // The revoked membership is still owned by the principal, so establishment fails
    // at the active-membership check — either way the next transaction is denied.
    await expect(withTrustedContext(app, id.ref(), async () => undefined)).rejects.toThrow(/membership not active|no active membership/i);
  });

  it("session revocation applies on the next transaction", async () => {
    const id = await provisionTrustedIdentity(admin, { tenantId: "t_acme" });
    expect((await withTrustedContext(app, id.ref(), async (_c, est) => est.tenantId))).toBe("t_acme");
    await admin.query("UPDATE continuum.authenticated_sessions SET revoked_at=now() WHERE session_id=$1", [id.sessionId]);
    await expect(withTrustedContext(app, id.ref(), async () => undefined)).rejects.toThrow(/session revoked/i);
  });

  it("principal suspension applies on the next transaction", async () => {
    const id = await provisionTrustedIdentity(admin, { tenantId: "t_acme" });
    expect((await withTrustedContext(app, id.ref(), async (_c, est) => est.tenantId))).toBe("t_acme");
    await admin.query("UPDATE continuum.principals SET status='suspended', suspended_at=now() WHERE principal_id=$1", [id.principalId]);
    await expect(withTrustedContext(app, id.ref(), async () => undefined)).rejects.toThrow(/principal not active/i);
  });

  it("tenant switching requires another active membership owned by the same principal", async () => {
    const base = { principalId: P_MULTI, sessionId: S_MULTI, requestId: randomUUID() };
    // The same principal reaches each tenant only by presenting the matching owned membership.
    expect(await withTrustedContext(app, { ...base, membershipId: M_ACME }, async (_c, est) => est.tenantId)).toBe("t_acme");
    expect(await withTrustedContext(app, { ...base, membershipId: M_GLOBEX }, async (_c, est) => est.tenantId)).toBe("t_globex");

    // Re-keying the tenant GUC WITHOUT re-establishing membership grants nothing.
    const bled = await withTrustedContext(app, { ...base, membershipId: M_ACME }, async (c) => {
      await c.query("SELECT set_config('app.current_tenant', 't_globex', true)");
      return (await c.query("SELECT memory_id FROM memory_objects")).rows.map((r) => r.memory_id);
    });
    expect(bled).toEqual([]); // membership-pinned current_tenant() ⇒ mismatch ⇒ no rows
  });

  it("pooled-connection reuse retains no prior authority", async () => {
    await withServiceCtx(app, "t_acme", async (c) => {
      expect((await c.query("SELECT count(*)::int n FROM memory_objects")).rows[0].n).toBe(10);
    });
    // A later transaction on the (reused) pool with no context sees nothing.
    const leaked = await withoutTenant(app, (c) => c.query("SELECT memory_id FROM memory_objects").then((r) => r.rows));
    expect(leaked).toHaveLength(0);
  });

  it("rollback removes the transaction-local context", async () => {
    const c = await app.connect();
    try {
      await c.query("BEGIN");
      await c.query("SELECT principal_id, tenant_id, membership_id FROM continuum.begin_authenticated_context($1,$2,$3,$4)", [
        serviceRef("t_acme").principalId, serviceRef("t_acme").sessionId, randomUUID(), serviceRef("t_acme").membershipId,
      ]);
      expect((await c.query("SELECT continuum.current_tenant() t")).rows[0].t).toBe("t_acme");
      await c.query("ROLLBACK");
      // After rollback the GUCs are gone; a fresh statement has no authority.
      expect((await c.query("SELECT continuum.current_tenant() t")).rows[0].t).toBeNull();
      expect((await c.query("SELECT count(*)::int n FROM memory_objects")).rows[0].n).toBe(0);
    } finally {
      c.release();
    }
  });

  it("the async runtime paths establish trusted context and derive the tenant", async () => {
    const acmeId = serviceRef("t_acme");
    const store = new PostgresStore(DB, {
      trustedSubjects: {
        "svc:acme": { principalId: acmeId.principalId, sessionId: acmeId.sessionId, membershipId: acmeId.membershipId },
      },
    });
    try {
      // resolveExecutionContext DERIVES the tenant from the DB (never a caller value).
      const ctx = await store.resolveExecutionContext({
        authenticatedSubject: "svc:acme", sessionId: "ignored", requestId: "r", traceId: "t", source: "console_api",
      });
      expect(ctx.tenant.tenantId).toBe("t_acme");
      expect(ctx.tenant.derivedFrom).toBe("trusted_delegation");
      // The runtime read path sees only the derived tenant.
      expect((await store.listAuthorizedMemory(ctx)).length).toBe(10);
      // An unprovisioned subject cannot resolve context (fail-closed).
      await expect(
        store.resolveExecutionContext({ authenticatedSubject: "svc:ghost", sessionId: "x", requestId: "r", traceId: "t", source: "console_api" }),
      ).rejects.toThrow(/no trusted identity mapping/i);
    } finally {
      await store.close();
    }
  });

  it("restart persistence: a fresh store still reads the tenant's data and chain", async () => {
    const store = new PostgresStore(DB);
    try {
      const ctx = serviceContext("t_acme", { nowMs: SLICE_TIME });
      expect((await store.listAuthorizedMemory(ctx)).length).toBe(10);
      const v = await store.verifyEvidenceChain(ctx);
      expect(v.valid).toBe(true);
      expect(v.length).toBeGreaterThan(0);
    } finally {
      await store.close();
    }
  });

  it("the app role cannot manufacture authority via a raw authority-setting call", async () => {
    // Setting every context GUC to fabricated (unowned) values grants nothing:
    // begin_authenticated_context is the only setter and it VALIDATES.
    const forgedAll = await withoutTenant(app, async (c) => {
      await c.query("BEGIN");
      await c.query("SELECT set_config('app.current_principal',$1,true)", [randomUUID()]);
      await c.query("SELECT set_config('app.current_session',$1,true)", [randomUUID()]);
      await c.query("SELECT set_config('app.current_membership',$1,true)", [randomUUID()]);
      await c.query("SELECT set_config('app.current_tenant','t_acme',true)");
      const t = (await c.query("SELECT continuum.current_tenant() t")).rows[0].t;
      const rows = (await c.query("SELECT memory_id FROM memory_objects")).rows;
      await c.query("ROLLBACK");
      return { t, count: rows.length };
    });
    expect(forgedAll.t).toBeNull();
    expect(forgedAll.count).toBe(0);

    // And calling the trusted establisher with unknown identity is DENIED, not granted.
    await expect(
      withTrustedContext(app, { principalId: randomUUID(), sessionId: randomUUID(), requestId: randomUUID() }, async () => undefined),
    ).rejects.toThrow(/auth_context_denied|unknown principal/i);
  });
});
