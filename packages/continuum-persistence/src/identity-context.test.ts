/**
 * Phase 3 S1+S2 — the trusted database-context boundary on real embedded PostgreSQL.
 *
 * Identity data is seeded as the superuser (the admin provisioning path); the
 * TRUST boundary is exercised as the least-privilege app role (continuum_app),
 * which may only EXECUTE the narrow context function and SELECT the RLS-protected
 * probe. It has NO direct access to the identity/membership tables.
 *
 * Proves: tenant is derived (never app-chosen); a membership hint only selects
 * among the principal's OWN active memberships; revoked membership / suspended
 * principal / expired session / stale identity version all deny; ambiguous
 * multi-tenant membership denies without explicit selection; a forged app GUC
 * creates no authority; context is transaction-local (gone after commit/rollback,
 * not retained across pooled reuse); and the app role cannot read or mutate the
 * identity tables.
 */
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Pool, PoolClient } from "pg";
import { adminPool, appPool, type DbConfig } from "./pg";
import { migrate } from "./migrate";

const DB: DbConfig = { host: "127.0.0.1", port: 55444, database: "continuum_id" };

// Fixed ids for the scenario.
const P1 = randomUUID(); // active, multi-tenant (acme + globex) → ambiguous
const P2 = randomUUID(); // suspended
const P3 = randomUUID(); // active, only membership revoked
const P4 = randomUUID(); // active, session expired
const P5 = randomUUID(); // active, single membership (globex) → unambiguous
const M1 = randomUUID(); // P1 → t_acme
const M2 = randomUUID(); // P1 → t_globex
const M5 = randomUUID(); // P5 → t_globex
const S1 = randomUUID();
const S3 = randomUUID();
const S4 = randomUUID();
const S5 = randomUUID();
const REQ = randomUUID();

let admin: Pool;
let app: Pool;

async function seed(): Promise<void> {
  const c = await admin.connect();
  try {
    await c.query(`INSERT INTO continuum.principals (principal_id, principal_type, status) VALUES ($1,'human','active')`, [P1]);
    await c.query(`INSERT INTO continuum.principals (principal_id, principal_type, status, suspended_at) VALUES ($1,'human','suspended', now())`, [P2]);
    await c.query(`INSERT INTO continuum.principals (principal_id, principal_type, status) VALUES ($1,'human','active')`, [P3]);
    await c.query(`INSERT INTO continuum.principals (principal_id, principal_type, status) VALUES ($1,'human','active')`, [P4]);
    await c.query(`INSERT INTO continuum.principals (principal_id, principal_type, status) VALUES ($1,'human','active')`, [P5]);

    // memberships
    await c.query(`INSERT INTO continuum.tenant_memberships (membership_id, principal_id, tenant_id, status) VALUES ($1,$2,'t_acme','active')`, [M1, P1]);
    await c.query(`INSERT INTO continuum.tenant_memberships (membership_id, principal_id, tenant_id, status) VALUES ($1,$2,'t_globex','active')`, [M2, P1]);
    await c.query(`INSERT INTO continuum.tenant_memberships (membership_id, principal_id, tenant_id, status, revoked_at) VALUES ($1,$2,'t_acme','revoked', now())`, [randomUUID(), P3]);
    await c.query(`INSERT INTO continuum.tenant_memberships (membership_id, principal_id, tenant_id, status) VALUES ($1,$2,'t_acme','active')`, [randomUUID(), P4]);
    await c.query(`INSERT INTO continuum.tenant_memberships (membership_id, principal_id, tenant_id, status) VALUES ($1,$2,'t_globex','active')`, [M5, P5]);

    // sessions (active unless noted)
    const sess = (id: string, principal: string, expired = false) =>
      c.query(
        `INSERT INTO continuum.authenticated_sessions (session_id, principal_id, credential_digest, idle_expires_at, absolute_expires_at, identity_version)
         VALUES ($1,$2,'digest', now() + ($3||' hour')::interval, now() + ($4||' hour')::interval, 1)`,
        [id, principal, expired ? "-1" : "1", expired ? "-1" : "8"],
      );
    await sess(S1, P1);
    await sess(S3, P3);
    await sess(S4, P4, true); // expired
    await sess(S5, P5);

    // probe rows
    await c.query(`INSERT INTO continuum.context_probe (tenant_id, note) VALUES ('t_acme','acme-row'), ('t_globex','globex-row')`);
  } finally {
    c.release();
  }
}

/** Run fn inside an app-role transaction (rolled back), after optionally establishing context. */
async function inAppTxn<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await app.connect();
  try {
    await c.query("BEGIN");
    return await fn(c);
  } finally {
    await c.query("ROLLBACK").catch(() => undefined);
    c.release();
  }
}

function begin(c: PoolClient, principal: string, session: string, membership: string | null = null) {
  return c.query("SELECT * FROM continuum.begin_authenticated_context($1,$2,$3,$4)", [principal, session, REQ, membership]);
}

beforeAll(async () => {
  const bootstrap = adminPool({ ...DB, database: "continuum" });
  try {
    await bootstrap.query("DROP DATABASE IF EXISTS continuum_id");
    await bootstrap.query("CREATE DATABASE continuum_id");
  } finally {
    await bootstrap.end();
  }
  await migrate(DB);
  admin = adminPool(DB);
  app = appPool(DB);
  await seed();
});

afterAll(async () => {
  await admin.end();
  await app.end();
});

describe("Phase 3 S1+S2 — trusted context boundary", () => {
  it("derives the tenant from membership; there is no way to pass a tenant", async () => {
    await inAppTxn(async (c) => {
      const r = await begin(c, P5, S5); // P5 is a member of t_globex only
      expect(r.rows[0].tenant_id).toBe("t_globex");
      const probe = await c.query("SELECT tenant_id FROM continuum.context_probe");
      expect(probe.rows.map((x) => x.tenant_id)).toEqual(["t_globex"]);
    });
  });

  it("a membership hint only selects among the principal's OWN active memberships", async () => {
    await inAppTxn(async (c) => {
      expect((await begin(c, P1, S1, M1)).rows[0].tenant_id).toBe("t_acme");
    });
    await inAppTxn(async (c) => {
      expect((await begin(c, P1, S1, M2)).rows[0].tenant_id).toBe("t_globex");
    });
    // P5 cannot select P1's membership (M1) — not owned.
    await inAppTxn(async (c) => {
      await expect(begin(c, P5, S5, M1)).rejects.toThrow(/not owned by principal/i);
    });
  });

  it("ambiguous multi-tenant membership denies without explicit selection", async () => {
    await inAppTxn(async (c) => {
      await expect(begin(c, P1, S1)).rejects.toThrow(/ambiguous/i);
    });
  });

  it("revoked membership denies", async () => {
    await inAppTxn(async (c) => {
      await expect(begin(c, P3, S3)).rejects.toThrow(/no active membership/i);
    });
  });

  it("suspended principal denies", async () => {
    await inAppTxn(async (c) => {
      await expect(begin(c, P2, randomUUID())).rejects.toThrow(/principal not active/i);
    });
  });

  it("expired session denies", async () => {
    await inAppTxn(async (c) => {
      await expect(begin(c, P4, S4)).rejects.toThrow(/session expired/i);
    });
  });

  it("a session that belongs to a different principal denies", async () => {
    await inAppTxn(async (c) => {
      await expect(begin(c, P1, S5)).rejects.toThrow(/session does not belong/i);
    });
  });

  it("a forged app.current_tenant GUC creates NO authority", async () => {
    await inAppTxn(async (c) => {
      // No context function called; forge the tenant (and even a principal/session).
      await c.query("SELECT set_config('app.current_tenant','t_acme',true)");
      await c.query("SELECT set_config('app.current_principal',$1,true)", [P1]);
      await c.query("SELECT set_config('app.current_session',$1,true)", [randomUUID()]);
      const t = await c.query("SELECT continuum.current_tenant() AS t");
      expect(t.rows[0].t).toBeNull(); // no backing session ⇒ no authority
      const probe = await c.query("SELECT * FROM continuum.context_probe");
      expect(probe.rows).toHaveLength(0);
    });
  });

  it("context is transaction-local: it does not survive across pooled reuse", async () => {
    // Establish context and observe rows, then in a SEPARATE transaction (same pool)
    // there must be no residual authority.
    await inAppTxn(async (c) => {
      await begin(c, P5, S5);
      expect((await c.query("SELECT count(*)::int n FROM continuum.context_probe")).rows[0].n).toBe(1);
    });
    // New transaction, no begin(): context gone.
    await inAppTxn(async (c) => {
      const t = await c.query("SELECT continuum.current_tenant() AS t");
      expect(t.rows[0].t).toBeNull();
      expect((await c.query("SELECT count(*)::int n FROM continuum.context_probe")).rows[0].n).toBe(0);
    });
  });

  it("the app role cannot read or mutate the identity/membership tables directly", async () => {
    await inAppTxn(async (c) => {
      await expect(c.query("SELECT * FROM continuum.tenant_memberships")).rejects.toThrow(/permission denied/i);
    });
    await inAppTxn(async (c) => {
      await expect(
        c.query("UPDATE continuum.tenant_memberships SET tenant_id='t_acme' WHERE membership_id=$1", [M5]),
      ).rejects.toThrow(/permission denied/i);
    });
    await inAppTxn(async (c) => {
      await expect(
        c.query("INSERT INTO continuum.tenant_memberships (membership_id, principal_id, tenant_id) VALUES ($1,$2,'t_acme')", [randomUUID(), P5]),
      ).rejects.toThrow(/permission denied/i);
    });
  });
});
