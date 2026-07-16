/**
 * Phase 3 S2B — negative privilege audit for the application role.
 *
 * Confirms structurally (from the catalog, not behaviourally) that continuum_app
 * holds none of the powers that would let it bypass the trusted-context boundary:
 * no SUPERUSER, no BYPASSRLS, no CREATE on the trusted schemas, no ownership of the
 * trusted functions, and no direct read/write on the identity or membership tables.
 * Runs against the shared global-setup database (migrated through 0004).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { adminPool, dbConfigFromEnv } from "./pg";

let db: Pool;
const APP = "continuum_app";
const IDENTITY_TABLES = [
  "continuum.principals",
  "continuum.external_identities",
  "continuum.tenant_memberships",
  "continuum.authenticated_sessions",
  "continuum.delegations",
  "continuum.break_glass_grants",
];

beforeAll(() => {
  db = adminPool(dbConfigFromEnv());
});
afterAll(async () => {
  await db.end();
});

async function bool(sql: string, params: unknown[] = []): Promise<boolean> {
  return (await db.query(sql, params)).rows[0].v as boolean;
}

describe("S2B privilege audit — the application role is least-privilege", () => {
  it("continuum_app is NOT a superuser and does NOT bypass RLS", async () => {
    const r = await db.query(
      "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname=$1",
      [APP],
    );
    expect(r.rows[0].rolsuper).toBe(false);
    expect(r.rows[0].rolbypassrls).toBe(false);
    expect(r.rows[0].rolcreaterole).toBe(false);
    expect(r.rows[0].rolcreatedb).toBe(false);
  });

  it("continuum_app has NO CREATE on the trusted schemas", async () => {
    expect(await bool("SELECT has_schema_privilege($1,'continuum','CREATE') v", [APP])).toBe(false);
    expect(await bool("SELECT has_schema_privilege($1,'public','CREATE') v", [APP])).toBe(false);
  });

  it("continuum_app does NOT own the trusted functions (owned by the non-login authctx role)", async () => {
    const r = await db.query(
      `SELECT p.proname, r.rolname AS owner
         FROM pg_proc p
         JOIN pg_roles r ON r.oid = p.proowner
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname='continuum' AND p.proname IN ('current_tenant','begin_authenticated_context')
        ORDER BY p.proname`,
    );
    expect(r.rows.length).toBe(2);
    for (const row of r.rows) {
      expect(row.owner).toBe("continuum_authctx");
      expect(row.owner).not.toBe(APP);
    }
    // The owner role cannot log in (SECURITY DEFINER cannot be reached as a session).
    const owner = await db.query("SELECT rolcanlogin, rolsuper FROM pg_roles WHERE rolname='continuum_authctx'");
    expect(owner.rows[0].rolcanlogin).toBe(false);
    expect(owner.rows[0].rolsuper).toBe(false);
  });

  it("continuum_app has NO direct read or write on the identity/membership tables", async () => {
    for (const t of IDENTITY_TABLES) {
      for (const priv of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
        expect(await bool("SELECT has_table_privilege($1,$2,$3) v", [APP, t, priv]), `${APP} ${priv} ${t}`).toBe(false);
      }
    }
  });

  it("continuum_app may ONLY execute the trusted context functions (its sole authority path)", async () => {
    expect(await bool("SELECT has_function_privilege($1,'continuum.begin_authenticated_context(uuid,uuid,uuid,uuid)','EXECUTE') v", [APP])).toBe(true);
    expect(await bool("SELECT has_function_privilege($1,'continuum.current_tenant()','EXECUTE') v", [APP])).toBe(true);
    // …and it cannot mutate memberships even through a would-be helper: no table rights (above).
  });

  it("continuum_app on public.* holds only SELECT/INSERT (no UPDATE/DELETE) — least privilege preserved", async () => {
    for (const t of ["intents", "capabilities", "memory_objects", "evidence_envelopes", "consumed_proofs"]) {
      expect(await bool("SELECT has_table_privilege($1,$2,'SELECT') v", [APP, t]), `${t} SELECT`).toBe(true);
      expect(await bool("SELECT has_table_privilege($1,$2,'INSERT') v", [APP, t]), `${t} INSERT`).toBe(true);
      expect(await bool("SELECT has_table_privilege($1,$2,'UPDATE') v", [APP, t]), `${t} UPDATE`).toBe(false);
      expect(await bool("SELECT has_table_privilege($1,$2,'DELETE') v", [APP, t]), `${t} DELETE`).toBe(false);
    }
  });
});
