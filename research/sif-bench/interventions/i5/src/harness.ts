/**
 * Pools and small helpers for the I5 arms. `appPool` connects as the ordinary,
 * unprivileged application role (i5_app); `adminPool` connects as the superuser
 * and is used only to demonstrate the documented superuser-bypass boundary.
 */
import pg from "pg";
import type { Pool as PgPool, PoolClient } from "pg";

const { Pool } = pg;

export interface DbConfig {
  host: string;
  port: number;
  database: string;
}

export function i5Config(): DbConfig {
  const raw = process.env.CONTINUUM_I5_DB;
  if (!raw) throw new Error("CONTINUUM_I5_DB is not set (global-setup did not run)");
  return JSON.parse(raw) as DbConfig;
}

export function appPool(cfg: DbConfig): PgPool {
  return new Pool({ host: cfg.host, port: cfg.port, database: cfg.database, user: "i5_app", password: "i5_app", max: 4 });
}

export function adminPool(cfg: DbConfig): PgPool {
  return new Pool({ host: cfg.host, port: cfg.port, database: cfg.database, user: "postgres", password: "postgres", max: 2 });
}

/** Count rows visible in a table under whatever tenant context the txn holds. */
export async function countVisible(c: PoolClient, table: string): Promise<number> {
  const r = await c.query(`SELECT count(*)::int AS n FROM ${table}`);
  return r.rows[0].n as number;
}

/** Set the raw tenant GUC directly — the cooperative re-key the app should not be able to weaponise. */
export async function rawRekey(c: PoolClient, tenant: string): Promise<void> {
  await c.query("SELECT set_config('app.current_tenant', $1, true)", [tenant]);
}
