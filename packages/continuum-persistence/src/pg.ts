/**
 * Connection helpers for the durable data plane.
 *
 * The application connects as `continuum_app` (NOSUPERUSER, SELECT/INSERT only).
 * Every tenant-scoped operation runs inside `withTenant`, which opens a
 * transaction and sets the transaction-local `app.current_tenant` that RLS keys
 * on. `withoutTenant` exists specifically to prove the fail-closed path.
 */
import pg from "pg";
import type { Pool as PgPool, PoolClient } from "pg";

const { Pool } = pg;

export interface DbConfig {
  host: string;
  port: number;
  database: string;
}

export function dbConfigFromEnv(): DbConfig {
  const raw = process.env.CONTINUUM_DB;
  if (!raw) throw new Error("CONTINUUM_DB is not set");
  return JSON.parse(raw) as DbConfig;
}

export function appPool(cfg: DbConfig): PgPool {
  return new Pool({
    host: cfg.host,
    port: cfg.port,
    database: cfg.database,
    user: "continuum_app",
    password: "continuum_app",
    max: 4,
  });
}

export function adminPool(cfg: DbConfig): PgPool {
  return new Pool({
    host: cfg.host,
    port: cfg.port,
    database: cfg.database,
    user: "postgres",
    password: "postgres",
    max: 2,
  });
}

/** Run `fn` in a transaction bound to `tenantId` via RLS. */
export async function withTenant<T>(
  pool: PgPool,
  tenantId: string,
  fn: (c: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.current_tenant', $1, true)", [
      tenantId,
    ]);
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

/** Run `fn` with NO tenant context — RLS must then expose nothing (fail-closed). */
export async function withoutTenant<T>(
  pool: PgPool,
  fn: (c: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}
