/**
 * Migration runner. Applies the SQL migrations as the superuser on a dedicated
 * connection (RLS/grants are created here; the app never runs DDL). Each file
 * runs inside one explicit, atomic transaction so grants issued after a DO
 * block become visible to later sessions. Reproducible from an empty database.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import type { DbConfig } from "./pg";

const { Client } = pg;
const here = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS = [
  "0001_init.sql",
  "0002_runtime.sql",
  "0003_identity.sql",
  "0004_public_trusted_context.sql",
  "0005_session_identity.sql",
];

/**
 * Apply the migrations in order. `through` pins the schema to a specific version
 * (inclusive) — used by frozen research harnesses to hold the exact schema they
 * were measured against (e.g. the concurrency baseline pins to the pre-S2B RLS).
 * Default: apply everything.
 */
export async function migrate(cfg: DbConfig, through?: string): Promise<void> {
  const idx = through ? MIGRATIONS.indexOf(through) : MIGRATIONS.length - 1;
  if (through && idx < 0) throw new Error(`unknown migration '${through}'`);
  const selected = MIGRATIONS.slice(0, idx + 1);
  const client = new Client({
    host: cfg.host,
    port: cfg.port,
    database: cfg.database,
    user: "postgres",
    password: "postgres",
  });
  await client.connect();
  try {
    for (const file of selected) {
      const sql = readFileSync(join(here, "..", "migrations", file), "utf8");
      try {
        await client.query("BEGIN");
        await client.query(sql);
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw err;
      }
    }
  } finally {
    await client.end();
  }
}
