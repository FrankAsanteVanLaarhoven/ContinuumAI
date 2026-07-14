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
const MIGRATIONS = ["0001_init.sql"];

export async function migrate(cfg: DbConfig): Promise<void> {
  const client = new Client({
    host: cfg.host,
    port: cfg.port,
    database: cfg.database,
    user: "postgres",
    password: "postgres",
  });
  await client.connect();
  try {
    for (const file of MIGRATIONS) {
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
