/**
 * Vitest global setup: boot one embedded PostgreSQL, migrate it, and persist a
 * single deterministic vertical-slice run. Test files read that durable state —
 * they connect over TCP, so they see the database rather than any in-process
 * engine memory. Teardown stops the cluster.
 */
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import EmbeddedPostgres from "embedded-postgres";
import { runVerticalSlice } from "@continuum/core";
import { migrate } from "../src/migrate";
import { appPool, adminPool, type DbConfig } from "../src/pg";
import { persistExport } from "../src/repository";
import { provisionForExport } from "./identity";

const DATA_DIR = join(tmpdir(), "continuum-pgtest-data");
const PORT = 55444;
const SLICE_TIME = Date.parse("2026-07-14T12:00:00.000Z");

let pg: EmbeddedPostgres | undefined;

export async function setup(): Promise<void> {
  rmSync(DATA_DIR, { recursive: true, force: true });
  pg = new EmbeddedPostgres({
    databaseDir: DATA_DIR,
    user: "postgres",
    password: "postgres",
    port: PORT,
    persistent: false,
  });
  await pg.initialise();
  await pg.start();
  await pg.createDatabase("continuum");

  const cfg: DbConfig = { host: "127.0.0.1", port: PORT, database: "continuum" };
  process.env.CONTINUUM_DB = JSON.stringify(cfg);

  await migrate(cfg);

  const slice = runVerticalSlice(SLICE_TIME);
  const exp = slice.engine.exportState();
  const admin = adminPool(cfg);
  const pool = appPool(cfg);
  try {
    // Provision the trusted service identities (admin path) THEN seed under
    // trusted context so the S2B RLS (continuum.current_tenant()) admits the writes.
    const resolveRef = await provisionForExport(admin, exp);
    await persistExport(pool, exp, resolveRef);
  } finally {
    await pool.end();
    await admin.end();
  }
}

export async function teardown(): Promise<void> {
  if (pg) await pg.stop();
}
