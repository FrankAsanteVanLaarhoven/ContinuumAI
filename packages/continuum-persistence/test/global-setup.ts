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
import { appPool, type DbConfig } from "../src/pg";
import { persistExport } from "../src/repository";

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
  const pool = appPool(cfg);
  try {
    await persistExport(pool, slice.engine.exportState());
  } finally {
    await pool.end();
  }
}

export async function teardown(): Promise<void> {
  if (pg) await pg.stop();
}
