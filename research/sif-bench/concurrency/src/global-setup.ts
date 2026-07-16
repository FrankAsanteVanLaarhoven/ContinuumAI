/**
 * Boot one embedded PostgreSQL for the concurrency suite, migrate it, and
 * persist a deterministic slice so the C3/C4 durable-race runners have real
 * tenant-scoped rows to contend over. A distinct port/data-dir from the
 * persistence suite so the two never collide.
 */
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import EmbeddedPostgres from "embedded-postgres";
import { runVerticalSlice } from "@continuum/core";
import { migrate, appPool, adminPool, persistExport, provisionForExport, type DbConfig } from "@continuum/persistence";

const DATA_DIR = join(tmpdir(), "continuum-conctest-data");
const PORT = 55446;
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

  // Pin the schema to the PRE-S2B RLS (through 0003): this suite is the FROZEN
  // concurrency before-picture that reproduces GAP-5 (the app-cooperative
  // app.current_tenant re-key in C3-06). S2B's 0004 trusted-context rewire must
  // NOT change what this baseline measures, so 0004 is deliberately not applied
  // here. Seeding still goes through a trusted (provisioned) context, which sets
  // app.current_tenant and is therefore admitted by the pre-0004 policy.
  await migrate(cfg, "0003_identity.sql");

  const slice = runVerticalSlice(SLICE_TIME);
  const exp = slice.engine.exportState();
  const admin = adminPool(cfg);
  const pool = appPool(cfg);
  try {
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
