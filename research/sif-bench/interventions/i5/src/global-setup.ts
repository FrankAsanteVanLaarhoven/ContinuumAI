/**
 * Boot one embedded PostgreSQL for the I5 suite on a dedicated port/data-dir,
 * apply the I5 schema as the superuser, and seed two tenants' rows plus the
 * authoritative principal→tenant mapping and session bindings. A distinct
 * port/data-dir from the persistence and concurrency suites so none collide.
 */
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import EmbeddedPostgres from "embedded-postgres";
import pg from "pg";

const { Client } = pg;
const here = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(tmpdir(), "continuum-i5test-data");
const PORT = 55447;

let embedded: EmbeddedPostgres | undefined;

export async function setup(): Promise<void> {
  rmSync(DATA_DIR, { recursive: true, force: true });
  embedded = new EmbeddedPostgres({
    databaseDir: DATA_DIR,
    user: "postgres",
    password: "postgres",
    port: PORT,
    persistent: false,
  });
  await embedded.initialise();
  await embedded.start();
  await embedded.createDatabase("continuum");

  process.env.CONTINUUM_I5_DB = JSON.stringify({ host: "127.0.0.1", port: PORT, database: "continuum" });

  const admin = new Client({ host: "127.0.0.1", port: PORT, database: "continuum", user: "postgres", password: "postgres" });
  await admin.connect();
  try {
    const schema = readFileSync(join(here, "..", "sql", "i5_schema.sql"), "utf8");
    await admin.query("BEGIN");
    await admin.query(schema);
    await admin.query("COMMIT");

    // Seed as superuser (RLS is forced, but the superuser bypasses it for setup).
    await admin.query(`
      INSERT INTO i5_baseline (tenant_id, id, payload) VALUES
        ('t_acme','a1','acme-quote-1'), ('t_acme','a2','acme-quote-2'),
        ('t_globex','g1','globex-quote-1')
      ON CONFLICT DO NOTHING;
      INSERT INTO i5_bound (tenant_id, id, payload) VALUES
        ('t_acme','a1','acme-quote-1'), ('t_acme','a2','acme-quote-2'),
        ('t_globex','g1','globex-quote-1')
      ON CONFLICT DO NOTHING;
      INSERT INTO i5_principal_tenant (principal_id, tenant_id, active) VALUES
        ('acme-principal','t_acme',true),
        ('globex-principal','t_globex',true),
        ('stale-principal','t_acme',false)
      ON CONFLICT DO NOTHING;
      INSERT INTO i5_session (session_id, principal_id, valid) VALUES
        ('acme-session','acme-principal',true),
        ('globex-session','globex-principal',true),
        ('revoked-session','acme-principal',false),
        ('stale-session','stale-principal',true)
      ON CONFLICT DO NOTHING;
    `);
  } finally {
    await admin.end();
  }
}

export async function teardown(): Promise<void> {
  if (embedded) await embedded.stop();
}
