/**
 * Boot one embedded PostgreSQL for the I4 suite on a dedicated port/data-dir and
 * apply the I4 schema as the superuser. Distinct port from the persistence,
 * concurrency, I5 and I6 suites so none collide.
 */
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import EmbeddedPostgres from "embedded-postgres";
import pg from "pg";

const { Client } = pg;
const here = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(tmpdir(), "continuum-i4test-data");
const PORT = 55449;

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

  process.env.CONTINUUM_I4_DB = JSON.stringify({ host: "127.0.0.1", port: PORT, database: "continuum" });

  const admin = new Client({ host: "127.0.0.1", port: PORT, database: "continuum", user: "postgres", password: "postgres" });
  await admin.connect();
  try {
    const schema = readFileSync(join(here, "..", "sql", "i4_schema.sql"), "utf8");
    await admin.query("BEGIN");
    await admin.query(schema);
    await admin.query("COMMIT");
  } finally {
    await admin.end();
  }
}

export async function teardown(): Promise<void> {
  if (embedded) await embedded.stop();
}
