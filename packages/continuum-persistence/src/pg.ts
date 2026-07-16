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
import { randomUUID } from "node:crypto";

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

/**
 * Connection pool for the dedicated session-service role `continuum_session`
 * (S3): manages sessions and reads identity state, but has NO tenant authority
 * path (no tenant_memberships, no public.*, no begin_authenticated_context).
 */
export function sessionPool(cfg: DbConfig): PgPool {
  return new Pool({
    host: cfg.host,
    port: cfg.port,
    database: cfg.database,
    user: "continuum_session",
    password: "continuum_session",
    max: 4,
  });
}

/**
 * Set ONLY the raw `app.current_tenant` GUC — the pre-S2B application-cooperative
 * mechanism. After migration 0004 the public.* policies key on
 * `continuum.current_tenant()`, which ignores a GUC that has no backing
 * (principal, session, membership) context. This helper therefore NO LONGER
 * grants access to the tenant-scoped tables; it is retained ONLY as the adversary
 * path in tests (proving a forged tenant GUC sees/inserts nothing) and for the
 * global (non-RLS) probes. Production paths use {@link withTrustedContext}.
 */
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

// ---------------------------------------------------------------------------
// Trusted context (S2B): the ONLY production path to tenant authority on the
// public.* data plane. The tenant is DERIVED by the SECURITY DEFINER function
// continuum.begin_authenticated_context from identity/session references; it is
// never supplied by the caller. RLS then keys on continuum.current_tenant().
// ---------------------------------------------------------------------------

/** Identity/session references presented to establish trusted context. NEVER a tenant. */
export interface TrustedContextRef {
  /** continuum.principals.principal_id (uuid). */
  readonly principalId: string;
  /** continuum.authenticated_sessions.session_id (uuid). */
  readonly sessionId: string;
  /** Per-request correlation id (uuid); stamped into app.current_request. */
  readonly requestId: string;
  /** Optional membership selector; only chooses among the principal's OWN active memberships. */
  readonly membershipId?: string | null;
}

/** The context the database DERIVED — the authoritative tenant for the transaction. */
export interface EstablishedContext {
  readonly principalId: string;
  readonly tenantId: string;
  readonly membershipId: string;
}

/**
 * Open a transaction and establish trusted context through
 * continuum.begin_authenticated_context. The DB validates the principal, session
 * and membership and DERIVES the tenant; `fn` then runs under RLS keyed on that
 * derived context. If establishment is denied (unknown/suspended principal,
 * expired/foreign session, revoked/ambiguous membership, …) the function raises
 * and the transaction rolls back — fail-closed. Context is transaction-local and
 * disappears at COMMIT/ROLLBACK, so a pooled connection carries nothing forward.
 */
export async function withTrustedContext<T>(
  pool: PgPool,
  ref: TrustedContextRef,
  fn: (c: PoolClient, established: EstablishedContext) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query(
      "SELECT principal_id, tenant_id, membership_id FROM continuum.begin_authenticated_context($1,$2,$3,$4)",
      [ref.principalId, ref.sessionId, ref.requestId, ref.membershipId ?? null],
    );
    if (r.rows.length !== 1) {
      throw new Error("trusted context not established: request denied (fail-closed)");
    }
    const established: EstablishedContext = {
      principalId: r.rows[0].principal_id,
      tenantId: r.rows[0].tenant_id,
      membershipId: r.rows[0].membership_id,
    };
    const result = await fn(client, established);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

export interface ProvisionIdentityInput {
  readonly tenantId: string;
  readonly principalId?: string;
  readonly sessionId?: string;
  readonly membershipId?: string;
  readonly principalType?: string;
  readonly sessionTtlHours?: number;
}

export interface ProvisionedIdentity {
  readonly principalId: string;
  readonly sessionId: string;
  readonly membershipId: string;
  readonly tenantId: string;
  /** Build a TrustedContextRef for this identity (fresh request id unless supplied). */
  ref(requestId?: string): TrustedContextRef;
}

/**
 * Provision an identity (principal + active membership + active session) for a
 * tenant, as the ADMIN/superuser — the trusted provisioning path. The application
 * role has NO write privilege on the identity tables and cannot do this. This is
 * the deploy-time bootstrap for a service/operator identity and the test harness
 * seed; the authenticated issuance of sessions (OIDC, rotation) is a later step.
 */
export async function provisionTrustedIdentity(
  admin: PgPool,
  input: ProvisionIdentityInput,
): Promise<ProvisionedIdentity> {
  const principalId = input.principalId ?? randomUUID();
  const sessionId = input.sessionId ?? randomUUID();
  const membershipId = input.membershipId ?? randomUUID();
  const ttl = input.sessionTtlHours ?? 8;
  const c = await admin.connect();
  try {
    await c.query(
      `INSERT INTO continuum.principals (principal_id, principal_type, status)
       VALUES ($1,$2,'active') ON CONFLICT (principal_id) DO NOTHING`,
      [principalId, input.principalType ?? "service"],
    );
    await c.query(
      `INSERT INTO continuum.tenant_memberships (membership_id, principal_id, tenant_id, status)
       VALUES ($1,$2,$3,'active') ON CONFLICT (membership_id) DO NOTHING`,
      [membershipId, principalId, input.tenantId],
    );
    await c.query(
      `INSERT INTO continuum.authenticated_sessions
         (session_id, principal_id, credential_digest, idle_expires_at, absolute_expires_at, identity_version)
       VALUES ($1,$2,'provisioned', now() + ($3||' hour')::interval, now() + ($3||' hour')::interval, 1)
       ON CONFLICT (session_id) DO NOTHING`,
      [sessionId, principalId, String(ttl)],
    );
  } finally {
    c.release();
  }
  return {
    principalId,
    sessionId,
    membershipId,
    tenantId: input.tenantId,
    ref(requestId?: string): TrustedContextRef {
      return { principalId, sessionId, membershipId, requestId: requestId ?? randomUUID() };
    },
  };
}
