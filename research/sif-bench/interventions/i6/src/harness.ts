/**
 * Pools, the canonical request digest, and per-case reset for the I6 arms.
 *
 * The request digest reuses the control plane's deterministic canonicalisation
 * (@continuum/core `canonicalJson`) so the SAME logical request always yields the
 * SAME digest and a materially different request yields a different one. The raw
 * idempotency key never enters evidence — only a keyed digest.
 */
import pg from "pg";
import type { Pool as PgPool, PoolClient } from "pg";
import { canonicalJson, sha256Hex } from "@continuum/core";

const { Pool } = pg;

export interface DbConfig {
  host: string;
  port: number;
  database: string;
}

export const DIGEST_ALG = "sha256/continuum-canonical-v1";
export const KEY_DIGEST_VERSION = "kd1"; // versioned so the construction can migrate
// Demonstration secret. Production holds this in a KMS / secret store with rotation;
// it keys ONLY the evidence-correlation digest, never the replay lookup (which uses
// the raw idempotency_key column in i6_action), so rotation cannot break replay.
const EVIDENCE_KEY_SECRET = ":i6-evidence-key-secret-2026";

export function i6Config(): DbConfig {
  const raw = process.env.CONTINUUM_I6_DB;
  if (!raw) throw new Error("CONTINUUM_I6_DB is not set (global-setup did not run)");
  return JSON.parse(raw) as DbConfig;
}

export function appPool(cfg: DbConfig): PgPool {
  return new Pool({ host: cfg.host, port: cfg.port, database: cfg.database, user: "i6_app", password: "i6_app", max: 6 });
}

export function adminPool(cfg: DbConfig): PgPool {
  return new Pool({ host: cfg.host, port: cfg.port, database: cfg.database, user: "postgres", password: "postgres", max: 2 });
}

/** The security-relevant, normalized request whose digest binds an idempotency key. */
export interface ActionRequest {
  tenant: string;
  principal: string;
  intent: string;
  operation: string;
  resource: string;
  arguments: Record<string, unknown>;
  purpose: string;
  capability: string;
  policy_version: string;
  approval_requirement: string;
}

/** Stable canonical digest of the request (deterministic key order, no volatile fields). */
export function canonicalRequestDigest(req: ActionRequest): string {
  return sha256Hex(canonicalJson(req));
}

/**
 * Keyed digest of the idempotency key for evidence CORRELATION without exposing the
 * raw value. Tenant-scoped so the SAME raw key yields UNLINKABLE digests across
 * tenants. Distinct in purpose from the request digest: this identifies repeated use
 * of the same client key; the request digest decides whether the repeat is
 * semantically identical. The two are never merged into one field.
 */
export function keyDigest(tenant: string, idempotencyKey: string): string {
  return KEY_DIGEST_VERSION + ":" + sha256Hex(tenant + "\x1f" + idempotencyKey + EVIDENCE_KEY_SECRET);
}

/** Reset both schemes to a clean slate before a case (as superuser). */
export async function resetAll(admin: PgPool): Promise<void> {
  const c = await admin.connect();
  try {
    await c.query("TRUNCATE i6_baseline_action, i6_baseline_execution, i6_action, i6_execution, i6_evidence RESTART IDENTITY");
  } finally {
    c.release();
  }
}

export async function count(c: PoolClient, table: string, where = "", params: unknown[] = []): Promise<number> {
  const r = await c.query(`SELECT count(*)::int n FROM ${table} ${where}`, params);
  return r.rows[0].n as number;
}
