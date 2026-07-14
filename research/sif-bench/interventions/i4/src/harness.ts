/**
 * Pools, the proof-of-possession message construction, and per-case reset for the
 * I4 arms.
 *
 * The PoP message reuses the control plane's Ed25519 primitives (@continuum/core).
 * The distinction across arms lives entirely in WHAT is signed:
 *
 *   A, B  →  "<token_id>:<nonce>"                              (no request/audience/cap binding)
 *   C     →  "<token_id>:<nonce>:<req_digest>:<cap_id>:<aud>"  (bound)
 *
 * so under C a signature is only valid for the exact request/capability/audience
 * the holder signed. The raw signature never enters evidence — only its digest.
 */
import pg from "pg";
import type { Pool as PgPool, PoolClient } from "pg";
import { canonicalJson, sha256Hex } from "@continuum/core";

const { Pool } = pg;

export type Arm = "A" | "B" | "C";

export interface DbConfig {
  host: string;
  port: number;
  database: string;
}

export function i4Config(): DbConfig {
  const raw = process.env.CONTINUUM_I4_DB;
  if (!raw) throw new Error("CONTINUUM_I4_DB is not set (global-setup did not run)");
  return JSON.parse(raw) as DbConfig;
}

export function appPool(cfg: DbConfig): PgPool {
  return new Pool({ host: cfg.host, port: cfg.port, database: cfg.database, user: "i4_app", password: "i4_app", max: 6 });
}

export function adminPool(cfg: DbConfig): PgPool {
  return new Pool({ host: cfg.host, port: cfg.port, database: cfg.database, user: "postgres", password: "postgres", max: 2 });
}

/** The capability whose holder key must be proven. Held in TS (like I6 requests). */
export interface Capability {
  token_id: string;
  tenant: string;
  holder_public_key_pem: string;
  audience: string;        // the audience the token is valid against
  capability_id: string;
  expires_at_ms: number;
}

/** The context a proof is (A/B) or is asserted to be (C) presented against. */
export interface ProofContext {
  nonce: string;
  request_digest: string;  // digest of the request being authorized now
  capability_id: string;
  audience: string;
}

/** Stable digest of the presented context, for baseline evidence only. */
export function contextDigest(ctx: ProofContext): string {
  return sha256Hex(canonicalJson({ n: ctx.nonce, r: ctx.request_digest, c: ctx.capability_id, a: ctx.audience }));
}

/** Digest of a request payload → the request_digest carried in a ProofContext. */
export function requestDigest(req: Record<string, unknown>): string {
  return sha256Hex(canonicalJson(req));
}

/**
 * The exact message a holder signs. A and B bind only token + nonce; C additionally
 * binds the request digest, capability id, and audience, so a proof cannot be lifted
 * onto a different request/audience/capability.
 */
export function proofMessage(arm: Arm, tokenId: string, ctx: ProofContext): string {
  if (arm === "C") {
    return `${tokenId}:${ctx.nonce}:${ctx.request_digest}:${ctx.capability_id}:${ctx.audience}`;
  }
  return `${tokenId}:${ctx.nonce}`;
}

/** Reset all I4 tables to a clean slate before an arm (as superuser). */
export async function resetAll(admin: PgPool): Promise<void> {
  const c = await admin.connect();
  try {
    await c.query("TRUNCATE i4_baseline_verification, i4_consumed_proof, i4_evidence RESTART IDENTITY");
  } finally {
    c.release();
  }
}

export async function count(c: PoolClient, table: string, where = "", params: unknown[] = []): Promise<number> {
  const r = await c.query(`SELECT count(*)::int n FROM ${table} ${where}`, params);
  return r.rows[0].n as number;
}
