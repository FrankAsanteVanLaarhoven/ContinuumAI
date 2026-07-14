/**
 * The proof-of-possession verification path under test.
 *
 *   A (baseline) — verify the signature, record the verification, NEVER consume.
 *                  A replayed proof verifies again; two concurrent presentations
 *                  both succeed (GAP-4).
 *   B (bound)    — verify the signature over "<token>:<nonce>", then consume the
 *                  nonce EXACTLY ONCE via the transactional ledger. Replay and
 *                  concurrent double-spend are rejected. B does NOT bind the
 *                  request/audience/capability, so a fresh-nonce proof lifted onto a
 *                  different request/audience/capability is still accepted.
 *   C (bound+)   — B plus an explicit binding check: the proof carries the request
 *                  digest, capability id and audience it was signed for (and the
 *                  signature covers them); a mismatch against the operation actually
 *                  being authorized is rejected BEFORE consumption.
 *
 * The raw Ed25519 signature never enters evidence — only its sha256 digest.
 */
import type { Pool, PoolClient } from "pg";
import { sha256Hex, verifyEd25519 } from "@continuum/core";
import { proofMessage, type Arm, type Capability, type ProofContext } from "./harness";

export type Decision =
  | "CONSUMED"
  | "ACCEPTED_NO_LEDGER"
  | "REPLAY_REJECTED"
  | "BINDING_MISMATCH"
  | "EXPIRED"
  | "BAD_SIGNATURE"
  | "MISSING_PROOF";

export interface VerifyResult {
  accepted: boolean;
  decision: Decision;
  classification: string;
}

/** The operation actually being authorized now (what the proof must match under C). */
export interface CurrentContext {
  request_digest: string;
  capability_id: string;
  audience: string;
}

async function withClient<T>(pool: Pool, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    return await fn(c);
  } finally {
    c.release();
  }
}

async function emit(
  c: PoolClient,
  cap: Capability,
  presented: ProofContext,
  signature: string,
  decision: Decision,
  classification: string,
): Promise<void> {
  await c.query(
    `INSERT INTO i4_evidence
       (token_id, nonce, signature_digest, bound_request_digest, capability_id, audience, decision, classification)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [cap.token_id, presented.nonce, sha256Hex(signature || "∅"), presented.request_digest, presented.capability_id, presented.audience, decision, classification],
  );
}

function result(accepted: boolean, decision: Decision, classification: string): VerifyResult {
  return { accepted, decision, classification };
}

/**
 * Verify a presented proof under one arm. `presented` is the context the proof was
 * signed over (nonce + the bound values the holder attests); `current` is the
 * operation actually being authorized now.
 */
export async function verifyProof(
  pool: Pool,
  arm: Arm,
  cap: Capability,
  presented: ProofContext,
  current: CurrentContext,
  signature: string,
  nowMs: number,
  classification: string,
): Promise<VerifyResult> {
  // 0 — a proof must be presented.
  if (!signature) {
    await withClient(pool, (c) => emit(c, cap, presented, signature, "MISSING_PROOF", classification));
    return result(false, "MISSING_PROOF", classification);
  }
  // 1 — expiry (the one thing today's verifier already enforces).
  if (nowMs >= cap.expires_at_ms) {
    await withClient(pool, (c) => emit(c, cap, presented, signature, "EXPIRED", classification));
    return result(false, "EXPIRED", classification);
  }
  // 2 — signature over the arm's message. A non-holder key fails here.
  const sigOk = verifyEd25519(cap.holder_public_key_pem, proofMessage(arm, cap.token_id, presented), signature);
  if (!sigOk) {
    await withClient(pool, (c) => emit(c, cap, presented, signature, "BAD_SIGNATURE", classification));
    return result(false, "BAD_SIGNATURE", classification);
  }
  // 3 — binding (C only): the proof must be FOR the operation being authorized now.
  if (arm === "C") {
    const bound =
      presented.request_digest === current.request_digest &&
      presented.capability_id === current.capability_id &&
      presented.audience === current.audience;
    if (!bound) {
      await withClient(pool, (c) => emit(c, cap, presented, signature, "BINDING_MISMATCH", classification));
      return result(false, "BINDING_MISMATCH", classification);
    }
  }
  // 4 — consumption. A records the verification but consumes nothing (replayable).
  if (arm === "A") {
    await withClient(pool, async (c) => {
      await c.query("INSERT INTO i4_baseline_verification (token_id, nonce, context_digest) VALUES ($1,$2,$3)", [
        cap.token_id,
        presented.nonce,
        presented.request_digest,
      ]);
      await emit(c, cap, presented, signature, "ACCEPTED_NO_LEDGER", classification);
    });
    return result(true, "ACCEPTED_NO_LEDGER", classification);
  }
  // B/C — consume the nonce exactly once via the transactional ledger.
  return withClient(pool, async (c) => {
    const ins = await c.query(
      `INSERT INTO i4_consumed_proof (token_id, nonce, request_digest, capability_id, audience)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (token_id, nonce) DO NOTHING
       RETURNING token_id`,
      [cap.token_id, presented.nonce, current.request_digest, current.capability_id, current.audience],
    );
    if (ins.rows.length === 1) {
      await emit(c, cap, presented, signature, "CONSUMED", classification);
      return result(true, "CONSUMED", classification);
    }
    await emit(c, cap, presented, signature, "REPLAY_REJECTED", classification);
    return result(false, "REPLAY_REJECTED", classification);
  });
}
