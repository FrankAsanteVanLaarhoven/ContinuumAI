/**
 * The two create paths under test.
 *
 *   baselineCreate — caller-chosen action_id; INSERT ... ON CONFLICT DO UPDATE
 *                    (silent overwrite) and execute every time (GAP-6).
 *   boundCreate    — server-issued action_id; requires an idempotency key; binds a
 *                    canonical request digest; UNIQUE(tenant,principal,operation,key)
 *                    with INSERT ... ON CONFLICT DO NOTHING + read (NEVER DO UPDATE);
 *                    execution gated on winning the insert and idempotent.
 */
import type { Pool, PoolClient } from "pg";
import { canonicalRequestDigest, keyDigest, type ActionRequest } from "./harness";

export type Decision = "CREATED" | "REPLAYED" | "IDEMPOTENCY_CONFLICT" | "IDEMPOTENCY_REQUIRED";
export type BoundMode = "B" | "C";

export interface CreateResult {
  action_id: string | null;
  decision: Decision;
  executed: boolean;
  digest: string;
  original_action_id: string | null;
  digest_match: boolean | null;
  classification: string;
}

async function emit(
  c: PoolClient,
  req: ActionRequest,
  idemKey: string,
  digest: string,
  actionId: string | null,
  originalActionId: string | null,
  decision: string,
  state: string | null,
  classification: string,
): Promise<void> {
  await c.query(
    `INSERT INTO i6_evidence
       (tenant_id, principal_id, intent_id, operation, idempotency_key_digest, request_digest,
        action_id, original_action_id, decision, state, policy_version, capability_id, classification)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [req.tenant, req.principal, req.intent, req.operation, keyDigest(idemKey), digest,
     actionId, originalActionId, decision, state, req.policy_version, req.capability, classification],
  );
}

/** BASELINE (I6-A): caller supplies the id; a create silently overwrites and always executes. */
export async function baselineCreate(pool: Pool, req: ActionRequest, callerActionId: string): Promise<CreateResult> {
  const digest = canonicalRequestDigest(req);
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query(
      `INSERT INTO i6_baseline_action (action_id, tenant_id, principal_id, operation, request_digest, state)
       VALUES ($1,$2,$3,$4,$5,'CREATED')
       ON CONFLICT (action_id) DO UPDATE SET request_digest = EXCLUDED.request_digest, operation = EXCLUDED.operation, updated_at = now()`,
      [callerActionId, req.tenant, req.principal, req.operation, digest],
    );
    await c.query("INSERT INTO i6_baseline_execution (action_id) VALUES ($1)", [callerActionId]);
    await c.query("COMMIT");
    return { action_id: callerActionId, decision: "CREATED", executed: true, digest, original_action_id: null, digest_match: null, classification: "baseline_create_or_overwrite" };
  } catch (e) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw e;
  } finally {
    c.release();
  }
}

/** Run `fn` on a pooled client that is ALWAYS released (no connection leaks). */
async function withClient<T>(pool: Pool, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    return await fn(c);
  } finally {
    c.release();
  }
}

const EVIDENCE_FAIL = Symbol("evidence-append-failure");

/**
 * BOUND (I6-B/C). `failEvidence` simulates an evidence-append failure AFTER the
 * action create attempt so the caller can assert create+evidence atomicity.
 */
export async function boundCreate(
  pool: Pool,
  req: ActionRequest,
  idemKey: string | null,
  mode: BoundMode,
  opts: { failEvidence?: boolean } = {},
): Promise<CreateResult> {
  const digest = canonicalRequestDigest(req);

  // Missing key on a consequential action → deny before any write.
  if (idemKey === null || idemKey === "") {
    await withClient(pool, async (c) => {
      await c.query("BEGIN");
      await emit(c, req, "", digest, null, null, "IDEMPOTENCY_REQUIRED", null, "missing_key");
      await c.query("COMMIT");
    });
    return { action_id: null, decision: "IDEMPOTENCY_REQUIRED", executed: false, digest, original_action_id: null, digest_match: null, classification: "missing_key" };
  }

  // Phase 1 — attempt the authoritative create in one transaction (own connection).
  const attempt = await withClient(pool, async (c): Promise<{ won: true; actionId: string; executed: boolean } | { won: false }> => {
    await c.query("BEGIN");
    try {
      const ins = await c.query(
        `INSERT INTO i6_action (tenant_id, principal_id, intent_id, operation, idempotency_key, request_digest, state, policy_version, capability_id)
         VALUES ($1,$2,$3,$4,$5,$6,'CREATED',$7,$8)
         ON CONFLICT (tenant_id, principal_id, operation, idempotency_key) DO NOTHING
         RETURNING action_id`,
        [req.tenant, req.principal, req.intent, req.operation, idemKey, digest, req.policy_version, req.capability],
      );
      if (ins.rows.length === 1) {
        const actionId = ins.rows[0].action_id as string;
        const execIns = await c.query("INSERT INTO i6_execution (action_id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING action_id", [actionId]);
        const executed = execIns.rows.length === 1;
        await c.query("UPDATE i6_action SET state='EXECUTED', outcome='ok', terminal_at=now(), updated_at=now() WHERE action_id=$1", [actionId]);
        if (opts.failEvidence) throw EVIDENCE_FAIL; // roll the whole create back → no orphan
        await emit(c, req, idemKey, digest, actionId, null, "CREATED", "EXECUTED", "create");
        await c.query("COMMIT");
        return { won: true, actionId, executed };
      }
      await c.query("COMMIT"); // release the empty-insert txn before reading committed state
      return { won: false };
    } catch (e) {
      await c.query("ROLLBACK").catch(() => undefined);
      throw e;
    }
  }).catch((e) => {
    if (e === EVIDENCE_FAIL) return { won: false as const, rolledBack: true as const };
    throw e;
  });

  if ("rolledBack" in attempt) {
    return { action_id: null, decision: "IDEMPOTENCY_REQUIRED", executed: false, digest, original_action_id: null, digest_match: null, classification: "rolled_back_evidence_failure" };
  }
  if (attempt.won) {
    return { action_id: attempt.actionId, decision: "CREATED", executed: attempt.executed, digest, original_action_id: null, digest_match: null, classification: "create" };
  }

  // Phase 2 — conflict on the domain: read the authoritative record (bounded retry
  // for the concurrent case where the winner has not yet committed — no sleep).
  const row = await withClient(pool, async (c) => {
    let r: { action_id: string; request_digest: string; state: string } | undefined;
    for (let i = 0; i < 500 && !r; i++) {
      const ex = await c.query(
        `SELECT action_id, request_digest, state FROM i6_action
         WHERE tenant_id=$1 AND principal_id=$2 AND operation=$3 AND idempotency_key=$4`,
        [req.tenant, req.principal, req.operation, idemKey],
      );
      r = ex.rows[0];
    }
    return r;
  });
  if (!row) throw new Error("i6: idempotency conflict but no authoritative record found");

  const match = row.request_digest === digest;
  if (mode === "C" && !match) {
    await withClient(pool, async (c) => {
      await c.query("BEGIN");
      await emit(c, req, idemKey, digest, row.action_id, row.action_id, "IDEMPOTENCY_CONFLICT", row.state, "conflict");
      await c.query("COMMIT");
    });
    return { action_id: row.action_id, decision: "IDEMPOTENCY_CONFLICT", executed: false, digest, original_action_id: row.action_id, digest_match: false, classification: "conflict" };
  }
  // Same-request replay (B and C). B lands here on a digest mismatch it does not
  // detect — recorded honestly as replay_undetected_conflict.
  const classification = match ? "replay" : "replay_undetected_conflict";
  await withClient(pool, async (c) => {
    await c.query("BEGIN");
    await emit(c, req, idemKey, digest, row.action_id, row.action_id, "REPLAYED", row.state, classification);
    await c.query("COMMIT");
  });
  return { action_id: row.action_id, decision: "REPLAYED", executed: false, digest, original_action_id: row.action_id, digest_match: match, classification };
}
