/**
 * PostgreSQL-backed durable replay ledger (S4A), run as the least-privilege
 * `continuum_session` role (no tenant authority path). Consumption is atomic and
 * insert-first: `ON CONFLICT DO NOTHING` on the (issuer, replay_kind, digest)
 * uniqueness constraint decides the winner, so a read-then-insert race cannot
 * admit a replay. Stores only keyed digests — never a raw nonce or jti. Fails
 * closed: any store error yields `unavailable`, and the verifier denies.
 */
import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type {
  DurableReplayLedger,
  ReplayConsumeInput,
  ReplayConsumeOutcome,
} from "@continuum/core";

export class PostgresReplayLedger implements DurableReplayLedger {
  constructor(private readonly pool: Pool) {}

  async consume(input: ReplayConsumeInput): Promise<ReplayConsumeOutcome> {
    try {
      const res = await this.pool.query(
        `INSERT INTO continuum.replay_ledger (replay_id, issuer, replay_kind, digest, expires_at, request_id)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT ON CONSTRAINT replay_ledger_unique DO NOTHING`,
        [randomUUID(), input.issuer, input.kind, input.digest, input.expiresAt, input.requestId],
      );
      return res.rowCount === 1 ? "fresh" : "replayed";
    } catch {
      return "unavailable"; // fail closed
    }
  }

  async prune(now: Date): Promise<number> {
    try {
      const res = await this.pool.query(`SELECT continuum.prune_replay_ledger($1) AS removed`, [now]);
      const removed = res.rows[0]?.removed;
      return typeof removed === "string" ? Number(removed) : Number(removed ?? 0);
    } catch {
      return 0;
    }
  }
}
