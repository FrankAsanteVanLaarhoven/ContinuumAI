/**
 * PostgreSQL-backed S4B authorization-transaction store + evidence sink, run as
 * the least-privilege `continuum_session` role (no tenant authority path).
 *
 * Transactions are created by INSERT; consumption/finalization/expiry go ONLY
 * through the narrow SECURITY-DEFINER functions (the session role has no direct
 * UPDATE/DELETE), so consumption is atomic and one-time and bindings stay
 * immutable. Consumption fails closed to `store_unavailable` on any error.
 */
import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type {
  AuthorizationEvent,
  AuthorizationEventSink,
  AuthorizationTransactionStore,
  ConsumeAuthorizationTransactionInput,
  ConsumeAuthorizationTransactionResult,
  CreatedAuthorizationTransaction,
  FinalizeAuthorizationTransactionInput,
  NewAuthorizationTransaction,
} from "@continuum/core";

export class PostgresAuthorizationTransactionStore implements AuthorizationTransactionStore {
  constructor(private readonly pool: Pool) {}

  async create(t: NewAuthorizationTransaction): Promise<CreatedAuthorizationTransaction> {
    await this.pool.query(
      `INSERT INTO continuum.authorization_transactions
         (transaction_id, state_digest, nonce_digest, pkce_verifier_secret, pkce_verifier_key_version,
          pkce_challenge, pkce_method, issuer, client_id, redirect_uri, created_at, expires_at, policy_version)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        t.transactionId, t.stateDigest, t.nonceDigest, t.pkceVerifierSecret, t.pkceVerifierKeyVersion,
        t.pkceChallenge, t.pkceMethod, t.issuer, t.clientId, t.redirectUri, t.createdAt, t.expiresAt, t.policyVersion,
      ],
    );
    return { transactionId: t.transactionId, expiresAt: t.expiresAt };
  }

  async consume(input: ConsumeAuthorizationTransactionInput): Promise<ConsumeAuthorizationTransactionResult> {
    try {
      const res = await this.pool.query(
        `SELECT outcome, transaction_id, issuer, client_id, redirect_uri, nonce_digest,
                pkce_verifier_secret, pkce_verifier_key_version, pkce_challenge, policy_version
           FROM continuum.consume_authorization_transaction($1,$2,$3)`,
        [input.stateDigest, input.requestId, input.now],
      );
      const row = res.rows[0];
      if (!row) return { outcome: "store_unavailable" };
      if (row.outcome === "consumed") {
        return {
          outcome: "consumed",
          transaction: {
            transactionId: row.transaction_id, issuer: row.issuer, clientId: row.client_id,
            redirectUri: row.redirect_uri, nonceDigest: row.nonce_digest,
            pkceVerifierSecret: row.pkce_verifier_secret, pkceVerifierKeyVersion: row.pkce_verifier_key_version,
            pkceChallenge: row.pkce_challenge, policyVersion: row.policy_version,
          },
        };
      }
      if (row.outcome === "unknown" || row.outcome === "already_consumed" || row.outcome === "expired") {
        return { outcome: row.outcome };
      }
      return { outcome: "store_unavailable" };
    } catch {
      return { outcome: "store_unavailable" };
    }
  }

  async finalize(input: FinalizeAuthorizationTransactionInput): Promise<void> {
    await this.pool.query(`SELECT continuum.finalize_authorization_transaction($1,$2,$3,$4)`, [
      input.transactionId, input.status, input.failureReason, input.requestId,
    ]);
  }

  async expireBefore(now: Date): Promise<number> {
    const res = await this.pool.query(`SELECT continuum.expire_authorization_transactions($1) AS n`, [now]);
    const n = res.rows[0]?.n;
    return typeof n === "string" ? Number(n) : Number(n ?? 0);
  }
}

export class PostgresAuthorizationEventSink implements AuthorizationEventSink {
  constructor(private readonly pool: Pool) {}
  async append(e: AuthorizationEvent): Promise<void> {
    await this.pool.query(
      `INSERT INTO continuum.auth_events
         (event_id, event_type, at, request_id, issuer_digest, subject_digest, principal_id, session_id,
          verification_policy_version, identity_mapping_version, outcome, reason, transaction_digest)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        randomUUID(), e.type, e.at, e.requestId, e.issuerDigest, e.subjectDigest, e.principalId, e.sessionId,
        e.policyVersion, null, e.outcome, e.reason, e.transactionDigest,
      ],
    );
  }
}
