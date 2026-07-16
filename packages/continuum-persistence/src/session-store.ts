/**
 * PostgreSQL-backed S3 identity/session layer, run as the dedicated
 * `continuum_session` role (no tenant authority path). Implements the core
 * SessionManager, PrincipalMapper and AuthEventSink contracts over the identity
 * schema (0003) + session/identity additions (0005).
 *
 * Sessions store only a KEYED digest of the opaque credential (never the raw
 * value). Rotation is atomic (create replacement + revoke old + evidence, one
 * transaction). The session layer returns internal identity state — never a
 * tenant; tenant authority remains the S2B trusted-context path.
 */
import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import {
  computeDigest,
  decodeCredential,
  encodeCredential,
  newSessionSecret,
  verifyDigest,
  identityDigests,
  type AuthEvent,
  type AuthEventSink,
  type AuthenticationStrength,
  type CreatedSession,
  type PrincipalMapper,
  type PrincipalMappingResult,
  type PrincipalReference,
  type SessionCredential,
  type SessionCreationInput,
  type SessionDigestKeys,
  type SessionManager,
  type SessionRevocationReason,
  type SessionRevocationResult,
  type SessionRotationReason,
  type SessionValidationInput,
  type SessionValidationResult,
  type VerifiedIdentity,
} from "@continuum/core";

const STRENGTH_RANK: Record<AuthenticationStrength, number> = {
  none: 0,
  single_factor: 1,
  multi_factor: 2,
  attested_workload: 2,
};

interface QueryRunner {
  query(text: string, params?: unknown[]): Promise<{ rows: any[]; rowCount: number | null }>;
}

/** Append one redacted auth event. Usable on a pool or an in-transaction client. */
async function insertAuthEvent(q: QueryRunner, e: AuthEvent): Promise<void> {
  await q.query(
    `INSERT INTO continuum.auth_events
       (event_id, event_type, at, request_id, issuer_digest, subject_digest, principal_id, session_id,
        verification_policy_version, identity_mapping_version, outcome, reason)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [
      randomUUID(), e.type, e.at, e.requestId, e.issuerDigest, e.subjectDigest, e.principalId, e.sessionId,
      e.verificationPolicyVersion, e.identityMappingVersion, e.outcome, e.reason,
    ],
  );
}

export class PostgresAuthEventSink implements AuthEventSink {
  constructor(private readonly pool: Pool) {}
  append(event: AuthEvent): Promise<void> {
    return insertAuthEvent(this.pool, event);
  }
}

// ---------------------------------------------------------------------------
// Principal mapper: (issuer, subject) → active internal principal. Deny by default.
// ---------------------------------------------------------------------------

export interface PrincipalMapperOptions {
  /** Deny any mapping whose version is below this (a policy revocation of old mappings). */
  readonly minimumMappingVersion?: number;
}

export class PostgresPrincipalMapper implements PrincipalMapper {
  constructor(private readonly pool: Pool, private readonly opts: PrincipalMapperOptions = {}) {}

  async resolve(identity: VerifiedIdentity): Promise<PrincipalMappingResult> {
    let rows: any[];
    try {
      rows = (
        await this.pool.query(
          `SELECT ei.status AS mapping_status, ei.mapping_version, ei.revoked_at AS mapping_revoked_at, ei.disabled_at,
                  p.status AS principal_status, p.suspended_at, p.deleted_at, p.version AS principal_version,
                  ei.principal_id
             FROM continuum.external_identities ei
             JOIN continuum.principals p ON p.principal_id = ei.principal_id
            WHERE ei.issuer = $1 AND ei.subject = $2`,
          [identity.issuer, identity.subject],
        )
      ).rows;
    } catch {
      return { mapped: false, reason: "mapping_store_unavailable" };
    }
    if (rows.length === 0) return { mapped: false, reason: "no_mapping" };
    if (rows.length > 1) return { mapped: false, reason: "ambiguous_mapping" };
    const r = rows[0];
    if (r.mapping_status === "revoked" || r.mapping_revoked_at) return { mapped: false, reason: "external_identity_revoked" };
    if (r.mapping_status === "disabled" || r.disabled_at) return { mapped: false, reason: "mapping_disabled" };
    if (this.opts.minimumMappingVersion !== undefined && Number(r.mapping_version) < this.opts.minimumMappingVersion) {
      return { mapped: false, reason: "mapping_version_stale" };
    }
    if (r.principal_status === "deleted" || r.deleted_at) return { mapped: false, reason: "principal_deleted" };
    if (r.principal_status === "suspended" || r.suspended_at) return { mapped: false, reason: "principal_suspended" };
    if (r.principal_status !== "active") return { mapped: false, reason: "principal_suspended" };
    return {
      mapped: true,
      principal: { principalId: r.principal_id, version: Number(r.principal_version) },
      mappingVersion: String(r.mapping_version),
    };
  }
}

// ---------------------------------------------------------------------------
// Session manager
// ---------------------------------------------------------------------------

export interface PostgresSessionManagerOptions {
  readonly digestKeys: SessionDigestKeys;
  /** Idle TTL applied when rotating (absolute expiry is preserved from the old session). */
  readonly rotationIdleTtlSeconds: number;
}

const SESSION_SELECT = `
  SELECT s.session_id, s.principal_id, s.credential_digest, s.credential_digest_version,
         s.identity_mapping_version, s.verification_policy_version, s.issued_at, s.idle_expires_at,
         s.absolute_expires_at, s.revoked_at, s.revocation_reason, s.authentication_strength, s.identity_version,
         p.status AS p_status, p.suspended_at, p.deleted_at, p.version AS p_version,
         (SELECT max(ei.mapping_version) FROM continuum.external_identities ei
            WHERE ei.principal_id = s.principal_id AND ei.status = 'active') AS current_mapping_version
    FROM continuum.authenticated_sessions s
    JOIN continuum.principals p ON p.principal_id = s.principal_id
   WHERE s.session_id = $1`;

export class PostgresSessionManager implements SessionManager {
  constructor(private readonly pool: Pool, private readonly opts: PostgresSessionManagerOptions) {}

  async createSession(
    identity: VerifiedIdentity,
    principal: PrincipalReference,
    input: SessionCreationInput,
  ): Promise<CreatedSession> {
    const sessionId = randomUUID();
    const secret = newSessionSecret();
    const version = this.opts.digestKeys.currentVersion;
    const digest = computeDigest(this.opts.digestKeys, version, sessionId, secret);
    const issuedAt = input.receivedAt;
    const idleExpiresAt = new Date(issuedAt.getTime() + input.idleTtlSeconds * 1000);
    const absoluteExpiresAt = new Date(issuedAt.getTime() + input.absoluteTtlSeconds * 1000);
    const d = identityDigests(identity);

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO continuum.authenticated_sessions
           (session_id, principal_id, credential_digest, credential_digest_version, identity_mapping_version,
            verification_policy_version, issued_at, last_seen_at, idle_expires_at, absolute_expires_at,
            authentication_strength, identity_version, created_request_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8,$9,$10,$11,$12)`,
        [
          sessionId, principal.principalId, digest, version, input.identityMappingVersion,
          input.verificationPolicyVersion, issuedAt, idleExpiresAt, absoluteExpiresAt,
          input.authenticationStrength, principal.version, input.requestId,
        ],
      );
      await insertAuthEvent(client, {
        type: "session.created", at: issuedAt, requestId: input.requestId,
        issuerDigest: d.issuerDigest, subjectDigest: d.subjectDigest,
        principalId: principal.principalId, sessionId,
        verificationPolicyVersion: input.verificationPolicyVersion,
        identityMappingVersion: input.identityMappingVersion, outcome: "success", reason: null,
      });
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw e;
    } finally {
      client.release();
    }
    return {
      sessionId,
      credential: { value: encodeCredential(sessionId, secret) },
      issuedAt, idleExpiresAt, absoluteExpiresAt,
    };
  }

  async validateSession(
    credential: SessionCredential,
    input: SessionValidationInput,
  ): Promise<SessionValidationResult> {
    const dec = decodeCredential(credential.value);
    if (!dec) return { valid: false, reason: "malformed_credential" };

    let r: any;
    try {
      r = (await this.pool.query(SESSION_SELECT, [dec.sessionId])).rows[0];
    } catch {
      return { valid: false, reason: "store_unavailable" };
    }
    if (!r) return { valid: false, reason: "unknown_session" };

    if (!r.credential_digest_version ||
        !verifyDigest(this.opts.digestKeys, r.credential_digest_version, dec.sessionId, dec.secret, r.credential_digest)) {
      return this.denied(dec.sessionId, r, input, "digest_mismatch");
    }
    if (r.revoked_at) return this.denied(dec.sessionId, r, input, r.revocation_reason === "rotated" ? "rotated" : "revoked");

    const now = input.receivedAt;
    if (now > r.idle_expires_at) return this.denied(dec.sessionId, r, input, "idle_expired");
    if (now > r.absolute_expires_at) return this.denied(dec.sessionId, r, input, "absolute_expired");
    if (r.p_status !== "active" || r.suspended_at || r.deleted_at) return this.denied(dec.sessionId, r, input, "principal_inactive");
    if (Number(r.p_version) !== Number(r.identity_version)) return this.denied(dec.sessionId, r, input, "identity_version_stale");
    if (r.identity_mapping_version != null &&
        (r.current_mapping_version == null || String(r.current_mapping_version) !== String(r.identity_mapping_version))) {
      return this.denied(dec.sessionId, r, input, "identity_mapping_stale");
    }
    if (input.requiredPolicyVersion && r.verification_policy_version !== input.requiredPolicyVersion) {
      return this.denied(dec.sessionId, r, input, "policy_version_stale");
    }
    if (input.requiredStrength &&
        STRENGTH_RANK[r.authentication_strength as AuthenticationStrength] < STRENGTH_RANK[input.requiredStrength]) {
      return this.denied(dec.sessionId, r, input, "insufficient_strength");
    }

    await this.pool.query("UPDATE continuum.authenticated_sessions SET last_seen_at = $2 WHERE session_id = $1", [dec.sessionId, now]);
    return {
      valid: true,
      session: {
        sessionId: dec.sessionId,
        principalId: r.principal_id,
        authenticationStrength: r.authentication_strength,
        issuedAt: r.issued_at,
        expiresAt: r.absolute_expires_at,
        identityMappingVersion: r.identity_mapping_version,
      },
    };
  }

  private async denied(
    sessionId: string,
    r: any,
    input: SessionValidationInput,
    reason: Extract<SessionValidationResult, { valid: false }>["reason"],
  ): Promise<SessionValidationResult> {
    await insertAuthEvent(this.pool, {
      type: "session.validation_denied", at: input.receivedAt, requestId: input.requestId,
      issuerDigest: null, subjectDigest: null, principalId: r?.principal_id ?? null, sessionId,
      verificationPolicyVersion: r?.verification_policy_version ?? null,
      identityMappingVersion: r?.identity_mapping_version ?? null, outcome: "denied", reason,
    }).catch(() => undefined);
    return { valid: false, reason };
  }

  async rotateSession(session: import("@continuum/core").ValidatedSession, reason: SessionRotationReason): Promise<CreatedSession> {
    const newId = randomUUID();
    const secret = newSessionSecret();
    const version = this.opts.digestKeys.currentVersion;
    const digest = computeDigest(this.opts.digestKeys, version, newId, secret);
    const now = new Date();
    let created: CreatedSession | null = null;

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const old = (await client.query(SESSION_SELECT, [session.sessionId])).rows[0];
      if (!old || old.revoked_at) throw new Error("cannot rotate a missing or already-revoked session");
      // Preserve the ABSOLUTE expiry (rotation must not extend lifetime); reset idle.
      const absoluteExpiresAt: Date = old.absolute_expires_at;
      const idleExpiresAt = new Date(now.getTime() + this.opts.rotationIdleTtlSeconds * 1000);
      await client.query(
        `INSERT INTO continuum.authenticated_sessions
           (session_id, principal_id, credential_digest, credential_digest_version, identity_mapping_version,
            verification_policy_version, issued_at, last_seen_at, idle_expires_at, absolute_expires_at,
            authentication_strength, identity_version, created_request_id, rotated_from_session_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8,$9,$10,$11,$12,$13)`,
        [
          newId, old.principal_id, digest, version, old.identity_mapping_version, old.verification_policy_version,
          now, idleExpiresAt, absoluteExpiresAt, old.authentication_strength, old.identity_version,
          `rotate:${reason}`, session.sessionId,
        ],
      );
      await client.query(
        "UPDATE continuum.authenticated_sessions SET revoked_at = $2, revocation_reason = 'rotated' WHERE session_id = $1 AND revoked_at IS NULL",
        [session.sessionId, now],
      );
      await insertAuthEvent(client, {
        type: "session.rotated", at: now, requestId: `rotate:${reason}`,
        issuerDigest: null, subjectDigest: null, principalId: old.principal_id, sessionId: newId,
        verificationPolicyVersion: old.verification_policy_version,
        identityMappingVersion: old.identity_mapping_version, outcome: "success", reason,
      });
      await client.query("COMMIT");
      created = {
        sessionId: newId, credential: { value: encodeCredential(newId, secret) },
        issuedAt: now, idleExpiresAt, absoluteExpiresAt,
      };
    } catch (e) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw e;
    } finally {
      client.release();
    }
    return created;
  }

  async revokeSession(sessionId: string, reason: SessionRevocationReason): Promise<SessionRevocationResult> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const upd = await client.query(
        "UPDATE continuum.authenticated_sessions SET revoked_at = now(), revocation_reason = $2 WHERE session_id = $1 AND revoked_at IS NULL",
        [sessionId, reason],
      );
      if (upd.rowCount === 0) {
        const exists = (await client.query("SELECT 1 FROM continuum.authenticated_sessions WHERE session_id = $1", [sessionId])).rows.length > 0;
        await client.query("ROLLBACK");
        return { revoked: false, reason: exists ? "already_revoked" : "unknown_session" };
      }
      await insertAuthEvent(client, {
        type: "session.revoked", at: new Date(), requestId: `revoke:${reason}`,
        issuerDigest: null, subjectDigest: null, principalId: null, sessionId,
        verificationPolicyVersion: null, identityMappingVersion: null, outcome: "success", reason,
      });
      await client.query("COMMIT");
      return { revoked: true };
    } catch {
      await client.query("ROLLBACK").catch(() => undefined);
      return { revoked: false, reason: "store_unavailable" };
    } finally {
      client.release();
    }
  }
}

export { insertAuthEvent };
