/**
 * In-memory S3 SessionManager (DEV/TEST ONLY — production uses the durable Postgres
 * session store). It reuses the S3 session-digest primitives so a session credential
 * is an opaque `${sessionId}.${secret}` whose only persisted form is a keyed digest.
 * Rotation preserves the ABSOLUTE expiry and never leaves both the old and new
 * session active (the old one becomes `rotated`). Revocation and idle/absolute expiry
 * fail closed. This mirrors the durable manager's semantics for browser-transport
 * tests without pulling in embedded PostgreSQL.
 */
import { randomBytes } from "node:crypto";
import type { AuthenticationStrength, PrincipalId, SessionId } from "../async/context";
import type {
  CreatedSession,
  PrincipalReference,
  SessionCreationInput,
  SessionManager,
  SessionRevocationReason,
  SessionRevocationResult,
  SessionRotationReason,
  SessionValidationInput,
  SessionValidationResult,
  VerifiedIdentity,
  SessionCredential,
} from "../identity/types";
import {
  computeDigest,
  decodeCredential,
  encodeCredential,
  newSessionSecret,
  verifyDigest,
  type SessionDigestKeys,
} from "../identity/session-digest";

const STRENGTH_RANK: Record<AuthenticationStrength, number> = {
  none: 0,
  single_factor: 1,
  multi_factor: 2,
  attested_workload: 3,
};

interface StoredSession {
  sessionId: SessionId;
  principalId: PrincipalId;
  digest: string;
  digestVersion: string;
  authenticationStrength: AuthenticationStrength;
  issuedAt: Date;
  idleTtlSeconds: number;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
  identityMappingVersion: string;
  verificationPolicyVersion: string;
  revoked: boolean;
  rotatedTo: SessionId | null;
}

export interface InMemorySessionManagerOptions {
  readonly keys: SessionDigestKeys;
  /** Clock for rotation (createSession/validateSession take an explicit receivedAt). */
  readonly clock?: () => Date;
}

export class InMemorySessionManager implements SessionManager {
  private readonly byId = new Map<string, StoredSession>();
  private readonly keys: SessionDigestKeys;
  private readonly clock: () => Date;

  constructor(opts: InMemorySessionManagerOptions) {
    this.keys = opts.keys;
    this.clock = opts.clock ?? (() => new Date());
  }

  async createSession(
    identity: VerifiedIdentity,
    principal: PrincipalReference,
    input: SessionCreationInput,
  ): Promise<CreatedSession> {
    const sessionId: SessionId = `sess_${randomBytes(12).toString("base64url")}`;
    const secret = newSessionSecret();
    const digest = computeDigest(this.keys, this.keys.currentVersion, sessionId, secret);
    const issuedAt = input.receivedAt;
    const idleExpiresAt = new Date(issuedAt.getTime() + input.idleTtlSeconds * 1000);
    const absoluteExpiresAt = new Date(issuedAt.getTime() + input.absoluteTtlSeconds * 1000);
    this.byId.set(sessionId, {
      sessionId,
      principalId: principal.principalId,
      digest,
      digestVersion: this.keys.currentVersion,
      authenticationStrength: input.authenticationStrength,
      issuedAt,
      idleTtlSeconds: input.idleTtlSeconds,
      idleExpiresAt,
      absoluteExpiresAt,
      identityMappingVersion: input.identityMappingVersion,
      verificationPolicyVersion: input.verificationPolicyVersion,
      revoked: false,
      rotatedTo: null,
    });
    return { sessionId, credential: { value: encodeCredential(sessionId, secret) }, issuedAt, idleExpiresAt, absoluteExpiresAt };
  }

  async validateSession(credential: SessionCredential, input: SessionValidationInput): Promise<SessionValidationResult> {
    const now = input.receivedAt;
    const decoded = decodeCredential(credential.value);
    if (!decoded) return { valid: false, reason: "malformed_credential" };
    const rec = this.byId.get(decoded.sessionId);
    if (!rec) return { valid: false, reason: "unknown_session" };
    if (!verifyDigest(this.keys, rec.digestVersion, decoded.sessionId, decoded.secret, rec.digest)) {
      return { valid: false, reason: "digest_mismatch" };
    }
    if (rec.revoked) return { valid: false, reason: "revoked" };
    if (rec.rotatedTo) return { valid: false, reason: "rotated" };
    if (now.getTime() >= rec.absoluteExpiresAt.getTime()) return { valid: false, reason: "absolute_expired" };
    if (now.getTime() >= rec.idleExpiresAt.getTime()) return { valid: false, reason: "idle_expired" };
    if (input.requiredStrength && STRENGTH_RANK[rec.authenticationStrength] < STRENGTH_RANK[input.requiredStrength]) {
      return { valid: false, reason: "insufficient_strength" };
    }
    if (input.requiredPolicyVersion && rec.verificationPolicyVersion !== input.requiredPolicyVersion) {
      return { valid: false, reason: "policy_version_stale" };
    }
    // Slide the idle window, never past the absolute expiry.
    const slid = Math.min(now.getTime() + rec.idleTtlSeconds * 1000, rec.absoluteExpiresAt.getTime());
    rec.idleExpiresAt = new Date(slid);
    return {
      valid: true,
      session: {
        sessionId: rec.sessionId,
        principalId: rec.principalId,
        authenticationStrength: rec.authenticationStrength,
        issuedAt: rec.issuedAt,
        expiresAt: rec.absoluteExpiresAt,
        identityMappingVersion: rec.identityMappingVersion,
      },
    };
  }

  async rotateSession(session: { sessionId: SessionId }, _reason: SessionRotationReason): Promise<CreatedSession> {
    const old = this.byId.get(session.sessionId);
    if (!old || old.revoked || old.rotatedTo) throw new Error("cannot rotate an inactive session");
    const now = this.clock();
    const sessionId: SessionId = `sess_${randomBytes(12).toString("base64url")}`;
    const secret = newSessionSecret();
    const digest = computeDigest(this.keys, this.keys.currentVersion, sessionId, secret);
    // Absolute expiry is PRESERVED across rotation; idle window restarts (capped).
    const absoluteExpiresAt = old.absoluteExpiresAt;
    const idleExpiresAt = new Date(Math.min(now.getTime() + old.idleTtlSeconds * 1000, absoluteExpiresAt.getTime()));
    this.byId.set(sessionId, {
      sessionId,
      principalId: old.principalId,
      digest,
      digestVersion: this.keys.currentVersion,
      authenticationStrength: old.authenticationStrength,
      issuedAt: now,
      idleTtlSeconds: old.idleTtlSeconds,
      idleExpiresAt,
      absoluteExpiresAt,
      identityMappingVersion: old.identityMappingVersion,
      verificationPolicyVersion: old.verificationPolicyVersion,
      revoked: false,
      rotatedTo: null,
    });
    // The old session is immediately invalidated — never both active.
    old.rotatedTo = sessionId;
    return { sessionId, credential: { value: encodeCredential(sessionId, secret) }, issuedAt: now, idleExpiresAt, absoluteExpiresAt };
  }

  async revokeSession(sessionId: SessionId, _reason: SessionRevocationReason): Promise<SessionRevocationResult> {
    const rec = this.byId.get(sessionId);
    if (!rec) return { revoked: false, reason: "unknown_session" };
    if (rec.revoked) return { revoked: false, reason: "already_revoked" };
    rec.revoked = true;
    return { revoked: true };
  }
}
