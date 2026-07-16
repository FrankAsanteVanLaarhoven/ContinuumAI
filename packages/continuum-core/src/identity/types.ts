/**
 * Phase 3 S3 — vendor-neutral identity-verification & session boundary (types).
 *
 * Four distinct layers, none of which accepts an authoritative tenant from the
 * caller:
 *
 *   external credential/assertion
 *     → IdentityVerifier        → normalized VerifiedIdentity
 *     → PrincipalMapper         → internal principal (issuer+subject → principal)
 *     → SessionManager          → validated internal session
 *     → S2B trusted DB context  → tenant (derived from membership, never here)
 *
 * The stable external identity key is ALWAYS (issuer, subject) — never email,
 * display name, username, or subject alone. Downstream authorization never sees
 * the raw claims object; it sees the normalized VerifiedIdentity and a digest of
 * the raw claims for correlation.
 */
import type {
  AuthenticationStrength,
  PrincipalId,
  RequestId,
  SessionId,
} from "../async/context";

export type { AuthenticationStrength };

// ---------------------------------------------------------------------------
// Normalized verified identity
// ---------------------------------------------------------------------------

export interface VerifiedIdentity {
  readonly issuer: string;
  readonly subject: string;
  readonly audiences: readonly string[];

  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly notBefore: Date | null;
  readonly authenticationTime: Date | null;

  readonly authenticationMethods: readonly string[];
  readonly authenticationStrength: AuthenticationStrength;

  readonly credentialId: string | null;
  readonly nonce: string | null;

  readonly verificationKeyId: string | null;
  readonly verificationPolicyVersion: string;

  /** Digest of the full raw claim set. The raw claims object is NEVER exposed. */
  readonly rawClaimsDigest: string;
}

/** The stable external identity key. Never email/username/subject alone. */
export function externalIdentityKey(id: { issuer: string; subject: string }): string {
  // Collision-safe join: a NUL cannot appear in a verified issuer or subject,
  // so (issuer, subject) maps injectively to one key.
  return `${id.issuer}\u0000${id.subject}`;
}

// ---------------------------------------------------------------------------
// Verifier contract
// ---------------------------------------------------------------------------

export interface AuthenticationInput {
  readonly credential: string;
  readonly expectedNonce?: string;
  readonly requestId: RequestId;
  readonly receivedAt: Date;
}

export type IdentityVerificationFailure =
  | "missing_credential"
  | "malformed_credential"
  | "unsupported_issuer"
  | "unsupported_algorithm"
  | "signature_invalid"
  | "verification_keys_unavailable"
  | "unknown_key"
  | "audience_mismatch"
  | "expired"
  | "not_yet_valid"
  | "issued_in_future"
  | "nonce_mismatch"
  | "replay_detected"
  | "subject_missing"
  | "claims_invalid"
  | "policy_version_mismatch";

/** Redacted evidence payload — digests only, never raw credential material. */
export interface AuthenticationEvidence {
  readonly requestId: RequestId;
  readonly issuerDigest: string | null;
  readonly subjectDigest: string | null;
  readonly verificationPolicyVersion: string;
  readonly verificationKeyId: string | null;
  readonly at: Date;
}

export type IdentityVerificationResult =
  | { readonly verified: true; readonly identity: VerifiedIdentity }
  | {
      readonly verified: false;
      readonly reason: IdentityVerificationFailure;
      readonly evidence: AuthenticationEvidence;
    };

export interface IdentityVerifier {
  verify(
    input: AuthenticationInput,
    policy: IdentityVerificationPolicy,
  ): Promise<IdentityVerificationResult>;
}

// ---------------------------------------------------------------------------
// Verification policy
// ---------------------------------------------------------------------------

export interface KeySourceReference {
  /** `test` = deterministic in-memory (dev/test only). `static` = configured static set. */
  readonly kind: "test" | "static";
  readonly ref: string;
}

export interface IssuerPolicy {
  readonly issuer: string;
  readonly allowedAudiences: readonly string[];
  readonly allowedAlgorithms: readonly string[];
  readonly keySource: KeySourceReference;
  readonly enabled: boolean;
}

export interface IdentityVerificationPolicy {
  readonly allowedIssuers: readonly IssuerPolicy[];
  readonly allowedAlgorithms: readonly string[];

  readonly maximumClockSkewSeconds: number;
  readonly maximumCredentialAgeSeconds: number;

  readonly requireIssuedAt: boolean;
  readonly requireExpiration: boolean;
  readonly requireSubject: boolean;
  readonly requireNonceWhenExpected: boolean;

  readonly policyVersion: string;
}

// ---------------------------------------------------------------------------
// Verification-key boundary
// ---------------------------------------------------------------------------

export interface VerificationKey {
  readonly kid: string;
  readonly algorithm: string;
  /** Base64 key material. Symmetric secret for the deterministic HMAC verifier;
   *  a public key for a future asymmetric verifier. NEVER logged. */
  readonly material: string;
}

export interface VerificationKeySet {
  readonly issuer: string;
  readonly version: string;
  readonly keys: readonly VerificationKey[];
  readonly fetchedAt: Date;
  /** Absolute instant after which this set is stale and must be refused. */
  readonly staleAfter: Date | null;
}

export type KeyLookup =
  | { readonly available: true; readonly keySet: VerificationKeySet }
  | { readonly available: false; readonly reason: "unavailable" | "stale" };

export interface VerificationKeyProvider {
  getVerificationKeys(issuer: string, at: Date): Promise<KeyLookup>;
}

/** Single-use guard for credential ids / nonces (replay protection). */
export interface ReplayGuard {
  checkAndConsume(issuer: string, credentialId: string): Promise<"fresh" | "replayed">;
}

// ---------------------------------------------------------------------------
// Principal mapping (issuer+subject → internal principal)
// ---------------------------------------------------------------------------

export interface PrincipalReference {
  readonly principalId: PrincipalId;
  readonly version: number;
}

export type PrincipalMappingFailure =
  | "no_mapping"
  | "mapping_disabled"
  | "principal_suspended"
  | "principal_deleted"
  | "mapping_version_stale"
  | "external_identity_revoked"
  | "ambiguous_mapping"
  | "mapping_store_unavailable";

export type PrincipalMappingResult =
  | {
      readonly mapped: true;
      readonly principal: PrincipalReference;
      readonly mappingVersion: string;
    }
  | { readonly mapped: false; readonly reason: PrincipalMappingFailure };

export interface PrincipalMapper {
  /** Resolve a verified identity to an active internal principal. Deny by default
   *  when no mapping exists (no implicit enrolment in this milestone). */
  resolve(identity: VerifiedIdentity): Promise<PrincipalMappingResult>;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/** Opaque bearer value returned ONLY at creation/rotation; never persisted raw. */
export interface SessionCredential {
  readonly value: string;
}

export interface SessionCreationInput {
  readonly requestId: RequestId;
  readonly receivedAt: Date;
  readonly authenticationStrength: AuthenticationStrength;
  readonly identityMappingVersion: string;
  readonly verificationPolicyVersion: string;
  readonly idleTtlSeconds: number;
  readonly absoluteTtlSeconds: number;
}

export interface CreatedSession {
  readonly sessionId: SessionId;
  readonly credential: SessionCredential;
  readonly issuedAt: Date;
  readonly idleExpiresAt: Date;
  readonly absoluteExpiresAt: Date;
}

export interface SessionValidationInput {
  readonly requestId: RequestId;
  readonly receivedAt: Date;
  /** Minimum authentication strength the requested operation needs. */
  readonly requiredStrength?: AuthenticationStrength;
  /** If set, a session bound to an older verification-policy version is stale. */
  readonly requiredPolicyVersion?: string;
}

export interface ValidatedSession {
  readonly sessionId: SessionId;
  readonly principalId: PrincipalId;
  readonly authenticationStrength: AuthenticationStrength;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly identityMappingVersion: string;
}

export type SessionValidationFailure =
  | "unknown_session"
  | "malformed_credential"
  | "digest_mismatch"
  | "revoked"
  | "rotated"
  | "idle_expired"
  | "absolute_expired"
  | "principal_inactive"
  | "identity_mapping_stale"
  | "identity_version_stale"
  | "policy_version_stale"
  | "insufficient_strength"
  | "store_unavailable";

export type SessionValidationResult =
  | { readonly valid: true; readonly session: ValidatedSession }
  | { readonly valid: false; readonly reason: SessionValidationFailure };

export type SessionRotationReason =
  | "authentication_completed"
  | "privilege_change"
  | "tenant_switch"
  | "reauthentication"
  | "suspected_fixation"
  | "credential_compromise";

export type SessionRevocationReason =
  | "logout"
  | "rotated"
  | "administrative"
  | "credential_compromise"
  | "identity_change";

export type SessionRevocationResult =
  | { readonly revoked: true }
  | { readonly revoked: false; readonly reason: "unknown_session" | "already_revoked" | "store_unavailable" };

export interface SessionManager {
  createSession(
    identity: VerifiedIdentity,
    principal: PrincipalReference,
    input: SessionCreationInput,
  ): Promise<CreatedSession>;

  validateSession(
    credential: SessionCredential,
    input: SessionValidationInput,
  ): Promise<SessionValidationResult>;

  rotateSession(
    session: ValidatedSession,
    reason: SessionRotationReason,
  ): Promise<CreatedSession>;

  revokeSession(sessionId: SessionId, reason: SessionRevocationReason): Promise<SessionRevocationResult>;
}

// ---------------------------------------------------------------------------
// Auth evidence sink (identity/session lifecycle — pre-tenant, cross-tenant)
// ---------------------------------------------------------------------------

export type AuthEventType =
  | "identity.verified"
  | "identity.denied"
  | "identity.unmapped"
  | "principal.suspended_denied"
  | "session.created"
  | "session.validation_denied"
  | "session.rotated"
  | "session.revoked"
  | "identity.mapping_stale_denied"
  | "verification.keys_unavailable_denied";

/** Redacted auth event. NEVER contains raw credentials/tokens/signatures/claims/
 *  session secrets/private keys — only digests and stable, non-secret ids. */
export interface AuthEvent {
  readonly type: AuthEventType;
  readonly at: Date;
  readonly requestId: RequestId;
  readonly issuerDigest: string | null;
  readonly subjectDigest: string | null;
  readonly principalId: PrincipalId | null;
  readonly sessionId: SessionId | null;
  readonly verificationPolicyVersion: string | null;
  readonly identityMappingVersion: string | null;
  readonly outcome: "success" | "denied";
  readonly reason: string | null;
}

export interface AuthEventSink {
  append(event: AuthEvent): Promise<void>;
}
