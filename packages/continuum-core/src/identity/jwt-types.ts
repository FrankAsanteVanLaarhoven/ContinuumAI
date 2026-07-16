/**
 * Phase 3 S4A — provider-neutral real verifier cryptographic boundary (types).
 *
 * Replaces the S3 deterministic assertion verifier with a standards-compliant,
 * provider-neutral JWT/JWS verification path that fails closed under issuer,
 * algorithm, key-resolution, rotation, outage, audience, temporal and replay
 * failures. This milestone is protocol-level only: NO browser routes, redirects,
 * PKCE, cookies, CSRF, provider SDKs, workload identity, or break-glass.
 *
 *   encoded assertion
 *     → structural JWT parsing
 *     → issuer policy lookup            (unverified iss — routing only, never authz)
 *     → algorithm allowlist
 *     → verification-key resolution
 *     → cryptographic signature verification
 *     → claims validation
 *     → replay/nonce validation where applicable
 *     → normalized VerifiedIdentity
 *     → existing S3 principal/session boundary
 *
 * The normalized output is the SAME VerifiedIdentity the S3 boundary already
 * consumes, so a real JWT still grants no tenant authority by itself — tenant
 * authority remains the S2B trusted database-context path.
 *
 * Naming note: the S4A key-provider interface is `JwtVerificationKeyProvider`
 * (not `VerificationKeyProvider`, which is the S3 in-memory contract with a
 * different shape) to avoid a symbol collision across the identity module.
 */
import type { RequestId } from "../async/context";
import type { VerifiedIdentity } from "./types";

// ---------------------------------------------------------------------------
// Algorithms — asymmetric only. No `none`, no HMAC (no symmetric/asymmetric
// substitution), no algorithm outside this closed set.
// ---------------------------------------------------------------------------

export type JwtAlgorithm =
  | "RS256" | "RS384" | "RS512"
  | "PS256" | "PS384" | "PS512"
  | "ES256" | "ES384" | "ES512"
  | "EdDSA";

export const SUPPORTED_JWT_ALGORITHMS: readonly JwtAlgorithm[] = [
  "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
];

export function isSupportedJwtAlgorithm(alg: unknown): alg is JwtAlgorithm {
  return typeof alg === "string" && (SUPPORTED_JWT_ALGORITHMS as readonly string[]).includes(alg);
}

/** Expected JWK `kty`/`crv` for each algorithm — used to reject key-type substitution. */
export const ALGORITHM_KEY_SHAPE: Record<JwtAlgorithm, { readonly kty: string; readonly crv?: string }> = {
  RS256: { kty: "RSA" }, RS384: { kty: "RSA" }, RS512: { kty: "RSA" },
  PS256: { kty: "RSA" }, PS384: { kty: "RSA" }, PS512: { kty: "RSA" },
  ES256: { kty: "EC", crv: "P-256" }, ES384: { kty: "EC", crv: "P-384" }, ES512: { kty: "EC", crv: "P-521" },
  EdDSA: { kty: "OKP" },
};

// ---------------------------------------------------------------------------
// Input boundary
// ---------------------------------------------------------------------------

export interface JwtAuthenticationInput {
  /** The encoded assertion, treated as opaque input until fully verified. */
  readonly assertion: string;
  readonly expectedNonce?: string;
  readonly requestId: RequestId;
  readonly receivedAt: Date;
}

/** Hard input limits applied BEFORE parsing and BEFORE any remote key resolution. */
export interface JwtInputLimits {
  readonly maxAssertionLength: number;
  readonly maxHeaderBytes: number;
  readonly maxPayloadBytes: number;
  readonly maxAudiences: number;
  readonly maxAuthenticationMethods: number;
  /** Max length for issuer, subject, nonce and key id strings. */
  readonly maxStringLength: number;
}

export const DEFAULT_JWT_LIMITS: JwtInputLimits = {
  maxAssertionLength: 8192,
  maxHeaderBytes: 2048,
  maxPayloadBytes: 8192,
  maxAudiences: 16,
  maxAuthenticationMethods: 16,
  maxStringLength: 1024,
};

// ---------------------------------------------------------------------------
// Issuer policy — issuers are registered in advance; never discovered from the
// assertion.
// ---------------------------------------------------------------------------

export type JwtReplayPolicy = "none" | "nonce" | "jti" | "nonce_and_jti";

export interface JwtIssuerPolicy {
  readonly issuer: string;
  readonly audiences: readonly string[];
  readonly allowedAlgorithms: readonly JwtAlgorithm[];

  /** Identifies the key provider/JWKS source that serves this issuer's keys. */
  readonly keyProviderId: string;
  readonly enabled: boolean;

  readonly requireSubject: boolean;
  readonly requireIssuedAt: boolean;
  readonly requireExpiration: boolean;
  readonly requireNonceWhenExpected: boolean;

  readonly maximumCredentialAgeSeconds: number;
  readonly maximumClockSkewSeconds: number;

  readonly replayPolicy: JwtReplayPolicy;

  readonly policyVersion: string;
}

export interface JwtVerificationPolicy {
  readonly issuers: readonly JwtIssuerPolicy[];
  readonly limits: JwtInputLimits;
}

/** Resolve a registered, enabled issuer policy from an unverified issuer string. */
export function resolveJwtIssuer(
  policy: JwtVerificationPolicy,
  iss: unknown,
): { readonly found: false; readonly disabled: boolean } | { readonly found: true; readonly policy: JwtIssuerPolicy } {
  if (typeof iss !== "string" || iss.length === 0) return { found: false, disabled: false };
  const p = policy.issuers.find((i) => i.issuer === iss);
  if (!p) return { found: false, disabled: false };
  if (!p.enabled) return { found: false, disabled: true };
  return { found: true, policy: p };
}

// ---------------------------------------------------------------------------
// Verification-key provider contract
// ---------------------------------------------------------------------------

export interface VerificationKeyRequest {
  readonly issuer: string;
  readonly keyId: string | null;
  readonly algorithm: JwtAlgorithm;
  readonly receivedAt: Date;
}

/** A resolved public verification key. NEVER carries private material. */
export interface ResolvedVerificationKey {
  readonly kid: string;
  readonly algorithm: JwtAlgorithm;
  /** Public JWK only. */
  readonly jwk: JsonWebKey;
  readonly keySetVersion: string;
  readonly keySetDigest: string;
}

export type VerificationKeyResolutionStatus =
  | "resolved"
  | "issuer_unknown"
  | "key_id_missing"
  | "key_unknown"
  | "algorithm_key_mismatch"
  | "keys_unavailable"
  | "keys_stale"
  | "refresh_failed"
  | "ambiguous_key"
  | "invalid_key_material";

export type VerificationKeyResolution =
  | { readonly status: "resolved"; readonly key: ResolvedVerificationKey }
  | { readonly status: Exclude<VerificationKeyResolutionStatus, "resolved"> };

export interface JwtVerificationKeyProvider {
  resolveKey(request: VerificationKeyRequest): Promise<VerificationKeyResolution>;
}

// ---------------------------------------------------------------------------
// JWKS source abstraction (provider-neutral)
// ---------------------------------------------------------------------------

/** A public JWK. Private members (`d`, symmetric `k`) are rejected on ingest. */
export interface Jwk {
  readonly kty: string;
  readonly kid?: string;
  readonly alg?: string;
  readonly use?: string;
  readonly crv?: string;
  readonly n?: string;
  readonly e?: string;
  readonly x?: string;
  readonly y?: string;
  readonly [k: string]: unknown;
}

export interface Jwks {
  readonly keys: readonly Jwk[];
}

export interface JwksSnapshot {
  readonly issuer: string;
  readonly keys: readonly Jwk[];
  readonly version: string;
  /** Stable digest of the key-set contents (for rotation/version-regression evidence). */
  readonly digest: string;
  readonly fetchedAt: Date;
}

export interface JwksLoadOptions {
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly maxKeyCount: number;
  readonly acceptedKeyTypes: readonly string[];
  readonly acceptedCurves: readonly string[];
  readonly at: Date;
}

export type JwksLoadResult =
  | { readonly ok: true; readonly snapshot: JwksSnapshot }
  | { readonly ok: false; readonly reason: JwksLoadFailure };

export type JwksLoadFailure =
  | "issuer_unknown"
  | "unavailable"
  | "refresh_failed"
  | "too_large"
  | "malformed"
  | "empty"
  | "unsupported_key_type";

export interface JwksSource {
  load(issuer: string, options: JwksLoadOptions): Promise<JwksLoadResult>;
}

// ---------------------------------------------------------------------------
// Key-cache policy
// ---------------------------------------------------------------------------

export interface JwksCachePolicy {
  readonly freshLifetimeSeconds: number;
  /** Additional grace during which a cached key already seen may still verify. */
  readonly staleGraceSeconds: number;
  readonly maxStaleAgeSeconds: number;
  readonly refreshTimeoutMs: number;
  readonly maxResponseBytes: number;
  readonly maxKeyCount: number;
  readonly acceptedKeyTypes: readonly string[];
  readonly acceptedCurves: readonly string[];
  /** How long an unknown-kid negative result suppresses further refreshes. */
  readonly negativeCacheSeconds: number;
}

export const DEFAULT_JWKS_CACHE_POLICY: JwksCachePolicy = {
  freshLifetimeSeconds: 300,
  staleGraceSeconds: 0,
  maxStaleAgeSeconds: 86_400,
  refreshTimeoutMs: 2000,
  maxResponseBytes: 65_536,
  maxKeyCount: 32,
  acceptedKeyTypes: ["RSA", "EC", "OKP"],
  acceptedCurves: ["P-256", "P-384", "P-521", "Ed25519"],
  negativeCacheSeconds: 30,
};

// ---------------------------------------------------------------------------
// Failure taxonomy — fail closed on all internal uncertainty.
// ---------------------------------------------------------------------------

export type JwtVerificationFailure =
  | "assertion_too_large"
  | "malformed_jwt"
  | "unsupported_issuer"
  | "issuer_disabled"
  | "unsupported_algorithm"
  | "missing_key_id"
  | "unknown_key"
  | "ambiguous_key"
  | "key_type_mismatch"
  | "keys_unavailable"
  | "keys_stale"
  | "jwks_refresh_failed"
  | "signature_invalid"
  | "issuer_mismatch"
  | "audience_mismatch"
  | "subject_missing"
  | "claims_invalid"
  | "expired"
  | "not_yet_valid"
  | "issued_in_future"
  | "credential_too_old"
  | "nonce_missing"
  | "nonce_mismatch"
  | "jti_missing"
  | "replay_detected"
  | "replay_store_unavailable"
  | "policy_version_mismatch"
  | "internal_verification_error";

export type ReplayOutcome = "fresh" | "replayed" | "skipped" | "unavailable";

/**
 * Redacted verification evidence. Records digests and safe identifiers only —
 * NEVER the raw assertion, signature, full claims, raw nonce/jti, private keys,
 * or session credentials.
 */
export interface JwtVerificationEvidence {
  readonly requestId: RequestId;
  readonly at: Date;
  readonly outcome: "success" | "denied";
  readonly reason: JwtVerificationFailure | null;
  readonly issuerDigest: string | null;
  readonly algorithm: string | null;
  readonly keyIdDigest: string | null;
  readonly keySetVersion: string | null;
  readonly keySetDigest: string | null;
  readonly verificationPolicyVersion: string | null;
  readonly assertionDigest: string | null;
  readonly identityDigest: string | null;
  readonly replayOutcome: ReplayOutcome | null;
  /** Coarse elapsed-time observation (ms); not a benchmark. */
  readonly elapsedMs: number | null;
}

export type JwtVerificationResult =
  | { readonly verified: true; readonly identity: VerifiedIdentity; readonly evidence: JwtVerificationEvidence }
  | { readonly verified: false; readonly reason: JwtVerificationFailure; readonly evidence: JwtVerificationEvidence };

export interface JwtIdentityVerifierContract {
  verifyAssertion(input: JwtAuthenticationInput): Promise<JwtVerificationResult>;
}
