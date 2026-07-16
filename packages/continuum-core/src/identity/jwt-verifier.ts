/**
 * S4A real JWT/JWS verifier — provider-neutral, standards-compliant. Uses the
 * `jose` library for JWS signature verification and JWK import; no cryptographic
 * primitive is implemented here. It runs the fixed sequence
 *
 *   input limits → structural parse → issuer policy → algorithm allowlist
 *   → key resolution → signature verification → claims validation
 *   → replay/nonce validation → normalized VerifiedIdentity
 *
 * and fails closed with a distinct failure class at every step. No downstream
 * code receives unverified claims: the normalized VerifiedIdentity is built only
 * from the payload returned by a successful signature verification.
 *
 * The normalized output is the SAME S3 VerifiedIdentity, so a valid JWT grants no
 * tenant authority by itself; tenant authority remains the S2B trusted-context
 * path. `JwtIdentityVerifierAdapter` plugs this into the existing S3
 * AuthenticationBoundary unchanged.
 */
import { compactVerify, decodeJwt, decodeProtectedHeader, errors as joseErrors, importJWK } from "jose";
import { digestOf, sha256Hex } from "../crypto";
import type { AuthenticationStrength } from "../async/context";
import type {
  AuthenticationInput,
  IdentityVerificationFailure,
  IdentityVerificationPolicy,
  IdentityVerificationResult,
  IdentityVerifier,
  VerifiedIdentity,
} from "./types";
import { issuerDigest, subjectDigest } from "./verification";
import {
  isSupportedJwtAlgorithm,
  resolveJwtIssuer,
  type JwtAlgorithm,
  type JwtAuthenticationInput,
  type JwtIdentityVerifierContract,
  type JwtIssuerPolicy,
  type JwtVerificationEvidence,
  type JwtVerificationFailure,
  type JwtVerificationKeyProvider,
  type JwtVerificationPolicy,
  type JwtVerificationResult,
  type ReplayOutcome,
  type VerificationKeyResolution,
} from "./jwt-types";
import { enforceAssertionEnvelope, withinStringLimit } from "./jwt-limits";
import { replayDigest, type DurableReplayLedger, type ReplayKind } from "./replay-ledger";

const STRENGTH_BY_ACR: Record<string, AuthenticationStrength> = {
  mfa: "multi_factor",
  multi_factor: "multi_factor",
  attested_workload: "attested_workload",
  pwd: "single_factor",
  single_factor: "single_factor",
};

export interface JwtVerifierOptions {
  readonly policy: JwtVerificationPolicy;
  readonly keyProvider: JwtVerificationKeyProvider;
  /** Required when any issuer's replayPolicy is not "none". */
  readonly replayLedger?: DurableReplayLedger;
  /** Base64 key for the replay digest. Required when replay handling is active. */
  readonly replayDigestKey?: string;
  /** Upper bound on how long a replay entry is retained (seconds). */
  readonly replayRetentionSeconds?: number;
}

interface DenyContext {
  iss?: string | undefined;
  sub?: string | undefined;
  alg?: string | undefined;
  kid?: string | undefined;
  keySetVersion?: string | undefined;
  keySetDigest?: string | undefined;
  policyVersion?: string | undefined;
  assertionDigest?: string | undefined;
  identityDigest?: string | undefined;
  replayOutcome?: ReplayOutcome | undefined;
}

export class JwtIdentityVerifier implements JwtIdentityVerifierContract {
  private readonly policy: JwtVerificationPolicy;
  private readonly keyProvider: JwtVerificationKeyProvider;
  private readonly replayLedger: DurableReplayLedger | null;
  private readonly replayDigestKey: string | null;
  private readonly replayRetentionSeconds: number;

  constructor(opts: JwtVerifierOptions) {
    this.policy = opts.policy;
    this.keyProvider = opts.keyProvider;
    this.replayLedger = opts.replayLedger ?? null;
    this.replayDigestKey = opts.replayDigestKey ?? null;
    this.replayRetentionSeconds = opts.replayRetentionSeconds ?? 3600;
  }

  async verifyAssertion(input: JwtAuthenticationInput): Promise<JwtVerificationResult> {
    const started = Date.now();
    const deny = (reason: JwtVerificationFailure, ctx: DenyContext = {}): JwtVerificationResult => ({
      verified: false,
      reason,
      evidence: this.evidence(input, "denied", reason, ctx, started),
    });

    // 1) Input limits (before any parse or network).
    const env = enforceAssertionEnvelope(input.assertion, this.policy.limits);
    if (!env.ok) return deny(env.reason);

    // 2) Structural parse — header + payload (unverified, routing only).
    let header: { alg?: unknown; kid?: unknown };
    let unverified: Record<string, unknown>;
    try {
      header = decodeProtectedHeader(input.assertion) as { alg?: unknown; kid?: unknown };
      unverified = decodeJwt(input.assertion) as Record<string, unknown>;
    } catch {
      return deny("malformed_jwt");
    }
    const alg = header.alg;
    if (!isSupportedJwtAlgorithm(alg)) return deny("unsupported_algorithm");
    const kid = typeof header.kid === "string" ? header.kid : null;
    const unvIss = typeof unverified.iss === "string" ? unverified.iss : undefined;
    if (!withinStringLimit(this.policy.limits, unvIss, kid)) return deny("malformed_jwt", { iss: unvIss, alg, kid: kid ?? undefined });

    // 3) Issuer policy (unverified issuer — routing only, never authorization).
    const resolved = resolveJwtIssuer(this.policy, unvIss);
    if (!resolved.found) return deny(resolved.disabled ? "issuer_disabled" : "unsupported_issuer", { iss: unvIss, alg });
    const issuer = resolved.policy;

    // 4) Algorithm allowlist (per issuer).
    if (!issuer.allowedAlgorithms.includes(alg)) return deny("unsupported_algorithm", { iss: unvIss, alg });

    // 5) Verification-key resolution.
    const resolution = await this.keyProvider.resolveKey({
      issuer: issuer.issuer,
      keyId: kid,
      algorithm: alg,
      receivedAt: input.receivedAt,
    });
    const keyReason = mapKeyResolution(resolution);
    if (keyReason !== null) return deny(keyReason, { iss: unvIss, alg, kid: kid ?? undefined });
    const key = (resolution as Extract<VerificationKeyResolution, { status: "resolved" }>).key;
    const keyCtx: DenyContext = {
      iss: unvIss, alg, kid: key.kid, keySetVersion: key.keySetVersion, keySetDigest: key.keySetDigest,
    };

    // 6) Signature verification (jose). Import failure ⇒ key/type mismatch.
    let imported: Awaited<ReturnType<typeof importJWK>>;
    try {
      imported = await importJWK(key.jwk, alg);
    } catch {
      return deny("key_type_mismatch", keyCtx);
    }
    let verifiedPayload: Record<string, unknown>;
    try {
      const result = await compactVerify(input.assertion, imported, { algorithms: [alg] });
      verifiedPayload = JSON.parse(Buffer.from(result.payload).toString("utf8")) as Record<string, unknown>;
    } catch (err: unknown) {
      if (err instanceof joseErrors.JWSSignatureVerificationFailed) return deny("signature_invalid", keyCtx);
      if (err instanceof joseErrors.JOSEAlgNotAllowed) return deny("unsupported_algorithm", keyCtx);
      if (err instanceof joseErrors.JOSENotSupported) return deny("key_type_mismatch", keyCtx);
      return deny("internal_verification_error", keyCtx);
    }

    // 7) Claims validation — on the VERIFIED payload only.
    const assertionDigest = sha256Hex(env.envelope.signingInput);
    const claimsCtx: DenyContext = { ...keyCtx, policyVersion: issuer.policyVersion, assertionDigest };
    const claimsResult = validateClaims(verifiedPayload, issuer, this.policy.limits, input, key.kid);
    if (!claimsResult.ok) return deny(claimsResult.reason, claimsCtx);
    const identity = claimsResult.identity;
    const identityDigest = digestOf({ iss: identity.issuer, sub: identity.subject });

    // 8) Replay / nonce consumption where the issuer policy requires it.
    const replay = await this.consumeReplay(issuer, identity, input);
    const okCtx: DenyContext = { ...claimsCtx, identityDigest, replayOutcome: replay.outcome };
    if (replay.reason !== null) return deny(replay.reason, okCtx);

    return { verified: true, identity, evidence: this.evidence(input, "success", null, okCtx, started) };
  }

  private async consumeReplay(
    issuer: JwtIssuerPolicy,
    identity: VerifiedIdentity,
    input: JwtAuthenticationInput,
  ): Promise<{ outcome: ReplayOutcome; reason: JwtVerificationFailure | null }> {
    const kinds: ReplayKind[] = [];
    if (issuer.replayPolicy === "nonce" || issuer.replayPolicy === "nonce_and_jti") kinds.push("nonce");
    if (issuer.replayPolicy === "jti" || issuer.replayPolicy === "nonce_and_jti") kinds.push("jti");
    if (kinds.length === 0) return { outcome: "skipped", reason: null };

    if (!this.replayLedger || !this.replayDigestKey) {
      // Replay handling required by policy but not configured ⇒ fail closed.
      return { outcome: "unavailable", reason: "replay_store_unavailable" };
    }
    const retentionCap = new Date(input.receivedAt.getTime() + this.replayRetentionSeconds * 1000);
    const expiresAt = identity.expiresAt.getTime() < retentionCap.getTime() ? identity.expiresAt : retentionCap;

    for (const kind of kinds) {
      const value = kind === "nonce" ? identity.nonce : identity.credentialId;
      if (!value) return { outcome: "skipped", reason: kind === "nonce" ? "nonce_missing" : "jti_missing" };
      const digest = replayDigest(this.replayDigestKey, issuer.issuer, kind, value);
      const outcome = await this.replayLedger.consume({
        issuer: issuer.issuer, kind, digest, expiresAt, requestId: input.requestId, at: input.receivedAt,
      });
      if (outcome === "unavailable") return { outcome: "unavailable", reason: "replay_store_unavailable" };
      if (outcome === "replayed") return { outcome: "replayed", reason: "replay_detected" };
    }
    return { outcome: "fresh", reason: null };
  }

  private evidence(
    input: JwtAuthenticationInput,
    outcome: "success" | "denied",
    reason: JwtVerificationFailure | null,
    ctx: DenyContext,
    started: number,
  ): JwtVerificationEvidence {
    return {
      requestId: input.requestId,
      at: input.receivedAt,
      outcome,
      reason,
      issuerDigest: ctx.iss ? issuerDigest(ctx.iss) : null,
      algorithm: ctx.alg ?? null,
      keyIdDigest: ctx.kid ? sha256Hex(`kid:${ctx.kid}`).slice(0, 32) : null,
      keySetVersion: ctx.keySetVersion ?? null,
      keySetDigest: ctx.keySetDigest ?? null,
      verificationPolicyVersion: ctx.policyVersion ?? null,
      assertionDigest: ctx.assertionDigest ?? null,
      identityDigest: ctx.identityDigest ?? null,
      replayOutcome: ctx.replayOutcome ?? null,
      elapsedMs: Math.max(0, Date.now() - started),
    };
  }
}

// ---------------------------------------------------------------------------
// Claims validation (on the verified payload)
// ---------------------------------------------------------------------------

type ClaimsOutcome =
  | { readonly ok: true; readonly identity: VerifiedIdentity }
  | { readonly ok: false; readonly reason: JwtVerificationFailure };

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function toAudiences(aud: unknown): string[] | null {
  if (aud === undefined) return [];
  if (typeof aud === "string") return [aud];
  if (Array.isArray(aud) && aud.every((a) => typeof a === "string")) return aud as string[];
  return null;
}

function validateClaims(
  c: Record<string, unknown>,
  issuer: JwtIssuerPolicy,
  limits: import("./jwt-types").JwtInputLimits,
  input: JwtAuthenticationInput,
  keyId: string,
): ClaimsOutcome {
  // Exact issuer (verified payload must match the routed, registered issuer).
  if (typeof c.iss !== "string" || c.iss !== issuer.issuer) return { ok: false, reason: "issuer_mismatch" };

  // Subject.
  const sub = c.sub;
  if (issuer.requireSubject && (typeof sub !== "string" || sub.length === 0)) return { ok: false, reason: "subject_missing" };
  if (sub !== undefined && typeof sub !== "string") return { ok: false, reason: "claims_invalid" };
  const subject = typeof sub === "string" ? sub : "";

  // Policy version (if the credential names one, it must match).
  if (c.pv !== undefined && c.pv !== issuer.policyVersion) return { ok: false, reason: "policy_version_mismatch" };

  // Structural claim shapes + string limits.
  const nonce = c.nonce;
  const jti = c.jti;
  if (nonce !== undefined && typeof nonce !== "string") return { ok: false, reason: "claims_invalid" };
  if (jti !== undefined && typeof jti !== "string") return { ok: false, reason: "claims_invalid" };
  if (!withinStringLimit(limits, issuer.issuer, subject, typeof nonce === "string" ? nonce : null, typeof jti === "string" ? jti : null, keyId)) {
    return { ok: false, reason: "claims_invalid" };
  }
  for (const key of ["iat", "exp", "nbf", "auth_time"] as const) {
    if (c[key] !== undefined && num(c[key]) === null) return { ok: false, reason: "claims_invalid" };
  }
  if (c.amr !== undefined && !(Array.isArray(c.amr) && c.amr.every((m) => typeof m === "string"))) {
    return { ok: false, reason: "claims_invalid" };
  }
  if (Array.isArray(c.amr) && c.amr.length > limits.maxAuthenticationMethods) return { ok: false, reason: "claims_invalid" };

  // Audience.
  const audiences = toAudiences(c.aud);
  if (audiences === null) return { ok: false, reason: "claims_invalid" };
  if (audiences.length > limits.maxAudiences) return { ok: false, reason: "claims_invalid" };
  if (!audiences.some((a) => issuer.audiences.includes(a))) return { ok: false, reason: "audience_mismatch" };

  // Temporal.
  const now = Math.floor(input.receivedAt.getTime() / 1000);
  const skew = issuer.maximumClockSkewSeconds;
  const iat = num(c.iat);
  if (issuer.requireIssuedAt && iat === null) return { ok: false, reason: "claims_invalid" };
  if (iat !== null && iat > now + skew) return { ok: false, reason: "issued_in_future" };
  if (iat !== null && now - iat > issuer.maximumCredentialAgeSeconds) return { ok: false, reason: "credential_too_old" };

  const exp = num(c.exp);
  if (issuer.requireExpiration && exp === null) return { ok: false, reason: "claims_invalid" };
  if (exp !== null && now > exp + skew) return { ok: false, reason: "expired" };

  const nbf = num(c.nbf);
  if (nbf !== null && now < nbf - skew) return { ok: false, reason: "not_yet_valid" };

  // Nonce (when the caller expected one and policy requires it).
  if (input.expectedNonce !== undefined && issuer.requireNonceWhenExpected) {
    if (typeof nonce !== "string" || nonce.length === 0) return { ok: false, reason: "nonce_missing" };
    if (nonce !== input.expectedNonce) return { ok: false, reason: "nonce_mismatch" };
  }

  // jti presence when the replay policy needs it.
  if ((issuer.replayPolicy === "jti" || issuer.replayPolicy === "nonce_and_jti") && (typeof jti !== "string" || jti.length === 0)) {
    return { ok: false, reason: "jti_missing" };
  }
  if ((issuer.replayPolicy === "nonce" || issuer.replayPolicy === "nonce_and_jti") && (typeof nonce !== "string" || nonce.length === 0)) {
    return { ok: false, reason: "nonce_missing" };
  }

  const acr = typeof c.acr === "string" ? c.acr : null;
  const strength: AuthenticationStrength = (acr && STRENGTH_BY_ACR[acr]) || "single_factor";
  const authTime = num(c.auth_time);

  const identity: VerifiedIdentity = {
    issuer: issuer.issuer,
    subject,
    audiences,
    issuedAt: new Date((iat ?? now) * 1000),
    expiresAt: new Date((exp ?? now) * 1000),
    notBefore: nbf !== null ? new Date(nbf * 1000) : null,
    authenticationTime: authTime !== null ? new Date(authTime * 1000) : null,
    authenticationMethods: Array.isArray(c.amr) ? (c.amr as string[]) : [],
    authenticationStrength: strength,
    credentialId: typeof jti === "string" ? jti : null,
    nonce: typeof nonce === "string" ? nonce : null,
    verificationKeyId: keyId,
    verificationPolicyVersion: issuer.policyVersion,
    rawClaimsDigest: digestOf(c),
  };
  return { ok: true, identity };
}

/** Map a key-resolution status to a failure class, or null when resolved. */
function mapKeyResolution(r: VerificationKeyResolution): JwtVerificationFailure | null {
  switch (r.status) {
    case "resolved": return null;
    case "key_id_missing": return "missing_key_id";
    case "issuer_unknown": return "unsupported_issuer";
    case "key_unknown": return "unknown_key";
    case "ambiguous_key": return "ambiguous_key";
    case "algorithm_key_mismatch": return "key_type_mismatch";
    case "invalid_key_material": return "key_type_mismatch";
    case "keys_unavailable": return "keys_unavailable";
    case "keys_stale": return "keys_stale";
    case "refresh_failed": return "jwks_refresh_failed";
    default: return "internal_verification_error";
  }
}

// ---------------------------------------------------------------------------
// S3 boundary adapter — lets the JWT verifier drop into AuthenticationBoundary.
// The S3 IdentityVerificationPolicy argument is unused: the JWT verifier carries
// its own JwtVerificationPolicy. The 28-class JWT taxonomy is projected onto the
// 16-class S3 taxonomy (a total mapping) for the boundary path.
// ---------------------------------------------------------------------------

const JWT_TO_S3: Record<JwtVerificationFailure, IdentityVerificationFailure> = {
  assertion_too_large: "malformed_credential",
  malformed_jwt: "malformed_credential",
  unsupported_issuer: "unsupported_issuer",
  issuer_disabled: "unsupported_issuer",
  unsupported_algorithm: "unsupported_algorithm",
  missing_key_id: "unknown_key",
  unknown_key: "unknown_key",
  ambiguous_key: "unknown_key",
  key_type_mismatch: "unsupported_algorithm",
  keys_unavailable: "verification_keys_unavailable",
  keys_stale: "verification_keys_unavailable",
  jwks_refresh_failed: "verification_keys_unavailable",
  signature_invalid: "signature_invalid",
  issuer_mismatch: "unsupported_issuer",
  audience_mismatch: "audience_mismatch",
  subject_missing: "subject_missing",
  claims_invalid: "claims_invalid",
  expired: "expired",
  not_yet_valid: "not_yet_valid",
  issued_in_future: "issued_in_future",
  credential_too_old: "expired",
  nonce_missing: "nonce_mismatch",
  nonce_mismatch: "nonce_mismatch",
  jti_missing: "claims_invalid",
  replay_detected: "replay_detected",
  replay_store_unavailable: "verification_keys_unavailable",
  policy_version_mismatch: "policy_version_mismatch",
  internal_verification_error: "malformed_credential",
};

export function mapJwtFailureToS3(reason: JwtVerificationFailure): IdentityVerificationFailure {
  return JWT_TO_S3[reason];
}

export class JwtIdentityVerifierAdapter implements IdentityVerifier {
  constructor(private readonly jwt: JwtIdentityVerifier) {}

  async verify(input: AuthenticationInput, policy: IdentityVerificationPolicy): Promise<IdentityVerificationResult> {
    const r = await this.jwt.verifyAssertion({
      assertion: input.credential,
      ...(input.expectedNonce !== undefined ? { expectedNonce: input.expectedNonce } : {}),
      requestId: input.requestId,
      receivedAt: input.receivedAt,
    });
    if (r.verified) return { verified: true, identity: r.identity };
    return {
      verified: false,
      reason: mapJwtFailureToS3(r.reason),
      evidence: {
        requestId: input.requestId,
        issuerDigest: r.evidence.issuerDigest,
        subjectDigest: null,
        verificationPolicyVersion: r.evidence.verificationPolicyVersion ?? policy.policyVersion,
        verificationKeyId: null,
        at: input.receivedAt,
      },
    };
  }
}
