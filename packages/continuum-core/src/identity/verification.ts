/**
 * Shared credential parsing, normalization and policy enforcement.
 *
 * Every IdentityVerifier — the deterministic one here and any future real one —
 * MUST run through these functions so that normalization and policy evaluation
 * are identical regardless of the signature scheme. Only the signature check
 * itself is verifier-specific. Verification errors are returned as distinct
 * failure classes and are never collapsed into a success-with-warning path.
 */
import { sha256Hex } from "../crypto";
import type { AuthenticationStrength } from "../async/context";
import type {
  AuthenticationEvidence,
  AuthenticationInput,
  IdentityVerificationFailure,
  IdentityVerificationPolicy,
  IssuerPolicy,
  VerifiedIdentity,
} from "./types";

/** JWS-compact-shaped credential (base64url(header).base64url(claims).base64(sig)). */
export interface DecodedCredential {
  readonly header: { readonly alg: string; readonly kid: string };
  readonly claims: RawClaims;
  readonly signingInput: string;
  readonly signature: string;
}

export interface RawClaims {
  readonly iss?: unknown;
  readonly sub?: unknown;
  readonly aud?: unknown;
  readonly iat?: unknown;
  readonly exp?: unknown;
  readonly nbf?: unknown;
  readonly auth_time?: unknown;
  readonly amr?: unknown;
  readonly acr?: unknown;
  readonly jti?: unknown;
  readonly nonce?: unknown;
  /** Policy version the credential was minted under (optional). */
  readonly pv?: unknown;
  readonly [k: string]: unknown;
}

function b64urlDecode(s: string): string {
  return Buffer.from(s, "base64url").toString("utf8");
}

/** Parse the compact credential. Returns null on any structural error. */
export function parseCredential(credential: string): DecodedCredential | null {
  const parts = credential.split(".");
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts as [string, string, string];
  try {
    const header = JSON.parse(b64urlDecode(h));
    const claims = JSON.parse(b64urlDecode(p));
    if (typeof header?.alg !== "string" || typeof header?.kid !== "string") return null;
    if (typeof claims !== "object" || claims === null) return null;
    return { header, claims, signingInput: `${h}.${p}`, signature: sig };
  } catch {
    return null;
  }
}

export function resolveIssuer(policy: IdentityVerificationPolicy, iss: unknown): IssuerPolicy | null {
  if (typeof iss !== "string" || iss.length === 0) return null;
  const p = policy.allowedIssuers.find((i) => i.issuer === iss);
  return p && p.enabled ? p : null;
}

/** The algorithm must be in BOTH the global and the issuer allowlist. Never trust
 *  an algorithm selected solely from the credential header. */
export function algorithmAllowed(policy: IdentityVerificationPolicy, issuer: IssuerPolicy, alg: string): boolean {
  return policy.allowedAlgorithms.includes(alg) && issuer.allowedAlgorithms.includes(alg);
}

const STRENGTH_BY_ACR: Record<string, AuthenticationStrength> = {
  mfa: "multi_factor",
  multi_factor: "multi_factor",
  attested_workload: "attested_workload",
  pwd: "single_factor",
  single_factor: "single_factor",
};

function toAudiences(aud: unknown): string[] | null {
  if (typeof aud === "string") return [aud];
  if (Array.isArray(aud) && aud.every((a) => typeof a === "string")) return aud as string[];
  if (aud === undefined) return [];
  return null; // malformed
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export function issuerDigest(iss: string): string {
  return sha256Hex(`iss:${iss}`).slice(0, 32);
}
export function subjectDigest(iss: string, sub: string): string {
  return sha256Hex(`sub:${iss}:${sub}`).slice(0, 32);
}

export function verificationEvidence(
  input: AuthenticationInput,
  policy: IdentityVerificationPolicy,
  ctx: { iss?: string | undefined; sub?: string | undefined; keyId?: string | null },
): AuthenticationEvidence {
  return {
    requestId: input.requestId,
    issuerDigest: ctx.iss ? issuerDigest(ctx.iss) : null,
    subjectDigest: ctx.iss && ctx.sub ? subjectDigest(ctx.iss, ctx.sub) : null,
    verificationPolicyVersion: policy.policyVersion,
    verificationKeyId: ctx.keyId ?? null,
    at: input.receivedAt,
  };
}

export type NormalizeOutcome =
  | { readonly ok: true; readonly identity: VerifiedIdentity }
  | { readonly ok: false; readonly reason: IdentityVerificationFailure };

/**
 * Normalize the decoded claims into a VerifiedIdentity and enforce the policy's
 * temporal, audience, subject, nonce and claim-shape rules. The signature is
 * assumed already verified by the caller; `keyId` is the verifying key. `now`
 * is `input.receivedAt`.
 */
export function normalizeAndEnforce(
  decoded: DecodedCredential,
  policy: IdentityVerificationPolicy,
  issuer: IssuerPolicy,
  input: AuthenticationInput,
  keyId: string,
): NormalizeOutcome {
  const c = decoded.claims;
  const now = Math.floor(input.receivedAt.getTime() / 1000);
  const skew = policy.maximumClockSkewSeconds;

  const iss = c.iss as string; // validated by resolveIssuer before this point
  const sub = c.sub;
  if (typeof sub !== "string" || sub.length === 0) return { ok: false, reason: "subject_missing" };

  // Structural claim validity.
  const audiences = toAudiences(c.aud);
  if (audiences === null) return { ok: false, reason: "claims_invalid" };
  for (const key of ["iat", "exp", "nbf", "auth_time"] as const) {
    if (c[key] !== undefined && num(c[key]) === null) return { ok: false, reason: "claims_invalid" };
  }
  if (c.amr !== undefined && !(Array.isArray(c.amr) && c.amr.every((m) => typeof m === "string"))) {
    return { ok: false, reason: "claims_invalid" };
  }

  // Policy version (if the credential names one, it must match).
  if (c.pv !== undefined && c.pv !== policy.policyVersion) return { ok: false, reason: "policy_version_mismatch" };

  // Audience: at least one credential audience must be allowed for this issuer.
  const audOk = audiences.some((a) => issuer.allowedAudiences.includes(a));
  if (!audOk) return { ok: false, reason: "audience_mismatch" };

  // Temporal.
  const iat = num(c.iat);
  if (policy.requireIssuedAt && iat === null) return { ok: false, reason: "claims_invalid" };
  if (iat !== null && iat > now + skew) return { ok: false, reason: "issued_in_future" };
  if (iat !== null && now - iat > policy.maximumCredentialAgeSeconds) return { ok: false, reason: "expired" };

  const exp = num(c.exp);
  if (policy.requireExpiration && exp === null) return { ok: false, reason: "claims_invalid" };
  if (exp !== null && now > exp + skew) return { ok: false, reason: "expired" };

  const nbf = num(c.nbf);
  if (nbf !== null && now < nbf - skew) return { ok: false, reason: "not_yet_valid" };

  // Nonce (when the caller expected one and policy requires it).
  if (input.expectedNonce !== undefined && policy.requireNonceWhenExpected) {
    if (c.nonce !== input.expectedNonce) return { ok: false, reason: "nonce_mismatch" };
  }

  const acr = typeof c.acr === "string" ? c.acr : null;
  const strength: AuthenticationStrength = (acr && STRENGTH_BY_ACR[acr]) || "single_factor";
  const authTime = num(c.auth_time);

  const identity: VerifiedIdentity = {
    issuer: iss,
    subject: sub,
    audiences,
    issuedAt: new Date((iat ?? now) * 1000),
    expiresAt: new Date((exp ?? now) * 1000),
    notBefore: nbf !== null ? new Date(nbf * 1000) : null,
    authenticationTime: authTime !== null ? new Date(authTime * 1000) : null,
    authenticationMethods: Array.isArray(c.amr) ? (c.amr as string[]) : [],
    authenticationStrength: strength,
    credentialId: typeof c.jti === "string" ? c.jti : null,
    nonce: typeof c.nonce === "string" ? c.nonce : null,
    verificationKeyId: keyId,
    verificationPolicyVersion: policy.policyVersion,
    rawClaimsDigest: sha256Hex(decoded.signingInput),
  };
  return { ok: true, identity };
}
