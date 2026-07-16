/**
 * Deterministic identity verifier (development/test ONLY — production must refuse
 * it, see config.ts). It uses a symmetric HMAC "signature" over a JWS-compact
 * credential so tests can mint credentials without asymmetric keys, but it runs
 * through EXACTLY the same shared normalization + policy path as a future real
 * verifier (verification.ts). It therefore exercises every real failure class.
 */
import { constantTimeEqual, hmacSha256Hex } from "../crypto";
import type {
  AuthenticationInput,
  IdentityVerificationPolicy,
  IdentityVerificationResult,
  IdentityVerifier,
  KeyLookup,
  ReplayGuard,
  VerificationKey,
  VerificationKeyProvider,
  VerificationKeySet,
} from "./types";
import {
  algorithmAllowed,
  normalizeAndEnforce,
  parseCredential,
  resolveIssuer,
  verificationEvidence,
  type RawClaims,
} from "./verification";

export const DETERMINISTIC_ALG = "HS256-TEST";

/** In-memory key provider. Models availability, staleness, and key-set versions. */
export class InMemoryVerificationKeyProvider implements VerificationKeyProvider {
  private readonly sets = new Map<string, VerificationKeySet>();
  private readonly unavailable = new Set<string>();

  setKeys(set: VerificationKeySet): void {
    this.sets.set(set.issuer, set);
    this.unavailable.delete(set.issuer);
  }
  markUnavailable(issuer: string): void {
    this.unavailable.add(issuer);
  }

  async getVerificationKeys(issuer: string, at: Date): Promise<KeyLookup> {
    if (this.unavailable.has(issuer)) return { available: false, reason: "unavailable" };
    const set = this.sets.get(issuer);
    if (!set) return { available: false, reason: "unavailable" };
    if (set.staleAfter && at.getTime() > set.staleAfter.getTime()) {
      return { available: false, reason: "stale" };
    }
    return { available: true, keySet: set };
  }
}

/** In-memory single-use guard for credential ids (replay protection in tests). */
export class InMemoryReplayGuard implements ReplayGuard {
  private readonly seen = new Set<string>();
  async checkAndConsume(issuer: string, credentialId: string): Promise<"fresh" | "replayed"> {
    const key = `${issuer}::${credentialId}`;
    if (this.seen.has(key)) return "replayed";
    this.seen.add(key);
    return "fresh";
  }
}

export interface DeterministicVerifierOptions {
  readonly keyProvider: VerificationKeyProvider;
  /** Optional replay guard. When set, credentials carrying a jti are single-use. */
  readonly replayGuard?: ReplayGuard;
}

export class DeterministicIdentityVerifier implements IdentityVerifier {
  private readonly keyProvider: VerificationKeyProvider;
  private readonly replayGuard: ReplayGuard | null;

  constructor(opts: DeterministicVerifierOptions) {
    this.keyProvider = opts.keyProvider;
    this.replayGuard = opts.replayGuard ?? null;
  }

  async verify(
    input: AuthenticationInput,
    policy: IdentityVerificationPolicy,
  ): Promise<IdentityVerificationResult> {
    const deny = (
      reason: Parameters<typeof denyResult>[0],
      ctx: { iss?: string | undefined; sub?: string | undefined; keyId?: string | null } = {},
    ) => denyResult(reason, input, policy, ctx);

    if (!input.credential) return deny("missing_credential");

    const decoded = parseCredential(input.credential);
    if (!decoded) return deny("malformed_credential");

    const claims = decoded.claims as RawClaims;
    const issuer = resolveIssuer(policy, claims.iss);
    if (!issuer) return deny("unsupported_issuer", { iss: typeof claims.iss === "string" ? claims.iss : undefined });

    const iss = issuer.issuer;
    const sub = typeof claims.sub === "string" ? claims.sub : undefined;

    if (!algorithmAllowed(policy, issuer, decoded.header.alg)) {
      return deny("unsupported_algorithm", { iss, sub });
    }

    const lookup = await this.keyProvider.getVerificationKeys(iss, input.receivedAt);
    if (!lookup.available) return deny("verification_keys_unavailable", { iss, sub });

    const key: VerificationKey | undefined = lookup.keySet.keys.find((k) => k.kid === decoded.header.kid);
    if (!key) return deny("unknown_key", { iss, sub });
    if (key.algorithm !== decoded.header.alg) return deny("unsupported_algorithm", { iss, sub, keyId: key.kid });

    const expectedSig = hmacSha256Hex(key.material, decoded.signingInput);
    if (!constantTimeEqual(expectedSig, decoded.signature)) {
      return deny("signature_invalid", { iss, sub, keyId: key.kid });
    }

    const norm = normalizeAndEnforce(decoded, policy, issuer, input, key.kid);
    if (!norm.ok) return deny(norm.reason, { iss, sub, keyId: key.kid });

    // Replay protection (single-use credential id), where applicable.
    if (this.replayGuard && norm.identity.credentialId) {
      const r = await this.replayGuard.checkAndConsume(iss, norm.identity.credentialId);
      if (r === "replayed") return deny("replay_detected", { iss, sub, keyId: key.kid });
    }

    return { verified: true, identity: norm.identity };
  }
}

function denyResult(
  reason: import("./types").IdentityVerificationFailure,
  input: AuthenticationInput,
  policy: IdentityVerificationPolicy,
  ctx: { iss?: string | undefined; sub?: string | undefined; keyId?: string | null },
): IdentityVerificationResult {
  return { verified: false, reason, evidence: verificationEvidence(input, policy, ctx) };
}

// ---------------------------------------------------------------------------
// Test credential minting (test/dev only)
// ---------------------------------------------------------------------------

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}

export interface MintOptions {
  readonly kid: string;
  /** Base64 HMAC secret; must match the key the provider serves for `kid`. */
  readonly keyMaterial: string;
  readonly alg?: string;
  /** Corrupt the signature to exercise signature_invalid. */
  readonly tamperSignature?: boolean;
}

/** Mint a deterministic credential for tests. Claim times are epoch SECONDS. */
export function mintCredential(claims: Record<string, unknown>, opts: MintOptions): string {
  const header = { alg: opts.alg ?? DETERMINISTIC_ALG, kid: opts.kid };
  const signingInput = `${b64url(header)}.${b64url(claims)}`;
  let sig = hmacSha256Hex(opts.keyMaterial, signingInput);
  if (opts.tamperSignature) sig = sig.slice(0, -1) + (sig.endsWith("0") ? "1" : "0");
  return `${signingInput}.${sig}`;
}
