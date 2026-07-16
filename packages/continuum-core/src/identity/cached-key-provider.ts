/**
 * S4A cached verification-key provider. Resolves a verification key for an
 * (issuer, kid, algorithm) from a JWKS source with a bounded, predeclared cache
 * policy:
 *
 *   fresh cache            → use directly
 *   unknown kid, fresh     → ONE bounded refresh, replace + retry once
 *   refresh succeeds       → replace snapshot, retry once
 *   refresh fails          → deny, unless a narrow still-valid stale key applies
 *   beyond max stale age   → deny
 *   repeated unknown kid   → briefly negative-cache to limit refresh amplification
 *
 * At most one refresh happens per verification attempt, and concurrent attempts
 * for the same issuer share a single in-flight refresh (single-flight).
 */
import {
  ALGORITHM_KEY_SHAPE,
  type Jwk,
  type JwksCachePolicy,
  type JwksLoadOptions,
  type JwksLoadResult,
  type JwksSnapshot,
  type JwksSource,
  type JwtVerificationKeyProvider,
  type ResolvedVerificationKey,
  type VerificationKeyRequest,
  type VerificationKeyResolution,
} from "./jwt-types";

interface CacheEntry {
  snapshot: JwksSnapshot;
  fetchedAt: number;
}

export interface CachedKeyProviderOptions {
  readonly source: JwksSource;
  readonly cachePolicy: JwksCachePolicy;
}

export class CachedVerificationKeyProvider implements JwtVerificationKeyProvider {
  private readonly source: JwksSource;
  private readonly policy: JwksCachePolicy;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly negative = new Map<string, number>(); // `${issuer}\0${kid}` → suppress-until (ms)
  private readonly inflight = new Map<string, Promise<JwksLoadResult>>();

  constructor(opts: CachedKeyProviderOptions) {
    this.source = opts.source;
    this.policy = opts.cachePolicy;
  }

  private loadOptions(at: Date): JwksLoadOptions {
    return {
      timeoutMs: this.policy.refreshTimeoutMs,
      maxResponseBytes: this.policy.maxResponseBytes,
      maxKeyCount: this.policy.maxKeyCount,
      acceptedKeyTypes: this.policy.acceptedKeyTypes,
      acceptedCurves: this.policy.acceptedCurves,
      at,
    };
  }

  /** One shared refresh per issuer (single-flight). */
  private async refresh(issuer: string, at: Date): Promise<JwksLoadResult> {
    const existing = this.inflight.get(issuer);
    if (existing) return existing;
    const p = this.source
      .load(issuer, this.loadOptions(at))
      .then((r) => {
        if (r.ok) this.cache.set(issuer, { snapshot: r.snapshot, fetchedAt: at.getTime() });
        return r;
      })
      .finally(() => this.inflight.delete(issuer));
    this.inflight.set(issuer, p);
    return p;
  }

  async resolveKey(request: VerificationKeyRequest): Promise<VerificationKeyResolution> {
    if (request.keyId === null || request.keyId.length === 0) return { status: "key_id_missing" };
    const now = request.receivedAt.getTime();
    const negKey = `${request.issuer}\u0000${request.keyId}`;

    const entry = this.cache.get(request.issuer);
    const ageSeconds = entry ? (now - entry.fetchedAt) / 1000 : Infinity;
    const fresh = entry !== undefined && ageSeconds <= this.policy.freshLifetimeSeconds;

    // 1) Fresh cache: try to resolve directly.
    if (entry && fresh) {
      const direct = this.match(entry.snapshot, request);
      if (direct.status !== "key_unknown") return direct;
      // Unknown kid in a fresh cache — one refresh, unless negatively cached.
      const until = this.negative.get(negKey);
      if (until !== undefined && now < until) return { status: "key_unknown" };
      return this.refreshAndMatch(request, negKey, now);
    }

    // 2) Stale cache within max stale age: try refresh, fall back to a narrow stale key.
    if (entry && ageSeconds <= this.policy.maxStaleAgeSeconds) {
      const refreshed = await this.refresh(request.issuer, request.receivedAt);
      if (refreshed.ok) {
        const m = this.match(refreshed.snapshot, request);
        if (m.status === "key_unknown") this.negative.set(negKey, now + this.policy.negativeCacheSeconds * 1000);
        return m;
      }
      // Refresh failed: only a still-within-grace, already-cached key may verify.
      const withinGrace = ageSeconds <= this.policy.freshLifetimeSeconds + this.policy.staleGraceSeconds;
      if (withinGrace) {
        const m = this.match(entry.snapshot, request);
        if (m.status === "resolved") return m;
      }
      return { status: this.mapRefreshFailure(refreshed) };
    }

    // 3) No cache, or cache beyond max stale age: refresh from scratch.
    if (entry && ageSeconds > this.policy.maxStaleAgeSeconds) {
      // Do not serve keys from a cache older than the policy permits.
      this.cache.delete(request.issuer);
    }
    return this.refreshAndMatch(request, negKey, now);
  }

  private async refreshAndMatch(
    request: VerificationKeyRequest,
    negKey: string,
    now: number,
  ): Promise<VerificationKeyResolution> {
    const refreshed = await this.refresh(request.issuer, request.receivedAt);
    if (!refreshed.ok) return { status: this.mapRefreshFailure(refreshed) };
    const m = this.match(refreshed.snapshot, request);
    if (m.status === "key_unknown") this.negative.set(negKey, now + this.policy.negativeCacheSeconds * 1000);
    return m;
  }

  private mapRefreshFailure(r: JwksLoadResult): Exclude<VerificationKeyResolution["status"], "resolved"> {
    if (r.ok) return "keys_unavailable";
    switch (r.reason) {
      case "issuer_unknown":
        return "issuer_unknown";
      case "unavailable":
        return "keys_unavailable";
      default:
        return "refresh_failed"; // refresh_failed | too_large | malformed | empty | unsupported_key_type
    }
  }

  /** Match a kid within a snapshot and enforce algorithm/key-type agreement. */
  private match(snapshot: JwksSnapshot, request: VerificationKeyRequest): VerificationKeyResolution {
    const candidates = snapshot.keys.filter((k) => k.kid === request.keyId);
    if (candidates.length === 0) return { status: "key_unknown" };
    if (candidates.length > 1) return { status: "ambiguous_key" };
    const jwk = candidates[0] as Jwk;

    const shape = ALGORITHM_KEY_SHAPE[request.algorithm];
    if (jwk.kty !== shape.kty) return { status: "algorithm_key_mismatch" };
    if (shape.crv !== undefined && jwk.crv !== shape.crv) return { status: "algorithm_key_mismatch" };
    // If the key pins an algorithm, it must equal the requested one.
    if (typeof jwk.alg === "string" && jwk.alg !== request.algorithm) return { status: "algorithm_key_mismatch" };

    const key: ResolvedVerificationKey = {
      kid: request.keyId as string,
      algorithm: request.algorithm,
      jwk: jwk as JsonWebKey,
      keySetVersion: snapshot.version,
      keySetDigest: snapshot.digest,
    };
    return { status: "resolved", key };
  }
}
