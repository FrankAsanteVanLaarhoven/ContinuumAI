/**
 * S4A — cached verification-key provider: cache freshness, one-refresh-per-attempt,
 * rotation, removal, staleness bounds, negative caching, single-flight, and
 * key/kid failure classification.
 */
import { beforeAll, describe, expect, it } from "vitest";
import {
  CachedVerificationKeyProvider,
  InMemoryJwksSource,
  type Jwk,
  type JwksCachePolicy,
  type JwksLoadOptions,
  type JwksLoadResult,
  type JwksSource,
  type VerificationKeyRequest,
} from "./index";
import { generateIssuerKey, type TestIssuerKey } from "./jwt-test-support";

const ISS = "https://issuer.test";
const NOW = Date.parse("2026-07-16T00:00:00.000Z");

let ecK1: TestIssuerKey;
let ecK2: TestIssuerKey;

class CountingSource implements JwksSource {
  loads = 0;
  constructor(private readonly inner: InMemoryJwksSource) {}
  load(issuer: string, options: JwksLoadOptions): Promise<JwksLoadResult> {
    this.loads++;
    return this.inner.load(issuer, options);
  }
}

const policy = (over: Partial<JwksCachePolicy> = {}): JwksCachePolicy => ({
  freshLifetimeSeconds: 300, staleGraceSeconds: 0, maxStaleAgeSeconds: 86_400, refreshTimeoutMs: 2000,
  maxResponseBytes: 65_536, maxKeyCount: 32, acceptedKeyTypes: ["RSA", "EC", "OKP"],
  acceptedCurves: ["P-256", "P-384", "P-521", "Ed25519"], negativeCacheSeconds: 30, ...over,
});

function req(kid: string | null, atOffsetSec = 0, algorithm: VerificationKeyRequest["algorithm"] = "ES256"): VerificationKeyRequest {
  return { issuer: ISS, keyId: kid, algorithm, receivedAt: new Date(NOW + atOffsetSec * 1000) };
}

beforeAll(async () => {
  ecK1 = await generateIssuerKey("ES256", "k1");
  ecK2 = await generateIssuerKey("ES256", "k2");
});

describe("S4A cached key provider", () => {
  it("resolves a known kid and reports the key-set version", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy() });
    const r = await p.resolveKey(req("k1"));
    expect(r.status).toBe("resolved");
    if (r.status === "resolved") expect(r.key.keySetVersion).toBe("v1");
  });

  it("triggers exactly one refresh for an unknown kid in a fresh cache", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const src = new CountingSource(inner);
    const p = new CachedVerificationKeyProvider({ source: src, cachePolicy: policy() });
    await p.resolveKey(req("k1"));            // load #1 (fills cache)
    expect(src.loads).toBe(1);
    const r = await p.resolveKey(req("k9"));  // unknown kid → exactly one refresh
    expect(src.loads).toBe(2);
    expect(r.status).toBe("key_unknown");
  });

  it("negative-caches a repeated unknown kid (no refresh amplification)", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const src = new CountingSource(inner);
    const p = new CachedVerificationKeyProvider({ source: src, cachePolicy: policy() });
    await p.resolveKey(req("k1"));
    await p.resolveKey(req("k9"));            // loads → 2, negative-caches k9
    const before = src.loads;
    const r = await p.resolveKey(req("k9", 5)); // still within negativeCacheSeconds
    expect(src.loads).toBe(before);           // no additional refresh
    expect(r.status).toBe("key_unknown");
  });

  it("accepts a rotated-in key after one refresh", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy() });
    await p.resolveKey(req("k1"));
    inner.setKeys(ISS, [ecK1.publicJwk, ecK2.publicJwk], "v2"); // rotation
    const r = await p.resolveKey(req("k2"));
    expect(r.status).toBe("resolved");
    if (r.status === "resolved") expect(r.key.keySetVersion).toBe("v2");
  });

  it("rejects a removed key once the cache is no longer fresh", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy({ freshLifetimeSeconds: 100 }) });
    await p.resolveKey(req("k1"));
    const cachedStillFresh = await p.resolveKey(req("k1", 50)); // served from fresh cache
    expect(cachedStillFresh.status).toBe("resolved");
    inner.setKeys(ISS, [ecK2.publicJwk], "v2"); // k1 removed
    const afterExpiry = await p.resolveKey(req("k1", 200)); // past freshness → refresh → gone
    expect(afterExpiry.status).toBe("key_unknown");
  });

  it("serves a cached key within stale grace when refresh fails", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy({ freshLifetimeSeconds: 100, staleGraceSeconds: 100 }) });
    await p.resolveKey(req("k1"));
    inner.markUnavailable(ISS);
    const r = await p.resolveKey(req("k1", 150)); // past fresh, within grace, refresh fails
    expect(r.status).toBe("resolved");
  });

  it("refuses a cache older than the maximum stale age", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy({ freshLifetimeSeconds: 100, maxStaleAgeSeconds: 200 }) });
    await p.resolveKey(req("k1"));
    inner.markUnavailable(ISS);
    const r = await p.resolveKey(req("k1", 10_000)); // beyond max stale age → refresh → unavailable
    expect(r.status).toBe("keys_unavailable");
  });

  it("classifies a JWKS outage with no cache as keys_unavailable", async () => {
    const inner = new InMemoryJwksSource(); inner.markUnavailable(ISS);
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy() });
    expect((await p.resolveKey(req("k1"))).status).toBe("keys_unavailable");
  });

  it("classifies an oversized/malformed JWKS as refresh_failed", async () => {
    const inner = new InMemoryJwksSource();
    inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    inner.failWithReason(ISS, "too_large");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy() });
    expect((await p.resolveKey(req("k1"))).status).toBe("refresh_failed");
  });

  it("rejects an unsupported key type in the set", async () => {
    const inner = new InMemoryJwksSource();
    inner.setKeys(ISS, [{ kty: "FOO", kid: "k1" } as Jwk], "v1");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy() });
    expect((await p.resolveKey(req("k1"))).status).toBe("refresh_failed");
  });

  it("rejects an ambiguous (duplicate) kid", async () => {
    const inner = new InMemoryJwksSource();
    inner.setKeys(ISS, [ecK1.publicJwk, { ...ecK1.publicJwk } as Jwk], "v1");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy() });
    expect((await p.resolveKey(req("k1"))).status).toBe("ambiguous_key");
  });

  it("requires a key id", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy() });
    expect((await p.resolveKey(req(null))).status).toBe("key_id_missing");
  });

  it("rejects an algorithm/key-type mismatch", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const p = new CachedVerificationKeyProvider({ source: inner, cachePolicy: policy() });
    expect((await p.resolveKey(req("k1", 0, "RS256"))).status).toBe("algorithm_key_mismatch");
  });

  it("coalesces concurrent refreshes into a single load (single-flight)", async () => {
    const inner = new InMemoryJwksSource(); inner.setKeys(ISS, [ecK1.publicJwk], "v1");
    const src = new CountingSource(inner);
    const p = new CachedVerificationKeyProvider({ source: src, cachePolicy: policy() });
    const [a, b, c] = await Promise.all([p.resolveKey(req("k1")), p.resolveKey(req("k1")), p.resolveKey(req("k1"))]);
    expect([a.status, b.status, c.status]).toEqual(["resolved", "resolved", "resolved"]);
    expect(src.loads).toBe(1);
  });
});
