/**
 * S4A — real JWT/JWS verifier: cryptographic verification, issuer & audience,
 * temporal claims, and claim validation. Uses genuine `jose` signatures.
 */
import { beforeAll, describe, expect, it } from "vitest";
import {
  CachedVerificationKeyProvider,
  DEFAULT_JWKS_CACHE_POLICY,
  DEFAULT_JWT_LIMITS,
  InMemoryDurableReplayLedger,
  InMemoryJwksSource,
  JwtIdentityVerifier,
  type Jwk,
  type JwtAuthenticationInput,
  type JwtIssuerPolicy,
  type JwtVerificationPolicy,
} from "./index";
import { generateIssuerKey, mintJwt, tamperPayload, tamperSignature, type TestIssuerKey } from "./jwt-test-support";

const ISS = "https://issuer.test";
const AUD = "continuum";
const NOW = Date.parse("2026-07-16T00:00:00.000Z");
const nowSec = Math.floor(NOW / 1000);
const REPLAY_KEY = Buffer.from("replay-digest-key-0123456789abcdef").toString("base64");

let ecK1: TestIssuerKey;
let ecK2: TestIssuerKey;
let rsaUnderK1: TestIssuerKey; // RSA key material published under kid "k1"

function issuerPolicy(over: Partial<JwtIssuerPolicy> = {}): JwtIssuerPolicy {
  return {
    issuer: ISS, audiences: [AUD], allowedAlgorithms: ["ES256"], keyProviderId: "kp", enabled: true,
    requireSubject: true, requireIssuedAt: true, requireExpiration: true, requireNonceWhenExpected: true,
    maximumCredentialAgeSeconds: 3600, maximumClockSkewSeconds: 60, replayPolicy: "none",
    policyVersion: "jwt-policy-v1", ...over,
  };
}

function setup(opts: { issuer?: Partial<JwtIssuerPolicy>; keys?: readonly Jwk[]; replay?: boolean } = {}) {
  const source = new InMemoryJwksSource();
  source.setKeys(ISS, opts.keys ?? [ecK1.publicJwk], "v1");
  const provider = new CachedVerificationKeyProvider({ source, cachePolicy: DEFAULT_JWKS_CACHE_POLICY });
  const policy: JwtVerificationPolicy = { issuers: [issuerPolicy(opts.issuer)], limits: DEFAULT_JWT_LIMITS };
  const verifier = new JwtIdentityVerifier({
    policy, keyProvider: provider,
    ...(opts.replay ? { replayLedger: new InMemoryDurableReplayLedger(), replayDigestKey: REPLAY_KEY } : {}),
  });
  return { source, provider, verifier };
}

function input(assertion: string, over: Partial<JwtAuthenticationInput> = {}): JwtAuthenticationInput {
  return { assertion, requestId: "req-1", receivedAt: new Date(NOW), ...over };
}

const baseClaims = (over: Record<string, unknown> = {}) => ({
  iss: ISS, sub: "user-1", aud: AUD, iat: nowSec - 10, exp: nowSec + 600, ...over,
});

beforeAll(async () => {
  ecK1 = await generateIssuerKey("ES256", "k1");
  ecK2 = await generateIssuerKey("ES256", "k2");
  const rsa = await generateIssuerKey("RS256", "k1"); // same kid, wrong type
  rsaUnderK1 = rsa;
});

describe("S4A cryptographic verification", () => {
  it("accepts a valid signature and normalizes the identity", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims())));
    expect(r.verified).toBe(true);
    if (r.verified) {
      expect(r.identity.issuer).toBe(ISS);
      expect(r.identity.subject).toBe("user-1");
      expect(r.identity.verificationKeyId).toBe("k1");
      expect(r.evidence.keySetVersion).toBe("v1");
    }
  });

  it("rejects an altered payload (signature over original bytes)", async () => {
    const { verifier } = setup();
    const jwt = await mintJwt(ecK1, baseClaims());
    const r = await verifier.verifyAssertion(input(tamperPayload(jwt, baseClaims({ sub: "attacker" }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("signature_invalid");
  });

  it("rejects an altered protected header", async () => {
    const { verifier } = setup();
    const jwt = await mintJwt(ecK1, baseClaims());
    const parts = jwt.split(".");
    parts[0] = Buffer.from(JSON.stringify({ alg: "ES256", kid: "k1", injected: true }), "utf8").toString("base64url");
    const r = await verifier.verifyAssertion(input(parts.join(".")));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("signature_invalid");
  });

  it("rejects an unsigned (alg=none) token", async () => {
    const { verifier } = setup();
    const h = Buffer.from(JSON.stringify({ alg: "none", kid: "k1" }), "utf8").toString("base64url");
    const p = Buffer.from(JSON.stringify(baseClaims()), "utf8").toString("base64url");
    const r = await verifier.verifyAssertion(input(`${h}.${p}.AAAA`));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("unsupported_algorithm");
  });

  it("rejects a symmetric-algorithm substitution (HS256)", async () => {
    const { verifier } = setup();
    const h = Buffer.from(JSON.stringify({ alg: "HS256", kid: "k1" }), "utf8").toString("base64url");
    const p = Buffer.from(JSON.stringify(baseClaims()), "utf8").toString("base64url");
    const r = await verifier.verifyAssertion(input(`${h}.${p}.AAAA`));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("unsupported_algorithm");
  });

  it("rejects a token signed with the wrong key", async () => {
    const { verifier } = setup(); // provider serves ecK1
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK2, baseClaims(), { kid: "k1" })));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("signature_invalid");
  });

  it("rejects a key-type mismatch (RSA key for an ES256 header)", async () => {
    const { verifier } = setup({ keys: [rsaUnderK1.publicJwk] }); // kid k1 is RSA
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims())));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("key_type_mismatch");
  });

  it("rejects an algorithm outside the issuer allowlist", async () => {
    const { verifier } = setup({ issuer: { allowedAlgorithms: ["ES256"] }, keys: [rsaUnderK1.publicJwk] });
    // Mint a real RS256 token under kid k1; header alg RS256 is not allowed for this issuer.
    const r = await verifier.verifyAssertion(input(await mintJwt(rsaUnderK1, baseClaims())));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("unsupported_algorithm");
  });

  it("does not expose raw claims downstream (only a digest)", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ secret_claim: "leak-me" }))));
    expect(r.verified).toBe(true);
    if (r.verified) {
      expect(JSON.stringify(r.identity)).not.toContain("leak-me");
      expect(r.identity.rawClaimsDigest).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

describe("S4A issuer and audience", () => {
  it("rejects an unknown issuer", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ iss: "https://evil.test" }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("unsupported_issuer");
  });

  it("rejects a non-exact issuer match (trailing slash)", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ iss: `${ISS}/` }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("unsupported_issuer");
  });

  it("rejects a disabled issuer", async () => {
    const { verifier } = setup({ issuer: { enabled: false } });
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims())));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("issuer_disabled");
  });

  it("rejects a wrong audience", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ aud: "someone-else" }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("audience_mismatch");
  });

  it("rejects a malformed audience (number)", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ aud: 5 }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("claims_invalid");
  });

  it("accepts when one of multiple audiences intersects", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ aud: ["other", AUD] }))));
    expect(r.verified).toBe(true);
  });

  it("rejects too many audiences", async () => {
    const { verifier } = setup();
    const aud = Array.from({ length: DEFAULT_JWT_LIMITS.maxAudiences + 1 }, (_, i) => `a${i}`);
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ aud }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("claims_invalid");
  });
});

describe("S4A temporal claims", () => {
  it("rejects an expired token", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ exp: nowSec - 1000 }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("expired");
  });

  it("rejects a not-yet-valid token", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ nbf: nowSec + 1000 }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("not_yet_valid");
  });

  it("rejects a future-issued token beyond skew", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ iat: nowSec + 10000 }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("issued_in_future");
  });

  it("rejects a token older than the maximum credential age", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ iat: nowSec - 100000, exp: nowSec + 600 }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("credential_too_old");
  });

  it("honors the clock-skew boundary", async () => {
    const { verifier } = setup({ issuer: { maximumClockSkewSeconds: 60 } });
    const atEdge = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ iat: nowSec + 60 }))));
    expect(atEdge.verified).toBe(true);
    const past = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ iat: nowSec + 61 }))));
    expect(past.verified).toBe(false);
    if (!past.verified) expect(past.reason).toBe("issued_in_future");
  });
});

describe("S4A claim validation", () => {
  it("rejects a missing subject", async () => {
    const { verifier } = setup();
    const c = baseClaims(); delete (c as Record<string, unknown>).sub;
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, c)));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("subject_missing");
  });

  it("rejects an empty subject", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ sub: "" }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("subject_missing");
  });

  it("rejects a wrong claim type (exp as text)", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ exp: "soon" }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("claims_invalid");
  });

  it("rejects a policy-version mismatch", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ pv: "some-other-version" }))));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("policy_version_mismatch");
  });

  it("enforces nonce presence and match when expected", async () => {
    const { verifier } = setup({ issuer: { replayPolicy: "nonce" }, replay: true });
    const missing = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims()), { expectedNonce: "n1" }));
    expect(missing.verified).toBe(false);
    if (!missing.verified) expect(missing.reason).toBe("nonce_missing");
    const wrong = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ nonce: "n2" })), { expectedNonce: "n1" }));
    expect(wrong.verified).toBe(false);
    if (!wrong.verified) expect(wrong.reason).toBe("nonce_mismatch");
    const ok = await verifier.verifyAssertion(input(await mintJwt(ecK1, baseClaims({ nonce: "n1" })), { expectedNonce: "n1" }));
    expect(ok.verified).toBe(true);
  });

  it("rejects an oversized assertion before parsing", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input("x".repeat(DEFAULT_JWT_LIMITS.maxAssertionLength + 1)));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("assertion_too_large");
  });

  it("rejects a structurally malformed assertion", async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAssertion(input("not-a-jwt"));
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.reason).toBe("malformed_jwt");
  });
});
