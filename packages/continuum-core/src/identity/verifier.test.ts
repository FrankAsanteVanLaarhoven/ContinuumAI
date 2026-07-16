/**
 * S3 — deterministic identity verifier: every failure class + normalization.
 * Verification errors are distinct classes, never collapsed into success.
 */
import { describe, expect, it } from "vitest";
import {
  DETERMINISTIC_ALG,
  DeterministicIdentityVerifier,
  InMemoryReplayGuard,
  InMemoryVerificationKeyProvider,
  externalIdentityKey,
  mintCredential,
  type IdentityVerificationPolicy,
  type VerificationKeySet,
} from "./index";

const KEY = Buffer.from("test-hmac-secret-key-0123456789abcdef").toString("base64");
const KID = "k1";
const ISS = "https://issuer.test";
const AUD = "continuum";
const NOW = Date.parse("2026-07-16T00:00:00.000Z");
const nowSec = Math.floor(NOW / 1000);

function keySet(over: Partial<VerificationKeySet> = {}): VerificationKeySet {
  return {
    issuer: ISS, version: "v1",
    keys: [{ kid: KID, algorithm: DETERMINISTIC_ALG, material: KEY }],
    fetchedAt: new Date(NOW), staleAfter: null, ...over,
  };
}

const policy: IdentityVerificationPolicy = {
  allowedIssuers: [
    { issuer: ISS, allowedAudiences: [AUD], allowedAlgorithms: [DETERMINISTIC_ALG], keySource: { kind: "test", ref: ISS }, enabled: true },
    { issuer: "https://disabled.test", allowedAudiences: [AUD], allowedAlgorithms: [DETERMINISTIC_ALG], keySource: { kind: "test", ref: "x" }, enabled: false },
  ],
  allowedAlgorithms: [DETERMINISTIC_ALG],
  maximumClockSkewSeconds: 60,
  maximumCredentialAgeSeconds: 3600,
  requireIssuedAt: true, requireExpiration: true, requireSubject: true, requireNonceWhenExpected: true,
  policyVersion: "idp-policy-v1",
};

function provider(): InMemoryVerificationKeyProvider {
  const p = new InMemoryVerificationKeyProvider();
  p.setKeys(keySet());
  return p;
}
function verifier(over?: { keys?: InMemoryVerificationKeyProvider; replay?: InMemoryReplayGuard }) {
  return new DeterministicIdentityVerifier({ keyProvider: over?.keys ?? provider(), ...(over?.replay ? { replayGuard: over.replay } : {}) });
}
function input(credential: string, expectedNonce?: string) {
  return { credential, requestId: "req-1", receivedAt: new Date(NOW), ...(expectedNonce ? { expectedNonce } : {}) };
}
function base(over: Record<string, unknown> = {}) {
  return { iss: ISS, sub: "user-123", aud: AUD, iat: nowSec - 10, exp: nowSec + 600, ...over };
}
function mint(claims: Record<string, unknown>, opts: Partial<{ kid: string; keyMaterial: string; alg: string; tamperSignature: boolean }> = {}) {
  return mintCredential(claims, { kid: KID, keyMaterial: KEY, ...opts });
}

async function reason(credential: string, expectedNonce?: string, v = verifier()): Promise<string> {
  const r = await v.verify(input(credential, expectedNonce), policy);
  return r.verified ? "VERIFIED" : r.reason;
}

describe("S3 deterministic identity verifier", () => {
  it("a valid credential normalizes to the expected VerifiedIdentity", async () => {
    const r = await verifier().verify(input(mint(base({ amr: ["pwd", "otp"], acr: "mfa", jti: "j1" }))), policy);
    expect(r.verified).toBe(true);
    if (!r.verified) return;
    expect(r.identity.issuer).toBe(ISS);
    expect(r.identity.subject).toBe("user-123");
    expect(r.identity.audiences).toContain(AUD);
    expect(r.identity.authenticationStrength).toBe("multi_factor");
    expect(r.identity.authenticationMethods).toEqual(["pwd", "otp"]);
    expect(r.identity.verificationPolicyVersion).toBe("idp-policy-v1");
    expect(r.identity.verificationKeyId).toBe(KID);
    expect(r.identity.rawClaimsDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("subject is unique only within an issuer (issuer+subject is the key)", () => {
    expect(externalIdentityKey({ issuer: "a", subject: "s" })).not.toBe(externalIdentityKey({ issuer: "b", subject: "s" }));
    expect(externalIdentityKey({ issuer: "a", subject: "s" })).toBe(externalIdentityKey({ issuer: "a", subject: "s" }));
  });

  it("missing / malformed credentials deny distinctly", async () => {
    expect(await reason("")).toBe("missing_credential");
    expect(await reason("not.a.jwt.extra")).toBe("malformed_credential");
    expect(await reason("only-one-part")).toBe("malformed_credential");
  });

  it("unsupported issuer denies (unknown and disabled)", async () => {
    expect(await reason(mint(base({ iss: "https://unknown.test" })))).toBe("unsupported_issuer");
    expect(await reason(mint(base({ iss: "https://disabled.test" })))).toBe("unsupported_issuer");
  });

  it("unsupported algorithm denies (header alg not in allowlist)", async () => {
    expect(await reason(mint(base(), { alg: "RS256" }))).toBe("unsupported_algorithm");
  });

  it("wrong audience denies", async () => {
    expect(await reason(mint(base({ aud: "other-service" })))).toBe("audience_mismatch");
  });

  it("expired and not-yet-valid credentials deny", async () => {
    expect(await reason(mint(base({ exp: nowSec - 120 })))).toBe("expired");
    expect(await reason(mint(base({ nbf: nowSec + 600 })))).toBe("not_yet_valid");
  });

  it("future-issued beyond skew, and over-age, deny", async () => {
    expect(await reason(mint(base({ iat: nowSec + 600 })))).toBe("issued_in_future");
    expect(await reason(mint(base({ iat: nowSec - 7200 })))).toBe("expired"); // exceeds maximumCredentialAge
  });

  it("unavailable and stale verification keys deny", async () => {
    const p = provider(); p.markUnavailable(ISS);
    expect(await reason(mint(base()), undefined, verifier({ keys: p }))).toBe("verification_keys_unavailable");
    const stale = provider(); stale.setKeys(keySet({ staleAfter: new Date(NOW - 1000) }));
    expect(await reason(mint(base()), undefined, verifier({ keys: stale }))).toBe("verification_keys_unavailable");
  });

  it("unknown key id denies", async () => {
    expect(await reason(mint(base(), { kid: "k-unknown" }))).toBe("unknown_key");
  });

  it("invalid signature denies", async () => {
    expect(await reason(mint(base(), { tamperSignature: true }))).toBe("signature_invalid");
    expect(await reason(mint(base(), { keyMaterial: Buffer.from("wrong-key").toString("base64") }))).toBe("signature_invalid");
  });

  it("nonce mismatch denies where a nonce is expected", async () => {
    expect(await reason(mint(base({ nonce: "N-server" })), "N-client")).toBe("nonce_mismatch");
    expect(await reason(mint(base({ nonce: "N-match" })), "N-match")).toBe("VERIFIED");
  });

  it("replay denies where replay protection applies", async () => {
    const v = verifier({ replay: new InMemoryReplayGuard() });
    const cred = mint(base({ jti: "unique-1" }));
    expect((await v.verify(input(cred), policy)).verified).toBe(true);
    expect(await reason(cred, undefined, v)).toBe("replay_detected");
  });

  it("missing subject, malformed claims, and policy-version mismatch deny distinctly", async () => {
    expect(await reason(mint(base({ sub: undefined })))).toBe("subject_missing");
    expect(await reason(mint(base({ aud: 123 })))).toBe("claims_invalid");
    expect(await reason(mint(base({ iat: "not-a-number" })))).toBe("claims_invalid");
    expect(await reason(mint(base({ pv: "some-other-policy" })))).toBe("policy_version_mismatch");
  });

  it("a verification denial carries redacted evidence (issuer/subject digests, not raw values)", async () => {
    const r = await verifier().verify(input(mint(base({ exp: nowSec - 120 }))), policy);
    expect(r.verified).toBe(false);
    if (r.verified) return;
    expect(r.evidence.issuerDigest).toMatch(/^[0-9a-f]{32}$/);
    expect(r.evidence.subjectDigest).toMatch(/^[0-9a-f]{32}$/);
    expect(JSON.stringify(r.evidence)).not.toContain("user-123");
    expect(JSON.stringify(r.evidence)).not.toContain(ISS);
  });
});
