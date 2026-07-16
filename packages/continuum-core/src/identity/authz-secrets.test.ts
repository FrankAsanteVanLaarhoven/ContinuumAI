/** S4B — state/nonce/PKCE generation, keyed digests, and the protected-secret store. */
import { describe, expect, it } from "vitest";
import {
  digestEquals,
  generateNonceValue,
  generatePkceVerifier,
  generateStateValue,
  isValidPkceVerifier,
  nonceDigest,
  pkceChallengeS256,
  stateDigest,
  TestProtectedSecretStore,
  transactionDigest,
} from "./index";

const KEY = Buffer.from("authz-digest-key-0123456789abcdef").toString("base64");
const SECRET_KEYS = { currentVersion: "p1", keys: { p1: Buffer.from("protected-secret-key-32byteslong").toString("base64"), p2: Buffer.from("second-protected-key-32byteslong").toString("base64") } };

describe("S4B secret generation", () => {
  it("state and nonce are high-entropy (>=128 bits) and unique", () => {
    const a = generateStateValue(), b = generateStateValue();
    expect(a).not.toBe(b);
    expect(a.length).toBeGreaterThanOrEqual(43); // 32 bytes → 43 base64url chars
    expect(generateNonceValue()).not.toBe(generateNonceValue());
  });

  it("PKCE verifier is valid and the S256 challenge matches", () => {
    const v = generatePkceVerifier();
    expect(isValidPkceVerifier(v)).toBe(true);
    expect(pkceChallengeS256(v)).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pkceChallengeS256(v)).toBe(pkceChallengeS256(v));
    // RFC 7636 test vector.
    expect(pkceChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    expect(isValidPkceVerifier("short")).toBe(false);
  });

  it("digests are deterministic, keyed and distinct by kind", () => {
    expect(stateDigest(KEY, "s")).toMatch(/^[0-9a-f]{64}$/);
    expect(stateDigest(KEY, "s")).toBe(stateDigest(KEY, "s"));
    expect(stateDigest(KEY, "s")).not.toBe(nonceDigest(KEY, "s"));
    expect(stateDigest(KEY, "s")).not.toBe(transactionDigest(KEY, "s"));
    expect(digestEquals(stateDigest(KEY, "s"), stateDigest(KEY, "s"))).toBe(true);
    expect(digestEquals(stateDigest(KEY, "s"), stateDigest(KEY, "t"))).toBe(false);
  });
});

describe("S4B protected-secret store", () => {
  it("round-trips a verifier and records the key version", () => {
    const store = new TestProtectedSecretStore(SECRET_KEYS);
    const verifier = generatePkceVerifier();
    const p = store.protect(verifier);
    expect(p.keyVersion).toBe("p1");
    expect(p.ciphertext).not.toContain(verifier);
    expect(store.reveal(p.ciphertext, p.keyVersion)).toBe(verifier);
  });

  it("fails closed on an unknown key version or tampered ciphertext", () => {
    const store = new TestProtectedSecretStore(SECRET_KEYS);
    const p = store.protect("secret-verifier-value");
    expect(store.reveal(p.ciphertext, "p9")).toBeNull();
    const tampered = Buffer.from(p.ciphertext, "base64");
    const last = tampered.length - 1;
    tampered[last] = (tampered[last] ?? 0) ^ 0xff;
    expect(store.reveal(tampered.toString("base64"), p.keyVersion)).toBeNull();
  });
});
