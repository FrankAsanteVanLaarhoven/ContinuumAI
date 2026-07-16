/**
 * TEST-ONLY support for S4A. NOT part of the public API (not exported from
 * index.ts) and never used on any production path. Generates real asymmetric
 * keys and mints real signed JWTs with `jose` so the verifier is exercised
 * against genuine signatures rather than a stand-in.
 */
import { CompactSign, exportJWK, generateKeyPair, SignJWT } from "jose";
import type { Jwk, JwtAlgorithm } from "./jwt-types";

export interface TestIssuerKey {
  readonly kid: string;
  readonly alg: JwtAlgorithm;
  readonly privateKey: CryptoKey;
  readonly publicJwk: Jwk;
}

/** Generate one signing key + its public JWK (with kid + alg). */
export async function generateIssuerKey(alg: JwtAlgorithm, kid: string): Promise<TestIssuerKey> {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const jwk = (await exportJWK(publicKey)) as Record<string, unknown>;
  jwk.kid = kid;
  jwk.alg = alg;
  jwk.use = "sig";
  return { kid, alg, privateKey: privateKey as CryptoKey, publicJwk: jwk as Jwk };
}

/** Mint a signed JWT with an arbitrary payload (so malformed claims can be tested). */
export async function mintJwt(
  key: TestIssuerKey,
  payload: Record<string, unknown>,
  headerOverride?: Record<string, unknown>,
): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: key.alg, kid: key.kid, ...headerOverride })
    .sign(key.privateKey);
}

/** Sign an arbitrary (possibly non-object) payload — for structurally odd tokens. */
export async function mintRaw(key: TestIssuerKey, payloadBytes: Uint8Array, headerOverride?: Record<string, unknown>): Promise<string> {
  return new CompactSign(payloadBytes)
    .setProtectedHeader({ alg: key.alg, kid: key.kid, ...headerOverride })
    .sign(key.privateKey);
}

/** Flip the last character of the signature segment to corrupt it. */
export function tamperSignature(jwt: string): string {
  const parts = jwt.split(".");
  const sig = parts[2] ?? "";
  parts[2] = sig.slice(0, -1) + (sig.endsWith("A") ? "B" : "A");
  return parts.join(".");
}

/** Replace the payload segment while keeping the original signature (payload tamper). */
export function tamperPayload(jwt: string, newPayload: Record<string, unknown>): string {
  const parts = jwt.split(".");
  parts[1] = Buffer.from(JSON.stringify(newPayload), "utf8").toString("base64url");
  return parts.join(".");
}
