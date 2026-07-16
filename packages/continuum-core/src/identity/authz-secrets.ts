/**
 * S4B secret generation, keyed digests, PKCE (S256) and a protected-secret store.
 *
 * State and nonce are high-entropy CSPRNG values (256 bits) persisted only as
 * keyed digests. The PKCE verifier must be replayed to the token endpoint at
 * exchange, so it is stored ENCRYPTED-at-rest under a versioned key (never a
 * one-way digest). Digest inputs use `:`-prefixed labels over base64url values
 * (which contain no `:`), so no control-byte delimiter is needed.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { hmacSha256Hex } from "../crypto";

/** 256 bits of CSPRNG entropy, base64url — opaque and unguessable. */
export function generateStateValue(): string {
  return randomBytes(32).toString("base64url");
}
export function generateNonceValue(): string {
  return randomBytes(32).toString("base64url");
}
/** RFC 7636 code_verifier: 43 unreserved chars from 32 random bytes (base64url). */
export function generatePkceVerifier(): string {
  return randomBytes(32).toString("base64url");
}

/** RFC 7636 S256 challenge: BASE64URL(SHA256(ASCII(verifier))). */
export function pkceChallengeS256(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

const PKCE_VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/;
/** Validate a code_verifier's length (43..128) and unreserved character set. */
export function isValidPkceVerifier(v: string): boolean {
  return PKCE_VERIFIER_RE.test(v);
}

export function stateDigest(keyBase64: string, state: string): string {
  return hmacSha256Hex(keyBase64, `authz-state:${state}`);
}
export function nonceDigest(keyBase64: string, nonce: string): string {
  return hmacSha256Hex(keyBase64, `authz-nonce:${nonce}`);
}
export function transactionDigest(keyBase64: string, transactionId: string): string {
  return hmacSha256Hex(keyBase64, `authz-txn:${transactionId}`);
}

/** Constant-time hex-digest comparison (for nonce binding). */
export function digestEquals(a: string, b: string): boolean {
  try {
    const ab = Buffer.from(a, "utf8");
    const bb = Buffer.from(b, "utf8");
    if (ab.length !== bb.length) return false;
    return timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Protected-secret store (encryption-at-rest for the PKCE verifier)
// ---------------------------------------------------------------------------

export interface ProtectedSecret {
  readonly ciphertext: string;
  readonly keyVersion: string;
}

export interface ProtectedSecretStore {
  protect(plaintext: string): ProtectedSecret;
  reveal(ciphertext: string, keyVersion: string): string | null;
}

export interface ProtectedSecretKeys {
  readonly currentVersion: string;
  /** version → base64 32-byte AES-256 key. */
  readonly keys: Record<string, string>;
}

/**
 * Test-protected AES-256-GCM secret store: genuine encryption-at-rest under a
 * versioned key. It is TEST-ONLY (keys are provisioned in-process) and MUST be
 * refused in production, where a KMS/HSM-backed store is required (out of S4B
 * scope). It is never a one-way digest — the PKCE verifier must be recoverable.
 */
export class TestProtectedSecretStore implements ProtectedSecretStore {
  constructor(private readonly keys: ProtectedSecretKeys) {}

  private keyFor(version: string): Buffer | null {
    const b64 = this.keys.keys[version];
    if (!b64) return null;
    const key = Buffer.from(b64, "base64");
    return key.length === 32 ? key : null;
  }

  protect(plaintext: string): ProtectedSecret {
    const version = this.keys.currentVersion;
    const key = this.keyFor(version);
    if (!key) throw new Error("protected-secret current key must be a 32-byte base64 value");
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { ciphertext: Buffer.concat([iv, tag, ct]).toString("base64"), keyVersion: version };
  }

  reveal(ciphertext: string, keyVersion: string): string | null {
    try {
      const key = this.keyFor(keyVersion);
      if (!key) return null;
      const raw = Buffer.from(ciphertext, "base64");
      if (raw.length < 28) return null;
      const iv = raw.subarray(0, 12);
      const tag = raw.subarray(12, 28);
      const ct = raw.subarray(28);
      const d = createDecipheriv("aes-256-gcm", key, iv);
      d.setAuthTag(tag);
      return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
    } catch {
      return null;
    }
  }
}
