/**
 * Cryptographic primitives for Continuum.
 *
 * Deliberately thin and standards-only. We use Node's OpenSSL-backed Ed25519
 * for detached signatures and SHA-256 for the tamper-evident hash chain.
 * No bespoke cryptography is invented here — this is the whole point of a
 * narrow, auditable trusted computing base. When these primitives are later
 * extracted into the Rust `security-core/` crate (v0.6+), the interface below
 * is the contract that must be preserved.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

export interface Ed25519Keypair {
  publicKeyPem: string;
  privateKeyPem: string;
}

/** Generate an Ed25519 keypair encoded as SPKI/PKCS8 PEM. */
export function generateEd25519(): Ed25519Keypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

/** SHA-256 over a UTF-8 string or buffer, hex-encoded. */
export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Detached Ed25519 signature over a UTF-8 message, base64-encoded. */
export function signEd25519(privateKeyPem: string, message: string): string {
  const key = createPrivateKey(privateKeyPem);
  return nodeSign(null, Buffer.from(message, "utf8"), key).toString("base64");
}

/** Verify a base64 Ed25519 signature. Never throws — returns false on any error. */
export function verifyEd25519(
  publicKeyPem: string,
  message: string,
  signatureB64: string,
): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    return nodeVerify(
      null,
      Buffer.from(message, "utf8"),
      key,
      Buffer.from(signatureB64, "base64"),
    );
  } catch {
    return false;
  }
}

/** Short stable fingerprint of a public key PEM, for display and holder binding. */
export function keyFingerprint(publicKeyPem: string): string {
  return `ed25519:${sha256Hex(publicKeyPem.trim()).slice(0, 16)}`;
}

/**
 * Deterministic JSON canonicalization (sorted object keys, no incidental
 * whitespace). Two structurally-equal values always produce identical bytes,
 * which is required so signatures and chain hashes are reproducible across
 * processes and languages.
 */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const body = keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(",");
  return `{${body}}`;
}

/** Convenience: SHA-256 over the canonical form of a value. */
export function digestOf(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}
