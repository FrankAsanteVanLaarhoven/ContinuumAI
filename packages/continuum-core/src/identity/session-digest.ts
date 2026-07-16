/**
 * Session-credential digest construction.
 *
 * A session credential is an OPAQUE bearer value `${sessionId}.${secret}`, where
 * `secret` is high-entropy random. Only a KEYED digest of it is ever persisted —
 * never the raw value. The digest is HMAC(key[version], `${sessionId}:${secret}`),
 * so the stored digest is useless without the server-side key, and it is bound to
 * the session id (a digest cannot be transplanted onto another session). Digest
 * keys are versioned so they can be rotated without invalidating existing digests
 * (each row records the version it was computed under).
 */
import { randomBytes } from "node:crypto";
import { constantTimeEqual, hmacSha256Hex } from "../crypto";

export interface SessionDigestKeys {
  readonly currentVersion: string;
  /** version → base64 HMAC key. Older versions retained so old sessions validate. */
  readonly keys: Readonly<Record<string, string>>;
}

/** Fresh opaque session secret (32 bytes, base64url). */
export function newSessionSecret(): string {
  return randomBytes(32).toString("base64url");
}

export function encodeCredential(sessionId: string, secret: string): string {
  return `${sessionId}.${secret}`;
}

export function decodeCredential(value: string): { sessionId: string; secret: string } | null {
  const dot = value.indexOf(".");
  if (dot <= 0 || dot === value.length - 1) return null;
  return { sessionId: value.slice(0, dot), secret: value.slice(dot + 1) };
}

export function computeDigest(keys: SessionDigestKeys, version: string, sessionId: string, secret: string): string {
  const key = keys.keys[version];
  if (!key) throw new Error(`session digest key version '${version}' is not available`);
  return hmacSha256Hex(key, `${sessionId}:${secret}`);
}

/** Constant-time verification of a presented secret against a stored digest. */
export function verifyDigest(
  keys: SessionDigestKeys,
  version: string,
  sessionId: string,
  secret: string,
  storedDigest: string,
): boolean {
  const key = keys.keys[version];
  if (!key) return false; // digest key version unavailable ⇒ fail closed
  return constantTimeEqual(hmacSha256Hex(key, `${sessionId}:${secret}`), storedDigest);
}
