/**
 * Phase 3 S4C — session-bound CSRF tokens.
 *
 * The token is a cryptographically bound double-submit value: `nonce.mac`, where
 * `mac = HMAC(csrfKey, "csrf:" + sessionId + ":" + nonce)`. Because the MAC is keyed
 * by a server-side secret AND bound to the session id, a token cannot be forged
 * without the key, cannot be transplanted onto another session, and is invalidated
 * automatically when the session rotates (the new session id yields a different MAC).
 * The controller additionally enforces the double-submit cookie==header equality and
 * an origin/referer check — a plain identical cookie/header compare is never relied
 * on by itself.
 */
import { randomBytes } from "node:crypto";
import { constantTimeEqual, hmacSha256Hex } from "../crypto";

function mac(key: string, sessionId: string, nonce: string): string {
  return hmacSha256Hex(key, `csrf:${sessionId}:${nonce}`);
}

/** Mint a fresh session-bound CSRF token. */
export function mintCsrfToken(key: string, sessionId: string): string {
  const nonce = randomBytes(18).toString("base64url");
  return `${nonce}.${mac(key, sessionId, nonce)}`;
}

/** Verify a CSRF token against the current session id (constant-time). */
export function verifyCsrfToken(key: string, sessionId: string, token: string | undefined | null): boolean {
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot <= 0 || dot === token.length - 1) return false;
  const nonce = token.slice(0, dot);
  const presented = token.slice(dot + 1);
  return constantTimeEqual(mac(key, sessionId, nonce), presented);
}
