/**
 * S4C — session-bound CSRF tokens. Keyed (HMAC) and bound to the session id, so a
 * token cannot be forged, transplanted onto another session, or survive rotation.
 */
import { describe, expect, it } from "vitest";
import { mintCsrfToken, verifyCsrfToken } from "./csrf";

const KEY = Buffer.from("csrf-key-0123456789abcdefghijklmn").toString("base64");
const KEY2 = Buffer.from("another-csrf-key-0123456789abcdef").toString("base64");

describe("S4C CSRF tokens", () => {
  it("verifies a token against the session it was minted for", () => {
    const t = mintCsrfToken(KEY, "sess-A");
    expect(verifyCsrfToken(KEY, "sess-A", t)).toBe(true);
  });

  it("rejects a token from another session (session binding)", () => {
    const t = mintCsrfToken(KEY, "sess-A");
    expect(verifyCsrfToken(KEY, "sess-B", t)).toBe(false);
  });

  it("rejects a token after rotation (new session id invalidates the old token)", () => {
    const t = mintCsrfToken(KEY, "sess-old");
    // Rotation yields a new session id; the old token no longer verifies.
    expect(verifyCsrfToken(KEY, "sess-new", t)).toBe(false);
  });

  it("rejects a token forged/verified under a different key", () => {
    const t = mintCsrfToken(KEY, "sess-A");
    expect(verifyCsrfToken(KEY2, "sess-A", t)).toBe(false);
  });

  it("rejects tampered, empty, and malformed tokens", () => {
    const t = mintCsrfToken(KEY, "sess-A");
    expect(verifyCsrfToken(KEY, "sess-A", `${t}x`)).toBe(false);
    expect(verifyCsrfToken(KEY, "sess-A", "")).toBe(false);
    expect(verifyCsrfToken(KEY, "sess-A", undefined)).toBe(false);
    expect(verifyCsrfToken(KEY, "sess-A", "no-dot-token")).toBe(false);
    expect(verifyCsrfToken(KEY, "sess-A", ".onlymac")).toBe(false);
  });

  it("produces distinct tokens on each mint (fresh nonce)", () => {
    expect(mintCsrfToken(KEY, "sess-A")).not.toBe(mintCsrfToken(KEY, "sess-A"));
  });
});
