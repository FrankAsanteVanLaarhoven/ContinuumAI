/** S3 — session-credential digest: keyed, bound to the session id, digest-only. */
import { describe, expect, it } from "vitest";
import {
  computeDigest,
  decodeCredential,
  encodeCredential,
  newSessionSecret,
  verifyDigest,
  type SessionDigestKeys,
} from "./index";

const keys: SessionDigestKeys = {
  currentVersion: "v1",
  keys: { v1: Buffer.from("digest-key-v1-0123456789abcdef").toString("base64"), v2: Buffer.from("digest-key-v2").toString("base64") },
};

describe("S3 session-credential digest", () => {
  it("encode/decode round-trips and rejects malformed values", () => {
    const c = encodeCredential("sid-1", "secret-abc");
    expect(decodeCredential(c)).toEqual({ sessionId: "sid-1", secret: "secret-abc" });
    expect(decodeCredential("nodot")).toBeNull();
    expect(decodeCredential(".leading")).toBeNull();
    expect(decodeCredential("trailing.")).toBeNull();
  });

  it("a fresh secret is high-entropy and unique", () => {
    const a = newSessionSecret(), b = newSessionSecret();
    expect(a).not.toBe(b);
    expect(a.length).toBeGreaterThanOrEqual(40);
  });

  it("the digest is keyed and verifies only for the correct secret", () => {
    const d = computeDigest(keys, "v1", "sid-1", "secret-abc");
    expect(d).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyDigest(keys, "v1", "sid-1", "secret-abc", d)).toBe(true);
    expect(verifyDigest(keys, "v1", "sid-1", "WRONG", d)).toBe(false);
  });

  it("the digest is BOUND to the session id (cannot be transplanted)", () => {
    const d = computeDigest(keys, "v1", "sid-1", "secret-abc");
    expect(verifyDigest(keys, "v1", "sid-2", "secret-abc", d)).toBe(false);
  });

  it("an unavailable digest-key version fails closed (no verification)", () => {
    const d = computeDigest(keys, "v1", "sid-1", "secret-abc");
    expect(verifyDigest(keys, "v-missing", "sid-1", "secret-abc", d)).toBe(false);
  });

  it("different key versions produce different digests for the same input", () => {
    expect(computeDigest(keys, "v1", "sid", "s")).not.toBe(computeDigest(keys, "v2", "sid", "s"));
  });
});
