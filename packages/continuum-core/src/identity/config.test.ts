/** S3 — identity/session configuration guards are explicit and fail-closed. */
import { describe, expect, it } from "vitest";
import {
  assertProductionIdentityConfig,
  parseSessionDigestKeys,
  resolveIdentityVerifierMode,
  resolveSessionStoreMode,
} from "./index";

const DIGEST = JSON.stringify({ v1: Buffer.from("k").toString("base64") });

describe("S3 config guards", () => {
  it("deterministic verifier is dev/test only; production refuses it", () => {
    expect(resolveIdentityVerifierMode({ NODE_ENV: "development", CONTINUUM_IDENTITY_VERIFIER: "deterministic" })).toBe("deterministic");
    expect(() => resolveIdentityVerifierMode({ NODE_ENV: "production", CONTINUUM_IDENTITY_VERIFIER: "deterministic" })).toThrow(/refused in production/i);
    expect(() => resolveIdentityVerifierMode({ NODE_ENV: "production" })).toThrow(/must be explicitly set/i);
    expect(() => resolveIdentityVerifierMode({ NODE_ENV: "development" })).toThrow(/must be set/i);
  });

  it("session store must be postgres; no memory fallback", () => {
    expect(resolveSessionStoreMode({ CONTINUUM_SESSION_STORE: "postgres" })).toBe("postgres");
    expect(() => resolveSessionStoreMode({ NODE_ENV: "production", CONTINUUM_SESSION_STORE: "memory" })).toThrow(/postgres/i);
    expect(() => resolveSessionStoreMode({ NODE_ENV: "development" })).toThrow(/must be set to postgres/i);
  });

  it("session digest keys must be present and contain the current version", () => {
    const ks = parseSessionDigestKeys({ CONTINUUM_SESSION_DIGEST_KEYS: DIGEST, CONTINUUM_SESSION_DIGEST_VERSION: "v1" });
    expect(ks.currentVersion).toBe("v1");
    expect(() => parseSessionDigestKeys({ CONTINUUM_SESSION_DIGEST_VERSION: "v1" })).toThrow(/required/i);
    expect(() => parseSessionDigestKeys({ CONTINUUM_SESSION_DIGEST_KEYS: DIGEST, CONTINUUM_SESSION_DIGEST_VERSION: "v9" })).toThrow(/does not contain/i);
    expect(() => parseSessionDigestKeys({ CONTINUUM_SESSION_DIGEST_KEYS: "{bad", CONTINUUM_SESSION_DIGEST_VERSION: "v1" })).toThrow(/valid JSON/i);
  });

  it("production startup guard fails closed while only the deterministic verifier exists", () => {
    // Non-production: no-op.
    expect(() => assertProductionIdentityConfig({ NODE_ENV: "development" })).not.toThrow();
    // Production: deterministic verifier is refused ⇒ startup terminates.
    expect(() =>
      assertProductionIdentityConfig({
        NODE_ENV: "production", CONTINUUM_IDENTITY_VERIFIER: "deterministic",
        CONTINUUM_SESSION_STORE: "postgres", CONTINUUM_SESSION_DIGEST_KEYS: DIGEST, CONTINUUM_SESSION_DIGEST_VERSION: "v1",
      }),
    ).toThrow(/deterministic/i);
  });
});
