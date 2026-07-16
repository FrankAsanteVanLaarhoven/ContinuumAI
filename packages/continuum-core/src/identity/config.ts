/**
 * S3 identity/session configuration guards. Explicit, fail-closed, no provider-
 * specific variables in this milestone.
 *
 *   CONTINUUM_IDENTITY_VERIFIER=deterministic   (dev/test ONLY; production refuses it)
 *   CONTINUUM_SESSION_STORE=postgres            (production requires it; no memory fallback)
 *   CONTINUUM_SESSION_DIGEST_KEYS={"v1":"<b64>"} + CONTINUUM_SESSION_DIGEST_VERSION=v1
 *
 * Missing/invalid configuration in production terminates startup.
 */
import { isProduction } from "../async/config";
import type { SessionDigestKeys } from "./session-digest";

export type IdentityVerifierMode = "deterministic";
export type SessionStoreMode = "postgres";

/** Resolve the identity verifier mode. Production must set a non-deterministic
 *  verifier; since S3 ships only the deterministic one, production has no valid
 *  verifier yet and MUST fail closed (a real verifier arrives in a later step). */
export function resolveIdentityVerifierMode(env: NodeJS.ProcessEnv): IdentityVerifierMode {
  const mode = env.CONTINUUM_IDENTITY_VERIFIER;
  if (mode === "deterministic") {
    if (isProduction(env)) {
      throw new Error(
        "CONTINUUM_IDENTITY_VERIFIER=deterministic is refused in production (deterministic verification is dev/test only)",
      );
    }
    return "deterministic";
  }
  if (isProduction(env)) {
    throw new Error("CONTINUUM_IDENTITY_VERIFIER must be explicitly set (and non-deterministic) in production");
  }
  throw new Error("CONTINUUM_IDENTITY_VERIFIER must be set (deterministic in dev/test)");
}

/** Resolve the session store mode. Production requires postgres; no memory fallback. */
export function resolveSessionStoreMode(env: NodeJS.ProcessEnv): SessionStoreMode {
  const mode = env.CONTINUUM_SESSION_STORE;
  if (mode === "postgres") return "postgres";
  if (isProduction(env)) {
    throw new Error("CONTINUUM_SESSION_STORE must be explicitly set to postgres in production (no memory fallback)");
  }
  // Non-production still requires an explicit postgres session store — sessions are
  // never held in memory. Tests provide an embedded PostgreSQL.
  throw new Error("CONTINUUM_SESSION_STORE must be set to postgres (session persistence is required)");
}

/** Parse and validate the versioned session digest keys from the environment. */
export function parseSessionDigestKeys(env: NodeJS.ProcessEnv): SessionDigestKeys {
  const raw = env.CONTINUUM_SESSION_DIGEST_KEYS;
  const version = env.CONTINUUM_SESSION_DIGEST_VERSION;
  if (!raw || !version) {
    throw new Error(
      "CONTINUUM_SESSION_DIGEST_KEYS and CONTINUUM_SESSION_DIGEST_VERSION are required (session digest key material)",
    );
  }
  let keys: Record<string, string>;
  try {
    keys = JSON.parse(raw) as Record<string, string>;
  } catch {
    throw new Error("CONTINUUM_SESSION_DIGEST_KEYS must be valid JSON of {version: base64key}");
  }
  if (typeof keys !== "object" || keys === null || !keys[version]) {
    throw new Error(`CONTINUUM_SESSION_DIGEST_KEYS does not contain the current version '${version}'`);
  }
  return { currentVersion: version, keys };
}

/** One-call production startup guard for the S3 identity/session subsystem. */
export function assertProductionIdentityConfig(env: NodeJS.ProcessEnv): void {
  if (!isProduction(env)) return;
  resolveIdentityVerifierMode(env); // throws on deterministic/unset
  resolveSessionStoreMode(env); // throws unless postgres
  parseSessionDigestKeys(env); // throws unless present + current version
}
