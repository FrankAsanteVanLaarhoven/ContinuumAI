/**
 * S4A configuration guards — vendor-neutral only, fail-closed. There is no
 * provider-branded variable here and no silent fallback to deterministic
 * verification.
 *
 *   CONTINUUM_IDENTITY_VERIFIER=jwt         (production requires it; deterministic refused)
 *   CONTINUUM_JWKS_PROVIDER=cached          (production requires it; fixture/local-http refused)
 *   CONTINUUM_REPLAY_STORE=postgres         (required in production where replay policy is active)
 *
 * Missing/invalid configuration in production terminates startup.
 */
import { isProduction } from "../async/config";

export type JwtVerifierMode = "jwt" | "deterministic";
export type JwksProviderMode = "cached" | "fixture" | "local_http";
export type ReplayStoreMode = "postgres" | "memory" | "none";

/** Production requires the real `jwt` verifier; the deterministic verifier and
 *  fixtures are dev/test only and are refused in production. */
export function resolveJwtVerifierMode(env: NodeJS.ProcessEnv): JwtVerifierMode {
  const mode = env.CONTINUUM_IDENTITY_VERIFIER;
  if (mode === "jwt") return "jwt";
  if (mode === "deterministic") {
    if (isProduction(env)) {
      throw new Error("CONTINUUM_IDENTITY_VERIFIER=deterministic is refused in production (real jwt verifier required)");
    }
    return "deterministic";
  }
  if (isProduction(env)) {
    throw new Error("CONTINUUM_IDENTITY_VERIFIER must be set to 'jwt' in production");
  }
  throw new Error("CONTINUUM_IDENTITY_VERIFIER must be set ('jwt', or 'deterministic' in dev/test)");
}

/** Production requires the `cached` provider; fixture and local-HTTP sources are
 *  test-only and are refused in production. */
export function resolveJwksProviderMode(env: NodeJS.ProcessEnv): JwksProviderMode {
  const mode = env.CONTINUUM_JWKS_PROVIDER;
  if (mode === "cached") return "cached";
  if (mode === "fixture" || mode === "local_http") {
    if (isProduction(env)) {
      throw new Error(`CONTINUUM_JWKS_PROVIDER=${mode} is refused in production (cached provider required)`);
    }
    return mode;
  }
  if (isProduction(env)) {
    throw new Error("CONTINUUM_JWKS_PROVIDER must be set to 'cached' in production");
  }
  throw new Error("CONTINUUM_JWKS_PROVIDER must be set ('cached', or 'fixture'/'local_http' in dev/test)");
}

/** The replay store. Production requires postgres when replay handling is active;
 *  `memory` is dev/test only; `none` is permitted only when no issuer enables replay. */
export function resolveReplayStoreMode(
  env: NodeJS.ProcessEnv,
  opts: { readonly replayEnabled: boolean },
): ReplayStoreMode {
  const mode = env.CONTINUUM_REPLAY_STORE;
  if (mode === "postgres") return "postgres";
  if (mode === "memory") {
    if (isProduction(env)) {
      throw new Error("CONTINUUM_REPLAY_STORE=memory is refused in production (postgres replay store required)");
    }
    return "memory";
  }
  if (mode === "none") {
    if (opts.replayEnabled) {
      throw new Error("CONTINUUM_REPLAY_STORE=none is invalid: an issuer policy enables replay handling");
    }
    return "none";
  }
  if (isProduction(env) && opts.replayEnabled) {
    throw new Error("CONTINUUM_REPLAY_STORE must be set to postgres in production when replay handling is enabled");
  }
  if (isProduction(env)) {
    throw new Error("CONTINUUM_REPLAY_STORE must be explicitly set in production");
  }
  throw new Error("CONTINUUM_REPLAY_STORE must be set ('postgres', or 'memory'/'none' in dev/test)");
}

/** One-call production startup guard for the S4A verifier subsystem. */
export function assertProductionJwtConfig(
  env: NodeJS.ProcessEnv,
  opts: { readonly replayEnabled: boolean } = { replayEnabled: true },
): void {
  if (!isProduction(env)) return;
  resolveJwtVerifierMode(env); // throws unless jwt
  resolveJwksProviderMode(env); // throws unless cached
  resolveReplayStoreMode(env, opts); // throws unless postgres (when replay enabled)
}
