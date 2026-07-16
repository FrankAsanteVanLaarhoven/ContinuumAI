/**
 * S4B configuration guards — provider-neutral, fail-closed, no silent fallback.
 *
 *   CONTINUUM_AUTH_CODE_FLOW=deterministic     (dev/test only; production refuses it)
 *   CONTINUUM_AUTH_TRANSACTION_STORE=postgres  (production requires it; no memory)
 *   CONTINUUM_CODE_EXCHANGER=fixture           (dev/test only; production refuses it)
 *   CONTINUUM_PKCE_SECRET_STORE=test-protected (dev/test only; production refuses it)
 *
 * Plain PKCE is never supported (S256 only), transaction lifetimes must be bounded,
 * and production additionally requires issuer/client/redirect registration. Because
 * S4B ships only the deterministic flow, fixture exchanger and test-protected PKCE
 * store, a production configuration fails closed (a real provider/exchanger/KMS
 * arrives in a later milestone).
 */
import { isProduction } from "../async/config";

export type AuthCodeFlowMode = "deterministic";
export type AuthTransactionStoreMode = "postgres" | "memory";
export type CodeExchangerMode = "fixture";
export type PkceSecretStoreMode = "test-protected";

export function resolveAuthCodeFlowMode(env: NodeJS.ProcessEnv): AuthCodeFlowMode {
  const mode = env.CONTINUUM_AUTH_CODE_FLOW;
  if (mode === "deterministic") {
    if (isProduction(env)) {
      throw new Error("CONTINUUM_AUTH_CODE_FLOW=deterministic is refused in production (real authorization flow required)");
    }
    return "deterministic";
  }
  if (isProduction(env)) throw new Error("CONTINUUM_AUTH_CODE_FLOW must be a real (non-deterministic) flow in production");
  throw new Error("CONTINUUM_AUTH_CODE_FLOW must be set (deterministic in dev/test)");
}

export function resolveAuthTransactionStoreMode(env: NodeJS.ProcessEnv): AuthTransactionStoreMode {
  const mode = env.CONTINUUM_AUTH_TRANSACTION_STORE;
  if (mode === "postgres") return "postgres";
  if (mode === "memory") {
    if (isProduction(env)) {
      throw new Error("CONTINUUM_AUTH_TRANSACTION_STORE=memory is refused in production (postgres required)");
    }
    return "memory";
  }
  if (isProduction(env)) throw new Error("CONTINUUM_AUTH_TRANSACTION_STORE must be set to postgres in production");
  throw new Error("CONTINUUM_AUTH_TRANSACTION_STORE must be set ('postgres', or 'memory' in dev/test)");
}

export function resolveCodeExchangerMode(env: NodeJS.ProcessEnv): CodeExchangerMode {
  const mode = env.CONTINUUM_CODE_EXCHANGER;
  if (mode === "fixture") {
    if (isProduction(env)) {
      throw new Error("CONTINUUM_CODE_EXCHANGER=fixture is refused in production (real token-exchange required)");
    }
    return "fixture";
  }
  if (isProduction(env)) throw new Error("CONTINUUM_CODE_EXCHANGER must be a real exchanger in production");
  throw new Error("CONTINUUM_CODE_EXCHANGER must be set (fixture in dev/test)");
}

export function resolvePkceSecretStoreMode(env: NodeJS.ProcessEnv): PkceSecretStoreMode {
  const mode = env.CONTINUUM_PKCE_SECRET_STORE;
  if (mode === "test-protected") {
    if (isProduction(env)) {
      throw new Error("CONTINUUM_PKCE_SECRET_STORE=test-protected is refused in production (KMS/HSM-backed store required)");
    }
    return "test-protected";
  }
  if (isProduction(env)) throw new Error("CONTINUUM_PKCE_SECRET_STORE must be a real protected store in production");
  throw new Error("CONTINUUM_PKCE_SECRET_STORE must be set (test-protected in dev/test)");
}

/** Plain PKCE is never supported. */
export function assertS256(method: string): void {
  if (method !== "S256") throw new Error(`unsupported PKCE method '${method}' (only S256 is supported)`);
}

/** Transaction lifetimes must be bounded and positive. */
export function assertBoundedTransactionTtl(seconds: number, maxSeconds = 3600): void {
  if (!Number.isFinite(seconds) || seconds <= 0 || seconds > maxSeconds) {
    throw new Error(`authorization transaction TTL must be a bounded positive value (0 < ttl <= ${maxSeconds}s)`);
  }
}

/** One-call production startup guard for the S4B subsystem. */
export function assertProductionAuthzConfig(env: NodeJS.ProcessEnv): void {
  if (!isProduction(env)) return;
  resolveAuthCodeFlowMode(env);
  resolveAuthTransactionStoreMode(env);
  resolveCodeExchangerMode(env);
  resolvePkceSecretStoreMode(env);
}
