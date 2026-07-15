/**
 * Store-selection gate. Fail-closed in production; never a silent memory fallback.
 *
 *   CONTINUUM_STORE=memory    — deterministic tests / research ONLY
 *   CONTINUUM_STORE=postgres  — development / staging / production
 *
 * Rules enforced here:
 *   - production requires an explicit `postgres` selection;
 *   - an unset/invalid value in production is a hard startup error;
 *   - memory mode carries a visible RESEARCH_ONLY classification.
 */
import type { StoreMode } from "./store";
import { RESEARCH_ONLY } from "./context";

export type StoreClassification = typeof RESEARCH_ONLY | "PRODUCTION_CANDIDATE";

export function isProduction(env: NodeJS.ProcessEnv): boolean {
  return env.NODE_ENV === "production";
}

/**
 * Resolve the store mode from the environment. In production the value must be
 * explicitly `postgres`; anything else throws. Outside production an unset value
 * defaults to `memory` (research/tests).
 */
export function resolveStoreMode(env: NodeJS.ProcessEnv): StoreMode {
  const mode = env.CONTINUUM_STORE;

  if (mode === "postgres") return "postgres";

  if (mode === "memory") {
    if (isProduction(env)) {
      throw new Error(
        "CONTINUUM_STORE=memory is refused in production (memory mode is research-only)",
      );
    }
    return "memory";
  }

  // Unset or invalid.
  if (isProduction(env)) {
    throw new Error(
      "CONTINUUM_STORE must be explicitly set to postgres in production",
    );
  }
  return "memory";
}

/** Runtime classification for logs/telemetry. Memory mode is always RESEARCH_ONLY. */
export function storeClassification(mode: StoreMode): StoreClassification {
  return mode === "postgres" ? "PRODUCTION_CANDIDATE" : RESEARCH_ONLY;
}

/**
 * Production guard, called once at startup after the store is constructed.
 * Refuses memory mode in production. There is no automatic postgres→memory
 * fallback anywhere in the codebase; a PostgreSQL failure must terminate startup.
 */
export function assertProductionStore(env: NodeJS.ProcessEnv, mode: StoreMode): void {
  if (isProduction(env) && mode !== "postgres") {
    throw new Error("production runtime requires CONTINUUM_STORE=postgres");
  }
}
