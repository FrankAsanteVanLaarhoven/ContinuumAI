/**
 * @continuum/core/async — asynchronous production store boundary (Phase 2).
 *
 * This surface deliberately does NOT re-export the synchronous `ContinuumEngine`;
 * production wiring must depend on the async engine + a ContinuumStore adapter.
 * (Enforced by async/import-boundary.test.ts.)
 */
export * from "./context";
export * from "./store";
export * from "./config";
export * from "./memory-store";
export * from "./engine";
