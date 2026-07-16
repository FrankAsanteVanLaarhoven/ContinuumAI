/**
 * @continuum/core — public API surface.
 *
 * Continuum control-plane core. Framework-free, strictly typed, runtime
 * validated. Consumed by the Next.js console API layer and by the SIF-Bench
 * research harness over HTTP.
 */
export * from "./crypto";
export * from "./types";
export * from "./protocol";
export * from "./policy";
export * from "./broker";
export * from "./gateway";
export * from "./capability";
export * from "./evidence";
export * from "./action";
export * from "./store";
export * from "./engine";
export * from "./slice";
export * from "./adversary";
export * from "./interventions/entitlement";
export * from "./interventions/metadata";
export * from "./interventions/freshness";
export * from "./stageb/normalize";
export * from "./async";
export * from "./identity";
