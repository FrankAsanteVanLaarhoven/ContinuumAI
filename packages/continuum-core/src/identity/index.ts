/**
 * @continuum/core/identity — Phase 3 S3: vendor-neutral identity-verification &
 * session boundary. Types + shared normalization + a deterministic verifier +
 * digest/config helpers. Neither the verifier nor the session layer accepts an
 * authoritative tenant from the caller; tenant authority remains the S2B trusted
 * database-context path.
 */
export * from "./types";
export * from "./verification";
export * from "./deterministic-verifier";
export * from "./session-digest";
export * from "./auth-events";
export * from "./auth-boundary";
export * from "./config";
