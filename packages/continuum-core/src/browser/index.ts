/**
 * @continuum/core/browser — Phase 3 S4C: browser transport & session boundary.
 *
 * A hardened, framework-neutral browser transport over the S4B authorization-code
 * state machine that binds the resulting S3 session to secure cookies and
 * CSRF-protected requests. It changes NO identity, tenant, or authorization
 * semantics: a completed login carries no tenant authority, and the browser cookie
 * is never a source of tenant authority (tenant resolution remains the S2B trusted
 * database context, keyed on the principal the middleware resolves).
 *
 * The deterministic local authorization server and in-memory session manager are
 * dev/test doubles; production configuration refuses them (fail-closed).
 */
export * from "./http";
export * from "./config";
export * from "./origin";
export * from "./cookies";
export * from "./csrf";
export * from "./headers";
export * from "./events";
export * from "./middleware";
export * from "./session-memory";
export * from "./controller";
export * from "./local-authz-server";
export * from "./dev-wiring";
