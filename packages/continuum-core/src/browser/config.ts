/**
 * Phase 3 S4C — browser-auth configuration (provider-neutral, fail-closed).
 *
 *   CONTINUUM_BROWSER_AUTH=enabled
 *   CONTINUUM_AUTH_SERVER=deterministic-local      (dev/test only; production refuses it)
 *   CONTINUUM_EXTERNAL_ORIGIN=https://configured.example
 *   CONTINUUM_TRUST_PROXY=false                    (explicit true|false only)
 *   CONTINUUM_SESSION_COOKIE_NAME=__Host-continuum_session
 *   CONTINUUM_AUTH_ISSUER=<registered issuer>
 *   CONTINUUM_AUTH_RETURN_PATHS=/,/app            (allowlisted RELATIVE paths)
 *   CONTINUUM_CSRF_KEY=<base64>                     (session-bound CSRF signing key)
 *
 * S4C ships only the deterministic-local authorization server, so a production
 * configuration fails closed (a real provider arrives in a later, separately
 * reviewed milestone). The production guard additionally composes the S3 identity
 * and S4B authorization-code production guards; there is no silent fallback.
 */
import { isProduction } from "../async/config";
import { assertProductionIdentityConfig } from "../identity/config";
import { assertProductionAuthzConfig } from "../identity/authz-config";
import { parseOrigin, type ParsedOrigin } from "./origin";

export type AuthServerMode = "deterministic-local";

export interface BrowserAuthConfig {
  readonly production: boolean;
  readonly authServer: AuthServerMode;
  readonly origin: ParsedOrigin;
  readonly trustProxy: boolean;
  /** Registered issuer the login route authenticates against (S4B client registry key). */
  readonly issuer: string;
  readonly loginPath: string;
  readonly callbackPath: string;
  readonly defaultReturnPath: string;
  readonly allowedReturnPaths: readonly string[];
  readonly sessionCookieName: string;
  readonly csrfCookieName: string;
  readonly loginCookieName: string;
  readonly csrfHeaderName: string;
  /** Whether cookies carry Secure (true in production; derived from origin otherwise). */
  readonly cookieSecure: boolean;
  /** Base64 HMAC key for session-bound CSRF tokens. Never logged. */
  readonly csrfKey: string;
  readonly loginCookieTtlSeconds: number;
  /** HSTS only where HTTPS is guaranteed (production + https origin). */
  readonly hsts: boolean;
}

function boolEnv(raw: string | undefined, name: string): boolean {
  if (raw === undefined || raw === "false") return false;
  if (raw === "true") return true;
  throw new Error(`${name} must be exactly 'true' or 'false' (got '${raw}')`);
}

function relativePath(raw: string, name: string): string {
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) {
    throw new Error(`${name} must be a relative path beginning with '/' (got '${raw}')`);
  }
  return raw;
}

const SECURE_PREFIX = /^__(Host|Secure)-/;

/**
 * Resolve the browser-auth configuration. Fails closed: an invalid/missing value
 * throws, and every production-forbidden setting is rejected here (there is no
 * silent fallback). In S4C production always fails closed because the only
 * authorization server available is the deterministic-local test server.
 */
export function resolveBrowserAuthConfig(env: NodeJS.ProcessEnv): BrowserAuthConfig {
  const production = isProduction(env);

  if (env.CONTINUUM_BROWSER_AUTH !== "enabled") {
    throw new Error("CONTINUUM_BROWSER_AUTH must be set to 'enabled'");
  }

  // Authorization server (structural). Only the deterministic-local test server
  // exists in S4C; the production REFUSAL is applied at the end so that every other
  // production guard below is independently reachable and testable.
  const server = env.CONTINUUM_AUTH_SERVER;
  if (server !== "deterministic-local") {
    if (production) throw new Error("CONTINUUM_AUTH_SERVER must be a real authorization server in production");
    throw new Error("CONTINUUM_AUTH_SERVER must be set ('deterministic-local' in dev/test)");
  }

  // External origin — required, exact (wildcards rejected), https in production.
  const origin = parseOrigin(env.CONTINUUM_EXTERNAL_ORIGIN);
  if (!origin) throw new Error("CONTINUUM_EXTERNAL_ORIGIN must be a valid exact origin (scheme+host[:port], no wildcards/path)");
  if (production && origin.scheme !== "https") {
    throw new Error("CONTINUUM_EXTERNAL_ORIGIN must be https in production (insecure origin refused)");
  }

  const trustProxy = boolEnv(env.CONTINUUM_TRUST_PROXY, "CONTINUUM_TRUST_PROXY");

  const issuer = env.CONTINUUM_AUTH_ISSUER;
  if (!issuer || issuer.length === 0) throw new Error("CONTINUUM_AUTH_ISSUER must be set (registered issuer to authenticate against)");

  const cookieSecure = production || origin.scheme === "https";

  const sessionCookieName = env.CONTINUUM_SESSION_COOKIE_NAME ?? (cookieSecure ? "__Host-continuum_session" : "continuum_session");
  const csrfCookieName = env.CONTINUUM_CSRF_COOKIE_NAME ?? (cookieSecure ? "__Host-continuum_csrf" : "continuum_csrf");
  const loginCookieName = env.CONTINUUM_LOGIN_COOKIE_NAME ?? (cookieSecure ? "__Host-continuum_login" : "continuum_login");
  if (production && !SECURE_PREFIX.test(sessionCookieName)) {
    throw new Error("production session cookie must use a '__Host-'/'__Secure-' secure prefix (insecure session cookie refused)");
  }
  // Reject at startup any secure-prefixed cookie whose attributes cannot be honoured
  // (a `__Host-`/`__Secure-` cookie requires Secure, which an http origin cannot set).
  for (const [name, label] of [[sessionCookieName, "session"], [csrfCookieName, "csrf"], [loginCookieName, "login"]] as const) {
    if (SECURE_PREFIX.test(name) && !cookieSecure) {
      throw new Error(`${label} cookie '${name}' uses a secure prefix but the origin is not secure — refusing an incompatible cookie configuration`);
    }
  }

  const csrfKey = env.CONTINUUM_CSRF_KEY;
  if (!csrfKey) {
    if (production) throw new Error("CONTINUUM_CSRF_KEY is required in production (missing CSRF protection refused)");
    throw new Error("CONTINUUM_CSRF_KEY must be set (base64 CSRF signing key)");
  }

  const defaultReturnPath = relativePath(env.CONTINUUM_AUTH_DEFAULT_RETURN ?? "/", "CONTINUUM_AUTH_DEFAULT_RETURN");
  const allowedReturnPaths = (env.CONTINUUM_AUTH_RETURN_PATHS ?? defaultReturnPath)
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
    .map((p) => relativePath(p, "CONTINUUM_AUTH_RETURN_PATHS"));

  // Final production refusal: S4C ships only the deterministic-local server, so a
  // production configuration always fails closed here (a real, separately-reviewed
  // authorization server arrives later). Reached only after every other guard passes.
  if (production) {
    throw new Error("CONTINUUM_AUTH_SERVER=deterministic-local is refused in production (real authorization server required)");
  }

  return {
    production,
    authServer: "deterministic-local",
    origin,
    trustProxy,
    issuer,
    loginPath: env.CONTINUUM_AUTH_LOGIN_PATH ?? "/api/auth/login",
    callbackPath: env.CONTINUUM_AUTH_CALLBACK_PATH ?? "/api/auth/callback",
    defaultReturnPath,
    allowedReturnPaths: allowedReturnPaths.length > 0 ? allowedReturnPaths : [defaultReturnPath],
    sessionCookieName,
    csrfCookieName,
    loginCookieName,
    csrfHeaderName: (env.CONTINUUM_CSRF_HEADER ?? "x-continuum-csrf").toLowerCase(),
    cookieSecure,
    csrfKey,
    loginCookieTtlSeconds: 300,
    hsts: production && origin.scheme === "https",
  };
}

/**
 * One-call production startup guard for the browser-auth surface. Composes the S3
 * identity, S4B authorization-code, and browser-transport production rejections.
 * In S4C this ALWAYS throws in production (the deterministic-local server is the
 * only available authorization server); the individual checks are enforced here so
 * each production-forbidden setting fails closed independently.
 */
export function assertProductionBrowserAuthConfig(env: NodeJS.ProcessEnv): void {
  if (!isProduction(env)) return;
  assertProductionIdentityConfig(env); // deterministic verifier / non-durable sessions refused
  assertProductionAuthzConfig(env); // fixture exchanger / test-protected PKCE / memory store refused
  resolveBrowserAuthConfig(env); // deterministic-local server / insecure cookies / wildcard origin refused
}
