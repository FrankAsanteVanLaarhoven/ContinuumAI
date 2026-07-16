/**
 * Phase 3 S4C — cookie construction for the browser-auth surface.
 *
 *   session cookie  — HttpOnly, opaque S3 credential only, bounded by absolute
 *                     session expiry, secure-prefixed in production.
 *   csrf cookie     — non-HttpOnly (client JS reads it to echo in a header), still
 *                     Secure + SameSite; the token is keyed and session-bound.
 *   login cookie    — HttpOnly short-lived correlation reference (opaque), distinct
 *                     from the authorization `state`.
 *
 * All cookies are host-only (no Domain) with Path=/ so a `__Host-` prefix is valid.
 * A "clear" reissues the same attributes with an empty value and Max-Age=0.
 */
import type { BrowserAuthConfig } from "./config";
import type { CookieAttributes, SetCookie } from "./http";

function baseAttributes(config: BrowserAuthConfig, httpOnly: boolean, maxAgeSeconds?: number): CookieAttributes {
  const attrs: CookieAttributes = {
    httpOnly,
    secure: config.cookieSecure,
    sameSite: "Lax",
    path: "/",
    ...(maxAgeSeconds !== undefined ? { maxAgeSeconds } : {}),
    // Deliberately no Domain — host-only, required for the `__Host-` prefix.
  };
  return attrs;
}

/** Seconds until an absolute instant, floored at 0. */
export function boundedMaxAge(absoluteExpiresAt: Date, now: Date): number {
  return Math.max(0, Math.floor((absoluteExpiresAt.getTime() - now.getTime()) / 1000));
}

/** Session cookie carrying ONLY the opaque S3 session credential. Max-Age never
 *  exceeds the absolute server-side session expiry. */
export function sessionCookie(config: BrowserAuthConfig, credential: string, absoluteExpiresAt: Date, now: Date): SetCookie {
  return { name: config.sessionCookieName, value: credential, attributes: baseAttributes(config, true, boundedMaxAge(absoluteExpiresAt, now)) };
}

export function clearSessionCookie(config: BrowserAuthConfig): SetCookie {
  return { name: config.sessionCookieName, value: "", attributes: baseAttributes(config, true, 0) };
}

/** CSRF cookie (non-HttpOnly). The value is a keyed, session-bound token. */
export function csrfCookie(config: BrowserAuthConfig, token: string, absoluteExpiresAt: Date, now: Date): SetCookie {
  return { name: config.csrfCookieName, value: token, attributes: baseAttributes(config, false, boundedMaxAge(absoluteExpiresAt, now)) };
}

export function clearCsrfCookie(config: BrowserAuthConfig): SetCookie {
  return { name: config.csrfCookieName, value: "", attributes: baseAttributes(config, false, 0) };
}

/** Short-lived opaque login-transaction correlation cookie (distinct from `state`). */
export function loginCookie(config: BrowserAuthConfig, reference: string): SetCookie {
  return { name: config.loginCookieName, value: reference, attributes: baseAttributes(config, true, config.loginCookieTtlSeconds) };
}

export function clearLoginCookie(config: BrowserAuthConfig): SetCookie {
  return { name: config.loginCookieName, value: "", attributes: baseAttributes(config, true, 0) };
}
