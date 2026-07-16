/**
 * Phase 3 S4C — security headers for the browser-auth surface.
 *
 * Authentication responses carry session/callback state and must never be cached
 * (`Cache-Control: no-store`). Framing is denied via CSP `frame-ancestors 'none'`.
 * HSTS is emitted ONLY where HTTPS is guaranteed (production + https origin); it is
 * never enabled for local http development.
 */
import type { BrowserAuthConfig } from "./config";

export function authSecurityHeaders(config: BrowserAuthConfig): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Security-Policy":
      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
    "Cache-Control": "no-store",
  };
  if (config.hsts) {
    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains";
  }
  return headers;
}
