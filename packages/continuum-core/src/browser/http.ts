/**
 * Phase 3 S4C — normalized browser transport (framework-neutral request/response).
 *
 * The browser-auth surface is expressed over a small, immutable request/response
 * shape so the entire transport can be exercised deterministically without a live
 * HTTP server or a specific web framework. A thin adapter (e.g. a Next.js route
 * handler) maps its native request/response onto these types; all security logic
 * lives in the framework-neutral controller.
 *
 * Header keys are lower-cased. A header may carry multiple values (an adapter must
 * preserve duplicates so conflicting forwarded headers can be rejected rather than
 * silently coalesced). Query values likewise preserve duplicates so a repeated
 * `code`/`state` is detectable.
 */
import type { RequestId } from "../async/context";

export interface BrowserRequest {
  readonly method: string;
  /** Path only (no query string). */
  readonly path: string;
  readonly query: Readonly<Record<string, string | readonly string[]>>;
  /** Lower-cased header name → value or values (duplicates preserved). */
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  /** Parsed request cookies (name → value). */
  readonly cookies: Readonly<Record<string, string>>;
  readonly requestId: RequestId;
  readonly receivedAt: Date;
}

export type SameSite = "Lax" | "Strict" | "None";

export interface CookieAttributes {
  readonly httpOnly: boolean;
  readonly secure: boolean;
  readonly sameSite: SameSite;
  readonly path: string;
  /** Omit for a session cookie (cleared when the browser closes / by server rotation). */
  readonly maxAgeSeconds?: number;
  /** MUST be absent for a `__Host-` prefixed cookie. */
  readonly domain?: string;
}

export interface SetCookie {
  readonly name: string;
  /** Empty string when clearing the cookie. */
  readonly value: string;
  readonly attributes: CookieAttributes;
}

export interface BrowserResponse {
  readonly status: number;
  /** Response headers (security headers, Cache-Control, etc.). */
  readonly headers: Readonly<Record<string, string>>;
  /** Cookies to serialize into distinct Set-Cookie headers. */
  readonly setCookies: readonly SetCookie[];
  /** JSON body (serialized by the adapter). Null for redirects / empty responses. */
  readonly body: unknown;
  /** Location header value for a redirect (status 302), if any. */
  readonly location?: string;
}

// ---------------------------------------------------------------------------
// Cookie parsing / serialization
// ---------------------------------------------------------------------------

/** Parse a `Cookie:` header into a name→value map. Malformed pairs are skipped. */
export function parseCookieHeader(header: string | undefined | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name.length === 0) continue;
    // First occurrence wins; do not let a duplicate silently override.
    if (!(name in out)) out[name] = value;
  }
  return out;
}

const COOKIE_NAME = /^[A-Za-z0-9!#$%&'*+._~^`|-]+$/;
// Cookie values here are always opaque tokens we produce (base64url + a dot / hex),
// so we require the RFC6265 cookie-octet set and reject anything with control chars,
// whitespace, or separators that would need quoting.
const COOKIE_VALUE = /^[A-Za-z0-9!#$%&'()*+./:<=>?@[\]^_`{|}~-]*$/;

/** Serialize a Set-Cookie directive. Throws on an unserializable name/value or a
 *  `__Host-`/`__Secure-` prefix whose attributes violate the prefix contract. */
export function serializeSetCookie(cookie: SetCookie): string {
  const { name, value, attributes } = cookie;
  if (!COOKIE_NAME.test(name)) throw new Error(`invalid cookie name '${name}'`);
  if (!COOKIE_VALUE.test(value)) throw new Error(`invalid cookie value for '${name}'`);

  // Cookie-prefix contracts (RFC6265bis). A clear (empty value, Max-Age=0) still
  // must satisfy them because the browser enforces the prefix on write.
  if (name.startsWith("__Host-")) {
    if (!attributes.secure) throw new Error(`__Host- cookie '${name}' requires Secure`);
    if (attributes.path !== "/") throw new Error(`__Host- cookie '${name}' requires Path=/`);
    if (attributes.domain !== undefined) throw new Error(`__Host- cookie '${name}' must not set Domain`);
  } else if (name.startsWith("__Secure-")) {
    if (!attributes.secure) throw new Error(`__Secure- cookie '${name}' requires Secure`);
  }

  const parts = [`${name}=${value}`, `Path=${attributes.path}`];
  if (attributes.domain !== undefined) parts.push(`Domain=${attributes.domain}`);
  if (attributes.maxAgeSeconds !== undefined) parts.push(`Max-Age=${Math.trunc(attributes.maxAgeSeconds)}`);
  if (attributes.httpOnly) parts.push("HttpOnly");
  if (attributes.secure) parts.push("Secure");
  parts.push(`SameSite=${attributes.sameSite}`);
  return parts.join("; ");
}

// ---------------------------------------------------------------------------
// Request accessors (duplicate-aware)
// ---------------------------------------------------------------------------

export type SingleValue =
  | { readonly ok: true; readonly value: string }
  | { readonly ok: false; readonly reason: "missing" | "duplicate" };

/** Extract exactly one query value; duplicates are a hard error (not last-wins). */
export function singleQueryValue(req: BrowserRequest, name: string): SingleValue {
  const raw = req.query[name];
  if (raw === undefined) return { ok: false, reason: "missing" };
  if (Array.isArray(raw)) {
    if (raw.length === 0) return { ok: false, reason: "missing" };
    if (raw.length > 1) return { ok: false, reason: "duplicate" };
    return { ok: true, value: raw[0] as string };
  }
  return { ok: true, value: raw as string };
}

/** A single header value; conflicting duplicates (>1 distinct) are a hard error. */
export function singleHeaderValue(req: BrowserRequest, name: string): SingleValue {
  const raw = req.headers[name.toLowerCase()];
  if (raw === undefined) return { ok: false, reason: "missing" };
  if (Array.isArray(raw)) {
    const distinct = Array.from(new Set(raw.map((v) => v.trim())));
    if (distinct.length === 0) return { ok: false, reason: "missing" };
    if (distinct.length > 1) return { ok: false, reason: "duplicate" };
    return { ok: true, value: distinct[0] as string };
  }
  return { ok: true, value: (raw as string).trim() };
}
