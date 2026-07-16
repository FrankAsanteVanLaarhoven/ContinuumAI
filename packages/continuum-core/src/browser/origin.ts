/**
 * Phase 3 S4C — host, origin and redirect-target validation.
 *
 * Redirect URIs and post-login destinations are NEVER derived from arbitrary
 * request headers. The external origin is fixed by trusted configuration; the
 * request host is validated against it; forwarded headers are honoured only when
 * an explicit trusted-proxy mode is enabled, and conflicting/malformed forwarded
 * values are rejected rather than coalesced. A post-login `returnTo` is restricted
 * to an allowlisted RELATIVE path — never an absolute or protocol-relative URL.
 */
import type { AuthorizationRequestParameters } from "../identity/authz-types";
import { singleHeaderValue, type BrowserRequest } from "./http";

export interface ParsedOrigin {
  readonly scheme: "http" | "https";
  readonly host: string;
  readonly port: number | null;
  /** Normalized `scheme://authority` with default ports elided; no trailing slash. */
  readonly value: string;
  /** `host` or `host:port` (default ports elided) — for Host-header comparison. */
  readonly authority: string;
}

const HOST_LABEL = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

function isPlausibleHost(host: string): boolean {
  if (host.length === 0 || host.length > 255) return false;
  // IPv6 literal (bracketed) is accepted verbatim; otherwise validate DNS labels.
  if (host.startsWith("[") && host.endsWith("]")) return host.length > 2;
  return host.split(".").every((l) => HOST_LABEL.test(l));
}

function defaultPort(scheme: "http" | "https"): number {
  return scheme === "https" ? 443 : 80;
}

/** Parse a configured external origin. Rejects wildcards, paths, and malformed hosts. */
export function parseOrigin(raw: string | undefined): ParsedOrigin | null {
  if (!raw || raw.includes("*")) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  // An origin must be scheme + host [+ port] only — no path/query/fragment/credentials.
  if ((u.pathname !== "" && u.pathname !== "/") || u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") {
    return null;
  }
  const scheme = u.protocol === "https:" ? "https" : "http";
  const host = u.hostname;
  if (!isPlausibleHost(host)) return null;
  const port = u.port === "" ? null : Number(u.port);
  if (port !== null && (!Number.isInteger(port) || port <= 0 || port > 65535)) return null;
  const effectivePort = port ?? defaultPort(scheme);
  const authority = effectivePort === defaultPort(scheme) ? host : `${host}:${effectivePort}`;
  return { scheme, host, port, value: `${scheme}://${authority}`, authority };
}

// ---------------------------------------------------------------------------
// Request host / scheme validation
// ---------------------------------------------------------------------------

export type HostValidation =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly reason:
        | "host_missing"
        | "host_mismatch"
        | "scheme_mismatch"
        | "forwarded_conflict"
        | "forwarded_untrusted";
    };

function normalizeAuthority(hostHeader: string, scheme: "http" | "https"): string | null {
  const trimmed = hostHeader.trim().toLowerCase();
  if (trimmed.length === 0) return null;
  const colon = trimmed.lastIndexOf(":");
  // Leave IPv6 literals ([::1]:443) alone unless a port clearly follows the bracket.
  if (trimmed.startsWith("[")) {
    const close = trimmed.indexOf("]");
    if (close < 0) return null;
    const host = trimmed.slice(0, close + 1);
    const rest = trimmed.slice(close + 1);
    if (rest === "") return host;
    if (!rest.startsWith(":")) return null;
    const port = Number(rest.slice(1));
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
    return port === defaultPort(scheme) ? host : `${host}:${port}`;
  }
  if (colon < 0) return trimmed;
  const host = trimmed.slice(0, colon);
  const port = Number(trimmed.slice(colon + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return port === defaultPort(scheme) ? host : `${host}:${port}`;
}

/**
 * Validate the request's host and scheme against the configured external origin.
 * Forwarded headers are consulted ONLY when `trustProxy` is true; otherwise the
 * direct Host header is authoritative and forwarded headers are ignored. Multiple
 * conflicting forwarded values are rejected.
 */
export function validateRequestHost(
  req: BrowserRequest,
  origin: ParsedOrigin,
  trustProxy: boolean,
): HostValidation {
  let scheme: "http" | "https" = origin.scheme;
  let hostHeaderName = "host";

  if (trustProxy) {
    const fHost = singleHeaderValue(req, "x-forwarded-host");
    if (!fHost.ok && fHost.reason === "duplicate") return { ok: false, reason: "forwarded_conflict" };
    if (fHost.ok) hostHeaderName = "x-forwarded-host";
    const proto = singleHeaderValue(req, "x-forwarded-proto");
    if (!proto.ok && proto.reason === "duplicate") return { ok: false, reason: "forwarded_conflict" };
    if (proto.ok) {
      const p = proto.value.trim().toLowerCase();
      if (p !== "http" && p !== "https") return { ok: false, reason: "forwarded_conflict" };
      scheme = p;
    }
  } else {
    // Not trusting the proxy: a forwarded host present here must never be honoured.
    // We simply ignore it and use the direct Host header.
  }

  const hostHeader = singleHeaderValue(req, hostHeaderName);
  if (!hostHeader.ok) {
    return { ok: false, reason: hostHeader.reason === "duplicate" ? "forwarded_conflict" : "host_missing" };
  }
  const authority = normalizeAuthority(hostHeader.value, scheme);
  if (authority === null) return { ok: false, reason: "host_missing" };
  if (authority !== origin.authority) return { ok: false, reason: "host_mismatch" };
  if (scheme !== origin.scheme) return { ok: false, reason: "scheme_mismatch" };
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Post-login return target (allowlisted relative path only)
// ---------------------------------------------------------------------------

export type ReturnTarget =
  | { readonly ok: true; readonly path: string }
  | { readonly ok: false; readonly reason: "absolute_url" | "not_allowlisted" | "malformed" };

/**
 * Resolve a post-login `returnTo`. Only an allowlisted RELATIVE path is permitted;
 * absolute URLs, protocol-relative `//host`, and backslash tricks are rejected. An
 * absent/empty value falls back to the fixed default destination.
 */
export function resolveReturnTo(
  raw: string | undefined,
  defaultPath: string,
  allowlist: readonly string[],
): ReturnTarget {
  if (raw === undefined || raw === "") return { ok: true, path: defaultPath };
  if (!raw.startsWith("/")) return { ok: false, reason: "absolute_url" };
  // Reject protocol-relative (`//host`) and any backslash smuggling.
  if (raw.startsWith("//") || raw.includes("\\")) return { ok: false, reason: "absolute_url" };
  // Reject control characters.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0020\u007f]/.test(raw)) return { ok: false, reason: "malformed" };
  if (!allowlist.includes(raw)) return { ok: false, reason: "not_allowlisted" };
  return { ok: true, path: raw };
}

// ---------------------------------------------------------------------------
// Authorization redirect construction
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Origin / Referer validation for state-changing requests
// ---------------------------------------------------------------------------

export type OriginValidation =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: "origin_missing" | "origin_mismatch" | "origin_conflict" };

function originOf(rawUrl: string): string | null {
  try {
    const u = new URL(rawUrl);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.origin;
  } catch {
    return null;
  }
}

/**
 * Validate the `Origin` (preferred) or `Referer` of a state-changing request against
 * the configured external origin. A request with neither header is denied (a
 * same-origin browser fetch always sends `Origin` on unsafe methods).
 */
export function validateRequestOrigin(req: BrowserRequest, origin: ParsedOrigin): OriginValidation {
  const o = singleHeaderValue(req, "origin");
  if (!o.ok && o.reason === "duplicate") return { ok: false, reason: "origin_conflict" };
  if (o.ok) {
    if (o.value === "null") return { ok: false, reason: "origin_mismatch" };
    return o.value === origin.value ? { ok: true } : { ok: false, reason: "origin_mismatch" };
  }
  const r = singleHeaderValue(req, "referer");
  if (!r.ok && r.reason === "duplicate") return { ok: false, reason: "origin_conflict" };
  if (r.ok) {
    const ro = originOf(r.value);
    if (ro === null) return { ok: false, reason: "origin_mismatch" };
    return ro === origin.value ? { ok: true } : { ok: false, reason: "origin_mismatch" };
  }
  return { ok: false, reason: "origin_missing" };
}

/** Build the authorization-request redirect URL from S4B parameters. The endpoint
 *  and redirect URI come from trusted client configuration inside `params`. */
export function buildAuthorizationRedirect(params: AuthorizationRequestParameters): string {
  const u = new URL(params.authorizationEndpoint);
  u.searchParams.set("response_type", params.responseType);
  u.searchParams.set("client_id", params.clientId);
  u.searchParams.set("redirect_uri", params.redirectUri);
  if (params.scope) u.searchParams.set("scope", params.scope);
  u.searchParams.set("state", params.state);
  u.searchParams.set("nonce", params.nonce);
  u.searchParams.set("code_challenge", params.codeChallenge);
  u.searchParams.set("code_challenge_method", params.codeChallengeMethod);
  return u.toString();
}
