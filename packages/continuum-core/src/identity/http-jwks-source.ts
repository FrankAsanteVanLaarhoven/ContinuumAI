/**
 * S4A HTTP JWKS source — an SSRF-sensitive boundary. The issuer→JWKS location is
 * ALWAYS trusted configuration; the assertion can never choose a URL. Requests
 * are HTTPS-only outside deterministic loopback tests, send no credentials,
 * refuse redirects, bound the timeout and response size, check the content type,
 * and (in production) refuse private/loopback destinations.
 *
 * The transport is injectable (`fetchImpl`) so tests drive a deterministic local
 * server; production uses the platform `fetch`.
 */
import type {
  JwksLoadFailure,
  JwksLoadOptions,
  JwksLoadResult,
  JwksSource,
} from "./jwt-types";
import { snapshotFrom } from "./jwks-source";

export interface HttpJwksLocation {
  readonly issuer: string;
  /** Trusted, preconfigured JWKS URL. NEVER derived from the assertion. */
  readonly url: string;
  readonly version?: string;
}

export interface HttpJwksSourceOptions {
  readonly locations: readonly HttpJwksLocation[];
  /** In production: HTTPS required and private/loopback destinations refused. */
  readonly production: boolean;
  /** Dev/test escape hatch for an http:// loopback test server. Ignored in production. */
  readonly allowInsecureLoopbackForTests?: boolean;
  /** Injectable transport (defaults to global fetch). */
  readonly fetchImpl?: typeof fetch;
}

/** Deny loopback, link-local, and RFC1918/ULA destinations (production SSRF guard). */
export function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".localhost") || h.endsWith(".internal")) return true;
  // IPv6
  if (h === "::1" || h === "::") return true;
  if (h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return true;
  // IPv4
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const o = m.slice(1, 5).map(Number) as [number, number, number, number];
    if (o.some((n) => n > 255)) return true; // malformed → deny
    const [a, b] = o;
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  return false;
}

async function readBounded(res: Response, maxBytes: number): Promise<string | null> {
  const cl = res.headers.get("content-length");
  if (cl && Number.isFinite(Number(cl)) && Number(cl) > maxBytes) return null;
  const reader = res.body?.getReader();
  if (!reader) {
    const buf = Buffer.from(await res.arrayBuffer());
    return buf.length > maxBytes ? null : buf.toString("utf8");
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(Buffer.from(value));
    }
  }
  return Buffer.concat(chunks).toString("utf8");
}

export class HttpJwksSource implements JwksSource {
  private readonly byIssuer = new Map<string, HttpJwksLocation>();
  private readonly production: boolean;
  private readonly allowInsecureLoopback: boolean;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: HttpJwksSourceOptions) {
    for (const loc of opts.locations) this.byIssuer.set(loc.issuer, loc);
    this.production = opts.production;
    this.allowInsecureLoopback = opts.allowInsecureLoopbackForTests === true && !opts.production;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private locationAllowed(url: URL): boolean {
    if (url.protocol !== "https:" && url.protocol !== "http:") return false;
    if (url.protocol === "http:" && !this.allowInsecureLoopback) return false; // https required unless test loopback
    if (this.production && isPrivateHost(url.hostname)) return false;
    return true;
  }

  async load(issuer: string, options: JwksLoadOptions): Promise<JwksLoadResult> {
    const loc = this.byIssuer.get(issuer);
    if (!loc) return { ok: false, reason: "issuer_unknown" };

    let url: URL;
    try {
      url = new URL(loc.url); // trusted config only
    } catch {
      return fail("refresh_failed");
    }
    if (!this.locationAllowed(url)) return fail("refresh_failed");

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs);
    try {
      const res = await this.fetchImpl(url, {
        method: "GET",
        redirect: "error", // no redirect-following
        signal: controller.signal,
        headers: { accept: "application/json" },
        // no credentials, no cookies
      });
      if (!res.ok) return fail("refresh_failed");
      const ct = (res.headers.get("content-type") ?? "").toLowerCase();
      if (!ct.includes("json")) return fail("refresh_failed");
      const body = await readBounded(res, options.maxResponseBytes);
      if (body === null) return fail("too_large");
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch {
        return fail("malformed");
      }
      return snapshotFrom(issuer, parsed, loc.version ?? "remote", options);
    } catch {
      return fail("refresh_failed"); // transport error, timeout, or refused redirect
    } finally {
      clearTimeout(timer);
    }
  }
}

function fail(reason: JwksLoadFailure): JwksLoadResult {
  return { ok: false, reason };
}
