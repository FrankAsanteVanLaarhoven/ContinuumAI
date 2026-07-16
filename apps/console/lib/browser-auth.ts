/**
 * Console browser-auth wiring — Phase 3 S4C.
 *
 * Thin Next.js adapter over the framework-neutral `BrowserAuthController` in
 * @continuum/core/browser. Configuration is fail-closed (see `resolveBrowserAuthConfig`):
 * in production the deterministic-local authorization server is refused, so
 * `getBrowserAuth()` throws and every auth route surfaces a 503 — never a silent
 * fallback and never a real provider. The browser cookie is never a source of tenant
 * authority; a resolved principal derives its tenant only through the S2B trusted
 * database context, exactly as elsewhere in the console.
 */
import { NextResponse, type NextRequest } from "next/server";
import { randomUUID } from "node:crypto";
import {
  createDeterministicBrowserAuth,
  resolveBrowserAuthConfig,
  serializeSetCookie,
  type BrowserAuthConfig,
  type BrowserAuthController,
  type BrowserRequest,
  type BrowserResponse,
  type DeterministicLocalAuthorizationServer,
} from "@continuum/core";

export interface ConsoleBrowserAuth {
  readonly controller: BrowserAuthController;
  readonly local: DeterministicLocalAuthorizationServer;
  readonly config: BrowserAuthConfig;
}

/** Build the browser-auth surface for the given environment (uncached; used by tests). */
export async function createBrowserAuth(env: NodeJS.ProcessEnv): Promise<ConsoleBrowserAuth> {
  const config = resolveBrowserAuthConfig(env); // throws (fail-closed) in production
  const { controller, local } = await createDeterministicBrowserAuth({ config });
  return { controller, local, config };
}

let cached: Promise<ConsoleBrowserAuth> | null = null;

/** Cached browser-auth surface over process.env (used by the route handlers). A
 *  failed build is not cached, so a corrected environment can succeed later. */
export function getBrowserAuth(): Promise<ConsoleBrowserAuth> {
  if (!cached) {
    cached = createBrowserAuth(process.env).catch((err) => {
      cached = null;
      throw err;
    });
  }
  return cached;
}

/** Map a Next.js request onto the framework-neutral BrowserRequest. */
export function toBrowserRequest(req: NextRequest): BrowserRequest {
  const url = new URL(req.url);
  const query: Record<string, string | string[]> = {};
  for (const key of new Set(url.searchParams.keys())) {
    const all = url.searchParams.getAll(key);
    query[key] = all.length > 1 ? all : (all[0] ?? "");
  }
  const headers: Record<string, string> = {};
  req.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
  });
  const cookies: Record<string, string> = {};
  for (const c of req.cookies.getAll()) cookies[c.name] = c.value;

  return { method: req.method, path: url.pathname, query, headers, cookies, requestId: `req_console_${randomUUID()}`, receivedAt: new Date() };
}

/** Serialize a BrowserResponse into a NextResponse (distinct Set-Cookie per cookie). */
export function toNextResponse(res: BrowserResponse): NextResponse {
  const out =
    res.location !== undefined
      ? new NextResponse(null, { status: res.status, headers: { ...res.headers, Location: res.location } })
      : NextResponse.json(res.body ?? {}, { status: res.status, headers: res.headers });
  for (const cookie of res.setCookies) {
    out.headers.append("Set-Cookie", serializeSetCookie(cookie));
  }
  return out;
}

/** Fail-closed error response for a browser-auth wiring failure (e.g. production). */
export function browserAuthUnavailable(err: unknown): NextResponse {
  return NextResponse.json({ error: "browser_auth_unavailable", detail: (err as Error).message }, { status: 503 });
}
