/**
 * Phase 3 S4C — the browser-auth controller.
 *
 * Exposes the already-tested S4B authorization-code state machine through a hardened
 * browser transport and binds the resulting S3 session to secure cookies and
 * CSRF-protected requests, WITHOUT changing the underlying identity, tenant, or
 * authorization semantics. A completed login carries no tenant authority; the browser
 * cookie is never a source of tenant authority — tenant resolution remains the S2B
 * trusted-context path, keyed on the principal the middleware resolves.
 *
 * All handlers are framework-neutral (BrowserRequest → BrowserResponse) so the full
 * surface is deterministically testable. A thin Next.js route adapter maps native
 * request/response onto these types.
 */
import { hmacSha256Hex } from "../crypto";
import type { AuthorizationCodeFlow, AuthorizationFailure } from "../identity/authz-types";
import type { SessionManager } from "../identity/types";
import type { BrowserAuthConfig } from "./config";
import { clearCsrfCookie, clearLoginCookie, clearSessionCookie, csrfCookie, loginCookie, sessionCookie } from "./cookies";
import { mintCsrfToken, verifyCsrfToken } from "./csrf";
import type { BrowserAuthEvent, BrowserAuthEventSink, BrowserAuthEventType } from "./events";
import { authSecurityHeaders } from "./headers";
import {
  singleHeaderValue,
  singleQueryValue,
  type BrowserRequest,
  type BrowserResponse,
  type SetCookie,
} from "./http";
import {
  mapSessionFailure,
  shouldClearOnDeny,
  type BrowserAuthenticationResult,
  type RouteClassifier,
} from "./middleware";
import { buildAuthorizationRedirect, resolveReturnTo, validateRequestHost, validateRequestOrigin } from "./origin";

export interface BrowserAuthControllerDeps {
  readonly config: BrowserAuthConfig;
  readonly flow: AuthorizationCodeFlow; // S4B
  readonly sessions: SessionManager; // S3
  readonly sink: BrowserAuthEventSink;
  readonly routes: RouteClassifier;
  /** Base64 key for hashing the login correlation reference into evidence. */
  readonly evidenceDigestKey: string;
}

/** Coarse, non-reflective error class for the HTTP body (never echoes inputs). */
function genericError(reason: AuthorizationFailure): { status: number; error: string } {
  switch (reason) {
    case "state_missing":
    case "state_malformed":
    case "code_missing":
    case "code_malformed":
    case "invalid_request":
      return { status: 400, error: "invalid_request" };
    default:
      return { status: 401, error: "authentication_failed" };
  }
}

export class BrowserAuthController {
  private readonly d: BrowserAuthControllerDeps;

  constructor(deps: BrowserAuthControllerDeps) {
    this.d = deps;
  }

  get routes(): RouteClassifier {
    return this.d.routes;
  }

  // -------------------------------------------------------------------------
  // login — GET
  // -------------------------------------------------------------------------

  async login(req: BrowserRequest): Promise<BrowserResponse> {
    if (req.method !== "GET") return this.respond(405, { error: "method_not_allowed" });

    const host = validateRequestHost(req, this.d.config.origin, this.d.config.trustProxy);
    if (!host.ok) {
      await this.event("browser.host_denied", req, "denied", host.reason, null, null, null);
      return this.respond(400, { error: "invalid_host" });
    }

    // Open-redirect gate: a supplied returnTo must be an allowlisted RELATIVE path.
    const rt = singleQueryValue(req, "returnTo");
    if (!rt.ok && rt.reason === "duplicate") return this.respond(400, { error: "invalid_request" });
    const returnTo = resolveReturnTo(rt.ok ? rt.value : undefined, this.d.config.defaultReturnPath, this.d.config.allowedReturnPaths);
    if (!returnTo.ok) return this.respond(400, { error: "invalid_request" });

    const begun = await this.d.flow.begin({ issuer: this.d.config.issuer, requestId: req.requestId, receivedAt: req.receivedAt });
    if (!begun.ok) {
      await this.event("browser.callback_denied", req, "denied", begun.reason, null, null, null);
      return this.respond(500, { error: "login_unavailable" });
    }

    const redirectUrl = buildAuthorizationRedirect(begun.request);
    const cookies = [loginCookie(this.d.config, begun.transactionId)];
    await this.event("browser.login_initiated", req, "success", null, null, null, this.correlation(begun.transactionId));
    return this.redirect(redirectUrl, cookies);
  }

  // -------------------------------------------------------------------------
  // callback — GET
  // -------------------------------------------------------------------------

  async callback(req: BrowserRequest): Promise<BrowserResponse> {
    if (req.method !== "GET") return this.respond(405, { error: "method_not_allowed" });
    const correlation = this.correlationFromCookie(req);

    const host = validateRequestHost(req, this.d.config.origin, this.d.config.trustProxy);
    if (!host.ok) {
      await this.event("browser.host_denied", req, "denied", host.reason, null, null, correlation);
      return this.respond(400, { error: "invalid_host" }, [clearLoginCookie(this.d.config)]);
    }

    // Provider-signalled denial (e.g. ?error=access_denied) — never call complete().
    const err = singleQueryValue(req, "error");
    if (err.ok) {
      await this.event("browser.callback_denied", req, "denied", "access_denied", null, null, correlation);
      return this.respond(401, { error: "access_denied" }, [clearLoginCookie(this.d.config)]);
    }

    const code = singleQueryValue(req, "code");
    const state = singleQueryValue(req, "state");
    if (!code.ok || !state.ok) {
      const reason = !code.ok
        ? code.reason === "duplicate" ? "code_duplicate" : "code_missing"
        : !state.ok
          ? state.reason === "duplicate" ? "state_duplicate" : "state_missing"
          : "invalid_request";
      await this.event("browser.callback_denied", req, "denied", reason, null, null, correlation);
      return this.respond(400, { error: "invalid_request" }, [clearLoginCookie(this.d.config)]);
    }

    const result = await this.d.flow.complete({ state: state.value, code: code.value, requestId: req.requestId, receivedAt: req.receivedAt });
    if (!result.ok) {
      await this.event("browser.callback_denied", req, "denied", result.reason, null, null, correlation);
      // Clear temporary auth cookies on terminal failure; NO session is issued.
      const cleared = [clearLoginCookie(this.d.config), clearSessionCookie(this.d.config), clearCsrfCookie(this.d.config)];
      const ge = genericError(result.reason);
      return this.respond(ge.status, { error: ge.error }, cleared);
    }

    // Success — mint the session cookie ONLY now (after complete() fully succeeds).
    const s = result.session;
    const csrfToken = mintCsrfToken(this.d.config.csrfKey, s.sessionId);
    const cookies: SetCookie[] = [
      sessionCookie(this.d.config, s.credential.value, s.absoluteExpiresAt, req.receivedAt),
      csrfCookie(this.d.config, csrfToken, s.absoluteExpiresAt, req.receivedAt),
      clearLoginCookie(this.d.config),
    ];
    await this.event("browser.callback_accepted", req, "success", null, result.principalId, s.sessionId, correlation);
    await this.event("browser.session_issued", req, "success", null, result.principalId, s.sessionId, correlation);
    return this.redirect(this.d.config.defaultReturnPath, cookies);
  }

  // -------------------------------------------------------------------------
  // authenticate — middleware primitive (pure; NO tenant authority)
  // -------------------------------------------------------------------------

  async authenticate(req: BrowserRequest): Promise<BrowserAuthenticationResult> {
    const raw = req.cookies[this.d.config.sessionCookieName];
    if (!raw) return { authenticated: false, reason: "missing_cookie" };
    const v = await this.d.sessions.validateSession({ value: raw }, { requestId: req.requestId, receivedAt: req.receivedAt });
    if (v.valid) return { authenticated: true, session: v.session, principalId: v.session.principalId };
    return { authenticated: false, reason: mapSessionFailure(v.reason) };
  }

  // -------------------------------------------------------------------------
  // session — GET (auth status; reads only, never mutates)
  // -------------------------------------------------------------------------

  async session(req: BrowserRequest): Promise<BrowserResponse> {
    if (req.method !== "GET") return this.respond(405, { error: "method_not_allowed" });
    const auth = await this.authenticate(req);
    if (auth.authenticated) {
      // Principal only — NEVER a tenant, role, or the session credential.
      return this.respond(200, { authenticated: true, principalId: auth.principalId });
    }
    if (auth.reason === "missing_cookie") return this.respond(200, { authenticated: false });
    if (auth.reason === "session_store_unavailable") return this.respond(503, { error: "unavailable" });
    await this.event("browser.session_validation_denied", req, "denied", auth.reason, null, null, null);
    const cookies = shouldClearOnDeny(auth.reason) ? [clearSessionCookie(this.d.config), clearCsrfCookie(this.d.config)] : [];
    return this.respond(200, { authenticated: false }, cookies);
  }

  // -------------------------------------------------------------------------
  // csrf — POST (issue a session-bound token to an authenticated caller)
  // -------------------------------------------------------------------------

  async csrf(req: BrowserRequest): Promise<BrowserResponse> {
    if (req.method !== "POST") return this.respond(405, { error: "method_not_allowed" });
    const host = validateRequestHost(req, this.d.config.origin, this.d.config.trustProxy);
    if (!host.ok) {
      await this.event("browser.host_denied", req, "denied", host.reason, null, null, null);
      return this.respond(400, { error: "invalid_host" });
    }
    const origin = validateRequestOrigin(req, this.d.config.origin);
    if (!origin.ok) {
      await this.event("browser.csrf_denied", req, "denied", origin.reason, null, null, null);
      return this.respond(403, { error: "forbidden" });
    }
    const auth = await this.authenticate(req);
    if (!auth.authenticated) {
      if (auth.reason === "session_store_unavailable") return this.respond(503, { error: "unavailable" });
      const cookies = shouldClearOnDeny(auth.reason) ? [clearSessionCookie(this.d.config), clearCsrfCookie(this.d.config)] : [];
      return this.respond(401, { error: "unauthenticated" }, cookies);
    }
    const token = mintCsrfToken(this.d.config.csrfKey, auth.session.sessionId);
    const cookies = [csrfCookie(this.d.config, token, auth.session.expiresAt, req.receivedAt)];
    return this.respond(200, { csrfToken: token }, cookies);
  }

  // -------------------------------------------------------------------------
  // logout — POST (CSRF-protected, revokes server-side, idempotent)
  // -------------------------------------------------------------------------

  async logout(req: BrowserRequest): Promise<BrowserResponse> {
    if (req.method !== "POST") return this.respond(405, { error: "method_not_allowed" });
    const host = validateRequestHost(req, this.d.config.origin, this.d.config.trustProxy);
    if (!host.ok) {
      await this.event("browser.host_denied", req, "denied", host.reason, null, null, null);
      return this.respond(400, { error: "invalid_host" });
    }
    const origin = validateRequestOrigin(req, this.d.config.origin);
    if (!origin.ok) {
      await this.event("browser.csrf_denied", req, "denied", origin.reason, null, null, null);
      return this.respond(403, { error: "forbidden" });
    }

    const auth = await this.authenticate(req);
    const clearCookies = [clearSessionCookie(this.d.config), clearCsrfCookie(this.d.config)];

    if (auth.authenticated) {
      if (!this.csrfSatisfied(req, auth.session.sessionId)) {
        await this.event("browser.csrf_denied", req, "denied", "csrf_invalid", auth.principalId, auth.session.sessionId, null);
        return this.respond(403, { error: "csrf_failed" }); // do NOT revoke on a failed CSRF check
      }
      const revoked = await this.d.sessions.revokeSession(auth.session.sessionId, "logout");
      // Fail closed if revocation storage is unavailable: do NOT clear the cookie and
      // claim logout while the server-side credential is still active.
      if (!revoked.revoked && revoked.reason === "store_unavailable") {
        await this.event("browser.logout_completed", req, "denied", "revocation_store_unavailable", auth.principalId, auth.session.sessionId, null);
        return this.respond(503, { error: "unavailable" });
      }
      // Revoked, or already-revoked/unknown (idempotent) — the credential is not active.
      await this.event("browser.logout_completed", req, "success", null, auth.principalId, auth.session.sessionId, null);
      return this.respond(200, { ok: true }, clearCookies);
    }

    if (auth.reason === "session_store_unavailable") return this.respond(503, { error: "unavailable" });

    // Idempotent: nothing to revoke; clear cookies and succeed.
    await this.event("browser.logout_completed", req, "success", "no_active_session", null, null, null);
    return this.respond(200, { ok: true }, clearCookies);
  }

  // -------------------------------------------------------------------------
  // helpers
  // -------------------------------------------------------------------------

  /** Double-submit (cookie==header) AND keyed, session-bound MAC verification. */
  private csrfSatisfied(req: BrowserRequest, sessionId: string): boolean {
    const header = singleHeaderValue(req, this.d.config.csrfHeaderName);
    if (!header.ok) return false;
    const cookieToken = req.cookies[this.d.config.csrfCookieName];
    if (!cookieToken || cookieToken !== header.value) return false;
    return verifyCsrfToken(this.d.config.csrfKey, sessionId, header.value);
  }

  private correlation(reference: string): string {
    return hmacSha256Hex(this.d.evidenceDigestKey, `browser-corr:${reference}`);
  }

  private correlationFromCookie(req: BrowserRequest): string | null {
    const ref = req.cookies[this.d.config.loginCookieName];
    return ref ? this.correlation(ref) : null;
  }

  private respond(status: number, body: unknown, setCookies: readonly SetCookie[] = []): BrowserResponse {
    return { status, headers: authSecurityHeaders(this.d.config), setCookies, body };
  }

  private redirect(location: string, setCookies: readonly SetCookie[] = []): BrowserResponse {
    return { status: 302, headers: authSecurityHeaders(this.d.config), setCookies, body: null, location };
  }

  private event(
    type: BrowserAuthEventType,
    req: BrowserRequest,
    outcome: "success" | "denied",
    reason: string | null,
    principalId: string | null,
    sessionId: string | null,
    correlationDigest: string | null,
  ): Promise<void> {
    const event: BrowserAuthEvent = {
      type,
      at: req.receivedAt,
      requestId: req.requestId,
      outcome,
      reason,
      principalId,
      sessionId,
      correlationDigest,
    };
    return this.d.sink.append(event).catch(() => undefined);
  }
}
