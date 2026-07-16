/**
 * S4C — authenticated-request middleware. Resolves the internal principal from a
 * validated S3 session and NEVER returns tenant authority; denies default-protected
 * routes; fails closed on a session-store outage; clears on a genuinely bad cookie.
 */
import { describe, expect, it } from "vitest";
import {
  BrowserAuthController,
  InMemoryBrowserAuthEventSink,
  makeRouteClassifier,
  mapSessionFailure,
  resolveBrowserAuthConfig,
  shouldClearOnDeny,
} from "./index";
import type {
  AuthorizationCodeFlow,
  SessionCredential,
  SessionManager,
  SessionValidationInput,
  SessionValidationResult,
} from "../identity";
import { buildHarness, login, mkReq } from "./harness";

function sessionCookieValue(res: { setCookies: readonly { name: string; value: string }[] }, name: string): string {
  return res.setCookies.find((c) => c.name === name && c.value !== "")!.value;
}

const DENYING_FLOW = {
  async begin() { throw new Error("not used"); },
  async complete() { throw new Error("not used"); },
} as unknown as AuthorizationCodeFlow;

function stubController(sessions: SessionManager) {
  const config = resolveBrowserAuthConfig({
    NODE_ENV: "development", CONTINUUM_BROWSER_AUTH: "enabled", CONTINUUM_AUTH_SERVER: "deterministic-local",
    CONTINUUM_EXTERNAL_ORIGIN: "https://app.example", CONTINUUM_TRUST_PROXY: "false",
    CONTINUUM_AUTH_ISSUER: "https://issuer.test", CONTINUUM_CSRF_KEY: Buffer.from("k".repeat(32)).toString("base64"),
  } as NodeJS.ProcessEnv);
  return new BrowserAuthController({
    config, flow: DENYING_FLOW, sessions, sink: new InMemoryBrowserAuthEventSink(),
    routes: makeRouteClassifier([]), evidenceDigestKey: Buffer.from("e".repeat(32)).toString("base64"),
  });
}

describe("S4C middleware — authenticate()", () => {
  it("missing cookie → unauthenticated (missing_cookie)", async () => {
    const h = await buildHarness();
    expect(await h.controller.authenticate(mkReq("GET", "/x"))).toMatchObject({ authenticated: false, reason: "missing_cookie" });
  });

  it("malformed cookie → malformed_cookie", async () => {
    const h = await buildHarness();
    const r = await h.controller.authenticate(mkReq("GET", "/x", { cookies: { [h.config.sessionCookieName]: "no-dot-here" } }));
    expect(r).toMatchObject({ authenticated: false, reason: "malformed_cookie" });
  });

  it("valid cookie authenticates and returns a principal but NO tenant authority", async () => {
    const h = await buildHarness();
    const { cbRes } = await login(h);
    const cred = sessionCookieValue(cbRes, h.config.sessionCookieName);
    const auth = await h.controller.authenticate(mkReq("GET", "/x", { cookies: { [h.config.sessionCookieName]: cred } }));
    expect(auth.authenticated).toBe(true);
    if (auth.authenticated) {
      expect(auth.principalId).toBe("P-user-1");
      expect("tenant" in auth).toBe(false);
      expect(JSON.stringify(auth)).not.toMatch(/tenant/i);
    }
  });

  it("revoked session denies immediately", async () => {
    const h = await buildHarness();
    const { cbRes } = await login(h);
    const cred = sessionCookieValue(cbRes, h.config.sessionCookieName);
    const sid = h.browserSink.events.find((e) => e.type === "browser.session_issued")!.sessionId!;
    await h.sessions.revokeSession(sid, "logout");
    const r = await h.controller.authenticate(mkReq("GET", "/x", { cookies: { [h.config.sessionCookieName]: cred } }));
    expect(r).toMatchObject({ authenticated: false, reason: "session_revoked" });
  });

  it("idle-expired and absolute-expired sessions deny (session_expired)", async () => {
    const h = await buildHarness();
    const { cbRes } = await login(h);
    const cred = sessionCookieValue(cbRes, h.config.sessionCookieName);
    const idle = await h.controller.authenticate(mkReq("GET", "/x", { cookies: { [h.config.sessionCookieName]: cred }, at: new Date(h.clock.now.getTime() + 1000_000) }));
    expect(idle).toMatchObject({ authenticated: false, reason: "session_expired" });
    const abs = await h.controller.authenticate(mkReq("GET", "/x", { cookies: { [h.config.sessionCookieName]: cred }, at: new Date(h.clock.now.getTime() + 4000_000) }));
    expect(abs).toMatchObject({ authenticated: false, reason: "session_expired" });
  });

  it("a rotated old cookie denies (session_revoked)", async () => {
    const h = await buildHarness();
    const { cbRes } = await login(h);
    const cred = sessionCookieValue(cbRes, h.config.sessionCookieName);
    const sid = h.browserSink.events.find((e) => e.type === "browser.session_issued")!.sessionId!;
    const rotated = await h.sessions.rotateSession({ sessionId: sid }, "reauthentication");
    // Old credential now denies; the new one authenticates — never both active.
    expect(await h.controller.authenticate(mkReq("GET", "/x", { cookies: { [h.config.sessionCookieName]: cred } }))).toMatchObject({ authenticated: false, reason: "session_revoked" });
    expect(await h.controller.authenticate(mkReq("GET", "/x", { cookies: { [h.config.sessionCookieName]: rotated.credential.value } }))).toMatchObject({ authenticated: true });
  });

  it("session-store outage fails closed (session_store_unavailable)", async () => {
    const outage: SessionManager = {
      async createSession() { throw new Error("nyi"); },
      async validateSession(_c: SessionCredential, _i: SessionValidationInput): Promise<SessionValidationResult> {
        return { valid: false, reason: "store_unavailable" };
      },
      async rotateSession() { throw new Error("nyi"); },
      async revokeSession() { return { revoked: false, reason: "store_unavailable" }; },
    };
    const c = stubController(outage);
    const r = await c.authenticate(mkReq("GET", "/x", { cookies: { "continuum_session": "sess.secret" } }));
    // The default (https) config uses __Host- names — supply that cookie name.
    const r2 = await c.authenticate(mkReq("GET", "/x", { cookies: { "__Host-continuum_session": "sess.secret" } }));
    expect(r.authenticated).toBe(false);
    expect(r2).toMatchObject({ authenticated: false, reason: "session_store_unavailable" });
  });
});

describe("S4C middleware — route classification + mapping", () => {
  it("public routes are explicit; unclassified routes default to protected", () => {
    const rc = makeRouteClassifier(["/api/auth/login", "/api/auth/callback", "/api/auth/session"]);
    expect(rc.isPublic("/api/auth/login")).toBe(true);
    expect(rc.isPublic("/api/auth/logout")).toBe(false); // logout needs auth+CSRF
    expect(rc.isPublic("/api/admin")).toBe(false);
    expect(rc.isPublic("/api/auth/login/extra")).toBe(false); // no prefix leakage
  });

  it("maps every S3 session failure to a deny reason and clears only genuine failures", () => {
    expect(mapSessionFailure("malformed_credential")).toBe("malformed_cookie");
    expect(mapSessionFailure("store_unavailable")).toBe("session_store_unavailable");
    expect(mapSessionFailure("policy_version_stale")).toBe("session_stale");
    expect(shouldClearOnDeny("session_store_unavailable")).toBe(false);
    expect(shouldClearOnDeny("missing_cookie")).toBe(false);
    expect(shouldClearOnDeny("session_revoked")).toBe(true);
  });
});
