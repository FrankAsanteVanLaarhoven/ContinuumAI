/**
 * S4C — session status endpoint, CSRF issuance, and CSRF-protected idempotent
 * logout. Logout revokes the server-side session BEFORE clearing the cookie; a
 * failed CSRF check never revokes; safe/other methods cannot mutate.
 */
import { describe, expect, it } from "vitest";
import {
  BrowserAuthController,
  InMemoryBrowserAuthEventSink,
  makeRouteClassifier,
  mintCsrfToken,
  resolveBrowserAuthConfig,
  verifyCsrfToken,
} from "./index";
import type { AuthorizationCodeFlow, SessionManager } from "../identity";
import { buildHarness, login, mkReq, ORIGIN, type Harness } from "./harness";

const DENYING_FLOW = { async begin() { throw new Error("nyi"); }, async complete() { throw new Error("nyi"); } } as unknown as AuthorizationCodeFlow;

function issued(res: { setCookies: readonly { name: string; value: string }[] }, name: string): string | undefined {
  return res.setCookies.find((c) => c.name === name && c.value !== "")?.value;
}
function cleared(res: { setCookies: readonly { name: string; value: string }[] }, name: string): boolean {
  return res.setCookies.some((c) => c.name === name && c.value === "");
}
async function authed(h: Harness) {
  const { cbRes } = await login(h);
  const session = issued(cbRes, h.config.sessionCookieName)!;
  const csrf = issued(cbRes, h.config.csrfCookieName)!;
  const sid = h.browserSink.events.find((e) => e.type === "browser.session_issued")!.sessionId!;
  return { session, csrf, sid };
}

describe("S4C session status endpoint", () => {
  it("returns the principal (no tenant, no credential) when authenticated", async () => {
    const h = await buildHarness();
    const { session } = await authed(h);
    const res = await h.controller.session(mkReq("GET", "/api/auth/session", { cookies: { [h.config.sessionCookieName]: session } }));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ authenticated: true, principalId: "P-user-1" });
    const body = JSON.stringify(res.body);
    expect(body).not.toMatch(/tenant/i);
    expect(body).not.toContain(session); // never echoes the credential
    expect(res.headers["Cache-Control"]).toBe("no-store");
  });

  it("reports unauthenticated for a missing cookie and clears on a bad cookie", async () => {
    const h = await buildHarness();
    expect((await h.controller.session(mkReq("GET", "/api/auth/session"))).body).toMatchObject({ authenticated: false });
    const bad = await h.controller.session(mkReq("GET", "/api/auth/session", { cookies: { [h.config.sessionCookieName]: "garbage" } }));
    expect(bad.body).toMatchObject({ authenticated: false });
    expect(cleared(bad, h.config.sessionCookieName)).toBe(true);
  });

  it("rejects a non-GET method", async () => {
    const h = await buildHarness();
    expect((await h.controller.session(mkReq("POST", "/api/auth/session"))).status).toBe(405);
  });
});

describe("S4C CSRF issuance", () => {
  it("issues a session-bound token to an authenticated same-origin caller", async () => {
    const h = await buildHarness();
    const { session, sid } = await authed(h);
    const res = await h.controller.csrf(mkReq("POST", "/api/auth/csrf", { cookies: { [h.config.sessionCookieName]: session }, headers: { origin: ORIGIN } }));
    expect(res.status).toBe(200);
    const token = (res.body as { csrfToken: string }).csrfToken;
    expect(verifyCsrfToken(h.config.csrfKey, sid, token)).toBe(true);
    expect(issued(res, h.config.csrfCookieName)).toBe(token);
  });

  it("denies an unauthenticated caller (401) and an invalid origin (403)", async () => {
    const h = await buildHarness();
    const { session } = await authed(h);
    expect((await h.controller.csrf(mkReq("POST", "/api/auth/csrf", { headers: { origin: ORIGIN } }))).status).toBe(401);
    expect((await h.controller.csrf(mkReq("POST", "/api/auth/csrf", { cookies: { [h.config.sessionCookieName]: session }, headers: { origin: "https://evil.example" } }))).status).toBe(403);
  });

  it("rejects a non-POST method", async () => {
    const h = await buildHarness();
    expect((await h.controller.csrf(mkReq("GET", "/api/auth/csrf"))).status).toBe(405);
  });
});

describe("S4C logout", () => {
  const logoutReq = (h: Harness, session: string, csrf: string | undefined, over: { origin?: string; header?: string } = {}) =>
    mkReq("POST", "/api/auth/logout", {
      cookies: { [h.config.sessionCookieName]: session, ...(csrf ? { [h.config.csrfCookieName]: csrf } : {}) },
      headers: { origin: over.origin ?? ORIGIN, ...(over.header !== undefined ? { [h.config.csrfHeaderName]: over.header } : {}) },
    });

  it("with valid CSRF: revokes server-side, clears cookies, and is recorded", async () => {
    const h = await buildHarness();
    const { session, csrf } = await authed(h);
    const res = await h.controller.logout(logoutReq(h, session, csrf, { header: csrf }));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true });
    expect(cleared(res, h.config.sessionCookieName)).toBe(true);
    expect(cleared(res, h.config.csrfCookieName)).toBe(true);
    // Server-side revocation took effect (not just a cleared cookie).
    expect(await h.controller.authenticate(mkReq("GET", "/x", { cookies: { [h.config.sessionCookieName]: session } }))).toMatchObject({ authenticated: false, reason: "session_revoked" });
    expect(h.browserSink.events.some((e) => e.type === "browser.logout_completed")).toBe(true);
  });

  it("denies (and does NOT revoke) on a missing, wrong, or cross-session CSRF token", async () => {
    const cross = mintCsrfToken(Buffer.from("browser-csrf-key-0123456789abcde").toString("base64"), "some-other-session");
    for (const header of [undefined, "wrong.token", cross]) {
      const h = await buildHarness();
      const { session, csrf } = await authed(h);
      const res = await h.controller.logout(logoutReq(h, session, csrf, header === undefined ? {} : { header }));
      expect(res.status).toBe(403);
      // Still authenticated — a failed CSRF check must not terminate the session.
      expect(await h.controller.authenticate(mkReq("GET", "/x", { cookies: { [h.config.sessionCookieName]: session } }))).toMatchObject({ authenticated: true });
    }
  });

  it("denies a cross-origin logout", async () => {
    const h = await buildHarness();
    const { session, csrf } = await authed(h);
    const res = await h.controller.logout(logoutReq(h, session, csrf, { origin: "https://evil.example", header: csrf }));
    expect(res.status).toBe(403);
  });

  it("is idempotent: a repeat logout without a session still succeeds", async () => {
    const h = await buildHarness();
    const res = await h.controller.logout(mkReq("POST", "/api/auth/logout", { headers: { origin: ORIGIN } }));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true });
  });

  it("rejects a non-POST method (a GET cannot mutate)", async () => {
    const h = await buildHarness();
    expect((await h.controller.logout(mkReq("GET", "/api/auth/logout"))).status).toBe(405);
  });

  it("fails closed when revocation storage is unavailable (503, no cookie cleared, credential stays active)", async () => {
    const CSRF = Buffer.from("logout-outage-key-0123456789abcd").toString("base64");
    const config = resolveBrowserAuthConfig({
      NODE_ENV: "development", CONTINUUM_BROWSER_AUTH: "enabled", CONTINUUM_AUTH_SERVER: "deterministic-local",
      CONTINUUM_EXTERNAL_ORIGIN: "https://app.example", CONTINUUM_TRUST_PROXY: "false",
      CONTINUUM_AUTH_ISSUER: "https://issuer.test", CONTINUUM_CSRF_KEY: CSRF,
    } as NodeJS.ProcessEnv);
    const sessions: SessionManager = {
      async createSession() { throw new Error("nyi"); },
      async validateSession() {
        return { valid: true, session: { sessionId: "sess-x", principalId: "P", authenticationStrength: "single_factor", issuedAt: new Date(0), expiresAt: new Date(Date.now() + 3600_000), identityMappingVersion: "1" } };
      },
      async rotateSession() { throw new Error("nyi"); },
      async revokeSession() { return { revoked: false, reason: "store_unavailable" }; },
    };
    const controller = new BrowserAuthController({
      config, flow: DENYING_FLOW, sessions, sink: new InMemoryBrowserAuthEventSink(),
      routes: makeRouteClassifier([]), evidenceDigestKey: Buffer.from("e".repeat(32)).toString("base64"),
    });
    const token = mintCsrfToken(CSRF, "sess-x");
    const res = await controller.logout(mkReq("POST", "/api/auth/logout", {
      cookies: { [config.sessionCookieName]: "sess-x.secret", [config.csrfCookieName]: token },
      headers: { origin: ORIGIN, [config.csrfHeaderName]: token },
    }));
    expect(res.status).toBe(503);
    // Cookie NOT cleared — clearing would hide a still-active server-side credential.
    expect(res.setCookies).toHaveLength(0);
  });
});
