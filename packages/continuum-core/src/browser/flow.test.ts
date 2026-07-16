/**
 * S4C — login initiation + callback over the REAL S4B/S4A/S3 path (deterministic
 * local authorization server; no bypass). A secure session cookie is issued ONLY
 * after complete() fully succeeds; every failure path issues no session and clears
 * the temporary login cookie.
 */
import { describe, expect, it } from "vitest";
import { buildHarness, login, mkReq, type Harness } from "./harness";

function sessionSet(res: { setCookies: readonly { name: string; value: string }[] }, name: string) {
  return res.setCookies.find((c) => c.name === name);
}
function issuedSession(res: { setCookies: readonly { name: string; value: string }[] }, name: string) {
  return res.setCookies.find((c) => c.name === name && c.value !== "");
}

describe("S4C login initiation", () => {
  it("creates exactly one S4B transaction, sets a login cookie, and redirects to the authorization server", async () => {
    const h = await buildHarness();
    const res = await h.controller.login(mkReq("GET", h.config.loginPath));
    expect(res.status).toBe(302);
    expect(res.location).toContain("https://authz.local/authorize");
    expect(res.location).toContain("code_challenge_method=S256");
    expect(sessionSet(res, h.config.loginCookieName)?.value).toBeTruthy();
    expect(h.authzSink.events.filter((e) => e.type === "authz.transaction_created")).toHaveLength(1);
    // The redirect target comes from trusted config, not from the caller.
    expect(res.location).not.toContain("evil");
  });

  it("denies an untrusted host", async () => {
    const h = await buildHarness();
    const res = await h.controller.login(mkReq("GET", h.config.loginPath, { host: "evil.example" }));
    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ error: "invalid_host" });
    expect(h.browserSink.events.some((e) => e.type === "browser.host_denied")).toBe(true);
  });

  it("permits an allowlisted relative returnTo and denies an absolute returnTo", async () => {
    const h = await buildHarness();
    const ok = await h.controller.login(mkReq("GET", h.config.loginPath, { query: { returnTo: "/app" } }));
    expect(ok.status).toBe(302);
    const bad = await h.controller.login(mkReq("GET", h.config.loginPath, { query: { returnTo: "https://evil.example" } }));
    expect(bad.status).toBe(400);
    expect(bad.body).toMatchObject({ error: "invalid_request" });
  });
});

describe("S4C callback — success", () => {
  it("issues a secure session cookie + a session-bound csrf cookie and clears the login cookie", async () => {
    const h = await buildHarness();
    const { cbRes } = await login(h);
    expect(cbRes.status).toBe(302);
    expect(cbRes.location).toBe(h.config.defaultReturnPath);

    const s = issuedSession(cbRes, h.config.sessionCookieName)!;
    expect(s.value).toMatch(/\./); // opaque `${sessionId}.${secret}`
    expect(s.name).toBe("__Host-continuum_session");

    const full = cbRes.setCookies.find((c) => c.name === h.config.sessionCookieName)!;
    expect(full.attributes.httpOnly).toBe(true);
    expect(full.attributes.secure).toBe(true);
    expect(full.attributes.sameSite).toBe("Lax");
    expect(full.attributes.domain).toBeUndefined();
    expect(full.attributes.maxAgeSeconds).toBeGreaterThan(0);
    expect(full.attributes.maxAgeSeconds).toBeLessThanOrEqual(3600);

    expect(issuedSession(cbRes, h.config.csrfCookieName)).toBeTruthy();

    const login_c = cbRes.setCookies.find((c) => c.name === h.config.loginCookieName)!;
    expect(login_c.value).toBe(""); // cleared
    expect(login_c.attributes.maxAgeSeconds).toBe(0);

    expect(h.browserSink.events.some((e) => e.type === "browser.session_issued" && e.outcome === "success")).toBe(true);
  });

  it("sets no-store + framing-denied security headers on auth responses", async () => {
    const h = await buildHarness();
    const { loginRes, cbRes } = await login(h);
    for (const res of [loginRes, cbRes]) {
      expect(res.headers["Cache-Control"]).toBe("no-store");
      expect(res.headers["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
      expect(res.headers["X-Content-Type-Options"]).toBe("nosniff");
    }
  });
});

describe("S4C callback — failures issue no session and clear the login cookie", () => {
  const cases: [string, string, number][] = [
    ["user_denied", "access_denied", 401],
    ["wrong_nonce", "authentication_failed", 401],
    ["malformed_token", "authentication_failed", 401],
    ["exchanger_outage", "authentication_failed", 401],
    ["delayed_response", "authentication_failed", 401],
    ["code_reuse", "authentication_failed", 401],
    ["wrong_issuer", "authentication_failed", 401],
    ["wrong_state", "authentication_failed", 401],
    ["missing_code", "invalid_request", 400],
    ["duplicate_code", "invalid_request", 400],
  ];
  for (const [scenario, error, status] of cases) {
    it(`${scenario} → ${error} (${status}), no session cookie`, async () => {
      const h = await buildHarness();
      const { cbRes } = await login(h, scenario as never);
      expect(cbRes.status).toBe(status);
      expect(cbRes.body).toMatchObject({ error });
      expect(issuedSession(cbRes, h.config.sessionCookieName)).toBeUndefined();
      // Temporary login cookie is cleared on terminal failure.
      const lc = cbRes.setCookies.find((c) => c.name === h.config.loginCookieName);
      expect(lc?.value).toBe("");
    });
  }

  it("denies a suspended principal with no session minted", async () => {
    const h = await buildHarness();
    const { cbRes } = await login(h, "success", "user-suspended");
    expect(cbRes.status).toBe(401);
    expect(issuedSession(cbRes, h.config.sessionCookieName)).toBeUndefined();
  });
});

describe("S4C callback — replay after a successful login is denied", () => {
  it("a second callback with the same state/code mints no new session", async () => {
    const h: Harness = await buildHarness();
    const { authz, loginCookie, cbRes } = await login(h);
    expect(cbRes.status).toBe(302); // first succeeded
    const replay = await h.controller.callback(
      mkReq("GET", h.config.callbackPath, {
        query: authz.callbackQuery,
        cookies: loginCookie ? { [h.config.loginCookieName]: loginCookie.value } : {},
      }),
    );
    expect(replay.status).toBe(401);
    expect(issuedSession(replay, h.config.sessionCookieName)).toBeUndefined();
  });
});
