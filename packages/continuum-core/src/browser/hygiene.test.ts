/**
 * S4C — secret hygiene. Evidence and response/error bodies never contain raw
 * cookies, raw state/code/nonce, the session credential, or the CSRF token; error
 * bodies never echo caller-supplied inputs.
 */
import { describe, expect, it } from "vitest";
import { buildHarness, login, mkReq } from "./harness";

describe("S4C secret hygiene", () => {
  it("no raw state/code/nonce/credential/csrf appears in evidence after a successful login", async () => {
    const h = await buildHarness();
    const { loginRes, authz, cbRes } = await login(h);
    const url = new URL(loginRes.location!);
    const state = url.searchParams.get("state")!;
    const nonce = url.searchParams.get("nonce")!;
    const code = (authz.callbackQuery.code as string) ?? "";
    const sessionCred = cbRes.setCookies.find((c) => c.name === h.config.sessionCookieName && c.value !== "")!.value;
    const csrfToken = cbRes.setCookies.find((c) => c.name === h.config.csrfCookieName && c.value !== "")!.value;

    const evidence = JSON.stringify(h.browserSink.events) + JSON.stringify(h.authzSink.events);
    for (const secret of [state, nonce, code, sessionCred, csrfToken]) {
      expect(secret.length).toBeGreaterThan(0);
      expect(evidence).not.toContain(secret);
    }
    // The session credential's secret half also never appears.
    const secretHalf = sessionCred.slice(sessionCred.indexOf(".") + 1);
    expect(evidence).not.toContain(secretHalf);
  });

  it("a denied callback error body does not echo caller-supplied code/state", async () => {
    const h = await buildHarness();
    const res = await h.controller.callback(mkReq("GET", h.config.callbackPath, { query: { code: "SECRETCODE123", state: "SECRETSTATE456" } }));
    const body = JSON.stringify(res.body);
    expect(body).not.toContain("SECRETCODE123");
    expect(body).not.toContain("SECRETSTATE456");
    expect(res.body).toMatchObject({ error: expect.any(String) });
    // Evidence records the failure reason + a keyed digest, never the raw inputs.
    const evidence = JSON.stringify(h.browserSink.events);
    expect(evidence).not.toContain("SECRETCODE123");
    expect(evidence).not.toContain("SECRETSTATE456");
  });

  it("the browser login rides the genuine S4B state machine (transaction created + session created), unchanged", async () => {
    const h = await buildHarness();
    await login(h);
    const types = h.authzSink.events.map((e) => e.type);
    expect(types).toContain("authz.transaction_created");
    expect(types).toContain("authz.session_created");
    expect(types).toContain("authz.transaction_completed");
  });
});
