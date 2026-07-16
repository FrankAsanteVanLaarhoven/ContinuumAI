/**
 * S4C — console browser-auth wiring. The Next.js adapter maps native request/
 * response onto the framework-neutral controller, drives a real deterministic
 * login→callback, and fails closed in production.
 */
import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import type { BrowserRequest } from "@continuum/core";
import { createBrowserAuth, toBrowserRequest, toNextResponse } from "./browser-auth";

const CSRF_KEY = Buffer.from("console-csrf-key-0123456789abcdef").toString("base64");

function devEnv(over: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "development",
    CONTINUUM_BROWSER_AUTH: "enabled",
    CONTINUUM_AUTH_SERVER: "deterministic-local",
    CONTINUUM_EXTERNAL_ORIGIN: "https://app.example",
    CONTINUUM_TRUST_PROXY: "false",
    CONTINUUM_AUTH_ISSUER: "https://issuer.test",
    CONTINUUM_CSRF_KEY: CSRF_KEY,
    ...over,
  } as NodeJS.ProcessEnv;
}

function mk(method: string, path: string, o: { query?: Record<string, string | string[]>; cookies?: Record<string, string>; at?: Date } = {}): BrowserRequest {
  return { method, path, query: o.query ?? {}, headers: { host: "app.example" }, cookies: o.cookies ?? {}, requestId: "r", receivedAt: o.at ?? new Date() };
}

describe("S4C console browser-auth wiring", () => {
  it("drives a working deterministic login → callback issuing a session cookie", async () => {
    const { controller, local, config } = await createBrowserAuth(devEnv());
    const now = new Date();
    const loginRes = await controller.login(mk("GET", config.loginPath, { at: now }));
    expect(loginRes.status).toBe(302);
    const loginCookie = loginRes.setCookies.find((c) => c.name === config.loginCookieName);
    const authz = await local.authorize(loginRes.location!, { now });
    const cbRes = await controller.callback(
      mk("GET", config.callbackPath, { query: authz.callbackQuery, cookies: loginCookie ? { [config.loginCookieName]: loginCookie.value } : {}, at: now }),
    );
    expect(cbRes.status).toBe(302);
    expect(cbRes.setCookies.some((c) => c.name === config.sessionCookieName && c.value !== "")).toBe(true);
  });

  it("toNextResponse serializes a redirect with a Set-Cookie header", async () => {
    const { controller, config } = await createBrowserAuth(devEnv());
    const loginRes = await controller.login(mk("GET", config.loginPath));
    const next = toNextResponse(loginRes);
    expect(next.status).toBe(302);
    expect(next.headers.get("location")).toBe(loginRes.location);
    expect(next.headers.get("Cache-Control")).toBe("no-store");
    const setCookies = next.headers.getSetCookie();
    expect(setCookies.some((c) => c.startsWith(config.loginCookieName))).toBe(true);
  });

  it("toBrowserRequest maps method, path, query and cookies from a NextRequest", () => {
    const nreq = new NextRequest(new URL("https://app.example/api/auth/login?returnTo=%2Fapp"), {
      headers: { host: "app.example", cookie: "__Host-continuum_session=abc.def" },
    });
    const br = toBrowserRequest(nreq);
    expect(br.method).toBe("GET");
    expect(br.path).toBe("/api/auth/login");
    expect(br.query.returnTo).toBe("/app");
    expect(br.cookies["__Host-continuum_session"]).toBe("abc.def");
  });

  it("fails closed in production (deterministic-local refused)", async () => {
    await expect(createBrowserAuth(devEnv({ NODE_ENV: "production", CONTINUUM_SESSION_COOKIE_NAME: "__Host-continuum_session" }))).rejects.toThrow();
  });
});
