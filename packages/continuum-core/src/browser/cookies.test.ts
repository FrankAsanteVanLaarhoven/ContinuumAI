/**
 * S4C — cookie attributes and serialization. Production session cookies are
 * HttpOnly + Secure + SameSite=Lax + Path=/ + host-only with a secure prefix and a
 * bounded lifetime; clears reissue the same attributes with Max-Age=0.
 */
import { describe, expect, it } from "vitest";
import { resolveBrowserAuthConfig } from "./config";
import {
  boundedMaxAge,
  clearCsrfCookie,
  clearLoginCookie,
  clearSessionCookie,
  csrfCookie,
  loginCookie,
  sessionCookie,
} from "./cookies";
import { serializeSetCookie } from "./http";

const CSRF_KEY = Buffer.from("csrf-signing-key-0123456789abcdef").toString("base64");

function config(origin: string) {
  return resolveBrowserAuthConfig({
    NODE_ENV: "development",
    CONTINUUM_BROWSER_AUTH: "enabled",
    CONTINUUM_AUTH_SERVER: "deterministic-local",
    CONTINUUM_EXTERNAL_ORIGIN: origin,
    CONTINUUM_TRUST_PROXY: "false",
    CONTINUUM_AUTH_ISSUER: "https://issuer.test",
    CONTINUUM_CSRF_KEY: CSRF_KEY,
  } as NodeJS.ProcessEnv);
}

const NOW = new Date("2026-07-16T00:00:00.000Z");
const ABS = new Date(NOW.getTime() + 3600_000);

describe("S4C cookies", () => {
  it("production-shaped session cookie: HttpOnly, Secure, SameSite=Lax, Path=/, __Host-, no Domain, bounded", () => {
    const c = config("https://app.example");
    const cookie = sessionCookie(c, "sess_abc.secretvalue", ABS, NOW);
    expect(cookie.name).toBe("__Host-continuum_session");
    expect(cookie.attributes.httpOnly).toBe(true);
    expect(cookie.attributes.secure).toBe(true);
    expect(cookie.attributes.sameSite).toBe("Lax");
    expect(cookie.attributes.path).toBe("/");
    expect(cookie.attributes.domain).toBeUndefined();
    expect(cookie.attributes.maxAgeSeconds).toBe(3600);
    const s = serializeSetCookie(cookie);
    expect(s).toContain("__Host-continuum_session=sess_abc.secretvalue");
    expect(s).toMatch(/HttpOnly/);
    expect(s).toMatch(/Secure/);
    expect(s).toMatch(/SameSite=Lax/);
    expect(s).toMatch(/Path=\//);
    expect(s).not.toMatch(/Domain=/);
  });

  it("cookie value carries only the opaque credential (no tenant/role embedded)", () => {
    const c = config("https://app.example");
    const s = serializeSetCookie(sessionCookie(c, "sess_abc.secretvalue", ABS, NOW));
    expect(s).not.toMatch(/tenant/i);
    expect(s).not.toMatch(/role/i);
  });

  it("Max-Age never exceeds the absolute session expiry", () => {
    expect(boundedMaxAge(ABS, NOW)).toBe(3600);
    // A past absolute expiry floors at 0 (never negative / unbounded).
    expect(boundedMaxAge(new Date(NOW.getTime() - 1000), NOW)).toBe(0);
  });

  it("csrf cookie is non-HttpOnly (readable by client JS) but still Secure", () => {
    const c = config("https://app.example");
    const cookie = csrfCookie(c, "nonce.mac", ABS, NOW);
    expect(cookie.attributes.httpOnly).toBe(false);
    expect(cookie.attributes.secure).toBe(true);
    expect(serializeSetCookie(cookie)).not.toMatch(/HttpOnly/);
  });

  it("login cookie is HttpOnly and short-lived", () => {
    const c = config("https://app.example");
    const cookie = loginCookie(c, "txn-123");
    expect(cookie.attributes.httpOnly).toBe(true);
    expect(cookie.attributes.maxAgeSeconds).toBe(300);
  });

  it("clears reissue empty value + Max-Age=0 with matching attributes", () => {
    const c = config("https://app.example");
    for (const cookie of [clearSessionCookie(c), clearCsrfCookie(c), clearLoginCookie(c)]) {
      expect(cookie.value).toBe("");
      expect(cookie.attributes.maxAgeSeconds).toBe(0);
      expect(serializeSetCookie(cookie)).toMatch(/Max-Age=0/);
    }
  });

  it("serialization enforces the __Host- prefix contract", () => {
    // __Host- requires Secure — an insecure __Host- cookie must not serialize.
    expect(() =>
      serializeSetCookie({ name: "__Host-x", value: "v", attributes: { httpOnly: true, secure: false, sameSite: "Lax", path: "/" } }),
    ).toThrow(/Secure/);
    // __Host- requires Path=/
    expect(() =>
      serializeSetCookie({ name: "__Host-x", value: "v", attributes: { httpOnly: true, secure: true, sameSite: "Lax", path: "/auth" } }),
    ).toThrow(/Path=\//);
    // __Host- must not set Domain
    expect(() =>
      serializeSetCookie({ name: "__Host-x", value: "v", attributes: { httpOnly: true, secure: true, sameSite: "Lax", path: "/", domain: "example.com" } }),
    ).toThrow(/Domain/);
  });
});
