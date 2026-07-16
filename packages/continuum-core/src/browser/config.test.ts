/**
 * S4C — browser-auth configuration guards. Fail-closed; every production-forbidden
 * setting is rejected, with no silent fallback.
 */
import { describe, expect, it } from "vitest";
import { resolveBrowserAuthConfig, assertProductionBrowserAuthConfig } from "./config";

const CSRF_KEY = Buffer.from("csrf-signing-key-0123456789abcdef").toString("base64");

function devEnv(over: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "development",
    CONTINUUM_BROWSER_AUTH: "enabled",
    CONTINUUM_AUTH_SERVER: "deterministic-local",
    CONTINUUM_EXTERNAL_ORIGIN: "http://localhost:4311",
    CONTINUUM_TRUST_PROXY: "false",
    CONTINUUM_AUTH_ISSUER: "https://issuer.test",
    CONTINUUM_CSRF_KEY: CSRF_KEY,
    ...over,
  } as NodeJS.ProcessEnv;
}

function prodEnv(over: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return devEnv({
    NODE_ENV: "production",
    CONTINUUM_EXTERNAL_ORIGIN: "https://app.example",
    CONTINUUM_SESSION_COOKIE_NAME: "__Host-continuum_session",
    ...over,
  });
}

describe("S4C browser-auth config", () => {
  it("resolves a valid dev configuration", () => {
    const c = resolveBrowserAuthConfig(devEnv());
    expect(c.authServer).toBe("deterministic-local");
    expect(c.origin.value).toBe("http://localhost:4311");
    expect(c.cookieSecure).toBe(false); // http origin, non-production
    expect(c.sessionCookieName).toBe("continuum_session");
    expect(c.trustProxy).toBe(false);
    expect(c.hsts).toBe(false);
    expect(c.defaultReturnPath).toBe("/");
  });

  it("derives Secure + secure-prefixed cookie names for an https origin", () => {
    const c = resolveBrowserAuthConfig(devEnv({ CONTINUUM_EXTERNAL_ORIGIN: "https://app.example" }));
    expect(c.cookieSecure).toBe(true);
    expect(c.sessionCookieName).toBe("__Host-continuum_session");
    expect(c.csrfCookieName).toBe("__Host-continuum_csrf");
  });

  it("requires CONTINUUM_BROWSER_AUTH=enabled", () => {
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_BROWSER_AUTH: undefined }))).toThrow(/CONTINUUM_BROWSER_AUTH/);
  });

  it("requires a set authorization server and a set issuer / csrf key", () => {
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_AUTH_SERVER: undefined }))).toThrow(/CONTINUUM_AUTH_SERVER/);
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_AUTH_ISSUER: undefined }))).toThrow(/CONTINUUM_AUTH_ISSUER/);
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_CSRF_KEY: undefined }))).toThrow(/CONTINUUM_CSRF_KEY/);
  });

  it("rejects a missing / wildcard / malformed external origin", () => {
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_EXTERNAL_ORIGIN: undefined }))).toThrow(/EXTERNAL_ORIGIN/);
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_EXTERNAL_ORIGIN: "https://*.example" }))).toThrow(/EXTERNAL_ORIGIN/);
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_EXTERNAL_ORIGIN: "https://app.example/path" }))).toThrow(/EXTERNAL_ORIGIN/);
  });

  it("rejects arbitrary proxy-trust values (only 'true'/'false')", () => {
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_TRUST_PROXY: "maybe" }))).toThrow(/TRUST_PROXY/);
    expect(resolveBrowserAuthConfig(devEnv({ CONTINUUM_TRUST_PROXY: "true" })).trustProxy).toBe(true);
  });

  it("rejects a secure-prefixed cookie name that cannot be honoured on an insecure origin (startup)", () => {
    // http origin → cookieSecure=false → a __Host- name is refused at config time.
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_SESSION_COOKIE_NAME: "__Host-continuum_session" }))).toThrow(/secure prefix/);
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_CSRF_COOKIE_NAME: "__Secure-csrf" }))).toThrow(/secure prefix/);
  });

  it("rejects a non-allowlisted-shape return path", () => {
    expect(() => resolveBrowserAuthConfig(devEnv({ CONTINUUM_AUTH_RETURN_PATHS: "https://evil.example" }))).toThrow(/RETURN_PATHS/);
    const c = resolveBrowserAuthConfig(devEnv({ CONTINUUM_AUTH_RETURN_PATHS: "/,/app" }));
    expect(c.allowedReturnPaths).toEqual(["/", "/app"]);
  });

  // --- production rejections (each independently reachable) ---

  it("production refuses an insecure (http) external origin", () => {
    expect(() => resolveBrowserAuthConfig(prodEnv({ CONTINUUM_EXTERNAL_ORIGIN: "http://app.example" }))).toThrow(/https in production/);
  });

  it("production refuses a session cookie without a secure prefix", () => {
    expect(() => resolveBrowserAuthConfig(prodEnv({ CONTINUUM_SESSION_COOKIE_NAME: "continuum_session" }))).toThrow(/secure prefix/);
  });

  it("production refuses a missing CSRF key", () => {
    expect(() => resolveBrowserAuthConfig(prodEnv({ CONTINUUM_CSRF_KEY: undefined }))).toThrow(/CSRF/);
  });

  it("production refuses the deterministic-local authorization server (final fail-closed)", () => {
    expect(() => resolveBrowserAuthConfig(prodEnv())).toThrow(/deterministic-local is refused in production/);
  });

  it("assertProductionBrowserAuthConfig is a no-op in dev and throws in production", () => {
    expect(() => assertProductionBrowserAuthConfig(devEnv())).not.toThrow();
    expect(() => assertProductionBrowserAuthConfig(prodEnv())).toThrow();
  });
});
