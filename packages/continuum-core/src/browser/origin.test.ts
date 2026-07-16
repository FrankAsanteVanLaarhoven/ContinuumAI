/**
 * S4C — host, forwarded-header, return-target and origin validation. Redirect and
 * post-login destinations are never derived from arbitrary request headers.
 */
import { describe, expect, it } from "vitest";
import type { BrowserRequest } from "./http";
import {
  parseOrigin,
  resolveReturnTo,
  validateRequestHost,
  validateRequestOrigin,
} from "./origin";

function mkReq(headers: Record<string, string | string[]>, query: Record<string, string | string[]> = {}): BrowserRequest {
  return { method: "GET", path: "/", query, headers, cookies: {}, requestId: "r", receivedAt: new Date(0) };
}

const ORIGIN = parseOrigin("https://app.example")!;

describe("S4C parseOrigin", () => {
  it("parses a valid origin and elides the default port", () => {
    expect(parseOrigin("https://app.example")!.authority).toBe("app.example");
    expect(parseOrigin("https://app.example:8443")!.authority).toBe("app.example:8443");
    expect(parseOrigin("https://app.example:443")!.authority).toBe("app.example");
  });
  it("rejects wildcards, paths, and non-http schemes", () => {
    expect(parseOrigin("https://*.example")).toBeNull();
    expect(parseOrigin("https://app.example/callback")).toBeNull();
    expect(parseOrigin("ftp://app.example")).toBeNull();
    expect(parseOrigin(undefined)).toBeNull();
  });
});

describe("S4C validateRequestHost", () => {
  it("accepts the configured host", () => {
    expect(validateRequestHost(mkReq({ host: "app.example" }), ORIGIN, false)).toEqual({ ok: true });
  });
  it("rejects an unregistered host", () => {
    expect(validateRequestHost(mkReq({ host: "evil.example" }), ORIGIN, false)).toMatchObject({ ok: false, reason: "host_mismatch" });
  });
  it("rejects a missing host", () => {
    expect(validateRequestHost(mkReq({}), ORIGIN, false)).toMatchObject({ ok: false, reason: "host_missing" });
  });
  it("ignores a forged forwarded host when trusted-proxy mode is OFF", () => {
    const req = mkReq({ host: "app.example", "x-forwarded-host": "evil.example" });
    expect(validateRequestHost(req, ORIGIN, false)).toEqual({ ok: true });
  });
  it("honours (and validates) the forwarded host only when trusted-proxy mode is ON", () => {
    const forged = mkReq({ host: "app.example", "x-forwarded-host": "evil.example" });
    expect(validateRequestHost(forged, ORIGIN, true)).toMatchObject({ ok: false, reason: "host_mismatch" });
    const good = mkReq({ host: "internal", "x-forwarded-host": "app.example", "x-forwarded-proto": "https" });
    expect(validateRequestHost(good, ORIGIN, true)).toEqual({ ok: true });
  });
  it("rejects conflicting forwarded values", () => {
    const req = mkReq({ host: "app.example", "x-forwarded-host": ["app.example", "evil.example"] });
    expect(validateRequestHost(req, ORIGIN, true)).toMatchObject({ ok: false, reason: "forwarded_conflict" });
  });
  it("rejects a mismatched forwarded scheme", () => {
    const req = mkReq({ host: "app.example", "x-forwarded-host": "app.example", "x-forwarded-proto": "http" });
    expect(validateRequestHost(req, ORIGIN, true)).toMatchObject({ ok: false, reason: "scheme_mismatch" });
  });
});

describe("S4C resolveReturnTo", () => {
  const allow = ["/", "/app"];
  it("falls back to the default when absent", () => {
    expect(resolveReturnTo(undefined, "/", allow)).toEqual({ ok: true, path: "/" });
  });
  it("permits an allowlisted relative path", () => {
    expect(resolveReturnTo("/app", "/", allow)).toEqual({ ok: true, path: "/app" });
  });
  it("rejects an absolute URL", () => {
    expect(resolveReturnTo("https://evil.example/x", "/", allow)).toMatchObject({ ok: false, reason: "absolute_url" });
  });
  it("rejects a protocol-relative URL and backslash smuggling", () => {
    expect(resolveReturnTo("//evil.example", "/", allow)).toMatchObject({ ok: false, reason: "absolute_url" });
    expect(resolveReturnTo("/\\evil.example", "/", allow)).toMatchObject({ ok: false, reason: "absolute_url" });
  });
  it("rejects a relative path that is not allowlisted", () => {
    expect(resolveReturnTo("/secret", "/", allow)).toMatchObject({ ok: false, reason: "not_allowlisted" });
  });
});

describe("S4C validateRequestOrigin", () => {
  it("accepts a matching Origin header", () => {
    expect(validateRequestOrigin(mkReq({ origin: "https://app.example" }), ORIGIN)).toEqual({ ok: true });
  });
  it("rejects a mismatched or null Origin", () => {
    expect(validateRequestOrigin(mkReq({ origin: "https://evil.example" }), ORIGIN)).toMatchObject({ ok: false, reason: "origin_mismatch" });
    expect(validateRequestOrigin(mkReq({ origin: "null" }), ORIGIN)).toMatchObject({ ok: false, reason: "origin_mismatch" });
  });
  it("falls back to Referer and rejects a missing origin/referer", () => {
    expect(validateRequestOrigin(mkReq({ referer: "https://app.example/page" }), ORIGIN)).toEqual({ ok: true });
    expect(validateRequestOrigin(mkReq({ referer: "https://evil.example/page" }), ORIGIN)).toMatchObject({ ok: false, reason: "origin_mismatch" });
    expect(validateRequestOrigin(mkReq({}), ORIGIN)).toMatchObject({ ok: false, reason: "origin_missing" });
  });
});
