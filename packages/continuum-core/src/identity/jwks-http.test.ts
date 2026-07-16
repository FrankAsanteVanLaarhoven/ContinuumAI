/**
 * S4A — HTTP JWKS source: retrieval safety (SSRF boundary) against a deterministic
 * local server. The issuer→URL mapping is trusted config; the assertion can never
 * choose a URL. HTTPS is required outside loopback test mode; redirects, oversized
 * bodies, wrong content types, timeouts and private destinations are refused.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  HttpJwksSource,
  isPrivateHost,
  type Jwk,
  type JwksLoadOptions,
} from "./index";
import { generateIssuerKey, type TestIssuerKey } from "./jwt-test-support";

const ISS = "https://issuer.test";
const NOW = Date.parse("2026-07-16T00:00:00.000Z");

let ecK1: TestIssuerKey;
let server: Server;
let port: number;
let responder: (req: IncomingMessage, res: ServerResponse) => void;

const jwksBody = () => JSON.stringify({ keys: [ecK1.publicJwk] });

function loadOptions(over: Partial<JwksLoadOptions> = {}): JwksLoadOptions {
  return {
    timeoutMs: 1000, maxResponseBytes: 65_536, maxKeyCount: 32,
    acceptedKeyTypes: ["RSA", "EC", "OKP"], acceptedCurves: ["P-256", "P-384", "P-521", "Ed25519"],
    at: new Date(NOW), ...over,
  };
}

function source(over: { production?: boolean; url?: string } = {}): HttpJwksSource {
  return new HttpJwksSource({
    locations: [{ issuer: ISS, url: over.url ?? `http://127.0.0.1:${port}/jwks`, version: "http-v1" }],
    production: over.production ?? false,
    allowInsecureLoopbackForTests: true,
  });
}

beforeAll(async () => {
  ecK1 = await generateIssuerKey("ES256", "k1");
  responder = (_req, res) => { res.setHeader("content-type", "application/json"); res.end(jwksBody()); };
  server = createServer((req, res) => responder(req, res));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  port = (server.address() as { port: number }).port;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

describe("S4A HTTP JWKS retrieval", () => {
  it("loads a valid JWKS over the configured loopback URL", async () => {
    responder = (_req, res) => { res.setHeader("content-type", "application/json"); res.end(jwksBody()); };
    const r = await source().load(ISS, loadOptions());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.snapshot.keys[0]?.kid).toBe("k1");
  });

  it("reflects rotation on the next load (no internal cache in the source)", async () => {
    const k2 = await generateIssuerKey("ES256", "k2");
    responder = (_req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ keys: [k2.publicJwk] })); };
    const r = await source().load(ISS, loadOptions());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.snapshot.keys[0]?.kid).toBe("k2");
  });

  it("returns issuer_unknown for an issuer with no configured location (URL is config-bound)", async () => {
    const r = await source().load("https://not-configured.test", loadOptions());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("issuer_unknown");
  });

  it("refuses a non-2xx response", async () => {
    responder = (_req, res) => { res.statusCode = 500; res.end("nope"); };
    const r = await source().load(ISS, loadOptions());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("refresh_failed");
  });

  it("refuses a wrong content type", async () => {
    responder = (_req, res) => { res.setHeader("content-type", "text/plain"); res.end(jwksBody()); };
    const r = await source().load(ISS, loadOptions());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("refresh_failed");
  });

  it("refuses an oversized body", async () => {
    responder = (_req, res) => { res.setHeader("content-type", "application/json"); res.end(jwksBody()); };
    const r = await source().load(ISS, loadOptions({ maxResponseBytes: 20 }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("too_large");
  });

  it("refuses malformed JSON", async () => {
    responder = (_req, res) => { res.setHeader("content-type", "application/json"); res.end("{ not json"); };
    const r = await source().load(ISS, loadOptions());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("malformed");
  });

  it("refuses a redirect", async () => {
    responder = (_req, res) => { res.statusCode = 302; res.setHeader("location", "https://elsewhere.test/jwks"); res.end(); };
    const r = await source().load(ISS, loadOptions());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("refresh_failed");
  });

  it("times out and denies a slow response", async () => {
    responder = (_req, res) => { setTimeout(() => { res.setHeader("content-type", "application/json"); res.end(jwksBody()); }, 300); };
    const r = await source().load(ISS, loadOptions({ timeoutMs: 30 }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("refresh_failed");
  });

  it("in production, refuses an http (non-HTTPS) location", async () => {
    const prod = new HttpJwksSource({ locations: [{ issuer: ISS, url: `http://127.0.0.1:${port}/jwks` }], production: true });
    const r = await prod.load(ISS, loadOptions());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("refresh_failed");
  });

  it("in production, refuses a private/loopback destination even over HTTPS", async () => {
    const prod = new HttpJwksSource({ locations: [{ issuer: ISS, url: "https://10.0.0.5/jwks" }], production: true });
    const r = await prod.load(ISS, loadOptions());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("refresh_failed");
  });
});

describe("S4A private-host detection", () => {
  it("flags loopback, RFC1918, link-local and ULA hosts", () => {
    for (const h of ["localhost", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "::1", "fd00::1", "svc.local", "0.0.0.0"]) {
      expect(isPrivateHost(h)).toBe(true);
    }
  });
  it("does not flag public hosts", () => {
    for (const h of ["issuer.example.com", "8.8.8.8", "203.0.113.5"]) {
      expect(isPrivateHost(h)).toBe(false);
    }
  });
});
