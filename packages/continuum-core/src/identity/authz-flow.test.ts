/**
 * S4B — authorization-code flow state machine (core, in-memory store + real S4A
 * verifier + stub principal/session layer). Covers begin generation/binding and
 * the complete() sequence: consumption, exchange, verification, nonce binding,
 * mapping, and fixation-resistant session minting only after every step succeeds.
 */
import { randomUUID } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  CachedVerificationKeyProvider,
  DEFAULT_JWKS_CACHE_POLICY,
  DEFAULT_JWT_LIMITS,
  DefaultAuthorizationCodeFlow,
  FixtureAuthorizationCodeExchanger,
  InMemoryAuthorizationEventSink,
  InMemoryAuthorizationTransactionStore,
  InMemoryJwksSource,
  JwtIdentityVerifier,
  StaticAuthorizationClientRegistry,
  TestProtectedSecretStore,
  pkceChallengeS256,
  type CreatedSession,
  type Jwk,
  type JwtIssuerPolicy,
  type JwtVerificationPolicy,
  type PrincipalMapper,
  type SessionCreationInput,
  type SessionManager,
  type VerifiedIdentity,
} from "./index";
import { generateIssuerKey, mintJwt, type TestIssuerKey } from "./jwt-test-support";

const ISS = "https://issuer.test";
const ISS2 = "https://other.test";
const CLIENT = "client-abc";
const REDIRECT = "https://app.test/callback";
const NOW = Date.parse("2026-07-16T00:00:00.000Z");
const nowSec = Math.floor(NOW / 1000);
const DIGEST_KEY = Buffer.from("authz-digest-key-0123456789abcdef").toString("base64");
const SECRET_KEYS = { currentVersion: "p1", keys: { p1: Buffer.from("protected-secret-key-32byteslong").toString("base64") } };

let ecK1: TestIssuerKey;
let ecK2: TestIssuerKey; // for ISS2

function jwtPolicy(): JwtVerificationPolicy {
  const mk = (issuer: string): JwtIssuerPolicy => ({
    issuer, audiences: [CLIENT], allowedAlgorithms: ["ES256"], keyProviderId: "kp", enabled: true,
    requireSubject: true, requireIssuedAt: true, requireExpiration: true, requireNonceWhenExpected: false,
    maximumCredentialAgeSeconds: 3600, maximumClockSkewSeconds: 60, replayPolicy: "none", policyVersion: "idp-v1",
  });
  return { issuers: [mk(ISS), mk(ISS2)], limits: DEFAULT_JWT_LIMITS };
}

let createCalls = 0;
const sessions: SessionManager = {
  async createSession(_identity: VerifiedIdentity, _principal, input: SessionCreationInput): Promise<CreatedSession> {
    createCalls += 1;
    return {
      sessionId: `sess-${randomUUID()}`,
      credential: { value: `sid.${randomUUID()}` },
      issuedAt: input.receivedAt,
      idleExpiresAt: new Date(input.receivedAt.getTime() + input.idleTtlSeconds * 1000),
      absoluteExpiresAt: new Date(input.receivedAt.getTime() + input.absoluteTtlSeconds * 1000),
    };
  },
  async validateSession() { throw new Error("nyi"); },
  async rotateSession() { throw new Error("nyi"); },
  async revokeSession() { throw new Error("nyi"); },
};

const mapper: PrincipalMapper = {
  async resolve(identity: VerifiedIdentity) {
    if (identity.subject === "user-suspended") return { mapped: false, reason: "principal_suspended" };
    if (identity.subject === "user-unmapped") return { mapped: false, reason: "no_mapping" };
    return { mapped: true, principal: { principalId: `P-${identity.subject}`, version: 1 }, mappingVersion: "1" };
  },
};

function build() {
  const store = new InMemoryAuthorizationTransactionStore();
  const exchanger = new FixtureAuthorizationCodeExchanger();
  const sink = new InMemoryAuthorizationEventSink();
  const source = new InMemoryJwksSource();
  source.setKeys(ISS, [ecK1.publicJwk], "v1");
  source.setKeys(ISS2, [ecK2.publicJwk], "v1");
  const verifier = new JwtIdentityVerifier({
    policy: jwtPolicy(), keyProvider: new CachedVerificationKeyProvider({ source, cachePolicy: DEFAULT_JWKS_CACHE_POLICY }),
  });
  const flow = new DefaultAuthorizationCodeFlow({
    store, exchanger, verifier, mapper, sessions, sink,
    secrets: new TestProtectedSecretStore(SECRET_KEYS),
    clients: new StaticAuthorizationClientRegistry([
      { issuer: ISS, clientId: CLIENT, redirectUri: REDIRECT, authorizationEndpoint: `${ISS}/authorize`, scope: "openid", policyVersion: "authz-v1", enabled: true },
    ]),
    digestKey: DIGEST_KEY, transactionTtlSeconds: 300, sessionIdleTtlSeconds: 900, sessionAbsoluteTtlSeconds: 3600,
  });
  return { store, exchanger, sink, flow };
}

async function idToken(key: TestIssuerKey, over: Record<string, unknown> = {}): Promise<string> {
  return mintJwt(key, { iss: ISS, sub: "user-1", aud: CLIENT, iat: nowSec - 10, exp: nowSec + 600, ...over });
}
const beginInput = () => ({ issuer: ISS, requestId: `req-${randomUUID()}`, receivedAt: new Date(NOW) });
const completeInput = (state: string, code: string, atMs = NOW + 1000) => ({ state, code, requestId: `req-${randomUUID()}`, receivedAt: new Date(atMs) });

beforeAll(async () => {
  ecK1 = await generateIssuerKey("ES256", "k1");
  ecK2 = await generateIssuerKey("ES256", "k1");
});

describe("S4B begin", () => {
  it("returns configured bindings and fresh, high-entropy state/nonce/challenge", async () => {
    const { flow } = build();
    const a = await flow.begin(beginInput());
    const b = await flow.begin(beginInput());
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.request.clientId).toBe(CLIENT);
    expect(a.request.redirectUri).toBe(REDIRECT);
    expect(a.request.codeChallengeMethod).toBe("S256");
    expect(a.request.state.length).toBeGreaterThanOrEqual(43); // 256-bit base64url
    expect(a.request.state).not.toBe(b.request.state);
    expect(a.request.nonce).not.toBe(b.request.nonce);
    expect(a.request.codeChallenge).not.toBe(b.request.codeChallenge);
  });

  it("denies an unregistered issuer and never persists raw state/nonce in evidence", async () => {
    const { flow, sink } = build();
    const bad = await flow.begin({ issuer: "https://evil.test", requestId: "r", receivedAt: new Date(NOW) });
    expect(bad).toMatchObject({ ok: false, reason: "unsupported_issuer" });
    const good = await flow.begin(beginInput());
    if (!good.ok) throw new Error("expected begin");
    expect(JSON.stringify(sink.events)).not.toContain(good.request.state);
    expect(JSON.stringify(sink.events)).not.toContain(good.request.nonce);
  });
});

describe("S4B complete — success and ordering", () => {
  it("mints a session only after exchange, verification, nonce and mapping succeed", async () => {
    createCalls = 0;
    const { flow, exchanger } = build();
    const begun = await flow.begin(beginInput());
    if (!begun.ok) throw new Error("begin");
    exchanger.register("code-ok", { identityToken: await idToken(ecK1, { nonce: begun.request.nonce }) });
    const r = await flow.complete(completeInput(begun.request.state, "code-ok"));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.principalId).toBe("P-user-1");
      expect(r.issuer).toBe(ISS);
      expect("tenant" in (r.session as unknown as Record<string, unknown>)).toBe(false);
    }
    expect(createCalls).toBe(1);
    // The exact persisted PKCE verifier reached the exchange step (challenge matches).
    expect(pkceChallengeS256(exchanger.lastInput!.pkceVerifier)).toBe(begun.request.codeChallenge);
  });

  it("consumes exactly once — a second callback with the same state is a replay", async () => {
    const { flow, exchanger } = build();
    const begun = await flow.begin(beginInput());
    if (!begun.ok) throw new Error("begin");
    exchanger.register("code-ok", { identityToken: await idToken(ecK1, { nonce: begun.request.nonce }) });
    const first = await flow.complete(completeInput(begun.request.state, "code-ok"));
    expect(first.ok).toBe(true);
    const second = await flow.complete(completeInput(begun.request.state, "code-ok"));
    expect(second).toMatchObject({ ok: false, reason: "transaction_already_consumed" });
  });
});

describe("S4B complete — denials (no session minted)", () => {
  it("validates callback input structure", async () => {
    const { flow } = build();
    expect(await flow.complete(completeInput("", "code"))).toMatchObject({ ok: false, reason: "state_missing" });
    expect(await flow.complete(completeInput("has space!", "code"))).toMatchObject({ ok: false, reason: "state_malformed" });
    const begun = await flow.begin(beginInput());
    if (!begun.ok) throw new Error("begin");
    expect(await flow.complete(completeInput(begun.request.state, ""))).toMatchObject({ ok: false, reason: "code_missing" });
  });

  it("denies unknown and expired transactions", async () => {
    const { flow } = build();
    expect(await flow.complete(completeInput("Zm9vYmFy", "code"))).toMatchObject({ ok: false, reason: "state_unknown" });
    const begun = await flow.begin(beginInput());
    if (!begun.ok) throw new Error("begin");
    const expired = await flow.complete(completeInput(begun.request.state, "code", NOW + 400_000));
    expect(expired).toMatchObject({ ok: false, reason: "transaction_expired" });
  });

  it("maps exchange failures without minting a session", async () => {
    createCalls = 0;
    for (const [code, entry, reason] of [
      ["c-bad", { forceFailure: "invalid_code" as const }, "code_exchange_denied"],
      ["c-iss", { forceFailure: "issuer_mismatch" as const }, "issuer_mismatch"],
      ["c-red", { forceFailure: "redirect_uri_mismatch" as const }, "redirect_uri_mismatch"],
      ["c-pkce", { forceFailure: "pkce_mismatch" as const }, "pkce_mismatch"],
      ["c-down", { forceFailure: "token_endpoint_unavailable" as const }, "code_exchange_unavailable"],
      ["c-notok", { forceFailure: "missing_identity_token" as const }, "identity_token_missing"],
    ] as const) {
      const { flow, exchanger } = build();
      const begun = await flow.begin(beginInput());
      if (!begun.ok) throw new Error("begin");
      exchanger.register(code, entry);
      expect(await flow.complete(completeInput(begun.request.state, code))).toMatchObject({ ok: false, reason });
    }
    expect(createCalls).toBe(0);
  });

  it("denies a token that fails S4A verification", async () => {
    const { flow, exchanger } = build();
    const begun = await flow.begin(beginInput());
    if (!begun.ok) throw new Error("begin");
    const forged = await mintJwt(await generateIssuerKey("ES256", "k1"), { iss: ISS, sub: "user-1", aud: CLIENT, iat: nowSec - 10, exp: nowSec + 600, nonce: begun.request.nonce });
    exchanger.register("code-forged", { identityToken: forged });
    expect(await flow.complete(completeInput(begun.request.state, "code-forged"))).toMatchObject({ ok: false, reason: "identity_verification_denied" });
  });

  it("denies a validly-signed token from another issuer (issuer binding)", async () => {
    const { flow, exchanger } = build();
    const begun = await flow.begin(beginInput());
    if (!begun.ok) throw new Error("begin");
    const otherIssToken = await mintJwt(ecK2, { iss: ISS2, sub: "user-1", aud: CLIENT, iat: nowSec - 10, exp: nowSec + 600, nonce: begun.request.nonce });
    exchanger.register("code-other", { identityToken: otherIssToken });
    expect(await flow.complete(completeInput(begun.request.state, "code-other"))).toMatchObject({ ok: false, reason: "issuer_mismatch" });
  });

  it("denies nonce mismatch and missing nonce", async () => {
    const { flow, exchanger } = build();
    const b1 = await flow.begin(beginInput());
    if (!b1.ok) throw new Error("begin");
    exchanger.register("code-wrongnonce", { identityToken: await idToken(ecK1, { nonce: "not-the-nonce" }) });
    expect(await flow.complete(completeInput(b1.request.state, "code-wrongnonce"))).toMatchObject({ ok: false, reason: "nonce_mismatch" });

    const b2 = await flow.begin(beginInput());
    if (!b2.ok) throw new Error("begin");
    exchanger.register("code-nonone", { identityToken: await idToken(ecK1) }); // no nonce claim
    expect(await flow.complete(completeInput(b2.request.state, "code-nonone"))).toMatchObject({ ok: false, reason: "nonce_missing" });
  });

  it("denies mapping failures", async () => {
    const { flow, exchanger } = build();
    const b1 = await flow.begin(beginInput());
    if (!b1.ok) throw new Error("begin");
    exchanger.register("code-unmapped", { identityToken: await idToken(ecK1, { sub: "user-unmapped", nonce: b1.request.nonce }) });
    expect(await flow.complete(completeInput(b1.request.state, "code-unmapped"))).toMatchObject({ ok: false, reason: "identity_mapping_denied" });

    const b2 = await flow.begin(beginInput());
    if (!b2.ok) throw new Error("begin");
    exchanger.register("code-susp", { identityToken: await idToken(ecK1, { sub: "user-suspended", nonce: b2.request.nonce }) });
    expect(await flow.complete(completeInput(b2.request.state, "code-susp"))).toMatchObject({ ok: false, reason: "principal_inactive" });
  });
});
