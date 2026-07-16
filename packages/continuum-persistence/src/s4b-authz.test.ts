/**
 * Phase 3 S4B — authorization-code flow on real embedded PostgreSQL.
 *
 * Proves atomic one-time consumption (one consumer under concurrency), restart-safe
 * pending + consumed + replay behaviour, strict issuer/nonce binding, a session
 * minted only after the full sequence succeeds (carrying no tenant authority),
 * digest/encrypted-only storage, and least-privilege (the session role cannot reach
 * tenant surfaces or mutate transactions directly).
 */
import { createHmac, randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import {
  CachedVerificationKeyProvider,
  DEFAULT_JWKS_CACHE_POLICY,
  DEFAULT_JWT_LIMITS,
  DefaultAuthorizationCodeFlow,
  FixtureAuthorizationCodeExchanger,
  InMemoryJwksSource,
  JwtIdentityVerifier,
  StaticAuthorizationClientRegistry,
  TestProtectedSecretStore,
  type Jwk,
  type JwtIssuerPolicy,
  type JwtVerificationPolicy,
  type SessionDigestKeys,
} from "@continuum/core";
import { adminPool, sessionPool, type DbConfig } from "./pg";
import { migrate } from "./migrate";
import { PostgresPrincipalMapper, PostgresSessionManager } from "./session-store";
import { PostgresAuthorizationEventSink, PostgresAuthorizationTransactionStore } from "./authz-store";

const DB: DbConfig = { host: "127.0.0.1", port: 55444, database: "continuum_s4b" };
const ISS = "https://issuer.test";
const ISS2 = "https://other.test";
const CLIENT = "client-abc";
const REDIRECT = "https://app.test/callback";
const NOW = Date.parse("2026-07-16T00:00:00.000Z");
const nowSec = Math.floor(NOW / 1000);
const DIGEST_KEY = Buffer.from("authz-digest-key-s4b-0123456789a").toString("base64");
const SECRET_KEYS = { currentVersion: "p1", keys: { p1: Buffer.from("protected-secret-key-32byteslong").toString("base64") } };
const SESSION_DIGEST: SessionDigestKeys = { currentVersion: "d1", keys: { d1: Buffer.from("session-digest-key-d1-0123456789").toString("base64") } };

const P_ACTIVE = randomUUID();
const P_SUSP = randomUUID();
const P_DISABLED = randomUUID();

let admin: Pool;
let sess: Pool;
let signK1: CryptoKey;
let signK2: CryptoKey;
let pubJwk1: Jwk;
let flow: DefaultAuthorizationCodeFlow;
let exchanger: FixtureAuthorizationCodeExchanger;
let store: PostgresAuthorizationTransactionStore;

function jwtIssuer(issuer: string): JwtIssuerPolicy {
  return {
    issuer, audiences: [CLIENT], allowedAlgorithms: ["ES256"], keyProviderId: "kp", enabled: true,
    requireSubject: true, requireIssuedAt: true, requireExpiration: true, requireNonceWhenExpected: false,
    maximumCredentialAgeSeconds: 3600, maximumClockSkewSeconds: 60, replayPolicy: "none", policyVersion: "idp-v1",
  };
}

async function idToken(key: CryptoKey, iss: string, sub: string, nonce: string): Promise<string> {
  return new SignJWT({ nonce }).setProtectedHeader({ alg: "ES256", kid: "k1" })
    .setIssuer(iss).setSubject(sub).setAudience(CLIENT).setIssuedAt(nowSec - 10).setExpirationTime(nowSec + 600).sign(key);
}
const beginInput = () => ({ issuer: ISS, requestId: `req-${randomUUID()}`, receivedAt: new Date(NOW) });
const completeInput = (state: string, code: string, atMs = NOW + 1000) => ({ state, code, requestId: `req-${randomUUID()}`, receivedAt: new Date(atMs) });

beforeAll(async () => {
  const bootstrap = adminPool({ ...DB, database: "continuum" });
  try {
    await bootstrap.query("DROP DATABASE IF EXISTS continuum_s4b");
    await bootstrap.query("CREATE DATABASE continuum_s4b");
  } finally {
    await bootstrap.end();
  }
  await migrate(DB);
  admin = adminPool(DB);
  sess = sessionPool(DB);

  const seedP = (id: string, status: string) =>
    admin.query(`INSERT INTO continuum.principals (principal_id, principal_type, status, suspended_at) VALUES ($1,'human',$2,$3)`,
      [id, status, status === "suspended" ? new Date() : null]);
  const seedI = (p: string, sub: string, status = "active") =>
    admin.query(`INSERT INTO continuum.external_identities (external_identity_id, principal_id, issuer, subject, status) VALUES ($1,$2,$3,$4,$5)`,
      [randomUUID(), p, ISS, sub, status]);
  await seedP(P_ACTIVE, "active"); await seedP(P_SUSP, "suspended"); await seedP(P_DISABLED, "active");
  await seedI(P_ACTIVE, "sub-active"); await seedI(P_SUSP, "sub-susp"); await seedI(P_DISABLED, "sub-disabled", "disabled");

  const k1 = await generateKeyPair("ES256", { extractable: true });
  const k2 = await generateKeyPair("ES256", { extractable: true });
  signK1 = k1.privateKey as CryptoKey; signK2 = k2.privateKey as CryptoKey;
  const jwk1 = (await exportJWK(k1.publicKey)) as Record<string, unknown>; jwk1.kid = "k1"; jwk1.alg = "ES256";
  const jwk2 = (await exportJWK(k2.publicKey)) as Record<string, unknown>; jwk2.kid = "k1"; jwk2.alg = "ES256";
  pubJwk1 = jwk1 as Jwk;
  const source = new InMemoryJwksSource();
  source.setKeys(ISS, [jwk1 as Jwk], "v1");
  source.setKeys(ISS2, [jwk2 as Jwk], "v1");
  const policy: JwtVerificationPolicy = { issuers: [jwtIssuer(ISS), jwtIssuer(ISS2)], limits: DEFAULT_JWT_LIMITS };
  const verifier = new JwtIdentityVerifier({ policy, keyProvider: new CachedVerificationKeyProvider({ source, cachePolicy: DEFAULT_JWKS_CACHE_POLICY }) });

  exchanger = new FixtureAuthorizationCodeExchanger();
  store = new PostgresAuthorizationTransactionStore(sess);
  flow = new DefaultAuthorizationCodeFlow({
    store, exchanger, verifier,
    mapper: new PostgresPrincipalMapper(sess),
    sessions: new PostgresSessionManager(sess, { digestKeys: SESSION_DIGEST, rotationIdleTtlSeconds: 900 }),
    sink: new PostgresAuthorizationEventSink(sess),
    secrets: new TestProtectedSecretStore(SECRET_KEYS),
    clients: new StaticAuthorizationClientRegistry([
      { issuer: ISS, clientId: CLIENT, redirectUri: REDIRECT, authorizationEndpoint: `${ISS}/authorize`, scope: "openid", policyVersion: "authz-v1", enabled: true },
    ]),
    digestKey: DIGEST_KEY, transactionTtlSeconds: 300, sessionIdleTtlSeconds: 900, sessionAbsoluteTtlSeconds: 3600,
  });
});

afterAll(async () => {
  await admin.end();
  await sess.end();
});

describe("S4B authorization-code flow (PostgreSQL)", () => {
  it("completes a valid login and mints a digest-only session with no tenant authority", async () => {
    const b = await flow.begin(beginInput());
    if (!b.ok) throw new Error("begin");
    exchanger.register("code-1", { identityToken: await idToken(signK1, ISS, "sub-active", b.request.nonce) });
    const r = await flow.complete(completeInput(b.request.state, "code-1"));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.principalId).toBe(P_ACTIVE);
    expect("tenant" in (r.session as unknown as Record<string, unknown>)).toBe(false);
    const row = (await admin.query("SELECT credential_digest FROM continuum.authenticated_sessions WHERE session_id=$1", [r.session.sessionId])).rows[0];
    expect(row.credential_digest).toMatch(/^[0-9a-f]{64}$/);
    // Transaction marked completed.
    const t = (await admin.query("SELECT status FROM continuum.authorization_transactions WHERE state_digest=$1", [require_digest(b.request.state)])).rows[0];
    expect(t.status).toBe("completed");
  });

  it("admits exactly one consumer under eight concurrent callbacks", async () => {
    const b = await flow.begin(beginInput());
    if (!b.ok) throw new Error("begin");
    exchanger.register("code-conc", { identityToken: await idToken(signK1, ISS, "sub-active", b.request.nonce) });
    const results = await Promise.all(Array.from({ length: 8 }, () => flow.complete(completeInput(b.request.state, "code-conc"))));
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.filter((r) => !r.ok && r.reason === "transaction_already_consumed")).toHaveLength(7);
  });

  it("survives restart: a pending transaction completes, and a consumed one denies, on a fresh pool", async () => {
    const b = await flow.begin(beginInput());
    if (!b.ok) throw new Error("begin");
    exchanger.register("code-restart", { identityToken: await idToken(signK1, ISS, "sub-active", b.request.nonce) });
    // "Restart": new pools + new store/flow bound to them.
    const sess2 = sessionPool(DB);
    try {
      const store2 = new PostgresAuthorizationTransactionStore(sess2);
      const source = new InMemoryJwksSource();
      source.setKeys(ISS, [pubJwk1], "v1");
      const flow2 = new DefaultAuthorizationCodeFlow({
        store: store2, exchanger,
        verifier: new JwtIdentityVerifier({ policy: { issuers: [jwtIssuer(ISS)], limits: DEFAULT_JWT_LIMITS }, keyProvider: new CachedVerificationKeyProvider({ source, cachePolicy: DEFAULT_JWKS_CACHE_POLICY }) }),
        mapper: new PostgresPrincipalMapper(sess2),
        sessions: new PostgresSessionManager(sess2, { digestKeys: SESSION_DIGEST, rotationIdleTtlSeconds: 900 }),
        sink: new PostgresAuthorizationEventSink(sess2),
        secrets: new TestProtectedSecretStore(SECRET_KEYS),
        clients: new StaticAuthorizationClientRegistry([{ issuer: ISS, clientId: CLIENT, redirectUri: REDIRECT, authorizationEndpoint: `${ISS}/authorize`, scope: "openid", policyVersion: "authz-v1", enabled: true }]),
        digestKey: DIGEST_KEY, transactionTtlSeconds: 300, sessionIdleTtlSeconds: 900, sessionAbsoluteTtlSeconds: 3600,
      });
      const first = await flow2.complete(completeInput(b.request.state, "code-restart"));
      expect(first.ok).toBe(true);
      const replay = await flow2.complete(completeInput(b.request.state, "code-restart"));
      expect(replay).toMatchObject({ ok: false, reason: "transaction_already_consumed" });
    } finally {
      await sess2.end();
    }
  });

  it("denies an expired transaction", async () => {
    const b = await flow.begin(beginInput());
    if (!b.ok) throw new Error("begin");
    exchanger.register("code-exp", { identityToken: await idToken(signK1, ISS, "sub-active", b.request.nonce) });
    expect(await flow.complete(completeInput(b.request.state, "code-exp", NOW + 400_000))).toMatchObject({ ok: false, reason: "transaction_expired" });
  });

  it("enforces issuer and nonce binding", async () => {
    const b1 = await flow.begin(beginInput());
    if (!b1.ok) throw new Error("begin");
    exchanger.register("code-otheriss", { identityToken: await idToken(signK2, ISS2, "sub-active", b1.request.nonce) });
    expect(await flow.complete(completeInput(b1.request.state, "code-otheriss"))).toMatchObject({ ok: false, reason: "issuer_mismatch" });

    const b2 = await flow.begin(beginInput());
    if (!b2.ok) throw new Error("begin");
    exchanger.register("code-wrongnonce", { identityToken: await idToken(signK1, ISS, "sub-active", "not-the-nonce") });
    expect(await flow.complete(completeInput(b2.request.state, "code-wrongnonce"))).toMatchObject({ ok: false, reason: "nonce_mismatch" });
  });

  it("denies suspended principal and disabled mapping without minting a session", async () => {
    const b1 = await flow.begin(beginInput());
    if (!b1.ok) throw new Error("begin");
    exchanger.register("code-susp", { identityToken: await idToken(signK1, ISS, "sub-susp", b1.request.nonce) });
    expect(await flow.complete(completeInput(b1.request.state, "code-susp"))).toMatchObject({ ok: false, reason: "principal_inactive" });

    const b2 = await flow.begin(beginInput());
    if (!b2.ok) throw new Error("begin");
    exchanger.register("code-dis", { identityToken: await idToken(signK1, ISS, "sub-disabled", b2.request.nonce) });
    expect(await flow.complete(completeInput(b2.request.state, "code-dis"))).toMatchObject({ ok: false, reason: "identity_mapping_denied" });
    // Terminal status is categorized by the failing stage, and stays consumed.
    const t = (await admin.query("SELECT status, failure_reason, consumed_at FROM continuum.authorization_transactions WHERE state_digest=$1", [require_digest(b2.request.state)])).rows[0];
    expect(t.status).toBe("mapping_failed");
    expect(t.failure_reason).toBe("identity_mapping_denied");
    expect(t.consumed_at).not.toBeNull();
  });

  it("stores state/nonce as digests and the PKCE verifier encrypted — no raw secrets", async () => {
    const b = await flow.begin(beginInput());
    if (!b.ok) throw new Error("begin");
    exchanger.register("code-hyg", { identityToken: await idToken(signK1, ISS, "sub-active", b.request.nonce) });
    await flow.complete(completeInput(b.request.state, "code-hyg"));
    const row = (await admin.query("SELECT * FROM continuum.authorization_transactions WHERE state_digest=$1", [require_digest(b.request.state)])).rows[0];
    const asText = JSON.stringify(row);
    expect(asText).not.toContain(b.request.state);
    expect(asText).not.toContain(b.request.nonce);
    expect(asText).not.toContain("code-hyg");
    expect(row.pkce_challenge).toBe(b.request.codeChallenge);
    expect(Object.keys(row)).not.toContain("code");
    // No raw code/state/nonce/token in the evidence stream either.
    const ev = JSON.stringify((await admin.query("SELECT * FROM continuum.auth_events WHERE event_type LIKE 'authz.%'")).rows);
    expect(ev).not.toContain(b.request.state);
    expect(ev).not.toContain(b.request.nonce);
    expect(ev).not.toContain("code-hyg");
  });

  it("the flow role has no tenant path and cannot mutate transactions directly", async () => {
    await expect(sess.query("SELECT * FROM continuum.tenant_memberships")).rejects.toThrow(/permission denied/i);
    await expect(sess.query("SELECT * FROM public.intents")).rejects.toThrow(/permission denied/i);
    await expect(sess.query("UPDATE continuum.authorization_transactions SET status='completed'")).rejects.toThrow(/permission denied/i);
    await expect(sess.query("DELETE FROM continuum.authorization_transactions")).rejects.toThrow(/permission denied/i);
  });
});

// Local helper: reproduce the flow's keyed state digest for row lookups.
function require_digest(state: string): string {
  return createHmac("sha256", Buffer.from(DIGEST_KEY, "base64")).update(`authz-state:${state}`, "utf8").digest("hex");
}
