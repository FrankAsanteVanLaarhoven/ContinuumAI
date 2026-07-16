/**
 * Phase 3 S4A — the real (jose) JWT verifier integrated with the S3 principal &
 * session boundary and the durable PostgreSQL replay ledger, on real embedded
 * PostgreSQL.
 *
 * Proves a genuine signed JWT normalizes through the existing S3 boundary, mints a
 * digest-only session that carries NO tenant, is single-use where the issuer's
 * replay policy requires it (durable, restart-safe), and that the identity/session/
 * replay role has no tenant-resolution path — S2B remains the only way to a tenant.
 */
import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import {
  AuthenticationBoundary,
  CachedVerificationKeyProvider,
  DEFAULT_JWKS_CACHE_POLICY,
  DEFAULT_JWT_LIMITS,
  InMemoryJwksSource,
  JwtIdentityVerifier,
  JwtIdentityVerifierAdapter,
  type IdentityVerificationPolicy,
  type Jwk,
  type JwtIssuerPolicy,
  type JwtVerificationPolicy,
  type SessionDigestKeys,
} from "@continuum/core";
import { adminPool, sessionPool, type DbConfig } from "./pg";
import { migrate } from "./migrate";
import { PostgresAuthEventSink, PostgresPrincipalMapper, PostgresSessionManager } from "./session-store";
import { PostgresReplayLedger } from "./replay-store";

const DB: DbConfig = { host: "127.0.0.1", port: 55444, database: "continuum_s4a_jwt" };
const ISS = "https://issuer.test";
const AUD = "continuum";
const KID = "k1";
const NOW = Date.parse("2026-07-16T00:00:00.000Z");
const nowSec = Math.floor(NOW / 1000);
const REPLAY_KEY = Buffer.from("replay-digest-key-s4a-0123456789").toString("base64");
const DIGEST_KEYS: SessionDigestKeys = {
  currentVersion: "d1",
  keys: { d1: Buffer.from("session-digest-key-d1-0123456789").toString("base64") },
};

const P_ACTIVE = randomUUID();
const P_DISABLED = randomUUID();

let admin: Pool;
let sess: Pool;
let signingKey: CryptoKey;
let boundary: AuthenticationBoundary;
let sessions: PostgresSessionManager;

const issuerPolicy: JwtIssuerPolicy = {
  issuer: ISS, audiences: [AUD], allowedAlgorithms: ["ES256"], keyProviderId: "kp", enabled: true,
  requireSubject: true, requireIssuedAt: true, requireExpiration: true, requireNonceWhenExpected: true,
  maximumCredentialAgeSeconds: 3600, maximumClockSkewSeconds: 60, replayPolicy: "jti", policyVersion: "jwt-policy-v1",
};
// Placeholder S3 policy for the boundary (the JWT verifier carries its own policy).
const s3Policy: IdentityVerificationPolicy = {
  allowedIssuers: [], allowedAlgorithms: [], maximumClockSkewSeconds: 60, maximumCredentialAgeSeconds: 3600,
  requireIssuedAt: true, requireExpiration: true, requireSubject: true, requireNonceWhenExpected: true,
  policyVersion: "jwt-policy-v1",
};

async function mint(sub: string, over: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ iss: ISS, sub, aud: AUD, iat: nowSec - 10, exp: nowSec + 600, jti: randomUUID(), ...over })
    .setProtectedHeader({ alg: "ES256", kid: KID })
    .sign(signingKey);
}
function input(credential: string) {
  return { credential, requestId: `req-${randomUUID()}`, receivedAt: new Date(NOW) };
}

beforeAll(async () => {
  const bootstrap = adminPool({ ...DB, database: "continuum" });
  try {
    await bootstrap.query("DROP DATABASE IF EXISTS continuum_s4a_jwt");
    await bootstrap.query("CREATE DATABASE continuum_s4a_jwt");
  } finally {
    await bootstrap.end();
  }
  await migrate(DB);
  admin = adminPool(DB);
  sess = sessionPool(DB);

  await admin.query(`INSERT INTO continuum.principals (principal_id, principal_type, status) VALUES ($1,'human','active')`, [P_ACTIVE]);
  await admin.query(`INSERT INTO continuum.principals (principal_id, principal_type, status) VALUES ($1,'human','active')`, [P_DISABLED]);
  await admin.query(`INSERT INTO continuum.external_identities (external_identity_id, principal_id, issuer, subject, status) VALUES ($1,$2,$3,$4,'active')`, [randomUUID(), P_ACTIVE, ISS, "sub-active"]);
  await admin.query(`INSERT INTO continuum.external_identities (external_identity_id, principal_id, issuer, subject, status) VALUES ($1,$2,$3,$4,'disabled')`, [randomUUID(), P_DISABLED, ISS, "sub-disabled"]);

  const kp = await generateKeyPair("ES256", { extractable: true });
  signingKey = kp.privateKey as CryptoKey;
  const jwk = (await exportJWK(kp.publicKey)) as Record<string, unknown>;
  jwk.kid = KID; jwk.alg = "ES256"; jwk.use = "sig";

  const source = new InMemoryJwksSource();
  source.setKeys(ISS, [jwk as Jwk], "v1");
  const provider = new CachedVerificationKeyProvider({ source, cachePolicy: DEFAULT_JWKS_CACHE_POLICY });
  const policy: JwtVerificationPolicy = { issuers: [issuerPolicy], limits: DEFAULT_JWT_LIMITS };
  const jwtVerifier = new JwtIdentityVerifier({
    policy, keyProvider: provider, replayLedger: new PostgresReplayLedger(sess), replayDigestKey: REPLAY_KEY,
  });

  sessions = new PostgresSessionManager(sess, { digestKeys: DIGEST_KEYS, rotationIdleTtlSeconds: 900 });
  boundary = new AuthenticationBoundary({
    verifier: new JwtIdentityVerifierAdapter(jwtVerifier), policy: s3Policy,
    mapper: new PostgresPrincipalMapper(sess), sessions, sink: new PostgresAuthEventSink(sess),
    idleTtlSeconds: 900, absoluteTtlSeconds: 3600,
  });
});

afterAll(async () => {
  await admin.end();
  await sess.end();
});

describe("S4A JWT → S3 boundary integration", () => {
  it("a genuine signed JWT normalizes through the S3 boundary and mints a session", async () => {
    const r = await boundary.authenticate(input(await mint("sub-active")));
    expect(r.authenticated).toBe(true);
    if (!r.authenticated) return;
    expect(r.principalId).toBe(P_ACTIVE);
    expect(r.issuer).toBe(ISS);
    const v = await sessions.validateSession(r.session.credential, { requestId: "r", receivedAt: new Date(NOW + 1000) });
    expect(v.valid).toBe(true);
    if (v.valid) {
      expect(v.session.principalId).toBe(P_ACTIVE);
      expect("tenant" in (v.session as unknown as Record<string, unknown>)).toBe(false);
    }
  });

  it("stores the session credential only as a keyed digest", async () => {
    const r = await boundary.authenticate(input(await mint("sub-active")));
    if (!r.authenticated) throw new Error("expected auth");
    const secret = r.session.credential.value.split(".")[1]!;
    const row = (await admin.query("SELECT credential_digest FROM continuum.authenticated_sessions WHERE session_id=$1", [r.session.sessionId])).rows[0];
    expect(row.credential_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(row.credential_digest).not.toContain(secret);
  });

  it("a valid JWT grants NO tenant authority (session role has no tenant path)", async () => {
    await expect(sess.query("SELECT * FROM continuum.tenant_memberships")).rejects.toThrow(/permission denied/i);
    await expect(sess.query("SELECT * FROM public.intents")).rejects.toThrow(/permission denied/i);
    await expect(sess.query("SELECT continuum.begin_authenticated_context($1,$2,$3,$4)", [P_ACTIVE, randomUUID(), randomUUID(), null]))
      .rejects.toThrow(/permission denied/i);
  });

  it("is single-use where the issuer replay policy requires it (durable jti replay)", async () => {
    const jwt = await mint("sub-active", { jti: "fixed-jti-1" });
    const first = await boundary.authenticate(input(jwt));
    expect(first.authenticated).toBe(true);
    const second = await boundary.authenticate(input(jwt)); // same jti replayed
    expect(second).toMatchObject({ authenticated: false, stage: "verification", reason: "replay_detected" });
  });

  it("denies a disabled external-identity mapping", async () => {
    const r = await boundary.authenticate(input(await mint("sub-disabled")));
    expect(r).toMatchObject({ authenticated: false, reason: "mapping_disabled" });
  });

  it("denies a signature forged with a different key", async () => {
    const other = await generateKeyPair("ES256", { extractable: true });
    const forged = await new SignJWT({ iss: ISS, sub: "sub-active", aud: AUD, iat: nowSec - 10, exp: nowSec + 600, jti: randomUUID() })
      .setProtectedHeader({ alg: "ES256", kid: KID })
      .sign(other.privateKey as CryptoKey);
    const r = await boundary.authenticate(input(forged));
    expect(r).toMatchObject({ authenticated: false, stage: "verification", reason: "signature_invalid" });
  });
});
