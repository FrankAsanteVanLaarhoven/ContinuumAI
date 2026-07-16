/**
 * Phase 3 S3 — identity-verification & session boundary on real embedded PostgreSQL.
 *
 * Proves the vendor-neutral flow end to end: an externally verified identity maps
 * to an internal principal and mints a restart-safe, revocable session whose
 * credential is stored only as a keyed digest — and that the session layer holds
 * NO tenant authority (tenant remains the S2B trusted-context path).
 */
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import {
  AuthenticationBoundary,
  DETERMINISTIC_ALG,
  DeterministicIdentityVerifier,
  InMemoryVerificationKeyProvider,
  mintCredential,
  type AuthenticationInput,
  type IdentityVerificationPolicy,
  type SessionDigestKeys,
  type VerifiedIdentity,
} from "@continuum/core";
import { adminPool, sessionPool, type DbConfig } from "./pg";
import { migrate } from "./migrate";
import {
  PostgresAuthEventSink,
  PostgresPrincipalMapper,
  PostgresSessionManager,
} from "./session-store";

const DB: DbConfig = { host: "127.0.0.1", port: 55444, database: "continuum_s3" };
const ISS = "https://issuer.test";
const AUD = "continuum";
const KEY = Buffer.from("test-hmac-secret-key-0123456789abcdef").toString("base64");
const KID = "k1";
const DIGEST_KEYS: SessionDigestKeys = {
  currentVersion: "d1",
  keys: { d1: Buffer.from("session-digest-key-d1-0123456789").toString("base64") },
};
const NOW = Date.parse("2026-07-16T00:00:00.000Z");
const nowSec = Math.floor(NOW / 1000);

const policy: IdentityVerificationPolicy = {
  allowedIssuers: [{ issuer: ISS, allowedAudiences: [AUD], allowedAlgorithms: [DETERMINISTIC_ALG], keySource: { kind: "test", ref: ISS }, enabled: true }],
  allowedAlgorithms: [DETERMINISTIC_ALG],
  maximumClockSkewSeconds: 60, maximumCredentialAgeSeconds: 3600,
  requireIssuedAt: true, requireExpiration: true, requireSubject: true, requireNonceWhenExpected: true,
  policyVersion: "idp-policy-v1",
};

// Principals for the scenario.
const P_ACTIVE = randomUUID();
const P_SUSP = randomUUID();
const P_DISABLED = randomUUID();

let admin: Pool;
let sess: Pool;
let sink: PostgresAuthEventSink;
let mapper: PostgresPrincipalMapper;
let sessions: PostgresSessionManager;
let boundary: AuthenticationBoundary;

function credentialFor(sub: string, over: Record<string, unknown> = {}): string {
  return mintCredential({ iss: ISS, sub, aud: AUD, iat: nowSec - 10, exp: nowSec + 600, ...over }, { kid: KID, keyMaterial: KEY });
}
function input(credential: string): AuthenticationInput {
  return { credential, requestId: `req-${randomUUID()}`, receivedAt: new Date(NOW) };
}
function mkIdentity(sub: string): VerifiedIdentity {
  return {
    issuer: ISS, subject: sub, audiences: [AUD],
    issuedAt: new Date(NOW), expiresAt: new Date(NOW + 600_000), notBefore: null, authenticationTime: null,
    authenticationMethods: [], authenticationStrength: "single_factor", credentialId: null, nonce: null,
    verificationKeyId: KID, verificationPolicyVersion: policy.policyVersion, rawClaimsDigest: "d",
  };
}

beforeAll(async () => {
  const bootstrap = adminPool({ ...DB, database: "continuum" });
  try {
    await bootstrap.query("DROP DATABASE IF EXISTS continuum_s3");
    await bootstrap.query("CREATE DATABASE continuum_s3");
  } finally {
    await bootstrap.end();
  }
  await migrate(DB); // through 0005
  admin = adminPool(DB);
  sess = sessionPool(DB);

  const seedPrincipal = (id: string, status: string) =>
    admin.query(`INSERT INTO continuum.principals (principal_id, principal_type, status, suspended_at) VALUES ($1,'human',$2,$3)`,
      [id, status, status === "suspended" ? new Date() : null]);
  const seedIdentity = (principal: string, sub: string, status = "active") =>
    admin.query(`INSERT INTO continuum.external_identities (external_identity_id, principal_id, issuer, subject, status) VALUES ($1,$2,$3,$4,$5)`,
      [randomUUID(), principal, ISS, sub, status]);

  await seedPrincipal(P_ACTIVE, "active");
  await seedPrincipal(P_SUSP, "suspended");
  await seedPrincipal(P_DISABLED, "active");
  await seedIdentity(P_ACTIVE, "sub-active");
  await seedIdentity(P_SUSP, "sub-susp");
  await seedIdentity(P_DISABLED, "sub-disabled", "disabled");

  const keyProvider = new InMemoryVerificationKeyProvider();
  keyProvider.setKeys({ issuer: ISS, version: "v1", keys: [{ kid: KID, algorithm: DETERMINISTIC_ALG, material: KEY }], fetchedAt: new Date(NOW), staleAfter: null });
  sink = new PostgresAuthEventSink(sess);
  mapper = new PostgresPrincipalMapper(sess);
  sessions = new PostgresSessionManager(sess, { digestKeys: DIGEST_KEYS, rotationIdleTtlSeconds: 900 });
  boundary = new AuthenticationBoundary({
    verifier: new DeterministicIdentityVerifier({ keyProvider }), policy, mapper, sessions, sink,
    idleTtlSeconds: 900, absoluteTtlSeconds: 3600,
  });
});

afterAll(async () => {
  await admin.end();
  await sess.end();
});

describe("S3 identity & session boundary", () => {
  it("a verified, mapped identity mints a session that validates before expiry", async () => {
    const r = await boundary.authenticate(input(credentialFor("sub-active")));
    expect(r.authenticated).toBe(true);
    if (!r.authenticated) return;
    expect(r.principalId).toBe(P_ACTIVE);
    const v = await sessions.validateSession(r.session.credential, { requestId: "r", receivedAt: new Date(NOW + 1000) });
    expect(v.valid).toBe(true);
    if (v.valid) {
      expect(v.session.principalId).toBe(P_ACTIVE);
      expect("tenant" in (v.session as unknown as Record<string, unknown>)).toBe(false); // NO tenant in a validated session
    }
  });

  it("the session credential is stored only as a keyed digest (never the raw secret)", async () => {
    const r = await boundary.authenticate(input(credentialFor("sub-active")));
    if (!r.authenticated) throw new Error("expected auth");
    const secret = r.session.credential.value.split(".")[1]!;
    const row = (await admin.query("SELECT credential_digest, credential_digest_version FROM continuum.authenticated_sessions WHERE session_id=$1", [r.session.sessionId])).rows[0];
    expect(row.credential_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(row.credential_digest).not.toContain(secret);
    expect(row.credential_digest_version).toBe("d1");
  });

  it("unmapped / disabled-mapping / suspended-principal identities deny at the mapping stage", async () => {
    const unmapped = await boundary.authenticate(input(credentialFor("sub-unmapped")));
    expect(unmapped).toMatchObject({ authenticated: false, stage: "mapping", reason: "no_mapping" });
    const disabled = await boundary.authenticate(input(credentialFor("sub-disabled")));
    expect(disabled).toMatchObject({ authenticated: false, reason: "mapping_disabled" });
    const susp = await boundary.authenticate(input(credentialFor("sub-susp")));
    expect(susp).toMatchObject({ authenticated: false, reason: "principal_suspended" });
  });

  it("a mapping below the required minimum version is stale", async () => {
    const strict = new PostgresPrincipalMapper(sess, { minimumMappingVersion: 2 });
    const m = await strict.resolve(mkIdentity("sub-active"));
    expect(m).toMatchObject({ mapped: false, reason: "mapping_version_stale" });
  });

  it("idle and absolute expiry deny", async () => {
    const idle = await sessions.createSession(mkIdentity("sub-active"), { principalId: P_ACTIVE, version: 1 }, {
      requestId: "r", receivedAt: new Date(NOW), authenticationStrength: "single_factor",
      identityMappingVersion: "1", verificationPolicyVersion: policy.policyVersion, idleTtlSeconds: 1, absoluteTtlSeconds: 3600,
    });
    const v1 = await sessions.validateSession(idle.credential, { requestId: "r", receivedAt: new Date(NOW + 5000) });
    expect(v1).toMatchObject({ valid: false, reason: "idle_expired" });

    const abs = await sessions.createSession(mkIdentity("sub-active"), { principalId: P_ACTIVE, version: 1 }, {
      requestId: "r", receivedAt: new Date(NOW), authenticationStrength: "single_factor",
      identityMappingVersion: "1", verificationPolicyVersion: policy.policyVersion, idleTtlSeconds: 3600, absoluteTtlSeconds: 1,
    });
    const v2 = await sessions.validateSession(abs.credential, { requestId: "r", receivedAt: new Date(NOW + 5000) });
    expect(v2).toMatchObject({ valid: false, reason: "absolute_expired" });
  });

  it("revoked session denies; unknown session denies; a tampered secret is a digest mismatch", async () => {
    const r = await boundary.authenticate(input(credentialFor("sub-active")));
    if (!r.authenticated) throw new Error("auth");
    expect(await sessions.revokeSession(r.session.sessionId, "logout")).toEqual({ revoked: true });
    expect(await sessions.validateSession(r.session.credential, { requestId: "r", receivedAt: new Date(NOW + 1000) }))
      .toMatchObject({ valid: false, reason: "revoked" });

    expect(await sessions.validateSession({ value: `${randomUUID()}.deadbeef` }, { requestId: "r", receivedAt: new Date(NOW) }))
      .toMatchObject({ valid: false, reason: "unknown_session" });

    const r2 = await boundary.authenticate(input(credentialFor("sub-active")));
    if (!r2.authenticated) throw new Error("auth");
    const tampered = { value: `${r2.session.sessionId}.${"x".repeat(43)}` };
    expect(await sessions.validateSession(tampered, { requestId: "r", receivedAt: new Date(NOW + 1000) }))
      .toMatchObject({ valid: false, reason: "digest_mismatch" });
  });

  it("rotation atomically invalidates the old credential and issues a new one (never both active)", async () => {
    const r = await boundary.authenticate(input(credentialFor("sub-active")));
    if (!r.authenticated) throw new Error("auth");
    const v = await sessions.validateSession(r.session.credential, { requestId: "r", receivedAt: new Date(NOW + 1000) });
    expect(v.valid).toBe(true);
    if (!v.valid) return;

    const rotated = await sessions.rotateSession(v.session, "reauthentication");
    // Old credential is now invalid (rotated); new one validates.
    expect(await sessions.validateSession(r.session.credential, { requestId: "r", receivedAt: new Date(NOW + 2000) }))
      .toMatchObject({ valid: false, reason: "rotated" });
    expect((await sessions.validateSession(rotated.credential, { requestId: "r", receivedAt: new Date(NOW + 2000) })).valid).toBe(true);
    // Exactly one active (non-revoked) session in the rotation lineage.
    const active = (await admin.query(
      "SELECT count(*)::int n FROM continuum.authenticated_sessions WHERE session_id IN ($1,$2) AND revoked_at IS NULL",
      [r.session.sessionId, rotated.sessionId])).rows[0].n;
    expect(active).toBe(1);
  });

  it("an identity-version change makes a prior session stale", async () => {
    const r = await boundary.authenticate(input(credentialFor("sub-active")));
    if (!r.authenticated) throw new Error("auth");
    await admin.query("UPDATE continuum.principals SET version = version + 1 WHERE principal_id=$1", [P_ACTIVE]);
    try {
      expect(await sessions.validateSession(r.session.credential, { requestId: "r", receivedAt: new Date(NOW + 1000) }))
        .toMatchObject({ valid: false, reason: "identity_version_stale" });
    } finally {
      await admin.query("UPDATE continuum.principals SET version = 1 WHERE principal_id=$1", [P_ACTIVE]);
    }
  });

  it("a mapping-version bump makes a prior session's identity mapping stale", async () => {
    const r = await boundary.authenticate(input(credentialFor("sub-active")));
    if (!r.authenticated) throw new Error("auth");
    await admin.query("UPDATE continuum.external_identities SET mapping_version = mapping_version + 1 WHERE principal_id=$1", [P_ACTIVE]);
    try {
      expect(await sessions.validateSession(r.session.credential, { requestId: "r", receivedAt: new Date(NOW + 1000) }))
        .toMatchObject({ valid: false, reason: "identity_mapping_stale" });
    } finally {
      await admin.query("UPDATE continuum.external_identities SET mapping_version = 1 WHERE principal_id=$1", [P_ACTIVE]);
    }
  });

  it("session persistence survives a restart (fresh pool)", async () => {
    const r = await boundary.authenticate(input(credentialFor("sub-active")));
    if (!r.authenticated) throw new Error("auth");
    const fresh = sessionPool(DB);
    const mgr2 = new PostgresSessionManager(fresh, { digestKeys: DIGEST_KEYS, rotationIdleTtlSeconds: 900 });
    try {
      expect((await mgr2.validateSession(r.session.credential, { requestId: "r", receivedAt: new Date(NOW + 1000) })).valid).toBe(true);
    } finally {
      await fresh.end();
    }
  });

  it("no raw credential or secret ever appears in the auth-event stream", async () => {
    const r = await boundary.authenticate(input(credentialFor("sub-active")));
    if (!r.authenticated) throw new Error("auth");
    const secret = r.session.credential.value.split(".")[1]!;
    const dump = JSON.stringify((await admin.query("SELECT * FROM continuum.auth_events")).rows);
    expect(dump).not.toContain(secret);
    expect(dump).not.toContain(r.session.credential.value);
    expect(dump).not.toContain("sub-active"); // subjects are digested, never raw
    // But the stream DID record the redacted lifecycle events.
    const types = (await admin.query("SELECT DISTINCT event_type FROM continuum.auth_events")).rows.map((x) => x.event_type);
    expect(types).toEqual(expect.arrayContaining(["identity.verified", "session.created"]));
  });

  it("the session role has NO tenant-authority path (S2B remains the only way to a tenant)", async () => {
    // Cannot read the public data plane…
    await expect(sess.query("SELECT 1 FROM public.intents LIMIT 1")).rejects.toThrow(/permission denied/i);
    // …cannot read tenant memberships…
    await expect(sess.query("SELECT 1 FROM continuum.tenant_memberships LIMIT 1")).rejects.toThrow(/permission denied/i);
    // …and cannot invoke the trusted tenant-context establisher.
    await expect(sess.query("SELECT continuum.begin_authenticated_context($1,$2,$3,$4)", [randomUUID(), randomUUID(), randomUUID(), null]))
      .rejects.toThrow(/permission denied/i);
  });
});
