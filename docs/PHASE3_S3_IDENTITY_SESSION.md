# Phase 3 S3 — Identity-verification & session boundary (vendor-neutral)

Establishes a vendor-neutral authentication-verification boundary that converts
externally verified identity assertions into normalized internal identities and
restart-safe, revocable sessions, **without granting tenant authority from
untrusted claims**. No provider SDK, browser redirect, PKCE, cookies, CSRF,
refresh tokens, workload identity, break-glass, or deployment config in this
milestone — those are later, separately-reviewed steps.

## Layering (none accepts a caller tenant)

```
external credential/assertion
  → IdentityVerifier        → normalized VerifiedIdentity
  → PrincipalMapper         → internal principal (issuer+subject → principal)
  → SessionManager          → validated internal session
  → S2B trusted DB context  → tenant (derived from an active membership, never here)
```

The stable external identity key is **(issuer, subject)** — never email, display
name, username, or subject alone (`externalIdentityKey`, tested). Downstream
authorization never sees the raw claims object; it sees the normalized
`VerifiedIdentity` plus a `rawClaimsDigest` for correlation.

## Claim-layer separation (do not conflate)

These are three distinct authority claims, and none implies the next:

- **Identity-assertion verification** → establishes a normalized *external identity*.
- **Session validation** → establishes an authenticated *internal principal*.
- **Trusted membership resolution** → establishes *tenant authority*.

A valid identity or a valid session **never** implies tenant membership by itself.
S2B (`continuum.current_tenant()` derived from an active owned membership) remains
the **sole** authority transition into the transaction-local tenant context.

## Interfaces (in `@continuum/core/identity`)

- `IdentityVerifier.verify(input, policy) → IdentityVerificationResult` — success
  yields a `VerifiedIdentity`; failure yields one of 15 distinct classes
  (`missing_credential, malformed_credential, unsupported_issuer,
  unsupported_algorithm, signature_invalid, verification_keys_unavailable,
  unknown_key, audience_mismatch, expired, not_yet_valid, issued_in_future,
  nonce_mismatch, replay_detected, subject_missing, claims_invalid,
  policy_version_mismatch`) plus redacted `AuthenticationEvidence` (digests only).
  Errors are never collapsed into a success-with-warning path.
- `VerificationKeyProvider.getVerificationKeys(issuer, at) → KeyLookup` — models
  availability, staleness (`staleAfter`) and key-set versions; unknown `kid`
  rejects; unavailable/stale fail closed. No remote fetch in S3.
- `ReplayGuard.checkAndConsume(issuer, credentialId)` — single-use credential-id
  guard. In the deterministic verifier this is **process-local and test-scoped
  only** (see "Deterministic replay limitation" below).
- `PrincipalMapper.resolve(identity) → PrincipalMappingResult` — deny by default;
  denies on `no_mapping, mapping_disabled, principal_suspended, principal_deleted,
  mapping_version_stale, external_identity_revoked, ambiguous_mapping,
  mapping_store_unavailable`. No implicit enrolment.
- `SessionManager.{createSession, validateSession, rotateSession, revokeSession}`.
- `AuthEventSink.append(event)` — redacted identity/session lifecycle events.
- `AuthenticationBoundary` — composes the four layers over the interfaces only.

## Identity normalization rules

Algorithm is checked against **both** the global and the issuer allowlist, and the
verifying key's algorithm must match — never trust the header `alg` alone. Audience
must intersect the issuer's allowed audiences. Temporal checks (iat/exp/nbf,
future-issued, maximum credential age) use a bounded clock skew. Subject is
required and is scoped to the issuer. `acr`→strength, `amr`→methods. The identity
carries `verificationKeyId`, `verificationPolicyVersion`, and `rawClaimsDigest`.

## Verification-key unavailability

`verification_keys_unavailable` when the provider reports the issuer's key set
absent OR stale beyond `staleAfter`; `unknown_key` when the `kid` is not in the
set. Stale keys are never silently reused. The deterministic in-memory provider
supports `setKeys`/`markUnavailable` and key-set versioning for tests.

## Deterministic replay limitation

Credential replay detection in the deterministic verifier is **process-local and
test-scoped**. It is **not restart-safe or distributed and is not a production
replay defence**. S3 is not described as providing durable external-assertion
replay prevention: the durable guarantees in this system apply to sessions and the
previously implemented proof-consumption ledger, not to external authentication
assertions. Durable/shared nonce-replay handling is deferred to the real verifier
milestone (S4A).

## Principal-mapping behaviour

`(issuer, subject)` resolves through `continuum.external_identities` to a single
active internal principal, joined to `continuum.principals` for state. Multiple
rows → `ambiguous_mapping`. Disabled/revoked mapping, suspended/deleted principal,
and (optionally) a mapping version below a configured minimum all deny. Absent
mapping → `no_mapping` (deny-by-default; enrolment is a separate future flow).

## Session digest construction & versioning

A session credential is the opaque value `${sessionId}.${secret}` (`secret` = 32
random bytes). Only `HMAC(digestKey[version], "${sessionId}:${secret}")` is stored,
with the `credential_digest_version` recorded per row. The digest is bound to the
session id (cannot be transplanted) and is useless without the server-side key.
Keys are versioned so they rotate without invalidating existing sessions; an
unavailable version fails closed. The raw credential is returned only at creation
and rotation and never enters the auth-event stream.

## Rotation transaction semantics

`rotateSession` runs one transaction: read the old session, INSERT the replacement
(fresh secret, `rotated_from_session_id` set, **absolute expiry preserved** so
rotation cannot extend lifetime, idle reset), UPDATE the old to
`revoked_at = now, revocation_reason = 'rotated'`, append a `session.rotated`
event, COMMIT. A successful rotation therefore never leaves both credentials
active (test asserts exactly one non-revoked session in the lineage).

## Revocation & expiry

Validation denies on `unknown_session, malformed_credential, digest_mismatch,
revoked, rotated, idle_expired, absolute_expired, principal_inactive,
identity_version_stale, identity_mapping_stale, policy_version_stale,
insufficient_strength, store_unavailable`. Revocation and suspension take effect on
the next validation; an identity-version or mapping-version bump makes prior
sessions stale.

## Tenant-authority separation

A `ValidatedSession` carries `principalId` + strength + timestamps + mapping
version — **no tenant**. The session runs as a dedicated `continuum_session` role
that has NO access to `tenant_memberships`, no `public.*` privileges, and no
`EXECUTE` on `begin_authenticated_context` (test asserts `permission denied` for
each). Tenant authority is reached only later, from the validated session's
principal, through the S2B trusted-context function. A tenant is never placed
inside a session credential as self-authorizing state.

## Production configuration guards

`CONTINUUM_IDENTITY_VERIFIER=deterministic` (dev/test only; production refuses it —
so production currently fails closed until a real verifier lands),
`CONTINUUM_SESSION_STORE=postgres` (production requires it; no memory fallback),
`CONTINUUM_SESSION_DIGEST_KEYS`+`CONTINUUM_SESSION_DIGEST_VERSION` (required). No
provider-specific variables. Missing/invalid config in production terminates
startup (`assertProductionIdentityConfig`).

## Persistence & role

Migration `0005_session_identity.sql`: session columns
(`credential_digest_version, identity_mapping_version, verification_policy_version,
revocation_reason, rotated_from_session_id, created_request_id`),
external-identity mapping state (`status, mapping_version, disabled_at,
revoked_at`), the append-only `continuum.auth_events` stream, and the least-
privilege `continuum_session` login role (SELECT on identities/principals;
SELECT/INSERT + column-level UPDATE on sessions; SELECT/INSERT on auth_events;
nothing else). All new session columns are nullable so the S2B admin provisioning
path is unaffected; an S3-minted session's `identity_version` matches the
principal, so it interoperates with `begin_authenticated_context`.

## Evidence

Recorded (redacted — digests + non-secret ids only): identity verified/denied,
unmapped identity, suspended-principal denial, session created/validation-denied/
rotated/revoked, stale-mapping denial, unavailable-keys denial. Never recorded: raw
credentials, tokens, signatures, full claim sets, session secrets, private keys.
The auth-event stream is pre-tenant/cross-tenant, so it is separate from the
tenant-scoped hash-chained evidence ledger; it is append-only (trigger-enforced).

## Tests & frozen results

Core: `verifier.test.ts` (15), `session-digest.test.ts` (6), `config.test.ts` (4).
Persistence: `s3-session.test.ts` (12, real embedded PostgreSQL). Frozen results
unchanged: core 116 (91 + 25 S3), persistence 91 (79 + 12 S3), console 7,
concurrency 9, stage-a 6, stage-b 7, i1–i7 6/8/6/6/7/22/8, comparative 44,
typecheck clean.

## Supported vs unsupported claims

**Supported:** a vendor-neutral verification boundary that normalizes verified
assertions to `(issuer, subject)` identities and mints digest-only, revocable,
restart-safe sessions; the session layer holds no tenant authority; fail-closed
configuration and denials throughout.

**Not supported:** end-to-end user authentication, OIDC/JWT security, a real
provider, remote JWKS retrieval or key-rotation resilience, durable/distributed
external-assertion replay prevention, browser flows, resistance to
database-superuser or session-role compromise, distributed/cross-region session
consistency, production-scale latency, penetration-tested isolation, or production
readiness.
