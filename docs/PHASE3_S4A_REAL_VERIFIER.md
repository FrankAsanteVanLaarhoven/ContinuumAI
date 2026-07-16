# Phase 3 S4A — provider-neutral real verifier cryptographic boundary

Replaces the S3 deterministic assertion verifier with **provider-neutral JWT/JWS
verification using standards-based JOSE processing within the explicitly supported
algorithms, key types, issuer policies, and claim-validation profile** — not
universal support for every JOSE serialization, algorithm, extension, or token
profile. It fails closed under issuer, algorithm, key-resolution, rotation, outage,
audience, temporal and replay failures. **Protocol level only** — no browser routes,
authorization redirects, PKCE, cookies, CSRF, provider SDKs, workload identity,
break-glass, deployment config, or HTTP SIF-Bench v0.2 in this milestone.

The normalized output is the SAME S3 `VerifiedIdentity`, so a valid JWT grants no
tenant authority by itself. **Claim-layer separation still holds** (S3): identity
verification ⇒ external identity; session validation ⇒ internal principal; trusted
membership resolution ⇒ tenant authority. S2B remains the sole authority transition
into the transaction-local tenant context.

## Standards library

`jose@6.2.3` (provider-neutral JOSE/JWT), pinned exactly in
`packages/continuum-core/package.json` + the lockfile. No cryptographic primitive
is implemented by hand: JWS verification and JWK import are `jose`. No
provider-branded SDK is used.

## Verification sequence (no downstream unverified claims)

```
encoded assertion
  → input limits (before parse / before network)
  → structural JWT parse (unverified header + issuer — routing only)
  → issuer policy lookup
  → algorithm allowlist (issuer + supported set)
  → verification-key resolution (cached provider over a JWKS source)
  → cryptographic signature verification (jose)
  → claims validation (on the VERIFIED payload only)
  → replay / nonce validation where the issuer policy requires it
  → normalized VerifiedIdentity
  → existing S3 principal/session boundary
```

The `VerifiedIdentity` is built only from the payload returned by a **successful**
signature verification; nothing downstream sees unverified claims.

## Input limits (`jwt-limits.ts`)

Applied to the opaque assertion before parse and before any key resolution:
max assertion length, max header bytes, max payload bytes, and (during claims
validation) max audiences, max authentication methods, and max string length for
issuer/subject/nonce/kid/jti. Oversized ⇒ `assertion_too_large`; structurally
malformed ⇒ `malformed_jwt`.

## Unverified-header use

The protected header (`alg`, `kid`) and the unverified `iss` are used ONLY to route
policy and keys — never to establish identity, tenant, role, strength, authorization
or session validity. All of those derive from the verified payload.

## Issuer policy

Issuers are registered in advance (`JwtIssuerPolicy`): audiences, per-issuer
algorithm allowlist, key-provider id, enabled flag, subject/iat/exp requirements,
nonce requirement, max credential age, max clock skew, replay policy
(`none | nonce | jti | nonce_and_jti`), and policy version. Arbitrary issuers are
never discovered or accepted from the assertion.

## Algorithm controls

Asymmetric only (`RS*`, `PS*`, `ES*`, `EdDSA`); no `none`, no HMAC (symmetric
substitution rejected at the supported-set gate). The header `alg` must be in **both**
the issuer allowlist and the supported set, and the resolved key's `kty`/`crv` must
match the algorithm (`ALGORITHM_KEY_SHAPE`); a key that merely *can* verify is not
sufficient. Signature verification restricts `jose` to the single expected algorithm,
so there is no post-failure algorithm fallback.

## Key provider, JWKS source, cache & rotation

- `JwtVerificationKeyProvider.resolveKey` returns a distinct status
  (`resolved | key_id_missing | key_unknown | ambiguous_key | algorithm_key_mismatch |
  keys_unavailable | keys_stale | refresh_failed | issuer_unknown | invalid_key_material`).
  A key outage is never collapsed into a signature failure.
- `JwksSource` is provider-neutral: an in-memory fixture source and an HTTP source,
  both validating key sets identically (`validateJwks`) — private key material in a
  public set is rejected.
- `CachedVerificationKeyProvider` implements a predeclared `JwksCachePolicy`
  (fresh lifetime, stale grace, max stale age, refresh timeout, max response bytes,
  max key count, accepted key types/curves, negative-cache lifetime): fresh cache is
  used directly; an unknown kid in a fresh cache triggers **one** bounded refresh and
  a single retry; a repeated unknown kid is briefly negative-cached to limit refresh
  amplification; a cache beyond max stale age is refused; concurrent refreshes for one
  issuer are coalesced (single-flight). At most one refresh per verification attempt.
- **Rotation** is covered by tests: old key valid before rotation, new key valid after
  refresh, cached key served within the stale grace on refresh failure, removed key
  rejected once the cache is no longer fresh, unknown kid triggers exactly one refresh.
  The key-set version and digest are recorded in evidence so a version regression is
  detectable.

## Remote retrieval security (SSRF boundary, `http-jwks-source.ts`)

The issuer→JWKS URL is trusted configuration; the assertion can never choose a URL.
HTTPS is required outside deterministic loopback tests; requests send no credentials,
refuse redirects (`redirect: "error"`), bound the timeout (AbortController), bound the
response size (streamed byte cap + content-length check), check the content type, and
— in production — refuse private/loopback/link-local/ULA destinations
(`isPrivateHost`). The transport is injectable so tests use a deterministic local
server, never a real provider.

**Scope of this control (do not overstate).** The tested JWKS transport applies
configured destination, protocol, redirect, timeout, response-size and content-type
restrictions. This is not a claim of complete SSRF elimination: DNS rebinding, proxy
behaviour, resolver configuration, and infrastructure-level egress controls remain
operational boundaries unless independently tested.

## Claims validation (on the verified payload)

Exact issuer; audience intersection with the configured audiences; subject present;
expiration; not-before; issued-at; maximum credential age; future-issued only within
skew; nonce when expected; jti when the replay policy requires it; claim type
validation (no coercion — `aud` as number, `exp` as text, empty subject, `amr` object,
`nonce`/`jti` array all deny); bounded array and string sizes; and a policy-version
match when the credential names one.

## Replay protection (durable, PostgreSQL-backed)

Where an issuer's replay policy is active, the verifier computes a **keyed digest** of
the nonce/jti and consumes it through a `DurableReplayLedger`. The PostgreSQL
implementation (`replay_ledger`, migration `0006`) stores only the digest, issuer,
kind, expiry, consumed-at and request id — never the raw identifier — and consumes
atomically with insert-first `ON CONFLICT DO NOTHING` on a `(issuer, replay_kind,
digest)` uniqueness constraint (no read-then-insert race). Replay state is
tenant-independent, scoped by (issuer, kind), survives restart, and expires by a
SECURITY-DEFINER pruner restricted to already-expired rows (the session role has no
direct DELETE, so it cannot remove a live consumed entry to re-enable a replay). The
store fails closed: an outage yields `unavailable` and the verifier denies
(`replay_store_unavailable`).

**Replay claim boundary (do not overstate).** The evaluated verifier supports durable,
**single-database** replay detection for configured nonce and/or `jti` policies using
atomic insert-first consumption. It does NOT provide global replay prevention,
cross-region or cross-deployment replay consistency (separate deployments that do not
share this ledger are not protected against each other), browser-flow nonce protection
(no browser protocol exists yet), or prevention of credential theft before first use.
The ledger proves duplicate consumption within its tested database boundary.

## Evidence

Recorded (`JwtVerificationEvidence`, redacted): outcome, reason class, issuer digest,
algorithm, key-id digest, key-set version + digest, verification-policy version,
assertion digest, normalized-identity digest, replay outcome, coarse elapsed time.
Never recorded: raw assertion, raw signature, full claims, raw nonce/jti, private
keys, session credentials.

## Failure taxonomy

`assertion_too_large, malformed_jwt, unsupported_issuer, issuer_disabled,
unsupported_algorithm, missing_key_id, unknown_key, ambiguous_key, key_type_mismatch,
keys_unavailable, keys_stale, jwks_refresh_failed, signature_invalid, issuer_mismatch,
audience_mismatch, subject_missing, claims_invalid, expired, not_yet_valid,
issued_in_future, credential_too_old, nonce_missing, nonce_mismatch, jti_missing,
replay_detected, replay_store_unavailable, policy_version_mismatch,
internal_verification_error`. Fail closed on all internal uncertainty. For the S3
boundary, this 28-class taxonomy is projected onto the 16-class S3 taxonomy by a total
mapping (`mapJwtFailureToS3`).

## Configuration (`jwt-config.ts`, fail-closed, vendor-neutral)

`CONTINUUM_IDENTITY_VERIFIER=jwt` (production requires it; deterministic refused),
`CONTINUUM_JWKS_PROVIDER=cached` (production requires it; fixture/local-http refused),
`CONTINUUM_REPLAY_STORE=postgres` (required in production where replay policy is
active). No provider-specific variables; no silent fallback to deterministic
verification. `assertProductionJwtConfig` terminates startup on any violation.

## Tests

Core: `jwt-verifier.test.ts` (28), `cached-key-provider.test.ts` (14),
`jwks-http.test.ts` (13), `jwt-config.test.ts` (4), `replay-ledger.test.ts` (6).
Persistence (real embedded PostgreSQL): `s4a-replay.test.ts` (8),
`s4a-jwt-integration.test.ts` (6). All use genuine `jose` signatures and a
deterministic local JWKS server; no test points at a real identity provider.

## Frozen results (unchanged)

core 181 (116 + 65 S4A) · persistence 105 (91 + 14 S4A) · console 7 · concurrency 9
(still pinned to `0003_identity.sql`) · stage-a 6 · stage-b 7 · i1–i7 6/8/6/6/7/22/8 ·
comparative 44 · typecheck clean. S4A adds migration `0006` without altering the
historical intervention/GAP evidence.

## Performance observations (coarse, NOT a benchmark)

From test wall-clock only (embedded single-node PostgreSQL, dev machine): the 28
core signature-verification cases (including token minting) complete in tens of
milliseconds total; the 6 PostgreSQL integration cases (verify + map + session +
replay round-trips) in a few hundred milliseconds total. Warm-cache verification does
no I/O; cold-cache and key-rotation paths add one bounded JWKS load; the replay ledger
adds one indexed insert per active-replay assertion. These are observations, not a
benchmark, and imply nothing about production-scale latency.

## Supported vs unsupported claims

**Supported:** provider-neutral JWT/JWS verification using standards-based JOSE
processing **within the explicitly supported algorithms, key types, issuer policies
and claim-validation profile**; preregistered issuer/audience policy; strict per-issuer
algorithm allowlisting; cached JWKS resolution with bounded refresh and tested rotation
handling; a JWKS transport that applies **configured** destination/protocol/redirect/
timeout/response-size/content-type restrictions; temporal, issuer, audience, subject
and configured replay-claim validation; durable **single-database** replay consumption
(atomic insert-first) in the tested configuration; redacted verification evidence;
fail-closed production configuration; and continued separation between verified
identity, session, membership and tenant authority.

**Not supported (do not claim):** universal JOSE interoperability (every serialization/
algorithm/extension/profile); complete SSRF elimination (DNS rebinding, proxy, resolver
and egress remain operational boundaries); distributed/cross-region or cross-deployment
replay consistency; real identity-provider integration; secure browser login;
authorization-code or PKCE correctness; cookie/CSRF protection; refresh tokens;
user-facing login; workload identity; break-glass; resistance to database-superuser or
privileged session-role compromise; production-scale latency; penetration-tested
authentication; or production readiness.
