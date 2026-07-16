# Phase 3 S4B — browser-independent authorization-code protocol state machine

A persisted, single-use authorization-code transaction boundary that binds
`state`, `nonce`, PKCE, issuer and redirect URI, and handles callback consumption
**before any browser-facing or provider-specific integration exists**. No session
is minted until every step succeeds; the normalized identity flows through the S4A
verifier and the S3 principal/session boundary, so a completed login still carries
no tenant authority — S2B remains the sole tenant-authority transition.

**Test-scope framing (do not overstate).** S4B ships a deterministic flow, a
**fixture** code exchanger (never a real provider/token endpoint), and a
**test-protected** (in-process AES-256-GCM) PKCE secret store. There are no browser
routes, cookies, CSRF middleware, refresh tokens, provider SDK, or deployment
config. Production configuration is refused (fail-closed) until the real
provider/exchanger/KMS-backed store arrive in a later, separately-reviewed step.

## Protocol sequence

```
begin login
  → create persisted authorization transaction (state, nonce, PKCE verifier+S256)
  → return authorization request parameters
receive callback
  → atomically consume the transaction (single-use)
  → validate state / issuer / redirect URI / expiry
  → exchange the code through an abstract (fixture) exchanger
  → verify the returned identity token through S4A
  → confirm the nonce matches the transaction
  → map the verified identity through S3
  → create a restart-safe, digest-only session
  → append evidence
```

Completion ordering (no session before every prior step succeeds): validate
callback structure → atomically consume by state digest → validate expiry/binding →
recover PKCE verifier → exchange code → S4A-verify the id token → issuer binding →
nonce binding → S3 principal mapping → create session → finalize + success evidence.

## Interfaces (provider-neutral)

`AuthorizationCodeFlow` (`begin`/`complete`), `AuthorizationTransactionStore`
(`create`/`consume`/`finalize`/`expireBefore`), `AuthorizationCodeExchanger`
(`exchange`), `AuthorizationClientRegistry`, `AuthorizationEventSink`,
`ProtectedSecretStore`. `finalize` is an internal terminal-status writer (audit
accuracy) beyond the three methods named in the milestone brief.

## State & nonce

CSPRNG, 256 bits, base64url — opaque and unguessable. Persisted only as **keyed
digests** (`state_digest`, `nonce_digest`); the raw values are returned once at
`begin` (they must travel to the provider) and never stored, logged, or written to
evidence. State is one-time-consumable, bound to the transaction, expiry-enforced,
and compared via its keyed digest. The nonce is validated against the S4A-verified
id token by digesting the token's `nonce` claim and comparing to `nonce_digest`
(constant-time), so successful state validation is never a substitute for nonce
validation.

## PKCE (S256 only)

`verifier` = 32 random bytes (base64url, RFC 7636 unreserved, length/charset
validated); `challenge` = BASE64URL(SHA256(verifier)); `method` = S256. Plain PKCE
is unsupported (`assertS256`). The challenge is generated internally; a caller
cannot supply a precomputed verifier or challenge.

**PKCE verifier custody boundary (non-production).** The verifier must reach the
token endpoint at exchange, so it is stored **encrypted-at-rest**, never as a
one-way digest, with these properties:

- **Format/version:** AES-256-GCM; ciphertext = `base64(iv[12] ‖ tag[16] ‖ ct)`;
  the key version is stored alongside (`pkce_verifier_key_version`).
- **Authenticated encryption:** GCM — decryption verifies the auth tag; any tampered
  ciphertext or wrong key returns `null` (fail-closed).
- **Key identifier & rotation:** keys are versioned; `protect` uses the current
  version, `reveal` selects by the stored version — a rotation boundary that does not
  invalidate in-flight transactions still readable under a retained version.
- **Decryption-unavailable behaviour:** an unknown/absent key version or a decryption
  failure yields `null`, which the flow treats as `internal_protocol_error` and
  denies — no session is minted.
- **Production prohibition:** this is the TEST-protected in-process store
  (`TestProtectedSecretStore`), used only to prove protocol binding and secret-handling
  semantics. Production refuses `CONTINUUM_PKCE_SECRET_STORE=test-protected`; a
  separately-reviewed KMS/HSM-backed (or equivalently protected) secret-custody
  mechanism is required before production. The test key is never valid in production.

Evidence contains only PKCE method metadata and safe digests — never the verifier.

## Redirect URI, client & issuer binding

Client id, redirect URI and authorization endpoint come from the trusted
`AuthorizationClientRegistry` keyed by issuer; the caller supplies only the issuer
to authenticate against and can inject none of them. The transaction is bound to
`(issuer, client_id, redirect_uri)`, and those columns are immutable (the session
role has no UPDATE; only narrow definer functions mutate the row, and none touch the
bindings). The callback identifies the expected issuer through the persisted
transaction, not through untrusted callback parameters; the S4A-verified token's
issuer must equal the transaction issuer, so a validly-signed token from a different
configured issuer is rejected for this transaction.

## Atomic one-time consumption

Consumption is a single guarded `UPDATE ... WHERE consumed_at IS NULL AND expires_at
> now RETURNING` inside the SECURITY-DEFINER `consume_authorization_transaction`
function (no read-then-update). Exactly one concurrent callback acquires the
transaction; the rest are classified `unknown` / `already_consumed` / `expired`. A
transaction is consumed **before** external exchange begins, so exchange or
verification failure does not make it reusable; a fresh login must create a new
transaction. The row is never DELETEd — expiry marks status, preserving audit
evidence.

**Terminal-status categorization.** A consumed transaction that does not complete is
finalized to the status of the stage that failed — `exchange_failed`,
`verification_failed`, `nonce_failed`, `mapping_failed`, or `session_failed` — versus
`completed` on success (and a generic `failed` for uncategorized denials). All of
these remain **consumed** (never reusable); the distinction exists only for audit
accuracy, not to reopen the transaction.

**Replay-prevention boundary (state precisely).** The evaluated S4B implementation
provides **restart-safe, single-database authorization-transaction replay prevention
using atomic one-time consumption**. It does **not** establish that "authorization
codes can never be replayed." Specifically NOT established by S4B: cross-region or
cross-deployment state-digest uniqueness; multiple-database / multi-writer
consistency; resistance to a privileged database role tampering with the transaction
row; provider-side authorization-code single-use enforcement (the exchanger is a
fixture); any browser-channel replay defense; and the case where an attacker already
holds the raw `state`, code, and PKCE verifier before the legitimate callback
completes. The guarantee is exactly: within one database, a given transaction is
consumable at most once, and that fact survives process restart.

## Code handling

The authorization code is treated as a bearer secret: length/charset bounded, never
persisted beyond the bounded exchange call, never written to evidence or returned
downstream. The exchange abstraction (`AuthorizationCodeExchangeInput`/`Result`) has
its own 14-class taxonomy (`invalid_code`, `expired_code`, `code_already_used`,
`pkce_mismatch`, `redirect_uri_mismatch`, `client_mismatch`, `issuer_mismatch`,
`token_endpoint_unavailable`, `timeout`, `malformed_response`,
`missing_identity_token`, `unexpected_token_type`, `internal_exchange_error`,
`success`), which is not collapsed into identity-verification failure.

## Session-fixation resistance

Even without cookies, `complete` accepts no pre-authentication session credential and
always mints a NEW session; no caller-supplied credential is ever upgraded. A prior
anonymous context id may be attached to `begin` for evidence only and never becomes
authenticated authority.

## Evidence

Recorded (redacted): transaction created, callback denied, state unknown/replayed,
transaction expired, issuer/redirect mismatch, code-exchange denied, identity-token
verification denied, nonce mismatch, principal-mapping denied, session created,
transaction completed — as digests + safe ids only (transaction digest, issuer/
subject digests, principal/session ids, policy version). Never recorded: raw state,
raw nonce, PKCE verifier, authorization code, identity token, token-endpoint
credentials, or session credential.

## Failure taxonomy (24)

`invalid_request, unsupported_issuer, state_missing, state_malformed, state_unknown,
state_replayed, transaction_expired, transaction_already_consumed, issuer_mismatch,
client_mismatch, redirect_uri_mismatch, code_missing, code_malformed,
code_exchange_denied, code_exchange_unavailable, pkce_mismatch, identity_token_missing,
identity_verification_denied, nonce_missing, nonce_mismatch, identity_mapping_denied,
principal_inactive, session_creation_failed, evidence_write_failed,
internal_protocol_error`. All uncertainty fails closed.

## Persistence & schema

Migration `0007_authorization_transactions.sql`: the `authorization_transactions`
table (unique `state_digest`; status + consumed-state consistency checks; S256-only
check; encrypted PKCE verifier + key version; immutable issuer/client/redirect
binding; expiry index), the SECURITY-DEFINER `consume`/`finalize`/`expire` functions
(session role EXECUTE-only, no direct UPDATE/DELETE — the definer owner
`continuum_authctx` holds SELECT+UPDATE, never DELETE), and a `transaction_digest`
column on the shared `auth_events` stream. All served by the least-privilege
`continuum_session` role with no tenant path.

## Configuration (fail-closed)

`CONTINUUM_AUTH_CODE_FLOW=deterministic`, `CONTINUUM_AUTH_TRANSACTION_STORE=postgres`,
`CONTINUUM_CODE_EXCHANGER=fixture`, `CONTINUUM_PKCE_SECRET_STORE=test-protected`.
Production refuses the deterministic flow, fixture exchanger, test-protected PKCE
store and memory transaction store; plain PKCE is always refused; transaction
lifetimes must be bounded and positive; there is no silent fallback.

## Tests

Core: `authz-flow.test.ts` (11), `authz-secrets.test.ts` (5), `authz-config.test.ts`
(4). Persistence (real embedded PostgreSQL): `s4b-authz.test.ts` (8) — valid login +
digest-only session with no tenant, exactly-one consumer under eight concurrent
callbacks, restart (pending completes, consumed denies on a fresh pool), expiry,
issuer + nonce binding, suspended-principal / disabled-mapping denials with no
session minted, secret hygiene (no raw state/nonce/code in the row or evidence), and
no tenant path / no direct transaction mutation for the flow role.

## Frozen results (unchanged)

core 201 (181 + 20 S4B) · persistence 113 (105 + 8 S4B) · console 7 · concurrency 9
(still pinned to `0003_identity.sql`) · stage-a 6 · stage-b 7 · i1–i7 6/8/6/6/7/22/8 ·
comparative 44 · typecheck clean. S4B adds migration `0007` without touching
historical evidence.

## Performance observations (coarse, NOT a benchmark)

From test wall-clock only (embedded single-node PostgreSQL): a full login (begin +
callback + atomic consume + fixture exchange + S4A verify + map + session + evidence)
completes in tens of milliseconds; eight concurrent callbacks resolve to one consumer
in well under a second. Observations only; nothing about production-scale latency.

## Supported vs unsupported claims

**Supported:** a persisted, single-use authorization-code **transaction boundary**
with keyed-digest state/nonce, S256 PKCE with an encrypted-at-rest verifier, trusted
issuer/client/redirect binding, atomic one-time consumption (single-database,
restart-safe), an abstract code-exchange contract, S4A id-token verification, S3
principal mapping, fixation-resistant digest-only session minting, redacted evidence,
and fail-closed production configuration.

**Not supported (do not claim):** a real identity provider or token endpoint (the
exchanger is a fixture), secure browser login, authorization-code/PKCE correctness
against a real provider, cookie or CSRF protection, refresh tokens, user-facing login,
KMS/HSM-backed PKCE storage, cross-region/cross-deployment transaction consistency,
workload identity, break-glass, resistance to database-superuser or privileged
session-role compromise, production-scale latency, penetration-tested authentication,
or production readiness.
