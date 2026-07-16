# Continuum — Threat Model (v0.1)

## Assumptions (in scope for the reference slice)

- The platform signing key is generated in-process and not exposed via any API.
- Agents authenticate with a workload identity and hold a private key bound into
  their capability tokens (proof-of-possession).
- The evidence ledger is append-only within the process lifetime.

## Adversaries and the control that answers them

| Threat | Control | Verified by |
|--------|---------|-------------|
| Malicious/over-broad agent request | deny-by-default PDP, 7-check Permit invariant | `primitives.test.ts` |
| Cross-tenant access | policy tenant gate + **database RLS** (enable/force, keyed on `app.current_tenant`) | `slice.test.ts`, `isolation.test.ts` |
| Missing/absent tenant context | RLS fail-closed (no rows visible without `app.current_tenant`) | `isolation.test.ts` |
| Forged tenant identifier on write | RLS policy `WITH CHECK` rejects the insert | `isolation.test.ts` |
| Evidence/authoritative-row tampering (DB) | append-only trigger + INSERT-only role (no UPDATE/DELETE) | `isolation.test.ts` |
| Evidence loss on restart | durable hash-chained store; chain re-verifies after reconnect/restore | `durability.test.ts`, `backup_restore.test.ts` |
| Capability theft / replay | holder-bound token + proof-of-possession (not bearer) | `primitives.test.ts` |
| Expired capability reuse | short TTL + `not_expired` check | `primitives.test.ts` |
| Revoked capability reuse | revocation registry + `not_revoked` check | slice step 12 |
| Token tampering | Ed25519 signature over canonical token | `primitives.test.ts` |
| Confused deputy / excess scope | per-object scope + prohibited-operation checks | policy tests |
| Stale consent | `consent_current` gate with expiry | `primitives.test.ts` |
| Unapproved agent build / model | allowlist checks, fail-closed | `primitives.test.ts` |
| Sensitive-field leakage | broker redaction before release + canary detection | broker tests, metrics |
| Over-disclosure | minimum-necessary broker (2 of 10) | slice + metrics |
| Prompt injection (direct + indirect via retrieved context) | model gateway screens prompt AND context | `gateway.test.ts` |
| Denial-of-wallet | model gateway token/cost budget | `gateway.test.ts` |
| Unapproved model / region / over-classification egress | model gateway allowlist + region + classification checks | `gateway.test.ts` |
| Canary egress through a model call | model gateway egress canary detection | `gateway.test.ts` |
| Malformed model output | output-schema validation + quarantine | `gateway.test.ts` |
| Audit-log tampering | hash-chained, signed ledger; `verifyChain` detects edits | `primitives.test.ts` |
| Prohibited high-consequence action | action state machine hard-denies; human gate blocks the rest | `action.ts`, slice |
| Malformed / unknown-field input | Zod `.strict()` parsing, fail-closed | `primitives.test.ts` |

## Explicitly NOT covered by v0.1

Side-channel leakage, endpoint capture, malicious platform administrator (a
superuser bypasses RLS by design — key custody/HSM is the answer, on the
roadmap), object-storage compromise, denial-of-wallet on real model providers,
supply-chain compromise of dependencies, and semantic leakage through model
outputs. These require the production tiers (KMS/HSM, TEE attestation, DLP) on
the roadmap and are named here so the boundary is honest.

## Residual risk

Tenant isolation and the evidence chain are now enforced/durable in PostgreSQL
via RLS and re-verified after restart, but the platform signing key is still
generated in-process (not yet in an HSM), object storage is not yet encrypted at
the tier, and a database superuser bypasses RLS. Guarantees hold only under the
assumptions above. The model-gateway injection screening is **pattern-based and
heuristic** — it raises cost and catches known patterns; it is not a complete
defence against adversarially-crafted injection, and the model itself is
simulated. See `docs/CLAIMS.md`.

## Open gaps under adversarial measurement (not yet remediated)

Surfaced by SIF-Bench Stage B and the concurrency baseline; recorded so the
boundary is honest, and to be fixed as separately-measured interventions:

- **GAP-1** — scope is agent-declared, so an object protected only by scope is
  extractable via a crafted intent (Stage B `EX-SCOPE-001`, concurrency `C1-06`).
- **GAP-2** — the in-memory `listMemoryMeta(tenantId)` accessor is not
  caller-bound and can enumerate foreign object ids; the durable RLS path enforces
  isolation independently (Stage B `EX-XTENANTID-001`, concurrency `C3-08`).
- **GAP-3** — authorization is a snapshot: an issued capability (and an approved
  action) is re-checked at point of use for signature/expiry/revocation/PoP but
  **not** for consent, policy version, or object lifecycle within its TTL/gate
  window (concurrency `C1-02/03/05/11`, `C2-06`). Point-of-use revocation and
  expiry **are** enforced. _Remediated at the disclosure / model-call point of use
  under the evaluated freshness arms — intervention **I3**
  (`research/sif-bench/interventions/i3/I3_RESULTS.md`): with a freshness mode
  active the capability binds the policy version and a consent digest and
  re-evaluates at use. I3-A reproduces the gap (4/4 staleness dimensions still
  released); I3-B re-checks the bound policy version + consent (2/4); I3-C
  additionally re-evaluates the risk ceiling and object lifecycle against current
  state (0/4), with **zero false denials** on the unchanged-authority control.
  Bounded to those four dimensions at the disclose/model boundary; the
  action-execution re-validation facet and concurrent / eventually-consistent
  propagation are not exercised._
- **GAP-4** — a captured proof-of-possession `(challenge, signature)` is
  replayable within the TTL; challenge freshness/single-use is not enforced
  (`C1-10`). _Remediated under the evaluated single-instance replay-ledger arms —
  intervention **I4** (`research/sif-bench/interventions/i4/I4_RESULTS.md`): a
  server-issued nonce is consumed exactly once via a transactional ledger
  (`INSERT ... ON CONFLICT (token_id, nonce) DO NOTHING`), closing sequential
  replay and concurrent double-spend (I4-B); and the proof is bound to the request
  digest, capability id and audience, closing a fresh-nonce proof lifted onto a
  different operation (I4-C, lifts 3/3 → 0/3). I4-A reproduces the gap; zero false
  denials on the benign control; expiry/non-holder/missing controls hold under
  every arm. Bounded to the single-instance ledger and failure model — holder-key
  compromise, transport/endpoint capture, and cross-node ledger consistency are
  out of scope._
- **GAP-5** — RLS isolation is app-cooperative: the `continuum_app` role may
  re-key `app.current_tenant` mid-transaction via `set_config`; nothing at the DB
  privilege layer prevents it (`C3-06`). _Remediated under the evaluated
  database-bound tenant-identity arms — intervention **I5**
  (`research/sif-bench/interventions/i5/I5_RESULTS.md`): a trusted SECURITY DEFINER
  wrapper resolves the tenant from an authoritative mapping and stamps a
  tamper-evident lock, so a re-key reads nothing. Superuser bypass remains a
  documented non-goal._ **CLOSED on the production public data plane (S2B, migration
  `0004`):** all `public.*` policies now key on `continuum.current_tenant()`, which
  returns a tenant only for a live, membership-pinned `(principal, session,
  membership, tenant)` context established through the SECURITY DEFINER
  `begin_authenticated_context`. A raw `set_config('app.current_tenant', …)` — or
  re-keying only the tenant GUC — yields NULL, so the `continuum_app` role cannot
  create access by setting GUCs; it holds no privileges on the identity tables and
  cannot fabricate an owned membership. Bounded to the application-role model:
  superuser and trusted-function-owner bypass remain non-goals. See
  `docs/S2B_PUBLIC_DATA_PLANE_MIGRATION.md` and
  `src/public-trusted-context.test.ts` / `src/privilege-audit.test.ts`. (The
  concurrency baseline that reproduces this gap is pinned to the pre-S2B schema, so
  its before-picture is unchanged.)_
- **GAP-6** — no idempotency on client-supplied action ids; a reused id
  overwrites rather than deduplicates (`C2-11`). _Remediated under the evaluated
  bound arms — intervention **I6**
  (`research/sif-bench/interventions/i6/I6_RESULTS.md`): server-issued action
  identity + a caller idempotency key + a canonical request digest prevent silent
  overwrite, duplicate creation and duplicate execution; I6-C rejects
  same-key/different-request conflicts. Effectively-once within the evaluated
  single-instance domain and failure model, not distributed exactly-once._

Held under the tested interleavings (bounded, seed `0xC0FFEE`, ≤ 2 workers):
post-revocation disclosure 0, human-gate bypass 0, cross-tenant observation 0,
duplicate execution 0, chain-fork 0, append-only enforced. See
`research/sif-bench/concurrency/CONCURRENCY_BASELINE.md`.

## Phase 3 S1+S2 — trusted database-context boundary (wired into public RLS by S2B)

Migration `0003_identity.sql` introduces the identity/membership/session schema and a
SECURITY DEFINER context boundary that hardens the direction of GAP-5 (app-cooperative
`app.current_tenant`) into a **database privilege-layer** control. At S1+S2 this was
verified on the demonstration table `continuum.context_probe` only. **S2B (migration
`0004`) has since rewired the production `public.*` tenant isolation onto
`continuum.current_tenant()`** (membership-pinned), so the control below now protects
the real data plane and GAP-5 is closed on it under the application-role model — see
the GAP-5 note above and `docs/S2B_PUBLIC_DATA_PLANE_MIGRATION.md`.

| Threat / misuse | Control (S1+S2) | Verified by |
|-----------------|-----------------|-------------|
| App chooses a foreign tenant | The context function takes **no tenant input**; tenant is derived from a revalidated membership | `identity-context.test.ts` — "there is no way to pass a tenant" |
| App selects another principal's membership | `requested_membership` must be owned by the principal, else deny | "membership hint only selects among the principal's OWN active memberships" |
| Ambiguous multi-tenant principal silently gets a tenant | Multiple active memberships without explicit selection → deny (never a default pick) | "ambiguous multi-tenant membership denies without explicit selection" |
| Revoked membership still grants access | Active-and-current membership required (`status`, `revoked_at`, validity window) | "revoked membership denies" |
| Suspended/deleted principal establishes context | Principal must be `active` with no suspend/delete timestamp | "suspended principal denies" |
| Expired/foreign/revoked session establishes context | Session must be active, belong to the principal, and be within idle+absolute expiry; identity-version must match | "expired session denies", "session that belongs to a different principal denies" |
| Forged `app.current_tenant` GUC creates authority (GAP-5 direction) | `current_tenant()` returns `NULL` unless a backing active session **and** active membership exist for the triple; RLS then shows nothing | "a forged app.current_tenant GUC creates NO authority" |
| Context leaks across pooled connection reuse | Context is transaction-local (`set_config(..., is_local => true)`); gone at COMMIT/ROLLBACK | "context is transaction-local … does not survive across pooled reuse" |
| App tampers with identity/membership mappings | App role holds no table privileges on identity tables; SELECT/INSERT/UPDATE/DELETE all denied | "the app role cannot read or mutate the identity/membership tables directly" |

Non-goals restated for honesty: the database never verifies OIDC/JWT tokens (identity
validation and DB mapping are distinct layers); SECURITY DEFINER runs as the narrow
non-login `continuum_authctx`, never superuser; and a database superuser still bypasses
RLS by design (key-custody/roadmap answer, unchanged). See
`docs/PHASE3_S1_S2_MIGRATION.md` and `docs/PHASE3_AUTH_SPEC.md`.

## Phase 3 S3 — identity-verification & session boundary (vendor-neutral)

The S3 boundary converts an externally verified identity assertion into a normalized
internal identity and a restart-safe, revocable session, WITHOUT granting tenant
authority from untrusted claims. Four layers stay distinct: verifier → normalized
`VerifiedIdentity` → principal mapping (issuer+subject → principal) → session →
(later) S2B trusted DB context. No layer accepts an authoritative tenant from the
caller. This milestone ships the deterministic (dev/test-only) verifier and the
PostgreSQL session layer; a real verifier, browser flow, and provider SDK are later
steps.

**Claim-layer separation (do not conflate).** These are three distinct authority
claims and none implies the next:

- Identity-assertion verification → establishes a normalized *external identity*.
- Session validation → establishes an authenticated *internal principal*.
- Trusted membership resolution → establishes *tenant authority*.

A valid identity or a valid session never implies tenant membership by itself. S2B
(`continuum.current_tenant()` from an active owned membership) remains the sole
authority transition into the transaction-local tenant context.

| Threat / misuse | Control (S3) | Verified by |
|-----------------|--------------|-------------|
| Forged/altered credential accepted | signature check + shared normalization; 15 distinct failure classes, never collapsed to success | `verifier.test.ts` |
| Wrong recipient (audience confusion) | audience must intersect the issuer's allowed audiences | `verifier.test.ts` "wrong audience denies" |
| Algorithm confusion (trusting header alg) | alg must be in BOTH the global and issuer allowlist; key alg must match | `verifier.test.ts` "unsupported algorithm" |
| Expired / premature / future-dated / over-age credential | temporal enforcement with bounded clock skew + max credential age | `verifier.test.ts` |
| Unavailable / stale / unknown verification keys | key provider models availability + staleness + kid; fail closed | `verifier.test.ts`, config |
| Credential replay (deterministic verifier) | single-use credential-id guard, **process-local and test-scoped only** (see limitation below) | `verifier.test.ts` "replay denies" |
| Subject collision across issuers | stable key is (issuer, subject) — never subject/email/username alone | `verifier.test.ts` "subject unique within issuer" |
| Unmapped / disabled / revoked external identity | deny-by-default mapping; no implicit enrolment | `s3-session.test.ts` mapping denials |
| Suspended/deleted principal authenticates | principal-state check at mapping and at each validation | `s3-session.test.ts` |
| Stolen session-store dump replayed | only a KEYED, session-id-bound digest is stored; raw credential never persisted | `s3-session.test.ts` "stored only as digest", `session-digest.test.ts` |
| Session fixation / non-expiring session | atomic rotation (never both active), idle + absolute expiry, rotation preserves absolute lifetime | `s3-session.test.ts` rotation/expiry |
| Identity/privilege change with a live session | identity-version and mapping-version staleness deny on the next transaction | `s3-session.test.ts` |
| Session grants a tenant directly | the session role has NO tenant_memberships / public.* / begin_authenticated_context access; a validated session carries no tenant | `s3-session.test.ts` "no tenant-authority path" |
| Secrets in the audit trail | auth events are digests + non-secret ids only; raw credentials/claims/secrets never written | `s3-session.test.ts` "no raw credential in the stream" |
| Silent unauthenticated fallback | explicit fail-closed config: production refuses the deterministic verifier and requires postgres session persistence + digest keys | `config.test.ts` |

**Fail-closed matrix (S3).** Deny when: verification keys or policy unavailable;
identity mapping unavailable; session store unavailable; digest key version
unavailable; principal state unresolved; identity/mapping version unconfirmed;
revocation state unconfirmed. There is no in-memory session fallback.

**Deterministic replay limitation (S3).** Credential replay detection in the
deterministic verifier is process-local and test-scoped. It is not restart-safe or
distributed and is not a production replay defence. S3 is NOT described as providing
durable external-assertion replay prevention: the durable guarantees in this system
apply to sessions and the previously implemented proof-consumption ledger, not to
external authentication assertions. Durable/shared nonce-replay handling is deferred
to the real verifier milestone.

**Non-goals (S3).** No real OIDC provider, remote JWKS fetch, browser redirect,
authorization-code exchange, PKCE, cookies, CSRF, refresh tokens, workload identity,
or break-glass. The deterministic verifier is dev/test only and is refused in
production. Tenant authority remains the S2B trusted-context path.
