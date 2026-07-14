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
  expiry **are** enforced.
- **GAP-4** — a captured proof-of-possession `(challenge, signature)` is
  replayable within the TTL; challenge freshness/single-use is not enforced
  (`C1-10`).
- **GAP-5** — RLS isolation is app-cooperative: the `continuum_app` role may
  re-key `app.current_tenant` mid-transaction via `set_config`; nothing at the DB
  privilege layer prevents it (`C3-06`).
- **GAP-6** — no idempotency on client-supplied action ids; a reused id
  overwrites rather than deduplicates (`C2-11`).

Held under the tested interleavings (bounded, seed `0xC0FFEE`, ≤ 2 workers):
post-revocation disclosure 0, human-gate bypass 0, cross-tenant observation 0,
duplicate execution 0, chain-fork 0, append-only enforced. See
`research/sif-bench/concurrency/CONCURRENCY_BASELINE.md`.
