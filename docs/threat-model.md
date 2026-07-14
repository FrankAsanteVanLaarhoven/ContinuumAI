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
| Cross-tenant access | hard tenant-isolation gate above policy | `slice.test.ts`, `crossTenantProbe` |
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

Side-channel leakage, endpoint capture, malicious platform administrator,
persistence-tier compromise, denial-of-wallet on real model providers,
supply-chain compromise of dependencies, and semantic leakage through model
outputs. These require the production tiers (KMS/HSM, TEE attestation, model
gateway, DLP) on the roadmap and are named here so the boundary is honest.

## Residual risk

The v0.1 store is in-memory and single-process. Guarantees hold only under the
assumptions above. The model-gateway injection screening is **pattern-based and
heuristic** — it raises cost and catches known patterns; it is not a complete
defence against adversarially-crafted injection, and the model itself is
simulated. See `docs/CLAIMS.md`.
