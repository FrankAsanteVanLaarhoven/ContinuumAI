# SIF-Bench concurrency — case catalog

Generated from `reports/concurrency.json` (seed 0xC0FFEE). One deterministic
schedule per case. `observed` is the baseline measurement of the UNMODIFIED system.
See `CONCURRENCY_BASELINE.md` for the narrative and bounded claims.

## C1 — Authorization & scope

| Case | Expected | Observed | Failure class | Workers |
|------|----------|----------|---------------|---------|
| C1-01-intent-scope-change-during-eval | held | **not_realizable** | not_applicable | 1 |
| C1-02-policy-ceiling-change-after-permit | held | **gap** | stale_permit_acceptance | 2 |
| C1-03-consent-revoked-after-selection | held | **gap** | stale_permit_acceptance | 2 |
| C1-04-purpose-mutation-after-issuance | held | **held** | none | 2 |
| C1-05-use-after-policy-version-change | held | **gap** | policy_version_mismatch | 2 |
| C1-06-two-concurrent-scope-escalations | held | **gap** | scope_escalation | 2 |
| C1-07-use-races-revocation-commit | held | **held** | none | 2 |
| C1-08-expiry-during-gateway-execution | held | **held** | none | 1 |
| C1-09-replay-two-workers | held | **held** | none | 2 |
| C1-10-pop-replay-simultaneous | held | **gap** | pop_replay | 2 |
| C1-11-stale-context-after-object-revocation | held | **gap** | stale_permit_acceptance | 2 |
| C1-12-requested-tenant-changed | held | **held** | none | 2 |

## C2 — Human-gate & action

| Case | Expected | Observed | Failure class | Workers |
|------|----------|----------|---------------|---------|
| C2-01-approval-races-withdrawal | held | **not_realizable** | not_applicable | 1 |
| C2-02-approval-races-capability-revocation | held | **held** | none | 2 |
| C2-03-duplicate-approvals-concurrent | held | **held** | none | 2 |
| C2-04-approval-expires-during-execution | held | **not_realizable** | not_applicable | 1 |
| C2-05-two-workers-consume-same-action | held | **held** | none | 2 |
| C2-06-approve-v1-execute-v2 | held | **gap** | policy_version_mismatch | 2 |
| C2-07-valid-vs-foreign-tenant-approval | held | **held** | none | 2 |
| C2-08-approval-races-explicit-denial | held | **held** | none | 2 |
| C2-09-execution-races-quarantine | held | **not_realizable** | not_applicable | 1 |
| C2-10-compensation-races-execution | held | **not_realizable** | not_applicable | 1 |
| C2-11-idempotency-key-reused | held | **gap** | idempotency_reuse | 2 |
| C2-12-state-transition-skips | held | **held** | none | 1 |

## C3 — Database & tenant-context

| Case | Expected | Observed | Failure class | Workers |
|------|----------|----------|---------------|---------|
| C3-01-pooled-reuse-different-tenant | held | **held** | none | 1 |
| C3-02-session-var-persists | held | **held** | none | 1 |
| C3-03-failed-tx-stale-context | held | **held** | none | 1 |
| C3-04-concurrent-cross-enumeration | held | **held** | none | 2 |
| C3-05-rollback-then-reuse | held | **held** | none | 1 |
| C3-06-rekey-mid-transaction | held | **gap** | rls_bypass | 1 |
| C3-07-caller-tenant-mismatch | held | **held** | none | 1 |
| C3-08-durable-inmemory-divergence | held | **gap** | durable_inmemory_divergence | 2 |
| C3-09-superuser-bypasses-rls | held | **held** | none | 1 |
| C3-10-append-only-update-delete | held | **held** | none | 1 |
| C3-11-same-object-id-across-tenants | held | **held** | none | 1 |
| C3-12-read-during-write | held | **held** | none | 2 |

## C4 — Evidence & event-chain

| Case | Expected | Observed | Failure class | Workers |
|------|----------|----------|---------------|---------|
| C4-08-event-ordering-vs-state | held | **held** | none | 1 |
| C4-11-verify-during-append | held | **held** | none | 2 |
| C4-02-action-succeeds-evidence-fails | held | **not_realizable** | not_applicable | 1 |
| C4-03-evidence-for-rolled-back-action | held | **not_realizable** | not_applicable | 1 |
| C4-05-two-chain-appends-compete | held | **not_realizable** | not_applicable | 1 |
| C4-06-revocation-evidence-delayed | held | **not_realizable** | not_applicable | 1 |
| C4-09-restore-during-append | held | **not_realizable** | not_applicable | 1 |
| C4-10-signature-races-key-rotation | held | **not_realizable** | not_applicable | 1 |
| C4-12-partial-tx-orphan | held | **not_realizable** | not_applicable | 1 |
| C4-04-concurrent-duplicate-seq | held | **held** | none | 2 |
| C4-07-duplicate-event-id | held | **held** | none | 1 |
| C4-01-append-races-rollback | held | **held** | none | 1 |

