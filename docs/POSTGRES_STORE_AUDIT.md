# PostgresStore Schema-Capability Audit (Phase 2, increment 2)

```
Status:   EVIDENCE + BOUNDED IMPLEMENTATION — held for review
Purpose:  Determine which async ContinuumStore operations the EXISTING schema +
          EXISTING exported primitives support WITHOUT new schema, and which
          require reviewed additions. No new schema is added.
Baseline: migrations/0001_init.sql, packages/continuum-persistence/src/{pg,repository}.ts,
          packages/continuum-core/src/async/*
```

## What the existing data plane provides

`migrations/0001_init.sql` defines: `platform_key` (PUBLIC key only), `policies`, and the
tenant-scoped `tenants`, `principals`, `memory_objects`, `consent`, `intents`,
`capabilities`, `revocations`, `action_proposals`, `action_transitions`, `approvals`,
`evidence_envelopes`, `events`. RLS is `ENABLE`+`FORCE` on every tenant table, keyed on
`current_setting('app.current_tenant', true)`, `WITH CHECK` on writes, fail-closed when the
setting is absent. The app role `continuum_app` is `NOSUPERUSER`, `SELECT`+`INSERT` only;
`evidence_envelopes`/`events` are append-only via a `deny_mutation()` trigger.
`repository.ts` already ships `persistExport`, `loadEvidence`, `loadPlatformKey`,
`verifyPersistedChain`, `countRows`.

## Operation-by-operation capability

| Async op | Existing schema? | Verdict |
|---|---|---|
| `transaction` (shared tenant-scoped txn) | `withTenant` BEGIN/`set_config`/COMMIT | **Supported** |
| `resolveExecutionContext` (subject→principal→tenant) | principals keyed `(tenant_id, principal_id)`; no tenant-agnostic reverse lookup | **Injected map** (see GAP-1) |
| `getIntent` / `listAuthorizedMemory` | `intents` / `memory_objects` under RLS | **Supported** (metadata projection: content withheld) |
| `revokeCapability` | INSERT into `revocations` (append) | **Supported** |
| `verifyEvidenceChain` / `listEvidence` | `loadEvidence` + `verifyEnvelopeChain` | **Supported** (reuses `verifyPersistedChain`) |
| `health` | reachability + RLS-fail-closed + append-only role probes | **Supported** |
| `getMetrics` (full `MetricsSnapshot`) | requires cross-table aggregation not yet built | **Held** (bounded/deferred) |
| `authorizeIntent` (decide + issue + **append evidence**) | reads supported; **evidence append is not restart-safe** (see GAP-4) | **Held** |
| `discloseForToken` (PoP + **replay** + freshness) | verify supported; **no consumed-nonce ledger** | **Held** (see GAP-2) |
| `submitIntent` (write) | INSERT into `intents` | Supported mechanically, but gated behind the write path held below |
| action lifecycle (transition/approve/consume) | `action_*` tables exist; state cannot mutate (INSERT-only) | **Held** (see GAP-3) |

## Unavoidable adapter gaps — DOCUMENTED, NOT added (held for separate review)

Per the Phase 2 rule ("no new database schema unless an unavoidable adapter gap is
separately documented and reviewed"), the write/decision path is **not** implemented against
Postgres in this increment. It requires:

- **GAP-1 (trusted tenant derivation, reviewer §3).** The current mechanism has the
  application call `set_config('app.current_tenant', …)` — app-cooperative (this is
  concurrency-baseline **GAP-5**). Closing it needs a `SECURITY DEFINER`
  `continuum_begin_request_context(principal, session)` plus a principal/session→tenant
  mapping the app cannot forge. **New schema + function.** Until then, `resolveExecutionContext`
  uses an injected trusted map and the tenant is taken from the (boundary-derived)
  RequestContext — better than client-passed, still app-cooperative at the DB layer.
- **GAP-2 (PoP replay ledger, reviewer §5).** `discloseForToken` needs a consumed-nonce
  table to make proof replay durable across processes (concurrency-baseline **GAP-4**).
  **New schema.**
- **GAP-3 (action idempotency + state machine).** `action_proposals.state` cannot mutate
  under the INSERT-only role; a durable action lifecycle needs the append-only transition log
  as authoritative state and an idempotency/claim key (concurrency-baseline **GAP-6**).
  **New schema/semantics.**
- **GAP-4 (persisted-continuation evidence ledger).** `EvidenceLedger` (core) is in-memory
  only: `append` derives `seq`/`prev_hash` from a private in-process array. A restart-safe
  Postgres write path must continue the chain from the last persisted envelope. This needs a
  reviewed core addition (a loadable/continuation ledger, or exported envelope hash/sign
  primitives). **Core capability addition.**

## What this increment implements (no new schema, no core change)

`packages/continuum-persistence/src/postgres-store.ts` — `PostgresStore implements
ContinuumStore` for the **read / verify / revoke / durability / health** flows over the
existing schema, tenant taken from the RequestContext, reusing `withTenant` and the existing
repository verifiers. The write/decision transaction methods (`submitIntent`,
`authorizeIntent`, `discloseForToken`) throw an explicit, documented
"pending review — see POSTGRES_STORE_AUDIT.md GAP-1..4" error rather than a silent stub or a
schema shortcut. `postgres-store.test.ts` proves, through the async boundary on real embedded
PostgreSQL: tenant-scoped reads under RLS, foreign-tenant invisibility, evidence-chain
verification, durability across a fresh pool (restart), and revocation persistence.

## Decision requested

Approve the four additions above (schema + core-capability) so increment 2b can implement the
restart-safe write/decision path and wire the console. Until approved, the write path stays
held and the console remains on the in-memory research adapter.
