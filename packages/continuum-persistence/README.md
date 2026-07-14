# @continuum/persistence

Durable data plane for Continuum. Converts the in-memory reference store into a
restart-safe, tenant-isolated, auditable PostgreSQL platform suitable for
SIF-Bench evaluation.

## Isolation mechanism

Tenant isolation is enforced by **PostgreSQL Row-Level Security**, not
application-side filtering:

- Every tenant-scoped table `ENABLE`s **and** `FORCE`s RLS (so even the table
  owner is subject to it).
- The policy is `tenant_id = current_setting('app.current_tenant', true)` for
  both `USING` (reads) and `WITH CHECK` (writes).
- The application connects as `continuum_app` — **NOSUPERUSER**, granted only
  `SELECT` and `INSERT` (never `UPDATE`/`DELETE`). Superusers bypass RLS, so the
  app must never connect as one.
- `withTenant(pool, tenantId, fn)` opens a transaction and sets the
  transaction-local `app.current_tenant`. Absent that setting,
  `current_setting(..., true)` is NULL and the table exposes nothing — the
  system **fails closed**.
- A forged `tenant_id` on write is rejected by the policy's `WITH CHECK`.
- The evidence stream is **append-only**: an `INSERT`-only grant plus a
  `BEFORE UPDATE OR DELETE` trigger that raises.

## Durability

Persisted evidence envelopes carry their hash-chain links and Ed25519
signatures. `verifyPersistedChain` reloads them over a fresh connection and
re-verifies the chain independently of any in-process ledger — so tamper and
loss are detectable after a restart or restore.

## Tests

Run against a **real** embedded PostgreSQL (no external service required):

```bash
npm run test -w @continuum/persistence
```

- `isolation.test.ts` — cross-tenant read/write, missing-context fail-closed,
  forged-`tenant_id` rejection, evidence isolation, append-only, least privilege.
- `durability.test.ts` — chain re-verification over a fresh connection,
  per-step evidence completeness, ordering, capability/revocation/action
  durability, idempotent migration.
- `backup_restore.test.ts` — restore into a fresh database reproduces the
  evidence digest and a valid chain.

## Scope

The store is a real Postgres tier, but the platform signing key is still
generated in-process (HSM/KMS is on the roadmap) and a database superuser
bypasses RLS. See `docs/CLAIMS.md` and `docs/threat-model.md`.
