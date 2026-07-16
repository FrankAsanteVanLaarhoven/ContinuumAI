# Phase 3 S1+S2 — Identity schema & trusted database-context boundary

**Milestone scope.** Migration `0003_identity.sql` plus the trusted-context test
suite (`packages/continuum-persistence/src/identity-context.test.ts`). This is the
authentication **data layer** and the SECURITY DEFINER **trust boundary** only. It
does **not** implement OIDC verification, session middleware, a provider SDK, a
browser login flow, or deployment configuration — those are later, separately
reviewed steps (S3–S8). It is **not yet wired into the existing public data-plane
RLS**; rewiring `public.*` tenant isolation onto the verified context is the next
milestone — **S2B (Public data-plane trusted-context migration)**. Until then the
demonstration table `continuum.context_probe`
is the only object whose RLS derives from the verified context.

## What the migration creates

Applied by the superuser through `migrate.ts` (the app role never runs DDL), inside
one atomic transaction, reproducible from an empty database.

| Object | Purpose |
|--------|---------|
| Role `continuum_authctx` (`NOLOGIN NOSUPERUSER`) | Dedicated non-login owner of the trusted functions. SECURITY DEFINER runs with **this** role's privileges — deliberately narrow, never superuser. |
| Schema `continuum` (owner `postgres`) | Global identity plane, distinct from the tenant-scoped `public.*` slice. |
| `continuum.principals` | Identity subjects (`active`/`suspended`/`deleted`, `version` for identity-version binding). |
| `continuum.external_identities` | External identity keyed by the `(issuer, subject)` **pair** — never subject alone. |
| `continuum.tenant_memberships` | Principal → tenant grants (`active`/`suspended`/`revoked`, validity window). Logical `tenant_id` reference to `public.tenants` (no hard FK so the identity plane is independently testable/migratable). |
| `continuum.authenticated_sessions` | Sessions storing a credential **digest** (never raw bearer material), idle + absolute expiry, `identity_version`. |
| `continuum.delegations`, `continuum.break_glass_grants` | Schema only in this milestone (behaviour in later delegation / break-glass steps). |
| `continuum.current_tenant()` | SECURITY DEFINER RLS helper. Returns the effective tenant **only** when the transaction-local `(principal, session, tenant)` triple corresponds to an active session for that principal **and** an active membership for `(principal, tenant)`. A raw `set_config` with no backing session/membership yields `NULL`. |
| `continuum.begin_authenticated_context(principal, session, request, requested_membership?)` | The narrow trusted boundary. Input is identity/session references **only** — never an authoritative tenant. Validates principal/session/identity-version, **derives** the tenant from a revalidated membership (ambiguity → deny; `requested_membership` may **select** among the principal's own active memberships, never **grant** one), sets five transaction-local GUCs, returns non-sensitive derived metadata. |
| `continuum.context_probe` + RLS policy | Demonstration table whose visibility is `tenant_id = continuum.current_tenant()`, proving a forged GUC yields no authority. |

## Privilege model (least privilege)

- Function owner is `continuum_authctx`, **not** the app role and **not** a superuser.
- `PUBLIC` execution is revoked on both functions; `search_path` is pinned to
  `pg_catalog, continuum`.
- `continuum_app` receives **only**: `USAGE` on schema `continuum`, `EXECUTE` on the
  two functions, and `SELECT` on `context_probe`.
- `continuum_app` holds **no** `SELECT/INSERT/UPDATE/DELETE` on any identity or
  membership table. It can neither read nor mutate membership mappings; it reaches
  identity state only through the trusted functions.

## Forward migration

```
CONTINUUM_DB=<host:port/db> npm -w @continuum/persistence run migrate   # or migrate(cfg)
```

`MIGRATIONS = ["0001_init.sql", "0002_runtime.sql", "0003_identity.sql"]`, each in its
own transaction. `0003` is **idempotent / re-runnable**: `CREATE ROLE` is guarded by a
`pg_roles` existence check, tables use `CREATE TABLE IF NOT EXISTS`, functions use
`CREATE OR REPLACE`, and the policy is `DROP POLICY IF EXISTS` then `CREATE`. Note that
roles are **cluster-global**: `continuum_authctx` is created once per cluster and reused
across databases; the guard makes a second migration on another database in the same
cluster a no-op for the role.

## Rollback

The migration is additive and not yet load-bearing for `public.*` isolation, so
rollback is low-risk. To reverse `0003` on a database (as superuser), drop in reverse
dependency order:

```sql
DROP TABLE IF EXISTS continuum.context_probe;
DROP FUNCTION IF EXISTS continuum.begin_authenticated_context(uuid, uuid, uuid, uuid);
DROP FUNCTION IF EXISTS continuum.current_tenant();
DROP TABLE IF EXISTS continuum.break_glass_grants;
DROP TABLE IF EXISTS continuum.delegations;
DROP TABLE IF EXISTS continuum.authenticated_sessions;
DROP TABLE IF EXISTS continuum.tenant_memberships;
DROP TABLE IF EXISTS continuum.external_identities;
DROP TABLE IF EXISTS continuum.principals;
DROP SCHEMA IF EXISTS continuum;         -- only if no other objects remain
-- Role removal is optional and cluster-scoped; only when no database uses it:
-- REVOKE ALL ON SCHEMA continuum FROM continuum_authctx;  DROP ROLE IF EXISTS continuum_authctx;
```

Because `tenant_id` in the identity tables is a **logical** reference (no hard FK to
`public.tenants`), dropping `continuum` does not cascade into or corrupt the existing
data plane. The `continuum_app` role and the `public.*` schema are untouched by both
the forward migration's grants and this rollback.

## Preconditions & non-goals

- **Preconditions:** `0001_init.sql` (creates `continuum_app`, `public.tenants`) and
  `0002_runtime.sql` applied first; a superuser connection for DDL.
- **Non-goals this milestone:** OIDC/JWT verification (the DB never verifies tokens —
  identity validation and DB mapping are distinct layers), session issuance/rotation
  middleware, provider SDK, browser login, deployment config, and rewiring `public.*`
  RLS onto `current_tenant()`.

## Verification

`identity-context.test.ts` provisions identity data as the superuser and exercises the
boundary **as the app role**, proving: tenant is derived (no tenant input exists); a
membership hint only selects among the principal's own active memberships; foreign
membership, revoked membership, suspended principal, expired session and mismatched
session→principal all deny; ambiguous multi-tenant membership denies without explicit
selection; a forged `app.current_tenant` GUC yields no authority; context is
transaction-local (gone after commit/rollback, not retained across pooled reuse); and
the app role can neither read nor mutate the identity/membership tables.
