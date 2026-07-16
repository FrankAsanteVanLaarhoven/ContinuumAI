# Phase 3 S2B — Public data-plane trusted-context migration

Migrates the real `public.*` data plane off the application-cooperative
`app.current_tenant` GUC and onto privilege-unforgeable tenant context derived
from the trusted principal/session/membership function (`0003`). This closes the
authority split left after S1+S2, where only the demonstration `context_probe`
table was protected by trusted context while the production tables still trusted a
GUC the application role sets itself (GAP-5).

## Bounded result (the claim this milestone supports)

> Within the tested application-role model, the real public data-plane paths —
> intents, capabilities, consent/revocation, memory metadata and disclosure,
> actions and approvals, consumed proofs, evidence and idempotency records —
> derive tenant authority from revalidated principal, session and membership
> state. Caller-controlled tenant GUCs do not create access.

It does **not** claim resistance to: database superusers; compromise of the
trusted-function owner (`continuum_authctx`); malicious migration owners; OS
compromise; a database administrator; or arbitrary SQL executed under a
privileged role. Those remain documented non-goals (see Residual boundaries).

## 1. Migrations changed

- **`migrations/0004_public_trusted_context.sql`** (new):
  - `CREATE OR REPLACE continuum.current_tenant()` — strengthened to bind the RLS
    predicate to the ACTIVE principal and the EXACT owned active membership, not
    merely "some membership for (principal, tenant)".
  - Rewires all 13 tenant-scoped policies to `tenant_id = continuum.current_tenant()`.
- **`src/migrate.ts`** — appends `0004` to `MIGRATIONS`; adds an optional `through`
  parameter so a caller can pin the schema to a specific version (used to hold the
  frozen concurrency baseline at the pre-S2B RLS).

## 2. Exact RLS policy changes

Before (`0001`/`0002`), for each of `tenants`, `principals`, `memory_objects`,
`consent`, `intents`, `capabilities`, `revocations`, `action_proposals`,
`action_transitions`, `approvals`, `evidence_envelopes`, `events`,
`consumed_proofs`:

```sql
USING      (tenant_id = current_setting('app.current_tenant', true))
WITH CHECK (tenant_id = current_setting('app.current_tenant', true))
```

After (`0004`), same 13 policies (names and ENABLE/FORCE unchanged — drop-in
replacement, no second overlapping policy):

```sql
USING      (tenant_id = continuum.current_tenant())
WITH CHECK (tenant_id = continuum.current_tenant())
```

`continuum.current_tenant()` (SECURITY DEFINER, owner `continuum_authctx`, fixed
`search_path`) returns the tenant **only** when the transaction-local
`(app.current_principal, app.current_session, app.current_membership,
app.current_tenant)` correspond to: an active, non-expired session owned by the
principal; an active (non-suspended, non-deleted) principal; and the exact,
owned, active membership whose `tenant_id` equals `app.current_tenant`. Otherwise
it returns `NULL`, the predicate is false, and the table is invisible/unwritable.

## 3. Runtime transactions rewired

`packages/continuum-persistence`:

- **`pg.ts`** — added `withTrustedContext(pool, ref, fn)`: opens a transaction and
  establishes context via `continuum.begin_authenticated_context(principal,
  session, request, membership?)`, which validates and DERIVES the tenant, then
  runs `fn` under RLS. Added `provisionTrustedIdentity(admin, …)` (admin bootstrap
  for a service/operator identity). `withTenant` (raw GUC) is retained ONLY as the
  adversary path in tests and for non-RLS global probes.
- **`repository.ts`** — `persistExport` takes a `RefResolver`; `loadEvidence`,
  `verifyPersistedChain`, `countRows` take a `TrustedContextRef`. All writes/reads
  run through `withTrustedContext`.
- **`postgres-store.ts`** — `transaction()` and every tenant-scoped read
  (`listEvidence`, `verifyEvidenceChain`, `getMetrics`, `listAuthorizedMemory`)
  establish trusted context via `withTrustedContext(refFromCtx(ctx))`;
  `transaction()` additionally asserts the DB-derived tenant matches the request
  context. `resolveExecutionContext` maps an authenticated subject to its
  provisioned identity and DERIVES the tenant from the database (never a caller
  value); the `trustedSubjects` map now carries `{principalId, sessionId,
  membershipId?}` with **no tenant**.

`apps/console/lib/runtime.ts` — the operator identity comes from the deployment
environment as `{principalId, sessionId, membershipId?}`; the tenant is derived by
the database. Absent identity ⇒ empty trusted map ⇒ `resolveExecutionContext`
fails closed. The console never selects a tenant.

## 4. Trusted-context establishment path

```
authenticated subject
  → resolveExecutionContext (maps subject → provisioned principal/session)
  → begin_authenticated_context(principal, session, request, membership?)   [SECURITY DEFINER]
      · principal active · session active & owned · identity_version matches
      · membership resolved (ambiguity denies; hint only selects an OWNED membership)
      · sets 5 transaction-local GUCs; RETURNS derived (principal, tenant, membership)
  → public.* RLS evaluates continuum.current_tenant() per statement
  → COMMIT / ROLLBACK ⇒ transaction-local context disappears
```

## 5. How forged GUC authority was neutralized

`continuum.current_tenant()` never trusts `app.current_tenant` on its own — it
re-derives authority from authoritative identity rows. A raw
`set_config('app.current_tenant', 't_acme')` (or setting all four GUCs to
fabricated values) has no backing active session/membership, so the function
returns `NULL` and nothing is visible or insertable. The application role cannot
write the identity tables and cannot guess an unowned membership uuid, so it
cannot manufacture a valid `(principal, session, membership)` triple it does not
already legitimately hold. Membership-pinning additionally means re-keying only
the tenant GUC (without re-establishing membership) yields `NULL` — tenant
switching requires presenting another owned active membership.

## 6. Privilege audit (`src/privilege-audit.test.ts`)

`continuum_app` has, from the catalog: `rolsuper=false`, `rolbypassrls=false`,
`rolcreaterole=false`, `rolcreatedb=false`; no `CREATE` on `continuum` or
`public`; it does not own the trusted functions (owner `continuum_authctx`, which
is `NOLOGIN`, non-superuser); no `SELECT/INSERT/UPDATE/DELETE` on any identity or
membership table (`principals`, `external_identities`, `tenant_memberships`,
`authenticated_sessions`, `delegations`, `break_glass_grants`); only `EXECUTE` on
the two trusted functions; and on `public.*` only `SELECT`/`INSERT` (never
`UPDATE`/`DELETE`). Its sole path to tenant authority is presenting a real
identity triple to `begin_authenticated_context`.

## 7. Tests (`src/public-trusted-context.test.ts`, real embedded PostgreSQL)

Forged tenant GUC reads nothing from any tenant-scoped table and cannot mutate
intents / memory / evidence / consumed_proofs / action_proposals; missing context
denies; a valid session+membership permit only the derived tenant; foreign
membership selection denies; membership revocation, session revocation and
principal suspension each deny on the next transaction; tenant switching requires
another owned active membership (re-keying the GUC bleeds nothing); pooled reuse
retains no authority; rollback clears context; the async runtime paths establish
trusted context and derive the tenant (and cannot resolve an unprovisioned
subject); restart persistence is intact; and a raw authority-setting call creates
no access.

## 8. Frozen results preserved

Core 91 · persistence 79 (54 prior + 25 S2B) · console 7 · concurrency 9 ·
stage-a 6 · stage-b 7 · i1 6 · i2 8 · i3 6 · i4 6 · i5 7 · i6 22 · i7 8 ·
comparative:validate 44 · typecheck clean. The concurrency baseline (the frozen
before-picture that REPRODUCES GAP-5 via the app-cooperative re-key, C3-06) is
pinned to the pre-S2B schema (`migrate(cfg, "0003_identity.sql")`) so 0004 does not
alter what it measures. The I1–I7 harnesses do not use the persistence migrations
and are unaffected.

## Migration-order (intervention versioning, not test inconsistency)

The two migrations are distinct evidence points and must stay that way:

```text
0003_identity.sql
  Historical trusted-context foundation and frozen GAP-5 reproduction boundary.

0004_public_trusted_context.sql
  Real public data-plane trusted-context intervention (this milestone).
```

The frozen concurrency suite **intentionally stops at `0003`** — it calls
`migrate(cfg, "0003_identity.sql")` so it keeps reproducing the historical
app-cooperative GAP-5 fixture (C3-06) exactly. The new S2B tests migrate **through
`0004`** and assert the closed behaviour. Two suites therefore run against two
schema versions on purpose: this is before/after intervention versioning, not a
test inconsistency, and it preserves the causal evidence rather than rewriting it.

## 9. Schema compatibility

`0004` is a policy/one-function replacement — no table shape changes, no dropped
columns, no data migration. `begin_authenticated_context` sets `app.current_tenant`
among its GUCs, so a trusted-context seed is admitted by BOTH the pre-0004 and
post-0004 policies (this is why the frozen concurrency suite still seeds cleanly
while pinned to 0003). Superuser (migration) access is unchanged.

## 10. Performance

Each tenant-scoped statement now evaluates `continuum.current_tenant()`, which
runs up to three indexed single-row lookups (session, principal, membership). Each
transaction adds one `begin_authenticated_context` round-trip at establishment. No
measurable change in the suites (persistence 79 in ~4.4s; runtime/RLS gates
unchanged). No load benchmark was run; that is noted, not claimed.

**`STABLE` is NOT an authorization cache.** `continuum.current_tenant()` is marked
`STABLE`, which only guarantees consistency **within a single SQL statement** — it
does not freeze the result across statements or across a transaction, and no
security decision depends on such reuse. Each new statement re-evaluates authority
(so membership/session/principal changes visible under the transaction's isolation
level take effect on the next statement), and each new transaction re-establishes
and re-validates context via `begin_authenticated_context`. This is exactly what
makes revocation and suspension effective on the next transaction. Security-
sensitive multi-statement flows therefore either run within one explicit
transaction at the intended isolation level, or re-establish trusted context per
transaction — never rely on a cached cross-statement/cross-transaction verdict.

## 11. Residual privileged-role boundaries (unchanged non-goals)

A database **superuser** bypasses RLS by design (migrations run as superuser;
key-custody/HSM is the roadmap answer). The trusted-function **owner**
(`continuum_authctx`) is a narrow `NOLOGIN` non-superuser role; compromising it, a
malicious migration owner, OS compromise, a DBA, or arbitrary SQL under a
privileged role are out of scope. Session issuance/rotation and OIDC verification
are later, separately-reviewed steps (S3+): this milestone protects the
authorization path given an identity, not the authentication that mints it.

## 12. Supported vs unsupported claims

**Supported:** the bounded result in §Bounded result — caller-controlled tenant
GUCs create no access on the real public data plane, under the application-role
model, with membership/session/principal state re-validated each transaction.

**Not supported:** protection against superuser/owner/DBA/OS/arbitrary-privileged
SQL; end-to-end authenticated identity (still S3+); and any performance guarantee
beyond "no regression in the test suites".
