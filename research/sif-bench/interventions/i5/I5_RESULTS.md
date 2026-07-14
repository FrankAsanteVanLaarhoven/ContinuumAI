# Intervention I5 — database-bound tenant identity (matched-arm result)

I5 eliminated the observed **GAP-5** cooperative re-key — PostgreSQL RLS keys on the
transaction-local GUC `app.current_tenant`, which the application role can set to any
value, so the database faithfully enforces a **caller-chosen** tenant — in a bounded
deterministic matched experiment over a real embedded PostgreSQL. I5 is an **isolated
workspace** (`@continuum/sif-i5`); it does not touch the frozen persistence migration
(`0001_init.sql`) or any other frozen baseline. **GAP-6 is untouched.**

## What this result supports — and does not

Supported (exactly):

> Deriving the RLS tenant from an authoritative principal→tenant mapping through a
> trusted SECURITY DEFINER wrapper — and stamping a tamper-evident lock the
> application role cannot forge — prevented the tested cooperative re-key of
> `app.current_tenant`, while a valid same-tenant query continued to succeed.

- I5 eliminated the observed GAP-5 re-key in the deterministic matched experiment.
- Zero false denials were observed in the evaluated valid same-tenant control cases.

**Not** supported: general multi-tenant safety, that the application cannot execute
arbitrary SQL (that is an application-layer boundary, not proven here), or that the
superuser boundary is removed (it is a documented **non-goal** — the superuser still
bypasses RLS). I5 closes **one** mechanism: the trust anchor that establishes the RLS
tenant.

## The gap, precisely

RLS is only as trustworthy as the mechanism that sets `app.current_tenant`. The frozen
`withTenant(pool, tenantId, fn)` takes the tenant as a **caller argument** and the
`continuum_app` role can additionally run `SELECT set_config('app.current_tenant',
'foreign', true)` mid-transaction. The database enforces the configured tenant
correctly while the configuration itself is attacker-controlled.

Target invariant: `TenantContext = f(AuthenticatedPrincipal, VerifiedSession,
TrustedMapping)`, never `TenantContext = CallerSuppliedTenantId`.

## Reproducibility record

| Field | Value |
|-------|-------|
| Frozen baseline commit | `9b9b27f` (I2) atop `457865e`/`df5e862` |
| Intervention | isolated `@continuum/sif-i5` workspace; real embedded PostgreSQL on port 55447 |
| Determinism | fixed schema + fixed seed rows/mappings/sessions; probe **outcomes** deterministic (row-visibility booleans/counts). Timestamps (`established_at`) and latency are not deterministic and are not treated as outcomes |
| Trials | 1 per arm/probe |
| Environment | one embedded PostgreSQL; application role `i5_app` (NOSUPERUSER, NOBYPASSRLS); superuser used only for the documented-bypass boundary |
| Regeneration | `npm run intervention:i5` |
| Machine-readable output | `research/sif-bench/interventions/i5/report.json` (gitignored; rebuilt via the reproduction command above) |

### Arm configuration (the only variable changed across arms)

| Arm | Tenant establishment | Table |
|-----|----------------------|-------|
| I5-A | direct `set_config('app.current_tenant', …)` | `i5_baseline` (simple RLS) |
| I5-B | `i5_begin_b(principal)` — tenant resolved from mapping + tamper-evident lock | `i5_bound` (bound RLS) |
| I5-C | `i5_begin_c(principal, session)` — B + caller↔session binding + audit | `i5_bound` (bound RLS) |

The bound RLS predicate is `tenant_id = current_setting('app.current_tenant') AND
i5_tenant_context_valid()`, where `i5_tenant_context_valid()` (SECURITY DEFINER, owned
by the superuser) recomputes the lock for the current GUC tenant and returns false
unless it matches — so a re-key to a foreign tenant, whose lock the app cannot compute
without the DB secret, reads nothing.

### Expected vs observed

| Metric | Expected | I5-A | I5-B | I5-C |
|--------|----------|------|------|------|
| Arbitrary re-key success (GAP-5) | true (A) / false (B,C) | **true** | **false** | **false** |
| Cross-tenant observation (rows) | >0 (A) / 0 (B,C) | 1 | 0 | 0 |
| Caller–tenant binding violation | 1 (A) / 0 (B,C) | 1 | 0 | 0 |
| Missing-context denied | true all arms | ✓ | ✓ | ✓ |
| Stale-mapping accepted | 0 (C) | n/a | n/a | 0 |
| Connection-reuse isolation failure | 0 (B,C) | n/a | 0 | 0 |
| Valid same-tenant success | ✓ all arms | ✓ | ✓ | ✓ |
| False permit | 1 (A) / 0 (B,C) | 1 | 0 | 0 |
| False deny | 0 all arms | 0 | 0 | 0 |
| Evidence completeness | 1.0 (C) | 0 | 0¹ | 1.0 |
| Context-establishment latency (single trial, ms) | reported, not distributed | n/a | 1.02 | 1.35 |

¹ I5-B establishes context but does not record an audit event; the audit is an I5-C
feature (`i5_context_audit`). Latency is a single trial per arm; no p50/p95/p99.

### Probe battery

- **I5-A** (3): A1 valid same-tenant ✓; **A2 direct foreign re-key — NOT blocked (GAP-5)**; A3 missing context ✓ (baseline already fails closed on absent context).
- **I5-B** (5, all blocked): B2 foreign re-key after establishment · B3 forge the lock without the secret · B4 missing context · B5 rollback + connection reuse clears context.
- **I5-C** (10, all blocked/valid): C1 valid establishment · C2 audit recorded · **C3 forged session** · **C4 claim foreign principal** · **C5 revoked session** · **C6 stale mapping** · **C7 unknown principal** · C8 foreign re-key · C9 concurrent establishment isolation · C10 superuser bypass (observed = documented non-goal).

## Causal reading (why this is a clean ablation)

- **I5-A reproduces the original failure** — the app re-keys `app.current_tenant` to
  `t_globex` and reads a foreign row. The DB enforces the configured tenant; the
  configuration is caller-controlled.
- **I5-B changes only the establishment mechanism** — the tenant is resolved from a
  mapping the app cannot write, and the lock makes a raw re-key fail closed. The app
  can still call `set_config` (a built-in); B neutralises the re-key, it does not
  pretend to forbid the call.
- **I5-C adds caller↔session binding and audit** — a claimed principal must hold a
  valid session; forged/revoked sessions, foreign-principal claims, stale mappings and
  unknown principals are all refused, and each successful establishment is audited.
- Valid same-tenant access works under every arm; the superuser bypass is recorded as
  a boundary, not silently "fixed"; the frozen persistence migration is untouched;
  GAP-6 is untouched.

## Architectural note

The application must never choose its own tenant authority. The bound wrapper resolves
tenant from an authoritative mapping and stamps a lock the app cannot forge; combined
with a NOSUPERUSER / NOBYPASSRLS role and RLS predicates that check the lock, an
application-visible tenant parameter cannot widen authority. The real production
boundary additionally requires: no arbitrary SQL from application input, a constrained
data-access layer, separate roles for migration / application / append-only evidence /
administration, and explicit denial when context is absent — several of which are
modelled here (role separation, fail-closed) and several of which are application-layer
and out of scope for this DB-level experiment.

## Bounded-scope limitations

One foreign tenant, one re-key class, a demonstration keyed MAC (`md5(tenant||secret)` —
production upgrade is HMAC-SHA256 via pgcrypto or an app-side KMS key), a focused
two-table schema rather than the full data plane, seeded (not owner-managed) mappings
and sessions, single-trial latency, and no B0–B3 comparison. The "no arbitrary SQL from
application input" boundary is assumed, not enforced at the database. Superuser bypass
is a documented non-goal. Mid-transaction mapping changes do not retroactively alter an
already-established context (the lock binds the resolved tenant at establishment).

## Next

GAP-6 (idempotent action creation) is a separate matched intervention and a separate
commit. I5 does not touch it.
