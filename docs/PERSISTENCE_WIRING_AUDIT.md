# Persistence-Wiring & Runtime-Path Audit

```
Status:      EVIDENCE-ONLY MILESTONE — no implementation, held for review
Scope:       Which live runtime paths use the PostgreSQL/RLS data plane, and
             which bypass it via the in-memory Store.
Claim:       This document makes NO production-readiness claim. It records the
             measured state of the code at HEAD.
Baseline:    HEAD 0fd91b4 (== origin/main)
```

## Question

Not "should we build Postgres?" — the durable data plane already exists
(`packages/continuum-persistence`: PostgreSQL, row-level security, least-privilege
`continuum_app` role, append-only evidence, logical-restore test). The question is:

> **Which console/API runtime paths still bypass the existing persistence package
> and run against the in-memory `Store`?**

## Method

Static trace of every live path plus the test/CI gates. Files inspected this pass:
`apps/console/app/page.tsx`, `app/api/state/route.ts`, `app/api/rerun/route.ts`,
`apps/console/lib/engine.ts`; `packages/continuum-core/src/slice.ts`, `engine.ts`,
`store.ts`, `gateway.ts`; `packages/continuum-persistence/src/repository.ts`,
`pg.ts`, `index.ts`; `.github/workflows/ci.yml`; `README.md`; `docs/threat-model.md`.
Core suite run: **68/68 pass**. Persistence suite (per README + CI): **14 tests**
(isolation 7, durability 6, logical restore 1).

## Canonical runtime path

```
browser → console API → authentication → tenant resolution
        → ContinuumEngine → Store interface → PostgreSQL/RLS → evidence ledger
```

## Runtime-path matrix

| Runtime path | Current store | Authenticated | Tenant-bound | Durable | Production status |
|---|---|---|---|---|---|
| Console SSR (`page.tsx` → `getConsoleState`) | **In-memory** | No | Hardcoded `t_acme` | No | In-memory demo |
| `GET /api/state` | **In-memory** | **No (open)** | Hardcoded `t_acme` | No | Unauthenticated, in-memory |
| `POST /api/rerun` (state-mutating) | **In-memory** | **No (open)** | Hardcoded `t_acme` | No | Unauthenticated, in-memory, mutating |
| Action propose/approve | In-memory (engine methods exist, **no API route**) | No | Slice-internal | No | Engine-capable, not exposed |
| Evidence query | **In-memory** (`engine.evidence()`), never `loadEvidence`/`verifyPersistedChain` | No | Slice-internal | No | In-memory, not durable-backed |
| Model gateway (`callModel`) | In-memory | Capability-bound (in slice) | Partial | No | **Simulated** (`simulateModel`) |
| Persistence tests / `repository.ts` | **PostgreSQL** | `continuum_app` (least-priv) | **Yes (RLS)** | **Yes** | Research-validated |
| Concurrency harness C3/C4 | PostgreSQL | Test principal | Yes | Yes | Research only |
| Comparative benchmarks | Frozen fixtures | Synthetic | Isolated | Reproducible | Research only (v0.2 real-model runs **held**) |

## Evidence (file → fact)

| Fact | Evidence |
|---|---|
| Console runs one in-memory engine singleton | `apps/console/lib/engine.ts:16` — `let current = runVerticalSlice()` |
| `runVerticalSlice` constructs a default (in-memory) engine | `packages/continuum-core/src/slice.ts:37` — `new ContinuumEngine()` |
| Default engine store is the seeded in-memory store | `engine.ts:167` — `this.store = store ?? createSeededStore()` |
| `Store` is synchronous & `Map`-shaped (holds keypair in-process) | `store.ts:30–48` — `Map<…>` fields + `platform: Ed25519Keypair` |
| Tenant is a hardcoded literal, not resolved from identity | `lib/engine.ts:139` — `engine.listMemoryMeta("t_acme")` |
| Both API routes have no auth/session/tenant guard | `api/state/route.ts:7`, `api/rerun/route.ts:7` — bare `GET`/`POST` |
| No runtime code imports the persistence package | grep: `@continuum/persistence` imported only by research harness + `core/adversary.ts`, **not** by `apps/console` |
| Persistence write path is snapshot-export, not per-op | `repository.ts:18` — `persistExport(pool, EngineExport)` |
| Persistence enforces RLS on read AND write via least-priv role | `pg.ts:5–7,31,49–69` — `continuum_app` SELECT/INSERT, `set_config('app.current_tenant', …, true)` |
| Model output is a deterministic stand-in | `gateway.ts:85–86,198` — `simulateModel(...)` |
| Signing key in-process; superuser bypasses RLS; logical restore only; no at-rest encryption | `README.md:68–73`; `docs/threat-model.md:41,47–52` |

## Findings

1. **The live console bypasses PostgreSQL entirely.** SSR + both API routes run a
   process-memory `ContinuumEngine` seeded by `createSeededStore()`. State is lost on
   restart; nothing is persisted; `persistExport` is never called by the console.

2. **The persistence package is a durable *sink + independent verifier*, not the live
   `Store`.** It ingests an `EngineExport` snapshot under tenant-scoped, RLS-enforced,
   append-only transactions and can reload + re-verify the chain. It does **not**
   implement the core `Store` interface and is not on the request path.

3. **Tenant authority is client-implicit / hardcoded.** The console pins `t_acme`;
   there is no authenticated identity from which to derive tenant. This is the
   authorization-model gap, distinct from the persistence gap.

4. **Models are simulated.** Gateway *screening* logic is real and tested; the model
   itself is `simulateModel`. Real provider adapters do not exist; real-model
   external-validity runs are held.

5. **The `Store` interface is the adapter's central design constraint.** It is
   **synchronous** and **`Map`-based**. A `PostgresStore` must reconcile this with
   async Postgres — either load tenant-scoped state into `Map`s per request, or evolve
   the interface to async — without duplicating the existing schema, migrations, or RLS.

## What is NOT a gap (do not rebuild)

- PostgreSQL schema, migrations, RLS policies, least-privilege role — **exist and are CI-gated.**
- Append-only evidence chain + independent re-verification — **exist.**
- Deny-by-default authorization, capability tokens, disclosure broker, human gate,
  revocation, I1–I3/I7 interventions, Stage-A adversarial gate — **exist, 68/68 pass.**

## Conclusion → next milestone

The keystone is **not** a new persistence subsystem. It is a **thin `PostgresStore`
adapter** that connects the existing schema/migrations/RLS/append-only evidence to the
live console/API path, selected by explicit config, failing closed in production. See
`docs/PRODUCTION_READINESS.md` for the phased plan and the must-not constraints.
