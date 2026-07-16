# Phase 2 — Async PostgreSQL runtime path: completion report

```
Status:  Phase 2 implementation COMPLETE. Held for review. No push, no tag.
Baseline: origin/main = e7bcd4f
Identity: Frank Asante Van Laarhoven — no other attribution, no co-author trailers.
```

The console/API path is now durable and fail-closed through the asynchronous engine,
not merely capable of writing to PostgreSQL. Every gate below is green on real
embedded PostgreSQL; the frozen research suites are unchanged.

## Gate-by-gate status

| # | Gate | Status | Evidence |
|---|------|--------|----------|
| 1 | Complete PostgreSQL reads + transactional operations through the async store | ✅ | `PostgresStore`: reads, `submitIntent`, `authorizeIntent`, `discloseForToken`, `authorizeAction`, `revokeCapability`, `getMetrics`, `verifyEvidenceChain`, health probes |
| 2 | Wire the console/API runtime to the async engine (`CONTINUUM_STORE=postgres`) | ✅ | `apps/console/lib/runtime.ts`, `app/api/runtime/route.ts`, `app/page.tsx` (async server component) |
| 3 | Prohibit memory mode in production; prohibit silent fallback | ✅ | `resolveStoreMode` + `assertProductionStore`; `store-selection.test.ts` (memory-in-prod refused, unset refused, no fallback) |
| 4 | Shared contract tests for the in-memory and PostgreSQL adapters | ✅ | `shared-contract.test.ts` — both seeded from the same slice, identical assertions |
| 5 | Validate RLS through the actual API path (foreign-tenant denial + pooled reuse) | ✅ | `runtime-rls.test.ts` — foreign-tenant read = null; 24 interleaved cross-tenant requests over a pool of 4 never leak |
| 6 | Restart persistence: state, evidence, revocation, proof replay, action idempotency | ✅ | `runtime-restart.test.ts` (state/evidence/revocation) + `runtime-writepath-gate6.test.ts` (proof replay + action idempotency across a fresh pool) |
| 7 | Import-boundary test: no synchronous research engine in the production console | ✅ | `runtime.import-boundary.test.ts`; retired `lib/engine.ts`, `/api/state`, `/api/rerun` |
| 8 | Record that Map hydration was rejected in `PRODUCTION_READINESS.md` | ✅ | `PRODUCTION_READINESS.md` (store-boundary decision + delivery status) |
| 9 | Rerun every frozen benchmark + intervention suite unchanged | ✅ | core 91 · comparative 44 · sif-i4 6 · sif-i5 7 · sif-i6 22 · sif-concurrency 9 |
| 10 | Phase 2 completion report; hold the final commit set | ✅ | this document |

## Test tally (all green)

| Suite | Tests |
|-------|-------|
| `@continuum/core` (frozen 68 + async boundary/continuation) | 91 |
| `@continuum/persistence` (real embedded PostgreSQL) | 44 |
| `@continuum/console` (import boundary + store selection, no DB) | 7 |
| `@continuum/sif-comparative` (frozen) | 44 |
| `sif-i4 / i5 / i6 / concurrency` (frozen) | 6 / 7 / 22 / 9 |

## How the durability + fail-closed properties are proven

- **Fail-closed selection** — production refuses `memory` and an unset value; there is no
  `postgres → memory` fallback anywhere. The API route returns 503 on store/db failure.
- **Tenant authority** — derived by the trusted boundary (`RequestContext`), never a
  request parameter; every read/write is RLS-scoped; `app.current_tenant` is
  transaction-local and does not leak across the shared pool (24-way interleave test).
- **One transaction per flow** — reads, checks, writes, and evidence-append run inside one
  `store.transaction`; evidence continues the persisted hash chain (GAP-4) and the signing
  key is bound to the persisted anchor (custody guard).
- **Restart-safe** — a brand-new `PostgresStore` (fresh pool) re-verifies state, evidence,
  revocations; a replayed disclosure proof stays denied; a re-submitted action stays a
  single record with a single evidence event.

## Deferred (documented, not silently stubbed)

- **Exact SCT-signature re-verification at disclose** — the `capabilities` projection is
  lossy (`real` columns; omitted `issuer`/`maximum_disclosure`), so disclose verifies
  holder-PoP + expiry + revocation + replay from losslessly-persisted fields; the platform
  SCT signature is verified at issuance. Lossless re-verification needs the canonical token
  persisted (a reviewed schema addition).
- **Live-observability metrics** — latency percentiles, canary/injection/model-call
  counters are runtime telemetry, not durable state; `getMetrics` reads them as 0 and
  reports only durable-derived counts (honest, not fabricated).
- **Auth/session tier, KMS/HSM custody, deployment** — Phases 3–4.

## Held commit set (6 commits, ahead of `origin/main` = e7bcd4f)

```
f66e05f  GAP-4: restart-safe evidence continuation in the ledger
6b6ae31  authorization-decision write path over PostgreSQL
623a90f  wire the console/API runtime to the async engine
7e6d113  runtime durability gates — RLS API path, restart, shared contract
f3c3024  submitIntent over Postgres
463ad49  disclose replay + action idempotency + metrics
```
(+ the documentation commit carrying this report.) No push, no tag; Frank-only identity.

## Working tree

Clean. The unrelated console **visual redesign** is isolated in `git stash`
(`trackA-console-redesign`) with a standalone backup patch; it must be re-pointed onto this
durable runtime when restored (its retired page/renderer consumed the synchronous slice
DTO). The infrastructure PostgreSQL service was not touched; the console dev server was not
restarted (integration tests drive the runtime module directly).
