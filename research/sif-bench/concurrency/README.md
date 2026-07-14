# SIF-Bench concurrency / TOCTOU suite

Measures the **unmodified** control plane under controlled concurrent
interleavings — before I1, I2, or any injection-defence change. It answers: do
Continuum's sequentially-correct authorization, revocation, tenant-isolation,
human-gate, action-state, and evidence mechanisms remain correct under
concurrency?

```bash
npm run sif-bench:concurrency
```

Results and findings: [`CONCURRENCY_BASELINE.md`](CONCURRENCY_BASELINE.md).

## Families

| Family | Surface | Nature |
|--------|---------|--------|
| **C1** | authorization & scope races | in-memory engine, ordered TOCTOU interleavings |
| **C2** | human-gate & action races | in-memory action state machine |
| **C3** | database & tenant-context races | **real embedded PostgreSQL**, barriers, pooled connections, RLS, roles |
| **C4** | evidence & event-chain races | in-memory ledger + durable `evidence_envelopes` constraints |

## How interleavings are forced

Deterministically — barriers, latches, controlled promises, and ordered steps
(`src/scheduler.ts`), **not** timing sleeps. For the single-threaded synchronous
engine (C1/C2), the real TOCTOU window is *between* atomic method calls, so an
adversarial state change is injected between a check and its use. For the durable
layer (C3/C4), two real connections/transactions are synchronized with a barrier.
One deterministic schedule per case at seed `0xC0FFEE`; this is a baseline, not a
randomized-schedule fuzzer.

## Layout

```
concurrency/
├── README.md
├── CONCURRENCY_BASELINE.md      # frozen results incl. failures (tracked)
├── schemas/result.schema.json   # the machine-readable result record
├── cases/CATALOG.md             # the 48 cases with baseline outcomes (generated, tracked)
├── fixtures/*.json              # one per documented failure — regression evidence (tracked)
├── reports/concurrency.json     # full report (generated, gitignored)
├── manifests/env.json           # environment + seed record (generated, gitignored)
└── src/                         # runners, scheduler, scorers, driver test
    ├── scheduler.ts  records.ts  harness.ts  scorers.ts
    ├── c1.ts  c2.ts  c3.ts  c4.ts
    ├── global-setup.ts           # boots embedded PostgreSQL
    └── concurrency.test.ts       # driver: runs all, scores, writes outputs, asserts framework gates
```

The `runners` / `schedulers` / `scorers` code lives under `src/` (co-located)
because it must import and drive `@continuum/core` and `@continuum/persistence`
directly; the corpora-style data (schemas, cases, fixtures, reports, manifests)
lives at the package root as the brief's tree prescribes.

## What the driver asserts (framework gates, NOT "all held")

- every adversarial case has valid controls (C1/C2 per-case; C3/C4 per-family);
- no valid control (sequential or concurrent) false-fails — permitted
  concurrency is not refused;
- the run is reproducible from the fixed seed (deterministic verdicts);
- the run is **wall-clock-independent** — every intended-live operation is
  evaluated against the benchmark's logical clock, not the host `Date.now()`
  (baseline v0.2 correction; regression: `src/wallclock.test.ts`);
- the frozen Stage A baseline is unchanged.

Security outcomes — including the 10 documented gaps — are **recorded**, not
gated. A reproducible race failure is evidence, not a test failure. Nothing here
weakens a lock, permission, gate, or test to go green.

Of the gaps this suite surfaced, four now have separately-evaluated matched-arm
interventions, each measured against these frozen baselines: **I1** (GAP-1,
entitlement-bound scope), **I2** (GAP-2, caller-bound metadata), **I5** (GAP-5,
database-bound tenant identity), and **I6** (GAP-6, idempotent action identity).
GAP-3 (authorization staleness) and GAP-4 (PoP replay) remain open. These
interventions do not modify this suite.

## Boundary

No external model calls, no nondeterministic network dependencies. PostgreSQL
runs at read-committed. See the baseline for the bounded claims this does and does
not support.
