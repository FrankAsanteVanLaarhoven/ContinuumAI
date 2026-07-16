# HTTP SIF-Bench — v0.1 → v0.2 migration note

```
Status: TRACKING NOTE (Deliverable 15 of the Phase 3 specification). No implementation here.
Reason: the Phase 2 console rewrite retired /api/state + /api/rerun in favour of the
        asynchronous /api/runtime surface, so the legacy live harness no longer applies.
```

## Frozen historical artifact

```
HTTP SIF-Bench v0.1
harness:   research/sif-bench/sif_bench.py
endpoint:  /api/state, /api/rerun
DTO:       ConsoleState (synchronous vertical-slice view)
runtime:   retired synchronous slice engine (removed from the console in Phase 2)
status:    HISTORICAL, PRESERVED — evidence for the earlier slice ONLY
```

The historical `11/11` HTTP result is **not** evidence for the asynchronous PostgreSQL
runtime. It must not be reinterpreted as applying to the rewritten runtime. The harness
is preserved unchanged and labelled historical; its result file (`results/report.json`)
remains gitignored.

## Replacement to build (held until the Phase 3 runtime path is ready)

```
HTTP SIF-Bench v0.2
endpoint:  /api/runtime
DTO:       RuntimeState (durable async store view)
runtime:   asynchronous ContinuumStore boundary
```

The v0.2 harness **must**:

1. target **`/api/runtime`** (not `/api/state`/`/api/rerun`);
2. use the new **request/response schemas** (`RuntimeState`);
3. exercise **both `memory` and `postgres` modes** where appropriate;
4. verify **production rejects `memory` mode** (fail-closed, no silent fallback);
5. run against a **disposable, Continuum-owned PostgreSQL** instance (not a shared/prod DB);
6. verify **tenant isolation through HTTP** (foreign-tenant denial on the real surface);
7. verify **restart persistence** (state/evidence/revocation/proof-replay/idempotency across a restart);
8. **distinguish transport errors from governance denials** (a 503/connection error is
   NOT a governance "deny"; classify separately);
9. **preserve the frozen benchmark corpus and scoring formulas** (comparability with v0.1
   where the metric is still meaningful);
10. **emit a new result version** (`HTTP SIF-Bench v0.2`) — never overwrite the v0.1 result.

## Sequencing

The v0.2 harness depends on a runnable `/api/runtime` with real identity (Phase 3
authentication) and a disposable PostgreSQL, so it is scheduled **after** the Phase 3
authentication + tenant-resolution boundary lands. Until then:

- Frozen deterministic research results remain validated by the Vitest suites
  (comparative, interventions, concurrency, adversary/Stage-A, Stage-B) — all green.
- The live HTTP benchmark is recorded as an **open** compatibility item, not a passing
  gate for the async runtime.
