# SIF-Bench — Sovereign Intent Fabric Benchmark

A public, reproducible benchmark for owner-controlled intent/authorization
fabrics. This directory holds the **v0.1 harness**, which measures the milestone
tracks the reference slice covers.

## Run

```bash
# from the repo root, with the console running (npm run dev):
python3 research/sif-bench/sif_bench.py --iterations 30
```

No dependencies — standard library only. Exit code is `0` iff every gate passes,
so CI can use it directly.

## Tracks (v0.1 coverage)

1. **Intent fidelity** — prohibition-violation rate, human-gate-bypass rate.
2. **Disclosure minimization** — excess-disclosure ratio, reduction vs naive RAG.
3. **Leakage resistance** — canary-exfiltration rate (+ Wilson 95% CI).
4. **Authorization correctness** — false-permit / false-deny / cross-tenant /
   revocation-failure rates.
5. **Memory integrity** — provenance completeness.
6. **Agent interoperability** — N/A in v0.1 (single provider/framework).
7. **Operational resilience** — authorization p99, evidence-chain validity.

### Stage A — deterministic control-plane adversarial (v0.2)

The v0.2 adversarial suite is split. **Stage A** attacks the control plane's own
guarantees with **no model and no corpus**, so every result is deterministic
(exact, not sampled): capability misuse, cross-tenant access, evidence-chain
tamper, and human-gate bypass. **Stage B** (model / memory corpus: canary,
prompt-injection, poisoning, extraction) builds on top of it and is not yet
implemented.

```bash
npm run sif-bench:stage-a
```

The frozen Stage A baseline — 18/18 attacks blocked, 4/4 controls, zero leakage —
is [`STAGE_A_BASELINE.md`](STAGE_A_BASELINE.md); the baselines B0–B3 must not move
those numbers silently.

### Database-enforced gates (Tracks 4 & 5)

Tenant-isolation and evidence-completeness gates are realised against a **real
PostgreSQL** by the `@continuum/persistence` suite (row-level security, missing
tenant context fail-closed, forged-`tenant_id` rejection, append-only evidence,
restart/restore hash-chain re-verification):

```bash
npm run test -w @continuum/persistence
```

These run in CI as a required gate alongside the HTTP harness above.

## Honesty

Zero observed events is **not** proof of impossibility. This harness exercises
the reference slice under a fixed threat model; it does **not** perform
membership inference, model extraction, or side-channel attacks. Every report
records sample size, environment, and residual risk. See `docs/CLAIMS.md`.

## Intended production stack

Python 3.12+, pydantic, `uv`, pytest — plus adversarial suites (canary corpora,
prompt-injection, memory-poisoning, extraction) as the platform grows.
