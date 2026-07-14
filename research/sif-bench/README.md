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

## Honesty

Zero observed events is **not** proof of impossibility. This harness exercises
the reference slice under a fixed threat model; it does **not** perform
membership inference, model extraction, or side-channel attacks. Every report
records sample size, environment, and residual risk. See `docs/CLAIMS.md`.

## Intended production stack

Python 3.12+, pydantic, `uv`, pytest — plus adversarial suites (canary corpora,
prompt-injection, memory-poisoning, extraction) as the platform grows.
