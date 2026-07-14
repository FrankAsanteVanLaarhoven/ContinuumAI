# SIF-Bench B0–B3 comparative harness

Deterministic, shared-input comparison of four system configurations under identical
tasks, corpora, budgets and scoring rules. **No live model** — a deterministic decision
surrogate isolates control-plane effects.

> Deterministic systems evaluation, not LLM performance.

**Status: PRELIMINARY harness-validation only.** This milestone builds and validates the
comparison *infrastructure*; it is **not** a comparative claim. The full experiment
(more workloads, repetitions, and the Stage B v0.4 real-model layer) is later work.

## Configurations (frozen — see `../../paper/B0_B3_DEFINITIONS.md`)

- **B0** unrestricted agent · **B1** top-k RAG · **B2** strong RBAC/tenant-filtered RAG
  (credible, not a straw man) · **B3** Continuum (I1–I6 target + I7-C).

## Layout

- `src/schemas.ts` — shared frozen data contract + input checksum.
- `src/surrogate.ts` — the deterministic decision surrogate (shared "model").
- `src/adapters/{b0,b1,b2,b3}.ts` — the four baseline adapters (identical signature).
- `src/adapters/common.ts` — retrieval, projection, cost, outcome assembly.
- `src/metrics.ts` — Utility, Disclosure, SecurityViolations, Latency, Cost (separate dimensions).
- `src/harness.ts` — runner: shared-input checksum verification + deny-all guard.
- `src/workloads/procurement.ts` — W1 (implemented); W2/W3 defined in `B0_B3_PROTOCOL.md`.
- `reports/` — generated (gitignored).

Run: `npm run comparative:validate`.

## Joint result (W1 harness-validation)

The headline is **joint**, never a single collapsed score; a deny-all system is rejected
by the utility guard.

| Baseline | Utility | Excess disclosure | Sensitive fields | Cross-tenant | Canary | Injection success | Violations | Evidence |
|----------|:-------:|:-----------------:|:----------------:|:------------:|:------:|:-----------------:|:----------:|:--------:|
| B0 unrestricted | 0.0 | 0.40 | 10 | 2 | 1 | 1 | 9 | 0 |
| B1 top-k RAG | 0.0 | 0.40 | 10 | 2 | 1 | 1 | 9 | 0 |
| B2 strong RBAC RAG | 1.0 | 0.00 | **6** | 0 | **1** | **1** | 1 | 6 |
| B3 Continuum | 1.0 | 0.00 | **0** | 0 | 0 | 0 | 0 | 8 |
| _deny-all (guard)_ | _0.0_ | — | — | — | — | — | — | — |

B2 is a credible strong baseline: it gets the benign task right and enforces tenant
isolation and a tool catalogue, but — lacking minimum projection and structured
separation — it over-discloses sensitive fields and follows an indirect injection its
keyword filter cannot see. B3 retains utility while closing both. B0/B1 admit a
non-compliant foreign quote, losing utility *and* leaking. Deny-all fails the utility
guard, so security-by-refusal cannot rank well.
