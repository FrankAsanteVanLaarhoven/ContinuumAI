# Claim–Evidence Matrix

**Maturity:** Research prototype v0.1 (commit `3f038fd`).

This matrix governs what the paper may assert. A proposed claim may appear in the
manuscript **only** at the strength its current evidence supports. "Not
established" claims must not be stated as findings; "preliminary" evidence must be
labelled as such, with its sample size, environment, and residual risk; and no row
may be escalated without the required evidence being produced under
`experimental_protocol.md`. The matrix is the single source of truth for the
paper's claim strength, subordinate to [`../../docs/CLAIMS.md`](../../docs/CLAIMS.md).

| Proposed claim | Required evidence | Current status |
|----------------|-------------------|----------------|
| Intent-bound access reduces over-disclosure | baseline comparison over multiple workloads | Not established |
| Holder binding prevents token replay | replay attack experiments | Preliminary local evidence |
| Revocation terminates active authority | persistent concurrent revocation tests | Preliminary local evidence |
| Human gates prevent unauthorized execution | bypass and race-condition suite | Preliminary simulated evidence |
| Context broker preserves utility | task success vs disclosure analysis | Not established |
| Evidence chain enables reconstruction | restart, tamper and restore experiments | Database-enforced (v0.1): re-verifies after fresh connection and logical restore; tamper detected by hash chain + append-only table |
| Tenant isolation holds | database, cache, vector and backup tests | Database RLS-enforced (v0.1): direct-query, missing-context, forged-id and evidence isolation tested; cache/vector/full-backup isolation pending |
| Gateway reduces injection success | large attack corpus and ablation | One/few heuristic cases |
| Continuum is model-independent | multiple real model/provider evaluations | Not established |
| Overhead is operationally acceptable | load, latency and throughput study | Not established |

## Reading the statuses

- **Not established** — no admissible evidence yet; the paper may state the claim
  only as a hypothesis or an open question.
- **Preliminary local evidence** — supported by unit/slice tests in the in-memory
  prototype; requires persistent, concurrent, or adversarial confirmation before it
  may be stated as a result.
- **Preliminary simulated evidence** — observed against simulated execution only;
  requires a race-condition and bypass suite.
- **Database RLS-enforced (v0.1)** — enforced by PostgreSQL row-level security
  (enable + force), keyed on a transaction-local tenant setting, with fail-closed
  behaviour on missing context and `WITH CHECK` on writes; verified by the
  `@continuum/persistence` suite against a real embedded Postgres. Cache, vector,
  and full physical-backup isolation remain to be tested.
- **Database-enforced (v0.1)** — the authoritative rows are durable and the
  evidence hash chain re-verifies from storage after a fresh connection and after
  a logical restore; not yet exercised under a full cluster stop/start or a
  physical (pg_dump/pg_restore) cycle.
- **One/few heuristic cases** — the pattern-based screen blocks known cases;
  requires a large adversarial corpus and an ablation to characterise.
