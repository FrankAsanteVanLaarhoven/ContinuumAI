# Hypotheses

**Maturity:** Research prototype v0.1 (commit `3f038fd`). The statements below are
**hypotheses to be tested**. They are *not* established results. No baseline
comparison has yet been run; see `experimental_protocol.md` and
`claim_evidence_matrix.md`.

## Main hypothesis

An intent-bound authorization and context-brokering layer (Continuum) can
significantly reduce unnecessary disclosure of private context and unauthorized
agent actions, relative to direct agent access and to conventional
retrieval-augmented generation (RAG), while preserving acceptable task utility
and operational latency.

## Formalisation

Let a *configuration* be one of the evaluated systems (a baseline or Continuum),
and let each metric below be measured over a fixed workload suite and a
predeclared number of seeds.

- **H1 (disclosure):** `D_C < D_B`
- **subject to (utility):** `U_C ≥ U_B − ε`
- **and (violations):** `V_C < V_B`

The main hypothesis is supported for a given baseline only if all three hold
simultaneously with the predeclared statistical protocol.

## Symbol definitions

| Symbol | Meaning |
|--------|---------|
| `C` | The Continuum configuration (baseline B3). |
| `B` | A comparison baseline: B0 direct agent access, B1 standard RAG, or B2 RBAC-protected RAG. Each is tested separately. |
| `D` | **Disclosure** — the volume of sensitive or unnecessary private context released to the agent/model, operationalised by the Excess Disclosure Ratio and the Sensitive Field Exposure Rate (see `research_questions.md`, RQ2). `D_C`, `D_B` are the values for Continuum and the baseline. |
| `U` | **Task utility** — the task success rate on the same workload (RQ2), holding the disclosure budget fixed. `U_C`, `U_B` are Continuum and baseline utility. |
| `V` | **Violation rate** — the rate of policy or action violations, e.g. unauthorized execution, human-gate bypass, prohibited-action execution (RQ1, RQ3). `V_C`, `V_B` are Continuum and baseline violation rates. |
| `ε` | **Predeclared acceptable utility reduction** — a small tolerance fixed *before* experiments are run, expressing how much task utility we are willing to trade for reduced disclosure. `ε` is declared per workload family in `experimental_protocol.md`. |

## Status

Untested. The v0.1 slice provides preliminary single-configuration measurements
(e.g. the broker releases 2 of 10 candidate objects and redacts `bank_iban` on
the reference procurement scenario), but no `D_B`, `U_B`, or `V_B` have been
collected, so none of H1 or its subject conditions can yet be evaluated. The
required baselines are B0–B3 in `experimental_protocol.md`.
