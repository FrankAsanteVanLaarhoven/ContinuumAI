# Continuum — Research Paper Artefacts

**Maturity:** Research prototype v0.1 — complete in-memory vertical slice + model
gateway, preliminary conformance tests. Latest commit `3f038fd` (two commits, no
tagged release, no published package).

**Author:** Frank Asante Van Laarhoven.

Candidate title: *Continuum: Intent-Bound Context Disclosure and Verifiable
Agency for Sovereign AI Systems*.

## Purpose of this directory

This directory holds the paper describing Continuum as a systems-and-security
research prototype. The paper is being written **incrementally**. Only the
**stable** components are committed at this stage — those that can be stated
without pre-empting baseline experiments that have not yet been run.

Stable now:

- Problem formulation and the permit invariant.
- Hypotheses (`hypothesis.md`) — stated as claims **to be tested**.
- Research questions and their metrics (`research_questions.md`).
- Research contributions, framed at the narrower defensible boundary
  (`contributions.md`).
- Architecture reference (see [`../../docs/architecture.md`](../../docs/architecture.md)).
- Threat-model reference (see [`../../docs/threat-model.md`](../../docs/threat-model.md)).
- Claim boundary (see [`../../docs/CLAIMS.md`](../../docs/CLAIMS.md)).
- Benchmark design summary (SIF-Bench; see [`../sif-bench/README.md`](../sif-bench/README.md)).
- Experimental protocol and baselines (`experimental_protocol.md`).
- Claim–evidence matrix (`claim_evidence_matrix.md`).
- Limitations (`limitations.md`).

Pending baseline experiments (explicitly **not** yet written):

- Abstract.
- Results.
- Failure analysis.
- Conclusion.

These sections remain marked `[PENDING EXPERIMENTS]` in `manuscript.md` until the
baselines B0–B3 (see `experimental_protocol.md`) have been run and analysed.

## Files

| File | Contents |
|------|----------|
| `manuscript.md` | Full paper skeleton; stable sections filled, pending sections marked. |
| `hypothesis.md` | Formal hypotheses H1 (and its subject conditions), with symbol definitions. |
| `research_questions.md` | RQ1–RQ7, their metrics, and current v0.1 status per RQ. |
| `contributions.md` | The three research artefacts and the narrower defensible claim. |
| `limitations.md` | Honest limitations of the v0.1 prototype and its evaluation. |
| `experimental_protocol.md` | Baselines, ablations, workload families, statistics, reproducibility manifest. |
| `claim_evidence_matrix.md` | What the paper may assert, the evidence each claim needs, and its current status. |

## Discipline

Every artefact here is bounded by [`../../docs/CLAIMS.md`](../../docs/CLAIMS.md).
Nothing in the paper may exceed that claim boundary. In particular: no claim of
impossible or zero leakage, no claim of production or enterprise security, no
claim of state-of-the-art or superiority over existing systems, and no claim of
model-independence (only one simulated model exists in v0.1). Prompt-injection
screening is pattern-based and incomplete; tool execution is simulated; tenant
isolation is currently logical, with database/row-level-security enforcement in
progress. Superiority over baselines is **not** demonstrated and must not be
asserted until B0–B3 are measured.
