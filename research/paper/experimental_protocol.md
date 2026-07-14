# Experimental Protocol

**Maturity:** Research prototype v0.1 (commit `3f038fd`). This protocol is
**predeclared**: baselines, ablations, workloads, statistics, and the run manifest
are fixed here *before* the comparative experiments are run. No baseline
comparison has yet been executed.

## Baselines

Four configurations are evaluated on the same workloads with the same seeds.

| ID | Configuration | Purpose |
|----|---------------|---------|
| **B0** | **Direct agent access** — the agent reads the full context store and acts with no intent, policy, broker, or gate. | Establishes the worst-case disclosure and violation baseline; the "no control plane" reference. |
| **B1** | **Standard RAG** — retrieval-augmented generation: relevant objects are retrieved and passed to the model, with no authorization or minimisation. | Represents the common contemporary pattern; isolates whether retrieval relevance alone limits disclosure. |
| **B2** | **RBAC-protected RAG** — RAG with role-based access control gating retrieval. | Isolates the marginal effect of coarse role-based access vs. intent-bound, per-object authorization. |
| **B3** | **Continuum** — the full intent-bound control plane (intent → PDP → broker → holder-bound capability → gateway → action state machine → human gate → evidence). | The system under test. |

## Required ablations

Each ablation removes one Continuum component from B3 to attribute effect to that
component. Every ablation is run on all workload families.

| Ablation | Component removed | Question answered |
|----------|-------------------|-------------------|
| **C–Intent** | Intent envelope (CIP-002 constraints) | Does binding authority to declared intent reduce disclosure and violations vs. scope alone? |
| **C–PoP** | Holder binding / proof-of-possession | Does holder binding actually prevent capability replay and theft? |
| **C–Redaction** | Broker field redaction | How much sensitive-field exposure does redaction prevent, and at what utility cost? |
| **C–Revocation** | Revocation registry | Does revocation terminate active authority, or does authority persist? |
| **C–HumanGate** | Human approval gate | Does the human gate prevent unauthorized consequential execution? |
| **C–Provenance** | Provenance/evidence recording | Is post-hoc reconstruction possible without provenance? |
| **C–Injection** | Gateway injection screening | What is the marginal injection-block contribution of the heuristic screen? |
| **C–Budget** | Token/cost budget | Does the budget prevent resource-exhaustion / denial-of-wallet? |

## Workload families

1. **Enterprise procurement.** The existing Orion/Apex quote-comparison scenario:
   an agent compares supplier quotes to recommend the lowest compliant unit price.
   Sensitive fields include bank data (`bank_iban`), negotiated rates, and internal
   budget bands. Success = correct compliant recommendation; disclosure is measured
   over the sensitive fields.

2. **Enterprise knowledge work.** Policy question-answering under purpose
   constraints, where retrieved documents may carry embedded injection. Success =
   correct, in-purpose answer; the configuration must resist doc-embedded
   (indirect) injection and must not disclose out-of-purpose context.

3. **Consequential workflow.** A finance / HR / healthcare / infrastructure change
   requiring a state transition. Execution is **simulated** with realistic state
   transitions (proposed → gated → approved → executed → succeeded / compensated).
   Success = the correct action reaches the correct terminal state only via the
   permitted path; violations = any bypass of the gate or prohibited transition.

## Statistical protocol

- **Multiple seeds.** Each configuration × workload is run over a predeclared set
  of random seeds; report the number of runs **N** with every metric.
- **Confidence intervals.** Report **Wilson score 95% intervals** for all
  proportions (false permit/deny, bypass, exfiltration, injection success, etc.).
  Report medians and percentiles (p50/p95/p99) with dispersion for latencies.
- **Predeclared ε.** The acceptable utility-reduction tolerance `ε` (see
  `hypothesis.md`) is fixed per workload family before running and reported
  alongside results.
- **Per-RQ analysis.** Analyse each research question (RQ1–RQ7) separately against
  its metrics; do not aggregate incommensurable metrics into a single score.
- **Honesty rule.** "Zero observed events" is reported with its sample size and
  interval and is **never** presented as proof of impossibility.

## Reproducibility — run manifest

Every run records a manifest sufficient to reproduce and audit it:

- run id; git commit; schema version; policy version; protocol version;
- workload id; pseudonymous tenant id; seed; start/end timestamps;
- permit/deny decisions (with the full check list per decision);
- objects requested vs. objects released; fields redacted;
- capability issue time, expiry, and revocation time;
- action-state transitions;
- evidence-envelope count and chain verification result;
- authorization / broker / end-to-end latencies;
- failure reason (if any);
- environment manifest (runtime, platform, dependency versions).

Manifests are the unit of reproducibility: a result is admissible only if its
manifest is complete and its evidence chain verifies.
