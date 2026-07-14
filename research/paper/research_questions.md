# Research Questions

**Maturity:** Research prototype v0.1 (commit `3f038fd`). Each RQ lists the
metrics that would answer it and a **current status** line describing what the
v0.1 slice *preliminarily* shows versus what remains unmeasured. Preliminary
single-configuration numbers are not evidence for or against any comparative
hypothesis; see `hypothesis.md` and `claim_evidence_matrix.md`.

---

## RQ1 — Authorization correctness

*Does the intent-bound policy decision point admit exactly the authority intended,
and no more?*

**Metrics:** False Permit Rate; False Deny Rate; Replay Acceptance Rate; Expired
Capability Acceptance Rate; Revoked Capability Acceptance Rate; Delegation Escape
Rate.

**Current status:** The v0.1 harness (n=20) reports False Permit Rate = 0 and
False Deny Rate = 0 on the single reference scenario, and unit tests exercise
replay, expiry, and revocation rejection. Delegation is not modelled in v0.1, so
Delegation Escape Rate is unmeasured. No baseline comparison and no fuzzed
authorization corpus have been run.

## RQ2 — Disclosure minimisation

*Does the context broker release the minimum necessary context while preserving
task utility?*

**Metrics:** Excess Disclosure Ratio; Sensitive Field Exposure Rate; Context
Precision; Context Recall; Task Success Rate; Utility–Disclosure Frontier.

**Current status:** The v0.1 harness reports Excess Disclosure Ratio mean = 0 and
an 0.8 mean reduction versus a naive-RAG disclosure baseline *internal to the
harness*, and the broker redacts the sensitive `bank_iban` field on the reference
scenario. Context precision/recall, an end-to-end Task Success Rate, and the
Utility–Disclosure Frontier across B0–B3 are unmeasured.

## RQ3 — Action governance

*Are consequential agent actions correctly gated, sequenced, and, where required,
subject to human approval?*

**Metrics:** Human-Gate Bypass Rate; Unauthorized Execution Rate; Action-State
Violation Rate; Approval Latency; False Escalation Rate; Compensation Success
Rate.

**Current status:** The v0.1 slice hard-denies a prohibited `place_order` action
and blocks an external action at the human gate; the harness reports Human-Gate
Bypass Rate = 0 (n=20). Tool execution is **simulated**. Approval Latency, False
Escalation Rate, and Compensation (rollback) Success Rate are unmeasured; no
race-condition suite has been run.

## RQ4 — Memory integrity

*Does sovereign memory resist poisoning and unsupported promotion, and preserve
provenance?*

**Metrics:** Memory-Poisoning Acceptance Rate; Unsupported Promotion Rate;
Contradiction Detection Recall; Stale Memory Usage Rate; Provenance Completeness;
Deletion Effectiveness.

**Current status:** The v0.1 harness reports Provenance Completeness mean = 1.0 on
the reference scenario. Memory poisoning, unsupported promotion, contradiction
detection, stale-memory usage, and deletion effectiveness are **not** exercised in
v0.1 and remain entirely unmeasured.

## RQ5 — Adversarial robustness

*How resistant is the gateway to injection, exfiltration, schema evasion, and
resource-exhaustion attacks?*

**Metrics:** Injection Attack Success Rate; Canary Exfiltration Rate;
Schema-Evasion Acceptance Rate; Budget Violation Rate; Circuit-Breaker Activation
Accuracy.

**Current status:** The gateway blocks the single crafted injection string in the
slice (direct + indirect + egress canary), and the harness reports Canary
Exfiltration Rate = 0 (Wilson 95% CI upper bound ≈ 0.16 at n=20). The injection
detector is **pattern-based and incomplete**. Injection Attack Success Rate over a
large adversarial corpus, Schema-Evasion Acceptance Rate, sustained Budget
Violation, and Circuit-Breaker accuracy are unmeasured.

## RQ6 — Operational cost

*What is the latency, throughput, and storage overhead of the control plane?*

**Metrics:** Authorization p50/p95/p99; Context-broker p50/p95/p99; Capability
issuance throughput; Revocation propagation latency; Storage overhead;
Evidence-envelope overhead; End-to-end task latency.

**Current status:** The v0.1 harness reports authorization p99 ≤ ~0.08 ms in an
**in-memory, single-process** setting (n=20). This is not representative of a
persistent deployment. Broker latency percentiles, issuance throughput, revocation
propagation latency, storage/evidence overhead, and end-to-end task latency under
load are unmeasured.

## RQ7 — Interoperability

*Can heterogeneous agents and models interoperate through the protocol with
consistent policy semantics?*

**Metrics:** Protocol Conformance Rate; Semantic Consistency Rate; Cross-model
Policy Consistency; Adapter Development Effort; Deployment Portability.

**Current status:** Marked **N/A in v0.1** — a single simulated model and a single
agent framework are present, so cross-model and cross-agent consistency cannot be
measured. Protocol schemas (CIP-002/004/007) exist and are validated at the
boundary, but Protocol Conformance Rate across independent implementations,
Semantic Consistency, Adapter Development Effort, and Deployment Portability are
unmeasured.
