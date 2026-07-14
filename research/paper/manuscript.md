# Continuum: Intent-Bound Context Disclosure and Verifiable Agency for Sovereign AI Systems

**Author:** Frank Asante Van Laarhoven

**Maturity:** Research prototype v0.1 — complete in-memory vertical slice + model
gateway, preliminary conformance tests. Latest commit `3f038fd`. Two commits, no
tagged release, no published package.

**Claim boundary (normative):** Continuum minimises disclosure and constrains
authorization within an explicitly defined threat model. It does not claim that
leakage is impossible, nor production/enterprise security, nor superiority over
existing systems, nor model-independence. See
[`../../docs/CLAIMS.md`](../../docs/CLAIMS.md). This manuscript is a **skeleton**:
stable sections are filled from the reference implementation; sections marked
`[PENDING EXPERIMENTS]` await baselines B0–B3 (`experimental_protocol.md`).

---

## Abstract  `[PENDING EXPERIMENTS]`

*Deferred until baseline experiments (B0–B3) have been run and analysed. Writing the
abstract before results would require asserting outcomes not yet measured; see
`claim_evidence_matrix.md`.*

---

## 1. Introduction

AI agents increasingly obtain private context and take consequential actions on
behalf of owners. Two dominant patterns govern this today: **direct agent access**,
where an agent reads a context store and acts with little constraint, and
**retrieval-augmented generation (RAG)**, where relevant context is retrieved and
supplied to a model. Neither pattern binds the *authority* an agent exercises to a
declared, machine-verifiable *intent*, and neither systematically minimises the
sensitive context disclosed to reach a result. The result is over-disclosure of
private data and under-governed action.

This paper describes **Continuum**, an owner-controlled control plane that binds
context disclosure and agent action to explicit intent, releases the
minimum-necessary context, and records every release and action in a
tamper-evident ledger. We formalise the problem and the permit invariant
(Section 2), position the design against prior mechanisms (Section 3), describe the
five-plane architecture (Section 4), the Continuum Interchange Protocol
(Section 5), and the security model (Section 6), and specify SIF-Bench, a
reproducible evaluation framework (Section 7). The comparative evaluation
(Sections 9–10) is pending and predeclared in `experimental_protocol.md`.

The contribution is a *design-and-measurement* contribution stated at a narrower
defensible boundary (`contributions.md`); it does **not** assert superiority over
prior systems, which requires the baselines B0–B3.

## 2. Problem Formulation

We consider an owner (a principal in a tenant) who wishes an agent to accomplish a
task using private context, subject to purpose, scope, risk, and consent
constraints. Let the agent's request be evaluated against these constraints. We
define authorization as a conjunction that defaults to **deny**:

```
Permit = I_v ∧ P_a ∧ S_a ∧ P_s ∧ R_l ∧ C_c ∧ E_s ∧ T_i
```

where each conjunct is a mandatory check:

| Symbol | Check |
|--------|-------|
| `I_v` | **Identity valid** — the principal and actor are authenticated and attested. |
| `P_a` | **Purpose allowed** — the declared purpose is within the intent envelope. |
| `S_a` | **Scope allowed** — the requested operations and resources are within scope. |
| `P_s` | **Policy satisfied** — the deny-by-default policy decision point admits the request. |
| `R_l` | **Risk within limit** — the assessed risk is within the declared threshold. |
| `C_c` | **Consent current** — required consent exists and has not expired. |
| `E_s` | **Evidence sufficient** — the evidence required by the intent is present. |
| `T_i` | **Tenant isolation** — the request stays within its tenant boundary. |

`T_i` is a **hard condition**: it sits above the policy conjunction and, if it
fails, the request is denied irrespective of the other checks. The default result
is deny; `Permit` becomes true only when every mandatory check passes, and every
allow *and* every deny carries its full check list for audit. This mirrors the
implemented invariant in [`../../docs/architecture.md`](../../docs/architecture.md).

Two quantities the paper seeks to reduce follow from this formulation:
**disclosure** `D` (the sensitive/unnecessary context released to reach a result)
and **violation rate** `V` (authority exercised outside the permitted path), while
preserving **task utility** `U`. These are formalised as hypotheses in
`hypothesis.md`.

## 3. Related Work

*Organised by mechanism, not by company or product. This section situates
Continuum among established techniques; a full survey and citations are to be
completed.*

- **Agent memory.** Mechanisms for giving agents durable state across turns and
  sessions, and the disclosure risks of unconstrained memory read/write.
- **Long-term / episodic memory.** Consolidation, promotion, and retrieval of
  episodic and semantic memory; provenance and staleness concerns.
- **Retrieval-augmented generation (RAG).** Retrieval to supply context to a
  model; relevance as an implicit (and insufficient) disclosure control.
- **Agent interoperability protocols.** Emerging protocols for agent/tool/context
  interchange; conformance, versioning, and fail-closed handling of unknown fields.
- **Identity and access management (IAM).** Authentication, roles, and coarse
  access control; the gap between role-based access and per-object, intent-bound
  authorization.
- **Capability-based security.** Unforgeable, least-authority tokens; holder
  binding, non-transferability, and revocation as contrasts to bearer tokens.
- **Zero-trust architecture.** Deny-by-default, continuous verification, and
  per-request authorization.
- **Data minimisation and privacy.** Purpose limitation and minimum-necessary
  disclosure as first-class controls rather than after-the-fact redaction.
- **Confidential computing.** Trusted execution and attestation to reduce exposure
  to infrastructure operators, and its explicit limits.
- **AI agent governance.** Policy, approval gates, and oversight of consequential
  agent actions.
- **Prompt-injection defences.** Direct and indirect (retrieved-context) injection,
  and the incompleteness of pattern-based screening.
- **Provenance and tamper-evident logging.** Hash-chained, signed ledgers for
  post-hoc reconstruction and audit.

## 4. System Architecture

Continuum is a five-plane control plane (see
[`../../docs/architecture.md`](../../docs/architecture.md)). The `ContinuumEngine`
is the orchestration facade; every operation threads a single evidence ledger.

| Plane | Responsibility |
|-------|----------------|
| A · Identity & Trust | principals, tenancy, attestation, holder keys |
| B · Intent, Policy & Authority | intent envelopes, deny-by-default PDP, capability tokens, revocation |
| C · Sovereign Memory & Knowledge | memory objects + provenance, minimum-disclosure broker |
| D · Agent, Model & Tool Execution | model gateway (allowlist, heuristic injection screening, egress canary, budget, output-schema), action state machine, human gate |
| E · Evidence, Observability & Governance | hash-chained signed ledger, metrics |

The reference vertical slice runs end to end: an owner and agent authenticate; the
agent submits a CIP-002 intent (schema-validated, fail-closed); the policy decision
point evaluates ten candidate memory objects and permits two; the broker computes
the minimum disclosure, redacts the sensitive `bank_iban` field, and emits a
digest; a holder-bound CIP-004 capability (Ed25519, short TTL, proof-of-possession)
is issued; the agent proves possession and the model gateway releases only the
permitted context; the gateway allows a screened, budgeted, schema-validated model
call and blocks a prompt-injection attempt (direct, indirect, and egress canary);
the agent proposes an external action that is blocked at the human gate; the owner
approves and the tool gateway executes (**simulated**), reaching a succeeded state;
every step appends a signed, hash-chained CIP-007 evidence envelope; the capability
is revoked and reuse is denied; and a cross-tenant probe is blocked by isolation.

The v0.1 store is **in-memory and single-process**. Persistence (PostgreSQL,
object storage, an append-only event store), workload identity, customer-managed
keys, durable revocation, and database-enforced tenant isolation are on the
roadmap and **in progress**.

## 5. Continuum Interchange Protocol (CIP)

The protocol is specified independently of the reference implementation so that
conformance is independently testable; vendor and infrastructure choices are not
part of the protocol (see [`../../protocol/README.md`](../../protocol/README.md)).
The stable core in v0.1:

- **CIP-002 Intent Envelope** — a machine-verifiable statement of purpose,
  requested/prohibited operations, constraints (maximum data classification,
  geographic boundary, validity window, maximum cost), and required evidence. It is
  **not** free-form prompt text.
- **CIP-004 Sovereign Capability Token** — a short-lived, **holder-bound**,
  non-transferable grant. It carries the exact permitted resources (never a
  wildcard scope), the holder public key that possession must be proved against,
  issue/expiry times, a nonce, and a revocation handle. It **must** be verified with
  proof-of-possession and **must not** be treated as a bearer token.
- **CIP-007 Evidence Envelope** — one append-only, hash-chained, signed audit
  record storing identifiers and digests only, never plaintext secrets. Each record
  chains `hash = sha256(prev_hash + canonicalJson(body))` and is Ed25519-signed.

Versioning is `major.minor.patch`; every request advertises supported versions;
**unknown mandatory fields MUST fail closed** (enforced by strict schema parsing);
and conformance MUST be independently testable. Normative language follows
RFC 2119.

## 6. Security Model

The threat model (see [`../../docs/threat-model.md`](../../docs/threat-model.md))
lists adversaries and the control that answers each, verified by the core test
suite. In scope for the reference slice: over-broad agent requests
(deny-by-default PDP + the Permit invariant); cross-tenant access (the hard tenant
isolation gate); capability theft/replay (holder binding + proof-of-possession);
expired and revoked capability reuse (TTL and revocation checks); token tampering
(Ed25519 over the canonical token); confused-deputy/excess scope (per-object scope
and prohibited-operation checks); stale consent; unapproved agent/model
(allowlists, fail-closed); sensitive-field leakage and over-disclosure (broker
redaction and minimum-necessary release); prompt injection, both **direct** and
**indirect via retrieved context** (gateway screening of prompt *and* context);
denial-of-wallet (token/cost budget); unapproved egress (region and classification
checks); canary egress (egress canary detection); malformed model output
(output-schema validation and quarantine); audit-log tampering (hash-chained signed
ledger with chain verification); and prohibited high-consequence actions (action
state machine + human gate).

Explicitly **not** covered by v0.1: side-channel leakage, endpoint capture,
malicious platform administrator, persistence-tier compromise, denial-of-wallet
against real providers, dependency supply-chain compromise, and semantic leakage
through model outputs. These are named so the boundary is honest, and they require
the production tiers on the roadmap. The injection screen is **pattern-based and
heuristic** — it raises attacker cost and catches known patterns but is not a
complete defence — and the model itself is **simulated**. No claim of absolute
confidentiality is made.

## 7. SIF-Bench

SIF-Bench is a reproducible evaluation framework for owner-controlled
intent/authorization fabrics (see [`../sif-bench/README.md`](../sif-bench/README.md)).
The v0.1 harness is an **internal consistency and invariant harness** over the
reference slice; it is deliberately scoped and reports that scope, and it is **not**
a validated external or industry benchmark.

The harness drives the running control plane and measures milestone tracks: intent
fidelity (prohibition-violation and human-gate-bypass rates, gateway injection-block
rate), disclosure minimisation (excess-disclosure ratio and reduction versus a
naive baseline internal to the harness), leakage resistance (canary-exfiltration
rate with a Wilson 95% interval), authorization correctness (false-permit,
false-deny, cross-tenant, and revocation-failure rates), memory integrity
(provenance completeness), agent interoperability (**N/A in v0.1** — single provider
and framework), and operational resilience (authorization p99 and evidence-chain
validity). Every report records sample size, environment, versions, confidence
intervals, and residual risk. "Zero observed events" is **not** treated as proof of
impossibility.

The full comparative design — baselines B0–B3, the eight required ablations, the
three workload families, the statistical protocol, and the run manifest — is
specified in `experimental_protocol.md`.

## 8. Experimental Setup

Baselines: **B0** direct agent access, **B1** standard RAG, **B2** RBAC-protected
RAG, **B3** Continuum. Ablations: C–Intent, C–PoP, C–Redaction, C–Revocation,
C–HumanGate, C–Provenance, C–Injection, C–Budget. Workload families: enterprise
procurement (Orion/Apex quote comparison; sensitive fields = bank data, negotiated
rates, internal budget), enterprise knowledge work (policy Q&A under purpose
constraints, resisting document-embedded injection), and a consequential workflow
(finance/HR/healthcare/infrastructure change with **simulated** execution and
realistic state transitions). Multiple seeds; report N; Wilson 95% intervals for
proportions; predeclared `ε`; per-RQ analysis. See `experimental_protocol.md` for
the predeclared protocol and the run manifest. *These experiments have not yet been
run.*

## 9. Results  `[PENDING EXPERIMENTS]`

*Deferred. No B0–B3 comparison has been run. The v0.1 harness provides
single-configuration consistency measurements only, which are not evidence for or
against any comparative hypothesis. Populate only from admissible runs whose
manifests are complete and whose evidence chains verify; report every metric with N
and a confidence interval; escalate a claim's strength only per
`claim_evidence_matrix.md`.*

## 10. Failure Analysis  `[PENDING EXPERIMENTS]`

*Deferred. To be written from observed failures across the baselines and ablations
(false permits/denies, gate bypasses, injection successes, schema evasions, chain
verification failures), with root-cause attribution to the removed or absent
component.*

## 11. Discussion

*To be expanded after results.* The design position is that binding authority to
declared intent and releasing minimum-necessary context are complementary controls:
the first governs *action*, the second governs *disclosure*, and a tamper-evident
ledger makes both auditable. Whether these controls reduce disclosure and violations
at acceptable utility and latency cost — and by how much relative to B0–B3 — is the
empirical question the pending experiments must answer. The discussion will also
weigh the cost of the control plane (RQ6) against its governance benefits, and the
incompleteness of heuristic injection screening (RQ5).

## 12. Limitations

Synthetic workloads; simulated tool execution; a single simulated model (no
model-independence claim); a heuristic, incomplete injection detector; no formal
verification; no independent red team; no longitudinal user study; no evidence of
network effects; no absolute confidentiality guarantee; an in-memory→persistence
transition in progress; and SIF-Bench as an internal conformance harness rather
than a validated external benchmark. See `limitations.md` for the full statement.

## 13. Conclusion  `[PENDING EXPERIMENTS]`

*Deferred until results and failure analysis are complete. No concluding claim of
effectiveness or advantage may be written before the baselines are measured.*

---

## References

*To be completed. Related work is organised by mechanism in Section 3; citations
will be added there.*
