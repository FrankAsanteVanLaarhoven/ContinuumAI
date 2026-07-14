# Contributions

**Maturity:** Research prototype v0.1 (commit `3f038fd`). This document states the
research contributions at their **narrower defensible boundary**. Superiority over
existing systems is **not** demonstrated and is not claimed here.

## The narrower defensible contribution

> Continuum introduces an intent-bound control plane for minimum-necessary context
> disclosure and policy-governed agent action, together with a reproducible
> benchmark that measures authorization correctness, disclosure minimisation,
> memory integrity, revocation, provenance, and action governance across
> heterogeneous agents and models.

This is a *design-and-measurement* contribution. It does not assert that Continuum
outperforms any prior system, nor that it eliminates leakage. Establishing
comparative advantage requires the baselines B0 (direct), B1 (standard RAG),
B2 (RBAC-RAG), and B3 (Continuum) defined in `experimental_protocol.md`; those
experiments have not yet been run.

## The three research artefacts

### 1. The Continuum architecture

A five-plane control plane with an **intent-bound control plane** at its centre:

- **Plane A — Identity & Trust:** principals, tenancy, attestation, holder keys.
- **Plane B — Intent, Policy & Authority:** machine-verifiable intent envelopes,
  a deny-by-default policy decision point, holder-bound capability tokens, and
  revocation.
- **Plane C — Sovereign Memory & Knowledge:** memory objects with provenance and a
  minimum-disclosure context broker.
- **Plane D — Agent, Model & Tool Execution:** a model gateway (allowlist,
  heuristic injection screening, egress canary, budget, output-schema validation),
  an action state machine, and a human gate.
- **Plane E — Evidence, Observability & Governance:** a hash-chained, signed
  evidence ledger and metrics.

Authority is granted only when intent, policy, scope, risk, consent, and evidence
all agree, with tenant isolation as a hard precondition. See
[`../../docs/architecture.md`](../../docs/architecture.md).

### 2. The Continuum Interchange Protocol (CIP)

A protocol specified independently of the reference implementation, so that
conformance is independently testable. The stable core:

- **CIP-002 Intent Envelope** — a machine-verifiable statement of purpose, scope,
  prohibitions, constraints, and required evidence (not free-form prompt text).
- **CIP-004 Sovereign Capability Token** — a short-lived, **holder-bound**,
  non-transferable grant verified by proof-of-possession, carrying exact permitted
  resources (never a wildcard scope) and a revocation handle.
- **CIP-007 Evidence Envelope** — one append-only, hash-chained, signed audit
  record storing identifiers and digests only, never plaintext secrets.

The protocol is **fail-closed** (unknown mandatory fields are rejected),
**holder-binding** (capabilities are not bearer tokens), and supports
**revocation**. See [`../../protocol/README.md`](../../protocol/README.md).

### 3. SIF-Bench — the evaluation framework

A reproducible benchmark design intended to measure authorization correctness,
disclosure minimisation, memory integrity, revocation, provenance, and action
governance across heterogeneous agents and models. The v0.1 harness is an
**internal conformance harness** over the reference slice, not a validated external
industry benchmark; it records sample size, environment, versions, confidence
intervals, and residual risk with every result. See
[`../sif-bench/README.md`](../sif-bench/README.md).

## What is explicitly not claimed

Superiority over prior systems is **not** demonstrated. The three artefacts are
offered as a coherent design and a measurement instrument; the comparative
evaluation (B0–B3 across the workload families in `experimental_protocol.md`)
remains to be conducted before any claim of advantage can be made.
