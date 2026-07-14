# Continuum — Claim Boundary

This document is normative. Marketing, documentation, papers, and the console
must not exceed it.

## The defensible claim

> Continuum minimises disclosure, cryptographically constrains authorization,
> records every release and action, supports confidential execution, and
> provides measurable leakage-resistance guarantees **within an explicitly
> defined threat model**.

## What Continuum does NOT claim

- Continuum does **not** claim that leakage is mathematically impossible. Once
  information is released to an external model, agent, human, browser, robot, or
  tool, no practical distributed system can guarantee it learns nothing.
- Zero-knowledge proofs are used only for **bounded predicates** (role
  membership, threshold satisfaction, credential validity, approved-set
  membership, policy satisfaction). They are **not** used to justify
  unrestricted private LLM inference without disclosure.
- Trusted execution environments (when added) reduce exposure to infrastructure
  operators. They do **not** eliminate side-channel risk, compromised
  application logic, malicious authorized agents, endpoint capture, semantic
  leakage through outputs, incorrect policy, or human misuse.
- Continuum does **not** claim concurrency safety, linearizability,
  serializability beyond the configured database level (read-committed), complete
  time-of-check/time-of-use resistance, or zero race conditions. The concurrency
  baseline (`research/sif-bench/concurrency`) measured the unmodified system under
  one deterministic schedule per case at a single seed with ≤ 2 workers; under
  that sample, point-of-use revocation/expiry, double-execution prevention,
  durable tenant isolation, and append-only evidence held, while authorization
  **staleness** within a capability's TTL/gate window (consent, policy version,
  object lifecycle not re-evaluated), PoP replay, app-cooperative RLS re-keying,
  and idempotency were open gaps. Absence of a finding is bounded by that sample.

## Evidence discipline

"Zero observed events" is **not** proof of impossibility. Every benchmark result
must report sample size, attack coverage, environment, model/agent/policy
versions, confidence interval, and residual risk. See `research/sif-bench`.

## Scope of the v0.1 reference implementation

The v0.1 slice demonstrates the control-plane invariants with an **in-memory,
in-process** store. It is explicitly **not** the production persistence,
key-custody, or deployment tier. Its guarantees hold for the threat model in
`docs/threat-model.md` under the stated assumptions, and no further.
