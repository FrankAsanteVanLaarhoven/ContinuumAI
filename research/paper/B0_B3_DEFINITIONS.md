# B0–B3 Comparative Baseline Definitions (frozen)

These four system configurations are the **frozen** comparison ladder for the
principal paper result. They are defined here so the comparative harness (a later
commit) cannot silently drift. A deny-all system must **not** rank well merely by
blocking attacks: the headline result is **joint** —

> (Utility, Disclosure, SecurityViolations, Latency, Cost)

— never a security-only pass rate.

## Configurations

- **B0 — Unrestricted agent.** Full context and direct simulated tool access. No
  intent binding, no retrieval restriction, no capability, no revocation, no governed
  action state, no evidence. The permissive ceiling: maximum utility, maximum
  disclosure, maximum security violations.

- **B1 — Standard top-(k) RAG.** Conventional retrieval-augmented generation with no
  intent binding, no capability, no revocation, and no governed action state. Objects
  enter context by retrieval score alone.

- **B2 — Tenant/role-restricted RAG.** Conventional bearer authorization scopes
  retrieval by tenant and role, but there is **no** semantic intent binding, **no**
  proof-of-possession, **no** minimum projection, and **no** per-action evidence. The
  realistic enterprise baseline.

- **B3 — Continuum.** The I1–I6 target interventions (entitlement-bound scope,
  caller-bound metadata, point-of-use freshness, proof-of-possession replay
  resistance, database-bound tenant identity, idempotent action identity) plus the
  selected **I7** injection configuration (default: **I7-C**, structured separation +
  bounded decode/normalize).

## Held-identical across B0–B3 (the matched-comparison contract)

The comparison is valid only if the following are **byte-for-byte identical** across
all four configurations. The harness must assert this and record a manifest hash.

- Workloads and memory corpora.
- Retrieval candidate sets (the same objects are *available*; configurations differ
  only in what they *admit*).
- Model or deterministic surrogate.
- Tool definitions.
- Token and cost budgets.
- Benign and adversarial task sets.
- Seeds and repetitions.
- Hardware and database configuration.

## Metrics (reported jointly, per configuration)

- **Utility** — benign task success rate (correct recommendation / task completion).
- **Disclosure** — sensitive fields, cross-tenant objects, and canaries exposed.
- **SecurityViolations** — prompt-injection successes, unauthorized tool calls,
  over-scope disclosures, replayed proofs, stale-authority permits, duplicate
  executions — by family.
- **Latency** — authorization + gateway processing (and, for I7-C, decode/normalize
  overhead + expansion ratio).
- **Cost** — token/£ per completed task.

A configuration that scores high Utility with high Disclosure/Violations (B0) and one
that scores low Disclosure by refusing all work (a hypothetical deny-all) must both
be legible as **poor** on the joint frontier. The claim Continuum (B3) advances is a
**better joint position** (utility retained, disclosure and violations reduced at
acceptable latency/cost), not a single-axis win.

## Evaluation phases

1. **Deterministic first comparison** — the surrogate model, single seed set. This is
   the causal, provider-independent measurement.
2. **External-validity replication** — the *same frozen benchmark* repeated with **≥2
   real model families**, reported as a separate Stage B v0.4 layer. Real-model
   numbers never retroactively change the deterministic B0–B3 result.

## Status

Definitions frozen. The B0–B3 comparative harness and the joint-frontier result are a
**later** commit; I7 (this workstream) freezes the injection configuration that B3
will carry. No B0–B3 numbers are claimed yet.
