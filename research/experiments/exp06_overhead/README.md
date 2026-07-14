# exp06 — Operational Overhead

**Answers:** RQ6 (operational cost).

**Maturity:** Research prototype v0.1 (commit `3f038fd`). Current numbers are
**in-memory, single-process** and not representative of a persistent deployment.

**Hypothesis:** The control plane's latency, throughput, and storage overhead are
operationally acceptable relative to the governance it provides.

**Baselines compared:** B0 direct agent access, B1 standard RAG, B2 RBAC-protected
RAG, B3 Continuum. Ablations that remove components (e.g. C–Provenance, C–Injection)
to attribute overhead.

**Metrics collected:** Authorization p50/p95/p99, Context-broker p50/p95/p99,
Capability issuance throughput, Revocation propagation latency, Storage overhead,
Evidence-envelope overhead, End-to-end task latency.

**Procedure outline:**
1. Drive each configuration under a fixed load profile across multiple seeds.
2. Record per-stage latencies, issuance throughput, revocation propagation, and
   storage/evidence bytes per run.
3. Report medians and p50/p95/p99 with dispersion, plus the environment manifest.
4. Repeat once the persistence tier lands to obtain deployment-representative
   figures.

**Note:** the v0.1 harness reports authorization p99 ≤ ~0.08 ms in memory (n=20);
this is preliminary and not a load or throughput study.

**Status: planned — not yet run.**
