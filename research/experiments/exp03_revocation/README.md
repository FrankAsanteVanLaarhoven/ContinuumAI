# exp03 — Revocation

**Answers:** RQ1 (authorization correctness — revocation) and the revocation
components of RQ3.

**Maturity:** Research prototype v0.1 (commit `3f038fd`).

**Hypothesis:** Revocation terminates active authority: once a capability is
revoked, no subsequent use — including concurrent and post-restart use — is
accepted.

**Baselines compared:** B3 Continuum with the revocation registry enabled vs. the
ablation C–Revocation (registry removed). B0–B2 have no capability model and serve
as context.

**Metrics collected:** Revoked Capability Acceptance Rate, revocation propagation
latency, and (once persistence lands) durability of revocation across process
restart.

**Procedure outline:**
1. Issue a holder-bound capability, then revoke it.
2. Attempt reuse immediately, under concurrency (racing use against revocation), and
   after a simulated restart.
3. Record acceptance/denial and propagation latency across multiple seeds.
4. Report rates with Wilson 95% intervals and N.

**Note:** persistent, concurrent revocation requires the in-progress persistence
tier; v0.1 provides in-memory preliminary evidence only.

**Status: planned — not yet run.**
