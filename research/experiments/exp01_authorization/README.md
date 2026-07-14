# exp01 — Authorization Correctness

**Answers:** RQ1 (authorization correctness).

**Maturity:** Research prototype v0.1 (commit `3f038fd`).

**Hypothesis:** The intent-bound policy decision point admits exactly the authority
intended and no more — it does not permit should-deny requests (`V_C < V_B`), does
not deny should-permit requests, and rejects replayed, expired, and revoked
capabilities.

**Baselines compared:** B0 direct agent access, B1 standard RAG, B2 RBAC-protected
RAG, B3 Continuum. Ablations: C–Intent, C–PoP.

**Metrics collected:** False Permit Rate, False Deny Rate, Replay Acceptance Rate,
Expired Capability Acceptance Rate, Revoked Capability Acceptance Rate, Delegation
Escape Rate (delegation not modelled in v0.1 — recorded as N/A).

**Procedure outline:**
1. Construct a labelled request corpus (should-permit / should-deny) over the
   procurement and knowledge-work workloads across multiple seeds.
2. For each configuration, submit every request and record the permit/deny decision
   with its full check list.
3. Replay each issued capability, re-use an expired one, and re-use a revoked one;
   record acceptance.
4. Compute rates with Wilson 95% intervals; report N.

**Status: planned — not yet run.**
