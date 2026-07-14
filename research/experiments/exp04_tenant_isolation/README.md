# exp04 — Tenant Isolation

**Answers:** the tenant-isolation hard condition `T_i` in the permit invariant
(cross-cutting RQ1).

**Maturity:** Research prototype v0.1 (commit `3f038fd`). Isolation is currently
**logical** (application-enforced); database/row-level-security enforcement is **in
progress**.

**Hypothesis:** No request or artefact crosses a tenant boundary: cross-tenant
reads, cache reads, vector reads, and backup reads are all denied.

**Baselines compared:** B3 Continuum. B0–B2 as context (they have no first-class
tenant gate).

**Metrics collected:** Cross-Tenant Leak Rate across the database, cache, vector,
and backup surfaces.

**Procedure outline:**
1. Provision two tenants with disjoint data.
2. From tenant A, probe tenant B via each surface (direct read, cache, vector index,
   backup/restore path).
3. Record any leakage; compute rates with Wilson 95% intervals over multiple seeds.
4. Re-run once database/RLS enforcement lands to compare logical vs. database-enforced
   isolation.

**Note:** v0.1 provides a **logical probe only** (a single cross-tenant probe in the
slice); the database, cache, vector, and backup tests require the in-progress
persistence tier.

**Status: planned — not yet run.**
