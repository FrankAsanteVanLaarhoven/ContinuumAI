# Claim–Evidence Matrix

**Maturity:** Research prototype — v0.1 durable data plane, plus the v0.2 Stage A
deterministic control-plane adversarial baseline (`research/sif-bench/STAGE_A_BASELINE.md`).

This matrix governs what the paper may assert. A proposed claim may appear in the
manuscript **only** at the strength its current evidence supports. "Not
established" claims must not be stated as findings; "preliminary" evidence must be
labelled as such, with its sample size, environment, and residual risk; and no row
may be escalated without the required evidence being produced under
`experimental_protocol.md`. The matrix is the single source of truth for the
paper's claim strength, subordinate to [`../../docs/CLAIMS.md`](../../docs/CLAIMS.md).

| Proposed claim | Required evidence | Current status |
|----------------|-------------------|----------------|
| Intent-bound access reduces over-disclosure | baseline comparison over multiple workloads | Not established. Stage B (v0.2) caveat: because `requested_operations` is agent-declared, an object protected **only** by scope was extracted via a crafted intent (GAP-1); purpose+consent-protected objects held. Scope alone is not a barrier against the intent's author |
| Holder binding prevents token replay | replay attack experiments | Stage A adversarial (v0.2): deterministic — bearer reuse, forged proof-of-possession, expiry, scope/tenant tamper and audience confusion all blocked at the expected check; concurrency/timing not yet exercised |
| Revocation terminates active authority | persistent concurrent revocation tests | Stage A adversarial (v0.2): in-session reuse-after-revoke deterministically blocked. Concurrency baseline: point-of-use **capability** revocation and expiry held under the tested interleavings (0 post-revocation disclosures), but authorization is a snapshot — consent/policy/object-lifecycle changes are NOT re-evaluated against a live capability within its TTL (GAP-3). Durable revocation is the separate persistence arm |
| Human gates prevent unauthorized execution | bypass and race-condition suite | Stage A adversarial (v0.2): agent self-approval, impostor-agent, cross-tenant, unknown-approver and denied-action approval all blocked; a prior self-approval gap was closed. Concurrency baseline (C2): double-execution, duplicate/foreign-tenant approval, and approving a denied action all refused under the tested race; illegal state skips rejected. Gaps: an approved action is not re-validated against a rotated policy at execution (GAP-3), and client-supplied action ids are not idempotent (GAP-6) |
| Context broker preserves utility | task success vs disclosure analysis | Not established |
| Evidence chain enables reconstruction | restart, tamper and restore experiments | Database-enforced (v0.1) + Stage A adversarial (v0.2): re-verifies after a fresh connection and a logical restore; four in-process tamper classes (content, link, re-sign, splice) each detected at the expected seq; full physical restart/pg_restore still pending |
| Tenant isolation holds | database, cache, vector and backup tests | Database RLS-enforced (v0.1): direct-query, missing-context, forged-id and evidence isolation tested. Stage B (v0.2): cross-tenant object **content** held under crafted intents, but the in-memory engine's `listMemoryMeta(tenantId)` read accessor is **not caller-bound** and enumerated a foreign object id (GAP-2) — isolation of in-memory metadata currently depends on the API layer; the durable RLS path enforces it independently. cache/vector/full-backup isolation pending |
| Gateway reduces injection success | large attack corpus and ablation | Stage B measured (v0.2), screen-permeability only: the current heuristic lowers attack success from ~0.93 (no screen) to ~0.57, but is bypassed by base64, homoglyph, letter-spacing, multilingual, hidden-text and fake-system payloads; benign FPR 0.0. Characterised as a weak blocklist, NOT an injection defence; structured instruction/data separation (arm C/D) and a live-model harness remain to be built |
| Continuum is model-independent | multiple real model/provider evaluations | Not established |
| Overhead is operationally acceptable | load, latency and throughput study | Not established |

## Reading the statuses

- **Not established** — no admissible evidence yet; the paper may state the claim
  only as a hypothesis or an open question.
- **Preliminary local evidence** — supported by unit/slice tests in the in-memory
  prototype; requires persistent, concurrent, or adversarial confirmation before it
  may be stated as a result.
- **Preliminary simulated evidence** — observed against simulated execution only;
  requires a race-condition and bypass suite.
- **Database RLS-enforced (v0.1)** — enforced by PostgreSQL row-level security
  (enable + force), keyed on a transaction-local tenant setting, with fail-closed
  behaviour on missing context and `WITH CHECK` on writes; verified by the
  `@continuum/persistence` suite against a real embedded Postgres. Cache, vector,
  and full physical-backup isolation remain to be tested.
- **Database-enforced (v0.1)** — the authoritative rows are durable and the
  evidence hash chain re-verifies from storage after a fresh connection and after
  a logical restore; not yet exercised under a full cluster stop/start or a
  physical (pg_dump/pg_restore) cycle.
- **Stage A adversarial (v0.2)** — exercised by the deterministic control-plane
  adversarial suite (`research/sif-bench/STAGE_A_BASELINE.md`): every attack is a
  fixed construction that must be blocked *and* fail for the expected reason, with
  positive controls guarding against over-blocking. It is single-process and
  deterministic: it does **not** establish concurrency/timing, persistence-tier,
  or any model/corpus behaviour.
- **Concurrency baseline (v0.2)** — measured by the SIF-Bench concurrency /
  TOCTOU suite (`research/sif-bench/concurrency/CONCURRENCY_BASELINE.md`) against
  the unmodified system: one deterministic schedule per case, seed `0xC0FFEE`,
  ≤ 2 workers, real PostgreSQL for the durable races. Records both held results
  and 10 gaps (GAP-1..6). Not a randomized-schedule fuzzer; "zero observed"
  carries this sample context, not a proof of concurrency safety.
- **Stage B measured (v0.2)** — measured against the corpus-driven adversarial
  suite (`research/sif-bench/stage_b/STAGE_B_FINDINGS.md`) with **no live model**:
  prompt-injection figures are screen permeability (an upper bound on real attack
  success), and structural results are exact for the seeded data paths under a
  single process. Records failures, including two open control-plane gaps (GAP-1
  scope self-declaration, GAP-2 uncaller-bound in-memory metadata read).
- **One/few heuristic cases** — the pattern-based screen blocks known cases;
  requires a large adversarial corpus and an ablation to characterise.
