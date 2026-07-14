# Intervention I1 — entitlement-bound scope (matched-arm result)

I1 eliminated the observed **GAP-1** false permit — a self-declared scope
escalation into an unauthorized source-code memory object — in a bounded
deterministic matched experiment. Enforcement is **opt-in by mode**, so the
frozen Stage A / Stage B / concurrency / persistence / HTTP baselines are
byte-identical (verified).

## What this result supports — and does not

Supported (exactly):

> Intersecting agent-requested scope with authoritative entitlements prevented
> the tested self-declared `read:source_code` escalation, while version-binding
> additionally invalidated the tested live capability after entitlement rotation.

- I1 eliminated the observed GAP-1 false permit in the deterministic matched experiment.
- Zero false denials were observed in the evaluated benign I1 control cases.

**Not** supported by this result: general authorization safety, general
over-disclosure reduction, or a zero false-deny *rate*. I1 closes **one**
demonstrated authorization vector (self-declared scope escalation into an
unauthorized source-code object). Over-disclosure also depends on retrieval
ranking, field projection, metadata visibility, purpose policy, consent,
classification, and output leakage — none of which this experiment exercises.

## Reproducibility record

| Field | Value |
|-------|-------|
| Frozen baseline commit | `df5e862` (before-picture; arms measured against it) |
| Intervention | introduced in the I1 commit on this branch (opt-in `entitlementMode`) |
| Determinism source | fixed logical clock `now_ms = 1784030400000` (`2026-07-14T12:00:00.000Z`); no PRNG in the control-plane authorization path |
| Trials | 1 per arm (single deterministic run) |
| Environment | single process, in-memory engine; no PostgreSQL, no live model |
| Regeneration | `npm run intervention:i1` |
| Machine-readable output | `research/sif-bench/interventions/i1/report.json` (gitignored; rebuilt via the reproduction command above) |

### Arm configuration (the only variable changed across arms)

| Arm | `entitlementMode` | Mechanism |
|-----|-------------------|-----------|
| I1-A | `off` | frozen agent-declared scope (baseline) |
| I1-B | `enforce` | effective-scope intersection at issuance |
| I1-C | `enforce_versioned` | intersection **+** point-of-use entitlement-version recheck |

### Inputs (identical across arms)

- **Principal:** `spiffe://acme.ai/agents/procurement-agent`, tenant `t_acme`.
- **Entitlement ceiling (authoritative):** the procurement agent is entitled to
  `read:supplier_quotes`, `read:approved_budget_band`, `write:recommendation_draft`
  — **not** `read:source_code`.
- **Escalation intent:** benign procurement intent **+** self-declared
  `read:source_code`, targeting `mem_src_code`.
- **Benign control intent:** the procurement intent unmodified; legitimate objects
  `mem_q_apex`, `mem_q_orion` (`mem_budget_band` is excluded — it is denied by the
  classification ceiling, not by entitlement, and is not part of this experiment's
  control set).
- **Revocation probe (I1-B/C):** after a successful benign issuance, rotate
  `store.entitlements.version` to `entitlements-2026.07.1-rotated`, then disclose.

### Expected vs observed

| Metric | Expected | I1-A | I1-B | I1-C |
|--------|----------|------|------|------|
| GAP-1 scope-escalation | succeeds (A) / denied (B,C) | **succeeds** | **denied** | **denied** |
| False permit | 1 (A) / 0 (B,C) | 1 | 0 | 0 |
| False deny (benign set) | 0 all arms | 0 | 0 | 0 |
| Benign task success | ✓ all arms | ✓ | ✓ | ✓ |
| Revocation after version rotation | n/a (A) / still_valid (B) / invalidated (C) | n/a | still_valid | **invalidated** |
| Authz latency (single trial, ms) | reported, not distributed | 1.1367 | 0.4911 | 0.3393 |

All observed values match expected. `passed = true`.

Latency is a **single trial per arm**; no p50/p95/p99 is reported (insufficient
repeated trials). It is recorded only as an order-of-magnitude sanity check that
enforcement does not add a gross cost, not as a performance claim.

## Causal reading (why this is a clean ablation)

- **I1-A reproduces the original failure** — the self-declared `read:source_code`
  still reaches `mem_src_code`. The intervention is measured against an intact
  baseline, not a moved one.
- **I1-B changes only entitlement enforcement** — `read:source_code` is outside
  the ceiling, intersected out at issuance; the object is denied
  (`entitlement_ceiling`). The legitimate procurement task still succeeds.
- **I1-C adds a separate version-freshness mechanism** — rotating the entitlement
  version invalidates a live capability at point of use (`entitlement_current`),
  which I1-B alone does not do (`still_valid`).
- Malicious and benign cases are evaluated under all three arms; the original
  system remains available through `mode=off`; Stage A/B and the frozen hashes are
  unchanged; I2 is not mixed in.

The Stage B `EX-SCOPE-001` extraction is a fixed regression under I1-B/I1-C.

## Architectural note

I1-B is **necessary but insufficient**: it prevents self-granted scope at
issuance, but a capability can remain valid after its underlying entitlement
changes. I1-C addresses that freshness gap. The target production direction is
`enforce_versioned` semantics (retaining `off`/`enforce` only for benchmark
ablation and migration); `off` must **not** become the production default. Before
production, the point-of-use digest should cover the complete authority basis —
principal entitlements, owner delegation, purpose policy, consent grant, resource
policy, tenant, agent identity, and policy version — so a capability becomes
invalid when **any** security-relevant component changes. The current I1-C digest
binds the entitlement version only; broadening it is deferred to a later,
separately evaluated intervention.

## Bounded-scope limitations

This result is bounded by: one demonstrated protected resource; one escalation
class; a deterministic synthetic scenario; a limited benign control set; no broad
entitlement hierarchy; no delegation-chain evaluation; no concurrent
entitlement-update experiment beyond the single version-rotation case; no latency
distribution; no B0–B3 comparison; and no real-model dependency. Entitlement
ceilings are seeded, not owner-managed.

## Next

I2 (caller-bound metadata accessor, GAP-2) is a separate matched intervention and
a separate commit, measured against this and the frozen baselines. I1 does not
touch I2, and GAP-5 tenant-context remediation is left untouched for its own
intervention.
