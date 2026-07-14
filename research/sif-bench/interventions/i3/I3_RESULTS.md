# Intervention I3 — point-of-use authorization freshness (matched-arm result)

I3 closed the four tested **GAP-3** staleness dimensions — a capability is an
authority snapshot taken at issuance, and the frozen point-of-use path releases
against that snapshot even after the underlying authority state has changed — in a
bounded deterministic matched experiment. Enforcement is **opt-in by mode**, so the
frozen Stage A / Stage B / concurrency / persistence / I5 / I6 / HTTP baselines are
byte-identical (verified: core 60, persistence 14, concurrency 9, I5 7, I6 22, HTTP
11/11, all-workspace typecheck).

## What this result supports — and does not

Supported (exactly):

> Re-checking bound policy-version and consent anchors at point of use closed the
> tested consent-withdrawal and policy-version-rotation dimensions; additionally
> re-evaluating the risk ceiling and object lifecycle against current state closed
> the tested risk-tightening and object-revocation dimensions.

- I3-A reproduced the observed GAP-3 stale permits (4/4) in the deterministic matched experiment.
- Zero false denials were observed in the evaluated benign (unchanged-authority) control cases.

**Not** claimed: general revocation safety, distributed or eventually-consistent
authority propagation, real-time policy replication, a complete re-authorization at
use, or that *every* authority component is re-evaluated. I3-C re-evaluates the
**four tested dimensions** (consent, policy version, risk ceiling, object lifecycle)
— not the full authority basis. Delegation-chain revalidation, classification
re-checks, entitlement version (that is I1-C's separate mechanism), tenant re-binding,
and human-gate re-evaluation are **out of scope** for this experiment. Propagation is
modelled as an immediate in-process state change, not a replicated one; there is no
staleness-window or race evaluation.

## The gap, precisely

A Sovereign Capability Token (CIP-004) is a **TTL-bounded snapshot** of the authority
that existed at issuance. `verifySCT` re-checks signature, expiry, revocation,
audience, and proof-of-possession at use — but **not** whether the authority the
snapshot encodes is still current. Within the (short) TTL window the snapshot is
therefore honoured even if consent was withdrawn, the risk ceiling was tightened,
the policy version was rotated, or the target object was revoked/deleted **after**
issuance. This undermines the revocation/freshness guarantee: revocation of the
*underlying authority* (as distinct from revoking the token handle) does not
terminate an already-issued capability until it expires.

Target invariant: at point of use, a capability is honoured only if the authority
it asserts is **still valid against current state** — consent still granted, policy
version unrotated, the risk gate still satisfied, and every referenced object still
live.

## Freshness anchors and re-evaluation

- **Bound anchors (issuance).** When a freshness mode is active, the token additionally
  carries `freshness_policy_version` (the store policy version at issuance) and
  `freshness_consent_digest` = `digestOf({present, granted, basis, valid_until})` over
  the owner+purpose consent record. These fields are **absent** unless a freshness mode
  issued the token, so a token issued with `mode=off` has an identical canonical form
  and signature to the frozen baseline.
- **Version re-check (both `version` and `transactional`).** At use, the bound
  policy version is compared to the current `config.policy_version`, and the bound
  consent digest is recomputed from current consent and compared. A mismatch denies
  (`policy_version_stale` / `consent_stale`).
- **Transactional re-evaluation (`transactional` only).** Additionally, the intent's
  `risk_score` is re-tested against the **current** `config.risk_threshold`
  (`risk_ceiling_stale`), and every `token.resources` id is re-checked for
  revocation/deletion in current memory state (`object_lifecycle_stale`).

`version` deliberately binds only *anchored* facts (things digested into the token);
`transactional` deliberately re-runs *live* evaluation against mutable state. The
two-step ladder isolates "detect that the snapshot's inputs changed" from "re-decide
against current state."

## Reproducibility record

| Field | Value |
|-------|-------|
| Frozen baseline commit | `a2c1367` (before-picture; arms measured against it) |
| Intervention | introduced in the I3 commit on this branch (opt-in `freshnessMode`) |
| Determinism source | fixed logical clock `now_ms = 1784030400000` (`2026-07-14T12:00:00.000Z`); no PRNG in the control-plane authorization path |
| Trials | 1 per arm per dimension (single deterministic run) |
| Environment | single process, in-memory engine; no PostgreSQL, no live model |
| Regeneration | `npm run intervention:i3` |
| Machine-readable output | `research/sif-bench/interventions/i3/report.json` (gitignored; rebuilt via the reproduction command above) |

### Arm configuration (the only variable changed across arms)

| Arm | `freshnessMode` | Mechanism |
|-----|-----------------|-----------|
| I3-A | `off` | frozen snapshot; no point-of-use re-evaluation (baseline) |
| I3-B | `version` | re-check bound policy version + consent digest at use |
| I3-C | `transactional` | version re-check **+** re-evaluate risk ceiling and object lifecycle against current state |

### Inputs (identical across arms)

- **Owner:** `did:continuum:enterprise:acme:owner`; **agent:**
  `spiffe://acme.ai/agents/procurement-agent`; tenant `t_acme`; purpose
  `supplier_quote_comparison`; `risk_score = 0.12`.
- **Benign capability:** issued from an unmodified procurement intent releasing
  `mem_q_apex`. Each probe issues this capability, then applies exactly one staleness
  mutation (or none, for the control), then discloses.
- **Four staleness dimensions (one mutation each, applied post-issuance):**
  - `consent_withdrawn` — set the owner+purpose consent `granted = false`.
  - `policy_ceiling_tightened` — set `config.risk_threshold = 0` (benign `0.12` now exceeds it).
  - `policy_version_rotated` — set `config.policy_version = "policy-2026.99.0-rotated"`.
  - `object_revoked` — set `mem_q_apex.revocation_state = "revoked"`.
- **Benign control:** the same issuance with **no** mutation — must still release
  under every arm (a stale permit is the fault; denying the unchanged capability
  would be a false deny).

### Expected vs observed (stale permit = point-of-use path still released)

| Dimension | I3-A (off) | I3-B (version) | I3-C (transactional) |
|-----------|-----------|----------------|----------------------|
| consent_withdrawn | **permit** | denied `consent_stale` | denied `consent_stale` |
| policy_ceiling_tightened | **permit** | **permit** (not anchored) | denied `risk_ceiling_stale` |
| policy_version_rotated | **permit** | denied `policy_version_stale` | denied `policy_version_stale` |
| object_revoked | **permit** | **permit** (not anchored) | denied `object_lifecycle_stale` |
| **Stale permits (of 4)** | **4** | **2** | **0** |
| Benign control released | ✓ | ✓ | ✓ |
| False deny | 0 | 0 | 0 |

All observed values match expected. `passed = true`.

## Causal reading (why this is a clean ablation)

- **I3-A reproduces GAP-3** — with no re-evaluation, all four post-issuance authority
  changes are ignored and the stale snapshot is honoured (4/4). The intervention is
  measured against an intact baseline.
- **I3-B changes only anchor re-checking** — it detects that a *digested* input
  changed (consent digest, policy version) and denies those two, but is **necessary
  but insufficient**: a tightened risk ceiling and a revoked object are not anchored
  facts, so B still permits them (2/4). This isolates "anchor drift detection" from
  "live re-evaluation."
- **I3-C adds live re-evaluation** — re-testing the risk gate and object lifecycle
  against current state closes the remaining two (0/4), without denying the unchanged
  benign capability.
- All four dimensions and the benign control are evaluated under all three arms; the
  original system remains available through `mode=off`; the frozen hashes/signatures
  are unchanged; I1/I2/I5/I6 are not mixed in.

## Relationship to I1-C

I1-C binds and re-checks the **entitlement** version; I3 binds and re-checks the
**policy** version and **consent**, and re-evaluates the **risk ceiling** and **object
lifecycle**. They are complementary point-of-use freshness mechanisms and, per the I1
architectural note, both are partial steps toward a production digest that covers the
**complete** authority basis (principal entitlements, owner delegation, purpose policy,
consent, resource policy, classification, tenant, agent identity, and policy version),
so that a capability becomes invalid when **any** security-relevant component changes.
Unifying these into a single authority digest is deferred to a later, separately
evaluated intervention.

## Bounded-scope limitations

Four demonstrated staleness dimensions; one deterministic synthetic scenario; a single
benign control; single-process, single-trial, in-memory engine (no PostgreSQL, no live
model, no B0–B3). Authority-state propagation is an immediate in-process mutation, not
a replicated or eventually-consistent one — there is no staleness-window, no
propagation-latency, and no concurrent-update race evaluation. Re-evaluation covers
consent, policy version, risk ceiling, and object lifecycle only; delegation chains,
classification, entitlement version (I1-C's mechanism), tenant re-binding, and
human-gate state are held constant and not re-evaluated. The action state machine,
authorization core, tenant binding, entitlement (I1), metadata (I2), tenant identity
(I5), and idempotency (I6) are unchanged.

## Next

GAP-3 is the only remediated gap in this commit, and only under the evaluated
four-dimension staleness model. GAP-4 (proof-of-possession replay) remains open for its
own separately evaluated matched intervention.
