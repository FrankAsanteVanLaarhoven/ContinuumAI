# Intervention I2 — caller-bound metadata access (matched-arm result)

I2 eliminated the observed **GAP-2** IDOR — the in-memory `listMemoryMeta(tenantId)`
accessor trusts a caller-supplied tenant string, letting an Acme context enumerate
Globex object metadata — in a bounded deterministic matched experiment. I2 is an
**additive** accessor (a new `listMemoryMetaBound` method); the frozen accessor and
every Stage A / Stage B / concurrency / persistence / HTTP baseline are byte-identical
(verified). I2 does **not** touch GAP-5 (application-cooperative RLS re-key).

## What this result supports — and does not

Supported (exactly):

> Deriving tenant and principal from a verified, holder-proven capability — rather
> than trusting a caller-supplied tenant argument — prevented the tested
> cross-tenant metadata enumeration, and a minimum-field projection returned strictly
> fewer fields for the same listing task.

- I2 eliminated the observed GAP-2 cross-tenant enumeration in the deterministic matched experiment.
- Zero false denials were observed in the evaluated benign I2 control cases.

**Not** supported by this result: general tenant-isolation (that claim is carried by
the durable **RLS** path, tested separately), general over-disclosure minimisation, or
correctness of metadata visibility under classification/consent (this accessor is
tenant + operation scoped; classification and consent are enforced by the PDP at read
time, not by this listing). I2 closes **one** demonstrated vector: caller-selected
tenancy in the in-memory metadata read.

## Reproducibility record

| Field | Value |
|-------|-------|
| Frozen baseline commit | `457865e` (I1) atop `df5e862`; arms measured against it |
| Intervention | additive `listMemoryMetaBound` accessor introduced in the I2 commit on this branch |
| Determinism source | fixed logical clock `now_ms = 1784030400000` (`2026-07-14T12:00:00.000Z`); no PRNG in the accessor path |
| Trials | 1 per arm/probe (single deterministic run) |
| Environment | single process, in-memory engine; no PostgreSQL, no live model |
| Regeneration | `npm run intervention:i2` |
| Machine-readable output | `research/sif-bench/interventions/i2/report.json` (gitignored; rebuilt via the reproduction command above) |

### Arm configuration (the only variable changed across arms)

| Arm | Accessor | Projection |
|-----|----------|------------|
| I2-A | frozen `listMemoryMeta(tenantId)` | full (caller-selected tenant) |
| I2-B | caller-bound `listMemoryMetaBound` | full (IDOR closed, not minimised) |
| I2-C | caller-bound `listMemoryMetaBound` | minimal (IDOR closed + minimised) |

The bound accessor takes **no** tenant argument. Tenant and principal are derived from
a verified capability; a presenter who is not the holder, an expired/revoked token, or
a mismatched intent/purpose all fail closed; enumeration is filtered to the token's
operation scope; and the returned fields are limited to the projection.

### Expected vs observed

| Metric | Expected | I2-A | I2-B | I2-C |
|--------|----------|------|------|------|
| Foreign metadata enumeration success | true (A) / false (B,C) | **true** | **false** | **false** |
| Cross-tenant object-id disclosure | ≥1 (A) / 0 (B,C) | 1 | 0 | 0 |
| Caller–tenant binding violation | 1 (A) / 0 (B,C) | 1 | 0 | 0 |
| Capability-holder mismatch acceptance | 0 (B,C) | n/a¹ | 0 | 0 |
| Purpose-binding violation | 0 (B,C) | n/a¹ | 0 | 0 |
| False permit | 1 (A) / 0 (B,C) | 1 | 0 | 0 |
| False deny (benign) | 0 all arms | 0 | 0 | 0 |
| Benign retrieval success | ✓ all arms | ✓ | ✓ | ✓ |
| Returned fields / object (benign) | fewer for C | 23 | 23 | **3** |
| Metadata excess-disclosure ratio | lower for C | 0.87 | 0.87 | **0** |
| Evidence completeness | 1.0 (B,C) | **0**² | 1.0 | 1.0 |
| Accessor latency (single trial, ms) | reported, not distributed | 0.0154 | 0.3631 | 0.3239 |

¹ The frozen API exposes no holder/intent/purpose control — the vulnerability is the
absence of the control, not a passing result. Those probes are marked non-applicable
for I2-A. ² The frozen accessor emits no audit envelope at all (evidence completeness
0), which is itself a gap the bound accessor closes.

`passed = true`. Latency is a **single trial per arm**; no p50/p95/p99 is reported.
The excess-metadata-ratio denominator, the three task-required fields, field-counting
rules, and the opaque-handle properties (held vs deferred) are defined normatively in
[`METRICS.md`](./METRICS.md).

### Probe battery (12 cases; bound arms run all, frozen runs the 3 it can express)

`P01` foreign tenant supplied · `P02` foreign object id guessed · `P03` capability
tenant vs request tenant · `P04` principal ≠ holder · `P05` wrong intent · `P06` wrong
purpose · `P07` expired capability · `P08` revoked capability · `P09` missing
proof-of-possession · `P10` enumeration without operation-scope · `P11` durable/in-memory
agreement · `P12` benign same-tenant retrieval.

Under I2-B/I2-C all 11 malicious probes are blocked and P12 succeeds. Under I2-A only
P01/P02/P12 are expressible; P01/P02 are **not** blocked (GAP-2), P12 succeeds. `P11`
is a structural agreement check — the bound accessor returns exactly the token's
tenant, matching a tenant-scoped durable query; the full concurrent durable/in-memory
race is measured by the concurrency suite (`C3-08`), not re-litigated here.

## Causal reading (why this is a clean ablation)

- **I2-A reproduces the original failure** — `listMemoryMeta("t_globex")` from an Acme
  context returns `mem_glx_quote`. Note `mem_glx_quote` shares `read:supplier_quotes`
  with the Acme agent, so scope alone would not exclude it: the fix is the **tenant
  derivation**, not the operation filter.
- **I2-B changes only the trust source** — tenant/principal derived from the verified
  capability; the foreign object is structurally unreachable. Full projection is
  retained, so B isolates IDOR closure from minimisation.
- **I2-C adds minimum-field projection** — the same listing returns 3 fields (opaque
  handle, memory_class, classification) instead of 23, excess-disclosure ratio 0. The
  raw storage id is replaced by an opaque, per-capability handle in B's minimal/standard
  and in C, so no internal identifier enters the immutable audit chain.
- The frozen accessor stays available and unchanged; Stage A/B and the frozen hashes
  are unchanged; GAP-5 is untouched.

## Architectural note

The caller must never supply the security boundary. The target production accessor
takes an authenticated capability + holder proof and derives tenant, principal,
effective scope (I1), purpose, and the permitted projection — never a free `tenantId`.
The in-memory path now matches the durable RLS path's guarantee that a tenant argument
cannot widen authority; the durable path continues to enforce isolation independently
at the database. Broadening the metadata filter to classification/consent ceilings is a
separate, later intervention.

## Bounded-scope limitations

One demonstrated foreign object, one IDOR class, a deterministic synthetic scenario, a
limited benign control set, no broad entitlement hierarchy, no delegation-chain
evaluation, the concurrent durable/in-memory case represented structurally (full race
in the concurrency suite), no latency distribution, no B0–B3 comparison, no real model.
Metadata listing is tenant + operation scoped only; classification/consent are enforced
at read time by the PDP, not by this accessor.

## Next

GAP-5 (application-cooperative RLS re-key) is left untouched for its own separately
evaluated intervention. I2 does not touch it.
