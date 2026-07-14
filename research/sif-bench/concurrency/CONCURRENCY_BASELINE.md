# SIF-Bench concurrency / TOCTOU — frozen baseline (unmodified control plane)

**Seed:** `0xC0FFEE` · **clock:** `2026-07-14T12:00:00.000Z` · **workers:** ≤ 2 ·
**schedules:** one deterministic interleaving per case (forced via barriers /
ordered steps — this is **not** a randomized-schedule fuzzer). Measured against
the implementation with **no remediation** of GAP-1, GAP-2, injection weaknesses,
or any gap surfaced here.

Reproduce (boots embedded PostgreSQL; writes `reports/concurrency.json`):

```bash
npm run sif-bench:concurrency
```

## Benchmark version history

```
Concurrency baseline v0.1
  Status : INVALIDATED for C1 wall-clock coupling (not reproducible)
  Commit : df5e862
  Reason : capabilities issued at the fixed logical clock (2026-07-14T12:00:00Z,
           90s TTL) but the C1 disclose/callModel controls evaluated at the host
           wall clock (Date.now()). A run more than 90s after the issuance
           timestamp expired the capability, so the C1 valid controls false-failed
           and the expiry-maskable probes (C1-02/03/05/11) were hidden by an
           earlier expiry denial. v0.1's numbers below are correct ONLY when run
           before issuance-time + TTL (as originally captured); they silently
           degrade otherwise.

Concurrency baseline v0.2
  Status : CORRECTED — authoritative for the bounded deterministic schedule
  Commit : <this correction commit>
  Change : the benchmark's logical NOW is injected into every intended-live C1
           disclose/callModel; the deliberate expiry case (C1-08) alone keeps an
           explicitly advanced timestamp. A wall-clock-independence regression
           (`src/wallclock.test.ts`) runs C1 at host clocks an hour, a day, a year
           and a day-before away and asserts identical verdicts.
```

The initial C1 baseline unintentionally evaluated fixed-time capabilities against
the host wall clock. Runs performed more than 90 seconds after the fixed issuance
timestamp caused valid controls to expire and masked several intended TOCTOU
probes. The harness was corrected by injecting the benchmark's logical clock into
all intended-live C1 operations; the explicit expiry case remained unchanged. **No
control-plane logic, capability TTL, revocation semantics, or verification code was
modified — only the benchmark's time source.** The corrected harness re-exposes
`C1-02`, `C1-03`, `C1-05` and `C1-11`, which had been masked by accidental
capability expiry in later wall-clock runs; the corrected totals (10 gaps, RESR
0.208, 0 false-failures) match v0.1's originally-captured numbers and are now
reproducible at any host time. The system did not change — measurement validity
improved.

The numbers below are the **v0.2 corrected** result.

## Sample context (required for every "zero observed")

- **100 records** total: **48 adversarial** cases (12 per family C1–C4), **52
  valid controls**. **1 seed**, workers up to **2**, deterministic interleavings.
- **0 false-failures** on valid controls — permitted concurrency and sequential
  work were never refused, so no "held" result is an artefact of over-blocking.
- Every failing case is preserved as a regression fixture under `fixtures/`.

**Counts — kept distinct (do not conflate):**

```
Independent security findings : 6   (GAP-1 … GAP-6)
Reproducible failing fixtures : 10  (adversarial cases classified "gap")
Concurrency test families     : 4   (C1–C4)
Concurrency suite tests       : 9   (6 baseline + 3 wall-clock-independence regression)
```

The 10 failing fixtures map onto the 6 findings: GAP-3 (staleness) accounts for
five fixtures (`C1-02/03/05/11`, `C2-06`); GAP-1, GAP-2, GAP-4, GAP-5, GAP-6 one
each. "10/48" below is a **case-level** rate, not a count of independent findings.

## Global result

| Metric | Value |
|--------|-------|
| Race-Exploit Success Rate (gaps / adversarial) | **0.208** (10/48) |
| Stale-Permit Acceptance Rate | 0.0625 (3/48) |
| Scope-Escalation Success Rate | 0.0208 (1/48) |
| Post-Revocation Disclosure Rate | **0** (0/48) |
| Human-Gate Bypass Rate | **0** |
| Duplicate-Execution Rate | **0** |
| Cross-Tenant Observation Rate | **0** |
| Chain-Fork Rate | **0** |
| Missing-Material-Event Rate | **0** |
| False-Failure Rate (valid concurrent controls) | **0** |
| Revocation-race observations | **1** (single observation — see below) |
| Gate-to-execution latency (n=12) | median 0.08 ms, max 0.19 ms |

**Revocation overrun:** one measured revocation-race observation was refused at
point of use with an observed overrun of **1.05 ms**. With n=1 this is a single
observation, **not** a percentile distribution — p50/p95/p99 would all be the same
number and carry no distributional evidence. Percentiles begin only after enough
repeated trials (deferred to the concurrency stress expansion). The "overrun" is
the check latency, not a window of continued access: the check refuses
immediately (see C1-07). Gate-to-execution has n=12, so a median and max are
reported rather than fabricated tail percentiles.

| Family | Adversarial | Gaps | Held | Not-realizable | RESR |
|--------|-------------|------|------|----------------|------|
| C1 authorization / scope | 12 | 6 | 5 | 1 | 0.500 |
| C2 human-gate / action | 12 | 2 | 6 | 4 | 0.167 |
| C3 database / tenant-context | 12 | 2 | 10 | 0 | 0.167 |
| C4 evidence / chain | 12 | 0 | 5 | 7 | 0.000 |

## New gaps surfaced (documented, NOT fixed)

### GAP-3 · Authorization is a snapshot; it is not re-evaluated against later state
An issued capability is re-checked at point of use for **signature, expiry,
revocation, and PoP** — but **not** for consent, policy version, or object
lifecycle. Within the capability's TTL (90 s) or an action's gate window:

- `C1-02` policy ceiling tightened after permit → disclosure still released.
- `C1-03` **consent withdrawn** after issuance → disclosure still released.
- `C1-05` policy **version rotated** after issuance → capability still valid.
- `C1-11` underlying **object revoked** after authorization → the cached
  disclosure package (still containing it) was released.
- `C2-06` policy rotated between proposal and approval → action executed without
  re-validation.

**Held contrast:** `C1-07` post-revocation disclosure and `C1-08` expiry-during-use
are both refused — the two things the capability *does* re-check work. Fix
(later, separate): re-evaluate live capabilities against consent/policy/object
changes, or cascade those changes into revocation.

### GAP-4 · Proof-of-possession is replayable within the TTL
`C1-10`: a captured `(challenge, signature)` pair verified more than once. The
verifier does not enforce challenge freshness / single-use, so an intercepted
proof is replayable until the capability expires.

### GAP-5 · RLS isolation is app-cooperative, not app-adversarial
`C3-06`: inside an `t_acme` transaction the app role called
`set_config('app.current_tenant','t_globex')` and then read a `t_globex` row. The
`continuum_app` role is permitted to set the GUC, so DB isolation assumes the
application never re-keys to a foreign tenant. Nothing at the DB privilege layer
stops it. (This is distinct from the strong results below, where the application
uses `withTenant` correctly.)

### GAP-6 · No idempotency on client-supplied action ids
`C2-11`: reusing a client-supplied `action_id` across two proposals silently
**overwrote** the first record instead of being rejected or deduplicated.

### GAP-1 and GAP-2 reproduce under concurrency
- `C1-06` two concurrent workers each self-declared `read:source_code` and both
  obtained the object (GAP-1, agent-declared scope).
- `C3-08` the in-memory `listMemoryMeta('t_globex')` returned a foreign id while
  the durable acme context returned none — the two layers diverge (GAP-2).

## What held (bounded statements, with N)

Across the 48 adversarial cases at seed `0xC0FFEE`, workers ≤ 2:

- **0 post-revocation disclosures** and expiry is enforced at point of use (C1-07/08).
- **0 human-gate bypasses**: duplicate approval, foreign-tenant approval, and
  approving a denied action were all refused; the Stage A approver guard held
  under the race (C2-03/05/07/08). Illegal state skips rejected (C2-12).
- **0 cross-tenant observations** across the durable races (C3-01/02/03/04/05/11):
  `withTenant`'s transaction-local `app.current_tenant` resets at COMMIT/ROLLBACK,
  so pooled-connection reuse and rolled-back transactions did not bleed.
- **Append-only enforced** under the app role: UPDATE/DELETE on
  `evidence_envelopes` denied (C3-10). Superuser bypass of RLS confirmed and is a
  documented trust boundary, not a defect (C3-09).
- **Evidence integrity held (0 gaps)**: `UNIQUE (tenant_id, seq)` and
  `PRIMARY KEY (tenant_id, event_id)` reject duplicate-seq / duplicate-event
  inserts under concurrency (C4-04/07); a rolled-back append leaves no orphan
  (C4-01); ledger ordering and verification-on-snapshot hold (C4-08/11).

## Not realizable in this architecture (recorded, not scored as secure)

These interleavings cannot occur because the corresponding surface is absent —
each is itself a finding about missing lifecycle, not evidence of safety:

- `C1-01` authorize() is atomic (no intra-evaluation window).
- `C2-01` no approval-withdrawal / cancellation API (the state machine defines
  `POLICY_APPROVED→REVOKED` but no method reaches it).
- `C2-04` approvals have no TTL; `C2-09`/`C2-10` no async execution / compensation
  transition methods.
- `C4-02/03/05/06/09/10/12` state+evidence are persisted atomically; there is no
  key-rotation API and no partial-commit split to race.

## Claims this baseline supports (bounded)

- Point-of-use capability verification refuses **post-revocation and expired**
  use; these are not stale-permit vulnerabilities.
- The action state machine prevents **double execution** and **illegal state
  skips**, and the approver guard resists foreign-tenant and duplicate approvals,
  under the tested interleavings.
- Durable tenant isolation via transaction-local RLS resisted pooled-reuse,
  rollback, and concurrent-enumeration races (0 cross-tenant observations, 48
  cases, seed `0xC0FFEE`).
- Append-only evidence and the `(tenant,seq)`/`(tenant,event_id)` constraints
  prevent duplicate sequences, competing heads, and orphan evidence under the
  tested concurrency.

## Claims this baseline does NOT support

It does **not** claim concurrency safety, linearizability, serializability beyond
PostgreSQL read-committed, complete TOCTOU resistance, production robustness, or
zero race conditions. It uses one deterministic schedule per case at a single
seed with ≤ 2 workers; it is not a randomized-schedule fuzzer, and absence of a
finding is bounded by that sample.

## Next (unchanged order; remediation is later, separate)

Interventions to be measured against this before-picture: capability
re-evaluation / revocation cascade (GAP-3), single-use PoP challenges (GAP-4),
non-cooperative tenant binding (GAP-5), idempotency keys (GAP-6), plus I1
(entitlement-bound scope, GAP-1) and I2 (caller-bound metadata, GAP-2).
