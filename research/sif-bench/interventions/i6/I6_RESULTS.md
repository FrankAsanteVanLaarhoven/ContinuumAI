# Intervention I6 — idempotent action identity (matched-arm result)

I6 eliminated the observed **GAP-6** — the action-creation path accepts a
caller-controlled `action_id` and silently overwrites an existing record, and a
retry re-executes — in a bounded deterministic matched experiment over a real
embedded PostgreSQL. I6 is an **isolated workspace** (`@continuum/sif-i6`); it does
not touch the frozen action state machine, persistence migration, or any other
baseline.

## What this result supports — and does not

Supported (exactly):

> Explicit server-issued action identity and digest-bound idempotency semantics
> prevented the tested silent overwrite, duplicate creation, conflicting key
> reuse, and duplicate execution cases.

- I6 eliminated the observed GAP-6 silent overwrite and duplicate execution in the deterministic matched experiment.
- Zero false denials were observed in the evaluated benign new-action control cases.

**Not** claimed: exactly-once execution in distributed systems, general
linearizability, complete replay resistance, production-grade payment idempotency,
general transaction safety, zero duplicate execution under arbitrary failures, or
full action integrity across untested tool providers. Within the evaluated
idempotency domain and failure model (single PostgreSQL instance; failures =
transaction rollback and post-create evidence-append failure; deterministic
two-worker races), the bound arms are **effectively-once**: exactly one
authoritative record and one execution per `(tenant, principal, operation,
idempotency_key)`.

## The gap, precisely

`proposeAction` accepts an optional caller `action_id` and stores it with
`actions.set(action_id, record)` (in-memory) / `INSERT ... ON CONFLICT DO UPDATE`
(modelled here) — so a reused id **silently overwrites**, and because low-consequence
actions auto-execute, a **retry re-executes**. The identifier is caller-selected
authority.

Target invariant: a consequential action has a **server-issued immutable** id, a
**separate caller idempotency key**, a **canonical request digest**, explicit
replay/conflict semantics, exactly one authoritative record per idempotency domain,
no silent overwrite, no duplicate execution, and complete create/replay/conflict/
deny/execute evidence.

## Idempotency domain and digest

- **Uniqueness domain:** `UNIQUE (tenant_id, principal_id, operation,
  idempotency_key)`. Enforced by a transactionally-safe `INSERT ... ON CONFLICT DO
  NOTHING` + read — **never** `DO UPDATE` (no in-place overwrite). Concurrent
  workers serialise on the constraint; the winner creates and executes, the loser
  reads the authoritative record.
- **Request digest:** `sha256` over the control plane's canonical JSON of
  `{tenant, principal, intent, operation, resource, arguments, purpose, capability,
  policy_version, approval_requirement}` (alg `sha256/continuum-canonical-v1`,
  recorded). Same logical request → same digest; materially different → different.
- **`intent`, `capability`, `policy_version` are in the digest but NOT the
  uniqueness domain.** A differing one with the same key/operation is therefore a
  **CONFLICT** under I6-C, not a silent second action — which keeps exactly one
  authoritative record per `(tenant, principal, operation, key)`. Justification:
  putting them in the domain would let a caller bypass idempotency by varying them;
  keeping them in the digest makes a materially different request a detectable
  conflict.

## Arms and results

| Metric | I6-A (frozen) | I6-B (server-id + key + replay) | I6-C (+ digest conflict + exec-once) |
|--------|---------------|----------------------------------|--------------------------------------|
| Silent overwrite success | **true** | false | false |
| Duplicate action creation | 1 | 0 | 0 |
| Duplicate execution | **2** | 0 | 0 |
| Same-request replay accurate | n/a | ✓ | ✓ |
| Different-request conflict detection | 0 | **0** | **4/4** |
| Missing-key denial | n/a | ✓ | ✓ |
| Valid new-action success | ✓ | ✓ | ✓ |
| False permit | 2 | 0 | 0 |
| False deny | 0 | 0 | 0 |
| Orphan / action–evidence divergence | 0 | 0 | 0 |
| Idempotency latency (single trial, ms) | n/a | 6.98 | 2.06 |

Causal reading:

- **I6-A reproduces GAP-6** — a reused `action_id` overwrote the record in place and
  a retry produced **2** execution rows.
- **I6-B changes only identity + replay** — the id is server-issued; the same
  key+request retry is REPLAYED (original id, no second execution); a missing key on
  a consequential action is denied. B **intentionally does not** detect a
  same-key/different-request conflict (it returns the original) — isolating identity/
  replay from conflict detection.
- **I6-C adds digest conflict rejection + execution-level idempotency** — a
  same-key request whose digest differs (arguments / intent / capability / policy
  version) is rejected `IDEMPOTENCY_CONFLICT` (4/4) without touching the original;
  execution stays at exactly one row per action.

## Case battery (24 scenarios) — coverage

New key/new request · same key+request sequential retry · same key+request
**concurrent** retry · same key different arguments/intent/capability/policy-version
· same key different operation/tenant/principal (distinct domains → separate
records) · missing key · caller cannot select `action_id` (server-issued) · two
workers same key+request · two workers same key/different request · evidence-append
failure rolls back (no orphan) + clean retry · evidence distinguishes
create/replay/conflict · benign distinct keys. Retry-after-terminal (success) is the
sequential replay case; retry-after-denied is the idempotent CONFLICT/missing-key
re-deny.

Concurrency uses `Promise.all` over separate connections racing on the UNIQUE
constraint (deterministic barrier via the DB, no timing sleeps): two workers with
the same key+request yield **one** action and **one** execution; with different
requests, **one** authoritative record (C rejects the loser's mismatch).

## Evidence

Every path emits a bounded `i6_evidence` row — tenant, principal, intent, operation,
**keyed idempotency-key digest** (never the raw key), request digest, action id,
original action id, decision, state, policy version, capability id, and a
create/replay/conflict/missing_key classification. Action–evidence divergence
(orphan actions) measured **0**; on the evidence-append-failure case the whole create
transaction rolls back, so no action exists without its evidence.

## Bounded-scope limitations

Single PostgreSQL instance (no cross-node / distributed exactly-once). Failure model
= transaction rollback + post-create evidence-append failure; arbitrary partial
failures and tool-provider failures are out of scope. Execution is modelled as a
counted side effect (`i6_execution`), not a real external tool. Seeded requests,
single-trial latency, no B0–B3. The action state machine, authorization, tenant
binding, entitlement (I1), metadata (I2), tenant identity (I5), injection controls,
and memory systems are held constant and unchanged.

## Next

GAP-6 is the only remediated gap in this commit. GAP-3 (authorization snapshot
staleness) and GAP-4 (proof-of-possession replay) remain open for their own
separately evaluated interventions.
