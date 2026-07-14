# Intervention I4 — proof-of-possession replay resistance (matched-arm result)

I4 closed the tested **GAP-4** proof-of-possession replay — a captured
`(challenge, signature)` pair verifies repeatedly within the TTL because the
verifier enforces signature/expiry but never consumes the challenge (concurrency
baseline `C1-10`) — in a bounded deterministic matched experiment over a real
embedded PostgreSQL. I4 is an **isolated workspace** (`@continuum/sif-i4`); it does
**not** modify the frozen control-plane PoP path (`capability.ts` / `engine.ts`),
Stage A/B, persistence, concurrency, I1, I2, I3, I5 or I6.

## What this result supports — and does not

Supported (exactly):

> Single-use consumption of a server-issued nonce via a transactional replay ledger
> prevented the tested sequential replay and concurrent double-spend of a captured
> proof; binding the proof to the request digest, capability id and audience
> additionally prevented the tested lifting of a fresh-nonce proof onto a different
> request, audience or capability.

- I4-A reproduced the observed GAP-4 replay and concurrent double-spend, and accepted all three lift cases (3/3).
- Zero false denials were observed in the evaluated benign controls across all three arms.

**Not** claimed: general credential-theft resistance, complete replay resistance,
protection of the holder private key, secure channel/transport security, resistance
to a compromised holder, distributed replay-ledger consistency across nodes, or
protection once an attacker can make the holder sign arbitrary messages. I4 closes
the **tested** replay and proof-lifting vectors within the evaluated single-instance
ledger and failure model — not replay resistance in general.

## The gap, precisely

The PoP message is `sign(holder_key, "<token_id>:<nonce>:<challenge>")` where the
challenge is a **caller-supplied, fixed string** (`"continuum-pop-challenge"`,
`"model-call"`), and `verifySCT` checks the signature, expiry, revocation and
audience but **does not record or consume** the challenge. So a captured
`(challenge, signature)` verifies again within the TTL, and two concurrent
presentations both succeed. The proof is also **not bound** to the specific
request/audience/capability, so a signature obtained for one operation is valid for
another.

Target invariant: a proof is accepted **at most once** (single-use), and only for the
**exact** operation it was produced for.

## Arms and results

| Metric | I4-A (baseline) | I4-B (single-use nonce) | I4-C (+ binding) |
|--------|-----------------|-------------------------|-------------------|
| Sequential replay accepted | **true** | false | false |
| Same-proof acceptances | **2** | 1 | 1 |
| Concurrent double-spend | **true** | false | false |
| Lifted onto different request | **true** | **true** | false |
| Lifted onto different audience | **true** | **true** | false |
| Lifted onto different capability | **true** | **true** | false |
| Lift cases accepted | **3/3** | **3/3** | **0/3** |
| Benign proof accepted | ✓ | ✓ | ✓ |
| Expired / non-holder / missing rejected | ✓ | ✓ | ✓ |
| False deny (benign) | 0 | 0 | 0 |

Causal reading (clean single-variable ablation):

- **I4-A reproduces GAP-4** — signature-only verification with no consumption: the same
  proof is accepted twice sequentially, two concurrent presentations both succeed, and
  a proof made for one request/audience/capability is accepted for another (3/3).
- **I4-B changes only consumption** — a server-issued nonce is consumed **exactly once**
  via `INSERT ... ON CONFLICT (token_id, nonce) DO NOTHING` on the replay ledger. The
  winner consumes; a replay (or the loser of a concurrent race) fails to insert and is
  rejected. B is **necessary but insufficient**: it binds only `<token>:<nonce>`, so a
  fresh-nonce proof lifted onto a different request/audience/capability is still
  accepted (3/3) — isolating consumption from binding.
- **I4-C adds request/capability/audience binding** — the proof is signed over, and
  checked against, the request digest, capability id and audience of the operation
  actually being authorized; a mismatch is rejected before consumption (0/3). Replay and
  double-spend remain closed.

The expiry, non-holder-key, and missing-proof controls are rejected under **every**
arm — expiry is the one property today's verifier already enforces, and it is
preserved unchanged.

## The transactional replay ledger

`i4_consumed_proof` has `PRIMARY KEY (token_id, nonce)`. Consumption is a single
`INSERT ... ON CONFLICT DO NOTHING RETURNING` — atomic and race-safe: concurrent
`Promise.all` presentations of one proof serialise on the primary key, so exactly one
consumes (`RETURNING` one row) and the other reads zero rows and is rejected. There is
no check-then-insert TOCTOU window. This transactional ledger is present from **I4-B**;
I4-C's *distinct* addition is the request/capability/audience binding, so the A→B→C
ablation changes exactly one variable per step (consumption, then binding).

## Evidence

Every verification appends a bounded `i4_evidence` row — token id, nonce, a **digest
of the signature** (never the raw signature), the bound request digest, capability id,
audience, the decision (`CONSUMED` / `REPLAY_REJECTED` / `BINDING_MISMATCH` / `EXPIRED`
/ `BAD_SIGNATURE` / `MISSING_PROOF` / `ACCEPTED_NO_LEDGER`), and an attack
classification. The baseline additionally appends an `i4_baseline_verification` row per
acceptance, so a replay is visible as two rows for one nonce.

## Reproducibility record

| Field | Value |
|-------|-------|
| Frozen baseline commit | `e1e374d` (before-picture; the frozen PoP path is unchanged) |
| Intervention | isolated workspace `@continuum/sif-i4` (new); the core verifier is not modified |
| Determinism source | fixed logical clock `now_ms = 1784030400000` (`2026-07-14T12:00:00.000Z`); arm **outcomes** are deterministic (Ed25519 key material is generated per run but does not affect any measured outcome; server-issued row ids are non-deterministic as in I5/I6) |
| Trials | 1 per arm per probe; the concurrent double-spend races 2 workers via `Promise.all` on the ledger primary key (no timing sleeps) |
| Environment | one embedded PostgreSQL 18 instance, port 55449, role `i4_app` (NOSUPERUSER / NOBYPASSRLS); no live model |
| Regeneration | `npm run intervention:i4` |
| Machine-readable output | `research/sif-bench/interventions/i4/report.json` (gitignored; rebuilt via the reproduction command above) |

## Architectural note

The production direction is I4-C semantics: a server-issued single-use nonce, a
transactional replay ledger, and a proof signed over the request digest, capability id
and audience. The ledger secret / nonce issuance should be server-controlled; nonces
should carry issuance + expiry so the ledger can be pruned to the TTL horizon; and the
ledger must be shared across all verifiers that can accept a given token (a per-node
ledger would not prevent cross-node replay — an explicit non-goal here). Binding should
eventually cover the full set of use-time parameters (operation, resource, arguments
digest, audience, capability, tenant) so a proof is inseparable from its operation.

## Bounded-scope limitations

Single PostgreSQL instance (no cross-node / distributed ledger consistency). The holder
key is assumed uncompromised; transport security and endpoint capture are out of scope
(I4 addresses replay/lifting of an intercepted proof, not prevention of interception).
Nonce issuance is modelled as caller-provided distinct strings, not a full server
issuance/expiry service. Seeded contexts, single-trial (except the 2-worker concurrent
case), no B0–B3, no live model. The control-plane PoP path, authorization core, tenant
binding, entitlement (I1), metadata (I2), freshness (I3), tenant identity (I5) and
idempotency (I6) are held constant and unchanged.

## Next

GAP-4 is the only gap addressed in this commit, and only under the evaluated
single-instance ledger and failure model. All six documented control-plane gaps
(GAP-1..6) now have separately-evaluated matched interventions; the remaining open
facets are explicitly recorded (GAP-3 action-execution re-validation; distributed
exactly-once for I6; cross-node ledger consistency for I4).
