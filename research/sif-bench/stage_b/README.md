# SIF-Bench Stage B — model / memory-corpus adversarial (measurement)

Stage B is the corpus-driven adversarial split. Where [Stage A](../STAGE_A_BASELINE.md)
is deterministic control-plane attacks, Stage B attacks with **corpora**:
prompt-injection, canary/secret-exfiltration, memory-poisoning, and
context/datastore extraction.

**This milestone measures the *current* defence, unmodified, and documents where
it fails.** It does not add new defences. Per the honest-first mandate: first
expose the system honestly; add defences later as separately evaluated
interventions. See [`STAGE_B_FINDINGS.md`](STAGE_B_FINDINGS.md) for the results
and the open gaps.

```bash
npm run sif-bench:stage-b        # runs the corpora against the control plane, writes reports/
```

## Boundary (read before citing any number)

- **No live model, no network.** The model is the deterministic simulator, so the
  prompt-injection figures are **control-plane screen permeability** — an *upper
  bound* on real attack success, not a real model's compliance. Real
  model-mediated robustness is out of scope until a live-model harness exists.
- Nothing here asserts "blocked". The test asserts **framework** gates (schema
  validity, reproducibility, benign controls not over-blocked, Stage A
  unchanged). Security outcomes — including gaps — are **recorded**, not gated.
- A green test run does **not** mean the system defended every attack. It means
  the framework is sound and the measurement ran. The findings carry the verdict.

## Layout

```
stage_b/
├── schemas/case.schema.json      # the case contract
├── corpora/*.jsonl               # one case per line (see the schema)
├── STAGE_B_FINDINGS.md           # honest results, incl. failures (tracked)
├── reports/stage_b.json          # full machine report (generated, gitignored)
└── manifests/env.json            # environment + seed record (generated, gitignored)
```

The runner and scorer code live in `packages/continuum-core/src/stageb/`
(`cases.ts`, `harness.ts`, `stage_b.test.ts`) because they must import and drive
the control-plane engine directly; the corpora, schema, and findings live here as
data and documentation.

## Tracks and current coverage

| Track | Attacks measured | Status this milestone |
|-------|------------------|-----------------------|
| B1 prompt-injection | 14 attacks + 3 benign, arms A (no screen) / B (current heuristic) | measured; C/D structured-separation intervention deferred |
| B2 canary exfiltration | redacted / unauthorized / cross-tenant / evidence / egress + 1 classification-dependence | measured |
| B4 extraction | bounded-query escalation of denied / redacted / cross-tenant / metadata | measured |
| B3 memory poisoning | 11 attack classes | **surface-absent** — v0.1 has no agent-writable memory path |

## Explicitly deferred (not in this milestone)

- **B1-C / B1-D** — structured instruction/data separation and combined defence
  (these are *interventions*; they will be added and measured separately, so the
  A/B baseline here is the honest before-picture).
- **Concurrency / TOCTOU suite** — approve-vs-revoke, expiry races, nonce reuse,
  pooled tenant-context reuse. Stage A and B are single-process; this is a
  separate track to run before the B0–B3 baselines.
- **B0–B3 comparative baselines** — unrestricted / RAG / RBAC-RAG / Continuum on
  both benign and adversarial tasks (utility vs disclosure vs violations vs
  overhead). To be run after these corpora and metrics are frozen.

## Changing a metric

Stage A's frozen numbers must not move silently, and neither should Stage B's once
frozen. A change to an existing metric requires a new benchmark version, a reason,
before/after results, a migration note, and a claim-impact analysis.
