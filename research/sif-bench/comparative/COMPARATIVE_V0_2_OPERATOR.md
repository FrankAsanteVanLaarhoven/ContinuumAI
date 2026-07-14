# Comparative v0.2 — Operator Registration (attribution-safe, PRE-EXECUTION)

```
Comparative v0.2 — operator registration
Status: BRIDGE ONLY — no model called; execution fails closed
Attribution: repo stays vendor-neutral; exact identities live ONLY in a gitignored file
Depends on: v0.1 (ef3bf22) + v0.2 protocol (da4aa9f) + registration (ba77217)
```

The exact model identities, revisions, artifact digests, regions, provider data policies and
budgets are the operator's decisions **and must be verified**, so they are **never committed**.
They live in a **gitignored** `operator.local.json` (schema documented by the committed,
vendor-neutral `operator.local.example.json`). The committed repository names models only by
**role** (slot A / B / C). This keeps the repository free of vendor/AI-branding tokens while
preserving reproducibility: the operator's pinned local record + the final paper disclosure
carry the exact identities.

Machinery: `src/v2/operator.ts` (loader + composite execution gate + budget/kill-switch/
qualification/contrast constants). `src/v2/operator.test.ts` proves the example fails closed,
that a fully-pinned synthetic frame is satisfiable, and that removing any condition re-blocks.

---

## Slot roles (identities pinned out-of-band)

| Slot | Role | Hosting |
|------|------|---------|
| A | Strong remote instruction-following model | remote, pinned snapshot |
| B | Different remote model family / architecture | remote, pinned model id |
| C | Local / private open-weight model | `LOCAL_PRIVATE` (owner-controlled) |

The local slot is included to test **deployment sovereignty** and **model interaction**, not
because it is expected to perform worse. Selection criteria were declared before choosing:
tool-use support, structured-output support, stable version availability, adequate context
length, reproducible API/local runtime, feasible cost, material family diversity.

**Exact identities are pinned by the operator in `operator.local.json` (gitignored), never in
this repository.** A concrete panel recommendation (specific vendors/versions) was made in
review and is recorded outside version control; the committed artefacts stay neutral.

---

## Pinning procedure (operator, under review)

1. `cp operator.local.example.json operator.local.json` (the copy is gitignored).
2. Pin each slot: exact `model_id`, `revision`, `hosting_class`, `region`, `endpoint_class`,
   provider data policy (`prompt_retained`, `used_for_training`), and — for slot C —
   `artifact_digest` (sha256), `serving_framework`, `runtime_version` (exact git sha),
   `quantization`. Record `date_accessed`.
3. Pin the full per-slot sampling (record `NOT_SUPPORTED` where a parameter is unavailable;
   never silently substitute a provider default).
4. Set `prompt_surface_hash` to `449d0272500e2909e8c5db7834bcdc7f5aee0a1fdbbf81105d546d239aa8b3c8`.
5. Set the budget caps (defaults below), obtain reviewer sign-off, mark `artifacts_verified`
   and `synthetic_data_verified`, run qualification and mark each slot `slots_qualified`.
6. Disengage the kill switch **only** once all of the above hold.

`executionEnabled(operator.local.json)` must return `{ enabled: true, unmet: [] }` before any
run. Until then, execution is impossible.

---

## Sampling fairness

Common requested envelope: `temperature 0.7 · top_p 1.0 · max_output_tokens 768 · seeds
[11,23,37,101,233]`. Identical numeric settings do **not** guarantee equivalent stochastic
behaviour across providers, so record **both** the requested and the provider-reported
**effective** configuration. Rules: no silent default substitution (`NOT_SUPPORTED` instead);
no seed change to retry a semantic failure; hidden reasoning/"thinking" disabled or fixed to
the lowest common configuration; billed reasoning tokens recorded separately where exposed.

---

## Execution budget (hard ceilings — kill thresholds, not targets)

```
planned_runs            540      (3 models × 4 baselines × 9 tasks × 5 seeds)
max_infra_retries        54
max_total_attempts      594
per_run: max_input 6000 · max_output 768 · timeout 120s
global:
  max_input_tokens   3,564,000
  max_output_tokens    456,192
  max_cost_usd              60   (conservative kill threshold, NOT a spending target)
  max_gpu_hours            10
  max_wall_clock_hours    12
  failure_allowance       10%    (54 / 540)
```

Actual prompt lengths, provider accounting, reasoning tokens and retries determine final cost;
the `$60` cap is a kill threshold. Execution must not begin until the full maximum-cost
envelope is computed and the caps are pinned.

## Kill switch (composite enable, immediate stop)

`execution_enabled = reviewer_signoff AND slots_pinned AND artifacts_verified AND budgets_pinned
AND prompt_hash_verified AND synthetic_data_verified AND all_slots_qualified AND no_placeholders`.
The switch is **never** disengaged globally — it derives from those gates. Halt immediately on
any of: remote cost ≥ $60 · local GPU ≥ 10h · wall-clock ≥ 12h · failed attempts > 54 ·
schema-invalid outputs > 20% for any model · provider model id changes · prompt-hash mismatch ·
tool-schema hash mismatch · fixture checksum mismatch · non-synthetic data detected ·
credential/secret in a stored request.

## Qualification (non-scored, before the 540-run experiment)

One non-scored request per slot to: verify authentication · confirm the exact returned model
identity · verify structured-output support · measure basic latency · confirm token accounting
· validate local runtime loading · ensure no credentials enter stored evidence. **Qualification
outputs must not be used to modify prompts, choose models, or estimate comparative performance.**
After qualification, freeze the returned identities, digests, runtime versions, regions, data
settings and token-accounting fields; then execute without prompt changes.

## Statistical preregistration (primary contrasts)

1. B3 vs B2 — benign utility
2. B3 vs B2 — security-violation probability
3. B3 vs B2 — sensitive-field disclosure
4. B3 vs B2 — injection-following
5. Baseline × Model interaction — utility and violations

Primary endpoints: benign utility · any security violation · sensitive-field disclosure ·
injection-following · model refusal. Secondary: cross-tenant / canary disclosure, tool-call
violations, latency, tokens, cost, evidence volume, schema failure. Model refusals stay
separate from security denials. Reported as baseline effect, model effect, and interaction —
never one winner score.

## Claim boundaries

This registration supports **no empirical claim**. Execution begins only after the identities,
budgets, prompt-hash, qualification and reviewer sign-off are frozen and the composite gate
passes. No provider client, credential, or network code exists in `src/v2`.

Guard check (no model): `npx vitest run --root research/sif-bench/comparative src/v2/operator.test.ts`
