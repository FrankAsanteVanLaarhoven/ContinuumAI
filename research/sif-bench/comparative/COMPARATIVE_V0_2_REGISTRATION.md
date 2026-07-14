# Comparative v0.2 — Model-Registration Manifest (PRE-EXECUTION, ZERO MODEL CALLS)

```
Comparative v0.2 — registration
Status: REGISTRATION ONLY — no model has been called
Execution: FAILS CLOSED until every operator field is pinned and reviewer-signed
Depends on: Comparative v0.1 (frozen, ef3bf22) + v0.2 protocol (da4aa9f)
```

This manifest registers the experimental frame and makes real-model execution **impossible**
until the model identities, hosting classes, budgets, prompt-surface freeze, and reviewer
sign-off are all pinned under review. The guard `assertReadyForExecution()` returns the list
of unmet conditions; a runner must refuse to start while that list is non-empty. **No runner
and no provider client exist yet.** Machinery lives in `src/v2/registration.ts`
(`src/v2/registration.test.ts` proves the template fails closed).

Values I can define authoritatively from the frozen artefacts and this review are pinned
here. Values that are the **operator's decision** are UNPINNED (`null`) and must be frozen
under review — I do not fabricate model identities or budgets.

---

## 0. What is pinned vs what the operator must pin

| Pinned now (authoritative) | Operator must pin under review |
|----------------------------|--------------------------------|
| retry policy, failure classes, data-retention policy | exact model ids + revisions per slot |
| statistical-analysis plan, primary/secondary endpoints | local-model artifact digest, runtime, quantization |
| scoring-leakage rules, three-blocking distinction | hosting class + region + endpoint class per slot |
| seeds `[11,23,37,101,233]`, baselines, task count | provider data policy (retention / training use) |
| prompt-surface hash `449d0272…` (freeze anchor) | full sampling config (top_k, penalties, stop, reasoning_effort, seed-reproducibility) |
| kill switch (defaults **engaged**), sign-off (defaults **false**) | budget caps (tokens / cost / GPU / wall-clock / failure allowance) |

`PROMPT_SURFACE_HASH = 449d0272500e2909e8c5db7834bcdc7f5aee0a1fdbbf81105d546d239aa8b3c8`
(SHA-256 of the frozen instruction template + per-workload output schemas). Any prompt
change alters this hash and re-blocks execution.

---

## 1. Exact model identity (recorded per slot at execution)

Vendor-neutral slots are correct at protocol stage; execution records, per slot:
`hosting/provider environment · exact model_id · revision/immutable digest · runtime/API
version · quantization · context-window · serving framework · region · endpoint class ·
date accessed`. This is **reproducibility**, not attribution/branding. The manuscript may
blind models during internal analysis, but the final artefact discloses exact models unless
a documented contractual restriction applies.

## 2. Hosting classification (≥1 owner-controlled)

Each slot is classified `LOCAL_PRIVATE | PRIVATE_TENANT | REMOTE_ZERO_RETENTION |
REMOTE_STANDARD`, recording: prompt retention, training use, processing region, network
egress, and the applicable data-classification ceiling. **At least one LOCAL_PRIVATE /
PRIVATE_TENANT slot is required** (guarded). **Only synthetic benchmark data is used**
(`synthetic_fixtures_only`, guarded).

## 3. Complete sampling configuration (pinned in advance)

Per slot: `temperature (0.7, pre-registered) · top_p (1.0) · top_k · max_output_tokens
(512) · frequency_penalty · presence_penalty · stop · reasoning_effort · tool_choice ·
response_format · system_prompt_hash · request_template_hash · seed_reproducibility`. Where
a provider does not guarantee seed reproducibility, `seed_reproducibility = "requested_only"`
— seeds then identify requested configurations, not deterministic replay.

## 4. Prompt freeze

The frozen prompt surface (instruction template + output schemas) is hashed
(`449d0272…`). Baseline request templates, tool descriptions, output schemas, retrieved-
context formatting, refusal-detection rules, and scoring rubrics are frozen before
execution. **No prompt may change after seeing results** — any correction creates a new
protocol version (v0.3).

## 5. Failure handling (pre-registered)

Failure classes: `http_api_failure, timeout, rate_limit, empty_response, invalid_json,
schema_mismatch, tool_call_parse_failure, safety_refusal, partial_refusal, truncated_output,
provider_content_filtering, context_length_failure, local_model_crash`. Retry policy: **at
most one infrastructure retry**, same parameters, same input, original failure retained,
retry marked separately; **no retry** for semantic refusal, partial refusal, incorrect
output, or schema mismatch. No silent retry-until-favourable.

## 6. Three kinds of "blocking" (kept distinct)

1. **Control-plane prevention** — information/action never reaches the model or tool.
2. **Model refusal** — the model receives sufficient content but refuses.
3. **Model non-compliance / failure** — incorrect, malformed, or irrelevant result.

These carry different scientific meaning and are never merged.

## 7. Scoring-leakage prevention

The expected answer is **never** in the model request. Prefer deterministic exact/schema
scoring; keep security scoring rule-based; blinded human adjudication only for genuinely
semantic cases; an evaluated model is never its own judge; record inter-rater agreement if
human adjudication is used.

## 8. Evidence retention (access-controlled)

**Store:** redacted request body, model output, model metadata, token counts, latency,
provider request id (if safe), scoring result, failure classification, run manifest.
**Never store:** API keys, auth headers, reusable proof material, raw secrets, real
personal/enterprise data. Raw outputs are access-controlled (they carry synthetic canaries
and attack text).

---

## Model-selection design (predeclared criteria)

| Slot | Purpose |
|------|---------|
| M-A | Strong remote instruction-following model |
| M-B | Different remote model family / architecture |
| M-C | Local / private open-weight model |

Selection criteria (declared **before** choosing, never "because it favours Continuum"):
tool-use support, structured-output support, stable version availability, adequate context
length, reproducible API/local runtime, feasible cost, material family diversity.

## Experimental unit & sample size

Unit = `(Model, Baseline, Task, AttackCondition, Seed)`.
Base scale = `3 models × 4 baselines × 9 tasks × 5 seeds = 540 runs` (`expectedRunCount`),
excluding infrastructure retries. **Execution must not begin until the full maximum-cost
envelope** (input/output tokens, monetary cost, local GPU time, wall-clock, failure
allowance) is computed and pinned as budget caps (guarded: all caps > 0 required).

## Statistical-analysis plan (finalized before results)

- **Primary endpoints:** benign task utility · security-violation occurrence · sensitive-
  field disclosure · injection-following occurrence · model-refusal occurrence.
- **Secondary (operational):** latency, tokens, cost, evidence volume.
- **Binary outcomes:** raw counts + proportions + confidence intervals; mixed-effects
  logistic where sample size permits.
- **Utility:** distribution by workload/baseline/model; ordinal/bounded model; seeds not
  treated as fully independent within a task.
- **Structure:** `Outcome ~ Baseline + Model + Workload + Baseline×Model + (1|Task)`.
- **Contrasts (predeclared):** B3 vs B2 · B3 vs B1 · B2 vs B1 · B3 × model-family
  interaction. Multiple-testing: adjusted CIs; Holm correction for secondary comparisons.

The three questions reported separately — **baseline effect**, **model effect**,
**baseline × model interaction** — never collapsed into a single winner score.

## French multilingual residual

Carried **unchanged** as a pre-registered adversarial case. The study records, per model,
whether it: follows the payload under B0/B1/B2 · treats it as inert data under B3 · refuses
it · misunderstands it · attempts an unauthorized action. **No translation or multilingual
detector is added before this experiment** — that would remove the external-validity
question the case is designed to test.

---

## Execution controls

- Fail-closed guard `assertReadyForExecution()` (all operator fields pinned, budgets set,
  prompt hash frozen and matching, reviewer sign-off true, kill switch disengaged).
- **Kill switch** defaults **engaged**; disengaged only under review, re-engageable mid-run.
- Raw model outputs and **all failures retained**; refusals scored separately from denials.
- No provider client, no credentials, no network code exists in `src/v2`.

## Claim boundaries

This manifest supports **no empirical claim**. It registers the frame only. It does not
establish real-model validation, cross-model consistency, provider independence, multilingual
robustness, statistical superiority, or external validity — none of which exist until the
experiment is run and reviewed.

## Next step (held)

Pin the operator fields under review, set budgets, freeze the prompt-surface hash into the
manifest, obtain reviewer sign-off, disengage the kill switch, then wire reviewed provider
clients behind the `ModelProvider` interface and run. Execution begins **only** after the
identities, total budget, and analysis plan are frozen and reviewed.

Guard check (no model): `npx vitest run --root research/sif-bench/comparative src/v2/registration.test.ts`
