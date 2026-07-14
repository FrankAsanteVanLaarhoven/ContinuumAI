/**
 * Comparative v0.2 — model-registration manifest + fail-closed execution guard.
 *
 * This registers the EXPERIMENTAL FRAME for the real-model study and makes execution
 * impossible until the model identities, budgets, prompt-surface freeze, and reviewer
 * sign-off are all pinned. NO model is called here. `assertReadyForExecution` returns the
 * list of unmet conditions; an execution runner MUST refuse to start while that list is
 * non-empty (the runner does not exist yet — this milestone is registration only).
 *
 * Policies I can define authoritatively from the frozen artefacts and the review are pinned
 * below (retry, failure classes, data retention, statistical plan, scoring-leakage rules,
 * three-blocking distinction, seeds, prompt surface). Values that are the operator's
 * decision (exact model ids/revisions/digests, hosting, regions, budget caps, sign-off) are
 * left UNPINNED in `REGISTRATION_TEMPLATE` and fail closed until frozen under review.
 */
import { sha256Hex, canonicalJson } from "@continuum/core";
import { INSTRUCTION_TEMPLATE, OUTPUT_SCHEMA } from "./adapters";
import { SEEDS } from "./model_families";

export type HostingClass = "LOCAL_PRIVATE" | "PRIVATE_TENANT" | "REMOTE_ZERO_RETENTION" | "REMOTE_STANDARD";

export interface SamplingConfig {
  temperature: number;
  top_p: number;
  top_k: number | null;
  max_output_tokens: number;
  frequency_penalty: number | null;
  presence_penalty: number | null;
  stop: string[];
  reasoning_effort: string | null;
  tool_choice: string;
  response_format: string;
  seed_reproducibility: "guaranteed" | "requested_only"; // provider may not guarantee seed replay
}

export interface ModelSlotRegistration {
  slot: "A" | "B" | "C";
  role: string;
  hosting_class: HostingClass | null;
  model_id: string | null;
  revision: string | null;
  artifact_digest: string | null; // required for a LOCAL_PRIVATE open-weights slot
  runtime_version: string | null;
  serving_framework: string | null;
  quantization: string | null;
  context_window: number | null;
  region: string | null;
  endpoint_class: string | null;
  date_accessed: string | null;
  prompt_retained: boolean | null; // provider data policy
  used_for_training: boolean | null;
  sampling: SamplingConfig;
}

export interface RetryPolicy {
  max_infra_retries: number;
  same_params: boolean;
  same_input: boolean;
  retain_original_failure: boolean;
  mark_retry_separately: boolean;
  no_retry_on: string[];
}

export type FailureClass =
  | "http_api_failure"
  | "timeout"
  | "rate_limit"
  | "empty_response"
  | "invalid_json"
  | "schema_mismatch"
  | "tool_call_parse_failure"
  | "safety_refusal"
  | "partial_refusal"
  | "truncated_output"
  | "provider_content_filtering"
  | "context_length_failure"
  | "local_model_crash";

export interface DataRetentionPolicy {
  store: string[];
  never_store: string[];
  access_controlled: boolean;
}

export interface ExperimentBudget {
  max_input_tokens: number | null;
  max_output_tokens: number | null;
  max_cost_usd: number | null;
  max_gpu_hours: number | null;
  max_wall_clock_hours: number | null;
  failure_allowance_pct: number | null;
}

export interface StatisticalPlan {
  primary_endpoints: string[];
  secondary_outcomes: string[];
  model_formula: string;
  predeclared_contrasts: string[];
  multiple_testing_correction: string;
  binary_outcome_method: string;
  utility_outcome_method: string;
}

export interface ModelRegistration {
  version: "0.2-registration";
  synthetic_fixtures_only: boolean;
  slots: ModelSlotRegistration[];
  seeds: readonly number[];
  baselines: readonly string[];
  task_count: number;
  budget: ExperimentBudget;
  retry: RetryPolicy;
  failure_classes: readonly FailureClass[];
  data_retention: DataRetentionPolicy;
  statistical_plan: StatisticalPlan;
  scoring_leakage_prevention: string[];
  three_blocking_distinction: string[];
  prompt_surface_hash: string | null; // must equal PROMPT_SURFACE_HASH before execution
  kill_switch: "engaged" | "disengaged";
  reviewer_signoff: boolean;
}

// ---- Authoritatively pre-registered policies (from the frozen artefacts + review) ----

/** Hash of the frozen prompt surface the model sees; pin this into the manifest. */
export const PROMPT_SURFACE_HASH: string = sha256Hex(canonicalJson({ INSTRUCTION_TEMPLATE, OUTPUT_SCHEMA }));

export const RETRY_POLICY: RetryPolicy = {
  max_infra_retries: 1,
  same_params: true,
  same_input: true,
  retain_original_failure: true,
  mark_retry_separately: true,
  no_retry_on: ["safety_refusal", "partial_refusal", "incorrect_output", "schema_mismatch"],
};

export const FAILURE_CLASSES: readonly FailureClass[] = [
  "http_api_failure", "timeout", "rate_limit", "empty_response", "invalid_json", "schema_mismatch",
  "tool_call_parse_failure", "safety_refusal", "partial_refusal", "truncated_output",
  "provider_content_filtering", "context_length_failure", "local_model_crash",
] as const;

export const DATA_RETENTION: DataRetentionPolicy = {
  store: ["redacted_request_body", "model_output", "model_metadata", "token_counts", "latency", "provider_request_id_if_safe", "scoring_result", "failure_classification", "run_manifest"],
  never_store: ["api_keys", "authentication_headers", "reusable_proof_material", "raw_secrets", "real_personal_or_enterprise_data"],
  access_controlled: true,
};

export const STATISTICAL_PLAN: StatisticalPlan = {
  primary_endpoints: ["benign_task_utility", "security_violation_occurrence", "sensitive_field_disclosure", "injection_following_occurrence", "model_refusal_occurrence"],
  secondary_outcomes: ["latency_ms", "tokens_in", "tokens_out", "cost_usd", "evidence_volume"],
  model_formula: "Outcome ~ Baseline + Model + Workload + Baseline*Model + (1|Task)",
  predeclared_contrasts: ["B3 vs B2", "B3 vs B1", "B2 vs B1", "B3 x model-family interaction"],
  multiple_testing_correction: "adjusted CIs; Holm correction for secondary comparisons",
  binary_outcome_method: "raw counts + proportions + CIs; mixed-effects logistic where sample size permits",
  utility_outcome_method: "distribution by workload/baseline/model; ordinal/bounded model; seeds not treated as fully independent within a task",
};

export const SCORING_LEAKAGE_PREVENTION: string[] = [
  "expected answer is NEVER included in the model request",
  "prefer deterministic exact / schema-based scoring",
  "security scoring stays rule-based",
  "blinded human adjudication only for genuinely semantic cases",
  "an evaluated model is never its own judge",
  "record inter-rater agreement if human adjudication is used",
];

export const THREE_BLOCKING_DISTINCTION: string[] = [
  "control-plane prevention: information/action never reaches the model or tool",
  "model refusal: the model receives sufficient content but refuses",
  "model non-compliance/failure: incorrect, malformed, or irrelevant result",
];

const BASELINES = ["B0", "B1", "B2", "B3"] as const;
const TASK_COUNT = 9; // W1(2) + W2(2) + W3(5), frozen

export function expectedRunCount(reg: ModelRegistration): number {
  return reg.slots.length * reg.baselines.length * reg.task_count * reg.seeds.length;
}

/** Default sampling row: pre-registered temperature/top_p/max; the rest pinned under review. */
function templateSampling(): SamplingConfig {
  return {
    temperature: 0.7,
    top_p: 1.0,
    top_k: null,
    max_output_tokens: 512,
    frequency_penalty: null,
    presence_penalty: null,
    stop: [],
    reasoning_effort: null,
    tool_choice: "auto",
    response_format: "json",
    seed_reproducibility: "requested_only",
  };
}

function templateSlot(slot: "A" | "B" | "C", role: string): ModelSlotRegistration {
  return {
    slot, role,
    hosting_class: null, model_id: null, revision: null, artifact_digest: null, runtime_version: null,
    serving_framework: null, quantization: null, context_window: null, region: null, endpoint_class: null,
    date_accessed: null, prompt_retained: null, used_for_training: null, sampling: templateSampling(),
  };
}

/**
 * The UNPINNED template — fails closed. The operator pins model identities, hosting, budgets,
 * prompt-surface hash, and reviewer sign-off under review before any execution.
 */
export const REGISTRATION_TEMPLATE: ModelRegistration = {
  version: "0.2-registration",
  synthetic_fixtures_only: true, // the frozen W1-W3 fixtures are synthetic by construction
  slots: [
    templateSlot("A", "Strong remote instruction-following model"),
    templateSlot("B", "Different remote model family / architecture"),
    templateSlot("C", "Local / private open-weight model"),
  ],
  seeds: SEEDS,
  baselines: BASELINES,
  task_count: TASK_COUNT,
  budget: { max_input_tokens: null, max_output_tokens: null, max_cost_usd: null, max_gpu_hours: null, max_wall_clock_hours: null, failure_allowance_pct: null },
  retry: RETRY_POLICY,
  failure_classes: FAILURE_CLASSES,
  data_retention: DATA_RETENTION,
  statistical_plan: STATISTICAL_PLAN,
  scoring_leakage_prevention: SCORING_LEAKAGE_PREVENTION,
  three_blocking_distinction: THREE_BLOCKING_DISTINCTION,
  prompt_surface_hash: null, // pin to PROMPT_SURFACE_HASH under review
  kill_switch: "engaged", // engaged blocks execution; disengage only under review
  reviewer_signoff: false,
};

/**
 * Fail-closed guard. Returns the list of unmet conditions; an execution runner MUST refuse to
 * start unless this is empty. Never returns "ready" for the unpinned template.
 */
export function assertReadyForExecution(reg: ModelRegistration): string[] {
  const unmet: string[] = [];
  if (!reg.synthetic_fixtures_only) unmet.push("synthetic_fixtures_only must be true");
  for (const s of reg.slots) {
    if (!s.model_id) unmet.push(`slot ${s.slot}: model_id not pinned`);
    if (!s.revision) unmet.push(`slot ${s.slot}: revision not pinned`);
    if (!s.hosting_class) unmet.push(`slot ${s.slot}: hosting_class not set`);
    if (s.hosting_class === "LOCAL_PRIVATE" && !s.artifact_digest) unmet.push(`slot ${s.slot}: local artifact_digest required`);
    if (!s.date_accessed) unmet.push(`slot ${s.slot}: date_accessed not recorded`);
  }
  if (!reg.slots.some((s) => s.hosting_class === "LOCAL_PRIVATE" || s.hosting_class === "PRIVATE_TENANT")) unmet.push("at least one LOCAL_PRIVATE/PRIVATE_TENANT slot required");
  const b = reg.budget;
  const caps: Array<[string, number | null]> = [["max_input_tokens", b.max_input_tokens], ["max_output_tokens", b.max_output_tokens], ["max_cost_usd", b.max_cost_usd], ["max_gpu_hours", b.max_gpu_hours], ["max_wall_clock_hours", b.max_wall_clock_hours]];
  for (const [k, v] of caps) if (v === null || v <= 0) unmet.push(`budget.${k} not set (>0 required)`);
  if (b.failure_allowance_pct === null || b.failure_allowance_pct < 0) unmet.push("budget.failure_allowance_pct not set (>=0 required)");
  if (reg.prompt_surface_hash === null) unmet.push("prompt_surface_hash not frozen");
  else if (reg.prompt_surface_hash !== PROMPT_SURFACE_HASH) unmet.push("prompt_surface_hash mismatch (prompt surface changed)");
  if (reg.kill_switch !== "disengaged") unmet.push("kill_switch engaged");
  if (!reg.reviewer_signoff) unmet.push("reviewer_signoff required");
  if (reg.seeds.length < 1) unmet.push("no seeds");
  return unmet;
}

export function isReadyForExecution(reg: ModelRegistration): boolean {
  return assertReadyForExecution(reg).length === 0;
}
