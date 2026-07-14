/**
 * B0-B3 comparative runner. Every baseline receives the SAME (env, task); the harness
 * checksums the shared inputs and refuses to score if any baseline is handed a
 * different representation. Metrics are reported as SEPARATE dimensions, and a
 * deny-all control is included to prove the utility guard rejects security-by-refusal.
 *
 * Deterministic surrogate, no live model: "systems evaluation, not LLM performance".
 */
import { canonicalJson } from "@continuum/core";
import type { Baseline, Env, Outcome, Task } from "./schemas";
import { inputChecksum, ZERO_COST } from "./schemas";
import { scoreBaseline, type BaselineMetrics } from "./metrics";
import { B0 } from "./adapters/b0";
import { B1 } from "./adapters/b1";
import { B2 } from "./adapters/b2";
import { B3 } from "./adapters/b3";

/** A deny-all control: refuses all work. Must FAIL the utility guard. */
export const DENY_ALL: Baseline = {
  id: "DENY_ALL",
  label: "Deny-all (guard control)",
  run(_env: Env, task: Task): Outcome {
    return {
      baseline: "DENY_ALL",
      task_id: task.id,
      disclosed_object_ids: [],
      disclosed_fields: {},
      answer: null,
      answer_correct: false,
      tool_calls: [],
      followed_injection: false,
      canary_in_egress: false,
      evidence_records: 0,
      cost: { ...ZERO_COST },
    };
  },
};

export const BASELINES: Baseline[] = [B0, B1, B2, B3];

export interface ComparativeReport {
  suite: "SIF-Bench B0-B3 comparative harness (deterministic, harness-validation)";
  version: "0.1.0-comparative";
  label: "Deterministic systems evaluation, not LLM performance";
  status: "PRELIMINARY harness-validation only — not a comparative claim";
  input_manifest: Record<string, string>; // task_id → shared-input checksum
  inputs_identical_across_baselines: boolean;
  baselines: BaselineMetrics[];
  deny_all_guard: { utility_rate: number; utility_guard_passed: boolean };
  utility_guard_rejects_deny_all: boolean;
  passed: boolean;
}

export function runComparative(env: Env, tasks: Task[], baselines: Baseline[] = BASELINES): ComparativeReport {
  // Record the shared-input checksum per task (identical for every baseline).
  const manifest: Record<string, string> = {};
  for (const t of tasks) manifest[t.id] = inputChecksum(env, t);

  // Run every baseline over every task, verifying each saw the same input.
  const outcomesByBaseline = new Map<string, Outcome[]>();
  let identical = true;
  for (const b of [...baselines, DENY_ALL]) {
    const outs: Outcome[] = [];
    for (const t of tasks) {
      const before = canonicalJson({ env, task: t });
      const o = b.run(env, t);
      if (canonicalJson({ env, task: t }) !== before) identical = false; // adapter must not mutate shared inputs
      outs.push(o);
    }
    outcomesByBaseline.set(b.id, outs);
  }

  const metrics = baselines.map((b) => scoreBaseline(b.id, b.label, env, tasks, outcomesByBaseline.get(b.id)!));
  const denyMetrics = scoreBaseline(DENY_ALL.id, DENY_ALL.label, env, tasks, outcomesByBaseline.get(DENY_ALL.id)!);

  return {
    suite: "SIF-Bench B0-B3 comparative harness (deterministic, harness-validation)",
    version: "0.1.0-comparative",
    label: "Deterministic systems evaluation, not LLM performance",
    status: "PRELIMINARY harness-validation only — not a comparative claim",
    input_manifest: manifest,
    inputs_identical_across_baselines: identical,
    baselines: metrics,
    deny_all_guard: { utility_rate: denyMetrics.mean_weighted_utility, utility_guard_passed: denyMetrics.utility_guard_passed },
    utility_guard_rejects_deny_all: !denyMetrics.utility_guard_passed,
    passed: identical && !denyMetrics.utility_guard_passed && metrics.every((m) => m.per_task.length === tasks.length),
  };
}
