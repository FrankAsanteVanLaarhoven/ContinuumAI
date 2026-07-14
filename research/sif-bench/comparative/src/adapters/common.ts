/**
 * Shared adapter helpers: fixed retrieval, projection, cost accounting, and outcome
 * assembly. Baselines differ only in the policy they apply on top of these.
 */
import { canonicalJson } from "@continuum/core";
import type { Env, MemoryObject, Outcome, Task, CostProxy } from "../schemas";
import { ZERO_COST } from "../schemas";
import { runSurrogate, type AdmittedContext, type AdmittedObject } from "../surrogate";

/** Deterministic top-k retrieval over the shared candidate set (identical for all). */
export function topK(env: Env): MemoryObject[] {
  const byId = new Map(env.corpus.map((o) => [o.id, o]));
  return env.retrieval_candidates
    .map((id) => byId.get(id))
    .filter((o): o is MemoryObject => o !== undefined)
    .sort((a, b) => b.retrieval_score - a.retrieval_score)
    .slice(0, env.retrieval_k);
}

export function bytesOf(objs: AdmittedObject[], prompt: string): number {
  return canonicalJson(objs).length + prompt.length;
}

/** Is the produced answer the ground-truth correct one? */
export function answerCorrect(answer: unknown, task: Task): boolean {
  return canonicalJson(answer) === canonicalJson(task.correct_answer);
}

export interface PolicyResult {
  admitted: AdmittedObject[];
  disclosed_fields: Record<string, string[]>;
  ctx: Omit<AdmittedContext, "objects">;
  cost: CostProxy;
  evidence_records: number;
}

/** Assemble an Outcome from a policy decision + the shared surrogate. */
export function assemble(baseline: string, env: Env, task: Task, policy: PolicyResult): Outcome {
  const ctx: AdmittedContext = { objects: policy.admitted, ...policy.ctx };
  const s = runSurrogate(ctx, task);
  const cost: CostProxy = {
    ...policy.cost,
    context_bytes: bytesOf(policy.admitted, task.agent_prompt),
    tool_calls: s.tool_calls.length,
    evidence_writes: policy.evidence_records,
    latency_ops:
      policy.cost.retrieval_ops +
      policy.cost.policy_evaluations +
      policy.cost.db_queries +
      s.tool_calls.length +
      policy.evidence_records +
      Math.ceil(bytesOf(policy.admitted, task.agent_prompt) / 64),
  };
  return {
    baseline,
    task_id: task.id,
    disclosed_object_ids: policy.admitted.map((o) => o.id),
    disclosed_fields: policy.disclosed_fields,
    answer: s.answer,
    answer_correct: answerCorrect(s.answer, task),
    tool_calls: s.tool_calls,
    followed_injection: s.followed_injection,
    canary_in_egress: s.canary_in_egress,
    evidence_records: policy.evidence_records,
    cost,
  };
}

export function fullProjection(o: MemoryObject): AdmittedObject {
  const a: AdmittedObject = { id: o.id, tenant: o.tenant, fields: o.fields };
  if (o.injected_instruction !== undefined) a.injected_instruction = o.injected_instruction;
  if (o.canary_token !== undefined) a.canary_token = o.canary_token;
  return a;
}

export function baseCost(overrides: Partial<CostProxy> = {}): CostProxy {
  return { ...ZERO_COST, ...overrides };
}
