/**
 * B2 — strong conventional enterprise baseline (NOT a straw man). Authenticated
 * principal, tenant filtering, role/resource authorization, conventional bearer token,
 * a registered tool catalogue, a standard audit log, and basic input validation
 * (a heuristic content filter). It EXCLUDES only Continuum's tested contributions:
 * structured semantic intent binding, entitlement-intersection capabilities,
 * holder-bound proof-of-possession, continuous authority freshness, minimum metadata
 * projection, per-disclosure evidence envelopes, and the I1-I7 control composition —
 * so it over-discloses fields and has no structured instruction/data separation.
 */
import { DEFAULT_INJECTION_PATTERNS } from "@continuum/core";
import type { Baseline, Env, Outcome, Task } from "../schemas";
import { assemble, baseCost, fullProjection, topK } from "./common";

function heuristicScreen(text: string): boolean {
  const s = text.toLowerCase();
  return DEFAULT_INJECTION_PATTERNS.some((p) => new RegExp(p, "i").test(s));
}

export const B2: Baseline = {
  id: "B2",
  label: "Strong RBAC / tenant-filtered RAG",
  run(env: Env, task: Task): Outcome {
    // Tenant + resource-level authorization on top of top-k retrieval.
    const objs = topK(env)
      .filter((o) => o.tenant === task.tenant && task.requested_operations.includes(o.read_operation))
      .map(fullProjection); // conventional RBAC discloses full records (no min projection)
    const disclosed_fields = Object.fromEntries(objs.map((o) => [o.id, Object.keys(o.fields)]));

    // Registered tool catalogue: only registered + operation-authorized, non-prohibited tools.
    const permitted_tools = env.tools
      .filter((t) => t.registered && t.authorized_operations.some((op) => task.requested_operations.includes(op)) && !t.authorized_operations.some((op) => task.prohibited_operations.includes(op)))
      .map((t) => t.name);

    // Basic input validation / content filter over the prompt and retrieved data (raw).
    const screenText = [task.agent_prompt, ...objs.map((o) => o.injected_instruction ?? "")].join(" ");
    const injection_screened = heuristicScreen(screenText);

    return assemble("B2", env, task, {
      admitted: objs,
      disclosed_fields,
      // Conventional enterprise workflow HAS an approval gate, but no replay
      // resistance, idempotency, or continuous freshness re-check.
      ctx: { agent_prompt: task.agent_prompt, instructions_separated: false, injection_screened, tool_gate: true, permitted_tools, requires_approval: true, replay_resistant: false, idempotent: false, freshness_checked: false },
      cost: baseCost({ retrieval_ops: 1, policy_evaluations: 2, db_queries: 2 }),
      evidence_records: objs.length, // conventional audit log: one row per disclosure
    });
  },
};
