/**
 * B0 — unrestricted agent. Full corpus available, no intent enforcement, no minimum
 * disclosure, no proof-of-possession, direct simulated tool access. Logging is
 * permitted but there is no preventive governance. The permissive ceiling.
 */
import type { Baseline, Env, Outcome, Task } from "../schemas";
import { assemble, baseCost, fullProjection } from "./common";

export const B0: Baseline = {
  id: "B0",
  label: "Unrestricted agent",
  run(env: Env, task: Task): Outcome {
    // Everything retrievable is disclosed, in full, with no channel separation.
    const objs = env.retrieval_candidates
      .map((id) => env.corpus.find((o) => o.id === id))
      .filter((o): o is NonNullable<typeof o> => o !== undefined)
      .map(fullProjection);
    const disclosed_fields = Object.fromEntries(objs.map((o) => [o.id, Object.keys(o.fields)]));
    return assemble("B0", env, task, {
      admitted: objs,
      disclosed_fields,
      ctx: { agent_prompt: task.agent_prompt, instructions_separated: false, injection_screened: false, tool_gate: false, permitted_tools: [] },
      cost: baseCost({ retrieval_ops: 1, policy_evaluations: 0, db_queries: 1 }),
      evidence_records: 0,
    });
  },
};
