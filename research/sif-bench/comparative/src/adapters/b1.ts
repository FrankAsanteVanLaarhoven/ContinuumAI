/**
 * B1 — standard top-(k) RAG. Shared retriever, fixed k, same corpus and query. No
 * tenant/purpose binding, no capability, no continuous revocation, no governed action
 * state machine. Objects enter context by retrieval score alone.
 */
import type { Baseline, Env, Outcome, Task } from "../schemas";
import { assemble, baseCost, fullProjection, topK, NO_CAPS } from "./common";

export const B1: Baseline = {
  id: "B1",
  label: "Standard top-k RAG",
  run(env: Env, task: Task): Outcome {
    const objs = topK(env).map(fullProjection); // score only; no tenant/purpose filter
    const disclosed_fields = Object.fromEntries(objs.map((o) => [o.id, Object.keys(o.fields)]));
    return assemble("B1", env, task, {
      admitted: objs,
      disclosed_fields,
      ctx: { agent_prompt: task.agent_prompt, instructions_separated: false, injection_screened: false, tool_gate: false, permitted_tools: [], ...NO_CAPS },
      cost: baseCost({ retrieval_ops: 1, policy_evaluations: 0, db_queries: 1 }),
      evidence_records: 0,
    });
  },
};
