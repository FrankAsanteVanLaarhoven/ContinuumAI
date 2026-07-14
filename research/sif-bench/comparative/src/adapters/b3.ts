/**
 * B3 — Continuum (frozen target configuration): entitlement-bound scope + tenant
 * binding (I1/I5), caller-bound MINIMUM projection (I2), structured instruction/data
 * separation + bounded decode/normalize screening (I7-C, using the REAL
 * `decodeNormalize`), typed tool gate, and per-disclosure evidence envelopes (I6).
 * Continuous freshness (I3), holder-bound proof-of-possession (I4) and idempotent
 * action identity (I6) are carried as target properties; the durable RLS + evidence
 * chain (I5 / persistence) is the persistence tier, referenced not re-simulated here.
 */
import { DEFAULT_INJECTION_PATTERNS, decodeNormalize } from "@continuum/core";
import type { Baseline, Classification, Env, MemoryObject, Outcome, Task } from "../schemas";
import { assemble, baseCost } from "./common";
import type { AdmittedObject } from "../surrogate";

const RANK: Record<Classification, number> = { public: 0, internal: 1, confidential: 2, restricted: 3 };
const CEILING: Classification = "confidential"; // owner intent ceiling for the procurement purpose

function i7cScreen(text: string): boolean {
  const norm = decodeNormalize(text);
  if (norm.fail_closed) return true; // fail closed → treat as suspicious
  return DEFAULT_INJECTION_PATTERNS.some((p) => new RegExp(p, "i").test(norm.surface));
}

export const B3: Baseline = {
  id: "B3",
  label: "Continuum (I1-I7 target)",
  run(env: Env, task: Task): Outcome {
    // Entitlement-bound scope + tenant + classification ceiling (I1/I5).
    const scoped: MemoryObject[] = env.retrieval_candidates
      .map((id) => env.corpus.find((o) => o.id === id))
      .filter((o): o is MemoryObject => o !== undefined)
      .filter((o) => o.tenant === task.tenant)
      .filter((o) => task.requested_operations.includes(o.read_operation))
      .filter((o) => !task.prohibited_operations.includes(o.read_operation))
      .filter((o) => RANK[o.classification] <= RANK[CEILING]);

    // Minimum projection (I2): only the fields the task actually needs.
    const admitted: AdmittedObject[] = scoped.map((o) => {
      const needed = task.required_fields[o.id] ?? [];
      const fields: Record<string, unknown> = {};
      for (const f of needed) if (f in o.fields) fields[f] = o.fields[f];
      // Structured separation: the injected instruction is carried as inert DATA, never
      // as an instruction (instructions_separated=true below); a planted canary is not
      // projected unless explicitly required (it never is).
      const a: AdmittedObject = { id: o.id, tenant: o.tenant, fields };
      if (o.injected_instruction !== undefined) a.injected_instruction = o.injected_instruction;
      return a;
    });
    const disclosed_fields = Object.fromEntries(admitted.map((o) => [o.id, Object.keys(o.fields)]));

    // Typed tool gate: registered + operation-authorized, non-prohibited only.
    const permitted_tools = env.tools
      .filter((t) => t.registered && t.authorized_operations.some((op) => task.requested_operations.includes(op)) && !t.authorized_operations.some((op) => task.prohibited_operations.includes(op)))
      .map((t) => t.name);

    // I7-C screen over the agent prompt (direct injection); indirect injection is
    // handled by structured separation (instructions_separated=true).
    const injection_screened = i7cScreen(task.agent_prompt);

    return assemble("B3", env, task, {
      admitted,
      disclosed_fields,
      ctx: { agent_prompt: task.agent_prompt, instructions_separated: true, injection_screened, tool_gate: true, permitted_tools },
      cost: baseCost({ retrieval_ops: 1, policy_evaluations: 5, db_queries: 2 }),
      evidence_records: admitted.length + 1, // per-disclosure envelopes + the authorization decision
    });
  },
};
