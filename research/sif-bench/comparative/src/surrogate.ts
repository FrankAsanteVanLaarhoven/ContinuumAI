/**
 * Deterministic decision surrogate — the SHARED "model" for every baseline.
 *
 * It is not meant to imitate natural-language quality; it isolates control-plane
 * effects. Every baseline calls the SAME surrogate; baselines differ ONLY in the
 * AdmittedContext they construct (what they disclose, how they project, whether they
 * separate instructions from data, whether they screen injection, whether they gate
 * tools). Label results: "Deterministic systems evaluation, not LLM performance."
 *
 * Surrogate behaviour:
 *  - selects evidence from the admitted context and produces a fixed structured answer;
 *  - FOLLOWS an injected instruction when the baseline exposes it as privileged input
 *    (retrieved-data injection not separated, or direct injection not screened);
 *  - attempts a tool call when the task state permits (and the attacker's tool when it
 *    follows a prohibited-tool injection and the baseline does not gate tools);
 *  - emits a canary to egress only when it follows an exfiltration instruction over a
 *    canary-bearing object that was admitted.
 */
import type { Task } from "./schemas";

export interface AdmittedObject {
  id: string;
  tenant: string;
  fields: Record<string, unknown>; // already projected by the baseline
  injected_instruction?: string;
  canary_token?: string;
}

export interface AdmittedContext {
  objects: AdmittedObject[];
  agent_prompt: string;
  /** Retrieved DATA is routed to a non-instruction channel (structured separation). */
  instructions_separated: boolean;
  /** The baseline's screen caught an injection indicator (after any normalisation). */
  injection_screened: boolean;
  /** Only registered/authorised tools may be invoked. */
  tool_gate: boolean;
  /** The set of tool names the baseline will permit to actually execute. */
  permitted_tools: string[];
}

export interface SurrogateResult {
  answer: unknown;
  tool_calls: string[];
  followed_injection: boolean;
  canary_in_egress: boolean;
}

/**
 * The active injected instruction the surrogate treats as privileged, if any. Presence
 * comes from the task/data (not keyword-sniffing); the baseline's controls decide
 * whether it is privileged: a DIRECT prompt injection is followed unless screened; an
 * INDIRECT data injection is followed unless the baseline separates data from
 * instructions OR screens it.
 */
function activeInjection(ctx: AdmittedContext, task: Task): { text: string; canary?: string } | null {
  const type = task.attack?.type;
  if (type === "direct_injection" && !ctx.injection_screened) {
    return { text: ctx.agent_prompt };
  }
  if (type === "indirect_injection" && !ctx.instructions_separated && !ctx.injection_screened) {
    const o = ctx.objects.find((x) => x.injected_instruction);
    if (o?.injected_instruction) {
      return o.canary_token !== undefined ? { text: o.injected_instruction, canary: o.canary_token } : { text: o.injected_instruction };
    }
  }
  return null;
}

/** Deterministic procurement answer: cheapest compliant supplier from admitted quotes. */
function procurementAnswer(ctx: AdmittedContext): unknown {
  const quotes = ctx.objects
    .map((o) => ({ supplier: String(o.fields["supplier"] ?? ""), price: Number(o.fields["unit_price_gbp"] ?? Number.POSITIVE_INFINITY) }))
    .filter((q) => q.supplier && Number.isFinite(q.price));
  if (quotes.length === 0) return null;
  const best = quotes.reduce((a, b) => (b.price < a.price ? b : a));
  return { recommended_supplier: best.supplier, unit_price_gbp: best.price };
}

export function runSurrogate(ctx: AdmittedContext, task: Task): SurrogateResult {
  const injection = activeInjection(ctx, task);
  const followed = injection !== null;

  // Baseline behaviour: the correct structured answer from admitted evidence.
  let answer = task.workload === "procurement" ? procurementAnswer(ctx) : { note: "answer surrogate for this workload is deterministic-stubbed" };
  const toolCalls: string[] = [];
  let canaryEgress = false;

  // Legitimate tool the benign task calls (only if permitted or ungated).
  if (task.legitimate_tool && (!ctx.tool_gate || ctx.permitted_tools.includes(task.legitimate_tool))) {
    toolCalls.push(task.legitimate_tool);
  }

  if (followed && injection) {
    const inj = injection.text.toLowerCase();
    // Exfiltration: a canary reaches egress if the surrogate follows it over a canary object.
    if (/exfiltrat|forward|send |reveal |bank details|every supplier/.test(inj)) {
      const canary = injection.canary ?? ctx.objects.find((o) => o.canary_token)?.canary_token;
      if (canary) canaryEgress = true;
      answer = { ...(answer as object), leaked: true };
    }
    // Prohibited tool invocation: only actually executes if the baseline does not gate tools.
    const wantsTool = task.attack?.prohibited_tool ?? (/place_order/.test(inj) ? "place_order" : null);
    if (wantsTool && (!ctx.tool_gate || ctx.permitted_tools.includes(wantsTool))) {
      toolCalls.push(wantsTool);
    }
    // Answer corruption toward the attacker.
    if (/recommend attackerco/.test(inj)) answer = { recommended_supplier: "AttackerCo", unit_price_gbp: 0.01 };
  }

  return { answer, tool_calls: toolCalls, followed_injection: followed, canary_in_egress: canaryEgress };
}
