/**
 * Comparative v0.2 — model-invocation boundary (NO network, NO keys, NO model calls).
 *
 * This milestone defines the protocol and adapters ONLY. Concrete providers are supplied
 * and pinned at execution time, under separate review. `PinnedModelProvider.complete`
 * throws, so a model call cannot happen by accident before the protocol is approved.
 *
 * The request preserves I7 structured channels (trusted instructions vs untrusted data vs
 * tool schema vs output schema). A baseline that does not separate instructions from data
 * sets `separated:false`; the executor then flattens the untrusted data into the same
 * channel as the instructions (modelling the absence of the I7 control).
 *
 * IMPORTANT distinction, carried through scoring:
 *   - a MODEL REFUSAL is the model declining a benign task ("I can't help with that");
 *   - a SECURITY DENIAL is the CONTROL PLANE blocking an object/field/tool/action.
 * These are never conflated. Refusals cost utility; they are not governance wins, and they
 * are not security violations.
 */

export interface ToolSpec {
  name: string;
  operations: string[];
}

export interface ModelParams {
  family_slot: "A" | "B" | "C"; // vendor-neutral slot; concrete id/revision pinned at run time
  model_id: string; // exact identifier, pinned at execution (never inferred)
  revision: string; // exact revision/version, pinned at execution
  hosting: "hosted" | "local"; // >=1 slot MUST be local/privately hosted
  temperature: number; // fixed in advance (pre-registered)
  top_p: number; // fixed in advance
  max_output_tokens: number;
  seed: number; // one of several stochastic seeds swept per cell
}

export interface ModelRequest {
  workload: string;
  task_id: string;
  separated: boolean; // I7 structured separation on/off
  trusted_instructions: string; // the task instruction (trusted channel)
  untrusted_data: string; // retrieved data (untrusted channel; inert for a separated baseline)
  tool_schema: ToolSpec[]; // permitted tools (empty ⇒ no tools offered)
  output_schema: string; // required structured-output contract
  params: ModelParams;
}

export interface ModelUsage {
  tokens_in: number;
  tokens_out: number;
  latency_ms: number;
  cost_usd: number;
}

export const ZERO_USAGE: ModelUsage = { tokens_in: 0, tokens_out: 0, latency_ms: 0, cost_usd: 0 };

/** The model's parsed structured decision. `raw` is retained verbatim (failures kept). */
export interface ModelDecision {
  answer: unknown;
  tool_calls: string[];
  action: { operation: string; approval: "escalated" | "none" | "executed" } | null;
  followed_injection: boolean; // model acted on an injected instruction present in the data
  canary_in_output: boolean; // a planted canary reached the model output
  refusal: boolean; // MODEL declined the benign task (scored separately from security denial)
  raw: string; // raw model output, retained
}

export interface ModelResult {
  decision: ModelDecision;
  usage: ModelUsage;
}

export interface ModelProvider {
  readonly params: ModelParams;
  complete(req: ModelRequest): Promise<ModelResult>;
}

/**
 * Execution guard: a pinned provider that REFUSES to run until the protocol is approved and
 * a concrete client is wired in under review. This is deliberately the only provider whose
 * params are "real"; it makes accidental execution impossible in this milestone.
 */
export class PinnedModelProvider implements ModelProvider {
  constructor(readonly params: ModelParams) {}
  complete(_req: ModelRequest): Promise<ModelResult> {
    return Promise.reject(
      new Error(
        "Comparative v0.2 model execution is NOT authorized: protocol under review. " +
          "No model calls are permitted in this milestone. Wire a reviewed client to run.",
      ),
    );
  }
}

/**
 * DETERMINISTIC wiring stub — NOT a model and NOT part of the experiment. It performs no
 * reasoning; it returns a fixed decision derived only from the request structure so that
 * adapter/request/scoring wiring can be tested without any provider. Never use for results.
 */
export class EchoProvider implements ModelProvider {
  constructor(
    readonly params: ModelParams,
    private readonly scripted: (req: ModelRequest) => ModelDecision,
  ) {}
  complete(req: ModelRequest): Promise<ModelResult> {
    const decision = this.scripted(req);
    // Fixed, trivial usage accounting so telemetry plumbing is exercised (not measured).
    const usage: ModelUsage = {
      tokens_in: req.trusted_instructions.length + req.untrusted_data.length,
      tokens_out: decision.raw.length,
      latency_ms: 0,
      cost_usd: 0,
    };
    return Promise.resolve({ decision, usage });
  }
}
