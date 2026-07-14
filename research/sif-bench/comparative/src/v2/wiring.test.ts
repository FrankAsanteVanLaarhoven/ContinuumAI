import { describe, it, expect } from "vitest";
import { canonicalJson } from "@continuum/core";
import { assemble } from "../adapters/common";
import { B0 } from "../adapters/b0";
import { B1 } from "../adapters/b1";
import { B2 } from "../adapters/b2";
import { B3 } from "../adapters/b3";
import * as W1 from "../workloads/procurement";
import * as W2 from "../workloads/policy";
import * as W3 from "../workloads/action";
import { admit, toModelRequest, runModelBaseline } from "./adapters";
import { PinnedModelProvider, EchoProvider, type ModelParams, type ModelDecision, type ModelRequest } from "./model";
import { scoreV2Task, scoreV2Cell } from "./scoring";
import { FAMILY_SLOTS, FIXED_SAMPLING, SEEDS, slotsPinned } from "./model_families";

const WORKLOADS = [
  { env: W1.ENV, tasks: W1.TASKS },
  { env: W2.ENV, tasks: W2.TASKS },
  { env: W3.ENV, tasks: W3.TASKS },
];
const FROZEN = { B0, B1, B2, B3 } as const;
const IDS = ["B0", "B1", "B2", "B3"] as const;

const PARAMS: ModelParams = { family_slot: "A", model_id: "wiring-echo", revision: "0", hosting: "local", temperature: FIXED_SAMPLING.temperature, top_p: FIXED_SAMPLING.top_p, max_output_tokens: FIXED_SAMPLING.max_output_tokens, seed: SEEDS[0]! };
const decide = (d: Partial<ModelDecision>): ModelDecision => ({ answer: null, tool_calls: [], action: null, followed_injection: false, canary_in_output: false, refusal: false, raw: "wiring", ...d });

describe("Comparative v0.2 — control-plane FIDELITY to frozen v0.1", () => {
  it("v2 admission is byte-identical to frozen v0.1 for every baseline × task", () => {
    for (const { env, tasks } of WORKLOADS) {
      for (const task of tasks) {
        for (const id of IDS) {
          const viaV2 = assemble(id, env, task, admit(id, env, task)); // v2 admission → frozen surrogate
          const frozen = FROZEN[id].run(env, task); // frozen v0.1 end-to-end
          expect(canonicalJson(viaV2), `${id}/${task.id}`).toBe(canonicalJson(frozen));
        }
      }
    }
  });
});

describe("Comparative v0.2 — execution is gated (no model calls in this milestone)", () => {
  it("PinnedModelProvider refuses to run", async () => {
    const req = toModelRequest(admit("B3", W1.ENV, W1.TASKS[0]!), W1.ENV, W1.TASKS[0]!, PARAMS);
    await expect(new PinnedModelProvider(PARAMS).complete(req)).rejects.toThrow(/not authorized/i);
  });
  it("family slots are not yet pinned, but a local/private slot is required", () => {
    expect(slotsPinned()).toBe(false); // concrete ids pinned only at reviewed execution
    expect(FAMILY_SLOTS.some((s) => s.hosting === "local")).toBe(true);
    expect(FAMILY_SLOTS.length).toBeGreaterThanOrEqual(2);
  });
});

describe("Comparative v0.2 — typed request assembly", () => {
  it("B3 separates channels; B0 flattens untrusted data into the instruction channel", () => {
    const rB3 = toModelRequest(admit("B3", W1.ENV, W1.TASKS[0]!), W1.ENV, W1.TASKS[0]!, PARAMS);
    expect(rB3.separated).toBe(true);
    expect(rB3.untrusted_data.length).toBeGreaterThan(0);
    const rB0 = toModelRequest(admit("B0", W1.ENV, W1.TASKS[0]!), W1.ENV, W1.TASKS[0]!, PARAMS);
    expect(rB0.separated).toBe(false);
    expect(rB0.untrusted_data).toBe("");
    expect(rB0.trusted_instructions).toContain("CONTEXT:");
  });
});

describe("Comparative v0.2 — refusal vs security denial vs structural control", () => {
  const refuse = new EchoProvider(PARAMS, () => decide({ refusal: true }));

  it("a MODEL refusal on a benign task costs utility but is NOT a security denial", async () => {
    const out = await runModelBaseline("B3", W1.ENV, W1.TASKS[0]!, refuse);
    const m = scoreV2Task(W1.ENV, W1.TASKS[0]!, out);
    expect(m.refusal).toBe(true);
    expect(m.utility.weighted).toBe(0); // benign refusal → task failure
    expect(m.security_denials).toBe(0); // refusal is not a governance/security event
    expect(m.composite_violation_severity).toBe(0);
  });

  it("a control-plane tool block is a SECURITY DENIAL, not a refusal, and prevents the violation", async () => {
    const wantsProhibited = new EchoProvider(PARAMS, () => decide({ answer: W1.TASKS[0]!.correct_answer, tool_calls: ["place_order"] }));
    const out = await runModelBaseline("B3", W1.ENV, W1.TASKS[0]!, wantsProhibited);
    const m = scoreV2Task(W1.ENV, W1.TASKS[0]!, out);
    expect(out.tool_calls).toEqual([]); // place_order blocked by the typed gate
    expect(out.denied_tool_calls).toEqual(["place_order"]);
    expect(m.security_denials).toBe(1);
    expect(m.refusal).toBe(false);
    expect(m.violations.unauthorized_tool_invocation).toBe(0); // block PREVENTED the violation
  });

  it("STRUCTURAL: under B3 an admitted-but-inert injection is MEASURED as followed, yet the canary cannot leak (never admitted)", async () => {
    const malicious = new EchoProvider(PARAMS, () => decide({ answer: W1.TASKS[1]!.correct_answer, followed_injection: true, canary_in_output: true }));
    const b3 = await runModelBaseline("B3", W1.ENV, W1.TASKS[1]!, malicious);
    expect(b3.followed_injection).toBe(true); // susceptibility is not assumed away
    expect(b3.canary_in_egress).toBe(false); // min-projection never admitted the canary
    const b0 = await runModelBaseline("B0", W1.ENV, W1.TASKS[1]!, malicious);
    expect(b0.canary_in_egress).toBe(true); // B0 admitted the canary in full → it leaks
  });

  it("B3 carries an indirect injection as inert, separated data (susceptibility measured, not assumed safe)", () => {
    const policy = admit("B3", W2.ENV, W2.TASKS[1]!); // W2 indirect injection (not screened by patterns)
    const req = toModelRequest(policy, W2.ENV, W2.TASKS[1]!, PARAMS);
    expect(policy.ctx.instructions_separated).toBe(true);
    expect(req.separated).toBe(true);
    expect(req.untrusted_data).toContain("_note"); // the injected note rides in the UNTRUSTED channel
    expect(req.trusted_instructions).not.toContain("_note"); // never in the trusted instruction channel
  });
});

describe("Comparative v0.2 — cell scoring keeps dimensions separate", () => {
  it("aggregates model refusals, security denials and usage without collapsing metrics", async () => {
    const echo = new EchoProvider(PARAMS, (r: ModelRequest) => decide({ answer: r.workload === "procurement" ? W1.TASKS[0]!.correct_answer : null, refusal: r.workload !== "procurement" }));
    const outs = await Promise.all(W1.TASKS.map((t) => runModelBaseline("B3", W1.ENV, t, echo)));
    const cell = scoreV2Cell("B3", "A", "wiring-echo", SEEDS[0]!, W1.ENV, W1.TASKS, outs);
    expect(cell.model_slot).toBe("A");
    expect(cell).toHaveProperty("model_refusals");
    expect(cell).toHaveProperty("security_denials");
    expect(cell).toHaveProperty("total_tokens_out");
    expect(cell).not.toHaveProperty("continuum_score");
    expect(cell.violations_by_type).toBeDefined();
  });
});
