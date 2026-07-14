import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PROMPT_SURFACE_HASH, type ModelSlotRegistration } from "./registration";
import {
  buildRegistration,
  executionEnabled,
  placeholders,
  RECOMMENDED_BUDGET,
  RUN_FRAME,
  KILL_SWITCH_STOP_CONDITIONS,
  QUALIFICATION_CHECKLIST,
  PRIMARY_CONTRASTS,
  type OperatorRegistrationFile,
} from "./operator";

const here = dirname(fileURLToPath(import.meta.url));
const examplePath = join(here, "..", "..", "operator.local.example.json");
const exampleRaw = readFileSync(examplePath, "utf8");
const example: OperatorRegistrationFile = JSON.parse(exampleRaw);

/** A fully-pinned SYNTHETIC operator file (vendor-neutral fakes) to prove the gate is satisfiable. */
function pinnedSynthetic(): OperatorRegistrationFile {
  const slot = (id: "A" | "B" | "C", hosting: string, local: boolean): ModelSlotRegistration => ({
    slot: id,
    role: `synthetic-${id}`,
    hosting_class: hosting as ModelSlotRegistration["hosting_class"],
    model_id: `SYNTH-MODEL-${id}`,
    revision: "rev-2026-07-15",
    artifact_digest: local ? "sha256:0000synthetic" : null,
    runtime_version: "runtime-1.0",
    serving_framework: local ? "local-runtime" : "remote-api",
    quantization: local ? "q4" : null,
    context_window: 32768,
    region: local ? "local-owner-controlled" : "eu-west",
    endpoint_class: local ? "local" : "standard",
    date_accessed: "2026-07-15",
    prompt_retained: false,
    used_for_training: false,
    sampling: { temperature: 0.7, top_p: 1.0, top_k: local ? 40 : null, max_output_tokens: 768, frequency_penalty: null, presence_penalty: null, stop: [], reasoning_effort: null, tool_choice: "auto", response_format: "json", seed_reproducibility: "requested_only" },
  });
  return {
    slots: [slot("A", "REMOTE_ZERO_RETENTION", false), slot("B", "REMOTE_ZERO_RETENTION", false), slot("C", "LOCAL_PRIVATE", true)],
    budget: { ...RECOMMENDED_BUDGET },
    prompt_surface_hash: PROMPT_SURFACE_HASH,
    kill_switch: "disengaged",
    verification: { reviewer_signoff: true, artifacts_verified: true, synthetic_data_verified: true, slots_qualified: { A: true, B: true, C: true } },
  };
}

describe("Comparative v0.2 — operator registration bridge (no model calls)", () => {
  it("the committed example commits NO real identities (every model_id is an unpinned placeholder)", () => {
    // Attribution-safe invariant expressed WITHOUT embedding any vendor token: each slot's
    // model_id must still be a placeholder, so no real/branded identity can land in the repo.
    const flagged = placeholders(example);
    for (const s of example.slots) {
      expect(flagged.some((f) => f.startsWith(`slot ${s.slot}: model_id`)), `slot ${s.slot} model_id`).toBe(true);
    }
  });

  it("the committed example FAILS CLOSED (execution impossible)", () => {
    const { enabled, unmet } = executionEnabled(example);
    expect(enabled).toBe(false);
    expect(unmet.some((u) => u.includes("placeholder"))).toBe(true);
    expect(unmet.some((u) => u.includes("kill_switch"))).toBe(true);
    expect(unmet.some((u) => u.includes("reviewer_signoff"))).toBe(true);
    expect(unmet.some((u) => u.includes("qualification"))).toBe(true);
  });

  it("placeholder detection flags every unpinned identity field in the example", () => {
    const flagged = placeholders(example);
    expect(flagged.some((f) => f.includes("model_id"))).toBe(true);
    expect(flagged.some((f) => f.includes("prompt_surface_hash"))).toBe(true);
  });

  it("a fully-pinned synthetic operator file passes the composite gate (satisfiable)", () => {
    const { enabled, unmet } = executionEnabled(pinnedSynthetic());
    expect(unmet).toEqual([]);
    expect(enabled).toBe(true);
  });

  it("removing ANY required condition re-blocks execution (fail-closed integrity)", () => {
    const mutations: Array<(o: OperatorRegistrationFile) => void> = [
      (o) => (o.verification.reviewer_signoff = false),
      (o) => (o.verification.artifacts_verified = false),
      (o) => (o.verification.synthetic_data_verified = false),
      (o) => (o.verification.slots_qualified.C = false),
      (o) => (o.kill_switch = "engaged"),
      (o) => (o.prompt_surface_hash = "deadbeef"),
      (o) => (o.budget.max_cost_usd = null),
      (o) => (o.slots[2]!.artifact_digest = null),
      (o) => (o.slots[0]!.model_id = "PIN: not yet chosen"),
    ];
    for (const mutate of mutations) {
      const o = pinnedSynthetic();
      mutate(o);
      expect(executionEnabled(o).enabled).toBe(false);
    }
  });

  it("buildRegistration carries the operator fields onto the frozen template", () => {
    const reg = buildRegistration(pinnedSynthetic());
    expect(reg.slots.length).toBe(3);
    expect(reg.reviewer_signoff).toBe(true);
    expect(reg.prompt_surface_hash).toBe(PROMPT_SURFACE_HASH);
  });

  it("pre-registers the reviewer's budget ceilings, run frame, kill switch, qualification and contrasts", () => {
    expect(RECOMMENDED_BUDGET.max_cost_usd).toBe(60);
    expect(RECOMMENDED_BUDGET.max_gpu_hours).toBe(10);
    expect(RUN_FRAME.planned_runs).toBe(540);
    expect(RUN_FRAME.maximum_total_attempts).toBe(594);
    expect(KILL_SWITCH_STOP_CONDITIONS.length).toBeGreaterThanOrEqual(11);
    expect(QUALIFICATION_CHECKLIST).toContain("confirm exact returned model identity");
    expect(PRIMARY_CONTRASTS.some((c) => c.includes("Baseline x Model"))).toBe(true);
  });
});
