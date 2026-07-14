import { describe, it, expect } from "vitest";
import {
  REGISTRATION_TEMPLATE,
  PROMPT_SURFACE_HASH,
  RETRY_POLICY,
  FAILURE_CLASSES,
  STATISTICAL_PLAN,
  assertReadyForExecution,
  isReadyForExecution,
  expectedRunCount,
  type ModelRegistration,
} from "./registration";

/** A fully-pinned SYNTHETIC registration used ONLY to prove the guard passes when frozen.
 *  These are obviously fake placeholders — NOT real models and NOT the experiment. */
function pinnedSynthetic(): ModelRegistration {
  const r: ModelRegistration = JSON.parse(JSON.stringify(REGISTRATION_TEMPLATE));
  r.slots[0]!.hosting_class = "REMOTE_STANDARD";
  r.slots[1]!.hosting_class = "REMOTE_ZERO_RETENTION";
  r.slots[2]!.hosting_class = "LOCAL_PRIVATE";
  for (const s of r.slots) {
    s.model_id = `TEST-MODEL-${s.slot}`;
    s.revision = "test-rev-0";
    s.date_accessed = "2026-07-14";
    if (s.hosting_class === "LOCAL_PRIVATE") s.artifact_digest = "sha256:testdigest";
  }
  r.budget = { max_input_tokens: 1_000_000, max_output_tokens: 500_000, max_cost_usd: 50, max_gpu_hours: 8, max_wall_clock_hours: 6, failure_allowance_pct: 0 };
  r.prompt_surface_hash = PROMPT_SURFACE_HASH;
  r.kill_switch = "disengaged";
  r.reviewer_signoff = true;
  return r;
}

describe("Comparative v0.2 — registration manifest (no model calls)", () => {
  it("the unpinned template FAILS CLOSED (execution impossible until frozen)", () => {
    expect(isReadyForExecution(REGISTRATION_TEMPLATE)).toBe(false);
    const unmet = assertReadyForExecution(REGISTRATION_TEMPLATE);
    // Must flag the operator-supplied gaps.
    expect(unmet.some((u) => u.includes("model_id"))).toBe(true);
    expect(unmet.some((u) => u.includes("budget."))).toBe(true);
    expect(unmet.some((u) => u.includes("prompt_surface_hash"))).toBe(true);
    expect(unmet.some((u) => u.includes("kill_switch"))).toBe(true);
    expect(unmet.some((u) => u.includes("reviewer_signoff"))).toBe(true);
  });

  it("kill switch defaults ENGAGED and sign-off defaults FALSE", () => {
    expect(REGISTRATION_TEMPLATE.kill_switch).toBe("engaged");
    expect(REGISTRATION_TEMPLATE.reviewer_signoff).toBe(false);
    expect(REGISTRATION_TEMPLATE.prompt_surface_hash).toBeNull();
  });

  it("requires at least one LOCAL_PRIVATE / PRIVATE_TENANT slot", () => {
    const r = pinnedSynthetic();
    r.slots.forEach((s) => (s.hosting_class = "REMOTE_STANDARD"));
    expect(assertReadyForExecution(r).some((u) => u.includes("LOCAL_PRIVATE/PRIVATE_TENANT"))).toBe(true);
  });

  it("a fully-pinned synthetic registration passes the guard (proves it is satisfiable)", () => {
    expect(isReadyForExecution(pinnedSynthetic())).toBe(true);
  });

  it("removing ANY frozen field re-blocks execution (fail-closed integrity)", () => {
    for (const mutate of [
      (r: ModelRegistration) => (r.reviewer_signoff = false),
      (r: ModelRegistration) => (r.kill_switch = "engaged"),
      (r: ModelRegistration) => (r.prompt_surface_hash = null),
      (r: ModelRegistration) => (r.prompt_surface_hash = "deadbeef"), // mismatch = prompt drift
      (r: ModelRegistration) => (r.budget.max_cost_usd = null),
      (r: ModelRegistration) => (r.slots[2]!.artifact_digest = null),
      (r: ModelRegistration) => (r.synthetic_fixtures_only = false),
    ]) {
      const r = pinnedSynthetic();
      mutate(r);
      expect(isReadyForExecution(r)).toBe(false);
    }
  });

  it("expected run count = models × baselines × tasks × seeds (540 at the registered frame)", () => {
    expect(expectedRunCount(REGISTRATION_TEMPLATE)).toBe(3 * 4 * 9 * 5);
    expect(expectedRunCount(REGISTRATION_TEMPLATE)).toBe(540);
  });

  it("pre-registers retry, failure classes, and the statistical plan authoritatively", () => {
    expect(RETRY_POLICY.max_infra_retries).toBe(1);
    expect(RETRY_POLICY.no_retry_on).toContain("safety_refusal");
    expect(FAILURE_CLASSES.length).toBe(13);
    expect(STATISTICAL_PLAN.model_formula).toContain("Baseline*Model");
    expect(STATISTICAL_PLAN.primary_endpoints).toContain("model_refusal_occurrence");
    expect(STATISTICAL_PLAN.predeclared_contrasts).toContain("B3 vs B2");
  });

  it("the prompt-surface hash is stable and non-empty (freeze anchor)", () => {
    expect(PROMPT_SURFACE_HASH).toMatch(/^[0-9a-f]{64}$/);
  });
});
