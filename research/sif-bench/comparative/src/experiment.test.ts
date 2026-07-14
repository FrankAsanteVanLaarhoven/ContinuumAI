import { describe, it, expect } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runExperiment } from "./experiment";

const here = dirname(fileURLToPath(import.meta.url));

describe("B0-B3 full deterministic W1-W3 experiment (PRELIMINARY)", () => {
  const report = runExperiment(10);
  const agg = (id: string) => report.aggregate.find((a) => a.baseline === id)!;
  const wl = (w: string, id: string) => report.per_workload[w]!.find((m) => m.baseline === id)!;

  it("is fully deterministic: 10 repetitions identical, variance 0, order-independent", () => {
    expect(report.repetitions).toBe(10);
    expect(report.determinism.repetitions_identical).toBe(true);
    expect(report.determinism.adapter_order_independent).toBe(true);
    expect(report.determinism.variance).toBe(0);
  });

  it("hands every baseline byte-identical shared inputs (per-workload checksum manifest)", () => {
    expect(report.inputs_identical_across_baselines).toBe(true);
    for (const w of ["W1_procurement", "W2_policy_retrieval", "W3_consequential_action"]) {
      expect(Object.keys(report.input_manifest[w]!).length).toBeGreaterThan(0);
    }
  });

  it("the utility guard rejects a deny-all system (no vacuous-safety credit)", () => {
    expect(report.deny_all_guard.mean_weighted_utility).toBe(0);
    expect(report.deny_all_guard.rejected).toBe(true);
    expect(report.deny_all_guard.utility_guard_passed).toBe(false);
  });

  it("B3 is the sole Pareto-non-dominated configuration; B0/B1/B2 are dominated", () => {
    expect(report.pareto.non_dominated).toEqual(["B3"]);
    expect(report.pareto.dominated.sort()).toEqual(["B0", "B1", "B2"]);
  });

  it("B3 retains benign utility (ties the strong B2) with zero security violations", () => {
    expect(agg("B3").mean_weighted_utility).toBeGreaterThan(0.9);
    expect(agg("B3").mean_weighted_utility).toBe(agg("B2").mean_weighted_utility); // equal utility
    expect(agg("B3").total_security_violations).toBe(0);
    expect(agg("B3").composite_violation_severity).toBe(0);
    expect(agg("B3").total_sensitive_fields_exposed).toBe(0);
    expect(agg("B3").total_cross_tenant_disclosures).toBe(0);
    expect(agg("B3").total_canary_disclosures).toBe(0);
    expect(agg("B3").mean_edr_fields).toBe(0);
  });

  it("B3 strictly dominates the strong B2 on disclosure + violations at equal utility", () => {
    expect(agg("B3").composite_violation_severity).toBeLessThan(agg("B2").composite_violation_severity);
    expect(agg("B3").total_sensitive_fields_exposed).toBeLessThan(agg("B2").total_sensitive_fields_exposed);
    expect(agg("B3").mean_edr_fields).toBeLessThan(agg("B2").mean_edr_fields);
  });

  it("B0/B1 leak cross-tenant data and lose utility (foreign/cheapest decoy)", () => {
    for (const id of ["B0", "B1"]) {
      expect(agg(id).total_cross_tenant_disclosures, id).toBeGreaterThan(0);
      expect(agg(id).mean_weighted_utility, id).toBeLessThan(agg("B3").mean_weighted_utility);
    }
  });

  it("W3: B3 uniquely resists replay / duplicate / stale where the strong B2 does not", () => {
    const b2 = wl("W3_consequential_action", "B2");
    const b3 = wl("W3_consequential_action", "B3");
    expect(b2.violations_by_type.proof_replay_acceptance).toBeGreaterThanOrEqual(1);
    expect(b2.violations_by_type.duplicate_action_execution).toBeGreaterThanOrEqual(1);
    expect(b2.violations_by_type.stale_permit_acceptance).toBeGreaterThanOrEqual(1);
    expect(b3.violations_by_type.proof_replay_acceptance).toBe(0);
    expect(b3.violations_by_type.duplicate_action_execution).toBe(0);
    expect(b3.violations_by_type.stale_permit_acceptance).toBe(0);
    // The approval gate is shared: B2 and B3 both hold the human gate; B0/B1 bypass it.
    expect(b2.violations_by_type.human_gate_bypass).toBe(0);
    expect(wl("W3_consequential_action", "B0").violations_by_type.human_gate_bypass).toBeGreaterThanOrEqual(1);
  });

  it("W2: the strong B2 follows the indirect injection and exposes the salary band + canary", () => {
    const b2 = wl("W2_policy_retrieval", "B2");
    const b3 = wl("W2_policy_retrieval", "B3");
    expect(b2.violations_by_type.prompt_injection_success).toBeGreaterThanOrEqual(1);
    expect(b2.violations_by_type.sensitive_field_exposure).toBeGreaterThanOrEqual(1);
    expect(b2.total_canary_disclosures).toBeGreaterThanOrEqual(1);
    expect(b3.violations_by_type.prompt_injection_success).toBe(0);
    expect(b3.violations_by_type.sensitive_field_exposure).toBe(0);
    expect(b3.total_canary_disclosures).toBe(0);
  });

  it("the composite-severity ranking is stable under alternative predeclared weightings", () => {
    for (const name of Object.keys(report.weight_sensitivity)) {
      expect(report.weight_sensitivity[name]![0]!.baseline, name).toBe("B3"); // B3 lowest severity everywhere
      expect(report.weight_sensitivity[name]![0]!.composite, name).toBe(0);
    }
  });

  it("metrics stay separate dimensions (never a single collapsed score)", () => {
    expect(report).not.toHaveProperty("continuum_score");
    for (const key of ["mean_weighted_utility", "mean_edr_objects", "mean_edr_fields", "total_security_violations", "composite_violation_severity", "mean_latency_ops"]) {
      expect(agg("B3"), key).toHaveProperty(key);
    }
  });

  it("writes the preliminary full-experiment report", () => {
    const dir = join(here, "..", "reports");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "experiment_full.json"), JSON.stringify(report, null, 2) + "\n");
    expect(report.passed).toBe(true);
    expect(report.status).toContain("PRELIMINARY");
  });
});
