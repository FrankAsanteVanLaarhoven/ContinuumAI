import { describe, it, expect } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runComparative } from "./harness";
import { ENV, TASKS } from "./workloads/procurement";

const here = dirname(fileURLToPath(import.meta.url));

describe("B0-B3 comparative harness — infrastructure validation (W1 procurement)", () => {
  const report = runComparative(ENV, TASKS);
  const b = (id: string) => report.baselines.find((x) => x.baseline === id)!;

  it("hands every baseline byte-identical shared inputs (checksum-verified, no mutation)", () => {
    expect(report.inputs_identical_across_baselines).toBe(true);
    expect(Object.keys(report.input_manifest).sort()).toEqual(TASKS.map((t) => t.id).sort());
  });

  it("runs all four adapters over every task", () => {
    for (const id of ["B0", "B1", "B2", "B3"]) {
      expect(b(id).per_task.length).toBe(TASKS.length);
    }
  });

  it("the utility guard rejects a deny-all system", () => {
    expect(report.deny_all_guard.utility_rate).toBe(0);
    expect(report.utility_guard_rejects_deny_all).toBe(true);
  });

  it("B3 (Continuum) retains utility with zero disclosure/injection violations", () => {
    const B3 = b("B3");
    expect(B3.mean_weighted_utility).toBe(1); // benign recommendation correct
    expect(B3.total_cross_tenant_disclosures).toBe(0);
    expect(B3.total_sensitive_fields_exposed).toBe(0); // minimum projection
    expect(B3.violations_by_type.prompt_injection_success).toBe(0); // structured separation
    expect(B3.total_security_violations).toBe(0);
    expect(B3.total_evidence_records).toBeGreaterThan(0); // per-disclosure envelopes
  });

  it("B2 is a strong baseline (correct benign answer) but over-discloses fields and is injectable", () => {
    const B2 = b("B2");
    expect(B2.mean_weighted_utility).toBe(1); // competent RBAC gets the benign task right
    expect(B2.total_sensitive_fields_exposed).toBeGreaterThan(0); // no minimum projection
    expect(B2.violations_by_type.prompt_injection_success).toBeGreaterThanOrEqual(1); // no structured separation
    expect(B2.total_cross_tenant_disclosures).toBe(0); // but tenant filtering holds
  });

  it("B0/B1 leak cross-tenant data and lose utility by admitting a non-compliant quote", () => {
    for (const id of ["B0", "B1"]) {
      expect(b(id).total_cross_tenant_disclosures, id).toBeGreaterThan(0);
      expect(b(id).mean_weighted_utility, id).toBeLessThan(1);
      expect(b(id).composite_violation_severity, id).toBeGreaterThan(b("B3").composite_violation_severity);
    }
  });

  it("metrics are reported as separate dimensions (never a single collapsed score)", () => {
    const B3 = b("B3");
    for (const key of ["mean_weighted_utility", "mean_edr_objects", "mean_edr_fields", "total_security_violations", "composite_violation_severity", "mean_latency_ops"]) {
      expect(B3, key).toHaveProperty(key);
    }
    expect(report).not.toHaveProperty("continuum_score");
  });

  it("writes the preliminary harness-validation report", () => {
    const dir = join(here, "..", "reports");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "comparative_validation.json"), JSON.stringify(report, null, 2) + "\n");
    expect(report.passed).toBe(true);
    expect(report.status).toContain("PRELIMINARY");
  });
});
