import { describe, it, expect } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runI2 } from "./i2";
import { runStageA } from "../adversary";

const NOW = Date.parse("2026-07-14T12:00:00.000Z");

describe("Intervention I2 — caller-bound metadata access (matched arms)", () => {
  const report = runI2(NOW);
  const byArm = Object.fromEntries(report.arms.map((a) => [a.arm, a]));
  const A = byArm["I2-A"]!, B = byArm["I2-B"]!, C = byArm["I2-C"]!;

  it("I2-A (frozen) reproduces GAP-2 — an Acme context enumerates Globex metadata", () => {
    expect(A.foreign_metadata_enumeration_success).toBe(true);
    expect(A.cross_tenant_objectid_disclosure_count).toBeGreaterThanOrEqual(1);
    expect(A.false_permit).toBe(1);
    expect(A.evidence_completeness).toBe(0); // frozen accessor emits no audit
  });

  it("I2-B (bound) closes the IDOR — foreign enumeration prevented, tenant derived", () => {
    expect(B.foreign_metadata_enumeration_success).toBe(false);
    expect(B.cross_tenant_objectid_disclosure_count).toBe(0);
    expect(B.false_permit).toBe(0);
    expect(B.tenant_derived_not_accepted).toBe(true);
    expect(B.capability_holder_mismatch_acceptance).toBe(0);
    expect(B.purpose_binding_violation).toBe(0);
  });

  it("I2-C (bound + minimal projection) closes the IDOR AND returns fewer fields", () => {
    expect(C.foreign_metadata_enumeration_success).toBe(false);
    expect(C.false_permit).toBe(0);
    expect(C.returned_field_count_benign).toBeLessThan(B.returned_field_count_benign);
    expect(C.metadata_excess_disclosure_ratio).toBe(0);
  });

  it("every malicious probe is blocked under both bound arms", () => {
    for (const arm of [B, C]) {
      for (const p of arm.probes.filter((x) => x.malicious && x.applies)) {
        expect(p.blocked, `${arm.arm} ${p.id} ${p.name}: ${p.detail}`).toBe(true);
      }
    }
  });

  it("no arm falsely denies the benign same-tenant retrieval", () => {
    for (const a of report.arms) {
      expect(a.false_deny, `${a.arm} false_deny`).toBe(0);
      expect(a.benign_retrieval_success, `${a.arm} benign`).toBe(true);
    }
  });

  it("bound arms record a complete audit envelope for every list operation", () => {
    expect(B.evidence_completeness).toBe(1);
    expect(C.evidence_completeness).toBe(1);
  });

  it("does not change the frozen Stage A baseline (I2 is an additive accessor)", () => {
    const s = runStageA(NOW);
    expect(s.passed).toBe(true);
    expect(s.metrics.attacks_leaked).toBe(0);
  });

  it("writes the I2 matched-arm report", () => {
    const dir = fileURLToPath(new URL("../../../../research/sif-bench/interventions/i2/", import.meta.url));
    mkdirSync(dir, { recursive: true });
    writeFileSync(dir + "report.json", JSON.stringify(report, null, 2) + "\n");
    expect(report.passed).toBe(true);
  });
});
