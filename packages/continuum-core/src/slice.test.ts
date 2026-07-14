import { describe, it, expect } from "vitest";
import { runVerticalSlice } from "./index";

const NOW = Date.parse("2026-07-14T12:00:00.000Z");

describe("vertical slice — first implementation milestone", () => {
  it("passes every assertion end to end", () => {
    const result = runVerticalSlice(NOW);
    for (const a of result.assertions) {
      expect(a.ok, `${a.name}: ${a.detail}`).toBe(true);
    }
    expect(result.passed).toBe(true);
    expect(result.steps.length).toBeGreaterThanOrEqual(13);
  });

  it("meets the first-milestone success gates in metrics", () => {
    const { engine } = runVerticalSlice(NOW);
    const m = engine.metrics();
    expect(m.evidence_chain_valid).toBe(true);
    expect(m.cross_tenant_leaks).toBe(0);
    expect(m.canary_exfiltration_rate).toBe(0);
    expect(m.human_gate_bypasses).toBe(0);
    expect(m.capabilities_issued).toBe(1);
    expect(m.capabilities_revoked).toBe(1);
    expect(m.provenance_completeness).toBe(1);
    expect(m.disclosure_reduction_vs_naive).toBeGreaterThan(0.75);
  });

  it("produces a complete, chained evidence trail", () => {
    const { engine } = runVerticalSlice(NOW);
    const { entries, verification } = engine.evidence();
    expect(verification.valid).toBe(true);
    const types = entries.map((e) => e.event_type);
    expect(types).toContain("intent.submitted");
    expect(types).toContain("authorization.decided");
    expect(types).toContain("capability.issued");
    expect(types).toContain("context.disclosed");
    expect(types).toContain("action.executed");
    expect(types).toContain("capability.revoked");
    expect(types).toContain("cross_tenant.probe");
  });
});
