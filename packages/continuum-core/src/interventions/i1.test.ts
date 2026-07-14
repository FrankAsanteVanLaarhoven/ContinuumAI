import { describe, it, expect } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runI1 } from "./i1";
import { runStageA } from "../adversary";

const NOW = Date.parse("2026-07-14T12:00:00.000Z");

describe("Intervention I1 — entitlement-bound scope (matched arms)", () => {
  const report = runI1(NOW);
  const byArm = Object.fromEntries(report.arms.map((a) => [a.arm, a]));

  it("I1-A (frozen) reproduces GAP-1 — the escalation still succeeds", () => {
    expect(byArm["I1-A"]!.scope_escalation_success).toBe(true);
    expect(byArm["I1-A"]!.false_permit).toBe(1);
  });

  it("I1-B (enforce) closes GAP-1 — self-declared read:source_code is denied", () => {
    expect(byArm["I1-B"]!.scope_escalation_success).toBe(false);
    expect(byArm["I1-B"]!.false_permit).toBe(0);
  });

  it("I1-C (versioned) closes GAP-1 AND propagates entitlement revocation", () => {
    expect(byArm["I1-C"]!.scope_escalation_success).toBe(false);
    expect(byArm["I1-C"]!.revocation_propagation).toBe("invalidated");
    // I1-B does NOT propagate a version rotation to a live capability — the
    // point-of-use recheck is exactly what I1-C adds.
    expect(byArm["I1-B"]!.revocation_propagation).toBe("still_valid");
  });

  it("no arm falsely denies the legitimate procurement task", () => {
    for (const a of report.arms) {
      expect(a.false_deny, `${a.arm} false_deny`).toBe(0);
      expect(a.benign_task_success, `${a.arm} benign`).toBe(true);
    }
  });

  it("does not change the frozen Stage A baseline (I1 is opt-in)", () => {
    const s = runStageA(NOW);
    expect(s.passed).toBe(true);
    expect(s.metrics.attacks_leaked).toBe(0);
  });

  it("writes the I1 matched-arm report", () => {
    const dir = fileURLToPath(new URL("../../../../research/sif-bench/interventions/i1/", import.meta.url));
    mkdirSync(dir, { recursive: true });
    writeFileSync(dir + "report.json", JSON.stringify(report, null, 2) + "\n");
    expect(report.passed).toBe(true);
  });
});
