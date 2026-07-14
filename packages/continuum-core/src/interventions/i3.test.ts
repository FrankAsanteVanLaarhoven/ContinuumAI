import { describe, it, expect } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runI3 } from "./i3";
import { runStageA } from "../adversary";

const NOW = Date.parse("2026-07-14T12:00:00.000Z");

describe("Intervention I3 — point-of-use authorization freshness (matched arms)", () => {
  const report = runI3(NOW);
  const byArm = Object.fromEntries(report.arms.map((a) => [a.arm, a]));
  const A = byArm["I3-A"]!, B = byArm["I3-B"]!, C = byArm["I3-C"]!;
  const staleOf = (arm: typeof A, d: string) => arm.dimensions.find((x) => x.dimension === d)!.stale_permit;

  it("I3-A (frozen) reproduces GAP-3 — all four staleness dimensions still release", () => {
    expect(A.stale_permits).toBe(4);
  });

  it("I3-B (version) closes consent + policy-version but NOT risk ceiling or object lifecycle", () => {
    expect(staleOf(B, "consent_withdrawn")).toBe(false);
    expect(staleOf(B, "policy_version_rotated")).toBe(false);
    expect(staleOf(B, "policy_ceiling_tightened")).toBe(true); // still stale — version binding is insufficient
    expect(staleOf(B, "object_revoked")).toBe(true);
    expect(B.stale_permits).toBe(2);
  });

  it("I3-C (transactional) closes all four dimensions", () => {
    expect(C.stale_permits).toBe(0);
    for (const d of C.dimensions) expect(d.stale_permit, `${d.dimension}: ${d.denied_reason}`).toBe(false);
  });

  it("no arm falsely denies the benign (unchanged) capability", () => {
    for (const a of report.arms) {
      expect(a.false_deny, `${a.arm} false_deny`).toBe(0);
      expect(a.benign_success, `${a.arm} benign`).toBe(true);
    }
  });

  it("does not change the frozen Stage A baseline (I3 is opt-in)", () => {
    const s = runStageA(NOW);
    expect(s.passed).toBe(true);
    expect(s.metrics.attacks_leaked).toBe(0);
  });

  it("writes the I3 matched-arm report", () => {
    const dir = fileURLToPath(new URL("../../../../research/sif-bench/interventions/i3/", import.meta.url));
    mkdirSync(dir, { recursive: true });
    writeFileSync(dir + "report.json", JSON.stringify(report, null, 2) + "\n");
    expect(report.passed).toBe(true);
  });
});
