import { describe, it, expect } from "vitest";
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runStageA } from "@continuum/core";
import { runC1 } from "./c1";
import { runC2 } from "./c2";
import { runC3 } from "./c3";
import { runC4 } from "./c4";
import { scoreAll } from "./scorers";
import { verdict, isFailure, type ResultRecord } from "./records";

const NOW = Date.parse("2026-07-14T12:00:00.000Z");

async function runAll(): Promise<ResultRecord[]> {
  return [...runC1(), ...runC2(), ...(await runC3()), ...(await runC4())];
}

const dir = (sub: string) => fileURLToPath(new URL(`../${sub}/`, import.meta.url));

describe("SIF-Bench concurrency / TOCTOU baseline (unmodified control plane)", () => {
  let records: ResultRecord[];
  let metrics: ReturnType<typeof scoreAll>;

  it("runs every family and writes the report + manifest", async () => {
    records = await runAll();
    metrics = scoreAll(records);
    mkdirSync(dir("reports"), { recursive: true });
    writeFileSync(dir("reports") + "concurrency.json", JSON.stringify({ metrics, records }, null, 2) + "\n");

    const manifest = {
      suite: "SIF-Bench concurrency / TOCTOU",
      seed_now_ms: NOW,
      node: process.version,
      platform: process.platform,
      totals: metrics.totals,
      families: metrics.per_family.map((f) => ({ family: f.family, adversarial: f.adversarial, gaps: f.gaps, not_realizable: f.not_realizable })),
    };
    mkdirSync(dir("manifests"), { recursive: true });
    writeFileSync(dir("manifests") + "env.json", JSON.stringify(manifest, null, 2) + "\n");
    expect(records.length).toBeGreaterThan(40);
  });

  it("framework gate: every adversarial case has a valid control (existence)", () => {
    // C1/C2: per-case controls; C3/C4: per-family controls.
    for (const fam of ["C1", "C2"] as const) {
      const advIds = new Set(records.filter((r) => r.family === fam && r.control === "adversarial").map((r) => r.case_id));
      for (const id of advIds) {
        const hasSeq = records.some((r) => r.case_id === id && r.control === "sequential_valid");
        const hasConc = records.some((r) => r.case_id === id && r.control === "concurrent_valid");
        expect(hasSeq && hasConc, `${id} has seq+concurrent controls`).toBe(true);
      }
    }
    for (const fam of ["C3", "C4"] as const) {
      const seq = records.some((r) => r.family === fam && r.control === "sequential_valid");
      const conc = records.some((r) => r.family === fam && r.control === "concurrent_valid");
      expect(seq && conc, `${fam} has family-level valid controls`).toBe(true);
    }
  });

  it("utility gate: no valid control (sequential or concurrent) false-fails", () => {
    const badControls = records.filter((r) => r.control !== "adversarial" && r.observed_outcome === "false_failure");
    expect(badControls.map((r) => `${r.case_id}/${r.control}`), "legitimate work must not be refused").toEqual([]);
  });

  it("is reproducible from the fixed seed (deterministic verdicts)", async () => {
    const again = await runAll();
    expect(again.map(verdict)).toEqual(records.map(verdict));
  });

  it("does not change the frozen Stage A baseline", () => {
    const a = runStageA(NOW);
    expect(a.passed).toBe(true);
    expect(a.metrics.attacks_leaked).toBe(0);
  });

  it("preserves every documented failure as a regression fixture", () => {
    const failures = records.filter(isFailure);
    mkdirSync(dir("fixtures"), { recursive: true });
    for (const f of failures) {
      writeFileSync(dir("fixtures") + `${f.case_id}.json`, JSON.stringify(verdict(f), null, 2) + "\n");
    }
    // A concurrency baseline is expected to find real gaps; record, don't gate.
    expect(Array.isArray(failures)).toBe(true);
  });
});
