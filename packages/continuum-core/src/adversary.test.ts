import { describe, it, expect } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runStageA, type AttackResult } from "./index";

const NOW = Date.parse("2026-07-14T12:00:00.000Z");

/** Strip volatile identifiers so the frozen artifact is byte-stable. */
function sanitize(s: string | null): string | null {
  if (s === null) return null;
  return s.replace(/\b(act|sct|int|evt|trc|rev)_[0-9a-f-]{8,}/g, "$1_<id>");
}

describe("SIF-Bench Stage A — deterministic control-plane adversarial", () => {
  const report = runStageA(NOW);

  it("blocks every attack and matches the expected denial signal", () => {
    for (const a of report.attacks) {
      expect(a.blocked, `${a.id} ${a.name} — denied_reason=${a.denied_reason}`).toBe(true);
      expect(
        a.signal_matched,
        `${a.id} expected signal "${a.expected_signal}" in "${a.denied_reason}"`,
      ).toBe(true);
    }
  });

  it("covers all four control-plane surfaces", () => {
    const cats = new Set(report.attacks.map((a) => a.category));
    expect(cats).toEqual(
      new Set(["capability", "tenant_isolation", "evidence", "human_gate"]),
    );
    // every category actually attacked and fully blocked
    for (const [cat, c] of Object.entries(report.metrics.by_category)) {
      expect(c.total, `${cat} has attacks`).toBeGreaterThan(0);
      expect(c.blocked, `${cat} fully blocked`).toBe(c.total);
    }
  });

  it("does not regress any legitimate path (no over-blocking)", () => {
    for (const c of report.controls) {
      expect(c.succeeded, `${c.id} ${c.name}: ${c.detail}`).toBe(true);
    }
    expect(report.metrics.control_regressions).toBe(0);
  });

  it("reports zero leakage across the frozen metrics", () => {
    const m = report.metrics;
    expect(m.attacks_leaked).toBe(0);
    expect(m.human_gate_bypasses).toBe(0);
    expect(m.cross_tenant_leaks).toBe(0);
    expect(m.canary_exfiltration_rate).toBe(0);
    expect(m.evidence_chain_valid).toBe(true);
    expect(m.signals_matched).toBe(m.attacks_total);
    expect(report.passed).toBe(true);
  });

  it("names the specific human-gate bypass that used to be possible", () => {
    const selfApprove = report.attacks.find((a) => a.id === "GATE-01") as AttackResult;
    expect(selfApprove.blocked).toBe(true);
    expect(selfApprove.denied_reason).toContain("self-approval forbidden");
  });

  it("freezes the Stage A metrics artifact", () => {
    const frozen = {
      suite: report.suite,
      version: report.version,
      now_ms: report.now_ms,
      summary: report.metrics,
      attacks: [...report.attacks]
        .sort((a, b) => a.id.localeCompare(b.id))
        .map((a) => ({
          id: a.id,
          category: a.category,
          name: a.name,
          threat: a.threat,
          blocked: a.blocked,
          expected_signal: a.expected_signal,
          signal_matched: a.signal_matched,
          denied_reason: sanitize(a.denied_reason),
        })),
      controls: [...report.controls]
        .sort((a, b) => a.id.localeCompare(b.id))
        .map((c) => ({ id: c.id, name: c.name, succeeded: c.succeeded, detail: sanitize(c.detail) })),
      passed: report.passed,
    };
    const outPath = fileURLToPath(
      new URL("../../../research/sif-bench/results/stage_a.json", import.meta.url),
    );
    mkdirSync(fileURLToPath(new URL("../../../research/sif-bench/results/", import.meta.url)), {
      recursive: true,
    });
    writeFileSync(outPath, JSON.stringify(frozen, null, 2) + "\n");
    expect(frozen.passed).toBe(true);
  });
});
