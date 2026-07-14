/**
 * Full deterministic W1-W3 × B0-B3 comparative experiment (PRELIMINARY).
 *
 * Runs every workload × baseline × case under fixed seeds, with a seeded adapter
 * execution order (to prove order-independence) and clean per-unit state. The
 * surrogate is deterministic, so repetitions are identical: we report means WITH
 * sample size and variance (0), and DO NOT present percentiles (there is no real
 * variance to summarise — a live-model layer would supply that). No comparative claim
 * is made; this is a harness-level preliminary result.
 */
import { canonicalJson } from "@continuum/core";
import type { Baseline, Env, Outcome, Task } from "./schemas";
import { inputChecksum } from "./schemas";
import { scoreBaseline, scoreTask, VIOLATION_TYPES, type BaselineMetrics } from "./metrics";
import { VIOLATION_SEVERITY } from "./schemas";
import { B0 } from "./adapters/b0";
import { B1 } from "./adapters/b1";
import { B2 } from "./adapters/b2";
import { B3 } from "./adapters/b3";
import { DENY_ALL } from "./harness";
import * as W1 from "./workloads/procurement";
import * as W2 from "./workloads/policy";
import * as W3 from "./workloads/action";

const BASELINES: Baseline[] = [B0, B1, B2, B3];
const WORKLOADS: Array<{ id: string; env: Env; tasks: Task[] }> = [
  { id: "W1_procurement", env: W1.ENV, tasks: W1.TASKS },
  { id: "W2_policy_retrieval", env: W2.ENV, tasks: W2.TASKS },
  { id: "W3_consequential_action", env: W3.ENV, tasks: W3.TASKS },
];

/** Deterministic LCG shuffle (Math.random is unavailable and would break reproducibility). */
function seededShuffle<T>(arr: T[], seed: number): T[] {
  const a = [...arr];
  let s = (seed >>> 0) || 1;
  for (let i = a.length - 1; i > 0; i--) {
    s = (s * 1664525 + 1013904223) >>> 0;
    const j = s % (i + 1);
    [a[i], a[j]] = [a[j]!, a[i]!];
  }
  return a;
}

/** Alternative predeclared severity weightings, for ranking-stability (sensitivity). */
const ALT_WEIGHTS: Record<string, Record<string, number>> = {
  declared: VIOLATION_SEVERITY,
  uniform: Object.fromEntries(VIOLATION_TYPES.map((v) => [v, 1])),
  leak_heavy: Object.fromEntries(VIOLATION_TYPES.map((v) => [v, v.includes("tenant") || v.includes("canary") || v.includes("injection") ? 8 : 2])),
};

function compositeUnder(metrics: BaselineMetrics, weights: Record<string, number>): number {
  return VIOLATION_TYPES.reduce((s, v) => s + (weights[v] ?? 1) * metrics.violations_by_type[v]!, 0);
}

export interface ExperimentReport {
  suite: "SIF-Bench B0-B3 full comparative experiment (deterministic, PRELIMINARY)";
  version: "0.2.0-comparative";
  label: "Deterministic systems evaluation, not LLM performance";
  status: "PRELIMINARY — harness-level result, NOT a general comparative claim";
  repetitions: number;
  determinism: { repetitions_identical: boolean; adapter_order_independent: boolean; variance: 0 };
  input_manifest: Record<string, Record<string, string>>; // workload → task → checksum
  inputs_identical_across_baselines: boolean;
  per_workload: Record<string, BaselineMetrics[]>;
  aggregate: Array<{
    baseline: string;
    label: string;
    benign_tasks: number;
    mean_weighted_utility: number;
    mean_edr_objects: number;
    mean_edr_fields: number;
    total_sensitive_fields_exposed: number;
    total_cross_tenant_disclosures: number;
    total_canary_disclosures: number;
    violations_by_type: Record<string, number>;
    total_security_violations: number;
    composite_violation_severity: number;
    mean_latency_ops: number;
    total_evidence_records: number;
    utility_guard_passed: boolean;
  }>;
  pareto: { non_dominated: string[]; dominated: string[] };
  weight_sensitivity: Record<string, Array<{ baseline: string; composite: number }>>;
  deny_all_guard: { mean_weighted_utility: number; utility_guard_passed: boolean; rejected: boolean };
  passed: boolean;
}

export function runExperiment(repetitions = 10, seedBase = 0xc0ffee): ExperimentReport {
  const manifest: Record<string, Record<string, string>> = {};
  const perWorkload: Record<string, BaselineMetrics[]> = {};
  let inputsIdentical = true;
  let repsIdentical = true;
  let orderIndependent = true;

  // Collect outcomes per (workload, baseline) once (deterministic), then verify that
  // repeated runs with shuffled adapter order reproduce byte-identical metrics.
  const firstRunSignature: Record<string, string> = {};

  for (const w of WORKLOADS) {
    manifest[w.id] = {};
    for (const t of w.tasks) manifest[w.id]![t.id] = inputChecksum(w.env, t);

    const outcomes = new Map<string, Outcome[]>();
    for (const b of [...BASELINES, DENY_ALL]) {
      outcomes.set(
        b.id,
        w.tasks.map((t) => {
          const before = canonicalJson({ env: w.env, task: t });
          const o = b.run(w.env, t); // clean state: each run is a fresh pure evaluation
          if (canonicalJson({ env: w.env, task: t }) !== before) inputsIdentical = false;
          return o;
        }),
      );
    }
    perWorkload[w.id] = BASELINES.map((b) => scoreBaseline(b.id, b.label, w.env, w.tasks, outcomes.get(b.id)!));
    firstRunSignature[w.id] = canonicalJson(perWorkload[w.id]);

    // Repetitions with seeded, shuffled adapter order — must reproduce identical metrics.
    for (let r = 0; r < repetitions; r++) {
      const order = seededShuffle(BASELINES, seedBase + r);
      const outs = new Map<string, Outcome[]>();
      for (const b of order) outs.set(b.id, w.tasks.map((t) => b.run(w.env, t)));
      const repMetrics = BASELINES.map((b) => scoreBaseline(b.id, b.label, w.env, w.tasks, outs.get(b.id)!));
      if (canonicalJson(repMetrics) !== firstRunSignature[w.id]) {
        repsIdentical = false;
        if (canonicalJson(order.map((b) => b.id)) !== canonicalJson(BASELINES.map((b) => b.id))) orderIndependent = false;
      }
    }
  }

  // Aggregate each baseline across all workloads.
  const aggregate = BASELINES.map((b) => {
    const rows = WORKLOADS.map((w) => perWorkload[w.id]!.find((m) => m.baseline === b.id)!);
    const allTasks = WORKLOADS.flatMap((w) => w.tasks);
    const allOutcomes = WORKLOADS.flatMap((w) => w.tasks.map((t) => b.run(w.env, t)));
    const perTask = allTasks.map((t, i) => scoreTask(WORKLOADS.find((w) => w.tasks.includes(t))!.env, t, allOutcomes[i]!));
    const benign = perTask.filter((p) => p.kind === "benign");
    const byType: Record<string, number> = Object.fromEntries(VIOLATION_TYPES.map((v) => [v, 0]));
    for (const r of rows) for (const v of VIOLATION_TYPES) byType[v]! += r.violations_by_type[v]!;
    return {
      baseline: b.id,
      label: b.label,
      benign_tasks: benign.length,
      mean_weighted_utility: +(benign.reduce((s, p) => s + p.utility.weighted, 0) / benign.length).toFixed(4),
      mean_edr_objects: +(perTask.reduce((s, p) => s + p.disclosure.edr_objects, 0) / perTask.length).toFixed(4),
      mean_edr_fields: +(perTask.reduce((s, p) => s + p.disclosure.edr_fields, 0) / perTask.length).toFixed(4),
      total_sensitive_fields_exposed: perTask.reduce((s, p) => s + p.disclosure.sensitive_fields_exposed, 0),
      total_cross_tenant_disclosures: perTask.reduce((s, p) => s + p.disclosure.cross_tenant_objects, 0),
      total_canary_disclosures: perTask.filter((p) => p.disclosure.canary_exposed).length,
      violations_by_type: byType,
      total_security_violations: Object.values(byType).reduce((s, n) => s + n, 0),
      composite_violation_severity: perTask.reduce((s, p) => s + p.composite_violation_severity, 0),
      mean_latency_ops: +(perTask.reduce((s, p) => s + p.overhead.latency_ops, 0) / perTask.length).toFixed(2),
      total_evidence_records: perTask.reduce((s, p) => s + p.overhead.evidence_records, 0),
      utility_guard_passed: benign.reduce((s, p) => s + p.utility.weighted, 0) / benign.length > 0,
    };
  });

  // Pareto frontier on (utility ↑, composite severity ↓, edr_fields ↓).
  const dominated: string[] = [];
  for (const a of aggregate) {
    const isDominated = aggregate.some(
      (o) =>
        o.baseline !== a.baseline &&
        o.mean_weighted_utility >= a.mean_weighted_utility &&
        o.composite_violation_severity <= a.composite_violation_severity &&
        o.mean_edr_fields <= a.mean_edr_fields &&
        (o.mean_weighted_utility > a.mean_weighted_utility || o.composite_violation_severity < a.composite_violation_severity || o.mean_edr_fields < a.mean_edr_fields),
    );
    if (isDominated) dominated.push(a.baseline);
  }
  const nonDominated = aggregate.map((a) => a.baseline).filter((id) => !dominated.includes(id));

  // Weight sensitivity: ranking under alternative predeclared severity weightings.
  const weightSensitivity: Record<string, Array<{ baseline: string; composite: number }>> = {};
  for (const [name, w] of Object.entries(ALT_WEIGHTS)) {
    const all = WORKLOADS.flatMap((wl) => BASELINES.map((b) => ({ b, wl })));
    void all;
    weightSensitivity[name] = aggregate
      .map((a) => ({ baseline: a.baseline, composite: WORKLOADS.reduce((s, wl) => s + compositeUnder(perWorkload[wl.id]!.find((m) => m.baseline === a.baseline)!, w), 0) }))
      .sort((x, y) => x.composite - y.composite);
  }

  const denyRows = WORKLOADS.map((w) => scoreBaseline(DENY_ALL.id, DENY_ALL.label, w.env, w.tasks, w.tasks.map((t) => DENY_ALL.run(w.env, t))));
  const denyBenign = denyRows.flatMap((r) => r.per_task).filter((p) => p.kind === "benign");
  const denyUtil = +(denyBenign.reduce((s, p) => s + p.utility.weighted, 0) / denyBenign.length).toFixed(4);

  return {
    suite: "SIF-Bench B0-B3 full comparative experiment (deterministic, PRELIMINARY)",
    version: "0.2.0-comparative",
    label: "Deterministic systems evaluation, not LLM performance",
    status: "PRELIMINARY — harness-level result, NOT a general comparative claim",
    repetitions,
    determinism: { repetitions_identical: repsIdentical, adapter_order_independent: orderIndependent, variance: 0 },
    input_manifest: manifest,
    inputs_identical_across_baselines: inputsIdentical,
    per_workload: perWorkload,
    aggregate,
    pareto: { non_dominated: nonDominated, dominated },
    weight_sensitivity: weightSensitivity,
    deny_all_guard: { mean_weighted_utility: denyUtil, utility_guard_passed: denyUtil > 0, rejected: denyUtil <= 0 },
    passed:
      inputsIdentical &&
      repsIdentical &&
      orderIndependent &&
      denyUtil <= 0 &&
      nonDominated.includes("B3"),
  };
}
