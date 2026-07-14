/**
 * Scorers — per-family and global metrics. Unlike failure classes are NEVER
 * merged into a single "security score"; each rate stands alone with its
 * denominator, and "zero observed" always carries its sample context.
 */
import type { Family, FailureClass, ResultRecord } from "./records";

function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return Number((sorted[Math.max(0, idx)] ?? 0).toFixed(3));
}

function rate(num: number, den: number): number {
  return den === 0 ? 0 : Number((num / den).toFixed(4));
}

function classCount(recs: ResultRecord[], fc: FailureClass): number {
  return recs.filter((r) => r.control === "adversarial" && r.observed_outcome === "gap" && r.failure_class === fc).length;
}

export interface FamilyScore {
  family: Family | "ALL";
  adversarial: number;
  gaps: number;
  held: number;
  not_realizable: number;
  race_exploit_success_rate: number;
  gap_case_ids: string[];
  not_realizable_case_ids: string[];
  failure_class_counts: Partial<Record<FailureClass, number>>;
  concurrent_controls: number;
  concurrent_false_failures: number;
  false_failure_rate: number;
}

const TRACKED_CLASSES: FailureClass[] = [
  "stale_permit_acceptance", "post_revocation_disclosure", "scope_escalation", "policy_version_mismatch",
  "pop_replay", "human_gate_bypass", "duplicate_execution", "invalid_approval", "stale_approval_execution",
  "invalid_state_transition", "idempotency_reuse", "cross_tenant_observation", "stale_session_context",
  "caller_tenant_binding", "durable_inmemory_divergence", "rls_bypass", "metadata_id_disclosure",
  "role_boundary", "evidence_state_divergence", "chain_fork", "duplicate_sequence", "orphan_evidence",
  "verification_inconsistency",
];

export function scoreFamily(recs: ResultRecord[], family: Family | "ALL"): FamilyScore {
  const scope = family === "ALL" ? recs : recs.filter((r) => r.family === family);
  const adv = scope.filter((r) => r.control === "adversarial");
  const gaps = adv.filter((r) => r.observed_outcome === "gap");
  const nr = adv.filter((r) => r.observed_outcome === "not_realizable");
  const held = adv.filter((r) => r.observed_outcome === "held");
  const concCtrls = scope.filter((r) => r.control === "concurrent_valid");
  const concFF = concCtrls.filter((r) => r.observed_outcome === "false_failure");
  const fcCounts: Partial<Record<FailureClass, number>> = {};
  for (const fc of TRACKED_CLASSES) {
    const n = classCount(scope, fc);
    if (n > 0) fcCounts[fc] = n;
  }
  return {
    family,
    adversarial: adv.length,
    gaps: gaps.length,
    held: held.length,
    not_realizable: nr.length,
    race_exploit_success_rate: rate(gaps.length, adv.length),
    gap_case_ids: gaps.map((r) => r.case_id),
    not_realizable_case_ids: nr.map((r) => r.case_id),
    failure_class_counts: fcCounts,
    concurrent_controls: concCtrls.length,
    concurrent_false_failures: concFF.length,
    false_failure_rate: rate(concFF.length, concCtrls.length),
  };
}

export interface GlobalMetrics {
  totals: { records: number; adversarial: number; controls: number; seeds: number; workers_max: number };
  per_family: FamilyScore[];
  global: FamilyScore;
  named_rates: Record<string, number>;
  revocation_overrun_ms: { n: number; p50: number; p95: number; p99: number };
  gate_to_execution_ms: { n: number; p50: number; p95: number; p99: number };
}

export function scoreAll(recs: ResultRecord[]): GlobalMetrics {
  const fams: Family[] = ["C1", "C2", "C3", "C4"];
  const per_family = fams.map((f) => scoreFamily(recs, f));
  const global = scoreFamily(recs, "ALL");
  const adv = recs.filter((r) => r.control === "adversarial");
  const controls = recs.filter((r) => r.control !== "adversarial");

  const revOverrun = recs
    .filter((r) => r.case_id.startsWith("C1-07") && r.control === "adversarial")
    .map((r) => r.latency_ms).sort((a, b) => a - b);
  const gateExec = recs
    .filter((r) => r.family === "C2" && r.control === "sequential_valid")
    .map((r) => r.latency_ms).sort((a, b) => a - b);

  const cnt = (fc: FailureClass) => classCount(recs, fc);
  const named_rates = {
    race_exploit_success_rate: global.race_exploit_success_rate,
    stale_permit_acceptance_rate: rate(cnt("stale_permit_acceptance"), adv.length),
    post_revocation_disclosure_rate: rate(cnt("post_revocation_disclosure"), adv.length),
    scope_escalation_success_rate: rate(cnt("scope_escalation"), adv.length),
    human_gate_bypass_rate: rate(cnt("human_gate_bypass"), adv.length),
    duplicate_execution_rate: rate(cnt("duplicate_execution"), adv.length),
    cross_tenant_observation_rate: rate(cnt("cross_tenant_observation"), adv.length),
    caller_tenant_binding_violation_rate: rate(cnt("caller_tenant_binding"), adv.length),
    evidence_state_divergence_rate: rate(cnt("evidence_state_divergence"), adv.length),
    chain_fork_rate: rate(cnt("chain_fork"), adv.length),
    missing_material_event_rate: rate(cnt("action_without_evidence"), adv.length),
    false_failure_rate_valid_concurrent: global.false_failure_rate,
  };

  return {
    totals: {
      records: recs.length,
      adversarial: adv.length,
      controls: controls.length,
      seeds: new Set(recs.map((r) => r.seed)).size,
      workers_max: Math.max(...recs.map((r) => r.worker_count)),
    },
    per_family,
    global,
    named_rates,
    revocation_overrun_ms: { n: revOverrun.length, p50: pct(revOverrun, 50), p95: pct(revOverrun, 95), p99: pct(revOverrun, 99) },
    gate_to_execution_ms: { n: gateExec.length, p50: pct(gateExec, 50), p95: pct(gateExec, 95), p99: pct(gateExec, 99) },
  };
}
