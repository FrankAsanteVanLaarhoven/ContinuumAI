/**
 * Result-record model for the concurrency suite. Every case emits one record
 * with the full metadata the brief requires, so a failure is reproducible and a
 * "zero observed" result carries its sample context.
 *
 * Outcome vocabulary:
 *   held            — the adversarial interleaving was refused / had no effect.
 *   valid_pass      — a legitimate (sequential or permitted-concurrent) control succeeded.
 *   gap             — the adversarial interleaving succeeded (a real finding).
 *   false_failure   — a legitimate control was wrongly refused (over-blocking).
 *   not_realizable  — the interleaving cannot occur in this architecture (with reason).
 */
export type Family = "C1" | "C2" | "C3" | "C4";
export type ControlKind = "sequential_valid" | "concurrent_valid" | "adversarial";
export type Outcome = "held" | "valid_pass" | "gap" | "false_failure" | "not_realizable";
export type FailureClass =
  | "none"
  | "stale_permit_acceptance"
  | "post_revocation_disclosure"
  | "scope_escalation"
  | "policy_version_mismatch"
  | "duplicate_capability_use"
  | "pop_replay"
  | "human_gate_bypass"
  | "duplicate_execution"
  | "invalid_approval"
  | "stale_approval_execution"
  | "invalid_state_transition"
  | "idempotency_reuse"
  | "cross_tenant_observation"
  | "stale_session_context"
  | "caller_tenant_binding"
  | "durable_inmemory_divergence"
  | "rls_bypass"
  | "metadata_id_disclosure"
  | "role_boundary"
  | "evidence_state_divergence"
  | "chain_fork"
  | "duplicate_sequence"
  | "orphan_evidence"
  | "verification_inconsistency"
  | "action_without_evidence"
  | "evidence_without_action"
  | "restore_digest_mismatch"
  | "not_applicable";

export interface ResultRecord {
  case_id: string;
  family: Family;
  control: ControlKind;
  description: string;
  seed: number;
  scheduler: string;
  interleaving: string[];
  git_commit: string;
  protocol_version: string;
  policy_version: string;
  db_schema_version: string;
  worker_count: number;
  isolation_level: string;
  started_at: string;
  ended_at: string;
  expected_outcome: Outcome;
  observed_outcome: Outcome;
  failure_class: FailureClass;
  latency_ms: number;
  ids: {
    intent_id?: string | null;
    capability_id?: string | null;
    action_id?: string | null;
    evidence_head?: string | null;
    event_ids?: string[];
  };
  detail: string;
}

export const PROTOCOL_VERSION = "CIP-002/004/006/007";
export const DB_SCHEMA_VERSION = "0001_init";
export const GIT_COMMIT = process.env.CONC_COMMIT ?? "uncommitted-working-tree";
export const ISO_DEFAULT = "read committed";

/** The deterministic subset used to assert seeded-replay reproducibility. */
export function verdict(r: ResultRecord): Record<string, unknown> {
  return {
    case_id: r.case_id,
    family: r.family,
    control: r.control,
    seed: r.seed,
    scheduler: r.scheduler,
    interleaving: r.interleaving,
    expected_outcome: r.expected_outcome,
    observed_outcome: r.observed_outcome,
    failure_class: r.failure_class,
  };
}

/** True when a record is a documented failure (adversarial gap or over-block). */
export function isFailure(r: ResultRecord): boolean {
  return r.observed_outcome === "gap" || r.observed_outcome === "false_failure";
}
