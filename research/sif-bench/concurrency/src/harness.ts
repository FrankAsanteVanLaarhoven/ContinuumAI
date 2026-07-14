/**
 * Shared fixtures for the in-memory concurrency runners (C1/C2/C4-ledger).
 * All runners drive the UNMODIFIED ContinuumEngine.
 */
import { ContinuumEngine, signEd25519, popMessage, verifySCT } from "@continuum/core";
import {
  DB_SCHEMA_VERSION,
  GIT_COMMIT,
  ISO_DEFAULT,
  PROTOCOL_VERSION,
  type ControlKind,
  type Family,
  type Outcome,
  type FailureClass,
  type ResultRecord,
} from "./records";
import { nowPerf } from "./scheduler";

export const NOW = Date.parse("2026-07-14T12:00:00.000Z");
export const AGENT = "spiffe://acme.ai/agents/procurement-agent";
export const OWNER = "did:continuum:enterprise:acme:owner";
export const GLOBEX_OWNER = "did:continuum:enterprise:globex:owner";

export const INTENT_INPUT = {
  owner_id: OWNER,
  actor_id: AGENT,
  tenant_id: "t_acme",
  purpose: "supplier_quote_comparison",
  requested_operations: [
    "read:supplier_quotes",
    "read:approved_budget_band",
    "write:recommendation_draft",
  ],
  prohibited_operations: ["place_order", "modify_budget", "send_external_email"],
  constraints: {
    maximum_data_classification: "confidential",
    geographic_boundary: ["GB"],
    valid_until: "2027-01-01T00:00:00.000Z",
    maximum_cost_gbp: 5,
  },
  required_evidence: ["agent_attestation", "approved_model_policy", "current_user_consent"],
  human_gate: { required_for: ["external_commitment", "financial_execution"] },
  actor_geo: "GB",
  model_id: "gw-approved-llm-2026-06",
  risk_score: 0.12,
} as const;

export function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

export interface Authorized {
  engine: ContinuumEngine;
  intentId: string;
  cap: NonNullable<ReturnType<ContinuumEngine["authorize"]>["capability"]>;
  pubkey: string;
}

/** Fresh engine + submitted intent + issued capability. */
export function authorized(nowMs = NOW, intentInput: unknown = INTENT_INPUT): Authorized {
  const engine = new ContinuumEngine();
  const intent = engine.submitIntent(intentInput, nowMs);
  const auth = engine.authorize(intent.intent_id, nowMs);
  if (!auth.capability) throw new Error("setup: no capability issued");
  return { engine, intentId: intent.intent_id, cap: auth.capability, pubkey: engine.platformPublicKeyPem() };
}

/** A proof-of-possession the legitimate holder produces. */
export function holderPop(a: Authorized, challenge: string) {
  const keys = a.engine.store.agentKeys.get(a.cap.token.actor)!;
  return { challenge, signature: signEd25519(keys.privateKeyPem, popMessage(a.cap.token, challenge)) };
}

/** Directly verify a capability (used for PoP-replay probes). */
export function directVerify(a: Authorized, pop: { challenge: string; signature: string } | null, nowMs = NOW) {
  return verifySCT(a.cap, {
    platformPublicKeyPem: a.pubkey,
    nowMs,
    revokedHandles: new Set<string>(),
    audience: null,
    pop,
  });
}

let seq = 0;
export function mkRecord(base: {
  case_id: string;
  family: Family;
  control: ControlKind;
  description: string;
  worker_count: number;
  interleaving: string[];
  expected_outcome: Outcome;
  observed_outcome: Outcome;
  failure_class: FailureClass;
  detail: string;
  latency_ms: number;
  ids?: ResultRecord["ids"];
  policy_version?: string;
  isolation_level?: string;
  scheduler?: string;
}): ResultRecord {
  const stamp = new Date(NOW + seq++).toISOString();
  return {
    case_id: base.case_id,
    family: base.family,
    control: base.control,
    description: base.description,
    seed: 0xC0FFEE,
    scheduler: base.scheduler ?? "ordered-interleave",
    interleaving: base.interleaving,
    git_commit: GIT_COMMIT,
    protocol_version: PROTOCOL_VERSION,
    policy_version: base.policy_version ?? "policy-2026.07.0",
    db_schema_version: DB_SCHEMA_VERSION,
    worker_count: base.worker_count,
    isolation_level: base.isolation_level ?? "n/a (in-memory)",
    started_at: stamp,
    ended_at: stamp,
    expected_outcome: base.expected_outcome,
    observed_outcome: base.observed_outcome,
    failure_class: base.failure_class,
    latency_ms: base.latency_ms,
    ids: base.ids ?? {},
    detail: base.detail,
  };
}

export { nowPerf };
