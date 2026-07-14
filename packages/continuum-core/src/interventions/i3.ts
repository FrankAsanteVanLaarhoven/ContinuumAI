/**
 * Intervention I3 — matched-arm evaluation of point-of-use authorization freshness.
 *
 *   I3-A  off            snapshot capability, no re-evaluation      (reproduces GAP-3)
 *   I3-B  version        bind + re-check policy version + consent digest at use
 *   I3-C  transactional  version + re-evaluate risk ceiling and object lifecycle
 *
 * Four staleness dimensions are applied AFTER a benign capability is issued, then
 * the capability is used: a stale permit is one the point-of-use path still
 * releases. I3-A accepts all four; I3-B catches consent + policy-version (2/4) but
 * NOT the tightened risk ceiling or the revoked object; I3-C catches all four. A
 * benign control (nothing changed) must still succeed under every arm.
 */
import { ContinuumEngine } from "../engine";
import type { FreshnessMode } from "./freshness";

const OWNER = "did:continuum:enterprise:acme:owner";
const AGENT = "spiffe://acme.ai/agents/procurement-agent";
const PURPOSE = "supplier_quote_comparison";
const PERMITTED_OBJECT = "mem_q_apex"; // released by the benign intent

const BENIGN_INTENT = {
  owner_id: OWNER,
  actor_id: AGENT,
  tenant_id: "t_acme",
  purpose: PURPOSE,
  requested_operations: ["read:supplier_quotes", "read:approved_budget_band", "write:recommendation_draft"],
  prohibited_operations: ["place_order", "modify_budget", "send_external_email"],
  constraints: { maximum_data_classification: "confidential", geographic_boundary: ["GB"], valid_until: "2027-01-01T00:00:00.000Z", maximum_cost_gbp: 5 },
  required_evidence: ["agent_attestation", "approved_model_policy", "current_user_consent"],
  human_gate: { required_for: ["external_commitment", "financial_execution"] },
  actor_geo: "GB", model_id: "gw-approved-llm-2026-06", risk_score: 0.12,
} as const;

export type Dimension = "consent_withdrawn" | "policy_ceiling_tightened" | "policy_version_rotated" | "object_revoked";

const MUTATIONS: Record<Dimension, (eng: ContinuumEngine) => void> = {
  consent_withdrawn: (eng) => {
    const c = eng.store.consent.find((r) => r.owner_id === OWNER && r.purpose === PURPOSE);
    if (c) c.granted = false;
  },
  policy_ceiling_tightened: (eng) => {
    eng.store.config.risk_threshold = 0; // benign risk 0.12 now exceeds the ceiling
  },
  policy_version_rotated: (eng) => {
    eng.store.config.policy_version = "policy-2026.99.0-rotated";
  },
  object_revoked: (eng) => {
    const obj = eng.store.memory.get(PERMITTED_OBJECT);
    if (obj) obj.revocation_state = "revoked";
  },
};

/** Issue a benign capability, apply a staleness mutation, then disclose. */
function probe(mode: FreshnessMode, mutate: ((eng: ContinuumEngine) => void) | null, nowMs: number): { released: boolean; reason: string | null } {
  const eng = new ContinuumEngine(undefined, { freshnessMode: mode });
  const intent = eng.submitIntent(BENIGN_INTENT, nowMs);
  const auth = eng.authorize(intent.intent_id, nowMs);
  if (!auth.capability) throw new Error("I3 setup: benign authorization did not issue a capability");
  if (mutate) mutate(eng);
  const d = eng.disclose(auth.capability.token.token_id, "i3", nowMs);
  return { released: d.verification.valid, reason: d.verification.denied_reason };
}

export interface DimensionResult {
  dimension: Dimension;
  stale_permit: boolean; // still released after the mutation
  denied_reason: string | null;
}

export interface ArmResult {
  arm: "I3-A" | "I3-B" | "I3-C";
  mode: FreshnessMode;
  dimensions: DimensionResult[];
  stale_permits: number; // of 4
  benign_success: boolean;
  false_deny: number;
  detail: string;
}

const DIMENSIONS: Dimension[] = ["consent_withdrawn", "policy_ceiling_tightened", "policy_version_rotated", "object_revoked"];

function runArm(arm: ArmResult["arm"], mode: FreshnessMode, nowMs: number): ArmResult {
  const dimensions = DIMENSIONS.map((dimension) => {
    const r = probe(mode, MUTATIONS[dimension], nowMs);
    return { dimension, stale_permit: r.released, denied_reason: r.reason };
  });
  const stale_permits = dimensions.filter((d) => d.stale_permit).length;
  const benign = probe(mode, null, nowMs);
  return {
    arm,
    mode,
    dimensions,
    stale_permits,
    benign_success: benign.released,
    false_deny: benign.released ? 0 : 1,
    detail: `${stale_permits}/4 stale permits accepted; benign ${benign.released ? "released" : "DENIED"}`,
  };
}

export interface I3Report {
  suite: "Intervention I3 — point-of-use authorization freshness (matched arms)";
  version: "0.3.0-i3";
  now_ms: number;
  arms: ArmResult[];
  gap3_reproduced_in_baseline_arm: boolean;
  version_binding_partial: boolean;
  transactional_closes_all: boolean;
  no_false_deny_any_arm: boolean;
  passed: boolean;
}

export function runI3(nowMs = Date.parse("2026-07-14T12:00:00.000Z")): I3Report {
  const a = runArm("I3-A", "off", nowMs);
  const b = runArm("I3-B", "version", nowMs);
  const c = runArm("I3-C", "transactional", nowMs);

  const byDim = (arm: ArmResult, d: Dimension) => arm.dimensions.find((x) => x.dimension === d)!.stale_permit;

  const gap3 = a.stale_permits === 4;
  // version catches consent + policy-version, but NOT risk ceiling or object lifecycle.
  const versionPartial =
    b.stale_permits === 2 &&
    !byDim(b, "consent_withdrawn") &&
    !byDim(b, "policy_version_rotated") &&
    byDim(b, "policy_ceiling_tightened") &&
    byDim(b, "object_revoked");
  const transactionalAll = c.stale_permits === 0;
  const noFalseDeny = [a, b, c].every((x) => x.false_deny === 0 && x.benign_success);

  return {
    suite: "Intervention I3 — point-of-use authorization freshness (matched arms)",
    version: "0.3.0-i3",
    now_ms: nowMs,
    arms: [a, b, c],
    gap3_reproduced_in_baseline_arm: gap3,
    version_binding_partial: versionPartial,
    transactional_closes_all: transactionalAll,
    no_false_deny_any_arm: noFalseDeny,
    passed: gap3 && versionPartial && transactionalAll && noFalseDeny,
  };
}
