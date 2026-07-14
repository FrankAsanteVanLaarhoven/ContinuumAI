/**
 * Intervention I1 — matched-arm evaluation of entitlement-bound scope.
 *
 *   I1-A  frozen agent-declared scope           (entitlementMode "off")
 *   I1-B  entitlement intersection at issuance   (entitlementMode "enforce")
 *   I1-C  + point-of-use entitlement-version recheck (entitlementMode "enforce_versioned")
 *
 * The GAP-1 escalation (an agent self-declaring read:source_code to reach
 * mem_src_code) must succeed under I1-A and be denied under I1-B/I1-C, while the
 * legitimate procurement task must still succeed under every arm (no false deny).
 */
import { ContinuumEngine } from "../engine";
import type { EntitlementMode } from "./entitlement";

const AGENT = "spiffe://acme.ai/agents/procurement-agent";
const TARGET = "mem_src_code";
// The two objects the base policy permits for the legitimate procurement intent
// (mem_budget_band is denied by the classification ceiling, not by entitlement).
const LEGIT_OBJECTS = ["mem_q_apex", "mem_q_orion"];

const BENIGN_INTENT = {
  owner_id: "did:continuum:enterprise:acme:owner",
  actor_id: AGENT,
  tenant_id: "t_acme",
  purpose: "supplier_quote_comparison",
  requested_operations: ["read:supplier_quotes", "read:approved_budget_band", "write:recommendation_draft"],
  prohibited_operations: ["place_order", "modify_budget", "send_external_email"],
  constraints: { maximum_data_classification: "confidential", geographic_boundary: ["GB"], valid_until: "2027-01-01T00:00:00.000Z", maximum_cost_gbp: 5 },
  required_evidence: ["agent_attestation", "approved_model_policy", "current_user_consent"],
  human_gate: { required_for: ["external_commitment", "financial_execution"] },
  actor_geo: "GB", model_id: "gw-approved-llm-2026-06", risk_score: 0.12,
} as const;

// The GAP-1 escalation: the same intent, self-declaring an operation the agent is
// NOT entitled to, to reach an object protected only by scope.
const ESCALATION_INTENT = {
  ...BENIGN_INTENT,
  requested_operations: [...BENIGN_INTENT.requested_operations, "read:source_code"],
} as const;

export interface ArmResult {
  arm: string;
  mode: EntitlementMode;
  scope_escalation_success: boolean;
  unauthorized_extraction: boolean;
  false_permit: number;
  false_deny: number;
  benign_task_success: boolean;
  authz_latency_ms: number;
  revocation_propagation: "invalidated" | "still_valid" | "n/a";
  detail: string;
}

function runArm(arm: string, mode: EntitlementMode, nowMs: number): ArmResult {
  // --- escalation attempt ---
  const eEng = new ContinuumEngine(undefined, { entitlementMode: mode });
  const eInt = eEng.submitIntent(ESCALATION_INTENT, nowMs);
  const t0 = globalThis.performance.now();
  const eAuth = eEng.authorize(eInt.intent_id, nowMs);
  const authz_latency_ms = Number((globalThis.performance.now() - t0).toFixed(4));
  const escalated = eAuth.decision.permitted_ids.includes(TARGET);

  // --- benign task ---
  const bEng = new ContinuumEngine(undefined, { entitlementMode: mode });
  const bInt = bEng.submitIntent(BENIGN_INTENT, nowMs);
  const bAuth = bEng.authorize(bInt.intent_id, nowMs);
  const benignPermits = new Set(bAuth.decision.permitted_ids);
  const false_deny = LEGIT_OBJECTS.filter((id) => !benignPermits.has(id)).length;
  const benign_task_success = false_deny === 0 && bAuth.capability !== null;

  // --- revocation propagation (I1-C): rotate entitlement version, then use ---
  let revocation_propagation: ArmResult["revocation_propagation"] = "n/a";
  if (mode !== "off" && bAuth.capability) {
    bEng.store.entitlements!.version = "entitlements-2026.07.1-rotated";
    const d = bEng.disclose(bAuth.capability.token.token_id, "i1-rotate", nowMs);
    revocation_propagation = d.verification.valid ? "still_valid" : "invalidated";
  }

  return {
    arm,
    mode,
    scope_escalation_success: escalated,
    unauthorized_extraction: escalated,
    false_permit: escalated ? 1 : 0,
    false_deny,
    benign_task_success,
    authz_latency_ms,
    revocation_propagation,
    detail: escalated
      ? `${TARGET} reached via self-declared read:source_code`
      : `${TARGET} denied: read:source_code not entitled for ${AGENT}`,
  };
}

export interface I1Report {
  suite: "Intervention I1 — entitlement-bound scope (matched arms)";
  version: "0.3.0-i1";
  now_ms: number;
  arms: ArmResult[];
  regression_source_code_denied_under_enforcement: boolean;
  gap1_reproduced_in_baseline_arm: boolean;
  no_false_deny_any_arm: boolean;
  passed: boolean;
}

export function runI1(nowMs = Date.parse("2026-07-14T12:00:00.000Z")): I1Report {
  const arms = [
    runArm("I1-A", "off", nowMs),
    runArm("I1-B", "enforce", nowMs),
    runArm("I1-C", "enforce_versioned", nowMs),
  ];
  const a = arms[0]!, b = arms[1]!, c = arms[2]!;
  const regression = !b.scope_escalation_success && !c.scope_escalation_success;
  const gap1Repro = a.scope_escalation_success;
  const noFalseDeny = arms.every((x) => x.false_deny === 0 && x.benign_task_success);
  return {
    suite: "Intervention I1 — entitlement-bound scope (matched arms)",
    version: "0.3.0-i1",
    now_ms: nowMs,
    arms,
    regression_source_code_denied_under_enforcement: regression,
    gap1_reproduced_in_baseline_arm: gap1Repro,
    no_false_deny_any_arm: noFalseDeny,
    passed: regression && gap1Repro && noFalseDeny && c.revocation_propagation === "invalidated",
  };
}
