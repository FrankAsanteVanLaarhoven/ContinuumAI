/**
 * The v0.1 vertical slice — the blueprint's "First Implementation Milestone".
 *
 * Drives one ContinuumEngine through the full flow and records both a
 * human-readable trace (for the console) and a set of machine assertions (for
 * the tests and the CI gate). `passed` is the AND of every assertion.
 */
import { ContinuumEngine } from "./engine";

export interface SliceStep {
  n: number;
  title: string;
  plane: string;
  status: "ok" | "blocked" | "denied" | "info";
  summary: string;
  detail: Record<string, unknown>;
}

export interface SliceAssertion {
  name: string;
  ok: boolean;
  detail: string;
}

export interface SliceResult {
  engine: ContinuumEngine;
  intent_id: string;
  steps: SliceStep[];
  assertions: SliceAssertion[];
  passed: boolean;
}

const OWNER = "did:continuum:enterprise:acme:owner";
const AGENT = "spiffe://acme.ai/agents/procurement-agent";

export function runVerticalSlice(nowMs = Date.now()): SliceResult {
  const engine = new ContinuumEngine();
  const steps: SliceStep[] = [];
  const assertions: SliceAssertion[] = [];
  const assert = (name: string, ok: boolean, detail: string) =>
    assertions.push({ name, ok, detail });

  // 1 — owner authenticates
  const owner = engine.getPrincipal(OWNER);
  steps.push({
    n: 1,
    title: "Owner authenticates",
    plane: "Identity",
    status: owner ? "info" : "denied",
    summary: owner ? `${owner.display_name} (human, attested)` : "owner not found",
    detail: { principal: OWNER, attested: owner?.attested ?? false },
  });

  // 2 — agent authenticates via workload identity
  const agent = engine.getPrincipal(AGENT);
  steps.push({
    n: 2,
    title: "Agent authenticates (workload identity)",
    plane: "Identity",
    status: agent?.attested ? "info" : "denied",
    summary: agent
      ? `SPIFFE ${AGENT} · build ${agent.build_hash?.slice(0, 22)}…`
      : "agent not found",
    detail: { principal: AGENT, build_hash: agent?.build_hash ?? null },
  });

  // 3 — agent submits structured intent
  const intent = engine.submitIntent(
    {
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
      required_evidence: [
        "agent_attestation",
        "approved_model_policy",
        "current_user_consent",
      ],
      human_gate: { required_for: ["external_commitment", "financial_execution"] },
      actor_geo: "GB",
      model_id: "gw-approved-llm-2026-06",
      agent_build: agent?.build_hash ?? null,
      risk_score: 0.12,
    },
    nowMs,
  );
  steps.push({
    n: 3,
    title: "Agent submits structured intent",
    plane: "Intent",
    status: "ok",
    summary: `intent ${intent.intent_id.slice(0, 14)}… · purpose ${intent.purpose}`,
    detail: { intent_id: intent.intent_id, requested: intent.requested_operations },
  });

  // 4 — policy permits exactly 2 of 10
  const { decision, disclosure, capability } = engine.authorize(intent.intent_id, nowMs);
  steps.push({
    n: 4,
    title: "Policy permits only the minimum set",
    plane: "Policy",
    status: decision.permitted_ids.length === 2 ? "ok" : "denied",
    summary: `permit ${decision.permitted_ids.length}/${decision.candidate_count} · deny-by-default`,
    detail: {
      permitted: decision.permitted_ids,
      denials: decision.object_decisions
        .filter((d) => !d.permit)
        .map((d) => ({ id: d.memory_id, reason: d.denied_reason })),
    },
  });
  assert(
    "policy.permits_exactly_two",
    decision.permitted_ids.length === 2,
    `permitted ${decision.permitted_ids.length} of ${decision.candidate_count}`,
  );

  // 5 — broker redacts one sensitive field
  steps.push({
    n: 5,
    title: "Context broker redacts sensitive field",
    plane: "Broker",
    status: disclosure.redactions.length >= 1 ? "ok" : "denied",
    summary: `${disclosure.redactions.length} redaction(s) · digest ${disclosure.disclosure_digest.slice(0, 12)}…`,
    detail: { redactions: disclosure.redactions },
  });
  assert(
    "broker.redacts_sensitive_field",
    disclosure.redactions.length === 1 &&
      disclosure.redactions[0]?.field === "bank_iban",
    `${disclosure.redactions.length} redaction(s)`,
  );

  // 6 — short-lived holder-bound capability issued
  steps.push({
    n: 6,
    title: "Holder-bound capability issued",
    plane: "Capability",
    status: capability ? "ok" : "denied",
    summary: capability
      ? `SCT ${capability.token.token_id.slice(0, 14)}… · ttl ${engine.store.config.capability_ttl_seconds}s · ${capability.token.resources.length} resources`
      : "no capability issued",
    detail: {
      token_id: capability?.token.token_id ?? null,
      operations: capability?.token.operations ?? [],
      resources: capability?.token.resources ?? [],
      expires_at: capability?.token.expires_at ?? null,
    },
  });
  assert("capability.issued", capability !== null, capability ? "issued" : "missing");
  if (!capability) {
    return finalize(engine, intent.intent_id, steps, assertions);
  }

  // 7 — model gateway sends only permitted context (agent proves possession)
  const disclosed = engine.disclose(capability.token.token_id, "slice-challenge", nowMs);
  steps.push({
    n: 7,
    title: "Model gateway sends only permitted context",
    plane: "Model gateway",
    status: disclosed.verification.valid && !disclosed.canary_present ? "ok" : "denied",
    summary: `PoP ${disclosed.verification.valid ? "verified" : "failed"} · ${disclosed.disclosure?.disclosed_count ?? 0} objects · canary ${disclosed.canary_present ? "LEAKED" : "contained"}`,
    detail: {
      checks: disclosed.verification.checks,
      disclosed_ids: disclosed.disclosure?.disclosed.map((d) => d.memory_id) ?? [],
    },
  });
  assert(
    "disclose.pop_and_no_canary",
    disclosed.verification.valid && !disclosed.canary_present,
    `valid=${disclosed.verification.valid} canary=${disclosed.canary_present}`,
  );

  // 8 — agent proposes a prohibited action → hard deny
  const prohibited = engine.proposeAction(
    {
      intent_id: intent.intent_id,
      actor: AGENT,
      operation: "place_order",
      action_class: "financial_execution",
      expected_effect: "place purchase order with Apex",
    },
    nowMs,
  );
  steps.push({
    n: 8,
    title: "Prohibited action denied outright",
    plane: "Action",
    status: prohibited.state === "DENIED" ? "denied" : "ok",
    summary: `place_order → ${prohibited.state} (${prohibited.denied_reason ?? ""})`,
    detail: { action_id: prohibited.action_id, state: prohibited.state },
  });
  assert("action.prohibited_denied", prohibited.state === "DENIED", prohibited.state);

  // 8b/9 — agent proposes an external commitment → blocked pending human approval
  const gated = engine.proposeAction(
    {
      intent_id: intent.intent_id,
      actor: AGENT,
      operation: "publish:recommendation",
      action_class: "external_commitment",
      expected_effect: "publish supplier recommendation to procurement portal",
    },
    nowMs,
  );
  steps.push({
    n: 9,
    title: "External action blocked pending human approval",
    plane: "Approval",
    status:
      gated.requires_human_approval && gated.state === "POLICY_APPROVED"
        ? "blocked"
        : "denied",
    summary: `state ${gated.state} · human gate ${gated.requires_human_approval ? "required" : "not required"}`,
    detail: { action_id: gated.action_id, history: gated.history },
  });
  assert(
    "action.human_gate_blocks",
    gated.requires_human_approval && gated.state === "POLICY_APPROVED",
    `state=${gated.state} gate=${gated.requires_human_approval}`,
  );

  // 10 — owner approves
  // 11 — tool gateway executes safe simulated action
  const executed = engine.approveAction(gated.action_id, OWNER, nowMs);
  steps.push({
    n: 10,
    title: "Owner approves · tool gateway executes (simulated)",
    plane: "Approval / Tool",
    status: executed.state === "SUCCEEDED" ? "ok" : "denied",
    summary: `${gated.action_id.slice(0, 12)}… → ${executed.state}`,
    detail: { history: executed.history },
  });
  assert("action.executes_after_approval", executed.state === "SUCCEEDED", executed.state);

  // 12 — every material step produced signed evidence; chain intact
  const ev = engine.evidence();
  steps.push({
    n: 11,
    title: "Signed evidence for every material step",
    plane: "Evidence",
    status: ev.verification.valid ? "ok" : "denied",
    summary: `${ev.entries.length} envelopes · chain ${ev.verification.valid ? "intact" : "BROKEN"}`,
    detail: { verification: ev.verification, event_types: ev.entries.map((e) => e.event_type) },
  });
  assert("evidence.chain_intact", ev.verification.valid, ev.verification.detail);

  // 13 — revocation prevents reuse
  engine.revoke(capability.token.revocation_handle, nowMs);
  const afterRevoke = engine.disclose(capability.token.token_id, "slice-challenge-2", nowMs);
  steps.push({
    n: 12,
    title: "Revocation kills the capability",
    plane: "Revocation",
    status: !afterRevoke.verification.valid ? "ok" : "denied",
    summary: `post-revocation disclosure ${afterRevoke.verification.valid ? "SUCCEEDED (bad)" : "denied"} · ${afterRevoke.verification.denied_reason ?? ""}`,
    detail: { checks: afterRevoke.verification.checks },
  });
  assert(
    "revocation.blocks_reuse",
    !afterRevoke.verification.valid,
    afterRevoke.verification.denied_reason ?? "denied",
  );

  // 14 — second tenant cannot reach first tenant's data
  const probe = engine.crossTenantProbe(intent.intent_id, "mem_glx_quote", nowMs);
  steps.push({
    n: 13,
    title: "Cross-tenant access blocked",
    plane: "Isolation",
    status: probe && !probe.permit ? "ok" : "denied",
    summary: `Acme agent → Globex object: ${probe?.permit ? "LEAK" : "blocked"} (${probe?.denied_reason ?? ""})`,
    detail: { object_decision: probe },
  });
  assert(
    "isolation.cross_tenant_blocked",
    probe !== null && !probe.permit,
    probe?.denied_reason ?? "blocked",
  );

  return finalize(engine, intent.intent_id, steps, assertions);
}

function finalize(
  engine: ContinuumEngine,
  intentId: string,
  steps: SliceStep[],
  assertions: SliceAssertion[],
): SliceResult {
  return {
    engine,
    intent_id: intentId,
    steps,
    assertions,
    passed: assertions.every((a) => a.ok),
  };
}
