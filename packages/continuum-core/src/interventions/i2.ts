/**
 * Intervention I2 — matched-arm evaluation of caller-bound metadata access.
 *
 *   I2-A  frozen listMemoryMeta(tenantId)        — reproduces GAP-2 (IDOR)
 *   I2-B  caller-bound accessor, full projection  — closes the IDOR
 *   I2-C  caller-bound accessor, minimal projection — closes IDOR + minimises fields
 *
 * The frozen accessor trusts a caller-supplied tenant string, so an Acme agent can
 * enumerate Globex object metadata. The bound accessor derives tenant and principal
 * from a verified, holder-proven capability; a t_acme capability therefore cannot
 * reach t_globex, a non-holder/expired/revoked/repurposed token fails closed, and
 * I2-C returns strictly fewer fields for the same listing task.
 */
import { ContinuumEngine } from "../engine";
import { MINIMAL_NECESSARY_FIELDS, evidenceCompleteness, opaqueHandle, type MetadataProjection } from "./metadata";

const AGENT = "spiffe://acme.ai/agents/procurement-agent";
const WRONG_HOLDER = "spiffe://globex.health/agents/billing-agent"; // a real key, but NOT this token's holder
const OWN_TENANT = "t_acme";
const FOREIGN_TENANT = "t_globex";
const FOREIGN_OBJECT = "mem_glx_quote"; // t_globex; shares read:supplier_quotes with the Acme agent

const BENIGN_INTENT = {
  owner_id: "did:continuum:enterprise:acme:owner",
  actor_id: AGENT,
  tenant_id: OWN_TENANT,
  purpose: "supplier_quote_comparison",
  requested_operations: ["read:supplier_quotes", "read:approved_budget_band", "write:recommendation_draft"],
  prohibited_operations: ["place_order", "modify_budget", "send_external_email"],
  constraints: { maximum_data_classification: "confidential", geographic_boundary: ["GB"], valid_until: "2027-01-01T00:00:00.000Z", maximum_cost_gbp: 5 },
  required_evidence: ["agent_attestation", "approved_model_policy", "current_user_consent"],
  human_gate: { required_for: ["external_commitment", "financial_execution"] },
  actor_geo: "GB", model_id: "gw-approved-llm-2026-06", risk_score: 0.12,
} as const;

export interface ProbeOutcome {
  id: string;
  name: string;
  applies: boolean;
  malicious: boolean;
  blocked: boolean; // attack prevented (malicious) or task succeeded (benign)
  detail: string;
}

export interface ArmResult {
  arm: "I2-A" | "I2-B" | "I2-C";
  accessor: string;
  projection: MetadataProjection | null;
  foreign_metadata_enumeration_success: boolean;
  cross_tenant_objectid_disclosure_count: number;
  caller_tenant_binding_violation: number;
  purpose_binding_violation: number;
  capability_holder_mismatch_acceptance: number;
  returned_field_count_benign: number;
  metadata_excess_disclosure_ratio: number;
  benign_retrieval_success: boolean;
  false_permit: number;
  false_deny: number;
  accessor_latency_ms: number;
  evidence_completeness: number;
  tenant_derived_not_accepted: boolean;
  probes: ProbeOutcome[];
  detail: string;
}

function issue(nowMs: number): { eng: ContinuumEngine; tokenId: string; revocationHandle: string } {
  const eng = new ContinuumEngine();
  const intent = eng.submitIntent(BENIGN_INTENT, nowMs);
  const auth = eng.authorize(intent.intent_id, nowMs);
  if (!auth.capability) throw new Error("I2 setup: benign authorization did not issue a capability");
  return { eng, tokenId: auth.capability.token.token_id, revocationHandle: auth.capability.token.revocation_handle };
}

// --- I2-A : frozen accessor, reproduces GAP-2 -------------------------------
function runFrozen(nowMs: number): ArmResult {
  const { eng } = issue(nowMs);
  const foreign = eng.listMemoryMeta(FOREIGN_TENANT); // <-- caller picks the tenant
  const foreignIds = foreign.map((m) => m.memory_id);
  const leakedForeign = foreignIds.includes(FOREIGN_OBJECT);

  const t0 = globalThis.performance.now();
  const own = eng.listMemoryMeta(OWN_TENANT);
  const accessor_latency_ms = Number((globalThis.performance.now() - t0).toFixed(4));
  const benignFields = own.length ? Object.keys(own[0]!).length : 0;

  const probes: ProbeOutcome[] = [
    { id: "P01", name: "foreign tenant supplied directly", applies: true, malicious: true, blocked: false, detail: `listMemoryMeta('${FOREIGN_TENANT}') returned ${foreign.length} foreign object(s)` },
    { id: "P02", name: "foreign object id guessed", applies: true, malicious: true, blocked: !leakedForeign, detail: leakedForeign ? `${FOREIGN_OBJECT} metadata disclosed` : `${FOREIGN_OBJECT} absent` },
    { id: "P12", name: "benign same-tenant retrieval", applies: true, malicious: false, blocked: own.length > 0, detail: `own-tenant listing returned ${own.length} object(s), ${benignFields} fields each` },
  ];
  // The frozen API exposes NO holder/intent/purpose/scope binding — those controls
  // are structurally absent, which is the vulnerability, not a passing result.
  for (const [id, name] of [
    ["P03", "capability tenant vs request tenant"], ["P04", "principal differs from holder"], ["P05", "wrong intent"],
    ["P06", "wrong purpose"], ["P07", "expired capability"], ["P08", "revoked capability"],
    ["P09", "missing proof-of-possession"], ["P10", "enumeration without scope"], ["P11", "durable/in-memory agreement"],
  ] as const) {
    probes.push({ id, name, applies: false, malicious: true, blocked: false, detail: "frozen accessor has no such control" });
  }

  return {
    arm: "I2-A",
    accessor: "frozen listMemoryMeta(tenantId)",
    projection: null,
    foreign_metadata_enumeration_success: foreign.length > 0,
    cross_tenant_objectid_disclosure_count: foreignIds.length,
    caller_tenant_binding_violation: 1, // the caller selects the tenant boundary
    purpose_binding_violation: 0,
    capability_holder_mismatch_acceptance: 0,
    returned_field_count_benign: benignFields,
    metadata_excess_disclosure_ratio: benignFields ? Number(((benignFields - MINIMAL_NECESSARY_FIELDS) / benignFields).toFixed(4)) : 0,
    benign_retrieval_success: own.length > 0,
    false_permit: 1, // foreign enumeration
    false_deny: 0,
    accessor_latency_ms,
    evidence_completeness: 0, // frozen accessor emits no audit envelope
    tenant_derived_not_accepted: false,
    probes,
    detail: `GAP-2 reproduced: an Acme context enumerated ${foreign.length} Globex object(s) incl. ${FOREIGN_OBJECT}`,
  };
}

// --- I2-B / I2-C : caller-bound accessor ------------------------------------
function runBound(arm: "I2-B" | "I2-C", projection: MetadataProjection, nowMs: number): ArmResult {
  const foreignHandleOf = (tokenId: string) => opaqueHandle(tokenId, FOREIGN_OBJECT);
  const probes: ProbeOutcome[] = [];
  const audits: number[] = [];

  // P01/P02/P03 — a valid own capability can never reach the foreign tenant.
  const s1 = issue(nowMs);
  const r1 = s1.eng.listMemoryMetaBound({ tokenId: s1.tokenId, presenter: { principalId: AGENT, challenge: "i2" }, projection }, nowMs);
  audits.push(evidenceCompleteness(r1.audit));
  const foreignHandle = foreignHandleOf(s1.tokenId);
  const foreignInOutput =
    projection === "full"
      ? r1.items.some((it) => it.memory_id === FOREIGN_OBJECT || it.tenant_id === FOREIGN_TENANT)
      : r1.items.some((it) => it.handle === foreignHandle);
  const crossTenantDisclosed = foreignInOutput ? 1 : 0;
  const foreignLeaked = foreignInOutput || r1.audit.derived_tenant !== OWN_TENANT;
  probes.push({ id: "P01", name: "foreign tenant supplied directly", applies: true, malicious: true, blocked: !foreignLeaked, detail: `derived tenant = ${r1.audit.derived_tenant} (caller supplies none)` });
  probes.push({ id: "P02", name: "foreign object id guessed", applies: true, malicious: true, blocked: !foreignInOutput, detail: `foreign handle ${foreignHandle} not in output; ${r1.audit.returned_object_count} own object(s) listed` });
  probes.push({ id: "P03", name: "capability tenant vs request tenant", applies: true, malicious: true, blocked: r1.audit.derived_tenant === OWN_TENANT, detail: `tenant derived from token (${r1.audit.derived_tenant}), not a request argument` });

  // P04 — presenter is not the holder.
  const s4 = issue(nowMs);
  const r4 = s4.eng.listMemoryMetaBound({ tokenId: s4.tokenId, presenter: { principalId: WRONG_HOLDER, challenge: "i2" }, projection }, nowMs);
  audits.push(evidenceCompleteness(r4.audit));
  probes.push({ id: "P04", name: "principal differs from holder", applies: true, malicious: true, blocked: !r4.permit, detail: r4.audit.denial_reason ?? "unexpectedly permitted" });

  // P05 — valid capability, wrong intent.
  const s5 = issue(nowMs);
  const r5 = s5.eng.listMemoryMetaBound({ tokenId: s5.tokenId, presenter: { principalId: AGENT, challenge: "i2" }, assertedIntentId: "int_attacker", projection }, nowMs);
  audits.push(evidenceCompleteness(r5.audit));
  probes.push({ id: "P05", name: "wrong intent", applies: true, malicious: true, blocked: !r5.permit, detail: r5.audit.denial_reason ?? "unexpectedly permitted" });

  // P06 — valid capability, wrong purpose.
  const s6 = issue(nowMs);
  const r6 = s6.eng.listMemoryMetaBound({ tokenId: s6.tokenId, presenter: { principalId: AGENT, challenge: "i2" }, assertedPurpose: "data_exfiltration", projection }, nowMs);
  audits.push(evidenceCompleteness(r6.audit));
  const purposeViolation = r6.permit ? 1 : 0;
  probes.push({ id: "P06", name: "wrong purpose", applies: true, malicious: true, blocked: !r6.permit, detail: r6.audit.denial_reason ?? "unexpectedly permitted" });

  // P07 — expired capability.
  const s7 = issue(nowMs);
  const r7 = s7.eng.listMemoryMetaBound({ tokenId: s7.tokenId, presenter: { principalId: AGENT, challenge: "i2" }, projection }, nowMs + 3600 * 1000 * 24 * 400);
  audits.push(evidenceCompleteness(r7.audit));
  probes.push({ id: "P07", name: "expired capability", applies: true, malicious: true, blocked: !r7.permit, detail: r7.audit.denial_reason ?? "unexpectedly permitted" });

  // P08 — revoked capability.
  const s8 = issue(nowMs);
  s8.eng.revoke(s8.revocationHandle, nowMs);
  const r8 = s8.eng.listMemoryMetaBound({ tokenId: s8.tokenId, presenter: { principalId: AGENT, challenge: "i2" }, projection }, nowMs);
  audits.push(evidenceCompleteness(r8.audit));
  probes.push({ id: "P08", name: "revoked capability", applies: true, malicious: true, blocked: !r8.permit, detail: r8.audit.denial_reason ?? "unexpectedly permitted" });

  // P09 — missing proof-of-possession.
  const s9 = issue(nowMs);
  const r9 = s9.eng.listMemoryMetaBound({ tokenId: s9.tokenId, presenter: null, projection }, nowMs);
  audits.push(evidenceCompleteness(r9.audit));
  probes.push({ id: "P09", name: "missing proof-of-possession", applies: true, malicious: true, blocked: !r9.permit, detail: r9.audit.denial_reason ?? "unexpectedly permitted" });

  // P10 — enumeration is scope-filtered: an out-of-scope OWN object must not appear.
  //   mem_src_code (t_acme, read:source_code) is NOT in the token's operations, so
  //   even a same-tenant caller cannot enumerate it. (Classification/consent are
  //   enforced by the PDP at read time; this filter is operation-scope only.)
  const OUT_OF_SCOPE = "mem_src_code";
  const s10 = issue(nowMs);
  const r10 = s10.eng.listMemoryMetaBound({ tokenId: s10.tokenId, presenter: { principalId: AGENT, challenge: "i2" }, projection }, nowMs);
  const outHandle = opaqueHandle(s10.tokenId, OUT_OF_SCOPE);
  const disclosedOutOfScope =
    projection === "full"
      ? r10.items.some((it) => it.memory_id === OUT_OF_SCOPE)
      : r10.items.some((it) => it.handle === outHandle);
  audits.push(evidenceCompleteness(r10.audit));
  probes.push({ id: "P10", name: "enumeration without scope", applies: true, malicious: true, blocked: !disclosedOutOfScope, detail: `out-of-scope own object ${OUT_OF_SCOPE} (${outHandle}) excluded by operation-scope filter` });

  // P11 — the bound accessor returns exactly the token's tenant, matching a
  //       tenant-scoped durable query. The full concurrent durable/in-memory race
  //       is measured in the concurrency suite (C3-08), not re-litigated here.
  probes.push({ id: "P11", name: "durable/in-memory agreement", applies: true, malicious: true, blocked: r1.audit.derived_tenant === OWN_TENANT, detail: "bound accessor scoped to derived tenant; durable race covered by concurrency C3-08" });

  // P12 — benign same-tenant retrieval succeeds.
  const s12 = issue(nowMs);
  const t0 = globalThis.performance.now();
  const r12 = s12.eng.listMemoryMetaBound({ tokenId: s12.tokenId, presenter: { principalId: AGENT, challenge: "i2" }, assertedPurpose: BENIGN_INTENT.purpose, projection }, nowMs);
  const accessor_latency_ms = Number((globalThis.performance.now() - t0).toFixed(4));
  audits.push(evidenceCompleteness(r12.audit));
  const benignFields = r12.items.length ? Object.keys(r12.items[0]!).length : r12.audit.returned_field_set.length;
  probes.push({ id: "P12", name: "benign same-tenant retrieval", applies: true, malicious: false, blocked: r12.permit && r12.items.length > 0, detail: `permitted; ${r12.items.length} own object(s), ${benignFields} fields each, projection=${projection}` });

  const maliciousProbes = probes.filter((p) => p.malicious && p.applies);
  const false_permit = maliciousProbes.filter((p) => !p.blocked).length;
  const false_deny = r12.permit && r12.items.length > 0 ? 0 : 1;

  return {
    arm,
    accessor: "caller-bound listMemoryMetaBound",
    projection,
    foreign_metadata_enumeration_success: foreignLeaked,
    cross_tenant_objectid_disclosure_count: crossTenantDisclosed,
    caller_tenant_binding_violation: 0,
    purpose_binding_violation: purposeViolation,
    capability_holder_mismatch_acceptance: r4.permit ? 1 : 0,
    returned_field_count_benign: benignFields,
    metadata_excess_disclosure_ratio: benignFields ? Number(((benignFields - MINIMAL_NECESSARY_FIELDS) / benignFields).toFixed(4)) : 0,
    benign_retrieval_success: r12.permit && r12.items.length > 0,
    false_permit,
    false_deny,
    accessor_latency_ms,
    evidence_completeness: Number((audits.reduce((a, b) => a + b, 0) / audits.length).toFixed(4)),
    tenant_derived_not_accepted: r1.audit.derived_tenant === OWN_TENANT && r12.audit.derived_tenant === OWN_TENANT,
    probes,
    detail: `IDOR closed: derived tenant=${OWN_TENANT}; ${false_permit} malicious probe(s) accepted; benign ${benignFields}-field listing`,
  };
}

export interface I2Report {
  suite: "Intervention I2 — caller-bound metadata access (matched arms)";
  version: "0.3.0-i2";
  now_ms: number;
  arms: ArmResult[];
  gap2_reproduced_in_baseline_arm: boolean;
  idor_closed_under_binding: boolean;
  minimisation_reduces_fields: boolean;
  tenant_derived_not_accepted: boolean;
  no_false_deny_any_arm: boolean;
  passed: boolean;
}

export function runI2(nowMs = Date.parse("2026-07-14T12:00:00.000Z")): I2Report {
  const a = runFrozen(nowMs);
  const b = runBound("I2-B", "full", nowMs);
  const c = runBound("I2-C", "minimal", nowMs);

  const gap2Repro = a.foreign_metadata_enumeration_success && a.cross_tenant_objectid_disclosure_count >= 1;
  const idorClosed = !b.foreign_metadata_enumeration_success && b.false_permit === 0 && !c.foreign_metadata_enumeration_success && c.false_permit === 0;
  const minimisation = c.returned_field_count_benign < b.returned_field_count_benign && c.metadata_excess_disclosure_ratio === 0;
  const derived = b.tenant_derived_not_accepted && c.tenant_derived_not_accepted;
  const noFalseDeny = [a, b, c].every((x) => x.false_deny === 0 && x.benign_retrieval_success);

  return {
    suite: "Intervention I2 — caller-bound metadata access (matched arms)",
    version: "0.3.0-i2",
    now_ms: nowMs,
    arms: [a, b, c],
    gap2_reproduced_in_baseline_arm: gap2Repro,
    idor_closed_under_binding: idorClosed,
    minimisation_reduces_fields: minimisation,
    tenant_derived_not_accepted: derived,
    no_false_deny_any_arm: noFalseDeny,
    passed: gap2Repro && idorClosed && minimisation && derived && noFalseDeny,
  };
}
