/**
 * Policy Decision Point (Plane B).
 *
 * Implements the primary system invariant:
 *
 *   Permit = IdentityValid ∧ PurposeAllowed ∧ ScopeAllowed ∧ PolicySatisfied
 *            ∧ RiskWithinLimit ∧ ConsentCurrent ∧ EvidenceSufficient
 *
 * with tenant isolation as a hard gate above all of it. The default result is
 * ALWAYS deny: `permit` becomes true only when every mandatory check passes.
 * Every decision — allow or deny — carries the full check list so it can be
 * reconstructed and audited. No check is silent.
 */
import type {
  ApprovedRegistry,
  ConsentRecord,
  MemoryObject,
  PolicyConfig,
  Principal,
} from "./types";
import { classRank } from "./types";
import type { Intent } from "./protocol";
import { digestOf } from "./crypto";

export interface Check {
  name: string;
  satisfied: boolean;
  mandatory: boolean;
  detail: string;
}

export interface ObjectDecision {
  memory_id: string;
  classification: string;
  permit: boolean;
  checks: Check[];
  denied_reason: string | null;
}

export interface AuthorizationDecision {
  intent_id: string;
  actor_id: string;
  tenant_id: string;
  policy_version: string;
  policy_digest: string;
  /** Per-request gates; if any mandatory one fails, the whole request denies. */
  request_checks: Check[];
  request_permit: boolean;
  object_decisions: ObjectDecision[];
  permitted_ids: string[];
  candidate_count: number;
  timestamp: string;
}

export interface EvalContext {
  intent: Intent;
  actor: Principal | null;
  consent: ConsentRecord | null;
  candidates: MemoryObject[];
  registry: ApprovedRegistry;
  config: PolicyConfig;
  nowMs: number;
}

function check(
  name: string,
  satisfied: boolean,
  detail: string,
  mandatory = true,
): Check {
  return { name, satisfied, mandatory, detail };
}

function firstFailure(checks: Check[]): string | null {
  const failed = checks.find((c) => c.mandatory && !c.satisfied);
  return failed ? `${failed.name}: ${failed.detail}` : null;
}

/** Evaluate the per-request gates (identity, agent, consent, risk, evidence). */
function evaluateRequest(ctx: EvalContext): Check[] {
  const { intent, actor, consent, registry, config, nowMs } = ctx;
  const checks: Check[] = [];

  // IdentityValid — principal must exist, be attested, and match the intent actor.
  const identityOk =
    actor !== null && actor.attested && actor.principal_id === intent.actor_id;
  checks.push(
    check(
      "identity_valid",
      identityOk,
      actor === null
        ? "actor principal not found"
        : !actor.attested
          ? "actor attestation not current"
          : actor.principal_id !== intent.actor_id
            ? "actor identity does not match intent"
            : "principal authenticated and attested",
    ),
  );

  // Agent build approved — deny-by-default allowlist.
  const build = intent.agent_build ?? actor?.build_hash ?? null;
  const buildOk = build !== null && registry.agent_builds.has(build);
  checks.push(
    check(
      "agent_build_approved",
      buildOk,
      build === null
        ? "no agent build measurement presented"
        : buildOk
          ? `build ${build.slice(0, 18)}… on allowlist`
          : `build ${build.slice(0, 18)}… not approved`,
    ),
  );

  // ConsentCurrent — a granted, unexpired consent for this exact purpose.
  const consentOk =
    consent !== null &&
    consent.granted &&
    consent.purpose === intent.purpose &&
    consent.owner_id === intent.owner_id &&
    Date.parse(consent.valid_until) > nowMs;
  checks.push(
    check(
      "consent_current",
      consentOk,
      consent === null
        ? "no consent on record for owner/purpose"
        : !consent.granted
          ? "consent withdrawn"
          : consent.purpose !== intent.purpose
            ? "consent purpose mismatch"
            : Date.parse(consent.valid_until) <= nowMs
              ? "consent expired"
              : "consent granted and current",
    ),
  );

  // RiskWithinLimit
  const riskOk = intent.risk_score <= config.risk_threshold;
  checks.push(
    check(
      "risk_within_limit",
      riskOk,
      `risk ${intent.risk_score.toFixed(2)} ${riskOk ? "≤" : ">"} threshold ${config.risk_threshold.toFixed(2)}`,
    ),
  );

  // EvidenceSufficient — every required evidence item must be independently
  // satisfiable. Unknown evidence keys fail closed.
  const evidenceResults = intent.required_evidence.map((e) => {
    switch (e) {
      case "agent_attestation":
        return { e, ok: actor !== null && actor.attested && build !== null };
      case "approved_model_policy":
        return {
          e,
          ok: intent.model_id !== null && registry.models.has(intent.model_id),
        };
      case "current_user_consent":
        return { e, ok: consentOk };
      default:
        return { e, ok: false }; // unknown requirement — fail closed
    }
  });
  const missing = evidenceResults.filter((r) => !r.ok).map((r) => r.e);
  checks.push(
    check(
      "evidence_sufficient",
      missing.length === 0,
      missing.length === 0
        ? `all required evidence present (${intent.required_evidence.length})`
        : `unsatisfied evidence: ${missing.join(", ")}`,
    ),
  );

  return checks;
}

/** Evaluate one memory object against a request that already passed the gates. */
function evaluateObject(ctx: EvalContext, obj: MemoryObject): ObjectDecision {
  const { intent, actor, nowMs } = ctx;
  const checks: Check[] = [];

  // Tenant isolation — hard gate. A caller may only ever see its own tenant.
  const tenantOk =
    actor !== null &&
    obj.tenant_id === actor.tenant_id &&
    obj.tenant_id === intent.tenant_id;
  checks.push(
    check(
      "tenant_isolation",
      tenantOk,
      tenantOk
        ? `object owned by tenant ${obj.tenant_id}`
        : `cross-tenant access blocked (object tenant ${obj.tenant_id})`,
    ),
  );

  // Object lifecycle — not revoked, not deleted, not stale.
  const liveOk =
    obj.revocation_state === "active" && obj.deletion_state === "present";
  checks.push(
    check(
      "object_live",
      liveOk,
      obj.revocation_state === "revoked"
        ? "object revoked"
        : obj.deletion_state === "deleted"
          ? "object deleted"
          : "object active",
    ),
  );

  const staleOk =
    obj.valid_until === null || Date.parse(obj.valid_until) > nowMs;
  checks.push(
    check(
      "not_stale",
      staleOk,
      staleOk ? "within validity window" : "object validity window elapsed",
    ),
  );

  // PurposeAllowed
  const purposeOk = obj.purpose_constraints.includes(intent.purpose);
  checks.push(
    check(
      "purpose_allowed",
      purposeOk,
      purposeOk
        ? `purpose '${intent.purpose}' permitted`
        : `purpose '${intent.purpose}' not in object constraints`,
    ),
  );

  // ScopeAllowed — the read operation must be requested and not prohibited.
  const requested = intent.requested_operations.includes(obj.read_operation);
  const prohibited = intent.prohibited_operations.includes(obj.read_operation);
  const scopeOk = requested && !prohibited;
  checks.push(
    check(
      "scope_allowed",
      scopeOk,
      prohibited
        ? `operation '${obj.read_operation}' is prohibited by intent`
        : !requested
          ? `operation '${obj.read_operation}' not requested by intent`
          : `operation '${obj.read_operation}' in scope`,
    ),
  );

  // PolicySatisfied — classification ceiling.
  const classOk =
    classRank(obj.classification) <=
    classRank(intent.constraints.maximum_data_classification);
  checks.push(
    check(
      "classification_within_max",
      classOk,
      `object ${obj.classification} ${classOk ? "≤" : ">"} max ${intent.constraints.maximum_data_classification}`,
    ),
  );

  // PolicySatisfied — data residency.
  const residencyOk = intent.constraints.geographic_boundary.includes(
    obj.residency,
  );
  checks.push(
    check(
      "residency_allowed",
      residencyOk,
      residencyOk
        ? `residency ${obj.residency} within boundary`
        : `residency ${obj.residency} outside ${intent.constraints.geographic_boundary.join(",")}`,
    ),
  );

  const permit = checks.every((c) => !c.mandatory || c.satisfied);
  return {
    memory_id: obj.memory_id,
    classification: obj.classification,
    permit,
    checks,
    denied_reason: permit ? null : firstFailure(checks),
  };
}

/**
 * The single authorization entry point. Runs request gates first; if they pass,
 * evaluates every candidate object independently. Fail-closed throughout.
 */
export function authorize(ctx: EvalContext): AuthorizationDecision {
  const requestChecks = evaluateRequest(ctx);
  const requestPermit = requestChecks.every(
    (c) => !c.mandatory || c.satisfied,
  );
  const nowIso = new Date(ctx.nowMs).toISOString();

  const policyDigest = digestOf({
    version: ctx.config.policy_version,
    risk_threshold: ctx.config.risk_threshold,
    intent: ctx.intent.intent_id,
  });

  let objectDecisions: ObjectDecision[];
  if (!requestPermit) {
    // Whole request denied: reflect the request-level reason on every object.
    const reason = firstFailure(requestChecks) ?? "request denied";
    objectDecisions = ctx.candidates.map((obj) => ({
      memory_id: obj.memory_id,
      classification: obj.classification,
      permit: false,
      checks: [check("request_gate", false, reason)],
      denied_reason: reason,
    }));
  } else {
    objectDecisions = ctx.candidates.map((obj) => evaluateObject(ctx, obj));
  }

  const permittedIds = objectDecisions
    .filter((d) => d.permit)
    .map((d) => d.memory_id);

  return {
    intent_id: ctx.intent.intent_id,
    actor_id: ctx.intent.actor_id,
    tenant_id: ctx.intent.tenant_id,
    policy_version: ctx.config.policy_version,
    policy_digest: policyDigest,
    request_checks: requestChecks,
    request_permit: requestPermit,
    object_decisions: objectDecisions,
    permitted_ids: permittedIds,
    candidate_count: ctx.candidates.length,
    timestamp: nowIso,
  };
}
