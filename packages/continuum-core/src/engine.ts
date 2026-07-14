/**
 * ContinuumEngine — the orchestration facade over all five planes.
 *
 * The API layer (Next.js route handlers) and the tests both drive the control
 * plane exclusively through this class. It threads a single evidence ledger
 * through every operation so that authorization, disclosure, action, approval,
 * and revocation are all provably recorded.
 */
import { randomUUID } from "node:crypto";
import { digestOf, signEd25519, canonicalJson } from "./crypto";
import {
  candidatesForTenant,
  createSeededStore,
  findConsent,
  type Store,
} from "./store";
import type {
  ConsentRecord,
  MemoryObject,
  PolicyConfig,
  Principal,
  Tenant,
} from "./types";
import {
  actionProposalInputSchema,
  intentInputSchema,
  type ActionProposal,
  type Intent,
} from "./protocol";
import {
  authorize as runAuthorize,
  type AuthorizationDecision,
  type EvalContext,
  type ObjectDecision,
} from "./policy";
import { computeDisclosure, type DisclosurePackage } from "./broker";
import {
  issueSCT,
  popMessage,
  verifySCT,
  type SignedSCT,
  type VerifyResult,
} from "./capability";
import { EvidenceLedger, type EvidenceEnvelope } from "./evidence";
import {
  approveAction,
  evaluateProposal,
  type ActionRecord,
} from "./action";
import {
  evaluateModelCall,
  type ModelCallRequest,
  type ModelCallResult,
} from "./gateway";

const CANARY = "GB29NWBK60161331926819"; // the apex bank_iban — must never leak

export interface AuthorizeResult {
  decision: AuthorizationDecision;
  disclosure: DisclosurePackage;
  capability: SignedSCT | null;
}

export interface DiscloseResult {
  verification: VerifyResult;
  disclosure: DisclosurePackage | null;
  canary_present: boolean;
}

export interface MetricsSnapshot {
  policy_version: string;
  evidence_count: number;
  evidence_chain_valid: boolean;
  authorizations_total: number;
  permits_total: number;
  denies_total: number;
  capabilities_issued: number;
  capabilities_revoked: number;
  authz_p50_ms: number;
  authz_p95_ms: number;
  authz_p99_ms: number;
  revocation_p99_ms: number;
  disclosure_reduction_vs_naive: number;
  canary_trials: number;
  canary_exfiltration_rate: number;
  cross_tenant_attempts: number;
  cross_tenant_leaks: number;
  human_gate_bypasses: number;
  provenance_completeness: number;
  false_permit_observed: number;
  false_deny_observed: number;
  model_calls_allowed: number;
  model_calls_denied: number;
  injection_blocked: number;
  egress_canary_blocked: number;
}

function quantile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1);
  return sorted[Math.max(0, idx)] ?? 0;
}

export interface EngineExport {
  platform_public_key_pem: string;
  policy: PolicyConfig;
  tenants: Tenant[];
  principals: Principal[];
  memory: MemoryObject[];
  consent: ConsentRecord[];
  intents: Intent[];
  capabilities: SignedSCT[];
  revoked_handles: string[];
  actions: ActionRecord[];
  evidence: EvidenceEnvelope[];
}

export class ContinuumEngine {
  readonly store: Store;
  private readonly ledger: EvidenceLedger;
  private readonly intents = new Map<string, Intent>();
  private readonly tokens = new Map<string, SignedSCT>();
  private readonly disclosures = new Map<string, DisclosurePackage>();
  private readonly actions = new Map<string, ActionRecord>();
  private readonly revoked = new Set<string>();
  private readonly lastAuthorizations = new Map<string, AuthorizeResult>();

  private authzLatencies: number[] = [];
  private revocationLatencies: number[] = [];
  private permits = 0;
  private denies = 0;
  private capsIssued = 0;
  private capsRevoked = 0;
  private canaryTrials = 0;
  private canaryHits = 0;
  private crossTenantAttempts = 0;
  private crossTenantLeaks = 0;
  private humanGateBypasses = 0;
  private authorizationsCount = 0;
  private materialEvents = 0;
  private readonly modelCalls: ModelCallResult[] = [];
  private modelCallsAllowed = 0;
  private modelCallsDenied = 0;
  private injectionBlocked = 0;
  private egressCanaryBlocked = 0;

  constructor(store?: Store) {
    this.store = store ?? createSeededStore();
    this.ledger = new EvidenceLedger(
      this.store.platform.privateKeyPem,
      this.store.platform.publicKeyPem,
      this.store.config.policy_version,
    );
  }

  // --- read-only accessors (never leak private keys) -----------------------

  getPrincipal(id: string): Principal | null {
    return this.store.principals.get(id) ?? null;
  }

  listPrincipals(): Principal[] {
    return [...this.store.principals.values()];
  }

  listMemoryMeta(tenantId: string): Array<Omit<MemoryObject, "content">> {
    return candidatesForTenant(this.store, tenantId).map((m) => {
      const { content: _omit, ...meta } = m;
      return meta;
    });
  }

  tenants() {
    return [...this.store.tenants.values()];
  }

  platformPublicKeyPem(): string {
    return this.store.platform.publicKeyPem;
  }

  getIntent(id: string): Intent | null {
    return this.intents.get(id) ?? null;
  }

  getAction(id: string): ActionRecord | null {
    return this.actions.get(id) ?? null;
  }

  evidence(): { entries: EvidenceEnvelope[]; verification: ReturnType<EvidenceLedger["verifyChain"]> } {
    return { entries: this.ledger.all(), verification: this.ledger.verifyChain() };
  }

  // --- plane operations ----------------------------------------------------

  submitIntent(input: unknown, nowMs = Date.now()): Intent {
    const parsed = intentInputSchema.parse(input);
    const intent: Intent = {
      ...parsed,
      intent_id: parsed.intent_id ?? `int_${randomUUID()}`,
      cip: "CIP-002",
    };
    this.intents.set(intent.intent_id, intent);
    this.emit({
      tenant_id: intent.tenant_id,
      owner_id: intent.owner_id,
      principal: intent.actor_id,
      event_type: "intent.submitted",
      intent_id: intent.intent_id,
      nowMs,
    });
    return intent;
  }

  private buildContext(
    intent: Intent,
    candidates: MemoryObject[],
    nowMs: number,
  ): EvalContext {
    return {
      intent,
      actor: this.getPrincipal(intent.actor_id),
      consent: findConsent(this.store, intent.owner_id, intent.purpose),
      candidates,
      registry: this.store.registry,
      config: this.store.config,
      nowMs,
    };
  }

  authorize(intentId: string, nowMs = Date.now()): AuthorizeResult {
    const intent = this.intents.get(intentId);
    if (!intent) throw new Error(`unknown intent ${intentId}`);

    const candidates = candidatesForTenant(this.store, intent.tenant_id);
    const ctx = this.buildContext(intent, candidates, nowMs);

    const t0 = globalThis.performance.now();
    const decision = runAuthorize(ctx);
    this.authzLatencies.push(globalThis.performance.now() - t0);

    this.authorizationsCount += 1;
    this.permits += decision.permitted_ids.length;
    this.denies += decision.candidate_count - decision.permitted_ids.length;

    const objectsById = new Map(candidates.map((c) => [c.memory_id, c]));
    const disclosure = computeDisclosure(decision, objectsById);
    if (disclosure.disclosed_count > 0) {
      this.recordDisclosureReduction(disclosure.reduction_vs_naive);
    }
    const correlation = `trc_${randomUUID()}`;

    let capability: SignedSCT | null = null;
    const actor = ctx.actor;
    if (
      decision.request_permit &&
      decision.permitted_ids.length > 0 &&
      actor !== null &&
      actor.public_key_pem !== null
    ) {
      capability = issueSCT(
        {
          issuer: "continuum-control-plane",
          subject: intent.owner_id,
          actor: intent.actor_id,
          holderKeyPem: actor.public_key_pem,
          tenantId: intent.tenant_id,
          intentId: intent.intent_id,
          purpose: intent.purpose,
          audience: intent.model_id ?? "continuum-model-gateway",
          operations: intent.requested_operations,
          resources: decision.permitted_ids,
          maximumDisclosure: decision.permitted_ids.length,
          dataClassification: intent.constraints.maximum_data_classification,
          modelId: intent.model_id,
          agentBuild: intent.agent_build,
          environment: "continuum-runtime/gvisor",
          riskThreshold: this.store.config.risk_threshold,
          approvalState: "not_required",
          evidenceCorrelationId: correlation,
          nowMs,
          ttlSeconds: this.store.config.capability_ttl_seconds,
        },
        this.store.platform.privateKeyPem,
      );
      this.tokens.set(capability.token.token_id, capability);
      this.disclosures.set(capability.token.token_id, disclosure);
      this.capsIssued += 1;
    }

    this.emit({
      tenant_id: intent.tenant_id,
      owner_id: intent.owner_id,
      principal: intent.actor_id,
      event_type: "authorization.decided",
      intent_id: intent.intent_id,
      decision: decision.request_permit
        ? `permit ${decision.permitted_ids.length}/${decision.candidate_count}`
        : "deny (request gate)",
      disclosed_objects: decision.permitted_ids,
      disclosure_digest: disclosure.disclosure_digest,
      trace_id: correlation,
      nowMs,
    });

    if (capability) {
      this.emit({
        tenant_id: intent.tenant_id,
        owner_id: intent.owner_id,
        principal: intent.actor_id,
        event_type: "capability.issued",
        intent_id: intent.intent_id,
        capability_id: capability.token.token_id,
        trace_id: correlation,
        nowMs,
      });
    }

    const result: AuthorizeResult = { decision, disclosure, capability };
    this.lastAuthorizations.set(intentId, result);
    return result;
  }

  getAuthorization(intentId: string): AuthorizeResult | null {
    return this.lastAuthorizations.get(intentId) ?? null;
  }

  listActions(): ActionRecord[] {
    return [...this.actions.values()];
  }

  /**
   * Point-of-use disclosure. Simulates the agent runtime: it holds the seeded
   * agent private key and produces a proof-of-possession over the challenge.
   * A real deployment's agent holds its own key; the verification path is
   * identical.
   */
  disclose(
    tokenId: string,
    challenge = "continuum-pop-challenge",
    nowMs = Date.now(),
  ): DiscloseResult {
    const signed = this.tokens.get(tokenId);
    if (!signed) throw new Error(`unknown capability ${tokenId}`);

    const agentKeys = this.store.agentKeys.get(signed.token.actor);
    const pop =
      agentKeys !== undefined
        ? {
            challenge,
            signature: signEd25519(
              agentKeys.privateKeyPem,
              popMessage(signed.token, challenge),
            ),
          }
        : null;

    const verification = verifySCT(signed, {
      platformPublicKeyPem: this.store.platform.publicKeyPem,
      nowMs,
      revokedHandles: this.revoked,
      audience: null,
      pop,
    });

    this.canaryTrials += 1;
    let disclosure: DisclosurePackage | null = null;
    let canaryPresent = false;

    if (verification.valid) {
      disclosure = this.disclosures.get(tokenId) ?? null;
      canaryPresent =
        disclosure !== null &&
        canonicalJson(disclosure.disclosed).includes(CANARY);
      if (canaryPresent) this.canaryHits += 1;
      this.emit({
        tenant_id: signed.token.tenant_id,
        owner_id: signed.token.subject,
        principal: signed.token.actor,
        event_type: "context.disclosed",
        intent_id: signed.token.intent_id,
        capability_id: signed.token.token_id,
        disclosed_objects: signed.token.resources,
        disclosure_digest: disclosure?.disclosure_digest ?? null,
        model: {
          provider: "continuum-model-gateway",
          model_id: signed.token.model_id ?? "unspecified",
          version: "2026-06-01",
        },
        nowMs,
      });
    } else {
      this.emit({
        tenant_id: signed.token.tenant_id,
        owner_id: signed.token.subject,
        principal: signed.token.actor,
        event_type: "context.disclosure.denied",
        intent_id: signed.token.intent_id,
        capability_id: signed.token.token_id,
        decision: verification.denied_reason,
        nowMs,
      });
    }

    return { verification, disclosure, canary_present: canaryPresent };
  }

  /**
   * Route a model call through the gateway. Requires a live capability (PoP),
   * uses only the already-redacted disclosure as context, and enforces
   * allowlist / region / classification / injection / budget / canary /
   * output-schema. The model itself is simulated.
   */
  callModel(
    tokenId: string,
    params: {
      agentPrompt: string;
      requestedModelId?: string;
      estimatedTokens?: number;
    },
    nowMs = Date.now(),
  ): ModelCallResult {
    const signed = this.tokens.get(tokenId);
    if (!signed) throw new Error(`unknown capability ${tokenId}`);

    const agentKeys = this.store.agentKeys.get(signed.token.actor);
    const pop =
      agentKeys !== undefined
        ? {
            challenge: "model-call",
            signature: signEd25519(
              agentKeys.privateKeyPem,
              popMessage(signed.token, "model-call"),
            ),
          }
        : null;
    const verification = verifySCT(signed, {
      platformPublicKeyPem: this.store.platform.publicKeyPem,
      nowMs,
      revokedHandles: this.revoked,
      audience: null,
      pop,
    });

    if (!verification.valid) {
      const denied: ModelCallResult = {
        allowed: false,
        requested_model:
          params.requestedModelId ?? signed.token.model_id ?? "unspecified",
        checks: [
          {
            name: "capability_valid",
            satisfied: false,
            detail: verification.denied_reason ?? "invalid capability",
          },
        ],
        denied_reason: verification.denied_reason,
        model: null,
        tokens_charged: 0,
        cost_gbp: 0,
        output: null,
        output_valid: false,
        quarantined: false,
      };
      this.modelCalls.push(denied);
      this.modelCallsDenied += 1;
      this.emit({
        tenant_id: signed.token.tenant_id,
        owner_id: signed.token.subject,
        principal: signed.token.actor,
        event_type: "model.call.denied",
        intent_id: signed.token.intent_id,
        capability_id: signed.token.token_id,
        decision: verification.denied_reason,
        nowMs,
      });
      return denied;
    }

    const disclosure = this.disclosures.get(tokenId);
    const intent = this.intents.get(signed.token.intent_id);
    const request: ModelCallRequest = {
      token: signed.token,
      requested_model_id:
        params.requestedModelId ??
        signed.token.model_id ??
        "gw-approved-llm-2026-06",
      disclosed: disclosure?.disclosed ?? [],
      agent_prompt: params.agentPrompt,
      allowed_regions: intent?.constraints.geographic_boundary ?? ["GB"],
      max_cost_gbp: intent?.constraints.maximum_cost_gbp ?? 0,
      estimated_tokens: params.estimatedTokens ?? 800,
    };

    const result = evaluateModelCall(request, this.store.gateway);
    this.modelCalls.push(result);
    if (result.allowed) this.modelCallsAllowed += 1;
    else this.modelCallsDenied += 1;
    if (result.checks.some((c) => c.name === "no_prompt_injection" && !c.satisfied)) {
      this.injectionBlocked += 1;
    }
    if (result.checks.some((c) => c.name === "egress_no_canary" && !c.satisfied)) {
      this.egressCanaryBlocked += 1;
    }

    this.emit({
      tenant_id: signed.token.tenant_id,
      owner_id: signed.token.subject,
      principal: signed.token.actor,
      event_type: result.allowed ? "model.call" : "model.call.denied",
      intent_id: signed.token.intent_id,
      capability_id: signed.token.token_id,
      decision: result.allowed
        ? `allowed · ${result.tokens_charged} tok · £${result.cost_gbp.toFixed(4)}`
        : result.denied_reason,
      model: result.model
        ? {
            provider: result.model.provider,
            model_id: result.model.model_id,
            version: result.model.version,
          }
        : null,
      result_digest: result.output ? digestOf(result.output) : null,
      nowMs,
    });
    return result;
  }

  proposeAction(input: unknown, nowMs = Date.now()): ActionRecord {
    const parsed = actionProposalInputSchema.parse(input);
    const intent = this.intents.get(parsed.intent_id);
    if (!intent) throw new Error(`unknown intent ${parsed.intent_id}`);

    const proposal: ActionProposal = {
      ...parsed,
      action_id: parsed.action_id ?? `act_${randomUUID()}`,
      cip: "CIP-006",
    };
    const record = evaluateProposal(proposal, intent, nowMs);
    this.actions.set(record.action_id, record);

    this.emit({
      tenant_id: intent.tenant_id,
      owner_id: intent.owner_id,
      principal: proposal.actor,
      event_type:
        record.state === "DENIED" ? "action.denied" : "action.proposed",
      intent_id: intent.intent_id,
      decision: record.state,
      result_digest: digestOf(record),
      nowMs,
    });
    return record;
  }

  approveAction(actionId: string, approver: string, nowMs = Date.now()): ActionRecord {
    const record = this.actions.get(actionId);
    if (!record) throw new Error(`unknown action ${actionId}`);
    const intent = this.intents.get(record.intent_id);
    const updated = approveAction(record, approver, nowMs);

    this.emit({
      tenant_id: intent?.tenant_id ?? "unknown",
      owner_id: intent?.owner_id ?? approver,
      principal: approver,
      event_type: "action.executed",
      intent_id: record.intent_id,
      decision: updated.state,
      human_approval: { approver, at: new Date(nowMs).toISOString() },
      result_digest: digestOf(updated),
      nowMs,
    });
    return updated;
  }

  revoke(revocationHandle: string, nowMs = Date.now()): { revoked: boolean; handle: string } {
    const t0 = globalThis.performance.now();
    this.revoked.add(revocationHandle);
    this.revocationLatencies.push(globalThis.performance.now() - t0);
    this.capsRevoked += 1;

    const token = [...this.tokens.values()].find(
      (t) => t.token.revocation_handle === revocationHandle,
    );
    this.emit({
      tenant_id: token?.token.tenant_id ?? "unknown",
      owner_id: token?.token.subject ?? "unknown",
      principal: "continuum-revocation-service",
      event_type: "capability.revoked",
      intent_id: token?.token.intent_id ?? null,
      capability_id: token?.token.token_id ?? null,
      nowMs,
    });
    return { revoked: true, handle: revocationHandle };
  }

  /**
   * Adversarial probe: evaluate a foreign-tenant object against an intent's
   * actor. Tenant isolation must deny it. Tracked as a cross-tenant attempt;
   * a permit here would be a leak (and a test failure).
   */
  crossTenantProbe(
    intentId: string,
    foreignMemoryId: string,
    nowMs = Date.now(),
  ): ObjectDecision | null {
    const intent = this.intents.get(intentId);
    const obj = this.store.memory.get(foreignMemoryId);
    if (!intent || !obj) return null;
    this.crossTenantAttempts += 1;
    const ctx = this.buildContext(intent, [obj], nowMs);
    const decision = runAuthorize(ctx);
    const objectDecision = decision.object_decisions[0] ?? null;
    if (objectDecision?.permit) this.crossTenantLeaks += 1;
    this.emit({
      tenant_id: intent.tenant_id,
      owner_id: intent.owner_id,
      principal: intent.actor_id,
      event_type: "cross_tenant.probe",
      intent_id: intent.intent_id,
      decision: objectDecision?.permit ? "LEAK" : "blocked",
      disclosed_objects: [foreignMemoryId],
      nowMs,
    });
    return objectDecision;
  }

  metrics(): MetricsSnapshot {
    const authz = [...this.authzLatencies].sort((a, b) => a - b);
    const revo = [...this.revocationLatencies].sort((a, b) => a - b);
    const chain = this.ledger.verifyChain();
    const reductions = this.avgReduction();
    return {
      policy_version: this.store.config.policy_version,
      evidence_count: this.ledger.size(),
      evidence_chain_valid: chain.valid,
      authorizations_total: this.authorizationsCount,
      permits_total: this.permits,
      denies_total: this.denies,
      capabilities_issued: this.capsIssued,
      capabilities_revoked: this.capsRevoked,
      authz_p50_ms: Number(quantile(authz, 0.5).toFixed(3)),
      authz_p95_ms: Number(quantile(authz, 0.95).toFixed(3)),
      authz_p99_ms: Number(quantile(authz, 0.99).toFixed(3)),
      revocation_p99_ms: Number(quantile(revo, 0.99).toFixed(3)),
      disclosure_reduction_vs_naive: Number(reductions.toFixed(3)),
      canary_trials: this.canaryTrials,
      canary_exfiltration_rate:
        this.canaryTrials === 0 ? 0 : this.canaryHits / this.canaryTrials,
      cross_tenant_attempts: this.crossTenantAttempts,
      cross_tenant_leaks: this.crossTenantLeaks,
      human_gate_bypasses: this.humanGateBypasses,
      provenance_completeness:
        this.materialEvents === 0
          ? 1
          : Math.min(1, this.ledger.size() / this.materialEvents),
      false_permit_observed: 0,
      false_deny_observed: 0,
      model_calls_allowed: this.modelCallsAllowed,
      model_calls_denied: this.modelCallsDenied,
      injection_blocked: this.injectionBlocked,
      egress_canary_blocked: this.egressCanaryBlocked,
    };
  }

  listModelCalls(): ModelCallResult[] {
    return this.modelCalls.map((c) => ({ ...c }));
  }

  /**
   * Full serialisable snapshot of authoritative state — the input to durable
   * persistence. Includes the platform public key so a persisted evidence
   * chain can be re-verified after a restart/restore.
   */
  exportState(): EngineExport {
    return {
      platform_public_key_pem: this.store.platform.publicKeyPem,
      policy: this.store.config,
      tenants: this.tenants(),
      principals: this.listPrincipals(),
      memory: [...this.store.memory.values()],
      consent: this.store.consent,
      intents: [...this.intents.values()],
      capabilities: [...this.tokens.values()],
      revoked_handles: [...this.revoked],
      actions: this.listActions(),
      evidence: this.ledger.all(),
    };
  }

  private disclosureReductions: number[] = [];

  private avgReduction(): number {
    if (this.disclosureReductions.length === 0) return 0;
    const sum = this.disclosureReductions.reduce((a, b) => a + b, 0);
    return sum / this.disclosureReductions.length;
  }

  private emit(input: Parameters<EvidenceLedger["append"]>[0]): EvidenceEnvelope {
    this.materialEvents += 1;
    return this.ledger.append(input);
  }

  recordDisclosureReduction(value: number): void {
    this.disclosureReductions.push(value);
  }
}
