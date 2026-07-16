/**
 * InMemoryAsyncStore — deterministic test/research adapter for ContinuumStore.
 *
 * It wraps ONE frozen synchronous `ContinuumEngine` and returns immediately
 * resolved promises, so its authorization/disclosure/evidence semantics are
 * byte-identical to the frozen path (no divergent semantics). Tenant authority
 * is taken from the RequestContext, never from a caller parameter; a context
 * whose tenant does not match the resource's tenant is denied.
 *
 * This adapter is RESEARCH_ONLY. The production guard (`assertProductionStore`)
 * refuses memory mode in production.
 */
import { randomUUID } from "node:crypto";
import { ContinuumEngine } from "../engine";
import { keyFingerprint } from "../crypto";
import type { Principal } from "../types";
import type { Intent } from "../protocol";
import type {
  ContinuumStore,
  ContinuumTransaction,
  AuthorizeOutcome,
  DiscloseOutcome,
  DiscloseProof,
  RevocationResult,
  AuthorizeActionInput,
  ActionOutcome,
  AuthorizedMemoryMetadata,
  EvidenceVerificationResult,
  StoreHealth,
  SubmitIntentInput,
} from "./store";
import {
  type RequestContext,
  type ExecutionContextInput,
  type IntentId,
  type PrincipalId,
  type TokenId,
} from "./context";

function requireTenant(ctx: RequestContext): string {
  const t = ctx.tenant?.tenantId;
  if (!t) throw new Error("missing tenant context: request denied (fail-closed)");
  return t;
}

/** Transaction facade bound to one RequestContext + the frozen engine. */
class InMemoryTransaction implements ContinuumTransaction {
  private closed = false;
  constructor(
    public readonly ctx: RequestContext,
    private readonly engine: ContinuumEngine,
  ) {}

  private guard(): void {
    if (this.closed) throw new Error("transaction already closed");
  }
  close(): void {
    this.closed = true;
  }

  private assertTenant(resourceTenant: string, what: string): void {
    const t = requireTenant(this.ctx);
    if (resourceTenant !== t) {
      throw new Error(`cross-tenant ${what} denied: context tenant ${t} ≠ resource tenant ${resourceTenant}`);
    }
  }

  async submitIntent(input: SubmitIntentInput): Promise<IntentId> {
    this.guard();
    const intent = this.engine.submitIntent(input);
    this.assertTenant(intent.tenant_id, "intent submission");
    return intent.intent_id;
  }

  async getIntent(intentId: IntentId): Promise<Intent | null> {
    this.guard();
    const intent = this.engine.getIntent(intentId);
    if (intent && intent.tenant_id !== requireTenant(this.ctx)) return null; // RLS-equivalent: foreign tenant is invisible
    return intent;
  }

  async getPrincipal(principalId: PrincipalId): Promise<Principal | null> {
    this.guard();
    const p = this.engine.getPrincipal(principalId);
    if (p && p.tenant_id !== requireTenant(this.ctx)) return null;
    return p;
  }

  async authorizeIntent(input: { intentId: IntentId }): Promise<AuthorizeOutcome> {
    this.guard();
    const intent = this.engine.getIntent(input.intentId);
    if (!intent) throw new Error(`unknown intent ${input.intentId}`);
    this.assertTenant(intent.tenant_id, "authorization");
    const r = this.engine.authorize(input.intentId);
    return { decision: r.decision, disclosure: r.disclosure, capability: r.capability };
  }

  async discloseForToken(input: { tokenId: TokenId; challenge?: string; proof?: DiscloseProof }): Promise<DiscloseOutcome> {
    this.guard();
    // The research adapter self-signs proof-of-possession from the in-process agent
    // keys; the presenter `proof` (a durable-store concern) is not required here.
    const r = input.challenge !== undefined
      ? this.engine.disclose(input.tokenId, input.challenge)
      : this.engine.disclose(input.tokenId);
    return { verification: r.verification, disclosure: r.disclosure, canaryPresent: r.canary_present };
  }

  async revokeCapability(input: { revocationHandle: string }): Promise<RevocationResult> {
    this.guard();
    return this.engine.revoke(input.revocationHandle);
  }

  async authorizeAction(input: AuthorizeActionInput): Promise<ActionOutcome> {
    this.guard();
    const intent = this.engine.getIntent(input.intentId);
    if (!intent) throw new Error(`unknown intent ${input.intentId}`);
    this.assertTenant(intent.tenant_id, "action");
    // Research adapter: no durable idempotency ledger — restart-safe idempotency is
    // a PostgresStore guarantee (gate 6). Here the frozen proposeAction evaluates.
    const action = this.engine.proposeAction({
      action_id: input.actionId,
      intent_id: input.intentId,
      actor: input.actor,
      operation: input.operation,
      action_class: input.actionClass,
      expected_effect: input.expectedEffect ?? "",
      reversible: input.reversible ?? true,
      cost_gbp: input.costGbp ?? 0,
    });
    return { action, idempotentReplay: false };
  }

  async listAuthorizedMemory(): Promise<readonly AuthorizedMemoryMetadata[]> {
    this.guard();
    return this.engine.listMemoryMeta(requireTenant(this.ctx));
  }

  async verifyEvidenceChain(): Promise<EvidenceVerificationResult> {
    this.guard();
    return this.engine.evidence().verification;
  }
}

export class InMemoryAsyncStore implements ContinuumStore {
  readonly mode = "memory" as const;
  private readonly engine: ContinuumEngine;

  constructor(engine?: ContinuumEngine) {
    this.engine = engine ?? new ContinuumEngine();
  }

  async resolveExecutionContext(input: ExecutionContextInput): Promise<RequestContext> {
    const principal = this.engine.getPrincipal(input.authenticatedSubject);
    if (!principal) throw new Error(`unknown authenticated subject ${input.authenticatedSubject}`);
    const now = new Date();
    return {
      requestId: input.requestId,
      traceId: input.traceId,
      principal: {
        principalId: principal.principal_id,
        subject: input.authenticatedSubject,
        principalType: principal.kind === "agent" ? "agent" : "human",
        roles: [],
        authenticationProvider: "in_memory_research",
        credentialId: null,
      },
      workload: input.workloadIdentity ?? null,
      tenant: {
        tenantId: principal.tenant_id,
        mappingVersion: "in_memory",
        mappingDigest: "in_memory",
        derivedFrom: "authenticated_session",
        databaseContextId: `dbctx_${randomUUID()}`,
      },
      sessionId: input.sessionId,
      authenticationTime: now,
      authenticationStrength: "none",
      policySnapshot: { policyVersion: this.engine.metrics().policy_version },
      executionMode: "development",
      issuedAt: now,
      deadline: null,
      source: input.source,
    };
  }

  async transaction<T>(ctx: RequestContext, op: (tx: ContinuumTransaction) => Promise<T>): Promise<T> {
    requireTenant(ctx); // fail closed on missing tenant context
    const tx = new InMemoryTransaction(ctx, this.engine);
    try {
      return await op(tx);
    } finally {
      tx.close();
    }
  }

  async getIntent(ctx: RequestContext, intentId: IntentId): Promise<Intent | null> {
    return this.transaction(ctx, (tx) => tx.getIntent(intentId));
  }

  async listEvidence(ctx: RequestContext) {
    requireTenant(ctx);
    return this.engine.evidence().entries;
  }

  async verifyEvidenceChain(ctx: RequestContext): Promise<EvidenceVerificationResult> {
    requireTenant(ctx);
    return this.engine.evidence().verification;
  }

  async getMetrics(ctx: RequestContext) {
    requireTenant(ctx);
    return this.engine.metrics();
  }

  async health(): Promise<StoreHealth> {
    const chainOk = this.engine.evidence().verification.valid;
    return {
      status: "healthy",
      mode: this.mode,
      databaseReachable: false,
      migrationsCurrent: true,
      rlsVerified: false, // n/a for in-memory; RLS is a PostgresStore property
      appendOnlyRoleVerified: false,
      evidenceChainVerified: chainOk,
      checkedAt: new Date(),
      failures: [],
    };
  }

  async close(): Promise<void> {
    // no-op: no external resources
  }

  /** Test-only: platform fingerprint of the underlying engine. */
  platformFingerprint(): string {
    return keyFingerprint(this.engine.platformPublicKeyPem());
  }
}
