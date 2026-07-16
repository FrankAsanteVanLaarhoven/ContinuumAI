/**
 * AsyncContinuumEngine — the production engine boundary. Promise-returning end
 * to end; no synchronous blocking facade. Every security-sensitive flow is run
 * inside one `store.transaction`, and tenant authority comes only from the
 * RequestContext.
 *
 * This module MUST NOT import the synchronous `ContinuumEngine` (enforced by
 * async/import-boundary.test.ts). It depends only on the ContinuumStore contract,
 * so the same orchestration runs over InMemoryAsyncStore and (increment 2)
 * PostgresStore without divergent semantics.
 *
 * Model calls and consequential actions use a two-stage flow (no DB transaction
 * held across a remote model/tool call); the orchestration for those lands with
 * the PostgresStore in increment 2.
 */
import type {
  ContinuumStore,
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
import type { RequestContext, IntentId, TokenId } from "./context";
import type { MetricsSnapshot } from "../engine";

export class AsyncContinuumEngine {
  constructor(private readonly store: ContinuumStore) {}

  get mode() {
    return this.store.mode;
  }

  submitIntent(ctx: RequestContext, input: SubmitIntentInput): Promise<IntentId> {
    return this.store.transaction(ctx, (tx) => tx.submitIntent(input));
  }

  authorize(ctx: RequestContext, input: { intentId: IntentId }): Promise<AuthorizeOutcome> {
    return this.store.transaction(ctx, (tx) => tx.authorizeIntent(input));
  }

  disclose(ctx: RequestContext, input: { tokenId: TokenId; challenge?: string; proof?: DiscloseProof }): Promise<DiscloseOutcome> {
    return this.store.transaction(ctx, (tx) => tx.discloseForToken(input));
  }

  revokeCapability(ctx: RequestContext, input: { revocationHandle: string }): Promise<RevocationResult> {
    return this.store.transaction(ctx, (tx) => tx.revokeCapability(input));
  }

  authorizeAction(ctx: RequestContext, input: AuthorizeActionInput): Promise<ActionOutcome> {
    return this.store.transaction(ctx, (tx) => tx.authorizeAction(input));
  }

  listAuthorizedMemory(ctx: RequestContext): Promise<readonly AuthorizedMemoryMetadata[]> {
    return this.store.transaction(ctx, (tx) => tx.listAuthorizedMemory());
  }

  verifyEvidenceChain(ctx: RequestContext): Promise<EvidenceVerificationResult> {
    return this.store.verifyEvidenceChain(ctx);
  }

  metrics(ctx: RequestContext): Promise<MetricsSnapshot> {
    return this.store.getMetrics(ctx);
  }

  health(): Promise<StoreHealth> {
    return this.store.health();
  }
}
