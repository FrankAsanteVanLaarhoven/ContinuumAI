/**
 * ContinuumStore — the asynchronous production store boundary.
 *
 * One interface, two adapters:
 *   - InMemoryAsyncStore (this increment): deterministic test/research adapter,
 *     immediately-resolved promises, reuses the FROZEN decision primitives so its
 *     semantics are identical to the synchronous engine.
 *   - PostgresStore (increment 2): the same contract over the existing
 *     PostgreSQL/RLS/append-only persistence package.
 *
 * Grain note (held for review): increment 1 exposes the security operations at
 * the COMPOSITE grain the frozen engine already supports (`authorizeIntent`,
 * `discloseForToken`, `revokeCapability`) so the frozen decision path is reused
 * verbatim — zero divergent authorization semantics. The reviewer's finer
 * decomposition (getEffectiveAuthority / createCapability / consumeProof / … as
 * separate transaction steps) is the TARGET grain for the PostgresStore, where a
 * real SQL transaction makes step-wise composition meaningful and RLS-enforced.
 * The invariant that holds now: every security-relevant read, check, write and
 * evidence append runs inside one shared `transaction`, and tenant authority
 * comes only from the RequestContext.
 */
import type { Principal, MemoryObject } from "../types";
import type { Intent } from "../protocol";
import type { AuthorizationDecision } from "../policy";
import type { DisclosurePackage } from "../broker";
import type { SignedSCT, VerifyResult } from "../capability";
import type { EvidenceEnvelope, ChainVerification } from "../evidence";
import type { MetricsSnapshot } from "../engine";
import type {
  RequestContext,
  ExecutionContextInput,
  IntentId,
  PrincipalId,
  TokenId,
} from "./context";

export type StoreMode = "memory" | "postgres";

/** Raw intent submission payload (validated by the store, as the sync engine does). */
export type SubmitIntentInput = unknown;

/** Metadata-only memory listing (content never leaves the store on this path). */
export type AuthorizedMemoryMetadata = Omit<MemoryObject, "content">;

export interface AuthorizeOutcome {
  readonly decision: AuthorizationDecision;
  readonly disclosure: DisclosurePackage;
  readonly capability: SignedSCT | null;
}

export interface DiscloseOutcome {
  readonly verification: VerifyResult;
  readonly disclosure: DisclosurePackage | null;
  readonly canaryPresent: boolean;
}

export interface RevocationResult {
  readonly revoked: boolean;
  readonly handle: string;
}

export type EvidenceVerificationResult = ChainVerification;

export interface StoreHealth {
  readonly status: "healthy" | "degraded" | "unhealthy";
  readonly mode: StoreMode;
  readonly databaseReachable: boolean;
  readonly migrationsCurrent: boolean;
  readonly rlsVerified: boolean;
  readonly appendOnlyRoleVerified: boolean;
  readonly evidenceChainVerified: boolean;
  readonly checkedAt: Date;
  readonly failures: readonly string[];
}

/**
 * The transaction facade. Every security-sensitive flow runs inside exactly one
 * of these. The underlying database client (for PostgresStore) is never exposed,
 * and the object must not be used after the transaction closes.
 */
export interface ContinuumTransaction {
  readonly ctx: RequestContext;

  submitIntent(input: SubmitIntentInput): Promise<IntentId>;
  getIntent(intentId: IntentId): Promise<Intent | null>;
  getPrincipal(principalId: PrincipalId): Promise<Principal | null>;

  /** Deny-by-default decision + minimum-necessary disclosure + capability issue, atomic. */
  authorizeIntent(input: { intentId: IntentId }): Promise<AuthorizeOutcome>;

  /** Point-of-use disclosure with proof-of-possession + freshness re-check, atomic. */
  discloseForToken(input: { tokenId: TokenId; challenge?: string }): Promise<DiscloseOutcome>;

  revokeCapability(input: { revocationHandle: string }): Promise<RevocationResult>;

  listAuthorizedMemory(): Promise<readonly AuthorizedMemoryMetadata[]>;
  verifyEvidenceChain(): Promise<EvidenceVerificationResult>;
}

export interface ContinuumStore {
  readonly mode: StoreMode;

  /**
   * Trusted resolver: authenticated subject → principal → tenant → db-bound
   * context. The ONLY sanctioned way to obtain a RequestContext at runtime.
   */
  resolveExecutionContext(input: ExecutionContextInput): Promise<RequestContext>;

  /** Run a security-sensitive flow inside one shared transaction. */
  transaction<T>(ctx: RequestContext, op: (tx: ContinuumTransaction) => Promise<T>): Promise<T>;

  // Convenience single-op reads (each still runs in a bounded transaction internally).
  getIntent(ctx: RequestContext, intentId: IntentId): Promise<Intent | null>;
  listEvidence(ctx: RequestContext): Promise<readonly EvidenceEnvelope[]>;
  verifyEvidenceChain(ctx: RequestContext): Promise<EvidenceVerificationResult>;
  getMetrics(ctx: RequestContext): Promise<MetricsSnapshot>;

  // Operational.
  health(): Promise<StoreHealth>;
  close(): Promise<void>;
}
