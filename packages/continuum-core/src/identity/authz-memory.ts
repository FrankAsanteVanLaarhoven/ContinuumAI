/**
 * S4B in-memory helpers. `StaticAuthorizationClientRegistry` is production-usable
 * (trusted configuration). The in-memory transaction store and event sink are
 * dev/test only — the memory transaction store is refused in production by config.
 */
import type {
  AuthorizationClientConfig,
  AuthorizationClientRegistry,
  AuthorizationEvent,
  AuthorizationEventSink,
  AuthorizationTransactionFinalStatus,
  AuthorizationTransactionStatus,
  AuthorizationTransactionStore,
  ConsumeAuthorizationTransactionInput,
  ConsumeAuthorizationTransactionResult,
  CreatedAuthorizationTransaction,
  FinalizeAuthorizationTransactionInput,
  NewAuthorizationTransaction,
} from "./authz-types";

export class StaticAuthorizationClientRegistry implements AuthorizationClientRegistry {
  private readonly byIssuer = new Map<string, AuthorizationClientConfig>();
  constructor(configs: readonly AuthorizationClientConfig[]) {
    for (const c of configs) this.byIssuer.set(c.issuer, c);
  }
  resolve(issuer: string): AuthorizationClientConfig | null {
    return this.byIssuer.get(issuer) ?? null;
  }
}

interface StoredTransaction extends NewAuthorizationTransaction {
  consumedAt: Date | null;
  consumptionRequestId: string | null;
  status: AuthorizationTransactionStatus | AuthorizationTransactionFinalStatus;
  failureReason: string | null;
  attemptCount: number;
}

/** In-memory transaction store (dev/test only). */
export class InMemoryAuthorizationTransactionStore implements AuthorizationTransactionStore {
  private readonly byStateDigest = new Map<string, StoredTransaction>();
  private readonly byId = new Map<string, StoredTransaction>();

  async create(t: NewAuthorizationTransaction): Promise<CreatedAuthorizationTransaction> {
    if (this.byStateDigest.has(t.stateDigest)) throw new Error("duplicate state digest");
    const stored: StoredTransaction = {
      ...t, consumedAt: null, consumptionRequestId: null, status: "pending", failureReason: null, attemptCount: 0,
    };
    this.byStateDigest.set(t.stateDigest, stored);
    this.byId.set(t.transactionId, stored);
    return { transactionId: t.transactionId, expiresAt: t.expiresAt };
  }

  async consume(input: ConsumeAuthorizationTransactionInput): Promise<ConsumeAuthorizationTransactionResult> {
    const t = this.byStateDigest.get(input.stateDigest);
    if (!t) return { outcome: "unknown" };
    if (t.consumedAt) return { outcome: "already_consumed" };
    if (t.expiresAt.getTime() <= input.now.getTime()) return { outcome: "expired" };
    t.consumedAt = input.now;
    t.consumptionRequestId = input.requestId;
    t.status = "consuming";
    t.attemptCount += 1;
    return {
      outcome: "consumed",
      transaction: {
        transactionId: t.transactionId, issuer: t.issuer, clientId: t.clientId, redirectUri: t.redirectUri,
        nonceDigest: t.nonceDigest, pkceVerifierSecret: t.pkceVerifierSecret,
        pkceVerifierKeyVersion: t.pkceVerifierKeyVersion, pkceChallenge: t.pkceChallenge, policyVersion: t.policyVersion,
      },
    };
  }

  async finalize(input: FinalizeAuthorizationTransactionInput): Promise<void> {
    const t = this.byId.get(input.transactionId);
    if (t && t.status === "consuming") {
      t.status = input.status;
      t.failureReason = input.failureReason;
    }
  }

  async expireBefore(now: Date): Promise<number> {
    let n = 0;
    for (const t of this.byId.values()) {
      if (t.status === "pending" && !t.consumedAt && t.expiresAt.getTime() <= now.getTime()) {
        t.status = "expired";
        n += 1;
      }
    }
    return n;
  }
}

export class InMemoryAuthorizationEventSink implements AuthorizationEventSink {
  readonly events: AuthorizationEvent[] = [];
  async append(event: AuthorizationEvent): Promise<void> {
    this.events.push(event);
  }
}
