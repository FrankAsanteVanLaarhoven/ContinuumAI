/**
 * S4A durable replay ledger — single-use consumption of assertion replay
 * identifiers (nonce / jti) where the issuer's replay policy requires it.
 *
 * The verifier computes a KEYED digest of the replay identifier and passes only
 * that digest here; the ledger never sees the raw nonce or jti. Consumption is
 * atomic and insert-first (a uniqueness constraint decides the winner), so two
 * concurrent attempts with the same identifier yield exactly one `fresh`.
 *
 * Replay state is tenant-independent at assertion-verification time and is
 * scoped by (issuer, kind). It fails CLOSED: when the store is unavailable the
 * outcome is `unavailable`, and the verifier must deny.
 */
import { hmacSha256Hex } from "../crypto";

export type ReplayKind = "nonce" | "jti";

export interface ReplayConsumeInput {
  readonly issuer: string;
  readonly kind: ReplayKind;
  /** Keyed digest of the raw identifier (never the raw value). */
  readonly digest: string;
  /** When this entry may be pruned — bounded by the assertion lifetime + retention. */
  readonly expiresAt: Date;
  readonly requestId: string;
  readonly at: Date;
}

export type ReplayConsumeOutcome = "fresh" | "replayed" | "unavailable";

export interface DurableReplayLedger {
  /** Atomically consume the identifier. `fresh` = first use; `replayed` = seen;
   *  `unavailable` = store error (caller must fail closed). */
  consume(input: ReplayConsumeInput): Promise<ReplayConsumeOutcome>;
  /** Remove entries whose expiry is at or before `now`. Returns rows removed. */
  prune(now: Date): Promise<number>;
}

/**
 * Compute the keyed replay digest. Includes issuer and kind in the keyed input
 * AND the ledger stores (issuer, kind, digest), so the same raw identifier under
 * a different issuer or kind cannot collide.
 */
export function replayDigest(replayKeyBase64: string, issuer: string, kind: ReplayKind, value: string): string {
  return hmacSha256Hex(replayKeyBase64, `${issuer}\u0000${kind}\u0000${value}`);
}

/** In-memory ledger for core tests. NOT durable — persistence uses PostgreSQL. */
export class InMemoryDurableReplayLedger implements DurableReplayLedger {
  private readonly seen = new Map<string, Date>();
  private available = true;

  /** Simulate a store outage for fail-closed tests. */
  setAvailable(available: boolean): void {
    this.available = available;
  }

  private key(input: Pick<ReplayConsumeInput, "issuer" | "kind" | "digest">): string {
    return `${input.issuer}\u0000${input.kind}\u0000${input.digest}`;
  }

  async consume(input: ReplayConsumeInput): Promise<ReplayConsumeOutcome> {
    if (!this.available) return "unavailable";
    const k = this.key(input);
    if (this.seen.has(k)) return "replayed";
    this.seen.set(k, input.expiresAt);
    return "fresh";
  }

  async prune(now: Date): Promise<number> {
    let removed = 0;
    for (const [k, exp] of this.seen) {
      if (exp.getTime() <= now.getTime()) {
        this.seen.delete(k);
        removed++;
      }
    }
    return removed;
  }
}
