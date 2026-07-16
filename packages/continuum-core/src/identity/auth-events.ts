/**
 * Auth-event sink — the identity/session lifecycle evidence stream.
 *
 * These events are pre-tenant / cross-tenant (identity verification and session
 * lifecycle happen BEFORE tenant resolution), so they are a separate stream from
 * the tenant-scoped, hash-chained evidence ledger. Every event is redacted:
 * digests and stable non-secret ids only — never raw credentials, tokens,
 * signatures, full claim sets, session secrets, or private keys.
 */
import type { AuthEvent, AuthEventSink, VerifiedIdentity } from "./types";
import { issuerDigest, subjectDigest } from "./verification";

/** In-memory sink for core tests. Records events; assertable and inspectable. */
export class InMemoryAuthEventSink implements AuthEventSink {
  readonly events: AuthEvent[] = [];
  async append(event: AuthEvent): Promise<void> {
    this.events.push(event);
  }
}

/** Redacted issuer/subject digests for an identity (or raw iss/sub pair). */
export function identityDigests(id: { issuer: string; subject: string }): {
  issuerDigest: string;
  subjectDigest: string;
} {
  return { issuerDigest: issuerDigest(id.issuer), subjectDigest: subjectDigest(id.issuer, id.subject) };
}

export function verifiedIdentityDigests(identity: VerifiedIdentity): {
  issuerDigest: string;
  subjectDigest: string;
} {
  return identityDigests(identity);
}
