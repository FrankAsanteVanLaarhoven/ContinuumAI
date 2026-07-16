/**
 * Phase 3 S4B — browser-independent authorization-code protocol state machine (types).
 *
 * A persisted, single-use authorization-code transaction boundary that binds
 * state, nonce, PKCE, issuer and redirect URI, and handles callback consumption
 * BEFORE any browser-facing or provider-specific integration exists. No session
 * is minted until every step of the completion sequence succeeds; the normalized
 * identity flows through the S4A verifier and the S3 principal/session boundary,
 * so a completed login still carries no tenant authority (S2B remains the sole
 * tenant-authority transition).
 *
 *   begin login
 *     → create persisted authorization transaction (state, nonce, PKCE)
 *     → return authorization request parameters
 *   receive callback
 *     → atomically consume the transaction (single-use)
 *     → validate state / issuer / redirect URI / expiry
 *     → exchange the code through an abstract interface (fixture in S4B)
 *     → verify the returned identity token through S4A
 *     → confirm nonce matches the transaction
 *     → map the verified identity through S3
 *     → create a restart-safe, digest-only session
 *     → append evidence
 *
 * This milestone ships NO real provider, browser routes, cookies, CSRF, or refresh
 * tokens. The code exchanger is a deterministic fixture; the PKCE secret store is
 * a test-protected implementation refused in production.
 */
import type { RequestId } from "../async/context";
import type { CreatedSession, VerifiedIdentity } from "./types";

// ---------------------------------------------------------------------------
// Client registry (trusted configuration; the caller never injects these)
// ---------------------------------------------------------------------------

export interface AuthorizationClientConfig {
  readonly issuer: string;
  readonly clientId: string;
  /** The single trusted redirect URI for this client (exact-match at callback). */
  readonly redirectUri: string;
  readonly authorizationEndpoint: string;
  readonly scope?: string;
  readonly policyVersion: string;
  readonly enabled: boolean;
}

export interface AuthorizationClientRegistry {
  /** Resolve the trusted client config for a registered issuer, or null. */
  resolve(issuer: string): AuthorizationClientConfig | null;
}

// ---------------------------------------------------------------------------
// Input limits
// ---------------------------------------------------------------------------

export interface AuthzInputLimits {
  readonly maxStateLength: number;
  readonly maxCodeLength: number;
  readonly maxIssuerLength: number;
}

export const DEFAULT_AUTHZ_LIMITS: AuthzInputLimits = {
  maxStateLength: 512,
  maxCodeLength: 4096,
  maxIssuerLength: 1024,
};

// ---------------------------------------------------------------------------
// Failure taxonomy — fail closed on all uncertainty.
// ---------------------------------------------------------------------------

export type AuthorizationFailure =
  | "invalid_request"
  | "unsupported_issuer"
  | "state_missing"
  | "state_malformed"
  | "state_unknown"
  | "state_replayed"
  | "transaction_expired"
  | "transaction_already_consumed"
  | "issuer_mismatch"
  | "client_mismatch"
  | "redirect_uri_mismatch"
  | "code_missing"
  | "code_malformed"
  | "code_exchange_denied"
  | "code_exchange_unavailable"
  | "pkce_mismatch"
  | "identity_token_missing"
  | "identity_verification_denied"
  | "nonce_missing"
  | "nonce_mismatch"
  | "identity_mapping_denied"
  | "principal_inactive"
  | "session_creation_failed"
  | "evidence_write_failed"
  | "internal_protocol_error";

// ---------------------------------------------------------------------------
// Authorization transaction (persisted)
// ---------------------------------------------------------------------------

export type AuthorizationTransactionStatus = "pending" | "consuming" | "completed" | "failed" | "expired";

/** The record written at `begin`. Raw state/nonce are NEVER persisted (digests
 *  only); the PKCE verifier is stored encrypted-at-rest, never as a one-way
 *  digest, because it must be replayed to the token endpoint at exchange. */
export interface NewAuthorizationTransaction {
  readonly transactionId: string;
  readonly stateDigest: string;
  readonly nonceDigest: string;
  /** Encrypted PKCE verifier (protected-secret ciphertext) + its key version. */
  readonly pkceVerifierSecret: string;
  readonly pkceVerifierKeyVersion: string;
  readonly pkceChallenge: string;
  readonly pkceMethod: "S256";
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly policyVersion: string;
}

export interface CreatedAuthorizationTransaction {
  readonly transactionId: string;
  readonly expiresAt: Date;
}

export interface ConsumeAuthorizationTransactionInput {
  readonly stateDigest: string;
  readonly requestId: RequestId;
  readonly now: Date;
}

/** The bindings + protected verifier returned by a successful atomic consume. */
export interface ConsumedAuthorizationTransaction {
  readonly transactionId: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly nonceDigest: string;
  readonly pkceVerifierSecret: string;
  readonly pkceVerifierKeyVersion: string;
  readonly pkceChallenge: string;
  readonly policyVersion: string;
}

export type ConsumeAuthorizationTransactionResult =
  | { readonly outcome: "consumed"; readonly transaction: ConsumedAuthorizationTransaction }
  | { readonly outcome: "unknown" | "already_consumed" | "expired" | "store_unavailable" };

/** Terminal statuses. A failure is categorized by the stage that failed; all
 *  terminal states keep the transaction consumed (single-use is preserved). */
export type AuthorizationTransactionFinalStatus =
  | "completed"
  | "exchange_failed"
  | "verification_failed"
  | "nonce_failed"
  | "mapping_failed"
  | "session_failed"
  | "failed";

export interface FinalizeAuthorizationTransactionInput {
  readonly transactionId: string;
  readonly status: AuthorizationTransactionFinalStatus;
  readonly failureReason: string | null;
  readonly requestId: RequestId;
}

export interface AuthorizationTransactionStore {
  create(transaction: NewAuthorizationTransaction): Promise<CreatedAuthorizationTransaction>;
  consume(input: ConsumeAuthorizationTransactionInput): Promise<ConsumeAuthorizationTransactionResult>;
  /** Mark the terminal status of an already-consumed transaction (audit only). */
  finalize(input: FinalizeAuthorizationTransactionInput): Promise<void>;
  /** Mark still-pending transactions with expiry at/prior to `now` as expired. Returns count. */
  expireBefore(now: Date): Promise<number>;
}

// ---------------------------------------------------------------------------
// Code exchange abstraction (fixture/local test only in S4B; never a provider)
// ---------------------------------------------------------------------------

export interface AuthorizationCodeExchangeInput {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly code: string;
  readonly pkceVerifier: string;
  readonly requestId: RequestId;
}

export type AuthorizationCodeExchangeFailure =
  | "invalid_code"
  | "expired_code"
  | "code_already_used"
  | "pkce_mismatch"
  | "redirect_uri_mismatch"
  | "client_mismatch"
  | "issuer_mismatch"
  | "token_endpoint_unavailable"
  | "timeout"
  | "malformed_response"
  | "missing_identity_token"
  | "unexpected_token_type"
  | "internal_exchange_error";

export type AuthorizationCodeExchangeResult =
  | { readonly ok: true; readonly identityToken: string; readonly tokenType: "id_token" }
  | { readonly ok: false; readonly reason: AuthorizationCodeExchangeFailure };

export interface AuthorizationCodeExchanger {
  exchange(input: AuthorizationCodeExchangeInput): Promise<AuthorizationCodeExchangeResult>;
}

// ---------------------------------------------------------------------------
// Flow contract
// ---------------------------------------------------------------------------

export interface BeginAuthorizationInput {
  /** Registered issuer to authenticate against. Client id + redirect come from
   *  trusted configuration — the caller cannot inject them. */
  readonly issuer: string;
  readonly requestId: RequestId;
  readonly receivedAt: Date;
  /** Optional non-authoritative correlation for a pre-auth context (evidence only). */
  readonly priorContextId?: string;
}

/** The parameters a caller would place in an authorization request/redirect. The
 *  raw `state` and `nonce` are returned here (they must travel to the provider)
 *  but are persisted only as keyed digests. */
export interface AuthorizationRequestParameters {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly authorizationEndpoint: string;
  readonly responseType: "code";
  readonly scope: string | null;
  readonly state: string;
  readonly nonce: string;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
  readonly expiresAt: Date;
}

export type BeginAuthorizationResult =
  | { readonly ok: true; readonly transactionId: string; readonly request: AuthorizationRequestParameters }
  | { readonly ok: false; readonly reason: AuthorizationFailure };

export interface CompleteAuthorizationInput {
  /** Raw callback `state` and authorization `code`. Issuer/redirect are NOT taken
   *  from the callback — they come from the persisted, consumed transaction. */
  readonly state: string;
  readonly code: string;
  readonly requestId: RequestId;
  readonly receivedAt: Date;
}

export type CompleteAuthorizationResult =
  | {
      readonly ok: true;
      readonly session: CreatedSession;
      readonly principalId: string;
      readonly issuer: string;
      readonly subject: string;
    }
  | { readonly ok: false; readonly reason: AuthorizationFailure };

export interface AuthorizationCodeFlow {
  begin(input: BeginAuthorizationInput): Promise<BeginAuthorizationResult>;
  complete(input: CompleteAuthorizationInput): Promise<CompleteAuthorizationResult>;
}

// ---------------------------------------------------------------------------
// Evidence (redacted — digests + safe ids only)
// ---------------------------------------------------------------------------

export type AuthorizationEventType =
  | "authz.transaction_created"
  | "authz.callback_denied"
  | "authz.state_unknown"
  | "authz.state_replayed"
  | "authz.transaction_expired"
  | "authz.issuer_mismatch"
  | "authz.redirect_mismatch"
  | "authz.code_exchange_denied"
  | "authz.identity_verification_denied"
  | "authz.nonce_mismatch"
  | "authz.principal_mapping_denied"
  | "authz.session_created"
  | "authz.transaction_completed";

export interface AuthorizationEvent {
  readonly type: AuthorizationEventType;
  readonly at: Date;
  readonly requestId: RequestId;
  readonly transactionDigest: string | null;
  readonly issuerDigest: string | null;
  readonly subjectDigest: string | null;
  readonly principalId: string | null;
  readonly sessionId: string | null;
  readonly policyVersion: string | null;
  readonly outcome: "success" | "denied";
  readonly reason: string | null;
}

export interface AuthorizationEventSink {
  append(event: AuthorizationEvent): Promise<void>;
}

/** Re-exported for flow consumers building sessions from a verified identity. */
export type { VerifiedIdentity };
