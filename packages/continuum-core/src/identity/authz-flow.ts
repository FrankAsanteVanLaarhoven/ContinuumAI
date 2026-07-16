/**
 * S4B authorization-code flow state machine. `begin` persists a single-use
 * transaction (state/nonce as keyed digests, PKCE verifier encrypted-at-rest,
 * issuer/client/redirect bound) and returns the authorization request parameters.
 * `complete` atomically consumes the transaction, validates it, exchanges the
 * code through an abstract (fixture) exchanger, verifies the returned identity
 * token through S4A, confirms the nonce binding, maps the identity through S3,
 * and only THEN mints a restart-safe, digest-only session — recording redacted
 * evidence throughout. No session is minted before every step succeeds, and a
 * successful login always mints a NEW session (fixation-resistant); no
 * pre-authentication credential from the caller is ever upgraded.
 *
 * A completed login carries no tenant authority; tenant authority remains the S2B
 * trusted-context path.
 */
import { randomUUID } from "node:crypto";
import type { PrincipalMapper, SessionManager } from "./types";
import type { JwtIdentityVerifierContract } from "./jwt-types";
import { issuerDigest, subjectDigest } from "./verification";
import {
  assertBoundedTransactionTtl,
  assertS256,
} from "./authz-config";
import {
  digestEquals,
  generateNonceValue,
  generatePkceVerifier,
  generateStateValue,
  nonceDigest,
  pkceChallengeS256,
  stateDigest,
  transactionDigest,
  type ProtectedSecretStore,
} from "./authz-secrets";
import type {
  AuthorizationClientRegistry,
  AuthorizationCodeExchanger,
  AuthorizationCodeFlow,
  AuthorizationEvent,
  AuthorizationEventSink,
  AuthorizationEventType,
  AuthorizationFailure,
  AuthorizationTransactionFinalStatus,
  AuthorizationTransactionStore,
  AuthzInputLimits,
  BeginAuthorizationInput,
  BeginAuthorizationResult,
  CompleteAuthorizationInput,
  CompleteAuthorizationResult,
  ConsumedAuthorizationTransaction,
} from "./authz-types";
import { DEFAULT_AUTHZ_LIMITS } from "./authz-types";

export interface AuthorizationCodeFlowOptions {
  readonly store: AuthorizationTransactionStore;
  readonly exchanger: AuthorizationCodeExchanger;
  readonly verifier: JwtIdentityVerifierContract; // S4A
  readonly mapper: PrincipalMapper; // S3
  readonly sessions: SessionManager; // S3
  readonly sink: AuthorizationEventSink;
  readonly secrets: ProtectedSecretStore; // PKCE verifier protection
  readonly clients: AuthorizationClientRegistry;
  /** Base64 key for state/nonce/transaction keyed digests. */
  readonly digestKey: string;
  readonly transactionTtlSeconds: number;
  readonly sessionIdleTtlSeconds: number;
  readonly sessionAbsoluteTtlSeconds: number;
  readonly limits?: AuthzInputLimits;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;
// Authorization codes are provider-defined; allow URL-safe + a few RFC3986 sub-delims,
// but no whitespace/control characters.
const CODE_CHARS = /^[A-Za-z0-9._~=+/-]+$/;

export class DefaultAuthorizationCodeFlow implements AuthorizationCodeFlow {
  private readonly o: AuthorizationCodeFlowOptions;
  private readonly limits: AuthzInputLimits;

  constructor(opts: AuthorizationCodeFlowOptions) {
    assertBoundedTransactionTtl(opts.transactionTtlSeconds);
    this.o = opts;
    this.limits = opts.limits ?? DEFAULT_AUTHZ_LIMITS;
  }

  // -------------------------------------------------------------------------
  // begin
  // -------------------------------------------------------------------------

  async begin(input: BeginAuthorizationInput): Promise<BeginAuthorizationResult> {
    if (typeof input.issuer !== "string" || input.issuer.length === 0 || input.issuer.length > this.limits.maxIssuerLength) {
      return { ok: false, reason: "unsupported_issuer" };
    }
    const cfg = this.o.clients.resolve(input.issuer);
    if (!cfg || !cfg.enabled) return { ok: false, reason: "unsupported_issuer" };

    const state = generateStateValue();
    const nonce = generateNonceValue();
    const verifier = generatePkceVerifier();
    const challenge = pkceChallengeS256(verifier);
    assertS256("S256");

    const transactionId = randomUUID();
    const protectedVerifier = this.o.secrets.protect(verifier);
    const createdAt = input.receivedAt;
    const expiresAt = new Date(createdAt.getTime() + this.o.transactionTtlSeconds * 1000);

    await this.o.store.create({
      transactionId,
      stateDigest: stateDigest(this.o.digestKey, state),
      nonceDigest: nonceDigest(this.o.digestKey, nonce),
      pkceVerifierSecret: protectedVerifier.ciphertext,
      pkceVerifierKeyVersion: protectedVerifier.keyVersion,
      pkceChallenge: challenge,
      pkceMethod: "S256",
      issuer: cfg.issuer,
      clientId: cfg.clientId,
      redirectUri: cfg.redirectUri,
      createdAt,
      expiresAt,
      policyVersion: cfg.policyVersion,
    });

    await this.event("authz.transaction_created", input.requestId, input.receivedAt, "success", null, {
      transactionId, issuer: cfg.issuer, policyVersion: cfg.policyVersion,
    });

    return {
      ok: true,
      transactionId,
      request: {
        issuer: cfg.issuer,
        clientId: cfg.clientId,
        redirectUri: cfg.redirectUri,
        authorizationEndpoint: cfg.authorizationEndpoint,
        responseType: "code",
        scope: cfg.scope ?? null,
        state,
        nonce,
        codeChallenge: challenge,
        codeChallengeMethod: "S256",
        expiresAt,
      },
    };
  }

  // -------------------------------------------------------------------------
  // complete
  // -------------------------------------------------------------------------

  async complete(input: CompleteAuthorizationInput): Promise<CompleteAuthorizationResult> {
    const { requestId, receivedAt } = input;

    // 1) Callback input structure.
    if (typeof input.state !== "string" || input.state.length === 0) return this.denyPre("state_missing", requestId, receivedAt);
    if (input.state.length > this.limits.maxStateLength || !BASE64URL.test(input.state)) {
      return this.denyPre("state_malformed", requestId, receivedAt);
    }
    if (typeof input.code !== "string" || input.code.length === 0) return this.denyPre("code_missing", requestId, receivedAt);
    if (input.code.length > this.limits.maxCodeLength || !CODE_CHARS.test(input.code)) {
      return this.denyPre("code_malformed", requestId, receivedAt);
    }

    // 2) Atomic one-time consumption by state digest.
    const digest = stateDigest(this.o.digestKey, input.state);
    const consumed = await this.o.store.consume({ stateDigest: digest, requestId, now: receivedAt });
    if (consumed.outcome !== "consumed") {
      switch (consumed.outcome) {
        case "unknown": return this.denyPre("state_unknown", requestId, receivedAt, "authz.state_unknown");
        case "already_consumed": return this.denyPre("transaction_already_consumed", requestId, receivedAt, "authz.state_replayed");
        case "expired": return this.denyPre("transaction_expired", requestId, receivedAt, "authz.transaction_expired");
        default: return this.denyPre("internal_protocol_error", requestId, receivedAt);
      }
    }
    const txn = consumed.transaction;

    // 3) Recover the PKCE verifier (encrypted-at-rest) and sanity-check the binding.
    const verifier = this.o.secrets.reveal(txn.pkceVerifierSecret, txn.pkceVerifierKeyVersion);
    if (verifier === null) return this.denyPost(txn, "internal_protocol_error", requestId, receivedAt);
    if (pkceChallengeS256(verifier) !== txn.pkceChallenge) return this.denyPost(txn, "pkce_mismatch", requestId, receivedAt);

    // 4) Exchange the authorization code (abstract; fixture in S4B).
    const ex = await this.o.exchanger.exchange({
      issuer: txn.issuer, clientId: txn.clientId, redirectUri: txn.redirectUri, code: input.code, pkceVerifier: verifier, requestId,
    });
    if (!ex.ok) {
      const mapped = EXCHANGE_TO_AUTHZ[ex.reason];
      const evt: AuthorizationEventType =
        mapped === "issuer_mismatch" ? "authz.issuer_mismatch"
        : mapped === "redirect_uri_mismatch" ? "authz.redirect_mismatch"
        : "authz.code_exchange_denied";
      return this.denyPost(txn, mapped, requestId, receivedAt, evt);
    }
    if (ex.tokenType !== "id_token") return this.denyPost(txn, "identity_token_missing", requestId, receivedAt);

    // 5) Verify the returned identity token through S4A.
    const v = await this.o.verifier.verifyAssertion({ assertion: ex.identityToken, requestId, receivedAt });
    if (!v.verified) return this.denyPost(txn, "identity_verification_denied", requestId, receivedAt, "authz.identity_verification_denied");
    const identity = v.identity;

    // 6) Issuer binding: the token issuer must match the transaction issuer.
    if (identity.issuer !== txn.issuer) return this.denyPost(txn, "issuer_mismatch", requestId, receivedAt, "authz.issuer_mismatch", identity.issuer, identity.subject, "verification_failed");

    // 7) Nonce binding (digest comparison — the raw nonce is never stored).
    if (!identity.nonce) return this.denyPost(txn, "nonce_missing", requestId, receivedAt, "authz.nonce_mismatch", identity.issuer, identity.subject);
    if (!digestEquals(nonceDigest(this.o.digestKey, identity.nonce), txn.nonceDigest)) {
      return this.denyPost(txn, "nonce_mismatch", requestId, receivedAt, "authz.nonce_mismatch", identity.issuer, identity.subject);
    }

    // 8) Map the verified identity to an active internal principal (S3).
    const m = await this.o.mapper.resolve(identity);
    if (!m.mapped) {
      const reason: AuthorizationFailure =
        m.reason === "principal_suspended" || m.reason === "principal_deleted" ? "principal_inactive" : "identity_mapping_denied";
      return this.denyPost(txn, reason, requestId, receivedAt, "authz.principal_mapping_denied", identity.issuer, identity.subject);
    }

    // 9) Create a NEW restart-safe, digest-only session (fixation-resistant).
    let session;
    try {
      session = await this.o.sessions.createSession(identity, m.principal, {
        requestId, receivedAt,
        authenticationStrength: identity.authenticationStrength,
        identityMappingVersion: m.mappingVersion,
        verificationPolicyVersion: identity.verificationPolicyVersion,
        idleTtlSeconds: this.o.sessionIdleTtlSeconds,
        absoluteTtlSeconds: this.o.sessionAbsoluteTtlSeconds,
      });
    } catch {
      return this.denyPost(txn, "session_creation_failed", requestId, receivedAt);
    }

    // 10) Finalize + success evidence.
    try {
      await this.o.store.finalize({ transactionId: txn.transactionId, status: "completed", failureReason: null, requestId });
      await this.event("authz.session_created", requestId, receivedAt, "success", null, {
        transactionId: txn.transactionId, issuer: identity.issuer, subject: identity.subject,
        principalId: m.principal.principalId, sessionId: session.sessionId, policyVersion: txn.policyVersion,
      });
      await this.event("authz.transaction_completed", requestId, receivedAt, "success", null, {
        transactionId: txn.transactionId, issuer: identity.issuer, policyVersion: txn.policyVersion,
      });
    } catch {
      return { ok: false, reason: "evidence_write_failed" };
    }

    return { ok: true, session, principalId: m.principal.principalId, issuer: identity.issuer, subject: identity.subject };
  }

  // -------------------------------------------------------------------------
  // evidence helpers
  // -------------------------------------------------------------------------

  private async denyPre(
    reason: AuthorizationFailure,
    requestId: string,
    at: Date,
    eventType: AuthorizationEventType = "authz.callback_denied",
  ): Promise<CompleteAuthorizationResult> {
    await this.event(eventType, requestId, at, "denied", reason, {}).catch(() => undefined);
    return { ok: false, reason };
  }

  private async denyPost(
    txn: ConsumedAuthorizationTransaction,
    reason: AuthorizationFailure,
    requestId: string,
    at: Date,
    eventType: AuthorizationEventType = "authz.callback_denied",
    iss?: string,
    sub?: string,
    terminalStatus?: AuthorizationTransactionFinalStatus,
  ): Promise<CompleteAuthorizationResult> {
    // The transaction stays consumed; the terminal status records WHICH stage failed.
    const status = terminalStatus ?? terminalStatusForReason(reason);
    await this.o.store.finalize({ transactionId: txn.transactionId, status, failureReason: reason, requestId }).catch(() => undefined);
    await this.event(eventType, requestId, at, "denied", reason, {
      transactionId: txn.transactionId, issuer: iss ?? txn.issuer, subject: sub, policyVersion: txn.policyVersion,
    }).catch(() => undefined);
    return { ok: false, reason };
  }

  private event(
    type: AuthorizationEventType,
    requestId: string,
    at: Date,
    outcome: "success" | "denied",
    reason: string | null,
    ctx: {
      transactionId?: string | undefined; issuer?: string | undefined; subject?: string | undefined;
      principalId?: string | undefined; sessionId?: string | undefined; policyVersion?: string | undefined;
    },
  ): Promise<void> {
    const event: AuthorizationEvent = {
      type, at, requestId,
      transactionDigest: ctx.transactionId ? transactionDigest(this.o.digestKey, ctx.transactionId) : null,
      issuerDigest: ctx.issuer ? issuerDigest(ctx.issuer) : null,
      subjectDigest: ctx.issuer && ctx.subject ? subjectDigest(ctx.issuer, ctx.subject) : null,
      principalId: ctx.principalId ?? null,
      sessionId: ctx.sessionId ?? null,
      policyVersion: ctx.policyVersion ?? null,
      outcome,
      reason,
    };
    return this.o.sink.append(event);
  }
}

/** Categorize a post-consume failure by the stage that failed (all stay consumed). */
function terminalStatusForReason(reason: AuthorizationFailure): AuthorizationTransactionFinalStatus {
  switch (reason) {
    case "code_exchange_denied":
    case "code_exchange_unavailable":
    case "issuer_mismatch":
    case "client_mismatch":
    case "redirect_uri_mismatch":
    case "pkce_mismatch":
    case "identity_token_missing":
      return "exchange_failed";
    case "identity_verification_denied":
      return "verification_failed";
    case "nonce_missing":
    case "nonce_mismatch":
      return "nonce_failed";
    case "identity_mapping_denied":
    case "principal_inactive":
      return "mapping_failed";
    case "session_creation_failed":
      return "session_failed";
    default:
      return "failed";
  }
}

const EXCHANGE_TO_AUTHZ: Record<import("./authz-types").AuthorizationCodeExchangeFailure, AuthorizationFailure> = {
  invalid_code: "code_exchange_denied",
  expired_code: "code_exchange_denied",
  code_already_used: "code_exchange_denied",
  pkce_mismatch: "pkce_mismatch",
  redirect_uri_mismatch: "redirect_uri_mismatch",
  client_mismatch: "client_mismatch",
  issuer_mismatch: "issuer_mismatch",
  token_endpoint_unavailable: "code_exchange_unavailable",
  timeout: "code_exchange_unavailable",
  malformed_response: "code_exchange_denied",
  missing_identity_token: "identity_token_missing",
  unexpected_token_type: "identity_token_missing",
  internal_exchange_error: "code_exchange_denied",
};
