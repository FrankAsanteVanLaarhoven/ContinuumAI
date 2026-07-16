/**
 * AuthenticationBoundary — composes the four S3 layers into one flow, over the
 * interfaces only (no vendor, no transport, no tenant). It converts an external
 * credential into a normalized identity, maps it to an internal principal, and
 * mints a session — recording redacted evidence at each decision. It NEVER
 * resolves a tenant: tenant authority is the S2B trusted-context path, reached
 * later from the validated session's principal + an active membership.
 */
import type {
  AuthEventSink,
  AuthEventType,
  AuthenticationInput,
  CreatedSession,
  IdentityVerificationPolicy,
  IdentityVerifier,
  PrincipalMapper,
  PrincipalMappingFailure,
  SessionManager,
  SessionValidationInput,
  SessionValidationResult,
  SessionCredential,
} from "./types";
import { identityDigests } from "./auth-events";

export interface AuthenticationBoundaryOptions {
  readonly verifier: IdentityVerifier;
  readonly policy: IdentityVerificationPolicy;
  readonly mapper: PrincipalMapper;
  readonly sessions: SessionManager;
  readonly sink: AuthEventSink;
  readonly idleTtlSeconds: number;
  readonly absoluteTtlSeconds: number;
}

export type AuthenticateResult =
  | {
      readonly authenticated: true;
      readonly session: CreatedSession;
      readonly principalId: string;
      readonly issuer: string;
      readonly subject: string;
    }
  | {
      readonly authenticated: false;
      readonly stage: "verification" | "mapping";
      readonly reason: string;
    };

const MAPPING_EVENT: Record<PrincipalMappingFailure, AuthEventType> = {
  no_mapping: "identity.unmapped",
  mapping_disabled: "identity.unmapped",
  principal_suspended: "principal.suspended_denied",
  principal_deleted: "principal.suspended_denied",
  mapping_version_stale: "identity.mapping_stale_denied",
  external_identity_revoked: "identity.unmapped",
  ambiguous_mapping: "identity.denied",
  mapping_store_unavailable: "identity.denied",
};

export class AuthenticationBoundary {
  constructor(private readonly o: AuthenticationBoundaryOptions) {}

  async authenticate(input: AuthenticationInput): Promise<AuthenticateResult> {
    const v = await this.o.verifier.verify(input, this.o.policy);
    if (!v.verified) {
      await this.o.sink.append({
        type: v.reason === "verification_keys_unavailable"
          ? "verification.keys_unavailable_denied"
          : "identity.denied",
        at: input.receivedAt, requestId: input.requestId,
        issuerDigest: v.evidence.issuerDigest, subjectDigest: v.evidence.subjectDigest,
        principalId: null, sessionId: null,
        verificationPolicyVersion: v.evidence.verificationPolicyVersion,
        identityMappingVersion: null, outcome: "denied", reason: v.reason,
      });
      return { authenticated: false, stage: "verification", reason: v.reason };
    }

    const d = identityDigests(v.identity);
    const m = await this.o.mapper.resolve(v.identity);
    if (!m.mapped) {
      await this.o.sink.append({
        type: MAPPING_EVENT[m.reason], at: input.receivedAt, requestId: input.requestId,
        issuerDigest: d.issuerDigest, subjectDigest: d.subjectDigest,
        principalId: null, sessionId: null,
        verificationPolicyVersion: this.o.policy.policyVersion, identityMappingVersion: null,
        outcome: "denied", reason: m.reason,
      });
      return { authenticated: false, stage: "mapping", reason: m.reason };
    }

    await this.o.sink.append({
      type: "identity.verified", at: input.receivedAt, requestId: input.requestId,
      issuerDigest: d.issuerDigest, subjectDigest: d.subjectDigest,
      principalId: m.principal.principalId, sessionId: null,
      verificationPolicyVersion: this.o.policy.policyVersion, identityMappingVersion: m.mappingVersion,
      outcome: "success", reason: null,
    });

    const session = await this.o.sessions.createSession(v.identity, m.principal, {
      requestId: input.requestId, receivedAt: input.receivedAt,
      authenticationStrength: v.identity.authenticationStrength,
      identityMappingVersion: m.mappingVersion, verificationPolicyVersion: this.o.policy.policyVersion,
      idleTtlSeconds: this.o.idleTtlSeconds, absoluteTtlSeconds: this.o.absoluteTtlSeconds,
    });

    return { authenticated: true, session, principalId: m.principal.principalId, issuer: v.identity.issuer, subject: v.identity.subject };
  }

  validate(credential: SessionCredential, input: SessionValidationInput): Promise<SessionValidationResult> {
    return this.o.sessions.validateSession(credential, input);
  }
}
