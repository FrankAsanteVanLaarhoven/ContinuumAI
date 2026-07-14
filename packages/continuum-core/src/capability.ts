/**
 * Sovereign Capability Token — CIP-004 (Plane B).
 *
 * A short-lived, holder-bound, non-transferable grant. It is NOT a bearer
 * token: to use it, the holder must prove possession of the private key bound
 * into `holder_key_pem` by signing a fresh challenge. The token enumerates the
 * exact resources, operations, purpose, and disclosure ceiling it authorizes —
 * never a broad `memory:read`.
 */
import { randomUUID } from "node:crypto";
import { canonicalJson, signEd25519, verifyEd25519 } from "./crypto";
import type { Classification } from "./types";

export interface SovereignCapabilityToken {
  cip: "CIP-004";
  token_id: string;
  issuer: string;
  subject: string; // owner on whose behalf authority is granted
  actor: string; // the agent exercising it
  holder_key_pem: string; // proof-of-possession key
  tenant_id: string;
  intent_id: string;
  purpose: string;
  audience: string; // model/tool boundary this token is valid against
  operations: string[];
  resources: string[]; // exact permitted memory ids
  maximum_disclosure: number;
  data_classification: Classification;
  model_id: string | null;
  agent_build: string | null;
  environment: string;
  risk_threshold: number;
  approval_state: "not_required" | "pending" | "approved";
  issued_at: string;
  expires_at: string;
  nonce: string;
  revocation_handle: string;
  evidence_correlation_id: string;
}

export interface SignedSCT {
  token: SovereignCapabilityToken;
  signature: string; // platform Ed25519 signature over canonicalJson(token)
}

export interface IssueParams {
  issuer: string;
  subject: string;
  actor: string;
  holderKeyPem: string;
  tenantId: string;
  intentId: string;
  purpose: string;
  audience: string;
  operations: string[];
  resources: string[];
  maximumDisclosure: number;
  dataClassification: Classification;
  modelId: string | null;
  agentBuild: string | null;
  environment: string;
  riskThreshold: number;
  approvalState: SovereignCapabilityToken["approval_state"];
  evidenceCorrelationId: string;
  nowMs: number;
  ttlSeconds: number;
}

/** Issue and sign a capability token. */
export function issueSCT(
  params: IssueParams,
  platformPrivateKeyPem: string,
): SignedSCT {
  const token: SovereignCapabilityToken = {
    cip: "CIP-004",
    token_id: `sct_${randomUUID()}`,
    issuer: params.issuer,
    subject: params.subject,
    actor: params.actor,
    holder_key_pem: params.holderKeyPem,
    tenant_id: params.tenantId,
    intent_id: params.intentId,
    purpose: params.purpose,
    audience: params.audience,
    operations: params.operations,
    resources: params.resources,
    maximum_disclosure: params.maximumDisclosure,
    data_classification: params.dataClassification,
    model_id: params.modelId,
    agent_build: params.agentBuild,
    environment: params.environment,
    risk_threshold: params.riskThreshold,
    approval_state: params.approvalState,
    issued_at: new Date(params.nowMs).toISOString(),
    expires_at: new Date(params.nowMs + params.ttlSeconds * 1000).toISOString(),
    nonce: randomUUID(),
    revocation_handle: `rev_${randomUUID()}`,
    evidence_correlation_id: params.evidenceCorrelationId,
  };
  const signature = signEd25519(platformPrivateKeyPem, canonicalJson(token));
  return { token, signature };
}

/** The exact message a holder must sign to demonstrate possession. */
export function popMessage(
  token: SovereignCapabilityToken,
  challenge: string,
): string {
  return `${token.token_id}:${token.nonce}:${challenge}`;
}

export interface CapabilityCheck {
  name: string;
  satisfied: boolean;
  detail: string;
}

export interface VerifyOptions {
  platformPublicKeyPem: string;
  nowMs: number;
  revokedHandles: Set<string>;
  audience: string | null;
  pop: { challenge: string; signature: string } | null;
}

export interface VerifyResult {
  valid: boolean;
  checks: CapabilityCheck[];
  denied_reason: string | null;
}

/**
 * Verify a capability at point of use. Signature, expiry, revocation, audience,
 * and — critically — proof-of-possession are all mandatory. A stolen or
 * replayed token without the holder key fails `holder_pop`.
 */
export function verifySCT(
  signed: SignedSCT,
  opts: VerifyOptions,
): VerifyResult {
  const { token } = signed;
  const checks: CapabilityCheck[] = [];

  const sigOk = verifyEd25519(
    opts.platformPublicKeyPem,
    canonicalJson(token),
    signed.signature,
  );
  checks.push({
    name: "signature_valid",
    satisfied: sigOk,
    detail: sigOk ? "issuer signature verified" : "issuer signature invalid",
  });

  const notExpired = opts.nowMs < Date.parse(token.expires_at);
  checks.push({
    name: "not_expired",
    satisfied: notExpired,
    detail: notExpired
      ? `valid until ${token.expires_at}`
      : `expired at ${token.expires_at}`,
  });

  const notRevoked = !opts.revokedHandles.has(token.revocation_handle);
  checks.push({
    name: "not_revoked",
    satisfied: notRevoked,
    detail: notRevoked ? "capability live" : "capability revoked",
  });

  const audienceOk = opts.audience === null || opts.audience === token.audience;
  checks.push({
    name: "audience_match",
    satisfied: audienceOk,
    detail: audienceOk
      ? `audience ${token.audience}`
      : `audience mismatch (token ${token.audience}, presented ${opts.audience})`,
  });

  const popOk =
    opts.pop !== null &&
    verifyEd25519(
      token.holder_key_pem,
      popMessage(token, opts.pop.challenge),
      opts.pop.signature,
    );
  checks.push({
    name: "holder_pop",
    satisfied: popOk,
    detail: popOk
      ? "holder proved possession of bound key"
      : opts.pop === null
        ? "no proof-of-possession presented"
        : "proof-of-possession invalid (token not held by presenter)",
  });

  const valid = checks.every((c) => c.satisfied);
  const failed = checks.find((c) => !c.satisfied);
  return {
    valid,
    checks,
    denied_reason: failed ? `${failed.name}: ${failed.detail}` : null,
  };
}
