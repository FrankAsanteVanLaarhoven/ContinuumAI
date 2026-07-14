/**
 * Evidence, provenance, and audit — CIP-007 (Plane E).
 *
 * An append-only, hash-chained, signed ledger. Each envelope commits to the
 * previous envelope's hash, so any retroactive edit breaks the chain and is
 * detectable by `verifyChain`. The ledger stores identifiers and digests only
 * — never plaintext secrets or raw sensitive payloads.
 */
import { randomUUID } from "node:crypto";
import { canonicalJson, sha256Hex, signEd25519, verifyEd25519 } from "./crypto";

const GENESIS = "GENESIS";

export interface EvidenceModel {
  provider: string;
  model_id: string;
  version: string;
}

export interface EvidenceEnvelope {
  cip: "CIP-007";
  event_id: string;
  trace_id: string;
  seq: number;
  tenant_id: string;
  owner_id: string;
  principal: string;
  intent_id: string | null;
  policy_version: string;
  event_type: string;
  decision: string | null;
  disclosed_objects: string[];
  disclosure_digest: string | null;
  capability_id: string | null;
  tool_calls: unknown[];
  human_approval: { approver: string; at: string } | null;
  result_digest: string | null;
  model: EvidenceModel | null;
  timestamp: string;
  prev_hash: string;
  scope?: Record<string, unknown>;
  hash: string;
  signature: string;
}

export interface EvidenceInput {
  tenant_id: string;
  owner_id: string;
  principal: string;
  event_type: string;
  nowMs: number;
  trace_id?: string;
  intent_id?: string | null;
  decision?: string | null;
  disclosed_objects?: string[];
  disclosure_digest?: string | null;
  capability_id?: string | null;
  tool_calls?: unknown[];
  human_approval?: { approver: string; at: string } | null;
  result_digest?: string | null;
  model?: EvidenceModel | null;
  /** Intervention I1 — effective-scope provenance. Included in the hash only when
   *  present, so evidence chains issued without I1 are byte-identical. */
  scope?: Record<string, unknown>;
}

export interface ChainVerification {
  valid: boolean;
  length: number;
  broken_at: number | null;
  detail: string;
}

export class EvidenceLedger {
  private entries: EvidenceEnvelope[] = [];

  constructor(
    private readonly platformPrivateKeyPem: string,
    private readonly platformPublicKeyPem: string,
    private readonly policyVersion: string,
  ) {}

  append(input: EvidenceInput): EvidenceEnvelope {
    const seq = this.entries.length;
    const prev = this.entries[seq - 1];
    const prevHash = prev ? prev.hash : GENESIS;

    const body = {
      cip: "CIP-007" as const,
      event_id: `evt_${randomUUID()}`,
      trace_id: input.trace_id ?? `trc_${randomUUID()}`,
      seq,
      tenant_id: input.tenant_id,
      owner_id: input.owner_id,
      principal: input.principal,
      intent_id: input.intent_id ?? null,
      policy_version: this.policyVersion,
      event_type: input.event_type,
      decision: input.decision ?? null,
      disclosed_objects: input.disclosed_objects ?? [],
      disclosure_digest: input.disclosure_digest ?? null,
      capability_id: input.capability_id ?? null,
      tool_calls: input.tool_calls ?? [],
      human_approval: input.human_approval ?? null,
      result_digest: input.result_digest ?? null,
      model: input.model ?? null,
      timestamp: new Date(input.nowMs).toISOString(),
      prev_hash: prevHash,
      ...(input.scope !== undefined ? { scope: input.scope } : {}),
    };

    const hash = sha256Hex(prevHash + canonicalJson(body));
    const signature = signEd25519(this.platformPrivateKeyPem, hash);
    const envelope: EvidenceEnvelope = { ...body, hash, signature };
    this.entries.push(envelope);
    return envelope;
  }

  all(): EvidenceEnvelope[] {
    return this.entries.map((e) => ({ ...e }));
  }

  size(): number {
    return this.entries.length;
  }

  /** Recompute the whole chain: links, hashes, and signatures. */
  verifyChain(): ChainVerification {
    return verifyEnvelopeChain(this.entries, this.platformPublicKeyPem);
  }
}

/**
 * Verify an evidence chain independently of any ledger instance. Used to
 * re-verify a chain reconstructed from durable storage after a restart or
 * restore — the whole point of tamper-evident persistence.
 */
export function verifyEnvelopeChain(
  entries: EvidenceEnvelope[],
  publicKeyPem: string,
): ChainVerification {
  let expectedPrev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const env = entries[i]!;
    const { hash, signature, ...body } = env;
    if (body.prev_hash !== expectedPrev) {
      return {
        valid: false,
        length: entries.length,
        broken_at: i,
        detail: `broken link at seq ${i}: prev_hash mismatch`,
      };
    }
    const recomputed = sha256Hex(expectedPrev + canonicalJson(body));
    if (recomputed !== hash) {
      return {
        valid: false,
        length: entries.length,
        broken_at: i,
        detail: `tampered content at seq ${i}: hash mismatch`,
      };
    }
    if (!verifyEd25519(publicKeyPem, hash, signature)) {
      return {
        valid: false,
        length: entries.length,
        broken_at: i,
        detail: `invalid signature at seq ${i}`,
      };
    }
    expectedPrev = hash;
  }
  return {
    valid: true,
    length: entries.length,
    broken_at: null,
    detail: `chain intact across ${entries.length} envelopes`,
  };
}
