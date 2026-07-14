/**
 * Continuum domain model.
 *
 * The central abstraction is the Sovereign Continuum tuple
 *   C_t = (I, G_t, M_t, P_t, A_t, R_t, E_t)
 * — identities, goals/intent, memory, policies, delegated authority,
 * relationships, and events/provenance. The types below make each component
 * explicit and machine-checkable. Nothing here is free-form prompt text.
 */

// ---------------------------------------------------------------------------
// Classification lattice
// ---------------------------------------------------------------------------

export const CLASSIFICATION_ORDER = [
  "public",
  "internal",
  "confidential",
  "restricted",
] as const;
export type Classification = (typeof CLASSIFICATION_ORDER)[number];

/** Rank in the classification lattice; higher means more sensitive. */
export function classRank(c: Classification): number {
  return CLASSIFICATION_ORDER.indexOf(c);
}

// ---------------------------------------------------------------------------
// Principals and tenancy (component I)
// ---------------------------------------------------------------------------

export type PrincipalKind =
  | "human"
  | "organization"
  | "workload"
  | "agent"
  | "device"
  | "robot"
  | "service";

export interface Principal {
  principal_id: string; // did:continuum:... or spiffe://...
  kind: PrincipalKind;
  tenant_id: string;
  trust_domain: string;
  display_name: string;
  /** Whether identity/runtime attestation currently holds. */
  attested: boolean;
  /** For agents: reproducible build measurement. */
  build_hash: string | null;
  /** For agents/devices: holder public key used for proof-of-possession. */
  public_key_pem: string | null;
}

export interface Tenant {
  tenant_id: string;
  display_name: string;
  trust_domain: string;
  residency: string; // ISO country code where the tenant's data lives
}

// ---------------------------------------------------------------------------
// Memory (component M_t)
// ---------------------------------------------------------------------------

export type MemoryClass =
  | "episodic"
  | "semantic"
  | "procedural"
  | "preference"
  | "intent"
  | "relational"
  | "evidence"
  | "prohibition"
  | "temporary"
  | "derived";

export type VerificationState = "candidate" | "verified" | "authoritative";
export type RevocationState = "active" | "revoked";
export type DeletionState = "present" | "deleted";

/**
 * A memory object with its mandatory provenance schema. Every field that the
 * blueprint requires for auditability is present; model-generated memory MUST
 * begin as `candidate` and can only be promoted through evidence/owner action.
 */
export interface MemoryObject {
  memory_id: string;
  owner_id: string;
  tenant_id: string;
  memory_class: MemoryClass;
  content: Record<string, unknown>;
  content_hash: string;
  source_type: string;
  source_reference: string;
  creator_principal: string;
  created_at: string; // ISO 8601
  valid_until: string | null; // ISO 8601, null = no expiry
  confidence: number; // 0..1
  classification: Classification;
  /** Purposes for which this object may be disclosed. */
  purpose_constraints: string[];
  /** The operation a caller must hold to read this object, e.g. "read:supplier_quotes". */
  read_operation: string;
  /** Data residency of this specific object (ISO country code). */
  residency: string;
  consent_basis: string | null;
  retention_policy: string;
  /** Dot-paths within `content` that must be redacted on disclosure. */
  sensitive_fields: string[];
  model_identity: string | null;
  verification_state: VerificationState;
  revocation_state: RevocationState;
  deletion_state: DeletionState;
  supersedes: string | null;
}

// ---------------------------------------------------------------------------
// Consent and approved registries (components P_t / A_t)
// ---------------------------------------------------------------------------

export interface ConsentRecord {
  owner_id: string;
  tenant_id: string;
  purpose: string;
  granted: boolean;
  basis: string;
  valid_until: string; // ISO 8601
}

/** What the platform currently trusts, by explicit allowlist. Deny by default. */
export interface ApprovedRegistry {
  agent_builds: Set<string>; // approved reproducible build hashes
  models: Set<string>; // approved model identifiers
  environments: Set<string>; // approved execution environments
  regions: Set<string>; // permitted processing regions
}

/** Policy configuration knobs (the P_t constants). */
export interface PolicyConfig {
  policy_version: string;
  risk_threshold: number; // requests above this are denied
  capability_ttl_seconds: number;
}

/**
 * Authoritative per-principal entitlement ceiling (intervention I1). An intent is
 * a *request*; authority is the intersection of the request with what the
 * principal is actually entitled to, delegated, and consented for. This is the
 * source of authority the intent is NOT.
 */
export interface Entitlement {
  principal_id: string;
  tenant_id: string;
  /** The operations this principal may ever request (the ceiling). */
  allowed_operations: string[];
  /** Owner delegation: operations the owner has delegated to this principal. */
  delegated_operations: string[];
}

export interface EntitlementPolicy {
  version: string;
  entitlements: Entitlement[];
}
