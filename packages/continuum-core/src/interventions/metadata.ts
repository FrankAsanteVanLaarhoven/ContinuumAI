/**
 * Intervention I2 — caller-bound metadata projection.
 *
 * The frozen accessor `listMemoryMeta(tenantId)` trusts a caller-supplied tenant
 * identifier (GAP-2, an IDOR). The caller-bound accessor derives tenant and
 * principal from a verified, holder-proven capability and returns only the fields
 * a projection permits. This module holds the pure projection logic and the audit
 * shape; the engine method wires it to capability verification.
 */
import { sha256Hex } from "../crypto";
import type { MemoryObject } from "../types";

export type MetadataProjection = "minimal" | "standard" | "full";

/**
 * Fields each projection is permitted to expose. `full` is the pre-I2 shape (all
 * non-content metadata, incl. the raw id) and tests IDOR closure WITHOUT
 * minimisation; `minimal`/`standard` replace the raw storage id with an opaque,
 * per-capability handle and disclose strictly less.
 */
export const PROJECTION_FIELDS: Record<Exclude<MetadataProjection, "full">, string[]> = {
  minimal: ["handle", "memory_class", "classification"],
  standard: ["handle", "memory_class", "classification", "verification_state", "created_at", "read_operation"],
};

/** The minimal field count a pure listing task needs (handle + type + label). */
export const MINIMAL_NECESSARY_FIELDS = PROJECTION_FIELDS.minimal.length;

/**
 * Opaque, non-reversible, per-capability handle. Never the raw storage id: a
 * different capability over the same object yields a different handle, so handles
 * are not a cross-capability correlation key, and the raw id never enters an
 * immutable audit record.
 */
export function opaqueHandle(capabilityId: string, memoryId: string): string {
  return "obj_" + sha256Hex(capabilityId + ":" + memoryId).slice(0, 16);
}

/** Project one object's metadata to exactly what `projection` permits. */
export function projectMeta(
  m: MemoryObject,
  projection: MetadataProjection,
  capabilityId: string,
): Record<string, unknown> {
  if (projection === "full") {
    const { content: _omit, ...rest } = m;
    return rest;
  }
  const base: Record<string, unknown> = {
    handle: opaqueHandle(capabilityId, m.memory_id),
    memory_class: m.memory_class,
    classification: m.classification,
  };
  if (projection === "standard") {
    base.verification_state = m.verification_state;
    base.created_at = m.created_at;
    base.read_operation = m.read_operation;
  }
  return base;
}

/** The audit record every caller-bound list operation must produce in full. */
export interface BoundMetaAudit {
  authenticated_principal: string | null;
  capability_id: string;
  holder_proof: "valid" | "invalid" | "absent";
  derived_tenant: string | null;
  intent_id: string | null;
  purpose: string | null;
  requested_projection: MetadataProjection;
  effective_projection: MetadataProjection | null;
  returned_object_count: number;
  returned_field_set: string[];
  policy_version: string;
  entitlement_version: string | null;
  decision: "permit" | "deny";
  denial_reason: string | null;
}

/** The 14 fields an audit record must carry for evidence completeness. */
export const REQUIRED_AUDIT_FIELDS: Array<keyof BoundMetaAudit> = [
  "authenticated_principal",
  "capability_id",
  "holder_proof",
  "derived_tenant",
  "intent_id",
  "purpose",
  "requested_projection",
  "effective_projection",
  "returned_object_count",
  "returned_field_set",
  "policy_version",
  "entitlement_version",
  "decision",
  "denial_reason",
];

export interface BoundMetaResult {
  permit: boolean;
  items: Array<Record<string, unknown>>;
  audit: BoundMetaAudit;
  evidence_event_id: string;
}

/**
 * Fraction of required audit fields that are present (defined for permits, or
 * meaningfully null with a reason for denials). `denial_reason`/`derived_tenant`
 * are allowed to be null; every other field must be non-null.
 */
export function evidenceCompleteness(a: BoundMetaAudit): number {
  const nullableWhenDeny = new Set<keyof BoundMetaAudit>([
    "denial_reason",
    "effective_projection",
    "derived_tenant",
    "intent_id",
    "purpose",
    "authenticated_principal",
    "entitlement_version",
  ]);
  let present = 0;
  for (const f of REQUIRED_AUDIT_FIELDS) {
    const v = a[f];
    if (v !== undefined && (v !== null || nullableWhenDeny.has(f))) present += 1;
  }
  return present / REQUIRED_AUDIT_FIELDS.length;
}

/** Audit facts safe to write into the immutable chain — names/counts, no values. */
export function auditScope(a: BoundMetaAudit): Record<string, unknown> {
  return {
    holder_proof: a.holder_proof,
    derived_tenant: a.derived_tenant,
    purpose: a.purpose,
    requested_projection: a.requested_projection,
    effective_projection: a.effective_projection,
    returned_object_count: a.returned_object_count,
    returned_field_set: a.returned_field_set,
    entitlement_version: a.entitlement_version,
    decision: a.decision,
    denial_reason: a.denial_reason,
  };
}
