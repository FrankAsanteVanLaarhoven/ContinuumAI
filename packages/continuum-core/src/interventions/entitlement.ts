/**
 * Intervention I1 — entitlement-bound effective scope.
 *
 * The intent is a *request*, never a source of authority. Effective authority is
 *
 *   S_effective = S_requested ∩ S_principal ∩ S_delegated ∩ S_purpose
 *                 ∩ S_consent ∩ S_resource
 *
 * The purpose/consent/resource intersections are already enforced per-object by
 * the PDP; I1 adds the missing **principal entitlement ceiling** so a self-declared
 * scope (GAP-1) cannot exceed what the principal is entitled to and the owner has
 * delegated. Enforcement is opt-in by mode so the frozen baselines are unchanged
 * when it is off.
 */
import { digestOf } from "../crypto";
import type { EntitlementPolicy } from "../types";

export type EntitlementMode = "off" | "enforce" | "enforce_versioned";

export interface EffectiveScope {
  requested_scope: string[];
  principal_scope: string[];
  delegated_scope: string[];
  effective_scope: string[];
  denied_scope_elements: string[];
}

/** Intersect a self-declared request with the principal's entitlement ceiling. */
export function computeEffectiveScope(
  policy: EntitlementPolicy,
  principalId: string,
  requested: string[],
): EffectiveScope {
  const ent = policy.entitlements.find((e) => e.principal_id === principalId);
  const allowed = new Set(ent?.allowed_operations ?? []);
  const delegated = new Set(ent?.delegated_operations ?? []);
  const permits = (op: string) => allowed.has(op) && delegated.has(op);
  return {
    requested_scope: [...requested],
    principal_scope: [...allowed],
    delegated_scope: [...delegated],
    effective_scope: requested.filter(permits),
    denied_scope_elements: requested.filter((op) => !permits(op)),
  };
}

export function entitlementDigest(policy: EntitlementPolicy): string {
  return digestOf(policy);
}
