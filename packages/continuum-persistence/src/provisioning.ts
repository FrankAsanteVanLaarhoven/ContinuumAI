/**
 * Trusted-identity provisioning utilities (S2B).
 *
 * After migration 0004, public.* RLS keys on continuum.current_tenant(), so a
 * tenant-scoped write/read needs a trusted (principal, session, membership)
 * context. These helpers provision — as the ADMIN/superuser, the trusted path the
 * application role cannot use — a DETERMINISTIC service identity per tenant, so
 * different callers (test files, seed harnesses in other workspaces) resolve the
 * SAME identity for the same tenant/database. Deterministic ids are a
 * provisioning/dev convenience; production identities come from the authenticated
 * issuance path (a later milestone).
 */
import { createHash, randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type { EngineExport } from "@continuum/core";
import { provisionTrustedIdentity, type ProvisionedIdentity, type TrustedContextRef } from "./pg";
import type { RefResolver } from "./repository";

/** Stable uuid-shaped id from a seed (valid uuid syntax; version bits not significant). */
export function detUuid(seed: string): string {
  const h = createHash("sha256").update(seed).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/**
 * Reconstruct the trusted reference for a tenant's deterministic service identity
 * (as provisioned by {@link ensureServiceIdentity}/{@link provisionForExport}).
 * No database access — the ids are derived, so any caller can rebuild the ref that
 * matches the already-provisioned identity in the shared database.
 */
export function serviceRef(tenantId: string): TrustedContextRef & { membershipId: string } {
  return {
    principalId: detUuid(`principal:${tenantId}`),
    sessionId: detUuid(`session:${tenantId}`),
    membershipId: detUuid(`membership:${tenantId}`),
    requestId: randomUUID(),
  };
}

/** Provision (idempotently) the deterministic service identity for a tenant. */
export function ensureServiceIdentity(admin: Pool, tenantId: string): Promise<ProvisionedIdentity> {
  return provisionTrustedIdentity(admin, {
    tenantId,
    principalId: detUuid(`principal:${tenantId}`),
    sessionId: detUuid(`session:${tenantId}`),
    membershipId: detUuid(`membership:${tenantId}`),
  });
}

/** Every distinct tenant referenced anywhere in an engine export. */
export function exportTenants(exp: EngineExport): string[] {
  const t = new Set<string>();
  exp.tenants.forEach((x) => t.add(x.tenant_id));
  exp.principals.forEach((x) => t.add(x.tenant_id));
  exp.memory.forEach((x) => t.add(x.tenant_id));
  exp.consent.forEach((x) => t.add(x.tenant_id));
  exp.intents.forEach((x) => t.add(x.tenant_id));
  exp.capabilities.forEach((x) => t.add(x.token.tenant_id));
  exp.evidence.forEach((x) => t.add(x.tenant_id));
  return [...t];
}

/**
 * Provision service identities for every tenant in an export and return a
 * RefResolver bound to them — ready to pass to persistExport.
 */
export async function provisionForExport(admin: Pool, exp: EngineExport): Promise<RefResolver> {
  const map = new Map<string, ProvisionedIdentity>();
  for (const tenantId of exportTenants(exp)) {
    map.set(tenantId, await ensureServiceIdentity(admin, tenantId));
  }
  return (tenantId: string) => {
    const id = map.get(tenantId);
    if (!id) throw new Error(`no provisioned identity for tenant ${tenantId}`);
    return id.ref();
  };
}
