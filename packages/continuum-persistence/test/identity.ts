/**
 * Test-only context builders on top of the shared S2B provisioning utilities
 * (src/provisioning.ts). Re-exports the reusable provisioning helpers so tests can
 * import everything from one place, and adds RequestContext/transaction
 * conveniences used only by the persistence test suite.
 */
import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { RequestContext, RequestSource } from "@continuum/core";
import { withTrustedContext } from "../src/pg";
import { detUuid, serviceRef } from "../src/provisioning";

export {
  detUuid,
  serviceRef,
  ensureServiceIdentity,
  exportTenants,
  provisionForExport,
} from "../src/provisioning";

/** Run `fn` under the tenant's provisioned service identity (trusted context). */
export function withServiceCtx<T>(
  pool: Pool,
  tenantId: string,
  fn: (c: PoolClient) => Promise<T>,
): Promise<T> {
  return withTrustedContext(pool, serviceRef(tenantId), (c) => fn(c));
}

/**
 * A production-shaped RequestContext carrying the tenant's deterministic service
 * identity — for driving PostgresStore directly in tests (the tenant is still
 * DERIVED and re-validated by the DB at each transaction; this only supplies the
 * principal/session/membership references). `nowMs` fixes the clock for
 * deterministic evidence timestamps.
 */
export function serviceContext(
  tenantId: string,
  opts?: { nowMs?: number; source?: RequestSource; subject?: string },
): RequestContext {
  const at = new Date(opts?.nowMs ?? 0);
  return {
    requestId: `req_${randomUUID()}`,
    traceId: `trc_${randomUUID()}`,
    principal: {
      principalId: detUuid(`principal:${tenantId}`),
      subject: opts?.subject ?? `svc:${tenantId}`,
      principalType: "service",
      roles: [],
      authenticationProvider: "provisioned_service_identity",
      credentialId: null,
    },
    workload: null,
    tenant: {
      tenantId,
      mappingVersion: "s2b-test",
      mappingDigest: "s2b-test",
      derivedFrom: "trusted_delegation",
      databaseContextId: `dbctx_${randomUUID()}`,
      membershipId: detUuid(`membership:${tenantId}`),
    },
    sessionId: detUuid(`session:${tenantId}`),
    authenticationTime: at,
    authenticationStrength: "single_factor",
    policySnapshot: { policyVersion: "postgres" },
    executionMode: "staging",
    issuedAt: at,
    deadline: null,
    source: opts?.source ?? "service_api",
  };
}
