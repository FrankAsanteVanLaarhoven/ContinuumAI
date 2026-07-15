/**
 * RequestContext — the trusted execution context for the asynchronous engine.
 *
 * Tenant authority is NEVER accepted from an untrusted browser/API parameter. A
 * RequestContext is produced only by the trusted authentication/session boundary
 * via `ContinuumStore.resolveExecutionContext`, which maps an authenticated
 * subject → principal → tenant → database-bound context. Application code cannot
 * construct one directly (there is no exported constructor for the derived
 * tenant); the only test/research path is `researchContext()`, which stamps a
 * `research_fixture` provenance that the production guard rejects.
 *
 * Increment 1 (Phase 2, Steps A–B). Branded-id nominal typing is deferred; ids
 * are string aliases here and are documented as a later hardening.
 */

export type RequestId = string;
export type TraceId = string;
export type SessionId = string;
export type PrincipalId = string;
export type WorkloadId = string;
export type TenantId = string;
export type IntentId = string;
export type CapabilityId = string;
export type TokenId = string;
export type MemoryId = string;
export type EvidenceId = string;

export type PrincipalType = "human" | "agent" | "service" | "device";
export type AuthenticationStrength = "none" | "single_factor" | "multi_factor" | "attested_workload";
export type ExecutionMode = "production" | "staging" | "development" | "research_only";
export type RequestSource = "console_ssr" | "console_api" | "service_api" | "research_harness";

export interface AuthenticatedPrincipal {
  readonly principalId: PrincipalId;
  readonly subject: string;
  readonly principalType: PrincipalType;
  readonly roles: readonly string[];
  readonly authenticationProvider: string;
  readonly credentialId: string | null;
}

export interface AuthenticatedWorkload {
  readonly workloadId: WorkloadId;
  readonly spiffeId: string | null;
  readonly buildDigest: string | null;
  readonly attestationDigest: string | null;
}

/**
 * How the tenant was derived. `research_fixture` is a NON-PRODUCTION provenance
 * used only by deterministic tests; the production guard MUST refuse it.
 */
export type TenantDerivation =
  | "authenticated_session"
  | "workload_identity"
  | "trusted_delegation"
  | "research_fixture";

export interface DerivedTenantContext {
  readonly tenantId: TenantId;
  readonly mappingVersion: string;
  readonly mappingDigest: string;
  readonly derivedFrom: TenantDerivation;
  /** DB transaction-context identifier. Generated internally; never caller-selectable. */
  readonly databaseContextId: string;
}

export interface PolicySnapshotReference {
  readonly policyVersion: string;
}

export interface RequestContext {
  readonly requestId: RequestId;
  readonly traceId: TraceId;

  readonly principal: AuthenticatedPrincipal;
  readonly workload: AuthenticatedWorkload | null;

  /** Derived by the trusted boundary; never copied from request body/query/header. */
  readonly tenant: DerivedTenantContext;

  readonly sessionId: SessionId;
  readonly authenticationTime: Date;
  readonly authenticationStrength: AuthenticationStrength;

  readonly policySnapshot: PolicySnapshotReference;
  readonly executionMode: ExecutionMode;

  readonly issuedAt: Date;
  readonly deadline: Date | null;

  readonly source: RequestSource;
}

/** Input accepted ONLY by the trusted authentication boundary. */
export interface ExecutionContextInput {
  readonly authenticatedSubject: string;
  readonly sessionId: SessionId;
  readonly workloadIdentity?: AuthenticatedWorkload;
  readonly requestId: RequestId;
  readonly traceId: TraceId;
  readonly source: RequestSource;
}

/** Marker returned by `resolveStoreMode` diagnostics when running in memory mode. */
export const RESEARCH_ONLY = "RESEARCH_ONLY" as const;

/**
 * Deterministic-test / research RequestContext. It is stamped with the
 * `research_fixture` provenance and `research_only` execution mode so that
 * `assertProductionContext` refuses it in production. Never call this from a
 * production runtime path.
 */
export function researchContext(overrides: {
  tenantId: TenantId;
  principalId: PrincipalId;
  subject?: string;
  principalType?: PrincipalType;
  roles?: readonly string[];
  requestId?: RequestId;
  traceId?: TraceId;
  sessionId?: SessionId;
  policyVersion?: string;
  nowMs: number;
  source?: RequestSource;
}): RequestContext {
  const at = new Date(overrides.nowMs);
  return {
    requestId: overrides.requestId ?? `req_research_${overrides.nowMs}`,
    traceId: overrides.traceId ?? `trc_research_${overrides.nowMs}`,
    principal: {
      principalId: overrides.principalId,
      subject: overrides.subject ?? overrides.principalId,
      principalType: overrides.principalType ?? "agent",
      roles: overrides.roles ?? ["research"],
      authenticationProvider: "research_fixture",
      credentialId: null,
    },
    workload: null,
    tenant: {
      tenantId: overrides.tenantId,
      mappingVersion: "research",
      mappingDigest: "research",
      derivedFrom: "research_fixture",
      databaseContextId: `dbctx_research_${overrides.nowMs}`,
    },
    sessionId: overrides.sessionId ?? "sess_research",
    authenticationTime: at,
    authenticationStrength: "none",
    policySnapshot: { policyVersion: overrides.policyVersion ?? "unknown" },
    executionMode: "research_only",
    issuedAt: at,
    deadline: null,
    source: overrides.source ?? "research_harness",
  };
}

/**
 * Production invariant: a research-fixture context or research_only execution
 * mode must never reach a production runtime. Fail closed.
 */
export function assertProductionContext(ctx: RequestContext): void {
  if (ctx.executionMode === "research_only" || ctx.tenant.derivedFrom === "research_fixture") {
    throw new Error(
      "production runtime refused a research/fixture RequestContext (tenant authority must be derived by the authentication boundary)",
    );
  }
}
