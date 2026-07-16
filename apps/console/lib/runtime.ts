/**
 * Console production runtime — the REAL async control-plane path.
 *
 * Store selection is fail-closed (see @continuum/core `resolveStoreMode`):
 *   CONTINUUM_STORE=postgres  → durable PostgreSQL/RLS data plane (dev/staging/prod)
 *   CONTINUUM_STORE=memory    → research-only in-memory adapter (non-production)
 * In production an unset/invalid value or `memory` is a hard startup error, and
 * there is NO silent postgres→memory fallback anywhere.
 *
 * IMPORT BOUNDARY (gate 7): this module — the production console path — depends
 * ONLY on the asynchronous engine + a ContinuumStore adapter. It must never
 * import or construct the synchronous research engine (`ContinuumEngine`) or run
 * `runVerticalSlice`. Enforced by runtime.import-boundary.test.ts.
 */
import {
  AsyncContinuumEngine,
  InMemoryAsyncStore,
  resolveStoreMode,
  assertProductionStore,
  storeClassification,
  type ContinuumStore,
  type RequestContext,
  type StoreMode,
} from "@continuum/core";
import { PostgresStore, dbConfigFromEnv, type DbConfig } from "@continuum/persistence";
import type { RuntimeState } from "./runtime-dto";

/** A subject's provisioned trusted identity — NO tenant; the DB derives it (S2B). */
export interface TrustedSubjectIdentity {
  readonly principalId: string;
  readonly sessionId: string;
  readonly membershipId?: string;
}

const CONSOLE_SUBJECT_DEFAULT = "spiffe://acme.ai/agents/procurement-agent";

/**
 * The console operator's provisioned identity, from the deployment environment.
 * The tenant is NEVER configured here — it is DERIVED by the trusted database
 * function from this identity's active membership (S2B). Absent identity ⇒ an
 * empty trusted map ⇒ resolveExecutionContext fails closed (no forged operator).
 * Provisioning the operator identity (principal/session/membership) is an admin
 * bootstrap step; authenticated session issuance is a later, separate milestone.
 */
function consoleTrustedSubjects(env: NodeJS.ProcessEnv): Record<string, TrustedSubjectIdentity> {
  const subject = env.CONTINUUM_CONSOLE_SUBJECT ?? CONSOLE_SUBJECT_DEFAULT;
  const principalId = env.CONTINUUM_CONSOLE_PRINCIPAL_ID;
  const sessionId = env.CONTINUUM_CONSOLE_SESSION_ID;
  const membershipId = env.CONTINUUM_CONSOLE_MEMBERSHIP_ID;
  if (!principalId || !sessionId) return {}; // fail-closed: no provisioned operator
  return { [subject]: { principalId, sessionId, membershipId } };
}

export interface Runtime {
  readonly engine: AsyncContinuumEngine;
  readonly store: ContinuumStore;
  readonly mode: StoreMode;
  /** The console operator subject this runtime resolves context for. */
  readonly subject: string;
}

export interface RuntimeOptions {
  env?: NodeJS.ProcessEnv;
  /** Postgres connection (defaults to CONTINUUM_DB). */
  dbConfig?: DbConfig;
  /** Trusted subject → provisioned identity map for the Postgres boundary (NO tenant). */
  trustedSubjects?: Record<string, TrustedSubjectIdentity>;
}

/**
 * Construct the runtime for the selected store. Throws (fail-closed) if the
 * environment does not permit the requested mode; never falls back silently.
 */
export function createRuntime(opts: RuntimeOptions = {}): Runtime {
  const env = opts.env ?? process.env;
  const mode = resolveStoreMode(env);
  const subject = env.CONTINUUM_CONSOLE_SUBJECT ?? CONSOLE_SUBJECT_DEFAULT;

  let store: ContinuumStore;
  if (mode === "postgres") {
    const trustedSubjects = opts.trustedSubjects ?? consoleTrustedSubjects(env);
    store = new PostgresStore(opts.dbConfig ?? dbConfigFromEnv(), { trustedSubjects });
  } else {
    store = new InMemoryAsyncStore();
  }

  // Defense in depth: refuse memory mode in production even if reached.
  assertProductionStore(env, mode);
  return { engine: new AsyncContinuumEngine(store), store, mode, subject };
}

/**
 * Resolve the console operator's RequestContext through the trusted boundary. The
 * tenant is DERIVED by the database from the operator's provisioned identity; the
 * console never selects it. Fails closed if the operator identity is not provisioned.
 */
export function resolveConsoleContext(rt: Runtime, subject = rt.subject): Promise<RequestContext> {
  const stamp = Date.now();
  return rt.store.resolveExecutionContext({
    authenticatedSubject: subject,
    sessionId: "console-operator",
    requestId: `req_console_${stamp}`,
    traceId: `trc_console_${stamp}`,
    source: "console_api",
  });
}

/** Read the durable control-plane state for the resolved context. */
export async function getRuntimeState(rt: Runtime, ctx: RequestContext): Promise<RuntimeState> {
  const health = await rt.store.health();
  const memory = await rt.engine.listAuthorizedMemory(ctx);
  const evidence = await rt.store.listEvidence(ctx);
  const chain = await rt.engine.verifyEvidenceChain(ctx);

  return {
    mode: rt.mode,
    classification: storeClassification(rt.mode),
    generated_at: new Date().toISOString(),
    tenant: ctx.tenant.tenantId,
    principal: ctx.principal.principalId,
    health,
    authorized_memory: [...memory],
    authorized_memory_count: memory.length,
    evidence_count: evidence.length,
    evidence_chain_valid: chain.valid,
    evidence_chain_detail: chain.detail,
  };
}
