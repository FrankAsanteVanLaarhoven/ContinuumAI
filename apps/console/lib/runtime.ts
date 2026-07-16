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

/** Operator identity for the console's read view. In a real deployment this is
 *  derived from the authenticated session; here it is a fixed operator subject. */
const CONSOLE_SUBJECT =
  process.env.CONTINUUM_CONSOLE_SUBJECT ?? "spiffe://acme.ai/agents/procurement-agent";
const CONSOLE_TENANT = process.env.CONTINUUM_CONSOLE_TENANT ?? "t_acme";

export interface Runtime {
  readonly engine: AsyncContinuumEngine;
  readonly store: ContinuumStore;
  readonly mode: StoreMode;
}

export interface RuntimeOptions {
  env?: NodeJS.ProcessEnv;
  /** Postgres connection (defaults to CONTINUUM_DB). */
  dbConfig?: DbConfig;
  /** Trusted subject → {principalId, tenantId} map for the Postgres boundary. */
  trustedSubjects?: Record<string, { principalId: string; tenantId: string }>;
}

/**
 * Construct the runtime for the selected store. Throws (fail-closed) if the
 * environment does not permit the requested mode; never falls back silently.
 */
export function createRuntime(opts: RuntimeOptions = {}): Runtime {
  const env = opts.env ?? process.env;
  const mode = resolveStoreMode(env);

  let store: ContinuumStore;
  if (mode === "postgres") {
    const trustedSubjects =
      opts.trustedSubjects ?? {
        [CONSOLE_SUBJECT]: { principalId: CONSOLE_SUBJECT, tenantId: CONSOLE_TENANT },
      };
    store = new PostgresStore(opts.dbConfig ?? dbConfigFromEnv(), { trustedSubjects });
  } else {
    store = new InMemoryAsyncStore();
  }

  // Defense in depth: refuse memory mode in production even if reached.
  assertProductionStore(env, mode);
  return { engine: new AsyncContinuumEngine(store), store, mode };
}

/** Resolve the console operator's RequestContext through the trusted boundary. */
export function resolveConsoleContext(rt: Runtime, subject = CONSOLE_SUBJECT): Promise<RequestContext> {
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
