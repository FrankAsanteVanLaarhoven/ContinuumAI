/**
 * Runtime state DTO — the DURABLE control-plane state the console renders.
 *
 * Pure types only (erased at build). Unlike the retired synchronous slice view,
 * every field here is READ from the async ContinuumStore (PostgreSQL in
 * production), so the console is a view over durable, evidenced state — not an
 * ephemeral in-process engine run.
 */
import type {
  AuthorizedMemoryMetadata,
  StoreHealth,
  StoreMode,
} from "@continuum/core";

export interface RuntimeState {
  /** Selected store: "postgres" (durable) or "memory" (research-only). */
  mode: StoreMode;
  /** RESEARCH_ONLY | PRODUCTION_CANDIDATE. */
  classification: string;
  generated_at: string;
  /** Tenant derived by the trusted boundary — never a request parameter. */
  tenant: string;
  principal: string;
  health: StoreHealth;
  authorized_memory: AuthorizedMemoryMetadata[];
  authorized_memory_count: number;
  evidence_count: number;
  evidence_chain_valid: boolean;
  evidence_chain_detail: string;
}
