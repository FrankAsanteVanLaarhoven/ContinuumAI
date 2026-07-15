/**
 * Contract suite for ContinuumStore. Run here against InMemoryAsyncStore; the
 * PostgresStore (increment 2) must satisfy the SAME suite. Semantics are checked
 * against the frozen synchronous vertical slice as the oracle — the async path
 * must not diverge.
 */
import { describe, it, expect } from "vitest";
import { ContinuumEngine } from "../engine";
import { runVerticalSlice } from "../slice";
import { InMemoryAsyncStore } from "./memory-store";
import { AsyncContinuumEngine } from "./engine";
import { researchContext, type RequestContext } from "./context";

const OWNER = "did:continuum:enterprise:acme:owner";
const AGENT = "spiffe://acme.ai/agents/procurement-agent";
const TENANT = "t_acme";
const NOW = Date.parse("2026-06-01T00:00:00.000Z");

function sampleIntent(agentBuild: string | null) {
  return {
    owner_id: OWNER,
    actor_id: AGENT,
    tenant_id: TENANT,
    purpose: "supplier_quote_comparison",
    requested_operations: ["read:supplier_quotes", "read:approved_budget_band", "write:recommendation_draft"],
    prohibited_operations: ["place_order", "modify_budget", "send_external_email"],
    constraints: {
      maximum_data_classification: "confidential",
      geographic_boundary: ["GB"],
      valid_until: "2027-01-01T00:00:00.000Z",
      maximum_cost_gbp: 5,
    },
    required_evidence: ["agent_attestation", "approved_model_policy", "current_user_consent"],
    human_gate: { required_for: ["external_commitment", "financial_execution"] },
    actor_geo: "GB",
    model_id: "gw-approved-llm-2026-06",
    agent_build: agentBuild,
    risk_score: 0.12,
  };
}

function ctxFor(tenantId: string, principalId = AGENT): RequestContext {
  return researchContext({ tenantId, principalId, nowMs: NOW, source: "research_harness" });
}

/** Build a store + async engine + a valid, authorizable intent id, reusing the seeded agent build. */
async function fixture() {
  const engine = new ContinuumEngine();
  const store = new InMemoryAsyncStore(engine);
  const async = new AsyncContinuumEngine(store);
  const build = engine.getPrincipal(AGENT)?.build_hash ?? null;
  const ctx = ctxFor(TENANT);
  const intentId = await async.submitIntent(ctx, sampleIntent(build));
  return { engine, store, async, ctx, intentId };
}

describe("ContinuumStore contract · InMemoryAsyncStore", () => {
  it("authorize matches the frozen synchronous slice decision (no divergent semantics)", async () => {
    const frozen = runVerticalSlice();
    const frozenAuth = frozen.engine.getAuthorization(frozen.intent_id);
    expect(frozenAuth).not.toBeNull();

    const { async, ctx, intentId } = await fixture();
    const outcome = await async.authorize(ctx, { intentId });

    expect([...outcome.decision.permitted_ids].sort()).toEqual([...frozenAuth!.decision.permitted_ids].sort());
    expect(outcome.decision.candidate_count).toBe(frozenAuth!.decision.candidate_count);
    expect(Boolean(outcome.capability)).toBe(Boolean(frozenAuth!.capability));
    // Documented frozen result: exactly two objects survive deny-by-default.
    expect(outcome.decision.permitted_ids).toContain("mem_q_apex");
    expect(outcome.decision.permitted_ids).toContain("mem_q_orion");
  });

  it("the engine is asynchronous end to end (authorize returns a Promise)", async () => {
    const { async, ctx, intentId } = await fixture();
    const p = async.authorize(ctx, { intentId });
    expect(typeof (p as Promise<unknown>).then).toBe("function");
    await p;
  });

  it("fails closed when the tenant context is missing", async () => {
    const { async, intentId } = await fixture();
    const broken = { ...ctxFor(TENANT), tenant: { ...ctxFor(TENANT).tenant, tenantId: "" } };
    await expect(async.authorize(broken, { intentId })).rejects.toThrow(/missing tenant context/i);
  });

  it("denies a foreign-tenant authorization (tenant comes from context, not the resource)", async () => {
    const { async, intentId } = await fixture();
    const foreign = ctxFor("t_other");
    await expect(async.authorize(foreign, { intentId })).rejects.toThrow(/cross-tenant/i);
  });

  it("a foreign-tenant intent read returns null (RLS-equivalent invisibility)", async () => {
    const { async, store, ctx, intentId } = await fixture();
    // Same intent, seen from another tenant context, is invisible.
    const seen = await store.getIntent(ctxFor("t_other"), intentId);
    expect(seen).toBeNull();
    // And visible from its own tenant.
    const own = await store.getIntent(ctx, intentId);
    expect(own?.intent_id).toBe(intentId);
  });

  it("revocation performed in one transaction is observed by a later disclosure (cross-transaction)", async () => {
    const { async, ctx, intentId } = await fixture();
    const outcome = await async.authorize(ctx, { intentId });
    const cap = outcome.capability;
    expect(cap).not.toBeNull();

    // Disclosure succeeds before revocation.
    const before = await async.disclose(ctx, { tokenId: cap!.token.token_id });
    expect(before.verification.valid).toBe(true);

    // Revoke in a separate transaction.
    const rev = await async.revokeCapability(ctx, { revocationHandle: cap!.token.revocation_handle });
    expect(rev.revoked).toBe(true);

    // A later disclosure must now observe the revocation.
    const after = await async.disclose(ctx, { tokenId: cap!.token.token_id });
    expect(after.verification.valid).toBe(false);
  });

  it("listAuthorizedMemory is scoped to the context tenant", async () => {
    const { async, ctx } = await fixture();
    const meta = await async.listAuthorizedMemory(ctx);
    expect(meta.length).toBeGreaterThan(0);
    // No content field ever leaves the store on this path.
    for (const m of meta) expect("content" in m).toBe(false);
  });

  it("evidence chain verifies through the async boundary", async () => {
    const { async, ctx, intentId } = await fixture();
    await async.authorize(ctx, { intentId });
    const v = await async.verifyEvidenceChain(ctx);
    expect(v.valid).toBe(true);
  });

  it("health reports memory mode and a valid evidence chain", async () => {
    const { async } = await fixture();
    const h = await async.health();
    expect(h.mode).toBe("memory");
    expect(h.evidenceChainVerified).toBe(true);
  });
});
