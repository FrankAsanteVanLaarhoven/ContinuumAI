/**
 * Gate 6 (proof replay · action idempotency) + gate 1 (durable metrics) over real
 * embedded PostgreSQL. A dedicated database is seeded from an engine that has only
 * submitted its intent; the write paths then run over Postgres, and a brand-new
 * PostgresStore (fresh pool) simulates a restart to prove the durable guarantees.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ContinuumEngine,
  researchContext,
  signEd25519,
  type Ed25519Keypair,
  type RequestContext,
} from "@continuum/core";
import { adminPool, appPool, withTenant, type DbConfig } from "./pg";
import { migrate } from "./migrate";
import { persistExport } from "./repository";
import { PostgresStore, type WriteAuthority } from "./postgres-store";

const OWNER = "did:continuum:enterprise:acme:owner";
const AGENT = "spiffe://acme.ai/agents/procurement-agent";
const NOW = Date.parse("2026-07-15T00:00:00.000Z");
const WP: DbConfig = { host: "127.0.0.1", port: 55444, database: "continuum_g6" };

function ctx(): RequestContext {
  return researchContext({ tenantId: "t_acme", principalId: AGENT, nowMs: NOW, source: "service_api" });
}

function rawIntent(engine: ContinuumEngine) {
  return {
    owner_id: OWNER,
    actor_id: AGENT,
    tenant_id: "t_acme",
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
    agent_build: engine.getPrincipal(AGENT)?.build_hash ?? null,
    risk_score: 0.12,
  };
}

let store: PostgresStore;
let engine: ContinuumEngine;
let agentKeys: Ed25519Keypair;
let authority: WriteAuthority;
let intentId: string;

beforeAll(async () => {
  const admin = adminPool({ ...WP, database: "continuum" });
  try {
    await admin.query("DROP DATABASE IF EXISTS continuum_g6");
    await admin.query("CREATE DATABASE continuum_g6");
  } finally {
    await admin.end();
  }
  await migrate(WP);

  engine = new ContinuumEngine();
  intentId = engine.submitIntent(rawIntent(engine), NOW).intent_id;
  agentKeys = engine.store.agentKeys.get(AGENT)!;
  const seed = appPool(WP);
  try {
    await persistExport(seed, engine.exportState());
  } finally {
    await seed.end();
  }

  authority = {
    platformKeys: engine.store.platform,
    registry: engine.store.registry,
    config: engine.store.config,
    canaries: engine.store.gateway.canaries,
  };
  store = new PostgresStore(WP, { writeAuthority: authority });
});

afterAll(async () => {
  await store.close();
});

describe("gate 6: proof replay + action idempotency over Postgres", () => {
  it("discloseForToken enforces durable proof-replay prevention across a restart", async () => {
    const out = await store.transaction(ctx(), (tx) => tx.authorizeIntent({ intentId }));
    expect(out.capability).not.toBeNull();
    const token = out.capability!.token;
    const proof = (challenge: string) => ({
      presenterPrincipalId: AGENT,
      signature: signEd25519(agentKeys.privateKeyPem, `${token.token_id}:${token.nonce}:${challenge}`),
    });

    const d1 = await store.transaction(ctx(), (tx) =>
      tx.discloseForToken({ tokenId: token.token_id, challenge: "C1", proof: proof("C1") }),
    );
    expect(d1.verification.valid).toBe(true);
    expect(d1.disclosure?.disclosed).toHaveLength(2);
    expect(d1.canaryPresent).toBe(false); // the bank_iban canary is redacted

    // Same challenge again → replay, denied.
    const d2 = await store.transaction(ctx(), (tx) =>
      tx.discloseForToken({ tokenId: token.token_id, challenge: "C1", proof: proof("C1") }),
    );
    expect(d2.verification.valid).toBe(false);
    expect(d2.verification.denied_reason).toMatch(/replay/i);

    // Restart: a fresh store/pool still denies the replay (durable), but a fresh
    // challenge still works.
    const restarted = new PostgresStore(WP, { writeAuthority: authority });
    try {
      const d3 = await restarted.transaction(ctx(), (tx) =>
        tx.discloseForToken({ tokenId: token.token_id, challenge: "C1", proof: proof("C1") }),
      );
      expect(d3.verification.valid).toBe(false);
      expect(d3.verification.denied_reason).toMatch(/replay/i);

      const d4 = await restarted.transaction(ctx(), (tx) =>
        tx.discloseForToken({ tokenId: token.token_id, challenge: "C2", proof: proof("C2") }),
      );
      expect(d4.verification.valid).toBe(true);
    } finally {
      await restarted.close();
    }

    // No proof presented → denied (holder_pop fails).
    const d5 = await store.transaction(ctx(), (tx) =>
      tx.discloseForToken({ tokenId: token.token_id, challenge: "C9" }),
    );
    expect(d5.verification.valid).toBe(false);
  });

  it("authorizeAction is idempotent on actionId and durable across a restart", async () => {
    const input = {
      actionId: "act_fixed_1",
      intentId,
      actor: AGENT,
      operation: "publish:recommendation",
      actionClass: "external_commitment",
      expectedEffect: "publish supplier recommendation",
    };
    const a1 = await store.transaction(ctx(), (tx) => tx.authorizeAction(input));
    expect(a1.idempotentReplay).toBe(false);
    expect(a1.action.action_id).toBe("act_fixed_1");
    expect(a1.action.requires_human_approval).toBe(true); // external_commitment gate

    const a2 = await store.transaction(ctx(), (tx) => tx.authorizeAction(input));
    expect(a2.idempotentReplay).toBe(true);
    expect(a2.action.state).toBe(a1.action.state);

    const restarted = new PostgresStore(WP, { writeAuthority: authority });
    try {
      const a3 = await restarted.transaction(ctx(), (tx) => tx.authorizeAction(input));
      expect(a3.idempotentReplay).toBe(true);
    } finally {
      await restarted.close();
    }

    // Exactly one action row and one action-proposed evidence event were written.
    const { actions, events } = await withTenant(appPool(WP), "t_acme", async (c) => ({
      actions: (await c.query("SELECT count(*)::int AS n FROM action_proposals WHERE action_id = $1", ["act_fixed_1"])).rows[0].n,
      events: (await c.query("SELECT count(*)::int AS n FROM evidence_envelopes WHERE event_type = 'action.proposed'")).rows[0].n,
    }));
    expect(actions).toBe(1);
    expect(events).toBe(1);
  });

  it("getMetrics returns durable-derived counts (gate 1)", async () => {
    const m = await store.getMetrics(ctx());
    expect(m.evidence_chain_valid).toBe(true);
    expect(m.evidence_count).toBeGreaterThan(0);
    expect(m.capabilities_issued).toBeGreaterThanOrEqual(1);
    expect(m.authorizations_total).toBeGreaterThanOrEqual(1);
    expect(m.permits_total).toBeGreaterThanOrEqual(2);
    expect(m.cross_tenant_leaks).toBe(0);
  });
});
