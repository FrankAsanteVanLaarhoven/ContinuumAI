/**
 * PostgresStore authorization-decision WRITE path over REAL embedded PostgreSQL.
 *
 * A dedicated database (continuum_wp) is migrated fresh and seeded from a single
 * ContinuumEngine that has ONLY submitted its intent (no authorization yet). The
 * write path then runs authorizeIntent over Postgres and must:
 *   - reproduce the FROZEN engine's decision + disclosure digest (semantic parity),
 *   - issue and persist a holder-bound capability,
 *   - continue the persisted evidence chain (GAP-4 restart-safe resume) and survive
 *     a fresh pool,
 *   - fail closed when the injected signing key does not match the persisted anchor,
 *   - stay HELD when no write authority is provided.
 *
 * The write path signs with an INJECTED in-process keypair whose public half equals
 * the persisted platform_key — matching the frozen slice's documented key-custody
 * limitation (production KMS/HSM custody is out of the Phase 2 scope).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AsyncContinuumEngine,
  ContinuumEngine,
  generateEd25519,
  researchContext,
  type RequestContext,
} from "@continuum/core";
import { adminPool, appPool, type DbConfig } from "./pg";
import { migrate } from "./migrate";
import { persistExport } from "./repository";
import { PostgresStore, type WriteAuthority } from "./postgres-store";

const OWNER = "did:continuum:enterprise:acme:owner";
const AGENT = "spiffe://acme.ai/agents/procurement-agent";
const NOW = Date.parse("2026-07-15T00:00:00.000Z");

function ctx(tenantId: string): RequestContext {
  return researchContext({ tenantId, principalId: AGENT, nowMs: NOW, source: "service_api" });
}

function canonicalIntent(engine: ContinuumEngine) {
  return engine.submitIntent(
    {
      owner_id: OWNER,
      actor_id: AGENT,
      tenant_id: "t_acme",
      purpose: "supplier_quote_comparison",
      requested_operations: [
        "read:supplier_quotes",
        "read:approved_budget_band",
        "write:recommendation_draft",
      ],
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
    },
    NOW,
  );
}

const WP: DbConfig = { host: "127.0.0.1", port: 55444, database: "continuum_wp" };

let store: PostgresStore;
let engine: ContinuumEngine;
let intentId: string;
let authority: WriteAuthority;

beforeAll(async () => {
  // 1. fresh database in the shared embedded cluster.
  const admin = adminPool({ ...WP, database: "continuum" });
  try {
    await admin.query("DROP DATABASE IF EXISTS continuum_wp");
    await admin.query("CREATE DATABASE continuum_wp");
  } finally {
    await admin.end();
  }
  await migrate(WP);

  // 2. seed from an engine that has ONLY submitted the intent (no authorization).
  engine = new ContinuumEngine();
  intentId = canonicalIntent(engine).intent_id;
  const seed = appPool(WP);
  try {
    await persistExport(seed, engine.exportState());
  } finally {
    await seed.end();
  }

  // 3. write authority: the engine's own keypair (its public half is the persisted anchor).
  authority = {
    platformKeys: engine.store.platform,
    registry: engine.store.registry,
    config: engine.store.config,
  };
  store = new PostgresStore(WP, { writeAuthority: authority });
});

afterAll(async () => {
  await store.close();
});

describe("PostgresStore · authorizeIntent write path over real RLS", () => {
  it("reproduces the frozen decision + disclosure digest and issues a capability", async () => {
    const out = await store.transaction(ctx("t_acme"), (tx) => tx.authorizeIntent({ intentId }));

    // Frozen reference: same store, same intent, same clock.
    const ref = engine.authorize(intentId, NOW);

    expect(out.decision.request_permit).toBe(true);
    expect([...out.decision.permitted_ids].sort()).toEqual([...ref.decision.permitted_ids].sort());
    expect(out.decision.permitted_ids).toHaveLength(2);
    expect(out.decision.candidate_count).toBe(10);
    // Semantic parity with the synchronous engine.
    expect(out.disclosure.disclosure_digest).toBe(ref.disclosure.disclosure_digest);
    expect(out.disclosure.redactions).toEqual([{ memory_id: "mem_q_apex", field: "bank_iban" }]);

    expect(out.capability).not.toBeNull();
    expect(out.capability!.token.resources.sort()).toEqual([...out.decision.permitted_ids].sort());
    expect(out.capability!.token.tenant_id).toBe("t_acme");
  });

  it("persisted the capability and continued the evidence chain (intent + decision + issue)", async () => {
    const v = await store.verifyEvidenceChain(ctx("t_acme"));
    expect(v.valid).toBe(true);
    expect(v.length).toBe(3); // intent.submitted → authorization.decided → capability.issued

    const eventTypes = (await store.listEvidence(ctx("t_acme"))).map((e) => e.event_type);
    expect(eventTypes).toEqual([
      "intent.submitted",
      "authorization.decided",
      "capability.issued",
    ]);
  });

  it("evidence durability survives a fresh pool (process-restart simulation)", async () => {
    const restarted = new PostgresStore(WP, { writeAuthority: authority });
    try {
      const v = await restarted.verifyEvidenceChain(ctx("t_acme"));
      expect(v.valid).toBe(true);
      expect(v.length).toBe(3);
    } finally {
      await restarted.close();
    }
  });

  it("runs through AsyncContinuumEngine unchanged (store-agnostic)", async () => {
    // A second, fresh database so the engine authorizes a not-yet-authorized intent.
    const admin = adminPool({ ...WP, database: "continuum" });
    try {
      await admin.query("DROP DATABASE IF EXISTS continuum_wp2");
      await admin.query("CREATE DATABASE continuum_wp2");
    } finally {
      await admin.end();
    }
    const cfg2: DbConfig = { ...WP, database: "continuum_wp2" };
    await migrate(cfg2);

    const eng2 = new ContinuumEngine();
    const id2 = canonicalIntent(eng2).intent_id;
    const seed = appPool(cfg2);
    try {
      await persistExport(seed, eng2.exportState());
    } finally {
      await seed.end();
    }

    const store2 = new PostgresStore(cfg2, {
      writeAuthority: {
        platformKeys: eng2.store.platform,
        registry: eng2.store.registry,
        config: eng2.store.config,
      },
    });
    try {
      const asyncEngine = new AsyncContinuumEngine(store2);
      const out = await asyncEngine.authorize(ctx("t_acme"), { intentId: id2 });
      expect(out.decision.permitted_ids).toHaveLength(2);
      expect(out.capability).not.toBeNull();
      const v = await asyncEngine.verifyEvidenceChain(ctx("t_acme"));
      expect(v.valid).toBe(true);
      expect(v.length).toBe(3);
    } finally {
      await store2.close();
    }
  });

  it("fails closed when the injected signing key does not match the persisted anchor", async () => {
    const foreign = new PostgresStore(WP, {
      writeAuthority: {
        platformKeys: generateEd25519(), // NOT the persisted anchor
        registry: engine.store.registry,
        config: engine.store.config,
      },
    });
    try {
      await expect(
        foreign.transaction(ctx("t_acme"), (tx) => tx.authorizeIntent({ intentId })),
      ).rejects.toThrow(/custody mismatch/i);
    } finally {
      await foreign.close();
    }
  });

  it("stays HELD when no write authority is configured", async () => {
    const noAuth = new PostgresStore(WP);
    try {
      await expect(
        noAuth.transaction(ctx("t_acme"), (tx) => tx.authorizeIntent({ intentId })),
      ).rejects.toThrow(/held pending review/i);
    } finally {
      await noAuth.close();
    }
  });

  it("submitIntent persists a new intent and authorizes it end-to-end over Postgres", async () => {
    const raw = {
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
    const newId = await store.transaction(ctx("t_acme"), (tx) => tx.submitIntent(raw));
    expect(newId).toMatch(/^int_/);

    // Read-back through RLS, then authorize the freshly-submitted intent.
    expect((await store.getIntent(ctx("t_acme"), newId))?.intent_id).toBe(newId);
    const out = await store.transaction(ctx("t_acme"), (tx) => tx.authorizeIntent({ intentId: newId }));
    expect(out.decision.permitted_ids).toHaveLength(2);
    expect(out.capability).not.toBeNull();

    const v = await store.verifyEvidenceChain(ctx("t_acme"));
    expect(v.valid).toBe(true);
  });
});
