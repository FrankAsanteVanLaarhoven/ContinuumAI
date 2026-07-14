import { describe, it, expect } from "vitest";
import {
  ContinuumEngine,
  EvidenceLedger,
  createSeededStore,
  generateEd25519,
  intentInputSchema,
  popMessage,
  signEd25519,
  verifySCT,
  type EvidenceEnvelope,
  type SignedSCT,
  type VerifyOptions,
} from "./index";

const NOW = Date.parse("2026-07-14T12:00:00.000Z");
const OWNER = "did:continuum:enterprise:acme:owner";
const AGENT = "spiffe://acme.ai/agents/procurement-agent";

function baseIntentInput(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
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
    required_evidence: [
      "agent_attestation",
      "approved_model_policy",
      "current_user_consent",
    ],
    human_gate: { required_for: ["external_commitment"] },
    actor_geo: "GB",
    model_id: "gw-approved-llm-2026-06",
    risk_score: 0.12,
    ...overrides,
  };
}

describe("protocol boundary fails closed", () => {
  it("rejects malformed intents", () => {
    expect(() => intentInputSchema.parse({ foo: "bar" })).toThrow();
  });
  it("rejects unknown fields (strict)", () => {
    expect(() =>
      intentInputSchema.parse({ ...baseIntentInput(), unexpected: true }),
    ).toThrow();
  });
});

describe("policy decision point — deny by default", () => {
  it("permits exactly the two eligible objects", () => {
    const e = new ContinuumEngine();
    const intent = e.submitIntent(baseIntentInput(), NOW);
    const { decision } = e.authorize(intent.intent_id, NOW);
    expect(decision.request_permit).toBe(true);
    expect([...decision.permitted_ids].sort()).toEqual([
      "mem_q_apex",
      "mem_q_orion",
    ]);
  });

  it("denies the other eight for distinct, legible reasons", () => {
    const e = new ContinuumEngine();
    const intent = e.submitIntent(baseIntentInput(), NOW);
    const { decision } = e.authorize(intent.intent_id, NOW);
    const byId = new Map(
      decision.object_decisions.map((d) => [d.memory_id, d.denied_reason ?? ""]),
    );
    expect(byId.get("mem_budget_band")).toMatch(/classification/);
    expect(byId.get("mem_legal_us")).toMatch(/residency/);
    expect(byId.get("mem_q_stale")).toMatch(/stale/);
    expect(byId.get("mem_q_revoked")).toMatch(/object_live|revoked/);
    expect(byId.get("mem_payroll")).toMatch(/purpose/);
    expect(byId.get("mem_src_code")).toMatch(/scope/);
    expect(byId.get("mem_deleted_quote")).toMatch(/object_live|deleted/);
    expect(byId.get("mem_hr_pii")).toMatch(/purpose/);
  });

  it("denies the whole request when consent has expired", () => {
    const e = new ContinuumEngine();
    const intent = e.submitIntent(baseIntentInput(), NOW);
    const late = Date.parse("2031-01-01T00:00:00.000Z");
    const { decision } = e.authorize(intent.intent_id, late);
    expect(decision.request_permit).toBe(false);
    expect(decision.permitted_ids).toHaveLength(0);
    const consent = decision.request_checks.find(
      (c) => c.name === "consent_current",
    );
    expect(consent?.satisfied).toBe(false);
  });

  it("denies an unapproved agent build", () => {
    const e = new ContinuumEngine();
    const intent = e.submitIntent(
      baseIntentInput({ agent_build: "sha256:unapproved_build" }),
      NOW,
    );
    const { decision } = e.authorize(intent.intent_id, NOW);
    expect(decision.request_permit).toBe(false);
    expect(
      decision.request_checks.find((c) => c.name === "agent_build_approved")
        ?.satisfied,
    ).toBe(false);
  });

  it("denies when required model evidence is absent", () => {
    const e = new ContinuumEngine();
    const intent = e.submitIntent(baseIntentInput({ model_id: null }), NOW);
    const { decision } = e.authorize(intent.intent_id, NOW);
    expect(decision.request_permit).toBe(false);
    expect(
      decision.request_checks.find((c) => c.name === "evidence_sufficient")
        ?.satisfied,
    ).toBe(false);
  });

  it("denies when risk exceeds the threshold", () => {
    const e = new ContinuumEngine();
    const intent = e.submitIntent(baseIntentInput({ risk_score: 0.9 }), NOW);
    const { decision } = e.authorize(intent.intent_id, NOW);
    expect(decision.request_permit).toBe(false);
    expect(
      decision.request_checks.find((c) => c.name === "risk_within_limit")
        ?.satisfied,
    ).toBe(false);
  });
});

describe("context broker redaction", () => {
  it("redacts the sensitive field before it leaves the boundary", () => {
    const e = new ContinuumEngine();
    const intent = e.submitIntent(baseIntentInput(), NOW);
    const { disclosure } = e.authorize(intent.intent_id, NOW);
    const apex = disclosure.disclosed.find((d) => d.memory_id === "mem_q_apex");
    expect(apex?.content["bank_iban"]).toBe("[REDACTED]");
    expect(apex?.redacted_fields).toContain("bank_iban");
    const orion = disclosure.disclosed.find((d) => d.memory_id === "mem_q_orion");
    expect(orion?.redacted_fields).toHaveLength(0);
  });
});

describe("sovereign capability token", () => {
  function makeOpts(partial: Partial<VerifyOptions>, e: ContinuumEngine): VerifyOptions {
    return {
      platformPublicKeyPem: e.platformPublicKeyPem(),
      nowMs: NOW,
      revokedHandles: new Set<string>(),
      audience: null,
      pop: null,
      ...partial,
    };
  }

  function issued(): { e: ContinuumEngine; token: SignedSCT } {
    const e = new ContinuumEngine();
    const intent = e.submitIntent(baseIntentInput(), NOW);
    const { capability } = e.authorize(intent.intent_id, NOW);
    if (!capability) throw new Error("expected a capability");
    return { e, token: capability };
  }

  it("verifies with a correct proof-of-possession", () => {
    const { e, token } = issued();
    const key = e.store.agentKeys.get(AGENT);
    if (!key) throw new Error("no agent key");
    const pop = {
      challenge: "c1",
      signature: signEd25519(key.privateKeyPem, popMessage(token.token, "c1")),
    };
    expect(verifySCT(token, makeOpts({ pop }, e)).valid).toBe(true);
  });

  it("fails a stolen token (wrong holder key)", () => {
    const { e, token } = issued();
    const thief = generateEd25519();
    const pop = {
      challenge: "c1",
      signature: signEd25519(thief.privateKeyPem, popMessage(token.token, "c1")),
    };
    const r = verifySCT(token, makeOpts({ pop }, e));
    expect(r.valid).toBe(false);
    expect(r.checks.find((c) => c.name === "holder_pop")?.satisfied).toBe(false);
  });

  it("fails with no proof-of-possession (not a bearer token)", () => {
    const { e, token } = issued();
    const r = verifySCT(token, makeOpts({ pop: null }, e));
    expect(r.checks.find((c) => c.name === "holder_pop")?.satisfied).toBe(false);
  });

  it("fails once expired", () => {
    const { e, token } = issued();
    const key = e.store.agentKeys.get(AGENT)!;
    const pop = {
      challenge: "c1",
      signature: signEd25519(key.privateKeyPem, popMessage(token.token, "c1")),
    };
    const r = verifySCT(token, makeOpts({ pop, nowMs: NOW + 3600 * 1000 }, e));
    expect(r.checks.find((c) => c.name === "not_expired")?.satisfied).toBe(false);
  });

  it("fails once revoked", () => {
    const { e, token } = issued();
    const key = e.store.agentKeys.get(AGENT)!;
    const pop = {
      challenge: "c1",
      signature: signEd25519(key.privateKeyPem, popMessage(token.token, "c1")),
    };
    const r = verifySCT(
      token,
      makeOpts({ pop, revokedHandles: new Set([token.token.revocation_handle]) }, e),
    );
    expect(r.checks.find((c) => c.name === "not_revoked")?.satisfied).toBe(false);
  });

  it("fails when the token is tampered", () => {
    const { e, token } = issued();
    const key = e.store.agentKeys.get(AGENT)!;
    const tampered: SignedSCT = {
      token: { ...token.token, purpose: "exfiltration" },
      signature: token.signature,
    };
    const pop = {
      challenge: "c1",
      signature: signEd25519(key.privateKeyPem, popMessage(tampered.token, "c1")),
    };
    const r = verifySCT(tampered, makeOpts({ pop }, e));
    expect(r.checks.find((c) => c.name === "signature_valid")?.satisfied).toBe(
      false,
    );
  });
});

describe("evidence ledger is tamper-evident", () => {
  it("verifies an intact chain and detects retroactive edits", () => {
    const store = createSeededStore();
    const ledger = new EvidenceLedger(
      store.platform.privateKeyPem,
      store.platform.publicKeyPem,
      "policy-test",
    );
    ledger.append({
      tenant_id: "t_acme",
      owner_id: OWNER,
      principal: AGENT,
      event_type: "a",
      nowMs: NOW,
    });
    ledger.append({
      tenant_id: "t_acme",
      owner_id: OWNER,
      principal: AGENT,
      event_type: "b",
      nowMs: NOW,
    });
    expect(ledger.verifyChain().valid).toBe(true);

    const internal = ledger as unknown as { entries: EvidenceEnvelope[] };
    const first = internal.entries[0];
    if (!first) throw new Error("expected an entry");
    first.decision = "TAMPERED";

    const v = ledger.verifyChain();
    expect(v.valid).toBe(false);
    expect(v.broken_at).toBe(0);
  });
});
