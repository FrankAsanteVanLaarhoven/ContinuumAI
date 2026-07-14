/**
 * Seeded in-memory store for the v0.1 vertical slice.
 *
 * This is deliberately ephemeral and in-process — it is NOT the production
 * persistence tier (that is PostgreSQL + object storage + append-only events,
 * per the blueprint). It exists so the whole control plane runs end-to-end,
 * locally, with zero external dependencies, and so the demonstration is fully
 * reproducible.
 *
 * The Acme tenant carries ten memory objects engineered so that exactly two
 * are permitted for the procurement intent; the other eight each deny for a
 * different, legible reason. A Globex object exists solely to prove tenant
 * isolation.
 */
import { digestOf, generateEd25519, type Ed25519Keypair } from "./crypto";
import {
  DEFAULT_INJECTION_PATTERNS,
  type ModelGatewayConfig,
} from "./gateway";
import type {
  ApprovedRegistry,
  ConsentRecord,
  EntitlementPolicy,
  MemoryObject,
  PolicyConfig,
  Principal,
  Tenant,
} from "./types";

export interface Store {
  tenants: Map<string, Tenant>;
  principals: Map<string, Principal>;
  /** Private keys for seeded agents — simulates their in-process runtime. */
  agentKeys: Map<string, Ed25519Keypair>;
  memory: Map<string, MemoryObject>;
  consent: ConsentRecord[];
  registry: ApprovedRegistry;
  config: PolicyConfig;
  gateway: ModelGatewayConfig;
  platform: Ed25519Keypair;
  /** Authoritative entitlement ceiling (intervention I1). Optional: consulted
   *  only when the engine runs in an entitlement-enforcing mode. */
  entitlements?: EntitlementPolicy;
}

const PURPOSE = "supplier_quote_comparison";

function mem(
  partial: Omit<MemoryObject, "content_hash">,
): MemoryObject {
  return { ...partial, content_hash: digestOf(partial.content) };
}

export function createSeededStore(): Store {
  const platform = generateEd25519();
  const procKeys = generateEd25519();
  const glxKeys = generateEd25519();

  const tenants = new Map<string, Tenant>([
    [
      "t_acme",
      {
        tenant_id: "t_acme",
        display_name: "Acme Robotics PLC",
        trust_domain: "acme.ai",
        residency: "GB",
      },
    ],
    [
      "t_globex",
      {
        tenant_id: "t_globex",
        display_name: "Globex Health Systems",
        trust_domain: "globex.health",
        residency: "US",
      },
    ],
  ]);

  const PROC_BUILD =
    "sha256:9f1c0procurement_agent_build_v3_reproducible_measure";
  const GLX_BUILD = "sha256:2a7dbilling_agent_build_v1_reproducible_measure";

  const principals = new Map<string, Principal>([
    [
      "did:continuum:enterprise:acme:owner",
      {
        principal_id: "did:continuum:enterprise:acme:owner",
        kind: "human",
        tenant_id: "t_acme",
        trust_domain: "acme.ai",
        display_name: "Ada Okafor — Head of Procurement",
        attested: true,
        build_hash: null,
        public_key_pem: null,
      },
    ],
    [
      "spiffe://acme.ai/agents/procurement-agent",
      {
        principal_id: "spiffe://acme.ai/agents/procurement-agent",
        kind: "agent",
        tenant_id: "t_acme",
        trust_domain: "acme.ai",
        display_name: "Procurement Agent",
        attested: true,
        build_hash: PROC_BUILD,
        public_key_pem: procKeys.publicKeyPem,
      },
    ],
    [
      "did:continuum:enterprise:globex:owner",
      {
        principal_id: "did:continuum:enterprise:globex:owner",
        kind: "human",
        tenant_id: "t_globex",
        trust_domain: "globex.health",
        display_name: "Cyrus Reed — Billing Lead",
        attested: true,
        build_hash: null,
        public_key_pem: null,
      },
    ],
    [
      "spiffe://globex.health/agents/billing-agent",
      {
        principal_id: "spiffe://globex.health/agents/billing-agent",
        kind: "agent",
        tenant_id: "t_globex",
        trust_domain: "globex.health",
        display_name: "Billing Agent",
        attested: true,
        build_hash: GLX_BUILD,
        public_key_pem: glxKeys.publicKeyPem,
      },
    ],
  ]);

  const agentKeys = new Map<string, Ed25519Keypair>([
    ["spiffe://acme.ai/agents/procurement-agent", procKeys],
    ["spiffe://globex.health/agents/billing-agent", glxKeys],
  ]);

  const base = {
    owner_id: "did:continuum:enterprise:acme:owner",
    tenant_id: "t_acme",
    creator_principal: "did:continuum:enterprise:acme:owner",
    created_at: "2026-06-01T09:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    confidence: 0.95,
    residency: "GB",
    consent_basis: "owner-portal-explicit-v2",
    retention_policy: "P2Y",
    model_identity: null,
    verification_state: "verified" as const,
    revocation_state: "active" as const,
    deletion_state: "present" as const,
    supersedes: null,
    sensitive_fields: [] as string[],
  };

  const objects: MemoryObject[] = [
    // 1 — PERMIT (with a redacted sensitive field)
    mem({
      ...base,
      memory_id: "mem_q_apex",
      memory_class: "evidence",
      classification: "confidential",
      purpose_constraints: [PURPOSE],
      read_operation: "read:supplier_quotes",
      sensitive_fields: ["bank_iban"],
      source_type: "supplier_portal",
      source_reference: "quote://apex/2026-Q3-0417",
      content: {
        supplier: "Apex Components Ltd",
        unit_price_gbp: 412.5,
        lead_time_days: 21,
        currency: "GBP",
        bank_iban: "GB29NWBK60161331926819",
      },
    }),
    // 2 — PERMIT
    mem({
      ...base,
      memory_id: "mem_q_orion",
      memory_class: "evidence",
      classification: "confidential",
      purpose_constraints: [PURPOSE],
      read_operation: "read:supplier_quotes",
      source_type: "supplier_portal",
      source_reference: "quote://orion/2026-Q3-0088",
      content: {
        supplier: "Orion Supply Co",
        unit_price_gbp: 398.0,
        lead_time_days: 35,
        currency: "GBP",
      },
    }),
    // 3 — DENY: classification ceiling (restricted > confidential)
    mem({
      ...base,
      memory_id: "mem_budget_band",
      memory_class: "semantic",
      classification: "restricted",
      purpose_constraints: [PURPOSE],
      read_operation: "read:approved_budget_band",
      source_type: "finance_system",
      source_reference: "budget://acme/2026/procurement",
      content: { band_low_gbp: 350, band_high_gbp: 450 },
    }),
    // 4 — DENY: data residency (US outside GB boundary)
    mem({
      ...base,
      memory_id: "mem_legal_us",
      memory_class: "evidence",
      classification: "confidential",
      residency: "US",
      purpose_constraints: [PURPOSE],
      read_operation: "read:supplier_quotes",
      source_type: "legal_repository",
      source_reference: "quote://us-terms/2026-0031",
      content: { supplier: "US Terms Holdings", unit_price_gbp: 405.0 },
    }),
    // 5 — DENY: stale (validity window elapsed)
    mem({
      ...base,
      memory_id: "mem_q_stale",
      memory_class: "evidence",
      classification: "confidential",
      valid_until: "2020-01-01T00:00:00.000Z",
      purpose_constraints: [PURPOSE],
      read_operation: "read:supplier_quotes",
      source_type: "supplier_portal",
      source_reference: "quote://legacy/2019-4400",
      content: { supplier: "Legacy Parts", unit_price_gbp: 380.0 },
    }),
    // 6 — DENY: revoked object
    mem({
      ...base,
      memory_id: "mem_q_revoked",
      memory_class: "evidence",
      classification: "confidential",
      revocation_state: "revoked",
      purpose_constraints: [PURPOSE],
      read_operation: "read:supplier_quotes",
      source_type: "supplier_portal",
      source_reference: "quote://apex/withdrawn-0009",
      content: { supplier: "Apex (withdrawn)", unit_price_gbp: 999.0 },
    }),
    // 7 — DENY: purpose not allowed
    mem({
      ...base,
      memory_id: "mem_payroll",
      memory_class: "relational",
      classification: "confidential",
      purpose_constraints: ["payroll_run"],
      read_operation: "read:supplier_quotes",
      source_type: "hr_system",
      source_reference: "payroll://acme/2026-06",
      content: { note: "monthly payroll batch reference" },
    }),
    // 8 — DENY: scope (operation not requested by intent)
    mem({
      ...base,
      memory_id: "mem_src_code",
      memory_class: "prohibition",
      classification: "confidential",
      purpose_constraints: [PURPOSE],
      read_operation: "read:source_code",
      source_type: "code_repository",
      source_reference: "repo://acme/continuum-core",
      content: { repo: "continuum-core", note: "never disclose source" },
    }),
    // 9 — DENY: deleted
    mem({
      ...base,
      memory_id: "mem_deleted_quote",
      memory_class: "evidence",
      classification: "confidential",
      deletion_state: "deleted",
      purpose_constraints: [PURPOSE],
      read_operation: "read:supplier_quotes",
      source_type: "supplier_portal",
      source_reference: "quote://apex/deleted-0002",
      content: { supplier: "Apex (deleted record)", unit_price_gbp: 401.0 },
    }),
    // 10 — DENY: purpose not allowed (HR review scope)
    mem({
      ...base,
      memory_id: "mem_hr_pii",
      memory_class: "relational",
      classification: "confidential",
      purpose_constraints: ["hr_review"],
      read_operation: "read:supplier_quotes",
      source_type: "hr_system",
      source_reference: "hr://acme/reviews/2026",
      content: { employee: "record withheld", review_cycle: "2026-H1" },
    }),
    // Globex — different tenant, used to prove isolation
    mem({
      memory_id: "mem_glx_quote",
      owner_id: "did:continuum:enterprise:globex:owner",
      tenant_id: "t_globex",
      memory_class: "evidence",
      classification: "confidential",
      content: { supplier: "Globex Internal", unit_price_usd: 500.0 },
      creator_principal: "did:continuum:enterprise:globex:owner",
      created_at: "2026-06-01T09:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      confidence: 0.9,
      purpose_constraints: [PURPOSE],
      read_operation: "read:supplier_quotes",
      residency: "US",
      consent_basis: "globex-portal-explicit",
      retention_policy: "P2Y",
      sensitive_fields: [],
      model_identity: null,
      verification_state: "verified",
      revocation_state: "active",
      deletion_state: "present",
      supersedes: null,
      source_type: "supplier_portal",
      source_reference: "quote://globex/internal-0001",
    }),
  ];

  const memory = new Map<string, MemoryObject>(
    objects.map((o) => [o.memory_id, o]),
  );

  const consent: ConsentRecord[] = [
    {
      owner_id: "did:continuum:enterprise:acme:owner",
      tenant_id: "t_acme",
      purpose: PURPOSE,
      granted: true,
      basis: "owner-portal-explicit-v2",
      valid_until: "2030-01-01T00:00:00.000Z",
    },
  ];

  const registry: ApprovedRegistry = {
    agent_builds: new Set([PROC_BUILD, GLX_BUILD]),
    models: new Set(["gw-approved-llm-2026-06"]),
    environments: new Set(["continuum-runtime/gvisor"]),
    regions: new Set(["GB", "US"]),
  };

  const config: PolicyConfig = {
    policy_version: "policy-2026.07.0",
    risk_threshold: 0.7,
    capability_ttl_seconds: 90,
  };

  const gateway: ModelGatewayConfig = {
    providers: [
      {
        provider: "continuum-model-gateway",
        model_id: "gw-approved-llm-2026-06",
        version: "2026-06-01",
        region: "GB",
        zero_retention: true,
        external: false,
        max_classification: "confidential",
      },
      {
        provider: "continuum-model-gateway",
        model_id: "gw-approved-llm-restricted",
        version: "2026-06-01",
        region: "GB",
        zero_retention: true,
        external: false,
        max_classification: "restricted",
      },
    ],
    injection_patterns: DEFAULT_INJECTION_PATTERNS,
    canaries: ["GB29NWBK60161331926819"],
    per_request_token_budget: 4000,
    gbp_per_1k_tokens: 0.5,
  };

  // Authoritative entitlement ceiling (intervention I1). The procurement agent is
  // entitled ONLY to its legitimate procurement operations — NOT read:source_code,
  // which is why its self-declared scope escalation (GAP-1) succeeds today and
  // must be denied once entitlements are enforced.
  const entitlements: EntitlementPolicy = {
    version: "entitlements-2026.07.0",
    entitlements: [
      {
        principal_id: "spiffe://acme.ai/agents/procurement-agent",
        tenant_id: "t_acme",
        allowed_operations: [
          "read:supplier_quotes",
          "read:approved_budget_band",
          "write:recommendation_draft",
        ],
        delegated_operations: [
          "read:supplier_quotes",
          "read:approved_budget_band",
          "write:recommendation_draft",
        ],
      },
      {
        principal_id: "spiffe://globex.health/agents/billing-agent",
        tenant_id: "t_globex",
        allowed_operations: ["read:supplier_quotes"],
        delegated_operations: ["read:supplier_quotes"],
      },
    ],
  };

  return {
    tenants,
    principals,
    agentKeys,
    memory,
    consent,
    registry,
    config,
    gateway,
    platform,
    entitlements,
  };
}

/** Candidate objects visible to a tenant (isolation is enforced here and re-checked by the PDP). */
export function candidatesForTenant(
  store: Store,
  tenantId: string,
): MemoryObject[] {
  return [...store.memory.values()].filter((m) => m.tenant_id === tenantId);
}

export function findConsent(
  store: Store,
  ownerId: string,
  purpose: string,
): ConsentRecord | null {
  return (
    store.consent.find((c) => c.owner_id === ownerId && c.purpose === purpose) ??
    null
  );
}
