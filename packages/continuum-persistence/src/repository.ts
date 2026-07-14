/**
 * Repository: persist an engine export durably, and reload the evidence chain
 * for independent re-verification. All writes go through tenant-scoped
 * transactions so RLS applies to inserts as well as reads (a forged tenant_id
 * is rejected by the policy's WITH CHECK).
 */
import type { Pool } from "pg";
import {
  verifyEnvelopeChain,
  type ChainVerification,
  type EngineExport,
  type EvidenceEnvelope,
} from "@continuum/core";
import { withTenant, withoutTenant } from "./pg";

const j = (v: unknown): string => JSON.stringify(v);

export async function persistExport(
  pool: Pool,
  exp: EngineExport,
): Promise<void> {
  // Global (non-tenant) rows.
  await withoutTenant(pool, async (c) => {
    // Write-once. The app role is INSERT-only (no UPDATE), so DO NOTHING — the
    // platform key is fixed for a deployment; changing it would orphan the
    // evidence chain that its predecessor signed.
    await c.query(
      `INSERT INTO platform_key (id, public_key_pem) VALUES (1, $1)
       ON CONFLICT (id) DO NOTHING`,
      [exp.platform_public_key_pem],
    );
    await c.query(
      `INSERT INTO policies (policy_version, risk_threshold, capability_ttl_seconds)
       VALUES ($1, $2, $3) ON CONFLICT (policy_version) DO NOTHING`,
      [exp.policy.policy_version, exp.policy.risk_threshold, exp.policy.capability_ttl_seconds],
    );
  });

  for (const t of exp.tenants) {
    await withTenant(pool, t.tenant_id, (c) =>
      c.query(
        `INSERT INTO tenants (tenant_id, display_name, trust_domain, residency)
         VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
        [t.tenant_id, t.display_name, t.trust_domain, t.residency],
      ),
    );
  }

  for (const p of exp.principals) {
    await withTenant(pool, p.tenant_id, (c) =>
      c.query(
        `INSERT INTO principals (tenant_id, principal_id, kind, trust_domain, display_name, attested, build_hash, public_key_pem)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
        [p.tenant_id, p.principal_id, p.kind, p.trust_domain, p.display_name, p.attested, p.build_hash, p.public_key_pem],
      ),
    );
  }

  for (const m of exp.memory) {
    await withTenant(pool, m.tenant_id, (c) =>
      c.query(
        `INSERT INTO memory_objects (tenant_id, memory_id, owner_id, memory_class, content, content_hash, classification, purpose_constraints, read_operation, residency, sensitive_fields, consent_basis, retention_policy, valid_until, confidence, verification_state, revocation_state, deletion_state, model_identity, supersedes, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT DO NOTHING`,
        [m.tenant_id, m.memory_id, m.owner_id, m.memory_class, j(m.content), m.content_hash, m.classification, j(m.purpose_constraints), m.read_operation, m.residency, j(m.sensitive_fields), m.consent_basis, m.retention_policy, m.valid_until, m.confidence, m.verification_state, m.revocation_state, m.deletion_state, m.model_identity, m.supersedes, m.created_at],
      ),
    );
  }

  for (const cn of exp.consent) {
    await withTenant(pool, cn.tenant_id, (c) =>
      c.query(
        `INSERT INTO consent (tenant_id, owner_id, purpose, granted, basis, valid_until)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [cn.tenant_id, cn.owner_id, cn.purpose, cn.granted, cn.basis, cn.valid_until],
      ),
    );
  }

  for (const it of exp.intents) {
    await withTenant(pool, it.tenant_id, (c) =>
      c.query(
        `INSERT INTO intents (tenant_id, intent_id, owner_id, actor_id, purpose, requested_operations, prohibited_operations, constraints, required_evidence, human_gate, actor_geo, model_id, agent_build, risk_score)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT DO NOTHING`,
        [it.tenant_id, it.intent_id, it.owner_id, it.actor_id, it.purpose, j(it.requested_operations), j(it.prohibited_operations), j(it.constraints), j(it.required_evidence), j(it.human_gate), it.actor_geo, it.model_id, it.agent_build, it.risk_score],
      ),
    );
  }

  const tokenByHandle = new Map(exp.capabilities.map((s) => [s.token.revocation_handle, s.token]));
  const intentTenant = new Map(exp.intents.map((i) => [i.intent_id, i.tenant_id]));

  for (const s of exp.capabilities) {
    const t = s.token;
    await withTenant(pool, t.tenant_id, (c) =>
      c.query(
        `INSERT INTO capabilities (tenant_id, token_id, actor, subject, intent_id, purpose, audience, operations, resources, data_classification, holder_key_pem, environment, risk_threshold, approval_state, issued_at, expires_at, nonce, revocation_handle, evidence_correlation_id, signature)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) ON CONFLICT DO NOTHING`,
        [t.tenant_id, t.token_id, t.actor, t.subject, t.intent_id, t.purpose, t.audience, j(t.operations), j(t.resources), t.data_classification, t.holder_key_pem, t.environment, t.risk_threshold, t.approval_state, t.issued_at, t.expires_at, t.nonce, t.revocation_handle, t.evidence_correlation_id, s.signature],
      ),
    );
  }

  for (const handle of exp.revoked_handles) {
    const t = tokenByHandle.get(handle);
    if (!t) continue;
    await withTenant(pool, t.tenant_id, (c) =>
      c.query(
        `INSERT INTO revocations (tenant_id, revocation_handle, token_id, revoked_at)
         VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
        [t.tenant_id, handle, t.token_id, new Date(0).toISOString()],
      ),
    );
  }

  for (const a of exp.actions) {
    const tenant = intentTenant.get(a.intent_id);
    if (!tenant) continue;
    await withTenant(pool, tenant, async (c) => {
      await c.query(
        `INSERT INTO action_proposals (tenant_id, action_id, intent_id, actor, operation, action_class, state, requires_human_approval, expected_effect, reversible, cost_gbp, denied_reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`,
        [tenant, a.action_id, a.intent_id, a.actor, a.operation, a.action_class, a.state, a.requires_human_approval, a.expected_effect, a.reversible, a.cost_gbp, a.denied_reason],
      );
      let seq = 0;
      for (const h of a.history) {
        await c.query(
          `INSERT INTO action_transitions (tenant_id, action_id, seq, state, at, note)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [tenant, a.action_id, seq++, h.state, h.at, h.note],
        );
        if (h.state === "HUMAN_APPROVED") {
          await c.query(
            `INSERT INTO approvals (tenant_id, action_id, approver, at) VALUES ($1,$2,$3,$4)`,
            [tenant, a.action_id, h.note.replace("approved by ", ""), h.at],
          );
        }
      }
    });
  }

  // Evidence in seq order per tenant (the append-only chain).
  const byTenant = new Map<string, EvidenceEnvelope[]>();
  for (const e of exp.evidence) {
    const list = byTenant.get(e.tenant_id) ?? [];
    list.push(e);
    byTenant.set(e.tenant_id, list);
  }
  for (const [tenant, list] of byTenant) {
    list.sort((a, b) => a.seq - b.seq);
    await withTenant(pool, tenant, async (c) => {
      for (const e of list) {
        await c.query(
          `INSERT INTO evidence_envelopes (tenant_id, event_id, seq, trace_id, owner_id, principal, intent_id, policy_version, event_type, decision, disclosed_objects, disclosure_digest, capability_id, tool_calls, human_approval, result_digest, model, ts, prev_hash, hash, signature)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT DO NOTHING`,
          [e.tenant_id, e.event_id, e.seq, e.trace_id, e.owner_id, e.principal, e.intent_id, e.policy_version, e.event_type, e.decision, j(e.disclosed_objects), e.disclosure_digest, e.capability_id, j(e.tool_calls), e.human_approval ? j(e.human_approval) : null, e.result_digest, e.model ? j(e.model) : null, e.timestamp, e.prev_hash, e.hash, e.signature],
        );
      }
    });
  }
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function rowToEnvelope(row: any): EvidenceEnvelope {
  return {
    cip: "CIP-007",
    event_id: row.event_id,
    trace_id: row.trace_id,
    seq: row.seq,
    tenant_id: row.tenant_id,
    owner_id: row.owner_id,
    principal: row.principal,
    intent_id: row.intent_id,
    policy_version: row.policy_version,
    event_type: row.event_type,
    decision: row.decision,
    disclosed_objects: row.disclosed_objects,
    disclosure_digest: row.disclosure_digest,
    capability_id: row.capability_id,
    tool_calls: row.tool_calls,
    human_approval: row.human_approval,
    result_digest: row.result_digest,
    model: row.model,
    timestamp: row.ts,
    prev_hash: row.prev_hash,
    hash: row.hash,
    signature: row.signature,
  };
}

export async function loadEvidence(
  pool: Pool,
  tenantId: string,
): Promise<EvidenceEnvelope[]> {
  return withTenant(pool, tenantId, async (c) => {
    const res = await c.query("SELECT * FROM evidence_envelopes ORDER BY seq ASC");
    return res.rows.map(rowToEnvelope);
  });
}

export async function loadPlatformKey(pool: Pool): Promise<string> {
  return withoutTenant(pool, async (c) => {
    const res = await c.query("SELECT public_key_pem FROM platform_key WHERE id = 1");
    if (res.rows.length === 0) throw new Error("platform key not persisted");
    return res.rows[0].public_key_pem as string;
  });
}

/** Reload the persisted evidence chain and re-verify it independently. */
export async function verifyPersistedChain(
  pool: Pool,
  tenantId: string,
): Promise<ChainVerification> {
  const [entries, publicKey] = await Promise.all([
    loadEvidence(pool, tenantId),
    loadPlatformKey(pool),
  ]);
  return verifyEnvelopeChain(entries, publicKey);
}

export async function countRows(
  pool: Pool,
  tenantId: string,
  table: string,
): Promise<number> {
  return withTenant(pool, tenantId, async (c) => {
    const res = await c.query(`SELECT count(*)::int AS n FROM ${table}`);
    return (res.rows[0]?.n as number) ?? 0;
  });
}
