-- Continuum durable data plane — initial schema.
--
-- Tenant isolation is enforced by PostgreSQL Row-Level Security, not by
-- application-side filtering. Every tenant-scoped table ENABLEs and FORCEs RLS
-- (so even the table owner is subject to it) and carries a policy keyed on the
-- transaction-local setting `app.current_tenant`. When that setting is absent,
-- `current_setting(..., true)` returns NULL, the predicate is false, and the
-- table is invisible — the system fails closed.
--
-- The application connects as the NOSUPERUSER role `continuum_app`, which is
-- granted only SELECT and INSERT (never UPDATE/DELETE). Migrations run as the
-- superuser. Superusers bypass RLS, so the app MUST NOT connect as one.

-- ---------------------------------------------------------------------------
-- Application role (idempotent)
-- ---------------------------------------------------------------------------
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'continuum_app') THEN
    CREATE ROLE continuum_app LOGIN PASSWORD 'continuum_app' NOSUPERUSER;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Global (non-tenant) tables — no RLS
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS platform_key (
  id integer PRIMARY KEY DEFAULT 1,
  public_key_pem text NOT NULL,
  CONSTRAINT platform_key_singleton CHECK (id = 1)
);

CREATE TABLE IF NOT EXISTS policies (
  policy_version text PRIMARY KEY,
  risk_threshold real NOT NULL,
  capability_ttl_seconds integer NOT NULL
);

-- ---------------------------------------------------------------------------
-- Tenant-scoped tables
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  tenant_id text NOT NULL,
  display_name text NOT NULL,
  trust_domain text NOT NULL,
  residency text NOT NULL,
  PRIMARY KEY (tenant_id)
);

CREATE TABLE IF NOT EXISTS principals (
  tenant_id text NOT NULL,
  principal_id text NOT NULL,
  kind text NOT NULL,
  trust_domain text NOT NULL,
  display_name text NOT NULL,
  attested boolean NOT NULL,
  build_hash text,
  public_key_pem text,
  PRIMARY KEY (tenant_id, principal_id)
);

CREATE TABLE IF NOT EXISTS memory_objects (
  tenant_id text NOT NULL,
  memory_id text NOT NULL,
  owner_id text NOT NULL,
  memory_class text NOT NULL,
  content jsonb NOT NULL,
  content_hash text NOT NULL,
  classification text NOT NULL,
  purpose_constraints jsonb NOT NULL,
  read_operation text NOT NULL,
  residency text NOT NULL,
  sensitive_fields jsonb NOT NULL,
  consent_basis text,
  retention_policy text NOT NULL,
  valid_until text,
  confidence real NOT NULL,
  verification_state text NOT NULL,
  revocation_state text NOT NULL,
  deletion_state text NOT NULL,
  model_identity text,
  supersedes text,
  created_at text NOT NULL,
  PRIMARY KEY (tenant_id, memory_id)
);

CREATE TABLE IF NOT EXISTS consent (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  owner_id text NOT NULL,
  purpose text NOT NULL,
  granted boolean NOT NULL,
  basis text NOT NULL,
  valid_until text NOT NULL
);

CREATE TABLE IF NOT EXISTS intents (
  tenant_id text NOT NULL,
  intent_id text NOT NULL,
  owner_id text NOT NULL,
  actor_id text NOT NULL,
  purpose text NOT NULL,
  requested_operations jsonb NOT NULL,
  prohibited_operations jsonb NOT NULL,
  constraints jsonb NOT NULL,
  required_evidence jsonb NOT NULL,
  human_gate jsonb NOT NULL,
  actor_geo text NOT NULL,
  model_id text,
  agent_build text,
  risk_score real NOT NULL,
  PRIMARY KEY (tenant_id, intent_id)
);

CREATE TABLE IF NOT EXISTS capabilities (
  tenant_id text NOT NULL,
  token_id text NOT NULL,
  actor text NOT NULL,
  subject text NOT NULL,
  intent_id text NOT NULL,
  purpose text NOT NULL,
  audience text NOT NULL,
  operations jsonb NOT NULL,
  resources jsonb NOT NULL,
  data_classification text NOT NULL,
  holder_key_pem text NOT NULL,
  environment text NOT NULL,
  risk_threshold real NOT NULL,
  approval_state text NOT NULL,
  issued_at text NOT NULL,
  expires_at text NOT NULL,
  nonce text NOT NULL,
  revocation_handle text NOT NULL,
  evidence_correlation_id text NOT NULL,
  signature text NOT NULL,
  PRIMARY KEY (tenant_id, token_id)
);

CREATE TABLE IF NOT EXISTS revocations (
  tenant_id text NOT NULL,
  revocation_handle text NOT NULL,
  token_id text NOT NULL,
  revoked_at text NOT NULL,
  PRIMARY KEY (tenant_id, revocation_handle)
);

CREATE TABLE IF NOT EXISTS action_proposals (
  tenant_id text NOT NULL,
  action_id text NOT NULL,
  intent_id text NOT NULL,
  actor text NOT NULL,
  operation text NOT NULL,
  action_class text NOT NULL,
  state text NOT NULL,
  requires_human_approval boolean NOT NULL,
  expected_effect text NOT NULL,
  reversible boolean NOT NULL,
  cost_gbp real NOT NULL,
  denied_reason text,
  PRIMARY KEY (tenant_id, action_id)
);

CREATE TABLE IF NOT EXISTS action_transitions (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  action_id text NOT NULL,
  seq integer NOT NULL,
  state text NOT NULL,
  at text NOT NULL,
  note text NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  action_id text NOT NULL,
  approver text NOT NULL,
  at text NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_envelopes (
  tenant_id text NOT NULL,
  event_id text NOT NULL,
  seq integer NOT NULL,
  trace_id text NOT NULL,
  owner_id text NOT NULL,
  principal text NOT NULL,
  intent_id text,
  policy_version text NOT NULL,
  event_type text NOT NULL,
  decision text,
  disclosed_objects jsonb NOT NULL,
  disclosure_digest text,
  capability_id text,
  tool_calls jsonb NOT NULL,
  human_approval jsonb,
  result_digest text,
  model jsonb,
  ts text NOT NULL,
  prev_hash text NOT NULL,
  hash text NOT NULL,
  signature text NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (tenant_id, seq)
);

CREATE TABLE IF NOT EXISTS events (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  kind text NOT NULL,
  payload jsonb NOT NULL,
  at text NOT NULL
);

-- ---------------------------------------------------------------------------
-- Row-Level Security for every tenant-scoped table
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'tenants','principals','memory_objects','consent','intents','capabilities',
    'revocations','action_proposals','action_transitions','approvals',
    'evidence_envelopes','events'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_isolation', t);
    EXECUTE format(
      'CREATE POLICY %I ON %I USING (tenant_id = current_setting(''app.current_tenant'', true)) WITH CHECK (tenant_id = current_setting(''app.current_tenant'', true))',
      t || '_isolation', t
    );
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Append-only enforcement on the evidence stream
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION deny_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'append-only table %: % is not permitted', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS evidence_append_only ON evidence_envelopes;
CREATE TRIGGER evidence_append_only
  BEFORE UPDATE OR DELETE ON evidence_envelopes
  FOR EACH ROW EXECUTE FUNCTION deny_mutation();

DROP TRIGGER IF EXISTS events_append_only ON events;
CREATE TRIGGER events_append_only
  BEFORE UPDATE OR DELETE ON events
  FOR EACH ROW EXECUTE FUNCTION deny_mutation();

-- ---------------------------------------------------------------------------
-- Least-privilege grants: SELECT + INSERT only, never UPDATE/DELETE
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO continuum_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO continuum_app;
