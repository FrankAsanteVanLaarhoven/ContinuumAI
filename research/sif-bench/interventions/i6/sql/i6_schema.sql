-- Intervention I6 — idempotent, server-issued action identity (GAP-6).
--
-- Two schemes on one database, applied as the superuser (postgres):
--
--   * BASELINE (i6_baseline_action) reproduces the current design: the caller
--     supplies action_id and a create silently overwrites any existing row with
--     the same id (INSERT ... ON CONFLICT (action_id) DO UPDATE), and every create
--     executes — so a reused id overwrites and a retry re-executes (GAP-6).
--
--   * BOUND (i6_action) issues the action_id server-side, requires a caller
--     idempotency key, binds a canonical request digest, and enforces exactly one
--     authoritative record per idempotency domain via a UNIQUE constraint plus a
--     transactionally-safe INSERT ... ON CONFLICT DO NOTHING + SELECT (never DO
--     UPDATE). Execution is gated on winning the insert and is itself idempotent.
--
-- The application role i6_app is NOSUPERUSER / NOBYPASSRLS.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'i6_app') THEN
    CREATE ROLE i6_app LOGIN PASSWORD 'i6_app' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

-- ===========================================================================
-- BASELINE scheme (reproduces GAP-6)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS i6_baseline_action (
  action_id     text PRIMARY KEY,          -- caller-chosen (the vulnerability)
  tenant_id     text NOT NULL,
  principal_id  text NOT NULL,
  operation     text NOT NULL,
  request_digest text NOT NULL,
  state         text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
-- Baseline records execution attempts with NO idempotency, so retries duplicate.
CREATE TABLE IF NOT EXISTS i6_baseline_execution (
  seq        bigserial PRIMARY KEY,
  action_id  text NOT NULL,
  executed_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON i6_baseline_action TO i6_app;
GRANT SELECT, INSERT ON i6_baseline_execution TO i6_app;
GRANT USAGE, SELECT ON SEQUENCE i6_baseline_execution_seq_seq TO i6_app;

-- ===========================================================================
-- BOUND scheme (I6-B / I6-C)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS i6_action (
  action_id     text PRIMARY KEY DEFAULT ('act_' || gen_random_uuid()),  -- server-issued
  tenant_id     text NOT NULL,
  principal_id  text NOT NULL,
  intent_id     text,
  operation     text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest  text NOT NULL,
  digest_alg     text NOT NULL DEFAULT 'sha256/continuum-canonical-v1',
  state          text NOT NULL,             -- CREATED | EXECUTED | DENIED
  outcome        text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  terminal_at    timestamptz,
  original_action_id text,
  policy_version text,
  capability_id  text,
  evidence_ref   text,
  -- Exactly one authoritative record per idempotency domain.
  UNIQUE (tenant_id, principal_id, operation, idempotency_key)
);

-- Execution-level idempotency: at most one execution row per action_id.
CREATE TABLE IF NOT EXISTS i6_execution (
  action_id   text PRIMARY KEY,
  executed_at timestamptz NOT NULL DEFAULT now()
);

-- Bounded audit. The raw idempotency key is NEVER stored — only a keyed digest.
CREATE TABLE IF NOT EXISTS i6_evidence (
  seq          bigserial PRIMARY KEY,
  tenant_id    text NOT NULL,
  principal_id text NOT NULL,
  intent_id    text,
  operation    text NOT NULL,
  idempotency_key_digest text NOT NULL,   -- md5(key||secret), not the raw key
  request_digest text NOT NULL,
  action_id    text,
  original_action_id text,
  decision     text NOT NULL,             -- CREATED | REPLAYED | CONFLICT | DENIED | EXEC_PREVENTED
  state        text,
  policy_version text,
  capability_id text,
  classification text NOT NULL,           -- create | replay | conflict | missing_key | exec_prevented
  recorded_at  timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON i6_action TO i6_app;
GRANT SELECT, INSERT ON i6_execution TO i6_app;
GRANT SELECT, INSERT ON i6_evidence TO i6_app;
GRANT USAGE, SELECT ON SEQUENCE i6_evidence_seq_seq TO i6_app;
