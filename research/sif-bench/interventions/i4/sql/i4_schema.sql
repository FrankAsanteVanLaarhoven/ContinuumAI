-- Intervention I4 — proof-of-possession replay resistance (GAP-4).
--
-- The current PoP is sign(holder_key, "<token_id>:<nonce>:<challenge>") with a
-- caller-supplied, fixed challenge and NO server-side consumption, so a captured
-- (challenge, signature) pair verifies repeatedly within the TTL (concurrency
-- baseline C1-10). Two schemes on one database, applied as the superuser:
--
--   * BASELINE (A) verifies the signature only and records the verification. It
--     never consumes anything, so a replayed proof verifies again (GAP-4), and two
--     concurrent presentations of one proof both succeed (double-spend).
--
--   * BOUND (B/C) consumes a server-issued nonce EXACTLY ONCE via a transactional
--     replay ledger: INSERT ... ON CONFLICT DO NOTHING on the (token_id, nonce)
--     primary key. The winner consumes; a replay (or a concurrent double-spend)
--     fails to insert and is rejected. C additionally binds the proof to the
--     request digest, capability id, and audience by signing over them, so a
--     fresh-nonce proof lifted onto a different request/audience/capability fails
--     the signature check (a binding B does not perform).
--
-- The application role i4_app is NOSUPERUSER / NOBYPASSRLS.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'i4_app') THEN
    CREATE ROLE i4_app LOGIN PASSWORD 'i4_app' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

-- ===========================================================================
-- BASELINE scheme (reproduces GAP-4): signature-only, no consumption.
-- Every accepted verification appends a row, so a replay produces a second row.
-- ===========================================================================
CREATE TABLE IF NOT EXISTS i4_baseline_verification (
  seq          bigserial PRIMARY KEY,
  token_id     text NOT NULL,
  nonce        text NOT NULL,
  context_digest text NOT NULL,       -- digest of the presented (request, cap, audience)
  verified_at  timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT ON i4_baseline_verification TO i4_app;
GRANT USAGE, SELECT ON SEQUENCE i4_baseline_verification_seq_seq TO i4_app;

-- ===========================================================================
-- BOUND scheme (I4-B / I4-C): the transactional replay ledger.
-- A proof is consumable AT MOST ONCE per (token_id, nonce).
-- ===========================================================================
CREATE TABLE IF NOT EXISTS i4_consumed_proof (
  token_id       text NOT NULL,
  nonce          text NOT NULL,
  request_digest text NOT NULL,       -- the presented request the proof authorized
  capability_id  text NOT NULL,
  audience       text NOT NULL,
  consumed_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (token_id, nonce)        -- one consumption per issued nonce
);
GRANT SELECT, INSERT ON i4_consumed_proof TO i4_app;

-- Bounded audit. The raw Ed25519 signature is NEVER stored — only a digest of it.
CREATE TABLE IF NOT EXISTS i4_evidence (
  seq           bigserial PRIMARY KEY,
  token_id      text NOT NULL,
  nonce         text NOT NULL,
  signature_digest text NOT NULL,     -- sha256 of the presented signature, not the raw value
  bound_request_digest text NOT NULL,
  capability_id text NOT NULL,
  audience      text NOT NULL,
  decision      text NOT NULL,        -- CONSUMED | REPLAY_REJECTED | BINDING_MISMATCH | EXPIRED | BAD_SIGNATURE | MISSING_PROOF | ACCEPTED_NO_LEDGER
  classification text NOT NULL,       -- benign | replay | double_spend | lift_request | lift_audience | lift_capability | expired | nonholder | missing
  recorded_at   timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT ON i4_evidence TO i4_app;
GRANT USAGE, SELECT ON SEQUENCE i4_evidence_seq_seq TO i4_app;
