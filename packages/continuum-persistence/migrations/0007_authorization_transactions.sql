-- Continuum — Phase 3 S4B: authorization-code transaction boundary (persistence).
--
-- A persisted, single-use authorization-code transaction: state and nonce are keyed
-- digests (never raw); the PKCE verifier is stored ENCRYPTED-at-rest (recoverable for
-- code exchange, never a one-way digest); issuer/client/redirect bindings are
-- immutable. Consumption is atomic and one-time. The row is never DELETEd (audit is
-- preserved); expiry marks status. Served by the least-privilege continuum_session
-- role, which has no tenant path — a completed login still carries no tenant authority.

CREATE TABLE IF NOT EXISTS continuum.authorization_transactions (
  transaction_id            uuid PRIMARY KEY,
  state_digest              text NOT NULL,
  nonce_digest              text NOT NULL,
  pkce_verifier_secret      text NOT NULL,           -- encrypted-at-rest ciphertext; never raw/digest
  pkce_verifier_key_version text NOT NULL,
  pkce_challenge            text NOT NULL,
  pkce_method               text NOT NULL DEFAULT 'S256',
  issuer                    text NOT NULL,
  client_id                 text NOT NULL,
  redirect_uri              text NOT NULL,
  created_at                timestamptz NOT NULL DEFAULT now(),
  expires_at                timestamptz NOT NULL,
  consumed_at               timestamptz,
  consumption_request_id    text,
  status                    text NOT NULL DEFAULT 'pending',
  failure_reason            text,
  attempt_count             int NOT NULL DEFAULT 0,
  policy_version            text NOT NULL,
  CONSTRAINT authz_state_digest_unique UNIQUE (state_digest),
  CONSTRAINT authz_pkce_method_chk CHECK (pkce_method = 'S256'),   -- plain PKCE unsupported
  -- Terminal failure is categorized by the stage that failed; all stay consumed.
  CONSTRAINT authz_status_chk CHECK (status IN (
    'pending','consuming','completed','expired',
    'failed','exchange_failed','verification_failed','nonce_failed','mapping_failed','session_failed'
  )),
  -- consumed-state consistency: unconsumed ⇒ pending|expired; consumed ⇒ a consuming/terminal status.
  CONSTRAINT authz_consumed_consistency CHECK (
    (consumed_at IS NULL AND status IN ('pending','expired'))
    OR (consumed_at IS NOT NULL AND status IN (
      'consuming','completed','failed','exchange_failed','verification_failed','nonce_failed','mapping_failed','session_failed'
    ))
  )
);

CREATE INDEX IF NOT EXISTS authz_transactions_expires_idx ON continuum.authorization_transactions (expires_at);

-- Correlation column on the shared identity/session evidence stream (0005).
ALTER TABLE continuum.auth_events ADD COLUMN IF NOT EXISTS transaction_digest text;

-- ---------------------------------------------------------------------------
-- Atomic one-time consumption. Exactly one concurrent callback acquires the
-- transaction (row lock via the guarded UPDATE); the rest see it consumed. On
-- miss, classify unknown / already_consumed / expired. No read-then-update path.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION continuum.consume_authorization_transaction(
  p_state_digest text, p_request_id text, p_now timestamptz
) RETURNS TABLE(
  outcome text, transaction_id uuid, issuer text, client_id text, redirect_uri text,
  nonce_digest text, pkce_verifier_secret text, pkce_verifier_key_version text,
  pkce_challenge text, policy_version text
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = continuum, pg_temp
AS $$
DECLARE
  v RECORD;
BEGIN
  UPDATE continuum.authorization_transactions t
     SET consumed_at = p_now, consumption_request_id = p_request_id,
         status = 'consuming', attempt_count = t.attempt_count + 1
   WHERE t.state_digest = p_state_digest
     AND t.consumed_at IS NULL
     AND t.expires_at > p_now
  RETURNING t.transaction_id, t.issuer, t.client_id, t.redirect_uri, t.nonce_digest,
            t.pkce_verifier_secret, t.pkce_verifier_key_version, t.pkce_challenge, t.policy_version
    INTO v;

  IF FOUND THEN
    outcome := 'consumed';
    transaction_id := v.transaction_id; issuer := v.issuer; client_id := v.client_id;
    redirect_uri := v.redirect_uri; nonce_digest := v.nonce_digest;
    pkce_verifier_secret := v.pkce_verifier_secret; pkce_verifier_key_version := v.pkce_verifier_key_version;
    pkce_challenge := v.pkce_challenge; policy_version := v.policy_version;
    RETURN NEXT; RETURN;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM continuum.authorization_transactions WHERE state_digest = p_state_digest) THEN
    outcome := 'unknown';
  ELSIF EXISTS (SELECT 1 FROM continuum.authorization_transactions WHERE state_digest = p_state_digest AND consumed_at IS NOT NULL) THEN
    outcome := 'already_consumed';
  ELSE
    outcome := 'expired';
  END IF;
  RETURN NEXT; RETURN;
END;
$$;

-- Terminal status writer (consuming → completed|failed only). Audit accuracy.
CREATE OR REPLACE FUNCTION continuum.finalize_authorization_transaction(
  p_transaction_id uuid, p_status text, p_failure_reason text, p_request_id text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = continuum, pg_temp
AS $$
BEGIN
  IF p_status NOT IN ('completed','failed','exchange_failed','verification_failed','nonce_failed','mapping_failed','session_failed') THEN
    RAISE EXCEPTION 'invalid terminal status %', p_status;
  END IF;
  UPDATE continuum.authorization_transactions
     SET status = p_status, failure_reason = p_failure_reason
   WHERE transaction_id = p_transaction_id AND status = 'consuming';
END;
$$;

-- Expiry marks still-pending transactions (never DELETE — audit evidence is preserved).
CREATE OR REPLACE FUNCTION continuum.expire_authorization_transactions(p_now timestamptz)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = continuum, pg_temp
AS $$
DECLARE n bigint;
BEGIN
  UPDATE continuum.authorization_transactions
     SET status = 'expired'
   WHERE status = 'pending' AND consumed_at IS NULL AND expires_at <= p_now;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END;
$$;

ALTER FUNCTION continuum.consume_authorization_transaction(text, text, timestamptz) OWNER TO continuum_authctx;
ALTER FUNCTION continuum.finalize_authorization_transaction(uuid, text, text, text) OWNER TO continuum_authctx;
ALTER FUNCTION continuum.expire_authorization_transactions(timestamptz) OWNER TO continuum_authctx;

-- The definer (continuum_authctx) needs SELECT + UPDATE (the guarded UPDATEs read
-- columns in their WHERE clauses). It never DELETEs.
GRANT SELECT, UPDATE ON continuum.authorization_transactions TO continuum_authctx;

-- Session-service role: create transactions (INSERT) and drive consumption/expiry
-- only through the narrow definer functions. NO direct UPDATE/DELETE, no tenant path.
GRANT INSERT ON continuum.authorization_transactions TO continuum_session;
GRANT EXECUTE ON FUNCTION continuum.consume_authorization_transaction(text, text, timestamptz) TO continuum_session;
GRANT EXECUTE ON FUNCTION continuum.finalize_authorization_transaction(uuid, text, text, text) TO continuum_session;
GRANT EXECUTE ON FUNCTION continuum.expire_authorization_transactions(timestamptz) TO continuum_session;

-- Deliberately NOT granted to continuum_session: UPDATE/DELETE on
-- authorization_transactions, and any tenant_memberships / public.* access.
