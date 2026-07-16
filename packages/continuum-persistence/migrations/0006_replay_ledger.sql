-- Continuum — Phase 3 S4A: durable replay ledger (persistence).
--
-- Backs the real (jose) verifier's replay/nonce protection where an issuer's
-- replay policy is active. Stores only a KEYED digest of the replay identifier
-- (nonce or jti) — never the raw value. Consumption is atomic and insert-first:
-- a uniqueness constraint decides the winner, so two concurrent attempts with the
-- same identifier yield exactly one acceptance.
--
-- The ledger is tenant-INDEPENDENT at assertion-verification time and is scoped by
-- (issuer, replay_kind). It is owned by the pre-tenant identity/session concern, so
-- it is served by the existing least-privilege continuum_session role, which still
-- has NO tenant authority path.

CREATE TABLE IF NOT EXISTS continuum.replay_ledger (
  replay_id    uuid PRIMARY KEY,
  issuer       text NOT NULL,
  replay_kind  text NOT NULL,          -- nonce | jti
  digest       text NOT NULL,          -- keyed digest of the identifier; never raw
  expires_at   timestamptz NOT NULL,   -- bounded by assertion lifetime + retention
  consumed_at  timestamptz NOT NULL DEFAULT now(),
  request_id   text NOT NULL,
  CONSTRAINT replay_ledger_unique UNIQUE (issuer, replay_kind, digest)
);

CREATE INDEX IF NOT EXISTS replay_ledger_expires_idx ON continuum.replay_ledger (expires_at);

-- Prune is restricted to ALREADY-EXPIRED rows via a SECURITY DEFINER function, so a
-- compromised session role cannot delete a still-live consumed entry to re-enable a
-- replay. The session role gets EXECUTE on the pruner, but NO direct DELETE.
CREATE OR REPLACE FUNCTION continuum.prune_replay_ledger(p_now timestamptz)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = continuum, pg_temp
AS $$
DECLARE
  removed bigint;
BEGIN
  DELETE FROM continuum.replay_ledger WHERE expires_at <= p_now;
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END;
$$;

ALTER FUNCTION continuum.prune_replay_ledger(timestamptz) OWNER TO continuum_authctx;

-- The definer (continuum_authctx) needs DELETE to prune, plus SELECT because the
-- prune predicate reads expires_at (a DELETE that reads a column requires SELECT on
-- it). Nobody else gets DELETE.
GRANT SELECT, DELETE ON continuum.replay_ledger TO continuum_authctx;

-- Session-service role: verify replays (SELECT/INSERT) and prune expired entries
-- (EXECUTE only). No direct DELETE, no tenant path.
GRANT SELECT, INSERT ON continuum.replay_ledger TO continuum_session;
GRANT EXECUTE ON FUNCTION continuum.prune_replay_ledger(timestamptz) TO continuum_session;

-- Deliberately NOT granted: UPDATE/DELETE on replay_ledger to continuum_session,
-- and any access to tenant_memberships / public.* — replay verification never
-- derives or grants a tenant.
