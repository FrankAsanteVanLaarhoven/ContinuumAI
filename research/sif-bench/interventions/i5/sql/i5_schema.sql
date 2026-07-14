-- Intervention I5 — database-bound tenant identity (GAP-5).
--
-- Two schemes on one database, applied as the superuser (postgres):
--
--   * BASELINE (i5_baseline) reproduces the current design: RLS keys on the
--     transaction-local GUC `app.current_tenant`, which the application role can
--     set to ANY value. The database enforces the configured tenant faithfully,
--     but the configuration itself is caller-controlled (GAP-5).
--
--   * BOUND (i5_bound) establishes tenant context ONLY through a SECURITY DEFINER
--     wrapper that resolves the tenant from an authoritative principal→tenant
--     mapping the app cannot write, and stamps a tamper-evident lock the app
--     cannot forge. Re-keying `app.current_tenant` without the matching lock makes
--     the RLS predicate fail closed.
--
-- The application role `i5_app` is NOSUPERUSER / NOBYPASSRLS and has no rights on
-- the mapping, session, or secret objects. It can still call set_config (a
-- built-in) — the bound scheme neutralises that, it does not pretend to forbid it.

-- ---------------------------------------------------------------------------
-- Application role (ordinary, unprivileged)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'i5_app') THEN
    CREATE ROLE i5_app LOGIN PASSWORD 'i5_app' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

-- ===========================================================================
-- BASELINE scheme (reproduces GAP-5)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS i5_baseline (
  tenant_id text NOT NULL,
  id        text NOT NULL,
  payload   text NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
ALTER TABLE i5_baseline ENABLE ROW LEVEL SECURITY;
ALTER TABLE i5_baseline FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS i5_baseline_iso ON i5_baseline;
CREATE POLICY i5_baseline_iso ON i5_baseline
  USING (tenant_id = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
GRANT SELECT, INSERT ON i5_baseline TO i5_app;

-- ===========================================================================
-- BOUND scheme (I5-B / I5-C)
-- ===========================================================================

-- Authoritative principal → tenant mapping. Owned by postgres; i5_app has NO
-- privileges on it and reaches a tenant only through the definer wrapper.
CREATE TABLE IF NOT EXISTS i5_principal_tenant (
  principal_id text PRIMARY KEY,
  tenant_id    text NOT NULL,
  active       boolean NOT NULL DEFAULT true
);

-- Verified session → principal binding (I5-C). A caller may only claim a
-- principal it holds a valid session for.
CREATE TABLE IF NOT EXISTS i5_session (
  session_id   text PRIMARY KEY,
  principal_id text NOT NULL,
  valid        boolean NOT NULL DEFAULT true
);

-- Immutable-ish audit of context establishment (I5-C). No protected payloads.
CREATE TABLE IF NOT EXISTS i5_context_audit (
  seq          bigserial PRIMARY KEY,
  principal_id text NOT NULL,
  session_id   text,
  tenant_id    text NOT NULL,
  established_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS i5_bound (
  tenant_id text NOT NULL,
  id        text NOT NULL,
  payload   text NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
ALTER TABLE i5_bound ENABLE ROW LEVEL SECURITY;
ALTER TABLE i5_bound FORCE ROW LEVEL SECURITY;

-- Tamper-evident lock check. SECURITY DEFINER, owned by postgres, so it reads the
-- secret even when i5_app is the querying role. Demonstration MAC: md5(tenant ||
-- secret) — the app cannot recompute it for a foreign tenant without the secret.
-- (Production upgrade: HMAC-SHA256 via pgcrypto or an app-side KMS key.)
CREATE OR REPLACE FUNCTION i5_tenant_context_valid() RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER STABLE AS $$
DECLARE
  t text := current_setting('app.current_tenant', true);
  l text := current_setting('app.tenant_lock', true);
BEGIN
  IF t IS NULL OR t = '' OR l IS NULL OR l = '' THEN
    RETURN false; -- fail closed when context is absent
  END IF;
  RETURN l = md5(t || ':i5-tenant-binding-secret-2026');
END $$;

-- I5-B: establish context from a resolved tenant, refusing any caller-supplied
-- tenant (the caller passes a PRINCIPAL, never a tenant). Sets the lock so a later
-- re-key of app.current_tenant cannot pass i5_tenant_context_valid().
CREATE OR REPLACE FUNCTION i5_begin_b(p_principal text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE resolved text;
BEGIN
  SELECT tenant_id INTO resolved FROM i5_principal_tenant
    WHERE principal_id = p_principal AND active = true;
  IF resolved IS NULL THEN
    RAISE EXCEPTION 'i5: no active tenant mapping for principal %', p_principal
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM set_config('app.current_tenant', resolved, true);
  PERFORM set_config('app.tenant_lock', md5(resolved || ':i5-tenant-binding-secret-2026'), true);
  RETURN resolved;
END $$;

-- I5-C: additionally bind the caller to a verified session, refusing a claimed
-- principal the session does not authenticate, and record an audit event.
CREATE OR REPLACE FUNCTION i5_begin_c(p_principal text, p_session text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE resolved text; sess_ok boolean;
BEGIN
  SELECT true INTO sess_ok FROM i5_session
    WHERE session_id = p_session AND principal_id = p_principal AND valid = true;
  IF sess_ok IS NULL THEN
    RAISE EXCEPTION 'i5: session % does not authenticate principal %', p_session, p_principal
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT tenant_id INTO resolved FROM i5_principal_tenant
    WHERE principal_id = p_principal AND active = true;
  IF resolved IS NULL THEN
    RAISE EXCEPTION 'i5: no active tenant mapping for principal %', p_principal
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM set_config('app.current_tenant', resolved, true);
  PERFORM set_config('app.tenant_lock', md5(resolved || ':i5-tenant-binding-secret-2026'), true);
  PERFORM set_config('app.current_principal', p_principal, true);
  INSERT INTO i5_context_audit (principal_id, session_id, tenant_id)
    VALUES (p_principal, p_session, resolved);
  RETURN resolved;
END $$;

DROP POLICY IF EXISTS i5_bound_iso ON i5_bound;
CREATE POLICY i5_bound_iso ON i5_bound
  USING (tenant_id = current_setting('app.current_tenant', true) AND i5_tenant_context_valid())
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true) AND i5_tenant_context_valid());

-- i5_app may read/write only through the bound policy, and may call ONLY the
-- wrappers + the predicate. It gets NO rights on the mapping/session/secret and
-- cannot execute a raw lock oracle.
GRANT SELECT, INSERT ON i5_bound TO i5_app;
REVOKE ALL ON FUNCTION i5_begin_b(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION i5_begin_c(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION i5_tenant_context_valid() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION i5_begin_b(text) TO i5_app;
GRANT EXECUTE ON FUNCTION i5_begin_c(text, text) TO i5_app;
GRANT EXECUTE ON FUNCTION i5_tenant_context_valid() TO i5_app;
-- i5_context_audit is written only inside the definer; i5_app may read its own
-- context audit for evidence completeness but never write it directly.
GRANT SELECT ON i5_context_audit TO i5_app;
