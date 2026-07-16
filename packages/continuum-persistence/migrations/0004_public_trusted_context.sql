-- Continuum — Phase 3 S2B: migrate the real public.* data plane off the
-- application-cooperative `app.current_tenant` GUC and onto privilege-unforgeable
-- tenant context derived from the trusted principal/session/membership function.
--
-- BEFORE (0001/0002): every public.* policy was
--     tenant_id = current_setting('app.current_tenant', true)
--   The application role sets that GUC itself, so any `set_config` chose a tenant.
--
-- AFTER (this migration): every public.* policy is
--     tenant_id = continuum.current_tenant()
--   continuum.current_tenant() returns a tenant ONLY when the transaction-local
--   (principal, session, membership, tenant) context corresponds to an active
--   session for that principal, an active (non-suspended, non-deleted) principal,
--   and the EXACT owned active membership that names that tenant. A raw
--   `set_config('app.current_tenant', ...)` with no backing session/membership —
--   or one that names a tenant other than the established membership's — yields
--   NULL, so the predicate is false and nothing is visible or insertable.
--
-- The context is established ONLY through the SECURITY DEFINER function
-- continuum.begin_authenticated_context (0003), which takes identity/session
-- references and DERIVES the tenant. The application role cannot write the
-- identity tables and cannot fabricate a valid membership id it does not own, so
-- it cannot manufacture authority by setting GUCs. Superusers still bypass RLS by
-- design (documented non-goal); the function owner (continuum_authctx) is a narrow
-- non-login role.

-- ---------------------------------------------------------------------------
-- Strengthen current_tenant(): pin to the ACTIVE principal and the EXACT owned
-- active membership, not merely "some membership for (principal, tenant)". This
-- makes principal suspension and membership revocation take effect immediately at
-- the RLS layer (re-evaluated per statement), and makes tenant-switching require
-- re-establishing context with a different owned active membership rather than
-- merely re-writing the tenant GUC. Replaces the 0003 definition in place;
-- ownership and grants are unchanged (re-asserted below for reproducibility).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION continuum.current_tenant()
RETURNS text
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, continuum
AS $fn$
DECLARE
  v_principal  uuid := nullif(current_setting('app.current_principal', true), '')::uuid;
  v_session    uuid := nullif(current_setting('app.current_session', true), '')::uuid;
  v_membership uuid := nullif(current_setting('app.current_membership', true), '')::uuid;
  v_tenant     text := nullif(current_setting('app.current_tenant', true), '');
  v_now        timestamptz := now();
BEGIN
  IF v_principal IS NULL OR v_session IS NULL OR v_membership IS NULL OR v_tenant IS NULL THEN
    RETURN NULL;
  END IF;
  -- active session that belongs to the principal
  PERFORM 1 FROM continuum.authenticated_sessions s
    WHERE s.session_id = v_session AND s.principal_id = v_principal
      AND s.revoked_at IS NULL AND s.idle_expires_at > v_now AND s.absolute_expires_at > v_now;
  IF NOT FOUND THEN RETURN NULL; END IF;
  -- principal is active (suspension/deletion revokes authority mid-flight too)
  PERFORM 1 FROM continuum.principals p
    WHERE p.principal_id = v_principal AND p.status = 'active'
      AND p.suspended_at IS NULL AND p.deleted_at IS NULL;
  IF NOT FOUND THEN RETURN NULL; END IF;
  -- the EXACT membership must be active, owned by the principal, and name this tenant
  PERFORM 1 FROM continuum.tenant_memberships m
    WHERE m.membership_id = v_membership AND m.principal_id = v_principal
      AND m.tenant_id = v_tenant AND m.status = 'active' AND m.revoked_at IS NULL
      AND m.valid_from <= v_now AND (m.valid_until IS NULL OR m.valid_until > v_now);
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN v_tenant;
END;
$fn$;

ALTER FUNCTION continuum.current_tenant() OWNER TO continuum_authctx;
REVOKE ALL ON FUNCTION continuum.current_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION continuum.current_tenant() TO continuum_app, continuum_authctx;

-- ---------------------------------------------------------------------------
-- Rewire every tenant-scoped public.* policy (0001) + consumed_proofs (0002) to
-- the trusted context. ENABLE/FORCE RLS is already set by 0001/0002 and is left
-- unchanged; only the USING/WITH CHECK predicate moves from the raw GUC to
-- continuum.current_tenant(). The policy name is preserved so this is a drop-in
-- replacement, not a second overlapping policy.
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'tenants','principals','memory_objects','consent','intents','capabilities',
    'revocations','action_proposals','action_transitions','approvals',
    'evidence_envelopes','events','consumed_proofs'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_isolation', t);
    EXECUTE format(
      'CREATE POLICY %I ON %I USING (tenant_id = continuum.current_tenant()) WITH CHECK (tenant_id = continuum.current_tenant())',
      t || '_isolation', t
    );
  END LOOP;
END $$;

-- The application role already holds EXECUTE on continuum.current_tenant() (0003)
-- and USAGE on the continuum schema, which is all it needs to have the rewired
-- policies evaluate. It still holds NO privileges on the identity/membership
-- tables and cannot set authority except by presenting a real (principal, session,
-- membership) triple through begin_authenticated_context.
