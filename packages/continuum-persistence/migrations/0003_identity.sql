-- Continuum — Phase 3 S1+S2: identity, membership, session schema + the narrow
-- trusted database-context establishment function.
--
-- This is the authentication DATA layer and the SECURITY DEFINER trust boundary.
-- It does NOT implement OIDC, sessions middleware, or any provider integration —
-- those are later, separately-reviewed steps. Held for review; not wired into the
-- existing public data-plane RLS yet (that is a later migration step, S4/S5).
--
-- Design (per docs/PHASE3_AUTH_SPEC.md):
--   * The context function's input is trusted identity/session references ONLY —
--     never an authoritative tenant. It DERIVES the tenant from a revalidated
--     membership.
--   * It is owned by a dedicated NON-LOGIN role (not the app role, not a superuser),
--     uses a fixed schema-qualified search_path, and PUBLIC execution is revoked.
--   * The app role holds ONLY EXECUTE on the function and has no ability to mutate
--     memberships or to create tenant authority via a raw GUC.

-- ---------------------------------------------------------------------------
-- Dedicated non-login role that OWNS the trusted functions (SECURITY DEFINER runs
-- with THIS role's privileges — deliberately narrow, never superuser).
-- ---------------------------------------------------------------------------
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'continuum_authctx') THEN
    CREATE ROLE continuum_authctx NOLOGIN NOSUPERUSER;
  END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS continuum AUTHORIZATION postgres;
GRANT USAGE ON SCHEMA continuum TO continuum_app, continuum_authctx;

-- ---------------------------------------------------------------------------
-- Identity tables (global identity plane — NOT the tenant-scoped slice principals
-- in public.principals). Access is mediated by the trusted functions.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS continuum.principals (
  principal_id   uuid PRIMARY KEY,
  principal_type text NOT NULL,                 -- human|service|agent|workload|device|break_glass
  status         text NOT NULL DEFAULT 'active',-- active|suspended|deleted
  created_at     timestamptz NOT NULL DEFAULT now(),
  suspended_at   timestamptz,
  deleted_at     timestamptz,
  version        bigint NOT NULL DEFAULT 1
);

-- External identity keyed by the (issuer, subject) PAIR — never subject alone.
CREATE TABLE IF NOT EXISTS continuum.external_identities (
  external_identity_id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES continuum.principals(principal_id),
  issuer  text NOT NULL,
  subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (issuer, subject)
);

-- tenant_id is a LOGICAL reference to public.tenants(tenant_id) (no hard FK so the
-- identity plane is independently testable/migratable).
CREATE TABLE IF NOT EXISTS continuum.tenant_memberships (
  membership_id uuid PRIMARY KEY,
  principal_id  uuid NOT NULL REFERENCES continuum.principals(principal_id),
  tenant_id     text NOT NULL,
  status        text NOT NULL DEFAULT 'active', -- active|suspended|revoked
  role          text NOT NULL DEFAULT 'member',
  valid_from    timestamptz NOT NULL DEFAULT now(),
  valid_until   timestamptz,
  version       bigint NOT NULL DEFAULT 1,
  created_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz
);

-- Sessions store a DIGEST, never raw bearer material.
CREATE TABLE IF NOT EXISTS continuum.authenticated_sessions (
  session_id           uuid PRIMARY KEY,
  principal_id         uuid NOT NULL REFERENCES continuum.principals(principal_id),
  credential_digest    text NOT NULL,
  issued_at            timestamptz NOT NULL DEFAULT now(),
  last_seen_at         timestamptz NOT NULL DEFAULT now(),
  idle_expires_at      timestamptz NOT NULL,
  absolute_expires_at  timestamptz NOT NULL,
  revoked_at           timestamptz,
  authentication_strength text NOT NULL DEFAULT 'single_factor',
  identity_version     bigint NOT NULL DEFAULT 1
);

-- Delegation + break-glass (schema only in S1; behaviour in S5/S7).
CREATE TABLE IF NOT EXISTS continuum.delegations (
  delegation_id          uuid PRIMARY KEY,
  delegator_principal_id uuid NOT NULL REFERENCES continuum.principals(principal_id),
  delegate_principal_id  uuid NOT NULL REFERENCES continuum.principals(principal_id),
  tenant_id              text NOT NULL,
  permitted_operations   jsonb NOT NULL DEFAULT '[]'::jsonb,
  valid_from             timestamptz NOT NULL DEFAULT now(),
  valid_until            timestamptz,
  transitive             boolean NOT NULL DEFAULT false,
  status                 text NOT NULL DEFAULT 'active',
  created_at             timestamptz NOT NULL DEFAULT now(),
  revoked_at             timestamptz
);

CREATE TABLE IF NOT EXISTS continuum.break_glass_grants (
  grant_id     uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES continuum.principals(principal_id),
  tenant_id    text NOT NULL,
  reason       text NOT NULL,
  opened_at    timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  closed_at    timestamptz,
  status       text NOT NULL DEFAULT 'open'
);

-- The trusted functions read the identity tables as their owner (authctx).
GRANT SELECT ON ALL TABLES IN SCHEMA continuum TO continuum_authctx;

-- ---------------------------------------------------------------------------
-- current_tenant(): the RLS helper. Returns the effective tenant ONLY when the
-- transaction-local (principal, session, tenant) triple corresponds to an ACTIVE
-- session for that principal AND an ACTIVE membership for (principal, tenant). A
-- raw set_config of app.current_tenant with no backing session/membership yields
-- NULL — so a forged GUC cannot create authority.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION continuum.current_tenant()
RETURNS text
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, continuum
AS $fn$
DECLARE
  v_principal uuid := nullif(current_setting('app.current_principal', true), '')::uuid;
  v_session   uuid := nullif(current_setting('app.current_session', true), '')::uuid;
  v_tenant    text := nullif(current_setting('app.current_tenant', true), '');
  v_now       timestamptz := now();
BEGIN
  IF v_principal IS NULL OR v_session IS NULL OR v_tenant IS NULL THEN
    RETURN NULL;
  END IF;
  PERFORM 1 FROM continuum.authenticated_sessions s
    WHERE s.session_id = v_session AND s.principal_id = v_principal
      AND s.revoked_at IS NULL AND s.idle_expires_at > v_now AND s.absolute_expires_at > v_now;
  IF NOT FOUND THEN RETURN NULL; END IF;
  PERFORM 1 FROM continuum.tenant_memberships m
    WHERE m.principal_id = v_principal AND m.tenant_id = v_tenant AND m.status = 'active'
      AND m.revoked_at IS NULL AND m.valid_from <= v_now
      AND (m.valid_until IS NULL OR m.valid_until > v_now);
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN v_tenant;
END;
$fn$;

-- ---------------------------------------------------------------------------
-- begin_authenticated_context(): the narrow trusted boundary. Input is identity/
-- session references ONLY — never an authoritative tenant. p_requested_membership_id
-- may SELECT among the principal's active memberships; it never GRANTS one.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION continuum.begin_authenticated_context(
  p_principal_id            uuid,
  p_session_id              uuid,
  p_request_id              uuid,
  p_requested_membership_id uuid DEFAULT NULL
)
RETURNS TABLE (principal_id uuid, tenant_id text, membership_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, continuum
AS $fn$
DECLARE
  v_now        timestamptz := now();
  v_principal  continuum.principals%ROWTYPE;
  v_session    continuum.authenticated_sessions%ROWTYPE;
  v_membership continuum.tenant_memberships%ROWTYPE;
  v_count      int;
BEGIN
  -- 1+2. principal exists and is active
  SELECT * INTO v_principal FROM continuum.principals WHERE continuum.principals.principal_id = p_principal_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'auth_context_denied: unknown principal'; END IF;
  IF v_principal.status <> 'active' OR v_principal.suspended_at IS NOT NULL OR v_principal.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'auth_context_denied: principal not active';
  END IF;

  -- 3. session active and belongs to the principal
  SELECT * INTO v_session FROM continuum.authenticated_sessions WHERE session_id = p_session_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'auth_context_denied: unknown session'; END IF;
  IF v_session.principal_id <> p_principal_id THEN RAISE EXCEPTION 'auth_context_denied: session does not belong to principal'; END IF;
  IF v_session.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'auth_context_denied: session revoked'; END IF;
  IF v_session.idle_expires_at <= v_now OR v_session.absolute_expires_at <= v_now THEN RAISE EXCEPTION 'auth_context_denied: session expired'; END IF;
  IF v_session.identity_version <> v_principal.version THEN RAISE EXCEPTION 'auth_context_denied: identity version stale'; END IF;

  -- 4+5. resolve the active membership; ambiguous without an explicit selection ⇒ deny
  IF p_requested_membership_id IS NOT NULL THEN
    SELECT * INTO v_membership FROM continuum.tenant_memberships
      WHERE continuum.tenant_memberships.membership_id = p_requested_membership_id
        AND continuum.tenant_memberships.principal_id = p_principal_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'auth_context_denied: requested membership not owned by principal'; END IF;
  ELSE
    SELECT count(*) INTO v_count FROM continuum.tenant_memberships m
      WHERE m.principal_id = p_principal_id AND m.status = 'active' AND m.revoked_at IS NULL
        AND m.valid_from <= v_now AND (m.valid_until IS NULL OR m.valid_until > v_now);
    IF v_count = 0 THEN RAISE EXCEPTION 'auth_context_denied: no active membership'; END IF;
    IF v_count > 1 THEN RAISE EXCEPTION 'auth_context_denied: ambiguous membership — explicit selection required'; END IF;
    SELECT * INTO v_membership FROM continuum.tenant_memberships m
      WHERE m.principal_id = p_principal_id AND m.status = 'active' AND m.revoked_at IS NULL
        AND m.valid_from <= v_now AND (m.valid_until IS NULL OR m.valid_until > v_now);
  END IF;

  -- the selected/derived membership must be active and current
  IF v_membership.status <> 'active' OR v_membership.revoked_at IS NOT NULL
     OR v_membership.valid_from > v_now OR (v_membership.valid_until IS NOT NULL AND v_membership.valid_until <= v_now) THEN
    RAISE EXCEPTION 'auth_context_denied: membership not active';
  END IF;

  -- 6. set transaction-local context (never session-level)
  PERFORM set_config('app.current_principal',  p_principal_id::text,          true);
  PERFORM set_config('app.current_tenant',     v_membership.tenant_id,        true);
  PERFORM set_config('app.current_membership', v_membership.membership_id::text, true);
  PERFORM set_config('app.current_session',    p_session_id::text,            true);
  PERFORM set_config('app.current_request',    p_request_id::text,            true);

  -- 7. return only non-sensitive derived metadata
  RETURN QUERY SELECT p_principal_id, v_membership.tenant_id, v_membership.membership_id;
END;
$fn$;

-- Owner + hardening: dedicated non-login role, PUBLIC execute revoked, app EXECUTE only.
ALTER FUNCTION continuum.current_tenant() OWNER TO continuum_authctx;
ALTER FUNCTION continuum.begin_authenticated_context(uuid, uuid, uuid, uuid) OWNER TO continuum_authctx;
REVOKE ALL ON FUNCTION continuum.current_tenant() FROM PUBLIC;
REVOKE ALL ON FUNCTION continuum.begin_authenticated_context(uuid, uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION continuum.current_tenant() TO continuum_app, continuum_authctx;
GRANT EXECUTE ON FUNCTION continuum.begin_authenticated_context(uuid, uuid, uuid, uuid) TO continuum_app;

-- ---------------------------------------------------------------------------
-- context_probe: a demonstration RLS table whose visibility is derived from the
-- VERIFIED context (current_tenant()), proving that a forged app.current_tenant
-- GUC without a backing session/membership yields no authority.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS continuum.context_probe (
  tenant_id text NOT NULL,
  note text NOT NULL
);
ALTER TABLE continuum.context_probe ENABLE ROW LEVEL SECURITY;
ALTER TABLE continuum.context_probe FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS context_probe_isolation ON continuum.context_probe;
CREATE POLICY context_probe_isolation ON continuum.context_probe
  USING (tenant_id = continuum.current_tenant())
  WITH CHECK (tenant_id = continuum.current_tenant());
GRANT SELECT ON continuum.context_probe TO continuum_app;

-- The app role must NOT be able to mutate identity/membership mappings. It holds no
-- table privileges on the identity tables (access is via the trusted functions);
-- the least-privilege grants below are the ONLY continuum-schema grants it receives.
-- (No GRANT of SELECT/INSERT/UPDATE/DELETE on principals/external_identities/
--  tenant_memberships/authenticated_sessions/delegations/break_glass_grants.)
