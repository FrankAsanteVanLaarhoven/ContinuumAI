-- Continuum — Phase 3 S3: identity-verification & session boundary (persistence).
--
-- Adds the durable state the SessionManager and PrincipalMapper need, plus a
-- dedicated NON-tenant, least-privilege session-service role. This layer converts
-- an externally verified identity into a restart-safe, revocable session; it does
-- NOT grant tenant authority — the session-service role has NO access to
-- tenant_memberships or public.*, so a session can never self-authorize a tenant.
-- Tenant authority remains the S2B trusted-context path (begin_authenticated_context).

-- ---------------------------------------------------------------------------
-- Session columns for digest versioning, staleness detection, rotation lineage
-- and request correlation. All nullable so the S2B admin provisioning path
-- (which does not set them) keeps working; the SessionManager always sets them.
-- ---------------------------------------------------------------------------
ALTER TABLE continuum.authenticated_sessions
  ADD COLUMN IF NOT EXISTS credential_digest_version    text,
  ADD COLUMN IF NOT EXISTS identity_mapping_version      text,
  ADD COLUMN IF NOT EXISTS verification_policy_version    text,
  ADD COLUMN IF NOT EXISTS revocation_reason             text,
  ADD COLUMN IF NOT EXISTS rotated_from_session_id       uuid,
  ADD COLUMN IF NOT EXISTS created_request_id            text;

-- ---------------------------------------------------------------------------
-- External-identity mapping state: an (issuer, subject) maps to a principal only
-- while active; disabling or revoking the mapping, or bumping its version, denies.
-- ---------------------------------------------------------------------------
ALTER TABLE continuum.external_identities
  ADD COLUMN IF NOT EXISTS status          text NOT NULL DEFAULT 'active', -- active|disabled|revoked
  ADD COLUMN IF NOT EXISTS mapping_version bigint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS disabled_at     timestamptz,
  ADD COLUMN IF NOT EXISTS revoked_at      timestamptz;

-- ---------------------------------------------------------------------------
-- auth_events: the identity/session lifecycle evidence stream. Pre-tenant and
-- cross-tenant, so it is separate from the tenant-scoped hash-chained ledger.
-- Append-only (no UPDATE/DELETE). Redacted by construction: digests + non-secret
-- ids only — the application never writes raw credentials/claims/secrets here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS continuum.auth_events (
  event_id                   uuid PRIMARY KEY,
  event_type                 text NOT NULL,
  at                         timestamptz NOT NULL DEFAULT now(),
  request_id                 text NOT NULL,
  issuer_digest              text,
  subject_digest             text,
  principal_id               uuid,
  session_id                 uuid,
  verification_policy_version text,
  identity_mapping_version    text,
  outcome                    text NOT NULL,          -- success|denied
  reason                     text
);

DROP TRIGGER IF EXISTS auth_events_append_only ON continuum.auth_events;
CREATE TRIGGER auth_events_append_only
  BEFORE UPDATE OR DELETE ON continuum.auth_events
  FOR EACH ROW EXECUTE FUNCTION public.deny_mutation();

-- ---------------------------------------------------------------------------
-- Dedicated session-service role: a LOGIN role, narrower than the data-plane app
-- role and far narrower than admin. It manages sessions and reads identity state,
-- but has NO tenant authority path.
-- ---------------------------------------------------------------------------
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'continuum_session') THEN
    CREATE ROLE continuum_session LOGIN PASSWORD 'continuum_session' NOSUPERUSER;
  END IF;
END $$;

GRANT USAGE ON SCHEMA continuum TO continuum_session;

-- Read-only on the identity/principal tables (for mapping + principal-state checks).
GRANT SELECT ON continuum.external_identities TO continuum_session;
GRANT SELECT ON continuum.principals          TO continuum_session;

-- Sessions: create + read + touch/revoke ONLY the mutable columns (never re-point
-- principal_id, expiries, or the digest of an existing row).
GRANT SELECT, INSERT ON continuum.authenticated_sessions TO continuum_session;
GRANT UPDATE (last_seen_at, revoked_at, revocation_reason) ON continuum.authenticated_sessions TO continuum_session;

-- Append-only auth evidence.
GRANT SELECT, INSERT ON continuum.auth_events TO continuum_session;

-- Deliberately NOT granted to continuum_session: tenant_memberships, delegations,
-- break_glass_grants, any public.* table, and EXECUTE on begin_authenticated_context.
-- The session layer therefore cannot derive or grant a tenant.
