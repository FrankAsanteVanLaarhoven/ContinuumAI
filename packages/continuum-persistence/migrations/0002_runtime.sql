-- Continuum durable data plane — runtime additions (Phase 2).
--
-- consumed_proofs: the durable point-of-use proof ledger. A disclosure consumes a
-- (token_id, challenge) proof exactly once; replaying the same challenge — even
-- after a process restart — is rejected because the row persists. The table is
-- RLS-scoped and append-only (deleting a consumed proof would re-enable replay).

CREATE TABLE IF NOT EXISTS consumed_proofs (
  tenant_id text NOT NULL,
  token_id text NOT NULL,
  challenge text NOT NULL,
  consumed_at text NOT NULL,
  PRIMARY KEY (tenant_id, token_id, challenge)
);

ALTER TABLE consumed_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE consumed_proofs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS consumed_proofs_isolation ON consumed_proofs;
CREATE POLICY consumed_proofs_isolation ON consumed_proofs
  USING (tenant_id = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true));

-- Append-only enforcement reuses deny_mutation() from 0001.
DROP TRIGGER IF EXISTS consumed_proofs_append_only ON consumed_proofs;
CREATE TRIGGER consumed_proofs_append_only
  BEFORE UPDATE OR DELETE ON consumed_proofs
  FOR EACH ROW EXECUTE FUNCTION deny_mutation();

GRANT SELECT, INSERT ON consumed_proofs TO continuum_app;
