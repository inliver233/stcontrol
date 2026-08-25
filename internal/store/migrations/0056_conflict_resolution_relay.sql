-- Conflict evidence is an immutable archive identified by replica_conflict_sources.evidence_id,
-- not by snapshot_manifests.  Allow the existing encrypted relay spool to carry those archives
-- while retaining the workflow ownership and per-source idempotency fence.
ALTER TABLE relay_transfers
  DROP CONSTRAINT IF EXISTS relay_transfers_snapshot_id_fkey;

ALTER TABLE relay_transfers
  ADD COLUMN IF NOT EXISTS transport_scope_id UUID;

UPDATE relay_transfers
  SET transport_scope_id=workflow_id
  WHERE transport_scope_id IS NULL;

ALTER TABLE relay_transfers
  ALTER COLUMN transport_scope_id SET NOT NULL;

ALTER TABLE relay_transfers
  DROP CONSTRAINT IF EXISTS relay_transfers_workflow_id_attempt_key;

ALTER TABLE relay_transfers
  ADD CONSTRAINT relay_transfers_workflow_attempt_snapshot_key
    UNIQUE (workflow_id,attempt,snapshot_id);
