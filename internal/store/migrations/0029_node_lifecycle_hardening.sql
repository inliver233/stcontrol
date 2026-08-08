ALTER TABLE node_lifecycle_events
  ADD CONSTRAINT node_lifecycle_reason_code_check
  CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$') NOT VALID;

CREATE INDEX IF NOT EXISTS idx_node_accounts_lifecycle_gate
  ON node_accounts (node_id,status);
CREATE INDEX IF NOT EXISTS idx_workflows_source_node_open
  ON workflows (source_node_id,state) WHERE source_node_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_workflows_target_node_open
  ON workflows (target_node_id,state) WHERE target_node_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_activity_leases_writer_node
  ON user_activity_leases (writer_node_id,state);
