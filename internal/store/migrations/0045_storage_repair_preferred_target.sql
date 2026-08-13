-- Round 26: administrators keep the ability to manually steer the storage
-- repair target.  When a preferred target is set on a pending task, the
-- reconciler prefers that node if it is still capacity/health eligible and
-- falls back to the deterministic auto-selection otherwise.  NULL = auto.
ALTER TABLE storage_repair_tasks
  ADD COLUMN IF NOT EXISTS preferred_target_node_id BIGINT
    REFERENCES nodes(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_storage_repair_preferred_target
  ON storage_repair_tasks (preferred_target_node_id)
  WHERE preferred_target_node_id IS NOT NULL;
