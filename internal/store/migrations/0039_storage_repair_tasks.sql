-- R09: automatic storage protection repairs are durable intents.  A task is
-- unique per user while active, owns an exact controller-generation execution
-- identity, and reserves the estimated archive bytes until its workflow is
-- terminal.  This prevents reconciler restarts from producing job storms or
-- overcommitting a storage node.
CREATE TABLE IF NOT EXISTS storage_repair_tasks (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  legacy_user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source_node_id        BIGINT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  target_node_id        BIGINT REFERENCES nodes(id) ON DELETE RESTRICT,
  last_target_node_id   BIGINT REFERENCES nodes(id) ON DELETE RESTRICT,
  estimated_bytes       BIGINT NOT NULL CHECK (estimated_bytes > 0),
  reserved_bytes        BIGINT NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
  state                 TEXT NOT NULL DEFAULT 'pending' CHECK (state IN (
                          'pending','retry_wait','workflow_running',
                          'succeeded','cancelled','failed')),
  attempt               INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  next_attempt_at       TIMESTAMPTZ NOT NULL,
  execution_id          UUID,
  lease_owner           UUID,
  lease_until           TIMESTAMPTZ,
  controller_generation BIGINT REFERENCES controller_epochs(generation) ON DELETE RESTRICT,
  workflow_id           UUID REFERENCES workflows(id) ON DELETE RESTRICT,
  last_workflow_id      UUID REFERENCES workflows(id) ON DELETE RESTRICT,
  backup_job_id         BIGINT REFERENCES backup_jobs(id) ON DELETE RESTRICT,
  last_error_code       TEXT CHECK (
                          last_error_code IS NULL OR
                          last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  created_at            TIMESTAMPTZ NOT NULL,
  updated_at            TIMESTAMPTZ NOT NULL,
  finished_at           TIMESTAMPTZ,
  CHECK (source_node_id <> COALESCE(target_node_id, 0)),
  CHECK (
    (state='workflow_running' AND target_node_id IS NOT NULL
      AND reserved_bytes=estimated_bytes AND execution_id IS NOT NULL
      AND lease_owner IS NOT NULL AND lease_until IS NOT NULL
      AND controller_generation IS NOT NULL AND workflow_id IS NOT NULL
      AND backup_job_id IS NOT NULL)
    OR
    (state<>'workflow_running' AND reserved_bytes=0 AND workflow_id IS NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_storage_repair_one_active_user
  ON storage_repair_tasks (user_id)
  WHERE state IN ('pending','retry_wait','workflow_running');

CREATE UNIQUE INDEX IF NOT EXISTS idx_storage_repair_execution
  ON storage_repair_tasks (execution_id) WHERE execution_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_storage_repair_lease_owner
  ON storage_repair_tasks (lease_owner) WHERE lease_owner IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_storage_repair_workflow
  ON storage_repair_tasks (workflow_id) WHERE workflow_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_storage_repair_due
  ON storage_repair_tasks (next_attempt_at,created_at,id)
  WHERE state IN ('pending','retry_wait');

CREATE INDEX IF NOT EXISTS idx_storage_repair_reservations
  ON storage_repair_tasks (target_node_id)
  WHERE state='workflow_running';
