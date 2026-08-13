-- R60: the Controller's own control-plane state is included in automatic
-- disaster backup.  Each run is a durable, idempotent intent (operation_id)
-- targeting one eligible pure-storage node.  A run owns a generation-fenced
-- execution lease, an attempt counter, and a bounded exponential retry backoff
-- that lives in the database so restarts cannot reset it.  Only the latest
-- successful backup per node is retained; older successes become 'superseded'.
CREATE TABLE IF NOT EXISTS controller_disaster_backups (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operation_id          UUID NOT NULL UNIQUE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  state                 TEXT NOT NULL CHECK (state IN (
                          'scheduled','snapshotting','transferring','verifying',
                          'publishing','succeeded','superseded','failed',
                          'retry_wait','cancelled')),
  controller_generation BIGINT REFERENCES controller_epochs(generation) ON DELETE RESTRICT,
  backup_kind           TEXT NOT NULL DEFAULT 'full' CHECK (
                          backup_kind IN ('pg_dump','control_snapshot','full')),
  payload_file_name     TEXT,
  payload_size_bytes    BIGINT,
  payload_sha256        BYTEA,
  manifest              JSONB,
  attempt               INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  next_attempt_at       TIMESTAMPTZ NOT NULL,
  lease_owner           UUID,
  lease_until           TIMESTAMPTZ,
  error_code            TEXT CHECK (
                          error_code IS NULL OR
                          error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  started_at            TIMESTAMPTZ,
  updated_at            TIMESTAMPTZ NOT NULL,
  finished_at           TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (payload_sha256 IS NULL OR octet_length(payload_sha256)=32),
  CHECK (
    NOT (state='scheduled' AND started_at IS NULL)
  )
);

-- One in-flight run per operation is guaranteed by the unique operation_id.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cdb_lease_owner
  ON controller_disaster_backups (lease_owner) WHERE lease_owner IS NOT NULL;

-- The reconciler drains due runs oldest-first and idempotently.
CREATE INDEX IF NOT EXISTS idx_cdb_due
  ON controller_disaster_backups (next_attempt_at,created_at,id)
  WHERE state IN ('scheduled','snapshotting','transferring','verifying','publishing','retry_wait');

-- Retention queries keeping the latest successful backup per node.
CREATE INDEX IF NOT EXISTS idx_cdb_success_per_node
  ON controller_disaster_backups (node_id,created_at DESC)
  WHERE state='succeeded';
