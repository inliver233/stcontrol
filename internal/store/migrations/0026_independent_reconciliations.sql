CREATE TABLE IF NOT EXISTS independent_user_reconciliations (
  id                    UUID PRIMARY KEY,
  operation_id          UUID NOT NULL UNIQUE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  user_id               BIGINT REFERENCES global_users(id) ON DELETE CASCADE,
  local_handle          TEXT NOT NULL,
  marker                UUID NOT NULL,
  changed_at            TIMESTAMPTZ NOT NULL,
  reason_code           TEXT NOT NULL,
  state                 TEXT NOT NULL CHECK (state IN (
                          'unmapped','pending','snapshotting','completing',
                          'completion_retry','conflict','retry_wait',
                          'succeeded','superseded','failed')),
  workflow_id           UUID UNIQUE REFERENCES workflows(id) ON DELETE SET NULL,
  attempt               INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  next_attempt_at       TIMESTAMPTZ,
  error_code            TEXT,
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  first_observed_at     TIMESTAMPTZ NOT NULL,
  last_observed_at      TIMESTAMPTZ NOT NULL,
  updated_at            TIMESTAMPTZ NOT NULL,
  completed_at          TIMESTAMPTZ,
  UNIQUE (node_id, local_handle, marker),
  CHECK ((state='succeeded') = (completed_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_independent_reconciliation_one_open_handle
  ON independent_user_reconciliations (node_id, local_handle)
  WHERE state NOT IN ('succeeded','superseded','failed');
CREATE INDEX IF NOT EXISTS idx_independent_reconciliation_schedulable
  ON independent_user_reconciliations (state, next_attempt_at, updated_at)
  WHERE state IN ('pending','snapshotting','completing','completion_retry','conflict','retry_wait');
CREATE INDEX IF NOT EXISTS idx_independent_reconciliation_user
  ON independent_user_reconciliations (user_id, state)
  WHERE user_id IS NOT NULL;
