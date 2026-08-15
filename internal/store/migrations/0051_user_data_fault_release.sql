ALTER TABLE user_data_faults
  ADD COLUMN IF NOT EXISTS release_state TEXT NOT NULL DEFAULT 'not_required',
  ADD COLUMN IF NOT EXISTS release_operation_id UUID,
  ADD COLUMN IF NOT EXISTS release_controller_generation BIGINT REFERENCES controller_epochs(generation),
  ADD COLUMN IF NOT EXISTS release_attempt INT NOT NULL DEFAULT 0 CHECK (release_attempt>=0),
  ADD COLUMN IF NOT EXISTS release_lease_owner UUID,
  ADD COLUMN IF NOT EXISTS release_lease_until TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS release_next_attempt_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS release_error_code TEXT CHECK (
    release_error_code IS NULL OR release_error_code ~ '^[a-z][a-z0-9_]{0,63}$'
  ),
  ADD COLUMN IF NOT EXISTS release_released_at TIMESTAMPTZ;

-- A node stores at most one data-fault gate for a handle.  If historical data
-- contains several resolved faults, only the newest resolved fault can still
-- own that gate.  A later open fault may coexist because its pre-migration
-- freeze can have been rejected by the older gate; release the older gate
-- first, then let the existing open fault retry its freeze.  Older resolved
-- history is explicitly superseded instead of creating permanent retries.
WITH ranked_resolved AS (
  SELECT fault.id,
    row_number() OVER (
      PARTITION BY fault.user_id
      ORDER BY fault.resolved_at DESC,fault.updated_at DESC,fault.id DESC
    ) AS resolved_rank
  FROM user_data_faults fault
  WHERE fault.state='resolved' AND fault.release_state='not_required'
)
UPDATE user_data_faults fault SET
  release_state=CASE
    WHEN ranked.resolved_rank=1 THEN 'pending'
    ELSE 'superseded'
  END,
  release_next_attempt_at=CASE
    WHEN ranked.resolved_rank=1
      THEN COALESCE(fault.resolved_at,fault.updated_at,now())
    ELSE NULL
  END
FROM ranked_resolved ranked
WHERE fault.id=ranked.id;

ALTER TABLE user_data_faults
  ADD CONSTRAINT ck_user_data_fault_release_state CHECK (release_state IN (
    'not_required','pending','releasing','retry_wait','released','superseded'
  )),
  ADD CONSTRAINT ck_user_data_fault_release_scope CHECK (
    ((state='resolved' AND release_state<>'not_required')
      OR (state<>'resolved' AND release_state='not_required'))
  ),
  ADD CONSTRAINT ck_user_data_fault_release_shape CHECK (
    (release_state='not_required'
      AND release_operation_id IS NULL AND release_controller_generation IS NULL
      AND release_attempt=0 AND release_lease_owner IS NULL AND release_lease_until IS NULL
      AND release_next_attempt_at IS NULL AND release_error_code IS NULL
      AND release_released_at IS NULL)
    OR (release_state='pending'
      AND release_operation_id IS NULL AND release_controller_generation IS NULL
      AND release_attempt=0 AND release_lease_owner IS NULL AND release_lease_until IS NULL
      AND release_next_attempt_at IS NOT NULL AND release_error_code IS NULL
      AND release_released_at IS NULL)
    OR (release_state='releasing'
      AND release_operation_id IS NOT NULL AND release_controller_generation IS NOT NULL
      AND release_attempt>0
      AND release_lease_owner IS NOT NULL AND release_lease_until IS NOT NULL
      AND release_next_attempt_at IS NULL AND release_error_code IS NULL
      AND release_released_at IS NULL)
    OR (release_state='retry_wait'
      AND release_operation_id IS NOT NULL AND release_controller_generation IS NOT NULL
      AND release_attempt>0
      AND release_lease_owner IS NULL AND release_lease_until IS NULL
      AND release_next_attempt_at IS NOT NULL AND release_error_code IS NOT NULL
      AND release_released_at IS NULL)
    OR (release_state='released'
      AND release_operation_id IS NOT NULL AND release_controller_generation IS NOT NULL
      AND release_attempt>0
      AND release_lease_owner IS NULL AND release_lease_until IS NULL
      AND release_next_attempt_at IS NULL AND release_error_code IS NULL
      AND release_released_at IS NOT NULL)
    OR (release_state='superseded'
      AND release_operation_id IS NULL AND release_controller_generation IS NULL
      AND release_attempt=0 AND release_lease_owner IS NULL AND release_lease_until IS NULL
      AND release_next_attempt_at IS NULL AND release_error_code IS NULL
      AND release_released_at IS NULL)
  );

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_data_fault_release_open
  ON user_data_faults (user_id)
  WHERE state='resolved' AND release_state NOT IN ('released','superseded');

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_data_fault_release_operation
  ON user_data_faults (release_operation_id)
  WHERE release_operation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_user_data_fault_release_schedulable
  ON user_data_faults (COALESCE(release_next_attempt_at,release_lease_until),updated_at,id)
  WHERE release_state IN ('pending','releasing','retry_wait');
