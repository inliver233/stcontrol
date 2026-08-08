CREATE TABLE IF NOT EXISTS user_data_faults (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operation_id          UUID NOT NULL UNIQUE,
  request_digest        BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  legacy_user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id),
  local_handle          TEXT NOT NULL CHECK (octet_length(local_handle) BETWEEN 1 AND 255),
  reason_code           TEXT NOT NULL CHECK (reason_code IN (
    'authoritative_integrity_mismatch',
    'user_directory_missing',
    'user_directory_unreadable',
    'user_database_corrupt'
  )),
  state                 TEXT NOT NULL CHECK (state IN (
    'reported','freezing','retry_wait','recovery_available',
    'recovery_unavailable','resolved'
  )),
  activity_epoch        BIGINT NOT NULL CHECK (activity_epoch>0),
  controller_generation BIGINT NOT NULL REFERENCES controller_epochs(generation),
  freeze_operation_id   UUID,
  attempt               INT NOT NULL DEFAULT 0 CHECK (attempt>=0),
  lease_owner           UUID,
  lease_until           TIMESTAMPTZ,
  next_attempt_at       TIMESTAMPTZ,
  protection_state      TEXT CHECK (protection_state IN (
    'takeover_available','restore_required','unavailable','conflict'
  )),
  error_code            TEXT CHECK (
    error_code IS NULL OR error_code ~ '^[a-z][a-z0-9_]{0,63}$'
  ),
  reported_by_admin_id  BIGINT NOT NULL REFERENCES admins(id),
  resolution_kind       TEXT CHECK (resolution_kind IN ('takeover','restore')),
  resolution_operation_id UUID,
  reported_at           TIMESTAMPTZ NOT NULL,
  frozen_at             TIMESTAMPTZ,
  resolved_at           TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (
    (state='freezing' AND freeze_operation_id IS NOT NULL
      AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
    OR (state<>'freezing' AND lease_owner IS NULL AND lease_until IS NULL)
  ),
  CHECK (
    (state='resolved' AND frozen_at IS NOT NULL AND resolved_at IS NOT NULL
      AND resolution_kind IS NOT NULL AND resolution_operation_id IS NOT NULL)
    OR (state<>'resolved' AND resolved_at IS NULL
      AND resolution_kind IS NULL AND resolution_operation_id IS NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_data_fault_open
  ON user_data_faults (user_id)
  WHERE state<>'resolved';

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_data_fault_freeze_operation
  ON user_data_faults (freeze_operation_id)
  WHERE freeze_operation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_user_data_fault_schedulable
  ON user_data_faults (next_attempt_at,updated_at,id)
  WHERE state IN ('reported','freezing','retry_wait');

CREATE INDEX IF NOT EXISTS idx_user_data_fault_recent
  ON user_data_faults (user_id,reported_at DESC);
