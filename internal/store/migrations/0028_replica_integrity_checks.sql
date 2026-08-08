ALTER TABLE replica_copies
  ADD COLUMN IF NOT EXISTS integrity_state TEXT NOT NULL DEFAULT 'due'
    CHECK (integrity_state IN ('due','checking','verified','retry_wait','corrupt')),
  ADD COLUMN IF NOT EXISTS integrity_operation_id UUID,
  ADD COLUMN IF NOT EXISTS integrity_controller_generation BIGINT,
  ADD COLUMN IF NOT EXISTS integrity_lease_until TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS integrity_attempt INT NOT NULL DEFAULT 0 CHECK (integrity_attempt >= 0),
  ADD COLUMN IF NOT EXISTS integrity_checked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS integrity_next_check_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS integrity_error_code TEXT;

CREATE INDEX IF NOT EXISTS idx_replica_integrity_due
  ON replica_copies (integrity_next_check_at,id)
  WHERE replica_kind='archive' AND state='ready'
    AND integrity_state IN ('due','verified','retry_wait','checking');
