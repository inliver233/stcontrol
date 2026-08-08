ALTER TABLE replica_copies
  ADD COLUMN IF NOT EXISTS integrity_check_kind TEXT NOT NULL DEFAULT 'deep'
    CHECK (integrity_check_kind IN ('light','deep')),
  ADD COLUMN IF NOT EXISTS integrity_last_light_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS integrity_last_deep_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS integrity_deep_check_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE replica_copies
SET integrity_deep_check_at=LEAST(integrity_deep_check_at,integrity_next_check_at)
WHERE integrity_last_deep_at IS NULL;

DROP INDEX IF EXISTS idx_replica_integrity_due;
CREATE INDEX idx_replica_integrity_due
  ON replica_copies (integrity_next_check_at,integrity_deep_check_at,id)
  WHERE replica_kind='archive' AND state='ready'
    AND integrity_state IN ('due','verified','retry_wait','checking');
