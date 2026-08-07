ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_id UUID;
UPDATE replica_conflict_sources SET evidence_id=gen_random_uuid() WHERE evidence_id IS NULL;
ALTER TABLE replica_conflict_sources ALTER COLUMN evidence_id SET NOT NULL;
ALTER TABLE replica_conflict_sources ADD CONSTRAINT uq_replica_conflict_source_evidence UNIQUE (evidence_id);

ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_state TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE replica_conflict_sources ADD CONSTRAINT ck_replica_conflict_source_evidence_state
  CHECK (evidence_state IN ('pending','capturing','retry_wait','ready','failed'));
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_capture_basis TEXT;
ALTER TABLE replica_conflict_sources ADD CONSTRAINT ck_replica_conflict_source_capture_basis
  CHECK (evidence_capture_basis IS NULL OR evidence_capture_basis IN ('verified_archive','frozen_live'));
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_entries_sha256 BYTEA;
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_file_count BIGINT;
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_total_bytes BIGINT;
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_error_code TEXT;
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_attempt INT NOT NULL DEFAULT 0;
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_next_attempt_at TIMESTAMPTZ;
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_lease_owner TEXT;
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_lease_until TIMESTAMPTZ;
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS evidence_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE replica_conflict_sources ADD CONSTRAINT ck_replica_conflict_source_evidence_counts
  CHECK (
    (evidence_state='ready' AND octet_length(evidence_entries_sha256)=32
      AND evidence_file_count >= 0 AND evidence_total_bytes >= 0
      AND evidence_capture_basis IS NOT NULL)
    OR evidence_state<>'ready'
  );

CREATE TABLE IF NOT EXISTS replica_conflict_manifest_pages (
  evidence_id        UUID NOT NULL REFERENCES replica_conflict_sources(evidence_id) ON DELETE CASCADE,
  page_index         INT NOT NULL CHECK (page_index >= 0),
  entry_count        INT NOT NULL CHECK (entry_count >= 0),
  encrypted_payload  TEXT NOT NULL,
  plaintext_sha256   BYTEA NOT NULL CHECK (octet_length(plaintext_sha256)=32),
  created_at         TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (evidence_id,page_index)
);
CREATE INDEX IF NOT EXISTS idx_replica_conflict_evidence_schedulable
  ON replica_conflict_sources (evidence_state,evidence_next_attempt_at,evidence_updated_at)
  WHERE evidence_state IN ('pending','capturing','retry_wait');
