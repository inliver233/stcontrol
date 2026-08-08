ALTER TABLE workflows
  ADD COLUMN IF NOT EXISTS transfer_mode TEXT NOT NULL DEFAULT 'direct'
    CHECK (transfer_mode IN ('direct','relay'));

CREATE TABLE IF NOT EXISTS relay_transfers (
  id                    UUID PRIMARY KEY,
  workflow_id           UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
  snapshot_id           UUID NOT NULL REFERENCES snapshot_manifests(id) ON DELETE CASCADE,
  source_node_id        BIGINT NOT NULL REFERENCES nodes(id),
  target_node_id        BIGINT NOT NULL REFERENCES nodes(id),
  attempt               INT NOT NULL CHECK (attempt >= 0),
  state                 TEXT NOT NULL CHECK (state IN (
                          'prepared','uploading','stored','downloading',
                          'consumed','expired','failed')),
  upload_token_hash     BYTEA NOT NULL CHECK (octet_length(upload_token_hash)=32),
  download_token_hash   BYTEA NOT NULL CHECK (octet_length(download_token_hash)=32),
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  max_ciphertext_bytes  BIGINT NOT NULL CHECK (max_ciphertext_bytes > 0),
  plaintext_bytes       BIGINT CHECK (plaintext_bytes IS NULL OR plaintext_bytes > 0),
  ciphertext_bytes      BIGINT CHECK (ciphertext_bytes IS NULL OR ciphertext_bytes > 0),
  archive_sha256        BYTEA CHECK (archive_sha256 IS NULL OR octet_length(archive_sha256)=32),
  ciphertext_sha256     BYTEA CHECK (ciphertext_sha256 IS NULL OR octet_length(ciphertext_sha256)=32),
  storage_path          TEXT,
  upload_lease_until    TIMESTAMPTZ,
  download_lease_until  TIMESTAMPTZ,
  expires_at            TIMESTAMPTZ NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL,
  updated_at            TIMESTAMPTZ NOT NULL,
  consumed_at           TIMESTAMPTZ,
  UNIQUE (workflow_id, attempt),
  CHECK (source_node_id<>target_node_id),
  CHECK (state NOT IN ('stored','downloading','consumed') OR storage_path IS NOT NULL),
  CHECK (state NOT IN ('stored','downloading','consumed') OR ciphertext_sha256 IS NOT NULL),
  CHECK (state NOT IN ('stored','downloading','consumed') OR ciphertext_bytes IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_relay_transfers_expiry
  ON relay_transfers (expires_at,state)
  WHERE state NOT IN ('consumed','expired','failed');
