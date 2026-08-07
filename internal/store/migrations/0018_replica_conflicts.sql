CREATE TABLE IF NOT EXISTS replica_conflicts (
  id                    UUID PRIMARY KEY,
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  state                 TEXT NOT NULL CHECK (state IN (
                          'detected','inspecting','awaiting_decision','resolving',
                          'resolved','failed')),
  protection_version    BIGINT NOT NULL CHECK (protection_version > 0),
  controller_generation BIGINT REFERENCES controller_epochs(generation) ON DELETE RESTRICT,
  version               BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
  detected_at           TIMESTAMPTZ NOT NULL,
  sources_captured_at   TIMESTAMPTZ,
  updated_at            TIMESTAMPTZ NOT NULL,
  resolved_at           TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_replica_conflicts_one_open_user
  ON replica_conflicts (user_id)
  WHERE state NOT IN ('resolved','failed');

CREATE TABLE IF NOT EXISTS replica_conflict_sources (
  conflict_id         UUID NOT NULL REFERENCES replica_conflicts(id) ON DELETE CASCADE,
  node_id             BIGINT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  node_name           TEXT NOT NULL,
  node_role           TEXT NOT NULL CHECK (node_role IN ('compute','storage')),
  snapshot_id         UUID REFERENCES snapshot_manifests(id) ON DELETE RESTRICT,
  source_kind         TEXT NOT NULL CHECK (source_kind IN ('active','archive','hot_standby','unknown')),
  replica_state       TEXT NOT NULL,
  is_authoritative    BOOLEAN NOT NULL DEFAULT false,
  manifest_sha256     BYTEA,
  file_count          BIGINT CHECK (file_count IS NULL OR file_count >= 0),
  total_bytes         BIGINT CHECK (total_bytes IS NULL OR total_bytes >= 0),
  published_at        TIMESTAMPTZ,
  legacy_data_version BIGINT CHECK (legacy_data_version IS NULL OR legacy_data_version >= 0),
  legacy_checksum     TEXT,
  captured_at         TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (conflict_id, node_id),
  CHECK ((snapshot_id IS NULL) = (manifest_sha256 IS NULL)),
  CHECK ((snapshot_id IS NULL) = (file_count IS NULL)),
  CHECK ((snapshot_id IS NULL) = (total_bytes IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_replica_conflict_sources_snapshot
  ON replica_conflict_sources (snapshot_id) WHERE snapshot_id IS NOT NULL;
