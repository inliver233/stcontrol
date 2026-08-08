CREATE TABLE IF NOT EXISTS conflict_resolution_operations (
  id                         BIGSERIAL PRIMARY KEY,
  operation_id               UUID NOT NULL UNIQUE,
  request_digest             BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
  workflow_id                UUID NOT NULL UNIQUE REFERENCES workflows(id) ON DELETE RESTRICT,
  conflict_id                UUID NOT NULL UNIQUE REFERENCES replica_conflicts(id) ON DELETE RESTRICT,
  user_id                    BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  base_node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  result_snapshot_id         UUID NOT NULL UNIQUE REFERENCES snapshot_manifests(id) ON DELETE RESTRICT,
  expected_conflict_version  BIGINT NOT NULL CHECK (expected_conflict_version > 0),
  default_action             TEXT NOT NULL CHECK (default_action IN ('use_base','preserve_all_originals')),
  decision_count             INT NOT NULL CHECK (decision_count >= 0 AND decision_count <= 100000),
  acknowledged_at            TIMESTAMPTZ NOT NULL,
  completed_at               TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_conflict_resolution_user
  ON conflict_resolution_operations (user_id,id DESC);

CREATE TABLE IF NOT EXISTS conflict_resolution_decisions (
  operation_id   UUID NOT NULL REFERENCES conflict_resolution_operations(operation_id) ON DELETE CASCADE,
  path           TEXT NOT NULL CHECK (path<>'' AND length(path)<=4096),
  path_sha256    BYTEA NOT NULL CHECK (octet_length(path_sha256)=32),
  source_node_id BIGINT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  action         TEXT NOT NULL CHECK (action IN ('use_source','preserve_both')),
  PRIMARY KEY (operation_id,path_sha256)
);

CREATE TABLE IF NOT EXISTS conflict_resolution_transfers (
  operation_id     UUID NOT NULL REFERENCES conflict_resolution_operations(operation_id) ON DELETE CASCADE,
  evidence_id      UUID NOT NULL REFERENCES replica_conflict_sources(evidence_id) ON DELETE RESTRICT,
  source_node_id   BIGINT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  target_node_id   BIGINT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  capability_id    UUID NOT NULL UNIQUE,
  capability_hash  BYTEA NOT NULL CHECK (octet_length(capability_hash)=32),
  state            TEXT NOT NULL CHECK (state IN ('prepared','consumed','revoked')),
  attempt          INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  expires_at       TIMESTAMPTZ NOT NULL,
  completed_at     TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (operation_id,evidence_id),
  CHECK (source_node_id<>target_node_id)
);
