CREATE TABLE IF NOT EXISTS user_protection_states (
  user_id                    BIGINT PRIMARY KEY REFERENCES global_users(id) ON DELETE CASCADE,
  state                      TEXT NOT NULL CHECK (state IN (
    'protected','temporary','unprotected','takeover_available',
    'restore_required','unavailable','conflict'
  )),
  reason_code                TEXT NOT NULL,
  authoritative_node_id      BIGINT REFERENCES nodes(id) ON DELETE SET NULL,
  recovery_node_id           BIGINT REFERENCES nodes(id) ON DELETE SET NULL,
  latest_recovery_snapshot_id UUID REFERENCES snapshot_manifests(id) ON DELETE SET NULL,
  latest_recovery_at         TIMESTAMPTZ,
  version                    BIGINT NOT NULL DEFAULT 1 CHECK (version>0),
  changed_at                 TIMESTAMPTZ NOT NULL,
  evaluated_at               TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_protection_attention
  ON user_protection_states (state,changed_at,user_id)
  WHERE state<>'protected';

CREATE TABLE IF NOT EXISTS replica_takeover_operations (
  operation_id          UUID PRIMARY KEY,
  request_digest        BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  source_node_id        BIGINT NOT NULL REFERENCES nodes(id),
  target_node_id        BIGINT NOT NULL REFERENCES nodes(id),
  snapshot_id           UUID NOT NULL REFERENCES snapshot_manifests(id) ON DELETE RESTRICT,
  snapshot_published_at TIMESTAMPTZ NOT NULL,
  previous_activity_epoch BIGINT,
  controller_generation BIGINT NOT NULL CHECK (controller_generation>0),
  acknowledged_at       TIMESTAMPTZ NOT NULL,
  completed_at          TIMESTAMPTZ NOT NULL,
  CHECK (source_node_id<>target_node_id)
);
CREATE INDEX IF NOT EXISTS idx_replica_takeover_user
  ON replica_takeover_operations (user_id,completed_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_visible
  ON alerts (state,notify_after,last_seen_at DESC)
  WHERE state IN ('open','acknowledged');
