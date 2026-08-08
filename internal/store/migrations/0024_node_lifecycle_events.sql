CREATE TABLE IF NOT EXISTS node_lifecycle_events (
  id              BIGSERIAL PRIMARY KEY,
  operation_id    UUID NOT NULL UNIQUE,
  node_id         BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  from_state      TEXT NOT NULL,
  to_state        TEXT NOT NULL,
  reason_code     TEXT NOT NULL,
  actor_admin_id  BIGINT REFERENCES admins(id) ON DELETE SET NULL,
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  created_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_node_lifecycle_events_node
  ON node_lifecycle_events (node_id,created_at DESC);
