ALTER TABLE nodes
  ADD COLUMN IF NOT EXISTS control_mode TEXT NOT NULL DEFAULT 'managed'
    CHECK (control_mode IN ('managed','controller-unreachable','independent','independent-draining')),
  ADD COLUMN IF NOT EXISTS control_mode_generation BIGINT NOT NULL DEFAULT 1
    CHECK (control_mode_generation > 0),
  ADD COLUMN IF NOT EXISTS desired_control_mode TEXT NOT NULL DEFAULT 'managed'
    CHECK (desired_control_mode IN ('managed','controller-unreachable','independent','independent-draining')),
  ADD COLUMN IF NOT EXISTS desired_mode_generation BIGINT NOT NULL DEFAULT 1
    CHECK (desired_mode_generation > 0),
  ADD COLUMN IF NOT EXISTS control_mode_reason_code TEXT,
  ADD COLUMN IF NOT EXISTS control_mode_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS controller_outage_started_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS independent_since TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_controller_success_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS controller_heartbeat_failures INT NOT NULL DEFAULT 0
    CHECK (controller_heartbeat_failures >= 0),
  ADD COLUMN IF NOT EXISTS controller_health_probe_failures INT NOT NULL DEFAULT 0
    CHECK (controller_health_probe_failures >= 0),
  ADD COLUMN IF NOT EXISTS active_independent_sessions INT NOT NULL DEFAULT 0
    CHECK (active_independent_sessions >= 0),
  ADD COLUMN IF NOT EXISTS pending_independent_syncs INT NOT NULL DEFAULT 0
    CHECK (pending_independent_syncs >= 0);

CREATE TABLE IF NOT EXISTS node_control_mode_events (
  id                            BIGSERIAL PRIMARY KEY,
  node_id                       BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  reported_mode                 TEXT NOT NULL CHECK (reported_mode IN ('managed','controller-unreachable','independent','independent-draining')),
  reported_mode_generation      BIGINT NOT NULL CHECK (reported_mode_generation > 0),
  desired_mode                  TEXT NOT NULL CHECK (desired_mode IN ('managed','controller-unreachable','independent','independent-draining')),
  desired_mode_generation       BIGINT NOT NULL CHECK (desired_mode_generation > 0),
  controller_generation         BIGINT NOT NULL CHECK (controller_generation > 0),
  reason_code                   TEXT NOT NULL,
  evidence                      JSONB NOT NULL,
  observed_at                   TIMESTAMPTZ NOT NULL,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_node_control_mode_events_node
  ON node_control_mode_events (node_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_nodes_control_mode_gate
  ON nodes (role, control_mode, desired_control_mode);
