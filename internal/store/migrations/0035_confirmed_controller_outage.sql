ALTER TABLE nodes
  ADD COLUMN IF NOT EXISTS confirmed_controller_outage_started_at TIMESTAMPTZ;

COMMENT ON COLUMN nodes.confirmed_controller_outage_started_at IS
  'Start of the current uninterrupted signed-heartbeat plus public-health failure window; independent mode may not use the broader heartbeat-only outage timestamp.';
