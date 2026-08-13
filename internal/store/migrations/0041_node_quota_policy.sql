-- R20/R21: node-level quota policy distribution.  The Controller stores the
-- administrator's expected disk quota (0 = inherit the agent's local
-- agent.yaml disk_quota_bytes) plus a monotonic policy version.  The agent
-- receives the expected policy in the heartbeat response, validates and
-- applies it locally, and reports the effective quota back on the next
-- heartbeat so the admin console can show expected vs effective vs sync state.
ALTER TABLE nodes
  ADD COLUMN expected_disk_quota_bytes BIGINT NOT NULL DEFAULT 0
    CHECK (expected_disk_quota_bytes >= 0),
  ADD COLUMN quota_policy_version BIGINT NOT NULL DEFAULT 0
    CHECK (quota_policy_version >= 0),
  ADD COLUMN quota_sync_state TEXT NOT NULL DEFAULT 'synced'
    CHECK (quota_sync_state IN ('synced','pending','applying','failed')),
  ADD COLUMN quota_sync_at TIMESTAMPTZ,
  ADD COLUMN quota_sync_error_code TEXT CHECK (
    quota_sync_error_code IS NULL OR
    quota_sync_error_code ~ '^[a-z][a-z0-9_]{0,63}$');
