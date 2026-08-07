ALTER TABLE enrollment_tokens
  ADD COLUMN IF NOT EXISTS expected_node_id BIGINT REFERENCES nodes(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_expiry
  ON enrollment_tokens (expires_at) WHERE consumed_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_credentials_one_active
  ON agent_credentials (node_id) WHERE revoked_at IS NULL;

ALTER TABLE agent_commands ADD COLUMN IF NOT EXISTS attempt INT NOT NULL DEFAULT 0;
ALTER TABLE agent_commands ADD COLUMN IF NOT EXISTS result_digest BYTEA;
CREATE INDEX IF NOT EXISTS idx_agent_commands_reclaim
  ON agent_commands (node_id, lease_until)
  WHERE state IN ('leased','acked','running');

-- Superseded demo enrollment tokens were stored in plaintext and were not
-- scoped to a pre-created node. Invalidate and remove them during cut-over.
DELETE FROM register_tokens;
