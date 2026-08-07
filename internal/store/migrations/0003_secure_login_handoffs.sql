-- Browser login handoffs are opaque, one-use POST codes. Only a hash of the
-- derived secret is stored, and every request can be retried by operation_id.
ALTER TABLE control_tickets ADD COLUMN IF NOT EXISTS operation_id UUID;
ALTER TABLE control_tickets ADD COLUMN IF NOT EXISTS secret_hash BYTEA;
ALTER TABLE control_tickets ADD COLUMN IF NOT EXISTS consumed_by_node_id BIGINT REFERENCES nodes(id);

-- Any rows created by the superseded JWT demo must never become redeemable by
-- the new flow. Populate the new required columns, then revoke those rows.
UPDATE control_tickets
SET operation_id = COALESCE(operation_id, jti),
    secret_hash = COALESCE(secret_hash, decode(repeat('00', 32), 'hex')),
    revoked_at = COALESCE(revoked_at, now())
WHERE operation_id IS NULL OR secret_hash IS NULL;

ALTER TABLE control_tickets ALTER COLUMN operation_id SET NOT NULL;
ALTER TABLE control_tickets ALTER COLUMN secret_hash SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_control_tickets_operation_id
  ON control_tickets (operation_id);

-- HMAC timestamps alone do not prevent replay inside their acceptance window.
-- Store only a digest of each nonce and reject duplicate inserts per node.
CREATE TABLE IF NOT EXISTS agent_request_nonces (
  node_id      BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  nonce_hash   BYTEA NOT NULL,
  signed_at    TIMESTAMPTZ NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (node_id, nonce_hash),
  CHECK (expires_at > signed_at)
);
CREATE INDEX IF NOT EXISTS idx_agent_request_nonces_expiry
  ON agent_request_nonces (expires_at);
