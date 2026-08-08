CREATE TABLE IF NOT EXISTS agent_credential_rotations (
  id                    UUID PRIMARY KEY,
  operation_id          UUID NOT NULL UNIQUE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  credential_version    BIGINT NOT NULL CHECK (credential_version > 0),
  secret_ciphertext     BYTEA NOT NULL,
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  state                 TEXT NOT NULL CHECK (state IN ('pending','activated','expired','revoked')),
  expires_at            TIMESTAMPTZ NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  confirmed_at          TIMESTAMPTZ,
  UNIQUE (node_id, credential_version)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_credential_rotation_pending
  ON agent_credential_rotations (node_id) WHERE state='pending';
CREATE INDEX IF NOT EXISTS idx_agent_credential_rotation_expiry
  ON agent_credential_rotations (expires_at) WHERE state='pending';
