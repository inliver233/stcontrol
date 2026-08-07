CREATE TABLE IF NOT EXISTS identity_recovery_operations (
  operation_id          UUID PRIMARY KEY,
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  admin_id              BIGINT NOT NULL REFERENCES admins(id) ON DELETE RESTRICT,
  request_digest        BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
  password_version      BIGINT NOT NULL CHECK (password_version>0),
  staged_node_count     INT NOT NULL CHECK (staged_node_count>=0),
  controller_generation BIGINT NOT NULL REFERENCES controller_epochs(generation) CHECK (controller_generation>0),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_identity_recovery_user
  ON identity_recovery_operations (user_id,created_at DESC);
