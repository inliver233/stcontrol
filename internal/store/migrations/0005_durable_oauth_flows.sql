CREATE TABLE IF NOT EXISTS oauth_authorization_states (
  state_hash            BYTEA PRIMARY KEY,
  provider              TEXT NOT NULL CHECK (provider IN ('discord','linuxdo')),
  node_id               BIGINT REFERENCES nodes(id) ON DELETE SET NULL,
  controller_generation BIGINT NOT NULL REFERENCES controller_epochs(generation) ON DELETE RESTRICT,
  expires_at            TIMESTAMPTZ NOT NULL,
  consumed_at           TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_states_expiry
  ON oauth_authorization_states (expires_at);

CREATE TABLE IF NOT EXISTS oauth_pending_enrollments (
  id                    UUID PRIMARY KEY,
  token_hash            BYTEA NOT NULL UNIQUE,
  provider              TEXT NOT NULL CHECK (provider IN ('discord','linuxdo')),
  provider_subject      TEXT NOT NULL,
  display_name          TEXT NOT NULL,
  avatar_url            TEXT,
  state                 TEXT NOT NULL CHECK (state IN ('pending','processing','consumed')),
  claim_id              UUID,
  claim_until           TIMESTAMPTZ,
  result_user_id        BIGINT REFERENCES users(id) ON DELETE SET NULL,
  controller_generation BIGINT NOT NULL REFERENCES controller_epochs(generation) ON DELETE RESTRICT,
  expires_at            TIMESTAMPTZ NOT NULL,
  consumed_at           TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((state = 'processing') = (claim_id IS NOT NULL AND claim_until IS NOT NULL)),
  CHECK ((state = 'consumed') = (consumed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_oauth_pending_enrollments_expiry
  ON oauth_pending_enrollments (expires_at);
