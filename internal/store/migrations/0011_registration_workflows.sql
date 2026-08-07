CREATE TABLE IF NOT EXISTS registration_workflows (
  workflow_id              UUID PRIMARY KEY REFERENCES workflows(id) ON DELETE CASCADE,
  request_digest           BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
  pending_token_hash       BYTEA NOT NULL CHECK (octet_length(pending_token_hash)=32),
  client_expires_at        TIMESTAMPTZ NOT NULL,
  local_handle             TEXT NOT NULL,
  display_name             TEXT NOT NULL,
  auth_provider            TEXT NOT NULL CHECK (auth_provider IN ('password','discord','linuxdo')),
  password_hash            TEXT,
  password_material_hash   TEXT,
  password_material_salt   TEXT,
  oauth_subject            TEXT,
  avatar_url               TEXT,
  invitation_ciphertext    TEXT,
  registration_policy_version BIGINT NOT NULL CHECK (registration_policy_version>0),
  reservation_state        TEXT NOT NULL DEFAULT 'pending'
    CHECK (reservation_state IN ('pending','published','released')),
  local_user_id            TEXT,
  result_user_id           BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (
    reservation_state<>'pending'
    OR (
      (auth_provider='password' AND password_hash IS NOT NULL
        AND password_material_hash IS NOT NULL AND password_material_salt IS NOT NULL
        AND oauth_subject IS NULL)
      OR
      (auth_provider IN ('discord','linuxdo') AND password_hash IS NULL
        AND password_material_hash IS NULL AND password_material_salt IS NULL
        AND oauth_subject IS NOT NULL)
    )
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_registration_pending_handle
  ON registration_workflows (lower(local_handle)) WHERE reservation_state='pending';
CREATE INDEX IF NOT EXISTS idx_registration_client_token
  ON registration_workflows (pending_token_hash,client_expires_at);
