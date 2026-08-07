ALTER TABLE auth_identities DROP CONSTRAINT IF EXISTS auth_identities_provider_provider_subject_key;
ALTER TABLE auth_identities DROP CONSTRAINT IF EXISTS auth_identities_user_id_provider_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_identity_active_subject
  ON auth_identities (provider,provider_subject) WHERE status IN ('active','pending');
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_identity_active_provider
  ON auth_identities (user_id,provider) WHERE status IN ('active','pending');

ALTER TABLE oauth_authorization_states
  ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'login';
ALTER TABLE oauth_authorization_states
  ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES global_users(id) ON DELETE CASCADE;
ALTER TABLE oauth_authorization_states
  ADD COLUMN IF NOT EXISTS session_id UUID REFERENCES controller_sessions(id) ON DELETE CASCADE;
ALTER TABLE oauth_authorization_states
  ADD CONSTRAINT oauth_authorization_states_purpose_check
  CHECK (
    (purpose='login' AND user_id IS NULL AND session_id IS NULL)
    OR (purpose='bind' AND user_id IS NOT NULL AND session_id IS NOT NULL AND node_id IS NULL)
  );
