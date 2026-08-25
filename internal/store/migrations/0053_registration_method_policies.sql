ALTER TABLE nodes
  ADD COLUMN IF NOT EXISTS registration_methods JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE nodes
  DROP CONSTRAINT IF EXISTS nodes_registration_methods_object_check;

ALTER TABLE nodes
  ADD CONSTRAINT nodes_registration_methods_object_check
  CHECK (jsonb_typeof(registration_methods) = 'object');

ALTER TABLE oauth_pending_enrollments
  ADD COLUMN IF NOT EXISTS node_id BIGINT REFERENCES nodes(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS registration_policy_version BIGINT,
  ADD COLUMN IF NOT EXISTS discord_membership_verified_at TIMESTAMPTZ;

ALTER TABLE oauth_pending_enrollments
  DROP CONSTRAINT IF EXISTS oauth_pending_node_policy_pair_check;

ALTER TABLE oauth_pending_enrollments
  ADD CONSTRAINT oauth_pending_node_policy_pair_check CHECK (
    (node_id IS NULL AND registration_policy_version IS NULL)
    OR (node_id IS NOT NULL AND registration_policy_version > 0)
  );

ALTER TABLE oauth_pending_enrollments
  DROP CONSTRAINT IF EXISTS oauth_pending_discord_membership_proof_check;

ALTER TABLE oauth_pending_enrollments
  ADD CONSTRAINT oauth_pending_discord_membership_proof_check CHECK (
    discord_membership_verified_at IS NULL
    OR (provider = 'discord' AND node_id IS NOT NULL)
  );
