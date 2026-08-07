ALTER TABLE nodes ADD COLUMN IF NOT EXISTS uuid UUID;
UPDATE nodes SET uuid=gen_random_uuid() WHERE uuid IS NULL;
ALTER TABLE nodes ALTER COLUMN uuid SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_uuid ON nodes(uuid);

ALTER TABLE nodes ADD COLUMN IF NOT EXISTS connectivity_state TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS operational_state TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS registration_policy_state TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS registration_policy_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS registration_policy_expires_at TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS compatibility_fingerprint TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS allocated_disk_bytes BIGINT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS disk_available_bytes BIGINT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS task_queue_depth INT NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS online_users INT NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS controller_generation BIGINT NOT NULL DEFAULT 0;

-- The demo stored reversible user passwords. The confirmed design synchronizes
-- compatible password material and never retains plaintext, so erase it during
-- the control-plane migration before any new workflow can read it.
UPDATE users SET password_enc=NULL WHERE password_enc IS NOT NULL;

CREATE TABLE IF NOT EXISTS controller_epochs (
  generation          BIGINT PRIMARY KEY CHECK (generation > 0),
  operation_id        UUID NOT NULL UNIQUE,
  controller_id       UUID NOT NULL,
  source              TEXT NOT NULL,
  state               TEXT NOT NULL CHECK (state IN ('active','revoked','rebuilding')),
  signing_key_version BIGINT NOT NULL CHECK (signing_key_version > 0),
  activated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at          TIMESTAMPTZ,
  CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_controller_one_active
  ON controller_epochs ((state)) WHERE state IN ('active','rebuilding');

INSERT INTO controller_epochs (
  generation, operation_id, controller_id, source, state, signing_key_version
)
VALUES (1, gen_random_uuid(), gen_random_uuid(), 'initial-migration', 'active', 1)
ON CONFLICT (generation) DO NOTHING;

CREATE TABLE IF NOT EXISTS global_users (
  id             BIGSERIAL PRIMARY KEY,
  uuid           UUID NOT NULL UNIQUE,
  legacy_user_id BIGINT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
  display_name   TEXT NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('active','disabled','conflict','recovering','deleted')),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO global_users (uuid, legacy_user_id, display_name, status, created_at, updated_at)
SELECT uuid, id, display_name,
       CASE WHEN status IN ('active','disabled') THEN status ELSE 'active' END,
       created_at, created_at
FROM users
ON CONFLICT (uuid) DO NOTHING;

CREATE TABLE IF NOT EXISTS auth_identities (
  id                    BIGSERIAL PRIMARY KEY,
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  provider              TEXT NOT NULL CHECK (provider IN ('password','discord','linuxdo')),
  provider_subject      TEXT NOT NULL,
  password_hash         TEXT,
  password_version      BIGINT NOT NULL DEFAULT 0 CHECK (password_version >= 0),
  status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','pending','revoked')),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_subject),
  UNIQUE (user_id, provider),
  CHECK ((provider = 'password') = (password_hash IS NOT NULL))
);

INSERT INTO auth_identities (user_id, provider, provider_subject, password_hash, status, created_at, updated_at)
SELECT gu.id, 'password', u.username, u.password_hash, 'active', u.created_at, u.created_at
FROM users u
JOIN global_users gu ON gu.legacy_user_id = u.id
WHERE u.auth_provider = 'password' AND u.password_hash IS NOT NULL
ON CONFLICT (provider, provider_subject) DO NOTHING;

INSERT INTO auth_identities (user_id, provider, provider_subject, status, created_at, updated_at)
SELECT gu.id, u.auth_provider, u.oauth_id, 'active', u.created_at, u.created_at
FROM users u
JOIN global_users gu ON gu.legacy_user_id = u.id
WHERE u.auth_provider IN ('discord','linuxdo') AND u.oauth_id IS NOT NULL
ON CONFLICT (provider, provider_subject) DO NOTHING;

CREATE TABLE IF NOT EXISTS node_accounts (
  id                        BIGSERIAL PRIMARY KEY,
  user_id                   BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  node_id                   BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  local_handle              TEXT NOT NULL,
  local_user_id             TEXT,
  status                    TEXT NOT NULL CHECK (status IN ('pending','active','disabled','conflict','stale','error')),
  account_version           BIGINT NOT NULL DEFAULT 0 CHECK (account_version >= 0),
  password_material_version BIGINT NOT NULL DEFAULT 0 CHECK (password_material_version >= 0),
  password_hash             TEXT,
  password_salt             TEXT,
  oauth_subjects            JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_admin                  BOOLEAN NOT NULL DEFAULT false,
  verified_at               TIMESTAMPTZ,
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, node_id),
  UNIQUE (node_id, local_handle)
);

INSERT INTO node_accounts (user_id, node_id, local_handle, status, updated_at)
SELECT gu.id, u.home_node_id, u.username, 'active', u.created_at
FROM users u
JOIN global_users gu ON gu.legacy_user_id = u.id
WHERE u.home_node_id IS NOT NULL
ON CONFLICT (user_id, node_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS controller_sessions (
  id             UUID PRIMARY KEY,
  user_id        BIGINT REFERENCES global_users(id) ON DELETE CASCADE,
  admin_id       BIGINT,
  token_hash     BYTEA NOT NULL UNIQUE,
  csrf_hash      BYTEA NOT NULL,
  expires_at     TIMESTAMPTZ NOT NULL,
  revoked_at     TIMESTAMPTZ,
  last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((user_id IS NOT NULL)::int + (admin_id IS NOT NULL)::int = 1)
);

CREATE TABLE IF NOT EXISTS user_activity_leases (
  user_id                BIGINT PRIMARY KEY REFERENCES global_users(id) ON DELETE CASCADE,
  writer_node_id         BIGINT NOT NULL REFERENCES nodes(id),
  session_id             UUID NOT NULL,
  activity_epoch         BIGINT NOT NULL CHECK (activity_epoch > 0),
  state                  TEXT NOT NULL CHECK (state IN ('active','quiescing','drained','ended','conflict','independent')),
  lease_expires_at       TIMESTAMPTZ NOT NULL,
  last_page_heartbeat_at TIMESTAMPTZ NOT NULL,
  last_request_at        TIMESTAMPTZ NOT NULL,
  in_flight_reads        INT NOT NULL DEFAULT 0 CHECK (in_flight_reads >= 0),
  in_flight_writes       INT NOT NULL DEFAULT 0 CHECK (in_flight_writes >= 0),
  controller_generation  BIGINT NOT NULL CHECK (controller_generation > 0),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS activity_lease_operations (
  operation_id          UUID PRIMARY KEY,
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  requested_node_id     BIGINT NOT NULL REFERENCES nodes(id),
  requested_session_id  UUID NOT NULL,
  outcome               TEXT NOT NULL CHECK (outcome IN ('acquired','existing','rejected','ended','renewed')),
  result_writer_node_id BIGINT REFERENCES nodes(id),
  result_session_id     UUID,
  result_activity_epoch BIGINT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workflows (
  id                    UUID PRIMARY KEY,
  operation_id          UUID NOT NULL UNIQUE,
  workflow_type         TEXT NOT NULL CHECK (workflow_type IN ('registration','password_sync','snapshot','restore','replica_move','conflict_resolution','node_retirement','controller_rebuild')),
  state                 TEXT NOT NULL CHECK (state IN ('scheduled','quiescing','drained','snapshotting','transferring','verifying','publishing','retry_wait','cancelled','failed','succeeded')),
  user_id               BIGINT REFERENCES global_users(id) ON DELETE CASCADE,
  source_node_id        BIGINT REFERENCES nodes(id),
  target_node_id        BIGINT REFERENCES nodes(id),
  activity_epoch        BIGINT,
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  attempt               INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  next_attempt_at       TIMESTAMPTZ,
  error_code            TEXT,
  error_summary         TEXT,
  cleanup_state         TEXT NOT NULL DEFAULT 'not_required' CHECK (cleanup_state IN ('not_required','pending','running','succeeded','failed')),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at           TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_workflows_schedulable
  ON workflows (state, next_attempt_at, created_at)
  WHERE state IN ('scheduled','retry_wait');
CREATE UNIQUE INDEX IF NOT EXISTS idx_workflows_one_user_snapshot
  ON workflows (user_id)
  WHERE workflow_type IN ('snapshot','restore','conflict_resolution')
    AND state NOT IN ('cancelled','failed','succeeded');

CREATE TABLE IF NOT EXISTS workflow_steps (
  workflow_id  UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
  step_name    TEXT NOT NULL,
  state        TEXT NOT NULL CHECK (state IN ('pending','running','retry_wait','cancelled','failed','succeeded')),
  attempt      INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  lease_owner  TEXT,
  lease_until  TIMESTAMPTZ,
  result       JSONB,
  error_code   TEXT,
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (workflow_id, step_name)
);

CREATE TABLE IF NOT EXISTS snapshot_manifests (
  id                    UUID PRIMARY KEY,
  workflow_id           UUID NOT NULL UNIQUE REFERENCES workflows(id) ON DELETE RESTRICT,
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  source_node_id        BIGINT NOT NULL REFERENCES nodes(id),
  activity_epoch        BIGINT NOT NULL,
  format_version        INT NOT NULL CHECK (format_version > 0),
  manifest_sha256       BYTEA NOT NULL,
  archive_sha256        BYTEA,
  file_count            BIGINT NOT NULL CHECK (file_count >= 0),
  total_bytes           BIGINT NOT NULL CHECK (total_bytes >= 0),
  state                 TEXT NOT NULL CHECK (state IN ('building','immutable','invalid','deleted')),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS replica_copies (
  id                 UUID PRIMARY KEY,
  user_id            BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  node_id            BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  snapshot_id        UUID REFERENCES snapshot_manifests(id) ON DELETE RESTRICT,
  replica_kind       TEXT NOT NULL CHECK (replica_kind IN ('active','archive','hot_standby')),
  state              TEXT NOT NULL CHECK (state IN ('empty','receiving','verifying','ready','stale','conflict','unprotected','corrupt','deleting','error')),
  origin             TEXT NOT NULL CHECK (origin IN ('primary','configured','temporary_failure_protection','migration','recovery')),
  is_authoritative   BOOLEAN NOT NULL DEFAULT false,
  compatibility_state TEXT NOT NULL DEFAULT 'unknown' CHECK (compatibility_state IN ('unknown','compatible','incompatible')),
  published_at       TIMESTAMPTZ,
  verified_at        TIMESTAMPTZ,
  retain_until       TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, node_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_replica_one_authoritative
  ON replica_copies (user_id) WHERE is_authoritative;

CREATE TABLE IF NOT EXISTS control_tickets (
  jti                   UUID PRIMARY KEY,
  ticket_type           TEXT NOT NULL CHECK (ticket_type IN ('user_login','node_admin','disaster_takeover','transfer_capability')),
  issuer                TEXT NOT NULL,
  audience              TEXT NOT NULL,
  subject               TEXT NOT NULL,
  user_id               BIGINT REFERENCES global_users(id) ON DELETE CASCADE,
  target_node_id        BIGINT REFERENCES nodes(id) ON DELETE CASCADE,
  session_id            UUID,
  activity_epoch        BIGINT,
  key_id                TEXT NOT NULL,
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  issued_at             TIMESTAMPTZ NOT NULL,
  not_before            TIMESTAMPTZ NOT NULL,
  expires_at            TIMESTAMPTZ NOT NULL,
  consumed_at           TIMESTAMPTZ,
  revoked_at            TIMESTAMPTZ,
  CHECK (not_before >= issued_at),
  CHECK (expires_at > not_before)
);
CREATE INDEX IF NOT EXISTS idx_control_tickets_expiry ON control_tickets (expires_at);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
  id                  UUID PRIMARY KEY,
  operation_id        UUID NOT NULL UNIQUE,
  token_hash          BYTEA NOT NULL UNIQUE,
  expected_role       TEXT NOT NULL CHECK (expected_role IN ('compute','storage','passive_controller')),
  expected_fingerprint TEXT,
  expires_at          TIMESTAMPTZ NOT NULL,
  consumed_at         TIMESTAMPTZ,
  consumed_node_id    BIGINT REFERENCES nodes(id),
  created_by_admin_id BIGINT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_credentials (
  id                    UUID PRIMARY KEY,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  credential_version    BIGINT NOT NULL CHECK (credential_version > 0),
  credential_type       TEXT NOT NULL CHECK (credential_type IN ('hmac','mtls','public_key')),
  secret_ciphertext     BYTEA,
  public_identity       TEXT,
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  expires_at            TIMESTAMPTZ,
  revoked_at            TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (node_id, credential_version),
  CHECK ((secret_ciphertext IS NOT NULL)::int + (public_identity IS NOT NULL)::int = 1)
);

CREATE TABLE IF NOT EXISTS agent_commands (
  id                    UUID PRIMARY KEY,
  operation_id          UUID NOT NULL UNIQUE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  command_type          TEXT NOT NULL,
  payload               JSONB NOT NULL,
  payload_sha256        BYTEA NOT NULL,
  state                 TEXT NOT NULL CHECK (state IN ('queued','leased','acked','running','succeeded','failed','cancelled','expired')),
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  lease_owner           TEXT,
  lease_until           TIMESTAMPTZ,
  expires_at            TIMESTAMPTZ NOT NULL,
  result_summary        JSONB,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_commands_delivery
  ON agent_commands (node_id, state, created_at) WHERE state IN ('queued','leased');

CREATE TABLE IF NOT EXISTS admins (
  id            BIGSERIAL PRIMARY KEY,
  uuid          UUID NOT NULL UNIQUE,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('active','disabled')),
  created_by    BIGINT REFERENCES admins(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE controller_sessions
  ADD CONSTRAINT fk_controller_sessions_admin
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS admin_node_links (
  admin_id             BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  node_id              BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  local_handle         TEXT NOT NULL,
  state                TEXT NOT NULL CHECK (state IN ('pending','verified','revoked','stale')),
  last_verified_at     TIMESTAMPTZ,
  revoked_at           TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (admin_id, node_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id                    BIGSERIAL PRIMARY KEY,
  occurred_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_type            TEXT NOT NULL CHECK (actor_type IN ('user','admin','agent','controller','system')),
  actor_id              TEXT,
  action                TEXT NOT NULL,
  target_type           TEXT NOT NULL,
  target_id             TEXT,
  operation_id          UUID,
  controller_generation BIGINT,
  input_digest          BYTEA,
  outcome               TEXT NOT NULL,
  detail                JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_operation ON audit_events (operation_id) WHERE operation_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS alerts (
  id                  UUID PRIMARY KEY,
  deduplication_key   TEXT NOT NULL UNIQUE,
  severity            TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
  state               TEXT NOT NULL CHECK (state IN ('open','suppressed','acknowledged','resolved')),
  category            TEXT NOT NULL,
  user_id             BIGINT REFERENCES global_users(id) ON DELETE CASCADE,
  node_id             BIGINT REFERENCES nodes(id) ON DELETE CASCADE,
  workflow_id         UUID REFERENCES workflows(id) ON DELETE SET NULL,
  summary             TEXT NOT NULL,
  first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  notify_after        TIMESTAMPTZ,
  resolved_at         TIMESTAMPTZ,
  occurrence_count    BIGINT NOT NULL DEFAULT 1 CHECK (occurrence_count > 0)
);

CREATE TABLE IF NOT EXISTS node_metric_samples (
  node_id              BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  sampled_at           TIMESTAMPTZ NOT NULL,
  cpu_avg_pct          REAL,
  cpu_peak_pct         REAL,
  memory_avg_pct       REAL,
  memory_peak_pct      REAL,
  disk_used_pct        REAL,
  disk_available_bytes BIGINT,
  online_users         INT,
  task_queue_depth     INT,
  latency_ms           INT,
  PRIMARY KEY (node_id, sampled_at)
);
CREATE INDEX IF NOT EXISTS idx_node_metric_samples_time ON node_metric_samples (sampled_at);
