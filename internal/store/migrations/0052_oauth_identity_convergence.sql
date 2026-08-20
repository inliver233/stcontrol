-- 0052: durable per-node OAuth identity convergence (R14).
--
-- A Controller user may bind both Discord and LinuxDo while older
-- SillyTavern records only projected one OAuth identity. Keep one durable,
-- version-fenced intent per node/provider so online nodes converge through the
-- fixed Agent command channel and offline nodes converge after reconnecting.

CREATE TABLE IF NOT EXISTS node_account_oauth_syncs (
  global_user_id   BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  node_id          BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  provider         TEXT NOT NULL CHECK (provider IN ('discord','linuxdo')),
  provider_subject TEXT NOT NULL,
  local_handle     TEXT NOT NULL,
  account_version  BIGINT NOT NULL CHECK (account_version > 0),
  desired_present  BOOLEAN NOT NULL,
  state            TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','completed')),
  attempt          INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (global_user_id,node_id,provider)
);

CREATE INDEX IF NOT EXISTS idx_node_account_oauth_syncs_pending
  ON node_account_oauth_syncs (state,updated_at)
  WHERE state='pending';
