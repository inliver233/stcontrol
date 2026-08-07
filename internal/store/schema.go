package store

// schemaSQL 建表语句（幂等, IF NOT EXISTS）。
const schemaSQL = `
CREATE TABLE IF NOT EXISTS users (
  id              BIGSERIAL PRIMARY KEY,
  uuid            UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  username        TEXT NOT NULL UNIQUE,
  display_name    TEXT NOT NULL,
  password_enc    TEXT,
  password_hash   TEXT,
  auth_provider   TEXT NOT NULL DEFAULT 'password',
  oauth_id        TEXT,
  avatar_url      TEXT,
  email           TEXT,
  home_node_id    BIGINT,
  status          TEXT NOT NULL DEFAULT 'active',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(auth_provider, oauth_id)
);

CREATE TABLE IF NOT EXISTS nodes (
  id              BIGSERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  role            TEXT NOT NULL DEFAULT 'compute',
  base_url        TEXT NOT NULL DEFAULT '',
  agent_url       TEXT NOT NULL DEFAULT '',
  agent_psk       TEXT NOT NULL DEFAULT '',
  region          TEXT,
  cpu_pct         REAL, mem_pct REAL, disk_pct REAL,
  agent_version   TEXT, tavern_version TEXT,
  last_seen_at    TIMESTAMPTZ,
  status          TEXT NOT NULL DEFAULT 'pending',
  allow_register  BOOLEAN NOT NULL DEFAULT true,
  is_backup_target BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_replicas (
  id              BIGSERIAL PRIMARY KEY,
  user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_id         BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL,
  data_version    BIGINT NOT NULL DEFAULT 0,
  state           TEXT NOT NULL DEFAULT 'empty',
  last_sync_at    TIMESTAMPTZ,
  checksum        TEXT,
  size_bytes      BIGINT,
  UNIQUE(user_id, node_id)
);

CREATE TABLE IF NOT EXISTS tickets (
  id              BIGSERIAL PRIMARY KEY,
  jti             TEXT NOT NULL UNIQUE,
  user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_id         BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  expires_at      TIMESTAMPTZ NOT NULL,
  used_at         TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS backup_jobs (
  id              BIGSERIAL PRIMARY KEY,
  user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  src_node_id     BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  dst_node_id     BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  trigger         TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending',
  data_version    BIGINT,
  bytes           BIGINT, file_count INT,
  error           TEXT,
  started_at      TIMESTAMPTZ, finished_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS invitation_codes (
  code            TEXT PRIMARY KEY,
  max_uses        INT NOT NULL DEFAULT 1,
  used_count      INT NOT NULL DEFAULT 0,
  node_id         BIGINT,
  expires_at      TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS register_tokens (
  token           TEXT PRIMARY KEY,
  note            TEXT,
  used            BOOLEAN NOT NULL DEFAULT false,
  expires_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY, actor TEXT, action TEXT,
  target TEXT, detail JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_replicas_user ON user_replicas(user_id);
CREATE INDEX IF NOT EXISTS idx_replicas_node ON user_replicas(node_id);
CREATE INDEX IF NOT EXISTS idx_tickets_jti ON tickets(jti);
CREATE INDEX IF NOT EXISTS idx_backup_user ON backup_jobs(user_id);
`
