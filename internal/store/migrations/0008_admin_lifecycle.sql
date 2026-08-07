ALTER TABLE admins ADD COLUMN IF NOT EXISTS password_version BIGINT NOT NULL DEFAULT 1 CHECK (password_version > 0);
ALTER TABLE admins ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_admins_status ON admins (status, id);
