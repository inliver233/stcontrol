-- Passkeys (WebAuthn) are an additional way to sign in to an existing global user. They never
-- count as the identity a user must keep, so losing every device never locks an account.
CREATE TABLE IF NOT EXISTS user_passkeys (
  id             BIGSERIAL PRIMARY KEY,
  user_id        BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  credential_id  BYTEA NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
  -- The library's full credential record (public key, sign count, flags, authenticator).
  credential     JSONB NOT NULL,
  name           TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 40),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_user_passkeys_user ON user_passkeys (user_id, created_at);

-- One-use challenges for a registration or sign-in in progress.
CREATE TABLE IF NOT EXISTS passkey_ceremonies (
  id          UUID PRIMARY KEY,
  purpose     TEXT NOT NULL CHECK (purpose IN ('register','login')),
  user_id     BIGINT REFERENCES global_users(id) ON DELETE CASCADE,
  session     JSONB NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((purpose = 'register') = (user_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_passkey_ceremonies_expiry ON passkey_ceremonies (expires_at);

-- Administrator settings; a single row. The feature starts switched off.
CREATE TABLE IF NOT EXISTS passkey_settings (
  id                  SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  enabled             BOOLEAN NOT NULL DEFAULT false,
  allow_registration  BOOLEAN NOT NULL DEFAULT true,
  show_on_login_page  BOOLEAN NOT NULL DEFAULT true,
  max_per_user        INT NOT NULL DEFAULT 10 CHECK (max_per_user BETWEEN 1 AND 10),
  user_verification   TEXT NOT NULL DEFAULT 'preferred'
                        CHECK (user_verification IN ('required','preferred','discouraged')),
  login_button_text   TEXT NOT NULL DEFAULT '通行密钥登录'
                        CHECK (char_length(login_button_text) BETWEEN 1 AND 24),
  login_hint_text     TEXT NOT NULL DEFAULT '指纹 / 面容一键登录，需先登录后在「账号安全」里添加'
                        CHECK (char_length(login_hint_text) <= 80),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by_admin_id BIGINT REFERENCES admins(id) ON DELETE SET NULL
);
INSERT INTO passkey_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
