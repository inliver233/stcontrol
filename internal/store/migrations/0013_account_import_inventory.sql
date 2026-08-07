CREATE TABLE IF NOT EXISTS account_import_batches (
  id                    UUID PRIMARY KEY,
  operation_id          UUID NOT NULL UNIQUE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  controller_generation BIGINT NOT NULL CHECK (controller_generation>0),
  inventory_digest      BYTEA NOT NULL CHECK (octet_length(inventory_digest)=32),
  source                TEXT NOT NULL CHECK (source IN ('adapter','directory_fallback','mixed')),
  state                 TEXT NOT NULL CHECK (state IN ('review','resolved','failed')),
  candidate_count       INT NOT NULL DEFAULT 0 CHECK (candidate_count>=0),
  auto_linked_count     INT NOT NULL DEFAULT 0 CHECK (auto_linked_count>=0),
  unresolved_count      INT NOT NULL DEFAULT 0 CHECK (unresolved_count>=0),
  created_by_admin_id   BIGINT REFERENCES admins(id) ON DELETE SET NULL,
  scanned_at            TIMESTAMPTZ NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (candidate_count=auto_linked_count+unresolved_count)
);
CREATE INDEX IF NOT EXISTS idx_account_import_batches_node
  ON account_import_batches (node_id,created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_node_accounts_local_user_id
  ON node_accounts (node_id,local_user_id) WHERE local_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS account_import_candidates (
  id                    UUID PRIMARY KEY,
  batch_id              UUID NOT NULL REFERENCES account_import_batches(id) ON DELETE CASCADE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  local_user_id         TEXT NOT NULL,
  local_handle          TEXT NOT NULL,
  size_bytes            BIGINT NOT NULL CHECK (size_bytes>=0),
  directory_fingerprint BYTEA NOT NULL CHECK (octet_length(directory_fingerprint)=32),
  source                TEXT NOT NULL CHECK (source IN ('adapter','directory_fallback')),
  account_kind          TEXT NOT NULL CHECK (account_kind IN ('password','oauth','mixed','unknown')),
  identity_fingerprints JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_admin              BOOLEAN NOT NULL DEFAULT false,
  resolution_state      TEXT NOT NULL CHECK (resolution_state IN (
    'already_managed','auto_linked','claim_required','recovery_required',
    'oauth_unmatched','identity_conflict','invalid'
  )),
  matched_user_id       BIGINT REFERENCES global_users(id) ON DELETE SET NULL,
  reason_code           TEXT NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (batch_id,node_id,local_user_id),
  CHECK ((resolution_state IN ('already_managed','auto_linked'))=(matched_user_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_account_import_candidates_review
  ON account_import_candidates (batch_id,resolution_state,local_handle);
