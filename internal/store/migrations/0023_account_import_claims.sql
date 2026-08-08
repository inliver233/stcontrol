ALTER TABLE account_import_candidates
  DROP CONSTRAINT IF EXISTS account_import_candidates_resolution_state_check,
  DROP CONSTRAINT IF EXISTS account_import_candidates_check;

ALTER TABLE account_import_candidates
  ADD CONSTRAINT account_import_candidates_resolution_state_check CHECK (resolution_state IN (
    'already_managed','auto_linked','claimed','claim_required','recovery_required',
    'oauth_unmatched','identity_conflict','invalid'
  )),
  ADD CONSTRAINT account_import_candidates_match_check CHECK (
    (resolution_state IN ('already_managed','auto_linked','claimed'))=(matched_user_id IS NOT NULL)
  );

CREATE TABLE IF NOT EXISTS account_import_claim_operations (
  operation_id       UUID PRIMARY KEY,
  candidate_id       UUID NOT NULL REFERENCES account_import_candidates(id) ON DELETE CASCADE,
  user_id            BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  node_id            BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  local_user_id      TEXT NOT NULL,
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  completed_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_import_claim_operations_user
  ON account_import_claim_operations (user_id,completed_at DESC);
