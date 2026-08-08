ALTER TABLE nodes
  ADD COLUMN IF NOT EXISTS controller_peer_witness_failures INTEGER NOT NULL DEFAULT 0
  CHECK (controller_peer_witness_failures >= 0);

COMMENT ON COLUMN nodes.controller_peer_witness_failures IS
  'Consecutive signed peer-witness quorums that independently observed the configured Controller unavailable; resets on missing or disagreeing quorum.';
