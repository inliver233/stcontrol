CREATE TABLE IF NOT EXISTS node_compatibility_incidents (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  node_id                  BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  state                    TEXT NOT NULL CHECK (state IN ('isolated','verifying','resolved')),
  reason_code              TEXT NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  previous_fingerprint     TEXT CHECK (
    previous_fingerprint IS NULL OR previous_fingerprint ~ '^[0-9a-fA-F]{64}$'
  ),
  observed_fingerprint     TEXT NOT NULL CHECK (observed_fingerprint ~ '^[0-9a-fA-F]{64}$'),
  observed_agent_version   TEXT NOT NULL CHECK (octet_length(observed_agent_version) <= 128),
  observed_tavern_version  TEXT NOT NULL CHECK (octet_length(observed_tavern_version) <= 128),
  compatible_observations  INT NOT NULL DEFAULT 0 CHECK (compatible_observations BETWEEN 0 AND 3),
  controller_generation    BIGINT NOT NULL REFERENCES controller_epochs(generation),
  verification_started_at  TIMESTAMPTZ,
  first_seen_at            TIMESTAMPTZ NOT NULL,
  last_seen_at             TIMESTAMPTZ NOT NULL,
  resolved_at              TIMESTAMPTZ,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (last_seen_at >= first_seen_at),
  CHECK (
    (state='isolated' AND compatible_observations=0 AND verification_started_at IS NULL AND resolved_at IS NULL)
    OR (state='verifying' AND compatible_observations BETWEEN 1 AND 2 AND verification_started_at IS NOT NULL AND resolved_at IS NULL)
    OR (state='resolved' AND compatible_observations=3 AND verification_started_at IS NOT NULL AND resolved_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_node_compatibility_incident_open
  ON node_compatibility_incidents (node_id)
  WHERE state IN ('isolated','verifying');

CREATE INDEX IF NOT EXISTS idx_node_compatibility_incidents_recent
  ON node_compatibility_incidents (node_id,created_at DESC);
