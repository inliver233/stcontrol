CREATE TABLE independent_activity_takeovers (
    operation_id UUID PRIMARY KEY,
    node_id BIGINT NOT NULL REFERENCES nodes(id),
    local_handle TEXT NOT NULL CHECK (
        local_handle = lower(local_handle)
        AND length(local_handle) BETWEEN 1 AND 128
        AND local_handle !~ '[[:cntrl:]]'
    ),
    parent_claim_id TEXT NOT NULL CHECK (parent_claim_id ~ '^[0-9a-f]{64}$'),
    claim_id TEXT NOT NULL CHECK (claim_id ~ '^[0-9a-f]{64}$'),
    controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
    activity_epoch BIGINT NOT NULL CHECK (activity_epoch > 0),
    takeover_sequence BIGINT NOT NULL CHECK (takeover_sequence > 0),
    confirmed_at TIMESTAMPTZ NOT NULL,
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (node_id, local_handle, controller_generation, activity_epoch, takeover_sequence),
    CHECK (last_observed_at >= first_observed_at)
);

CREATE INDEX independent_activity_takeovers_node_handle_idx
    ON independent_activity_takeovers (node_id, local_handle, confirmed_at DESC);
